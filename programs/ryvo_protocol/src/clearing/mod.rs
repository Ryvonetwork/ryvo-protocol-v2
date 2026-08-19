//! Arcium clearing: staging, queueing, the callback that records the verified bitmap, and
//! `settle_channels`, which does every piece of money math on-chain.
//!
//! # Trust split
//!
//! The MPC circuit answers exactly one question per staged commitment — *did the channel's
//! registered key(s) sign these fields?* — and returns one bit. It never sees a balance.
//! Everything about money (`min(delta, locked_balance)`, monotonicity, who gets credited) is
//! re-derived here from the same sealed bytes the circuit read, so a compromised MPC could at
//! worst approve an invalid signature, and even then the payment is capped by what the payer had
//! already locked in that specific channel.
//!
//! # Two phases
//!
//! 1. `clear_*_callback` — invoked by Arcium. Verifies the cluster's BLS signature over the
//!    output and writes the bitmap into `ClearingResult`. Touches no channels, so it is one small
//!    transaction whether the batch has 1 commitment or `N`.
//! 2. `settle_channels(indices)` — permissionless and repeatable. Reads the bitmap and the staged
//!    slots, is handed the channel and balance accounts for the commitments it is asked to
//!    settle, and moves funds.
//!
//! # Where the signing keys come from
//!
//! The relayer does not stage keys. It stages the **channel address**, and `seal_and_queue_*`
//! hands the circuit that channel's `signer_slots` bytes as an account argument, read by the
//! ARX nodes straight from the on-chain `Channel`. `settle_channels` then only has to check that
//! the account it is handed *is* the staged address (and carries the staged `channel_id`). A
//! relayer therefore cannot substitute a key: the key the circuit verified against is by
//! construction the one registered on the channel that will be debited.
//!
//! # Slot layout
//!
//! A `StagingBuffer` is `MAX_SLOTS` × 32-byte slots. Plaintext u128 = 16 LE bytes in the low
//! half; a channel address = one slot; packed signature bytes = 26 per slot, LE (3 slots).
//!
//! ```text
//! unilateral (N commitments, 5N slots):  ids[N] | channel[N] | sig[3N]
//! route      (N commitments, 10N slots): ids[N] | targets[N] | channel_ag[N] | channel_gp[N] | sig_agent[3N] | sig_gateway[3N]
//! ```
//!
//! The circuit's parameter order is `domain, ids, (targets,) keys…, sigs…`; the argument list is
//! assembled from buffer ranges and per-channel account reads to match it exactly.
//!
//! # Buffer reuse
//!
//! A relayer creates one buffer (`open_staging`) and reuses it: `reset_staging` clears a fully
//! settled (or failed) batch in place, so a steady-state batch costs no account creation, no
//! close, and no rent churn.

use crate::commitment::{unpack_pair, KIND_ROUTE, KIND_UNILATERAL, SIG_SLOTS, SLOT};
use crate::constants::{CLEARING_SEED, CONFIG_SEED};
use crate::error::RyvoError;
use crate::events::{BatchCleared, BatchClearingFailed, BatchQueued, ChannelSettled, RouteSettled};
use crate::state::{Balance, Channel, Config};
use crate::{ArciumSignerAccount, ID, ID_CONST};
use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::CallbackAccount;

/// Commitments per batch. Must equal `N_UNI` / `N_ROUTE` in `encrypted-ixs`. The circuit shape
/// is fixed at compile time, so a shorter batch is padded by the relayer (repeat a valid
/// commitment) and `count` tells `settle_channels` where the real ones end. 64 is the most an
/// 8-byte bitmap holds. Route batches are 32 because each route needs two key account arguments
/// and the Arcium program's own heap tops out between 66 and 131 account arguments per
/// computation (measured on localnet: 66 works, 131 does not).
pub const N_UNI: usize = 64;
pub const N_ROUTE: usize = 32;

pub const UNILATERAL_SLOTS_PER_RECORD: usize = 1 + 1 + SIG_SLOTS; // id, channel, sig = 5
pub const ROUTE_SLOTS_PER_RECORD: usize = 2 + 2 + 2 * SIG_SLOTS; // ids, targets, 2 channels, 2 sigs = 10
pub const UNILATERAL_SLOTS: usize = N_UNI * UNILATERAL_SLOTS_PER_RECORD; // 320
pub const ROUTE_SLOTS: usize = N_ROUTE * ROUTE_SLOTS_PER_RECORD; // 320
pub const MAX_SLOTS: usize = if UNILATERAL_SLOTS > ROUTE_SLOTS { UNILATERAL_SLOTS } else { ROUTE_SLOTS };

/// Byte offset of `slots` inside the account: 8-byte discriminator + header.
pub const SLOTS_OFFSET: usize = 8 + StagingBuffer::HEADER_LEN;

// Column offsets (in slots) within a batch.
pub const UNI_COL_IDS: usize = 0;
pub const UNI_COL_CHANNEL: usize = N_UNI;
pub const UNI_COL_SIG: usize = 2 * N_UNI;
pub const RT_COL_IDS: usize = 0;
pub const RT_COL_TARGETS: usize = N_ROUTE;
pub const RT_COL_CHANNEL_A: usize = 2 * N_ROUTE;
pub const RT_COL_CHANNEL_G: usize = 3 * N_ROUTE;
pub const RT_COL_SIG_A: usize = 4 * N_ROUTE;
pub const RT_COL_SIG_G: usize = 4 * N_ROUTE + SIG_SLOTS * N_ROUTE;

pub const fn batch_size(kind: u8) -> usize {
    if kind == KIND_ROUTE { N_ROUTE } else { N_UNI }
}

const COMP_DEF_OFFSET_CLEAR_UNILATERAL: u32 = comp_def_offset("clear_unilateral");
const COMP_DEF_OFFSET_CLEAR_ROUTE: u32 = comp_def_offset("clear_route");

// ============================================================================================
// State
// ============================================================================================

/// One relayer's batch buffer, reused across batches. Zero-copy: 20 KB, and `settle_channels`
/// reads only the slots it needs.
///
/// Not a PDA: it exceeds the 10 KB cap on accounts created inside a CPI, so the relayer creates
/// it with `SystemProgram::create_account` in the same transaction as `open_staging`, which takes
/// it via `#[account(zero)]`. Everything tied to it (`ClearingResult`) is a PDA seeded by its
/// address.
#[account(zero_copy)]
#[repr(C)]
pub struct StagingBuffer {
    /// Increments on every `reset_staging`; identifies the batch in events.
    pub batch_seq: u64,
    pub relayer: Pubkey,
    /// Real commitments staged; the rest of the batch is padding the circuit still processes.
    pub count: u16,
    /// `KIND_UNILATERAL` or `KIND_ROUTE` for the current batch.
    pub kind: u8,
    /// Set by `seal_and_queue_*`. Once sealed the slots are immutable — the circuit and
    /// `settle_channels` must read the same bytes.
    pub sealed: u8,
    pub _pad: [u8; 4],
    pub slots: [[u8; SLOT]; MAX_SLOTS],
}

impl StagingBuffer {
    pub const HEADER_LEN: usize = 8 + 32 + 2 + 1 + 1 + 4; // 48
    pub const SPACE: usize = 8 + Self::HEADER_LEN + SLOT * MAX_SLOTS;

    pub fn slots_per_record(kind: u8) -> Result<usize> {
        match kind {
            KIND_UNILATERAL => Ok(UNILATERAL_SLOTS_PER_RECORD),
            KIND_ROUTE => Ok(ROUTE_SLOTS_PER_RECORD),
            _ => Err(RyvoError::InvalidStagingKind.into()),
        }
    }

    pub fn batch_slots(kind: u8) -> Result<usize> {
        Ok(batch_size(kind) * Self::slots_per_record(kind)?)
    }
}

/// The verified verdict for the batch currently in a staging buffer. Created once with the
/// buffer, reset with it. PDA seeds: `["clearing", staging]`.
#[account]
#[derive(InitSpace)]
pub struct ClearingResult {
    pub staging: Pubkey,
    pub count: u16,
    pub kind: u8,
    /// True once the callback has landed with a successful output and `bitmap` is authoritative.
    pub verified: bool,
    pub bump: u8,
    /// Bit i set ⇒ commitment i's signature(s) verified.
    pub bitmap: [u8; 8],
    /// Bit i set ⇒ commitment i has been processed by `settle_channels` in this batch. Stops
    /// double-processing within the batch; monotonicity is the real replay guard.
    pub applied: [u8; 8],
    /// True if the computation itself failed (circuit fetch, abort, …). Nothing is verified;
    /// the relayer resets and re-stages. Recorded rather than erroring so the node's callback
    /// transaction lands on the first attempt instead of burning its retries.
    pub failed: bool,
    pub _reserved: [u8; 31],
}

impl ClearingResult {
    fn clear(&mut self, kind: u8, count: u16) {
        self.count = count;
        self.kind = kind;
        self.verified = false;
        self.failed = false;
        self.bitmap = [0u8; 8];
        self.applied = [0u8; 8];
    }
    /// Every verified commitment applied, or the computation failed.
    pub fn is_done(&self) -> bool {
        if self.failed {
            return true;
        }
        if !self.verified {
            return false;
        }
        (0..self.count as usize).all(|i| !bit(&self.bitmap, i) || bit(&self.applied, i))
    }
}

fn bit(map: &[u8; 8], i: usize) -> bool {
    map[i / 8] & (1 << (i % 8)) != 0
}
fn set_bit(map: &mut [u8; 8], i: usize) {
    map[i / 8] |= 1 << (i % 8);
}

// ============================================================================================
// One-time setup
// ============================================================================================

/// Explicit creation of Arcium's signer PDA. The reference programs use `init_if_needed` on
/// every queue; this program forbids `init_if_needed` everywhere, so it is created once here.
#[derive(Accounts)]
pub struct InitArciumSigner<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = 9,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    pub system_program: Program<'info, System>,
}

pub fn init_arcium_signer_handler(ctx: Context<InitArciumSigner>) -> Result<()> {
    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;
    Ok(())
}

#[init_computation_definition_accounts("clear_unilateral", payer)]
#[derive(Accounts)]
pub struct InitClearUnilateralCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program. Not initialised yet.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[init_computation_definition_accounts("clear_route", payer)]
#[derive(Accounts)]
pub struct InitClearRouteCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program. Not initialised yet.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

// ============================================================================================
// Staging
// ============================================================================================

#[derive(Accounts)]
pub struct OpenStaging<'info> {
    #[account(mut)]
    pub relayer: Signer<'info>,
    /// Pre-created by the relayer (`create_account` with this program as owner and
    /// `StagingBuffer::SPACE` bytes); `zero` requires an unused, program-owned account.
    #[account(zero)]
    pub staging: AccountLoader<'info, StagingBuffer>,
    /// Lives as long as the buffer; reset with it.
    #[account(
        init,
        payer = relayer,
        space = 8 + ClearingResult::INIT_SPACE,
        seeds = [CLEARING_SEED.as_bytes(), staging.key().as_ref()],
        bump,
    )]
    pub clearing_result: Box<Account<'info, ClearingResult>>,
    pub system_program: Program<'info, System>,
}

pub fn open_staging_handler(ctx: Context<OpenStaging>, kind: u8) -> Result<()> {
    StagingBuffer::slots_per_record(kind)?;
    let mut s = ctx.accounts.staging.load_init()?;
    s.batch_seq = 0;
    s.relayer = ctx.accounts.relayer.key();
    s.count = 0;
    s.kind = kind;
    s.sealed = 0;
    let r = &mut ctx.accounts.clearing_result;
    r.staging = ctx.accounts.staging.key();
    r.bump = ctx.bumps.clearing_result;
    r._reserved = [0u8; 31];
    r.clear(kind, 0);
    Ok(())
}

#[derive(Accounts)]
pub struct ResetStaging<'info> {
    pub relayer: Signer<'info>,
    #[account(mut, has_one = relayer)]
    pub staging: AccountLoader<'info, StagingBuffer>,
    #[account(
        mut,
        seeds = [CLEARING_SEED.as_bytes(), staging.key().as_ref()],
        bump = clearing_result.bump,
        has_one = staging,
    )]
    pub clearing_result: Box<Account<'info, ClearingResult>>,
}

/// Start the next batch in the same buffer. Allowed once the previous batch is done — every
/// verified commitment applied, or the computation failed — or if it was never queued. Slots are
/// not zeroed: the relayer overwrites what it uses and `count` bounds what is read.
pub fn reset_staging_handler(ctx: Context<ResetStaging>, kind: u8) -> Result<()> {
    StagingBuffer::slots_per_record(kind)?;
    let mut s = ctx.accounts.staging.load_mut()?;
    let r = &mut ctx.accounts.clearing_result;
    if s.sealed == 1 {
        require!(r.is_done(), RyvoError::StagingBusy);
    }
    s.batch_seq = s.batch_seq.checked_add(1).ok_or(RyvoError::MathOverflow)?;
    s.count = 0;
    s.kind = kind;
    s.sealed = 0;
    r.clear(kind, 0);
    Ok(())
}

#[derive(Accounts)]
pub struct StageSlots<'info> {
    pub relayer: Signer<'info>,
    #[account(mut, has_one = relayer)]
    pub staging: AccountLoader<'info, StagingBuffer>,
}

/// Write raw slot bytes at a slot offset. The relayer lays the columns out client-side; the
/// program only checks bounds and that the buffer is still open.
pub fn stage_slots_handler(ctx: Context<StageSlots>, slot_offset: u16, data: Vec<u8>) -> Result<()> {
    require!(data.len() % SLOT == 0, RyvoError::InvalidStagingData);
    let mut s = ctx.accounts.staging.load_mut()?;
    require!(s.sealed == 0, RyvoError::StagingSealed);
    let first = slot_offset as usize;
    let n = data.len() / SLOT;
    let batch = StagingBuffer::batch_slots(s.kind)?;
    require!(first + n <= batch, RyvoError::InvalidStagingData);
    for (i, chunk) in data.chunks(SLOT).enumerate() {
        s.slots[first + i].copy_from_slice(chunk);
    }
    Ok(())
}

// ============================================================================================
// Seal + queue
// ============================================================================================

#[queue_computation_accounts("clear_unilateral", relayer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct SealAndQueueUnilateral<'info> {
    #[account(mut)]
    pub relayer: Signer<'info>,
    #[account(seeds = [CONFIG_SEED.as_bytes()], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    #[account(mut, has_one = relayer)]
    pub staging: AccountLoader<'info, StagingBuffer>,
    #[account(
        mut,
        seeds = [CLEARING_SEED.as_bytes(), staging.key().as_ref()],
        bump = clearing_result.bump,
        has_one = staging,
    )]
    pub clearing_result: Box<Account<'info, ClearingResult>>,

    // --- Arcium standard set ---
    #[account(mut, seeds = [&SIGN_PDA_SEED], bump = sign_pda_account.bump, address = derive_sign_pda!())]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account))]
    /// CHECK: checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account))]
    /// CHECK: checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account))]
    /// CHECK: checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_CLEAR_UNILATERAL))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[queue_computation_accounts("clear_route", relayer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct SealAndQueueRoute<'info> {
    #[account(mut)]
    pub relayer: Signer<'info>,
    #[account(seeds = [CONFIG_SEED.as_bytes()], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    #[account(mut, has_one = relayer)]
    pub staging: AccountLoader<'info, StagingBuffer>,
    #[account(
        mut,
        seeds = [CLEARING_SEED.as_bytes(), staging.key().as_ref()],
        bump = clearing_result.bump,
        has_one = staging,
    )]
    pub clearing_result: Box<Account<'info, ClearingResult>>,

    #[account(mut, seeds = [&SIGN_PDA_SEED], bump = sign_pda_account.bump, address = derive_sign_pda!())]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut, address = derive_mempool_pda!(mxe_account))]
    /// CHECK: checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account))]
    /// CHECK: checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account))]
    /// CHECK: checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_CLEAR_ROUTE))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,
    #[account(mut, address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Box<Account<'info, Cluster>>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

fn staged_pubkey(s: &StagingBuffer, col: usize, i: usize) -> Pubkey {
    Pubkey::new_from_array(s.slots[col + i])
}

fn range(staging: Pubkey, col: usize, slots: usize) -> (Pubkey, u32, u32) {
    (staging, (SLOTS_OFFSET + col * SLOT) as u32, (slots * SLOT) as u32)
}

/// Shared body: seal the buffer, reset the result for this batch, and build the argument list in
/// the circuit's parameter order. The domain comes from `Config`, never from the relayer, so a
/// batch cannot be verified against a foreign deployment's domain; the keys come from the
/// `Channel` accounts the relayer named, never from staged bytes.
fn seal_common(
    staging_loader: &AccountLoader<StagingBuffer>,
    clearing_result: &mut ClearingResult,
    config: &Config,
    kind: u8,
    count: u16,
) -> Result<ArgumentList> {
    let mut s = staging_loader.load_mut()?;
    require!(s.kind == kind, RyvoError::InvalidStagingKind);
    require!(s.sealed == 0, RyvoError::StagingSealed);
    require!(count as usize >= 1 && count as usize <= batch_size(kind), RyvoError::InvalidStagingData);
    s.count = count;
    s.sealed = 1;
    clearing_result.clear(kind, count);

    // Built by hand rather than through ArgBuilder so the vectors are sized once: the on-chain
    // bump allocator never frees, so a growing Vec leaves every earlier buffer behind.
    let key = staging_loader.key();
    let n_accounts = match kind {
        KIND_UNILATERAL => N_UNI + 2,
        KIND_ROUTE => 2 * N_ROUTE + 2,
        _ => return Err(RyvoError::InvalidStagingKind.into()),
    };
    let mut args: Vec<ArgumentRef> = Vec::with_capacity(n_accounts + 1);
    let mut accounts: Vec<AccountArgument> = Vec::with_capacity(n_accounts);
    let push_account = |accounts: &mut Vec<AccountArgument>, args: &mut Vec<ArgumentRef>, pubkey: Pubkey, offset: u32, length: u32| {
        args.push(ArgumentRef::Account(accounts.len() as u8));
        accounts.push(AccountArgument { pubkey, offset, length });
    };
    args.push(ArgumentRef::PlaintextU128(0)); // index into values_128_bit
    let values_128_bit = vec![crate::commitment::domain_slot(&config.message_domain)];
    match kind {
        KIND_UNILATERAL => {
            let (k, o, l) = range(key, UNI_COL_IDS, N_UNI);
            push_account(&mut accounts, &mut args, k, o, l);
            for i in 0..N_UNI {
                push_account(&mut accounts, &mut args, staged_pubkey(&s, UNI_COL_CHANNEL, i), Channel::SIGNER_SLOTS_OFFSET as u32, Channel::SIGNER_SLOTS_LEN as u32);
            }
            let (k, o, l) = range(key, UNI_COL_SIG, SIG_SLOTS * N_UNI);
            push_account(&mut accounts, &mut args, k, o, l);
        }
        KIND_ROUTE => {
            let (k, o, l) = range(key, RT_COL_IDS, 2 * N_ROUTE); // ids then targets are adjacent
            push_account(&mut accounts, &mut args, k, o, l);
            for col in [RT_COL_CHANNEL_A, RT_COL_CHANNEL_G] {
                for i in 0..N_ROUTE {
                    push_account(&mut accounts, &mut args, staged_pubkey(&s, col, i), Channel::SIGNER_SLOTS_OFFSET as u32, Channel::SIGNER_SLOTS_LEN as u32);
                }
            }
            let (k, o, l) = range(key, RT_COL_SIG_A, 2 * SIG_SLOTS * N_ROUTE); // agent then gateway sigs are adjacent
            push_account(&mut accounts, &mut args, k, o, l);
        }
        _ => unreachable!(),
    }
    Ok(ArgumentList { args, byte_arrays: Vec::new(), plaintext_numbers: Vec::new(), values_128_bit, accounts })
}

pub fn seal_and_queue_unilateral_handler(
    ctx: Context<SealAndQueueUnilateral>,
    computation_offset: u64,
    count: u16,
) -> Result<()> {
    let clearing_key = ctx.accounts.clearing_result.key();
    let args = seal_common(
        &ctx.accounts.staging,
        &mut ctx.accounts.clearing_result,
        &ctx.accounts.config,
        KIND_UNILATERAL,
        count,
    )?;
    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![ClearUnilateralCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[CallbackAccount { pubkey: clearing_key, is_writable: true }],
        )?],
        1,
        0,
        0,
    )?;
    emit!(BatchQueued {
        staging: ctx.accounts.staging.key(),
        clearing_result: clearing_key,
        kind: KIND_UNILATERAL,
        count,
        computation_offset,
    });
    Ok(())
}

pub fn seal_and_queue_route_handler(
    ctx: Context<SealAndQueueRoute>,
    computation_offset: u64,
    count: u16,
) -> Result<()> {
    let clearing_key = ctx.accounts.clearing_result.key();
    let args = seal_common(
        &ctx.accounts.staging,
        &mut ctx.accounts.clearing_result,
        &ctx.accounts.config,
        KIND_ROUTE,
        count,
    )?;
    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![ClearRouteCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[CallbackAccount { pubkey: clearing_key, is_writable: true }],
        )?],
        1,
        0,
        0,
    )?;
    emit!(BatchQueued {
        staging: ctx.accounts.staging.key(),
        clearing_result: clearing_key,
        kind: KIND_ROUTE,
        count,
        computation_offset,
    });
    Ok(())
}

// ============================================================================================
// Callbacks
// ============================================================================================

#[callback_accounts("clear_unilateral")]
#[derive(Accounts)]
pub struct ClearUnilateralCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_CLEAR_UNILATERAL))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: validated by the Arcium program; verify_output reads slot data from it.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(address = ::arcium_anchor::solana_instructions_sysvar::ID)]
    /// CHECK: checked by the account constraint
    pub instructions_sysvar: UncheckedAccount<'info>,
    // --- ours, declared at queue time ---
    #[account(
        mut,
        seeds = [CLEARING_SEED.as_bytes(), clearing_result.staging.as_ref()],
        bump = clearing_result.bump,
    )]
    pub clearing_result: Box<Account<'info, ClearingResult>>,
}

#[callback_accounts("clear_route")]
#[derive(Accounts)]
pub struct ClearRouteCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_CLEAR_ROUTE))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: validated by the Arcium program; verify_output reads slot data from it.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(address = ::arcium_anchor::solana_instructions_sysvar::ID)]
    /// CHECK: checked by the account constraint
    pub instructions_sysvar: UncheckedAccount<'info>,
    #[account(
        mut,
        seeds = [CLEARING_SEED.as_bytes(), clearing_result.staging.as_ref()],
        bump = clearing_result.bump,
    )]
    pub clearing_result: Box<Account<'info, ClearingResult>>,
}

/// The computation did not produce an output. Recorded, not errored: see `ClearingResult::failed`.
pub fn record_failure(result: &mut ClearingResult) -> Result<()> {
    require!(!result.verified, RyvoError::BatchAlreadyCleared);
    result.failed = true;
    emit!(BatchClearingFailed { staging: result.staging, kind: result.kind });
    Ok(())
}

/// Record the verified bits. Idempotent guard: a callback may only land once per batch.
pub fn record_bitmap(result: &mut ClearingResult, bits: &[bool], kind: u8) -> Result<()> {
    require!(!result.verified, RyvoError::BatchAlreadyCleared);
    require!(result.kind == kind, RyvoError::InvalidStagingKind);
    result.failed = false;
    let mut bitmap = [0u8; 8];
    let mut set = 0u16;
    for (i, b) in bits.iter().enumerate() {
        if *b && i < result.count as usize {
            set_bit(&mut bitmap, i);
            set += 1;
        }
    }
    result.bitmap = bitmap;
    result.verified = true;
    emit!(BatchCleared {
        staging: result.staging,
        kind,
        count: result.count,
        verified_count: set,
    });
    Ok(())
}

// ============================================================================================
// Settlement
// ============================================================================================

#[derive(Accounts)]
pub struct SettleChannels<'info> {
    pub staging: AccountLoader<'info, StagingBuffer>,
    #[account(
        mut,
        seeds = [CLEARING_SEED.as_bytes(), staging.key().as_ref()],
        bump = clearing_result.bump,
        has_one = staging,
    )]
    pub clearing_result: Box<Account<'info, ClearingResult>>,
    // remaining_accounts: per index, in order —
    //   unilateral: [channel (mut), payee_balance (mut)]
    //   route:      [channel_ag (mut), channel_gp (mut), provider_balance (mut)]
}

/// Move funds for the listed commitments. Anyone may call it; a wrong or missing account simply
/// fails the transaction and can be retried, and a commitment that moves nothing (`delta <= 0`
/// or nothing locked) is skipped rather than failing the batch.
pub fn settle_channels_handler<'info>(
    ctx: Context<'info, SettleChannels<'info>>,
    indices: Vec<u8>,
) -> Result<()> {
    let result = &mut ctx.accounts.clearing_result;
    require!(result.verified, RyvoError::BatchNotCleared);
    let staging = ctx.accounts.staging.load()?;
    require!(staging.sealed == 1 && staging.kind == result.kind, RyvoError::InvalidStagingKind);
    let kind = staging.kind;
    let per = match kind {
        KIND_UNILATERAL => 2,
        KIND_ROUTE => 3,
        _ => return Err(RyvoError::InvalidStagingKind.into()),
    };
    require!(
        ctx.remaining_accounts.len() == indices.len() * per,
        RyvoError::InvalidSettlementAccounts
    );

    for (k, &idx) in indices.iter().enumerate() {
        let i = idx as usize;
        require!(i < result.count as usize, RyvoError::InvalidSettlementIndex);
        require!(bit(&result.bitmap, i), RyvoError::RecordNotVerified);
        require!(!bit(&result.applied, i), RyvoError::RecordAlreadyApplied);
        let accs = &ctx.remaining_accounts[k * per..(k + 1) * per];
        match kind {
            KIND_UNILATERAL => settle_unilateral(&staging, i, accs)?,
            KIND_ROUTE => settle_route(&staging, i, accs)?,
            _ => unreachable!(),
        }
        set_bit(&mut result.applied, i);
    }
    Ok(())
}

fn load_mut<'info, T: AccountSerialize + AccountDeserialize + Owner + Clone>(
    info: &'info AccountInfo<'info>,
) -> Result<Account<'info, T>> {
    require!(info.is_writable, RyvoError::InvalidSettlementAccounts);
    Account::<T>::try_from(info)
}

fn staged_u128(staging: &StagingBuffer, col: usize, i: usize) -> u128 {
    let mut b = [0u8; 16];
    b.copy_from_slice(&staging.slots[col + i][..16]);
    u128::from_le_bytes(b)
}

/// `moved = min(target - settled, locked)`; returns 0 when nothing can move. Never fails on an
/// exhausted or already-satisfied commitment — that is a skip, not an error.
fn payable(target: u64, settled: u64, locked: u64) -> u64 {
    target.saturating_sub(settled).min(locked)
}

fn settle_unilateral<'info>(
    staging: &StagingBuffer,
    i: usize,
    accs: &'info [AccountInfo<'info>],
) -> Result<()> {
    let (channel_id, target) = unpack_pair(staged_u128(staging, UNI_COL_IDS, i));
    let staged_channel = staged_pubkey(staging, UNI_COL_CHANNEL, i);

    // The circuit verified the signature under the key stored in the channel account at
    // `staged_channel`; the account we are handed must be that one, and it must carry the id
    // that was inside the signed message.
    require!(accs[0].key() == staged_channel, RyvoError::SettlementChannelMismatch);
    let mut channel = load_mut::<Channel>(&accs[0])?;
    let mut payee_balance = load_mut::<Balance>(&accs[1])?;
    require!(channel.channel_id == channel_id, RyvoError::SettlementChannelMismatch);
    require!(
        payee_balance.participant == channel.payee && payee_balance.mint == channel.mint,
        RyvoError::SettlementBalanceMismatch
    );

    let moved = payable(target, channel.settled_cumulative, channel.locked_balance);
    if moved > 0 {
        channel.locked_balance -= moved;
        channel.settled_cumulative += moved;
        payee_balance.available = payee_balance
            .available
            .checked_add(moved)
            .ok_or(RyvoError::MathOverflow)?;
        channel.exit(&crate::ID)?;
        payee_balance.exit(&crate::ID)?;
    }
    emit!(ChannelSettled {
        channel: channel.key(),
        channel_id,
        target_cumulative: target,
        moved,
        settled_cumulative: channel.settled_cumulative,
        locked_balance: channel.locked_balance,
    });
    Ok(())
}

fn settle_route<'info>(
    staging: &StagingBuffer,
    i: usize,
    accs: &'info [AccountInfo<'info>],
) -> Result<()> {
    let (ag_id, gp_id) = unpack_pair(staged_u128(staging, RT_COL_IDS, i));
    let (target_ag, target_gp) = unpack_pair(staged_u128(staging, RT_COL_TARGETS, i));
    let staged_ag = staged_pubkey(staging, RT_COL_CHANNEL_A, i);
    let staged_gp = staged_pubkey(staging, RT_COL_CHANNEL_G, i);

    require!(accs[0].key() == staged_ag, RyvoError::SettlementChannelMismatch);
    require!(accs[1].key() == staged_gp, RyvoError::SettlementChannelMismatch);
    let mut channel_ag = load_mut::<Channel>(&accs[0])?;
    let mut channel_gp = load_mut::<Channel>(&accs[1])?;
    let mut provider_balance = load_mut::<Balance>(&accs[2])?;

    require!(channel_ag.channel_id == ag_id, RyvoError::SettlementChannelMismatch);
    require!(channel_gp.channel_id == gp_id, RyvoError::SettlementChannelMismatch);
    // The two legs must actually chain: the gateway is the payee of one and the payer of the
    // other, in the same asset.
    require!(
        channel_ag.payee == channel_gp.payer && channel_ag.mint == channel_gp.mint,
        RyvoError::SettlementRouteMismatch
    );
    require!(
        provider_balance.participant == channel_gp.payee && provider_balance.mint == channel_gp.mint,
        RyvoError::SettlementBalanceMismatch
    );

    // Leg 1: agent -> gateway, credited straight into the gateway->provider channel's lock so
    // leg 2 can spend it in the same instruction. No gateway prefunding, no gateway signature.
    let moved_ag = payable(target_ag, channel_ag.settled_cumulative, channel_ag.locked_balance);
    channel_ag.locked_balance -= moved_ag;
    channel_ag.settled_cumulative += moved_ag;
    channel_gp.locked_balance = channel_gp
        .locked_balance
        .checked_add(moved_ag)
        .ok_or(RyvoError::MathOverflow)?;

    // Leg 2: gateway -> provider. Whatever `moved_ag - moved_gp` remains stays locked in the
    // gateway's channel — that is the gateway's fee, with no fee logic anywhere.
    let moved_gp = payable(target_gp, channel_gp.settled_cumulative, channel_gp.locked_balance);
    channel_gp.locked_balance -= moved_gp;
    channel_gp.settled_cumulative += moved_gp;
    provider_balance.available = provider_balance
        .available
        .checked_add(moved_gp)
        .ok_or(RyvoError::MathOverflow)?;

    if moved_ag > 0 || moved_gp > 0 {
        channel_ag.exit(&crate::ID)?;
        channel_gp.exit(&crate::ID)?;
        provider_balance.exit(&crate::ID)?;
    }
    emit!(RouteSettled {
        channel_ag: channel_ag.key(),
        channel_gp: channel_gp.key(),
        channel_ag_id: ag_id,
        channel_gp_id: gp_id,
        moved_ag,
        moved_gp,
    });
    Ok(())
}

// ============================================================================================
// Close
// ============================================================================================

#[derive(Accounts)]
pub struct CloseStaging<'info> {
    #[account(mut)]
    pub relayer: Signer<'info>,
    #[account(mut, close = relayer, has_one = relayer)]
    pub staging: AccountLoader<'info, StagingBuffer>,
    #[account(
        mut,
        close = relayer,
        seeds = [CLEARING_SEED.as_bytes(), staging.key().as_ref()],
        bump = clearing_result.bump,
        has_one = staging,
    )]
    pub clearing_result: Box<Account<'info, ClearingResult>>,
}

/// Reclaim rent for a buffer the relayer no longer needs. Same precondition as `reset_staging`.
pub fn close_staging_handler(ctx: Context<CloseStaging>) -> Result<()> {
    let s = ctx.accounts.staging.load()?;
    if s.sealed == 1 {
        require!(ctx.accounts.clearing_result.is_done(), RyvoError::StagingBusy);
    }
    Ok(())
}
