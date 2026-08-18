//! Arcium clearing: staging, queueing, the callback that records the verified bitmap, and
//! `settle_channels`, which does every piece of money math on-chain.
//!
//! # Trust split
//!
//! The MPC circuit answers exactly one question per staged record — *did the named key(s) sign
//! this record's fields?* — and returns one bit. It never sees a balance. Everything about money
//! (`min(delta, locked_balance)`, monotonicity, who gets credited) is re-derived here from the
//! same sealed bytes the circuit read, so a compromised MPC could at worst approve an invalid
//! signature, and even then the payment is capped by what the payer had already locked in that
//! specific channel.
//!
//! # Two phases
//!
//! 1. `clear_*_callback` — invoked by Arcium. Verifies the cluster's BLS signature over the
//!    output and writes the bitmap into `ClearingResult`. Touches no channels, so it is one small
//!    transaction whether the batch has 1 record or `N`.
//! 2. `settle_channels(indices)` — permissionless and repeatable. Reads the bitmap and the staged
//!    slots, is handed the channel and balance accounts for the records it is asked to settle,
//!    and moves funds. Batch size becomes a client-side loop over `indices` rather than a
//!    protocol constraint.
//!
//! # Slot layout
//!
//! A `StagingBuffer` is `MAX_SLOTS` × 32-byte slots. Every slot is one circuit parameter, in
//! circuit declaration order, after the leading `domain` argument the program supplies from
//! `Config`. Plaintext u128 = 16 LE bytes in the low half; packed bytes = 26 per slot, LE.
//!
//! ```text
//! unilateral (N records, 6N slots):   ids[N] | vk[2N] | sig[3N]
//! route      (N records, 12N slots):  ids[N] | targets[N] | vk_agent[2N] | vk_gateway[2N] | sig_agent[3N] | sig_gateway[3N]
//! ```
//!
//! Records are column-major so the id column sits at the front of the buffer, which is what
//! `settle_channels` reads most.

use crate::commitment::{
    unpack_pair, unpack_pubkey, KIND_ROUTE, KIND_UNILATERAL, PUBKEY_SLOTS, SIG_SLOTS, SLOT,
};
use crate::constants::{CLEARING_SEED, CONFIG_SEED};
use crate::error::RyvoError;
use crate::events::{BatchCleared, BatchClearingFailed, BatchQueued, ChannelSettled, RouteSettled};
use crate::state::{Balance, Channel, Config};
use crate::{ArciumSignerAccount, ID, ID_CONST};
use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::CallbackAccount;

/// Records per batch. Must equal `N` in `encrypted-ixs`. The circuit shape is fixed at compile
/// time, so a shorter batch is padded by the relayer (repeat a valid record) and `count` tells
/// `settle_channels` where the real records end.
pub const N: usize = 32;

pub const UNILATERAL_SLOTS_PER_RECORD: usize = 1 + PUBKEY_SLOTS + SIG_SLOTS; // 6
pub const ROUTE_SLOTS_PER_RECORD: usize = 2 + 2 * PUBKEY_SLOTS + 2 * SIG_SLOTS; // 12
pub const UNILATERAL_SLOTS: usize = N * UNILATERAL_SLOTS_PER_RECORD; // 192
pub const ROUTE_SLOTS: usize = N * ROUTE_SLOTS_PER_RECORD; // 384
pub const MAX_SLOTS: usize = ROUTE_SLOTS;

/// Byte offset of `slots` inside the account: 8-byte discriminator + header.
pub const SLOTS_OFFSET: usize = 8 + StagingBuffer::HEADER_LEN;

// Column offsets (in slots) within a batch.
pub const UNI_COL_IDS: usize = 0;
pub const UNI_COL_VK: usize = N;
pub const UNI_COL_SIG: usize = N + PUBKEY_SLOTS * N;
pub const RT_COL_IDS: usize = 0;
pub const RT_COL_TARGETS: usize = N;
pub const RT_COL_VK_A: usize = 2 * N;
pub const RT_COL_VK_G: usize = 2 * N + PUBKEY_SLOTS * N;
pub const RT_COL_SIG_A: usize = 2 * N + 2 * PUBKEY_SLOTS * N;
pub const RT_COL_SIG_G: usize = 2 * N + 2 * PUBKEY_SLOTS * N + SIG_SLOTS * N;

const COMP_DEF_OFFSET_CLEAR_UNILATERAL: u32 = comp_def_offset("clear_unilateral");
const COMP_DEF_OFFSET_CLEAR_ROUTE: u32 = comp_def_offset("clear_route");

// ============================================================================================
// State
// ============================================================================================

/// One batch of staged records, owned by the relayer that pays its rent. Zero-copy: the buffer
/// is 12 KB and `settle_channels` reads only the slots it needs.
///
/// Not a PDA: at 12 KB it exceeds the 10 KB cap on accounts created inside a CPI, so the relayer
/// creates it with `SystemProgram::create_account` in the same transaction and `open_staging`
/// takes it via `#[account(zero)]`. Everything that must be tied to it (`ClearingResult`) is a
/// PDA seeded by its address.
#[account(zero_copy)]
#[repr(C)]
pub struct StagingBuffer {
    /// Relayer-chosen label; not part of any derivation.
    pub batch_seq: u64,
    pub relayer: Pubkey,
    /// Real records staged; the rest of the batch is padding the circuit still processes.
    pub count: u16,
    /// `KIND_UNILATERAL` or `KIND_ROUTE`; fixed at `open_staging`.
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
        Ok(N * Self::slots_per_record(kind)?)
    }
}

/// The verified verdict for one staging buffer. Created by `seal_and_queue_*`, written once by
/// the callback, consumed by `settle_channels`.
/// PDA seeds: `["clearing", staging]`.
#[account]
#[derive(InitSpace)]
pub struct ClearingResult {
    pub staging: Pubkey,
    pub count: u16,
    pub kind: u8,
    /// True once the callback has landed with a successful output and `bitmap` is authoritative.
    pub verified: bool,
    pub bump: u8,
    /// Bit i set ⇒ record i's signature(s) verified. Sized for up to 64 records.
    pub bitmap: [u8; 8],
    /// Bit i set ⇒ record i has been processed by `settle_channels` in this batch. Stops
    /// double-processing within the batch; monotonicity is the real replay guard.
    pub applied: [u8; 8],
    /// True if the computation itself failed (circuit fetch, abort, …). Nothing is verified;
    /// the relayer closes this batch and re-stages. Recorded rather than erroring so the node's
    /// callback transaction lands on the first attempt instead of burning its retries.
    pub failed: bool,
    pub _reserved: [u8; 31],
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
    pub relayer: Signer<'info>,
    /// Pre-created by the relayer (`create_account` with this program as owner and
    /// `StagingBuffer::SPACE` bytes); `zero` requires an unused, program-owned account.
    #[account(zero)]
    pub staging: AccountLoader<'info, StagingBuffer>,
}

pub fn open_staging_handler(ctx: Context<OpenStaging>, batch_seq: u64, kind: u8) -> Result<()> {
    StagingBuffer::slots_per_record(kind)?;
    let mut s = ctx.accounts.staging.load_init()?;
    s.batch_seq = batch_seq;
    s.relayer = ctx.accounts.relayer.key();
    s.count = 0;
    s.kind = kind;
    s.sealed = 0;
    Ok(())
}

#[derive(Accounts)]
pub struct StageSlots<'info> {
    pub relayer: Signer<'info>,
    #[account(mut, has_one = relayer)]
    pub staging: AccountLoader<'info, StagingBuffer>,
}

/// Write raw slot bytes at a slot offset. Sent in v1 transactions (4,096 bytes) — ~120 slots
/// per transaction. The relayer lays the columns out client-side; the program only checks bounds
/// and that the buffer is still open.
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
        init,
        payer = relayer,
        space = 8 + ClearingResult::INIT_SPACE,
        seeds = [CLEARING_SEED.as_bytes(), staging.key().as_ref()],
        bump,
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
        init,
        payer = relayer,
        space = 8 + ClearingResult::INIT_SPACE,
        seeds = [CLEARING_SEED.as_bytes(), staging.key().as_ref()],
        bump,
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

/// Shared body: seal the buffer, initialise the result, build the argument list. The domain is
/// supplied by the program from `Config`, never by the relayer, so a batch cannot be verified
/// against a foreign deployment's domain.
fn seal_common(
    staging_loader: &AccountLoader<StagingBuffer>,
    clearing_result: &mut ClearingResult,
    clearing_bump: u8,
    config: &Config,
    kind: u8,
    count: u16,
) -> Result<ArgumentList> {
    let mut s = staging_loader.load_mut()?;
    require!(s.kind == kind, RyvoError::InvalidStagingKind);
    require!(s.sealed == 0, RyvoError::StagingSealed);
    require!(count as usize >= 1 && count as usize <= N, RyvoError::InvalidStagingData);
    s.count = count;
    s.sealed = 1;

    clearing_result.staging = staging_loader.key();
    clearing_result.count = count;
    clearing_result.kind = kind;
    clearing_result.verified = false;
    clearing_result.bump = clearing_bump;
    clearing_result.bitmap = [0u8; 8];
    clearing_result.applied = [0u8; 8];
    clearing_result.failed = false;
    clearing_result._reserved = [0u8; 31];

    let batch_len = (StagingBuffer::batch_slots(kind)? * SLOT) as u32;
    Ok(ArgBuilder::new()
        .plaintext_u128(crate::commitment::domain_slot(&config.message_domain))
        .account(staging_loader.key(), SLOTS_OFFSET as u32, batch_len)
        .build())
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
        ctx.bumps.clearing_result,
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
        ctx.bumps.clearing_result,
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

/// Record the verified bits. Idempotent guard: a callback may only land once per result.
pub fn record_bitmap(result: &mut ClearingResult, bits: &[bool; N], kind: u8) -> Result<()> {
    require!(!result.verified, RyvoError::BatchAlreadyCleared);
    result.failed = false;
    require!(result.kind == kind, RyvoError::InvalidStagingKind);
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

/// Move funds for the listed records. Anyone may call it; a wrong or missing account simply
/// fails the transaction and can be retried, and a record that moves nothing (`delta <= 0` or
/// nothing locked) is skipped rather than failing the batch.
pub fn settle_channels_handler<'info>(
    ctx: Context<'info, SettleChannels<'info>>,
    indices: Vec<u8>,
) -> Result<()> {
    let result = &mut ctx.accounts.clearing_result;
    require!(result.verified, RyvoError::BatchNotCleared);
    let staging = ctx.accounts.staging.load()?;
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

fn staged_pubkey(staging: &StagingBuffer, col: usize, i: usize) -> [u8; 32] {
    unpack_pubkey(&[
        staging.slots[col + PUBKEY_SLOTS * i],
        staging.slots[col + PUBKEY_SLOTS * i + 1],
    ])
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
    let signer = staged_pubkey(staging, UNI_COL_VK, i);

    let mut channel = load_mut::<Channel>(&accs[0])?;
    let mut payee_balance = load_mut::<Balance>(&accs[1])?;

    // Bind the staged record to the accounts we were handed. The signature was verified over
    // (channel_id, target) under `signer`; the channel must be the one with that id and that
    // registered signer, and the balance must be its payee's balance for its mint.
    require!(channel.channel_id == channel_id, RyvoError::SettlementChannelMismatch);
    require!(
        channel.authorized_signer.to_bytes() == signer,
        RyvoError::SettlementSignerMismatch
    );
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
    let signer_agent = staged_pubkey(staging, RT_COL_VK_A, i);
    let signer_gateway = staged_pubkey(staging, RT_COL_VK_G, i);

    let mut channel_ag = load_mut::<Channel>(&accs[0])?;
    let mut channel_gp = load_mut::<Channel>(&accs[1])?;
    let mut provider_balance = load_mut::<Balance>(&accs[2])?;

    require!(channel_ag.channel_id == ag_id, RyvoError::SettlementChannelMismatch);
    require!(channel_gp.channel_id == gp_id, RyvoError::SettlementChannelMismatch);
    require!(
        channel_ag.authorized_signer.to_bytes() == signer_agent,
        RyvoError::SettlementSignerMismatch
    );
    require!(
        channel_gp.authorized_signer.to_bytes() == signer_gateway,
        RyvoError::SettlementSignerMismatch
    );
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
    /// Present iff the batch was queued. Closed alongside.
    #[account(
        mut,
        close = relayer,
        seeds = [CLEARING_SEED.as_bytes(), staging.key().as_ref()],
        bump = clearing_result.bump,
        has_one = staging,
    )]
    pub clearing_result: Option<Box<Account<'info, ClearingResult>>>,
}

/// Reclaim rent. Allowed once every verified record has been applied (or the batch was never
/// queued). Unverified records are simply invalid signatures and owe nothing.
pub fn close_staging_handler(ctx: Context<CloseStaging>) -> Result<()> {
    let s = ctx.accounts.staging.load()?;
    if s.sealed == 1 {
        let r = ctx
            .accounts
            .clearing_result
            .as_ref()
            .ok_or(RyvoError::InvalidSettlementAccounts)?;
        if r.failed {
            return Ok(());
        }
        require!(r.verified, RyvoError::BatchNotCleared);
        for i in 0..r.count as usize {
            require!(!bit(&r.bitmap, i) || bit(&r.applied, i), RyvoError::BatchNotFullyApplied);
        }
    }
    Ok(())
}
