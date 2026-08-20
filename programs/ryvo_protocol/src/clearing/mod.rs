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
//! already locked in that specific channel slot. A route debits one agent-to-gateway channel and
//! directly credits every provider named in the same two-signature commitment. Any signed
//! remainder is the gateway fee. There is no gateway pool or gateway-to-provider channel.
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
//! # Staging: dense records in, slots out
//!
//! The relayer sends each commitment as a dense record — `stage_records(start, bytes)` with the
//! source bucket accounts as remaining accounts — and the *program* lays it out in
//! the buffer: ids/targets/allocations as plaintext u128 slots, signatures packed 26 bytes per
//! slot, and registered signing keys copied from program accounts. The relayer never writes a
//! key slot directly. A route batch uses one gateway and mint, so the gateway key is copied once
//! from its `Participant`; each payer key and bucket address come from its channel bucket.
//!
//! Route records are compact and variable-width: unused provider allocation slots are omitted
//! from staging transactions, then zero-filled by the program for the fixed-size circuit input.
//! A short batch stages only `count` commitments; `seal_and_queue_*` pads the remaining circuit
//! inputs by repeating commitment 0.
//!
//! ```text
//! unilateral record (80 B):  channel_id u64 | target u64 | sig[64]                     + accounts: source bucket
//! route record:              source_id u64 | base u64 | target u64 | count u8
//!                            | (provider_id u64 | amount u64)[count]
//!                            | sig_agent[64] | sig_gateway[64]
//!                            + accounts: gateway participant once, then one source bucket per commitment
//! ```
//!
//! The circuit reads everything from the buffer through a few account ranges (one per column).
//! Every range points into the same staging account, however many source channels the batch
//! represents; source addresses and registered keys were copied into that account at staging.
//!
//! # Slot layout
//!
//! A `StagingBuffer` is `MAX_SLOTS` × 32-byte slots. Plaintext u128 = 16 LE bytes in the low
//! half; packed key = 2 slots, packed signature = 3 slots (26 bytes per slot, LE); a channel
//! address = one slot. All columns are program-written.
//!
//! ```text
//! unilateral (N commitments, 7N slots):  ids[N] | sig[3N] | key[2N] | source_bucket[N]
//! route (N commitments, 27N + 2 slots): source_base[N] | target_count[N]
//!                                        | allocations[16N] | sig_agent[3N]
//!                                        | sig_gateway[3N] | key_agent[2N]
//!                                        | source_bucket[N] | gateway_key[2]
//! ```
//!
//! The circuit's parameter order is `domain, message fields, keys, signatures`; the argument list is
//! assembled from buffer column ranges to match it exactly.
//!
//! # Buffer reuse
//!
//! A relayer creates one buffer (`open_staging`) and reuses it: `reset_staging` clears a fully
//! settled (or failed) batch in place, so a steady-state batch costs no account creation, no
//! close, and no rent churn.

use crate::commitment::{
    pack_pair, pack_pubkey, pack_signature, unpack_pair, RouteAllocation, RouteCommitment,
    KIND_ROUTE, KIND_UNILATERAL, MAX_ROUTE_ALLOCATIONS, PUBKEY_SLOTS as KEY_SLOTS, SIG_SLOTS, SLOT,
};
use crate::constants::{
    CHANNEL_KIND_DIRECT, CHANNEL_KIND_ROUTED, CLEARING_SEED, CONFIG_SEED, MAX_CLEARING_COMMITMENTS,
};
use crate::error::RyvoError;
use crate::events::{
    BatchAbandoned, BatchCleared, BatchClearingFailed, BatchQueued, ChannelSettled,
    RouteProviderPaid, RouteSettled,
};
use crate::state::{Balance, ChannelBucket, Config, Participant, CHANNEL_BUCKET_VERSION};
use crate::{ArciumSignerAccount, ID, ID_CONST};
use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::CallbackAccount;

/// Commitments per batch. Must equal `N_UNI` / `N_ROUTE` in `encrypted-ixs`. The circuit shape
/// is fixed at compile time, so a shorter batch is padded at seal time (record 0 repeated) and
/// `count` tells `settle_channels` where the real ones end. The current circuits use 64 direct or
/// 32 routed commitments; `ClearingResult` reserves 256 bits for the off-chain-input path.
pub const N_UNI: usize = 64;
pub const N_ROUTE: usize = 32;

/// Dense record sizes on the wire (`stage_records`).
pub const UNILATERAL_RECORD_LEN: usize = 8 + 8 + 64; // channel_id, target, sig
/// Compact route record: source/base/target, count, active allocations, then two signatures.
pub const ROUTE_RECORD_BASE_LEN: usize = 3 * 8 + 1 + 2 * 64;
pub const ROUTE_ALLOCATION_LEN: usize = 16;
/// Slots per commitment once laid out.
pub const UNILATERAL_SLOTS_PER_RECORD: usize = 1 + SIG_SLOTS + KEY_SLOTS + 1; // 7
pub const ROUTE_SLOTS_PER_RECORD: usize = 2 + MAX_ROUTE_ALLOCATIONS + 2 * SIG_SLOTS + KEY_SLOTS + 1; // 27
pub const UNILATERAL_SLOTS: usize = N_UNI * UNILATERAL_SLOTS_PER_RECORD; // 448
pub const ROUTE_SLOTS: usize = N_ROUTE * ROUTE_SLOTS_PER_RECORD + KEY_SLOTS; // 866
pub const MAX_SLOTS: usize = if UNILATERAL_SLOTS > ROUTE_SLOTS {
    UNILATERAL_SLOTS
} else {
    ROUTE_SLOTS
};

/// Byte offset of `slots` inside the account: 8-byte discriminator + header.
pub const SLOTS_OFFSET: usize = 8 + StagingBuffer::HEADER_LEN;

// Column offsets (in slots) within a batch.
pub const UNI_COL_IDS: usize = 0;
pub const UNI_COL_SIG: usize = N_UNI;
pub const UNI_COL_KEY: usize = 4 * N_UNI;
pub const UNI_COL_BUCKET: usize = 6 * N_UNI;
pub const RT_COL_SOURCE_BASE: usize = 0;
pub const RT_COL_TARGET_COUNT: usize = N_ROUTE;
pub const RT_COL_ALLOCATIONS: usize = 2 * N_ROUTE;
pub const RT_COL_SIG_A: usize = (2 + MAX_ROUTE_ALLOCATIONS) * N_ROUTE;
pub const RT_COL_SIG_G: usize = RT_COL_SIG_A + SIG_SLOTS * N_ROUTE;
pub const RT_COL_KEY_A: usize = RT_COL_SIG_G + SIG_SLOTS * N_ROUTE;
pub const RT_COL_SOURCE_BUCKET: usize = RT_COL_KEY_A + KEY_SLOTS * N_ROUTE;
pub const RT_GATEWAY_KEY: usize = RT_COL_SOURCE_BUCKET + N_ROUTE;

pub const fn batch_size(kind: u8) -> usize {
    if kind == KIND_ROUTE {
        N_ROUTE
    } else {
        N_UNI
    }
}

const COMP_DEF_OFFSET_CLEAR_UNILATERAL: u32 = comp_def_offset("clear_unilateral64");
const COMP_DEF_OFFSET_CLEAR_ROUTE: u32 = comp_def_offset("clear_route32");

// ============================================================================================
// State
// ============================================================================================

/// One relayer's batch buffer, reused across batches. Zero-copy, and
/// `settle_channels` reads only the slots it needs.
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
    /// Bit i set ⇒ index i was written by `stage_records` in THIS batch. Seal requires every
    /// index below `count` to be set, so a batch can never carry a previous batch's bytes.
    pub staged_mask: u64,
    /// Route batches contain one gateway and mint so the gateway verification key is shared.
    /// Both are zero for unilateral batches.
    pub route_gateway: Pubkey,
    pub route_mint: Pubkey,
    pub slots: [[u8; SLOT]; MAX_SLOTS],
}

impl StagingBuffer {
    pub const HEADER_LEN: usize = 8 + 32 + 2 + 1 + 1 + 4 + 8 + 32 + 32; // 120
    pub const SPACE: usize = 8 + Self::HEADER_LEN + SLOT * MAX_SLOTS;

    pub fn slots_per_record(kind: u8) -> Result<usize> {
        match kind {
            KIND_UNILATERAL => Ok(UNILATERAL_SLOTS_PER_RECORD),
            KIND_ROUTE => Ok(ROUTE_SLOTS_PER_RECORD),
            _ => Err(RyvoError::InvalidStagingKind.into()),
        }
    }

    /// Every column of record `i` as (column offset, slots) pairs, for copying a whole record.
    fn record_columns(kind: u8) -> &'static [(usize, usize)] {
        match kind {
            KIND_UNILATERAL => &[
                (UNI_COL_IDS, 1),
                (UNI_COL_SIG, SIG_SLOTS),
                (UNI_COL_KEY, KEY_SLOTS),
                (UNI_COL_BUCKET, 1),
            ],
            _ => &[
                (RT_COL_SOURCE_BASE, 1),
                (RT_COL_TARGET_COUNT, 1),
                (RT_COL_ALLOCATIONS, MAX_ROUTE_ALLOCATIONS),
                (RT_COL_SIG_A, SIG_SLOTS),
                (RT_COL_SIG_G, SIG_SLOTS),
                (RT_COL_KEY_A, KEY_SLOTS),
                (RT_COL_SOURCE_BUCKET, 1),
            ],
        }
    }

    /// Copy record `from` over record `to` in every column (padding a short batch).
    fn copy_record(&mut self, kind: u8, from: usize, to: usize) {
        for &(col, width) in Self::record_columns(kind) {
            for k in 0..width {
                self.slots[col + width * to + k] = self.slots[col + width * from + k];
            }
        }
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
    pub bitmap: [u8; (MAX_CLEARING_COMMITMENTS / 8) as usize],
    /// Bit i set ⇒ commitment i has been processed by `settle_channels` in this batch. Stops
    /// double-processing within the batch; monotonicity is the real replay guard.
    pub applied: [u8; (MAX_CLEARING_COMMITMENTS / 8) as usize],
    /// True if the computation itself failed (circuit fetch, abort, …). Nothing is verified;
    /// the relayer resets and re-stages. Recorded rather than erroring so the node's callback
    /// transaction lands on the first attempt instead of burning its retries.
    pub failed: bool,
    /// The Arcium computation this batch was queued with. The callback must come from exactly
    /// this computation: the buffer and this account are reused batch after batch, so without
    /// the binding a late or duplicate callback for an earlier computation would be recorded as
    /// the verdict of whatever batch is current.
    pub computation_offset: u64,
    /// `StagingBuffer.batch_seq` at seal time, for events and post-mortems.
    pub batch_seq: u64,
    /// `(slot, slot_counter)` of the computation account right after it was queued — the same
    /// two fields the cluster's BLS signature covers. The computation PDA is only
    /// `(cluster, offset)`, so an offset can be reused once the old account is closed; these pin
    /// the verdict to the exact computation instance this batch was queued as.
    pub comp_slot: u64,
    pub comp_slot_counter: u16,
    pub _reserved: [u8; 5],
}

impl ClearingResult {
    fn clear(&mut self, kind: u8, count: u16) {
        self.count = count;
        self.kind = kind;
        self.verified = false;
        self.failed = false;
        self.bitmap = [0u8; (MAX_CLEARING_COMMITMENTS / 8) as usize];
        self.applied = [0u8; (MAX_CLEARING_COMMITMENTS / 8) as usize];
        // No computation is bound until the next seal, so a late callback for an abandoned one
        // is refused rather than recorded against an unsealed buffer.
        self.computation_offset = 0;
        self.comp_slot = 0;
        self.comp_slot_counter = 0;
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

fn bit(map: &[u8], i: usize) -> bool {
    map[i / 8] & (1 << (i % 8)) != 0
}
fn set_bit(map: &mut [u8], i: usize) {
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

#[init_computation_definition_accounts("clear_unilateral64", payer)]
#[derive(Accounts)]
pub struct InitClearUnilateralCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    // Arcium's `init_computation_definition` itself requires the payer to be the MXE authority
    // (`InvalidAuthority` otherwise), so a stranger cannot register a dead circuit URL for us.
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

#[init_computation_definition_accounts("clear_route32", payer)]
#[derive(Accounts)]
pub struct InitClearRouteCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    // Arcium's `init_computation_definition` itself requires the payer to be the MXE authority
    // (`InvalidAuthority` otherwise), so a stranger cannot register a dead circuit URL for us.
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
    s.staged_mask = 0;
    s.route_gateway = Pubkey::default();
    s.route_mint = Pubkey::default();
    let r = &mut ctx.accounts.clearing_result;
    r.staging = ctx.accounts.staging.key();
    r.bump = ctx.bumps.clearing_result;
    r.computation_offset = 0;
    r.batch_seq = 0;
    r.comp_slot = 0;
    r.comp_slot_counter = 0;
    r._reserved = [0u8; 5];
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

/// Start the next batch in the same buffer. Always allowed for the buffer's relayer: a batch
/// that is not done — callback never landed, or verified commitments left unapplied — is
/// abandoned, which is safe because a commitment is never "consumed" by a batch: monotonicity
/// lives on the channel, so anything skipped here is simply re-submittable, and a late callback
/// for the abandoned computation is refused by the `computation_offset` binding.
pub fn reset_staging_handler(ctx: Context<ResetStaging>, kind: u8) -> Result<()> {
    StagingBuffer::slots_per_record(kind)?;
    let mut s = ctx.accounts.staging.load_mut()?;
    let r = &mut ctx.accounts.clearing_result;
    if s.sealed == 1 && !r.is_done() {
        emit!(BatchAbandoned {
            staging: ctx.accounts.staging.key(),
            batch_seq: s.batch_seq,
            computation_offset: r.computation_offset,
            verified: r.verified,
        });
    }
    s.batch_seq = s.batch_seq.checked_add(1).ok_or(RyvoError::MathOverflow)?;
    s.count = 0;
    s.kind = kind;
    s.sealed = 0;
    s.staged_mask = 0;
    s.route_gateway = Pubkey::default();
    s.route_mint = Pubkey::default();
    // Zero the slots (one memset; cheap). `staged_mask` already guarantees a sealed batch never
    // carries an older batch's bytes below `count`; this removes them from the account entirely,
    // so even a node that read the buffer at a stale slot could only ever see zeros, never a
    // previous batch's valid records at this batch's indices.
    s.slots.fill([0u8; SLOT]);
    r.clear(kind, 0);
    Ok(())
}

#[derive(Accounts)]
pub struct StageRecords<'info> {
    pub relayer: Signer<'info>,
    #[account(mut, has_one = relayer)]
    pub staging: AccountLoader<'info, StagingBuffer>,
    // remaining_accounts:
    //   unilateral: one direct source bucket per commitment
    //   route: gateway Participant once, then one routed source bucket per commitment
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Stage dense records for indices `start..start + n`. The program lays them out in slots and
/// copies each bucket slot's address and registered signing key from the bucket account itself,
/// so the key staged for an index is always the one registered for the channel id staged at that
/// index. Bounds-checked against the batch size; the buffer must be open.
///
/// It also refuses, up front, anything that could verify but never settle: the source channel
/// must carry the signed id, route allocations must be canonical, every route in a batch must
/// pay the same gateway in the same mint, and the signed base must already be reachable.
pub fn stage_records_handler<'info>(
    ctx: Context<'info, StageRecords<'info>>,
    start: u16,
    data: Vec<u8>,
) -> Result<()> {
    let mut s = ctx.accounts.staging.load_mut()?;
    require!(s.sealed == 0, RyvoError::StagingSealed);
    let kind = s.kind;
    let accs = ctx.remaining_accounts;
    let start = start as usize;
    match kind {
        KIND_UNILATERAL => {
            require!(
                !data.is_empty() && data.len() % UNILATERAL_RECORD_LEN == 0,
                RyvoError::InvalidStagingData
            );
            let n = data.len() / UNILATERAL_RECORD_LEN;
            require!(accs.len() == n, RyvoError::InvalidStagingData);
            require!(start + n <= N_UNI, RyvoError::InvalidStagingData);
            for r in 0..n {
                let i = start + r;
                let rec = &data[r * UNILATERAL_RECORD_LEN..(r + 1) * UNILATERAL_RECORD_LEN];
                let channel_id = u64_at(rec, 0);
                s.slots[UNI_COL_IDS + i] = u128_slot(pack_pair(channel_id, u64_at(rec, 8)));
                write_sig(&mut s.slots, UNI_COL_SIG + SIG_SLOTS * i, &rec[16..80]);
                let source = write_bucket_source(
                    &mut s.slots,
                    UNI_COL_KEY + KEY_SLOTS * i,
                    UNI_COL_BUCKET + i,
                    &accs[r],
                    channel_id,
                )?;
                require!(
                    source.kind == CHANNEL_KIND_DIRECT,
                    RyvoError::InvalidChannelKind
                );
                require!(
                    u64_at(rec, 8) > source.settled_cumulative,
                    RyvoError::CommitmentAlreadySettled
                );
                s.staged_mask |= 1u64 << i;
            }
        }
        KIND_ROUTE => {
            require!(
                !data.is_empty() && !accs.is_empty(),
                RyvoError::InvalidStagingData
            );
            let gateway: Account<Participant> = Account::try_from(&accs[0])?;
            require!(
                gateway.authorized_signer != Pubkey::default(),
                RyvoError::InvalidAuthorizedSigner
            );

            let mut records: Vec<(usize, usize)> = Vec::new();
            let mut cursor = 0usize;
            while cursor < data.len() {
                require!(
                    data.len() - cursor >= ROUTE_RECORD_BASE_LEN,
                    RyvoError::InvalidStagingData
                );
                let allocation_count = data[cursor + 24] as usize;
                require!(
                    (1..=MAX_ROUTE_ALLOCATIONS).contains(&allocation_count),
                    RyvoError::InvalidRouteAllocations
                );
                let len = ROUTE_RECORD_BASE_LEN
                    .checked_add(
                        allocation_count
                            .checked_mul(ROUTE_ALLOCATION_LEN)
                            .ok_or(RyvoError::MathOverflow)?,
                    )
                    .ok_or(RyvoError::MathOverflow)?;
                require!(cursor + len <= data.len(), RyvoError::InvalidStagingData);
                records.push((cursor, len));
                cursor += len;
            }
            let n = records.len();
            require!(
                cursor == data.len() && accs.len() == n + 1,
                RyvoError::InvalidStagingData
            );
            require!(start + n <= N_ROUTE, RyvoError::InvalidStagingData);

            let gateway_key = pack_pubkey(&gateway.authorized_signer.to_bytes());
            s.slots[RT_GATEWAY_KEY..RT_GATEWAY_KEY + KEY_SLOTS].copy_from_slice(&gateway_key);

            for (r, (record_at, record_len)) in records.into_iter().enumerate() {
                let i = start + r;
                let rec = &data[record_at..record_at + record_len];
                let source_id = u64_at(rec, 0);
                let base = u64_at(rec, 8);
                let target = u64_at(rec, 16);
                let allocation_count = rec[24] as usize;
                let signatures_at = 25 + allocation_count * ROUTE_ALLOCATION_LEN;

                let mut allocations = [RouteAllocation::default(); MAX_ROUTE_ALLOCATIONS];
                for (a, allocation) in allocations.iter_mut().take(allocation_count).enumerate() {
                    let at = 25 + a * ROUTE_ALLOCATION_LEN;
                    allocation.participant_id = u64_at(rec, at);
                    allocation.amount = u64_at(rec, at + 8);
                }
                let commitment = RouteCommitment {
                    message_domain: [0u8; 16],
                    source_channel_id: source_id,
                    base_cumulative: base,
                    target_cumulative: target,
                    allocation_count: allocation_count as u8,
                    allocations,
                };
                commitment.validate()?;
                require!(
                    !allocations[..allocation_count]
                        .iter()
                        .any(|allocation| allocation.participant_id == gateway.participant_id),
                    RyvoError::InvalidRouteAllocations
                );

                s.slots[RT_COL_SOURCE_BASE + i] = u128_slot(pack_pair(source_id, base));
                s.slots[RT_COL_TARGET_COUNT + i] =
                    u128_slot(pack_pair(target, allocation_count as u64));
                for (a, allocation) in allocations.iter().enumerate() {
                    s.slots[RT_COL_ALLOCATIONS + MAX_ROUTE_ALLOCATIONS * i + a] =
                        u128_slot(pack_pair(allocation.participant_id, allocation.amount));
                }
                write_sig(
                    &mut s.slots,
                    RT_COL_SIG_A + SIG_SLOTS * i,
                    &rec[signatures_at..signatures_at + 64],
                );
                write_sig(
                    &mut s.slots,
                    RT_COL_SIG_G + SIG_SLOTS * i,
                    &rec[signatures_at + 64..signatures_at + 128],
                );
                let source = write_bucket_source(
                    &mut s.slots,
                    RT_COL_KEY_A + KEY_SLOTS * i,
                    RT_COL_SOURCE_BUCKET + i,
                    &accs[r + 1],
                    source_id,
                )?;
                require!(
                    source.kind == CHANNEL_KIND_ROUTED,
                    RyvoError::InvalidChannelKind
                );
                require!(
                    source.payee == gateway.key(),
                    RyvoError::StagedRecordMismatch
                );
                require!(
                    base <= source.settled_cumulative,
                    RyvoError::RouteBaseNotReached
                );
                require!(
                    target > source.settled_cumulative,
                    RyvoError::CommitmentAlreadySettled
                );
                if s.route_gateway == Pubkey::default() {
                    s.route_gateway = gateway.key();
                    s.route_mint = source.mint;
                }
                require!(
                    s.route_gateway == gateway.key() && s.route_mint == source.mint,
                    RyvoError::RouteBatchMismatch
                );
                s.staged_mask |= 1u64 << i;
            }
        }
        _ => return Err(RyvoError::InvalidStagingKind.into()),
    }
    Ok(())
}

fn u128_slot(v: u128) -> [u8; SLOT] {
    let mut out = [0u8; SLOT];
    out[..16].copy_from_slice(&v.to_le_bytes());
    out
}

fn write_sig(slots: &mut [[u8; SLOT]; MAX_SLOTS], at: usize, sig: &[u8]) {
    let packed = pack_signature(sig.try_into().unwrap());
    slots[at..at + SIG_SLOTS].copy_from_slice(&packed);
}

struct BucketSource {
    payee: Pubkey,
    mint: Pubkey,
    kind: u8,
    settled_cumulative: u64,
}

/// Bucket address + registered key for the signed channel id. The id selects an occupied
/// permanent slot, so callers cannot substitute another agent's key or balance within the bucket.
fn write_bucket_source<'info>(
    slots: &mut [[u8; SLOT]; MAX_SLOTS],
    key_at: usize,
    bucket_at: usize,
    info: &'info AccountInfo<'info>,
    channel_id: u64,
) -> Result<BucketSource> {
    let loader: AccountLoader<ChannelBucket> = AccountLoader::try_from(info)?;
    let bucket = loader.load()?;
    require!(
        bucket.version == CHANNEL_BUCKET_VERSION,
        RyvoError::InvalidChannelBucket
    );
    let slot = bucket
        .slot_for_channel_id(channel_id)
        .ok_or(RyvoError::StagedRecordMismatch)?;
    slots[bucket_at] = info.key().to_bytes();
    slots[key_at] = bucket.signer_slot_0[slot];
    slots[key_at + 1] = bucket.signer_slot_1[slot];
    Ok(BucketSource {
        payee: bucket.payee,
        mint: bucket.mint,
        kind: bucket.kind,
        settled_cumulative: bucket.settled_cumulative[slot],
    })
}

// ============================================================================================
// Seal + queue
// ============================================================================================

#[queue_computation_accounts("clear_unilateral64", relayer)]
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

#[queue_computation_accounts("clear_route32", relayer)]
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
    (
        staging,
        (SLOTS_OFFSET + col * SLOT) as u32,
        (slots * SLOT) as u32,
    )
}

/// Shared body: seal the buffer, reset the result for this batch, bind it to the computation,
/// and build the argument list in the circuit's parameter order. The domain comes from `Config`,
/// never from the relayer, so a batch cannot be verified against a foreign deployment's domain;
/// the keys were copied from channel bucket slots by `stage_records`, never written by the
/// relayer.
fn seal_common(
    staging_loader: &AccountLoader<StagingBuffer>,
    clearing_result: &mut ClearingResult,
    config: &Config,
    kind: u8,
    count: u16,
    computation_offset: u64,
) -> Result<ArgumentList> {
    let mut s = staging_loader.load_mut()?;
    require!(s.kind == kind, RyvoError::InvalidStagingKind);
    require!(s.sealed == 0, RyvoError::StagingSealed);
    require!(
        count as usize >= 1 && count as usize <= batch_size(kind),
        RyvoError::InvalidStagingData
    );
    // 0 means "no computation bound" in ClearingResult, so it is not a usable offset.
    require!(computation_offset != 0, RyvoError::InvalidStagingData);
    // Every index below count must have been staged in this batch — never a previous batch's bytes.
    let needed: u64 = if count as usize == 64 {
        u64::MAX
    } else {
        (1u64 << count) - 1
    };
    require!(s.staged_mask & needed == needed, RyvoError::IncompleteBatch);
    if kind == KIND_ROUTE {
        require!(
            s.route_gateway != Pubkey::default() && s.route_mint != Pubkey::default(),
            RyvoError::RouteBatchMismatch
        );
    }
    s.count = count;
    s.sealed = 1;
    clearing_result.clear(kind, count);
    clearing_result.computation_offset = computation_offset;
    clearing_result.batch_seq = s.batch_seq;
    // The circuit's input is fixed-size: pad a short batch by repeating record 0, which is a
    // complete, verifiable record. Padded indices are >= count and never settled.
    for i in count as usize..batch_size(kind) {
        s.copy_record(kind, 0, i);
    }

    // Built by hand rather than through ArgBuilder so the vectors are sized once (the on-chain
    // bump allocator never frees). One account range per column, in the circuit's parameter
    // order (each range stays within the 6 KB proven on devnet).
    let key = staging_loader.key();
    let mut args: Vec<ArgumentRef> = Vec::with_capacity(7);
    let mut accounts: Vec<AccountArgument> = Vec::with_capacity(6);
    args.push(ArgumentRef::PlaintextU128(0)); // index into values_128_bit
    let values_128_bit = vec![crate::commitment::domain_slot(&config.message_domain)];
    let ranges: &[(usize, usize)] = match kind {
        KIND_UNILATERAL => &[
            (UNI_COL_IDS, N_UNI),
            (UNI_COL_KEY, KEY_SLOTS * N_UNI),
            (UNI_COL_SIG, SIG_SLOTS * N_UNI),
        ],
        KIND_ROUTE => &[
            (RT_COL_SOURCE_BASE, N_ROUTE),
            (RT_COL_TARGET_COUNT, N_ROUTE),
            (RT_COL_ALLOCATIONS, MAX_ROUTE_ALLOCATIONS * N_ROUTE),
            (RT_COL_KEY_A, KEY_SLOTS * N_ROUTE),
            (RT_GATEWAY_KEY, KEY_SLOTS),
            (RT_COL_SIG_A, SIG_SLOTS * N_ROUTE),
            (RT_COL_SIG_G, SIG_SLOTS * N_ROUTE),
        ],
        _ => return Err(RyvoError::InvalidStagingKind.into()),
    };
    for &(col, slots) in ranges {
        args.push(ArgumentRef::Account(accounts.len() as u8));
        let (pubkey, offset, length) = range(key, col, slots);
        accounts.push(AccountArgument {
            pubkey,
            offset,
            length,
        });
    }
    Ok(ArgumentList {
        args,
        byte_arrays: Vec::new(),
        plaintext_numbers: Vec::new(),
        values_128_bit,
        accounts,
    })
}

pub fn seal_and_queue_unilateral_handler(
    ctx: Context<SealAndQueueUnilateral>,
    computation_offset: u64,
    count: u16,
    callback_cu_limit: u32,
    cu_price_micro: u64,
) -> Result<()> {
    require!(
        callback_cu_limit <= MAX_CALLBACK_CU_LIMIT,
        RyvoError::InvalidStagingData
    );
    let clearing_key = ctx.accounts.clearing_result.key();
    let args = seal_common(
        &ctx.accounts.staging,
        &mut ctx.accounts.clearing_result,
        &ctx.accounts.config,
        KIND_UNILATERAL,
        count,
        computation_offset,
    )?;
    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![ClearUnilateral64Callback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[CallbackAccount {
                pubkey: clearing_key,
                is_writable: true,
            }],
        )?],
        1,
        cu_price_micro,
        callback_cu_limit,
    )?;
    pin_computation(
        &mut ctx.accounts.clearing_result,
        &ctx.accounts.computation_account.to_account_info(),
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
    callback_cu_limit: u32,
    cu_price_micro: u64,
) -> Result<()> {
    require!(
        callback_cu_limit <= MAX_CALLBACK_CU_LIMIT,
        RyvoError::InvalidStagingData
    );
    let clearing_key = ctx.accounts.clearing_result.key();
    let args = seal_common(
        &ctx.accounts.staging,
        &mut ctx.accounts.clearing_result,
        &ctx.accounts.config,
        KIND_ROUTE,
        count,
        computation_offset,
    )?;
    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![ClearRoute32Callback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[CallbackAccount {
                pubkey: clearing_key,
                is_writable: true,
            }],
        )?],
        1,
        cu_price_micro,
        callback_cu_limit,
    )?;
    pin_computation(
        &mut ctx.accounts.clearing_result,
        &ctx.accounts.computation_account.to_account_info(),
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

#[callback_accounts("clear_unilateral64")]
#[derive(Accounts)]
pub struct ClearUnilateral64Callback<'info> {
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

#[callback_accounts("clear_route32")]
#[derive(Accounts)]
pub struct ClearRoute32Callback<'info> {
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

/// The callback must come from the computation this batch was sealed with. The Arcium program
/// already guarantees the transaction is a genuine node callback; this guarantees it is *ours*,
/// and current.
///
/// Three checks, because the computation PDA is scoped to the *cluster*, not to this program:
/// `[seed, cluster, offset]`. Another MXE on the same cluster could queue a computation at an
/// offset we once used (after ours was closed) with a custom callback aimed at this program and
/// our accounts, and the cluster would sign its output honestly. So: (1) the account is the PDA
/// for the offset sealed into this batch, (2) the account says it was queued by THIS program for
/// THIS circuit (`mxe_program_id`, `computation_definition_offset` — only our sign-PDA-gated
/// `seal_and_queue_*` can create such an account), (3) a batch is bound at all (offset ≠ 0,
/// count > 0). A callback for an abandoned, earlier, or foreign computation is refused.
/// Upper bound on the callback compute budget a relayer may request (the Solana per-tx cap).
pub const MAX_CALLBACK_CU_LIMIT: u32 = 1_400_000;

// ComputationAccount (Arcium): disc(8) | payer(32) | mxe_program_id(32) | computation_definition_offset(u32)
// | execution_fee(24) | slot(u64) | slot_counter(u16) | …  — the same offsets arcium-anchor uses.
const COMP_MXE_PROGRAM: core::ops::Range<usize> = 40..72;
const COMP_DEF_OFFSET: core::ops::Range<usize> = 72..76;
const COMP_SLOT: core::ops::Range<usize> = 100..108;
const COMP_SLOT_COUNTER: core::ops::Range<usize> = 108..110;

/// Record the exact computation instance right after the queue CPI created it.
fn pin_computation(result: &mut ClearingResult, computation_account: &AccountInfo) -> Result<()> {
    let data = computation_account.try_borrow_data()?;
    require!(
        data.len() >= COMP_SLOT_COUNTER.end,
        RyvoError::ForeignComputation
    );
    result.comp_slot = u64::from_le_bytes(data[COMP_SLOT].try_into().unwrap());
    result.comp_slot_counter = u16::from_le_bytes(data[COMP_SLOT_COUNTER].try_into().unwrap());
    Ok(())
}

/// Verdict of the callback's provenance check.
pub enum CallbackMatch {
    /// The computation this batch is bound to.
    Current,
    /// One of ours (queued by this program for this circuit) but not the bound one — abandoned,
    /// earlier, or a reused offset. Ignore it quietly so Arcium can still finalize it and the
    /// relayer can reclaim its rent.
    Stale,
}

/// The callback must come from the computation this batch was sealed with. The Arcium program
/// already guarantees the transaction is a genuine node callback; this decides whether it is
/// *ours*, and current.
///
/// The computation PDA is scoped to the *cluster*, not to this program: `[seed, cluster, offset]`.
/// Another MXE on the same cluster could queue a computation at an offset we once used (after
/// ours was closed) with a custom callback aimed at this program and our accounts, and the
/// cluster would sign its output honestly. So: the account must be owned by Arcium and say it
/// was queued by THIS program for THIS circuit (only our sign-PDA-gated `seal_and_queue_*` can
/// create such an account) — anything else is an error. Among ours, only the bound instance
/// (offset + the `(slot, slot_counter)` pinned at queue time) is `Current`.
pub fn require_current_computation(
    result: &ClearingResult,
    computation_account: &AccountInfo,
    mxe_account: &MXEAccount,
    comp_def_offset: u32,
) -> Result<CallbackMatch> {
    require!(
        computation_account.owner == &ARCIUM_PROG_ID,
        RyvoError::ForeignComputation
    );
    let data = computation_account.try_borrow_data()?;
    require!(
        data.len() >= COMP_SLOT_COUNTER.end,
        RyvoError::ForeignComputation
    );
    let mxe_program = Pubkey::new_from_array(data[COMP_MXE_PROGRAM].try_into().unwrap());
    let def = u32::from_le_bytes(data[COMP_DEF_OFFSET].try_into().unwrap());
    require!(
        mxe_program == crate::ID && def == comp_def_offset,
        RyvoError::ForeignComputation
    );
    if result.computation_offset == 0 || result.count == 0 {
        return Ok(CallbackMatch::Stale);
    }
    let expected = derive_comp_pda!(result.computation_offset, mxe_account);
    let slot = u64::from_le_bytes(data[COMP_SLOT].try_into().unwrap());
    let counter = u16::from_le_bytes(data[COMP_SLOT_COUNTER].try_into().unwrap());
    if computation_account.key() != expected
        || slot != result.comp_slot
        || counter != result.comp_slot_counter
    {
        return Ok(CallbackMatch::Stale);
    }
    Ok(CallbackMatch::Current)
}

pub const fn comp_def_offset_for(kind: u8) -> u32 {
    if kind == KIND_ROUTE {
        COMP_DEF_OFFSET_CLEAR_ROUTE
    } else {
        COMP_DEF_OFFSET_CLEAR_UNILATERAL
    }
}

/// The computation did not produce an output. Recorded, not errored: see `ClearingResult::failed`.
pub fn record_failure(result: &mut ClearingResult) -> Result<()> {
    require!(
        !result.verified && !result.failed,
        RyvoError::BatchAlreadyCleared
    );
    result.failed = true;
    emit!(BatchClearingFailed {
        staging: result.staging,
        kind: result.kind
    });
    Ok(())
}

/// Record the verified bits. A batch takes exactly one verdict: once verified or failed, nothing
/// else is accepted (an honest computation delivers one callback; a second one is not ours).
pub fn record_bitmap(result: &mut ClearingResult, bits: &[bool], kind: u8) -> Result<()> {
    require!(
        !result.verified && !result.failed,
        RyvoError::BatchAlreadyCleared
    );
    require!(result.kind == kind, RyvoError::InvalidStagingKind);
    let mut bitmap = [0u8; (MAX_CLEARING_COMMITMENTS / 8) as usize];
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
    //   unilateral: [source_bucket (mut), payee_balance (mut)]
    //   route:      [source_bucket (mut), gateway_balance (mut), provider_balance (mut) x count]
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
    require!(
        staging.sealed == 1 && staging.kind == result.kind,
        RyvoError::InvalidStagingKind
    );
    let kind = staging.kind;
    let mut account_cursor = 0usize;
    for &idx in &indices {
        let i = idx as usize;
        require!(i < result.count as usize, RyvoError::InvalidSettlementIndex);
        require!(bit(&result.bitmap, i), RyvoError::RecordNotVerified);
        require!(!bit(&result.applied, i), RyvoError::RecordAlreadyApplied);
        let account_count = match kind {
            KIND_UNILATERAL => 2,
            KIND_ROUTE => {
                let (_, count) = unpack_pair(staged_u128(&staging, RT_COL_TARGET_COUNT, i));
                require!(
                    count >= 1 && count <= MAX_ROUTE_ALLOCATIONS as u64,
                    RyvoError::InvalidRouteAllocations
                );
                2usize
                    .checked_add(count as usize)
                    .ok_or(RyvoError::MathOverflow)?
            }
            _ => return Err(RyvoError::InvalidStagingKind.into()),
        };
        let end = account_cursor
            .checked_add(account_count)
            .ok_or(RyvoError::MathOverflow)?;
        require!(
            end <= ctx.remaining_accounts.len(),
            RyvoError::InvalidSettlementAccounts
        );
        let accs = &ctx.remaining_accounts[account_cursor..end];
        match kind {
            KIND_UNILATERAL => settle_unilateral(&staging, i, accs)?,
            KIND_ROUTE => settle_route(&staging, i, accs)?,
            _ => unreachable!(),
        }
        account_cursor = end;
        set_bit(&mut result.applied, i);
    }
    require!(
        account_cursor == ctx.remaining_accounts.len(),
        RyvoError::InvalidSettlementAccounts
    );
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
    let staged_bucket = staged_pubkey(staging, UNI_COL_BUCKET, i);

    // The circuit verified the signature under the key stored in this bucket slot. Settlement
    // rebinds the signed channel id to the same bucket and occupied slot.
    require!(
        accs[0].key() == staged_bucket,
        RyvoError::SettlementChannelMismatch
    );
    require!(accs[0].is_writable, RyvoError::InvalidSettlementAccounts);
    let bucket_loader: AccountLoader<ChannelBucket> = AccountLoader::try_from(&accs[0])?;
    let mut bucket = bucket_loader.load_mut()?;
    let mut payee_balance = load_mut::<Balance>(&accs[1])?;
    require!(
        bucket.version == CHANNEL_BUCKET_VERSION && bucket.kind == CHANNEL_KIND_DIRECT,
        RyvoError::InvalidChannelBucket
    );
    let slot = bucket
        .slot_for_channel_id(channel_id)
        .ok_or(RyvoError::SettlementChannelMismatch)?;
    require!(
        payee_balance.participant == bucket.payee && payee_balance.mint == bucket.mint,
        RyvoError::SettlementBalanceMismatch
    );

    let moved = payable(
        target,
        bucket.settled_cumulative[slot],
        bucket.locked_balance[slot],
    );
    if moved > 0 {
        bucket.locked_balance[slot] -= moved;
        bucket.settled_cumulative[slot] += moved;
        payee_balance.available = payee_balance
            .available
            .checked_add(moved)
            .ok_or(RyvoError::MathOverflow)?;
        payee_balance.exit(&crate::ID)?;
    }
    emit!(ChannelSettled {
        bucket: staged_bucket,
        slot: slot as u8,
        channel_id,
        target_cumulative: target,
        moved,
        settled_cumulative: bucket.settled_cumulative[slot],
        locked_balance: bucket.locked_balance[slot],
    });
    Ok(())
}

fn settle_route<'info>(
    staging: &StagingBuffer,
    i: usize,
    accs: &'info [AccountInfo<'info>],
) -> Result<()> {
    let (source_id, base) = unpack_pair(staged_u128(staging, RT_COL_SOURCE_BASE, i));
    let (target, allocation_count) = unpack_pair(staged_u128(staging, RT_COL_TARGET_COUNT, i));
    require!(
        allocation_count >= 1 && allocation_count <= MAX_ROUTE_ALLOCATIONS as u64,
        RyvoError::InvalidRouteAllocations
    );
    require!(
        accs.len() == 2 + allocation_count as usize,
        RyvoError::InvalidSettlementAccounts
    );
    let staged_bucket = staged_pubkey(staging, RT_COL_SOURCE_BUCKET, i);

    require!(
        accs[0].key() == staged_bucket,
        RyvoError::SettlementChannelMismatch
    );
    require!(accs[0].is_writable, RyvoError::InvalidSettlementAccounts);
    let bucket_loader: AccountLoader<ChannelBucket> = AccountLoader::try_from(&accs[0])?;
    let mut bucket = bucket_loader.load_mut()?;
    let mut gateway_balance = load_mut::<Balance>(&accs[1])?;
    require!(
        bucket.version == CHANNEL_BUCKET_VERSION && bucket.kind == CHANNEL_KIND_ROUTED,
        RyvoError::InvalidChannelBucket
    );
    let slot = bucket
        .slot_for_channel_id(source_id)
        .ok_or(RyvoError::SettlementChannelMismatch)?;
    require!(
        bucket.payee == staging.route_gateway && bucket.mint == staging.route_mint,
        RyvoError::SettlementRouteMismatch
    );
    require!(
        gateway_balance.participant == staging.route_gateway
            && gateway_balance.mint == staging.route_mint,
        RyvoError::SettlementBalanceMismatch
    );
    require!(
        bucket.settled_cumulative[slot] >= base,
        RyvoError::RouteBaseNotReached
    );

    let old_cumulative = bucket.settled_cumulative[slot];
    let moved = payable(target, old_cumulative, bucket.locked_balance[slot]);
    let new_cumulative = old_cumulative
        .checked_add(moved)
        .ok_or(RyvoError::MathOverflow)?;
    bucket.locked_balance[slot] -= moved;
    bucket.settled_cumulative[slot] = new_cumulative;

    let mut provider_paid = 0u64;
    let mut range_start = base;
    for a in 0..allocation_count as usize {
        let (participant_id, amount) = unpack_pair(staged_u128(
            staging,
            RT_COL_ALLOCATIONS,
            i * MAX_ROUTE_ALLOCATIONS + a,
        ));
        let range_end = range_start
            .checked_add(amount)
            .ok_or(RyvoError::MathOverflow)?;
        require!(range_end <= target, RyvoError::InvalidRouteAllocations);
        require!(
            accs[a + 2].key() != accs[1].key(),
            RyvoError::InvalidSettlementAccounts
        );
        let mut provider_balance = load_mut::<Balance>(&accs[a + 2])?;
        require!(
            provider_balance.participant_id == participant_id
                && provider_balance.mint == staging.route_mint,
            RyvoError::SettlementBalanceMismatch
        );

        let paid_start = old_cumulative.max(range_start);
        let paid_end = new_cumulative.min(range_end);
        let paid = paid_end.saturating_sub(paid_start);
        if paid > 0 {
            provider_balance.available = provider_balance
                .available
                .checked_add(paid)
                .ok_or(RyvoError::MathOverflow)?;
            provider_balance.exit(&crate::ID)?;
            provider_paid = provider_paid
                .checked_add(paid)
                .ok_or(RyvoError::MathOverflow)?;
        }
        emit!(RouteProviderPaid {
            source_bucket: staged_bucket,
            source_slot: slot as u8,
            source_channel_id: source_id,
            provider: provider_balance.participant,
            participant_id,
            amount: paid,
        });
        range_start = range_end;
    }

    let gateway_fee = moved
        .checked_sub(provider_paid)
        .ok_or(RyvoError::MathOverflow)?;
    if gateway_fee > 0 {
        gateway_balance.available = gateway_balance
            .available
            .checked_add(gateway_fee)
            .ok_or(RyvoError::MathOverflow)?;
        gateway_balance.exit(&crate::ID)?;
    }
    emit!(RouteSettled {
        source_bucket: staged_bucket,
        source_slot: slot as u8,
        source_channel_id: source_id,
        base_cumulative: base,
        target_cumulative: target,
        moved,
        provider_paid,
        gateway_fee,
        allocation_count: allocation_count as u8,
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

/// Reclaim rent for a buffer the relayer no longer needs. Same semantics as `reset_staging`: an
/// unfinished batch is abandoned (its commitments remain re-submittable); a late callback for it
/// then fails on the missing account and the node gives up.
pub fn close_staging_handler(ctx: Context<CloseStaging>) -> Result<()> {
    let s = ctx.accounts.staging.load()?;
    let r = &ctx.accounts.clearing_result;
    if s.sealed == 1 && !r.is_done() {
        emit!(BatchAbandoned {
            staging: ctx.accounts.staging.key(),
            batch_seq: s.batch_seq,
            computation_offset: r.computation_offset,
            verified: r.verified,
        });
    }
    Ok(())
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    use anchor_lang::Space;

    #[test]
    fn clearing_account_sizes_are_pinned() {
        assert_eq!(core::mem::size_of::<StagingBuffer>(), 27_832);
        assert_eq!(StagingBuffer::SPACE, 27_840);
        assert_eq!(ClearingResult::INIT_SPACE, 133);
    }

    #[test]
    fn clearing_result_reserves_256_commitment_bits() {
        assert_eq!(MAX_CLEARING_COMMITMENTS, 256);
        let mut bitmap = [0u8; (MAX_CLEARING_COMMITMENTS / 8) as usize];
        set_bit(&mut bitmap, 255);
        assert!(bit(&bitmap, 255));
        assert!(!bit(&bitmap, 254));
    }
}
