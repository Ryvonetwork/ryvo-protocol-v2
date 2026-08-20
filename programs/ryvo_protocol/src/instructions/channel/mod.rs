use crate::constants::{
    BALANCE_SEED, CHANNEL_BUCKET_CAPACITY, CHANNEL_KIND_DIRECT, CHANNEL_KIND_ROUTED, CONFIG_SEED,
    PARTICIPANT_SEED, TOKEN_CONFIG_SEED,
};
use crate::error::RyvoError;
use crate::events::{
    ChannelBucketCreated, ChannelCreated, ChannelFundsLocked, ChannelFundsUnlocked,
    ChannelUnlockCancelled, ChannelUnlockRequested,
};
use crate::state::{
    Balance, ChannelBucket, Config, Participant, TokenConfig, CHANNEL_BUCKET_VERSION,
};
use anchor_lang::prelude::*;
use anchor_spl::token::Mint;

/// Initialize a pre-created, program-owned bucket and reserve its contiguous channel-id range.
/// The account is created by the client because its 32 KB size exceeds Solana's CPI allocation cap.
#[derive(Accounts)]
pub struct InitializeChannelBucket<'info> {
    #[account(mut)]
    pub payee_owner: Signer<'info>,

    #[account(mut, seeds = [CONFIG_SEED.as_bytes()], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), payee_owner.key().as_ref()],
        bump = payee_participant.bump,
    )]
    pub payee_participant: Box<Account<'info, Participant>>,

    pub mint: Box<Account<'info, Mint>>,

    #[account(
        seeds = [TOKEN_CONFIG_SEED.as_bytes(), mint.key().as_ref()],
        bump = token_config.bump,
        has_one = mint,
    )]
    pub token_config: Box<Account<'info, TokenConfig>>,

    #[account(
        seeds = [
            BALANCE_SEED.as_bytes(),
            payee_participant.key().as_ref(),
            mint.key().as_ref(),
        ],
        bump = payee_balance.bump,
    )]
    pub payee_balance: Box<Account<'info, Balance>>,

    /// Pre-created with `ChannelBucket::SPACE` bytes and this program as owner.
    #[account(zero)]
    pub bucket: AccountLoader<'info, ChannelBucket>,
}

pub fn initialize_channel_bucket_handler(
    ctx: Context<InitializeChannelBucket>,
    kind: u8,
) -> Result<()> {
    require!(
        kind == CHANNEL_KIND_DIRECT || kind == CHANNEL_KIND_ROUTED,
        RyvoError::InvalidChannelKind
    );
    let config = &mut ctx.accounts.config;
    let base_channel_id = config.next_channel_id;
    config.next_channel_id = base_channel_id
        .checked_add(CHANNEL_BUCKET_CAPACITY as u64)
        .ok_or(RyvoError::MathOverflow)?;

    let mut bucket = ctx.accounts.bucket.load_init()?;
    bucket.payee = ctx.accounts.payee_participant.key();
    bucket.mint = ctx.accounts.mint.key();
    bucket.base_channel_id = base_channel_id;
    bucket.version = CHANNEL_BUCKET_VERSION;
    bucket.kind = kind;

    emit!(ChannelBucketCreated {
        bucket: ctx.accounts.bucket.key(),
        payee: bucket.payee,
        mint: bucket.mint,
        base_channel_id,
        capacity: CHANNEL_BUCKET_CAPACITY,
        kind,
    });
    Ok(())
}

/// Permanently assign one slot. The payer and bucket payee both approve the relationship.
#[derive(Accounts)]
pub struct CreateChannel<'info> {
    pub payer_owner: Signer<'info>,
    pub payee_owner: Signer<'info>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), payer_owner.key().as_ref()],
        bump = payer_participant.bump,
    )]
    pub payer_participant: Box<Account<'info, Participant>>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), payee_owner.key().as_ref()],
        bump = payee_participant.bump,
    )]
    pub payee_participant: Box<Account<'info, Participant>>,

    #[account(mut)]
    pub bucket: AccountLoader<'info, ChannelBucket>,

    #[account(
        seeds = [
            BALANCE_SEED.as_bytes(),
            payer_participant.key().as_ref(),
            payer_balance.mint.as_ref(),
        ],
        bump = payer_balance.bump,
    )]
    pub payer_balance: Box<Account<'info, Balance>>,

    #[account(
        seeds = [
            BALANCE_SEED.as_bytes(),
            payee_participant.key().as_ref(),
            payee_balance.mint.as_ref(),
        ],
        bump = payee_balance.bump,
    )]
    pub payee_balance: Box<Account<'info, Balance>>,
}

pub fn create_channel_handler(ctx: Context<CreateChannel>, slot: u8) -> Result<()> {
    require!(
        ctx.accounts.payer_participant.key() != ctx.accounts.payee_participant.key(),
        RyvoError::SelfChannelNotAllowed
    );
    let bucket_key = ctx.accounts.bucket.key();
    let mut bucket = ctx.accounts.bucket.load_mut()?;
    require!(
        bucket.version == CHANNEL_BUCKET_VERSION
            && bucket.payee == ctx.accounts.payee_participant.key()
            && bucket.mint == ctx.accounts.payer_balance.mint
            && bucket.mint == ctx.accounts.payee_balance.mint,
        RyvoError::InvalidChannelBucket
    );
    let i = slot as usize;
    require!(!bucket.is_occupied(i), RyvoError::ChannelSlotOccupied);
    let channel_id = bucket.channel_id(i).ok_or(RyvoError::InvalidChannelSlot)?;
    let signer = ctx.accounts.payer_participant.authorized_signer;
    let packed = crate::commitment::pack_pubkey(&signer.to_bytes());

    bucket.occupy(i);
    bucket.payers[i] = ctx.accounts.payer_participant.key();
    bucket.signer_slot_0[i] = packed[0];
    bucket.signer_slot_1[i] = packed[1];

    emit!(ChannelCreated {
        bucket: bucket_key,
        slot,
        channel_id,
        payer: bucket.payers[i],
        payee: bucket.payee,
        mint: bucket.mint,
        authorized_signer: signer,
        kind: bucket.kind,
    });
    Ok(())
}

#[derive(Accounts)]
pub struct PayerChannelOp<'info> {
    pub payer_owner: Signer<'info>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), payer_owner.key().as_ref()],
        bump = payer_participant.bump,
    )]
    pub payer_participant: Box<Account<'info, Participant>>,

    #[account(seeds = [CONFIG_SEED.as_bytes()], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,

    #[account(mut)]
    pub bucket: AccountLoader<'info, ChannelBucket>,

    #[account(
        mut,
        seeds = [
            BALANCE_SEED.as_bytes(),
            payer_participant.key().as_ref(),
            payer_balance.mint.as_ref(),
        ],
        bump = payer_balance.bump,
    )]
    pub payer_balance: Box<Account<'info, Balance>>,
}

fn payer_slot(
    bucket: &ChannelBucket,
    slot: u8,
    payer: Pubkey,
    mint: Pubkey,
) -> Result<(usize, u64)> {
    let i = slot as usize;
    require!(
        bucket.version == CHANNEL_BUCKET_VERSION && bucket.mint == mint,
        RyvoError::InvalidChannelBucket
    );
    require!(
        bucket.is_occupied(i) && bucket.payers[i] == payer,
        RyvoError::InvalidChannelSlot
    );
    let channel_id = bucket.channel_id(i).ok_or(RyvoError::InvalidChannelSlot)?;
    Ok((i, channel_id))
}

pub fn lock_channel_funds_handler(
    ctx: Context<PayerChannelOp>,
    slot: u8,
    amount: u64,
) -> Result<()> {
    require!(amount > 0, RyvoError::AmountMustBePositive);
    require!(
        amount <= ctx.accounts.payer_balance.available,
        RyvoError::InsufficientBalance
    );
    let bucket_key = ctx.accounts.bucket.key();
    let mut bucket = ctx.accounts.bucket.load_mut()?;
    let (i, channel_id) = payer_slot(
        &bucket,
        slot,
        ctx.accounts.payer_participant.key(),
        ctx.accounts.payer_balance.mint,
    )?;

    ctx.accounts.payer_balance.available = ctx
        .accounts
        .payer_balance
        .available
        .checked_sub(amount)
        .ok_or(RyvoError::MathOverflow)?;
    bucket.locked_balance[i] = bucket.locked_balance[i]
        .checked_add(amount)
        .ok_or(RyvoError::MathOverflow)?;
    let cancelled = bucket.pending_unlock_amount[i];
    bucket.pending_unlock_amount[i] = 0;
    bucket.pending_unlock_at[i] = 0;

    emit!(ChannelFundsLocked {
        bucket: bucket_key,
        slot,
        channel_id,
        amount,
        locked_balance: bucket.locked_balance[i],
    });
    if cancelled > 0 {
        emit!(ChannelUnlockCancelled {
            bucket: bucket_key,
            slot,
            channel_id,
            cancelled_amount: cancelled,
        });
    }
    Ok(())
}

pub fn request_unlock_channel_funds_handler(
    ctx: Context<PayerChannelOp>,
    slot: u8,
    amount: u64,
) -> Result<()> {
    require!(amount > 0, RyvoError::AmountMustBePositive);
    let bucket_key = ctx.accounts.bucket.key();
    let mut bucket = ctx.accounts.bucket.load_mut()?;
    let (i, channel_id) = payer_slot(
        &bucket,
        slot,
        ctx.accounts.payer_participant.key(),
        ctx.accounts.payer_balance.mint,
    )?;
    require!(
        amount <= bucket.locked_balance[i],
        RyvoError::InsufficientLockedBalance
    );
    let unlock_at = Clock::get()?
        .unix_timestamp
        .checked_add(ctx.accounts.config.channel_timelock_seconds)
        .ok_or(RyvoError::MathOverflow)?;
    bucket.pending_unlock_amount[i] = amount;
    bucket.pending_unlock_at[i] = unlock_at;

    emit!(ChannelUnlockRequested {
        bucket: bucket_key,
        slot,
        channel_id,
        requested_amount: amount,
        unlock_at,
    });
    Ok(())
}

pub fn execute_unlock_channel_funds_handler(ctx: Context<PayerChannelOp>, slot: u8) -> Result<()> {
    let bucket_key = ctx.accounts.bucket.key();
    let mut bucket = ctx.accounts.bucket.load_mut()?;
    let (i, channel_id) = payer_slot(
        &bucket,
        slot,
        ctx.accounts.payer_participant.key(),
        ctx.accounts.payer_balance.mint,
    )?;
    let pending = bucket.pending_unlock_amount[i];
    require!(pending > 0, RyvoError::NoChannelUnlockPending);
    require!(
        Clock::get()?.unix_timestamp >= bucket.pending_unlock_at[i],
        RyvoError::ChannelUnlockLocked
    );
    let released = pending.min(bucket.locked_balance[i]);
    bucket.locked_balance[i] -= released;
    bucket.pending_unlock_amount[i] = 0;
    bucket.pending_unlock_at[i] = 0;
    ctx.accounts.payer_balance.available = ctx
        .accounts
        .payer_balance
        .available
        .checked_add(released)
        .ok_or(RyvoError::MathOverflow)?;

    emit!(ChannelFundsUnlocked {
        bucket: bucket_key,
        slot,
        channel_id,
        released_amount: released,
        remaining_locked: bucket.locked_balance[i],
        cooperative: false,
    });
    Ok(())
}

#[derive(Accounts)]
pub struct CooperativeUnlockChannelFunds<'info> {
    pub payer_owner: Signer<'info>,
    pub payee_owner: Signer<'info>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), payer_owner.key().as_ref()],
        bump = payer_participant.bump,
    )]
    pub payer_participant: Box<Account<'info, Participant>>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), payee_owner.key().as_ref()],
        bump = payee_participant.bump,
    )]
    pub payee_participant: Box<Account<'info, Participant>>,

    #[account(mut)]
    pub bucket: AccountLoader<'info, ChannelBucket>,

    #[account(
        mut,
        seeds = [
            BALANCE_SEED.as_bytes(),
            payer_participant.key().as_ref(),
            payer_balance.mint.as_ref(),
        ],
        bump = payer_balance.bump,
    )]
    pub payer_balance: Box<Account<'info, Balance>>,
}

pub fn cooperative_unlock_channel_funds_handler(
    ctx: Context<CooperativeUnlockChannelFunds>,
    slot: u8,
    amount: u64,
) -> Result<()> {
    require!(amount > 0, RyvoError::AmountMustBePositive);
    let bucket_key = ctx.accounts.bucket.key();
    let mut bucket = ctx.accounts.bucket.load_mut()?;
    require!(
        bucket.payee == ctx.accounts.payee_participant.key(),
        RyvoError::InvalidChannelBucket
    );
    let (i, channel_id) = payer_slot(
        &bucket,
        slot,
        ctx.accounts.payer_participant.key(),
        ctx.accounts.payer_balance.mint,
    )?;
    let released = amount.min(bucket.locked_balance[i]);
    require!(released > 0, RyvoError::InsufficientLockedBalance);
    bucket.locked_balance[i] -= released;
    bucket.pending_unlock_amount[i] = 0;
    bucket.pending_unlock_at[i] = 0;
    ctx.accounts.payer_balance.available = ctx
        .accounts
        .payer_balance
        .available
        .checked_add(released)
        .ok_or(RyvoError::MathOverflow)?;

    emit!(ChannelFundsUnlocked {
        bucket: bucket_key,
        slot,
        channel_id,
        released_amount: released,
        remaining_locked: bucket.locked_balance[i],
        cooperative: true,
    });
    Ok(())
}
