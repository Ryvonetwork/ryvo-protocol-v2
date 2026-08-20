use crate::constants::{
    BALANCE_SEED, CONFIG_SEED, PARTICIPANT_SEED, ROUTED_BUCKET_CAPACITY, TOKEN_CONFIG_SEED,
};
use crate::error::RyvoError;
use crate::events::{
    RoutedBucketCreated, RoutedChannelCreated, RoutedChannelFundsLocked,
    RoutedChannelFundsUnlocked, RoutedChannelUnlockCancelled, RoutedChannelUnlockRequested,
};
use crate::state::{
    Balance, Config, Participant, RoutedChannelBucket, TokenConfig, ROUTED_BUCKET_VERSION,
};
use anchor_lang::prelude::*;
use anchor_spl::token::Mint;

/// Initialize a pre-created, program-owned bucket and reserve its contiguous channel-id range.
/// The account is created by the client because its 32 KB size exceeds Solana's CPI allocation cap.
#[derive(Accounts)]
pub struct InitializeRoutedBucket<'info> {
    #[account(mut)]
    pub gateway_owner: Signer<'info>,

    #[account(mut, seeds = [CONFIG_SEED.as_bytes()], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), gateway_owner.key().as_ref()],
        bump = gateway_participant.bump,
    )]
    pub gateway_participant: Box<Account<'info, Participant>>,

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
            gateway_participant.key().as_ref(),
            mint.key().as_ref(),
        ],
        bump = gateway_balance.bump,
    )]
    pub gateway_balance: Box<Account<'info, Balance>>,

    /// Pre-created with `RoutedChannelBucket::SPACE` bytes and this program as owner.
    #[account(zero)]
    pub bucket: AccountLoader<'info, RoutedChannelBucket>,
}

pub fn initialize_routed_bucket_handler(ctx: Context<InitializeRoutedBucket>) -> Result<()> {
    let config = &mut ctx.accounts.config;
    let base_channel_id = config.next_channel_id;
    config.next_channel_id = base_channel_id
        .checked_add(ROUTED_BUCKET_CAPACITY as u64)
        .ok_or(RyvoError::MathOverflow)?;

    let mut bucket = ctx.accounts.bucket.load_init()?;
    bucket.gateway = ctx.accounts.gateway_participant.key();
    bucket.mint = ctx.accounts.mint.key();
    bucket.base_channel_id = base_channel_id;
    bucket.version = ROUTED_BUCKET_VERSION;

    emit!(RoutedBucketCreated {
        bucket: ctx.accounts.bucket.key(),
        gateway: bucket.gateway,
        mint: bucket.mint,
        base_channel_id,
        capacity: ROUTED_BUCKET_CAPACITY,
    });
    Ok(())
}

/// Occupy one permanent routed-channel slot. Both agent and gateway sign so an unrelated account
/// cannot consume gateway-funded bucket capacity.
#[derive(Accounts)]
pub struct CreateRoutedChannel<'info> {
    pub payer_owner: Signer<'info>,
    pub gateway_owner: Signer<'info>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), payer_owner.key().as_ref()],
        bump = payer_participant.bump,
    )]
    pub payer_participant: Box<Account<'info, Participant>>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), gateway_owner.key().as_ref()],
        bump = gateway_participant.bump,
    )]
    pub gateway_participant: Box<Account<'info, Participant>>,

    #[account(mut)]
    pub bucket: AccountLoader<'info, RoutedChannelBucket>,

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
            gateway_participant.key().as_ref(),
            gateway_balance.mint.as_ref(),
        ],
        bump = gateway_balance.bump,
    )]
    pub gateway_balance: Box<Account<'info, Balance>>,
}

pub fn create_routed_channel_handler(ctx: Context<CreateRoutedChannel>, slot: u8) -> Result<()> {
    require!(
        ctx.accounts.payer_participant.key() != ctx.accounts.gateway_participant.key(),
        RyvoError::SelfChannelNotAllowed
    );
    let bucket_key = ctx.accounts.bucket.key();
    let mut bucket = ctx.accounts.bucket.load_mut()?;
    require!(
        bucket.version == ROUTED_BUCKET_VERSION
            && bucket.gateway == ctx.accounts.gateway_participant.key()
            && bucket.mint == ctx.accounts.payer_balance.mint
            && bucket.mint == ctx.accounts.gateway_balance.mint,
        RyvoError::InvalidRoutedBucket
    );
    let i = slot as usize;
    require!(!bucket.is_occupied(i), RyvoError::RoutedSlotOccupied);
    let channel_id = bucket.channel_id(i).ok_or(RyvoError::InvalidRoutedSlot)?;
    let signer = ctx.accounts.payer_participant.authorized_signer;
    let packed = crate::commitment::pack_pubkey(&signer.to_bytes());

    bucket.occupy(i);
    bucket.payers[i] = ctx.accounts.payer_participant.key();
    bucket.signer_slot_0[i] = packed[0];
    bucket.signer_slot_1[i] = packed[1];

    emit!(RoutedChannelCreated {
        bucket: bucket_key,
        slot,
        channel_id,
        payer: bucket.payers[i],
        gateway: bucket.gateway,
        mint: bucket.mint,
        authorized_signer: signer,
    });
    Ok(())
}

#[derive(Accounts)]
pub struct RoutedChannelOp<'info> {
    pub payer_owner: Signer<'info>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), payer_owner.key().as_ref()],
        bump = payer_participant.bump,
    )]
    pub payer_participant: Box<Account<'info, Participant>>,

    #[account(seeds = [CONFIG_SEED.as_bytes()], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,

    #[account(mut)]
    pub bucket: AccountLoader<'info, RoutedChannelBucket>,

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
    bucket: &RoutedChannelBucket,
    slot: u8,
    payer: Pubkey,
    mint: Pubkey,
) -> Result<(usize, u64)> {
    let i = slot as usize;
    require!(
        bucket.version == ROUTED_BUCKET_VERSION && bucket.mint == mint,
        RyvoError::InvalidRoutedBucket
    );
    require!(
        bucket.is_occupied(i) && bucket.payers[i] == payer,
        RyvoError::InvalidRoutedSlot
    );
    let channel_id = bucket.channel_id(i).ok_or(RyvoError::InvalidRoutedSlot)?;
    Ok((i, channel_id))
}

pub fn lock_routed_channel_funds_handler(
    ctx: Context<RoutedChannelOp>,
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

    emit!(RoutedChannelFundsLocked {
        bucket: bucket_key,
        slot,
        channel_id,
        amount,
        locked_balance: bucket.locked_balance[i],
    });
    if cancelled > 0 {
        emit!(RoutedChannelUnlockCancelled {
            bucket: bucket_key,
            slot,
            channel_id,
            cancelled_amount: cancelled,
        });
    }
    Ok(())
}

pub fn request_unlock_routed_channel_funds_handler(
    ctx: Context<RoutedChannelOp>,
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

    emit!(RoutedChannelUnlockRequested {
        bucket: bucket_key,
        slot,
        channel_id,
        requested_amount: amount,
        unlock_at,
    });
    Ok(())
}

pub fn execute_unlock_routed_channel_funds_handler(
    ctx: Context<RoutedChannelOp>,
    slot: u8,
) -> Result<()> {
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

    emit!(RoutedChannelFundsUnlocked {
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
pub struct CooperativeUnlockRoutedChannelFunds<'info> {
    pub payer_owner: Signer<'info>,
    pub gateway_owner: Signer<'info>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), payer_owner.key().as_ref()],
        bump = payer_participant.bump,
    )]
    pub payer_participant: Box<Account<'info, Participant>>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), gateway_owner.key().as_ref()],
        bump = gateway_participant.bump,
    )]
    pub gateway_participant: Box<Account<'info, Participant>>,

    #[account(mut)]
    pub bucket: AccountLoader<'info, RoutedChannelBucket>,

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

pub fn cooperative_unlock_routed_channel_funds_handler(
    ctx: Context<CooperativeUnlockRoutedChannelFunds>,
    slot: u8,
    amount: u64,
) -> Result<()> {
    require!(amount > 0, RyvoError::AmountMustBePositive);
    let bucket_key = ctx.accounts.bucket.key();
    let mut bucket = ctx.accounts.bucket.load_mut()?;
    require!(
        bucket.gateway == ctx.accounts.gateway_participant.key(),
        RyvoError::InvalidRoutedBucket
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

    emit!(RoutedChannelFundsUnlocked {
        bucket: bucket_key,
        slot,
        channel_id,
        released_amount: released,
        remaining_locked: bucket.locked_balance[i],
        cooperative: true,
    });
    Ok(())
}
