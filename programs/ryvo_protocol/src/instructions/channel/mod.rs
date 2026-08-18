use crate::constants::{
    BALANCE_SEED, CHANNEL_SEED, CONFIG_SEED, PARTICIPANT_SEED, TOKEN_CONFIG_SEED,
};
use crate::error::RyvoError;
use crate::events::{
    ChannelCreated, ChannelFundsLocked, ChannelFundsUnlocked, ChannelUnlockRequested,
};
use crate::state::{Balance, Channel, Config, Participant, TokenConfig};
use anchor_lang::prelude::*;
use anchor_spl::token::Mint;

/// Open a one-way payment relationship. No payee involvement: opening a channel to someone costs
/// them nothing and only enables paying them.
///
/// Both parties' `Balance` accounts must already exist and are passed read-only. That is a
/// forward-compatibility requirement, not a convenience: the v2 settlement applier cannot create
/// accounts, so a channel whose payee has no balance for the mint would produce settlements that can
/// never be applied, stranding funds until the unlock timelock. `open_balance` lets the payer
/// create the payee's balance for them, so this needs no coordination.
///
/// `authorized_signer` is required rather than defaulting to the payer's wallet. Under
/// Arcium-only settlement a commitment must be signed with SHA3-512 (ArcisEd25519), which a
/// browser or hardware wallet cannot do — so a wallet default would silently create channels that
/// can never yield a settleable commitment, discovered only after funds were locked.
#[derive(Accounts)]
pub struct CreateChannel<'info> {
    #[account(mut)]
    pub payer_owner: Signer<'info>,

    /// Written: hands out the next `channel_id`. This is the only place settlement-unrelated
    /// traffic takes a write lock on the singleton, and channel creation is rare.
    #[account(
        mut,
        seeds = [CONFIG_SEED.as_bytes()],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, Config>>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), payer_owner.key().as_ref()],
        bump = payer_participant.bump,
    )]
    pub payer_participant: Box<Account<'info, Participant>>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), payee_participant.owner.as_ref()],
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
        seeds = [BALANCE_SEED.as_bytes(), payer_participant.key().as_ref(), mint.key().as_ref()],
        bump = payer_balance.bump,
    )]
    pub payer_balance: Box<Account<'info, Balance>>,

    #[account(
        seeds = [BALANCE_SEED.as_bytes(), payee_participant.key().as_ref(), mint.key().as_ref()],
        bump = payee_balance.bump,
    )]
    pub payee_balance: Box<Account<'info, Balance>>,

    #[account(
        init,
        payer = payer_owner,
        space = 8 + Channel::INIT_SPACE,
        seeds = [
            CHANNEL_SEED.as_bytes(),
            payer_participant.key().as_ref(),
            payee_participant.key().as_ref(),
            mint.key().as_ref(),
        ],
        bump,
    )]
    pub channel: Box<Account<'info, Channel>>,

    pub system_program: Program<'info, System>,
}

pub fn create_channel_handler(
    ctx: Context<CreateChannel>,
    authorized_signer: Pubkey,
) -> Result<()> {
    require!(
        ctx.accounts.payer_participant.key() != ctx.accounts.payee_participant.key(),
        RyvoError::SelfChannelNotAllowed
    );
    require!(
        authorized_signer != Pubkey::default(),
        RyvoError::InvalidAuthorizedSigner
    );

    let config = &mut ctx.accounts.config;
    let channel_id = config.next_channel_id;
    config.next_channel_id = channel_id.checked_add(1).ok_or(RyvoError::MathOverflow)?;

    let channel = &mut ctx.accounts.channel;
    channel.channel_id = channel_id;
    channel.payer = ctx.accounts.payer_participant.key();
    channel.payee = ctx.accounts.payee_participant.key();
    channel.mint = ctx.accounts.mint.key();
    channel.authorized_signer = authorized_signer;
    channel.settled_cumulative = 0;
    channel.locked_balance = 0;
    channel.pending_unlock_amount = 0;
    channel.pending_unlock_at = 0;
    channel.bump = ctx.bumps.channel;
    channel._reserved = [0u8; 88];

    emit!(ChannelCreated {
        channel: channel.key(),
        payer: channel.payer,
        payee: channel.payee,
        mint: channel.mint,
        authorized_signer,
        channel_id,
    });
    Ok(())
}

/// Shared account set for the payer-signed channel operations.
///
/// Note there is nothing to cross-check by hand: the seeds on `channel` and `payer_balance` both
/// include the payer participant and the mint, so Anchor's constraints alone prove the two refer
/// to the same payer and the same asset.
#[derive(Accounts)]
pub struct PayerChannelOp<'info> {
    pub payer_owner: Signer<'info>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), payer_owner.key().as_ref()],
        bump = payer_participant.bump,
    )]
    pub payer_participant: Box<Account<'info, Participant>>,

    #[account(
        seeds = [CONFIG_SEED.as_bytes()],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, Config>>,

    #[account(
        mut,
        seeds = [
            CHANNEL_SEED.as_bytes(),
            payer_participant.key().as_ref(),
            channel.payee.as_ref(),
            channel.mint.as_ref(),
        ],
        bump = channel.bump,
    )]
    pub channel: Box<Account<'info, Channel>>,

    #[account(
        mut,
        seeds = [BALANCE_SEED.as_bytes(), payer_participant.key().as_ref(), channel.mint.as_ref()],
        bump = payer_balance.bump,
    )]
    pub payer_balance: Box<Account<'info, Balance>>,
}

// No `token_config` here. It was only ever read for the deposit gate, and the channel's existence
// already proves the mint was allowlisted when it was opened — so carrying it would be an account
// lock per transaction bought for nothing.

/// Move funds from shared available balance into this channel's lock.
///
/// No tokens move: the vault total is unchanged, only the ledger split between `available` and
/// `locked_balance`. Locked funds cannot be withdrawn and cannot fund another channel.
pub fn lock_channel_funds_handler(ctx: Context<PayerChannelOp>, amount: u64) -> Result<()> {
    require!(amount > 0, RyvoError::AmountMustBePositive);
    require!(
        amount <= ctx.accounts.payer_balance.available,
        RyvoError::InsufficientBalance
    );

    let balance = &mut ctx.accounts.payer_balance;
    balance.available = balance
        .available
        .checked_sub(amount)
        .ok_or(RyvoError::MathOverflow)?;

    let channel = &mut ctx.accounts.channel;
    channel.locked_balance = channel
        .locked_balance
        .checked_add(amount)
        .ok_or(RyvoError::MathOverflow)?;

    emit!(ChannelFundsLocked {
        channel: channel.key(),
        amount,
        locked_balance: channel.locked_balance,
    });
    Ok(())
}

/// Start the timelock on releasing locked collateral.
///
/// A re-request overwrites any outstanding one and always pushes the deadline out, never in. That
/// is what makes a cancel instruction unnecessary and is why `execute` is payer-signed: a stale
/// request cannot be triggered later by a stranger.
pub fn request_unlock_channel_funds_handler(
    ctx: Context<PayerChannelOp>,
    amount: u64,
) -> Result<()> {
    require!(amount > 0, RyvoError::AmountMustBePositive);
    require!(
        amount <= ctx.accounts.channel.locked_balance,
        RyvoError::InsufficientLockedBalance
    );

    let unlock_at = Clock::get()?
        .unix_timestamp
        .checked_add(ctx.accounts.config.channel_timelock_seconds)
        .ok_or(RyvoError::MathOverflow)?;

    let channel = &mut ctx.accounts.channel;
    channel.pending_unlock_amount = amount;
    channel.pending_unlock_at = unlock_at;

    emit!(ChannelUnlockRequested {
        channel: channel.key(),
        requested_amount: amount,
        unlock_at,
    });
    Ok(())
}

pub fn execute_unlock_channel_funds_handler(ctx: Context<PayerChannelOp>) -> Result<()> {
    let channel_pending = ctx.accounts.channel.pending_unlock_amount;
    require!(channel_pending > 0, RyvoError::NoChannelUnlockPending);
    require!(
        Clock::get()?.unix_timestamp >= ctx.accounts.channel.pending_unlock_at,
        RyvoError::ChannelUnlockLocked
    );

    // Clamped at execute time, not request time: settlement may already have consumed part of the
    // lock, in which case only the remainder is released.
    let released = channel_pending.min(ctx.accounts.channel.locked_balance);

    let channel = &mut ctx.accounts.channel;
    channel.locked_balance = channel
        .locked_balance
        .checked_sub(released)
        .ok_or(RyvoError::MathOverflow)?;
    channel.pending_unlock_amount = 0;
    channel.pending_unlock_at = 0;
    let remaining_locked = channel.locked_balance;
    let channel_key = channel.key();

    let balance = &mut ctx.accounts.payer_balance;
    balance.available = balance
        .available
        .checked_add(released)
        .ok_or(RyvoError::MathOverflow)?;

    emit!(ChannelFundsUnlocked {
        channel: channel_key,
        released_amount: released,
        remaining_locked,
        cooperative: false,
    });
    Ok(())
}

/// Release collateral immediately with both parties' consent.
///
/// No timelock is needed because the party the timelock protects — the payee — is signing.
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

    #[account(
        mut,
        seeds = [
            CHANNEL_SEED.as_bytes(),
            payer_participant.key().as_ref(),
            payee_participant.key().as_ref(),
            channel.mint.as_ref(),
        ],
        bump = channel.bump,
    )]
    pub channel: Box<Account<'info, Channel>>,

    #[account(
        mut,
        seeds = [BALANCE_SEED.as_bytes(), payer_participant.key().as_ref(), channel.mint.as_ref()],
        bump = payer_balance.bump,
    )]
    pub payer_balance: Box<Account<'info, Balance>>,
}

pub fn cooperative_unlock_channel_funds_handler(
    ctx: Context<CooperativeUnlockChannelFunds>,
    amount: u64,
) -> Result<()> {
    require!(amount > 0, RyvoError::AmountMustBePositive);

    let released = amount.min(ctx.accounts.channel.locked_balance);
    require!(released > 0, RyvoError::InsufficientLockedBalance);

    let channel = &mut ctx.accounts.channel;
    channel.locked_balance = channel
        .locked_balance
        .checked_sub(released)
        .ok_or(RyvoError::MathOverflow)?;
    // A cooperative release supersedes any outstanding unilateral request.
    channel.pending_unlock_amount = 0;
    channel.pending_unlock_at = 0;
    let remaining_locked = channel.locked_balance;
    let channel_key = channel.key();

    let balance = &mut ctx.accounts.payer_balance;
    balance.available = balance
        .available
        .checked_add(released)
        .ok_or(RyvoError::MathOverflow)?;

    emit!(ChannelFundsUnlocked {
        channel: channel_key,
        released_amount: released,
        remaining_locked,
        cooperative: true,
    });
    Ok(())
}
