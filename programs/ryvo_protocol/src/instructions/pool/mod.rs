use crate::constants::{BALANCE_SEED, CONFIG_SEED, PARTICIPANT_SEED, POOL_SEED, TOKEN_CONFIG_SEED};
use crate::error::RyvoError;
use crate::events::{RoutePoolFunded, RoutePoolOpened, RoutePoolUnlockRequested, RoutePoolUnlocked};
use crate::state::{Balance, Config, Participant, RoutePool, TokenConfig};
use anchor_lang::prelude::*;
use anchor_spl::token::Mint;

/// Create a gateway's pool for one mint. Anyone may pay the rent (as with `open_balance`), so a
/// provider can make sure the gateway it is about to serve has one. Must exist before a route
/// naming this gateway can settle.
#[derive(Accounts)]
pub struct OpenRoutePool<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), participant.owner.as_ref()],
        bump = participant.bump,
    )]
    pub participant: Box<Account<'info, Participant>>,

    pub mint: Box<Account<'info, Mint>>,

    #[account(
        seeds = [TOKEN_CONFIG_SEED.as_bytes(), mint.key().as_ref()],
        bump = token_config.bump,
        has_one = mint,
    )]
    pub token_config: Box<Account<'info, TokenConfig>>,

    #[account(
        init,
        payer = payer,
        space = 8 + RoutePool::INIT_SPACE,
        seeds = [POOL_SEED.as_bytes(), participant.key().as_ref(), mint.key().as_ref()],
        bump,
    )]
    pub pool: Box<Account<'info, RoutePool>>,

    pub system_program: Program<'info, System>,
}

pub fn open_route_pool_handler(ctx: Context<OpenRoutePool>) -> Result<()> {
    let pool = &mut ctx.accounts.pool;
    pool.participant = ctx.accounts.participant.key();
    pool.mint = ctx.accounts.mint.key();
    pool.balance = 0;
    pool.pending_unlock_amount = 0;
    pool.pending_unlock_at = 0;
    pool.bump = ctx.bumps.pool;
    pool._reserved = [0u8; 96];
    emit!(RoutePoolOpened { pool: pool.key(), participant: pool.participant, mint: pool.mint });
    Ok(())
}

/// Shared account set for the gateway-signed pool operations. Seeds tie `pool` and `balance`
/// to the signer's participant and the pool's mint.
#[derive(Accounts)]
pub struct PoolOp<'info> {
    pub owner: Signer<'info>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), owner.key().as_ref()],
        bump = participant.bump,
    )]
    pub participant: Box<Account<'info, Participant>>,

    #[account(seeds = [CONFIG_SEED.as_bytes()], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,

    #[account(
        mut,
        seeds = [POOL_SEED.as_bytes(), participant.key().as_ref(), pool.mint.as_ref()],
        bump = pool.bump,
    )]
    pub pool: Box<Account<'info, RoutePool>>,

    #[account(
        mut,
        seeds = [BALANCE_SEED.as_bytes(), participant.key().as_ref(), pool.mint.as_ref()],
        bump = balance.bump,
    )]
    pub balance: Box<Account<'info, Balance>>,
}

/// Move free balance into the pool — the gateway extending credit to its providers ahead of
/// agent inflows. Cancels a pending withdrawal, for the same reason `lock_channel_funds` does.
pub fn fund_route_pool_handler(ctx: Context<PoolOp>, amount: u64) -> Result<()> {
    require!(amount > 0, RyvoError::AmountMustBePositive);
    require!(amount <= ctx.accounts.balance.available, RyvoError::InsufficientBalance);
    let balance = &mut ctx.accounts.balance;
    balance.available = balance.available.checked_sub(amount).ok_or(RyvoError::MathOverflow)?;
    let pool = &mut ctx.accounts.pool;
    pool.balance = pool.balance.checked_add(amount).ok_or(RyvoError::MathOverflow)?;
    let cancelled = pool.pending_unlock_amount;
    pool.pending_unlock_amount = 0;
    pool.pending_unlock_at = 0;
    emit!(RoutePoolFunded { pool: pool.key(), amount, balance: pool.balance, cancelled_unlock: cancelled });
    Ok(())
}

/// Start the timelock on taking float out of the pool. Re-request overwrites and always pushes
/// the deadline out, never in.
pub fn request_pool_unlock_handler(ctx: Context<PoolOp>, amount: u64) -> Result<()> {
    require!(amount > 0, RyvoError::AmountMustBePositive);
    require!(amount <= ctx.accounts.pool.balance, RyvoError::InsufficientPoolBalance);
    let unlock_at = Clock::get()?
        .unix_timestamp
        .checked_add(ctx.accounts.config.channel_timelock_seconds)
        .ok_or(RyvoError::MathOverflow)?;
    let pool = &mut ctx.accounts.pool;
    pool.pending_unlock_amount = amount;
    pool.pending_unlock_at = unlock_at;
    emit!(RoutePoolUnlockRequested { pool: pool.key(), requested_amount: amount, unlock_at });
    Ok(())
}

/// Release `min(pending, balance)` to the gateway's free balance once the timelock has passed.
/// Clamped at execute time because providers may have been paid from the pool meanwhile.
pub fn execute_pool_unlock_handler(ctx: Context<PoolOp>) -> Result<()> {
    let pending = ctx.accounts.pool.pending_unlock_amount;
    require!(pending > 0, RyvoError::NoPoolUnlockPending);
    require!(
        Clock::get()?.unix_timestamp >= ctx.accounts.pool.pending_unlock_at,
        RyvoError::PoolUnlockLocked
    );
    let released = pending.min(ctx.accounts.pool.balance);
    let pool = &mut ctx.accounts.pool;
    pool.balance = pool.balance.checked_sub(released).ok_or(RyvoError::MathOverflow)?;
    pool.pending_unlock_amount = 0;
    pool.pending_unlock_at = 0;
    let remaining = pool.balance;
    let pool_key = pool.key();
    let balance = &mut ctx.accounts.balance;
    balance.available = balance.available.checked_add(released).ok_or(RyvoError::MathOverflow)?;
    emit!(RoutePoolUnlocked { pool: pool_key, released_amount: released, remaining });
    Ok(())
}
