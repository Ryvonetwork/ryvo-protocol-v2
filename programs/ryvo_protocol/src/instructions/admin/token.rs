use crate::constants::{CONFIG_SEED, MAX_MINT_DECIMALS, TOKEN_CONFIG_SEED, VAULT_SEED};
use crate::error::RyvoError;
use crate::events::{ProtocolFeesWithdrawn, TokenEnabledChanged, TokenRegistered};
use crate::state::{Config, TokenConfig};
use anchor_lang::prelude::*;
use anchor_spl::token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked};

/// Allowlist a mint and create its vault.
///
/// `Program<'info, Token>` plus `Account<'info, Mint>` from `anchor_spl::token` pin this to the
/// legacy SPL Token program: a token-2022 mint is owned by a different program and fails the
/// ownership check. That matters because transfer fees, transfer hooks and confidential
/// transfers would each break the solvency invariant
/// `vault.amount == sum(available) + sum(locked) + accrued_fees`.
#[derive(Accounts)]
pub struct RegisterToken<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        seeds = [CONFIG_SEED.as_bytes()],
        bump = config.bump,
        has_one = authority,
    )]
    pub config: Account<'info, Config>,

    pub mint: Account<'info, Mint>,

    #[account(
        init,
        payer = authority,
        space = 8 + TokenConfig::INIT_SPACE,
        seeds = [TOKEN_CONFIG_SEED.as_bytes(), mint.key().as_ref()],
        bump,
    )]
    pub token_config: Account<'info, TokenConfig>,

    /// Vault authority is `token_config`, per mint rather than the global `Config`, so a
    /// signer-seed mistake for one mint cannot reach another mint's vault.
    #[account(
        init,
        payer = authority,
        seeds = [VAULT_SEED.as_bytes(), mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = token_config,
    )]
    pub vault: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

pub fn register_token_handler(ctx: Context<RegisterToken>) -> Result<()> {
    let mint = &ctx.accounts.mint;
    require!(
        mint.decimals <= MAX_MINT_DECIMALS,
        RyvoError::InvalidTokenDecimals
    );

    let token_config = &mut ctx.accounts.token_config;
    token_config.mint = mint.key();
    token_config.vault = ctx.accounts.vault.key();
    token_config.accrued_fees = 0;
    token_config.decimals = mint.decimals;
    token_config.enabled = true;
    token_config.bump = ctx.bumps.token_config;
    token_config._reserved = [0u8; 96];

    emit!(TokenRegistered {
        mint: mint.key(),
        vault: ctx.accounts.vault.key(),
        decimals: mint.decimals,
    });
    Ok(())
}

#[derive(Accounts)]
pub struct SetTokenEnabled<'info> {
    pub authority: Signer<'info>,

    #[account(
        seeds = [CONFIG_SEED.as_bytes()],
        bump = config.bump,
        has_one = authority,
    )]
    pub config: Account<'info, Config>,

    #[account(
        mut,
        seeds = [TOKEN_CONFIG_SEED.as_bytes(), token_config.mint.as_ref()],
        bump = token_config.bump,
    )]
    pub token_config: Account<'info, TokenConfig>,
}

/// Gates *entry* only. Callers must never consult this flag on a withdrawal, an unlock, or
/// settlement — doing so would turn a pause into a fund freeze.
pub fn set_token_enabled_handler(ctx: Context<SetTokenEnabled>, enabled: bool) -> Result<()> {
    let token_config = &mut ctx.accounts.token_config;
    token_config.enabled = enabled;

    emit!(TokenEnabledChanged {
        mint: token_config.mint,
        enabled,
    });
    Ok(())
}

/// The only admin instruction that moves tokens, and it is bounded by `accrued_fees`.
///
/// Fees accumulate inside the vault rather than being pushed to an external account during each
/// user withdrawal, because a frozen, closed or missing fee account would otherwise break *user*
/// exits.
#[derive(Accounts)]
pub struct WithdrawProtocolFees<'info> {
    pub authority: Signer<'info>,

    #[account(
        seeds = [CONFIG_SEED.as_bytes()],
        bump = config.bump,
        has_one = authority,
    )]
    pub config: Account<'info, Config>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        seeds = [TOKEN_CONFIG_SEED.as_bytes(), mint.key().as_ref()],
        bump = token_config.bump,
        has_one = mint,
        has_one = vault,
    )]
    pub token_config: Account<'info, TokenConfig>,

    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        token::mint = mint,
        constraint = destination.owner == config.fee_recipient @ RyvoError::InvalidFeeRecipient,
    )]
    pub destination: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

pub fn withdraw_protocol_fees_handler(
    ctx: Context<WithdrawProtocolFees>,
    amount: u64,
) -> Result<()> {
    require!(amount > 0, RyvoError::AmountMustBePositive);
    require!(
        amount <= ctx.accounts.token_config.accrued_fees,
        RyvoError::InsufficientProtocolFees
    );

    let mint_key = ctx.accounts.mint.key();
    let bump = ctx.accounts.token_config.bump;
    let seeds: &[&[u8]] = &[TOKEN_CONFIG_SEED.as_bytes(), mint_key.as_ref(), &[bump]];

    transfer_checked(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            TransferChecked {
                from: ctx.accounts.vault.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.destination.to_account_info(),
                authority: ctx.accounts.token_config.to_account_info(),
            },
            &[seeds],
        ),
        amount,
        ctx.accounts.token_config.decimals,
    )?;

    let token_config = &mut ctx.accounts.token_config;
    token_config.accrued_fees = token_config
        .accrued_fees
        .checked_sub(amount)
        .ok_or(RyvoError::MathOverflow)?;

    emit!(ProtocolFeesWithdrawn {
        mint: mint_key,
        amount,
        destination: ctx.accounts.destination.key(),
        remaining_accrued: token_config.accrued_fees,
    });
    Ok(())
}
