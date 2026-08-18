use crate::constants::{CONFIG_SEED, MAX_MINT_DECIMALS, TOKEN_CONFIG_SEED, VAULT_SEED};
use crate::error::RyvoError;
use crate::events::{TokenDepositEnabledChanged, TokenRegistered};
use crate::state::{Config, TokenConfig};
use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, Token, TokenAccount};

/// Allowlist a mint and create its vault.
///
/// `Program<'info, Token>` plus `Account<'info, Mint>` from `anchor_spl::token` pin this to the
/// legacy SPL Token program: a token-2022 mint is owned by a different program and fails the
/// ownership check. That matters because transfer fees, transfer hooks and confidential
/// transfers would each break the solvency invariant
/// `vault.amount == sum(available) + sum(locked)`.
#[derive(Accounts)]
pub struct RegisterToken<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        seeds = [CONFIG_SEED.as_bytes()],
        bump = config.bump,
        has_one = authority,
    )]
    pub config: Box<Account<'info, Config>>,

    pub mint: Box<Account<'info, Mint>>,

    #[account(
        init,
        payer = authority,
        space = 8 + TokenConfig::INIT_SPACE,
        seeds = [TOKEN_CONFIG_SEED.as_bytes(), mint.key().as_ref()],
        bump,
    )]
    pub token_config: Box<Account<'info, TokenConfig>>,

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
    pub vault: Box<Account<'info, TokenAccount>>,

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
    token_config.decimals = mint.decimals;
    token_config.deposits_enabled = true;
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
pub struct SetTokenDepositEnabled<'info> {
    pub authority: Signer<'info>,

    #[account(
        seeds = [CONFIG_SEED.as_bytes()],
        bump = config.bump,
        has_one = authority,
    )]
    pub config: Box<Account<'info, Config>>,

    #[account(
        mut,
        seeds = [TOKEN_CONFIG_SEED.as_bytes(), token_config.mint.as_ref()],
        bump = token_config.bump,
    )]
    pub token_config: Box<Account<'info, TokenConfig>>,
}

/// Stop or resume deposits for one mint.
///
/// This is the only thing the flag does. Withdrawals, channel operations and settlement never
/// consult it, so it can pause intake without ever trapping funds.
pub fn set_token_deposit_enabled_handler(
    ctx: Context<SetTokenDepositEnabled>,
    deposits_enabled: bool,
) -> Result<()> {
    let token_config = &mut ctx.accounts.token_config;
    token_config.deposits_enabled = deposits_enabled;

    emit!(TokenDepositEnabledChanged {
        mint: token_config.mint,
        deposits_enabled,
    });
    Ok(())
}
