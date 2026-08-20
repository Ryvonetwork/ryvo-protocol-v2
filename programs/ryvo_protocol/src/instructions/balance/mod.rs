use crate::constants::{BALANCE_SEED, PARTICIPANT_SEED, TOKEN_CONFIG_SEED, VAULT_SEED};
use crate::error::RyvoError;
use crate::events::{BalanceOpened, Deposited, Withdrawn};
use crate::state::{Balance, Participant, TokenConfig};
use anchor_lang::prelude::*;
use anchor_spl::token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked};

/// Create the per-(participant, mint) balance account.
///
/// Explicit rather than `init_if_needed` on `deposit`, so account creation can never be an
/// implicit side effect of a money-moving instruction. The rent payer need not be the
/// participant, so a payer can open a counterparty's balance for them — which is what makes
/// `create_channel`'s requirement that both balances exist a non-issue in practice.
#[derive(Accounts)]
pub struct OpenBalance<'info> {
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
        space = 8 + Balance::INIT_SPACE,
        seeds = [BALANCE_SEED.as_bytes(), participant.key().as_ref(), mint.key().as_ref()],
        bump,
    )]
    pub balance: Box<Account<'info, Balance>>,

    pub system_program: Program<'info, System>,
}

pub fn open_balance_handler(ctx: Context<OpenBalance>) -> Result<()> {
    let balance = &mut ctx.accounts.balance;
    balance.participant = ctx.accounts.participant.key();
    balance.mint = ctx.accounts.mint.key();
    balance.participant_id = ctx.accounts.participant.participant_id;
    balance.available = 0;
    balance.bump = ctx.bumps.balance;
    balance._reserved = [0u8; 88];

    emit!(BalanceOpened {
        balance: balance.key(),
        participant: ctx.accounts.participant.key(),
        mint: ctx.accounts.mint.key(),
    });
    Ok(())
}

/// Move tokens into the protocol vault and credit a participant.
///
/// The funder need not be the participant, which subsumes the prior design's batched
/// `deposit_for`: a client packs several `deposit` instructions into one transaction, with no
/// `remaining_accounts` iteration to audit.
#[derive(Accounts)]
pub struct Deposit<'info> {
    pub funder: Signer<'info>,

    pub mint: Box<Account<'info, Mint>>,

    #[account(
        seeds = [TOKEN_CONFIG_SEED.as_bytes(), mint.key().as_ref()],
        bump = token_config.bump,
        has_one = mint,
        has_one = vault,
    )]
    pub token_config: Box<Account<'info, TokenConfig>>,

    #[account(mut)]
    pub vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        token::mint = mint,
        token::authority = funder,
    )]
    pub funder_token_account: Box<Account<'info, TokenAccount>>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), participant.owner.as_ref()],
        bump = participant.bump,
    )]
    pub participant: Box<Account<'info, Participant>>,

    /// Seeds tie this balance to both the participant and the mint, so no stored-field comparison
    /// is needed to prove they agree.
    #[account(
        mut,
        seeds = [BALANCE_SEED.as_bytes(), participant.key().as_ref(), mint.key().as_ref()],
        bump = balance.bump,
    )]
    pub balance: Box<Account<'info, Balance>>,

    pub token_program: Program<'info, Token>,
}

pub fn deposit_handler(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    require!(amount > 0, RyvoError::AmountMustBePositive);
    require!(
        ctx.accounts.token_config.deposits_enabled,
        RyvoError::TokenDepositsDisabled
    );

    transfer_checked(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            TransferChecked {
                from: ctx.accounts.funder_token_account.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
                authority: ctx.accounts.funder.to_account_info(),
            },
        ),
        amount,
        ctx.accounts.token_config.decimals,
    )?;

    let balance = &mut ctx.accounts.balance;
    balance.available = balance
        .available
        .checked_add(amount)
        .ok_or(RyvoError::MathOverflow)?;

    emit!(Deposited {
        balance: balance.key(),
        participant: ctx.accounts.participant.key(),
        mint: ctx.accounts.mint.key(),
        funder: ctx.accounts.funder.key(),
        amount,
        available: balance.available,
    });
    Ok(())
}

/// Withdraw unlocked balance. Immediate — there is no timelock and no pending state.
///
/// This is safe precisely because settlement cannot reach `available`: a commitment is payable
/// only from the channel's `locked_balance`, so free balance is free in the literal sense and no
/// counterparty has a claim on it that a delay would need to protect.
///
/// Note `deposits_enabled` is deliberately not checked. Pausing a mint stops intake; it must never
/// block an exit, or it would be a fund-freeze switch.
#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub owner: Signer<'info>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), owner.key().as_ref()],
        bump = participant.bump,
        has_one = owner,
    )]
    pub participant: Box<Account<'info, Participant>>,

    pub mint: Box<Account<'info, Mint>>,

    /// Read-only, and that matters. This account is the vault's signing authority and the source
    /// of `decimals`, but nothing here writes it. Marking it `mut` would take a *write* lock,
    /// which serialises every withdrawal of the same mint against every other — a throughput
    /// ceiling bought for nothing, since read locks are shared.
    #[account(
        seeds = [TOKEN_CONFIG_SEED.as_bytes(), mint.key().as_ref()],
        bump = token_config.bump,
        has_one = mint,
        has_one = vault,
    )]
    pub token_config: Box<Account<'info, TokenConfig>>,

    #[account(
        mut,
        seeds = [VAULT_SEED.as_bytes(), mint.key().as_ref()],
        bump,
    )]
    pub vault: Box<Account<'info, TokenAccount>>,

    #[account(
        mut,
        seeds = [BALANCE_SEED.as_bytes(), participant.key().as_ref(), mint.key().as_ref()],
        bump = balance.bump,
    )]
    pub balance: Box<Account<'info, Balance>>,

    #[account(mut, token::mint = mint)]
    pub destination: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

pub fn withdraw_handler(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    require!(amount > 0, RyvoError::AmountMustBePositive);
    require!(
        amount <= ctx.accounts.balance.available,
        RyvoError::InsufficientBalance
    );
    require!(
        ctx.accounts.destination.key() != ctx.accounts.vault.key(),
        RyvoError::InvalidWithdrawalDestination
    );

    let mint_key = ctx.accounts.mint.key();
    let bump = ctx.accounts.token_config.bump;
    let seeds: &[&[u8]] = &[TOKEN_CONFIG_SEED.as_bytes(), mint_key.as_ref(), &[bump]];

    // The full amount leaves. The protocol takes no cut: a payment moves numbers between two
    // ledger rows and the tokens never leave the vault, so there is no on-chain service to charge
    // for.
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

    let balance = &mut ctx.accounts.balance;
    balance.available = balance
        .available
        .checked_sub(amount)
        .ok_or(RyvoError::MathOverflow)?;

    emit!(Withdrawn {
        balance: balance.key(),
        participant: ctx.accounts.participant.key(),
        mint: mint_key,
        amount,
        destination: ctx.accounts.destination.key(),
        available: balance.available,
    });
    Ok(())
}
