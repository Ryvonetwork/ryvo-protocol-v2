use crate::constants::{
    BALANCE_SEED, BPS_DENOMINATOR, CONFIG_SEED, PARTICIPANT_SEED, TOKEN_CONFIG_SEED, VAULT_SEED,
};
use crate::error::RyvoError;
use crate::events::{
    BalanceOpened, Deposited, WithdrawalCancelled, WithdrawalRequested, Withdrawn,
};
use crate::state::{Balance, Config, Participant, TokenConfig};
use anchor_lang::prelude::*;
use anchor_spl::token::{transfer_checked, Mint, Token, TokenAccount, TransferChecked};

/// Create the per-(participant, mint) balance account.
///
/// Explicit rather than `init_if_needed` on `deposit`, so account creation can never be an
/// implicit side effect of a money-moving instruction. The rent payer may be anyone, which lets an
/// operator open balances on a user's behalf.
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
    balance.available = 0;
    balance.pending_withdrawal_amount = 0;
    balance.withdrawal_unlock_at = 0;
    balance.withdrawal_destination = Pubkey::default();
    balance.bump = ctx.bumps.balance;
    balance._reserved = [0u8; 96];

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
/// `deposit_for`: a client simply packs several `deposit` instructions into one transaction,
/// with no `remaining_accounts` iteration to audit.
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
    require!(ctx.accounts.token_config.enabled, RyvoError::TokenDisabled);

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

/// Record intent to withdraw. Deliberately moves no funds.
///
/// Reserving a balance here would create a third tier that is senior to nothing: settlement must
/// still be able to consume it, so "reserved" would be a lie in the state. Instead
/// `execute_withdrawal` pays `min(pending, available)`, which makes "a pending withdrawal is not
/// senior to settlement" true by construction.
#[derive(Accounts)]
pub struct RequestWithdrawal<'info> {
    pub owner: Signer<'info>,

    #[account(
        seeds = [CONFIG_SEED.as_bytes()],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, Config>>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), owner.key().as_ref()],
        bump = participant.bump,
        has_one = owner,
    )]
    pub participant: Box<Account<'info, Participant>>,

    pub mint: Box<Account<'info, Mint>>,

    #[account(
        mut,
        seeds = [BALANCE_SEED.as_bytes(), participant.key().as_ref(), mint.key().as_ref()],
        bump = balance.bump,
    )]
    pub balance: Box<Account<'info, Balance>>,

    /// Recorded now and the only account `execute_withdrawal` may pay.
    #[account(token::mint = mint)]
    pub destination: Box<Account<'info, TokenAccount>>,

    #[account(
        seeds = [VAULT_SEED.as_bytes(), mint.key().as_ref()],
        bump,
    )]
    pub vault: Box<Account<'info, TokenAccount>>,
}

pub fn request_withdrawal_handler(ctx: Context<RequestWithdrawal>, amount: u64) -> Result<()> {
    let balance = &mut ctx.accounts.balance;
    require!(
        balance.pending_withdrawal_amount == 0,
        RyvoError::WithdrawalAlreadyPending
    );
    require!(amount > 0, RyvoError::AmountMustBePositive);
    // Checked for the caller's benefit; the authoritative clamp is at execute time.
    require!(amount <= balance.available, RyvoError::InsufficientBalance);
    require!(
        ctx.accounts.destination.key() != ctx.accounts.vault.key(),
        RyvoError::InvalidWithdrawalDestination
    );

    let unlock_at = Clock::get()?
        .unix_timestamp
        .checked_add(ctx.accounts.config.withdrawal_timelock_seconds)
        .ok_or(RyvoError::MathOverflow)?;

    balance.pending_withdrawal_amount = amount;
    balance.withdrawal_destination = ctx.accounts.destination.key();
    balance.withdrawal_unlock_at = unlock_at;

    emit!(WithdrawalRequested {
        balance: balance.key(),
        participant: ctx.accounts.participant.key(),
        mint: ctx.accounts.mint.key(),
        amount,
        destination: ctx.accounts.destination.key(),
        unlock_at,
    });
    Ok(())
}

#[derive(Accounts)]
pub struct CancelWithdrawal<'info> {
    pub owner: Signer<'info>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), owner.key().as_ref()],
        bump = participant.bump,
        has_one = owner,
    )]
    pub participant: Box<Account<'info, Participant>>,

    #[account(
        mut,
        seeds = [BALANCE_SEED.as_bytes(), participant.key().as_ref(), balance.mint.as_ref()],
        bump = balance.bump,
    )]
    pub balance: Box<Account<'info, Balance>>,
}

pub fn cancel_withdrawal_handler(ctx: Context<CancelWithdrawal>) -> Result<()> {
    let balance = &mut ctx.accounts.balance;
    require!(
        balance.pending_withdrawal_amount > 0,
        RyvoError::NoWithdrawalPending
    );

    let amount_cancelled = balance.pending_withdrawal_amount;
    balance.pending_withdrawal_amount = 0;
    balance.withdrawal_unlock_at = 0;
    balance.withdrawal_destination = Pubkey::default();

    emit!(WithdrawalCancelled {
        balance: balance.key(),
        participant: ctx.accounts.participant.key(),
        mint: balance.mint,
        amount_cancelled,
    });
    Ok(())
}

/// Pay out a matured withdrawal. **Permissionless** — no signer.
///
/// The destination was fixed at request time, so anyone pushing a matured withdrawal can only send
/// funds where the owner already chose. That means a user who has lost their signing key can still
/// have their exit completed by a crank.
/// Every account is `Box`ed. Deserializing this many accounts inline overflows the 4KB SBF stack
/// frame — it fails at runtime with "Access violation in stack frame", not at compile time, so it
/// is worth being deliberate about rather than discovering per instruction.
#[derive(Accounts)]
pub struct ExecuteWithdrawal<'info> {
    #[account(
        seeds = [CONFIG_SEED.as_bytes()],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, Config>>,

    pub mint: Box<Account<'info, Mint>>,

    #[account(
        mut,
        seeds = [TOKEN_CONFIG_SEED.as_bytes(), mint.key().as_ref()],
        bump = token_config.bump,
        has_one = mint,
        has_one = vault,
    )]
    pub token_config: Box<Account<'info, TokenConfig>>,

    #[account(mut)]
    pub vault: Box<Account<'info, TokenAccount>>,

    #[account(
        seeds = [PARTICIPANT_SEED.as_bytes(), participant.owner.as_ref()],
        bump = participant.bump,
    )]
    pub participant: Box<Account<'info, Participant>>,

    #[account(
        mut,
        seeds = [BALANCE_SEED.as_bytes(), participant.key().as_ref(), mint.key().as_ref()],
        bump = balance.bump,
    )]
    pub balance: Box<Account<'info, Balance>>,

    /// Destination equality is checked in the handler rather than as an account constraint, so
    /// that "nothing is pending" reports `NoWithdrawalPending` instead of the misleading
    /// `InvalidWithdrawalDestination` a constraint would raise first (a settled withdrawal resets
    /// the stored destination to the default pubkey).
    #[account(mut, token::mint = mint)]
    pub destination: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
}

pub fn execute_withdrawal_handler(ctx: Context<ExecuteWithdrawal>) -> Result<()> {
    let pending = ctx.accounts.balance.pending_withdrawal_amount;
    require!(pending > 0, RyvoError::NoWithdrawalPending);
    require!(
        ctx.accounts.destination.key() == ctx.accounts.balance.withdrawal_destination,
        RyvoError::InvalidWithdrawalDestination
    );
    require!(
        Clock::get()?.unix_timestamp >= ctx.accounts.balance.withdrawal_unlock_at,
        RyvoError::WithdrawalLocked
    );

    // Settlement may have consumed the balance since the request. Paying the residual — possibly
    // zero — is the whole point: "requested for withdrawal" is not stronger than "already spent".
    let gross = pending.min(ctx.accounts.balance.available);

    let fee = ((gross as u128)
        .checked_mul(ctx.accounts.config.fee_bps as u128)
        .ok_or(RyvoError::MathOverflow)?
        / BPS_DENOMINATOR) as u64;
    let net = gross.checked_sub(fee).ok_or(RyvoError::MathOverflow)?;

    if gross > 0 {
        let mint_key = ctx.accounts.mint.key();
        let bump = ctx.accounts.token_config.bump;
        let seeds: &[&[u8]] = &[TOKEN_CONFIG_SEED.as_bytes(), mint_key.as_ref(), &[bump]];

        if net > 0 {
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
                net,
                ctx.accounts.token_config.decimals,
            )?;
        }

        // The fee stays in the vault, tracked as accrued. It is never pushed to an external
        // account here, so a frozen or closed fee account cannot break a user's exit.
        let token_config = &mut ctx.accounts.token_config;
        token_config.accrued_fees = token_config
            .accrued_fees
            .checked_add(fee)
            .ok_or(RyvoError::MathOverflow)?;

        let balance = &mut ctx.accounts.balance;
        balance.available = balance
            .available
            .checked_sub(gross)
            .ok_or(RyvoError::MathOverflow)?;
    }

    let balance = &mut ctx.accounts.balance;
    let destination = balance.withdrawal_destination;
    balance.pending_withdrawal_amount = 0;
    balance.withdrawal_unlock_at = 0;
    balance.withdrawal_destination = Pubkey::default();

    emit!(Withdrawn {
        balance: balance.key(),
        participant: ctx.accounts.participant.key(),
        mint: ctx.accounts.mint.key(),
        gross_amount: gross,
        fee_amount: fee,
        net_amount: net,
        destination,
    });
    Ok(())
}
