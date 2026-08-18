use crate::constants::CONFIG_SEED;
use crate::error::RyvoError;
use crate::events::{AuthorityAccepted, AuthorityNominated};
use crate::state::Config;
use anchor_lang::prelude::*;

/// Nominate a successor authority.
///
/// This is the whole of config mutability. `chain_id`, `message_domain` and the channel timelock
/// have no setter anywhere, and with fees gone there is nothing else to tune. Passing
/// `Pubkey::default()` withdraws an outstanding nomination.
#[derive(Accounts)]
pub struct NominateAuthority<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [CONFIG_SEED.as_bytes()],
        bump = config.bump,
        has_one = authority,
    )]
    pub config: Box<Account<'info, Config>>,
}

pub fn nominate_authority_handler(
    ctx: Context<NominateAuthority>,
    new_authority: Pubkey,
) -> Result<()> {
    let config = &mut ctx.accounts.config;
    config.pending_authority = new_authority;

    emit!(AuthorityNominated {
        authority: config.authority,
        pending_authority: new_authority,
    });
    Ok(())
}

/// Two-step handoff: the successor must explicitly accept, so a typo in a nomination cannot
/// brick the protocol authority.
#[derive(Accounts)]
pub struct AcceptConfigAuthority<'info> {
    pub pending_authority: Signer<'info>,

    #[account(
        mut,
        seeds = [CONFIG_SEED.as_bytes()],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, Config>>,
}

pub fn accept_config_authority_handler(ctx: Context<AcceptConfigAuthority>) -> Result<()> {
    let config = &mut ctx.accounts.config;
    require!(
        config.pending_authority != Pubkey::default(),
        RyvoError::NoPendingAuthority
    );
    require!(
        config.pending_authority == ctx.accounts.pending_authority.key(),
        RyvoError::UnauthorizedPendingAuthority
    );

    let previous_authority = config.authority;
    config.authority = config.pending_authority;
    config.pending_authority = Pubkey::default();

    emit!(AuthorityAccepted {
        previous_authority,
        new_authority: config.authority,
    });
    Ok(())
}
