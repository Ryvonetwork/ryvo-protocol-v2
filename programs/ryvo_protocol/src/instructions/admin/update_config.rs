use crate::constants::{CONFIG_SEED, MAX_FEE_BPS};
use crate::error::RyvoError;
use crate::events::{ConfigAuthorityAccepted, ConfigUpdated};
use crate::state::Config;
use anchor_lang::prelude::*;

/// Note what is absent: there is no way to change `chain_id`, `message_domain`, or either
/// timelock. Those are immutable by construction rather than by policy.
#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [CONFIG_SEED.as_bytes()],
        bump = config.bump,
        has_one = authority,
    )]
    pub config: Account<'info, Config>,
}

pub fn update_config_handler(
    ctx: Context<UpdateConfig>,
    new_fee_recipient: Option<Pubkey>,
    new_fee_bps: Option<u16>,
    new_pending_authority: Option<Pubkey>,
) -> Result<()> {
    let config = &mut ctx.accounts.config;

    if let Some(fee_recipient) = new_fee_recipient {
        require!(
            fee_recipient != Pubkey::default(),
            RyvoError::InvalidFeeRecipient
        );
        config.fee_recipient = fee_recipient;
    }
    if let Some(fee_bps) = new_fee_bps {
        require!(fee_bps <= MAX_FEE_BPS, RyvoError::InvalidFeeBps);
        config.fee_bps = fee_bps;
    }
    // `Pubkey::default()` clears a nomination, which is how a mistaken handoff is withdrawn.
    if let Some(pending) = new_pending_authority {
        config.pending_authority = pending;
    }

    emit!(ConfigUpdated {
        authority: config.authority,
        fee_recipient: config.fee_recipient,
        fee_bps: config.fee_bps,
        pending_authority: config.pending_authority,
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
    pub config: Account<'info, Config>,
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

    emit!(ConfigAuthorityAccepted {
        previous_authority,
        new_authority: config.authority,
    });
    Ok(())
}
