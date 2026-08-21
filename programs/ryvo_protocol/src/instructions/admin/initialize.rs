use crate::constants::{
    CONFIG_SEED, MAINNET_CHAIN_ID, MAINNET_CHANNEL_TIMELOCK_SECONDS, MAX_TIMELOCK_SECONDS,
    MIN_TIMELOCK_SECONDS,
};
use crate::domain::derive_message_domain;
use crate::error::RyvoError;
use crate::events::ConfigInitialized;
use crate::state::Config;
use anchor_lang::prelude::*;

/// Highest recognised deployment selector. `0` localnet, `1` devnet, `2` testnet, `3` mainnet.
const MAX_CHAIN_ID: u16 = MAINNET_CHAIN_ID;

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// The first config authority. Must sign: `Config` is immutable and lives forever, so a
    /// mistyped authority would leave the protocol with no one able to allowlist a mint and no
    /// recovery short of a new program id (and with it a new message domain).
    pub initial_authority: Signer<'info>,

    #[account(
        init,
        payer = payer,
        space = 8 + Config::INIT_SPACE,
        seeds = [CONFIG_SEED.as_bytes()],
        bump,
    )]
    pub config: Box<Account<'info, Config>>,

    /// Gates initialization on the program's upgrade authority.
    ///
    /// Without this, `Config` sits at a fixed seed with no natural gate and anyone could
    /// front-run deployment to become the protocol authority. Note the ordering constraint this
    /// creates: initialize *before* making the program non-upgradeable.
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = anchor_lang::solana_program::bpf_loader_upgradeable::ID,
    )]
    pub program_data: Box<Account<'info, ProgramData>>,

    pub system_program: Program<'info, System>,
}

fn valid_channel_timelock(chain_id: u16, channel_timelock_seconds: i64) -> bool {
    (MIN_TIMELOCK_SECONDS..=MAX_TIMELOCK_SECONDS).contains(&channel_timelock_seconds)
        && (chain_id != MAINNET_CHAIN_ID
            || channel_timelock_seconds == MAINNET_CHANNEL_TIMELOCK_SECONDS)
}

pub fn handler(
    ctx: Context<Initialize>,
    chain_id: u16,
    channel_timelock_seconds: i64,
) -> Result<()> {
    require!(
        ctx.accounts.program_data.upgrade_authority_address == Some(ctx.accounts.payer.key()),
        RyvoError::UnauthorizedInitializer
    );
    require!(chain_id <= MAX_CHAIN_ID, RyvoError::InvalidChainId);
    // Non-mainnet deployments may use short values for testing. Mainnet is fixed to seven days,
    // making a deployment typo impossible because the value can never be changed later.
    require!(
        valid_channel_timelock(chain_id, channel_timelock_seconds),
        RyvoError::InvalidTimelock
    );
    let initial_authority = ctx.accounts.initial_authority.key();

    // Derived, never supplied, so no authority can set it to collide with another deployment.
    let message_domain = derive_message_domain(&crate::ID, chain_id);

    let config = &mut ctx.accounts.config;
    config.authority = initial_authority;
    config.pending_authority = Pubkey::default();
    config.message_domain = message_domain;
    config.channel_timelock_seconds = channel_timelock_seconds;
    config.chain_id = chain_id;
    config.next_participant_id = 1;
    config.next_channel_id = 1;
    config.bump = ctx.bumps.config;
    config._reserved = [0u8; 112];

    emit!(ConfigInitialized {
        authority: initial_authority,
        chain_id,
        message_domain,
        channel_timelock_seconds,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_requires_exactly_seven_days() {
        assert!(valid_channel_timelock(
            MAINNET_CHAIN_ID,
            MAINNET_CHANNEL_TIMELOCK_SECONDS
        ));
        assert!(!valid_channel_timelock(MAINNET_CHAIN_ID, 1));
        assert!(!valid_channel_timelock(
            MAINNET_CHAIN_ID,
            MAINNET_CHANNEL_TIMELOCK_SECONDS - 1
        ));
        assert!(!valid_channel_timelock(
            MAINNET_CHAIN_ID,
            MAINNET_CHANNEL_TIMELOCK_SECONDS + 1
        ));
    }

    #[test]
    fn test_networks_allow_short_timelocks() {
        assert!(valid_channel_timelock(0, 1));
        assert!(valid_channel_timelock(1, 10));
        assert!(valid_channel_timelock(2, 60));
    }
}
