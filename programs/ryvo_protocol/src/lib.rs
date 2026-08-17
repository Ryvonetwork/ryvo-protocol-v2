//! Ryvo protocol — unilateral cumulative payment channels on Solana.
//!
//! v1 is the custody layer only: deposits, withdrawals, permanent participant identity and
//! payment channels. It contains no signature verification and no settlement. Off-chain
//! commitments are verified through Arcium MPC in v2; `commitment.rs` fixes the format now so
//! that landing v2 requires neither a state migration nor re-signing live commitments.

pub mod commitment;
pub mod constants;
pub mod domain;
pub mod error;
pub mod events;
pub mod instructions;
pub mod state;

use anchor_lang::prelude::*;

pub use constants::*;
#[allow(unused_imports)]
pub use events::*;
#[allow(unused_imports)]
pub use instructions::*;
#[allow(unused_imports)]
pub use state::*;

declare_id!("4kRnxdszLpHvrLzi4EDyyTRAWqkdmANzSGFPqncr2uxc");

/// Plain `#[program]`, not `#[arcium_program]`. Anchor instruction discriminators are
/// `sha256("global:<name>")[..8]` and account discriminators `sha256("account:<Name>")[..8]`,
/// both independent of which program macro is used — so v2 can switch to `#[arcium_program]`
/// without changing a single discriminator or account layout. The benefit is that v1 tests run
/// under a plain local validator instead of requiring the 2-node Arcium Docker localnet.
#[program]
pub mod ryvo_protocol {
    #[allow(unused_imports)]
    use super::*;

    // --- admin ---

    /// Bootstrap the singleton config. Gated on the program upgrade authority, so the fixed-seed
    /// `Config` account cannot be front-run by an unrelated caller.
    pub fn initialize(
        ctx: Context<Initialize>,
        chain_id: u16,
        fee_bps: u16,
        withdrawal_timelock_seconds: i64,
        channel_timelock_seconds: i64,
        initial_authority: Pubkey,
        fee_recipient: Pubkey,
    ) -> Result<()> {
        instructions::admin::initialize::handler(
            ctx,
            chain_id,
            fee_bps,
            withdrawal_timelock_seconds,
            channel_timelock_seconds,
            initial_authority,
            fee_recipient,
        )
    }

    /// Update the mutable subset only. `chain_id`, `message_domain` and both timelocks are
    /// deliberately unreachable from here.
    pub fn update_config(
        ctx: Context<UpdateConfig>,
        new_fee_recipient: Option<Pubkey>,
        new_fee_bps: Option<u16>,
        new_pending_authority: Option<Pubkey>,
    ) -> Result<()> {
        instructions::admin::update_config::update_config_handler(
            ctx,
            new_fee_recipient,
            new_fee_bps,
            new_pending_authority,
        )
    }

    pub fn accept_config_authority(ctx: Context<AcceptConfigAuthority>) -> Result<()> {
        instructions::admin::update_config::accept_config_authority_handler(ctx)
    }
}
