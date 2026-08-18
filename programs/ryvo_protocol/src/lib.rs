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

declare_id!("7QBj1XUYe4RbMxJd8H42gWR7QWeRiRuYQbwbwAjAmjqQ");

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
        channel_timelock_seconds: i64,
        initial_authority: Pubkey,
    ) -> Result<()> {
        instructions::admin::initialize::handler(
            ctx,
            chain_id,
            channel_timelock_seconds,
            initial_authority,
        )
    }

    /// Nominate a successor authority. This is the whole of config mutability.
    pub fn nominate_authority(
        ctx: Context<NominateAuthority>,
        new_authority: Pubkey,
    ) -> Result<()> {
        instructions::admin::update_config::nominate_authority_handler(ctx, new_authority)
    }

    pub fn accept_config_authority(ctx: Context<AcceptConfigAuthority>) -> Result<()> {
        instructions::admin::update_config::accept_config_authority_handler(ctx)
    }

    /// Allowlist a mint and create its vault. Legacy SPL Token only.
    pub fn register_token(ctx: Context<RegisterToken>) -> Result<()> {
        instructions::admin::token::register_token_handler(ctx)
    }

    /// Stop or resume deposits for a mint. Touches nothing else, so it can never trap funds.
    pub fn set_token_deposit_enabled(
        ctx: Context<SetTokenDepositEnabled>,
        deposits_enabled: bool,
    ) -> Result<()> {
        instructions::admin::token::set_token_deposit_enabled_handler(ctx, deposits_enabled)
    }

    // --- participants ---

    /// Register a permanent identity. Never recycled: the PDA derives from the owner and there is
    /// no close instruction.
    pub fn initialize_participant(ctx: Context<InitializeParticipant>) -> Result<()> {
        instructions::participant::initialize_participant_handler(ctx)
    }

    // --- balances ---

    pub fn open_balance(ctx: Context<OpenBalance>) -> Result<()> {
        instructions::balance::open_balance_handler(ctx)
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        instructions::balance::deposit_handler(ctx, amount)
    }

    /// Withdraw unlocked balance, immediately and in full. Safe without a timelock because
    /// settlement is payable only from a channel's locked collateral, never from this balance.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        instructions::balance::withdraw_handler(ctx, amount)
    }

    // --- channels ---

    /// Open a one-way channel. `authorized_signer` is required, not defaulted — see the handler.
    pub fn create_channel(ctx: Context<CreateChannel>, authorized_signer: Pubkey) -> Result<()> {
        instructions::channel::create_channel_handler(ctx, authorized_signer)
    }

    pub fn lock_channel_funds(ctx: Context<PayerChannelOp>, amount: u64) -> Result<()> {
        instructions::channel::lock_channel_funds_handler(ctx, amount)
    }

    pub fn request_unlock_channel_funds(
        ctx: Context<PayerChannelOp>,
        amount: u64,
    ) -> Result<()> {
        instructions::channel::request_unlock_channel_funds_handler(ctx, amount)
    }

    /// Payer-signed, not permissionless: a stale request must not be triggerable by a stranger.
    pub fn execute_unlock_channel_funds(ctx: Context<PayerChannelOp>) -> Result<()> {
        instructions::channel::execute_unlock_channel_funds_handler(ctx)
    }

    /// Immediate release with both parties signing — no timelock, since the party it protects
    /// is consenting.
    pub fn cooperative_unlock_channel_funds(
        ctx: Context<CooperativeUnlockChannelFunds>,
        amount: u64,
    ) -> Result<()> {
        instructions::channel::cooperative_unlock_channel_funds_handler(ctx, amount)
    }
}
