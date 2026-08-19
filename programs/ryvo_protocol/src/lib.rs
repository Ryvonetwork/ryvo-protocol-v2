//! Ryvo protocol — unilateral cumulative payment channels on Solana, cleared through Arcium.
//!
//! Custody (deposits, withdrawals, participants, channels) is plain Anchor. Clearing stages
//! signed commitments on-chain, has an Arcium MPC circuit verify the signatures, and settles
//! on-chain from the same sealed bytes — see `clearing`.

pub mod clearing;
pub mod commitment;
pub mod constants;
pub mod domain;
pub mod error;
pub mod events;
pub mod instructions;
pub mod state;

use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::{CircuitSource, OffChainCircuitSource};
use arcium_macros::circuit_hash;

pub use clearing::*;
pub use commitment::{KIND_ROUTE, KIND_UNILATERAL};
pub use constants::*;
use error::RyvoError;
#[allow(unused_imports)]
pub use events::*;
#[allow(unused_imports)]
pub use instructions::*;
#[allow(unused_imports)]
pub use state::*;

declare_id!("DD7m7B1FggiCQCURQ2pNXyDtPZPRdJYYgq9dthtaJtii");

#[arcium_program]
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
    ) -> Result<()> {
        instructions::admin::initialize::handler(ctx, chain_id, channel_timelock_seconds)
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

    // --- clearing: one-time setup ---

    pub fn init_arcium_signer(ctx: Context<InitArciumSigner>) -> Result<()> {
        clearing::init_arcium_signer_handler(ctx)
    }

    /// `circuit_url = None` means the circuit bytes are uploaded on-chain afterwards (localnet).
    /// `Some(url)` registers a publicly fetchable `.arcis` whose SHA-256 must equal the hash
    /// baked in at build time — the compiled circuits are ~1.5–3 MB, far too large to rent
    /// on-chain, so this is the only sane path on devnet/mainnet.
    pub fn init_clear_unilateral_comp_def(
        ctx: Context<InitClearUnilateralCompDef>,
        circuit_url: Option<String>,
    ) -> Result<()> {
        let source = circuit_url.map(|url| {
            CircuitSource::OffChain(OffChainCircuitSource {
                source: url,
                hash: circuit_hash!("clear_unilateral64"),
            })
        });
        init_computation_def(ctx.accounts, source)?;
        Ok(())
    }

    pub fn init_clear_route_comp_def(
        ctx: Context<InitClearRouteCompDef>,
        circuit_url: Option<String>,
    ) -> Result<()> {
        let source = circuit_url.map(|url| {
            CircuitSource::OffChain(OffChainCircuitSource {
                source: url,
                hash: circuit_hash!("clear_route64"),
            })
        });
        init_computation_def(ctx.accounts, source)?;
        Ok(())
    }

    // --- clearing: staging ---

    /// Create a relayer's reusable staging buffer (pre-created account) and its clearing result.
    pub fn open_staging(ctx: Context<OpenStaging>, kind: u8) -> Result<()> {
        clearing::open_staging_handler(ctx, kind)
    }

    /// Start the next batch in an existing buffer once the previous one is fully settled.
    pub fn reset_staging(ctx: Context<ResetStaging>, kind: u8) -> Result<()> {
        clearing::reset_staging_handler(ctx, kind)
    }

    pub fn stage_records<'info>(
        ctx: Context<'info, StageRecords<'info>>,
        start: u16,
        data: Vec<u8>,
    ) -> Result<()> {
        clearing::stage_records_handler(ctx, start, data)
    }

    pub fn seal_and_queue_unilateral(
        ctx: Context<SealAndQueueUnilateral>,
        computation_offset: u64,
        count: u16,
    ) -> Result<()> {
        clearing::seal_and_queue_unilateral_handler(ctx, computation_offset, count)
    }

    pub fn seal_and_queue_route(
        ctx: Context<SealAndQueueRoute>,
        computation_offset: u64,
        count: u16,
    ) -> Result<()> {
        clearing::seal_and_queue_route_handler(ctx, computation_offset, count)
    }

    // --- clearing: callbacks (invoked by Arcium) ---

    #[arcium_callback(encrypted_ix = "clear_unilateral64")]
    pub fn clear_unilateral64_callback(
        ctx: Context<ClearUnilateral64Callback>,
        output: SignedComputationOutputs<ClearUnilateral64Output>,
    ) -> Result<()> {
        clearing::require_current_computation(
            &ctx.accounts.clearing_result,
            &ctx.accounts.computation_account.key(),
            &ctx.accounts.mxe_account,
        )?;
        if let SignedComputationOutputs::Failure(_) = output {
            return clearing::record_failure(&mut ctx.accounts.clearing_result);
        }
        let bits = match output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) {
            Ok(ClearUnilateral64Output { field_0 }) => field_0,
            Err(_) => return Err(RyvoError::AbortedComputation.into()),
        };
        clearing::record_bitmap(&mut ctx.accounts.clearing_result, &bits, KIND_UNILATERAL)
    }

    #[arcium_callback(encrypted_ix = "clear_route64")]
    pub fn clear_route64_callback(
        ctx: Context<ClearRoute64Callback>,
        output: SignedComputationOutputs<ClearRoute64Output>,
    ) -> Result<()> {
        clearing::require_current_computation(
            &ctx.accounts.clearing_result,
            &ctx.accounts.computation_account.key(),
            &ctx.accounts.mxe_account,
        )?;
        if let SignedComputationOutputs::Failure(_) = output {
            return clearing::record_failure(&mut ctx.accounts.clearing_result);
        }
        let bits = match output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) {
            Ok(ClearRoute64Output { field_0 }) => field_0,
            Err(_) => return Err(RyvoError::AbortedComputation.into()),
        };
        clearing::record_bitmap(&mut ctx.accounts.clearing_result, &bits, KIND_ROUTE)
    }

    // --- clearing: settlement (permissionless) ---

    pub fn settle_channels<'info>(
        ctx: Context<'info, SettleChannels<'info>>,
        indices: Vec<u8>,
    ) -> Result<()> {
        clearing::settle_channels_handler(ctx, indices)
    }

    pub fn close_staging(ctx: Context<CloseStaging>) -> Result<()> {
        clearing::close_staging_handler(ctx)
    }
}
