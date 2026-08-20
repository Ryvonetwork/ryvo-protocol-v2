use anchor_lang::prelude::*;

/// Singleton protocol configuration. PDA seeds: `["config"]`.
///
/// `chain_id`, `message_domain` and the timelock are immutable after `initialize`. The timelock is
/// the only thing backing the payee's collateral guarantee: lowering it would let a payer yank
/// collateral out from under a payee mid-service, so there is no safe mutable range. The price of
/// that is that a wrong timelock means a redeploy.
///
/// The protocol takes no fee. There is nothing on-chain for it to charge for — a payment moves
/// numbers between two ledger rows and the tokens never leave the vault — so a withdrawal fee
/// would be rent extraction rather than payment for a service. Any future revenue belongs off-chain
/// or in a yield layer that does not exist yet.
#[account]
#[derive(InitSpace)]
pub struct Config {
    /// Active config authority. Its only powers are allowlisting mints, pausing them for new
    /// deposits, and handing the role on. It can never move user funds.
    pub authority: Pubkey,
    /// Nominated successor. `Pubkey::default()` means no handoff is pending. A handoff requires
    /// the successor to explicitly accept, so a typo cannot brick the authority.
    pub pending_authority: Pubkey,
    /// Immutable. `SHA256(MESSAGE_DOMAIN_TAG || program_id || chain_id_le)[..16]`.
    pub message_domain: [u8; 16],
    /// Immutable. Delay before a unilateral channel unlock may execute.
    ///
    /// This is the protocol's only timelock. Withdrawals need none, because `available` is money
    /// nobody else has a claim on — settlement is payable strictly from `locked_balance`, so the
    /// payee's protection lives entirely on the unlock path, which is where the collateral is.
    pub channel_timelock_seconds: i64,
    /// Immutable deployment selector that feeds `message_domain`.
    pub chain_id: u16,
    /// Next permanent participant id. Starts at 1; 0 is reserved for padded route allocations.
    pub next_participant_id: u64,
    /// Next channel id range to reserve. Starts at 1; 0 is never a valid id. Commitments
    /// name channels by this id rather than by their 32-byte address, which is what keeps a
    /// staged record small enough to clear in bulk. Written only by `initialize_channel_bucket`,
    /// so settlement never contends on it.
    pub next_channel_id: u64,
    pub bump: u8,
    /// Singleton, so reserved space is cheap.
    pub _reserved: [u8; 112],
}
