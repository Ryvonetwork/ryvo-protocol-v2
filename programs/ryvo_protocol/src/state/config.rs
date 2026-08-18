use anchor_lang::prelude::*;

/// Singleton protocol configuration. PDA seeds: `["config"]`.
///
/// `chain_id`, `message_domain` and both timelocks are immutable after `initialize`. The
/// timelocks are the only thing backing the payee's collateral guarantee and the user's exit
/// guarantee: lowering the channel timelock would let a payer yank collateral out from under a
/// payee mid-service, and raising the withdrawal timelock would freeze user funds. Both
/// directions have a victim, so there is no safe mutable range. The price of that is that a
/// wrong timelock means a redeploy.
#[account]
#[derive(InitSpace)]
pub struct Config {
    /// Active config authority.
    pub authority: Pubkey,
    /// Nominated successor. `Pubkey::default()` means no handoff is pending. A handoff requires
    /// the successor to explicitly accept, so a typo cannot brick the authority.
    pub pending_authority: Pubkey,
    /// Owner of the accounts that protocol fees may be withdrawn to.
    pub fee_recipient: Pubkey,
    /// Immutable. `SHA256(MESSAGE_DOMAIN_TAG || program_id || chain_id_le)[..16]`.
    pub message_domain: [u8; 16],
    /// Immutable. Delay for both channel unlock and (in v2) authorized-signer rotation. One
    /// field rather than two: the two flows protect the same counterparty against the same
    /// class of surprise, so a single knob is easier to reason about and to audit.
    ///
    /// This is the protocol's only timelock. Withdrawals need none, because `available` is money
    /// nobody else has a claim on — settlement is payable strictly from `locked_balance`, so the
    /// payee's protection lives entirely on the unlock path, which is where the collateral is.
    pub channel_timelock_seconds: i64,
    /// Withdrawal fee in basis points, `0..=MAX_FEE_BPS`.
    pub fee_bps: u16,
    /// Immutable deployment selector that feeds `message_domain`.
    pub chain_id: u16,
    pub bump: u8,
    /// Singleton, so reserved space is cheap — 128 bytes costs a fraction of a cent once.
    pub _reserved: [u8; 128],
}
