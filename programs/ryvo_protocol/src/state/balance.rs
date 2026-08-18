use anchor_lang::prelude::*;

/// One participant's unlocked holdings of one mint. PDA seeds: `["balance", participant, mint]`.
///
/// A separate account per (participant, mint) rather than an array inside `Participant`. That
/// removes a fixed token cap, but the decisive reason is write contention: an inlined array would
/// make one account write-locked by every deposit and every settlement across all of that
/// participant's channels and tokens, serialising an operator hub's entire throughput into a
/// single account.
///
/// `available` is genuinely free money. Settlement can never reach it — a commitment is payable
/// only from the channel's `locked_balance` — so it carries no timelock and no pending state, and
/// `withdraw` pays out immediately.
///
/// Solvency, in one equation:
///
/// `vault.amount == sum(Balance.available) + sum(Channel.locked_balance) + TokenConfig.accrued_fees`
#[account]
#[derive(InitSpace)]
pub struct Balance {
    /// The `Participant` PDA this balance belongs to.
    pub participant: Pubkey,
    pub mint: Pubkey,
    /// Spendable or withdrawable right now. Nothing else has a claim on it.
    pub available: u64,
    pub bump: u8,
    pub _reserved: [u8; 96],
}
