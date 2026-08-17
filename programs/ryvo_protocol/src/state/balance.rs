use anchor_lang::prelude::*;

/// One participant's holdings of one mint. PDA seeds: `["balance", participant, mint]`.
///
/// A separate account per (participant, mint) rather than an array inside `Participant`. That
/// removes a fixed token cap, but the decisive reason is write contention: an inlined array would
/// make one account write-locked by every deposit and every settlement across all of that
/// participant's channels and tokens, serialising an operator hub's entire throughput into a
/// single account. This is the same argument that removes the prior design's shared channel
/// buckets, applied one level up.
///
/// There is no `withdrawing` bucket. A pending withdrawal reserves nothing: `request_withdrawal`
/// records intent only, and `execute_withdrawal` transfers `min(pending_withdrawal_amount,
/// available)`. That makes "a pending withdrawal is not senior to settlement" true by
/// construction, lets settlement stay ignorant of withdrawals entirely, and keeps solvency to a
/// single equation:
///
/// `vault.amount == sum(Balance.available) + sum(Channel.locked_balance) + TokenConfig.accrued_fees`
///
/// A reserved bucket that is senior to nothing would have been a lie in the state.
#[account]
#[derive(InitSpace)]
pub struct Balance {
    /// The `Participant` PDA this balance belongs to.
    pub participant: Pubkey,
    pub mint: Pubkey,
    /// Spendable inside the protocol right now.
    pub available: u64,
    /// Non-zero iff a withdrawal is pending. Funds are *not* moved at request time.
    pub pending_withdrawal_amount: u64,
    /// Absolute deadline, never a "requested_at" — a relative timestamp would let a config
    /// change retroactively re-time requests already in flight.
    pub withdrawal_unlock_at: i64,
    /// Token account recorded at request time; `execute_withdrawal` may pay only here.
    pub withdrawal_destination: Pubkey,
    pub bump: u8,
    pub _reserved: [u8; 96],
}
