use anchor_lang::prelude::*;

/// A gateway's float for routed payments, one per (gateway participant, mint).
/// PDA seeds: `["pool", participant, mint]`.
///
/// Why it exists. An agent has one channel to the gateway with one cumulative total across every
/// provider it is routed to. When a route settles, the agent's outstanding increase has to land
/// somewhere the provider can be paid from — and it must not land in the channel of *whichever
/// route happens to settle first*, or a gateway could settle a later route ahead of an earlier
/// one and keep money that was owed to the earlier provider. So the increase lands here, in a
/// pool that belongs to the gateway but that every provider of that gateway is paid out of.
/// Settlement order stops mattering; the gateway's fee is simply what remains. It is also the
/// *only* money a route pays providers from: a gateway that wants to extend credit ahead of agent
/// inflows funds the pool, not individual provider channels (those channels' locks serve the
/// gateway's own direct payments to a provider).
///
/// The pool is timelocked exactly like a channel lock, and for the same reason: a provider that
/// holds a countersigned commitment needs T to settle it before the gateway can take the float
/// back. Funding the pool (or receiving a route) never shortens that clock; a new funding
/// cancels a pending request, as locking more into a channel does.
///
/// Solvency, updated: `vault.amount == Σ Balance.available + Σ Channel.locked_balance + Σ RoutePool.balance`.
#[account]
#[derive(InitSpace)]
pub struct RoutePool {
    /// The gateway's `Participant` PDA.
    pub participant: Pubkey,
    pub mint: Pubkey,
    /// Routed value waiting to be paid out to providers, plus the gateway's accumulated margin.
    pub balance: u64,
    /// Non-zero iff a withdrawal is pending.
    pub pending_unlock_amount: u64,
    /// Absolute deadline for the pending withdrawal.
    pub pending_unlock_at: i64,
    pub bump: u8,
    pub _reserved: [u8; 96],
}
