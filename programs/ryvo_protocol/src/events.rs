use anchor_lang::prelude::*;

// One event per state transition. Indexers reconstruct protocol history from these alone, so
// every event carries enough identity to locate the accounts it refers to without a prior read.

#[event]
pub struct ConfigInitialized {
    pub authority: Pubkey,
    pub chain_id: u16,
    pub message_domain: [u8; 16],
    pub channel_timelock_seconds: i64,
}

#[event]
pub struct AuthorityNominated {
    pub authority: Pubkey,
    pub pending_authority: Pubkey,
}

#[event]
pub struct AuthorityAccepted {
    pub previous_authority: Pubkey,
    pub new_authority: Pubkey,
}

#[event]
pub struct TokenRegistered {
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub decimals: u8,
}

#[event]
pub struct TokenDepositEnabledChanged {
    pub mint: Pubkey,
    pub deposits_enabled: bool,
}

#[event]
pub struct ParticipantInitialized {
    pub participant: Pubkey,
    pub owner: Pubkey,
}

#[event]
pub struct BalanceOpened {
    pub balance: Pubkey,
    pub participant: Pubkey,
    pub mint: Pubkey,
}

#[event]
pub struct Deposited {
    pub balance: Pubkey,
    pub participant: Pubkey,
    pub mint: Pubkey,
    pub funder: Pubkey,
    pub amount: u64,
    pub available: u64,
}

#[event]
pub struct Withdrawn {
    pub balance: Pubkey,
    pub participant: Pubkey,
    pub mint: Pubkey,
    pub amount: u64,
    pub destination: Pubkey,
    /// Post-withdrawal balance, so indexers can follow `available` from events alone.
    pub available: u64,
}

#[event]
pub struct ChannelCreated {
    pub channel: Pubkey,
    pub payer: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub authorized_signer: Pubkey,
    pub channel_id: u64,
}

#[event]
pub struct ChannelFundsLocked {
    pub channel: Pubkey,
    pub amount: u64,
    pub locked_balance: u64,
}

/// A payer locked more collateral while an unlock request was outstanding; the request is void.
#[event]
pub struct ChannelUnlockCancelled {
    pub channel: Pubkey,
    pub cancelled_amount: u64,
}

#[event]
pub struct ChannelUnlockRequested {
    pub channel: Pubkey,
    pub requested_amount: u64,
    pub unlock_at: i64,
}

#[event]
pub struct ChannelFundsUnlocked {
    pub channel: Pubkey,
    /// `min(pending_unlock_amount, locked_balance)` at execute time — settlement may already
    /// have consumed part of the lock.
    pub released_amount: u64,
    pub remaining_locked: u64,
    pub cooperative: bool,
}

// --- clearing ---

#[event]
pub struct BatchQueued {
    pub staging: Pubkey,
    pub clearing_result: Pubkey,
    pub kind: u8,
    pub count: u16,
    pub computation_offset: u64,
}

#[event]
pub struct BatchCleared {
    pub staging: Pubkey,
    pub kind: u8,
    pub count: u16,
    pub verified_count: u16,
}

#[event]
pub struct ChannelSettled {
    pub channel: Pubkey,
    pub channel_id: u64,
    pub target_cumulative: u64,
    /// `min(target - settled, locked)`. Zero means the record was a no-op skip.
    pub moved: u64,
    pub settled_cumulative: u64,
    pub locked_balance: u64,
}

#[event]
pub struct RouteSettled {
    pub channel_ag: Pubkey,
    pub channel_gp: Pubkey,
    pub channel_ag_id: u64,
    pub channel_gp_id: u64,
    pub moved_ag: u64,
    pub moved_gp: u64,
}

/// The relayer reset or closed a buffer whose batch was not done (callback missing, or verified
/// commitments left unapplied). Nothing is lost: those commitments are re-submittable.
#[event]
pub struct BatchAbandoned {
    pub staging: Pubkey,
    pub batch_seq: u64,
    pub computation_offset: u64,
    pub verified: bool,
}

#[event]
pub struct BatchClearingFailed {
    pub staging: Pubkey,
    pub kind: u8,
}
