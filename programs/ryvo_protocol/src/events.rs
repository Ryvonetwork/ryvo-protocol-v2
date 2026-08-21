use anchor_lang::prelude::*;

// Events expose protocol state transitions. Settlement emits one summary per instruction because
// one event per commitment would exceed Solana's transaction log limit at production batch sizes.

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
    pub participant_id: u64,
    pub authorized_signer: Pubkey,
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
pub struct ChannelBucketCreated {
    pub bucket: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub base_channel_id: u64,
    pub capacity: u16,
    pub kind: u8,
}

#[event]
pub struct ChannelCreated {
    pub bucket: Pubkey,
    pub slot: u8,
    pub channel_id: u64,
    pub payer: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub authorized_signer: Pubkey,
    pub kind: u8,
}

#[event]
pub struct ChannelFundsLocked {
    pub bucket: Pubkey,
    pub slot: u8,
    pub channel_id: u64,
    pub amount: u64,
    pub locked_balance: u64,
}

#[event]
pub struct ChannelUnlockCancelled {
    pub bucket: Pubkey,
    pub slot: u8,
    pub channel_id: u64,
    pub cancelled_amount: u64,
}

#[event]
pub struct ChannelUnlockRequested {
    pub bucket: Pubkey,
    pub slot: u8,
    pub channel_id: u64,
    pub requested_amount: u64,
    pub unlock_at: i64,
}

#[event]
pub struct ChannelFundsUnlocked {
    pub bucket: Pubkey,
    pub slot: u8,
    pub channel_id: u64,
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
pub struct CommitmentsSettled {
    pub staging: Pubkey,
    pub kind: u8,
    pub commitment_count: u16,
    /// Total removed from source channels by this instruction.
    pub moved: u64,
    /// Direct payee credits, or routed provider credits.
    pub provider_paid: u64,
    /// Always zero for direct commitments.
    pub gateway_fee: u64,
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

/// A genuine callback from one of our computations arrived for a batch that is no longer bound
/// to it (abandoned or superseded). Nothing was recorded.
#[event]
pub struct StaleCallbackIgnored {
    pub clearing_result: Pubkey,
    pub computation_account: Pubkey,
}

#[event]
pub struct BatchClearingFailed {
    pub staging: Pubkey,
    pub kind: u8,
}
