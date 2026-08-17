use anchor_lang::prelude::*;

// One event per state transition. Indexers reconstruct protocol history from these alone, so
// every event carries enough identity to locate the accounts it refers to without a prior read.

#[event]
pub struct ConfigInitialized {
    pub authority: Pubkey,
    pub fee_recipient: Pubkey,
    pub chain_id: u16,
    pub message_domain: [u8; 16],
    pub fee_bps: u16,
    pub withdrawal_timelock_seconds: i64,
    pub channel_timelock_seconds: i64,
}

#[event]
pub struct ConfigUpdated {
    pub authority: Pubkey,
    pub fee_recipient: Pubkey,
    pub fee_bps: u16,
    pub pending_authority: Pubkey,
}

#[event]
pub struct ConfigAuthorityAccepted {
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
pub struct TokenEnabledChanged {
    pub mint: Pubkey,
    pub enabled: bool,
}

#[event]
pub struct ProtocolFeesWithdrawn {
    pub mint: Pubkey,
    pub amount: u64,
    pub destination: Pubkey,
    pub remaining_accrued: u64,
}

#[event]
pub struct ParticipantInitialized {
    pub participant: Pubkey,
    pub owner: Pubkey,
}

#[event]
pub struct InboundChannelPolicyUpdated {
    pub participant: Pubkey,
    pub policy: u8,
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
pub struct WithdrawalRequested {
    pub balance: Pubkey,
    pub participant: Pubkey,
    pub mint: Pubkey,
    pub amount: u64,
    pub destination: Pubkey,
    pub unlock_at: i64,
}

#[event]
pub struct WithdrawalCancelled {
    pub balance: Pubkey,
    pub participant: Pubkey,
    pub mint: Pubkey,
    pub amount_cancelled: u64,
}

#[event]
pub struct Withdrawn {
    pub balance: Pubkey,
    pub participant: Pubkey,
    pub mint: Pubkey,
    /// Amount actually debited: `min(pending_withdrawal_amount, available)`. May be less than
    /// the requested amount, or zero, if settlement consumed the balance first.
    pub gross_amount: u64,
    pub fee_amount: u64,
    pub net_amount: u64,
    pub destination: Pubkey,
}

#[event]
pub struct ChannelCreated {
    pub channel: Pubkey,
    pub payer: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub authorized_signer: Pubkey,
}

#[event]
pub struct ChannelFundsLocked {
    pub channel: Pubkey,
    pub amount: u64,
    pub locked_balance: u64,
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
