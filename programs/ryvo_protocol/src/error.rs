use anchor_lang::prelude::*;

#[error_code]
pub enum RyvoError {
    // --- arithmetic ---
    #[msg("Arithmetic overflow")]
    MathOverflow,

    // --- config / authority ---
    #[msg("Chain id is not a recognised deployment target")]
    InvalidChainId,
    #[msg("Timelock is outside the permitted range")]
    InvalidTimelock,
    #[msg("Authority may not be the default pubkey")]
    InvalidAuthority,
    #[msg("Only the program upgrade authority may initialize the config")]
    UnauthorizedInitializer,
    #[msg("No pending authority has been nominated")]
    NoPendingAuthority,
    #[msg("Signer is not the nominated pending authority")]
    UnauthorizedPendingAuthority,

    // --- token ---
    #[msg("Mint decimals exceed the permitted maximum")]
    InvalidTokenDecimals,
    #[msg("Deposits are disabled for this token")]
    TokenDepositsDisabled,

    // --- balance / withdrawal ---
    #[msg("Amount must be greater than zero")]
    AmountMustBePositive,
    #[msg("Insufficient available balance")]
    InsufficientBalance,
    #[msg("Withdrawal destination is not permitted")]
    InvalidWithdrawalDestination,

    // --- channel ---
    #[msg("A participant may not open a channel to itself")]
    SelfChannelNotAllowed,
    #[msg("Authorized signer is invalid")]
    InvalidAuthorizedSigner,
    #[msg("Insufficient locked balance on this channel")]
    InsufficientLockedBalance,
    #[msg("No channel unlock is pending")]
    NoChannelUnlockPending,
    #[msg("Channel unlock timelock has not elapsed")]
    ChannelUnlockLocked,

    // --- commitment message ---
    // Exercised by unit tests in v1; the settlement path that consumes them lands in v2.
    #[msg("Commitment message is malformed")]
    InvalidCommitmentMessage,
    #[msg("Commitment message domain does not match this deployment")]
    InvalidMessageDomain,
    #[msg("Commitment amount must strictly increase")]
    CommitmentAmountMustIncrease,

    // --- clearing ---
    #[msg("Staging kind is not unilateral or route")]
    InvalidStagingKind,
    #[msg("Staged data is malformed or out of bounds")]
    InvalidStagingData,
    #[msg("Staging buffer is sealed")]
    StagingSealed,
    #[msg("Batch has not been cleared by Arcium yet")]
    BatchNotCleared,
    #[msg("Batch already has a recorded verdict")]
    BatchAlreadyCleared,
    #[msg("Batch still has verified records that were not applied")]
    BatchNotFullyApplied,
    #[msg("Settlement account list does not match the indices")]
    InvalidSettlementAccounts,
    #[msg("Settlement index is out of range for this batch")]
    InvalidSettlementIndex,
    #[msg("Record was not verified by the circuit")]
    RecordNotVerified,
    #[msg("Record was already applied in this batch")]
    RecordAlreadyApplied,
    #[msg("Channel account does not match the staged channel id")]
    SettlementChannelMismatch,
    #[msg("Staged signer does not match the channel authorized signer")]
    SettlementSignerMismatch,
    #[msg("Balance account is not the payee balance for this channel")]
    SettlementBalanceMismatch,
    #[msg("Route legs do not chain through the same gateway and mint")]
    SettlementRouteMismatch,
    #[msg("The Arcium computation was aborted or its output failed verification")]
    AbortedComputation,
}
