use anchor_lang::prelude::*;

#[error_code]
pub enum RyvoError {
    // --- arithmetic ---
    #[msg("Arithmetic overflow")]
    MathOverflow,

    // --- config / authority ---
    #[msg("Chain id is not a recognised deployment target")]
    InvalidChainId,
    #[msg("Fee exceeds the maximum permitted basis points")]
    InvalidFeeBps,
    #[msg("Timelock is outside the permitted range")]
    InvalidTimelock,
    #[msg("Authority may not be the default pubkey")]
    InvalidAuthority,
    #[msg("Fee recipient may not be the default pubkey")]
    InvalidFeeRecipient,
    #[msg("Only the program upgrade authority may initialize the config")]
    UnauthorizedInitializer,
    #[msg("No pending authority has been nominated")]
    NoPendingAuthority,
    #[msg("Signer is not the nominated pending authority")]
    UnauthorizedPendingAuthority,

    // --- token ---
    #[msg("Mint decimals exceed the permitted maximum")]
    InvalidTokenDecimals,
    #[msg("Token is disabled for new deposits and channel funding")]
    TokenDisabled,
    #[msg("Token mint does not match the account it was passed with")]
    InvalidTokenMint,
    #[msg("Requested amount exceeds accrued protocol fees")]
    InsufficientProtocolFees,

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
    #[msg("No signer rotation is pending")]
    NoSignerRotationPending,
    #[msg("Signer rotation timelock has not elapsed")]
    SignerRotationLocked,

    // --- commitment message ---
    // Exercised by unit tests in v1; the settlement path that consumes them lands in v2.
    #[msg("Commitment message is malformed")]
    InvalidCommitmentMessage,
    #[msg("Commitment message domain does not match this deployment")]
    InvalidMessageDomain,
    #[msg("Commitment amount must strictly increase")]
    CommitmentAmountMustIncrease,
    #[msg("Commitment signer epoch does not match the channel")]
    InvalidSignerEpoch,
    #[msg("Commitment has expired")]
    CommitmentExpired,
}
