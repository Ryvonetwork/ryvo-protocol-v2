use anchor_lang::prelude::*;

// PDA seeds. Exported as IDL constants so the TypeScript client reads them from the IDL
// rather than re-declaring them — seed drift between Rust and TS is the most common source
// of "account does not exist" bugs in this shape of program.

#[constant]
pub const CONFIG_SEED: &str = "config";

#[constant]
pub const PARTICIPANT_SEED: &str = "participant";

#[constant]
pub const TOKEN_CONFIG_SEED: &str = "token";

#[constant]
pub const VAULT_SEED: &str = "vault";

#[constant]
pub const BALANCE_SEED: &str = "balance";

#[constant]
pub const CHANNEL_SEED: &str = "channel";

#[constant]
pub const CLEARING_SEED: &str = "clearing";

// Immutable channel types. A channel accepts exactly one commitment format for its lifetime.

#[constant]
pub const CHANNEL_KIND_DIRECT: u8 = 1;

#[constant]
pub const CHANNEL_KIND_ROUTED: u8 = 2;

// Domain-separation tags.

/// Preimage tag for the deployment-scoped message domain:
/// `SHA256(MESSAGE_DOMAIN_TAG || program_id || chain_id_le)[..16]`.
#[constant]
pub const MESSAGE_DOMAIN_TAG: &str = "ryvo-message-domain-v1";

/// Preimage tag for the commitment digest that agents actually sign:
/// `SHA3_256(COMMITMENT_DIGEST_TAG || canonical_message)`. SHA3 because the Arcis circuit
/// rebuilds this digest itself from the staged fields.
#[constant]
pub const COMMITMENT_DIGEST_TAG: &str = "ryvo-commitment-v1";

// Bounds.

/// Timelock ceiling, in seconds (30 days). Applies to the channel unlock timelock, which is the
/// protocol's only timelock and is immutable after `initialize`.
pub const MAX_TIMELOCK_SECONDS: i64 = 30 * 24 * 60 * 60;
/// Timelock floor. Zero is rejected: request and execute would fit in one transaction and the
/// payee would have no window at all. One second is the floor for test networks; a real
/// deployment wants hours.
pub const MIN_TIMELOCK_SECONDS: i64 = 1;

/// Mint decimals ceiling. Nothing sane exceeds 9.
pub const MAX_MINT_DECIMALS: u8 = 9;
