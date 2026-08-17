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

// Domain-separation tags.

/// Preimage tag for the deployment-scoped message domain:
/// `SHA256(MESSAGE_DOMAIN_TAG || program_id || chain_id_le)[..16]`.
#[constant]
pub const MESSAGE_DOMAIN_TAG: &str = "ryvo-message-domain-v1";

/// Preimage tag for the commitment digest that agents actually sign:
/// `SHA256(COMMITMENT_DIGEST_TAG || canonical_message)`.
#[constant]
pub const COMMITMENT_DIGEST_TAG: &str = "ryvo-commitment-v1";

// Bounds.

/// Withdrawal fee ceiling, in basis points.
pub const MAX_FEE_BPS: u16 = 30;

/// Timelock ceiling, in seconds (30 days). Applies to both the withdrawal timelock and the
/// channel timelock. Both are immutable after `initialize`.
pub const MAX_TIMELOCK_SECONDS: i64 = 30 * 24 * 60 * 60;

/// Mint decimals ceiling. Bounds fee arithmetic; nothing sane exceeds 9.
pub const MAX_MINT_DECIMALS: u8 = 9;

/// Basis-point denominator.
pub const BPS_DENOMINATOR: u128 = 10_000;
