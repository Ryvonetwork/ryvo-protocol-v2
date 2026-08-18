use anchor_lang::prelude::*;

/// Per-mint allowlist entry and vault owner. PDA seeds: `["token", mint]`.
///
/// This replaces the prior design's `Vec<TokenEntry>` registry, which carried a capacity cap, a
/// realloc path, and a mutable `token_id -> mint` mapping that every outstanding commitment
/// implicitly trusted. Here "is this mint allowed?" is a PDA-existence question — the cheapest
/// possible allowlist, with no authority-held mapping to re-point.
///
/// This account is also the vault's authority, deliberately per-mint rather than the global
/// `Config`: a signer-seed mistake for one mint then cannot reach another mint's vault.
#[account]
#[derive(InitSpace)]
pub struct TokenConfig {
    pub mint: Pubkey,
    /// The SPL token account at `["vault", mint]` holding all deposits for this mint.
    pub vault: Pubkey,
    /// Mirrors `mint.decimals`, validated at registration. Needed for `transfer_checked`.
    pub decimals: u8,
    /// Gates *entry* only: deposits, channel creation, and locking funds. It must never gate
    /// withdrawals, unlocks, or settlement — otherwise it is a fund-freeze switch rather than a
    /// pause.
    pub enabled: bool,
    pub bump: u8,
    pub _reserved: [u8; 96],
}
