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
    /// Gates `deposit` and nothing else.
    ///
    /// Deliberately narrow. Turning it off stops the protocol taking on *new* exposure to a mint
    /// that has become problematic, while leaving everyone already inside free to move, lock,
    /// unlock and withdraw. Gating those too would stop a user using funds they had already
    /// committed, which is a freeze wearing a pause's name.
    pub deposits_enabled: bool,
    pub bump: u8,
    pub _reserved: [u8; 96],
}
