use anchor_lang::prelude::*;

/// One unidirectional payment relationship.
/// PDA seeds: `["channel", payer_participant, payee_participant, mint]`.
///
/// Strictly one-way: `(A -> B)` and `(B -> A)` are different accounts, so bidirectional traffic
/// uses two channels. Permanent — there is no close instruction, which removes any
/// close-and-reopen replay boundary.
///
/// Because the PDA is derived from payer, payee and mint, the channel's own address commits to
/// all three. That is why the signed commitment carries this address and there is no separate
/// lane-binding hash: an account address is collision-free by construction, needs no truncation
/// or birthday argument, is invertible for dispute forensics, and removes a derivation that would
/// otherwise have to be mirrored bug-for-bug in Rust, TypeScript and an Arcis circuit.
#[account]
#[derive(InitSpace)]
pub struct Channel {
    /// Payer `Participant` PDA.
    pub payer: Pubkey,
    /// Payee `Participant` PDA.
    pub payee: Pubkey,
    pub mint: Pubkey,
    /// Key permitted to sign cumulative commitments for this channel. Must be a raw keypair the
    /// payer's agent can sign with using SHA3-512 (ArcisEd25519) — not a browser or hardware
    /// wallet, which can only produce RFC 8032 signatures.
    pub authorized_signer: Pubkey,
    /// Reserved for the v2 rotation instructions. `Pubkey::default()` means none pending.
    pub pending_authorized_signer: Pubkey,
    /// Highest cumulative amount already settled. Monotonic: never decreases. This is the whole
    /// replay-protection mechanism — a commitment whose target is `<=` this value is rejected,
    /// which is what makes "keep only the newest commitment" safe off-chain and why no nonce or
    /// sequence number is needed.
    pub settled_cumulative: u64,
    /// Funds ring-fenced to this channel. Settlement spends this before shared `available`.
    pub locked_balance: u64,
    /// Non-zero iff an unlock is pending.
    pub pending_unlock_amount: u64,
    /// Absolute deadline for the pending unlock.
    pub pending_unlock_at: i64,
    /// Absolute deadline for the pending signer rotation. Reserved for v2.
    pub signer_rotation_unlock_at: i64,
    /// Incremented on every executed signer rotation, and carried in every signed commitment.
    ///
    /// Live state in v1 even though the rotation instructions land in v2, because it is a
    /// *message-format* field: without it, rotating a signer away and later back to the same key
    /// resurrects every stale commitment from the first era, and cumulative monotonicity waves
    /// them through. Adding it after commitments exist would mean re-signing all of them.
    pub signer_epoch: u32,
    pub bump: u8,
    pub _reserved: [u8; 96],
}
