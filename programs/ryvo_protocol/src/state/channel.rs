use anchor_lang::prelude::*;

/// One standalone direct payment relationship.
/// PDA seeds: `["channel", payer_participant, payee_participant, mint]`.
///
/// Strictly one-way: `(A -> B)` and `(B -> A)` are different accounts, so bidirectional traffic
/// uses two channels. Permanent — there is no close instruction, which removes any
/// close-and-reopen replay boundary.
///
/// The PDA is derived from payer, payee and mint, so the address commits to all three. Signed
/// commitments name the channel by `channel_id` (a global counter) rather than by that address:
/// eight bytes instead of thirty-two keeps a staged record small enough to clear in bulk. The
/// binding is transitive — `settle_channels` requires `staged_id == channel.channel_id` on the
/// account it is handed — and safe because ids are never reused.
///
/// Routed channels do not use this account type; they occupy permanent slots in a
/// `RoutedChannelBucket`. `kind` remains pinned to `CHANNEL_KIND_DIRECT` as an explicit wire guard.
#[account]
#[derive(InitSpace)]
pub struct Channel {
    /// Payer `Participant` PDA.
    pub payer: Pubkey,
    /// Payee `Participant` PDA.
    pub payee: Pubkey,
    pub mint: Pubkey,
    /// Key permitted to sign cumulative commitments for this channel, fixed for the channel's
    /// life. Must be a raw keypair the payer's agent can sign with using SHA3-512
    /// (ArcisEd25519) — a smart account cannot be a signer here, because signing requires a
    /// private key rather than program privilege.
    ///
    /// **There is deliberately no rotation.** Changing the signer would invalidate every
    /// outstanding commitment, which hands the payer a weapon: sign, receive service, then rotate
    /// and leave the payee unpaid. A timelock narrows that window without closing it. The
    /// alternative — a permanently dead relationship after a key leak — is the cheaper failure,
    /// because the loss is bounded and recoverable: a leaked signer can only authorise payments
    /// to this channel's payee, capped at `locked_balance`, and the owner wallet (which the leak
    /// does not touch) can always unlock the collateral through the timelock.
    pub authorized_signer: Pubkey,
    /// Highest cumulative amount already settled. Monotonic: never decreases. This is the whole
    /// replay-protection mechanism — a commitment whose target is `<=` this value is rejected,
    /// which is what makes "keep only the newest commitment" safe off-chain and why no nonce or
    /// sequence number is needed.
    pub settled_cumulative: u64,
    /// Funds ring-fenced to this channel, and the *only* source settlement may spend. It can
    /// never reach the payer's shared `available` balance, which is what bounds a payee's
    /// exposure to exactly what was locked and lets withdrawals be immediate.
    pub locked_balance: u64,
    /// Non-zero iff an unlock is pending.
    pub pending_unlock_amount: u64,
    /// Absolute deadline for the pending unlock.
    pub pending_unlock_at: i64,
    /// Assigned from `Config.next_channel_id` at creation. Never 0, never reused.
    pub channel_id: u64,
    /// `authorized_signer` in the two-slot packed form the Arcis circuit unpacks
    /// (`Pack<VerifyingKey>`: 26 bytes + 6 bytes, little-endian, one 32-byte slot each).
    /// `stage_records` copies these two slots from this account into the staging buffer the
    /// circuit reads, so the relayer never stages keys and cannot substitute one.
    pub signer_slots: [[u8; 32]; 2],
    pub bump: u8,
    /// Always `CHANNEL_KIND_DIRECT`. Kept after `signer_slots` so their circuit-facing byte offset
    /// remains unchanged and old standalone routed accounts cannot be interpreted as direct.
    pub kind: u8,
    pub _reserved: [u8; 87],
}

impl Channel {
    /// 8 (discriminator) + 4 × 32 (pubkeys) + 5 × 8 (u64/i64) = 176.
    pub const SIGNER_SLOTS_OFFSET: usize = 8 + 4 * 32 + 5 * 8;
    pub const SIGNER_SLOTS_LEN: usize = 64;
}
