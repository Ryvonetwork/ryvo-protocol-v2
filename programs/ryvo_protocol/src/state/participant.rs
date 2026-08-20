use anchor_lang::prelude::*;

/// Permanent protocol identity for one wallet. PDA seeds: `["participant", owner]`.
///
/// There is also no inbound-channel policy. Opening a channel *to* someone costs them nothing —
/// the payer pays the rent and the only thing it enables is sending them money — so requiring
/// their consent was friction without a matching protection. A payee's real control is whether
/// they choose to serve the payer, which lives off-chain.
///
/// This account is never written after creation, so identity cannot be corrupted by a bug in the
/// balance or channel arithmetic.
#[account]
#[derive(InitSpace)]
pub struct Participant {
    pub owner: Pubkey,
    /// Immutable ArcisEd25519 key used for every channel this participant pays from.
    pub authorized_signer: Pubkey,
    /// Compact, permanent identifier used inside routed commitments.
    pub participant_id: u64,
    pub bump: u8,
    /// Sized for at least two pubkeys plus two timestamps, per the reserved-space rule. The
    /// prior design's participant record had zero reserved bytes, which is precisely what made
    /// its migrations unavoidable.
    pub _reserved: [u8; 56],
}
