use anchor_lang::prelude::*;

/// Whether other parties may open channels *to* this participant.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum InboundChannelPolicy {
    /// Anyone may open an inbound channel without the payee signing.
    Permissionless,
    /// The payee must co-sign `create_channel`. Default.
    ConsentRequired,
    /// No new inbound channels.
    Disabled,
}

impl Space for InboundChannelPolicy {
    /// Borsh encodes a fieldless enum as a single-byte discriminant.
    const INIT_SPACE: usize = 1;
}

/// Permanent protocol identity for one wallet. PDA seeds: `["participant", owner]`.
///
/// There is deliberately no numeric participant id and no global counter. The PDA *is* the
/// identity: it is derived from the owner, there is no close instruction, so it can never be
/// recycled — which is the property that matters for replay safety. A counter would also have
/// forced every registration to write-lock the singleton `Config`, serialising all sign-ups and
/// letting a user-facing instruction mutate the account that holds the fee parameters.
///
/// This account is written only by `update_inbound_channel_policy`; the money path never touches
/// it, so identity cannot be corrupted by a bug in balance or channel arithmetic.
#[account]
#[derive(InitSpace)]
pub struct Participant {
    pub owner: Pubkey,
    pub inbound_channel_policy: InboundChannelPolicy,
    pub bump: u8,
    /// Sized for at least two pubkeys plus two timestamps, per the reserved-space rule. The
    /// prior design's participant record had zero reserved bytes, which is precisely what made
    /// its migrations unavoidable.
    pub _reserved: [u8; 96],
}
