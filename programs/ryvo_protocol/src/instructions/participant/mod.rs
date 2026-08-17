use crate::constants::PARTICIPANT_SEED;
use crate::events::{InboundChannelPolicyUpdated, ParticipantInitialized};
use crate::state::{InboundChannelPolicy, Participant};
use anchor_lang::prelude::*;

/// Register a permanent protocol identity for one wallet.
///
/// Deliberately touches no other account: there is no global counter, so registrations never
/// contend on a shared account and a user-facing instruction never mutates the singleton config.
#[derive(Accounts)]
pub struct InitializeParticipant<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        init,
        payer = owner,
        space = 8 + Participant::INIT_SPACE,
        seeds = [PARTICIPANT_SEED.as_bytes(), owner.key().as_ref()],
        bump,
    )]
    pub participant: Box<Account<'info, Participant>>,

    pub system_program: Program<'info, System>,
}

pub fn initialize_participant_handler(ctx: Context<InitializeParticipant>) -> Result<()> {
    let participant = &mut ctx.accounts.participant;
    participant.owner = ctx.accounts.owner.key();
    // Consent-required by default: opening a channel *to* someone is a claim on their attention,
    // so the safe default is that they must agree.
    participant.inbound_channel_policy = InboundChannelPolicy::ConsentRequired;
    participant.bump = ctx.bumps.participant;
    participant._reserved = [0u8; 96];

    emit!(ParticipantInitialized {
        participant: participant.key(),
        owner: ctx.accounts.owner.key(),
    });
    Ok(())
}

#[derive(Accounts)]
pub struct UpdateInboundChannelPolicy<'info> {
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [PARTICIPANT_SEED.as_bytes(), owner.key().as_ref()],
        bump = participant.bump,
        has_one = owner,
    )]
    pub participant: Box<Account<'info, Participant>>,
}

pub fn update_inbound_channel_policy_handler(
    ctx: Context<UpdateInboundChannelPolicy>,
    policy: InboundChannelPolicy,
) -> Result<()> {
    let participant = &mut ctx.accounts.participant;
    participant.inbound_channel_policy = policy;

    emit!(InboundChannelPolicyUpdated {
        participant: participant.key(),
        policy: policy as u8,
    });
    Ok(())
}
