use crate::constants::PARTICIPANT_SEED;
use crate::events::ParticipantInitialized;
use crate::state::Participant;
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
    participant.bump = ctx.bumps.participant;
    participant._reserved = [0u8; 96];

    emit!(ParticipantInitialized {
        participant: participant.key(),
        owner: ctx.accounts.owner.key(),
    });
    Ok(())
}
