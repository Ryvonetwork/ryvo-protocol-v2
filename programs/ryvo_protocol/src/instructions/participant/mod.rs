use crate::constants::{CONFIG_SEED, PARTICIPANT_SEED};
use crate::error::RyvoError;
use crate::events::ParticipantInitialized;
use crate::state::{Config, Participant};
use anchor_lang::prelude::*;

/// Register a permanent protocol identity for one wallet.
///
#[derive(Accounts)]
pub struct InitializeParticipant<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        mut,
        seeds = [CONFIG_SEED.as_bytes()],
        bump = config.bump,
    )]
    pub config: Box<Account<'info, Config>>,

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

pub fn initialize_participant_handler(
    ctx: Context<InitializeParticipant>,
    authorized_signer: Pubkey,
) -> Result<()> {
    require!(
        authorized_signer != Pubkey::default(),
        RyvoError::InvalidAuthorizedSigner
    );

    let participant_id = ctx.accounts.config.next_participant_id;
    ctx.accounts.config.next_participant_id = participant_id
        .checked_add(1)
        .ok_or(RyvoError::MathOverflow)?;

    let participant = &mut ctx.accounts.participant;
    participant.owner = ctx.accounts.owner.key();
    participant.authorized_signer = authorized_signer;
    participant.participant_id = participant_id;
    participant.bump = ctx.bumps.participant;
    participant._reserved = [0u8; 56];

    emit!(ParticipantInitialized {
        participant: participant.key(),
        owner: ctx.accounts.owner.key(),
        participant_id,
        authorized_signer,
    });
    Ok(())
}
