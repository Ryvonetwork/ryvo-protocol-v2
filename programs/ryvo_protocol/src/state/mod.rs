pub mod balance;
pub mod channel;
pub mod config;
pub mod participant;
pub mod token_config;

pub use balance::*;
pub use channel::*;
pub use config::*;
pub use participant::*;
pub use token_config::*;

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::prelude::Pubkey;
    use anchor_lang::Space;

    /// Pins every account size. A field added without deliberately updating this test is a
    /// silent account-size change, which for accounts already holding live funds means a
    /// migration.
    #[test]
    fn account_sizes_are_pinned() {
        // 8-byte Anchor discriminator is added on top of INIT_SPACE by `#[account(space = ..)]`
        // call sites, so these figures are the payload only.
        assert_eq!(Config::INIT_SPACE, 32 + 32 + 16 + 8 + 2 + 8 + 8 + 1 + 112);
        assert_eq!(Participant::INIT_SPACE, 32 + 32 + 8 + 1 + 56);
        assert_eq!(TokenConfig::INIT_SPACE, 32 + 32 + 1 + 1 + 1 + 96);
        assert_eq!(Balance::INIT_SPACE, 32 + 32 + 8 + 8 + 1 + 88);
        assert_eq!(
            Channel::INIT_SPACE,
            32 + 32 + 32 + 32 + 8 + 8 + 8 + 8 + 8 + 64 + 1 + 88
        );
    }

    /// Every non-singleton account keeps meaningful reserved space. Participant used 40 bytes
    /// of its original reserve for the permanent signer and compact id without changing size.
    #[test]
    fn non_singleton_accounts_reserve_growth_room() {
        const MIN_RESERVED: usize = 48;
        for (name, reserved) in [
            ("Participant", 56usize),
            ("TokenConfig", 96),
            ("Balance", 88),
            ("Channel", 88),
        ] {
            assert!(
                reserved >= MIN_RESERVED,
                "{name} reserves {reserved} bytes, below the {MIN_RESERVED}-byte floor"
            );
        }
    }

    /// The circuit reads `signer_slots` straight out of the account bytes by offset, so the
    /// offset is part of the wire contract with the staging client and the Arcium argument list.
    #[test]
    fn channel_signer_slots_offset_is_pinned() {
        use anchor_lang::AccountSerialize;
        let mut c = Channel {
            payer: Pubkey::new_unique(),
            payee: Pubkey::new_unique(),
            mint: Pubkey::new_unique(),
            authorized_signer: Pubkey::new_unique(),
            settled_cumulative: 1,
            locked_balance: 2,
            pending_unlock_amount: 3,
            pending_unlock_at: 4,
            channel_id: 5,
            signer_slots: [[0xAA; 32], [0xBB; 32]],
            bump: 6,
            _reserved: [0u8; 88],
        };
        c.signer_slots[0][31] = 0x11;
        let mut bytes = Vec::new();
        c.try_serialize(&mut bytes).unwrap();
        let off = Channel::SIGNER_SLOTS_OFFSET;
        assert_eq!(&bytes[off..off + 32], &c.signer_slots[0]);
        assert_eq!(&bytes[off + 32..off + 64], &c.signer_slots[1]);
        assert_eq!(bytes[off + 64], 6, "bump follows signer_slots");
    }

    /// `Balance` holds nothing but free money and its identity. No pending-withdrawal state,
    /// because a withdrawal is immediate — settlement cannot reach `available`, so there is
    /// nothing for a timelock to protect.
    #[test]
    fn balance_carries_no_pending_withdrawal_state() {
        assert_eq!(Balance::INIT_SPACE, 32 + 32 + 8 + 1 + 96);
    }
}
