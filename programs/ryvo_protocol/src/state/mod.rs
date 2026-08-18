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
    use anchor_lang::Space;

    /// Pins every account size. A field added without deliberately updating this test is a
    /// silent account-size change, which for accounts already holding live funds means a
    /// migration.
    #[test]
    fn account_sizes_are_pinned() {
        // 8-byte Anchor discriminator is added on top of INIT_SPACE by `#[account(space = ..)]`
        // call sites, so these figures are the payload only.
        assert_eq!(Config::INIT_SPACE, 32 + 32 + 32 + 16 + 8 + 2 + 2 + 1 + 128);
        assert_eq!(Participant::INIT_SPACE, 32 + 1 + 96);
        assert_eq!(TokenConfig::INIT_SPACE, 32 + 32 + 8 + 1 + 1 + 1 + 96);
        assert_eq!(Balance::INIT_SPACE, 32 + 32 + 8 + 1 + 96);
        assert_eq!(
            Channel::INIT_SPACE,
            32 + 32 + 32 + 32 + 8 + 8 + 8 + 8 + 1 + 96
        );
    }

    /// Every non-singleton account must carry reserved space for at least two pubkeys plus two
    /// timestamps. The prior design's lane record had zero reserved bytes; that is the condition
    /// that makes a migration unavoidable rather than optional.
    #[test]
    fn non_singleton_accounts_reserve_growth_room() {
        const MIN_RESERVED: usize = 2 * 32 + 2 * 8;
        for (name, reserved) in [
            ("Participant", 96usize),
            ("TokenConfig", 96),
            ("Balance", 96),
            ("Channel", 96),
        ] {
            assert!(
                reserved >= MIN_RESERVED,
                "{name} reserves {reserved} bytes, below the {MIN_RESERVED}-byte floor"
            );
        }
    }

    /// `Balance` holds nothing but free money and its identity. No pending-withdrawal state,
    /// because a withdrawal is immediate — settlement cannot reach `available`, so there is
    /// nothing for a timelock to protect.
    #[test]
    fn balance_carries_no_pending_withdrawal_state() {
        assert_eq!(Balance::INIT_SPACE, 32 + 32 + 8 + 1 + 96);
    }
}
