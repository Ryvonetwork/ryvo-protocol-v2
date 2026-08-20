use crate::constants::MESSAGE_DOMAIN_TAG;
use anchor_lang::prelude::*;
use solana_sha256_hasher::hashv;

/// Deployment-scoped replay boundary, derived in-program at `initialize` and immutable after.
///
/// `SHA256(MESSAGE_DOMAIN_TAG || program_id || chain_id_le)[..16]`
///
/// Every signed commitment carries this value, so a commitment signed for one deployment can
/// never be replayed against another — a different program id or a different chain id yields a
/// different domain. It is derived rather than supplied so no authority can ever set it to a
/// value that collides with another deployment.
pub fn derive_message_domain(program_id: &Pubkey, chain_id: u16) -> [u8; 16] {
    let digest = hashv(&[
        MESSAGE_DOMAIN_TAG.as_bytes(),
        program_id.as_ref(),
        &chain_id.to_le_bytes(),
    ]);
    let mut domain = [0u8; 16];
    domain.copy_from_slice(&digest.to_bytes()[..16]);
    domain
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// The program id this deployment declares. Kept here so the vector test below fails loudly
    /// if `declare_id!` ever changes without the message-domain implications being considered:
    /// changing the program id invalidates every previously signed commitment.
    fn program_id() -> Pubkey {
        Pubkey::from_str("9QHMKt6ANEzaCEgzk9p1Vaex2yeLLhaLXNfEYCiGGS2Q").unwrap()
    }

    #[test]
    fn is_deterministic() {
        let a = derive_message_domain(&program_id(), 1);
        let b = derive_message_domain(&program_id(), 1);
        assert_eq!(a, b);
    }

    #[test]
    fn differs_per_chain_id() {
        let mut seen = std::collections::HashSet::new();
        for chain_id in 0u16..4 {
            assert!(
                seen.insert(derive_message_domain(&program_id(), chain_id)),
                "chain_id {chain_id} collided with another chain_id"
            );
        }
    }

    #[test]
    fn differs_per_program_id() {
        let other = Pubkey::new_unique();
        assert_ne!(
            derive_message_domain(&program_id(), 1),
            derive_message_domain(&other, 1),
            "domain must bind to the program id"
        );
    }

    /// Golden vectors for this deployment, computed independently of this implementation. The
    /// TypeScript client asserts the same values, so a change to the tag, the field order, the
    /// endianness, or the truncation length breaks this test on one side and the conformance
    /// test on the other.
    #[test]
    fn golden_vectors() {
        let cases: [(u16, &str); 4] = [
            (0, "5ff81e93bfc5175dbd76d33921fe3fec"),
            (1, "f1d306e12e54ad4762ad363ef481cddb"),
            (2, "94dcb0d27d52fec356d908a0752d3a18"),
            (3, "dd42adb878834422a8bf8d42d0f2daee"),
        ];
        for (chain_id, expected) in cases {
            assert_eq!(
                hex(&derive_message_domain(&program_id(), chain_id)),
                expected,
                "message_domain changed for chain_id {chain_id}; this invalidates every \
                 previously signed commitment"
            );
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
