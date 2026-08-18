//! The off-chain commitment format.
//!
//! An agent signs a 32-byte SHA-256 digest of a fixed-width canonical message. Nothing in v1
//! verifies signatures — settlement lands in v2 — but the format is fixed now because agents
//! begin signing against it immediately, and changing it later would invalidate every
//! outstanding commitment.
//!
//! # Why a digest rather than raw packed fields
//!
//! ArcisEd25519 verifies a fixed 32-byte message. Packing the fields into those 32 bytes
//! directly would work but leaves only a few bytes of headroom forever. Signing a digest instead
//! costs no extra circuit parameters — only the digest is a circuit input, while the canonical
//! message is staged in an account the callback already reads — and lets the format grow by
//! appending fields and bumping `VERSION`.
//!
//! # Why fixed-width, not compact varints
//!
//! The prior format used LEB128-style compact integers. Varints admit non-canonical encodings
//! (`0x81 0x00` and `0x01` both decode to 1), so one semantic commitment would have several
//! valid signatures — harmless under monotonicity, but it forces any future signature dedup or
//! off-chain cache keying to special-case canonicity. MPC circuits also want fixed-size inputs.
//! Fixed width costs at most 7 bytes.
//!
//! # Length budget
//!
//! In-circuit Ed25519 hashes `R || A || M` = `64 + |M|` bytes through SHA3-512, whose rate is 72
//! bytes. At `|M| = 70` that is 134 bytes, so two permutations, with headroom to `|M| = 79`
//! before a third. `MAX_CANONICAL_LEN` pins that ceiling.

use crate::constants::COMMITMENT_DIGEST_TAG;
use crate::error::RyvoError;
use anchor_lang::prelude::*;
use solana_sha256_hasher::hashv;

/// Distinguishes a unilateral commitment from any future message kind.
pub const KIND_UNILATERAL_COMMITMENT: u8 = 0x01;

/// Identifies both the wire format *and* the signature scheme (ArcisEd25519 / SHA3-512), so a
/// future standard-Ed25519 path can coexist as a different version rather than a new kind.
pub const VERSION: u8 = 0x01;

/// Exact length of the canonical message.
pub const CANONICAL_LEN: usize = 70;

/// Ceiling that keeps in-circuit SHA3-512 at two permutations. See the module docs.
pub const MAX_CANONICAL_LEN: usize = 79;

// Field offsets within the canonical message.
const OFF_DOMAIN: usize = 0;
const OFF_KIND: usize = 16;
const OFF_VERSION: usize = 17;
const OFF_CHANNEL: usize = 18;
const OFF_TARGET: usize = 50;
const OFF_SIGNER_EPOCH: usize = 58;
const OFF_EXPIRY: usize = 62;

/// A decoded commitment. Field order matches the wire layout.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Commitment {
    /// Deployment replay boundary; must equal `Config.message_domain`.
    pub message_domain: [u8; 16],
    /// The `Channel` PDA. Commits to payer, payee, mint and program id at once, which is why
    /// there is no separate lane-binding hash.
    pub channel: Pubkey,
    /// New cumulative authorization. Must strictly exceed `Channel.settled_cumulative`.
    pub target_cumulative: u64,
    /// Must equal `Channel.signer_epoch`. Binds the commitment to one signer era so that
    /// rotating a signer away and later back cannot resurrect stale commitments.
    pub signer_epoch: u32,
    /// Unix seconds; `0` means no expiry.
    pub expiry_unix: i64,
}

impl Commitment {
    /// Serialize to the canonical byte layout that gets hashed and signed.
    pub fn encode(&self) -> [u8; CANONICAL_LEN] {
        let mut out = [0u8; CANONICAL_LEN];
        out[OFF_DOMAIN..OFF_KIND].copy_from_slice(&self.message_domain);
        out[OFF_KIND] = KIND_UNILATERAL_COMMITMENT;
        out[OFF_VERSION] = VERSION;
        out[OFF_CHANNEL..OFF_TARGET].copy_from_slice(self.channel.as_ref());
        out[OFF_TARGET..OFF_SIGNER_EPOCH].copy_from_slice(&self.target_cumulative.to_le_bytes());
        out[OFF_SIGNER_EPOCH..OFF_EXPIRY].copy_from_slice(&self.signer_epoch.to_le_bytes());
        out[OFF_EXPIRY..CANONICAL_LEN].copy_from_slice(&self.expiry_unix.to_le_bytes());
        out
    }

    /// The 32 bytes an agent actually signs.
    pub fn digest(&self) -> [u8; 32] {
        digest_of(&self.encode())
    }

    /// Parse a canonical message, rejecting anything malformed.
    ///
    /// Strict about length, `kind` and `version` so that a v2 reader can never silently accept a
    /// message a future version meant differently.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        require!(
            bytes.len() == CANONICAL_LEN,
            RyvoError::InvalidCommitmentMessage
        );
        require!(
            bytes[OFF_KIND] == KIND_UNILATERAL_COMMITMENT,
            RyvoError::InvalidCommitmentMessage
        );
        require!(
            bytes[OFF_VERSION] == VERSION,
            RyvoError::InvalidCommitmentMessage
        );

        let mut message_domain = [0u8; 16];
        message_domain.copy_from_slice(&bytes[OFF_DOMAIN..OFF_KIND]);

        let mut channel = [0u8; 32];
        channel.copy_from_slice(&bytes[OFF_CHANNEL..OFF_TARGET]);

        let mut target = [0u8; 8];
        target.copy_from_slice(&bytes[OFF_TARGET..OFF_SIGNER_EPOCH]);

        let mut epoch = [0u8; 4];
        epoch.copy_from_slice(&bytes[OFF_SIGNER_EPOCH..OFF_EXPIRY]);

        let mut expiry = [0u8; 8];
        expiry.copy_from_slice(&bytes[OFF_EXPIRY..CANONICAL_LEN]);

        Ok(Self {
            message_domain,
            channel: Pubkey::new_from_array(channel),
            target_cumulative: u64::from_le_bytes(target),
            signer_epoch: u32::from_le_bytes(epoch),
            expiry_unix: i64::from_le_bytes(expiry),
        })
    }
}

/// Domain-separated digest of an already-encoded canonical message.
pub fn digest_of(canonical: &[u8]) -> [u8; 32] {
    hashv(&[COMMITMENT_DIGEST_TAG.as_bytes(), canonical]).to_bytes()
}

/// The replay rule: a commitment must strictly increase the channel's cumulative total.
///
/// This *is* the replay-protection mechanism, which is why the format carries no nonce and no
/// sequence number. It is also what makes "keep only the newest commitment" safe off-chain.
pub fn check_monotonic(target_cumulative: u64, settled_cumulative: u64) -> Result<u64> {
    require!(
        target_cumulative > settled_cumulative,
        RyvoError::CommitmentAmountMustIncrease
    );
    target_cumulative
        .checked_sub(settled_cumulative)
        .ok_or_else(|| RyvoError::MathOverflow.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sample() -> Commitment {
        Commitment {
            message_domain: [
                0x99, 0xc6, 0x70, 0xaf, 0x9d, 0xa7, 0x68, 0xbc, 0x42, 0x7a, 0x4b, 0x1b, 0x1b, 0x0f,
                0x12, 0x67,
            ],
            channel: Pubkey::from_str("7QBj1XUYe4RbMxJd8H42gWR7QWeRiRuYQbwbwAjAmjqQ").unwrap(),
            target_cumulative: 1_000_000,
            signer_epoch: 0,
            expiry_unix: 0,
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn length_is_within_the_sha3_budget() {
        assert_eq!(CANONICAL_LEN, 70);
        assert!(
            CANONICAL_LEN <= MAX_CANONICAL_LEN,
            "canonical message exceeds the two-permutation SHA3-512 budget"
        );
    }

    #[test]
    fn round_trips() {
        let c = sample();
        assert_eq!(Commitment::decode(&c.encode()).unwrap(), c);
    }

    #[test]
    fn field_offsets_are_stable() {
        let c = sample();
        let b = c.encode();
        assert_eq!(&b[0..16], &c.message_domain);
        assert_eq!(b[16], KIND_UNILATERAL_COMMITMENT);
        assert_eq!(b[17], VERSION);
        assert_eq!(&b[18..50], c.channel.as_ref());
        assert_eq!(&b[50..58], &1_000_000u64.to_le_bytes());
        assert_eq!(&b[58..62], &0u32.to_le_bytes());
        assert_eq!(&b[62..70], &0i64.to_le_bytes());
    }

    #[test]
    fn rejects_wrong_length() {
        let c = sample();
        let b = c.encode();
        assert!(Commitment::decode(&b[..69]).is_err());
        let mut long = b.to_vec();
        long.push(0);
        assert!(Commitment::decode(&long).is_err());
    }

    #[test]
    fn rejects_wrong_kind_and_version() {
        let c = sample();

        let mut bad_kind = c.encode();
        bad_kind[OFF_KIND] = 0x02;
        assert!(Commitment::decode(&bad_kind).is_err());

        let mut bad_version = c.encode();
        bad_version[OFF_VERSION] = 0x02;
        assert!(Commitment::decode(&bad_version).is_err());
    }

    /// Every field must change the digest, or it is not actually being signed over.
    #[test]
    fn every_field_is_covered_by_the_digest() {
        let base = sample();
        let d = base.digest();

        let mut variants = vec![];
        variants.push(Commitment {
            message_domain: [0xff; 16],
            ..base
        });
        variants.push(Commitment {
            channel: Pubkey::new_unique(),
            ..base
        });
        variants.push(Commitment {
            target_cumulative: base.target_cumulative + 1,
            ..base
        });
        variants.push(Commitment {
            signer_epoch: 1,
            ..base
        });
        variants.push(Commitment {
            expiry_unix: 1,
            ..base
        });

        for v in variants {
            assert_ne!(v.digest(), d, "a field change did not alter the digest: {v:?}");
        }
    }

    #[test]
    fn monotonicity_rejects_equal_and_lower() {
        assert!(check_monotonic(100, 100).is_err());
        assert!(check_monotonic(99, 100).is_err());
        assert_eq!(check_monotonic(150, 100).unwrap(), 50);
        assert_eq!(check_monotonic(u64::MAX, 0).unwrap(), u64::MAX);
        assert_eq!(check_monotonic(u64::MAX, u64::MAX - 1).unwrap(), 1);
    }

    /// Golden vectors. `tests/vectors/commitment.json` carries the same values and the
    /// TypeScript client is asserted against that file, so a field added on one side without the
    /// other breaks a test immediately rather than silently producing unverifiable signatures.
    #[test]
    fn golden_vectors() {
        let c = sample();
        assert_eq!(
            hex(&c.encode()),
            "99c670af9da768bc427a4b1b1b0f126701015f169b2d9ed820c0eaf9c72740fa\
             39e309e4fdd94c8cc5105bf66b53837ed0cf40420f0000000000000000000000\
             000000000000",
        );
        assert_eq!(
            hex(&c.digest()),
            "dde0727db01c86c1f5bdbf04696d654b20d24a26e81030a97726eab3b60469c9",
        );
    }
}
