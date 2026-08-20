//! The off-chain commitment format, and the slot layout it is staged in for Arcium.
//!
//! An agent signs a 32-byte SHA3-256 digest of a fixed-width canonical message. The Arcis
//! circuit rebuilds that digest itself from the staged fields and verifies the ArcisEd25519
//! signature over it, so a signature can only ever vouch for the exact `(channel, target)` that
//! was staged — nothing on-chain has to hash anything.
//!
//! # Two message kinds
//!
//! * `kind = 0x01` **unilateral**: one signer, one channel. "I authorise this channel up to
//!   `target_cumulative`."
//! * `kind = 0x02` **route**: the agent and gateway sign one cumulative source-channel target
//!   plus the complete provider allocation for that increase. Settlement debits the agent's
//!   locked channel and credits every provider and the gateway fee directly in one instruction.
//!   There is no gateway pool and no gateway-to-provider channel.
//!
//! Channels and providers are named by permanent u64 ids, not 32-byte addresses. A route carries
//! at most `MAX_ROUTE_ALLOCATIONS` providers; unused entries are zero. The fixed canonical width
//! keeps the circuit shape deterministic, while staging transmits only active allocations.
//!
//! # Why SHA3-256, not SHA-256
//!
//! `SHA3_256::digest` exists inside the circuit and costs nothing on-chain, because no
//! instruction ever computes a digest: the circuit binds the signature to the staged fields,
//! and `settle_channels` reads those same sealed bytes. Solana has no SHA3-256 syscall, so
//! SHA-256 would have forced either staging the digest (32 extra bytes per record) or a
//! per-record on-chain re-hash. This crate's `digest_of` is host-side only in practice.
//!
//! # Why fixed-width, not compact varints
//!
//! Varints admit non-canonical encodings, so one commitment would have several valid
//! signatures, and MPC circuits want fixed-size inputs anyway.
//!
//! # Why there is no expiry
//!
//! A commitment records that the payee did the work and the payer owes for it. It is a debt,
//! not a time-limited offer. An expiry field would let a payer repudiate by waiting — the same
//! attack signer rotation was removed to prevent. The accepted cost: a payer who over-signs can
//! never clear the claim on-chain and must abandon that channel.

use crate::constants::COMMITMENT_DIGEST_TAG;
use crate::error::RyvoError;
use anchor_lang::prelude::*;

pub const KIND_UNILATERAL: u8 = 0x01;
pub const KIND_ROUTE: u8 = 0x02;
pub const MAX_ROUTE_ALLOCATIONS: usize = 16;

/// Identifies both the wire format *and* the signature scheme (ArcisEd25519 / SHA3-512).
pub const VERSION: u8 = 0x01;

/// `domain(16) | kind(1) | version(1) | channel_id(8) | target(8)`
pub const UNILATERAL_LEN: usize = 34;
/// `domain | kind | version | source_id | base | target | count | (provider_id, amount)[16]`.
pub const ROUTE_LEN: usize = 18 + 4 * 8 + MAX_ROUTE_ALLOCATIONS * 16;

const OFF_DOMAIN: usize = 0;
const OFF_KIND: usize = 16;
const OFF_VERSION: usize = 17;
const OFF_BODY: usize = 18;

/// A single-signer commitment.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UnilateralCommitment {
    /// Deployment replay boundary; must equal `Config.message_domain`.
    pub message_domain: [u8; 16],
    pub channel_id: u64,
    /// New cumulative authorisation. Must strictly exceed `Channel.settled_cumulative`.
    pub target_cumulative: u64,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct RouteAllocation {
    pub participant_id: u64,
    pub amount: u64,
}

/// One two-signer cumulative route bundle for an agent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RouteCommitment {
    pub message_domain: [u8; 16],
    /// Agent -> gateway source channel, signed by the agent and the gateway.
    pub source_channel_id: u64,
    /// First cumulative unit described by this bundle. A newer bundle keeps the same base until
    /// the previous allocations have settled, so it can replace every older off-chain message.
    pub base_cumulative: u64,
    pub target_cumulative: u64,
    pub allocation_count: u8,
    /// Ordered provider ranges. Partial settlement pays them in this signed order; any remainder
    /// between the last provider range and `target_cumulative` is the gateway fee.
    pub allocations: [RouteAllocation; MAX_ROUTE_ALLOCATIONS],
}

impl UnilateralCommitment {
    pub fn encode(&self) -> [u8; UNILATERAL_LEN] {
        let mut out = [0u8; UNILATERAL_LEN];
        out[OFF_DOMAIN..OFF_KIND].copy_from_slice(&self.message_domain);
        out[OFF_KIND] = KIND_UNILATERAL;
        out[OFF_VERSION] = VERSION;
        out[OFF_BODY..OFF_BODY + 8].copy_from_slice(&self.channel_id.to_le_bytes());
        out[OFF_BODY + 8..OFF_BODY + 16].copy_from_slice(&self.target_cumulative.to_le_bytes());
        out
    }

    pub fn digest(&self) -> [u8; 32] {
        digest_of(&self.encode())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        require!(
            bytes.len() == UNILATERAL_LEN,
            RyvoError::InvalidCommitmentMessage
        );
        require!(
            bytes[OFF_KIND] == KIND_UNILATERAL,
            RyvoError::InvalidCommitmentMessage
        );
        require!(
            bytes[OFF_VERSION] == VERSION,
            RyvoError::InvalidCommitmentMessage
        );
        let mut message_domain = [0u8; 16];
        message_domain.copy_from_slice(&bytes[OFF_DOMAIN..OFF_KIND]);
        Ok(Self {
            message_domain,
            channel_id: u64::from_le_bytes(bytes[OFF_BODY..OFF_BODY + 8].try_into().unwrap()),
            target_cumulative: u64::from_le_bytes(
                bytes[OFF_BODY + 8..OFF_BODY + 16].try_into().unwrap(),
            ),
        })
    }

    /// The single u128 slot the circuit and the staging buffer use for this record's body.
    /// Its little-endian bytes are exactly canonical bytes `[18..34]`.
    pub fn body_slot(&self) -> u128 {
        pack_pair(self.channel_id, self.target_cumulative)
    }
}

impl RouteCommitment {
    pub fn encode(&self) -> [u8; ROUTE_LEN] {
        let mut out = [0u8; ROUTE_LEN];
        out[OFF_DOMAIN..OFF_KIND].copy_from_slice(&self.message_domain);
        out[OFF_KIND] = KIND_ROUTE;
        out[OFF_VERSION] = VERSION;
        out[OFF_BODY..OFF_BODY + 8].copy_from_slice(&self.source_channel_id.to_le_bytes());
        out[OFF_BODY + 8..OFF_BODY + 16].copy_from_slice(&self.base_cumulative.to_le_bytes());
        out[OFF_BODY + 16..OFF_BODY + 24].copy_from_slice(&self.target_cumulative.to_le_bytes());
        out[OFF_BODY + 24..OFF_BODY + 32]
            .copy_from_slice(&(self.allocation_count as u64).to_le_bytes());
        for (i, allocation) in self.allocations.iter().enumerate() {
            let at = OFF_BODY + 32 + i * 16;
            out[at..at + 8].copy_from_slice(&allocation.participant_id.to_le_bytes());
            out[at + 8..at + 16].copy_from_slice(&allocation.amount.to_le_bytes());
        }
        out
    }

    pub fn digest(&self) -> [u8; 32] {
        digest_of(&self.encode())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        require!(
            bytes.len() == ROUTE_LEN,
            RyvoError::InvalidCommitmentMessage
        );
        require!(
            bytes[OFF_KIND] == KIND_ROUTE,
            RyvoError::InvalidCommitmentMessage
        );
        require!(
            bytes[OFF_VERSION] == VERSION,
            RyvoError::InvalidCommitmentMessage
        );
        let mut message_domain = [0u8; 16];
        message_domain.copy_from_slice(&bytes[OFF_DOMAIN..OFF_KIND]);
        let u = |o: usize| {
            u64::from_le_bytes(bytes[OFF_BODY + o..OFF_BODY + o + 8].try_into().unwrap())
        };
        let count = u(24);
        require!(
            count <= MAX_ROUTE_ALLOCATIONS as u64,
            RyvoError::InvalidRouteAllocations
        );
        let mut allocations = [RouteAllocation::default(); MAX_ROUTE_ALLOCATIONS];
        for (i, allocation) in allocations.iter_mut().enumerate() {
            let at = 32 + i * 16;
            allocation.participant_id = u(at);
            allocation.amount = u(at + 8);
        }
        let commitment = Self {
            message_domain,
            source_channel_id: u(0),
            base_cumulative: u(8),
            target_cumulative: u(16),
            allocation_count: count as u8,
            allocations,
        };
        commitment.validate()?;
        Ok(commitment)
    }

    pub fn validate(&self) -> Result<(u64, u64)> {
        let count = self.allocation_count as usize;
        require!(
            count > 0 && count <= MAX_ROUTE_ALLOCATIONS,
            RyvoError::InvalidRouteAllocations
        );
        require!(
            self.base_cumulative < self.target_cumulative,
            RyvoError::InvalidRouteAllocations
        );
        let mut provider_total = 0u64;
        for (i, allocation) in self.allocations.iter().enumerate() {
            if i < count {
                require!(
                    allocation.participant_id != 0 && allocation.amount > 0,
                    RyvoError::InvalidRouteAllocations
                );
                require!(
                    !self.allocations[..i]
                        .iter()
                        .any(|prior| prior.participant_id == allocation.participant_id),
                    RyvoError::InvalidRouteAllocations
                );
                provider_total = provider_total
                    .checked_add(allocation.amount)
                    .ok_or(RyvoError::MathOverflow)?;
            } else {
                require!(
                    allocation.participant_id == 0 && allocation.amount == 0,
                    RyvoError::InvalidRouteAllocations
                );
            }
        }
        let increase = self
            .target_cumulative
            .checked_sub(self.base_cumulative)
            .ok_or(RyvoError::MathOverflow)?;
        require!(
            provider_total <= increase,
            RyvoError::InvalidRouteAllocations
        );
        Ok((provider_total, increase - provider_total))
    }

    /// Fixed body slots read by the route circuit. Little-endian bytes are the canonical body.
    pub fn body_slots(&self) -> [u128; 2 + MAX_ROUTE_ALLOCATIONS] {
        let mut out = [0u128; 2 + MAX_ROUTE_ALLOCATIONS];
        out[0] = pack_pair(self.source_channel_id, self.base_cumulative);
        out[1] = pack_pair(self.target_cumulative, self.allocation_count as u64);
        for (i, allocation) in self.allocations.iter().enumerate() {
            out[2 + i] = pack_pair(allocation.participant_id, allocation.amount);
        }
        out
    }
}

/// `lo | hi << 64`. Little-endian bytes of the result are `lo_le || hi_le`.
pub const fn pack_pair(lo: u64, hi: u64) -> u128 {
    (lo as u128) | ((hi as u128) << 64)
}

pub const fn unpack_pair(v: u128) -> (u64, u64) {
    (v as u64, (v >> 64) as u64)
}

/// The 16 message-domain bytes as the u128 slot the circuit receives them in.
pub fn domain_slot(message_domain: &[u8; 16]) -> u128 {
    u128::from_le_bytes(*message_domain)
}

/// Domain-separated digest: `SHA3-256(COMMITMENT_DIGEST_TAG || canonical)`. Not called by any
/// instruction; the circuit computes the same thing in-MPC.
pub fn digest_of(canonical: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(COMMITMENT_DIGEST_TAG.as_bytes());
    h.update(canonical);
    h.finalize().into()
}

// ---------------------------------------------------------------------------------------------
// Field-element slot packing, mirroring arcis-compiler's first-fit-decreasing byte packing:
// 214 usable bits per element => 26 bytes per slot, little-endian within the slot. A 32-byte
// public key is 2 slots (26 + 6), a 64-byte signature is 3 (26 + 26 + 12). These are the exact
// bytes `Pack<VerifyingKey>` / `Pack<Sig>` unpack inside the circuit; `stage_records` writes
// them from the record and the `Channel` account.

pub const SLOT: usize = 32;
pub const BYTES_PER_SLOT: usize = 26;
pub const PUBKEY_SLOTS: usize = 2;
pub const SIG_SLOTS: usize = 3;

pub fn pack_bytes_into_slots<const N: usize>(bytes: &[u8], out: &mut [[u8; SLOT]; N]) {
    for (i, chunk) in bytes.chunks(BYTES_PER_SLOT).enumerate() {
        out[i] = [0u8; SLOT];
        out[i][..chunk.len()].copy_from_slice(chunk);
    }
}

pub fn pack_pubkey(pk: &[u8; 32]) -> [[u8; SLOT]; PUBKEY_SLOTS] {
    let mut out = [[0u8; SLOT]; PUBKEY_SLOTS];
    pack_bytes_into_slots(pk, &mut out);
    out
}

pub fn unpack_pubkey(slots: &[[u8; SLOT]; PUBKEY_SLOTS]) -> [u8; 32] {
    let mut pk = [0u8; 32];
    pk[..26].copy_from_slice(&slots[0][..26]);
    pk[26..].copy_from_slice(&slots[1][..6]);
    pk
}

pub fn pack_signature(sig: &[u8; 64]) -> [[u8; SLOT]; SIG_SLOTS] {
    let mut out = [[0u8; SLOT]; SIG_SLOTS];
    pack_bytes_into_slots(sig, &mut out);
    out
}

/// The replay rule: a commitment must strictly increase the channel's cumulative total.
///
/// This *is* the replay-protection mechanism, which is why the format carries no nonce and no
/// sequence number. It is also what makes "keep only the newest commitment" safe off-chain.
///
/// Returns the *authorised* delta, not the payable one. Settlement is partial: the caller moves
/// `min(delta, locked_balance)` and advances `settled_cumulative` by only what it actually
/// moved, so an under-collateralised commitment stays live and collects the remainder later.
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

    const DOMAIN: [u8; 16] = [
        0x99, 0xc6, 0x70, 0xaf, 0x9d, 0xa7, 0x68, 0xbc, 0x42, 0x7a, 0x4b, 0x1b, 0x1b, 0x0f, 0x12,
        0x67,
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn uni() -> UnilateralCommitment {
        UnilateralCommitment {
            message_domain: DOMAIN,
            channel_id: 7,
            target_cumulative: 1_000_000,
        }
    }
    fn route() -> RouteCommitment {
        let mut allocations = [RouteAllocation::default(); MAX_ROUTE_ALLOCATIONS];
        allocations[0] = RouteAllocation {
            participant_id: 41,
            amount: 600_000,
        };
        allocations[1] = RouteAllocation {
            participant_id: 42,
            amount: 390_000,
        };
        RouteCommitment {
            message_domain: DOMAIN,
            source_channel_id: 7,
            base_cumulative: 0,
            target_cumulative: 1_000_000,
            allocation_count: 2,
            allocations,
        }
    }

    #[test]
    fn lengths() {
        assert_eq!(UNILATERAL_LEN, 34);
        assert_eq!(ROUTE_LEN, 306);
        assert_eq!(uni().encode().len(), UNILATERAL_LEN);
        assert_eq!(route().encode().len(), ROUTE_LEN);
    }

    #[test]
    fn round_trips() {
        assert_eq!(
            UnilateralCommitment::decode(&uni().encode()).unwrap(),
            uni()
        );
        assert_eq!(RouteCommitment::decode(&route().encode()).unwrap(), route());
    }

    #[test]
    fn kinds_do_not_cross_decode() {
        assert!(UnilateralCommitment::decode(&route().encode()).is_err());
        assert!(RouteCommitment::decode(&uni().encode()).is_err());
        let mut bad = uni().encode();
        bad[OFF_VERSION] = 0x02;
        assert!(UnilateralCommitment::decode(&bad).is_err());
        assert!(UnilateralCommitment::decode(&uni().encode()[..33]).is_err());
    }

    /// The circuit rebuilds canonical bytes from u128 slots; the slots' LE bytes must be the
    /// canonical body verbatim, or the in-circuit digest will not match what the agent signed.
    #[test]
    fn slots_are_the_canonical_body() {
        let c = uni();
        assert_eq!(&c.encode()[18..34], &c.body_slot().to_le_bytes());
        let r = route();
        let slots = r.body_slots();
        for (i, slot) in slots.iter().enumerate() {
            assert_eq!(&r.encode()[18 + i * 16..34 + i * 16], &slot.to_le_bytes());
        }
        assert_eq!(&DOMAIN, &domain_slot(&DOMAIN).to_le_bytes());
        assert_eq!(unpack_pair(pack_pair(7, 9)), (7, 9));
    }

    #[test]
    fn every_field_is_covered_by_the_digest() {
        let d = uni().digest();
        for v in [
            UnilateralCommitment {
                message_domain: [0xff; 16],
                ..uni()
            },
            UnilateralCommitment {
                channel_id: 8,
                ..uni()
            },
            UnilateralCommitment {
                target_cumulative: 1_000_001,
                ..uni()
            },
        ] {
            assert_ne!(v.digest(), d, "{v:?}");
        }
        let d = route().digest();
        for v in [
            RouteCommitment {
                message_domain: [0xff; 16],
                ..route()
            },
            RouteCommitment {
                source_channel_id: 8,
                ..route()
            },
            RouteCommitment {
                base_cumulative: 1,
                ..route()
            },
            RouteCommitment {
                target_cumulative: 1_000_001,
                ..route()
            },
            RouteCommitment {
                allocation_count: 1,
                ..route()
            },
            RouteCommitment {
                allocations: {
                    let mut a = route().allocations;
                    a[0].amount += 1;
                    a
                },
                ..route()
            },
        ] {
            assert_ne!(v.digest(), d, "{v:?}");
        }
        // And a route never collides with a unilateral over the same leading fields.
        assert_ne!(uni().digest(), route().digest());
    }

    #[test]
    fn pubkey_and_signature_pack_like_the_circuit() {
        let pk: [u8; 32] = core::array::from_fn(|i| i as u8);
        let s = pack_pubkey(&pk);
        assert_eq!(&s[0][..26], &pk[..26]);
        assert_eq!(&s[1][..6], &pk[26..]);
        assert!(s[0][26..].iter().all(|b| *b == 0) && s[1][6..].iter().all(|b| *b == 0));
        assert_eq!(unpack_pubkey(&s), pk);

        let sig: [u8; 64] = core::array::from_fn(|i| 100 + i as u8);
        let t = pack_signature(&sig);
        assert_eq!(&t[0][..26], &sig[..26]);
        assert_eq!(&t[1][..26], &sig[26..52]);
        assert_eq!(&t[2][..12], &sig[52..]);
    }

    #[test]
    fn monotonicity_rejects_equal_and_lower() {
        assert!(check_monotonic(100, 100).is_err());
        assert!(check_monotonic(99, 100).is_err());
        assert_eq!(check_monotonic(150, 100).unwrap(), 50);
        assert_eq!(check_monotonic(u64::MAX, u64::MAX - 1).unwrap(), 1);
    }

    #[test]
    fn route_allocation_validation() {
        assert_eq!(route().validate().unwrap(), (990_000, 10_000));
        let mut duplicate = route();
        duplicate.allocations[1].participant_id = duplicate.allocations[0].participant_id;
        assert!(duplicate.validate().is_err());
        let mut too_much = route();
        too_much.allocations[1].amount = 500_000;
        assert!(too_much.validate().is_err());
        let mut dirty_padding = route();
        dirty_padding.allocations[3].amount = 1;
        assert!(dirty_padding.validate().is_err());
    }

    /// Golden vectors, mirrored in `tests/vectors/commitment.json` for the TypeScript client.
    #[test]
    fn golden_vectors() {
        assert_eq!(
            hex(&uni().encode()),
            "99c670af9da768bc427a4b1b1b0f12670101070000000000000040420f0000000000",
        );
        assert_eq!(
            hex(&uni().digest()),
            "52686ad6b6051d37c5591e62815dc581451ff568976769e1018eb0d72d7ce7eb",
        );
        assert_eq!(route().encode().len(), ROUTE_LEN);
        assert_eq!(
            hex(&route().digest()),
            "2de675518f0de35de938add2a086b565fd906b260b992a005332c97d26674be1",
        );
    }
}
