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
//! * `kind = 0x02` **route**: two signers, two channels. The agent and the gateway both sign the
//!   same bytes; the agent authorises `channel_ag` up to `target_ag`, the gateway authorises
//!   `channel_gp` up to `target_gp`, and settlement moves both legs in one instruction. The
//!   gateway never holds the money and cannot withhold the payout, because its consent is
//!   already inside the record the provider holds.
//!
//! Channels are named by `channel_id: u64` (a global counter assigned at `create_channel`), not
//! by their 32-byte address. That is what keeps a route message at 50 bytes and lets a staged
//! record fit in a handful of 32-byte field-element slots.
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

/// Identifies both the wire format *and* the signature scheme (ArcisEd25519 / SHA3-512).
pub const VERSION: u8 = 0x01;

/// `domain(16) | kind(1) | version(1) | channel_id(8) | target(8)`
pub const UNILATERAL_LEN: usize = 34;
/// `domain(16) | kind(1) | version(1) | channel_ag_id(8) | channel_gp_id(8) | target_ag(8) | target_gp(8)`
pub const ROUTE_LEN: usize = 50;

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

/// A two-signer route through a gateway: `agent -> gateway -> provider`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RouteCommitment {
    pub message_domain: [u8; 16],
    /// agent -> gateway channel, signed by the agent's key.
    pub channel_ag_id: u64,
    /// gateway -> provider channel, signed by the gateway's key.
    pub channel_gp_id: u64,
    pub target_ag: u64,
    pub target_gp: u64,
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
        require!(bytes.len() == UNILATERAL_LEN, RyvoError::InvalidCommitmentMessage);
        require!(bytes[OFF_KIND] == KIND_UNILATERAL, RyvoError::InvalidCommitmentMessage);
        require!(bytes[OFF_VERSION] == VERSION, RyvoError::InvalidCommitmentMessage);
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
        out[OFF_BODY..OFF_BODY + 8].copy_from_slice(&self.channel_ag_id.to_le_bytes());
        out[OFF_BODY + 8..OFF_BODY + 16].copy_from_slice(&self.channel_gp_id.to_le_bytes());
        out[OFF_BODY + 16..OFF_BODY + 24].copy_from_slice(&self.target_ag.to_le_bytes());
        out[OFF_BODY + 24..OFF_BODY + 32].copy_from_slice(&self.target_gp.to_le_bytes());
        out
    }

    pub fn digest(&self) -> [u8; 32] {
        digest_of(&self.encode())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        require!(bytes.len() == ROUTE_LEN, RyvoError::InvalidCommitmentMessage);
        require!(bytes[OFF_KIND] == KIND_ROUTE, RyvoError::InvalidCommitmentMessage);
        require!(bytes[OFF_VERSION] == VERSION, RyvoError::InvalidCommitmentMessage);
        let mut message_domain = [0u8; 16];
        message_domain.copy_from_slice(&bytes[OFF_DOMAIN..OFF_KIND]);
        let u = |o: usize| u64::from_le_bytes(bytes[OFF_BODY + o..OFF_BODY + o + 8].try_into().unwrap());
        Ok(Self {
            message_domain,
            channel_ag_id: u(0),
            channel_gp_id: u(8),
            target_ag: u(16),
            target_gp: u(24),
        })
    }

    /// The two u128 slots for this record's body: `(ids, targets)`. Their little-endian bytes
    /// are canonical bytes `[18..34]` and `[34..50]` respectively.
    pub fn body_slots(&self) -> (u128, u128) {
        (
            pack_pair(self.channel_ag_id, self.channel_gp_id),
            pack_pair(self.target_ag, self.target_gp),
        )
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
// bytes `Pack<VerifyingKey>` / `Pack<Sig>` unpack inside the circuit, and what `settle_channels`
// reads back to compare against `Channel.authorized_signer`.

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
        UnilateralCommitment { message_domain: DOMAIN, channel_id: 7, target_cumulative: 1_000_000 }
    }
    fn route() -> RouteCommitment {
        RouteCommitment {
            message_domain: DOMAIN,
            channel_ag_id: 7,
            channel_gp_id: 9,
            target_ag: 1_000_000,
            target_gp: 990_000,
        }
    }

    #[test]
    fn lengths() {
        assert_eq!(UNILATERAL_LEN, 34);
        assert_eq!(ROUTE_LEN, 50);
        assert_eq!(uni().encode().len(), UNILATERAL_LEN);
        assert_eq!(route().encode().len(), ROUTE_LEN);
    }

    #[test]
    fn round_trips() {
        assert_eq!(UnilateralCommitment::decode(&uni().encode()).unwrap(), uni());
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
        let (ids, targets) = r.body_slots();
        assert_eq!(&r.encode()[18..34], &ids.to_le_bytes());
        assert_eq!(&r.encode()[34..50], &targets.to_le_bytes());
        assert_eq!(&DOMAIN, &domain_slot(&DOMAIN).to_le_bytes());
        assert_eq!(unpack_pair(pack_pair(7, 9)), (7, 9));
    }

    #[test]
    fn every_field_is_covered_by_the_digest() {
        let d = uni().digest();
        for v in [
            UnilateralCommitment { message_domain: [0xff; 16], ..uni() },
            UnilateralCommitment { channel_id: 8, ..uni() },
            UnilateralCommitment { target_cumulative: 1_000_001, ..uni() },
        ] {
            assert_ne!(v.digest(), d, "{v:?}");
        }
        let d = route().digest();
        for v in [
            RouteCommitment { message_domain: [0xff; 16], ..route() },
            RouteCommitment { channel_ag_id: 8, ..route() },
            RouteCommitment { channel_gp_id: 8, ..route() },
            RouteCommitment { target_ag: 1, ..route() },
            RouteCommitment { target_gp: 1, ..route() },
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
        assert_eq!(
            hex(&route().encode()),
            "99c670af9da768bc427a4b1b1b0f126702010700000000000000090000000000000040420f0000000000301b0f0000000000",
        );
        assert_eq!(
            hex(&route().digest()),
            "e542843e915ee03bf3b12cb56881cc7832a28a99ea5d47f2585c4783ead0d3ce",
        );
    }
}
