//! Ryvo clearing circuits.
//!
//! Each circuit takes one batch of staged commitment records and returns one bit per record:
//! `true` iff every signature the record needs verifies over the digest the circuit rebuilds
//! from the record's own fields. Nothing else. The circuit never sees a balance; all money math
//! happens on-chain in `settle_channels`, which reads the same sealed bytes.
//!
//! Layout (mirrors `ryvo_protocol::clearing`): every parameter is one 32-byte slot in the staging
//! buffer, in declaration order, after a leading plaintext `domain` argument that the program
//! supplies from `Config.message_domain`. `Pack<VerifyingKey>` is 2 slots, `Pack<Sig>` is 3.
//!
//! Digest = SHA3-256(TAG || domain(16) || kind(1) || version(1) || body). Byte-for-byte the same
//! as `commitment.rs::digest_of` on the host.
use arcis::*;

#[encrypted]
mod circuits {
    use arcis::*;

    /// Commitments per batch. Fixed at compile time; shorter batches are padded by the relayer.
    /// Route batches are half the size: each route needs two key account arguments, and the
    /// Arcium program's own 32 KB heap tops out somewhere between 66 and 131 account arguments
    /// per computation.
    pub const N_UNI: usize = 64;
    pub const N_ROUTE: usize = 64;

    /// `b"ryvo-commitment-v1"`
    const TAG: [u8; 18] = [
        0x72, 0x79, 0x76, 0x6f, 0x2d, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74,
        0x2d, 0x76, 0x31,
    ];
    const KIND_UNILATERAL: u8 = 0x01;
    const KIND_ROUTE: u8 = 0x02;
    const VERSION: u8 = 0x01;

    /// Named wrapper so the generated client type gets a legal identifier.
    pub struct Sig {
        pub bytes: [u8; 64],
    }

    fn u128_to_le_bytes(v: u128) -> [u8; 16] {
        let mut out = [0u8; 16];
        let mut x = v;
        for i in 0..16 {
            out[i] = (x % 256) as u8;
            x >>= 8;
        }
        out
    }

    /// One signer per record. Preimage: TAG(18) | domain(16) | 0x01 | 0x01 | id_target(16) = 52 B.
    #[instruction]
    pub fn clear_unilateral64(
        domain: u128,
        ids: [u128; N_UNI],
        vks: [Pack<VerifyingKey>; N_UNI],
        sigs: [Pack<Sig>; N_UNI],
    ) -> [bool; N_UNI] {
        let d = u128_to_le_bytes(domain);
        let mut out = [false; N_UNI];
        for i in 0..N_UNI {
            let body = u128_to_le_bytes(ids[i]);
            let mut pre = [0u8; 52];
            for j in 0..18 {
                pre[j] = TAG[j];
            }
            for j in 0..16 {
                pre[18 + j] = d[j];
                pre[36 + j] = body[j];
            }
            pre[34] = KIND_UNILATERAL;
            pre[35] = VERSION;
            let digest = SHA3_256::new().digest(&pre);
            let vk = vks[i].unpack();
            let sig = ArcisEd25519Signature::from_bytes(sigs[i].unpack().bytes);
            out[i] = vk.verify(&digest, &sig);
        }
        out
    }

    /// Two signers per record over the same bytes: the agent (channel_ag) and the gateway
    /// (channel_gp). Preimage: TAG | domain | 0x02 | 0x01 | ids(16) | targets(16) = 68 B.
    /// The bit is set only if BOTH signatures verify.
    #[instruction]
    pub fn clear_route64(
        domain: u128,
        ids: [u128; N_ROUTE],
        targets: [u128; N_ROUTE],
        vk_agent: [Pack<VerifyingKey>; N_ROUTE],
        vk_gateway: [Pack<VerifyingKey>; N_ROUTE],
        sig_agent: [Pack<Sig>; N_ROUTE],
        sig_gateway: [Pack<Sig>; N_ROUTE],
    ) -> [bool; N_ROUTE] {
        let d = u128_to_le_bytes(domain);
        let mut out = [false; N_ROUTE];
        for i in 0..N_ROUTE {
            let idb = u128_to_le_bytes(ids[i]);
            let tgb = u128_to_le_bytes(targets[i]);
            let mut pre = [0u8; 68];
            for j in 0..18 {
                pre[j] = TAG[j];
            }
            for j in 0..16 {
                pre[18 + j] = d[j];
                pre[36 + j] = idb[j];
                pre[52 + j] = tgb[j];
            }
            pre[34] = KIND_ROUTE;
            pre[35] = VERSION;
            let digest = SHA3_256::new().digest(&pre);
            let a_ok = vk_agent[i]
                .unpack()
                .verify(&digest, &ArcisEd25519Signature::from_bytes(sig_agent[i].unpack().bytes));
            let g_ok = vk_gateway[i]
                .unpack()
                .verify(&digest, &ArcisEd25519Signature::from_bytes(sig_gateway[i].unpack().bytes));
            out[i] = a_ok && g_ok;
        }
        out
    }
}
