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

    /// Records per batch. Fixed at compile time; shorter batches are padded by the relayer.
    pub const N: usize = 32;

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
    pub fn clear_unilateral(
        domain: u128,
        ids: [u128; N],
        vks: [Pack<VerifyingKey>; N],
        sigs: [Pack<Sig>; N],
    ) -> [bool; N] {
        let d = u128_to_le_bytes(domain);
        let mut out = [false; N];
        for i in 0..N {
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
    pub fn clear_route(
        domain: u128,
        ids: [u128; N],
        targets: [u128; N],
        vk_agent: [Pack<VerifyingKey>; N],
        vk_gateway: [Pack<VerifyingKey>; N],
        sig_agent: [Pack<Sig>; N],
        sig_gateway: [Pack<Sig>; N],
    ) -> [bool; N] {
        let d = u128_to_le_bytes(domain);
        let mut out = [false; N];
        for i in 0..N {
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
