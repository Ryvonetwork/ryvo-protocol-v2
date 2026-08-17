/**
 * TypeScript side of the commitment format and the ArcisEd25519 signer.
 *
 * This is asserted byte-for-byte against the Rust implementation's golden vectors in
 * `tests/vectors/commitment.json`. A field added on one side without the other breaks the
 * conformance test rather than silently producing signatures nothing can verify.
 */
import { PublicKey } from "@solana/web3.js";
import { createHash } from "crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { arcisEd25519 as arcisEd25519Upstream } from "@arcium-hq/client";

export const KIND_UNILATERAL_COMMITMENT = 0x01;
export const VERSION = 0x01;
export const CANONICAL_LEN = 70;
/** Keeps in-circuit SHA3-512 at two permutations: 64 + |M| <= 143. */
export const MAX_CANONICAL_LEN = 79;

export const MESSAGE_DOMAIN_TAG = "ryvo-message-domain-v1";
export const COMMITMENT_DIGEST_TAG = "ryvo-commitment-v1";

export interface Commitment {
  messageDomain: Buffer; // 16 bytes
  channel: PublicKey;
  targetCumulative: bigint;
  signerEpoch: number;
  expiryUnix: bigint;
}

export function deriveMessageDomain(programId: PublicKey, chainId: number): Buffer {
  const chainLe = Buffer.alloc(2);
  chainLe.writeUInt16LE(chainId);
  return createHash("sha256")
    .update(Buffer.concat([Buffer.from(MESSAGE_DOMAIN_TAG), programId.toBuffer(), chainLe]))
    .digest()
    .subarray(0, 16);
}

export function encodeCommitment(c: Commitment): Buffer {
  if (c.messageDomain.length !== 16) {
    throw new Error(`messageDomain must be 16 bytes, got ${c.messageDomain.length}`);
  }
  const out = Buffer.alloc(CANONICAL_LEN);
  c.messageDomain.copy(out, 0);
  out[16] = KIND_UNILATERAL_COMMITMENT;
  out[17] = VERSION;
  c.channel.toBuffer().copy(out, 18);
  out.writeBigUInt64LE(c.targetCumulative, 50);
  out.writeUInt32LE(c.signerEpoch, 58);
  out.writeBigInt64LE(c.expiryUnix, 62);
  return out;
}

/** The 32 bytes an agent actually signs. */
export function commitmentDigest(c: Commitment): Buffer {
  return digestOf(encodeCommitment(c));
}

export function digestOf(canonical: Buffer): Buffer {
  return createHash("sha256")
    .update(Buffer.concat([Buffer.from(COMMITMENT_DIGEST_TAG), canonical]))
    .digest();
}

export function decodeCommitment(bytes: Buffer): Commitment {
  if (bytes.length !== CANONICAL_LEN) throw new Error("bad length");
  if (bytes[16] !== KIND_UNILATERAL_COMMITMENT) throw new Error("bad kind");
  if (bytes[17] !== VERSION) throw new Error("bad version");
  return {
    messageDomain: Buffer.from(bytes.subarray(0, 16)),
    channel: new PublicKey(bytes.subarray(18, 50)),
    targetCumulative: bytes.readBigUInt64LE(50),
    signerEpoch: bytes.readUInt32LE(58),
    expiryUnix: bytes.readBigInt64LE(62),
  };
}

/**
 * ArcisEd25519, re-exported from `@arcium-hq/client` rather than reconstructed here.
 *
 * Upstream builds it as `twistedEdwards({ ...ed25519 params, hash: sha3_512 })` — SHA3-512 has a
 * much lower multiplicative depth, which is what makes verification affordable inside MPC.
 *
 * Two consequences, both verified against this exact library:
 *
 * 1. Signature bytes are NOT interchangeable with RFC 8032. A wallet signature is rejected
 *    in-MPC, as the prior devnet POC also confirmed end to end.
 * 2. `hash` is a single parameter feeding the whole scheme, key derivation included. Ed25519
 *    derives its secret scalar as `clamp(hash(seed)[0..32])`, so one seed yields a DIFFERENT
 *    public key here than under standard Ed25519 — which means an agent's Solana wallet address
 *    can never be a channel's `authorized_signer`. Register the ArcisEd25519 pubkey.
 *
 * Using upstream directly means a change to their scheme breaks our conformance tests instead of
 * silently diverging from a local model of it.
 */
export const arcisEd25519 = arcisEd25519Upstream;

export function arcisPublicKey(seed: Uint8Array): Uint8Array {
  return arcisEd25519.getPublicKey(seed);
}

export const ARCIS_SIGNER_TAG = "ryvo-arcis-signer-v1";

/**
 * Derive a channel's signing seed from an agent's wallet seed.
 *
 * `SHA256(ARCIS_SIGNER_TAG || wallet_seed || channel || epoch_le)`
 *
 * Three properties, in the order they matter:
 *
 * 1. **One secret.** The agent backs up its wallet seed and nothing else; every signing key is
 *    recomputed on demand, so there is no key material to store, sync or lose.
 * 2. **Per-channel blast radius.** A leaked signing key authorises payments on exactly one
 *    channel. It cannot be replayed onto another channel, and it does not expose the wallet seed
 *    — SHA-256 is one-way, so the derivation cannot be run backwards.
 * 3. **Rotation is a counter.** `epoch` matches the on-chain `Channel.signer_epoch`, so rotating
 *    means bumping it and re-deriving. Because every commitment carries the epoch it was signed
 *    under, commitments from a previous epoch stay dead even if the same key is later re-derived.
 *
 * Domain separation matters here: reusing the raw wallet seed directly under two different hash
 * functions would work, but it is a non-standard construction and gives one key two lives. This
 * costs one SHA-256 and avoids the question.
 */
export function deriveArcisSignerSeed(
  walletSeed: Uint8Array,
  channel: PublicKey,
  epoch: number,
): Buffer {
  if (walletSeed.length !== 32) {
    throw new Error(`wallet seed must be 32 bytes, got ${walletSeed.length}`);
  }
  const epochLe = Buffer.alloc(4);
  epochLe.writeUInt32LE(epoch);
  return createHash("sha256")
    .update(
      Buffer.concat([
        Buffer.from(ARCIS_SIGNER_TAG),
        Buffer.from(walletSeed),
        channel.toBuffer(),
        epochLe,
      ]),
    )
    .digest();
}

export interface ArcisSigner {
  /** Never leaves the agent. Recomputed on demand rather than stored. */
  seed: Buffer;
  /** The 32 bytes registered on-chain as `Channel.authorized_signer`. */
  publicKey: Buffer;
  epoch: number;
}

/** Derive the signer an agent should register for a channel, and sign with. */
export function deriveArcisSigner(
  walletSeed: Uint8Array,
  channel: PublicKey,
  epoch = 0,
): ArcisSigner {
  const seed = deriveArcisSignerSeed(walletSeed, channel, epoch);
  return { seed, publicKey: Buffer.from(arcisEd25519.getPublicKey(seed)), epoch };
}

/** Sign a commitment for `channel` with the derived key for that channel and epoch. */
export function signCommitment(
  walletSeed: Uint8Array,
  commitment: Commitment,
): { signature: Buffer; publicKey: Buffer; digest: Buffer } {
  const signer = deriveArcisSigner(walletSeed, commitment.channel, commitment.signerEpoch);
  const digest = commitmentDigest(commitment);
  return {
    signature: Buffer.from(arcisSign(digest, signer.seed)),
    publicKey: signer.publicKey,
    digest,
  };
}

export function arcisSign(digest: Uint8Array, seed: Uint8Array): Uint8Array {
  return arcisEd25519.sign(digest, seed);
}

export function arcisVerify(
  signature: Uint8Array,
  digest: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  return arcisEd25519.verify(signature, digest, publicKey);
}

/** Standard RFC 8032, for the negative tests only. Never used to sign a commitment. */
export const standardEd25519 = ed25519;
