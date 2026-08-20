/**
 * TypeScript side of the commitment format, its Arcium slot layout, and the ArcisEd25519 signer.
 *
 * Asserted byte-for-byte against the Rust implementation's golden vectors in
 * `tests/vectors/commitment.json`. A field added on one side without the other breaks the
 * conformance test rather than silently producing signatures nothing can verify.
 */
import { PublicKey } from "@solana/web3.js";
import { createHash } from "crypto";
import { sha3_256 } from "@noble/hashes/sha3";
import { ed25519 } from "@noble/curves/ed25519";
import { arcisEd25519 as arcisEd25519Upstream } from "@arcium-hq/client";

export const KIND_UNILATERAL = 0x01;
export const KIND_ROUTE = 0x02;
export const VERSION = 0x01;
/** domain(16) | kind | version | channel_id(8) | target(8) */
export const UNILATERAL_LEN = 34;
export const MAX_ROUTE_ALLOCATIONS = 16;
/** domain | kind | version | source_id | base | target | count(u64) | allocations[16] */
export const ROUTE_LEN = 18 + 4 * 8 + MAX_ROUTE_ALLOCATIONS * 16;

export const MESSAGE_DOMAIN_TAG = "ryvo-message-domain-v1";
export const COMMITMENT_DIGEST_TAG = "ryvo-commitment-v1";

/** One signer, one channel: "I authorise `channelId` up to `targetCumulative`". */
export interface UnilateralCommitment {
  kind: typeof KIND_UNILATERAL;
  messageDomain: Buffer; // 16 bytes
  channelId: bigint;
  targetCumulative: bigint;
}

/**
 * One provider allocation inside a route commitment. `amount` is a range length inside
 * `baseCumulative..targetCumulative`, not a separate provider-channel counter.
 */
export interface RouteAllocation {
  participantId: bigint;
  amount: bigint;
}

/**
 * The agent and gateway sign the same cumulative commitment. Settlement debits the agent's
 * locked source channel and directly credits the listed providers in order. Any signed
 * remainder after the allocations is the gateway fee.
 */
export interface RouteCommitment {
  kind: typeof KIND_ROUTE;
  messageDomain: Buffer;
  sourceChannelId: bigint;
  baseCumulative: bigint;
  targetCumulative: bigint;
  allocations: RouteAllocation[];
}

export type Commitment = UnilateralCommitment | RouteCommitment;

export function deriveMessageDomain(
  programId: PublicKey,
  chainId: number
): Buffer {
  const chainLe = Buffer.alloc(2);
  chainLe.writeUInt16LE(chainId);
  return createHash("sha256")
    .update(
      Buffer.concat([
        Buffer.from(MESSAGE_DOMAIN_TAG),
        programId.toBuffer(),
        chainLe,
      ])
    )
    .digest()
    .subarray(0, 16);
}

function header(out: Buffer, domain: Buffer, kind: number) {
  if (domain.length !== 16)
    throw new Error(`messageDomain must be 16 bytes, got ${domain.length}`);
  domain.copy(out, 0);
  out[16] = kind;
  out[17] = VERSION;
}

export function encodeCommitment(c: Commitment): Buffer {
  if (c.kind === KIND_UNILATERAL) {
    const out = Buffer.alloc(UNILATERAL_LEN);
    header(out, c.messageDomain, KIND_UNILATERAL);
    out.writeBigUInt64LE(c.channelId, 18);
    out.writeBigUInt64LE(c.targetCumulative, 26);
    return out;
  }
  const out = Buffer.alloc(ROUTE_LEN);
  header(out, c.messageDomain, KIND_ROUTE);
  validateRoute(c);
  out.writeBigUInt64LE(c.sourceChannelId, 18);
  out.writeBigUInt64LE(c.baseCumulative, 26);
  out.writeBigUInt64LE(c.targetCumulative, 34);
  out.writeBigUInt64LE(BigInt(c.allocations.length), 42);
  c.allocations.forEach((allocation, i) => {
    const at = 50 + i * 16;
    out.writeBigUInt64LE(allocation.participantId, at);
    out.writeBigUInt64LE(allocation.amount, at + 8);
  });
  return out;
}

export function validateRoute(c: RouteCommitment): {
  providerTotal: bigint;
  gatewayFee: bigint;
} {
  if (
    c.allocations.length < 1 ||
    c.allocations.length > MAX_ROUTE_ALLOCATIONS
  ) {
    throw new Error("bad allocation count");
  }
  if (c.baseCumulative >= c.targetCumulative)
    throw new Error("bad cumulative range");
  const ids = new Set<string>();
  let providerTotal = 0n;
  for (const allocation of c.allocations) {
    if (allocation.participantId === 0n || allocation.amount === 0n) {
      throw new Error("bad allocation");
    }
    const id = allocation.participantId.toString();
    if (ids.has(id)) throw new Error("duplicate provider");
    ids.add(id);
    providerTotal += allocation.amount;
  }
  const total = c.targetCumulative - c.baseCumulative;
  if (providerTotal > total)
    throw new Error("allocations exceed cumulative increase");
  return { providerTotal, gatewayFee: total - providerTotal };
}

/** The 32 bytes an agent actually signs: `SHA3-256(tag || canonical)`. */
export function commitmentDigest(c: Commitment): Buffer {
  return digestOf(encodeCommitment(c));
}

export function digestOf(canonical: Buffer): Buffer {
  return Buffer.from(
    sha3_256(Buffer.concat([Buffer.from(COMMITMENT_DIGEST_TAG), canonical]))
  );
}

export function decodeCommitment(bytes: Buffer): Commitment {
  if (bytes.length !== UNILATERAL_LEN && bytes.length !== ROUTE_LEN)
    throw new Error("bad length");
  if (bytes[17] !== VERSION) throw new Error("bad version");
  const messageDomain = Buffer.from(bytes.subarray(0, 16));
  if (bytes[16] === KIND_UNILATERAL) {
    if (bytes.length !== UNILATERAL_LEN) throw new Error("bad length");
    return {
      kind: KIND_UNILATERAL,
      messageDomain,
      channelId: bytes.readBigUInt64LE(18),
      targetCumulative: bytes.readBigUInt64LE(26),
    };
  }
  if (bytes[16] === KIND_ROUTE) {
    if (bytes.length !== ROUTE_LEN) throw new Error("bad length");
    const count = Number(bytes.readBigUInt64LE(42));
    if (count < 1 || count > MAX_ROUTE_ALLOCATIONS)
      throw new Error("bad allocation count");
    const allocations: RouteAllocation[] = [];
    for (let i = 0; i < MAX_ROUTE_ALLOCATIONS; i++) {
      const at = 50 + i * 16;
      const participantId = bytes.readBigUInt64LE(at);
      const amount = bytes.readBigUInt64LE(at + 8);
      if (i < count) allocations.push({ participantId, amount });
      else if (participantId !== 0n || amount !== 0n)
        throw new Error("nonzero allocation padding");
    }
    const route: RouteCommitment = {
      kind: KIND_ROUTE,
      messageDomain,
      sourceChannelId: bytes.readBigUInt64LE(18),
      baseCumulative: bytes.readBigUInt64LE(26),
      targetCumulative: bytes.readBigUInt64LE(34),
      allocations,
    };
    validateRoute(route);
    return route;
  }
  throw new Error("bad kind");
}

// -------------------------------------------------------------------------------------------
// Arcium slot layout. A staged batch is a byte buffer of 32-byte slots, one slot per circuit
// parameter. Plaintext u128 = 16 LE bytes in the low half. Packed bytes follow arcis-compiler's
// first-fit-decreasing rule for u8 fields: 26 bytes per slot, LE within the slot — a 32-byte key
// is 2 slots (26 + 6), a 64-byte signature is 3 (26 + 26 + 12). Measured against a live circuit;
// see the Rust `commitment.rs` for the mirror image, and do NOT use @arcium-hq/client's
// createPacker for signatures (it overflows the second element for >26 same-width fields).

export const SLOT = 32;
export const BYTES_PER_SLOT = 26;
export const PUBKEY_SLOTS = 2;
export const SIG_SLOTS = 3;

export function u128Slot(v: bigint): Buffer {
  const b = Buffer.alloc(SLOT);
  b.writeBigUInt64LE(v & ((1n << 64n) - 1n), 0);
  b.writeBigUInt64LE(v >> 64n, 8);
  return b;
}

/** `lo | hi << 64`; its LE bytes are `lo_le || hi_le`. */
export const packPair = (lo: bigint, hi: bigint): bigint => lo | (hi << 64n);

export function packBytesToSlots(bytes: Uint8Array): Buffer[] {
  const out: Buffer[] = [];
  for (let i = 0; i < bytes.length; i += BYTES_PER_SLOT) {
    const s = Buffer.alloc(SLOT);
    Buffer.from(
      bytes.subarray(i, Math.min(i + BYTES_PER_SLOT, bytes.length))
    ).copy(s, 0);
    out.push(s);
  }
  return out;
}

export function unpackPubkeySlots(slots: Buffer[]): Buffer {
  return Buffer.concat([slots[0].subarray(0, 26), slots[1].subarray(0, 6)]);
}

/** The u128 slot(s) holding a commitment's body; their LE bytes are canonical bytes [18..]. */
export function bodySlots(c: Commitment): bigint[] {
  if (c.kind === KIND_UNILATERAL)
    return [packPair(c.channelId, c.targetCumulative)];
  const slots = [
    packPair(c.sourceChannelId, c.baseCumulative),
    packPair(c.targetCumulative, BigInt(c.allocations.length)),
  ];
  for (let i = 0; i < MAX_ROUTE_ALLOCATIONS; i++) {
    const allocation = c.allocations[i];
    slots.push(
      allocation ? packPair(allocation.participantId, allocation.amount) : 0n
    );
  }
  return slots;
}

export const domainSlot = (messageDomain: Buffer): bigint =>
  messageDomain.readBigUInt64LE(0) | (messageDomain.readBigUInt64LE(8) << 64n);

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
 * Derive an agent's signing seed from its wallet seed.
 *
 * `SHA256(ARCIS_SIGNER_TAG || wallet_seed)`
 *
 * One key per wallet, used as `authorized_signer` on every channel that wallet opens. The agent
 * backs up its wallet seed and nothing else; the signing key is recomputed on demand, so there is
 * no key material to store, sync or lose.
 *
 * The blast radius of a leaked signing key is every channel it signs for, capped at the sum of
 * their locked collateral. Deriving a distinct key per channel would narrow that only in the case
 * where a single derived key leaks *without* the wallet seed — and since the seed must be present
 * to derive at all, that case is rare enough not to pay for.
 *
 * There is no epoch and no rotation. A channel's signer is fixed for its life: changing it would
 * invalidate outstanding commitments, which would let a payer take service and then repudiate.
 *
 * Domain separation matters here: reusing the raw wallet seed directly under two different hash
 * functions would work, but it is a non-standard construction and gives one key two lives. This
 * costs one SHA-256 and avoids the question.
 */
export function deriveArcisSignerSeed(walletSeed: Uint8Array): Buffer {
  if (walletSeed.length !== 32) {
    throw new Error(`wallet seed must be 32 bytes, got ${walletSeed.length}`);
  }
  return createHash("sha256")
    .update(
      Buffer.concat([Buffer.from(ARCIS_SIGNER_TAG), Buffer.from(walletSeed)])
    )
    .digest();
}

export interface ArcisSigner {
  /** Never leaves the agent. Recomputed on demand rather than stored. */
  seed: Buffer;
  /** The 32 bytes registered on-chain as `Channel.authorized_signer`. */
  publicKey: Buffer;
}

/** Derive the signer an agent registers on every channel it opens, and signs with. */
export function deriveArcisSigner(walletSeed: Uint8Array): ArcisSigner {
  const seed = deriveArcisSignerSeed(walletSeed);
  return { seed, publicKey: Buffer.from(arcisEd25519.getPublicKey(seed)) };
}

/** Sign a commitment with the agent's signing key. */
export function signCommitment(
  walletSeed: Uint8Array,
  commitment: Commitment
): { signature: Buffer; publicKey: Buffer; digest: Buffer } {
  const signer = deriveArcisSigner(walletSeed);
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
  publicKey: Uint8Array
): boolean {
  return arcisEd25519.verify(signature, digest, publicKey);
}

/** Standard RFC 8032, for the negative tests only. Never used to sign a commitment. */
export const standardEd25519 = ed25519;
