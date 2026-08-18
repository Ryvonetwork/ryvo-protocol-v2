/**
 * Transaction v1 (SIMD-0385 / SIMD-0296): 4,096-byte transactions, no address lookup tables,
 * compute budget carried in the header. web3.js 1.98 cannot build these, so this serialises the
 * wire format by hand:
 *
 *   VersionByte(129) | LegacyHeader(3) | ConfigMask(u32) | Lifetime[32] | NumInstructions(u8)
 *   | NumAddresses(u8) | Addresses[32 each] | ConfigValues[4 each] | InstructionHeaders(u8,u8,u16)
 *   | InstructionPayloads | Signatures[64 each]
 *
 * Signatures are over everything before them (unlike legacy, where they come first). The
 * compute-unit limit defaults to 0 when the mask bit is unset, so it is always set here.
 */
import { Connection, Keypair, PublicKey, TransactionInstruction } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519";

export const TX_V1_MAX_BYTES = 4096;
const VERSION_BYTE = 129;
const MASK_PRIORITY_FEE = 0b11; // bits 0,1: u64 total lamports
const MASK_CU_LIMIT = 0b100; // bit 2: u32

export interface V1Options {
  computeUnitLimit: number;
  priorityFeeLamports?: bigint;
}

interface AccountSlot { pubkey: PublicKey; signer: boolean; writable: boolean }

/** Build the signed v1 wire bytes for `instructions` paid for and signed by `signers[0]`. */
export function buildV1Transaction(
  instructions: TransactionInstruction[],
  signers: Keypair[],
  recentBlockhash: string,
  opts: V1Options,
): Buffer {
  const feePayer = signers[0].publicKey;
  // Collect accounts: fee payer first, then merge metas by pubkey (signer/writable OR-ed).
  const map = new Map<string, AccountSlot>();
  const upsert = (pubkey: PublicKey, signer: boolean, writable: boolean) => {
    const k = pubkey.toBase58();
    const cur = map.get(k);
    if (cur) { cur.signer ||= signer; cur.writable ||= writable; }
    else map.set(k, { pubkey, signer, writable });
  };
  upsert(feePayer, true, true);
  for (const ix of instructions) {
    for (const m of ix.keys) upsert(m.pubkey, m.isSigner, m.isWritable);
    upsert(ix.programId, false, false);
  }
  const all = [...map.values()];
  const signedW = all.filter((a) => a.signer && a.writable && !a.pubkey.equals(feePayer));
  const signedR = all.filter((a) => a.signer && !a.writable);
  const unsignedW = all.filter((a) => !a.signer && a.writable);
  const unsignedR = all.filter((a) => !a.signer && !a.writable);
  const ordered = [map.get(feePayer.toBase58())!, ...signedW, ...signedR, ...unsignedW, ...unsignedR];
  const index = new Map(ordered.map((a, i) => [a.pubkey.toBase58(), i]));
  const numRequiredSignatures = 1 + signedW.length + signedR.length;
  if (numRequiredSignatures > 12) throw new Error("v1: at most 12 signatures");
  if (ordered.length > 64) throw new Error(`v1: at most 64 accounts, got ${ordered.length}`);
  if (instructions.length > 64) throw new Error("v1: at most 64 instructions");

  const parts: Buffer[] = [];
  parts.push(Buffer.from([VERSION_BYTE]));
  parts.push(Buffer.from([numRequiredSignatures, signedR.length, unsignedR.length]));
  let mask = MASK_CU_LIMIT;
  const configValues: Buffer[] = [];
  if (opts.priorityFeeLamports && opts.priorityFeeLamports > 0n) {
    mask |= MASK_PRIORITY_FEE;
    const b = Buffer.alloc(8); b.writeBigUInt64LE(opts.priorityFeeLamports); configValues.push(b);
  }
  const cu = Buffer.alloc(4); cu.writeUInt32LE(opts.computeUnitLimit); configValues.push(cu);
  const maskB = Buffer.alloc(4); maskB.writeUInt32LE(mask); parts.push(maskB);
  parts.push(Buffer.from(bs58decode(recentBlockhash)));
  parts.push(Buffer.from([instructions.length, ordered.length]));
  for (const a of ordered) parts.push(a.pubkey.toBuffer());
  parts.push(...configValues);
  for (const ix of instructions) {
    if (ix.data.length > 0xffff) throw new Error("v1: instruction data too long");
    const h = Buffer.alloc(4);
    h[0] = index.get(ix.programId.toBase58())!;
    h[1] = ix.keys.length;
    h.writeUInt16LE(ix.data.length, 2);
    parts.push(h);
  }
  for (const ix of instructions) {
    parts.push(Buffer.from(ix.keys.map((m) => index.get(m.pubkey.toBase58())!)));
    parts.push(Buffer.from(ix.data));
  }
  const message = Buffer.concat(parts);
  const sigs: Buffer[] = [];
  for (let i = 0; i < numRequiredSignatures; i++) {
    const who = ordered[i].pubkey;
    const kp = signers.find((s) => s.publicKey.equals(who));
    if (!kp) throw new Error(`v1: missing signer for ${who.toBase58()}`);
    sigs.push(Buffer.from(ed25519.sign(message, kp.secretKey.slice(0, 32))));
  }
  const wire = Buffer.concat([message, ...sigs]);
  if (wire.length > TX_V1_MAX_BYTES) throw new Error(`v1: ${wire.length} bytes exceeds ${TX_V1_MAX_BYTES}`);
  return wire;
}

export async function sendV1(
  connection: Connection,
  instructions: TransactionInstruction[],
  signers: Keypair[],
  opts: V1Options,
): Promise<{ signature: string; bytes: number }> {
  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash("confirmed");
  const wire = buildV1Transaction(instructions, signers, blockhash, opts);
  const signature = await connection.sendRawTransaction(wire, { skipPreflight: !!process.env.V1_SKIP_PREFLIGHT, maxRetries: 5 });
  await connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");
  return { signature, bytes: wire.length };
}

// minimal base58 (web3.js's PublicKey handles pubkeys; blockhashes need this)
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function bs58decode(s: string): Uint8Array {
  let n = 0n;
  for (const ch of s) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new Error("bad base58");
    n = n * 58n + BigInt(v);
  }
  const out: number[] = [];
  while (n > 0n) { out.push(Number(n & 0xffn)); n >>= 8n; }
  for (const ch of s) { if (ch === "1") out.push(0); else break; }
  const bytes = Uint8Array.from(out.reverse());
  if (bytes.length !== 32) throw new Error(`blockhash decodes to ${bytes.length} bytes`);
  return bytes;
}
