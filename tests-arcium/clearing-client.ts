/**
 * Relayer-side helpers for Arcium clearing: build a batch's slot buffer, stage it, seal + queue,
 * wait for the callback, settle. Mirrors `programs/ryvo_protocol/src/clearing/mod.rs` exactly —
 * the slot layout is the contract between the three parties that read it (this client, the
 * circuit, `settle_channels`).
 */
import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { AccountMeta, Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { randomBytes } from "crypto";
import * as fs from "fs";
import {
  awaitComputationFinalization,
  getArciumEnv,
  getCompDefAccOffset,
  getArciumAccountBaseSeed,
  getArciumProgramId,
  getArciumProgram,
  uploadCircuit,
  getMXEAccAddress,
  getMempoolAccAddress,
  getCompDefAccAddress,
  getExecutingPoolAccAddress,
  getComputationAccAddress,
  getClusterAccAddress,
  getLookupTableAddress,
} from "@arcium-hq/client";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { sendV1 } from "./txv1";
import {
  KIND_ROUTE,
  KIND_UNILATERAL,
  PUBKEY_SLOTS,
  RouteCommitment,
  SIG_SLOTS,
  SLOT,
  UnilateralCommitment,
  bodySlots,
  packBytesToSlots,
  u128Slot,
} from "../tests/commitment-client";

/** Records per batch. Must equal `N` in the program and the circuit. */
export const N = 32;
export const UNILATERAL_SLOTS = N * (1 + PUBKEY_SLOTS + SIG_SLOTS); // 192
export const ROUTE_SLOTS = N * (2 + 2 * PUBKEY_SLOTS + 2 * SIG_SLOTS); // 384

export interface UnilateralRecord {
  commitment: UnilateralCommitment;
  signer: Uint8Array; // 32-byte ArcisEd25519 pubkey registered as Channel.authorized_signer
  signature: Uint8Array; // 64
}

export interface RouteRecord {
  commitment: RouteCommitment;
  agentSigner: Uint8Array;
  agentSignature: Uint8Array;
  gatewaySigner: Uint8Array;
  gatewaySignature: Uint8Array;
}

function padTo<T>(xs: T[], n: number): T[] {
  if (xs.length === 0 || xs.length > n) throw new Error(`batch must hold 1..${n} records, got ${xs.length}`);
  const out = [...xs];
  // Pad by repeating a real record: every padding slot is still a valid, verifiable record, so
  // the circuit never sees garbage. Padded indices are >= count and ignored on-chain.
  while (out.length < n) out.push(xs[0]);
  return out;
}

/** Column-major: ids[N] | vk[2N] | sig[3N]. */
export function buildUnilateralBatch(records: UnilateralRecord[]): Buffer {
  const rs = padTo(records, N);
  const cols: Buffer[] = [];
  for (const r of rs) cols.push(u128Slot(bodySlots(r.commitment)[0]));
  for (const r of rs) cols.push(...packBytesToSlots(r.signer));
  for (const r of rs) cols.push(...packBytesToSlots(r.signature));
  const out = Buffer.concat(cols);
  if (out.length !== UNILATERAL_SLOTS * SLOT) throw new Error(`bad unilateral batch length ${out.length}`);
  return out;
}

/** Column-major: ids[N] | targets[N] | vk_agent[2N] | vk_gateway[2N] | sig_agent[3N] | sig_gateway[3N]. */
export function buildRouteBatch(records: RouteRecord[]): Buffer {
  const rs = padTo(records, N);
  const cols: Buffer[] = [];
  for (const r of rs) cols.push(u128Slot(bodySlots(r.commitment)[0]));
  for (const r of rs) cols.push(u128Slot(bodySlots(r.commitment)[1]));
  for (const r of rs) cols.push(...packBytesToSlots(r.agentSigner));
  for (const r of rs) cols.push(...packBytesToSlots(r.gatewaySigner));
  for (const r of rs) cols.push(...packBytesToSlots(r.agentSignature));
  for (const r of rs) cols.push(...packBytesToSlots(r.gatewaySignature));
  const out = Buffer.concat(cols);
  if (out.length !== ROUTE_SLOTS * SLOT) throw new Error(`bad route batch length ${out.length}`);
  return out;
}

/** 8-byte discriminator + 48-byte header + 384 slots. Must equal `StagingBuffer::SPACE`. */
export const STAGING_SPACE = 8 + 48 + ROUTE_SLOTS * SLOT;

export const clearingPda = (programId: PublicKey, staging: PublicKey) =>
  PublicKey.findProgramAddressSync([Buffer.from("clearing"), staging.toBuffer()], programId)[0];

/** Slots per legacy transaction: 30 × 32 = 960 bytes of instruction data (1,232-byte packet). */
const SLOTS_PER_LEGACY_TX = 30;
/** Slots per v1 transaction: 120 × 32 = 3,840 bytes of instruction data (4,096-byte packet). */
const SLOTS_PER_V1_TX = 120;

let v1Support: boolean | undefined;
/**
 * Transaction v1 (SIMD-0296/0385) quadruples the packet, cutting staging transactions ~4×.
 * It is feature-gated; probe once per process with a real send and fall back to legacy.
 * Set RYVO_TX_V1=0 to force legacy, RYVO_TX_V1=1 to force v1.
 */
export async function supportsTxV1(program: Program<RyvoProtocol>, payer: Keypair): Promise<boolean> {
  if (process.env.RYVO_TX_V1 === "0") return false;
  if (process.env.RYVO_TX_V1 === "1") return true;
  if (v1Support !== undefined) return v1Support;
  try {
    await sendV1(program.provider.connection, [SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: payer.publicKey, lamports: 1 })], [payer], { computeUnitLimit: 20_000 });
    v1Support = true;
  } catch (e: any) {
    v1Support = false;
    if (!/version is unsupported/i.test(String(e?.message))) console.warn("v1 probe failed for a reason other than the gate:", String(e?.message).slice(0, 120));
  }
  return v1Support;
}

/**
 * create_account + open_staging in one transaction, then stage_slots in chunks. The buffer is
 * a fresh keypair account (12 KB exceeds the CPI-creation cap, so the relayer creates it at the
 * top level with the program as owner).
 */
export async function stageBatch(
  program: Program<RyvoProtocol>,
  relayer: Keypair,
  batchSeq: bigint,
  kind: number,
  slots: Buffer,
): Promise<PublicKey> {
  const stagingKp = Keypair.generate();
  const staging = stagingKp.publicKey;
  const lamports = await program.provider.connection.getMinimumBalanceForRentExemption(STAGING_SPACE);
  await program.methods
    .openStaging(new anchor.BN(batchSeq.toString()), kind)
    .accounts({ relayer: relayer.publicKey, staging })
    .preInstructions([
      SystemProgram.createAccount({
        fromPubkey: relayer.publicKey,
        newAccountPubkey: staging,
        lamports,
        space: STAGING_SPACE,
        programId: program.programId,
      }),
    ])
    .signers([relayer, stagingKp])
    .rpc();
  const total = slots.length / SLOT;
  const useV1 = await supportsTxV1(program, relayer);
  const per = useV1 ? SLOTS_PER_V1_TX : SLOTS_PER_LEGACY_TX;
  const sends: Promise<unknown>[] = [];
  for (let s = 0; s < total; s += per) {
    const chunk = slots.subarray(s * SLOT, Math.min(s + per, total) * SLOT);
    if (useV1) {
      const ix = await program.methods.stageSlots(s, chunk).accounts({ relayer: relayer.publicKey, staging }).instruction();
      sends.push(sendV1(program.provider.connection, [ix], [relayer], { computeUnitLimit: 50_000 }));
    } else {
      sends.push(program.methods.stageSlots(s, chunk).accounts({ relayer: relayer.publicKey, staging }).signers([relayer]).rpc());
    }
  }
  await Promise.all(sends);
  return staging;
}

/** Staging transactions a batch of `slots` needs under each format (for reporting). */
export function stagingTxCount(slots: number): { legacy: number; v1: number } {
  return { legacy: Math.ceil(slots / SLOTS_PER_LEGACY_TX), v1: Math.ceil(slots / SLOTS_PER_V1_TX) };
}

export function arciumEnv() {
  const env = getArciumEnv();
  return { env, clusterAccount: getClusterAccAddress(env.arciumClusterOffset) };
}

/** seal_and_queue_* — returns the computation offset to await. */
export async function sealAndQueue(
  program: Program<RyvoProtocol>,
  relayer: Keypair,
  staging: PublicKey,
  kind: number,
  count: number,
): Promise<{ computationOffset: anchor.BN; clearingResult: PublicKey; sig: string }> {
  const { env, clusterAccount } = arciumEnv();
  const computationOffset = new anchor.BN(randomBytes(8), "hex");
  const circuit = kind === KIND_UNILATERAL ? "clear_unilateral" : "clear_route";
  const clearingResult = clearingPda(program.programId, staging);
  const accounts = {
    relayer: relayer.publicKey,
    config: PublicKey.findProgramAddressSync([Buffer.from("config")], program.programId)[0],
    staging,
    clearingResult,
    computationAccount: getComputationAccAddress(env.arciumClusterOffset, computationOffset),
    clusterAccount,
    mxeAccount: getMXEAccAddress(program.programId),
    mempoolAccount: getMempoolAccAddress(env.arciumClusterOffset),
    executingPool: getExecutingPoolAccAddress(env.arciumClusterOffset),
    compDefAccount: getCompDefAccAddress(
      program.programId,
      Buffer.from(getCompDefAccOffset(circuit)).readUInt32LE(),
    ),
  };
  const m = kind === KIND_UNILATERAL
    ? program.methods.sealAndQueueUnilateral(computationOffset, count)
    : program.methods.sealAndQueueRoute(computationOffset, count);
  const sig = await m.accountsPartial(accounts).signers([relayer]).rpc({ commitment: "confirmed" });
  return { computationOffset, clearingResult, sig };
}

export async function awaitClearing(
  provider: anchor.AnchorProvider,
  program: Program<RyvoProtocol>,
  computationOffset: anchor.BN,
): Promise<string> {
  return awaitComputationFinalization(provider, computationOffset, program.programId, "confirmed");
}

export function bitmapBits(bitmap: number[], count: number): boolean[] {
  return Array.from({ length: count }, (_, i) => (bitmap[i >> 3] & (1 << (i & 7))) !== 0);
}

/**
 * settle_channels for a set of indices. `accountsFor(i)` returns the per-record accounts in the
 * order the program expects (unilateral: [channel, payeeBalance]; route: [channelAg, channelGp,
 * providerBalance]).
 */
export async function settle(
  program: Program<RyvoProtocol>,
  staging: PublicKey,
  indices: number[],
  accountsFor: (i: number) => PublicKey[],
): Promise<string> {
  const remaining: AccountMeta[] = indices.flatMap((i) =>
    accountsFor(i).map((pubkey) => ({ pubkey, isWritable: true, isSigner: false })),
  );
  return program.methods
    .settleChannels(Buffer.from(indices))
    .accounts({ staging, clearingResult: clearingPda(program.programId, staging) })
    .remainingAccounts(remaining)
    .rpc({ commitment: "confirmed" });
}

// ---------------------------------------------------------------------------- one-time setup

export async function ensureArciumSigner(program: Program<RyvoProtocol>, payer: Keypair) {
  const [signPda] = PublicKey.findProgramAddressSync([Buffer.from("ArciumSignerAccount")], program.programId);
  const info = await program.provider.connection.getAccountInfo(signPda);
  if (info) return signPda;
  await program.methods
    .initArciumSigner()
    .accounts({ payer: payer.publicKey, signPdaAccount: signPda, systemProgram: SystemProgram.programId })
    .signers([payer])
    .rpc({ commitment: "confirmed" });
  return signPda;
}

/**
 * Register a comp def. With `offchainUrl` the circuit is fetched by the nodes from that URL
 * (its SHA-256 is baked into the program). Without it, the raw circuit is uploaded on-chain
 * from `build/<circuit>.arcis`, which is slow for these sizes and only sensible on localnet.
 */
export async function ensureCompDef(
  program: Program<RyvoProtocol>,
  provider: anchor.AnchorProvider,
  payer: Keypair,
  circuit: "clear_unilateral" | "clear_route",
  offchainUrl?: string,
): Promise<PublicKey> {
  const arciumProgram = getArciumProgram(provider);
  const baseSeed = getArciumAccountBaseSeed("ComputationDefinitionAccount");
  const offset = getCompDefAccOffset(circuit);
  const compDef = PublicKey.findProgramAddressSync(
    [baseSeed, program.programId.toBuffer(), offset], getArciumProgramId(),
  )[0];
  const exists = await provider.connection.getAccountInfo(compDef);
  if (exists) return compDef;

  const mxeAccount = getMXEAccAddress(program.programId);
  const mxeAcc = await arciumProgram.account.mxeAccount.fetch(mxeAccount);
  const lut = getLookupTableAddress(program.programId, mxeAcc.lutOffsetSlot);
  const m = circuit === "clear_unilateral"
    ? program.methods.initClearUnilateralCompDef(offchainUrl ?? null)
    : program.methods.initClearRouteCompDef(offchainUrl ?? null);
  await m
    .accounts({ compDefAccount: compDef, payer: payer.publicKey, mxeAccount, addressLookupTable: lut })
    .signers([payer])
    .rpc({ commitment: "confirmed" });

  if (!offchainUrl) {
    const raw = fs.readFileSync(`build/${circuit}.arcis`);
    await uploadCircuit(provider, circuit, program.programId, raw, false, 500, {
      skipPreflight: true, preflightCommitment: "confirmed", commitment: "confirmed",
    });
  }
  return compDef;
}
