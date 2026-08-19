/**
 * Relayer-side helpers for Arcium clearing: build a batch's slot buffer, stage it, seal + queue,
 * wait for the callback, settle. Mirrors `programs/ryvo_protocol/src/clearing/mod.rs` exactly —
 * the slot layout is the contract between the three parties that read it (this client, the
 * circuit via the argument list the program builds, and `settle_channels`).
 *
 * A relayer owns one reusable staging buffer: `openStaging` once, then per batch
 * `stageBatch` (which resets the buffer in the first transaction) → `sealAndQueue` →
 * `awaitClearing` → `settle`. Keys are never staged by the relayer: `stage_channels` names the
 * `Channel` accounts and the program copies each one's address and `signer_slots` into the
 * buffer's key columns, which `stage_slots` cannot reach.
 */
import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { AccountMeta, ComputeBudgetProgram, Keypair, PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";
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
import {
  KIND_ROUTE,
  KIND_UNILATERAL,
  RouteCommitment,
  SIG_SLOTS,
  SLOT,
  UnilateralCommitment,
  bodySlots,
  packBytesToSlots,
  u128Slot,
} from "../tests/commitment-client";
import { sendV1 } from "./txv1";

/** Commitments per batch. Must equal `N_UNI` / `N_ROUTE` in the program and the circuit. */
export const N_UNI = 64;
export const N_ROUTE = 32;
/** Slots the relayer stages per commitment (the data columns). */
export const UNILATERAL_DATA_SLOTS_PER_RECORD = 1 + SIG_SLOTS; // id, sig
export const ROUTE_DATA_SLOTS_PER_RECORD = 2 + 2 * SIG_SLOTS; // ids, targets, 2 sigs
export const UNILATERAL_DATA_SLOTS = N_UNI * UNILATERAL_DATA_SLOTS_PER_RECORD; // 256
export const ROUTE_DATA_SLOTS = N_ROUTE * ROUTE_DATA_SLOTS_PER_RECORD; // 256
/** Slots per commitment including the program-written key (2 per channel) and channel columns. */
export const UNILATERAL_SLOTS_PER_RECORD = UNILATERAL_DATA_SLOTS_PER_RECORD + 2 + 1; // 7
export const ROUTE_SLOTS_PER_RECORD = ROUTE_DATA_SLOTS_PER_RECORD + 4 + 2; // 14
export const UNILATERAL_SLOTS = N_UNI * UNILATERAL_SLOTS_PER_RECORD; // 448
export const ROUTE_SLOTS = N_ROUTE * ROUTE_SLOTS_PER_RECORD; // 448
export const MAX_SLOTS = Math.max(UNILATERAL_SLOTS, ROUTE_SLOTS);
/** Channel accounts per `stage_channels` call (program cap; ~31 accounts fit a legacy tx). */
export const MAX_CHANNELS_PER_STAGE = 30;
/** 8-byte discriminator + 48-byte header + MAX_SLOTS slots. Must equal `StagingBuffer::SPACE`. */
export const STAGING_SPACE = 8 + 48 + MAX_SLOTS * SLOT;

export interface UnilateralRecord {
  commitment: UnilateralCommitment;
  channel: PublicKey; // the Channel account whose registered signer signed
  signature: Uint8Array; // 64
}

export interface RouteRecord {
  commitment: RouteCommitment;
  channelAg: PublicKey;
  channelGp: PublicKey;
  agentSignature: Uint8Array;
  gatewaySignature: Uint8Array;
}

/** A batch ready to stage: the data columns as bytes, and the channel accounts per column. */
export interface Batch {
  slots: Buffer;
  /** `channels[col][i]` — col 0 = payer/agent channel, col 1 = gateway→provider channel (route). */
  channels: PublicKey[][];
}

function padTo<T>(xs: T[], n: number): T[] {
  if (xs.length === 0 || xs.length > n) throw new Error(`batch must hold 1..${n} commitments, got ${xs.length}`);
  const out = [...xs];
  // Pad by repeating a real commitment: every padding slot is still a valid, verifiable record,
  // so the circuit never sees garbage. Padded indices are >= count and ignored on-chain.
  while (out.length < n) out.push(xs[0]);
  return out;
}

/** Data columns: ids[N] | sig[3N]; channels for column 0. */
export function buildUnilateralBatch(records: UnilateralRecord[]): Batch {
  const rs = padTo(records, N_UNI);
  const cols: Buffer[] = [];
  for (const r of rs) cols.push(u128Slot(bodySlots(r.commitment)[0]));
  for (const r of rs) cols.push(...packBytesToSlots(r.signature));
  const slots = Buffer.concat(cols);
  if (slots.length !== UNILATERAL_DATA_SLOTS * SLOT) throw new Error(`bad unilateral batch length ${slots.length}`);
  return { slots, channels: [rs.map((r) => r.channel)] };
}

/** Data columns: ids[N] | targets[N] | sig_agent[3N] | sig_gateway[3N]; channels for columns 0 and 1. */
export function buildRouteBatch(records: RouteRecord[]): Batch {
  const rs = padTo(records, N_ROUTE);
  const cols: Buffer[] = [];
  for (const r of rs) cols.push(u128Slot(bodySlots(r.commitment)[0]));
  for (const r of rs) cols.push(u128Slot(bodySlots(r.commitment)[1]));
  for (const r of rs) cols.push(...packBytesToSlots(r.agentSignature));
  for (const r of rs) cols.push(...packBytesToSlots(r.gatewaySignature));
  const slots = Buffer.concat(cols);
  if (slots.length !== ROUTE_DATA_SLOTS * SLOT) throw new Error(`bad route batch length ${slots.length}`);
  return { slots, channels: [rs.map((r) => r.channelAg), rs.map((r) => r.channelGp)] };
}

export const clearingPda = (programId: PublicKey, staging: PublicKey) =>
  PublicKey.findProgramAddressSync([Buffer.from("clearing"), staging.toBuffer()], programId)[0];

/** Slots per legacy transaction: 30 × 32 = 960 bytes of instruction data (1,232-byte packet). */
const SLOTS_PER_LEGACY_TX = 30;
/** Slots per v1 transaction: 120 × 32 = 3,840 bytes of instruction data (4,096-byte packet). */
const SLOTS_PER_V1_TX = 120;
/** A stage_slots chunk this small still fits in one legacy tx alongside seal_and_queue's 15 accounts. */
const MERGEABLE_TAIL_SLOTS = 18;
/** Channel accounts per staging transaction: one stage_channels call's worth in legacy, three in v1. */
const CHANNELS_PER_LEGACY_TX = MAX_CHANNELS_PER_STAGE;
const CHANNELS_PER_V1_TX = 3 * MAX_CHANNELS_PER_STAGE;

/** Split `channels` per column into stage_channels calls, then pack calls into transactions of at most `perTx` accounts. */
function packChannelCalls(channels: PublicKey[][], perTx: number): { col: number; start: number; part: PublicKey[] }[][] {
  const calls: { col: number; start: number; part: PublicKey[] }[] = [];
  channels.forEach((chs, col) => {
    for (let start = 0; start < chs.length; start += MAX_CHANNELS_PER_STAGE)
      calls.push({ col, start, part: chs.slice(start, start + MAX_CHANNELS_PER_STAGE) });
  });
  calls.sort((a, b) => b.part.length - a.part.length); // big calls first, remainders share a tx
  const txs: typeof calls[] = [];
  for (const c of calls) {
    const home = txs.find((t) => t.reduce((n, x) => n + x.part.length, 0) + c.part.length <= perTx);
    if (home) home.push(c); else txs.push([c]);
  }
  return txs;
}

let v1Support: boolean | undefined;
/**
 * Transaction v1 (SIMD-0296/0385) quadruples the packet, cutting staging transactions ~4×.
 * It is feature-gated (`enable_tx_v1`); probe once per process with a real send and fall back
 * to legacy. RYVO_TX_V1=0 forces legacy, RYVO_TX_V1=1 forces v1.
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
    if (!/version is unsupported|expired/i.test(String(e?.message))) console.warn("v1 probe failed for a reason other than the gate:", String(e?.message).slice(0, 120));
  }
  return v1Support;
}

/** Staging transactions a full batch of `kind` needs under each format (for reporting). */
export function stagingTxCount(kind: number): { legacy: number; v1: number } {
  const slots = kind === KIND_UNILATERAL ? UNILATERAL_DATA_SLOTS : ROUTE_DATA_SLOTS;
  const tail = slots % SLOTS_PER_LEGACY_TX;
  const legacySlots = Math.floor(slots / SLOTS_PER_LEGACY_TX) + (tail === 0 ? 0 : 1) - (tail > 0 && tail <= MERGEABLE_TAIL_SLOTS ? 1 : 0);
  const cols = kind === KIND_UNILATERAL ? [new Array(N_UNI).fill(PublicKey.default)] : [new Array(N_ROUTE).fill(PublicKey.default), new Array(N_ROUTE).fill(PublicKey.default)];
  return { legacy: legacySlots + packChannelCalls(cols, CHANNELS_PER_LEGACY_TX).length, v1: Math.ceil(slots / SLOTS_PER_V1_TX) + packChannelCalls(cols, CHANNELS_PER_V1_TX).length };
}

/**
 * Create a relayer's reusable staging buffer: `create_account` (20 KB exceeds the CPI-creation
 * cap, so the relayer creates it at the top level with the program as owner) + `open_staging`,
 * which also creates the buffer's `ClearingResult`. One transaction.
 */
export async function openStaging(program: Program<RyvoProtocol>, relayer: Keypair, kind: number): Promise<PublicKey> {
  const stagingKp = Keypair.generate();
  const staging = stagingKp.publicKey;
  const lamports = await program.provider.connection.getMinimumBalanceForRentExemption(STAGING_SPACE);
  await program.methods
    .openStaging(kind)
    .accounts({ relayer: relayer.publicKey, staging, clearingResult: clearingPda(program.programId, staging), systemProgram: SystemProgram.programId })
    .preInstructions([
      SystemProgram.createAccount({ fromPubkey: relayer.publicKey, newAccountPubkey: staging, lamports, space: STAGING_SPACE, programId: program.programId }),
    ])
    .signers([relayer, stagingKp])
    .rpc({ commitment: "confirmed" });
  return staging;
}

/**
 * Stage a batch into an existing buffer. The first transaction carries `reset_staging` (which
 * requires the previous batch to be fully settled) unless `fresh` says the buffer was just
 * opened. Returns the last chunk *unsent* when it is small enough to ride along with
 * `seal_and_queue` in one transaction; pass it to `sealAndQueue` as `tailIx`.
 */
export async function stageBatch(
  program: Program<RyvoProtocol>,
  relayer: Keypair,
  staging: PublicKey,
  kind: number,
  batch: Batch,
  opts: { fresh?: boolean } = {},
): Promise<{ tailIx?: TransactionInstruction; txCount: number }> {
  const { slots } = batch;
  const total = slots.length / SLOT;
  const useV1 = await supportsTxV1(program, relayer);
  const per = useV1 ? SLOTS_PER_V1_TX : SLOTS_PER_LEGACY_TX;
  const chunk = (s: number, n: number) => program.methods
    .stageSlots(s, slots.subarray(s * SLOT, (s + n) * SLOT))
    .accounts({ relayer: relayer.publicKey, staging })
    .instruction();

  const sends: Promise<unknown>[] = [];
  let txCount = 0;
  const send = async (ixs: TransactionInstruction[]) => {
    txCount++;
    if (useV1) return sendV1(program.provider.connection, ixs, [relayer], { computeUnitLimit: 60_000 });
    const tx = new anchor.web3.Transaction().add(...ixs);
    return (program.provider as anchor.AnchorProvider).sendAndConfirm(tx, [relayer], { commitment: "confirmed" });
  };

  // stage_channels: the program copies address + registered key for indices start.. of a column
  const channelTxs: TransactionInstruction[][] = [];
  for (const calls of packChannelCalls(batch.channels, useV1 ? CHANNELS_PER_V1_TX : CHANNELS_PER_LEGACY_TX)) {
    channelTxs.push(await Promise.all(calls.map(({ col, start, part }) => program.methods
      .stageChannels(col, start)
      .accounts({ relayer: relayer.publicKey, staging })
      .remainingAccounts(part.map((pubkey) => ({ pubkey, isSigner: false, isWritable: false })))
      .instruction())));
  }

  let s = 0;
  let first = true;
  let tailIx: TransactionInstruction | undefined;
  while (s < total) {
    const n = Math.min(per, total - s);
    const isLast = s + n >= total;
    if (isLast && !useV1 && n <= MERGEABLE_TAIL_SLOTS && !first) {
      tailIx = await chunk(s, n); // merged into seal_and_queue by the caller
      break;
    }
    const ixs: TransactionInstruction[] = [];
    if (first && !opts.fresh) {
      ixs.push(await program.methods.resetStaging(kind)
        .accounts({ relayer: relayer.publicKey, staging, clearingResult: clearingPda(program.programId, staging) })
        .instruction());
    }
    ixs.push(await chunk(s, n));
    // the reset must land before any other chunk; send it alone first, the rest in parallel
    if (first) await send(ixs); else sends.push(send(ixs));
    first = false;
    s += n;
  }
  for (const ixs of channelTxs) sends.push(send(ixs));
  await Promise.all(sends);
  return { tailIx, txCount };
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
  tailIx?: TransactionInstruction,
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
    compDefAccount: getCompDefAccAddress(program.programId, Buffer.from(getCompDefAccOffset(circuit)).readUInt32LE()),
  };
  const m = kind === KIND_UNILATERAL
    ? program.methods.sealAndQueueUnilateral(computationOffset, count)
    : program.methods.sealAndQueueRoute(computationOffset, count);
  const pre: TransactionInstruction[] = tailIx ? [tailIx] : [];
  const sig = await m.accountsPartial(accounts).preInstructions(pre).signers([relayer]).rpc({ commitment: "confirmed" });
  return { computationOffset, clearingResult, sig };
}

export async function awaitClearing(provider: anchor.AnchorProvider, program: Program<RyvoProtocol>, computationOffset: anchor.BN): Promise<string> {
  return awaitComputationFinalization(provider, computationOffset, program.programId, "confirmed");
}

export function bitmapBits(bitmap: number[], count: number): boolean[] {
  return Array.from({ length: count }, (_, i) => (bitmap[i >> 3] & (1 << (i & 7))) !== 0);
}

/**
 * settle_channels for a set of indices. `accountsFor(i)` returns the per-commitment accounts in
 * the order the program expects (unilateral: [channel, payeeBalance]; route: [channelAg,
 * channelGp, providerBalance]).
 */
export async function settle(
  program: Program<RyvoProtocol>,
  staging: PublicKey,
  indices: number[],
  accountsFor: (i: number) => PublicKey[],
): Promise<string> {
  const remaining: AccountMeta[] = indices.flatMap((i) => accountsFor(i).map((pubkey) => ({ pubkey, isWritable: true, isSigner: false })));
  return program.methods
    .settleChannels(Buffer.from(indices))
    .accounts({ staging, clearingResult: clearingPda(program.programId, staging) })
    .remainingAccounts(remaining)
    .rpc({ commitment: "confirmed" });
}

/** Return rent for a buffer whose current batch is fully settled (or was never queued). */
export async function closeStaging(program: Program<RyvoProtocol>, relayer: Keypair, staging: PublicKey): Promise<string> {
  return program.methods.closeStaging()
    .accounts({ relayer: relayer.publicKey, staging, clearingResult: clearingPda(program.programId, staging) })
    .signers([relayer]).rpc({ commitment: "confirmed" });
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
 * from `build/<circuit>.arcis`, which is only sensible on localnet.
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
  const compDef = PublicKey.findProgramAddressSync([baseSeed, program.programId.toBuffer(), offset], getArciumProgramId())[0];
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
    await uploadCircuit(provider, circuit, program.programId, raw, false, 500, { skipPreflight: true, preflightCommitment: "confirmed", commitment: "confirmed" });
  }
  return compDef;
}
