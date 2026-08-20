/**
 * Relayer-side helpers for Arcium clearing: build a batch's slot buffer, stage it, seal + queue,
 * wait for the callback, settle. Mirrors `programs/ryvo_protocol/src/clearing/mod.rs` exactly —
 * the slot layout is the contract between the three parties that read it (this client, the
 * circuit via the argument list the program builds, and `settle_channels`).
 *
 * A relayer owns one reusable staging buffer: `openStaging` once, then per batch
 * `stageBatch` (which resets the buffer in the first transaction) → `sealAndQueue` →
 * `awaitClearing` → `settle`. The relayer sends dense records (`stage_records`: ids, targets,
 * signatures as raw bytes + the source bucket accounts); the program lays them out in slots and
 * copies each channel slot's registered key from the bucket. A short batch stages only
 * its real records; the program pads at seal time.
 */
import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import {
  AccountMeta,
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import { randomBytes } from "crypto";
import * as fs from "fs";
import {
  awaitComputationFinalization,
  getArciumEnv,
  getCompDefAccOffset,
  getArciumAccountBaseSeed,
  getArciumProgramId,
  uploadCircuit,
  getMXEAccAddress,
  getMempoolAccAddress,
  getCompDefAccAddress,
  getExecutingPoolAccAddress,
  getComputationAccAddress,
  getClusterAccAddress,
  getLookupTableAddress,
  getArciumProgram,
} from "@arcium-hq/client";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import {
  KIND_ROUTE,
  KIND_UNILATERAL,
  MAX_ROUTE_ALLOCATIONS,
  RouteCommitment,
  SIG_SLOTS,
  SLOT,
  UnilateralCommitment,
} from "../tests/commitment-client";
import { buildV1Transaction, sendV1 } from "./txv1";

/** Commitments per batch. Must equal `N_UNI` / `N_ROUTE` in the program and the circuit. */
export const N_UNI = 64;
export const N_ROUTE = 32;
/** Dense record sizes on the wire (what `stage_records` takes). */
export const UNILATERAL_RECORD_LEN = 8 + 8 + 64; // channel_id, target, sig
export const ROUTE_RECORD_BASE_LEN = 3 * 8 + 1 + 2 * 64;
export const ROUTE_ALLOCATION_LEN = 16;
/** Slots per commitment once the program has laid it out (ids, sigs, keys, channel addresses). */
export const UNILATERAL_SLOTS_PER_RECORD = 1 + SIG_SLOTS + 2 + 1; // 7
export const ROUTE_SLOTS_PER_RECORD =
  2 + MAX_ROUTE_ALLOCATIONS + 2 * SIG_SLOTS + 2 + 1; // 27
export const UNILATERAL_SLOTS = N_UNI * UNILATERAL_SLOTS_PER_RECORD; // 448
export const ROUTE_SLOTS = N_ROUTE * ROUTE_SLOTS_PER_RECORD + 2; // shared gateway key
export const MAX_SLOTS = Math.max(UNILATERAL_SLOTS, ROUTE_SLOTS);
/** 8-byte discriminator + 120-byte header + MAX_SLOTS slots. Must equal `StagingBuffer::SPACE`. */
export const STAGING_SPACE = 8 + 120 + MAX_SLOTS * SLOT;
export const CIRCUITS = {
  [KIND_UNILATERAL]: "clear_unilateral64",
  [KIND_ROUTE]: "clear_route32",
} as const;
export type CircuitName = (typeof CIRCUITS)[keyof typeof CIRCUITS];

export interface UnilateralRecord {
  commitment: UnilateralCommitment;
  sourceBucket: PublicKey;
  signature: Uint8Array; // 64
}

export interface RouteRecord {
  commitment: RouteCommitment;
  sourceBucket: PublicKey;
  agentSignature: Uint8Array;
  gatewaySignature: Uint8Array;
}

/** A batch ready to stage: one dense record + its source account per commitment, no padding. */
export interface Batch {
  kind: number;
  sharedAccounts: PublicKey[];
  records: { data: Buffer; channels: PublicKey[] }[];
}

function u64le(v: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(v);
  return b;
}

function checkSize<T>(xs: T[], n: number) {
  if (xs.length === 0 || xs.length > n)
    throw new Error(`batch must hold 1..${n} commitments, got ${xs.length}`);
}

/** Record: channel_id u64 | target u64 | sig[64]; accounts: source bucket. */
export function buildUnilateralBatch(records: UnilateralRecord[]): Batch {
  checkSize(records, N_UNI);
  return {
    kind: KIND_UNILATERAL,
    sharedAccounts: [],
    records: records.map((r) => ({
      data: Buffer.concat([
        u64le(r.commitment.channelId),
        u64le(r.commitment.targetCumulative),
        Buffer.from(r.signature),
      ]),
      channels: [r.sourceBucket],
    })),
  };
}

/** Compact record: source/base/target/count | active allocations | two signatures. */
export function buildRouteBatch(
  records: RouteRecord[],
  gatewayParticipant: PublicKey
): Batch {
  checkSize(records, N_ROUTE);
  return {
    kind: KIND_ROUTE,
    sharedAccounts: [gatewayParticipant],
    records: records.map((r) => ({
      data: Buffer.concat([
        u64le(r.commitment.sourceChannelId),
        u64le(r.commitment.baseCumulative),
        u64le(r.commitment.targetCumulative),
        Buffer.from([r.commitment.allocations.length]),
        ...r.commitment.allocations.flatMap((allocation) => [
          u64le(allocation.participantId),
          u64le(allocation.amount),
        ]),
        Buffer.from(r.agentSignature),
        Buffer.from(r.gatewaySignature),
      ]),
      channels: [r.sourceBucket],
    })),
  };
}

export const clearingPda = (programId: PublicKey, staging: PublicKey) =>
  PublicKey.findProgramAddressSync(
    [Buffer.from("clearing"), staging.toBuffer()],
    programId
  )[0];

/** Legacy packet limit; staging transactions are packed against the real serialized size. */
const LEGACY_TX_BYTES = 1232;
const DUMMY_BLOCKHASH = "11111111111111111111111111111111";

/** Serialized legacy size of a transaction holding `ixs` with one signer. */
function legacySize(
  feePayer: PublicKey,
  ixs: TransactionInstruction[]
): number {
  const tx = new anchor.web3.Transaction({
    feePayer,
    recentBlockhash: DUMMY_BLOCKHASH,
  }).add(...ixs);
  try {
    return tx.serialize({
      requireAllSignatures: false,
      verifySignatures: false,
    }).length;
  } catch {
    return Number.MAX_SAFE_INTEGER; // web3 refuses to serialize an oversized message
  }
}

function fitsV1(relayer: Keypair, ixs: TransactionInstruction[]): boolean {
  try {
    buildV1Transaction(ixs, [relayer], DUMMY_BLOCKHASH, {
      computeUnitLimit: 200_000,
    });
    return true;
  } catch {
    return false;
  }
}

let v1Support: boolean | undefined;
/**
 * Transaction v1 (SIMD-0296/0385) quadruples the packet, cutting staging transactions ~4×.
 * It is feature-gated (`enable_tx_v1`); probe once per process with a real send and fall back
 * to legacy. RYVO_TX_V1=0 forces legacy, RYVO_TX_V1=1 forces v1.
 */
export async function supportsTxV1(
  program: Program<RyvoProtocol>,
  payer: Keypair
): Promise<boolean> {
  if (process.env.RYVO_TX_V1 === "0") return false;
  if (process.env.RYVO_TX_V1 === "1") return true;
  if (v1Support !== undefined) return v1Support;
  try {
    await sendV1(
      program.provider.connection,
      [
        SystemProgram.transfer({
          fromPubkey: payer.publicKey,
          toPubkey: payer.publicKey,
          lamports: 1,
        }),
      ],
      [payer],
      { computeUnitLimit: 20_000 }
    );
    v1Support = true;
  } catch (e: any) {
    v1Support = false;
    if (!/version is unsupported|expired/i.test(String(e?.message)))
      console.warn(
        "v1 probe failed for a reason other than the gate:",
        String(e?.message).slice(0, 120)
      );
  }
  return v1Support;
}

/** Staging transactions a full batch of `kind` needs under each format (for reporting): a dry run of the packer. */
export async function stagingTxCount(
  program: Program<RyvoProtocol>,
  relayer: Keypair,
  kind: number
): Promise<{ legacy: number; v1: number }> {
  const n = kind === KIND_UNILATERAL ? N_UNI : N_ROUTE;
  const len =
    kind === KIND_UNILATERAL
      ? UNILATERAL_RECORD_LEN
      : ROUTE_RECORD_BASE_LEN + ROUTE_ALLOCATION_LEN;
  const batch: Batch = {
    kind,
    sharedAccounts: kind === KIND_ROUTE ? [Keypair.generate().publicKey] : [],
    records: Array.from({ length: n }, () => ({
      data: Buffer.alloc(len, 1),
      channels: [Keypair.generate().publicKey],
    })),
  };
  const staging = Keypair.generate().publicKey;
  const legacy = (
    await planStaging(
      program,
      relayer,
      staging,
      batch,
      { fresh: false, reclaim: new anchor.BN(1) },
      false
    )
  ).txs.length;
  const v1 = (
    await planStaging(
      program,
      relayer,
      staging,
      batch,
      { fresh: false, reclaim: new anchor.BN(1) },
      true
    )
  ).txs.length;
  return { legacy, v1 };
}

/**
 * Create a relayer's reusable staging buffer: `create_account` (20 KB exceeds the CPI-creation
 * cap, so the relayer creates it at the top level with the program as owner) + `open_staging`,
 * which also creates the buffer's `ClearingResult`. One transaction.
 */
export async function openStaging(
  program: Program<RyvoProtocol>,
  relayer: Keypair,
  kind: number
): Promise<PublicKey> {
  const stagingKp = Keypair.generate();
  const staging = stagingKp.publicKey;
  const lamports =
    await program.provider.connection.getMinimumBalanceForRentExemption(
      STAGING_SPACE
    );
  await program.methods
    .openStaging(kind)
    .accounts({
      relayer: relayer.publicKey,
      staging,
      clearingResult: clearingPda(program.programId, staging),
      systemProgram: SystemProgram.programId,
    })
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
    .rpc({ commitment: "confirmed" });
  return staging;
}

/**
 * Arcium's `claim_computation_rent`: the queue tx funds a ~560-byte computation account
 * (~0.0048 SOL); once the computation has finished, the payer gets that rent back with this.
 */
export async function claimComputationRentIx(
  program: Program<RyvoProtocol>,
  payer: PublicKey,
  computationOffset: anchor.BN
): Promise<TransactionInstruction> {
  const { env } = arciumEnv();
  return getArciumProgram(program.provider as anchor.AnchorProvider)
    .methods.claimComputationRent(computationOffset, env.arciumClusterOffset)
    .accountsPartial({
      signer: payer,
      comp: getComputationAccAddress(
        env.arciumClusterOffset,
        computationOffset
      ),
    })
    .instruction();
}

interface StagingPlan {
  /** Transactions to send, in order; the first carries `reset_staging` when the buffer is reused. */
  txs: TransactionInstruction[][];
  /** Instructions that ride in the seal_and_queue transaction (rent claim, a small tail of records). */
  sealPre: TransactionInstruction[];
  /** Number of records that ride in the seal transaction. */
  tailRecords: number;
}

/**
 * Pack a batch into transactions against the real serialized size (legacy) or a fixed record
 * count (v1). The previous computation's rent claim and the last few records ride in the
 * seal_and_queue transaction when they fit.
 */
async function planStaging(
  program: Program<RyvoProtocol>,
  relayer: Keypair,
  staging: PublicKey,
  batch: Batch,
  opts: { fresh?: boolean; reclaim?: anchor.BN },
  useV1: boolean
): Promise<StagingPlan> {
  // Built by hand: Anchor's instruction encoder caps data at 1,000 bytes, and a v1 chunk is bigger.
  const disc = Buffer.from(
    (
      program.idl.instructions.find(
        (i) => i.name === "stage_records" || i.name === "stageRecords"
      ) as any
    ).discriminator
  );
  const stageIx = async (start: number, recs: Batch["records"]) => {
    const body = Buffer.concat(recs.map((r) => r.data));
    const head = Buffer.alloc(2 + 4);
    head.writeUInt16LE(start, 0);
    head.writeUInt32LE(body.length, 2);
    return new TransactionInstruction({
      programId: program.programId,
      keys: [
        { pubkey: relayer.publicKey, isSigner: true, isWritable: false },
        { pubkey: staging, isSigner: false, isWritable: true },
        ...batch.sharedAccounts.map((pubkey) => ({
          pubkey,
          isSigner: false,
          isWritable: false,
        })),
        ...recs.flatMap((r) =>
          r.channels.map((pubkey) => ({
            pubkey,
            isSigner: false,
            isWritable: false,
          }))
        ),
      ],
      data: Buffer.concat([disc, head, body]),
    });
  };
  const resetIx = opts.fresh
    ? undefined
    : await program.methods
        .resetStaging(batch.kind)
        .accounts({
          relayer: relayer.publicKey,
          staging,
          clearingResult: clearingPda(program.programId, staging),
        })
        .instruction();
  const claimIx = opts.reclaim
    ? await claimComputationRentIx(program, relayer.publicKey, opts.reclaim)
    : undefined;
  // what the seal tx already carries: 15 accounts + its own data; measured against the same limit
  const sealShape = await program.methods
    .sealAndQueueRoute(new anchor.BN(1), 1, 0, new anchor.BN(0))
    .accountsPartial(
      sealAccounts(
        program,
        relayer.publicKey,
        staging,
        batch.kind,
        new anchor.BN(1)
      )
    )
    .instruction();

  const recs = batch.records;
  const txs: TransactionInstruction[][] = [];
  let sealPre: TransactionInstruction[] = claimIx ? [claimIx] : [];
  let tailRecords = 0;
  if (useV1) {
    let i = 0;
    while (i < recs.length) {
      const extras = i === 0 && resetIx ? [resetIx] : [];
      let n = 1;
      let ix = await stageIx(i, recs.slice(i, i + 1));
      while (i + n < recs.length) {
        const next = await stageIx(i, recs.slice(i, i + n + 1));
        if (!fitsV1(relayer, [...extras, next])) break;
        ix = next;
        n++;
      }
      txs.push([...extras, ix]);
      i += n;
    }
    return { txs, sealPre, tailRecords };
  }
  // legacy: grow each chunk until the next record no longer fits
  let i = 0;
  while (i < recs.length) {
    const extras = i === 0 && resetIx ? [resetIx] : [];
    let n = 1;
    let ix = await stageIx(i, recs.slice(i, i + 1));
    while (i + n < recs.length) {
      const next = await stageIx(i, recs.slice(i, i + n + 1));
      if (legacySize(relayer.publicKey, [...extras, next]) > LEGACY_TX_BYTES)
        break;
      ix = next;
      n++;
    }
    // the last chunk rides in the seal tx if it fits there
    if (
      i + n >= recs.length &&
      legacySize(relayer.publicKey, [...sealPre, ...extras, ix, sealShape]) <=
        LEGACY_TX_BYTES
    ) {
      sealPre = [...sealPre, ...extras, ix];
      tailRecords = n;
      break;
    }
    txs.push([...extras, ix]);
    i += n;
  }
  return { txs, sealPre, tailRecords };
}

function sealAccounts(
  program: Program<RyvoProtocol>,
  relayer: PublicKey,
  staging: PublicKey,
  kind: number,
  computationOffset: anchor.BN
) {
  const { env, clusterAccount } = arciumEnv();
  return {
    relayer,
    config: PublicKey.findProgramAddressSync(
      [Buffer.from("config")],
      program.programId
    )[0],
    staging,
    clearingResult: clearingPda(program.programId, staging),
    computationAccount: getComputationAccAddress(
      env.arciumClusterOffset,
      computationOffset
    ),
    clusterAccount,
    mxeAccount: getMXEAccAddress(program.programId),
    mempoolAccount: getMempoolAccAddress(env.arciumClusterOffset),
    executingPool: getExecutingPoolAccAddress(env.arciumClusterOffset),
    compDefAccount: getCompDefAccAddress(
      program.programId,
      Buffer.from(getCompDefAccOffset(CIRCUITS[kind as 1 | 2])).readUInt32LE()
    ),
  };
}

/**
 * Stage a batch into an existing buffer. The first transaction carries `reset_staging` (which
 * requires the previous batch to be fully settled) unless `fresh` says the buffer was just
 * opened. Pass the previous batch's computation offset as `reclaim` and its rent claim rides in
 * the seal transaction. Returns the instructions that must go into the seal transaction
 * (`sealPre`: the claim and any tail records) — hand them to `sealAndQueue`.
 */
export async function stageBatch(
  program: Program<RyvoProtocol>,
  relayer: Keypair,
  staging: PublicKey,
  batch: Batch,
  opts: { fresh?: boolean; reclaim?: anchor.BN } = {}
): Promise<{
  sealPre: TransactionInstruction[];
  txCount: number;
  tailRecords: number;
}> {
  const useV1 = await supportsTxV1(program, relayer);
  const plan = await planStaging(program, relayer, staging, batch, opts, useV1);
  const send = async (ixs: TransactionInstruction[]) => {
    if (useV1)
      return sendV1(program.provider.connection, ixs, [relayer], {
        computeUnitLimit: 200_000,
      });
    const tx = new anchor.web3.Transaction().add(...ixs);
    return (program.provider as anchor.AnchorProvider).sendAndConfirm(
      tx,
      [relayer],
      { commitment: "confirmed" }
    );
  };
  // the reset must land before any other chunk: first tx alone, the rest in parallel
  if (plan.txs.length) await send(plan.txs[0]);
  await Promise.all(plan.txs.slice(1).map(send));
  return {
    sealPre: plan.sealPre,
    txCount: plan.txs.length,
    tailRecords: plan.tailRecords,
  };
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
  pre: TransactionInstruction[] = []
): Promise<{
  computationOffset: anchor.BN;
  clearingResult: PublicKey;
  sig: string;
}> {
  const computationOffset = new anchor.BN(randomBytes(8), "hex");
  const clearingResult = clearingPda(program.programId, staging);
  const accounts = sealAccounts(
    program,
    relayer.publicKey,
    staging,
    kind,
    computationOffset
  );
  const cu = Number(process.env.RYVO_CALLBACK_CU_LIMIT ?? 0); // 0 = Arcium node default
  const price = new anchor.BN(process.env.RYVO_CU_PRICE_MICRO ?? 0); // Arcium mempool priority
  const m =
    kind === KIND_UNILATERAL
      ? program.methods.sealAndQueueUnilateral(
          computationOffset,
          count,
          cu,
          price
        )
      : program.methods.sealAndQueueRoute(computationOffset, count, cu, price);
  const sig = await m
    .accountsPartial(accounts)
    .preInstructions(pre)
    .signers([relayer])
    .rpc({ commitment: "confirmed" });
  return { computationOffset, clearingResult, sig };
}

export async function awaitClearing(
  provider: anchor.AnchorProvider,
  program: Program<RyvoProtocol>,
  computationOffset: anchor.BN
): Promise<string> {
  return awaitComputationFinalization(
    provider,
    computationOffset,
    program.programId,
    "confirmed"
  );
}

export function bitmapBits(bitmap: number[], count: number): boolean[] {
  return Array.from(
    { length: count },
    (_, i) => (bitmap[i >> 3] & (1 << (i & 7))) !== 0
  );
}

async function settlementInstruction(
  program: Program<RyvoProtocol>,
  staging: PublicKey,
  indices: number[],
  accountsFor: (i: number) => PublicKey[]
): Promise<TransactionInstruction> {
  const remaining: AccountMeta[] = indices.flatMap((i) =>
    accountsFor(i).map((pubkey) => ({
      pubkey,
      isWritable: true,
      isSigner: false,
    }))
  );
  return program.methods
    .settleChannels(Buffer.from(indices))
    .accounts({
      staging,
      clearingResult: clearingPda(program.programId, staging),
    })
    .remainingAccounts(remaining)
    .instruction();
}

/**
 * settle_channels for a set of indices. `accountsFor(i)` returns the per-commitment accounts in
 * the order the program expects (unilateral: [sourceBucket, payeeBalance]; route:
 * [sourceBucket, gatewayBalance, providerBalance x allocation count]).
 */
export async function settle(
  program: Program<RyvoProtocol>,
  staging: PublicKey,
  indices: number[],
  accountsFor: (i: number) => PublicKey[]
): Promise<string> {
  const ix = await settlementInstruction(
    program,
    staging,
    indices,
    accountsFor
  );
  return (program.provider as anchor.AnchorProvider).sendAndConfirm(
    new anchor.web3.Transaction().add(ix),
    [],
    { commitment: "confirmed" }
  );
}

export interface SettlementMeasurement {
  signature: string;
  legacyBytes: number;
  uniqueAccounts: number;
  computeUnits: number;
}

/** Send one maximum-budget legacy settlement and report its actual resource use. */
export async function settleMeasured(
  program: Program<RyvoProtocol>,
  staging: PublicKey,
  indices: number[],
  accountsFor: (i: number) => PublicKey[]
): Promise<SettlementMeasurement> {
  const provider = program.provider as anchor.AnchorProvider;
  const ix = await settlementInstruction(
    program,
    staging,
    indices,
    accountsFor
  );
  const budget = ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 });
  const legacyBytes = legacySize(provider.wallet.publicKey, [budget, ix]);
  const unique = new Set<string>([
    provider.wallet.publicKey.toBase58(),
    budget.programId.toBase58(),
    ix.programId.toBase58(),
    ...budget.keys.map((meta) => meta.pubkey.toBase58()),
    ...ix.keys.map((meta) => meta.pubkey.toBase58()),
  ]);
  const signature = await provider.sendAndConfirm(
    new anchor.web3.Transaction().add(budget, ix),
    [],
    { commitment: "confirmed" }
  );
  const landed = await provider.connection.getTransaction(signature, {
    commitment: "confirmed",
    maxSupportedTransactionVersion: 0,
  });
  if (!landed)
    throw new Error(`settlement transaction ${signature} was not found`);
  return {
    signature,
    legacyBytes,
    uniqueAccounts: unique.size,
    computeUnits: Number(landed.meta?.computeUnitsConsumed ?? 0),
  };
}

/** Return rent for a buffer whose current batch is fully settled (or was never queued). */
export async function closeStaging(
  program: Program<RyvoProtocol>,
  relayer: Keypair,
  staging: PublicKey
): Promise<string> {
  return program.methods
    .closeStaging()
    .accounts({
      relayer: relayer.publicKey,
      staging,
      clearingResult: clearingPda(program.programId, staging),
    })
    .signers([relayer])
    .rpc({ commitment: "confirmed" });
}

// ---------------------------------------------------------------------------- one-time setup

export async function ensureArciumSigner(
  program: Program<RyvoProtocol>,
  payer: Keypair
) {
  const [signPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("ArciumSignerAccount")],
    program.programId
  );
  const info = await program.provider.connection.getAccountInfo(signPda);
  if (info) return signPda;
  await program.methods
    .initArciumSigner()
    .accounts({
      payer: payer.publicKey,
      signPdaAccount: signPda,
      systemProgram: SystemProgram.programId,
    })
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
  circuit: CircuitName,
  offchainUrl?: string
): Promise<PublicKey> {
  const arciumProgram = getArciumProgram(provider);
  const baseSeed = getArciumAccountBaseSeed("ComputationDefinitionAccount");
  const offset = getCompDefAccOffset(circuit);
  const compDef = PublicKey.findProgramAddressSync(
    [baseSeed, program.programId.toBuffer(), offset],
    getArciumProgramId()
  )[0];
  const exists = await provider.connection.getAccountInfo(compDef);
  if (exists) return compDef;

  const mxeAccount = getMXEAccAddress(program.programId);
  const mxeAcc = await arciumProgram.account.mxeAccount.fetch(mxeAccount);
  const lut = getLookupTableAddress(program.programId, mxeAcc.lutOffsetSlot);
  const m =
    circuit === "clear_unilateral64"
      ? program.methods.initClearUnilateralCompDef(offchainUrl ?? null)
      : program.methods.initClearRouteCompDef(offchainUrl ?? null);
  await m
    .accounts({
      compDefAccount: compDef,
      payer: payer.publicKey,
      mxeAccount,
      addressLookupTable: lut,
    })
    .signers([payer])
    .rpc({ commitment: "confirmed" });

  if (!offchainUrl) {
    const raw = fs.readFileSync(`build/${circuit}.arcis`);
    await uploadCircuit(provider, circuit, program.programId, raw, false, 500, {
      skipPreflight: true,
      preflightCommitment: "confirmed",
      commitment: "confirmed",
    });
  }
  return compDef;
}
