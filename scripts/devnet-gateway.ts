/**
 * Devnet gateway smoke: 100 agents pay 10 providers through one gateway, cleared by Arcium.
 *
 *   one agent + gateway commitment directly pays provider_(i mod 10)
 *
 * What it does, in order (each step is idempotent where the protocol allows):
 *   1. bootstrap: initialize config, Arcium signer PDA, computation definitions (circuits by URL)
 *   2. test mint + vault; 100 agents / 1 gateway / 10 providers registered; 100 source channels
 *   3. 100 route commitments signed by agent then gateway
 *   4. staged in 4 batches of 32, sealed + queued, callbacks awaited
 *   5. settled through v0 transactions and an address lookup table
 *   6. balances asserted, solvency asserted, costs printed, staging rent reclaimed
 *
 * Prerequisites: `arcium deploy --cluster-offset 456 ...` done for this program id, and the
 * circuits in `circuits/` pushed to GitHub (the comp defs point at raw.githubusercontent.com).
 *
 *   npx ts-mocha -p ./tsconfig.json -t 3600000 scripts/devnet-gateway.ts
 */
import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import {
  AddressLookupTableProgram,
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createMint,
  createAssociatedTokenAccountIdempotentInstruction,
  createMintToInstruction,
  getAssociatedTokenAddressSync,
  getAccount,
} from "@solana/spl-token";
import { getClusterAccAddress } from "@arcium-hq/client";
import { expect } from "chai";
import * as fs from "fs";
import * as os from "os";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { partyKeypair, recordRun } from "./party-keys";
import {
  KIND_ROUTE,
  RouteCommitment,
  deriveArcisSigner,
  deriveMessageDomain,
  signCommitment,
} from "../tests/commitment-client";
import {
  N_ROUTE,
  RouteRecord,
  awaitClearing,
  bitmapBits,
  buildRouteBatch,
  clearingPda,
  claimComputationRentIx,
  ensureArciumSigner,
  ensureCompDef,
  openStaging,
  sealAndQueue,
  stageBatch,
  stagingTxCount,
  supportsTxV1,
} from "../tests-arcium/clearing-client";

// ------------------------------------------------------------------ configuration
const RPC = process.env.ANCHOR_PROVIDER_URL ?? "https://api.devnet.solana.com";
const CLUSTER_OFFSET = Number(process.env.ARCIUM_CLUSTER_OFFSET ?? 456);
const CIRCUIT_BASE_URL =
  process.env.RYVO_CIRCUIT_BASE_URL ??
  "https://raw.githubusercontent.com/Ryvonetwork/ryvo-protocol-v2/master/circuits";
const DEVNET_CHAIN_ID = 1;
const CHANNEL_TIMELOCK = 10;
const AGENTS = Number(process.env.RYVO_AGENTS ?? 100);
const PROVIDERS = Number(process.env.RYVO_PROVIDERS ?? 10);
const ONE = 1_000_000; // 6 decimals
const AGENT_DEPOSIT = 50 * ONE;
const AGENT_LOCK = 40 * ONE;
const CONCURRENCY = 6; // public devnet RPC is rate limited

// The arcium client reads the cluster offset from env; set it before any helper runs.
process.env.ARCIUM_CLUSTER_OFFSET = String(CLUSTER_OFFSET);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
function wallet(): Keypair {
  return Keypair.fromSecretKey(
    new Uint8Array(
      JSON.parse(
        fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8")
      )
    )
  );
}
async function pmap<T, R>(
  xs: T[],
  f: (x: T, i: number) => Promise<R>,
  n = CONCURRENCY
): Promise<R[]> {
  const out: R[] = new Array(xs.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, xs.length) }, async () => {
      while (next < xs.length) {
        const i = next++;
        out[i] = await f(xs[i], i);
      }
    })
  );
  return out;
}
async function retry<T>(
  f: () => Promise<T>,
  tries = 5,
  label = ""
): Promise<T> {
  let last: any;
  for (let i = 0; i < tries; i++) {
    try {
      return await f();
    } catch (e) {
      last = e;
      await sleep(500 * (i + 1) * (i + 1));
    }
  }
  throw new Error(
    `${label} failed after ${tries} tries: ${last?.message ?? last}`
  );
}

describe("ryvo_protocol devnet gateway smoke", function () {
  this.timeout(3_600_000);

  const connection = new anchor.web3.Connection(RPC, "confirmed");
  const payer = wallet();
  const provider = new anchor.AnchorProvider(
    connection,
    new anchor.Wallet(payer),
    { commitment: "confirmed", preflightCommitment: "confirmed" }
  );
  anchor.setProvider(provider);
  const idl = JSON.parse(
    fs.readFileSync("target/idl/ryvo_protocol.json", "utf8")
  );
  const program = new Program<RyvoProtocol>(idl, provider);
  const programId = program.programId;
  const domain = deriveMessageDomain(programId, DEVNET_CHAIN_ID);

  const pda = {
    config: PublicKey.findProgramAddressSync(
      [Buffer.from("config")],
      programId
    )[0],
    participant: (o: PublicKey) =>
      PublicKey.findProgramAddressSync(
        [Buffer.from("participant"), o.toBuffer()],
        programId
      )[0],
    tokenConfig: (m: PublicKey) =>
      PublicKey.findProgramAddressSync(
        [Buffer.from("token"), m.toBuffer()],
        programId
      )[0],
    vault: (m: PublicKey) =>
      PublicKey.findProgramAddressSync(
        [Buffer.from("vault"), m.toBuffer()],
        programId
      )[0],
    balance: (p: PublicKey, m: PublicKey) =>
      PublicKey.findProgramAddressSync(
        [Buffer.from("balance"), p.toBuffer(), m.toBuffer()],
        programId
      )[0],
    channel: (a: PublicKey, b: PublicKey, m: PublicKey) =>
      PublicKey.findProgramAddressSync(
        [Buffer.from("channel"), a.toBuffer(), b.toBuffer(), m.toBuffer()],
        programId
      )[0],
    programData: PublicKey.findProgramAddressSync(
      [programId.toBuffer()],
      new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111")
    )[0],
  };

  interface Party {
    owner: Keypair;
    participant: PublicKey;
    participantId: bigint;
    balance: PublicKey;
    seed: Uint8Array;
    signer: Buffer;
  }
  interface Chan {
    key: PublicKey;
    id: bigint;
    payer: Party;
    payee: Party;
  }

  let mint: PublicKey;
  let tokenConfig: PublicKey;
  let vault: PublicKey;
  let agents: Party[] = [];
  let gateway: Party;
  let providers: Party[] = [];
  const chanAG: Chan[] = [];
  const records: RouteRecord[] = [];
  const routeOf: {
    agent: number;
    provider: number;
    target: number;
    providerAmount: number;
    fee: number;
  }[] = [];
  /** The relayer's single reusable staging buffer. */
  let staging: PublicKey;
  /** The previous batch's computation; its rent comes back in the next batch's first tx. */
  let lastComputation: anchor.BN | undefined;
  const batches: { first: number; count: number; bits: boolean[] }[] = [];
  const stats = {
    tx: { setup: 0, stage: 0, queue: 0, callback: 0, settle: 0 },
    solStart: 0,
    t: {} as Record<string, number>,
  };
  const startedAt = Date.now();

  const mkParty = (owner: Keypair): Party => {
    const participant = pda.participant(owner.publicKey);
    const seed = owner.secretKey.slice(0, 32);
    return {
      owner,
      participant,
      participantId: 0n,
      balance: pda.balance(participant, mint),
      seed,
      signer: deriveArcisSigner(seed).publicKey,
    };
  };

  before(async () => {
    stats.solStart = await connection.getBalance(payer.publicKey);
    console.log(
      `    program ${programId.toBase58()} | rpc ${RPC} | cluster ${CLUSTER_OFFSET} | wallet ${payer.publicKey.toBase58()} (${(
        stats.solStart / 1e9
      ).toFixed(3)} SOL)`
    );
  });

  it("1. bootstraps config, Arcium signer and computation definitions", async () => {
    if (!(await connection.getAccountInfo(pda.config))) {
      await program.methods
        .initialize(DEVNET_CHAIN_ID, new anchor.BN(CHANNEL_TIMELOCK))
        .accounts({
          payer: payer.publicKey,
          initialAuthority: payer.publicKey,
          config: pda.config,
          programData: pda.programData,
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("    initialized config");
    }
    const cfg = await program.account.config.fetch(pda.config);
    expect(Buffer.from(cfg.messageDomain).toString("hex")).to.equal(
      domain.toString("hex")
    );
    console.log(
      `    message_domain ${domain.toString(
        "hex"
      )} next_channel_id ${cfg.nextChannelId.toString()}`
    );
    await ensureArciumSigner(program, payer);
    const t0 = Date.now();
    // The unilateral comp def is registered on demand (this smoke exercises routes only, and a
    // deactivated-but-not-yet-closable comp def at that offset would make init fail).
    await ensureCompDef(
      program,
      provider,
      payer,
      "clear_unilateral64",
      `${CIRCUIT_BASE_URL}/clear_unilateral64.arcis`
    );
    await ensureCompDef(
      program,
      provider,
      payer,
      "clear_route32",
      `${CIRCUIT_BASE_URL}/clear_route32.arcis`
    );
    console.log(
      `    comp defs ready (${((Date.now() - t0) / 1000).toFixed(
        1
      )}s) — circuits at ${CIRCUIT_BASE_URL}`
    );
  });

  it("2. creates a test mint, registers it, and sets up 100 agents, 1 gateway, 10 providers", async () => {
    const t0 = Date.now();
    mint = await createMint(
      connection,
      payer,
      payer.publicKey,
      null,
      6,
      undefined,
      { commitment: "confirmed" },
      TOKEN_PROGRAM_ID
    );
    tokenConfig = pda.tokenConfig(mint);
    vault = pda.vault(mint);
    await program.methods
      .registerToken()
      .accounts({
        authority: payer.publicKey,
        config: pda.config,
        mint,
        tokenConfig,
        vault,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .rpc();
    console.log(`    mint ${mint.toBase58()}`);

    // Deterministic throwaway keys (recorded in ~/.ryvo-devnet-runs.json) so the SOL of an
    // aborted run can always be swept back with scripts/sweep-runs.ts.
    const nonce = Date.now();
    recordRun({
      nonce,
      parties: AGENTS + 1 + PROVIDERS,
      startedAt: new Date(nonce).toISOString(),
      note: `gateway smoke ${AGENTS}x${PROVIDERS}`,
    });
    let partyIndex = 0;
    const nextParty = () => mkParty(partyKeypair(payer, nonce, partyIndex++));
    agents = Array.from({ length: AGENTS }, nextParty);
    gateway = nextParty();
    providers = Array.from({ length: PROVIDERS }, nextParty);
    const all = [...agents, gateway, ...providers];

    // Fund SOL from the wallet (the faucet is rate limited): 8 transfers per tx.
    const lamports = (p: Party) => (p === gateway ? 0.12 : 0.03) * 1e9;
    for (let i = 0; i < all.length; i += 8) {
      const tx = new anchor.web3.Transaction();
      for (const p of all.slice(i, i + 8))
        tx.add(
          SystemProgram.transfer({
            fromPubkey: payer.publicKey,
            toPubkey: p.owner.publicKey,
            lamports: lamports(p),
          })
        );
      await retry(() => provider.sendAndConfirm(tx, []), 5, "fund");
      stats.tx.setup++;
    }

    // Registration: participant + balance (+ channel for agents) in one tx per party.
    const register = async (p: Party, channelTo?: Party) => {
      const ixs: TransactionInstruction[] = [
        await program.methods
          .initializeParticipant(new PublicKey(p.signer))
          .accounts({
            owner: p.owner.publicKey,
            config: pda.config,
            participant: p.participant,
            systemProgram: SystemProgram.programId,
          })
          .instruction(),
        await program.methods
          .openBalance()
          .accounts({
            payer: p.owner.publicKey,
            participant: p.participant,
            mint,
            tokenConfig,
            balance: p.balance,
            systemProgram: SystemProgram.programId,
          })
          .instruction(),
      ];
      const tx = new anchor.web3.Transaction().add(...ixs);
      tx.feePayer = p.owner.publicKey;
      await retry(
        () =>
          sendAndConfirmTransaction(connection, tx, [p.owner], {
            commitment: "confirmed",
          }),
        5,
        "register"
      );
      stats.tx.setup++;
    };
    await register(gateway);
    await pmap(providers, (p) => register(p));
    await pmap(agents, (a) => register(a));
    await pmap(all, async (p) => {
      const account = await program.account.participant.fetch(p.participant);
      p.participantId = BigInt(account.participantId.toString());
    });

    // Only agent -> gateway source channels are needed. Providers receive Balance credits
    // directly from the signed route commitment.
    const openChannel = async (from: Party, to: Party): Promise<Chan> => {
      const key = pda.channel(from.participant, to.participant, mint);
      const tx = new anchor.web3.Transaction().add(
        await program.methods
          .createChannel()
          .accounts({
            payerOwner: from.owner.publicKey,
            config: pda.config,
            payerParticipant: from.participant,
            payeeParticipant: to.participant,
            mint,
            tokenConfig,
            payerBalance: from.balance,
            payeeBalance: to.balance,
            channel: key,
            systemProgram: SystemProgram.programId,
          })
          .instruction()
      );
      tx.feePayer = from.owner.publicKey;
      await retry(
        () =>
          sendAndConfirmTransaction(connection, tx, [from.owner], {
            commitment: "confirmed",
          }),
        5,
        "channel"
      );
      stats.tx.setup++;
      const c = await program.account.channel.fetch(key);
      return {
        key,
        id: BigInt(c.channelId.toString()),
        payer: from,
        payee: to,
      };
    };
    // Config is write-locked by create_channel, so these serialize on-chain anyway; keep
    // concurrency modest to avoid preflight races on the id counter.
    const ag = await pmap(agents, (a) => openChannel(a, gateway), 3);
    chanAG.push(...ag);

    // Fund + deposit + lock per agent: ATA, mintTo (wallet is mint authority), deposit, lock.
    await pmap(agents, async (a, i) => {
      const ata = getAssociatedTokenAddressSync(
        mint,
        a.owner.publicKey,
        false,
        TOKEN_PROGRAM_ID
      );
      const tx = new anchor.web3.Transaction().add(
        createAssociatedTokenAccountIdempotentInstruction(
          payer.publicKey,
          ata,
          a.owner.publicKey,
          mint,
          TOKEN_PROGRAM_ID
        ),
        createMintToInstruction(
          mint,
          ata,
          payer.publicKey,
          AGENT_DEPOSIT,
          [],
          TOKEN_PROGRAM_ID
        ),
        await program.methods
          .deposit(new anchor.BN(AGENT_DEPOSIT))
          .accounts({
            funder: a.owner.publicKey,
            mint,
            tokenConfig,
            vault,
            funderTokenAccount: ata,
            participant: a.participant,
            balance: a.balance,
            tokenProgram: TOKEN_PROGRAM_ID,
          })
          .instruction(),
        await program.methods
          .lockChannelFunds(new anchor.BN(AGENT_LOCK))
          .accounts({
            payerOwner: a.owner.publicKey,
            payerParticipant: a.participant,
            config: pda.config,
            channel: chanAG[i].key,
            payerBalance: a.balance,
          })
          .instruction()
      );
      tx.feePayer = payer.publicKey;
      await retry(
        () => provider.sendAndConfirm(tx, [a.owner]),
        5,
        "deposit+lock"
      );
      stats.tx.setup++;
    });
    stats.t.setup = Date.now() - t0;
    console.log(
      `    ${AGENTS} agents funded, deposited ${
        AGENT_DEPOSIT / ONE
      } and locked ${AGENT_LOCK / ONE} each; ${chanAG.length} channels (${(
        stats.t.setup / 1000
      ).toFixed(0)}s, ${stats.tx.setup} tx)`
    );
  });

  it("3. signs 100 route commitments: agent, then gateway countersigns", async () => {
    // Each agent has one cumulative source channel. The commitment names the provider directly;
    // the one-unit signed remainder is the gateway fee.
    for (let i = 0; i < AGENTS; i++) {
      const providerIndex = i % PROVIDERS;
      const target = (10 + (i % 25)) * ONE; // 10..34 of the 40 locked
      const providerAmount = target - ONE;
      const c: RouteCommitment = {
        kind: KIND_ROUTE,
        messageDomain: domain,
        sourceChannelId: chanAG[i].id,
        baseCumulative: 0n,
        targetCumulative: BigInt(target),
        allocations: [
          {
            participantId: providers[providerIndex].participantId,
            amount: BigInt(providerAmount),
          },
        ],
      };
      const a = signCommitment(agents[i].seed, c);
      const g = signCommitment(gateway.seed, c);
      records.push({
        commitment: c,
        sourceChannel: chanAG[i].key,
        agentSignature: a.signature,
        gatewaySignature: g.signature,
      });
      routeOf.push({
        agent: i,
        provider: providerIndex,
        target,
        providerAmount,
        fee: ONE,
      });
    }
    console.log(
      `    ${records.length} route commitments, ${
        records.length * 2
      } signatures`
    );
  });

  it("4. stages, seals and queues the batches through one reusable buffer; Arcium clears them", async () => {
    const t0 = Date.now();
    const v1 = await supportsTxV1(program, payer);
    console.log(
      `    staging in ${
        v1 ? "v1 (4,096 B)" : "legacy (1,232 B)"
      } transactions; N=${N_ROUTE} commitments per batch`
    );
    const txc = await stagingTxCount(program, payer, KIND_ROUTE);
    if (!v1)
      console.log(
        `    (transaction v1 not active on this cluster; with it a full route batch would stage in ${txc.v1} tx instead of ${txc.legacy})`
      );
    staging = await openStaging(program, payer, KIND_ROUTE);
    stats.tx.stage += 1; // create + open (once per buffer, not per batch)
    for (let first = 0, k = 0; first < records.length; first += N_ROUTE, k++) {
      const batch = records.slice(first, first + N_ROUTE);
      const t1 = Date.now();
      const { sealPre, txCount, tailRecords } = await stageBatch(
        program,
        payer,
        staging,
        buildRouteBatch(batch, gateway.participant),
        { fresh: k === 0, reclaim: lastComputation }
      );
      stats.tx.stage += txCount;
      const { computationOffset, clearingResult } = await sealAndQueue(
        program,
        payer,
        staging,
        KIND_ROUTE,
        batch.length,
        sealPre
      );
      lastComputation = computationOffset;
      stats.tx.queue++;
      await awaitClearing(provider, program, computationOffset);
      const r = await program.account.clearingResult.fetch(clearingResult);
      const bits = bitmapBits(r.bitmap as number[], batch.length);
      stats.tx.callback++;
      console.log(
        `    batch ${k}: ${batch.length} routes staged in ${txCount + 1} tx${
          tailRecords ? ` (${tailRecords} records ride in the seal tx)` : ""
        }, verified=${r.verified} ${bits.filter(Boolean).length}/${
          batch.length
        } valid (${((Date.now() - t1) / 1000).toFixed(0)}s)`
      );
      expect(r.verified).to.be.true;
      expect(bits.every(Boolean)).to.be.true;
      batches.push({ first, count: batch.length, bits });
      // Settle right away so the buffer can be reset for the next batch (settlement is step 5's
      // job in the report; here it is interleaved because reuse requires it).
      await settleBatch(batches[batches.length - 1]);
    }
    stats.t.clear = Date.now() - t0;
  });

  /** Settle through the lookup table in v0 transactions. Each one-provider commitment supplies
   *  its source channel, the shared gateway balance and one provider balance. */
  const MAX_TX_ACCOUNTS = 64;
  const SETTLE_PER_TX = Number(process.env.RYVO_SETTLE_PER_TX ?? 64);
  let table:
    | Awaited<ReturnType<typeof connection.getAddressLookupTable>>["value"]
    | null = null;
  async function ensureLookupTable() {
    if (table) return table;
    const addresses = [
      ...chanAG.map((c) => c.key),
      gateway.balance,
      ...providers.map((p) => p.balance),
    ];
    const slot = await connection.getSlot("finalized");
    const [createIx, lut] = AddressLookupTableProgram.createLookupTable({
      authority: payer.publicKey,
      payer: payer.publicKey,
      recentSlot: slot,
    });
    await retry(
      () =>
        provider.sendAndConfirm(
          new anchor.web3.Transaction().add(createIx),
          []
        ),
      5,
      "lut create"
    );
    for (let i = 0; i < addresses.length; i += 25) {
      const ix = AddressLookupTableProgram.extendLookupTable({
        lookupTable: lut,
        authority: payer.publicKey,
        payer: payer.publicKey,
        addresses: addresses.slice(i, i + 25),
      });
      await retry(
        () =>
          provider.sendAndConfirm(new anchor.web3.Transaction().add(ix), []),
        5,
        "lut extend"
      );
    }
    await sleep(2000);
    table = (await connection.getAddressLookupTable(lut)).value!;
    console.log(
      `    lookup table ${lut.toBase58()} with ${
        table!.state.addresses.length
      } addresses`
    );
    return table!;
  }
  /** Split a batch into settle transactions of at most MAX_TX_ACCOUNTS unique accounts. */
  function settleChunks(b: { first: number; count: number }): number[][] {
    const fixed = 5; // payer, program, compute budget program, staging, clearing result
    const chunks: number[][] = [];
    let cur: number[] = [];
    let uniq = new Set<string>();
    for (let i = 0; i < b.count; i++) {
      const r = routeOf[b.first + i];
      const keys = [
        chanAG[r.agent].key,
        gateway.balance,
        providers[r.provider].balance,
      ].map((k) => k.toBase58());
      const next = new Set([...uniq, ...keys]);
      if (
        cur.length &&
        (next.size + fixed > MAX_TX_ACCOUNTS || cur.length >= SETTLE_PER_TX)
      ) {
        chunks.push(cur);
        cur = [];
        uniq = new Set();
      }
      keys.forEach((k) => uniq.add(k));
      cur.push(i);
    }
    if (cur.length) chunks.push(cur);
    return chunks;
  }
  async function settleBatch(b: { first: number; count: number }) {
    const t = await ensureLookupTable();
    for (const indices of settleChunks(b)) {
      const remaining = indices.flatMap((i) => {
        const r = routeOf[b.first + i];
        return [
          chanAG[r.agent].key,
          gateway.balance,
          providers[r.provider].balance,
        ].map((pubkey) => ({ pubkey, isWritable: true, isSigner: false }));
      });
      const ix = await program.methods
        .settleChannels(Buffer.from(indices))
        .accounts({ staging, clearingResult: clearingPda(programId, staging) })
        .remainingAccounts(remaining)
        .instruction();
      const { blockhash } = await connection.getLatestBlockhash("confirmed");
      const msg = new TransactionMessage({
        payerKey: payer.publicKey,
        recentBlockhash: blockhash,
        instructions: [
          ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
          ix,
        ],
      }).compileToV0Message([t!]);
      const vtx = new VersionedTransaction(msg);
      vtx.sign([payer]);
      const sig = await retry(
        () => connection.sendTransaction(vtx, { maxRetries: 3 }),
        3,
        "settle"
      );
      await connection.confirmTransaction(sig, "confirmed");
      const got = await connection.getTransaction(sig, {
        maxSupportedTransactionVersion: 0,
      });
      console.log(
        `    settled ${indices.length} routes in one tx: ${
          got?.meta?.computeUnitsConsumed
        } CU, ${
          got?.transaction.message.getAccountKeys({
            addressLookupTableAccounts: [t!],
          }).length
        } unique accounts`
      );
      stats.tx.settle++;
    }
  }

  it("5. settled every batch in v0 transactions through an address lookup table (interleaved above)", async () => {
    expect(stats.tx.settle).to.be.greaterThan(0);
  });

  it("6. asserts every balance and the solvency invariant, then reclaims staging rent", async () => {
    const expProvider = new Array(PROVIDERS).fill(0);
    let expFee = 0;
    for (const r of routeOf) {
      expProvider[r.provider] += r.providerAmount;
      expFee += r.fee;
    }
    for (let j = 0; j < PROVIDERS; j++) {
      const bal = await program.account.balance.fetch(providers[j].balance);
      expect(bal.available.toNumber(), `provider ${j}`).to.equal(
        expProvider[j]
      );
    }
    for (let i = 0; i < AGENTS; i++) {
      const c = await program.account.channel.fetch(chanAG[i].key);
      expect(c.settledCumulative.toNumber(), `agent ${i}`).to.equal(
        routeOf[i].target
      );
      expect(c.lockedBalance.toNumber()).to.equal(
        AGENT_LOCK - routeOf[i].target
      );
    }
    expect(
      (
        await program.account.balance.fetch(gateway.balance)
      ).available.toNumber()
    ).to.equal(expFee);
    const vaultAcc = await getAccount(
      connection,
      vault,
      "confirmed",
      TOKEN_PROGRAM_ID
    );
    const balances = await program.account.balance.all([
      { memcmp: { offset: 8 + 32, bytes: mint.toBase58() } },
    ]);
    const channels = await program.account.channel.all([
      { memcmp: { offset: 8 + 64, bytes: mint.toBase58() } },
    ]);
    const sumAvail = balances.reduce(
      (a, b) => a + BigInt(b.account.available.toString()),
      0n
    );
    const sumLocked = channels.reduce(
      (a, c) => a + BigInt(c.account.lockedBalance.toString()),
      0n
    );
    expect(vaultAcc.amount.toString()).to.equal(
      (sumAvail + sumLocked).toString()
    );
    console.log(
      `    providers paid ${
        expProvider.reduce((a, b) => a + b, 0) / ONE
      }, gateway fees ${expFee / ONE}, vault ${
        Number(vaultAcc.amount) / ONE
      } == available ${Number(sumAvail) / ONE} + locked ${
        Number(sumLocked) / ONE
      }`
    );

    // last computation's rent + the buffer's rent come back in one tx
    const closeIxs = lastComputation
      ? [
          await claimComputationRentIx(
            program,
            payer.publicKey,
            lastComputation
          ),
        ]
      : [];
    await program.methods
      .closeStaging()
      .accounts({
        relayer: payer.publicKey,
        staging,
        clearingResult: clearingPda(program.programId, staging),
      })
      .preInstructions(closeIxs)
      .signers([payer])
      .rpc({ commitment: "confirmed" });
    // Sweep the parties' unspent SOL back (their keypairs are throwaway); rent stays parked.
    const parties = [...agents, gateway, ...providers];
    let swept = 0;
    for (let i = 0; i < parties.length; i += 6) {
      const group = parties.slice(i, i + 6);
      const tx = new anchor.web3.Transaction();
      const signers: Keypair[] = [];
      for (const p of group) {
        const bal = await connection.getBalance(p.owner.publicKey);
        if (bal <= 10_000) continue;
        tx.add(
          SystemProgram.transfer({
            fromPubkey: p.owner.publicKey,
            toPubkey: payer.publicKey,
            lamports: bal,
          })
        );
        signers.push(p.owner);
        swept += bal;
      }
      if (signers.length)
        await retry(() => provider.sendAndConfirm(tx, signers), 5, "sweep");
    }
    console.log(
      `    swept ${(swept / 1e9).toFixed(
        4
      )} SOL of unspent party balances back to the wallet`
    );
    const solEnd = await connection.getBalance(payer.publicKey);
    const total = Object.values(stats.tx).reduce((a, b) => a + b, 0);
    console.log(`\n    ==== ${AGENTS} routed payments cleared ====`);
    console.log(
      `    tx: setup ${stats.tx.setup} | stage ${stats.tx.stage} | queue ${stats.tx.queue} | callback ${stats.tx.callback} | settle ${stats.tx.settle} | total ${total}`
    );
    console.log(
      `    clearing path only (stage+queue+callback+settle): ${
        stats.tx.stage + stats.tx.queue + stats.tx.callback + stats.tx.settle
      } tx for ${AGENTS} routes`
    );
    console.log(
      `    time: setup ${(stats.t.setup / 1000).toFixed(0)}s, clear+settle ${(
        stats.t.clear / 1000
      ).toFixed(0)}s, total ${((Date.now() - startedAt) / 1000).toFixed(0)}s`
    );
    console.log(
      `    SOL: ${((stats.solStart - solEnd) / 1e9).toFixed(
        4
      )} spent by the wallet (incl. rent parked in ${
        AGENTS + PROVIDERS + 1
      } participants/balances/channels)`
    );
  });
});
