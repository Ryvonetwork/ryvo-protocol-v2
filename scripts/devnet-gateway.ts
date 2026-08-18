/**
 * Devnet gateway smoke: 100 agents pay 10 providers through one gateway, cleared by Arcium.
 *
 *   agent_i --(route commitment, co-signed by gateway)--> gateway --> provider_(i mod 10)
 *
 * What it does, in order (each step is idempotent where the protocol allows):
 *   1. bootstrap: initialize config, Arcium signer PDA, computation definitions (circuits by URL)
 *   2. test mint + vault; 100 agents / 1 gateway / 10 providers registered, funded, channels opened
 *   3. 100 route commitments signed by agent then gateway
 *   4. staged in 4 batches of 32, sealed + queued, callbacks awaited
 *   5. settled — one v0 transaction per batch through an address lookup table
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
import {
  KIND_ROUTE,
  RouteCommitment,
  deriveArcisSigner,
  deriveMessageDomain,
  signCommitment,
} from "../tests/commitment-client";
import {
  N,
  ROUTE_SLOTS,
  RouteRecord,
  awaitClearing,
  bitmapBits,
  buildRouteBatch,
  clearingPda,
  ensureArciumSigner,
  ensureCompDef,
  sealAndQueue,
  stageBatch,
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
  return Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8"))));
}
async function pmap<T, R>(xs: T[], f: (x: T, i: number) => Promise<R>, n = CONCURRENCY): Promise<R[]> {
  const out: R[] = new Array(xs.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(n, xs.length) }, async () => {
    while (next < xs.length) {
      const i = next++;
      out[i] = await f(xs[i], i);
    }
  }));
  return out;
}
async function retry<T>(f: () => Promise<T>, tries = 5, label = ""): Promise<T> {
  let last: any;
  for (let i = 0; i < tries; i++) {
    try { return await f(); } catch (e) { last = e; await sleep(500 * (i + 1) * (i + 1)); }
  }
  throw new Error(`${label} failed after ${tries} tries: ${last?.message ?? last}`);
}

describe("ryvo_protocol devnet gateway smoke", function () {
  this.timeout(3_600_000);

  const connection = new anchor.web3.Connection(RPC, "confirmed");
  const payer = wallet();
  const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(payer), { commitment: "confirmed", preflightCommitment: "confirmed" });
  anchor.setProvider(provider);
  const idl = JSON.parse(fs.readFileSync("target/idl/ryvo_protocol.json", "utf8"));
  const program = new Program<RyvoProtocol>(idl, provider);
  const programId = program.programId;
  const domain = deriveMessageDomain(programId, DEVNET_CHAIN_ID);

  const pda = {
    config: PublicKey.findProgramAddressSync([Buffer.from("config")], programId)[0],
    participant: (o: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from("participant"), o.toBuffer()], programId)[0],
    tokenConfig: (m: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from("token"), m.toBuffer()], programId)[0],
    vault: (m: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from("vault"), m.toBuffer()], programId)[0],
    balance: (p: PublicKey, m: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from("balance"), p.toBuffer(), m.toBuffer()], programId)[0],
    channel: (a: PublicKey, b: PublicKey, m: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from("channel"), a.toBuffer(), b.toBuffer(), m.toBuffer()], programId)[0],
    programData: PublicKey.findProgramAddressSync([programId.toBuffer()], new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111"))[0],
  };

  interface Party { owner: Keypair; participant: PublicKey; balance: PublicKey; seed: Uint8Array; signer: Buffer }
  interface Chan { key: PublicKey; id: bigint; payer: Party; payee: Party }

  let mint: PublicKey;
  let tokenConfig: PublicKey;
  let vault: PublicKey;
  let agents: Party[] = [];
  let gateway: Party;
  let providers: Party[] = [];
  const chanAG: Chan[] = [];
  const chanGP: Chan[] = [];
  const records: RouteRecord[] = [];
  const routeOf: { ag: number; gp: number; targetAg: number; targetGp: number }[] = [];
  const stagings: { staging: PublicKey; count: number; bits: boolean[] }[] = [];
  const stats = { tx: { setup: 0, stage: 0, queue: 0, callback: 0, settle: 0 }, solStart: 0, t: {} as Record<string, number> };
  const startedAt = Date.now();

  const mkParty = (owner: Keypair): Party => {
    const participant = pda.participant(owner.publicKey);
    const seed = owner.secretKey.slice(0, 32);
    return { owner, participant, balance: pda.balance(participant, mint), seed, signer: deriveArcisSigner(seed).publicKey };
  };

  before(async () => {
    stats.solStart = await connection.getBalance(payer.publicKey);
    console.log(`    program ${programId.toBase58()} | rpc ${RPC} | cluster ${CLUSTER_OFFSET} | wallet ${payer.publicKey.toBase58()} (${(stats.solStart / 1e9).toFixed(3)} SOL)`);
  });

  it("1. bootstraps config, Arcium signer and computation definitions", async () => {
    if (!(await connection.getAccountInfo(pda.config))) {
      await program.methods.initialize(DEVNET_CHAIN_ID, new anchor.BN(CHANNEL_TIMELOCK), payer.publicKey)
        .accounts({ payer: payer.publicKey, config: pda.config, programData: pda.programData, systemProgram: SystemProgram.programId })
        .rpc();
      console.log("    initialized config");
    }
    const cfg = await program.account.config.fetch(pda.config);
    expect(Buffer.from(cfg.messageDomain).toString("hex")).to.equal(domain.toString("hex"));
    console.log(`    message_domain ${domain.toString("hex")} next_channel_id ${cfg.nextChannelId.toString()}`);
    await ensureArciumSigner(program, payer);
    const t0 = Date.now();
    await ensureCompDef(program, provider, payer, "clear_unilateral", `${CIRCUIT_BASE_URL}/clear_unilateral.arcis`);
    await ensureCompDef(program, provider, payer, "clear_route", `${CIRCUIT_BASE_URL}/clear_route.arcis`);
    console.log(`    comp defs ready (${((Date.now() - t0) / 1000).toFixed(1)}s) — circuits at ${CIRCUIT_BASE_URL}`);
  });

  it("2. creates a test mint, registers it, and sets up 100 agents, 1 gateway, 10 providers", async () => {
    const t0 = Date.now();
    mint = await createMint(connection, payer, payer.publicKey, null, 6, undefined, { commitment: "confirmed" }, TOKEN_PROGRAM_ID);
    tokenConfig = pda.tokenConfig(mint);
    vault = pda.vault(mint);
    await program.methods.registerToken()
      .accounts({ authority: payer.publicKey, config: pda.config, mint, tokenConfig, vault, tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId, rent: anchor.web3.SYSVAR_RENT_PUBKEY })
      .rpc();
    console.log(`    mint ${mint.toBase58()}`);

    agents = Array.from({ length: AGENTS }, () => mkParty(Keypair.generate()));
    gateway = mkParty(Keypair.generate());
    providers = Array.from({ length: PROVIDERS }, () => mkParty(Keypair.generate()));
    const all = [...agents, gateway, ...providers];

    // Fund SOL from the wallet (the faucet is rate limited): 8 transfers per tx.
    const lamports = (p: Party) => (p === gateway ? 0.12 : 0.03) * 1e9;
    for (let i = 0; i < all.length; i += 8) {
      const tx = new anchor.web3.Transaction();
      for (const p of all.slice(i, i + 8)) tx.add(SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: p.owner.publicKey, lamports: lamports(p) }));
      await retry(() => provider.sendAndConfirm(tx, []), 5, "fund");
      stats.tx.setup++;
    }

    // Registration: participant + balance (+ channel for agents) in one tx per party.
    const register = async (p: Party, channelTo?: Party) => {
      const ixs: TransactionInstruction[] = [
        await program.methods.initializeParticipant().accounts({ owner: p.owner.publicKey, participant: p.participant, systemProgram: SystemProgram.programId }).instruction(),
        await program.methods.openBalance().accounts({ payer: p.owner.publicKey, participant: p.participant, mint, tokenConfig, balance: p.balance, systemProgram: SystemProgram.programId }).instruction(),
      ];
      const tx = new anchor.web3.Transaction().add(...ixs);
      tx.feePayer = p.owner.publicKey;
      await retry(() => provider.sendAndConfirm(tx, [p.owner]), 5, "register");
      stats.tx.setup++;
    };
    await register(gateway);
    await pmap(providers, (p) => register(p));
    await pmap(agents, (a) => register(a));

    // Channels: agent -> gateway (100), gateway -> provider (10). Payee balances must exist first.
    const openChannel = async (from: Party, to: Party): Promise<Chan> => {
      const key = pda.channel(from.participant, to.participant, mint);
      const tx = new anchor.web3.Transaction().add(
        await program.methods.createChannel(new PublicKey(from.signer)).accounts({
          payerOwner: from.owner.publicKey, config: pda.config, payerParticipant: from.participant, payeeParticipant: to.participant,
          mint, tokenConfig, payerBalance: from.balance, payeeBalance: to.balance, channel: key, systemProgram: SystemProgram.programId,
        }).instruction(),
      );
      tx.feePayer = from.owner.publicKey;
      await retry(() => provider.sendAndConfirm(tx, [from.owner]), 5, "channel");
      stats.tx.setup++;
      const c = await program.account.channel.fetch(key);
      return { key, id: BigInt(c.channelId.toString()), payer: from, payee: to };
    };
    // Config is write-locked by create_channel, so these serialize on-chain anyway; keep
    // concurrency modest to avoid preflight races on the id counter.
    for (const p of providers) chanGP.push(await openChannel(gateway, p));
    const ag = await pmap(agents, (a) => openChannel(a, gateway), 3);
    chanAG.push(...ag);

    // Fund + deposit + lock per agent: ATA, mintTo (wallet is mint authority), deposit, lock.
    await pmap(agents, async (a, i) => {
      const ata = getAssociatedTokenAddressSync(mint, a.owner.publicKey, false, TOKEN_PROGRAM_ID);
      const tx = new anchor.web3.Transaction().add(
        createAssociatedTokenAccountIdempotentInstruction(payer.publicKey, ata, a.owner.publicKey, mint, TOKEN_PROGRAM_ID),
        createMintToInstruction(mint, ata, payer.publicKey, AGENT_DEPOSIT, [], TOKEN_PROGRAM_ID),
        await program.methods.deposit(new anchor.BN(AGENT_DEPOSIT)).accounts({ funder: a.owner.publicKey, mint, tokenConfig, vault, funderTokenAccount: ata, participant: a.participant, balance: a.balance, tokenProgram: TOKEN_PROGRAM_ID }).instruction(),
        await program.methods.lockChannelFunds(new anchor.BN(AGENT_LOCK)).accounts({ payerOwner: a.owner.publicKey, payerParticipant: a.participant, config: pda.config, channel: chanAG[i].key, payerBalance: a.balance }).instruction(),
      );
      tx.feePayer = payer.publicKey;
      await retry(() => provider.sendAndConfirm(tx, [a.owner]), 5, "deposit+lock");
      stats.tx.setup++;
    });
    stats.t.setup = Date.now() - t0;
    console.log(`    ${AGENTS} agents funded, deposited ${AGENT_DEPOSIT / ONE} and locked ${AGENT_LOCK / ONE} each; ${chanAG.length + chanGP.length} channels (${(stats.t.setup / 1000).toFixed(0)}s, ${stats.tx.setup} tx)`);
  });

  it("3. signs 100 route commitments: agent, then gateway countersigns", async () => {
    for (let i = 0; i < AGENTS; i++) {
      const gp = i % PROVIDERS;
      const targetAg = (10 + (i % 25)) * ONE; // 10..34 of the 40 locked
      const targetGp = targetAg - ONE; // gateway keeps 1 as its fee
      const c: RouteCommitment = { kind: KIND_ROUTE, messageDomain: domain, channelAgId: chanAG[i].id, channelGpId: chanGP[gp].id, targetAg: BigInt(targetAg), targetGp: BigInt(targetGp) };
      const a = signCommitment(agents[i].seed, c);
      const g = signCommitment(gateway.seed, c);
      records.push({ commitment: c, agentSigner: a.publicKey, agentSignature: a.signature, gatewaySigner: g.publicKey, gatewaySignature: g.signature });
      routeOf.push({ ag: i, gp, targetAg, targetGp });
    }
    console.log(`    ${records.length} route commitments, ${records.length * 2} signatures`);
  });

  it("4. stages, seals and queues the batches; Arcium clears them", async () => {
    const t0 = Date.now();
    const batches: RouteRecord[][] = [];
    for (let i = 0; i < records.length; i += N) batches.push(records.slice(i, i + N));
    // Stage all, then queue all, then wait for all — the MPC runs the batches back to back.
    const staged = await pmap(batches, async (b, k) => {
      const staging = await stageBatch(program, payer, BigInt(Date.now()) * 100n + BigInt(k), KIND_ROUTE, buildRouteBatch(b));
      stats.tx.stage += 1 + Math.ceil(ROUTE_SLOTS / 30); // open+create, then slot chunks
      return { staging, count: b.length };
    }, 2);
    console.log(`    staged ${batches.length} batches (${((Date.now() - t0) / 1000).toFixed(0)}s)`);
    const queued = [];
    for (const s of staged) {
      queued.push({ ...s, ...(await sealAndQueue(program, payer, s.staging, KIND_ROUTE, s.count)) });
      stats.tx.queue++;
    }
    console.log(`    queued ${queued.length} computations`);
    for (const q of queued) {
      const t1 = Date.now();
      await awaitClearing(provider, program, q.computationOffset);
      const r = await program.account.clearingResult.fetch(q.clearingResult);
      const bits = bitmapBits(r.bitmap as number[], q.count);
      console.log(`    batch ${q.staging.toBase58().slice(0, 8)}… verified=${r.verified} ${bits.filter(Boolean).length}/${q.count} valid (${((Date.now() - t1) / 1000).toFixed(0)}s)`);
      expect(r.verified).to.be.true;
      expect(bits.every(Boolean)).to.be.true;
      stats.tx.callback++;
      stagings.push({ staging: q.staging, count: q.count, bits });
    }
    stats.t.clear = Date.now() - t0;
  });

  it("5. settles every batch in one v0 transaction through an address lookup table", async () => {
    const t0 = Date.now();
    // Every account settlement touches: 100 agent channels + 10 gateway channels + 10 provider balances.
    const addresses = [...chanAG.map((c) => c.key), ...chanGP.map((c) => c.key), ...providers.map((p) => p.balance)];
    const slot = await connection.getSlot("finalized");
    const [createIx, lut] = AddressLookupTableProgram.createLookupTable({ authority: payer.publicKey, payer: payer.publicKey, recentSlot: slot });
    await retry(() => provider.sendAndConfirm(new anchor.web3.Transaction().add(createIx), []), 5, "lut create");
    for (let i = 0; i < addresses.length; i += 25) {
      const ix = AddressLookupTableProgram.extendLookupTable({ lookupTable: lut, authority: payer.publicKey, payer: payer.publicKey, addresses: addresses.slice(i, i + 25) });
      await retry(() => provider.sendAndConfirm(new anchor.web3.Transaction().add(ix), []), 5, "lut extend");
    }
    // A table becomes usable one slot after its last extension.
    await sleep(2000);
    const table = (await connection.getAddressLookupTable(lut)).value!;
    console.log(`    lookup table ${lut.toBase58()} with ${table.state.addresses.length} addresses`);

    let recordIndex = 0;
    for (const s of stagings) {
      const indices = Array.from({ length: s.count }, (_, i) => i);
      const remaining = indices.flatMap((i) => {
        const r = routeOf[recordIndex + i];
        return [chanAG[r.ag].key, chanGP[r.gp].key, providers[r.gp].balance].map((pubkey) => ({ pubkey, isWritable: true, isSigner: false }));
      });
      const ix = await program.methods.settleChannels(Buffer.from(indices))
        .accounts({ staging: s.staging, clearingResult: clearingPda(programId, s.staging) })
        .remainingAccounts(remaining)
        .instruction();
      const { blockhash } = await connection.getLatestBlockhash("confirmed");
      const msg = new TransactionMessage({
        payerKey: payer.publicKey,
        recentBlockhash: blockhash,
        instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }), ix],
      }).compileToV0Message([table]);
      const vtx = new VersionedTransaction(msg);
      vtx.sign([payer]);
      const sig = await retry(() => connection.sendTransaction(vtx, { maxRetries: 3 }), 3, "settle");
      await connection.confirmTransaction(sig, "confirmed");
      const got = await connection.getTransaction(sig, { maxSupportedTransactionVersion: 0 });
      console.log(`    settled ${s.count} routes in one tx: ${got?.meta?.computeUnitsConsumed} CU, ${remaining.length + 2} accounts`);
      stats.tx.settle++;
      recordIndex += s.count;
    }
    stats.t.settle = Date.now() - t0;
  });

  it("6. asserts every balance and the solvency invariant, then reclaims staging rent", async () => {
    const expProvider = new Array(PROVIDERS).fill(0);
    const expFee = new Array(PROVIDERS).fill(0);
    for (const r of routeOf) { expProvider[r.gp] += r.targetGp; expFee[r.gp] += r.targetAg - r.targetGp; }
    for (let j = 0; j < PROVIDERS; j++) {
      const bal = await program.account.balance.fetch(providers[j].balance);
      expect(bal.available.toNumber(), `provider ${j}`).to.equal(expProvider[j]);
      const gp = await program.account.channel.fetch(chanGP[j].key);
      expect(gp.lockedBalance.toNumber(), `gateway fee ${j}`).to.equal(expFee[j]);
      expect(gp.settledCumulative.toNumber()).to.equal(expProvider[j]);
    }
    for (let i = 0; i < AGENTS; i++) {
      const c = await program.account.channel.fetch(chanAG[i].key);
      expect(c.settledCumulative.toNumber(), `agent ${i}`).to.equal(routeOf[i].targetAg);
      expect(c.lockedBalance.toNumber()).to.equal(AGENT_LOCK - routeOf[i].targetAg);
    }
    const vaultAcc = await getAccount(connection, vault, "confirmed", TOKEN_PROGRAM_ID);
    const balances = await program.account.balance.all([{ memcmp: { offset: 8 + 32, bytes: mint.toBase58() } }]);
    const channels = await program.account.channel.all([{ memcmp: { offset: 8 + 64, bytes: mint.toBase58() } }]);
    const sumAvail = balances.reduce((a, b) => a + BigInt(b.account.available.toString()), 0n);
    const sumLocked = channels.reduce((a, c) => a + BigInt(c.account.lockedBalance.toString()), 0n);
    expect(vaultAcc.amount.toString()).to.equal((sumAvail + sumLocked).toString());
    console.log(`    providers paid ${expProvider.reduce((a, b) => a + b, 0) / ONE}, gateway fees ${expFee.reduce((a, b) => a + b, 0) / ONE}, vault ${Number(vaultAcc.amount) / ONE} == available ${Number(sumAvail) / ONE} + locked ${Number(sumLocked) / ONE}`);

    for (const s of stagings) {
      await program.methods.closeStaging().accounts({ relayer: payer.publicKey, staging: s.staging, clearingResult: clearingPda(programId, s.staging) }).rpc();
    }
    const solEnd = await connection.getBalance(payer.publicKey);
    const total = Object.values(stats.tx).reduce((a, b) => a + b, 0);
    console.log(`\n    ==== ${AGENTS} routed payments cleared ====`);
    console.log(`    tx: setup ${stats.tx.setup} | stage ${stats.tx.stage} | queue ${stats.tx.queue} | callback ${stats.tx.callback} | settle ${stats.tx.settle} | total ${total}`);
    console.log(`    clearing path only (stage+queue+callback+settle): ${stats.tx.stage + stats.tx.queue + stats.tx.callback + stats.tx.settle} tx for ${AGENTS} routes`);
    console.log(`    time: setup ${(stats.t.setup / 1000).toFixed(0)}s, clear ${(stats.t.clear / 1000).toFixed(0)}s, settle ${(stats.t.settle / 1000).toFixed(0)}s, total ${((Date.now() - startedAt) / 1000).toFixed(0)}s`);
    console.log(`    SOL: ${((stats.solStart - solEnd) / 1e9).toFixed(4)} spent by the wallet (incl. rent parked in ${AGENTS + PROVIDERS + 1} participants/balances/channels)`);
  });
});
