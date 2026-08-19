/**
 * Step 9: end-to-end Arcium clearing on the localnet — stage, queue, MPC verify, callback,
 * settle — for both record kinds, including the failure modes settlement must tolerate.
 *
 * Runs under `arcium test` only (needs the 2-node ARX localnet). Circuits are uploaded on-chain
 * (fast on localnet: parallel chunks). ARX nodes refuse private-address URLs (SSRF guard), so a
 * local HTTP server cannot serve them; set RYVO_CIRCUIT_BASE_URL to a public URL to exercise the
 * off-chain path used on devnet.
 */
import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, createAssociatedTokenAccount, mintTo, getAccount } from "@solana/spl-token";
import { expect } from "chai";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import {
  CHAIN_ID,
  ensureConfig,
  expectReject,
  fund,
  localWallet,
  newMint,
  protocolAuthority,
  setupProvider,
  seeds,
} from "../tests/shared";
import {
  KIND_ROUTE,
  KIND_UNILATERAL,
  RouteCommitment,
  UnilateralCommitment,
  deriveArcisSigner,
  deriveMessageDomain,
  signCommitment,
} from "../tests/commitment-client";
import {
  Batch,
  N_ROUTE,
  RouteRecord,
  UnilateralRecord,
  awaitClearing,
  bitmapBits,
  buildRouteBatch,
  buildUnilateralBatch,
  clearingPda,
  closeStaging,
  ensureArciumSigner,
  ensureCompDef,
  openStaging,
  sealAndQueue,
  settle,
  stageBatch,
} from "./clearing-client";

const ONE = 1_000_000;

describe("ryvo_protocol / step 9: Arcium clearing", () => {
  const provider = setupProvider();
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;
  const authority = protocolAuthority();
  const relayer = localWallet(); // the local wallet plays relayer
  const configPda = seeds.config(program.programId);
  const domain = deriveMessageDomain(program.programId, CHAIN_ID);

  let mint: PublicKey;
  let tokenConfig: PublicKey;
  let vault: PublicKey;

  interface Party {
    owner: Keypair;
    participant: PublicKey;
    balance: PublicKey;
    seed: Uint8Array; // wallet seed -> Arcis signer
    signer: Buffer; // Arcis pubkey
  }
  interface Chan {
    key: PublicKey;
    id: bigint;
    payer: Party;
    payee: Party;
  }

  let agents: Party[] = [];
  let gateway: Party;
  let providers: Party[] = [];
  const chanAG: Chan[] = []; // agent i -> gateway
  const chanGP: Chan[] = []; // gateway -> provider j
  /** The relayer's one reusable staging buffer, opened in `before`, closed at the end. */
  let staging: PublicKey;
  let firstBatch = true;

  async function makeParty(deposit = 0): Promise<Party> {
    const owner = Keypair.generate();
    await fund(provider, owner.publicKey, 5);
    const participant = seeds.participant(program.programId, owner.publicKey);
    await program.methods
      .initializeParticipant()
      .accounts({ owner: owner.publicKey, participant, systemProgram: SystemProgram.programId })
      .signers([owner]).rpc();
    const balance = seeds.balance(program.programId, participant, mint);
    await program.methods
      .openBalance()
      .accounts({ payer: owner.publicKey, participant, mint, tokenConfig, balance, systemProgram: SystemProgram.programId })
      .signers([owner]).rpc();
    if (deposit > 0) {
      const ata = await createAssociatedTokenAccount(provider.connection, relayer, mint, owner.publicKey, { commitment: "confirmed" }, TOKEN_PROGRAM_ID);
      await mintTo(provider.connection, relayer, mint, ata, relayer, deposit, [], { commitment: "confirmed" }, TOKEN_PROGRAM_ID);
      await program.methods
        .deposit(new anchor.BN(deposit))
        .accounts({ funder: owner.publicKey, mint, tokenConfig, vault, funderTokenAccount: ata, participant, balance, tokenProgram: TOKEN_PROGRAM_ID })
        .signers([owner]).rpc();
    }
    const seed = owner.secretKey.slice(0, 32);
    const signer = deriveArcisSigner(seed).publicKey;
    return { owner, participant, balance, seed, signer };
  }

  async function openChannel(from: Party, to: Party): Promise<Chan> {
    const key = seeds.channel(program.programId, from.participant, to.participant, mint);
    await program.methods
      .createChannel(new PublicKey(from.signer))
      .accounts({
        payerOwner: from.owner.publicKey, config: configPda,
        payerParticipant: from.participant, payeeParticipant: to.participant,
        mint, tokenConfig, payerBalance: from.balance, payeeBalance: to.balance,
        channel: key, systemProgram: SystemProgram.programId,
      })
      .signers([from.owner]).rpc();
    const c = await program.account.channel.fetch(key);
    return { key, id: BigInt(c.channelId.toString()), payer: from, payee: to };
  }

  async function lock(ch: Chan, amount: number) {
    await program.methods
      .lockChannelFunds(new anchor.BN(amount))
      .accounts({ payerOwner: ch.payer.owner.publicKey, payerParticipant: ch.payer.participant, config: configPda, channel: ch.key, payerBalance: ch.payer.balance })
      .signers([ch.payer.owner]).rpc();
  }

  const uni = (ch: Chan, target: number): UnilateralCommitment => ({
    kind: KIND_UNILATERAL, messageDomain: domain, channelId: ch.id, targetCumulative: BigInt(target),
  });
  const route = (ag: Chan, gp: Chan, targetAg: number, targetGp: number): RouteCommitment => ({
    kind: KIND_ROUTE, messageDomain: domain,
    channelAgId: ag.id, channelGpId: gp.id, targetAg: BigInt(targetAg), targetGp: BigInt(targetGp),
  });
  const uniRecord = (ch: Chan, target: number, corrupt = false): UnilateralRecord => {
    const s = signCommitment(ch.payer.seed, uni(ch, target));
    const signature = Buffer.from(s.signature);
    if (corrupt) signature[3] ^= 0xff;
    return { commitment: uni(ch, target), channel: ch.key, signature };
  };
  const routeRecord = (ag: Chan, gp: Chan, targetAg: number, targetGp: number, corruptGateway = false): RouteRecord => {
    const c = route(ag, gp, targetAg, targetGp);
    const a = signCommitment(ag.payer.seed, c);
    const g = signCommitment(gp.payer.seed, c);
    const gatewaySignature = Buffer.from(g.signature);
    if (corruptGateway) gatewaySignature[10] ^= 0x01;
    return { commitment: c, channelAg: ag.key, channelGp: gp.key, agentSignature: a.signature, gatewaySignature };
  };

  async function chan(ch: Chan) {
    const c = await program.account.channel.fetch(ch.key);
    return { settled: c.settledCumulative.toNumber(), locked: c.lockedBalance.toNumber() };
  }
  async function avail(p: Party) {
    return (await program.account.balance.fetch(p.balance)).available.toNumber();
  }
  async function assertSolvent() {
    const vaultAcc = await getAccount(provider.connection, vault, "confirmed", TOKEN_PROGRAM_ID);
    const balances = await program.account.balance.all();
    const channels = await program.account.channel.all();
    const sumAvailable = balances.filter((b) => b.account.mint.equals(mint)).reduce((a, b) => a + BigInt(b.account.available.toString()), 0n);
    const sumLocked = channels.filter((c) => c.account.mint.equals(mint)).reduce((a, c) => a + BigInt(c.account.lockedBalance.toString()), 0n);
    expect(vaultAcc.amount.toString()).to.equal((sumAvailable + sumLocked).toString(), "solvency invariant violated");
  }

  /** Stage into the shared buffer (resetting it) + queue + wait; returns the bitmap. */
  async function clear(kind: number, batch: Batch, count: number) {
    const t0 = Date.now();
    const { tailIx, txCount } = await stageBatch(program, relayer, staging, kind, batch, { fresh: firstBatch });
    firstBatch = false;
    const { computationOffset, clearingResult } = await sealAndQueue(program, relayer, staging, kind, count, tailIx);
    await awaitClearing(provider, program, computationOffset);
    const r = await program.account.clearingResult.fetch(clearingResult);
    console.log(`      [clear] kind=${kind} count=${count} verified=${r.verified} bits=${JSON.stringify(bitmapBits(r.bitmap as number[], count))} staging tx=${txCount + 1}${tailIx ? " (tail merged into seal)" : ""} (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
    if (!r.verified) {
      throw new Error(r.failed
        ? "computation FAILED (BatchClearingFailed) — check artifacts/arx_node_logs (circuit fetch?)"
        : "callback did not land — check artifacts/arx_node_logs");
    }
    return { bits: bitmapBits(r.bitmap as number[], count) };
  }

  before(async () => {
    await ensureConfig(program, provider, authority);
    mint = await newMint(provider, 6);
    tokenConfig = seeds.tokenConfig(program.programId, mint);
    vault = seeds.vault(program.programId, mint);
    await program.methods
      .registerToken()
      .accounts({ authority: authority.publicKey, config: configPda, mint, tokenConfig, vault, tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId, rent: anchor.web3.SYSVAR_RENT_PUBKEY })
      .signers([authority]).rpc();

    await ensureArciumSigner(program, relayer);

    const baseUrl: string | undefined = process.env.RYVO_CIRCUIT_BASE_URL;
    const t0 = Date.now();
    await ensureCompDef(program, provider, relayer, "clear_unilateral", baseUrl && `${baseUrl}/clear_unilateral.arcis`);
    await ensureCompDef(program, provider, relayer, "clear_route", baseUrl && `${baseUrl}/clear_route.arcis`);
    console.log(`      comp defs ready in ${((Date.now() - t0) / 1000).toFixed(1)}s (${baseUrl ? "off-chain URL" : "on-chain upload"})`);

    agents = [await makeParty(100 * ONE), await makeParty(100 * ONE), await makeParty(100 * ONE)];
    gateway = await makeParty(0);
    providers = [await makeParty(0), await makeParty(0)];
    for (const a of agents) chanAG.push(await openChannel(a, gateway));
    for (const p of providers) chanGP.push(await openChannel(gateway, p));
    await lock(chanAG[0], 60 * ONE);
    await lock(chanAG[1], 30 * ONE);
    await lock(chanAG[2], 100 * ONE);
    await assertSolvent();
    staging = await openStaging(program, relayer, KIND_UNILATERAL);
  });

  it("clears a unilateral batch: valid, corrupt, partial and settles the valid ones", async () => {
    const records = [
      uniRecord(chanAG[0], 40 * ONE), // moves 40 of 60
      uniRecord(chanAG[1], 50 * ONE), // only 30 locked -> partial, stays live
      uniRecord(chanAG[2], 10 * ONE, true), // corrupt signature -> bit 0
      uniRecord(chanAG[2], 25 * ONE), // moves 25 of 100
    ];
    const { bits } = await clear(KIND_UNILATERAL, buildUnilateralBatch(records), records.length);
    expect(bits).to.deep.equal([true, true, false, true]);

    const chanOf = (i: number) =>
      records[i].commitment.channelId === chanAG[0].id ? chanAG[0].key
        : records[i].commitment.channelId === chanAG[1].id ? chanAG[1].key : chanAG[2].key;

    // Wrong channel account for a record's id, and a balance that is not the payee's, are both
    // refused before any state changes.
    await expectReject(settle(program, staging, [3], () => [chanAG[0].key, gateway.balance]), /SettlementChannelMismatch/);
    await expectReject(settle(program, staging, [3], () => [chanAG[2].key, agents[0].balance]), /SettlementBalanceMismatch/);

    const gBefore = await avail(gateway);
    await settle(program, staging, [0, 1, 3], (i) => [chanOf(i), gateway.balance]);

    expect(await chan(chanAG[0])).to.deep.equal({ settled: 40 * ONE, locked: 20 * ONE });
    expect(await chan(chanAG[1])).to.deep.equal({ settled: 30 * ONE, locked: 0 });
    expect(await chan(chanAG[2])).to.deep.equal({ settled: 25 * ONE, locked: 75 * ONE });
    expect(await avail(gateway)).to.equal(gBefore + 95 * ONE);
    await assertSolvent();

    // A record the circuit rejected cannot be settled; an applied one cannot be re-applied.
    await expectReject(settle(program, staging, [2], () => [chanAG[2].key, gateway.balance]), /RecordNotVerified/);
    await expectReject(settle(program, staging, [0], () => [chanAG[0].key, gateway.balance]), /RecordAlreadyApplied/);
  });

  it("collects the remainder of a partially settled commitment in a later batch, and skips a satisfied one", async () => {
    await lock(chanAG[1], 20 * ONE); // agent 2 tops up; the same 50 commitment is still live
    const records = [
      uniRecord(chanAG[1], 50 * ONE), // same commitment as before -> moves the remaining 20
      uniRecord(chanAG[0], 40 * ONE), // already fully settled -> moves 0, still "applied"
    ];
    const { bits } = await clear(KIND_UNILATERAL, buildUnilateralBatch(records), records.length);
    expect(bits).to.deep.equal([true, true]);
    // The buffer cannot be reset for a new batch while verified commitments are still unapplied.
    await expectReject(stageBatch(program, relayer, staging, KIND_UNILATERAL, buildUnilateralBatch(records)), /StagingBusy/);
    const gBefore = await avail(gateway);
    await settle(program, staging, [0, 1], (i) => [i === 0 ? chanAG[1].key : chanAG[0].key, gateway.balance]);
    expect(await chan(chanAG[1])).to.deep.equal({ settled: 50 * ONE, locked: 0 });
    expect(await chan(chanAG[0])).to.deep.equal({ settled: 40 * ONE, locked: 20 * ONE });
    expect(await avail(gateway)).to.equal(gBefore + 20 * ONE);
    // Re-submitting the satisfied commitment yet again is refused by monotonicity at settle time
    // only in the sense that it moves nothing; here the guard is per-batch `applied`.
    await expectReject(settle(program, staging, [1], () => [chanAG[0].key, gateway.balance]), /RecordAlreadyApplied/);
    await assertSolvent();
  });

  it("clears a route batch and settles agent -> gateway -> provider atomically, with no gateway prefunding", async () => {
    // agent 1: 20 locked, settled 40. Route to provider 1: agent authorises up to 55 (delta 15),
    // gateway forwards up to 12. Gateway keeps 3 as its implicit fee.
    // agent 3: 75 locked, settled 25. Route to provider 2 with a corrupt gateway signature -> bit 0.
    // agent 3 again, valid: up to 60 (delta 35), gateway forwards 35 -> provider 2 gets 35.
    const records = [
      routeRecord(chanAG[0], chanGP[0], 55 * ONE, 12 * ONE),
      routeRecord(chanAG[2], chanGP[1], 30 * ONE, 5 * ONE, true),
      routeRecord(chanAG[2], chanGP[1], 60 * ONE, 35 * ONE),
    ];
    expect(await chan(chanGP[0])).to.deep.equal({ settled: 0, locked: 0 });

    // Race setup for the last test: while agent 1 still has 20 locked, it requests to unlock
    // all 20. Settlement below will take 15 of it first — the payee wins the timelock race.
    await program.methods.requestUnlockChannelFunds(new anchor.BN(20 * ONE))
      .accounts({ payerOwner: agents[0].owner.publicKey, payerParticipant: agents[0].participant, config: configPda, channel: chanAG[0].key, payerBalance: agents[0].balance })
      .signers([agents[0].owner]).rpc();

    const { bits } = await clear(KIND_ROUTE, buildRouteBatch(records), records.length);
    expect(bits).to.deep.equal([true, false, true]);

    // Legs that do not chain (wrong provider balance for the gateway->provider channel) are refused.
    await expectReject(settle(program, staging, [0], () => [chanAG[0].key, chanGP[0].key, providers[1].balance]), /SettlementBalanceMismatch/);
    // And a gateway->provider channel that is not fed by this agent->gateway channel is refused.
    await expectReject(settle(program, staging, [0], () => [chanAG[0].key, chanAG[1].key, providers[0].balance]), /SettlementChannelMismatch/);

    const p1Before = await avail(providers[0]);
    const p2Before = await avail(providers[1]);
    const gBefore = await avail(gateway);
    await settle(program, staging, [0, 2], (i) => i === 0
      ? [chanAG[0].key, chanGP[0].key, providers[0].balance]
      : [chanAG[2].key, chanGP[1].key, providers[1].balance]);

    expect(await chan(chanAG[0])).to.deep.equal({ settled: 55 * ONE, locked: 5 * ONE });
    expect(await chan(chanGP[0])).to.deep.equal({ settled: 12 * ONE, locked: 3 * ONE }); // fee stays locked
    expect(await avail(providers[0])).to.equal(p1Before + 12 * ONE);
    expect(await chan(chanAG[2])).to.deep.equal({ settled: 60 * ONE, locked: 40 * ONE });
    expect(await chan(chanGP[1])).to.deep.equal({ settled: 35 * ONE, locked: 0 });
    expect(await avail(providers[1])).to.equal(p2Before + 35 * ONE);
    // The gateway's own free balance is untouched: routing never passes through it.
    expect(await avail(gateway)).to.equal(gBefore);
    await assertSolvent();

    await expectReject(settle(program, staging, [1], () => [chanAG[2].key, chanGP[1].key, providers[1].balance]), /RecordNotVerified/);
  });

  it("releases only what settlement left when the payer's unlock executes: the v1 clamp, end to end", async () => {
    // Agent 1 requested 20 before settlement; settlement took 15. `execute` releases
    // min(pending 20, locked 5) = 5 — the min(pending, locked) path that was unreachable in v1.
    const ch = chanAG[0];
    expect((await program.account.channel.fetch(ch.key)).pendingUnlockAmount.toNumber()).to.equal(20 * ONE);
    await new Promise((r) => setTimeout(r, 3000));
    const before = await avail(ch.payer);
    await program.methods.executeUnlockChannelFunds()
      .accounts({ payerOwner: ch.payer.owner.publicKey, payerParticipant: ch.payer.participant, config: configPda, channel: ch.key, payerBalance: ch.payer.balance })
      .signers([ch.payer.owner]).rpc();
    expect(await avail(ch.payer)).to.equal(before + 5 * ONE);
    expect(await chan(ch)).to.deep.equal({ settled: 55 * ONE, locked: 0 });
    await assertSolvent();
  });

  it("clears a full route batch of 32 distinct agents and settles all of them (many-channel case)", async () => {
    // Every batch index names its own agent channel: 32 + 2 distinct channels. Keys are copied
    // on-chain by stage_channels, so the computation still has three account arguments — the
    // Arcium program refuses a queue whose account arguments name more than ~14 distinct
    // accounts, which is what per-channel arguments ran into on devnet.
    const many: Chan[] = [];
    for (let i = 0; i < N_ROUTE; i++) {
      const a = await makeParty(10 * ONE);
      const ch = await openChannel(a, gateway);
      await lock(ch, 8 * ONE);
      many.push(ch);
    }
    const gpBefore = [await chan(chanGP[0]), await chan(chanGP[1])];
    // gateway targets are cumulative per gateway->provider channel: 1 unit fee per route
    const cum = [gpBefore[0].settled, gpBefore[1].settled];
    const records = many.map((ch, i) => {
      const gp = i % 2;
      cum[gp] += 2 * ONE;
      return routeRecord(ch, chanGP[gp], 3 * ONE, cum[gp]);
    });
    const { bits } = await clear(KIND_ROUTE, buildRouteBatch(records), records.length);
    expect(bits).to.deep.equal(new Array(N_ROUTE).fill(true));
    for (let i = 0; i < N_ROUTE; i += 8) {
      const idx = Array.from({ length: 8 }, (_, k) => i + k);
      await settle(program, staging, idx, (j) => [many[j].key, chanGP[j % 2].key, providers[j % 2].balance]);
    }
    for (const ch of many) expect(await chan(ch)).to.deep.equal({ settled: 3 * ONE, locked: 5 * ONE });
    expect((await program.account.clearingResult.fetch(clearingPda(program.programId, staging))).applied.slice(0, 4)).to.deep.equal([255, 255, 255, 255]);
    await assertSolvent();
  });

  it("reclaims the buffer's rent once its last batch is fully applied", async () => {
    // Every index of the last batch is applied.
    const before = await provider.connection.getBalance(relayer.publicKey);
    await closeStaging(program, relayer, staging);
    expect(await provider.connection.getBalance(relayer.publicKey)).to.be.greaterThan(before);
    expect(await provider.connection.getAccountInfo(staging)).to.be.null;
  });
});
