/** End-to-end Arcium clearing on localnet. */
import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createAssociatedTokenAccount,
  getAccount,
  mintTo,
} from "@solana/spl-token";
import { expect } from "chai";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import {
  CHAIN_ID,
  CHANNEL_KIND_DIRECT,
  CHANNEL_KIND_ROUTED,
  ensureConfig,
  expectReject,
  fund,
  localWallet,
  newMint,
  protocolAuthority,
  seeds,
  setupProvider,
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
const ROUTED_BUCKET_SPACE = 32_944;

describe("ryvo_protocol / step 9: Arcium clearing", () => {
  const provider = setupProvider();
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;
  const authority = protocolAuthority();
  const relayer = localWallet();
  const configPda = seeds.config(program.programId);
  const domain = deriveMessageDomain(program.programId, CHAIN_ID);

  let mint: PublicKey;
  let tokenConfig: PublicKey;
  let vault: PublicKey;

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
    slot?: number;
    id: bigint;
    payer: Party;
    payee: Party;
  }

  let directAgents: Party[] = [];
  let gateway: Party;
  let providers: Party[] = [];
  const directAG: Chan[] = [];
  let routedAgent: Party;
  let routedAG: Chan;
  let staging: PublicKey;
  let firstBatch = true;
  let lastComputation: anchor.BN | undefined;
  const routedBuckets = new Map<
    string,
    { key: PublicKey; nextSlot: number; baseId: bigint }
  >();

  async function makeParty(
    deposit = 0,
    signerOverride?: PublicKey
  ): Promise<Party> {
    const owner = Keypair.generate();
    await fund(provider, owner.publicKey, 5);
    const participant = seeds.participant(program.programId, owner.publicKey);
    const seed = owner.secretKey.slice(0, 32);
    const signer = deriveArcisSigner(seed).publicKey;
    await program.methods
      .initializeParticipant(signerOverride ?? new PublicKey(signer))
      .accounts({
        owner: owner.publicKey,
        config: configPda,
        participant,
        systemProgram: SystemProgram.programId,
      })
      .signers([owner])
      .rpc();
    const participantAccount = await program.account.participant.fetch(
      participant
    );
    const balance = seeds.balance(program.programId, participant, mint);
    await program.methods
      .openBalance()
      .accounts({
        payer: owner.publicKey,
        participant,
        mint,
        tokenConfig,
        balance,
        systemProgram: SystemProgram.programId,
      })
      .signers([owner])
      .rpc();
    if (deposit > 0) {
      const ata = await createAssociatedTokenAccount(
        provider.connection,
        relayer,
        mint,
        owner.publicKey,
        { commitment: "confirmed" },
        TOKEN_PROGRAM_ID
      );
      await mintTo(
        provider.connection,
        relayer,
        mint,
        ata,
        relayer,
        deposit,
        [],
        { commitment: "confirmed" },
        TOKEN_PROGRAM_ID
      );
      await program.methods
        .deposit(new anchor.BN(deposit))
        .accounts({
          funder: owner.publicKey,
          mint,
          tokenConfig,
          vault,
          funderTokenAccount: ata,
          participant,
          balance,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([owner])
        .rpc();
    }
    return {
      owner,
      participant,
      participantId: BigInt(participantAccount.participantId.toString()),
      balance,
      seed,
      signer,
    };
  }

  async function openChannel(
    from: Party,
    to: Party,
    kind: number
  ): Promise<Chan> {
    if (kind === CHANNEL_KIND_ROUTED) {
      const bucketKey = to.participant.toBase58();
      let routedBucket = routedBuckets.get(bucketKey);
      if (!routedBucket) {
        const bucket = Keypair.generate();
        const rent =
          await provider.connection.getMinimumBalanceForRentExemption(
            ROUTED_BUCKET_SPACE
          );
        await program.methods
          .initializeRoutedBucket()
          .accounts({
            gatewayOwner: to.owner.publicKey,
            config: configPda,
            gatewayParticipant: to.participant,
            mint,
            tokenConfig,
            gatewayBalance: to.balance,
            bucket: bucket.publicKey,
          })
          .preInstructions([
            SystemProgram.createAccount({
              fromPubkey: to.owner.publicKey,
              newAccountPubkey: bucket.publicKey,
              lamports: rent,
              space: ROUTED_BUCKET_SPACE,
              programId: program.programId,
            }),
          ])
          .signers([to.owner, bucket])
          .rpc();
        const state = await program.account.routedChannelBucket.fetch(
          bucket.publicKey
        );
        routedBucket = {
          key: bucket.publicKey,
          nextSlot: 0,
          baseId: BigInt(state.baseChannelId.toString()),
        };
        routedBuckets.set(bucketKey, routedBucket);
      }
      if (routedBucket.nextSlot >= 256)
        throw new Error("routed bucket is full");
      const slot = routedBucket.nextSlot++;
      await program.methods
        .createRoutedChannel(slot)
        .accounts({
          payerOwner: from.owner.publicKey,
          gatewayOwner: to.owner.publicKey,
          payerParticipant: from.participant,
          gatewayParticipant: to.participant,
          bucket: routedBucket.key,
          payerBalance: from.balance,
          gatewayBalance: to.balance,
        })
        .signers([from.owner, to.owner])
        .rpc();
      return {
        key: routedBucket.key,
        slot,
        id: routedBucket.baseId + BigInt(slot),
        payer: from,
        payee: to,
      };
    }

    const key = seeds.channel(
      program.programId,
      from.participant,
      to.participant,
      mint
    );
    await program.methods
      .createChannel(kind)
      .accounts({
        payerOwner: from.owner.publicKey,
        config: configPda,
        payerParticipant: from.participant,
        payeeParticipant: to.participant,
        mint,
        tokenConfig,
        payerBalance: from.balance,
        payeeBalance: to.balance,
        channel: key,
        systemProgram: SystemProgram.programId,
      })
      .signers([from.owner])
      .rpc();
    const channel = await program.account.channel.fetch(key);
    expect(channel.kind).to.equal(kind);
    return {
      key,
      id: BigInt(channel.channelId.toString()),
      payer: from,
      payee: to,
    };
  }

  async function lock(channel: Chan, amount: number) {
    if (channel.slot !== undefined) {
      await program.methods
        .lockRoutedChannelFunds(channel.slot, new anchor.BN(amount))
        .accounts({
          payerOwner: channel.payer.owner.publicKey,
          payerParticipant: channel.payer.participant,
          config: configPda,
          bucket: channel.key,
          payerBalance: channel.payer.balance,
        })
        .signers([channel.payer.owner])
        .rpc();
      return;
    }
    await program.methods
      .lockChannelFunds(new anchor.BN(amount))
      .accounts({
        payerOwner: channel.payer.owner.publicKey,
        payerParticipant: channel.payer.participant,
        config: configPda,
        channel: channel.key,
        payerBalance: channel.payer.balance,
      })
      .signers([channel.payer.owner])
      .rpc();
  }

  const uni = (channel: Chan, target: number): UnilateralCommitment => ({
    kind: KIND_UNILATERAL,
    messageDomain: domain,
    channelId: channel.id,
    targetCumulative: BigInt(target),
  });

  const route = (
    source: Chan,
    base: number,
    target: number,
    allocations: { provider: Party; amount: number }[]
  ): RouteCommitment => ({
    kind: KIND_ROUTE,
    messageDomain: domain,
    sourceChannelId: source.id,
    baseCumulative: BigInt(base),
    targetCumulative: BigInt(target),
    allocations: allocations.map(({ provider, amount }) => ({
      participantId: provider.participantId,
      amount: BigInt(amount),
    })),
  });

  const uniRecord = (
    channel: Chan,
    target: number,
    corrupt = false
  ): UnilateralRecord => {
    const commitment = uni(channel, target);
    const signed = signCommitment(channel.payer.seed, commitment);
    const signature = Buffer.from(signed.signature);
    if (corrupt) signature[3] ^= 0xff;
    return { commitment, channel: channel.key, signature };
  };

  const routeRecord = (
    source: Chan,
    base: number,
    target: number,
    allocations: { provider: Party; amount: number }[],
    corruptGateway = false,
    signingGateway = gateway
  ): RouteRecord => {
    const commitment = route(source, base, target, allocations);
    const agent = signCommitment(source.payer.seed, commitment);
    const gatewaySigned = signCommitment(signingGateway.seed, commitment);
    const gatewaySignature = Buffer.from(gatewaySigned.signature);
    if (corruptGateway) gatewaySignature[10] ^= 1;
    return {
      commitment,
      sourceBucket: source.key,
      agentSignature: agent.signature,
      gatewaySignature,
    };
  };

  async function channelState(channel: Chan) {
    if (channel.slot !== undefined) {
      const state = await program.account.routedChannelBucket.fetch(
        channel.key
      );
      return {
        settled: state.settledCumulative[channel.slot].toNumber(),
        locked: state.lockedBalance[channel.slot].toNumber(),
      };
    }
    const state = await program.account.channel.fetch(channel.key);
    return {
      settled: state.settledCumulative.toNumber(),
      locked: state.lockedBalance.toNumber(),
    };
  }

  async function available(party: Party) {
    return (
      await program.account.balance.fetch(party.balance)
    ).available.toNumber();
  }

  async function assertSolvent() {
    const vaultAccount = await getAccount(
      provider.connection,
      vault,
      "confirmed",
      TOKEN_PROGRAM_ID
    );
    const balances = await program.account.balance.all();
    const channels = await program.account.channel.all();
    const buckets = await program.account.routedChannelBucket.all();
    const sumAvailable = balances
      .filter((b) => b.account.mint.equals(mint))
      .reduce((sum, b) => sum + BigInt(b.account.available.toString()), 0n);
    const sumLocked = channels
      .filter((c) => c.account.mint.equals(mint))
      .reduce((sum, c) => sum + BigInt(c.account.lockedBalance.toString()), 0n);
    const sumBucketLocked = buckets
      .filter((b) => b.account.mint.equals(mint))
      .reduce(
        (sum, b) =>
          sum +
          b.account.lockedBalance.reduce(
            (bucketSum, amount) => bucketSum + BigInt(amount.toString()),
            0n
          ),
        0n
      );
    expect(vaultAccount.amount.toString()).to.equal(
      (sumAvailable + sumLocked + sumBucketLocked).toString(),
      "solvency invariant violated"
    );
  }

  async function clear(kind: number, batch: Batch, count: number) {
    const { sealPre } = await stageBatch(program, relayer, staging, batch, {
      fresh: firstBatch,
      reclaim: lastComputation,
    });
    firstBatch = false;
    const { computationOffset, clearingResult } = await sealAndQueue(
      program,
      relayer,
      staging,
      kind,
      count,
      sealPre
    );
    lastComputation = computationOffset;
    await awaitClearing(provider, program, computationOffset);
    const result = await program.account.clearingResult.fetch(clearingResult);
    if (!result.verified)
      throw new Error(
        result.failed ? "computation failed" : "callback missing"
      );
    return bitmapBits(result.bitmap as number[], count);
  }

  before(async () => {
    await ensureConfig(program, provider, authority);
    mint = await newMint(provider, 6);
    tokenConfig = seeds.tokenConfig(program.programId, mint);
    vault = seeds.vault(program.programId, mint);
    await program.methods
      .registerToken()
      .accounts({
        authority: authority.publicKey,
        config: configPda,
        mint,
        tokenConfig,
        vault,
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .signers([authority])
      .rpc();

    await ensureArciumSigner(program, relayer);
    const baseUrl = process.env.RYVO_CIRCUIT_BASE_URL;
    await ensureCompDef(
      program,
      provider,
      relayer,
      "clear_unilateral64",
      baseUrl && `${baseUrl}/clear_unilateral64.arcis`
    );
    await ensureCompDef(
      program,
      provider,
      relayer,
      "clear_route32",
      baseUrl && `${baseUrl}/clear_route32.arcis`
    );

    directAgents = [
      await makeParty(100 * ONE),
      await makeParty(100 * ONE),
      await makeParty(100 * ONE),
    ];
    gateway = await makeParty();
    providers = [await makeParty(), await makeParty()];
    for (const agent of directAgents)
      directAG.push(await openChannel(agent, gateway, CHANNEL_KIND_DIRECT));
    await lock(directAG[0], 60 * ONE);
    await lock(directAG[1], 30 * ONE);
    await lock(directAG[2], 100 * ONE);
    routedAgent = await makeParty(100 * ONE);
    routedAG = await openChannel(routedAgent, gateway, CHANNEL_KIND_ROUTED);
    await lock(routedAG, 60 * ONE);
    staging = await openStaging(program, relayer, KIND_UNILATERAL);
    await assertSolvent();
  });

  it("stores routed channels in permanent bucket slots", async () => {
    const state = await program.account.routedChannelBucket.fetch(routedAG.key);
    expect(routedAG.id).to.equal(
      BigInt(state.baseChannelId.toString()) + BigInt(routedAG.slot!)
    );
    expect(state.payers[routedAG.slot!].toBase58()).to.equal(
      routedAgent.participant.toBase58()
    );
    expect(
      state.occupied[Math.floor(routedAG.slot! / 8)] & (1 << routedAG.slot! % 8)
    ).to.not.equal(0);
    const config = await program.account.config.fetch(configPda);
    expect(config.nextChannelId.toString()).to.equal(
      (BigInt(state.baseChannelId.toString()) + 256n).toString()
    );

    await expectReject(
      program.methods
        .createRoutedChannel(routedAG.slot!)
        .accounts({
          payerOwner: routedAgent.owner.publicKey,
          gatewayOwner: gateway.owner.publicKey,
          payerParticipant: routedAgent.participant,
          gatewayParticipant: gateway.participant,
          bucket: routedAG.key,
          payerBalance: routedAgent.balance,
          gatewayBalance: gateway.balance,
        })
        .signers([routedAgent.owner, gateway.owner])
        .rpc(),
      /RoutedSlotOccupied/
    );
    await expectReject(
      program.methods
        .lockRoutedChannelFunds(routedAG.slot!, new anchor.BN(ONE))
        .accounts({
          payerOwner: directAgents[0].owner.publicKey,
          payerParticipant: directAgents[0].participant,
          config: configPda,
          bucket: routedAG.key,
          payerBalance: directAgents[0].balance,
        })
        .signers([directAgents[0].owner])
        .rpc(),
      /InvalidRoutedSlot/
    );
  });

  it("returns false for a malformed key or signature without failing the batch", async () => {
    const weird = await makeParty(
      10 * ONE,
      new PublicKey(Buffer.alloc(32, 0xff))
    );
    const weirdChannel = await openChannel(weird, gateway, CHANNEL_KIND_DIRECT);
    await lock(weirdChannel, 5 * ONE);
    const records: UnilateralRecord[] = [
      {
        commitment: uni(weirdChannel, ONE),
        channel: weirdChannel.key,
        signature: Buffer.alloc(64, 0xff),
      },
      { ...uniRecord(directAG[2], ONE), signature: Buffer.alloc(64, 1) },
      uniRecord(directAG[2], ONE),
    ];
    expect(
      await clear(
        KIND_UNILATERAL,
        buildUnilateralBatch(records),
        records.length
      )
    ).to.deep.equal([false, false, true]);
    await expectReject(
      settle(program, staging, [0], () => [weirdChannel.key, gateway.balance]),
      /RecordNotVerified/
    );
  });

  it("rejects direct commitments on Routed channels and routed commitments on Direct channels", async () => {
    const tryBatch = async (kind: number, batch: Batch, fresh: boolean) => {
      const { sealPre } = await stageBatch(program, relayer, staging, batch, {
        fresh,
      });
      await sealAndQueue(program, relayer, staging, kind, 1, sealPre);
    };

    await expectReject(
      tryBatch(
        KIND_UNILATERAL,
        buildUnilateralBatch([uniRecord(routedAG, ONE)]),
        false
      ),
      /AccountDiscriminatorMismatch|AccountDiscriminatorNotFound|InvalidAccountData/
    );
    await expectReject(
      tryBatch(
        KIND_ROUTE,
        buildRouteBatch(
          [
            routeRecord(directAG[0], 0, ONE, [
              { provider: providers[0], amount: ONE },
            ]),
          ],
          gateway.participant
        ),
        false
      ),
      /AccountDiscriminatorMismatch|AccountDiscriminatorNotFound|InvalidAccountData/
    );
    expect(await channelState(routedAG)).to.deep.equal({
      settled: 0,
      locked: 60 * ONE,
    });
    expect(await channelState(directAG[0])).to.deep.equal({
      settled: 0,
      locked: 60 * ONE,
    });
  });

  it("settles valid unilateral commitments and clamps to locked funds", async () => {
    const records = [
      uniRecord(directAG[0], 40 * ONE),
      uniRecord(directAG[1], 50 * ONE),
      uniRecord(directAG[2], 10 * ONE, true),
      uniRecord(directAG[2], 25 * ONE),
    ];
    expect(
      await clear(
        KIND_UNILATERAL,
        buildUnilateralBatch(records),
        records.length
      )
    ).to.deep.equal([true, true, false, true]);
    const source = (i: number) =>
      i === 0 ? directAG[0].key : i === 1 ? directAG[1].key : directAG[2].key;
    await settle(program, staging, [0, 1, 3], (i) => [
      source(i),
      gateway.balance,
    ]);
    expect(await channelState(directAG[0])).to.deep.equal({
      settled: 40 * ONE,
      locked: 20 * ONE,
    });
    expect(await channelState(directAG[1])).to.deep.equal({
      settled: 30 * ONE,
      locked: 0,
    });
    expect(await channelState(directAG[2])).to.deep.equal({
      settled: 25 * ONE,
      locked: 75 * ONE,
    });
    await assertSolvent();
  });

  it("resumes the same unilateral commitment after more funds are locked", async () => {
    await lock(directAG[1], 20 * ONE);
    const records = [
      uniRecord(directAG[1], 50 * ONE),
      uniRecord(directAG[1], 50 * ONE),
    ];
    expect(
      await clear(KIND_UNILATERAL, buildUnilateralBatch(records), 2)
    ).to.deep.equal([true, true]);
    await settle(program, staging, [0, 1], () => [
      directAG[1].key,
      gateway.balance,
    ]);
    expect(await channelState(directAG[1])).to.deep.equal({
      settled: 50 * ONE,
      locked: 0,
    });
    await assertSolvent();
  });

  it("pays multiple providers and the gateway fee from one signed commitment", async () => {
    const record = routeRecord(routedAG, 0, 15 * ONE, [
      { provider: providers[0], amount: 12 * ONE },
      { provider: providers[1], amount: 2 * ONE },
    ]);
    await program.methods
      .requestUnlockRoutedChannelFunds(routedAG.slot!, new anchor.BN(20 * ONE))
      .accounts({
        payerOwner: routedAgent.owner.publicKey,
        payerParticipant: routedAgent.participant,
        config: configPda,
        bucket: routedAG.key,
        payerBalance: routedAgent.balance,
      })
      .signers([routedAgent.owner])
      .rpc();

    expect(
      await clear(KIND_ROUTE, buildRouteBatch([record], gateway.participant), 1)
    ).to.deep.equal([true]);
    const p0 = await available(providers[0]);
    const p1 = await available(providers[1]);
    const g = await available(gateway);
    await expectReject(
      settle(program, staging, [0], () => [
        routedAG.key,
        gateway.balance,
        providers[1].balance,
        providers[0].balance,
      ]),
      /SettlementBalanceMismatch/
    );
    await settle(program, staging, [0], () => [
      routedAG.key,
      gateway.balance,
      providers[0].balance,
      providers[1].balance,
    ]);
    expect(await channelState(routedAG)).to.deep.equal({
      settled: 15 * ONE,
      locked: 45 * ONE,
    });
    expect(await available(providers[0])).to.equal(p0 + 12 * ONE);
    expect(await available(providers[1])).to.equal(p1 + 2 * ONE);
    expect(await available(gateway)).to.equal(g + ONE);
    await assertSolvent();
  });

  it("pays whatever is locked now and resumes the same multi-provider commitment later", async () => {
    const agent = await makeParty(30 * ONE);
    const source = await openChannel(agent, gateway, CHANNEL_KIND_ROUTED);
    await lock(source, 20 * ONE);
    const record = routeRecord(source, 0, 25 * ONE, [
      { provider: providers[0], amount: 15 * ONE },
      { provider: providers[1], amount: 8 * ONE },
    ]);
    const p0 = await available(providers[0]);
    const p1 = await available(providers[1]);
    const g = await available(gateway);

    await clear(KIND_ROUTE, buildRouteBatch([record], gateway.participant), 1);
    await settle(program, staging, [0], () => [
      source.key,
      gateway.balance,
      providers[0].balance,
      providers[1].balance,
    ]);
    expect(await channelState(source)).to.deep.equal({
      settled: 20 * ONE,
      locked: 0,
    });
    expect(await available(providers[0])).to.equal(p0 + 15 * ONE);
    expect(await available(providers[1])).to.equal(p1 + 5 * ONE);
    expect(await available(gateway)).to.equal(g);

    await lock(source, 5 * ONE);
    await clear(KIND_ROUTE, buildRouteBatch([record], gateway.participant), 1);
    await settle(program, staging, [0], () => [
      source.key,
      gateway.balance,
      providers[0].balance,
      providers[1].balance,
    ]);
    expect(await channelState(source)).to.deep.equal({
      settled: 25 * ONE,
      locked: 0,
    });
    expect(await available(providers[1])).to.equal(p1 + 8 * ONE);
    expect(await available(gateway)).to.equal(g + 2 * ONE);
    await assertSolvent();
  });

  it("does not block the bucket when an unlock leaves a valid commitment unfunded", async () => {
    const agent = await makeParty(12 * ONE);
    const source = await openChannel(agent, gateway, CHANNEL_KIND_ROUTED);
    await lock(source, 10 * ONE);
    const record = routeRecord(source, 0, 11 * ONE, [
      { provider: providers[0], amount: 11 * ONE },
    ]);
    await program.methods
      .requestUnlockRoutedChannelFunds(source.slot!, new anchor.BN(10 * ONE))
      .accounts({
        payerOwner: agent.owner.publicKey,
        payerParticipant: agent.participant,
        config: configPda,
        bucket: source.key,
        payerBalance: agent.balance,
      })
      .signers([agent.owner])
      .rpc();
    await new Promise((resolve) => setTimeout(resolve, 3000));
    await program.methods
      .executeUnlockRoutedChannelFunds(source.slot!)
      .accounts({
        payerOwner: agent.owner.publicKey,
        payerParticipant: agent.participant,
        config: configPda,
        bucket: source.key,
        payerBalance: agent.balance,
      })
      .signers([agent.owner])
      .rpc();

    await clear(KIND_ROUTE, buildRouteBatch([record], gateway.participant), 1);
    await settle(program, staging, [0], () => [
      source.key,
      gateway.balance,
      providers[0].balance,
    ]);
    expect(await channelState(source)).to.deep.equal({ settled: 0, locked: 0 });

    const providerBefore = await available(providers[0]);
    await lock(source, 10 * ONE);
    await clear(KIND_ROUTE, buildRouteBatch([record], gateway.participant), 1);
    await settle(program, staging, [0], () => [
      source.key,
      gateway.balance,
      providers[0].balance,
    ]);
    expect(await channelState(source)).to.deep.equal({
      settled: 10 * ONE,
      locked: 0,
    });
    expect(await available(providers[0])).to.equal(providerBefore + 10 * ONE);
    await assertSolvent();
  });

  it("cooperatively unlocks a routed bucket slot with both signatures", async () => {
    const agent = await makeParty(5 * ONE);
    const source = await openChannel(agent, gateway, CHANNEL_KIND_ROUTED);
    await lock(source, 5 * ONE);
    await program.methods
      .cooperativeUnlockRoutedChannelFunds(source.slot!, new anchor.BN(3 * ONE))
      .accounts({
        payerOwner: agent.owner.publicKey,
        gatewayOwner: gateway.owner.publicKey,
        payerParticipant: agent.participant,
        gatewayParticipant: gateway.participant,
        bucket: source.key,
        payerBalance: agent.balance,
      })
      .signers([agent.owner, gateway.owner])
      .rpc();
    expect(await channelState(source)).to.deep.equal({
      settled: 0,
      locked: 2 * ONE,
    });
    await assertSolvent();
  });

  it("makes the gateway accounting trust explicit: the first conflicting commitment wins", async () => {
    const agent = await makeParty(25 * ONE);
    const source = await openChannel(agent, gateway, CHANNEL_KIND_ROUTED);
    await lock(source, 25 * ONE);
    const toProvider0 = routeRecord(source, 0, 25 * ONE, [
      { provider: providers[0], amount: 25 * ONE },
    ]);
    const toProvider1 = routeRecord(source, 0, 25 * ONE, [
      { provider: providers[1], amount: 25 * ONE },
    ]);
    expect(
      await clear(
        KIND_ROUTE,
        buildRouteBatch([toProvider0, toProvider1], gateway.participant),
        2
      )
    ).to.deep.equal([true, true]);
    const p0 = await available(providers[0]);
    const p1 = await available(providers[1]);
    await settle(program, staging, [1], () => [
      source.key,
      gateway.balance,
      providers[1].balance,
    ]);
    await settle(program, staging, [0], () => [
      source.key,
      gateway.balance,
      providers[0].balance,
    ]);
    expect(await available(providers[1])).to.equal(p1 + 25 * ONE);
    expect(await available(providers[0])).to.equal(p0);
    expect(await channelState(source)).to.deep.equal({
      settled: 25 * ONE,
      locked: 0,
    });
  });

  it("rejects invalid source, base, gateway allocation, mixed gateway, and incomplete staging", async () => {
    const tryBatch = async (batch: Batch, count: number) => {
      const plan = await stageBatch(program, relayer, staging, batch);
      await sealAndQueue(
        program,
        relayer,
        staging,
        batch.kind,
        count,
        plan.sealPre
      );
    };
    const wrongId: UnilateralRecord = {
      ...uniRecord(directAG[0], 56 * ONE),
      channel: directAG[1].key,
    };
    await expectReject(
      tryBatch(buildUnilateralBatch([wrongId]), 1),
      /StagedRecordMismatch/
    );

    const future = routeRecord(routedAG, 30 * ONE, 40 * ONE, [
      { provider: providers[0], amount: 10 * ONE },
    ]);
    await expectReject(
      tryBatch(buildRouteBatch([future], gateway.participant), 1),
      /RouteBaseNotReached/
    );

    const gatewayAsProvider = routeRecord(routedAG, 15 * ONE, 20 * ONE, [
      { provider: gateway, amount: 5 * ONE },
    ]);
    await expectReject(
      tryBatch(buildRouteBatch([gatewayAsProvider], gateway.participant), 1),
      /InvalidRouteAllocations/
    );

    const otherGateway = await makeParty();
    const agent = await makeParty(10 * ONE);
    const wrongGatewaySource = await openChannel(
      agent,
      otherGateway,
      CHANNEL_KIND_ROUTED
    );
    await lock(wrongGatewaySource, 5 * ONE);
    const mixed = routeRecord(
      wrongGatewaySource,
      0,
      5 * ONE,
      [{ provider: providers[0], amount: 5 * ONE }],
      false,
      gateway
    );
    await expectReject(
      tryBatch(buildRouteBatch([mixed], gateway.participant), 1),
      /StagedRecordMismatch/
    );

    await expectReject(
      tryBatch(buildUnilateralBatch([uniRecord(directAG[2], 60 * ONE)]), 2),
      /IncompleteBatch/
    );
  });

  it("executes an unlock for only what settlement left", async () => {
    expect(
      (
        await program.account.routedChannelBucket.fetch(routedAG.key)
      ).pendingUnlockAmount[routedAG.slot!].toNumber()
    ).to.equal(20 * ONE);
    await new Promise((resolve) => setTimeout(resolve, 3000));
    const before = await available(routedAgent);
    await program.methods
      .executeUnlockRoutedChannelFunds(routedAG.slot!)
      .accounts({
        payerOwner: routedAgent.owner.publicKey,
        payerParticipant: routedAgent.participant,
        config: configPda,
        bucket: routedAG.key,
        payerBalance: routedAgent.balance,
      })
      .signers([routedAgent.owner])
      .rpc();
    expect(await available(routedAgent)).to.equal(before + 20 * ONE);
    expect(await channelState(routedAG)).to.deep.equal({
      settled: 15 * ONE,
      locked: 25 * ONE,
    });
    await assertSolvent();
  });

  it("clears a full route batch of distinct agent channels", async () => {
    const channels: Chan[] = [];
    for (let i = 0; i < N_ROUTE; i++) {
      const agent = await makeParty(10 * ONE);
      const source = await openChannel(agent, gateway, CHANNEL_KIND_ROUTED);
      await lock(source, 8 * ONE);
      channels.push(source);
    }
    const records = channels.map((source, i) =>
      routeRecord(source, 0, 3 * ONE, [
        { provider: providers[i % providers.length], amount: 2 * ONE },
      ])
    );
    expect(
      await clear(
        KIND_ROUTE,
        buildRouteBatch(records, gateway.participant),
        N_ROUTE
      )
    ).to.deep.equal(new Array(N_ROUTE).fill(true));
    for (let i = 0; i < N_ROUTE; i += 8) {
      const indices = Array.from(
        { length: Math.min(8, N_ROUTE - i) },
        (_, k) => i + k
      );
      await settle(program, staging, indices, (index) => [
        channels[index].key,
        gateway.balance,
        providers[index % providers.length].balance,
      ]);
    }
    for (const channel of channels) {
      expect(await channelState(channel)).to.deep.equal({
        settled: 3 * ONE,
        locked: 5 * ONE,
      });
    }
    await assertSolvent();
  });

  it("reclaims staging rent", async () => {
    const before = await provider.connection.getBalance(relayer.publicKey);
    await closeStaging(program, relayer, staging);
    expect(
      await provider.connection.getBalance(relayer.publicKey)
    ).to.be.greaterThan(before);
    expect(await provider.connection.getAccountInfo(staging)).to.be.null;
  });
});
