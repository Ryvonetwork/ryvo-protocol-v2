import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createAssociatedTokenAccount,
  getAssociatedTokenAddressSync,
  getAccount,
  mintTo,
} from "@solana/spl-token";
import { expect } from "chai";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { deriveArcisSigner } from "./commitment-client";
import {
  CHANNEL_KIND_DIRECT,
  CHANNEL_TIMELOCK,
  ensureConfig,
  expectReject,
  fund,
  localWallet,
  newMint,
  protocolAuthority,
  seeds,
  setupProvider,
} from "./shared";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const ONE = 1_000_000;
const CHANNEL_BUCKET_SPACE = 32_944;

describe("ryvo_protocol / step 7: channel buckets, lock, unlock", () => {
  const provider = setupProvider();
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;
  const authority = protocolAuthority();
  const configPda = seeds.config(program.programId);
  const payerWallet = localWallet();

  let mint: PublicKey;
  let tokenConfig: PublicKey;
  let vault: PublicKey;

  interface Party {
    owner: Keypair;
    participant: PublicKey;
    balance: PublicKey;
    signer: PublicKey;
  }

  let payer: Party;
  let payee: Party;
  let secondPayer: Party;
  const directBucket = Keypair.generate();
  const slot = 0;

  async function makeParty(deposit = 0): Promise<Party> {
    const owner = Keypair.generate();
    await fund(provider, owner.publicKey, 5);
    const participant = seeds.participant(program.programId, owner.publicKey);
    const signer = new PublicKey(
      deriveArcisSigner(owner.secretKey.slice(0, 32)).publicKey
    );
    await program.methods
      .initializeParticipant(signer)
      .accounts({
        owner: owner.publicKey,
        config: configPda,
        participant,
        systemProgram: SystemProgram.programId,
      })
      .signers([owner])
      .rpc();

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
        payerWallet,
        mint,
        owner.publicKey,
        { commitment: "confirmed" },
        TOKEN_PROGRAM_ID
      );
      await mintTo(
        provider.connection,
        payerWallet,
        mint,
        ata,
        payerWallet,
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
    return { owner, participant, balance, signer };
  }

  async function initializeBucket(
    bucket: Keypair,
    recipient: Party,
    kind: number
  ) {
    const rent = await provider.connection.getMinimumBalanceForRentExemption(
      CHANNEL_BUCKET_SPACE
    );
    return program.methods
      .initializeChannelBucket(kind)
      .accounts({
        payeeOwner: recipient.owner.publicKey,
        config: configPda,
        payeeParticipant: recipient.participant,
        mint,
        tokenConfig,
        payeeBalance: recipient.balance,
        bucket: bucket.publicKey,
      })
      .preInstructions([
        SystemProgram.createAccount({
          fromPubkey: recipient.owner.publicKey,
          newAccountPubkey: bucket.publicKey,
          lamports: rent,
          space: CHANNEL_BUCKET_SPACE,
          programId: program.programId,
        }),
      ])
      .signers([recipient.owner, bucket])
      .rpc();
  }

  const createChannel = (
    from: Party,
    to: Party,
    bucket: PublicKey,
    channelSlot: number
  ) =>
    program.methods
      .createChannel(channelSlot)
      .accounts({
        payerOwner: from.owner.publicKey,
        payeeOwner: to.owner.publicKey,
        payerParticipant: from.participant,
        payeeParticipant: to.participant,
        bucket,
        payerBalance: from.balance,
        payeeBalance: to.balance,
      })
      .signers([from.owner, to.owner]);

  const payerOp = (from: Party, bucket = directBucket.publicKey) => ({
    payerOwner: from.owner.publicKey,
    payerParticipant: from.participant,
    config: configPda,
    bucket,
    payerBalance: from.balance,
  });

  async function state(channelSlot = slot) {
    const bucket = await program.account.channelBucket.fetch(
      directBucket.publicKey
    );
    return {
      bucket,
      settled: bucket.settledCumulative[channelSlot].toNumber(),
      locked: bucket.lockedBalance[channelSlot].toNumber(),
      pending: bucket.pendingUnlockAmount[channelSlot].toNumber(),
      unlockAt: bucket.pendingUnlockAt[channelSlot].toNumber(),
    };
  }

  async function assertSolvent() {
    const vaultAcc = await getAccount(
      provider.connection,
      vault,
      "confirmed",
      TOKEN_PROGRAM_ID
    );
    const balances = await program.account.balance.all();
    const buckets = await program.account.channelBucket.all();
    const sumAvailable = balances
      .filter((b) => b.account.mint.toBase58() === mint.toBase58())
      .reduce((a, b) => a + BigInt(b.account.available.toString()), 0n);
    const sumLocked = buckets
      .filter((b) => b.account.mint.toBase58() === mint.toBase58())
      .reduce(
        (sum, b) =>
          sum +
          b.account.lockedBalance.reduce(
            (bucketSum, amount) => bucketSum + BigInt(amount.toString()),
            0n
          ),
        0n
      );
    expect(vaultAcc.amount.toString()).to.equal(
      (sumAvailable + sumLocked).toString(),
      "solvency invariant violated"
    );
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

    payer = await makeParty(100 * ONE);
    payee = await makeParty();
    secondPayer = await makeParty(ONE);
  });

  it("rejects an unknown bucket type", async () => {
    await expectReject(
      initializeBucket(Keypair.generate(), payee, 0),
      /InvalidChannelKind/
    );
  });

  it("creates a direct bucket and reserves 256 permanent channel ids", async () => {
    const before = await program.account.config.fetch(configPda);
    await initializeBucket(directBucket, payee, CHANNEL_KIND_DIRECT);
    const bucket = await program.account.channelBucket.fetch(
      directBucket.publicKey
    );
    const after = await program.account.config.fetch(configPda);

    expect(bucket.payee.toBase58()).to.equal(payee.participant.toBase58());
    expect(bucket.mint.toBase58()).to.equal(mint.toBase58());
    expect(bucket.kind).to.equal(CHANNEL_KIND_DIRECT);
    expect(bucket.baseChannelId.toString()).to.equal(
      before.nextChannelId.toString()
    );
    expect(after.nextChannelId.toNumber()).to.equal(
      before.nextChannelId.toNumber() + 256
    );
  });

  it("refuses a self-channel", async () => {
    await expectReject(
      createChannel(payee, payee, directBucket.publicKey, 0).rpc(),
      /SelfChannelNotAllowed/
    );
  });

  it("requires payee approval and creates the first direct channel slot", async () => {
    await expectReject(
      program.methods
        .createChannel(slot)
        .accounts({
          payerOwner: payer.owner.publicKey,
          payeeOwner: payee.owner.publicKey,
          payerParticipant: payer.participant,
          payeeParticipant: payee.participant,
          bucket: directBucket.publicKey,
          payerBalance: payer.balance,
          payeeBalance: payee.balance,
        })
        .signers([payer.owner])
        .rpc()
    );

    await createChannel(payer, payee, directBucket.publicKey, slot).rpc();
    const { bucket } = await state();
    expect(bucket.payers[slot].toBase58()).to.equal(
      payer.participant.toBase58()
    );
    expect(bucket.occupied[0] & 1).to.equal(1);
    expect(bucket.settledCumulative[slot].toNumber()).to.equal(0);
    expect(bucket.lockedBalance[slot].toNumber()).to.equal(0);

    const packedSigner = Buffer.concat([
      Buffer.from(bucket.signerSlot0[slot]).subarray(0, 26),
      Buffer.from(bucket.signerSlot1[slot]).subarray(0, 6),
    ]);
    expect(new PublicKey(packedSigner).toBase58()).to.equal(
      payer.signer.toBase58()
    );
  });

  it("keeps slots permanent and isolates each payer", async () => {
    await expectReject(
      createChannel(payer, payee, directBucket.publicKey, slot).rpc(),
      /ChannelSlotOccupied/
    );
    await createChannel(secondPayer, payee, directBucket.publicKey, 1).rpc();
    await expectReject(
      program.methods
        .lockChannelFunds(slot, new anchor.BN(1))
        .accounts(payerOp(secondPayer))
        .signers([secondPayer.owner])
        .rpc(),
      /InvalidChannelSlot/
    );
  });

  it("locks funds without moving vault tokens", async () => {
    const balBefore = await program.account.balance.fetch(payer.balance);
    const vaultBefore = await getAccount(
      provider.connection,
      vault,
      "confirmed",
      TOKEN_PROGRAM_ID
    );
    await program.methods
      .lockChannelFunds(slot, new anchor.BN(40 * ONE))
      .accounts(payerOp(payer))
      .signers([payer.owner])
      .rpc();

    const balAfter = await program.account.balance.fetch(payer.balance);
    const vaultAfter = await getAccount(
      provider.connection,
      vault,
      "confirmed",
      TOKEN_PROGRAM_ID
    );
    expect(balAfter.available.toNumber()).to.equal(
      balBefore.available.toNumber() - 40 * ONE
    );
    expect((await state()).locked).to.equal(40 * ONE);
    expect(vaultAfter.amount.toString()).to.equal(
      vaultBefore.amount.toString()
    );
    await assertSolvent();
  });

  it("keeps locked funds beyond the reach of withdrawal", async () => {
    const balance = await program.account.balance.fetch(payer.balance);
    const ata = getAssociatedTokenAddressSync(
      mint,
      payer.owner.publicKey,
      false,
      TOKEN_PROGRAM_ID
    );
    await expectReject(
      program.methods
        .withdraw(new anchor.BN(balance.available.toNumber() + 1))
        .accounts({
          owner: payer.owner.publicKey,
          participant: payer.participant,
          mint,
          tokenConfig,
          vault,
          balance: payer.balance,
          destination: ata,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([payer.owner])
        .rpc(),
      /InsufficientBalance/
    );
  });

  it("rejects locking or requesting more than the available amount", async () => {
    const balance = await program.account.balance.fetch(payer.balance);
    await expectReject(
      program.methods
        .lockChannelFunds(slot, new anchor.BN(balance.available.toNumber() + 1))
        .accounts(payerOp(payer))
        .signers([payer.owner])
        .rpc(),
      /InsufficientBalance/
    );
    await expectReject(
      program.methods
        .requestUnlockChannelFunds(slot, new anchor.BN(1000 * ONE))
        .accounts(payerOp(payer))
        .signers([payer.owner])
        .rpc(),
      /InsufficientLockedBalance/
    );
  });

  it("enforces the timelock and pushes the deadline out on re-request", async () => {
    await program.methods
      .requestUnlockChannelFunds(slot, new anchor.BN(10 * ONE))
      .accounts(payerOp(payer))
      .signers([payer.owner])
      .rpc();
    const first = await state();
    expect(first.pending).to.equal(10 * ONE);

    await expectReject(
      program.methods
        .executeUnlockChannelFunds(slot)
        .accounts(payerOp(payer))
        .signers([payer.owner])
        .rpc(),
      /ChannelUnlockLocked/
    );

    await sleep(1200);
    await program.methods
      .requestUnlockChannelFunds(slot, new anchor.BN(15 * ONE))
      .accounts(payerOp(payer))
      .signers([payer.owner])
      .rpc();
    const second = await state();
    expect(second.pending).to.equal(15 * ONE);
    expect(second.unlockAt).to.be.greaterThan(first.unlockAt);
  });

  it("releases the pending amount and refuses a non-payer", async () => {
    await sleep((CHANNEL_TIMELOCK + 1) * 1000);
    const stranger = Keypair.generate();
    await fund(provider, stranger.publicKey, 2);
    await expectReject(
      program.methods
        .executeUnlockChannelFunds(slot)
        .accounts({ ...payerOp(payer), payerOwner: stranger.publicKey })
        .signers([stranger])
        .rpc()
    );

    const before = await program.account.balance.fetch(payer.balance);
    await program.methods
      .executeUnlockChannelFunds(slot)
      .accounts(payerOp(payer))
      .signers([payer.owner])
      .rpc();
    const after = await program.account.balance.fetch(payer.balance);
    const channel = await state();
    expect(after.available.toNumber()).to.equal(
      before.available.toNumber() + 15 * ONE
    );
    expect(channel.locked).to.equal(25 * ONE);
    expect(channel.pending).to.equal(0);
    expect(channel.unlockAt).to.equal(0);
    await expectReject(
      program.methods
        .executeUnlockChannelFunds(slot)
        .accounts(payerOp(payer))
        .signers([payer.owner])
        .rpc(),
      /NoChannelUnlockPending/
    );
    await assertSolvent();
  });

  it("cancels a matured request when more funds are locked", async () => {
    await program.methods
      .requestUnlockChannelFunds(slot, new anchor.BN(5 * ONE))
      .accounts(payerOp(payer))
      .signers([payer.owner])
      .rpc();
    await sleep((CHANNEL_TIMELOCK + 1) * 1000);
    await program.methods
      .lockChannelFunds(slot, new anchor.BN(ONE))
      .accounts(payerOp(payer))
      .signers([payer.owner])
      .rpc();
    expect((await state()).pending).to.equal(0);
    await expectReject(
      program.methods
        .executeUnlockChannelFunds(slot)
        .accounts(payerOp(payer))
        .signers([payer.owner])
        .rpc(),
      /NoChannelUnlockPending/
    );

    await program.methods
      .requestUnlockChannelFunds(slot, new anchor.BN(5 * ONE))
      .accounts(payerOp(payer))
      .signers([payer.owner])
      .rpc();
    await expectReject(
      program.methods
        .executeUnlockChannelFunds(slot)
        .accounts(payerOp(payer))
        .signers([payer.owner])
        .rpc(),
      /ChannelUnlockLocked/
    );
    await program.methods
      .cooperativeUnlockChannelFunds(slot, new anchor.BN(ONE))
      .accounts({
        payerOwner: payer.owner.publicKey,
        payeeOwner: payee.owner.publicKey,
        payerParticipant: payer.participant,
        payeeParticipant: payee.participant,
        bucket: directBucket.publicKey,
        payerBalance: payer.balance,
      })
      .signers([payer.owner, payee.owner])
      .rpc();
    expect((await state()).locked).to.equal(25 * ONE);
    await assertSolvent();
  });

  it("cooperative release supersedes a pending request", async () => {
    await program.methods
      .requestUnlockChannelFunds(slot, new anchor.BN(25 * ONE))
      .accounts(payerOp(payer))
      .signers([payer.owner])
      .rpc();
    await program.methods
      .cooperativeUnlockChannelFunds(slot, new anchor.BN(20 * ONE))
      .accounts({
        payerOwner: payer.owner.publicKey,
        payeeOwner: payee.owner.publicKey,
        payerParticipant: payer.participant,
        payeeParticipant: payee.participant,
        bucket: directBucket.publicKey,
        payerBalance: payer.balance,
      })
      .signers([payer.owner, payee.owner])
      .rpc();
    let channel = await state();
    expect(channel.locked).to.equal(5 * ONE);
    expect(channel.pending).to.equal(0);

    await program.methods
      .requestUnlockChannelFunds(slot, new anchor.BN(5 * ONE))
      .accounts(payerOp(payer))
      .signers([payer.owner])
      .rpc();
    await sleep((CHANNEL_TIMELOCK + 1) * 1000);
    await program.methods
      .executeUnlockChannelFunds(slot)
      .accounts(payerOp(payer))
      .signers([payer.owner])
      .rpc();
    channel = await state();
    expect(channel.locked).to.equal(0);
    await assertSolvent();
  });

  it("requires both signatures for cooperative unlock", async () => {
    await program.methods
      .lockChannelFunds(slot, new anchor.BN(ONE))
      .accounts(payerOp(payer))
      .signers([payer.owner])
      .rpc();
    await expectReject(
      program.methods
        .cooperativeUnlockChannelFunds(slot, new anchor.BN(ONE))
        .accounts({
          payerOwner: payer.owner.publicKey,
          payeeOwner: payee.owner.publicKey,
          payerParticipant: payer.participant,
          payeeParticipant: payee.participant,
          bucket: directBucket.publicKey,
          payerBalance: payer.balance,
        })
        .signers([payer.owner])
        .rpc()
    );
    await assertSolvent();
  });
});
