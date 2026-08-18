import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createAssociatedTokenAccount,
  getAssociatedTokenAddressSync,
  mintTo,
  getAccount,
} from "@solana/spl-token";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { expect } from "chai";
import { deriveArcisSigner } from "./commitment-client";
import {
  CHANNEL_TIMELOCK,
  ensureConfig,
  expectReject,
  fund,
  localWallet,
  newMint,
  protocolAuthority,
  protocolFeeRecipient,
  setupProvider,
  seeds,
} from "./shared";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const ONE = 1_000_000;

describe("ryvo_protocol / step 7: channels, lock, unlock", () => {
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
  }

  let payer: Party;
  let payee: Party;

  async function makeParty(deposit = 0): Promise<Party> {
    const owner = Keypair.generate();
    await fund(provider, owner.publicKey, 5);
    const participant = seeds.participant(program.programId, owner.publicKey);
    await program.methods
      .initializeParticipant()
      .accounts({ owner: owner.publicKey, participant, systemProgram: SystemProgram.programId })
      .signers([owner])
      .rpc();

    const balance = seeds.balance(program.programId, participant, mint);
    await program.methods
      .openBalance()
      .accounts({
        payer: owner.publicKey, participant, mint, tokenConfig, balance,
        systemProgram: SystemProgram.programId,
      })
      .signers([owner])
      .rpc();

    if (deposit > 0) {
      const ata = await createAssociatedTokenAccount(
        provider.connection, payerWallet, mint, owner.publicKey,
        { commitment: "confirmed" }, TOKEN_PROGRAM_ID,
      );
      await mintTo(
        provider.connection, payerWallet, mint, ata, payerWallet, deposit, [],
        { commitment: "confirmed" }, TOKEN_PROGRAM_ID,
      );
      await program.methods
        .deposit(new anchor.BN(deposit))
        .accounts({
          funder: owner.publicKey, mint, tokenConfig, vault,
          funderTokenAccount: ata, participant, balance,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([owner])
        .rpc();
    }
    return { owner, participant, balance };
  }


  const createChannel = (from: Party, to: Party, signer: PublicKey) =>
    program.methods
      .createChannel(signer)
      .accounts({
        payerOwner: from.owner.publicKey,
        payerParticipant: from.participant,
        payeeParticipant: to.participant,
        mint,
        tokenConfig,
        payerBalance: from.balance,
        payeeBalance: to.balance,
        channel: seeds.channel(program.programId, from.participant, to.participant, mint),
        systemProgram: SystemProgram.programId,
      })
      .signers([from.owner]);

  const payerOp = (from: Party, channel: PublicKey) => ({
    payerOwner: from.owner.publicKey,
    payerParticipant: from.participant,
    config: configPda,
    channel,
    payerBalance: from.balance,
    tokenConfig,
  });

  before(async () => {
    await ensureConfig(program, provider, authority, protocolFeeRecipient().publicKey);
    mint = await newMint(provider, 6);
    tokenConfig = seeds.tokenConfig(program.programId, mint);
    vault = seeds.vault(program.programId, mint);
    await program.methods
      .registerToken()
      .accounts({
        authority: authority.publicKey, config: configPda, mint, tokenConfig, vault,
        tokenProgram: TOKEN_PROGRAM_ID, systemProgram: SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .signers([authority])
      .rpc();

    payer = await makeParty(100 * ONE);
    payee = await makeParty(0);
  });

  async function assertSolvent() {
    const vaultAcc = await getAccount(provider.connection, vault, "confirmed", TOKEN_PROGRAM_ID);
    const tc = await program.account.tokenConfig.fetch(tokenConfig);
    const balances = await program.account.balance.all();
    const channels = await program.account.channel.all();

    const sumAvailable = balances
      .filter((b) => b.account.mint.toBase58() === mint.toBase58())
      .reduce((a, b) => a + BigInt(b.account.available.toString()), 0n);
    const sumLocked = channels
      .filter((c) => c.account.mint.toBase58() === mint.toBase58())
      .reduce((a, c) => a + BigInt(c.account.lockedBalance.toString()), 0n);

    expect(vaultAcc.amount.toString()).to.equal(
      (sumAvailable + sumLocked + BigInt(tc.accruedFees.toString())).toString(),
      "solvency invariant violated",
    );
  }

  it("requires an explicit authorized signer", async () => {
    await expectReject(
      createChannel(payer, payee, PublicKey.default).rpc(),
      /InvalidAuthorizedSigner/,
    );
  });

  it("refuses a self-channel", async () => {
    await expectReject(
      createChannel(payer, payer, payer.owner.publicKey).rpc(),
      /SelfChannelNotAllowed/,
    );
  });

  it("creates a channel with a derived signer and no payee involvement", async () => {
    const channel = seeds.channel(program.programId, payer.participant, payee.participant, mint);
    // The real pattern: derive the signer for this channel from the agent wallet seed,
    // rather than registering an arbitrary throwaway key.
    const signer = deriveArcisSigner(payer.owner.secretKey.slice(0, 32), channel);
    const signingKey = new PublicKey(signer.publicKey);
    await createChannel(payer, payee, signingKey).rpc();

    const c = await program.account.channel.fetch(channel);
    expect(c.payer.toBase58()).to.equal(payer.participant.toBase58());
    expect(c.payee.toBase58()).to.equal(payee.participant.toBase58());
    expect(c.mint.toBase58()).to.equal(mint.toBase58());
    expect(c.authorizedSigner.toBase58()).to.equal(signingKey.toBase58());
    expect(c.settledCumulative.toNumber()).to.equal(0);
    expect(c.lockedBalance.toNumber()).to.equal(0);

    // And the registered signer is NOT the agent's wallet address.
    expect(c.authorizedSigner.toBase58()).to.not.equal(payer.owner.publicKey.toBase58());
  });

  it("refuses a duplicate channel but allows the reverse direction", async () => {
    await expectReject(createChannel(payer, payee, payer.owner.publicKey).rpc());

    // Unidirectional: (payee -> payer) is a different account entirely.
    await createChannel(payee, payer, payee.owner.publicKey).rpc();
    const reverse = seeds.channel(program.programId, payee.participant, payer.participant, mint);
    const c = await program.account.channel.fetch(reverse);
    expect(c.payer.toBase58()).to.equal(payee.participant.toBase58());
  });


  it("refuses a channel when the payee has no balance for the mint", async () => {
    // This is the forward-compatibility guard: v2 settlement cannot create accounts, so a lane
    // with no payee balance would be permanently unappliable.
    const owner = Keypair.generate();
    await fund(provider, owner.publicKey, 3);
    const participant = seeds.participant(program.programId, owner.publicKey);
    await program.methods
      .initializeParticipant()
      .accounts({ owner: owner.publicKey, participant, systemProgram: SystemProgram.programId })
      .signers([owner])
      .rpc();
    // Deliberately no openBalance.
    await expectReject(
      createChannel(payer, { owner, participant, balance: seeds.balance(program.programId, participant, mint) }, payer.owner.publicKey, owner).rpc(),
    );
  });

  it("locks funds, moving the ledger split without moving tokens", async () => {
    const channel = seeds.channel(program.programId, payer.participant, payee.participant, mint);
    const balBefore = await program.account.balance.fetch(payer.balance);
    const vaultBefore = await getAccount(provider.connection, vault, "confirmed", TOKEN_PROGRAM_ID);

    await program.methods
      .lockChannelFunds(new anchor.BN(40 * ONE))
      .accounts(payerOp(payer, channel))
      .signers([payer.owner])
      .rpc();

    const balAfter = await program.account.balance.fetch(payer.balance);
    const c = await program.account.channel.fetch(channel);
    const vaultAfter = await getAccount(provider.connection, vault, "confirmed", TOKEN_PROGRAM_ID);

    expect(balAfter.available.toNumber()).to.equal(balBefore.available.toNumber() - 40 * ONE);
    expect(c.lockedBalance.toNumber()).to.equal(40 * ONE);
    expect(vaultAfter.amount.toString()).to.equal(vaultBefore.amount.toString());
    await assertSolvent();
  });

  it("keeps locked funds beyond the reach of a withdrawal", async () => {
    // available is 60, locked is 40. Locked collateral lives on the Channel account, so a
    // withdrawal can never see it.
    const b = await program.account.balance.fetch(payer.balance);
    // The payer's ATA already exists from the deposit in `makeParty`; derive it rather than
    // trying to create it again.
    const ata = getAssociatedTokenAddressSync(
      mint, payer.owner.publicKey, false, TOKEN_PROGRAM_ID,
    );
    await expectReject(
      program.methods
        .withdraw(new anchor.BN(b.available.toNumber() + 1))
        .accounts({
          owner: payer.owner.publicKey, config: configPda, participant: payer.participant,
          mint, tokenConfig, vault, balance: payer.balance, destination: ata,
          tokenProgram: TOKEN_PROGRAM_ID,
        })
        .signers([payer.owner])
        .rpc(),
      /InsufficientBalance/,
    );
  });

  it("refuses to lock more than is available and to unlock more than is locked", async () => {
    const channel = seeds.channel(program.programId, payer.participant, payee.participant, mint);
    const b = await program.account.balance.fetch(payer.balance);
    await expectReject(
      program.methods
        .lockChannelFunds(new anchor.BN(b.available.toNumber() + 1))
        .accounts(payerOp(payer, channel))
        .signers([payer.owner])
        .rpc(),
      /InsufficientBalance/,
    );
    await expectReject(
      program.methods
        .requestUnlockChannelFunds(new anchor.BN(1000 * ONE))
        .accounts(payerOp(payer, channel))
        .signers([payer.owner])
        .rpc(),
      /InsufficientLockedBalance/,
    );
  });

  it("enforces the unlock timelock and pushes the deadline out on re-request", async () => {
    const channel = seeds.channel(program.programId, payer.participant, payee.participant, mint);

    await program.methods
      .requestUnlockChannelFunds(new anchor.BN(10 * ONE))
      .accounts(payerOp(payer, channel))
      .signers([payer.owner])
      .rpc();
    const first = await program.account.channel.fetch(channel);
    expect(first.pendingUnlockAmount.toNumber()).to.equal(10 * ONE);

    await expectReject(
      program.methods
        .executeUnlockChannelFunds()
        .accounts(payerOp(payer, channel))
        .signers([payer.owner])
        .rpc(),
      /ChannelUnlockLocked/,
    );

    await sleep(1200);
    await program.methods
      .requestUnlockChannelFunds(new anchor.BN(15 * ONE))
      .accounts(payerOp(payer, channel))
      .signers([payer.owner])
      .rpc();
    const second = await program.account.channel.fetch(channel);
    expect(second.pendingUnlockAmount.toNumber()).to.equal(15 * ONE);
    expect(second.pendingUnlockAt.toNumber()).to.be.greaterThan(first.pendingUnlockAt.toNumber());
  });

  it("releases min(pending, locked) and refuses a non-payer executor", async () => {
    const channel = seeds.channel(program.programId, payer.participant, payee.participant, mint);
    await sleep((CHANNEL_TIMELOCK + 1) * 1000);

    const stranger = Keypair.generate();
    await fund(provider, stranger.publicKey, 2);
    await expectReject(
      program.methods
        .executeUnlockChannelFunds()
        .accounts({ ...payerOp(payer, channel), payerOwner: stranger.publicKey })
        .signers([stranger])
        .rpc(),
    );

    const balBefore = await program.account.balance.fetch(payer.balance);
    await program.methods
      .executeUnlockChannelFunds()
      .accounts(payerOp(payer, channel))
      .signers([payer.owner])
      .rpc();

    const balAfter = await program.account.balance.fetch(payer.balance);
    const c = await program.account.channel.fetch(channel);
    expect(balAfter.available.toNumber()).to.equal(balBefore.available.toNumber() + 15 * ONE);
    expect(c.lockedBalance.toNumber()).to.equal(25 * ONE);
    expect(c.pendingUnlockAmount.toNumber()).to.equal(0);
    expect(c.pendingUnlockAt.toNumber()).to.equal(0);

    await expectReject(
      program.methods
        .executeUnlockChannelFunds()
        .accounts(payerOp(payer, channel))
        .signers([payer.owner])
        .rpc(),
      /NoChannelUnlockPending/,
    );
    await assertSolvent();
  });

  it("clamps the release to locked_balance when pending exceeds it", async () => {
    // The invariant-6 case: request the full lock, then cooperatively release most of it, so the
    // pending amount now exceeds what remains locked.
    const channel = seeds.channel(program.programId, payer.participant, payee.participant, mint);

    await program.methods
      .requestUnlockChannelFunds(new anchor.BN(25 * ONE))
      .accounts(payerOp(payer, channel))
      .signers([payer.owner])
      .rpc();

    await program.methods
      .cooperativeUnlockChannelFunds(new anchor.BN(20 * ONE))
      .accounts({
        payerOwner: payer.owner.publicKey,
        payeeOwner: payee.owner.publicKey,
        payerParticipant: payer.participant,
        payeeParticipant: payee.participant,
        channel,
        payerBalance: payer.balance,
      })
      .signers([payer.owner, payee.owner])
      .rpc();

    let c = await program.account.channel.fetch(channel);
    expect(c.lockedBalance.toNumber()).to.equal(5 * ONE);
    // A cooperative release supersedes the outstanding unilateral request.
    expect(c.pendingUnlockAmount.toNumber()).to.equal(0);
    await assertSolvent();

    // Re-request more than remains, then confirm the release clamps to locked_balance.
    await program.methods
      .requestUnlockChannelFunds(new anchor.BN(5 * ONE))
      .accounts(payerOp(payer, channel))
      .signers([payer.owner])
      .rpc();
    await sleep((CHANNEL_TIMELOCK + 1) * 1000);
    await program.methods
      .executeUnlockChannelFunds()
      .accounts(payerOp(payer, channel))
      .signers([payer.owner])
      .rpc();

    c = await program.account.channel.fetch(channel);
    expect(c.lockedBalance.toNumber()).to.equal(0);
    await assertSolvent();
  });

  it("requires both signatures for a cooperative unlock", async () => {
    const channel = seeds.channel(program.programId, payer.participant, payee.participant, mint);
    await program.methods
      .lockChannelFunds(new anchor.BN(ONE))
      .accounts(payerOp(payer, channel))
      .signers([payer.owner])
      .rpc();

    await expectReject(
      program.methods
        .cooperativeUnlockChannelFunds(new anchor.BN(ONE))
        .accounts({
          payerOwner: payer.owner.publicKey,
          payeeOwner: payee.owner.publicKey,
          payerParticipant: payer.participant,
          payeeParticipant: payee.participant,
          channel,
          payerBalance: payer.balance,
        })
        .signers([payer.owner]) // payee missing
        .rpc(),
    );
    await assertSolvent();
  });
});
