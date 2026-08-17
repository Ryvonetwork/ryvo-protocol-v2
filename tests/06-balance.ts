import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createAssociatedTokenAccount,
  mintTo,
  getAccount,
} from "@solana/spl-token";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { expect } from "chai";
import {
  FEE_BPS,
  WITHDRAWAL_TIMELOCK,
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

describe("ryvo_protocol / step 6: balances and withdrawals", () => {
  const provider = setupProvider();
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;

  const authority = protocolAuthority();
  const feeRecipient = protocolFeeRecipient();
  const configPda = seeds.config(program.programId);
  const payer = localWallet();

  let mint: PublicKey;
  let tokenConfig: PublicKey;
  let vault: PublicKey;

  // A registered participant with a funded token account.
  let owner: Keypair;
  let participant: PublicKey;
  let balance: PublicKey;
  let ownerAta: PublicKey;

  const DECIMALS = 6;
  const ONE = 1_000_000;

  before(async () => {
    await ensureConfig(program, provider, authority, feeRecipient.publicKey);

    mint = await newMint(provider, DECIMALS);
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

    owner = Keypair.generate();
    await fund(provider, owner.publicKey, 5);
    participant = seeds.participant(program.programId, owner.publicKey);
    await program.methods
      .initializeParticipant()
      .accounts({
        owner: owner.publicKey,
        participant,
        systemProgram: SystemProgram.programId,
      })
      .signers([owner])
      .rpc();

    balance = seeds.balance(program.programId, participant, mint);
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

    ownerAta = await createAssociatedTokenAccount(
      provider.connection,
      payer,
      mint,
      owner.publicKey,
      { commitment: "confirmed" },
      TOKEN_PROGRAM_ID,
    );
    await mintTo(
      provider.connection,
      payer,
      mint,
      ownerAta,
      payer,
      1000 * ONE,
      [],
      { commitment: "confirmed" },
      TOKEN_PROGRAM_ID,
    );
  });

  /** vault.amount == sum(available) + sum(locked) + accrued_fees */
  async function assertSolvent() {
    const vaultAcc = await getAccount(provider.connection, vault, "confirmed", TOKEN_PROGRAM_ID);
    const tc = await program.account.tokenConfig.fetch(tokenConfig);
    const balances = await program.account.balance.all();
    // `channel` only exists in the IDL once step 7 adds a channel instruction.
    const channels = (program.account as any).channel
      ? await (program.account as any).channel.all()
      : [];

    const sumAvailable = balances
      .filter((b) => b.account.mint.toBase58() === mint.toBase58())
      .reduce((a, b) => a + BigInt(b.account.available.toString()), 0n);
    const sumLocked = (channels as any[])
      .filter((c) => c.account.mint.toBase58() === mint.toBase58())
      .reduce((a, c) => a + BigInt(c.account.lockedBalance.toString()), 0n);

    expect(vaultAcc.amount.toString()).to.equal(
      (sumAvailable + sumLocked + BigInt(tc.accruedFees.toString())).toString(),
      "solvency invariant violated",
    );
  }

  const deposit = (amount: number, funder = owner, funderAta = ownerAta) =>
    program.methods
      .deposit(new anchor.BN(amount))
      .accounts({
        funder: funder.publicKey,
        mint,
        tokenConfig,
        vault,
        funderTokenAccount: funderAta,
        participant,
        balance,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([funder]);

  it("deposits into the vault and credits available", async () => {
    await deposit(100 * ONE).rpc();
    const b = await program.account.balance.fetch(balance);
    expect(b.available.toNumber()).to.equal(100 * ONE);
    await assertSolvent();
  });

  it("refuses a zero deposit and a disabled token", async () => {
    await expectReject(deposit(0).rpc(), /AmountMustBePositive/);

    await program.methods
      .setTokenEnabled(false)
      .accounts({ authority: authority.publicKey, config: configPda, tokenConfig })
      .signers([authority])
      .rpc();
    await expectReject(deposit(ONE).rpc(), /TokenDisabled/);
    await program.methods
      .setTokenEnabled(true)
      .accounts({ authority: authority.publicKey, config: configPda, tokenConfig })
      .signers([authority])
      .rpc();
  });

  it("accepts a third-party funder, crediting the participant not the funder", async () => {
    const before = await program.account.balance.fetch(balance);
    await deposit(5 * ONE, payer, await (async () => {
      const ata = await createAssociatedTokenAccount(
        provider.connection,
        payer,
        mint,
        payer.publicKey,
        { commitment: "confirmed" },
        TOKEN_PROGRAM_ID,
      );
      await mintTo(provider.connection, payer, mint, ata, payer, 10 * ONE, [], { commitment: "confirmed" }, TOKEN_PROGRAM_ID);
      return ata;
    })()).rpc();
    const after = await program.account.balance.fetch(balance);
    expect(after.available.toNumber()).to.equal(before.available.toNumber() + 5 * ONE);
    await assertSolvent();
  });

  it("request_withdrawal records intent and moves no funds", async () => {
    const before = await program.account.balance.fetch(balance);
    const vaultBefore = await getAccount(provider.connection, vault, "confirmed", TOKEN_PROGRAM_ID);

    await program.methods
      .requestWithdrawal(new anchor.BN(10 * ONE))
      .accounts({
        owner: owner.publicKey,
        config: configPda,
        participant,
        mint,
        balance,
        destination: ownerAta,
        vault,
      })
      .signers([owner])
      .rpc();

    const after = await program.account.balance.fetch(balance);
    // The load-bearing assertion for removing the `withdrawing` bucket.
    expect(after.available.toNumber()).to.equal(before.available.toNumber());
    expect(after.pendingWithdrawalAmount.toNumber()).to.equal(10 * ONE);
    expect(after.withdrawalDestination.toBase58()).to.equal(ownerAta.toBase58());
    expect(after.withdrawalUnlockAt.toNumber()).to.be.greaterThan(0);

    const vaultAfter = await getAccount(provider.connection, vault, "confirmed", TOKEN_PROGRAM_ID);
    expect(vaultAfter.amount.toString()).to.equal(vaultBefore.amount.toString());
    await assertSolvent();
  });

  it("refuses a second pending withdrawal, an over-balance amount, and the vault as destination", async () => {
    await expectReject(
      program.methods
        .requestWithdrawal(new anchor.BN(ONE))
        .accounts({ owner: owner.publicKey, config: configPda, participant, mint, balance, destination: ownerAta, vault })
        .signers([owner])
        .rpc(),
      /WithdrawalAlreadyPending/,
    );

    await program.methods
      .cancelWithdrawal()
      .accounts({ owner: owner.publicKey, participant, balance })
      .signers([owner])
      .rpc();

    const b = await program.account.balance.fetch(balance);
    await expectReject(
      program.methods
        .requestWithdrawal(new anchor.BN(b.available.toNumber() + 1))
        .accounts({ owner: owner.publicKey, config: configPda, participant, mint, balance, destination: ownerAta, vault })
        .signers([owner])
        .rpc(),
      /InsufficientBalance/,
    );
  });

  it("cancel clears state with no timelock and no balance change", async () => {
    const before = await program.account.balance.fetch(balance);
    await program.methods
      .requestWithdrawal(new anchor.BN(ONE))
      .accounts({ owner: owner.publicKey, config: configPda, participant, mint, balance, destination: ownerAta, vault })
      .signers([owner])
      .rpc();
    await program.methods
      .cancelWithdrawal()
      .accounts({ owner: owner.publicKey, participant, balance })
      .signers([owner])
      .rpc();

    const after = await program.account.balance.fetch(balance);
    expect(after.available.toNumber()).to.equal(before.available.toNumber());
    expect(after.pendingWithdrawalAmount.toNumber()).to.equal(0);
    expect(after.withdrawalUnlockAt.toNumber()).to.equal(0);
    expect(after.withdrawalDestination.toBase58()).to.equal(PublicKey.default.toBase58());

    await expectReject(
      program.methods
        .cancelWithdrawal()
        .accounts({ owner: owner.publicKey, participant, balance })
        .signers([owner])
        .rpc(),
      /NoWithdrawalPending/,
    );
  });

  const execute = (destination = ownerAta) =>
    program.methods
      .executeWithdrawal()
      .accounts({
        config: configPda,
        mint,
        tokenConfig,
        vault,
        participant,
        balance,
        destination,
        tokenProgram: TOKEN_PROGRAM_ID,
      });

  it("enforces the timelock, then pays net-of-fee, permissionlessly", async () => {
    await program.methods
      .requestWithdrawal(new anchor.BN(20 * ONE))
      .accounts({ owner: owner.publicKey, config: configPda, participant, mint, balance, destination: ownerAta, vault })
      .signers([owner])
      .rpc();

    await expectReject(execute().rpc(), /WithdrawalLocked/);

    // A substituted destination must be refused even after maturity.
    const stranger = Keypair.generate();
    const strangerAta = await createAssociatedTokenAccount(
      provider.connection, payer, mint, stranger.publicKey, { commitment: "confirmed" }, TOKEN_PROGRAM_ID,
    );
    await sleep((WITHDRAWAL_TIMELOCK + 1) * 1000);
    await expectReject(execute(strangerAta).rpc(), /InvalidWithdrawalDestination/);

    const balBefore = await program.account.balance.fetch(balance);
    const ataBefore = await getAccount(provider.connection, ownerAta, "confirmed", TOKEN_PROGRAM_ID);
    const tcBefore = await program.account.tokenConfig.fetch(tokenConfig);

    // No signer at all: the crank is open to anyone.
    await execute().rpc();

    const expectedFee = Math.floor((20 * ONE * FEE_BPS) / 10_000);
    const expectedNet = 20 * ONE - expectedFee;

    const balAfter = await program.account.balance.fetch(balance);
    const ataAfter = await getAccount(provider.connection, ownerAta, "confirmed", TOKEN_PROGRAM_ID);
    const tcAfter = await program.account.tokenConfig.fetch(tokenConfig);

    expect(balAfter.available.toNumber()).to.equal(balBefore.available.toNumber() - 20 * ONE);
    expect(Number(ataAfter.amount - ataBefore.amount)).to.equal(expectedNet);
    expect(tcAfter.accruedFees.toNumber()).to.equal(tcBefore.accruedFees.toNumber() + expectedFee);
    expect(balAfter.pendingWithdrawalAmount.toNumber()).to.equal(0);
    await assertSolvent();
  });

  it("rounds a sub-fee withdrawal to a zero fee without underflowing", async () => {
    await program.methods
      .requestWithdrawal(new anchor.BN(1))
      .accounts({ owner: owner.publicKey, config: configPda, participant, mint, balance, destination: ownerAta, vault })
      .signers([owner])
      .rpc();
    await sleep((WITHDRAWAL_TIMELOCK + 1) * 1000);

    const ataBefore = await getAccount(provider.connection, ownerAta, "confirmed", TOKEN_PROGRAM_ID);
    await execute().rpc();
    const ataAfter = await getAccount(provider.connection, ownerAta, "confirmed", TOKEN_PROGRAM_ID);

    // 1 * 30 / 10000 == 0, so the user receives the whole unit.
    expect(Number(ataAfter.amount - ataBefore.amount)).to.equal(1);
    await assertSolvent();
  });

  it("refuses to execute with nothing pending", async () => {
    await expectReject(execute().rpc(), /NoWithdrawalPending/);
  });
});
