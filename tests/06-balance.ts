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
import { deriveArcisSigner } from "./commitment-client";
import {
  ensureConfig,
  expectReject,
  fund,
  localWallet,
  newMint,
  protocolAuthority,
  setupProvider,
  seeds,
} from "./shared";

describe("ryvo_protocol / step 6: balances and withdrawals", () => {
  const provider = setupProvider();
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;

  const authority = protocolAuthority();
  const configPda = seeds.config(program.programId);
  const payer = localWallet();

  let mint: PublicKey;
  let tokenConfig: PublicKey;
  let vault: PublicKey;

  let owner: Keypair;
  let participant: PublicKey;
  let balance: PublicKey;
  let ownerAta: PublicKey;

  const DECIMALS = 6;
  const ONE = 1_000_000;

  before(async () => {
    await ensureConfig(program, provider, authority);

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
      TOKEN_PROGRAM_ID
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
      TOKEN_PROGRAM_ID
    );
  });

  /** vault.amount == sum(available) + sum(locked) */
  async function assertSolvent() {
    const vaultAcc = await getAccount(
      provider.connection,
      vault,
      "confirmed",
      TOKEN_PROGRAM_ID
    );
    const balances = await program.account.balance.all();
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
      (sumAvailable + sumLocked).toString(),
      "solvency invariant violated"
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

  const withdraw = (amount: number, destination = ownerAta, who = owner) =>
    program.methods
      .withdraw(new anchor.BN(amount))
      .accounts({
        owner: who.publicKey,
        config: configPda,
        participant,
        mint,
        tokenConfig,
        vault,
        balance,
        destination,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([who]);

  it("deposits into the vault and credits available", async () => {
    await deposit(100 * ONE).rpc();
    const b = await program.account.balance.fetch(balance);
    expect(b.available.toNumber()).to.equal(100 * ONE);
    await assertSolvent();
  });

  it("refuses a zero deposit and a disabled token", async () => {
    await expectReject(deposit(0).rpc(), /AmountMustBePositive/);

    await program.methods
      .setTokenDepositEnabled(false)
      .accounts({
        authority: authority.publicKey,
        config: configPda,
        tokenConfig,
      })
      .signers([authority])
      .rpc();
    await expectReject(deposit(ONE).rpc(), /TokenDepositsDisabled/);
    await program.methods
      .setTokenDepositEnabled(true)
      .accounts({
        authority: authority.publicKey,
        config: configPda,
        tokenConfig,
      })
      .signers([authority])
      .rpc();
  });

  it("accepts a third-party funder, crediting the participant not the funder", async () => {
    const before = await program.account.balance.fetch(balance);
    const ata = await createAssociatedTokenAccount(
      provider.connection,
      payer,
      mint,
      payer.publicKey,
      { commitment: "confirmed" },
      TOKEN_PROGRAM_ID
    );
    await mintTo(
      provider.connection,
      payer,
      mint,
      ata,
      payer,
      10 * ONE,
      [],
      { commitment: "confirmed" },
      TOKEN_PROGRAM_ID
    );
    await deposit(5 * ONE, payer, ata).rpc();

    const after = await program.account.balance.fetch(balance);
    expect(after.available.toNumber()).to.equal(
      before.available.toNumber() + 5 * ONE
    );
    await assertSolvent();
  });

  it("withdraws immediately and in full, with no timelock and no fee", async () => {
    const balBefore = await program.account.balance.fetch(balance);
    const ataBefore = await getAccount(
      provider.connection,
      ownerAta,
      "confirmed",
      TOKEN_PROGRAM_ID
    );

    await withdraw(20 * ONE).rpc();

    const balAfter = await program.account.balance.fetch(balance);
    const ataAfter = await getAccount(
      provider.connection,
      ownerAta,
      "confirmed",
      TOKEN_PROGRAM_ID
    );

    expect(balAfter.available.toNumber()).to.equal(
      balBefore.available.toNumber() - 20 * ONE
    );
    // The whole amount arrives: the protocol takes no cut.
    expect(Number(ataAfter.amount - ataBefore.amount)).to.equal(20 * ONE);
    await assertSolvent();
  });

  it("refuses more than available, a zero amount, and the vault as destination", async () => {
    const b = await program.account.balance.fetch(balance);
    await expectReject(
      withdraw(b.available.toNumber() + 1).rpc(),
      /InsufficientBalance/
    );
    await expectReject(withdraw(0).rpc(), /AmountMustBePositive/);
    // Draining the vault into itself is blocked twice over: Anchor's duplicate-mutable-account
    // check fires first (the vault is already `mut` in the struct), and the handler's explicit
    // destination check backs it up. Assert only the rejection, not which layer caught it.
    await expectReject(withdraw(ONE, vault).rpc());
  });

  it("refuses a withdrawal signed by anyone but the owner", async () => {
    // There is no permissionless crank: the owner names the destination in the same call, so the
    // signature is what binds where the money goes.
    const stranger = Keypair.generate();
    await fund(provider, stranger.publicKey, 2);
    await expectReject(withdraw(ONE, ownerAta, stranger).rpc());
  });

  it("withdraws a single unit without rounding it away", async () => {
    const ataBefore = await getAccount(
      provider.connection,
      ownerAta,
      "confirmed",
      TOKEN_PROGRAM_ID
    );
    await withdraw(1).rpc();
    const ataAfter = await getAccount(
      provider.connection,
      ownerAta,
      "confirmed",
      TOKEN_PROGRAM_ID
    );
    expect(Number(ataAfter.amount - ataBefore.amount)).to.equal(1);
    await assertSolvent();
  });

  it("lets the authority disable a token without blocking exits", async () => {
    // The freeze question: `enabled` gates entry only. If it gated withdrawal, the authority
    // could strand user funds.
    await program.methods
      .setTokenDepositEnabled(false)
      .accounts({
        authority: authority.publicKey,
        config: configPda,
        tokenConfig,
      })
      .signers([authority])
      .rpc();

    await expectReject(deposit(ONE).rpc(), /TokenDepositsDisabled/);
    await withdraw(ONE).rpc(); // must still succeed

    await program.methods
      .setTokenDepositEnabled(true)
      .accounts({
        authority: authority.publicKey,
        config: configPda,
        tokenConfig,
      })
      .signers([authority])
      .rpc();
    await assertSolvent();
  });
});
