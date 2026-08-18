/**
 * Devnet end-to-end smoke test.
 *
 * Runs the full v1 lifecycle against a real cluster: bootstrap, allowlist a mint, register two
 * participants, deposit, open a channel with a derived Arcis signer, lock, unlock, withdraw.
 *
 * Idempotent where it can be. `initialize` runs once per deployment — Config is a singleton PDA
 * with no close instruction, so its parameters, including the immutable channel timelock, are
 * fixed for the life of this program id on devnet.
 *
 *   npx ts-mocha -p ./tsconfig.json -t 900000 scripts/devnet-smoke.ts
 */
import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createMint,
  createAssociatedTokenAccount,
  mintTo,
  getAccount,
} from "@solana/spl-token";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { expect } from "chai";
import * as fs from "fs";
import * as os from "os";
import { deriveArcisSigner, deriveMessageDomain } from "../tests/commitment-client";

const DEVNET_CHAIN_ID = 1;
// Devnet-only, and permanent for this deployment. The channel unlock delay is the protocol's
// only timelock; withdrawals are immediate because settlement cannot reach free balance.
const CHANNEL_TIMELOCK = 10;
const FEE_BPS = 30;
const ONE = 1_000_000;

const BPF_LOADER_UPGRADEABLE = new PublicKey(
  "BPFLoaderUpgradeab1e11111111111111111111111",
);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function wallet(): Keypair {
  return Keypair.fromSecretKey(
    new Uint8Array(
      JSON.parse(fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8")),
    ),
  );
}

describe("ryvo_protocol devnet smoke", function () {
  this.timeout(900_000);

  const connection = new anchor.web3.Connection(
    process.env.ANCHOR_PROVIDER_URL ?? "https://api.devnet.solana.com",
    "confirmed",
  );
  const payer = wallet();
  const provider = new anchor.AnchorProvider(
    connection,
    new anchor.Wallet(payer),
    { commitment: "confirmed", preflightCommitment: "confirmed" },
  );
  anchor.setProvider(provider);
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;

  const pda = {
    config: () => PublicKey.findProgramAddressSync([Buffer.from("config")], program.programId)[0],
    participant: (o: PublicKey) =>
      PublicKey.findProgramAddressSync([Buffer.from("participant"), o.toBuffer()], program.programId)[0],
    tokenConfig: (m: PublicKey) =>
      PublicKey.findProgramAddressSync([Buffer.from("token"), m.toBuffer()], program.programId)[0],
    vault: (m: PublicKey) =>
      PublicKey.findProgramAddressSync([Buffer.from("vault"), m.toBuffer()], program.programId)[0],
    balance: (p: PublicKey, m: PublicKey) =>
      PublicKey.findProgramAddressSync(
        [Buffer.from("balance"), p.toBuffer(), m.toBuffer()], program.programId)[0],
    channel: (a: PublicKey, b: PublicKey, m: PublicKey) =>
      PublicKey.findProgramAddressSync(
        [Buffer.from("channel"), a.toBuffer(), b.toBuffer(), m.toBuffer()], program.programId)[0],
    programData: () =>
      PublicKey.findProgramAddressSync([program.programId.toBuffer()], BPF_LOADER_UPGRADEABLE)[0],
  };

  let mint: PublicKey;
  let payerParty: { owner: Keypair; participant: PublicKey; balance: PublicKey; ata: PublicKey };
  let payeeParty: { owner: Keypair; participant: PublicKey; balance: PublicKey };
  let channel: PublicKey;

  it("bootstraps config, deriving the devnet message domain in-program", async () => {
    const config = pda.config();
    if (!(await connection.getAccountInfo(config))) {
      await program.methods
        .initialize(
          DEVNET_CHAIN_ID,
          FEE_BPS,
          new anchor.BN(CHANNEL_TIMELOCK),
          payer.publicKey,
          payer.publicKey,
        )
        .accounts({
          payer: payer.publicKey,
          config,
          programData: pda.programData(),
          systemProgram: SystemProgram.programId,
        })
        .rpc();
      console.log("    initialized config");
    } else {
      console.log("    config already exists, reusing");
    }

    const cfg = await program.account.config.fetch(config);
    expect(cfg.chainId).to.equal(DEVNET_CHAIN_ID);
    const expected = deriveMessageDomain(program.programId, DEVNET_CHAIN_ID);
    expect(Buffer.from(cfg.messageDomain).toString("hex")).to.equal(expected.toString("hex"));
    console.log("    message_domain:", Buffer.from(cfg.messageDomain).toString("hex"));
    console.log("    authority:", cfg.authority.toBase58());
  });

  it("allowlists a mint and creates its vault", async () => {
    mint = await createMint(
      connection, payer, payer.publicKey, null, 6, undefined,
      { commitment: "confirmed" }, TOKEN_PROGRAM_ID,
    );
    await program.methods
      .registerToken()
      .accounts({
        authority: payer.publicKey,
        config: pda.config(),
        mint,
        tokenConfig: pda.tokenConfig(mint),
        vault: pda.vault(mint),
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
        rent: anchor.web3.SYSVAR_RENT_PUBKEY,
      })
      .rpc();

    const tc = await program.account.tokenConfig.fetch(pda.tokenConfig(mint));
    expect(tc.enabled).to.be.true;
    expect(tc.decimals).to.equal(6);
    console.log("    mint:", mint.toBase58());
  });

  it("registers two participants and opens their balances", async () => {
    // Transfer from our funded wallet rather than the faucet: devnet airdrops are rate-limited
    // and return 429 once the daily cap is hit, which has nothing to do with the protocol.
    const fundFromWallet = async (to: PublicKey, sol: number) => {
      const tx = new anchor.web3.Transaction().add(
        SystemProgram.transfer({
          fromPubkey: payer.publicKey,
          toPubkey: to,
          lamports: sol * anchor.web3.LAMPORTS_PER_SOL,
        }),
      );
      await provider.sendAndConfirm(tx, [payer]);
    };

    const mk = async (fund: number) => {
      const owner = Keypair.generate();
      await fundFromWallet(owner.publicKey, 0.2);

      const participant = pda.participant(owner.publicKey);
      await program.methods
        .initializeParticipant()
        .accounts({ owner: owner.publicKey, participant, systemProgram: SystemProgram.programId })
        .signers([owner]).rpc();

      const balance = pda.balance(participant, mint);
      await program.methods
        .openBalance()
        .accounts({
          payer: owner.publicKey, participant, mint,
          tokenConfig: pda.tokenConfig(mint), balance,
          systemProgram: SystemProgram.programId,
        })
        .signers([owner]).rpc();

      let ata = PublicKey.default;
      if (fund > 0) {
        ata = await createAssociatedTokenAccount(
          connection, payer, mint, owner.publicKey, { commitment: "confirmed" }, TOKEN_PROGRAM_ID,
        );
        await mintTo(connection, payer, mint, ata, payer, fund, [], { commitment: "confirmed" }, TOKEN_PROGRAM_ID);
      }
      return { owner, participant, balance, ata };
    };

    payerParty = await mk(200 * ONE);
    payeeParty = await mk(0);
    console.log("    payer participant:", payerParty.participant.toBase58());
    console.log("    payee participant:", payeeParty.participant.toBase58());
  });

  it("deposits into the vault", async () => {
    await program.methods
      .deposit(new anchor.BN(100 * ONE))
      .accounts({
        funder: payerParty.owner.publicKey, mint,
        tokenConfig: pda.tokenConfig(mint), vault: pda.vault(mint),
        funderTokenAccount: payerParty.ata,
        participant: payerParty.participant, balance: payerParty.balance,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([payerParty.owner]).rpc();

    const b = await program.account.balance.fetch(payerParty.balance);
    expect(b.available.toNumber()).to.equal(100 * ONE);
  });

  it("opens a channel whose signer is derived, not the wallet address", async () => {
    channel = pda.channel(payerParty.participant, payeeParty.participant, mint);
    const signer = deriveArcisSigner(payerParty.owner.secretKey.slice(0, 32), channel);

    await program.methods
      .createChannel(new PublicKey(signer.publicKey))
      .accounts({
        payerOwner: payerParty.owner.publicKey,
        payerParticipant: payerParty.participant,
        payeeParticipant: payeeParty.participant,
        mint,
        tokenConfig: pda.tokenConfig(mint),
        payerBalance: payerParty.balance,
        payeeBalance: payeeParty.balance,
        channel,
        systemProgram: SystemProgram.programId,
      })
      .signers([payerParty.owner]).rpc();

    const c = await program.account.channel.fetch(channel);
    expect(c.authorizedSigner.toBase58()).to.equal(new PublicKey(signer.publicKey).toBase58());
    expect(c.authorizedSigner.toBase58()).to.not.equal(payerParty.owner.publicKey.toBase58());
    console.log("    channel:", channel.toBase58());
    console.log("    authorized_signer:", c.authorizedSigner.toBase58());
    console.log("    payer wallet:      ", payerParty.owner.publicKey.toBase58());
  });

  const payerOp = () => ({
    payerOwner: payerParty.owner.publicKey,
    payerParticipant: payerParty.participant,
    config: pda.config(),
    channel,
    payerBalance: payerParty.balance,
    tokenConfig: pda.tokenConfig(mint),
  });

  it("locks and then unlocks channel collateral through the timelock", async () => {
    await program.methods
      .lockChannelFunds(new anchor.BN(40 * ONE))
      .accounts(payerOp()).signers([payerParty.owner]).rpc();
    let c = await program.account.channel.fetch(channel);
    expect(c.lockedBalance.toNumber()).to.equal(40 * ONE);

    await program.methods
      .requestUnlockChannelFunds(new anchor.BN(40 * ONE))
      .accounts(payerOp()).signers([payerParty.owner]).rpc();

    let rejected = false;
    try {
      await program.methods
        .executeUnlockChannelFunds().accounts(payerOp()).signers([payerParty.owner]).rpc();
    } catch { rejected = true; }
    expect(rejected, "unlock executed before the timelock elapsed").to.be.true;

    console.log(`    waiting ${CHANNEL_TIMELOCK + 2}s for the channel timelock`);
    await sleep((CHANNEL_TIMELOCK + 2) * 1000);

    await program.methods
      .executeUnlockChannelFunds().accounts(payerOp()).signers([payerParty.owner]).rpc();
    c = await program.account.channel.fetch(channel);
    expect(c.lockedBalance.toNumber()).to.equal(0);
  });

  it("withdraws immediately, net of fee, leaving the vault solvent", async () => {
    const ataBefore = await getAccount(connection, payerParty.ata, "confirmed", TOKEN_PROGRAM_ID);
    await program.methods
      .withdraw(new anchor.BN(50 * ONE))
      .accounts({
        owner: payerParty.owner.publicKey, config: pda.config(),
        participant: payerParty.participant, mint,
        tokenConfig: pda.tokenConfig(mint), vault: pda.vault(mint),
        balance: payerParty.balance, destination: payerParty.ata,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .signers([payerParty.owner]).rpc();
    const ataAfter = await getAccount(connection, payerParty.ata, "confirmed", TOKEN_PROGRAM_ID);

    const fee = Math.floor((50 * ONE * FEE_BPS) / 10_000);
    expect(Number(ataAfter.amount - ataBefore.amount)).to.equal(50 * ONE - fee);

    const vaultAcc = await getAccount(connection, pda.vault(mint), "confirmed", TOKEN_PROGRAM_ID);
    const tc = await program.account.tokenConfig.fetch(pda.tokenConfig(mint));
    const bal = await program.account.balance.fetch(payerParty.balance);
    const chan = await program.account.channel.fetch(channel);
    expect(vaultAcc.amount.toString()).to.equal(
      (
        BigInt(bal.available.toString()) +
        BigInt(chan.lockedBalance.toString()) +
        BigInt(tc.accruedFees.toString())
      ).toString(),
      "solvency invariant violated on devnet",
    );
    console.log("    vault:", vaultAcc.amount.toString(), "accrued fees:", tc.accruedFees.toString());
  });
});
