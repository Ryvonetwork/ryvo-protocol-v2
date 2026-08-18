import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, createMint } from "@solana/spl-token";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import * as fs from "fs";
import * as os from "os";

export const BPF_LOADER_UPGRADEABLE = new PublicKey(
  "BPFLoaderUpgradeab1e11111111111111111111111",
);

/**
 * The protocol's only timelock, kept small so tests can wait it out for real. Withdrawals have
 * none: settlement is payable strictly from a channel's locked collateral, so `available` is free
 * money and `withdraw` is immediate.
 */
export const CHANNEL_TIMELOCK = 2;
export const FEE_BPS = 30;
export const CHAIN_ID = 0; // localnet

/**
 * Provider pinned to `confirmed`.
 *
 * Anchor's default options use `processed`, so `.rpc()` resolves before a subsequent account read
 * can observe the write. That produced reads that lagged writes by one deposit — the kind of
 * flake that looks like a protocol bug. Every test file must use this.
 */
export function setupProvider(): anchor.AnchorProvider {
  const base = anchor.AnchorProvider.env();
  const connection = new anchor.web3.Connection(
    process.env.ANCHOR_PROVIDER_URL ?? "http://127.0.0.1:8899",
    "confirmed",
  );
  const provider = new anchor.AnchorProvider(connection, base.wallet, {
    commitment: "confirmed",
    preflightCommitment: "confirmed",
  });
  anchor.setProvider(provider);
  return provider;
}

/**
 * Deterministic protocol authority shared by every test file.
 *
 * Test files run against one validator within a single `npm test`, so the authority must be
 * stable across them. Step 3 exercises the authority handoff and then restores this key, so
 * later files can still perform authority-gated actions.
 */
export function protocolAuthority(): Keypair {
  return Keypair.fromSeed(Uint8Array.from(Buffer.alloc(32, 7)));
}

export function protocolFeeRecipient(): Keypair {
  return Keypair.fromSeed(Uint8Array.from(Buffer.alloc(32, 9)));
}

export function localWallet(): Keypair {
  return Keypair.fromSecretKey(
    new Uint8Array(
      JSON.parse(fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8")),
    ),
  );
}

export const seeds = {
  config: (programId: PublicKey) =>
    PublicKey.findProgramAddressSync([Buffer.from("config")], programId)[0],
  participant: (programId: PublicKey, owner: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("participant"), owner.toBuffer()],
      programId,
    )[0],
  tokenConfig: (programId: PublicKey, mint: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("token"), mint.toBuffer()],
      programId,
    )[0],
  vault: (programId: PublicKey, mint: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("vault"), mint.toBuffer()],
      programId,
    )[0],
  balance: (programId: PublicKey, participant: PublicKey, mint: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [Buffer.from("balance"), participant.toBuffer(), mint.toBuffer()],
      programId,
    )[0],
  channel: (
    programId: PublicKey,
    payer: PublicKey,
    payee: PublicKey,
    mint: PublicKey,
  ) =>
    PublicKey.findProgramAddressSync(
      [
        Buffer.from("channel"),
        payer.toBuffer(),
        payee.toBuffer(),
        mint.toBuffer(),
      ],
      programId,
    )[0],
  programData: (programId: PublicKey) =>
    PublicKey.findProgramAddressSync(
      [programId.toBuffer()],
      BPF_LOADER_UPGRADEABLE,
    )[0],
};

/** Fund a fresh keypair so it can pay fees. */
export async function fund(
  provider: anchor.AnchorProvider,
  who: PublicKey,
  sol = 5,
) {
  const sig = await provider.connection.requestAirdrop(
    who,
    sol * anchor.web3.LAMPORTS_PER_SOL,
  );
  await provider.connection.confirmTransaction(sig, "confirmed");
}

/**
 * Idempotent config bootstrap. Every test file can call this; only the first one does work.
 * Returns the authority keypair so callers can perform authority-gated actions.
 */
export async function ensureConfig(
  program: Program<RyvoProtocol>,
  provider: anchor.AnchorProvider,
  authority: Keypair,
  feeRecipient: PublicKey,
): Promise<void> {
  // The authority is the rent payer for authority-gated `init` accounts (register_token), so it
  // needs lamports of its own — Anchor's provider wallet pays fees but not another account's rent.
  const balance = await provider.connection.getBalance(authority.publicKey);
  if (balance < anchor.web3.LAMPORTS_PER_SOL) {
    await fund(provider, authority.publicKey, 10);
  }

  const configPda = seeds.config(program.programId);
  const existing = await provider.connection.getAccountInfo(configPda);
  if (existing) return;

  const upgradeAuthority = localWallet();
  await program.methods
    .initialize(
      CHAIN_ID,
      FEE_BPS,
      new anchor.BN(CHANNEL_TIMELOCK),
      authority.publicKey,
      feeRecipient,
    )
    .accounts({
      payer: upgradeAuthority.publicKey,
      config: configPda,
      programData: seeds.programData(program.programId),
      systemProgram: SystemProgram.programId,
    })
    .signers([upgradeAuthority])
    .rpc();
}

/** Create a legacy SPL mint owned by the local wallet. */
export async function newMint(
  provider: anchor.AnchorProvider,
  decimals = 6,
): Promise<PublicKey> {
  const payer = localWallet();
  return createMint(
    provider.connection,
    payer,
    payer.publicKey,
    null,
    decimals,
    undefined,
    { commitment: "confirmed" },
    TOKEN_PROGRAM_ID,
  );
}

/** Assert a promise rejects, optionally matching the error text. */
export async function expectReject(
  p: Promise<unknown>,
  match?: RegExp | string,
): Promise<string> {
  try {
    await p;
  } catch (e) {
    const msg = `${e}`;
    if (match) {
      const ok =
        typeof match === "string" ? msg.includes(match) : match.test(msg);
      if (!ok) {
        throw new Error(`rejected, but not with ${match}. Got: ${msg}`);
      }
    }
    return msg;
  }
  throw new Error("expected a rejection, but the call succeeded");
}
