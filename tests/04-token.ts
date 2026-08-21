import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_RENT_PUBKEY,
} from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  createMint,
} from "@solana/spl-token";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { expect } from "chai";
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

describe("ryvo_protocol / step 4: token registration and vault", () => {
  const provider = setupProvider();
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;

  const authority = protocolAuthority();
  const configPda = seeds.config(program.programId);
  const payer = localWallet();

  let mint: PublicKey;

  before(async () => {
    await ensureConfig(program, provider, authority);
    mint = await newMint(provider, 6);
  });

  const register = (
    m: PublicKey,
    who = authority,
    tokenProgram = TOKEN_PROGRAM_ID
  ) =>
    program.methods
      .registerToken()
      .accountsPartial({
        authority: who.publicKey,
        config: configPda,
        mint: m,
        tokenConfig: seeds.tokenConfig(program.programId, m),
        vault: seeds.vault(program.programId, m),
        tokenProgram,
        systemProgram: SystemProgram.programId,
        rent: SYSVAR_RENT_PUBKEY,
      })
      .signers([who]);

  it("registers a mint and creates its vault under the token config authority", async () => {
    await register(mint).rpc();

    const tc = await program.account.tokenConfig.fetch(
      seeds.tokenConfig(program.programId, mint)
    );
    expect(tc.mint.toBase58()).to.equal(mint.toBase58());
    expect(tc.vault.toBase58()).to.equal(
      seeds.vault(program.programId, mint).toBase58()
    );
    expect(tc.decimals).to.equal(6);
    expect(tc.depositsEnabled).to.be.true;

    // The vault must be owned by the per-mint token config, not the global config.
    const vault = await provider.connection.getTokenAccountBalance(
      seeds.vault(program.programId, mint)
    );
    expect(vault.value.amount).to.equal("0");

    const raw = await provider.connection.getParsedAccountInfo(
      seeds.vault(program.programId, mint)
    );
    const info = (raw.value?.data as any).parsed.info;
    expect(info.mint).to.equal(mint.toBase58());
    expect(info.owner).to.equal(
      seeds.tokenConfig(program.programId, mint).toBase58()
    );
  });

  it("refuses to register the same mint twice", async () => {
    await expectReject(register(mint).rpc());
  });

  it("refuses a non-authority", async () => {
    const stranger = Keypair.generate();
    await fund(provider, stranger.publicKey, 2);
    const other = await newMint(provider, 6);
    await expectReject(register(other, stranger).rpc());
  });

  it("refuses a mint with more than 9 decimals", async () => {
    const wide = await newMint(provider, 10);
    await expectReject(register(wide).rpc(), /InvalidTokenDecimals/);
  });

  it("refuses a token-2022 mint, proving the legacy-only posture", async () => {
    // Transfer fees, transfer hooks and confidential transfers would each break
    // vault.amount == sum(available) + sum(locked).
    const t22 = await createMint(
      provider.connection,
      payer,
      payer.publicKey,
      null,
      6,
      undefined,
      { commitment: "confirmed" },
      TOKEN_2022_PROGRAM_ID
    );
    await expectReject(register(t22, authority, TOKEN_2022_PROGRAM_ID).rpc());
    // ...and also when the caller lies about the token program.
    await expectReject(register(t22, authority, TOKEN_PROGRAM_ID).rpc());
  });

  it("toggles enabled without touching anything else", async () => {
    const tokenConfig = seeds.tokenConfig(program.programId, mint);
    const before = await program.account.tokenConfig.fetch(tokenConfig);

    await program.methods
      .setTokenDepositEnabled(false)
      .accountsPartial({
        authority: authority.publicKey,
        config: configPda,
        tokenConfig,
      })
      .signers([authority])
      .rpc();

    let tc = await program.account.tokenConfig.fetch(tokenConfig);
    expect(tc.depositsEnabled).to.be.false;
    expect(tc.mint.toBase58()).to.equal(before.mint.toBase58());
    expect(tc.vault.toBase58()).to.equal(before.vault.toBase58());
    expect(tc.decimals).to.equal(before.decimals);

    await program.methods
      .setTokenDepositEnabled(true)
      .accountsPartial({
        authority: authority.publicKey,
        config: configPda,
        tokenConfig,
      })
      .signers([authority])
      .rpc();
    tc = await program.account.tokenConfig.fetch(tokenConfig);
    expect(tc.depositsEnabled).to.be.true;
  });
});
