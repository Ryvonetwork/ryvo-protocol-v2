import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { expect } from "chai";
import { createHash } from "crypto";
import * as fs from "fs";
import * as os from "os";
import {
  fund,
  protocolAuthority,
  protocolFeeRecipient,
  setupProvider,
} from "./shared";

const BPF_LOADER_UPGRADEABLE = new PublicKey(
  "BPFLoaderUpgradeab1e11111111111111111111111",
);

/** Independent TS derivation of the message domain. Must agree with the on-chain value. */
function deriveMessageDomain(programId: PublicKey, chainId: number): Buffer {
  const chainLe = Buffer.alloc(2);
  chainLe.writeUInt16LE(chainId);
  return createHash("sha256")
    .update(Buffer.concat([
      Buffer.from("ryvo-message-domain-v1"),
      programId.toBuffer(),
      chainLe,
    ]))
    .digest()
    .subarray(0, 16);
}

function localWallet(): Keypair {
  return Keypair.fromSecretKey(
    new Uint8Array(
      JSON.parse(fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8")),
    ),
  );
}

describe("ryvo_protocol / step 3: config and authority", () => {
  const provider = setupProvider();
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;

  const upgradeAuthority = localWallet();
  const [configPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("config")],
    program.programId,
  );
  const [programData] = PublicKey.findProgramAddressSync(
    [program.programId.toBuffer()],
    BPF_LOADER_UPGRADEABLE,
  );

  const CHAIN_ID = 0; // localnet
  const FEE_BPS = 30;
  const CHANNEL_TIMELOCK = 2;

  // Deterministic so later test files can sign as the authority. See tests/shared.ts.
  const authority = protocolAuthority();
  const feeRecipient = protocolFeeRecipient();
  const successor = Keypair.generate();

  const init = (overrides: Partial<{
    chainId: number;
    feeBps: number;
    channelTimelock: number;
    initialAuthority: PublicKey;
    feeRecipient: PublicKey;
    payer: Keypair;
  }> = {}) => {
    const payer = overrides.payer ?? upgradeAuthority;
    return program.methods
      .initialize(
        overrides.chainId ?? CHAIN_ID,
        overrides.feeBps ?? FEE_BPS,
        new anchor.BN(overrides.channelTimelock ?? CHANNEL_TIMELOCK),
        overrides.initialAuthority ?? authority.publicKey,
        overrides.feeRecipient ?? feeRecipient.publicKey,
      )
      .accounts({ payer: payer.publicKey, config: configPda, programData, systemProgram: SystemProgram.programId })
      .signers([payer]);
  };

  it("rejects a caller that is not the program upgrade authority", async () => {
    // This is the front-run guard: Config sits at a fixed seed with no natural gate.
    const stranger = Keypair.generate();
    await provider.connection.requestAirdrop(stranger.publicKey, 2_000_000_000);
    await new Promise((r) => setTimeout(r, 1200));

    let failed = false;
    try {
      await init({ payer: stranger }).rpc();
    } catch (e) {
      failed = true;
      expect(`${e}`).to.match(/UnauthorizedInitializer|ConstraintSeeds|not been initialized/);
    }
    expect(failed, "a stranger was able to initialize the config").to.be.true;
  });

  it("rejects out-of-range parameters", async () => {
    for (const [label, o] of [
      ["chain_id 4", { chainId: 4 }],
      ["fee_bps 31", { feeBps: 31 }],
      ["channel timelock 30d+1", { channelTimelock: 30 * 24 * 60 * 60 + 1 }],
      ["default authority", { initialAuthority: PublicKey.default }],
      ["default fee recipient", { feeRecipient: PublicKey.default }],
    ] as const) {
      let failed = false;
      try {
        await init(o as any).rpc();
      } catch {
        failed = true;
      }
      expect(failed, `${label} was accepted`).to.be.true;
    }
  });

  it("initializes and derives message_domain in-program", async () => {
    await init().rpc();
    const cfg = await program.account.config.fetch(configPda);

    expect(cfg.authority.toBase58()).to.equal(authority.publicKey.toBase58());
    expect(cfg.pendingAuthority.toBase58()).to.equal(PublicKey.default.toBase58());
    expect(cfg.feeRecipient.toBase58()).to.equal(feeRecipient.publicKey.toBase58());
    expect(cfg.feeBps).to.equal(FEE_BPS);
    expect(cfg.chainId).to.equal(CHAIN_ID);
    expect(cfg.channelTimelockSeconds.toNumber()).to.equal(CHANNEL_TIMELOCK);

    // The whole point of deriving rather than accepting it as an argument.
    const expected = deriveMessageDomain(program.programId, CHAIN_ID);
    expect(Buffer.from(cfg.messageDomain)).to.deep.equal(expected);
  });

  it("cannot be initialized twice", async () => {
    let failed = false;
    try {
      await init().rpc();
    } catch {
      failed = true;
    }
    expect(failed).to.be.true;
  });

  it("exposes no way to mutate chain_id, message_domain, or the timelocks", () => {
    const norm = (s: string) => s.replace(/_/g, "").toLowerCase();
    const ix = program.idl.instructions.find(
      (i) => norm(i.name) === norm("update_config"),
    );
    expect(ix, "update_config missing from the IDL").to.not.be.undefined;
    const argNames = ix!.args.map((a) => a.name.toLowerCase());
    for (const forbidden of ["chain", "domain", "timelock"]) {
      expect(
        argNames.some((n) => n.includes(forbidden)),
        `update_config must not accept a ${forbidden} argument`,
      ).to.be.false;
    }
  });

  it("updates only the mutable subset, and only for the authority", async () => {
    const before = await program.account.config.fetch(configPda);

    let failed = false;
    try {
      await program.methods
        .updateConfig(null, 10, null)
        .accounts({ authority: successor.publicKey, config: configPda })
        .signers([successor])
        .rpc();
    } catch {
      failed = true;
    }
    expect(failed, "a non-authority updated the config").to.be.true;

    const newRecipient = Keypair.generate().publicKey;
    await program.methods
      .updateConfig(newRecipient, 10, null)
      .accounts({ authority: authority.publicKey, config: configPda })
      .signers([authority])
      .rpc();

    const after = await program.account.config.fetch(configPda);
    expect(after.feeBps).to.equal(10);
    expect(after.feeRecipient.toBase58()).to.equal(newRecipient.toBase58());
    // Immutables untouched.
    expect(after.chainId).to.equal(before.chainId);
    expect(Buffer.from(after.messageDomain)).to.deep.equal(Buffer.from(before.messageDomain));
    expect(after.channelTimelockSeconds.toNumber()).to.equal(
      before.channelTimelockSeconds.toNumber(),
    );
  });

  it("rejects a fee above the cap", async () => {
    let failed = false;
    try {
      await program.methods
        .updateConfig(null, 31, null)
        .accounts({ authority: authority.publicKey, config: configPda })
        .signers([authority])
        .rpc();
    } catch (e) {
      failed = true;
      expect(`${e}`).to.include("InvalidFeeBps");
    }
    expect(failed).to.be.true;
  });

  it("hands off authority only via explicit acceptance", async () => {
    let failed = false;
    try {
      await program.methods
        .acceptConfigAuthority()
        .accounts({ pendingAuthority: successor.publicKey, config: configPda })
        .signers([successor])
        .rpc();
    } catch (e) {
      failed = true;
      expect(`${e}`).to.include("NoPendingAuthority");
    }
    expect(failed, "accepted with no nomination outstanding").to.be.true;

    await program.methods
      .updateConfig(null, null, successor.publicKey)
      .accounts({ authority: authority.publicKey, config: configPda })
      .signers([authority])
      .rpc();

    const wrong = Keypair.generate();
    await provider.connection.requestAirdrop(wrong.publicKey, 1_000_000_000);
    await new Promise((r) => setTimeout(r, 1200));
    failed = false;
    try {
      await program.methods
        .acceptConfigAuthority()
        .accounts({ pendingAuthority: wrong.publicKey, config: configPda })
        .signers([wrong])
        .rpc();
    } catch (e) {
      failed = true;
      expect(`${e}`).to.include("UnauthorizedPendingAuthority");
    }
    expect(failed, "the wrong key accepted the handoff").to.be.true;

    await program.methods
      .acceptConfigAuthority()
      .accounts({ pendingAuthority: successor.publicKey, config: configPda })
      .signers([successor])
      .rpc();

    const cfg = await program.account.config.fetch(configPda);
    expect(cfg.authority.toBase58()).to.equal(successor.publicKey.toBase58());
    expect(cfg.pendingAuthority.toBase58()).to.equal(PublicKey.default.toBase58());

    // The old authority is now powerless.
    failed = false;
    try {
      await program.methods
        .updateConfig(null, 5, null)
        .accounts({ authority: authority.publicKey, config: configPda })
        .signers([authority])
        .rpc();
    } catch {
      failed = true;
    }
    expect(failed, "the previous authority retained power").to.be.true;

    // Restore the canonical authority, and the fee settings later files expect. Test files share
    // one validator, so leaving authority with a throwaway key would break every later file.
    await fund(provider, successor.publicKey, 2);
    await program.methods
      .updateConfig(null, null, authority.publicKey)
      .accounts({ authority: successor.publicKey, config: configPda })
      .signers([successor])
      .rpc();
    await program.methods
      .acceptConfigAuthority()
      .accounts({ pendingAuthority: authority.publicKey, config: configPda })
      .signers([authority])
      .rpc();
    await program.methods
      .updateConfig(feeRecipient.publicKey, FEE_BPS, null)
      .accounts({ authority: authority.publicKey, config: configPda })
      .signers([authority])
      .rpc();

    const restored = await program.account.config.fetch(configPda);
    expect(restored.authority.toBase58()).to.equal(authority.publicKey.toBase58());
    expect(restored.feeBps).to.equal(FEE_BPS);
    expect(restored.feeRecipient.toBase58()).to.equal(feeRecipient.publicKey.toBase58());
  });
});
