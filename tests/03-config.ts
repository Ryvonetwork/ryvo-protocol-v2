import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { expect } from "chai";
import { createHash } from "crypto";
import { fund, localWallet, protocolAuthority, seeds, setupProvider } from "./shared";

/** Independent TS derivation of the message domain. Must agree with the on-chain value. */
function deriveMessageDomain(programId: PublicKey, chainId: number): Buffer {
  const chainLe = Buffer.alloc(2);
  chainLe.writeUInt16LE(chainId);
  return createHash("sha256")
    .update(
      Buffer.concat([
        Buffer.from("ryvo-message-domain-v1"),
        programId.toBuffer(),
        chainLe,
      ]),
    )
    .digest()
    .subarray(0, 16);
}

describe("ryvo_protocol / step 3: config and authority", () => {
  const provider = setupProvider();
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;

  const upgradeAuthority = localWallet();
  const configPda = seeds.config(program.programId);
  const programData = seeds.programData(program.programId);

  const CHAIN_ID = 0; // localnet
  const CHANNEL_TIMELOCK = 2;

  // Deterministic so later test files can sign as the authority. See tests/shared.ts.
  const authority = protocolAuthority();
  const successor = Keypair.generate();

  const init = (
    overrides: Partial<{
      chainId: number;
      channelTimelock: number;
      initialAuthority: PublicKey;
      payer: Keypair;
    }> = {},
  ) => {
    const payer = overrides.payer ?? upgradeAuthority;
    return program.methods
      .initialize(
        overrides.chainId ?? CHAIN_ID,
        new anchor.BN(overrides.channelTimelock ?? CHANNEL_TIMELOCK),
        overrides.initialAuthority ?? authority.publicKey,
      )
      .accounts({
        payer: payer.publicKey,
        config: configPda,
        programData,
        systemProgram: SystemProgram.programId,
      })
      .signers([payer]);
  };

  it("rejects a caller that is not the program upgrade authority", async () => {
    // This is the front-run guard: Config sits at a fixed seed with no natural gate.
    const stranger = Keypair.generate();
    await fund(provider, stranger.publicKey, 2);

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
      ["channel timelock 30d+1", { channelTimelock: 30 * 24 * 60 * 60 + 1 }],
      ["default authority", { initialAuthority: PublicKey.default }],
    ] as const) {
      let failed = false;
      try {
        await init(o as never).rpc();
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
    expect(cfg.chainId).to.equal(CHAIN_ID);
    expect(cfg.channelTimelockSeconds.toNumber()).to.equal(CHANNEL_TIMELOCK);

    // The whole point of deriving rather than accepting it as an argument.
    expect(Buffer.from(cfg.messageDomain)).to.deep.equal(
      deriveMessageDomain(program.programId, CHAIN_ID),
    );
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

  it("carries no fee state at all", async () => {
    // The protocol takes no cut: a payment moves numbers between ledger rows and the tokens never
    // leave the vault, so there is nothing on-chain to charge for.
    const norm = (s: string) => s.replace(/_/g, "").toLowerCase();
    const configType = program.idl.types.find((t) => norm(t.name) === "config")!;
    const fields = (configType.type as never as { fields: { name: string }[] }).fields;
    for (const f of fields) {
      expect(norm(f.name), `Config still has a fee field: ${f.name}`).to.not.include("fee");
    }
    const ixNames = program.idl.instructions.map((i) => norm(i.name));
    expect(ixNames).to.not.include(norm("withdraw_protocol_fees"));
  });

  it("exposes no setter for chain_id, message_domain, or the timelock", () => {
    const norm = (s: string) => s.replace(/_/g, "").toLowerCase();
    const ix = program.idl.instructions.find(
      (i) => norm(i.name) === norm("nominate_authority"),
    );
    expect(ix, "nominate_authority missing from the IDL").to.not.be.undefined;
    // Its only argument is the successor; there is no other config mutation instruction.
    expect(ix!.args).to.have.length(1);
    for (const other of program.idl.instructions) {
      const args = other.args.map((a) => a.name.toLowerCase()).join(" ");
      for (const forbidden of ["chain", "domain", "timelock"]) {
        if (norm(other.name) === norm("initialize")) continue;
        expect(
          args.includes(forbidden),
          `${other.name} must not accept a ${forbidden} argument`,
        ).to.be.false;
      }
    }
  });

  it("nominates only for the authority", async () => {
    let failed = false;
    try {
      await program.methods
        .nominateAuthority(successor.publicKey)
        .accounts({ authority: successor.publicKey, config: configPda })
        .signers([successor])
        .rpc();
    } catch {
      failed = true;
    }
    expect(failed, "a non-authority nominated a successor").to.be.true;
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
      .nominateAuthority(successor.publicKey)
      .accounts({ authority: authority.publicKey, config: configPda })
      .signers([authority])
      .rpc();

    const wrong = Keypair.generate();
    await fund(provider, wrong.publicKey, 1);
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
        .nominateAuthority(authority.publicKey)
        .accounts({ authority: authority.publicKey, config: configPda })
        .signers([authority])
        .rpc();
    } catch {
      failed = true;
    }
    expect(failed, "the previous authority retained power").to.be.true;

    // Restore the canonical authority. Test files share one validator, so leaving it with a
    // throwaway key would break every later file.
    await fund(provider, successor.publicKey, 2);
    await program.methods
      .nominateAuthority(authority.publicKey)
      .accounts({ authority: successor.publicKey, config: configPda })
      .signers([successor])
      .rpc();
    await program.methods
      .acceptConfigAuthority()
      .accounts({ pendingAuthority: authority.publicKey, config: configPda })
      .signers([authority])
      .rpc();

    const restored = await program.account.config.fetch(configPda);
    expect(restored.authority.toBase58()).to.equal(authority.publicKey.toBase58());
  });
});
