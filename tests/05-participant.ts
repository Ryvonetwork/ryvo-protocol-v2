import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { Keypair, SystemProgram } from "@solana/web3.js";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { expect } from "chai";
import {
  ensureConfig,
  expectReject,
  fund,
  protocolAuthority,
  setupProvider,
  seeds,
} from "./shared";

describe("ryvo_protocol / step 5: participants", () => {
  const provider = setupProvider();
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;

  const configPda = seeds.config(program.programId);

  before(async () => {
    await ensureConfig(program, provider, protocolAuthority());
  });

  const register = async (owner: Keypair) => {
    await fund(provider, owner.publicKey, 2);
    return program.methods
      .initializeParticipant()
      .accounts({
        owner: owner.publicKey,
        participant: seeds.participant(program.programId, owner.publicKey),
        systemProgram: SystemProgram.programId,
      })
      .signers([owner])
      .rpc();
  };

  it("registers an identity at the owner-derived PDA", async () => {
    const owner = Keypair.generate();
    await register(owner);

    const p = await program.account.participant.fetch(
      seeds.participant(program.programId, owner.publicKey),
    );
    expect(p.owner.toBase58()).to.equal(owner.publicKey.toBase58());
  });

  it("leaves the singleton config byte-identical, proving no global counter", async () => {
    // A participant-id counter in Config would write-lock the singleton on every registration,
    // serialising sign-ups and letting a user instruction mutate the singleton config.
    const before = await provider.connection.getAccountInfo(configPda);
    await register(Keypair.generate());
    await register(Keypair.generate());
    const after = await provider.connection.getAccountInfo(configPda);

    expect(Buffer.compare(before!.data, after!.data)).to.equal(0);
    expect(after!.lamports).to.equal(before!.lamports);
  });

  it("refuses to register the same owner twice, so identity cannot be recycled", async () => {
    const owner = Keypair.generate();
    await register(owner);
    await expectReject(register(owner));
  });

});
