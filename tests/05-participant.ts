import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { Keypair, SystemProgram } from "@solana/web3.js";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { expect } from "chai";
import { deriveArcisSigner } from "./commitment-client";
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
    const signer = new anchor.web3.PublicKey(
      deriveArcisSigner(owner.secretKey.slice(0, 32)).publicKey
    );
    return program.methods
      .initializeParticipant(signer)
      .accounts({
        owner: owner.publicKey,
        config: configPda,
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
      seeds.participant(program.programId, owner.publicKey)
    );
    expect(p.owner.toBase58()).to.equal(owner.publicKey.toBase58());
    expect(p.authorizedSigner.toBase58()).to.equal(
      new anchor.web3.PublicKey(
        deriveArcisSigner(owner.secretKey.slice(0, 32)).publicKey
      ).toBase58()
    );
    expect(p.participantId.toNumber()).to.be.greaterThan(0);
  });

  it("assigns permanent increasing participant ids", async () => {
    const before = await program.account.config.fetch(configPda);
    await register(Keypair.generate());
    await register(Keypair.generate());
    const after = await program.account.config.fetch(configPda);
    expect(after.nextParticipantId.toNumber()).to.equal(
      before.nextParticipantId.toNumber() + 2
    );
  });

  it("rejects the default Arcis signer", async () => {
    const owner = Keypair.generate();
    await fund(provider, owner.publicKey, 2);
    await expectReject(
      program.methods
        .initializeParticipant(anchor.web3.PublicKey.default)
        .accounts({
          owner: owner.publicKey,
          config: configPda,
          participant: seeds.participant(program.programId, owner.publicKey),
          systemProgram: SystemProgram.programId,
        })
        .signers([owner])
        .rpc(),
      /InvalidAuthorizedSigner/
    );
  });

  it("refuses to register the same owner twice, so identity cannot be recycled", async () => {
    const owner = Keypair.generate();
    await register(owner);
    await expectReject(register(owner));
  });
});
