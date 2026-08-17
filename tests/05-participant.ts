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
  protocolFeeRecipient,
  seeds,
} from "./shared";

describe("ryvo_protocol / step 5: participants", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;

  const configPda = seeds.config(program.programId);

  before(async () => {
    await ensureConfig(
      program,
      provider,
      protocolAuthority(),
      protocolFeeRecipient().publicKey,
    );
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

  it("registers an identity at the owner-derived PDA, consent-required by default", async () => {
    const owner = Keypair.generate();
    await register(owner);

    const p = await program.account.participant.fetch(
      seeds.participant(program.programId, owner.publicKey),
    );
    expect(p.owner.toBase58()).to.equal(owner.publicKey.toBase58());
    expect(p.inboundChannelPolicy).to.deep.equal({ consentRequired: {} });
  });

  it("leaves the singleton config byte-identical, proving no global counter", async () => {
    // A participant-id counter in Config would write-lock the singleton on every registration,
    // serialising sign-ups and letting a user instruction mutate the fee parameters.
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

  it("lets only the owner change their own policy, and round-trips all three values", async () => {
    const owner = Keypair.generate();
    await register(owner);
    const participant = seeds.participant(program.programId, owner.publicKey);

    const stranger = Keypair.generate();
    await fund(provider, stranger.publicKey, 2);
    await expectReject(
      program.methods
        .updateInboundChannelPolicy({ permissionless: {} })
        .accounts({ owner: stranger.publicKey, participant })
        .signers([stranger])
        .rpc(),
    );

    for (const policy of [
      { permissionless: {} },
      { disabled: {} },
      { consentRequired: {} },
    ]) {
      await program.methods
        .updateInboundChannelPolicy(policy as never)
        .accounts({ owner: owner.publicKey, participant })
        .signers([owner])
        .rpc();
      const p = await program.account.participant.fetch(participant);
      expect(p.inboundChannelPolicy).to.deep.equal(policy);
    }
  });
});
