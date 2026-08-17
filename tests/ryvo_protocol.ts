import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { expect } from "chai";

/**
 * Step 0 smoke test.
 *
 * Proves the toolchain end to end before any protocol logic exists: the program builds,
 * the IDL and generated types regenerate, and the suite runs against a plain local
 * validator with no Arcium localnet and no MXE bootstrap.
 *
 * It also pins the seed constants, which the TS client must read from the IDL rather than
 * re-declare — seed drift between Rust and TS is the most common cause of
 * "account does not exist" bugs in this shape of program.
 */
describe("ryvo_protocol / step 0: toolchain", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;

  const normalize = (s: string) => s.replace(/_/g, "").toLowerCase();

  it("loads the program at the declared address", () => {
    expect(program.programId.toBase58()).to.equal(
      "4kRnxdszLpHvrLzi4EDyyTRAWqkdmANzSGFPqncr2uxc",
    );
  });

  it("exports every PDA seed and domain tag as an IDL constant", () => {
    const constants = program.idl.constants ?? [];
    const names = constants.map((c) => normalize(c.name));

    for (const expected of [
      "configSeed",
      "participantSeed",
      "tokenConfigSeed",
      "vaultSeed",
      "balanceSeed",
      "channelSeed",
      "messageDomainTag",
      "commitmentDigestTag",
    ]) {
      expect(names, `IDL is missing constant ${expected}`).to.include(
        normalize(expected),
      );
    }
  });

  it("has no instructions yet", () => {
    expect(program.idl.instructions).to.have.length(0);
  });
});
