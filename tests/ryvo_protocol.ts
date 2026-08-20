import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { expect } from "chai";
import { setupProvider } from "./shared";

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
  const provider = setupProvider();
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;

  const normalize = (s: string) => s.replace(/_/g, "").toLowerCase();

  it("loads the program at the declared address", () => {
    expect(program.programId.toBase58()).to.equal(
      "9QHMKt6ANEzaCEgzk9p1Vaex2yeLLhaLXNfEYCiGGS2Q"
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
      "messageDomainTag",
      "commitmentDigestTag",
    ]) {
      expect(names, `IDL is missing constant ${expected}`).to.include(
        normalize(expected)
      );
    }
  });

  it("exports stable Direct and Routed channel type values", () => {
    const constants = new Map(
      (program.idl.constants ?? []).map((c) => [normalize(c.name), c.value])
    );
    expect(constants.get(normalize("CHANNEL_KIND_DIRECT"))).to.equal("1");
    expect(constants.get(normalize("CHANNEL_KIND_ROUTED"))).to.equal("2");
  });

  it("declares no account type without reserved growth room", () => {
    // Every non-singleton account must carry reserved bytes so a v2 field addition never
    // forces a realloc of accounts already holding live funds.
    const accounts = program.idl.types.filter((t) =>
      (program.idl.accounts ?? []).some((a) => a.name === t.name)
    );
    // Exempt: the singleton config (checked in Rust); Arcium's own signer PDA (not ours to
    // shape); and the staging buffer, which is a per-batch scratch account that is closed for
    // rent once settled — it never holds funds and never outlives a batch.
    const exempt = new Set(["config", "arciumsigneraccount", "stagingbuffer"]);
    for (const t of accounts) {
      if (exempt.has(normalize(t.name))) continue;
      const fields = (t.type as any).fields ?? [];
      // Anchor's TS layer camelCases IDL names and strips the leading underscore, so compare
      // normalized.
      const reserved = fields.find(
        (f: any) => normalize(f.name) === "reserved"
      );
      expect(reserved, `${t.name} has no reserved field`).to.not.be.undefined;
    }
  });
});
