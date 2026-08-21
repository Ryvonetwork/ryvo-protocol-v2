import { createHash } from "crypto";
import { Connection, PublicKey } from "@solana/web3.js";

const CONFIG_SIZE = 8 + 32 + 32 + 16 + 8 + 2 + 8 + 8 + 1 + 112;
const CONFIG_DISCRIMINATOR = createHash("sha256")
  .update("account:Config")
  .digest()
  .subarray(0, 8);
const DEFAULT_PUBKEY = new PublicKey(new Uint8Array(32));
const KNOWN_GENESIS_HASHES: Readonly<Partial<Record<number, string>>> = {
  1: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
  2: "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
  3: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
};

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`set ${name}`);
  return value;
}

function expectedInteger(name: string, maximum: number): number {
  const raw = required(name);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new Error(`${name} must be an integer from 0 to ${maximum}`);
  }
  return value;
}

function equal(
  actual: string | number,
  expected: string | number,
  label: string
) {
  if (actual !== expected) {
    throw new Error(`${label} is ${actual}, expected ${expected}`);
  }
}

async function main() {
  const rpcUrl = required("RPC_URL");
  const programId = new PublicKey(required("PROGRAM_ID"));
  const expectedAuthority = new PublicKey(
    required("EXPECTED_CONFIG_AUTHORITY")
  );
  const expectedChainId = expectedInteger("EXPECTED_CHAIN_ID", 3);
  const expectedTimelock = expectedInteger(
    "EXPECTED_TIMELOCK_SECONDS",
    30 * 24 * 60 * 60
  );
  const connection = new Connection(rpcUrl, "confirmed");

  const expectedGenesisHash = KNOWN_GENESIS_HASHES[expectedChainId];
  if (expectedGenesisHash) {
    const genesisHash = await connection.getGenesisHash();
    equal(genesisHash, expectedGenesisHash, "RPC genesis hash");
  }

  const program = await connection.getAccountInfo(programId, "confirmed");
  if (!program?.executable) {
    throw new Error(
      `program ${programId.toBase58()} is absent or not executable`
    );
  }

  const [configPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("config")],
    programId
  );
  const account = await connection.getAccountInfo(configPda, "confirmed");
  if (!account) {
    throw new Error(`Config ${configPda.toBase58()} is not initialized`);
  }
  if (!account.owner.equals(programId)) {
    throw new Error(
      `Config owner is ${account.owner.toBase58()}, expected ${programId.toBase58()}`
    );
  }
  equal(account.data.length, CONFIG_SIZE, "Config size");
  if (!account.data.subarray(0, 8).equals(CONFIG_DISCRIMINATOR)) {
    throw new Error("Config discriminator is invalid");
  }

  let offset = 8;
  const authority = new PublicKey(
    account.data.subarray(offset, (offset += 32))
  );
  const pendingAuthority = new PublicKey(
    account.data.subarray(offset, (offset += 32))
  );
  const messageDomain = account.data.subarray(offset, (offset += 16));
  const timelock = Number(account.data.readBigInt64LE(offset));
  offset += 8;
  const chainId = account.data.readUInt16LE(offset);
  offset += 2;
  const nextParticipantId = account.data.readBigUInt64LE(offset);
  offset += 8;
  const nextChannelId = account.data.readBigUInt64LE(offset);

  equal(authority.toBase58(), expectedAuthority.toBase58(), "Config authority");
  equal(
    pendingAuthority.toBase58(),
    DEFAULT_PUBKEY.toBase58(),
    "pending Config authority"
  );
  equal(chainId, expectedChainId, "chain id");
  equal(timelock, expectedTimelock, "channel timelock");
  if (nextParticipantId < 1n || nextChannelId < 1n) {
    throw new Error("Config counters are not initialized");
  }

  const chainLe = Buffer.alloc(2);
  chainLe.writeUInt16LE(chainId);
  const expectedDomain = createHash("sha256")
    .update(
      Buffer.concat([
        Buffer.from("ryvo-message-domain-v1"),
        programId.toBuffer(),
        chainLe,
      ])
    )
    .digest()
    .subarray(0, 16);
  if (!messageDomain.equals(expectedDomain)) {
    throw new Error(
      `message domain is ${messageDomain.toString(
        "hex"
      )}, expected ${expectedDomain.toString("hex")}`
    );
  }

  console.log(
    `Verified Config ${configPda.toBase58()}: authority ${authority.toBase58()}, chain ${chainId}, timelock ${timelock}s`
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
