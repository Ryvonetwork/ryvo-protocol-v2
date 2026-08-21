/**
 * Deterministic throwaway keypairs for devnet runs, so their SOL can always be swept back.
 *
 * A run picks a nonce, records it in ~/.ryvo-devnet-runs.json, and derives every party as
 * sha256("ryvo-devnet-party" | wallet secret | nonce | index). `scripts/sweep-runs.ts` re-derives
 * the parties of every recorded run and returns whatever SOL they still hold. Never use
 * `Keypair.generate()` for funded test accounts: 21.6 SOL of devnet SOL was stranded that way.
 */
import { Keypair } from "@solana/web3.js";
import { createHash } from "crypto";
import * as fs from "fs";
import * as os from "os";

export const RUNS_FILE = `${os.homedir()}/.ryvo-devnet-runs.json`;

export interface RunRecord {
  nonce: number;
  parties: number;
  startedAt: string;
  note?: string;
}

export function partyKeypair(
  wallet: Keypair,
  nonce: number,
  index: number
): Keypair {
  const h = createHash("sha256");
  h.update("ryvo-devnet-party");
  h.update(wallet.secretKey.subarray(0, 32));
  const n = Buffer.alloc(8);
  n.writeBigUInt64LE(BigInt(nonce));
  const i = Buffer.alloc(4);
  i.writeUInt32LE(index);
  h.update(n);
  h.update(i);
  return Keypair.fromSeed(h.digest());
}

export function recordRun(rec: RunRecord) {
  const runs = readRuns();
  runs.push(rec);
  fs.writeFileSync(RUNS_FILE, JSON.stringify(runs, null, 1));
}

export function readRuns(): RunRecord[] {
  try {
    return JSON.parse(fs.readFileSync(RUNS_FILE, "utf8"));
  } catch {
    return [];
  }
}
