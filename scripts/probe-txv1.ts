/**
 * Does the cluster accept transaction v1? Sends a 1-lamport self-transfer as v1, then a
 * ~3.5 KB memo-sized v1 to prove the size limit. Prints the result.
 *   ANCHOR_PROVIDER_URL=<rpc> npx ts-node scripts/probe-txv1.ts
 */
import { Connection, Keypair, PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";
import { sendV1 } from "../tests-arcium/txv1";

const MEMO = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

(async () => {
  const url = process.env.ANCHOR_PROVIDER_URL ?? "http://127.0.0.1:8899";
  const c = new Connection(url, "confirmed");
  const kp = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8"))));
  console.log("cluster:", (await c.getVersion())["solana-core"]);

  try {
    const r = await sendV1(c, [SystemProgram.transfer({ fromPubkey: kp.publicKey, toPubkey: kp.publicKey, lamports: 1 })], [kp], { computeUnitLimit: 50_000 });
    console.log("small v1 OK:", r.signature, r.bytes, "bytes");
  } catch (e: any) {
    console.log("small v1 FAILED:", e.message?.slice(0, 300));
    return;
  }
  try {
    const big = Buffer.alloc(3500, 0x41);
    const ix = new TransactionInstruction({ programId: MEMO, keys: [{ pubkey: kp.publicKey, isSigner: true, isWritable: false }], data: big });
    const r = await sendV1(c, [ix], [kp], { computeUnitLimit: 200_000 });
    console.log("large v1 OK:", r.signature, r.bytes, "bytes");
    const tx = await c.getTransaction(r.signature, { maxSupportedTransactionVersion: 1 } as any);
    console.log("fetched version:", (tx as any)?.version, "CU:", tx?.meta?.computeUnitsConsumed);
  } catch (e: any) {
    console.log("large v1 FAILED:", e.message?.slice(0, 300));
  }
})();
