/**
 * Finish every batch of ours that was verified but never (fully) settled — e.g. after a relayer
 * crash — using only what is on-chain: the staged channel addresses in the buffer, the bitmap in
 * the ClearingResult, and the payee's balance PDA derived from the channel. Then close the buffer.
 * Settles in legacy transactions packed under the 64-account-lock limit.
 *
 *   ANCHOR_PROVIDER_URL=<helius devnet> ARCIUM_CLUSTER_OFFSET=456 npx ts-node -T -P tsconfig.json scripts/settle-leftovers.ts
 */
import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { Keypair, PublicKey } from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { N_ROUTE, N_UNI, bitmapBits, clearingPda, closeStaging, settle } from "../tests-arcium/clearing-client";

const KIND_UNILATERAL = 1, KIND_ROUTE = 2;
const MAX_UNIQUE_ACCOUNTS = 64; // tx account-lock limit (the 128 feature is inactive on devnet and mainnet)
const LEGACY_ACCOUNT_BUDGET = 30; // what fits a 1,232-byte legacy tx without a lookup table

(async () => {
  const connection = new anchor.web3.Connection(process.env.ANCHOR_PROVIDER_URL!, "confirmed");
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8"))));
  const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(payer), { commitment: "confirmed" });
  anchor.setProvider(provider);
  const idl = JSON.parse(fs.readFileSync("target/idl/ryvo_protocol.json", "utf8"));
  const program = new Program<RyvoProtocol>(idl, provider);
  const start = await connection.getBalance(payer.publicKey);

  const bufs = (await program.account.stagingBuffer.all()).filter((b) => b.account.relayer.equals(payer.publicKey));
  console.log(`${bufs.length} staging buffers of ours`);
  for (const b of bufs) {
    const staging = b.publicKey;
    const s = b.account;
    const result = await program.account.clearingResult.fetch(clearingPda(program.programId, staging));
    const count = result.count;
    if (s.sealed === 1 && result.verified && !result.failed) {
      const bits = bitmapBits(result.bitmap as number[], count);
      const applied = bitmapBits(result.applied as number[], count);
      const todo = bits.map((v, i) => (v && !applied[i] ? i : -1)).filter((i) => i >= 0);
      console.log(`${staging.toBase58()}: kind=${s.kind} count=${count} verified; ${todo.length} still to settle`);
      // accounts per index from the buffer's channel columns + the channels' payee balance
      const N = s.kind === KIND_ROUTE ? N_ROUTE : N_UNI;
      const slots = s.slots as number[][];
      const key = (col: number, i: number) => new PublicKey(Buffer.from(slots[col + i]));
      const accountsFor = new Map<number, PublicKey[]>();
      for (const i of todo) {
        if (s.kind === KIND_ROUTE) {
          const chAg = key(12 * N, i), chGp = key(13 * N, i);
          const gp = await program.account.channel.fetch(chGp);
          const bal = PublicKey.findProgramAddressSync([Buffer.from("balance"), gp.payee.toBuffer(), gp.mint.toBuffer()], program.programId)[0];
          const pool = PublicKey.findProgramAddressSync([Buffer.from("pool"), gp.payer.toBuffer(), gp.mint.toBuffer()], program.programId)[0];
          accountsFor.set(i, [chAg, chGp, pool, bal]);
        } else {
          const ch = key(6 * N, i);
          const c = await program.account.channel.fetch(ch);
          const bal = PublicKey.findProgramAddressSync([Buffer.from("balance"), c.payee.toBuffer(), c.mint.toBuffer()], program.programId)[0];
          accountsFor.set(i, [ch, bal]);
        }
      }
      // pack under the lock limit and the legacy size
      let chunk: number[] = [];
      let uniq = new Set<string>();
      const flush = async () => {
        if (!chunk.length) return;
        await settle(program, staging, chunk, (i) => accountsFor.get(i)!);
        console.log(`  settled ${chunk.length} (${uniq.size + 5} unique accounts)`);
        chunk = []; uniq = new Set();
      };
      for (const i of todo) {
        const next = new Set(uniq);
        accountsFor.get(i)!.forEach((k) => next.add(k.toBase58()));
        if (next.size + 5 > Math.min(MAX_UNIQUE_ACCOUNTS, LEGACY_ACCOUNT_BUDGET)) await flush();
        accountsFor.get(i)!.forEach((k) => uniq.add(k.toBase58()));
        chunk.push(i);
      }
      await flush();
    }
    try { await closeStaging(program, payer, staging); console.log(`  closed ${staging.toBase58()}`); }
    catch (e: any) { console.log(`  could not close ${staging.toBase58()}: ${String(e?.message).slice(0, 100)}`); }
  }
  const end = await connection.getBalance(payer.publicKey);
  console.log(`recovered ${((end - start) / 1e9).toFixed(4)} SOL; balance ${(end / 1e9).toFixed(4)} SOL`);
})();
