/**
 * Measure what the last devnet gateway run actually cost, from the chain: every transaction the
 * wallet signed, classified by instruction, with fee, lamport delta (fee + Arcium computation fee
 * + rent) and compute units. Run after scripts/devnet-gateway.ts.
 *
 *   ANCHOR_PROVIDER_URL=<helius devnet> npx ts-node -T -P tsconfig.json scripts/devnet-costs.ts [maxTx]
 */
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";

const PROGRAM_ID = new PublicKey("DD7m7B1FggiCQCURQ2pNXyDtPZPRdJYYgq9dthtaJtii");
const CLEARING = ["ResetStaging", "StageSlots", "StageChannels", "SealAndQueueRoute", "SealAndQueueUnilateral", "SettleChannels", "OpenStaging", "CloseStaging"];

(async () => {
  const connection = new Connection(process.env.ANCHOR_PROVIDER_URL!, "confirmed");
  const wallet = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8")))).publicKey;
  const max = Number(process.argv[2] ?? 600);
  const sigs: { signature: string; blockTime?: number | null }[] = [];
  let before: string | undefined;
  while (sigs.length < max) {
    const page = await connection.getSignaturesForAddress(wallet, { before, limit: Math.min(1000, max - sigs.length) });
    if (!page.length) break;
    sigs.push(...page);
    before = page[page.length - 1].signature;
  }
  console.log(`${sigs.length} recent wallet transactions`);

  type Row = { kind: string; fee: number; delta: number; cu: number; n: number; arciumFee: number };
  const rows = new Map<string, Row>();
  const add = (kind: string, fee: number, delta: number, cu: number, arciumFee = 0) => {
    const r = rows.get(kind) ?? { kind, fee: 0, delta: 0, cu: 0, n: 0, arciumFee: 0 };
    r.fee += fee; r.delta += delta; r.cu += cu; r.n++; r.arciumFee += arciumFee;
    rows.set(kind, r);
  };
  // newest first; stop at the first "OpenStaging" of the run (the smoke opens one buffer per run) —
  // we walk back until we have seen the run's open_staging, then keep going for the setup txs? No:
  // only the clearing path is wanted, so we stop at open_staging.
  // argv[3] = how many most-recent runs to skip (each run starts, walking backwards, at its open_staging)
  let skip = Number(process.argv[3] ?? 0);
  let stop = false;
  for (let i = 0; i < sigs.length && !stop; i += 20) {
    const batch = sigs.slice(i, i + 20);
    const txs = await Promise.all(batch.map((s) => connection.getTransaction(s.signature, { maxSupportedTransactionVersion: 0, commitment: "confirmed" })));
    for (const tx of txs) {
      if (!tx || !tx.meta || tx.meta.err) continue;
      const logs = tx.meta.logMessages ?? [];
      const ixNames = logs.filter((l) => l.includes("Instruction: ")).map((l) => l.split("Instruction: ")[1].trim());
      const mine = ixNames.filter((n) => CLEARING.includes(n));
      if (!mine.length) continue;
      const fee = tx.meta.fee;
      const keys = tx.transaction.message.staticAccountKeys ?? (tx.transaction.message as any).accountKeys;
      const idx = keys.findIndex((k: PublicKey) => k.equals(wallet));
      const delta = tx.meta.preBalances[idx] - tx.meta.postBalances[idx];
      const cu = tx.meta.computeUnitsConsumed ?? 0;
      // primary label: the most specific instruction in the tx
      const label = mine.includes("SealAndQueueRoute") ? "seal_and_queue (+tail stage_slots)"
        : mine.includes("SettleChannels") ? "settle_channels"
        : mine.includes("StageChannels") ? "stage_channels"
        : mine.includes("ResetStaging") ? "stage_slots (+reset_staging)"
        : mine.includes("StageSlots") ? "stage_slots"
        : mine.includes("CloseStaging") ? "close_staging"
        : "open_staging";
      const arciumFee = label.startsWith("seal") ? delta - fee : 0;
      if (label === "open_staging") {
        if (skip > 0) { skip--; rows.clear(); continue; }
        stop = true;
      }
      if (skip > 0) continue;
      add(label, fee, delta, cu, arciumFee);
    }
  }
  let tFee = 0, tDelta = 0, tCu = 0, tN = 0;
  console.log("| instruction | tx | fees (SOL) | Arcium fee (SOL) | total paid (SOL) | CU total | CU/tx |");
  console.log("|---|---|---|---|---|---|---|");
  for (const r of [...rows.values()].sort((a, b) => b.n - a.n)) {
    console.log(`| ${r.kind} | ${r.n} | ${(r.fee / 1e9).toFixed(6)} | ${(r.arciumFee / 1e9).toFixed(6)} | ${(r.delta / 1e9).toFixed(6)} | ${r.cu.toLocaleString()} | ${Math.round(r.cu / r.n).toLocaleString()} |`);
    tFee += r.fee; tDelta += r.delta; tCu += r.cu; tN += r.n;
  }
  console.log(`| TOTAL | ${tN} | ${(tFee / 1e9).toFixed(6)} | | ${(tDelta / 1e9).toFixed(6)} | ${tCu.toLocaleString()} | |`);
})();
