/**
 * Reclaim the rent of finished Arcium computation accounts we paid for. Walks the wallet's recent
 * seal_and_queue transactions, reads the computation offset from the instruction data and calls
 * Arcium's claim_computation_rent for each account that still exists.
 *
 *   ANCHOR_PROVIDER_URL=<helius devnet> ARCIUM_CLUSTER_OFFSET=456 npx ts-node -T -P tsconfig.json scripts/reclaim-computations.ts [maxTx]
 */
import * as anchor from "@anchor-lang/core";
import { Keypair, PublicKey } from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";
import { claimComputationRent, getComputationAccAddress } from "@arcium-hq/client";

(async () => {
  const connection = new anchor.web3.Connection(process.env.ANCHOR_PROVIDER_URL!, "confirmed");
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8"))));
  const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(payer), { commitment: "confirmed" });
  const clusterOffset = Number(process.env.ARCIUM_CLUSTER_OFFSET ?? 456);
  const programId = new PublicKey("DD7m7B1FggiCQCURQ2pNXyDtPZPRdJYYgq9dthtaJtii");
  const max = Number(process.argv[2] ?? 1000);
  const sigs: string[] = [];
  let before: string | undefined;
  while (sigs.length < max) {
    const page = await connection.getSignaturesForAddress(payer.publicKey, { before, limit: Math.min(1000, max - sigs.length) });
    if (!page.length) break;
    sigs.push(...page.map((p) => p.signature));
    before = page[page.length - 1].signature;
  }
  const start = await connection.getBalance(payer.publicKey);
  let found = 0, claimed = 0, kept = 0;
  for (let i = 0; i < sigs.length; i += 20) {
    const txs = await Promise.all(sigs.slice(i, i + 20).map((s) => connection.getTransaction(s, { maxSupportedTransactionVersion: 0, commitment: "confirmed" })));
    for (const tx of txs) {
      if (!tx?.meta || tx.meta.err) continue;
      const logs = tx.meta.logMessages ?? [];
      if (!logs.some((l) => /Instruction: SealAndQueue/.test(l))) continue;
      const keys = tx.transaction.message.staticAccountKeys;
      for (const ix of tx.transaction.message.compiledInstructions) {
        if (!keys[ix.programIdIndex].equals(programId)) continue;
        const data = Buffer.from(ix.data);
        if (data.length < 16) continue;
        const offset = new anchor.BN(data.subarray(8, 16), "le");
        const comp = getComputationAccAddress(clusterOffset, offset);
        const info = await connection.getAccountInfo(comp);
        if (!info) continue;
        found++;
        try {
          await claimComputationRent(provider as any, clusterOffset, offset);
          claimed++;
          console.log(`claimed ${comp.toBase58()} (${info.lamports} lamports)`);
        } catch (e: any) {
          kept++;
          console.log(`kept ${comp.toBase58()}: ${String(e?.message).slice(0, 120)}`);
        }
      }
    }
  }
  const end = await connection.getBalance(payer.publicKey);
  console.log(`${found} live computation accounts, ${claimed} claimed, ${kept} kept; wallet ${((end - start) / 1e9).toFixed(6)} SOL net (${end / 1e9} SOL)`);
})();
