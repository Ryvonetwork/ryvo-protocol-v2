/** Show where the lamports went in the most recent seal_and_queue transaction (fee vs computation-account rent vs pool). */
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";

(async () => {
  const connection = new Connection(
    process.env.ANCHOR_PROVIDER_URL!,
    "confirmed"
  );
  const wallet = Keypair.fromSecretKey(
    new Uint8Array(
      JSON.parse(
        fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8")
      )
    )
  ).publicKey;
  const sigs = await connection.getSignaturesForAddress(wallet, { limit: 200 });
  for (const s of sigs) {
    const tx = await connection.getTransaction(s.signature, {
      maxSupportedTransactionVersion: 0,
      commitment: "confirmed",
    });
    if (!tx?.meta || tx.meta.err) continue;
    const logs = tx.meta.logMessages ?? [];
    if (!logs.some((l) => l.includes("Instruction: SealAndQueueRoute")))
      continue;
    console.log(
      "tx",
      s.signature,
      "fee",
      tx.meta.fee,
      "CU",
      tx.meta.computeUnitsConsumed
    );
    const keys = tx.transaction.message.staticAccountKeys;
    keys.forEach((k, i) => {
      const d = tx.meta!.postBalances[i] - tx.meta!.preBalances[i];
      if (d !== 0)
        console.log(`  ${k.toBase58()}  ${d > 0 ? "+" : ""}${d} lamports`);
    });
    const inner = tx.meta.innerInstructions ?? [];
    for (const ii of inner)
      for (const ix of ii.instructions) {
        const pid = keys[ix.programIdIndex];
        if (pid.equals(new PublicKey("11111111111111111111111111111111")))
          console.log(
            "  system ix accounts:",
            ix.accounts.map((a) => keys[a].toBase58()).join(", ")
          );
      }
    // does the computation account still exist?
    for (let i = 0; i < keys.length; i++) {
      const d = tx.meta.postBalances[i] - tx.meta.preBalances[i];
      if (d > 0) {
        const info = await connection.getAccountInfo(keys[i]);
        console.log(
          `  ${keys[i].toBase58()} now: ${
            info
              ? `${info.lamports} lamports, ${
                  info.data.length
                } bytes, owner ${info.owner.toBase58()}`
              : "closed"
          }`
        );
      }
    }
    break;
  }
})();
