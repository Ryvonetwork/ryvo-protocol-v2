/** How much SOL is still sitting in the throwaway party keypairs the smoke runs funded (read-only). */
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
  const sigs: string[] = [];
  let before: string | undefined;
  for (;;) {
    const page = await connection.getSignaturesForAddress(wallet, {
      before,
      limit: 1000,
    });
    if (!page.length) break;
    sigs.push(...page.map((p) => p.signature));
    before = page[page.length - 1].signature;
    if (page.length < 1000) break;
  }
  const recipients = new Set<string>();
  for (let i = 0; i < sigs.length; i += 25) {
    const txs = await Promise.all(
      sigs.slice(i, i + 25).map((s) =>
        connection
          .getTransaction(s, {
            maxSupportedTransactionVersion: 0,
            commitment: "confirmed",
          })
          .catch(() => null)
      )
    );
    for (const tx of txs) {
      if (!tx?.meta || tx.meta.err) continue;
      const keys = tx.transaction.message.staticAccountKeys;
      const progs = new Set(
        tx.transaction.message.compiledInstructions.map((ix) =>
          keys[ix.programIdIndex].toBase58()
        )
      );
      if (progs.size !== 1 || !progs.has("11111111111111111111111111111111"))
        continue;
      const w = keys.findIndex((k) => k.equals(wallet));
      if (tx.meta.postBalances[w] >= tx.meta.preBalances[w]) continue; // not outgoing
      keys.forEach((k, i) => {
        if (i !== w && tx.meta!.postBalances[i] > tx.meta!.preBalances[i])
          recipients.add(k.toBase58());
      });
    }
  }
  const list = [...recipients].map((k) => new PublicKey(k));
  let total = 0,
    nonEmpty = 0;
  for (let i = 0; i < list.length; i += 100) {
    const infos = await connection.getMultipleAccountsInfo(
      list.slice(i, i + 100)
    );
    for (const info of infos)
      if (info && info.lamports > 0) {
        total += info.lamports;
        nonEmpty++;
      }
  }
  console.log(
    `${list.length} funded party keypairs; ${nonEmpty} still hold SOL: ${(
      total / 1e9
    ).toFixed(4)} SOL (keys were random and discarded — unrecoverable)`
  );
})();
