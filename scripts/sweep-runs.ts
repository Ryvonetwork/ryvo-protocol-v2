/** Sweep the SOL of every party keypair of every recorded devnet run back to the wallet. */
import {
  Connection,
  Keypair,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";
import { partyKeypair, readRuns } from "./party-keys";

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
  );
  let swept = 0;
  for (const run of readRuns()) {
    const parties = Array.from({ length: run.parties }, (_, i) =>
      partyKeypair(wallet, run.nonce, i)
    );
    for (let i = 0; i < parties.length; i += 6) {
      const group = parties.slice(i, i + 6);
      const infos = await connection.getMultipleAccountsInfo(
        group.map((k) => k.publicKey)
      );
      const tx = new Transaction();
      const signers: Keypair[] = [];
      group.forEach((k, j) => {
        const bal = infos[j]?.lamports ?? 0;
        if (bal <= 10_000) return;
        tx.add(
          SystemProgram.transfer({
            fromPubkey: k.publicKey,
            toPubkey: wallet.publicKey,
            lamports: bal,
          })
        );
        signers.push(k);
        swept += bal;
      });
      if (signers.length)
        await sendAndConfirmTransaction(connection, tx, [wallet, ...signers], {
          commitment: "confirmed",
        });
    }
    console.log(
      `run ${run.nonce} (${run.startedAt}, ${run.parties} parties): swept`
    );
  }
  console.log(
    `swept ${(swept / 1e9).toFixed(4)} SOL; wallet ${
      (await connection.getBalance(wallet.publicKey)) / 1e9
    } SOL`
  );
})();
