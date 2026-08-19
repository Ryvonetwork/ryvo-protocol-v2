/** Reclaim rent on devnet: close every staging buffer of ours whose batch is done or was never queued. */
import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { Keypair, PublicKey } from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { closeStaging } from "../tests-arcium/clearing-client";

(async () => {
  const connection = new anchor.web3.Connection(process.env.ANCHOR_PROVIDER_URL!, "confirmed");
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8"))));
  const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(payer), { commitment: "confirmed" });
  anchor.setProvider(provider);
  const idl = JSON.parse(fs.readFileSync("target/idl/ryvo_protocol.json", "utf8"));
  const program = new Program<RyvoProtocol>(idl, provider);
  const before = await connection.getBalance(payer.publicKey);
  // raw scan: buffers staged by an older layout do not decode with the current IDL
  const disc = program.coder.accounts.memcmp("stagingBuffer");
  const accs = await connection.getProgramAccounts(program.programId, {
    dataSlice: { offset: 0, length: 0 },
    filters: [{ memcmp: { offset: 0, bytes: disc.bytes as string } }, { memcmp: { offset: 16, bytes: payer.publicKey.toBase58() } }],
  });
  console.log(`${accs.length} staging buffers owned by us`);
  for (const a of accs) {
    try {
      await closeStaging(program, payer, new PublicKey(a.pubkey));
      console.log("closed", a.pubkey.toBase58());
    } catch (e: any) {
      console.log("kept", a.pubkey.toBase58(), String(e?.message).slice(0, 80));
    }
  }
  const after = await connection.getBalance(payer.publicKey);
  console.log(`reclaimed ${(after - before) / 1e9} SOL; balance ${after / 1e9}`);
})();
