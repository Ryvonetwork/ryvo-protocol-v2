/**
 * Definitive v1 acceptance probe. Sends a v1 self-transfer with skipPreflight, computes the
 * signature from the wire bytes ourselves (v1 puts signatures LAST; an RPC that cannot decode
 * v1 returns a bogus signature), and polls signature status on-chain. Also checks the
 * enable_tx_v1 feature account.
 *   ANCHOR_PROVIDER_URL=<rpc> npx ts-node -T -P tsconfig.json scripts/probe-txv1.ts
 */
import { Connection, Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";
import { buildV1Transaction } from "../tests-arcium/txv1";

const FEATURE = new PublicKey("txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL"); // SIMD-0385 enable_tx_v1
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function bs58(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let s = "";
  while (n > 0n) {
    s = ALPHABET[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) s = "1" + s;
    else break;
  }
  return s;
}

(async () => {
  const url =
    process.env.ANCHOR_PROVIDER_URL ?? "https://api.devnet.solana.com";
  const c = new Connection(url, "confirmed");
  const kp = Keypair.fromSecretKey(
    new Uint8Array(
      JSON.parse(
        fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8")
      )
    )
  );
  const v = await c.getVersion();
  console.log(
    "rpc:",
    url.replace(/api-key=.*/, "api-key=…"),
    "| node:",
    v["solana-core"],
    "| feature-set:",
    v["feature-set"]
  );
  const feat = await c.getAccountInfo(FEATURE);
  console.log(
    "enable_tx_v1 feature account:",
    feat ? `EXISTS (${feat.data.length} bytes)` : "absent (not activated)"
  );

  const { blockhash, lastValidBlockHeight } = await c.getLatestBlockhash(
    "confirmed"
  );
  const wire = buildV1Transaction(
    [
      SystemProgram.transfer({
        fromPubkey: kp.publicKey,
        toPubkey: kp.publicKey,
        lamports: 1,
      }),
    ],
    [kp],
    blockhash,
    { computeUnitLimit: 20_000 }
  );
  const mySig = bs58(wire.subarray(wire.length - 64));
  let rpcSig = "";
  try {
    rpcSig = await c.sendRawTransaction(wire, {
      skipPreflight: true,
      maxRetries: 3,
    });
  } catch (e: any) {
    console.log(
      "sendRawTransaction rejected:",
      String(e.message).slice(0, 200)
    );
    return;
  }
  console.log(
    "rpc-returned sig:",
    rpcSig,
    "\nreal sig (last 64B):",
    mySig,
    rpcSig === mySig ? "(same)" : "(DIFFERENT — RPC did not decode v1)"
  );
  for (let i = 0; i < 40; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    const st = await c.getSignatureStatuses([mySig, rpcSig], {
      searchTransactionHistory: true,
    });
    const [a, b] = st.value;
    if (a || b) {
      console.log("LANDED:", JSON.stringify(a ?? b));
      return;
    }
    const h = await c.getBlockHeight("confirmed");
    if (h > lastValidBlockHeight) {
      console.log(
        "expired without landing (block height exceeded) — validators did not accept it"
      );
      return;
    }
  }
  console.log("timed out waiting");
})();
