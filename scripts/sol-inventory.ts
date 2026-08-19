/**
 * Where did the wallet's SOL go? Walks the wallet's entire devnet history, attributes each
 * transaction's lamport delta to a category, and lists accounts we can still close. Read-only.
 *
 *   ANCHOR_PROVIDER_URL=<helius devnet> npx ts-node -T -P tsconfig.json scripts/sol-inventory.ts
 */
import { Connection, Keypair, PublicKey, VersionedTransactionResponse } from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";

const PROGRAMS = ["DD7m7B1FggiCQCURQ2pNXyDtPZPRdJYYgq9dthtaJtii", "7QBj1XUYe4RbMxJd8H42gWR7QWeRiRuYQbwbwAjAmjqQ", "4kRnxdszLpHvrLzi4EDyyTRAWqkdmANzSGFPqncr2uxc"];
const ARCIUM = "Arcj82pX7HxYKLR92qvgZUAd7vGS1k4hQvAFcPATFdEQ";
const LOADER = "BPFLoaderUpgradeab1e11111111111111111111111";
const ALT = "AddressLookupTab1e1111111111111111111111111";
const TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

(async () => {
  const connection = new Connection(process.env.ANCHOR_PROVIDER_URL!, "confirmed");
  const wallet = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8")))).publicKey;
  const sigs: string[] = [];
  let before: string | undefined;
  for (;;) {
    const page = await connection.getSignaturesForAddress(wallet, { before, limit: 1000 });
    if (!page.length) break;
    sigs.push(...page.map((p) => p.signature));
    before = page[page.length - 1].signature;
    if (page.length < 1000) break;
  }
  console.log(`${sigs.length} transactions in the wallet's history`);

  const cats = new Map<string, { n: number; delta: number }>();
  const add = (c: string, d: number) => { const r = cats.get(c) ?? { n: 0, delta: 0 }; r.n++; r.delta += d; cats.set(c, r); };
  const queueOffsets: { program: string; offset: bigint }[] = [];
  for (let i = 0; i < sigs.length; i += 25) {
    const txs = await Promise.all(sigs.slice(i, i + 25).map((s) => connection.getTransaction(s, { maxSupportedTransactionVersion: 0, commitment: "confirmed" }).catch(() => null)));
    for (const tx of txs as (VersionedTransactionResponse | null)[]) {
      if (!tx?.meta) continue;
      const keys = tx.transaction.message.staticAccountKeys.map((k) => k.toBase58());
      const idx = keys.indexOf(wallet.toBase58());
      if (idx < 0) continue;
      const delta = tx.meta.preBalances[idx] - tx.meta.postBalances[idx]; // positive = spent
      if (tx.meta.err) { add("failed tx (fee only)", delta); continue; }
      const logs = tx.meta.logMessages ?? [];
      const ixNames = logs.filter((l) => l.includes("Instruction: ")).map((l) => l.split("Instruction: ")[1].trim());
      const progs = new Set(tx.transaction.message.compiledInstructions.map((ix) => keys[ix.programIdIndex]));
      let cat = "other";
      if (progs.has(LOADER)) cat = "program deploy/upgrade/close (loader)";
      else if (ixNames.some((n) => /SealAndQueue/.test(n))) {
        cat = "seal_and_queue (Arcium fee + computation rent)";
        for (const ix of tx.transaction.message.compiledInstructions) {
          const p = keys[ix.programIdIndex];
          if (PROGRAMS.includes(p) && ix.data.length >= 16) queueOffsets.push({ program: p, offset: Buffer.from(ix.data).readBigUInt64LE(8) });
        }
      }
      else if (ixNames.some((n) => /InitClear.*CompDef|InitComputationDefinition|UploadCircuit|FinalizeComputationDefinition/.test(n))) cat = "comp def init / circuit upload";
      else if (ixNames.some((n) => /InitMxe|InitializeMxe|CreateLookupTable|ExtendLookupTable|InitArciumSigner/.test(n)) || progs.has(ALT)) cat = progs.has(ALT) && !progs.has(ARCIUM) ? "address lookup tables" : "arcium MXE setup";
      else if (ixNames.some((n) => /OpenStaging/.test(n))) cat = "open_staging (buffer rent, reclaimed on close)";
      else if (ixNames.some((n) => /CloseStaging|ClaimComputationRent/.test(n))) cat = "reclaims (close_staging / claim rent)";
      else if (ixNames.some((n) => /StageSlots|StageChannels|StageRecords|ResetStaging|SettleChannels/.test(n))) cat = "clearing tx fees (stage/settle)";
      else if (ixNames.some((n) => /Initialize$|RegisterToken|InitializeParticipant|OpenBalance|CreateChannel|Deposit|LockChannelFunds/.test(n))) cat = "protocol setup tx (rent of PDAs paid by the party that signed)";
      else if (progs.has(TOKEN) && ixNames.some((n) => /InitializeMint|MintTo/.test(n))) cat = "test mints / minting";
      else if (progs.has("11111111111111111111111111111111") && progs.size === 1) cat = delta > 0 ? "SOL sent to party keypairs (funding)" : "SOL received (airdrops / sweeps)";
      add(cat, delta);
    }
  }
  let total = 0;
  console.log("\n| category | tx | SOL (positive = left the wallet) |\n|---|---|---|");
  for (const [c, r] of [...cats.entries()].sort((a, b) => b[1].delta - a[1].delta)) { console.log(`| ${c} | ${r.n} | ${(r.delta / 1e9).toFixed(4)} |`); total += r.delta; }
  console.log(`| **net** | | ${(total / 1e9).toFixed(4)} |`);
  const bal = await connection.getBalance(wallet);
  console.log(`wallet balance now: ${(bal / 1e9).toFixed(4)} SOL`);

  // --- still-open things we control
  console.log("\n== still open ==");
  let live = 0, liveLamports = 0;
  const { getComputationAccAddress } = await import("@arcium-hq/client");
  const seen = new Set<string>();
  for (const q of queueOffsets) {
    const acc = getComputationAccAddress(456, new (await import("@anchor-lang/core")).BN(q.offset.toString()));
    if (seen.has(acc.toBase58())) continue;
    seen.add(acc.toBase58());
    const info = await connection.getAccountInfo(acc);
    if (info) { live++; liveLamports += info.lamports; }
  }
  console.log(`computation accounts still open: ${live} (${(liveLamports / 1e9).toFixed(4)} SOL) of ${seen.size} queued`);
  const alts = await connection.getProgramAccounts(new PublicKey(ALT), { filters: [{ memcmp: { offset: 22, bytes: wallet.toBase58() } }] });
  console.log(`lookup tables with the wallet as authority: ${alts.length} (${(alts.reduce((a, b) => a + b.account.lamports, 0) / 1e9).toFixed(4)} SOL)`);
  const toks = await connection.getParsedTokenAccountsByOwner(wallet, { programId: new PublicKey(TOKEN) });
  console.log(`token accounts owned by the wallet: ${toks.value.length} (${(toks.value.reduce((a, b) => a + b.account.lamports, 0) / 1e9).toFixed(4)} SOL)`);
  const bufs = await connection.getProgramAccounts(new PublicKey(LOADER), { filters: [{ memcmp: { offset: 5, bytes: wallet.toBase58() } }], dataSlice: { offset: 0, length: 0 } });
  console.log(`loader accounts (buffers/programdata) with the wallet as authority: ${bufs.length} (${(bufs.reduce((a, b) => a + b.account.lamports, 0) / 1e9).toFixed(4)} SOL)`);
  for (const p of PROGRAMS) {
    const info = await connection.getAccountInfo(new PublicKey(p));
    console.log(`program ${p}: ${info ? "exists" : "closed"}`);
  }
})();
