/**
 * Reclaim every lamport still sitting in accounts the wallet controls on devnet:
 *   - finished Arcium computation accounts of all our program ids (claim_computation_rent)
 *   - address lookup tables (deactivate, wait out the cooldown, close)
 *   - superseded computation definitions (deactivate, wait out the TTL, close)
 *   - leftover staging buffers (close_staging)
 *
 *   ANCHOR_PROVIDER_URL=<helius devnet> ARCIUM_CLUSTER_OFFSET=456 npx ts-node -T -P tsconfig.json scripts/reclaim-all.ts
 */
import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { AddressLookupTableProgram, Keypair, PublicKey, Transaction } from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";
import { claimComputationRent, getArciumProgram, getComputationAccAddress, getCompDefAccOffset, getCompDefAccAddress, getMXEAccAddress, getExecutingPoolAccAddress } from "@arcium-hq/client";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { closeStaging } from "../tests-arcium/clearing-client";

const PROGRAMS = ["DD7m7B1FggiCQCURQ2pNXyDtPZPRdJYYgq9dthtaJtii", "7QBj1XUYe4RbMxJd8H42gWR7QWeRiRuYQbwbwAjAmjqQ", "4kRnxdszLpHvrLzi4EDyyTRAWqkdmANzSGFPqncr2uxc"];
const ALT = new PublicKey("AddressLookupTab1e1111111111111111111111111");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const connection = new anchor.web3.Connection(process.env.ANCHOR_PROVIDER_URL!, "confirmed");
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8"))));
  const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(payer), { commitment: "confirmed" });
  anchor.setProvider(provider);
  const clusterOffset = Number(process.env.ARCIUM_CLUSTER_OFFSET ?? 456);
  const start = await connection.getBalance(payer.publicKey);
  const arcium = getArciumProgram(provider as any);

  // 1. computation accounts: walk the whole history for seal_and_queue instructions
  const sigs: string[] = [];
  let before: string | undefined;
  for (;;) {
    const page = await connection.getSignaturesForAddress(payer.publicKey, { before, limit: 1000 });
    if (!page.length) break;
    sigs.push(...page.map((p) => p.signature));
    before = page[page.length - 1].signature;
    if (page.length < 1000) break;
  }
  let claimed = 0;
  const seen = new Set<string>();
  for (let i = 0; i < sigs.length; i += 25) {
    const txs = await Promise.all(sigs.slice(i, i + 25).map((s) => connection.getTransaction(s, { maxSupportedTransactionVersion: 0, commitment: "confirmed" }).catch(() => null)));
    for (const tx of txs) {
      if (!tx?.meta || tx.meta.err) continue;
      if (!(tx.meta.logMessages ?? []).some((l) => /Instruction: SealAndQueue/.test(l))) continue;
      const keys = tx.transaction.message.staticAccountKeys.map((k) => k.toBase58());
      for (const ix of tx.transaction.message.compiledInstructions) {
        if (!PROGRAMS.includes(keys[ix.programIdIndex]) || ix.data.length < 16) continue;
        const offset = new anchor.BN(Buffer.from(ix.data).subarray(8, 16), "le");
        const comp = getComputationAccAddress(clusterOffset, offset);
        if (seen.has(comp.toBase58())) continue;
        seen.add(comp.toBase58());
        const info = await connection.getAccountInfo(comp);
        if (!info) continue;
        try { await claimComputationRent(provider as any, clusterOffset, offset); claimed += info.lamports; console.log(`claimed computation ${comp.toBase58()} ${info.lamports}`); }
        catch (e: any) { console.log(`kept computation ${comp.toBase58()}: ${String(e?.message).slice(0, 100)}`); }
      }
    }
  }
  console.log(`computation rent claimed: ${(claimed / 1e9).toFixed(4)} SOL`);

  // 2. staging buffers
  try {
    const idl = JSON.parse(fs.readFileSync("target/idl/ryvo_protocol.json", "utf8"));
    const program = new Program<RyvoProtocol>(idl, provider);
    const disc = program.coder.accounts.memcmp("stagingBuffer");
    const bufs = await connection.getProgramAccounts(program.programId, { dataSlice: { offset: 0, length: 0 }, filters: [{ memcmp: { offset: 0, bytes: disc.bytes as string } }, { memcmp: { offset: 16, bytes: payer.publicKey.toBase58() } }] });
    for (const b of bufs) { try { await closeStaging(program, payer, b.pubkey); console.log("closed staging", b.pubkey.toBase58()); } catch (e: any) { console.log("kept staging", b.pubkey.toBase58(), String(e?.message).slice(0, 80)); } }
  } catch (e: any) { console.log("staging scan skipped:", String(e?.message).slice(0, 80)); }

  // 3. comp defs on the live program: deactivate the superseded ones, then close what is past its TTL
  const live = new PublicKey(PROGRAMS[0]);
  const mxe = getMXEAccAddress(live);
  for (const name of ["clear_unilateral", "clear_route"]) {
    const off = Buffer.from(getCompDefAccOffset(name)).readUInt32LE();
    const pda = getCompDefAccAddress(live, off);
    const info = await connection.getAccountInfo(pda);
    if (!info) { console.log(`comp def ${name}: gone`); continue; }
    const cd: any = await (arcium.account as any).computationDefinitionAccount.fetch(pda);
    if (cd.deactivationSlot === null || cd.deactivationSlot === undefined) {
      try {
        await (arcium.methods as any).deactivateComputationDefinition(off, live).accountsPartial({ signer: payer.publicKey, mxe, compDefAcc: pda }).rpc({ commitment: "confirmed" });
        console.log(`comp def ${name}: deactivated (TTL ~180 slots before close)`);
      } catch (e: any) { console.log(`comp def ${name}: deactivate failed: ${String(e?.message).slice(0, 120)}`); }
    }
    try {
      await (arcium.methods as any).closeComputationDefinition(off, live, clusterOffset)
        .accountsPartial({ signer: payer.publicKey, mxe, compDefAcc: pda, executingPool: getExecutingPoolAccAddress(clusterOffset) })
        .rpc({ commitment: "confirmed" });
      console.log(`comp def ${name}: closed (+${info.lamports})`);
    } catch (e: any) { console.log(`comp def ${name}: close failed: ${String(e?.message).slice(0, 140)}`); }
  }

  // 4. lookup tables: deactivate, wait out the cooldown (~513 slots), close
  const alts = await connection.getProgramAccounts(ALT, { filters: [{ memcmp: { offset: 22, bytes: payer.publicKey.toBase58() } }] });
  console.log(`${alts.length} lookup tables to close (${(alts.reduce((a, b) => a + b.account.lamports, 0) / 1e9).toFixed(4)} SOL)`);
  const toDeactivate: PublicKey[] = [];
  for (const a of alts) {
    const st = (await connection.getAddressLookupTable(a.pubkey)).value?.state;
    if (st && st.deactivationSlot === BigInt("0xffffffffffffffff")) toDeactivate.push(a.pubkey);
  }
  for (let i = 0; i < toDeactivate.length; i += 8) {
    const tx = new Transaction();
    for (const k of toDeactivate.slice(i, i + 8)) tx.add(AddressLookupTableProgram.deactivateLookupTable({ lookupTable: k, authority: payer.publicKey }));
    await provider.sendAndConfirm(tx, []);
  }
  if (toDeactivate.length) console.log(`deactivated ${toDeactivate.length} lookup tables; waiting for the cooldown`);
  let remaining = alts.map((a) => a.pubkey);
  for (let attempt = 0; attempt < 40 && remaining.length; attempt++) {
    const still: PublicKey[] = [];
    for (let i = 0; i < remaining.length; i += 8) {
      const chunk = remaining.slice(i, i + 8);
      const tx = new Transaction();
      for (const k of chunk) tx.add(AddressLookupTableProgram.closeLookupTable({ lookupTable: k, authority: payer.publicKey, recipient: payer.publicKey }));
      try { await provider.sendAndConfirm(tx, []); console.log(`closed ${chunk.length} lookup tables`); }
      catch { still.push(...chunk); }
    }
    remaining = still;
    if (remaining.length) await sleep(30_000);
  }
  if (remaining.length) console.log(`${remaining.length} lookup tables still in cooldown — rerun later`);

  const end = await connection.getBalance(payer.publicKey);
  console.log(`net recovered this run: ${((end - start) / 1e9).toFixed(4)} SOL; balance ${(end / 1e9).toFixed(4)} SOL`);
})();
