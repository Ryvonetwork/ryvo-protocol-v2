/** Print the devnet cluster's fee parameters and our comp defs' CU amounts. */
import * as anchor from "@anchor-lang/core";
import { Keypair, PublicKey } from "@solana/web3.js";
import * as fs from "fs";
import * as os from "os";
import { getArciumProgram, getClusterAccAddress, getCompDefAccAddress, getCompDefAccOffset, getMXEAccAddress } from "@arcium-hq/client";

(async () => {
  const connection = new anchor.web3.Connection(process.env.ANCHOR_PROVIDER_URL!, "confirmed");
  const payer = Keypair.fromSecretKey(new Uint8Array(JSON.parse(fs.readFileSync(`${os.homedir()}/.config/solana/id.json`, "utf8"))));
  const provider = new anchor.AnchorProvider(connection, new anchor.Wallet(payer), { commitment: "confirmed" });
  const arcium = getArciumProgram(provider as any);
  const programId = new PublicKey("DD7m7B1FggiCQCURQ2pNXyDtPZPRdJYYgq9dthtaJtii");
  const offset = Number(process.env.ARCIUM_CLUSTER_OFFSET ?? 456);
  const cluster: any = await (arcium.account as any).cluster.fetch(getClusterAccAddress(offset));
  const show = (o: any) => JSON.stringify(o, (_, v) => (v && v.toNumber ? v.toString() : v instanceof Uint8Array || Array.isArray(v) && v.length > 8 ? `[${v.length} items]` : v), 1).slice(0, 4000);
  console.log("cluster:", show({ cuPrice: cluster.cuPrice, maxCapacity: cluster.maxCapacity, nodes: cluster.nodes?.length, status: cluster.status, ...Object.fromEntries(Object.entries(cluster).filter(([k]) => /fee|price|cu|epoch/i.test(k))) }));
  for (const name of ["clear_route", "clear_unilateral"]) {
    const pda = getCompDefAccAddress(programId, Buffer.from(getCompDefAccOffset(name)).readUInt32LE());
    const cd: any = await (arcium.account as any).computationDefinitionAccount.fetch(pda);
    console.log(name, show({ cuAmount: cd.cuAmount, deactivationSlot: cd.deactivationSlot, finalized: cd.finalized }));
  }
  const mxe: any = await (arcium.account as any).mxeAccount.fetch(getMXEAccAddress(programId));
  console.log("mxe keys:", Object.keys(mxe).join(","));
})();
