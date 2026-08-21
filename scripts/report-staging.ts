import * as anchor from "@anchor-lang/core";
import { Program } from "@anchor-lang/core";
import { RyvoProtocol } from "../target/types/ryvo_protocol";
import { localWallet, setupProvider } from "../tests/shared";
import { KIND_ROUTE, KIND_UNILATERAL } from "../tests/commitment-client";
import { stagingTxCount } from "../tests-arcium/clearing-client";

async function main() {
  setupProvider();
  const program = anchor.workspace.RyvoProtocol as Program<RyvoProtocol>;
  const relayer = localWallet();
  console.log(
    JSON.stringify({
      direct: await stagingTxCount(program, relayer, KIND_UNILATERAL),
      routed: await stagingTxCount(program, relayer, KIND_ROUTE),
    })
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
