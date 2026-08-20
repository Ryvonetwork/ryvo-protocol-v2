#!/usr/bin/env bash
# Permanently remove the program upgrade authority. This cannot be reversed.
set -euo pipefail

RPC_URL="${RPC_URL:?set RPC_URL to the target cluster RPC URL}"
WALLET="${WALLET:-$HOME/.config/solana/id.json}"
PROGRAM_KEYPAIR="${PROGRAM_KEYPAIR:-target/deploy/ryvo_protocol-keypair.json}"
PROGRAM_ID="${PROGRAM_ID:-$(solana address --keypair "$PROGRAM_KEYPAIR")}"

if [ "${RYVO_CONFIRM_FINALIZE:-}" != "$PROGRAM_ID" ]; then
  echo "Refusing to finalize without exact program confirmation."
  echo "Set RYVO_CONFIRM_FINALIZE=$PROGRAM_ID"
  exit 1
fi

EXPECTED_AUTHORITY="$(solana address --keypair "$WALLET")"
SHOW="$(solana --url "$RPC_URL" program show "$PROGRAM_ID")"
CURRENT_AUTHORITY="$(printf '%s\n' "$SHOW" | awk '/Authority/ {print $2}')"

if [ "$CURRENT_AUTHORITY" = "none" ]; then
  echo "Program $PROGRAM_ID is already immutable."
  exit 0
fi
if [ "$CURRENT_AUTHORITY" != "$EXPECTED_AUTHORITY" ]; then
  echo "Refusing to finalize: upgrade authority is $CURRENT_AUTHORITY, expected $EXPECTED_AUTHORITY"
  exit 1
fi

CONFIG_PDA="$(node - "$PROGRAM_ID" <<'NODE'
const { PublicKey } = require("@solana/web3.js");
const programId = new PublicKey(process.argv[2]);
const [config] = PublicKey.findProgramAddressSync(
  [Buffer.from("config")],
  programId
);
process.stdout.write(config.toBase58());
NODE
)"
if ! solana --url "$RPC_URL" account "$CONFIG_PDA" >/dev/null 2>&1; then
  echo "Refusing to finalize: Config $CONFIG_PDA is not initialized."
  exit 1
fi

echo "Permanently removing upgrade authority from $PROGRAM_ID"
solana --url "$RPC_URL" --keypair "$WALLET" program set-upgrade-authority \
  "$PROGRAM_ID" \
  --upgrade-authority "$WALLET" \
  --final

FINAL_AUTHORITY="$(solana --url "$RPC_URL" program show "$PROGRAM_ID" | awk '/Authority/ {print $2}')"
if [ "$FINAL_AUTHORITY" != "none" ]; then
  echo "Finalization verification failed: authority is $FINAL_AUTHORITY"
  exit 1
fi
echo "Program $PROGRAM_ID is immutable."
