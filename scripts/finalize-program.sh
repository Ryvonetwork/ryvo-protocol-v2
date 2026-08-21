#!/usr/bin/env bash
# Permanently remove the program upgrade authority. This cannot be reversed.
set -euo pipefail

RPC_URL="${RPC_URL:?set RPC_URL to the target cluster RPC URL}"
WALLET="${WALLET:-$HOME/.config/solana/id.json}"
PROGRAM_KEYPAIR="${PROGRAM_KEYPAIR:-target/deploy/ryvo_protocol-keypair.json}"
PROGRAM_SO="${PROGRAM_SO:-target/deploy/ryvo_protocol.so}"
PROGRAM_ID="${PROGRAM_ID:-$(solana address --keypair "$PROGRAM_KEYPAIR")}"
EXPECTED_CONFIG_AUTHORITY="${EXPECTED_CONFIG_AUTHORITY:?set EXPECTED_CONFIG_AUTHORITY}"
EXPECTED_CHAIN_ID="${EXPECTED_CHAIN_ID:?set EXPECTED_CHAIN_ID}"
EXPECTED_TIMELOCK_SECONDS="${EXPECTED_TIMELOCK_SECONDS:?set EXPECTED_TIMELOCK_SECONDS}"

if [ "${RYVO_CONFIRM_FINALIZE:-}" != "$PROGRAM_ID" ]; then
  echo "Refusing to finalize without exact program confirmation."
  echo "Set RYVO_CONFIRM_FINALIZE=$PROGRAM_ID"
  exit 1
fi

EXPECTED_UPGRADE_AUTHORITY="$(solana address --keypair "$WALLET")"
SHOW="$(solana --url "$RPC_URL" program show "$PROGRAM_ID")"
CURRENT_AUTHORITY="$(printf '%s\n' "$SHOW" | awk '/Authority/ {print $2}')"
if [ "$CURRENT_AUTHORITY" != "none" ] && [ "$CURRENT_AUTHORITY" != "$EXPECTED_UPGRADE_AUTHORITY" ]; then
  echo "Refusing to finalize: upgrade authority is $CURRENT_AUTHORITY, expected $EXPECTED_UPGRADE_AUTHORITY"
  exit 1
fi

RPC_URL="$RPC_URL" \
PROGRAM_ID="$PROGRAM_ID" \
EXPECTED_CONFIG_AUTHORITY="$EXPECTED_CONFIG_AUTHORITY" \
EXPECTED_CHAIN_ID="$EXPECTED_CHAIN_ID" \
EXPECTED_TIMELOCK_SECONDS="$EXPECTED_TIMELOCK_SECONDS" \
  npx ts-node -T -P tsconfig.json scripts/verify-config.ts

if [ ! -f "$PROGRAM_SO" ]; then
  echo "Refusing to finalize: local program binary $PROGRAM_SO does not exist."
  exit 1
fi

DUMP="$(mktemp)"
cleanup() { rm -f "$DUMP"; }
trap cleanup EXIT
solana --url "$RPC_URL" program dump "$PROGRAM_ID" "$DUMP" >/dev/null
LOCAL_SHA="$(sha256sum "$PROGRAM_SO" | awk '{print $1}')"
ONCHAIN_SHA="$(sha256sum "$DUMP" | awk '{print $1}')"
if [ "$LOCAL_SHA" != "$ONCHAIN_SHA" ]; then
  echo "Refusing to finalize: deployed binary does not match $PROGRAM_SO."
  echo "local:   $LOCAL_SHA"
  echo "onchain: $ONCHAIN_SHA"
  exit 1
fi
echo "Verified deployed binary: $LOCAL_SHA"

if [ "$CURRENT_AUTHORITY" = "none" ]; then
  echo "Program $PROGRAM_ID is already immutable and matches the expected deployment."
  exit 0
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
