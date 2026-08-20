#!/usr/bin/env bash
# Self-contained test harness.
#
# `anchor test` cannot be used directly: it loads the program into validator genesis with the
# upgrade authority set to the all-zero pubkey, so nobody can sign for it and `initialize` —
# which is deliberately gated on the upgrade authority to stop the fixed-seed Config account
# being front-run — is uncallable. Here we run our own validator and deploy with our own wallet,
# so the upgrade authority is a key we hold. That also matches how a real deployment works.
#
# NOTE: Linux truncates the validator's process name to 15 bytes (`solana-test-val`). Always use
# that exact name, never `pkill -f`: `-f` also matches this script's command line and kills the
# harness itself.
set -euo pipefail

RPC_URL="${RPC_URL:-http://127.0.0.1:8899}"
LEDGER="${LEDGER:-/tmp/ryvo-test-ledger}"
WALLET="${WALLET:-$HOME/.config/solana/id.json}"
PROGRAM_SO="target/deploy/ryvo_protocol.so"
PROGRAM_KEYPAIR="target/deploy/ryvo_protocol-keypair.json"

cleanup() { pkill -x solana-test-val 2>/dev/null || true; }
trap cleanup EXIT

echo "==> stopping any running validator"
pkill -x solana-test-val 2>/dev/null || true
sleep 2
rm -rf "$LEDGER"

echo "==> starting validator"
solana-test-validator --reset --quiet --ledger "$LEDGER" >/tmp/ryvo-validator.log 2>&1 &

for i in $(seq 1 60); do
  if solana --url "$RPC_URL" cluster-version >/dev/null 2>&1; then
    echo "    rpc up after ${i}s"
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "!! validator failed to start; tail of log:"
    tail -20 /tmp/ryvo-validator.log
    exit 1
  fi
  sleep 1
done

echo "==> funding wallet"
solana --url "$RPC_URL" --keypair "$WALLET" airdrop 100 >/dev/null 2>&1 || true
echo "    balance: $(solana --url "$RPC_URL" --keypair "$WALLET" balance)"

echo "==> deploying program (upgrade authority = our wallet)"
solana --url "$RPC_URL" --keypair "$WALLET" program deploy \
  --program-id "$PROGRAM_KEYPAIR" "$PROGRAM_SO" >/dev/null

PROGRAM_ID="$(solana address --keypair "$PROGRAM_KEYPAIR")"
AUTHORITY="$(solana --url "$RPC_URL" program show "$PROGRAM_ID" | awk '/Authority/ {print $2}')"
EXPECTED="$(solana address --keypair "$WALLET")"
echo "    program:   $PROGRAM_ID"
echo "    authority: $AUTHORITY"
if [ "$AUTHORITY" != "$EXPECTED" ]; then
  echo "!! upgrade authority is $AUTHORITY, expected $EXPECTED"
  exit 1
fi

echo "==> running tests"
export ANCHOR_PROVIDER_URL="$RPC_URL"
export ANCHOR_WALLET="$WALLET"
npx ts-mocha -p ./tsconfig.json -t 1000000 "tests/**/*.ts"
