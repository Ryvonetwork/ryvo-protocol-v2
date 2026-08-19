"""
Scaling model: Ryvo batch clearing vs 1:1 channel settlement (one on-chain tx per channel settled).

Inputs are numbers measured on devnet (program DD7m7B1F…, cluster 456) plus the staging
arithmetic that follows from the record format. Everything estimated is labelled.

Per batch of N commitments the clearing path is (current implementation, dense staging):
  stage_records × S (first carries reset_staging; the last few records may ride in the seal tx)
  | seal_and_queue (+ previous computation's rent claim) | callback (sent by the Arcium node)
  | settle_channels × T (v0 + lookup table)
The buffer is created once per relayer and reused; no per-batch open/close.
"""
SOL_USD = 77.0
BASE_FEE = 5000               # lamports per signature
LEGACY_TX_BYTES = 1232
V1_TX_BYTES = 4096            # transaction v1 (gate not yet active on devnet)

# dense record bytes on the wire: data + 33 B per channel account (key + index)
ROUTE_WIRE = 160 + 2 * 33     # 226
UNI_WIRE = 80 + 33            # 113
TX_OVERHEAD = 217             # signature, header, 3 fixed accounts, blockhash, ix framing (legacy)
def records_per_tx(wire, tx_bytes, extra=0):
    return (tx_bytes - TX_OVERHEAD - extra) // wire

# measured on devnet 2026-08-19 with the N=64 dense build (scripts/devnet-costs.ts, scripts/seal-tx-detail.ts):
# 100 routes = 2 batches = 32 wallet tx + 2 callbacks; 64-route batch = 16 stage + seal + callback + 2 settle = 20 tx
ARCIUM_FEE_LAMPORTS = 10_045                # paid to the Arcium fee pool per computation (devnet price; 64-route batch; 32-route was 10,023)
COMPUTATION_RENT_LAMPORTS = 5_679_360       # 678-byte computation account; reclaimed in the next seal tx (net zero in steady state)
SETTLE_CU_PER_ROUTE = 171_363 / 39          # 4,394 (39 routes, 64 unique accounts, one v0 tx)
SETTLE_ROUTES_PER_TX = 39                   # tx account-lock limit is 64 (the 128 feature is inactive on devnet and mainnet): 39 agent channels + 10 gateway channels + 10 balances + 5
SETTLE_UNI_PER_TX = 58                      # 58 channels + 1 shared payee balance + 5 (lock limit)
STAGE_TX_CU = 10_232                        # measured: 4 routes packed on-chain per tx
QUEUE_TX_CU = 177_007                       # measured (seal + pad + Arcium CPI, N=64)
OPEN_TX_CU = 12_000                         # est
CLOSE_TX_CU = 6_000                         # est
ONE_TO_ONE_CU = 15_000                      # est: one channel settlement tx with a sig check + 2 writes

def ceil(a, b):
    return -(-a // b)

def ryvo(n_records, N, kind, tx_bytes, mode, reuse, settle_per_tx):
    batches = ceil(n_records, N)
    if mode == "prev":   # slot staging of ids/sigs (8 slots/route, 4/uni, 30 per tx, tail merged) + stage_channels (30 accounts/tx)
        slots = N * (8 if kind == "route" else 4)
        stage_tx = ceil(slots, 30) - 1 + ceil(N * (2 if kind == "route" else 1), 30)   # measured: 8 + 3 = 11
    elif mode == "dense":
        wire = ROUTE_WIRE if kind == "route" else UNI_WIRE
        per = records_per_tx(wire, tx_bytes)
        stage_tx = ceil(N, per)
        # tail: records that fit in the seal tx next to the rent claim (seal ≈ 620 B used, claim 115 B)
        tail_cap = (LEGACY_TX_BYTES - 620 - 115) // wire if tx_bytes == LEGACY_TX_BYTES else 0
        if N - (stage_tx - 1) * per <= tail_cap:
            stage_tx -= 1
    else:  # slot staging: 32-byte slots, 30 per legacy tx, keys staged as data (first deployment)
        slots = N * (12 if kind == "route" else 6)
        stage_tx = ceil(slots, 30 if tx_bytes == LEGACY_TX_BYTES else 120)
    settle_tx = ceil(N, settle_per_tx)
    if reuse:
        per_batch_tx = stage_tx + 1 + 1 + settle_tx            # stage(+reset) | seal(+claim) | callback | settle
        cu_batch = stage_tx * STAGE_TX_CU + QUEUE_TX_CU
    else:
        per_batch_tx = 1 + stage_tx + 1 + 1 + settle_tx + 1     # open | stage | seal | callback | settle | close
        cu_batch = OPEN_TX_CU + stage_tx * STAGE_TX_CU + QUEUE_TX_CU + CLOSE_TX_CU
    tx = batches * per_batch_tx
    cu = batches * cu_batch + n_records * (SETTLE_CU_PER_ROUTE if kind == "route" else SETTLE_CU_PER_ROUTE * 0.66)
    return tx, cu, per_batch_tx, batches

def usd(tx, cu, prio_lam_per_cu, batches=0):
    return (tx * BASE_FEE + cu * prio_lam_per_cu + batches * ARCIUM_FEE_LAMPORTS) / 1e9 * SOL_USD

def row(label, tx, cu, base_tx, base_cu, batches):
    out = f"| {label:<78} | {tx:>6,} | {cu/1e6:>6.2f}M |"
    for p in (0, 0.01, 1):
        out += f" {usd(tx, cu, p, batches):>7.4f} ({usd(base_tx, base_cu, p)/usd(tx, cu, p, batches):>4.1f}×) |"
    return out

N_REC = 1000
print(f"Per {N_REC:,} channel settlements. Ratio in parentheses = 1:1 cost / Ryvo cost. USD at SOL ${SOL_USD:.0f}.")
print("Ryvo columns include the Arcium computation fee (devnet price); computation-account rent is reclaimed in-flow, so excluded.")
print("Priority fee columns: none | 0.01 lamport/CU (moderate) | 1 lamport/CU (heavy)\n")
for kind, base_settlements in (("route", 2), ("unilateral", 1)):
    print(f"### {kind} ({'2 channel settlements per route' if kind=='route' else '1 channel settlement'})")
    print("| configuration | tx | CU | no priority | moderate | heavy |")
    print("|---|---|---|---|---|---|")
    b_tx = N_REC * base_settlements
    b_cu = b_tx * ONE_TO_ONE_CU
    print(f"| {'1:1 — one tx per channel settlement':<78} | {b_tx:>6,} | {b_cu/1e6:>6.2f}M | {usd(b_tx,b_cu,0):>7.4f} (1.0×) | {usd(b_tx,b_cu,0.01):>7.4f} (1.0×) | {usd(b_tx,b_cu,1):>7.4f} (1.0×) |")
    settle_per = SETTLE_ROUTES_PER_TX if kind == "route" else SETTLE_UNI_PER_TX
    configs = [
        ("first deployment: N=32, slot staging, keys staged, open/close per batch", 32, LEGACY_TX_BYTES, "first", False, 32),
        ("previous: N=64 uni / 32 route, keys copied on-chain, buffer reuse",       32 if kind == "route" else 64, LEGACY_TX_BYTES, "prev", True, 32),
        ("NOW: N=64, dense records, on-chain padding (measured)",                  64, LEGACY_TX_BYTES, "dense", True, settle_per),
        ("NOW + transaction v1 (client ready; gate pending)",                       64, V1_TX_BYTES, "dense", True, settle_per),
    ]
    for label, N, txb, mode, reuse, sp in configs:
        tx, cu, per_batch, batches = ryvo(N_REC, N, kind, txb, mode, reuse, sp)
        print(row(f"{label} [{per_batch} tx/batch]", tx, cu, b_tx, b_cu, batches))
    print()
