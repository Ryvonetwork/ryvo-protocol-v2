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

# One-provider route: compact data (153 + 16) + one repeated source-bucket account index.
# Direct: 80 bytes + one repeated source-bucket account index. When commitments share a payee,
# the bucket pubkey is unique once per staging transaction, not once per commitment.
ROUTE_WIRE = 169 + 1          # 170
UNI_WIRE = 80 + 1             # 81
TX_OVERHEAD = 217             # signature, header, 3 fixed accounts, blockhash, ix framing (legacy)
def records_per_tx(wire, tx_bytes, extra=0):
    return (tx_bytes - TX_OVERHEAD - extra) // wire

# Existing fee measurements; the new 32-commitment route circuit must be remeasured on devnet.
ARCIUM_FEE_LAMPORTS = 10_023
COMPUTATION_RENT_LAMPORTS = 5_679_360       # 678-byte computation account; reclaimed in the next seal tx (net zero in steady state)
SETTLE_CU_PER_ROUTE = 3_000                 # estimate until the new direct-credit path is measured
SETTLE_ROUTES_PER_TX = 32                   # current route circuit returns 32 results
SETTLE_UNI_PER_TX = 64                      # full circuit batch when channels share a bucket/payee
# Off-chain sourcing removes staging, not settlement data. These conservative v1/legacy limits
# reserve room for ids, targets, active provider allocations, account indices, and tx framing.
OFFCHAIN_ROUTE_SETTLE_LEGACY = 20
OFFCHAIN_UNI_SETTLE_LEGACY = 50
OFFCHAIN_ROUTE_SETTLE_V1 = 80
OFFCHAIN_UNI_SETTLE_V1 = 200
STAGE_TX_CU = 10_232                        # measured: 4 routes packed on-chain per tx
QUEUE_TX_CU = 177_007                       # prior measurement; remeasure for the new N=32 route circuit
OPEN_TX_CU = 12_000                         # est
CLOSE_TX_CU = 6_000                         # est
ONE_TO_ONE_CU = 15_000                      # est: one channel settlement tx with a sig check + 2 writes

def ceil(a, b):
    return -(-a // b)

def ryvo(n_records, N, kind, tx_bytes, mode, reuse, settle_per_tx):
    batches = ceil(n_records, N)
    if mode == "offchain":   # hypothetical: Arcium reads ids/targets/keys/sigs off-chain; nothing is staged.
        # Settlement still carries the verified commitment fields and provider allocations as
        # instruction data. A circuit output/root must bind those bytes to what Arcium verified.
        stage_tx = 0
    elif mode == "prev":   # slot staging of ids/sigs (8 slots/route, 4/uni, 30 per tx, tail merged) + stage_channels (30 accounts/tx)
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
for kind, base_settlements in (("route", 1), ("unilateral", 1)):
    print(f"### {kind} (compared with one direct channel settlement per payment)")
    print("| configuration | tx | CU | no priority | moderate | heavy |")
    print("|---|---|---|---|---|---|")
    b_tx = N_REC * base_settlements
    b_cu = b_tx * ONE_TO_ONE_CU
    print(f"| {'1:1 — one tx per channel settlement':<78} | {b_tx:>6,} | {b_cu/1e6:>6.2f}M | {usd(b_tx,b_cu,0):>7.4f} (1.0×) | {usd(b_tx,b_cu,0.01):>7.4f} (1.0×) | {usd(b_tx,b_cu,1):>7.4f} (1.0×) |")
    settle_per = SETTLE_ROUTES_PER_TX if kind == "route" else SETTLE_UNI_PER_TX
    configs = [
        ("first deployment: N=32, slot staging, keys staged, open/close per batch", 32, LEGACY_TX_BYTES, "first", False, 32),
        ("previous: N=64 uni / 32 route, keys copied on-chain, buffer reuse",       32 if kind == "route" else 64, LEGACY_TX_BYTES, "prev", True, 32),
        ("NOW: all channels use 256-slot payee buckets; N=32 route / N=64 direct",     32 if kind == "route" else 64, LEGACY_TX_BYTES, "dense", True, settle_per),
        ("NOW + transaction v1",                                                     32 if kind == "route" else 64, V1_TX_BYTES, "dense", True, settle_per),
        ("NOW + v1 + 128 account locks",                                             32 if kind == "route" else 64, V1_TX_BYTES, "dense", True, settle_per),
        # hypothetical: Arcium sources inputs off-chain (no staging at all); settle carries ids+targets as data
        ("OFF-CHAIN INPUTS, legacy tx, 64 locks, N=64",                             64, LEGACY_TX_BYTES, "offchain", True, OFFCHAIN_ROUTE_SETTLE_LEGACY if kind == "route" else OFFCHAIN_UNI_SETTLE_LEGACY),
        ("OFF-CHAIN INPUTS + v1 + 128 locks, N=64",                                 64, V1_TX_BYTES, "offchain", True, 64),
        ("OFF-CHAIN INPUTS + v1, N=256 (settlement data split as needed)",            256, V1_TX_BYTES, "offchain", True, OFFCHAIN_ROUTE_SETTLE_V1 if kind == "route" else OFFCHAIN_UNI_SETTLE_V1),
    ]
    for label, N, txb, mode, reuse, sp in configs:
        tx, cu, per_batch, batches = ryvo(N_REC, N, kind, txb, mode, reuse, sp)
        print(row(f"{label} [{per_batch} tx/batch]", tx, cu, b_tx, b_cu, batches))
    print()
