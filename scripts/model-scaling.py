"""
Scaling model: Ryvo batch clearing vs 1:1 channel settlement (one on-chain tx per channel settled).

Inputs are the numbers measured on devnet 2026-08-19 (program DD7m7B1F…, cluster 456) plus the
staging arithmetic that follows from the slot layout. Everything estimated is labelled.

Per batch of N commitments the clearing path is (current implementation):
  stage_slots × S (first carries reset_staging) | seal_and_queue (merged with a small tail chunk)
  | callback (fee paid by the Arcium node) | settle_channels × T
The buffer itself is created once per relayer and reused; no per-batch open/close.
"""
SOL_USD = 77.0
BASE_FEE = 5000               # lamports per signature
LEGACY_SLOTS_PER_TX = 30      # 960 B payload in a 1,232 B packet
V1_SLOTS_PER_TX = 120         # 3,840 B payload in a 4,096 B packet (gate not yet active)
MERGEABLE_TAIL = 18           # a stage chunk this small rides in the seal_and_queue tx (legacy)

# measured on devnet
SETTLE_CU_PER_ROUTE = 126_457 / 32          # 3,952
SETTLE_ROUTES_PER_TX = 32                   # 98 accounts, ALT; measured
SETTLE_UNI_PER_TX = 100                     # est: 1 channel each + shared payee balance, ~126 locks
STAGE_TX_CU = 6_000                         # est
OPEN_TX_CU = 12_000                         # est (create 20 KB account + init)
QUEUE_TX_CU = 60_000                        # est (Arcium CPI)
CLOSE_TX_CU = 6_000                         # est
ONE_TO_ONE_CU = 15_000                      # est: one channel settlement tx with a sig check + 2 writes

def ryvo(n_records, N, slots_per_record, slots_per_tx, settle_per_tx, kind, reuse):
    batches = -(-n_records // N)
    slots = N * slots_per_record
    stage_tx = -(-slots // slots_per_tx)
    settle_tx = -(-N // settle_per_tx)
    if reuse:
        tail = slots % slots_per_tx
        merged = 1 if (slots_per_tx == LEGACY_SLOTS_PER_TX and 0 < tail <= MERGEABLE_TAIL) else 0
        per_batch_tx = stage_tx - merged + 1 + 1 + settle_tx   # stage(+reset) | seal(+tail) | callback | settle
        cu_batch = stage_tx * STAGE_TX_CU + QUEUE_TX_CU
    else:
        per_batch_tx = 1 + stage_tx + 1 + 1 + settle_tx + 1     # open | stage | seal | callback | settle | close
        cu_batch = OPEN_TX_CU + stage_tx * STAGE_TX_CU + QUEUE_TX_CU + CLOSE_TX_CU
    tx = batches * per_batch_tx
    cu = batches * cu_batch + n_records * (SETTLE_CU_PER_ROUTE if kind == "route" else SETTLE_CU_PER_ROUTE * 0.66)
    return tx, cu, per_batch_tx

def usd(tx, cu, prio_lam_per_cu):
    return (tx * BASE_FEE + cu * prio_lam_per_cu) / 1e9 * SOL_USD

def row(label, tx, cu, base_tx, base_cu):
    out = f"| {label:<78} | {tx:>6,} | {cu/1e6:>6.2f}M |"
    for p in (0, 0.01, 1):
        out += f" {usd(tx, cu, p):>7.4f} ({usd(base_tx, base_cu, p)/usd(tx, cu, p):>4.1f}×) |"
    return out

N_REC = 1000
print(f"Per {N_REC:,} channel settlements. Ratio in parentheses = 1:1 cost / Ryvo cost.")
print("Priority fee columns: none | 0.01 lamport/CU (moderate) | 1 lamport/CU (heavy)\n")
for kind, base_settlements in (("route", 2), ("unilateral", 1)):
    print(f"### {kind} ({'2 channel settlements per route' if kind=='route' else '1 channel settlement'})")
    print("| configuration | tx | CU | no priority | moderate | heavy |")
    print("|---|---|---|---|---|---|")
    b_tx = N_REC * base_settlements
    b_cu = b_tx * ONE_TO_ONE_CU
    print(f"| {'1:1 — one tx per channel settlement':<78} | {b_tx:>6,} | {b_cu/1e6:>6.2f}M | {usd(b_tx,b_cu,0):>7.4f} (1.0×) | {usd(b_tx,b_cu,0.01):>7.4f} (1.0×) | {usd(b_tx,b_cu,1):>7.4f} (1.0×) |")
    spr_first = 12 if kind == "route" else 6      # keys staged (2 slots each)
    spr_now = 10 if kind == "route" else 5        # channel address staged (1 slot), key read from the account
    settle_per = SETTLE_ROUTES_PER_TX if kind == "route" else SETTLE_UNI_PER_TX
    configs = [
        ("first deployment: N=32, legacy tx, keys staged, open/close per batch",           32, spr_first, LEGACY_SLOTS_PER_TX, False),
        ("NOW: N=64 uni / 32 route, keys from Channel accounts, buffer reuse, merged seal", 32 if kind == "route" else 64, spr_now, LEGACY_SLOTS_PER_TX, True),
        ("NOW + transaction v1 (client ready; gate pending)",                               32 if kind == "route" else 64, spr_now, V1_SLOTS_PER_TX, True),
        ("NOW + v1 + N=128 (bitmap growth; routes need Arcium heap headroom)",              128, spr_now, V1_SLOTS_PER_TX, True),
    ]
    for label, N, spr, sptx, reuse in configs:
        tx, cu, per_batch = ryvo(N_REC, N, spr, sptx, settle_per, kind, reuse)
        print(row(f"{label} [{per_batch} tx/batch]", tx, cu, b_tx, b_cu))
    print()
