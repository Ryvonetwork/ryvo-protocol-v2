"""
Scaling model: Ryvo batch clearing vs 1:1 channel settlement (one on-chain tx per channel settled).

Inputs are the numbers measured on devnet 2026-08-19 (program DD7m7B1F…, cluster 456) plus the
staging arithmetic that follows from the slot layout. Everything estimated is labelled.

Per batch of N records the clearing path is:
  open+create staging (1 tx) | stage_slots (S tx) | seal_and_queue (1) | callback (1, fee paid by
  the Arcium node) | settle_channels (T tx) | close_staging (1)
"""
SOL_USD = 77.0
BASE_FEE = 5000               # lamports per signature
LEGACY_SLOTS_PER_TX = 30      # 960 B payload in a 1,232 B packet
V1_SLOTS_PER_TX = 120         # 3,840 B payload in a 4,096 B packet (gate not yet active)

# measured on devnet
SETTLE_CU_PER_ROUTE = 126_457 / 32          # 3,952
SETTLE_ROUTES_PER_TX = 32                   # 98 accounts, ALT; measured
SETTLE_UNI_PER_TX = 100                     # est: 1 channel each + shared payee balance, ~126 locks
STAGE_TX_CU = 6_000                         # est
OPEN_TX_CU = 12_000                         # est (create 12 KB account + init)
QUEUE_TX_CU = 60_000                        # est (Arcium CPI)
CLOSE_TX_CU = 6_000                         # est
ONE_TO_ONE_CU = 15_000                      # est: one channel settlement tx with a sig check + 2 writes

def ryvo(n_records, N, slots_per_record, slots_per_tx, settle_per_tx, kind):
    batches = -(-n_records // N)
    stage_tx = -(-(N * slots_per_record) // slots_per_tx)
    settle_tx = -(-N // settle_per_tx)
    per_batch_tx = 1 + stage_tx + 1 + 1 + settle_tx + 1
    tx = batches * per_batch_tx
    cu = batches * (OPEN_TX_CU + stage_tx * STAGE_TX_CU + QUEUE_TX_CU + CLOSE_TX_CU) \
         + n_records * (SETTLE_CU_PER_ROUTE if kind == "route" else SETTLE_CU_PER_ROUTE * 0.66)
    return tx, cu, per_batch_tx

def usd(tx, cu, prio_lam_per_cu):
    lam = tx * BASE_FEE + cu * prio_lam_per_cu
    return lam / 1e9 * SOL_USD

def row(label, tx, cu, base_tx, base_cu):
    out = f"| {label:<52} | {tx:>6,} | {cu/1e6:>7.2f}M |"
    for p in (0, 0.01, 1):
        out += f" {usd(tx, cu, p):>8.4f} ({usd(base_tx, base_cu, p)/usd(tx, cu, p):>4.1f}×) |"
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
    print(f"| {'1:1 — one tx per channel settlement':<52} | {b_tx:>6,} | {b_cu/1e6:>7.2f}M | {usd(b_tx,b_cu,0):>8.4f} (1.0×) | {usd(b_tx,b_cu,0.01):>8.4f} (1.0×) | {usd(b_tx,b_cu,1):>8.4f} (1.0×) |")
    spr_today = 12 if kind == "route" else 6      # keys staged
    spr_acct = 8 if kind == "route" else 4        # keys read from Channel accounts by the circuit
    settle_per = SETTLE_ROUTES_PER_TX if kind == "route" else SETTLE_UNI_PER_TX
    configs = [
        ("Ryvo today: N=32, legacy tx, keys staged (deployed)", 32, spr_today, LEGACY_SLOTS_PER_TX),
        ("+ transaction v1 (client ready; gate pending)",        32, spr_today, V1_SLOTS_PER_TX),
        ("+ v1 + keys via account args (no key staging)",        32, spr_acct,  V1_SLOTS_PER_TX),
        ("+ v1 + account-arg keys + N=64",                       64, spr_acct,  V1_SLOTS_PER_TX),
        ("+ v1 + account-arg keys + N=128 (bitmap growth)",      128, spr_acct, V1_SLOTS_PER_TX),
    ]
    for label, N, spr, sptx in configs:
        tx, cu, per_batch = ryvo(N_REC, N, spr, sptx, settle_per, kind)
        print(row(f"{label} [{per_batch} tx/batch]", tx, cu, b_tx, b_cu))
    print()
