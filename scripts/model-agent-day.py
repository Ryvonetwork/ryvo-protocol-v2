"""
Per-agent-day benchmark: an agent pays 3 providers every day.

1:1 baseline: a direct payment channel per (agent, provider) per day — open (create + fund),
pay off-chain, then settle + close. Two variants:
  cooperative: open 1 tx, settle+close 1 tx (both sign)            -> 2 tx per channel-day
  unilateral:  open 1 tx, submit state 1 tx, close after challenge -> 3 tx per channel-day
Rent of the channel account is returned on close, so it is churn, not cost.

Ryvo: the agent keeps one slot in a 256-channel routed bucket owned by the gateway. One daily commitment contains all 3 provider
allocations and both signatures. There are no gateway-to-provider channels or pool. Per agent-day
we charge 1/N of a batch plus the amortised lock top-up.
"""
SOL_USD = 77.0
BASE_FEE = 5000
ARCIUM_FEE = 10_045
PROVIDERS = 3
TOPUPS_PER_DAY = 1 / 7            # agent locks more funds once a week (1 tx)
OPEN_CU, SETTLE_CLOSE_CU = 15_000, 20_000   # est: account creation + transfer; signed-state check + 2 writes + close
ROUTE_CU = 5_000                  # estimated for one source + gateway + 3 provider balance writes
STAGE_CU, QUEUE_CU, CALLBACK_CU = 10_232, 177_007, 30_000  # measured / est

def one_to_one(tx_per_channel_day, cu_per_channel_day):
    return PROVIDERS * tx_per_channel_day, PROVIDERS * cu_per_channel_day, 0

def ryvo(N, stage_tx, settle_tx):
    per_batch_tx = stage_tx + 1 + 1 + settle_tx
    share = 1 / N
    tx = per_batch_tx * share + TOPUPS_PER_DAY
    cu = (stage_tx * STAGE_CU + QUEUE_CU + CALLBACK_CU) * share + ROUTE_CU + TOPUPS_PER_DAY * 8_000
    fee = ARCIUM_FEE * share
    return tx, cu, fee

def usd(tx, cu, fee, prio):
    return (tx * BASE_FEE + cu * prio + fee) / 1e9 * SOL_USD

rows = [
    ("1:1 cooperative close (open, settle+close)", one_to_one(2, OPEN_CU + SETTLE_CLOSE_CU)),
    ("1:1 unilateral close (open, submit state, close)", one_to_one(3, OPEN_CU + SETTLE_CLOSE_CU + 8_000)),
    ("Ryvo today: one 3-provider commitment, N=32 (9 tx/batch)", ryvo(32, 6, 1)),
    ("Ryvo + v1: one 3-provider commitment, N=32 (5 tx/batch)", ryvo(32, 2, 1)),
    ("Ryvo + off-chain inputs + v1, N=32 (3 tx/batch)", ryvo(32, 0, 1)),
    ("Ryvo + off-chain inputs + v1, N=256 bucket (7 tx/batch)", ryvo(256, 0, 5)),
]
base = rows[0][1]
print(f"Per agent-day, {PROVIDERS} providers paid. Ratio = 1:1-cooperative cost / row cost. USD at SOL ${SOL_USD:.0f}.\n")
print("| configuration | tx / agent-day | CU | $ no priority | $ heavy priority (1 lamport/CU) |")
print("|---|---|---|---|---|")
for label, (tx, cu, fee) in rows:
    r0 = usd(*base, 0) / usd(tx, cu, fee, 0)
    r1 = usd(*base, 1) / usd(tx, cu, fee, 1)
    print(f"| {label} | {tx:.2f} | {cu/1e3:.1f}k | {usd(tx, cu, fee, 0):.6f} ({r0:.1f}×) | {usd(tx, cu, fee, 1):.6f} ({r1:.1f}×) |")
print(f"\nPer 1,000 agents per day: 1:1 cooperative = {base[0]*1000:,.0f} tx; Ryvo today = {rows[2][1][0]*1000:,.0f} tx; "
      f"Ryvo + v1 + 128 locks = {rows[3][1][0]*1000:,.0f} tx; off-chain N=256 = {rows[5][1][0]*1000:,.0f} tx.")
