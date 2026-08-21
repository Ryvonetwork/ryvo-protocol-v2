"""Measured Ryvo clearing scale versus one settlement transaction per channel.

The settlement and staging values below come from the local Arcium integration suite and the
real transaction serializer. The queue and individual-settlement compute values are estimates;
they are labelled and affect only the priority-fee columns.

Arcium execution fees are excluded. Network transaction counts include the Arcium callback;
caller costs do not, because the Arcium node pays for that transaction.
"""

from math import ceil

SOL_USD = 77.0
BASE_FEE_LAMPORTS = 5_000
CHANNEL_SETTLEMENTS = 1_000

# Measured production batch sizes.
BATCH = {"direct": 128, "routed": 32}
STAGE_TX = {
    "direct": {"legacy": 11, "v1": 3},
    "routed": {"legacy": 6, "v1": 2},
}
SETTLEMENT_CU = {"direct": 29_142, "routed": 45_075}

# Existing measurements/estimates used only for priority-fee comparisons.
STAGE_CU = 10_232
QUEUE_CU = 177_007
ONE_TO_ONE_CU = 15_000


def usd(lamports: float) -> float:
    return lamports / 1_000_000_000 * SOL_USD


def path(kind: str, staging: str | None):
    batches = ceil(CHANNEL_SETTLEMENTS / BATCH[kind])
    if staging == "settlement-only":
        network_per_batch = 1
        caller_per_batch = 1
        caller_cu_per_batch = SETTLEMENT_CU[kind]
    elif staging == "offchain":
        # queue | Arcium callback | settle
        network_per_batch = 3
        caller_per_batch = 2
        caller_cu_per_batch = QUEUE_CU + SETTLEMENT_CU[kind]
    else:
        stage = STAGE_TX[kind][staging]
        # stage x N | queue | Arcium callback | settle
        network_per_batch = stage + 3
        caller_per_batch = stage + 2
        caller_cu_per_batch = stage * STAGE_CU + QUEUE_CU + SETTLEMENT_CU[kind]
    return {
        "batches": batches,
        "network_tx": batches * network_per_batch,
        "caller_tx": batches * caller_per_batch,
        "caller_cu": batches * caller_cu_per_batch,
    }


def caller_cost(result, priority_lamports_per_cu: float) -> float:
    lamports = (
        result["caller_tx"] * BASE_FEE_LAMPORTS
        + result["caller_cu"] * priority_lamports_per_cu
    )
    return usd(lamports)


baseline = {
    "network_tx": CHANNEL_SETTLEMENTS,
    "caller_tx": CHANNEL_SETTLEMENTS,
    "caller_cu": CHANNEL_SETTLEMENTS * ONE_TO_ONE_CU,
}

print(f"{CHANNEL_SETTLEMENTS:,} channel settlements, SOL ${SOL_USD:.0f}")
print("Dollar figures exclude Arcium fees. Priority-fee CU uses labelled estimates.\n")

for kind in ("direct", "routed"):
    print(f"## {kind}")
    print(
        "| configuration | batches | network tx | settlement compression | caller tx | "
        "caller cost (0 / 0.01 / 1 lamport per CU) |"
    )
    print("|---|---:|---:|---:|---:|---:|")
    baseline_costs = " / ".join(
        f"${caller_cost(baseline, priority):.4f}" for priority in (0, 0.01, 1)
    )
    print(
        f"| 1:1 channel settlement | 1,000 | 1,000 | 1.00x | 1,000 | {baseline_costs} |"
    )
    for label, mode in (
        ("settlement only", "settlement-only"),
        ("current legacy staging", "legacy"),
        ("transaction v1 staging", "v1"),
        ("Arcium off-chain inputs", "offchain"),
    ):
        result = path(kind, mode)
        costs = " / ".join(
            f"${caller_cost(result, priority):.4f}" for priority in (0, 0.01, 1)
        )
        compression = CHANNEL_SETTLEMENTS / result["network_tx"]
        print(
            f"| {label} | {result['batches']} | {result['network_tx']} | "
            f"{compression:.2f}x | {result['caller_tx']} | {costs} |"
        )
    print()
