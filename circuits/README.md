# Compiled Arcis circuits

Built by `arcium build` from `encrypted-ixs/src/lib.rs` and committed here so a durable, public
URL exists for the computation definitions (the on-chain `init_clear_*_comp_def` instructions
register these files by URL; the ARX nodes fetch them and check the SHA-256 that is baked into
the program at build time via `circuit_hash!`).

| circuit | sha256 |
| --- | --- |
| clear_unilateral64.arcis (N_UNI = 64) | 6854ddf42a6fc3498a4e851b41e3afc95c009f4c1e54ae0931bef7a1c69ee012 |
| clear_route32.arcis (N_ROUTE = 32, 16 provider allocations each) | ab8c41161aaf9898c32c3a098fddfc6bef9a741228f33651bdd3df5782bc9e82 |

The batch size is part of the name: a comp def is registered once per name, and the circuit
shape (N) is what a name stands for, so a new N is a new name rather than a re-registration.

Rebuilding the circuits changes the hash; the program must be rebuilt and redeployed with the
same `build/` output, and this directory recommitted, or nodes will refuse the circuit.
