# Compiled Arcis circuits

Built by `arcium build` from `encrypted-ixs/src/lib.rs` and committed here so a durable, public
URL exists for the computation definitions (the on-chain `init_clear_*_comp_def` instructions
register these files by URL; the ARX nodes fetch them and check the SHA-256 that is baked into
the program at build time via `circuit_hash!`).

| circuit | sha256 |
| --- | --- |
| clear_unilateral.arcis | 3aa0dd6bef51bdc5c2b7eb224f5110b3590eb01eb1cde6e7b86fbbae62eea91d |
| clear_route.arcis | 17cdd545e2977027ef82bb7d5e2af2fc4366f138dc67e76be92317117283be6a |

Rebuilding the circuits changes the hash; the program must be rebuilt and redeployed with the
same `build/` output, and this directory recommitted, or nodes will refuse the circuit.
