# Dial-patch experiment instruments (2026-08-22)

The compiler-binary-surgery experiment briefed in `docs/watcom-dial-patch-experiment.md`.
Results, with every offset, byte and sha256, are in `docs/watcom-dial-patch-results.md`.

These are **instruments, not product**. None of them is on any build path; byte-exactness stays
defined against stock 10.0a. They live here so the measurements in the results document are
reproducible.

Every patch script is idempotent, asserts its pre-image bytes and refuses on mismatch, and takes
the target path as an argument — **always pass a copy**, never
`the RE tracker/tmp/watcom-experiments/watcom_10.0a/WATCOM`.

| script | what it does |
| --- | --- |
| `patch_dialA_ebx_ecx.py` | swaps EBX/ECX in the 4-byte allocation table at file `0x7ba50`. **Rejected as an instrument**: in 10.0a that table is also the parameter table, so this changes the calling convention. Kept as the worked negative. |
| `patch_dialA_tieorder.py` | `0x59ea3` `7f`→`7d`. Flips `GiveBestReg`'s equal-score tie-break from first-wins to last-wins. The measured Dial-A patch. |
| `patch_dialB_weights.py` | four variants of `InsStallable`'s operand-stall weights (`reg0`, `reg1`, `idx1`, `idx5`). |
| `patch_dialB_idorder.py` | `0x661bd` `7e`→`7d`. Reverses `ScheduleIns`'s final source-order tie-break. Diagnostic only. |

Binary-reconnaissance instruments (read-only, take a `wcc386.exe` path):

| script | what it does |
| --- | --- |
| `find_regtables.py` | derives the `hw_reg_set` byte encoding from `cgi86reg.h` and locates every `386rgtbl.c` register table by signature |
| `maptables.py` | decodes a byte range as an array of `hw_reg_set` words and names each register |
| `census_doubleregs.py` | finds the allocation-order table in *any* Watcom `wcc386` whatever its order — used for the 8.5a → OW2 version census |
| `findrefs.py` | finds little-endian u32 references to an address (how the file↔VA delta of `0x2200` was pinned) |

Source-side probes (take a function index/name, use stock 10.0a):

| script | what it does |
| --- | --- |
| `permute.py` | searches local-declaration-order permutations of one recovered function for a byte-exact one |
| `declorder_ceiling.py` | the corpus-wide ceiling census of that axis, batched one permutation-round per dosemu session |

**Always use a separate compile cache for a patched compiler.** The cache is keyed on source
content plus toolchain id, and a binary patch does not change the toolchain id, so a shared cache
silently serves stock objects. One cache dir per variant; the ones used are named in the results
document.
