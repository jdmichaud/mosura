---
name: ghidra-dependency-pin
description: "How the one hard build/test dep (Ghidra source) is fetched + pinned + compiled — scripts/setup-ghidra.sh, tag Ghidra_12.0.3_build @09f14c92."
metadata: 
  node_type: memory
  type: reference
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-07-20T17:21:19.838Z
---

The Ghidra source checkout is mosura's ONE mandatory build/test dependency (`paths.rs::
ghidra_src` reads .sla/.pspec/.cspec/.ldefs/.opinion + the decompiler datatests; already
repo-relative + `GHIDRA_SRC`-overridable — that part needed no change).

**Bootstrap from a clean clone: `scripts/setup-ghidra.sh`** (task#4, landed `6bc227d` on
analysis-port). Shallow-clones `github.com/NationalSecurityAgency/ghidra` at tag
`Ghidra_12.0.3_build` into `GHIDRA_SRC` (default `<workspace>/../ghidra`), VERIFIES
`HEAD == 09f14c92d3da6e5d5f6b7dea115409719db3cce1` (git commit id = content hash = the
checksum), then compiles the `.sla` (a fresh clone ships none — git-ignored). Idempotent
(existing checkout at the pin is reused, never clobbered). Modes: `--verify-only` (assert the
pin, no fetch — for CI), `--no-sla` (fetch only). It delegates the compile to the new
`scripts/setup-oracle.sh --sla-only` (build sleigh_opt + `sleigh_opt -a`, no oracle tools —
the minimal BUILD/TEST step, libbfd not needed).

**Fetch script, not a git submodule** (deliberate): the checkout is a sibling *outside* the
repo, Ghidra's full history bloats every clone, and a fresh source clone needs the post-fetch
sleigh compile a submodule can't do. Chosen per task#4's "submodule OR checksummed fetch".

Full doc: `docs/dependencies.md` (the manifest, BUILD/TEST tier). Shared infra (scripts/docs)
— user pre-authorized touching it without clearing.

**Dependency-hardening line:** #15 manifest (done) → #4 pin `6bc227d` (done) → **#5 CI
clean-clone split ✅ `1e8e986`**: `scripts/ci-clean-clone.sh` (fetch pinned Ghidra → full suite
with NO oracle tools; `--hermetic` hides local oracle/user-binaries with restore-trap to prove
it locally; validated green — ir_parity/decompile_corpus/le_subjects/pe_compiler_opinion all
skip-if-absent) + `.github/workflows/ci.yml` (thin, portable). Audited: no test shells to a
compiler/analyzeHeadless at test time → **#6 MOSURA_*_EXE vars ✅ `b0d298b`+`9b9dd7e`**:
`paths.rs::{cnv_exe,comcom32_exe}` (env override, `$HOME`-relative default); adopted in
all tests + capture-analysis.sh + ci-clean-clone.sh; docs flipped to implemented; ZERO
`/home/jd` literals remain in src/tests/scripts. `9b9dd7e`: `ci-clean-clone.sh --hermetic` now
points MOSURA_*_EXE at `build/hermetic-absent/*` (user's $HOME files NEVER moved; only in-repo
oracle tools still move-aside). Part-(a) audit: only beyond-Ghidra datum is the
watcall cspec (specs/, vendored); noreturn lists are Ghidra data vendored as `const` — nothing
else to vendor. **paths.rs is SHARED infra (decompiler track) — my change is additive-only.**
See (subject-profile note `dos4gw-le`).
