# Dependency manifest

The one auditable inventory of every external dependency the repo relies on: what it is, how
it is located, how it is pinned, and what breaks without it. Move #1 of the
dependency-hardening line (#15).

**Portability rule (hard constraint).** This manifest contains **no absolute paths** — nothing
machine-specific like `/home/<user>/…`. Every dependency is located through an **environment
variable** with a sensible **relative default**, so a reader can place a dependency anywhere
and point the var at it. The two anchors used below:

- **`$REPO`** — the mosura repo/worktree root (the directory containing `crates/`, `oracle/`,
  `goldens/`, `specs/`, `scripts/`, `docs/`). The code derives it automatically from
  `CARGO_MANIFEST_DIR` (`crates/mosura/src/paths.rs::workspace_root`); it is never hard-coded.
- **`$HOME`** — the user's home directory. Used only for dependencies that live outside the
  repo tree and have no in-tree default.

## The key insight: the test/ship surface is small

**A clean clone + the pinned Ghidra processor data + the in-repo committed goldens/fixtures
runs the full `cargo test` suite.** Everything else — the Ghidra C++ oracle tools,
`analyzeHeadless`, the cross-toolchains, Open Watcom, dosemu2, `warcraft2-re`, and the
user-provided binaries — is **regeneration-only**: it exists to re-derive the committed
goldens and fixtures, and is never touched by `cargo test`. The user-provided-binary gates
**skip when the file is absent**, so they never fail a clean checkout.

Two tiers, made explicit:

- **BUILD/TEST** — needed by `cargo test`. In practice: the Rust toolchain, the Ghidra
  processor **data** (via `GHIDRA_SRC`, with the `.sla` compiled once), and the committed
  in-repo test data. That's the entire shipping/testing surface.
- **DEV-ORACLE** — needed **only** to regenerate goldens/fixtures, **not** by `cargo test`:
  `oracle/capture`(+`_trace`), `decomp_dbg`/`decomp_test_dbg`, `analyzeHeadless`, the
  cross-toolchains, Open Watcom, the historical Watcom 10.0a toolchain, dosemu2,
  `warcraft2-re`, and the user-provided binaries.

## Inventory

Locator column reads `ENV_VAR → default` where the default is `$REPO`- or `$HOME`-relative.
`n/a` = a host toolchain resolved from `PATH`, not a repo-configured location.

### BUILD/TEST tier — `cargo test` needs these

| Dependency | Locator (env → default) | Pin / version | Source |
| --- | --- | --- | --- |
| Rust + Cargo toolchain | `n/a` (PATH / rustup) | edition per `Cargo.toml`; stable | rustup / distro |
| **Ghidra processor data** (`.slaspec`/`.pspec`/`.cspec`/`.ldefs`/`.opinion`) | `GHIDRA_SRC → $REPO/../ghidra` | tag `Ghidra_12.0.3_build`, commit `09f14c92d3da6e5d5f6b7dea115409719db3cce1` | git `github.com/NationalSecurityAgency/ghidra` |
| Compiled `.sla` (what mosura's engine loads) | under `GHIDRA_SRC/Ghidra/Processors/*/data/languages/` | built from the pinned `.slaspec` | produced once by `sleigh_opt` (see below) |
| `sleigh_opt` (compiles `.slaspec → .sla`, one-time) | built in-place in `GHIDRA_SRC` by `scripts/setup-oracle.sh` | from the pinned Ghidra cpp source | Ghidra source + g++/bison/flex/libbfd |
| In-repo committed test data (goldens + fixtures + corpus + repo cspec) | in `$REPO` (committed) | tracked in git | this repo — see [In-repo test data](#in-repo-test-data-committed-not-external) |

Notes on the Ghidra BUILD/TEST dependency:
- **Vendored in-repo fallback — `cargo test` is self-contained from a bare clone.** The exact
  subset the tests read (the used processors' `data/languages` incl. compiled `.sla`, and the
  decompiler datatests) is committed at `third_party/ghidra/` (~9.5 MB, Apache-2.0 with Ghidra's
  LICENSE/NOTICE alongside; provenance in its README). Resolution order (`paths.rs`):
  `GHIDRA_SRC` env → the sibling checkout → the vendored copy, so a developer's checkout wins
  when present and a bare clone needs **no fetch and no sleigh compile**.
  `scripts/verify-vendored-ghidra.sh` proves the vendored copy byte-identical to the pin
  (`--refresh` re-copies after a pin bump), and the `sleigh_canary` test **fails loudly** —
  where other suites skip — if language tables/datatests stop resolving (added after a deleted
  checkout silently hollowed the suite: green run, sleigh-gated tests all skipping). The
  checkout is still required for the DEV/ORACLE tier (decompiler C++ reference, oracle tools,
  golden regeneration).
- **One-command acquisition (the pin).** `scripts/setup-ghidra.sh` fetches this dependency
  reproducibly: it shallow-clones `github.com/NationalSecurityAgency/ghidra` at the pinned tag
  into `GHIDRA_SRC` (default `$REPO/../ghidra`), **verifies `HEAD` == the pinned commit
  `09f14c92…`** (a git commit id is a content hash, so this is the checksum), and compiles the
  `.sla`. It is idempotent (an existing checkout at the pin is reused, never clobbered) and has
  a `--verify-only` mode (assert the pin without fetching — for CI). A **fetch script, not a git
  submodule**: the checkout is a sibling *outside* `$REPO`, Ghidra's full history would bloat
  every clone, and a fresh source clone needs the post-fetch sleigh compile a submodule can't do.
- **Data, not the whole clone.** `crates/mosura/src/lang.rs` reads the processor `.ldefs`
  (for the `slafile`/`processorspec`/`cspec` names), then loads the compiled **`.sla`** plus
  the `.pspec`/`.cspec`. Those are the only Ghidra files `cargo test` touches.
- **The `.sla` is a build artifact, not shipped.** A fresh Ghidra clone does **not** contain
  compiled `.sla` (they are git-ignored outputs). Producing them is a one-time
  `sleigh_opt -a` step — `setup-ghidra.sh` runs it (via `setup-oracle.sh --sla-only`, the
  minimal sleigh_opt build + spec compile, no oracle tools); `sleigh_opt` itself builds fast
  from the pinned cpp source, offline. After that, `cargo test` is self-contained.
- **What breaks without it:** every disassembly/p-code/analysis test — the SLEIGH engine has
  no language tables to load. This is the single mandatory external dependency of the suite.

### DEV-ORACLE tier — regeneration only; NOT needed by `cargo test`

| Dependency | Locator (env → default) | Pin / version | Regenerates |
| --- | --- | --- | --- |
| `oracle/capture` + `oracle/capture_trace` | `$REPO/oracle/capture[_trace]` (built) | links Ghidra `libdecomp_dbg.a`, `-DCPUI_DEBUG -D__TERMINAL__` | `goldens/disasm/*.golden` (`cargo xtask baseline`); rule-trace diffs |
| `decomp_dbg` / `decomp_test_dbg` (Ghidra C++ oracle) | built in `GHIDRA_SRC` by `setup-oracle.sh` | pinned Ghidra source | raw-p-code cross-check; runs Ghidra's own datatests |
| `analyzeHeadless` (built Ghidra **distribution**) | `GHIDRA_DIST → GHIDRA_SRC/build/dist/ghidra_*_DEV` | built from the pinned source by `scripts/build-ghidra-dist.sh` | `goldens/analysis/*.snapshot` (`scripts/capture-analysis.sh`) |
| JDK (to build the Ghidra dist) | `n/a` (PATH / `JAVA_HOME`) | OpenJDK **21** (tested 21.0.11) | prerequisite of `build-ghidra-dist.sh` |
| Host `gcc`/`g++` | `n/a` (PATH) | Debian gcc **14.2.0** | `freestanding/basic/switchtab/cppsym.elf` (x86-64) |
| aarch64 cross-gcc | `n/a` (PATH: `aarch64-linux-gnu-gcc`) | apt `gcc-14-aarch64-linux-gnu` **14.2.0-19cross1** | `aarch64.elf` |
| riscv64 cross-gcc | `n/a` (PATH: `riscv64-linux-gnu-gcc`) | apt `gcc-14-riscv64-linux-gnu` **14.2.0-19cross1** | `riscv.elf` |
| m68k cross-gcc | `n/a` (PATH: `m68k-linux-gnu-gcc`) | apt `gcc-14-m68k-linux-gnu` **14.2.0-19cross1** | `m68k.elf` |
| sdcc (+ `sdasz80`/`sdldz80`/`makebin`) | `n/a` (PATH: `sdcc`) | apt `sdcc` **4.5.0+dfsg-1** | `z80.com` |
| **Open Watcom** (built `wcc386`, native Linux) | `GT_WATCOM → $HOME/tools/open-watcom` (`wcc386` at `$GT_WATCOM/binl/wcc386`) | built from git `open-watcom/open-watcom-v2` HEAD `4e566a7891`; **source tree dropped, only the ~295 MB release retained** (grounding is committed — cspec citations + inlined banner strings) | empirical `watcall` cross-check + `watcall_probe.c` + the `narrowsw`/`watprog` ground-truth columns (runs native on Linux — no dosemu2) |
| **Watcom 10.0a toolchain** (historical, under dosemu2) | *unpinned — see [Gaps](#gaps--honesty-notes)* | release **10.0a** (not publicly pinned) | `watcom_hello.exe` fixture + CLIB3R.LIB banner strings |
| **dosemu2** (to run the DOS Watcom 10.0a tools) | `n/a` (PATH: `dosemu`) | `dosemu2-2.0pre9-dev-20260428-4642-gc24eb0498` (source/PPA build, not dpkg-owned) | prerequisite for the Watcom 10.0a fixture regen only |
| **warcraft2-re** (RE ground truth, read-only) | `WARCRAFT2_RE → $HOME/projects/warcraft2-re` | git `github.com/jdmichaud/warcaft2-re` HEAD `71f8193` | reference (not executed): WAR2 objects/entry/switch ground truth for the native-LE two-oracle path |

### User-provided binaries — skip-if-absent gates

Copyrighted third-party files; **not committed**. The tests that use them **skip when the
file is absent**, so `cargo test` is green on a clean checkout without any of them. sha256 is
recorded so a reader can confirm they have the exact artifact these gates were written
against.

| Binary | Locator (env → default) | sha256 / size | Used by | What it validates |
| --- | --- | --- | --- | --- |
| `WAR2.EXE` (DOS/4GW-bound Watcom LE) | `MOSURA_WAR2_EXE → $HOME/WAR2.EXE` | `4789987d1c4f4c3d02ad28cd20377d58d54f51c1fd2976d842ac33861eed0f63` / 878119 B | `le_war2_analysis`, `le_war2_objects`, `watcom_detection` | native-LE analysis + Watcom detection ground truth |
| `cnv.exe` (Clang PE) | `MOSURA_CNV_EXE → $HOME/cnv.exe` | `132b8d5c005cc0cdb6c5e7f91d326eb1339f4faf97c132c94552bc6d65dd9903` / 1075200 B | `pe_compiler_opinion` | `PeLoader.CompilerOpinion` → `clangwindows`/`clang:unknown` |
| `comcom32.exe` (DJGPP MZ) | `MOSURA_COMCOM32_EXE → $HOME/.local/share/comcom32/comcom32.exe` | `e079ab24ef15a2855fde282c4a2fc020b09fc720487e67b82ec2f2f0c98cea56` / 219648 B | `watcom_detection` | Watcom no-false-positive (non-Watcom MZ → `unknown`) |

> **Implemented (task #6).** These three env vars are live, resolved by
> `crates/mosura/src/paths.rs::{war2_exe, cnv_exe, comcom32_exe}` (env override, else the
> `$HOME`-relative default above — the same convention as `GHIDRA_SRC`/`GHIDRA_DIST`). The
> tests (`analysis_parity.rs`, `analysis/loader/{pe,mz}.rs`, `analysis/mod.rs`) and
> `scripts/capture-analysis.sh` + `scripts/ci-clean-clone.sh` all honor them; no absolute path
> is baked into code, tests, or scripts.

### In-repo test data (committed; not external)

Part of the `cargo test` surface, but tracked in git — **not** an external dependency; listed
so the full test surface is auditable. All under `$REPO`:

| Data | Location | Count | Regenerated by |
| --- | --- | --- | --- |
| Disasm/p-code goldens | `goldens/disasm/*.golden` | 16 | `cargo xtask baseline` (needs `oracle/capture`) |
| Analysis snapshots | `goldens/analysis/*.snapshot` | 21 | `scripts/capture-analysis.sh` (needs `analyzeHeadless`) |
| Capture fixtures | `oracle/fixtures/*.xml` | 31 | hand-authored / extracted |
| Analysis corpus | `oracle/analysis-corpus/*.elf` (7) + `z80.com` + `watcom_hello.exe` | 9 | `oracle/analysis-corpus/build.sh` (needs the cross-toolchains + Watcom 10.0a) |
| Ground-truth corpus | `oracle/ground-truth/*.<cc>-<arch>` (stripped) + `*.truth` | 2 (phase-1) | `oracle/ground-truth/build.sh` (needs the toolchains; truth derived by nm+objdump) — source-owned oracle, not Ghidra ([`ground-truth-corpus.md`](ground-truth-corpus.md)) |
| SLEIGH decode fixture | `crates/mosura/tests/fixtures/sla/6502.sla` | 1 | committed |
| Repo-owned cspec (beyond-Ghidra) | `specs/x86-32-watcom.cspec` | 1 | hand-authored (Open Watcom source) |

Corpus binary checksums (committed, for reference): `watcom_hello.exe`
`73598262a8e517540ca3693628441eb38493faa719dc1e66db42e1fe3ba0931d` (15995 B); `z80.com`
`032da06bab8dc812c0db20ef8945deee70d7ce9218c470ca5ac07dfe806688a0` (65 B).

## Build prerequisites (DEV-ORACLE builds only)

For the Ghidra oracle/dist builds — **not** needed by `cargo test`:

- **C++ oracle** (`scripts/setup-oracle.sh`): `g++`, `make`, `bison`, `flex`, and `bfd.h`.
  Debian/Ubuntu: `sudo apt-get install -y build-essential bison flex binutils-dev libbfd-dev zlib1g-dev`.
- **Ghidra distribution** (`scripts/build-ghidra-dist.sh`): JDK 21, the bundled `./gradlew`
  wrapper, network access for the first dependency fetch, and a UTF-8 locale
  (`LC_ALL=C.UTF-8`; the build sets it — a non-ASCII jar entry trips ASCII `sun.jnu.encoding`).

### Compiler-detection & version fixtures — historical toolchains (DEV-ORACLE)

Used **only** to regenerate PE/MZ compiler-detection fixtures (`pe_compiler_opinion`) and the
Watcom banner→version table (`watcom_detection`); the resulting fixtures + goldens are
**committed**, so `cargo test` never needs any of this. All of it is a beyond-Ghidra /
WAR2-recompilation aid, not a build/test dependency.

- **Toolchain archives** live outside the repo at `MOSURA_TOOLS → $HOME/projects/tools`
  (env-var-located, `$HOME`-relative default — no absolute path). Three families, each as raw
  `.7z`/ISO archives, **extracted on demand** (`7z x …`) into the scratch workspace:
  `watcom/` (9.5b, 10.0 LA preprod, 10.0a, 10.5, 10.6, 11.0, 11.0a — see `watcom/README.md`),
  `borland_turbo_c/` (Turbo C 1.0–2.01, Borland C++ 2.0–4.52/5), `visual_studio/`
  (MSVC 1.52, 2.0, 4.0, 5, 6.0, VS97, 2005).
- **Runners — a compiler needs the host it targets:**
  - **`dosemu2`** (PATH `dosemu`) runs the **DOS-hosted** compilers → 16-bit MZ / DOS-extended
    output: the Watcom `wcc386`/`wpp386` family (all eras), Turbo C 2.0, MSVC 1.52.
  - **`wine`** runs the **Win32-hosted** compilers → real PE output: MSVC 4.0/5/6.0, Borland
    C++ 4.x/5.x. `dosemu` **cannot** run these (16-bit DOS only). Only the genuine MSVC/Borland
    compilers produce the DOS-stub / `e_lfanew` / error-string tells `CompilerOpinion` keys on,
    so wine is the faithful path for the **VisualStudio** and **Borland** detection branches.
- **Native cross-compilers** (no wine) for the *other* `CompilerOpinion` branches:
  `gcc-mingw-w64` → **GCC** PE; `clang` → **Clang** PE (`clang-cl` approximates MSVC but is not
  it); `golang-go` (`GOOS=windows`) → **GOLANG**; `rustc`/rustup (`--target *-windows`) → **Rustc**.

**Debian 13 (trixie) install — packages verified present in apt:**

```sh
# A2 (32-bit dynamic ELF) — already required:
sudo apt install -y gcc-multilib libc6-dev-i386

# PE detection of the provided MSVC + Borland compilers (the primary need) — wine.
# MSVC/Borland here are 32-bit Windows apps, so i386 must be enabled for wine32:
sudo dpkg --add-architecture i386 && sudo apt update
sudo apt install -y wine wine64 wine32:i386 winbind          # winbind: wine runtime dep
sudo apt install -y p7zip-full                               # extract the ISO/.7z archives

# Optional — native cross-compilers for the other CompilerOpinion branches (no wine):
sudo apt install -y gcc-mingw-w64      # GCC PE  (14.2.0; x86-64 + i686)
sudo apt install -y clang              # Clang PE
sudo apt install -y golang-go          # GOLANG PE (GOOS=windows go build)
# rustc is packaged (rustc 1.85) but Windows cross-targets are easiest via rustup.
```

`dosemu2` itself is a source/PPA build (see the Watcom-10.0a gap note below), not a distro
package.

## Gaps / honesty notes

- **Watcom 10.0a toolchain is not publicly pinned.** It is a historical DOS toolchain run
  under dosemu2; no reproducible git tag / package version exists for it. This is acceptable
  because its only outputs — `watcom_hello.exe` and the CLIB3R.LIB banner strings — are
  **committed** (the fixture and the unit-test string literals), so the test surface never
  needs the toolchain. Regenerating that one fixture requires re-obtaining 10.0a. (The modern
  **Open Watcom** build is pinned and present, but it emits the *Open Watcom Contributors*
  banner, not the classic *WATCOM International Corp.* one — a different era fingerprint — so
  it does not substitute for 10.0a as the fixture source.) Follow-up: task #14.
- **`MOSURA_*_EXE` env vars are implemented** (task #6) — `paths.rs::{war2_exe,cnv_exe,comcom32_exe}`;
  tests + scripts honor them with `$HOME`-relative defaults (no hard-coded absolute paths).
- **dosemu2 is a source/PPA build**, not a distro package, so its pin is the build-string
  version rather than an `apt` version.
- **`warcraft2-re` origin spells `warcaft2-re`** (single `r`) in the remote URL — recorded
  verbatim so the clone URL is correct.

## Reproduction entry points (for context)

- Bootstrap the BUILD/TEST tier from a clean clone: `scripts/setup-ghidra.sh` (fetch + pin the
  Ghidra source, compile the `.sla`), then `cargo test`. `GHIDRA_SRC` overrides the location;
  `scripts/setup-ghidra.sh --verify-only` asserts an existing checkout is at the pin.
- Prove/guard the clean-clone split: `scripts/ci-clean-clone.sh` — fetches the pinned Ghidra
  then runs the FULL suite with none of the regeneration-only tooling present, so the BUILD/TEST
  surface can't silently grow a hard oracle/user-binary dependency (it would turn the run red).
  `--hermetic` hides a dev machine's local oracle tools + user binaries (restored on exit) to
  reproduce CI's absence locally. Run in CI by `.github/workflows/ci.yml` (portable; the script
  is the authority).
- Test surface: `cargo test -p mosura` (needs only the BUILD/TEST tier).
- Regenerate disasm goldens: `scripts/setup-oracle.sh` then `cargo xtask baseline`.
- Regenerate analysis goldens: `scripts/build-ghidra-dist.sh` then `scripts/capture-analysis.sh`.
- Regenerate the corpus: `oracle/analysis-corpus/build.sh` (cross-toolchains + Watcom 10.0a).
- Regenerate the ground-truth corpus: `oracle/ground-truth/build.sh` (toolchains; truth derived
  from the build via nm+objdump — the source-owned oracle, not Ghidra).
- Full reproduction chain: `oracle/analysis-capture.md`.
