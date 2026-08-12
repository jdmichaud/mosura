# Plan — porting Ghidra's debug-information story to mosura

Ghidra reads DWARF, PDB and CodeView, and lets what it finds override what analysis guessed.
mosura reads none of it. This is the plan to close that, faithfully, with the testing story
that makes each step checkable.

Status: **not started.** Nothing in this document is implemented yet. Live task status belongs
in [`TODO.md`](../TODO.md); this file is the design and the sequence.

## 0. What Ghidra actually does (the inventory)

Five independent consumers, all Java-side, all analyzers writing into the Program DB:

| Consumer | Where | Size | Gate |
|---|---|---|---|
| `DWARFAnalyzer` | `app/plugin/core/analysis/DWARFAnalyzer.java` + `app/util/bin/format/dwarf/` | 113 files, 20,440 lines | `DWARFSectionProviderFactory` finds sections |
| `PdbUniversalAnalyzer` | `Features/PDB/.../pdb2/pdbreader` + `pdb/pdbapplicator` | 591 + 80 files, 75,680 lines | PE with a PDB reference |
| `PdbAnalyzer` | `Features/PDB/.../format/pdb` | 23 files, 5,266 lines | Windows-only (MSDIA COM) |
| CodeView / COFF debug | `app/util/bin/format/pe/debug/` | 48 files | PE debug directory |
| `GolangSymbolAnalyzer` | `app/plugin/core/analysis/` | — | Go build info present |

Both headline analyzers are `AnalyzerType.BYTE_ANALYZER` at
`AnalysisPriority.FORMAT_ANALYSIS.after()` and **default-enabled**. That priority is the whole
design: debug import runs *after* the loader has laid out memory but *before* disassembly and
function discovery, so everything downstream sees debug-derived functions, types and names as
inputs rather than as corrections.

`DWARFAnalyzer.added()` is worth reading once for the shape it imposes: it runs at most once per
analysis transaction (`txId == lastTxId` → return), skips if a `DWARF Loaded` program property
says the work is done, asks the factory for a section provider and **silently declines** when
there is none (`"Unable to find DWARF information, skipping"`), and logs — without failing — when
the language has no DWARF register mapping. Declining is a first-class outcome, not an error.

`DWARFImporter.performImport()` is four phases, each behind an option:

1. `dwarfDTM.importAllDataTypes()` — every DIE type into the DataTypeManager
2. `DWARFFunctionImporter.importFunctions()` — signatures, params, locals, storage
3. `moveTypesIntoSourceFolders()` — cosmetic category organisation
4. `addSourceLineInfo()` — the line program into the program's source map

`DWARFImportOptions` carries 22 knobs. The ones with semantics (not cosmetics):
`importDataTypes`, `importFuncs`, `createFuncSignatures`, `importLocalVariables`,
`outputSourceLineInfo`, `ignoreParamStorage`, `useStaticStackFrameRegisterValue`, `defaultCC`,
`elideTypedefsWithSameName`, `tryPackStructs`, `specialCaseSizedBaseTypes`,
`copyExternalDebugFileSymbols`.

Two structural details to copy rather than reinvent:

- **`DWARFFunctionFixup` is an extension point** with seven implementations shipped
  (`SanityCheck`, `StorageVerification`, `OutputParamCheck`, `ParamName`, `ParamSpill`,
  `ThisCallingConvention`, `Rust`). A prototype is assembled from DWARF and then *filtered* by a
  chain of fixups that can reject it outright. This is where "DWARF said so" stops being
  authoritative, and it is the part a naive port omits.
- **Version support is deliberately partial.** `DWARFUnitHeader.read` throws below v2, takes v2–v4
  through `readV4`, and for v5 accepts **only** `DW_UT_compile` —
  `DW_UT_type`/`partial`/`skeleton`/`split_compile`/`split_type` all throw "Unsupported unitType".
  Split DWARF is *not* supported. Parity means reproducing that refusal, not exceeding it.

## 1. The finding that shapes this plan: we have the bytes, not the sink

The parser is the easy half. mosura's problem is that there is nowhere to put the answer.

| Ghidra sink | mosura today |
|---|---|
| `DataTypeManager` — named, categorised, persistent types | **does not exist** |
| `Function` with signature, params, locals, calling convention | `Function { entry_point, name, body }` — `program/function.rs:12` |
| `FuncProto` with `inputlock`/`outputlock`/`typelock` | `FuncProto { params: Vec<ProtoSlot>, output }` — `decompile/fspec.rs:1167`, **recovered only, no locks** |
| `Datatype` hierarchy with names, typedefs, enums, unions | `Datatype` enum — `decompile/types.rs:9`; anonymous, `Struct(size, Vec<(offset, ty)>)` has no field names |
| Source map (address → file:line) | **does not exist** |
| PE debug directory | **not parsed** — nothing in `loader/pe.rs` |
| ELF `.debug_*` bytes | **reachable** — `loader/elf.rs:392` already reads `sh_offset`/`sh_size` per section |

The last row is the only green one, and it matters: byte supply for ELF is a non-problem.
Everything else is missing, and the *middle* rows are the real work.

The critical one is `FuncProto`'s missing lock. In Ghidra, debug info changes decompilation
because a Program-DB function with a locked signature is handed to the decompiler as a
*constraint*, and `ActionInputPrototype`/`ActionOutputPrototype` respect it instead of running
recovery. mosura has only the recovery half (`recover_input_params`, `recover_output`,
`recover_func_proto`). **Until a declared prototype can enter the decompiler and win, a DWARF
parser changes nothing an observer can see.** That inverts the natural build order: the override
path comes first, and it is testable long before any DWARF byte is read.

Second finding, on the corpus: **no committed binary carries debug info.**
`oracle/analysis-corpus/build.sh` passes `-g` nowhere, no committed ELF has a `.debug_*` section,
and the DOS-era games are empty too — `WRMS.EXE` and `DESCENTR.EXE` both have `e32_debuglen = 0`
in their LE headers, and no CodeView (`NB09`/`NB10`/`RSDS`), HLL or Watcom-debug marker appears in
any of Flashback, Descent, Worms or POOL.EXE. So this track needs its own corpus, and adding one
perturbs existing measurement (§5h).

Note also that this is a **parity** port, not a beyond-Ghidra feature: DWARF import lives inside
Ghidra, so it belongs in the default dispatch, unlike the X-32 loader
([`docs/x32-loader-notes.md`](x32-loader-notes.md)) which is opt-in by policy.

## 2. Scope: DWARF first, PDB deferred

DWARF is 20k lines; PDB is 76k across a reader and an applicator, plus a Windows-only DIA variant
we can never run. DWARF also has the better test story by a wide margin — the fixtures are
`gcc -g`, reproducible on this machine, at any DWARF version, for any of our target architectures.
So: **all of DWARF, then reassess.**

In scope: DWARF v2–v5 (`DW_UT_compile` only, per §0), ELF as the container, external debug files,
x86/x86-64 register mappings, types, signatures, locals, source lines.

Out of scope for this plan (each a follow-on, each noted so nobody assumes coverage): PDB
(either implementation), PE CodeView/COFF debug symbols, Go, MachO `.dSYM`, `.debug_macro`,
split DWARF (Ghidra refuses it too), and the ~19 non-x86 `.dwarf` register mappings beyond
whichever architectures the multi-arch track has already reached.

## 3. Architecture to port, in dependency order

**D0 — the Program-DB sink.** A type registry and function signatures on the analysis side.
This is the port of `DataTypeManager` at the granularity we need (named types, categories,
composites with *named* fields, typedefs, enums, unions) plus `Function` gaining a signature,
parameters with storage and names, locals, and a calling convention. Large, and shared with the
type-system track — the decompiler's `Datatype` (`decompile/types.rs`) and Ghidra's Java
`DataType` are two different systems in Ghidra too, and the port keeps them separate for the same
reason. D0 is where debug facts *land*.

**D1 — the override path (the payoff gate).** `FuncProto` gains Ghidra's `inputlock`,
`outputlock`, `typelock`; `ActionInputPrototype`/`ActionOutputPrototype` honour a locked
prototype instead of recovering one; the local-variable scope (`decompile/varmap.rs`, `ScopeLocal`)
accepts externally-supplied names instead of only generating them. Faithful to Ghidra's own
mechanism, and **independently testable with hand-declared prototypes and zero DWARF** — which is
exactly how it should be built, because it decouples "can declared info win?" from "can we parse
DWARF?".

**D2 — section supply.** `DWARFSectionProvider` and its factory: `BaseSectionProvider` (sections
in the program), `CompressedSectionProvider` (the `z`-prefix convention — `.zdebug_info` etc.,
inflated and cached per base name; note this is the legacy GNU form, *not* `SHF_COMPRESSED`),
`ExternalDebugFileSectionProvider`, `NullSectionProvider`. Then `dwarf/external/`: build-id and
`.gnu_debuglink` lookup (`elf/info/GnuDebugLink.java`), `SameDirSearchLocation`,
`LocalDirectorySearchLocation`, a registry, and `ExternalDebugFileSymbolImporter` for the
symbols-only case. Mechanical, well-isolated, and the first place a real `-g` binary is touched.

**D3 — the DIE layer.** `DWARFProgram`, `DWARFCompilationUnit` (`readV4`/`readV5`),
`DebugInfoEntry`, the abbreviation reader, `dwarf/attribs/` (form decoding, including v5
`str_offsets`/`addr`/`rnglists`/`loclists` indirection via `DWARFIndirectTable`), `DWARFTag`,
`StringTable`, `DWARFName`/`NamespacePath`, `DWARFRange`/`DWARFRangeList`. Pure parsing over a
byte supply — the part where synthetic fixtures do the heavy lifting.

**D4 — the type importer.** `DWARFDataTypeManager` and `DWARFDataTypeImporter`: DIE →
D0 type, with Ghidra's specific decisions preserved — `elideTypedefsWithSameName`,
`copyRenameAnonTypes`, `tryPackStructs`, `specialCaseSizedBaseTypes`, `NameDeduper`,
`fixupAnonStructMembers`. Bitfields, incomplete types, and cycles are the substance here.

**D5 — the function importer.** `DWARFFunctionImporter`, `DWARFFunction`, `DWARFVariable`, the
location decoder (`dwarf/expression/`: `DWARFExpression`, `DWARFExpressionEvaluator`, the opcode
set), `DWARFLocationList`, `DWARFRegisterMappings` (§4), and the seven `funcfixup` implementations
as a real chain with the same ordering and veto semantics. Feeds D1.

**D6 — line numbers.** `dwarf/line/`: the line program state machine
(`DWARFLineProgramExecutor`, standard and extended opcodes, v5 content types) → a source map in
D0, plus `DWARFSourceInfo`. Independent of D4/D5 and separately valuable: address → `file:line`
is the single most useful debug fact for a human reading mosura's output.

**D7 — the analyzer.** `DwarfAnalyzer` registered at the mosura equivalent of
`FORMAT_ANALYSIS.after()`, with the once-per-session guard, the already-imported property, the
graceful decline when no provider matches, the missing-register-mapping warning, and an import
summary mirroring `DWARFImportSummary`. Small, but it is the piece that makes the rest reachable
from `analyze()`.

Dependency order: D0 → D1 (testable alone) → D2 → D3 → {D4, D6} → D5 → D7.

## 4. Parity artifacts copied verbatim

The 19 `.dwarf` files under `Ghidra/Processors/*/data/languages/` are configuration, not code —
the same category as `.cspec` and `.sla`, and copied the same way:

```xml
<register_mapping dwarf="0" ghidra="EAX"/>
<register_mapping dwarf="4" ghidra="ESP" stackpointer="true"/>
<register_mapping dwarf="11" ghidra="ST0" auto_count="8"/>
```

Ship `x86.dwarf` and `x86-64.dwarf` under `specs/` beside the cspecs, parsed into
`DWARFRegisterMappings`, resolved by language id exactly as `resolve_cspec` does today
(`crates/mosura/src/lang.rs`). The files also carry `call_frame_cfa` and `stack_frame` static
values that `DW_AT_frame_base`/`DW_OP_fbreg` resolution needs; `useStaticStackFrameRegisterValue`
is the option that consumes them. A missing mapping must degrade to a warning, never a failure —
that is what Ghidra does, and it is what lets architectures land incrementally.

## 5. The testing story

Debug-info import is unusually testable, and unusually easy to test *badly* — a parser that
reads `gcc`'s output is not the same as a parser that reads DWARF. Five layers, innermost first.

### 5a. Which oracle answers this, and which cannot

The C++ oracle (`oracle/capture`, `capture.cc`) **cannot** be used here. DWARF import is
Java-side; the C++ decompiler never sees a `.debug_info` section. It stays the oracle for D1's
decompiler-side behaviour (a locked prototype's effect on output is a C++ concern), but it is
blind to D2–D6.

The Java-side oracle already exists and is the right vehicle:
`oracle/ghidra_scripts/DumpAnalysisSnapshot.java` driven by `analyzeHeadless`, producing
`goldens/analysis/*.snapshot` parsed by `crates/mosura/src/analysis/snapshot.rs` — the harness
documented in [`oracle/analysis-capture.md`](../oracle/analysis-capture.md). Since `DWARFAnalyzer`
is default-enabled in headless analysis, a snapshot of a `-g` binary captures its effects for
free. What is missing is snapshot *vocabulary*.

### 5b. Snapshot format extension

Today's record kinds are `block`, `data`, `entry`, `fnbody`, `func`, `insn`, `ref`, `sym`. The
parser ignores unknown prefixes by design, so old goldens keep working as we add:

- `proto <addr> <cc> <ret-type> (<type> <name> @<storage>, …)` — the imported signature
- `local <addr> <type> <name> @<storage>` — imported locals
- `type <path>/<name> <kind> size=<n> [fields…]` — imported types
- `srcline <addr> <file>:<line>` — the source map
- `dwarfsummary <n-types> <n-funcs> <n-lines> <n-errors>` — the `DWARFImportSummary` shape

Ordering and normalisation rules follow the existing ones; types are printed canonically so
category cosmetics (phase 3 of `performImport`) do not churn goldens.

### 5c. Layer 1 — synthetic fixtures, no binaries committed

The pattern that worked for the LE and X-32 loaders (`tests/le_loader.rs`, `tests/x32_loader.rs`):
Rust builders that emit the container and the debug sections byte by byte, so each test states
*exactly* which bytes produce which conclusion, and the suite needs no third-party material.

A `DwarfBuilder` emitting a minimal `.debug_abbrev` + `.debug_info` + `.debug_line`
inside a synthetic ELF, with a case matrix over: DWARF v2/v3/v4/v5; 32- and 64-bit DWARF
(`0xffffffff` length escape); little- and big-endian; `DW_FORM_*` coverage including v5
indirection; `DW_UT_compile` accepted vs the five unit types Ghidra refuses. Every gate that
follows is then a handful of DIEs, and the negative gates (§5g) are where this layer earns its
keep — malformed DWARF is trivial to *build* and near-impossible to *find*.

### 5d. Layer 2 — a compiled corpus

`oracle/debug-corpus/build.sh` beside the existing analysis corpus, committed (goldens must be
toolchain-stable), each binary tiny and reviewable:

| Fixture | Why |
|---|---|
| `dwarf4.elf`, `dwarf5.elf` (`-gdwarf-4` / `-gdwarf-5`) | the two shapes in the wild |
| `dwarf_o2.elf` (`-g -O2`) | inlining, `DW_AT_ranges`, location lists, spilled params — where `ParamSpill` and `StorageVerification` fire |
| `dwarf_types.elf` | struct/union/enum/typedef/bitfield/anon/array/function-pointer/cycle |
| `dwarf_cpp.elf` (`g++ -g`) | namespaces, `this` → `ThisCallingConventionDWARFFunctionFixup` |
| `dwarf_debuglink.elf` + `.debug` | `.gnu_debuglink` external lookup (D2) |
| `dwarf_buildid.elf` + `.build-id/…` | build-id external lookup (D2) |
| `dwarf_zdebug.elf` (`-gz=zlib-gnu`) | `.zdebug_*`, the form `CompressedSectionProvider` handles |
| `dwarf_split.elf` (`-gsplit-dwarf`) | **must be refused**, matching Ghidra |
| `dwarf_stripped.elf` | no debug info → the graceful-decline path |

`clang -g` variants where the producer differs materially. The same `.c` sources compiled without
`-g` give paired debug/no-debug binaries, which is what makes §5f measurable.

### 5e. Layer 3 — Ghidra-parity snapshots

For every layer-2 fixture, a committed `.snapshot` captured through `analyzeHeadless` +
`DumpAnalysisSnapshot`, and a mosura test asserting equality on the extended record kinds. This
is the actual parity bar: not "we parsed DWARF" but "we reached the same Program state Ghidra
reached, including where Ghidra declines, warns or lets a fixup veto a signature".

Per-option coverage matters here. `DWARFImportOptions` has 22 knobs and Ghidra's defaults are
what the snapshot records; each semantic option we implement gets at least one non-default
snapshot so the option is proven to *do* something.

### 5f. Layer 4 — the decompilation effect

The reason any of this exists. Using the paired debug/no-debug binaries, `ccompare` mosura's
output against Ghidra's *with DWARF applied*, and separately assert that the debug-informed run
differs from the debug-free run in the expected direction: named parameters instead of
`param_1`, declared types instead of `undefined4`, named locals instead of `local_18`, the
declared calling convention instead of the recovered one.

Note the interaction with `ccompare`'s type-name erasure documented in
[`docs/type-system-plan.md`](type-system-plan.md): the structural comparator maps type names to
`T`, so DWARF's *names* will not move that score. The score-visible wins are structural —
correct parameter *count* and *storage*, array indexing, casts. Both effects are worth measuring;
only one shows up in the existing metric, and the plan should not pretend otherwise.

### 5g. Layer 5 — robustness

Debug sections are attacker-adjacent and compiler-bug-adjacent. Requirements, each a test built
on the §5c builder: truncated `.debug_info`; a `DW_AT_type` pointing outside the unit; an
abbreviation code with no declaration; a cyclic type reference; an absurd array count; a
`DW_OP_*` we do not implement; a location expression that underflows its stack; a compilation
unit whose length runs past the section. Every one must produce a *reported* failure and a
program that still analyses — Ghidra's `reportError` continues; a panic is a bug. If the
project gains a fuzz target, the DWARF reader is the first place to point it.

### 5h. Measurement discipline

Adding debug info to the corpus perturbs existing numbers, so, per
[`docs/measurement-rules.md`](measurement-rules.md):

- New fixtures go in a **new** corpus directory. Existing `oracle/analysis-corpus` binaries stay
  `-g`-free so existing goldens stay comparable.
- Function-count and FID-coverage baselines must be re-cut when debug-derived functions appear:
  DWARF creates functions Ghidra's discovery would not have found, and names functions FID would
  otherwise have named. Report the two effects separately or the FID numbers become unreadable.
- The DOS-era corpus is unaffected — it has no debug info at all (§1) — so `WAR2`, Descent,
  Flashback, Worms and POOL.EXE measurements are untouched by this whole track.

## 6. Phases and exit criteria

| Phase | Content | Exit criterion |
|---|---|---|
| P0 | D0 sink: type registry + function signatures | round-trip tests; nothing else changes |
| P1 | D1 override path + snapshot vocabulary (§5b) | a **hand-declared** prototype changes decompiler output, matched against the C++ oracle via `DecompileWithForcedParams` |
| P2 | D2 section supply + D7 analyzer skeleton | `dwarf_stripped.elf` declines gracefully; `dwarf_debuglink.elf`/`dwarf_buildid.elf` locate their external file; `dwarf_split.elf` is refused exactly as Ghidra refuses it |
| P3 | D3 DIE layer | §5c matrix green: v2–v5, 32/64-bit, both endians, all `DW_FORM`s in the fixtures; §5g negatives all report-and-continue |
| P4 | D6 line numbers | `srcline` snapshot parity on `dwarf4.elf`/`dwarf5.elf` |
| P5 | D4 types | `type` snapshot parity on `dwarf_types.elf`, including bitfields and cycles |
| P6 | D5 functions + fixup chain | `proto`/`local` snapshot parity on all fixtures, `-O2` included; each of the seven fixups has a test that shows it firing |
| P7 | measurement | §5f: `ccompare` on paired binaries, with the two effects reported separately |

P1 is the one to be strict about. It is the only phase that delivers user-visible value with no
DWARF at all, and it is the phase that proves the rest is worth building.

## 7. Honest scope — what this does not buy

- **Nothing for the DOS-era corpus.** Zero debug info in any of it (§1). Those binaries are FID
  and cspec territory, and that is the correct tool for stripped 1990s game code.
- **Nothing for stripped modern binaries**, which is most of what anyone reverse-engineers.
- **No PDB**, so nothing for the Windows corpus — 76k lines deferred, deliberately (§2).
- **Not a decompiler-quality win by itself.** Debug info makes output *readable* (real names, real
  types); it makes it *structurally* better only where the declared prototype differs from the
  recovered one. Expect the readability win to be large and the `ccompare` win to be modest.

The strongest reason to do it anyway is diagnostic: a `-g` binary is ground truth. Every
parameter, type and stack slot the compiler recorded is a statement mosura's recovery can be
checked against — for the first time, without Ghidra in the loop.
