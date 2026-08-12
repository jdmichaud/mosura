# Plan — porting Ghidra's debug-information story to mosura

Ghidra reads DWARF, PDB, PE CodeView/COFF, Go symbol metadata and PEF debug, and lets what it
finds override what analysis guessed. mosura reads none of it. This plans **all of it**, faithfully,
with the testing story that makes each step checkable — plus the extension point the DOS-era
compiler formats will need later.

Status: **not started.** Nothing here is implemented. Live task status belongs in
[`TODO.md`](../TODO.md); this file is the design and the sequence.

## 0. What Ghidra actually does (the complete inventory)

| # | Consumer | Where | Size | Applied by | Gate |
|---|---|---|---|---|---|
| 1 | **DWARF** | `app/plugin/core/analysis/DWARFAnalyzer.java` + `app/util/bin/format/dwarf/` | 113 files, 20,440 lines | analyzer | `DWARFSectionProviderFactory` finds sections |
| 2 | **PDB Universal** | `Features/PDB/.../pdb2/pdbreader` + `pdb/pdbapplicator` | 671 files, 75,680 lines | analyzer | PE with a PDB reference |
| 3 | **PDB MSDIA** | `Features/PDB/.../format/pdb` | 23 files, 5,266 lines | analyzer | **Windows only** — needs the MS DIA-SDK |
| 4 | **PE CodeView + COFF** | `app/util/opinion/AbstractPeDebugLoader.java`, `app/util/bin/format/pe/debug/` | 48 files + loader | **loader**, not an analyzer | PE debug directory present |
| 5 | **Separate `.dbg`** | `app/util/opinion/DbgLoader.java`, `pe/SeparateDebugHeader.java` | — | loader | a `.dbg` file is opened |
| 6 | **Go symbols** | `app/plugin/core/analysis/GolangSymbolAnalyzer.java` + `format/golang/` | 1,327 lines + 85 files | analyzer | Go build info present |
| 7 | **PEF debug** | `app/plugin/core/analysis/PefDebugAnalyzer.java` | 117 lines | analyzer | PEF container |
| 8 | **MachO `.dSYM`** | `dwarf/sectionprovider/DSymSectionProvider.java` | — | feeds #1 | `.dSYM` bundle beside the binary |
| 9 | **External debug files** | `dwarf/external/`, `elf/info/GnuDebugLink.java` | 9 files | feeds #1 | build-id or `.gnu_debuglink` |

Two structural facts to carry into the design:

- **Not everything is an analyzer.** #1, #2, #3, #6, #7 are `AnalyzerType.BYTE_ANALYZER`s; #1 and #2
  both sit at `AnalysisPriority.FORMAT_ANALYSIS.after()` and are default-enabled. But #4 and #5 are
  done by the **loader** (`PeLoader extends AbstractPeDebugLoader`) — CodeView and COFF debug
  symbols are applied while the image is being laid out, with a `-showDebugLineNumbers` load option.
  mosura must reproduce that split, not unify it.
- **Ghidra has no stabs support.** Nothing in `format/elf/` mentions it. Parity means we don't
  either; recorded here so nobody assumes coverage.

The priority choice is the whole design: debug import runs *after* the loader has laid out memory
but *before* disassembly and function discovery, so everything downstream sees debug-derived
functions, types and names as inputs rather than as corrections.

`DWARFAnalyzer.added()` is worth reading once for the shape it imposes: at most once per analysis
transaction (`txId == lastTxId` → return), skip if a `DWARF Loaded` property says the work is done,
ask the factory for a section provider and **silently decline** when there is none, log — without
failing — when the language has no DWARF register mapping. Declining is a first-class outcome.

`DWARFImporter.performImport()` is four phases, each behind an option:

1. `dwarfDTM.importAllDataTypes()` — every DIE type into the DataTypeManager
2. `DWARFFunctionImporter.importFunctions()` — signatures, params, locals, storage, comments
3. `moveTypesIntoSourceFolders()` — cosmetic category organisation
4. `addSourceLineInfo()` — the line program into the program's source map

`DWARFImportOptions` carries 22 knobs; the ones with semantics (not cosmetics) are
`importDataTypes`, `importFuncs`, `createFuncSignatures`, `importLocalVariables`,
`outputSourceLineInfo`, `outputInlineFuncComments`, `outputLexicalBlockComments`,
`ignoreParamStorage`, `useStaticStackFrameRegisterValue`, `defaultCC`,
`elideTypedefsWithSameName`, `tryPackStructs`, `specialCaseSizedBaseTypes`,
`copyExternalDebugFileSymbols`.

Two details to copy rather than reinvent:

- **`DWARFFunctionFixup` is an extension point** with seven implementations (`SanityCheck`,
  `StorageVerification`, `OutputParamCheck`, `ParamName`, `ParamSpill`, `ThisCallingConvention`,
  `Rust`). A prototype is assembled from DWARF then *filtered* by a chain that can reject it
  outright. This is where "DWARF said so" stops being authoritative — the part a naive port omits.
- **Version support is deliberately partial.** `DWARFUnitHeader.read` throws below v2, takes v2–v4
  through `readV4`, and for v5 accepts **only** `DW_UT_compile`;
  `DW_UT_type`/`partial`/`skeleton`/`split_compile`/`split_type` all throw "Unsupported unitType".
  Split DWARF is not supported. Parity means reproducing that refusal, not exceeding it.

## 1. Does debug info influence decompilation? Precisely.

Worth settling before planning around it, because the intuitive answer and the real one differ.

**Debug info contains no source text.** DWARF line tables map addresses to `file:line` and record
directory/timestamp/size/MD5 — `DWARFLineContentType` stops at `DW_LNCT_MD5`, with no
`DW_LNCT_LLVM_source`, and nothing in Ghidra's whole `format/` tree reads embedded source. PDB is
the same: file names and line numbers, no text.

**The line/source map does not reach Ghidra's decompiler.** `SourceMapEntry` is consumed by
`util/viewer/field/SourceMapFieldFactory` (a listing field) and `plugin/core/sourcefilestable/`
(a table). There are **zero references in `Features/Decompiler`**. Line info is a listing feature.

**But debug info does change decompiled text — through comments.** This is the path the intuition
was reaching for, and it is real:

- `DWARFFunctionImporter` writes code-unit comments at function starts, inline-function sites,
  lexical-block starts, and variable/global sites — `CommentType.PRE` and `CommentType.EOL`, via
  `DWARFUtil.appendComment` — and their content includes `sourceInfo.getDescriptionStr()`, i.e.
  `file:line` strings. `outputInlineFuncComments` and `outputLexicalBlockComments` gate two of them.
- PDB does the same through `BlockCommentsManager` and `PdbSourceLinesApplicator`.
- The PE debug loader writes `CommentType.PLATE` and `PRE` comments carrying source file and line
  (`AbstractPeDebugLoader.processFiles`, `processLineNumbers`).
- The **C++ decompiler prints comments**: `printc.cc:2650` feeds `commsorter` from
  `fd->getArch()->commentdb` with `instr_comment_type|head_comment_type`, and `emitLineComment`
  emits them into the C output.

So the influence is: **types, signatures, locals and calling convention change the code; comments
carrying `file:line` change the text around it.** mosura has **no comment database at all**, so
that becomes a required piece of this port rather than a nicety (§3, D0b).

**Beyond-Ghidra opportunity, opt-in.** Two things Ghidra leaves on the table, both squarely in the
`analyze_native_file` opt-in category the X-32 loader established
([`docs/x32-loader-notes.md`](x32-loader-notes.md)): interleaving *actual source lines* into
decompiled output when the source tree is on disk and the line map says which line to show; and
reading clang's `-gembed-source` (`DW_LNCT_LLVM_source`, 0x2001), which really does put source text
in `.debug_line_str` and which Ghidra ignores. Neither is parity work; both are cheap once the line
map exists, and both are the single biggest readability win available. Kept out of the parity
phases and named explicitly so they don't leak into a golden.

## 2. The finding that shapes the build order: we have the bytes, not the sink

The parsers are the easy half. mosura's problem is that there is nowhere to put the answer.

| Ghidra sink | mosura today |
|---|---|
| `DataTypeManager` — named, categorised types | **does not exist** |
| `Function` with signature, params, locals, calling convention | `Function { entry_point, name, body }` — `program/function.rs:12` |
| `FuncProto` with `inputlock`/`outputlock`/`typelock` | `FuncProto { params: Vec<ProtoSlot>, output }` — `decompile/fspec.rs:1167`, **recovered only, no locks** |
| `Datatype` with names, typedefs, enums, unions | `Datatype` enum — `decompile/types.rs:9`; anonymous, `Struct` fields unnamed |
| Comment database (reaches decompiled text) | **does not exist** |
| Source map (address → `file:line`) | **does not exist** |
| PE debug directory | **not parsed** — nothing in `loader/pe.rs` |
| ELF `.debug_*` bytes | **reachable** — `loader/elf.rs:392` reads `sh_offset`/`sh_size` |

The last row is the only green one, and it matters: byte supply for ELF is a non-problem.

The critical one is `FuncProto`'s missing lock. In Ghidra, debug info changes decompilation because
a Program-DB function with a locked signature is handed to the decompiler as a *constraint*, and
`ActionInputPrototype`/`ActionOutputPrototype` respect it instead of running recovery. mosura has
only the recovery half (`recover_input_params`, `recover_output`, `recover_func_proto`). **Until a
declared prototype can enter the decompiler and win, no parser changes anything an observer can
see.** So the override path comes first, and it is testable long before any debug byte is read.

Second finding, on the corpus: **no committed binary carries debug info.**
`oracle/analysis-corpus/build.sh` passes `-g` nowhere, no committed ELF has a `.debug_*` section,
and the DOS-era games are empty too — `WRMS.EXE` and `DESCENTR.EXE` both have `e32_debuglen = 0`,
and no CodeView (`NB09`/`NB10`/`RSDS`), HLL or Watcom-debug marker appears in Flashback, Descent,
Worms or POOL.EXE. This track needs its own corpus, and adding one perturbs existing measurement
(§6h).

Note that all nine consumers are **parity** work — they live inside Ghidra, so they belong in the
default dispatch, unlike the opt-in items in §1 and §5.

## 3. Architecture, in dependency order

### Shared substrate (everything depends on it)

**D0a — the type sink.** A port of `DataTypeManager` at the granularity we need: named types,
categories, composites with *named* fields, typedefs, enums, unions, function definitions. Shared
with the type-system track; the decompiler's `Datatype` (`decompile/types.rs`) and Ghidra's Java
`DataType` stay two separate systems, as they are in Ghidra, for the same reasons.

**D0b — the comment database.** Ghidra's `CommentType.{PLATE,PRE,EOL,POST,REPEATABLE}` on code
units, and the decompiler-side `commentdb` + `commsorter` + `emitLineComment` that puts them in the
C output. Required by §1: it is *the* mechanism by which every debug format's source information
becomes visible in decompiled text. Also independently useful, and testable with hand-written
comments and no debug info at all.

**D0c — function signatures on the analysis side.** `Function` gains a signature, parameters with
storage and names, locals, and a calling convention.

**D0d — the source map.** Address → `file:line`, plus the file table. Feeds the listing view and
the opt-in source interleaving of §1.

**D1 — the override path (the payoff gate).** `FuncProto` gains `inputlock`, `outputlock`,
`typelock`; `ActionInputPrototype`/`ActionOutputPrototype` honour a locked prototype instead of
recovering one; the local scope (`decompile/varmap.rs`, `ScopeLocal`) accepts externally-supplied
names instead of only generating them. Faithful to Ghidra's mechanism, and **independently testable
with hand-declared prototypes and zero debug info** — which decouples "can declared info win?" from
"can we parse format X?".

### Format 1 — DWARF (D2–D7)

**D2 — section supply.** `DWARFSectionProvider` and its factory: `BaseSectionProvider`,
`CompressedSectionProvider` (the `z`-prefix convention — `.zdebug_info` etc., inflated and cached
per base name; the legacy GNU form, *not* `SHF_COMPRESSED`), `DSymSectionProvider` (#8),
`ExternalDebugFileSectionProvider`, `NullSectionProvider`. Then `dwarf/external/`: build-id and
`.gnu_debuglink` lookup, `SameDirSearchLocation`, `LocalDirectorySearchLocation`, a registry, and
`ExternalDebugFileSymbolImporter` for the symbols-only case.

**D3 — the DIE layer.** `DWARFProgram`, `DWARFCompilationUnit` (`readV4`/`readV5`),
`DebugInfoEntry`, the abbreviation reader, `dwarf/attribs/` (form decoding, including v5
`str_offsets`/`addr`/`rnglists`/`loclists` indirection via `DWARFIndirectTable`), `DWARFTag`,
`StringTable`, `DWARFName`/`NamespacePath`, `DWARFRange`/`DWARFRangeList`.

**D4 — types.** `DWARFDataTypeManager`, `DWARFDataTypeImporter`: DIE → D0a, preserving Ghidra's
decisions — `elideTypedefsWithSameName`, `copyRenameAnonTypes`, `tryPackStructs`,
`specialCaseSizedBaseTypes`, `NameDeduper`, `fixupAnonStructMembers`. Bitfields, incomplete types
and cycles are the substance.

**D5 — functions.** `DWARFFunctionImporter`, `DWARFFunction`, `DWARFVariable`, the location decoder
(`dwarf/expression/`), `DWARFLocationList`, `DWARFRegisterMappings` (§4), the seven `funcfixup`
implementations as a real chain with the same order and veto semantics, and the comment writes into
D0b. Feeds D1.

**D6 — line numbers.** `dwarf/line/`: the line-program state machine (`DWARFLineProgramExecutor`,
standard and extended opcodes, v5 content types) → D0d, plus `DWARFSourceInfo`. Independent of
D4/D5 and separately valuable.

**D7 — the analyzer.** `DwarfAnalyzer` at the mosura equivalent of `FORMAT_ANALYSIS.after()`, with
the once-per-session guard, the already-imported property, the graceful decline, the
missing-register-mapping warning, and a summary mirroring `DWARFImportSummary`.

### Format 2 — PE CodeView + COFF, at load time (D8)

`AbstractPeDebugLoader` and `pe/debug/`: `DebugDirectoryParser`, `DebugCodeView`,
`DebugCodeViewSymbolTable`, the `OMF*` subsection readers (`OMFSrcModule`, `OMFSrcModuleFile`,
`OMFSrcModuleLine`, `OMFGlobal`, `OMFSegMap`, …) and the `S_*` symbol records (`S_GPROC32_NEW`,
`S_BPREL32_NEW`, `S_LDATA32_NEW`, `S_UDT32_NEW`, `S_BLOCK32`, `S_LABEL32`, `S_CONSTANT32`, …),
plus `DebugCOFFSymbolTable`/`DebugCOFFLineNumber` and `DebugMisc`. Applied by the loader, with the
`-showDebugLineNumbers` option and the PLATE/PRE comment writes. `DbgLoader` and
`SeparateDebugHeader` (#5) cover the separate-`.dbg` case.

This is also the phase that pays forward: the CodeView 4.x / OMF `S_*` family here is **the same
format MS C 7 and Watcom `-hc` emit for DOS targets** (§5), so porting it once serves both.

### Format 3 — PDB (D9–D11)

**D9 — the reader.** `pdb2/pdbreader` (591 files): the MSF container, the stream directory, TPI/IPI
type streams, DBI, module info, global/public symbol streams, C13 line sections. Large but
mechanical, and **platform-independent by design** ("it written in java, making it platform
independent, unlike a previous PDB analyzer") — so it is fully testable on this machine.

**D10 — the applicator.** `pdb/pdbapplicator` (80 files): `DefaultPdbApplicator`,
`TypeApplierFactory`/`CompositeTypeApplier`, `SymbolApplierFactory`/`FunctionSymbolApplier`/
`DataSymbolApplier`/`TypedefSymbolApplier`, `PdbSourceLinesApplicator`, `BlockCommentsManager`,
`CppCompositeType`. Targets D0a–D0d and D1, exactly as DWARF's importer does.

**D11 — `PdbUniversalAnalyzer`**, with the same gating discipline as D7.

**PDB MSDIA (#3) is not portable.** It needs the Windows-only MS DIA-SDK; the legacy
`format/pdb` package's other input is a `.pdb.xml` produced by a Windows-side tool. Parity here is
to reproduce the *refusal* — Ghidra itself cannot run it off-Windows — and, optionally, the XML
path since it is only 5k lines and needs no COM. Not on the critical path either way.

### Format 4 — Go (D12)

`GolangSymbolAnalyzer` (1,327 lines) + `format/golang/` (85 files): build info/build id,
`moduledata`, `pclntab` → function names **and source line info** (`GoFuncData` produces
`SourceMapEntry`s), RTTI → types. Self-contained relative to D0a–D0d; ordered last of the parity
formats because it is one ecosystem rather than a general mechanism.

### Format 5 — PEF (D13)

`PefDebugAnalyzer`, 117 lines. Included for completeness of the "everything Ghidra does" claim; a
day's work once D0b exists, and only reachable if a PEF loader exists.

Dependency order: D0a–D0d → D1 → D2 → D3 → {D4, D6} → D5 → D7 → D8 → D9 → D10 → D11 → D12 → D13.

## 4. Parity artifacts copied verbatim

The 19 `.dwarf` files under `Ghidra/Processors/*/data/languages/` are configuration, not code — the
same category as `.cspec` and `.sla`, copied the same way:

```xml
<register_mapping dwarf="0" ghidra="EAX"/>
<register_mapping dwarf="4" ghidra="ESP" stackpointer="true"/>
<register_mapping dwarf="11" ghidra="ST0" auto_count="8"/>
```

Ship `x86.dwarf` and `x86-64.dwarf` under `specs/` beside the cspecs, parsed into
`DWARFRegisterMappings`, resolved by language id exactly as `resolve_cspec` does today
(`crates/mosura/src/lang.rs`); add the other 17 as the multi-arch track reaches them. The files also
carry `call_frame_cfa` and `stack_frame` static values that `DW_AT_frame_base`/`DW_OP_fbreg`
resolution needs (`useStaticStackFrameRegisterValue` consumes them). A missing mapping must degrade
to a warning, never a failure — that is what Ghidra does, and it is what lets architectures land
incrementally.

## 5. The extension point for DOS-era compiler debug formats (later stage)

Deliberately out of the parity phases, and deliberately designed for: **Ghidra supports none of
these**, so they are beyond-Ghidra work behind the `analyze_native_file` opt-in, exactly like the
LE and X-32 loaders.

| Format | Emitted by | Notes |
|---|---|---|
| CodeView, appended to MZ/LE | MS C 6/7/8, Watcom `-hc`, `386\|LINK` | **same `S_*`/OMF family as D8** — the reader is shared, only the container differs |
| DWARF in an LE/MZ image | Watcom `-hd` (Open Watcom's default) | **the D3–D6 reader applies unchanged** — only a section provider for LE/MZ is new |
| Watcom's own format | Watcom `-hw` | proprietary; the only genuinely new parser |
| Borland TDS (`.tds` or appended) | Turbo C/C++, Borland C++ | separate format, separate work |

The design consequence for the parity phases: keep `DWARFSectionProvider` **container-agnostic**.
Ghidra's providers are ELF/MachO-shaped because those are the containers it loads; ours must take
"named byte ranges" from any loader, so an `LeSectionProvider` is later a small addition rather than
a refactor. Same for D8's CodeView reader: it must be driven by a blob + a segment map, not by a PE
header.

The pay-off note, recorded so the sequencing is deliberate: **D8 (PE CodeView) and D3–D6 (DWARF)
between them cover most of the DOS-era story** — a Watcom binary built with `-hd` carries DWARF a
completed D3–D6 already reads, and one built with `-hc`, like MS C's output, carries the CodeView
D8 already reads. Only Watcom `-hw` and Borland TDS are new parsers. None of the currently
committed game binaries has any debug info at all (§2), so this pays off on *rebuilt* or
*differently-sourced* DOS binaries, not on the corpus as it stands.

## 6. The testing story

Debug-info import is unusually testable, and unusually easy to test *badly* — a parser that reads
`gcc`'s output is not a parser that reads DWARF. Five layers, innermost first.

### 6a. Which oracle answers this, and which cannot

The C++ oracle (`oracle/capture`, `capture.cc`) **cannot** be used for the import itself: every
debug consumer is Java-side and the C++ decompiler never sees a `.debug_info` section. It remains
the oracle for D0b's and D1's decompiler-side behaviour — a locked prototype's effect on output,
and whether a comment lands in the C text — which is exactly what `printc.cc`'s commentdb path and
`oracle/ghidra_scripts/DecompileWithForcedParams.java` already exercise.

For D2–D13 the Java-side oracle is the vehicle, and it already exists:
`oracle/ghidra_scripts/DumpAnalysisSnapshot.java` driven by `analyzeHeadless`, producing
`goldens/analysis/*.snapshot` parsed by `crates/mosura/src/analysis/snapshot.rs` — the harness in
[`oracle/analysis-capture.md`](../oracle/analysis-capture.md). `DWARFAnalyzer` and
`PdbUniversalAnalyzer` are default-enabled in headless analysis, so a snapshot of a `-g` or
PDB-bearing binary captures their effects for free. What is missing is snapshot *vocabulary*.

### 6b. Snapshot format extension

Today's kinds are `block`, `data`, `entry`, `fnbody`, `func`, `insn`, `ref`, `sym`. The parser
ignores unknown prefixes by design, so old goldens keep working as we add:

- `proto <addr> <cc> <ret-type> (<type> <name> @<storage>, …)` — imported signature
- `local <addr> <type> <name> @<storage>` — imported locals
- `type <path>/<name> <kind> size=<n> [fields…]` — imported types
- `srcline <addr> <file>:<line>` — the source map
- `comment <addr> <type> <text>` — the comment DB, which is how source info becomes visible
- `dbgsummary <format> <n-types> <n-funcs> <n-lines> <n-errors>` — the `DWARFImportSummary` shape,
  generalised across formats

Types print canonically so category cosmetics (`moveTypesIntoSourceFolders`) don't churn goldens.

### 6c. Layer 1 — synthetic fixtures, no binaries committed

The pattern that worked for the LE and X-32 loaders (`tests/le_loader.rs`, `tests/x32_loader.rs`):
Rust builders emitting the container and debug sections byte by byte, so each test states *exactly*
which bytes produce which conclusion, and the suite needs no third-party material.

- `DwarfBuilder` — minimal `.debug_abbrev` + `.debug_info` + `.debug_line` in a synthetic ELF, with
  a matrix over DWARF v2/v3/v4/v5, 32- and 64-bit DWARF (the `0xffffffff` length escape), both
  endiannesses, `DW_FORM_*` coverage including v5 indirection, and `DW_UT_compile` accepted vs the
  five unit types Ghidra refuses.
- `CodeViewBuilder` — a PE debug directory + CodeView `S_*` records and `OMFSrcModule` line tables,
  built the same way. This one doubles as the DOS-era groundwork (§5).
- `PdbBuilder` — an MSF container with a stream directory and a minimal TPI/DBI, enough for the
  reader's structural gates. Full PDB coverage comes from layer 2; the synthetic builder exists for
  the malformed cases.

The negative gates (§6g) are where this layer earns its keep: malformed debug data is trivial to
*build* and near-impossible to *find*.

### 6d. Layer 2 — a compiled corpus

`oracle/debug-corpus/build.sh` beside the existing analysis corpus, committed (goldens must be
toolchain-stable), each binary tiny and reviewable:

| Fixture | Why |
|---|---|
| `dwarf4.elf`, `dwarf5.elf` (`-gdwarf-4` / `-gdwarf-5`) | the two shapes in the wild |
| `dwarf_o2.elf` (`-g -O2`) | inlining, `DW_AT_ranges`, location lists, spilled params — where `ParamSpill` and `StorageVerification` fire |
| `dwarf_types.elf` | struct/union/enum/typedef/bitfield/anon/array/function-pointer/cycle |
| `dwarf_cpp.elf` (`g++ -g`) | namespaces, `this` → `ThisCallingConventionDWARFFunctionFixup` |
| `dwarf_debuglink.elf` + `.debug` | `.gnu_debuglink` external lookup |
| `dwarf_buildid.elf` + `.build-id/…` | build-id external lookup |
| `dwarf_zdebug.elf` (`-gz=zlib-gnu`) | `.zdebug_*`, the form `CompressedSectionProvider` handles |
| `dwarf_split.elf` (`-gsplit-dwarf`) | **must be refused**, matching Ghidra |
| `dwarf_stripped.elf` | no debug info → the graceful-decline path |
| `dwarf_embedsrc.elf` (`clang -gembed-source`) | the opt-in beyond-Ghidra case of §1 |
| `cv_pe.exe` + `pdb_pe.exe` + `.pdb` | D8 and D9–D11; cross-built (`mingw-w64`) or committed prebuilt |
| `go_hello.elf` | D12 |

`clang -g` variants where the producer differs materially. The same sources compiled *without* `-g`
give paired debug/no-debug binaries, which is what makes §6f measurable.

Sourcing note: the PE/PDB fixtures must be ours to commit —
[`docs/third-party-test-binaries.md`](third-party-test-binaries.md) governs anything that isn't.
`mingw-w64` produces DWARF-in-PE for free; a real `.pdb` needs MSVC, so if none can be produced
here the `PdbBuilder` of §6c plus layer-3 snapshots from a PDB we are licensed to use is the
fallback, and the gap gets stated rather than papered over.

### 6e. Layer 3 — Ghidra-parity snapshots

For every layer-2 fixture, a committed `.snapshot` captured through `analyzeHeadless` +
`DumpAnalysisSnapshot`, and a mosura test asserting equality on the extended record kinds. This is
the parity bar: not "we parsed DWARF" but "we reached the same Program state Ghidra reached,
including where Ghidra declines, warns, or lets a fixup veto a signature".

Per-option coverage matters. `DWARFImportOptions` has 22 knobs and the snapshot records Ghidra's
defaults; each semantic option we implement gets at least one non-default snapshot so it is proven
to *do* something.

### 6f. Layer 4 — the decompilation effect

The reason any of this exists. Using the paired debug/no-debug binaries, `ccompare` mosura's output
against Ghidra's *with debug info applied*, and separately assert the debug-informed run differs
from the debug-free run in the expected direction: named parameters instead of `param_1`, declared
types instead of `undefined4`, named locals instead of `local_18`, the declared calling convention
instead of the recovered one, and `file:line` comments in the C text (§1).

Note the interaction with `ccompare`'s type-name erasure documented in
[`docs/type-system-plan.md`](type-system-plan.md): the structural comparator maps type names to `T`,
so debug info's *names* will not move that score. The score-visible wins are structural — correct
parameter count and storage, array indexing, casts. Both effects are worth measuring; only one
shows up in the existing metric, and the plan should not pretend otherwise.

### 6g. Layer 5 — robustness

Debug sections are attacker-adjacent and compiler-bug-adjacent. Each of these is a test built on
the §6c builders: truncated `.debug_info`; a `DW_AT_type` pointing outside the unit; an abbreviation
code with no declaration; a cyclic type reference; an absurd array count; an unimplemented `DW_OP_*`;
a location expression that underflows its stack; a unit whose length runs past the section; a PDB
stream directory pointing outside the file; a CodeView subsection with a bogus length. Every one
must produce a *reported* failure and a program that still analyses — Ghidra's `reportError`
continues; a panic is a bug. If the project gains a fuzz target, these readers are the first place
to point it.

### 6h. Measurement discipline

Adding debug info to the corpus perturbs existing numbers, so, per
[`docs/measurement-rules.md`](measurement-rules.md):

- New fixtures go in a **new** corpus directory. Existing `oracle/analysis-corpus` binaries stay
  `-g`-free so existing goldens stay comparable.
- Function-count and FID-coverage baselines must be re-cut when debug-derived functions appear:
  debug info creates functions discovery would not have found, and names functions FID would
  otherwise have named. Report the two effects separately or the FID numbers become unreadable.
- The DOS-era corpus is unaffected — it has no debug info at all (§2) — so `WAR2`, Descent,
  Flashback, Worms and POOL.EXE measurements are untouched by this whole track.

## 7. Phases and exit criteria

| Phase | Content | Exit criterion |
|---|---|---|
| P0 | D0a–D0d: types, comments, signatures, source map | round-trip tests; nothing else changes |
| P1 | D1 override path + snapshot vocabulary (§6b) | a **hand-declared** prototype changes decompiler output, matched against the C++ oracle via `DecompileWithForcedParams`; a hand-written comment appears in the C text |
| P2 | D2 + D7 skeleton | `dwarf_stripped.elf` declines gracefully; debuglink/build-id fixtures locate their external file; `dwarf_split.elf` refused exactly as Ghidra refuses it |
| P3 | D3 DIE layer | §6c matrix green; §6g negatives all report-and-continue |
| P4 | D6 line numbers | `srcline` + `comment` snapshot parity on `dwarf4.elf`/`dwarf5.elf` |
| P5 | D4 types | `type` snapshot parity on `dwarf_types.elf`, bitfields and cycles included |
| P6 | D5 functions + fixup chain | `proto`/`local` parity on all DWARF fixtures, `-O2` included; each of the seven fixups has a test showing it fire |
| P7 | measurement | §6f: `ccompare` on paired binaries, two effects reported separately |
| P8 | D8 PE CodeView + COFF + `.dbg` | `cv_pe.exe` parity, applied at **load** time; the reader is container-agnostic (§5) |
| P9 | D9 PDB reader | structural parity on `pdb_pe.exe`'s streams; malformed-MSF negatives |
| P10 | D10–D11 PDB applicator + analyzer | `proto`/`type`/`local`/`srcline`/`comment` parity on `pdb_pe.exe` |
| P11 | D12 Go | `go_hello.elf` parity: names, source lines, RTTI types |
| P12 | D13 PEF | only if a PEF loader exists; else recorded as unreachable |
| P13 | opt-in extras (§1) | source interleaving and `-gembed-source`, behind the native flag, no golden touched |

P1 is the one to be strict about. It is the only phase that delivers user-visible value with no
debug parser at all, and it is the phase that proves the other twelve are worth building.

The DOS-era formats of §5 are a **later stage**, sequenced after P8 so they inherit a
container-agnostic CodeView reader and a working DWARF reader, and they get their own plan then.

## 8. Honest scope — what this does not buy

- **Nothing for the DOS-era corpus as it stands.** Zero debug info in any of it (§2). Those
  binaries are FID and cspec territory, which is the correct tool for stripped 1990s game code. §5
  is what changes that, and only for binaries that actually carry debug data.
- **Nothing for stripped modern binaries**, which is most of what anyone reverse-engineers.
- **No MSDIA path** — Windows-only by construction (§3); we port the refusal.
- **No stabs** — Ghidra has none either (§0); parity by omission.
- **Not a decompiler-quality win by itself.** Debug info makes output *readable* (real names, real
  types, `file:line` comments); it makes it *structurally* better only where the declared prototype
  differs from the recovered one. Expect the readability win to be large and the `ccompare` win to
  be modest.

The strongest reason to do it anyway is diagnostic: a `-g` binary is ground truth. Every parameter,
type and stack slot the compiler recorded is a statement mosura's recovery can be checked
against — for the first time, without Ghidra in the loop.
