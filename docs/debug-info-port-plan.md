# Plan — porting Ghidra's debug-information story to mosura

Ghidra reads DWARF, PDB, PE CodeView/COFF, Go symbol metadata and PEF debug, and lets what it
finds override what analysis guessed. mosura reads none of it. This plans **all of it** — plus the
extension point the DOS-era compiler formats will need later — under one governing policy.

## The policy: port the judgement, offload the parsing

**What we want from Ghidra is the analysis and the decompilation — what makes Ghidra unique.**
Reading a debug format is not that. It is commodity work, specified by a public standard, and the
Rust ecosystem already does it in libraries that are more heavily exercised than anything we would
write. So **format reading is offloaded to reliable third-party crates as long as they provide what
we need**, and what we port is the part no library has: Ghidra's *decisions* about what the debug
data means for a program.

The split, measured against Ghidra's source rather than estimated:

| | lines | who does it |
|---|---:|---|
| **Port** — Ghidra's decisions | **35,830** | DWARF importers + fixups 12,828 · PDB applicator 21,156 · PE debug loader 402 · Go 1,327 · PEF 117 |
| **Offload** — format reading | **67,136** | DWARF reader 7,612 · PDB reader 54,524 · CodeView/COFF readers 4,927 |
| Not ported at all | 5,266 | PDB MSDIA — Windows-only by construction |

**65% of the 103,000 lines is parsing we do not write.** That is the difference between a plausible
track and an implausible one, and it is why this plan covers every format Ghidra reads instead of
deferring most of them.

The line is drawn precisely, because it is the thing that will drift:

- **A crate supplies bytes and structure.** `gimli` hands us a DIE tree, attribute values, location
  expressions and line programs; the `pdb` crate hands us MSF streams, TPI/DBI records and C13 line
  sections; `flate2` (already a dependency) inflates `.zdebug_*`.
- **We supply every judgement.** Which DIEs become functions, how a location expression becomes
  storage, when a fixup vetoes a prototype, how a type graph maps onto the program's types, what
  gets a comment, and — critically — **every refusal and every warning**. `gimli` reads split DWARF
  happily; Ghidra refuses it (§0), so that refusal is ours, gated above `gimli`.
- **Where a crate cannot express a Ghidra decision, the decision wins.** We drop to the crate's raw
  reader for that case, or decode that one record locally. Never the reverse, and never a fork.

This is the same line `loader/elf.rs` already draws with `object`: the crate parses ELF, and mosura
ports `ElfProgramBuilder`'s decisions about what the sections *mean*. `roxmltree`, `regex`,
`cpp_demangle` and `flate2` are all there on that basis.

Status: **not started.** Nothing here is implemented. Live task status belongs in
[`TODO.md`](../TODO.md); this file is the design and the sequence.

**How to refer to this work.** It is the **debug-info track**, and it owns the letter **`D`**, the
way the decompiler port owns `P` (`port-plan.md`), the analysis port owns `A`, the cspec track owns
`C`, switches own `S` and floats own `F`. So:

- **Phases are `D0`–`D12`** — `D0` is the spine, `D8` is the PDB spine, and so on (§7). These are
  the citable IDs: "landed `D2`", "blocked on `D1`".
- **Components are dotted handles**, not numbers, because §3 is a dependency *graph* rather than a
  schedule: `sink.types`, `sink.comments`, `sink.signatures`, `sink.srcmap`, `locks`,
  `dwarf.sections`, `dwarf.adapt`, `dwarf.types`, `dwarf.funcs`, `dwarf.lines`, `dwarf.analyzer`,
  `cv`, `pdb.adapt`, `pdb.applicator`, `pdb.analyzer`, `go`, `pef`. A phase delivers a slice of
  several components; a component spans several phases.
- Commit subjects use `debug:` as the area prefix.

## 0. What Ghidra actually does (the complete inventory)

| # | Consumer | Where | Size | Applied by | Gate |
|---|---|---|---|---|---|
| 1 | **DWARF** | `app/plugin/core/analysis/DWARFAnalyzer.java` + `app/util/bin/format/dwarf/` | 113 files, 20,440 lines | analyzer | `DWARFSectionProviderFactory` finds sections |
| 2 | **PDB Universal** | `Features/PDB/.../pdb2/pdbreader` + `pdb/pdbapplicator` | 671 files, 75,680 lines — but see §0a | analyzer | PE with a PDB reference |
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

## 0a. Reading those sizes honestly (especially PDB's)

Raw file counts mislead here, and PDB's mislead badly. The 671 files break down as:

| Subpackage | Files | Lines | What it is |
|---|---|---|---|
| `pdbreader/msf` | 17 | 2,059 | the MSF container (real logic) |
| `pdbreader` (top level) | 98 | 16,844 | streams, stream directory, TPI/IPI/DBI, module info (real logic) |
| `pdbreader/symbol` | 280 | 20,221 | **one class per CodeView symbol record type** |
| `pdbreader/type` | 196 | 15,400 | **one class per type record type** |
| `pdb/pdbapplicator` | 80 | 21,156 | the applicator (real logic) |

476 of the 591 reader files are record classes, and **421 of 591 are under 80 lines** — only 10 are
over 500. A representative one, `AbstractLocalDataMsSymbol.java`, is 40 lines whose entire body is a
constructor calling `super`. That is Java's class-per-record idiom, and in Rust the two catalogues
collapse into a pair of enums plus a parse `match`.

**Under the offload policy, none of that is ours.** The MSF container, the reader core and both
catalogues — 54,524 of the 75,680 lines — are the `pdb` crate's job. What we port is the applicator's
21,156 lines of decisions. The breakdown still matters for two reasons: it tells us what to *check*
the crate against at the adoption gate (§3a.1), and it sets expectations about coverage — a crate is
unlikely to decode all 326 IDs, so unknown kinds skip with a report and coverage grows one record at
a time.

The measure that survives translation is the **dispatcher**, not the directory:

| | dispatch arms | dispatcher size |
|---|---|---|
| `SymbolParser.java` | 195 `case`s | 704 lines |
| `TypeParser.java` | 131 `case`s | 562 lines |

326 record IDs, dispatched from 1,266 lines. The 476 files carry the *identity* of those records —
`GlobalData16` / `GlobalData3216` / `GlobalData32` / `GlobalData32St` / `GlobalDataHLSL` /
`GlobalDataHLSL32` / `GlobalDataHLSL32Ext` are seven files for one record family — and 112 of them
are `Abstract*` bases that exist only to be extended. In Rust that shape is a table, not a
hierarchy:

``rust
enum SymbolRecord { GlobalData { seg16: bool, hlsl: bool, st: bool, ty: TypeIndex, … }, … }
fn parse(id: u16, r: &mut Reader) -> Result<SymbolRecord, PdbError> { … }   // one match, 326 arms
``

so the seven files become one variant with flags, and the abstract bases disappear entirely — they
are Java's way of sharing a constructor. Budget the catalogue as ~326 rows of decoding, not 35,000
lines.

The same caution applies more mildly elsewhere: DWARF's 113 files include 20+ small enum/exception
classes, and `format/golang`'s 85 files include the RTTI struct mirrors.

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
that becomes a required piece of this port rather than a nicety (§3, `sink.comments`).

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

**`sink.types` — the type sink.** A port of `DataTypeManager` at the granularity we need: named types,
categories, composites with *named* fields, typedefs, enums, unions, function definitions. Shared
with the type-system track; the decompiler's `Datatype` (`decompile/types.rs`) and Ghidra's Java
`DataType` stay two separate systems, as they are in Ghidra, for the same reasons.

**`sink.comments` — the comment database.** Ghidra's `CommentType.{PLATE,PRE,EOL,POST,REPEATABLE}` on code
units, and the decompiler-side `commentdb` + `commsorter` + `emitLineComment` that puts them in the
C output. Required by §1: it is *the* mechanism by which every debug format's source information
becomes visible in decompiled text. Also independently useful, and testable with hand-written
comments and no debug info at all.

**`sink.signatures` — function signatures on the analysis side.** `Function` gains a signature, parameters with
storage and names, locals, and a calling convention.

**`sink.srcmap` — the source map.** Address → `file:line`, plus the file table. Feeds the listing view and
the opt-in source interleaving of §1.

**`locks` — the override path (the payoff gate).** `FuncProto` gains `inputlock`, `outputlock`,
`typelock`; `ActionInputPrototype`/`ActionOutputPrototype` honour a locked prototype instead of
recovering one; the local scope (`decompile/varmap.rs`, `ScopeLocal`) accepts externally-supplied
names instead of only generating them. Faithful to Ghidra's mechanism, and **independently testable
with hand-declared prototypes and zero debug info** — which decouples "can declared info win?" from
"can we parse format X?".

### Format 1 — DWARF (`dwarf.sections`–`dwarf.analyzer`)

**`dwarf.sections` — section supply.** `DWARFSectionProvider` and its factory: `BaseSectionProvider`,
`CompressedSectionProvider` (the `z`-prefix convention — `.zdebug_info` etc., inflated and cached
per base name; the legacy GNU form, *not* `SHF_COMPRESSED`), `DSymSectionProvider` (#8),
`ExternalDebugFileSectionProvider`, `NullSectionProvider`. Then `dwarf/external/`: build-id and
`.gnu_debuglink` lookup, `SameDirSearchLocation`, `LocalDirectorySearchLocation`, a registry, and
`ExternalDebugFileSymbolImporter` for the symbols-only case.

**`dwarf.adapt` — the DIE layer, as an adapter.** Under the policy this is **not a port**: `gimli`
supplies the unit headers, DIE tree, abbreviations, attribute forms (including v5
`str_offsets`/`addr`/`rnglists`/`loclists` indirection) and the location-expression evaluator that
`DWARFProgram`, `DebugInfoEntry`, `dwarf/attribs/` and `dwarf/expression/` implement in 7,612 lines
of Java. What we write is the adapter and the judgement on top of it:

- **Ghidra's refusals**, which `gimli` does not share: reject below v2, accept v5 only for
  `DW_UT_compile`, and reproduce the "Unsupported unitType" outcome for the other five (§0).
- **Ghidra's naming and scoping** — `DWARFName`, `NamespacePath`, `NameDeduper` (327 + 93 lines),
  which are decisions about program symbols, not about DWARF.
- **The register mapping** (§4) turning DWARF register numbers into our register space.
- The traversal budget and depth caps of §3a.5, which are ours because the *traversal* is ours.

**`dwarf.types` — types.** `DWARFDataTypeManager`, `DWARFDataTypeImporter`: DIE → `sink.types`, preserving Ghidra's
decisions — `elideTypedefsWithSameName`, `copyRenameAnonTypes`, `tryPackStructs`,
`specialCaseSizedBaseTypes`, `NameDeduper`, `fixupAnonStructMembers`. Bitfields, incomplete types
and cycles are the substance.

**`dwarf.funcs` — functions.** `DWARFFunctionImporter`, `DWARFFunction`, `DWARFVariable`, the location decoder
(`dwarf/expression/`), `DWARFLocationList`, `DWARFRegisterMappings` (§4), the seven `funcfixup`
implementations as a real chain with the same order and veto semantics, and the comment writes into
`sink.comments`. Feeds `locks`.

**`dwarf.lines` — line numbers.** `gimli` runs the line-number program (the state machine, standard
and extended opcodes, v5 content types) that `dwarf/line/` implements; we port `addSourceLineInfo`'s
and `DWARFSourceInfo`'s decisions — which rows become source-map entries, and which become the
`file:line` comments that are the only debug fact reaching decompiled text (§1). Independent of
`dwarf.types`/`dwarf.funcs` and separately valuable.

**`dwarf.analyzer` — the analyzer.** `DwarfAnalyzer` at the mosura equivalent of `FORMAT_ANALYSIS.after()`, with
the once-per-session guard, the already-imported property, the graceful decline, the
missing-register-mapping warning, and a summary mirroring `DWARFImportSummary`.

### Format 2 — PE CodeView + COFF, at load time (`cv`)

`AbstractPeDebugLoader` and `pe/debug/`: `DebugDirectoryParser`, `DebugCodeView`,
`DebugCodeViewSymbolTable`, the `OMF*` subsection readers (`OMFSrcModule`, `OMFSrcModuleFile`,
`OMFSrcModuleLine`, `OMFGlobal`, `OMFSegMap`, …) and the `S_*` symbol records (`S_GPROC32_NEW`,
`S_BPREL32_NEW`, `S_LDATA32_NEW`, `S_UDT32_NEW`, `S_BLOCK32`, `S_LABEL32`, `S_CONSTANT32`, …),
plus `DebugCOFFSymbolTable`/`DebugCOFFLineNumber` and `DebugMisc`. Applied by the loader, with the
`-showDebugLineNumbers` option and the PLATE/PRE comment writes. `DbgLoader` and
`SeparateDebugHeader` (#5) cover the separate-`.dbg` case.

This is also the phase that pays forward: the CodeView 4.x / OMF `S_*` family here is **the same
format MS C 7 and Watcom `-hc` emit for DOS targets** (§5), so porting it once serves both.

### Format 3 — PDB (`pdb.adapt`–`pdb.analyzer`)

**`pdb.adapt` — the reader, as an adapter.** The `pdb` crate supplies the MSF container, stream
directory, TPI/IPI, DBI, symbol streams and C13 line sections — the 54,524 lines that dominate
Ghidra's PDB code and the 326-ID catalogue of §0a. We write the adapter, the coverage gaps the
adoption gate (§3a.1) records, and the skip-with-report path for record kinds the crate does not
decode. **This is the phase most exposed to "as long as they provide what we need"**, so its exit
criterion is a measured coverage number against a real `.pdb`, not a green test.

**`pdb.applicator` — the applicator.** `pdb/pdbapplicator` (80 files): `DefaultPdbApplicator`,
`TypeApplierFactory`/`CompositeTypeApplier`, `SymbolApplierFactory`/`FunctionSymbolApplier`/
`DataSymbolApplier`/`TypedefSymbolApplier`, `PdbSourceLinesApplicator`, `BlockCommentsManager`,
`CppCompositeType`. Targets `sink.types`–`sink.srcmap` and `locks`, exactly as DWARF's importer does.

**`pdb.analyzer` — `PdbUniversalAnalyzer`**, with the same gating discipline as `dwarf.analyzer`.

**PDB MSDIA (#3) is not portable.** It needs the Windows-only MS DIA-SDK; the legacy
`format/pdb` package's other input is a `.pdb.xml` produced by a Windows-side tool. Parity here is
to reproduce the *refusal* — Ghidra itself cannot run it off-Windows — and, optionally, the XML
path since it is only 5k lines and needs no COM. Not on the critical path either way.

### Format 4 — Go (`go`)

`GolangSymbolAnalyzer` (1,327 lines) + `format/golang/` (85 files): build info/build id,
`moduledata`, `pclntab` → function names **and source line info** (`GoFuncData` produces
`SourceMapEntry`s), RTTI → types. Self-contained relative to `sink.types`–`sink.srcmap`; ordered last of the parity
formats because it is one ecosystem rather than a general mechanism.

### Format 5 — PEF (`pef`)

`PefDebugAnalyzer`, 117 lines. Included for completeness of the "everything Ghidra does" claim; a
day's work once `sink.comments` exists, and only reachable if a PEF loader exists.

Dependency order is **not** the phase order. The components above are a dependency graph — `sink.types`–`sink.srcmap`
and `locks` are the substrate every format targets, and the format blocks (DWARF `dwarf.*`, CodeView `cv`, PDB `pdb.*`, Go, PEF) are independent of each other, sharing only that substrate. §7 walks
that graph **spine-first**: a thin vertical slice of the substrate plus a thin slice of DWARF, end
to end, before any layer is built out.

## 3a. Design: maintainable, extensible, fast, secure

The §3 blocks are *what* to port. This is *how*, and it is where the four properties are decided —
none of them survives being retrofitted onto 40,000 lines of parser.

### 3a.1 Crate adoption: the gate, and what happens when a crate falls short

The policy is settled at the top of this plan; this is how it is executed, because "as long as they
provide what we need" is the whole risk and it must be checked before a phase depends on it.

**Adoption gate — every crate, before the phase that needs it starts:**

1. **Coverage check against the importer's needs, itemised.** For `gimli`: DIE tree with sibling
   traversal, all `DW_FORM`s our fixtures use, v5 `str_offsets`/`addr`/`rnglists`/`loclists`
   indirection, location-expression evaluation, and the line-number program. For the `pdb` crate:
   MSF streams, the stream directory, TPI *and* IPI, DBI module info, global/public symbol streams,
   C13 line sections, and section contributions. Anything on that list the crate does not expose is
   a gap recorded in the phase, not discovered mid-implementation.
2. **`unsafe` posture and fuzzing.** mosura has **zero `unsafe`** in `crates/mosura/src/` (§3a.5);
   a crate that parses hostile input on our behalf should forbid `unsafe` and be continuously
   fuzzed. `gimli` is the reference case — it is the DWARF reader behind `addr2line` and rustc's
   backtraces, so it is exercised far harder than a fresh port could be. **Verify at adoption**
   rather than assuming: neither `gimli` nor `pdb` is in this machine's registry today, so the
   posture claim above is a requirement, not a measurement.
3. **Inventory it.** `docs/dependencies.md` is the auditable list, with a pin and "what breaks
   without it". A new BUILD/TEST-tier dependency that is not in there is a hole in the
   clean-clone guarantee `scripts/ci-clean-clone.sh` exists to protect.

**When a crate falls short**, in order of preference: (1) decode that one record or form locally,
behind our own reader, and keep the crate for everything else; (2) contribute upstream; (3) only if
neither works, port that reader from Ghidra — a scoped exception, recorded with its reason. Not on
the list: forking the crate, or bending a Ghidra decision to fit what the crate offers.

**The PDB crate is the live risk and should be treated as such.** Ghidra's catalogue dispatches 326
record IDs (§0a); a third-party crate is unlikely to decode all of them, and the ones it misses are
exactly the obscure records that appear in old or unusual binaries. Mitigation is already in the
design: unknown record kinds skip with a report (§3a.3), so a gap degrades coverage instead of
failing the import — and the gap is *visible*, which is what makes it fixable one record at a time.

### 3a.2 Maintainable

- **Mirror Ghidra's extension-point shape**, not just its behaviour, so the Rust reads beside the
  Java: a trait per Ghidra interface (`DebugSectionProvider`, `DWARFFunctionFixup`), the same
  names, the same veto semantics.
- **Name-level traceability.** Where Java's class-per-record collapses to an enum (§0a), variant
  names keep Ghidra's class names — `GlobalData32`, `FramePointerRelative`, `FrameSecurityCookie` —
  so one `grep` hits both trees. The port already holds this line for rules and actions; the
  catalogues are where it is easiest to lose.
- **Registries as `const` slices**, following `NATIVE_LOADERS` (`analysis/mod.rs:136`) rather than
  inventing a plugin mechanism.
- A **file → module mapping table** in this doc when implementation starts, per the convention in
  [`analysis-port-plan.md`](analysis-port-plan.md) §6, and a doc comment per ported unit citing the
  Ghidra file and line, as the rest of the codebase does.

### 3a.3 Extensible

Three traits and one sink, sized so the later formats are additions rather than refactors:

``rust
/// Ghidra `DWARFSectionProvider`. Named byte ranges — deliberately NOT a container, so an
/// `LeSectionProvider` (§5) is a new impl, not a refactor.
pub trait DebugSectionProvider {
    fn has_section(&self, names: &[&str]) -> bool;
    fn section(&self, name: &str) -> Option<&[u8]>;
}

/// One debug format. DWARF, CodeView, PDB and Go are four impls over one sink.
pub trait DebugImporter {
    fn claims(&self, p: &dyn DebugSectionProvider) -> bool;   // Ghidra's silent-decline gate
    fn import(&self, src: &dyn DebugSectionProvider, sink: &mut dyn DebugSink) -> ImportSummary;
}

/// Ghidra `DWARFFunctionFixup`: assembled prototype in, veto or amend out.
type FunctionFixup = fn(&mut DebugFunction) -> FixupVerdict;   // a `const` slice, per 3a.2
``

`DebugSink` is the format-neutral face of `sink.types`–`sink.srcmap` (`declare_type`, `set_signature`, `add_local`,
`add_comment`, `add_source_line`) and it is the interface D1 exists to prove: a second format runs
through it before DWARF-specific detail can settle into it.

**Unknown-value tolerance is a rule, not a fallback.** An unknown `DW_TAG`, `DW_FORM` or record ID
must skip with a report and never fail the import — Ghidra says so in its own source
("Users of this enum should be tolerant of unknown values"). That is precisely what lets the 326-ID
catalogue (§0a) land record by record without blocking the phases around it.

### 3a.4 Fast

The project has a real perf discipline ([`perf-log.md`](perf-log.md)): `perf record` plus
`MOSURA_ANALYSIS_TRACE=1` per-analyzer sums, with before/after rows and byte-identical output at
every step. Requirements, not aspirations:

- **No new analyzer lands untraced.** One perf-log row per phase, measured the existing way.
- **Reuse the two lessons the log already paid for**: `decompile/fasthash.rs` (`FxHasher`) for hot
  integer-keyed maps, and a dense `Vec` indexed by a dense id instead of a `HashMap` — the log's
  row #1 was exactly that win (69.6s → 35.2s). A DIE-offset → index map is the same shape.
- **Index first, decode on demand.** One pass building offset → (unit, tag, depth, sibling), with
  attributes decoded only for DIEs we actually import. Ghidra pre-materialises the DIE tree; parity
  is over *results*, so the internal representation is ours to choose, and `gimli` is built for the
  lazy shape.
- **Intern names.** Type names and file paths repeat heavily across compilation units.
- **Pay nothing when absent.** The decline path must cost one section lookup — that is Ghidra's
  shape too, and it keeps the whole track free for the DOS corpus, which has no debug info at all.

### 3a.5 Secure

**Threat model, stated plainly.** Debug sections are attacker-controlled bytes inside the file under
analysis — the one input class a reverse-engineering tool is *guaranteed* to be fed hostile samples
of. mosura has **zero `unsafe`** in `crates/mosura/src/`, so the realistic harms are **denial of
service** (hang, OOM, process abort) and **wrong output**, not memory-safety compromise.

The offload policy is the single largest security decision in this plan: **67,136 lines of parsing of
that hostile input becomes someone else's continuously-fuzzed code** rather than 67,136 lines of ours
written once. What remains on our side is the adapter and the *traversal* — and the traversal is
where the sharpest hazard lives, because building a type graph from attacker-shaped input is our
code no matter who decodes the bytes. The five hazards and the rule for each:

1. **Stack overflow — the sharpest one.** DIE trees and type graphs are recursive and
   attacker-shaped, and a deep chain aborts the process: Rust cannot catch stack exhaustion.
   Rule: explicit depth caps or iterative worklists on every traversal. Precedent exists —
   `decompile/mergesnip.rs:112` truncates recursion at a maximum depth, mirroring Ghidra.
2. **Unbounded allocation.** Never size a collection from file data. A `DW_AT_count` near 2^64, a
   bogus PDB stream length or an absurd array bound must never reach `Vec::with_capacity`; grow as
   you read, and cap against the section length.
3. **Cycles.** Type graphs cycle legitimately (self-referential structs) and maliciously. Every
   traversal carries a visited set; §6g gates it.
4. **Panics.** Extend `loader/read.rs`'s stated policy — "every reader returns `None` rather than
   panicking on a short buffer, because a loader's job on a truncated file is to refuse it" — to
   these modules: `Result` out, no indexing, no `unwrap`. Enforce with a module-level
   `#![deny(clippy::indexing_slicing, clippy::unwrap_used)]` on the new modules, rather than
   crate-wide, which would be a large retrofit.
5. **Time.** A work-unit counter so a hostile file cannot wedge the analyzer: report and stop,
   rather than run forever inside `analyze()`.

**Path traversal — the one that is easy to miss.** External debug files are located from a
`.gnu_debuglink` string or a build-id embedded *in the file being analysed*, and then opened. That
is an attacker-controlled filename reaching the filesystem. Rule: reject absolute paths and any
`..` component, and resolve only beneath the configured `SearchLocation` roots — Ghidra's
`SameDirSearchLocation`/`LocalDirectorySearchLocation` are the only roots, and ours must be too.

**Fuzzing, concretely, and aimed at what is ours.** The crates are fuzzed upstream; our targets
belong at the *adapter and importer* boundary — `cargo-fuzz` on `DebugImporter::import` over a
synthetic provider, seeded from the §6d corpus, with the §6c builders as structure-aware generators.
That is where a malformed-but-decodable input (a valid DIE tree describing a 100,000-deep type chain)
does its damage: the crate returns it happily and *our* traversal is what must survive. The
acceptance bar is §6g's — every malformed input reports and continues; a panic or abort is a bug.

## 4. Parity artifacts copied verbatim

The 19 `.dwarf` files under `Ghidra/Processors/*/data/languages/` are configuration, not code — the
same category as `.cspec` and `.sla`, copied the same way:

``xml
<register_mapping dwarf="0" ghidra="EAX"/>
<register_mapping dwarf="4" ghidra="ESP" stackpointer="true"/>
<register_mapping dwarf="11" ghidra="ST0" auto_count="8"/>
``

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
| CodeView, appended to MZ/LE | MS C 6/7/8, Watcom `-hc`, `386\|LINK` | **same `S_*`/OMF family as `cv`** — the reader is shared, only the container differs |
| DWARF in an LE/MZ image | Watcom `-hd` (Open Watcom's default) | **the `dwarf.adapt`–`dwarf.lines` reader applies unchanged** — only a section provider for LE/MZ is new |
| Watcom's own format | Watcom `-hw` | proprietary; the only genuinely new parser |
| Borland TDS (`.tds` or appended) | Turbo C/C++, Borland C++ | separate format, separate work |

The design consequence for the parity phases: keep `DWARFSectionProvider` **container-agnostic**.
Ghidra's providers are ELF/MachO-shaped because those are the containers it loads; ours must take
"named byte ranges" from any loader, so an `LeSectionProvider` is later a small addition rather than
a refactor. Same for `cv`'s CodeView reader: it must be driven by a blob + a segment map, not by a PE
header.

The policy applies here too, and it changes what "new parser" means: Watcom `-hd` output is read by
`gimli`, and CodeView by the `pdb` crate, so those two need only a container-agnostic section
provider from us. Watcom `-hw` and Borland TDS have **no Rust library worth offloading to and no
Ghidra code to port** — Ghidra reads neither — so they are, uniquely in this whole plan, genuinely new
parsers written here, and they should be judged on that cost when the time comes rather than assumed
cheap by association.

The pay-off note, recorded so the sequencing is deliberate: **`cv` (PE CodeView) and `dwarf.adapt`–`dwarf.lines` (DWARF)
between them cover most of the DOS-era story** — a Watcom binary built with `-hd` carries DWARF a
completed `dwarf.adapt`–`dwarf.lines` already reads, and one built with `-hc`, like MS C's output, carries the CodeView
`cv` already reads. Only Watcom `-hw` and Borland TDS are new parsers. None of the currently
committed game binaries has any debug info at all (§2), so this pays off on *rebuilt* or
*differently-sourced* DOS binaries, not on the corpus as it stands.

## 6. The testing story

Debug-info import is unusually testable, and unusually easy to test *badly* — a parser that reads
`gcc`'s output is not a parser that reads DWARF. Five layers, innermost first.

### 6a. Which oracle answers this, and which cannot

The C++ oracle (`oracle/capture`, `capture.cc`) **cannot** be used for the import itself: every
debug consumer is Java-side and the C++ decompiler never sees a `.debug_info` section. It remains
the oracle for `sink.comments`'s and `locks`'s decompiler-side behaviour — a locked prototype's effect on output,
and whether a comment lands in the C text — which is exactly what `printc.cc`'s commentdb path and
`oracle/ghidra_scripts/DecompileWithForcedParams.java` already exercise.

For `dwarf.sections`–`pef` the Java-side oracle is the vehicle, and it already exists:
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

**What these builders test changed with the offload policy, and it is worth being explicit about.**
They are no longer covering a hand-rolled parser — `gimli` and the `pdb` crate are tested upstream.
They cover *our* three things: the **refusals** (Ghidra rejects what `gimli` accepts, so those gates
are about our layer, not the crate's), the **adapter** (a form the crate exposes differently than
Ghidra reads it), and the **traversal** (§6g's malformed-but-decodable cases, which a crate hands
over cheerfully). That makes the `PdbBuilder` in particular much smaller than first drafted: enough
MSF structure to drive the adapter, not a second implementation of the container.

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
| `cv_pe.exe` + `pdb_pe.exe` + `.pdb` | `cv` and `pdb.adapt`–`pdb.analyzer`; cross-built (`mingw-w64`) or committed prebuilt |
| `go_hello.elf` | `go` |

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
- The DOS-era corpus is unaffected — it has no debug info at all (§2) — so `the subject`, Descent,
  Flashback, Worms and POOL.EXE measurements are untouched by this whole track.

## 7. Phases and exit criteria

The temptation — and the shape of this plan's first draft — is to build the sink completely, then
the DIE layer completely, then types, then functions. That is layer-first, and it defers the only
question that matters (does the architecture compose end to end?) until six phases in. So instead:

**D0 — the spine.** The thinnest possible vertical slice, one binary, one path, bytes to visible
output. Minimum of *each* layer, not all of any:

- `sink.types`: enough type sink for `int` and a pointer. No categories, no composites.
- `sink.comments`: a comment DB with one comment type reaching the C output.
- `sink.signatures`: a signature on `Function` with one named parameter.
- `sink.srcmap`: nothing (deferred to D5).
- `locks`: `inputlock` only, honoured by `ActionInputPrototype`.
- `dwarf.sections`: `BaseSectionProvider` over ELF sections, `.debug_abbrev` + `.debug_info` only.
- `dwarf.adapt`: `DW_TAG_compile_unit` + `DW_TAG_subprogram`, `DW_AT_name`/`low_pc`/`type`. DWARF 4,
  32-bit, little-endian, no v5 indirection, no location expressions.
- `dwarf.funcs`: name and one parameter, no fixup chain.
- `dwarf.analyzer`: the analyzer, with the decline path.
- §6b snapshot vocabulary for `proto`, `comment`, and the `dbgsummary` line.

*Exit criterion:* a `gcc -g` hello-world's function is **named from DWARF**, its one-parameter
prototype **survives recovery because it is locked**, and a DWARF-derived comment appears in the
decompiled C — with snapshot parity against Ghidra on those records. If the architecture is wrong,
this is where it shows, at a fraction of the cost.

**D1 — the second format's spine, immediately.** `DW_TAG_subprogram` → PE CodeView `S_GPROC32`,
through the *same* substrate, on a `cv_pe.exe` fixture. Deliberately not at the end: the sink has
to be format-neutral, and the only way to know is to run a second format through it **before**
DWARF-specific detail accumulates in it. CodeView is the right second choice for two reasons — it
is applied by the **loader**, so it proves the analyzer/loader split of §0 rather than assuming it;
and it is the DOS-era format family (§5), so the container-agnostic constraint gets exercised while
it is still cheap to honour.

*Exit criterion:* one function named and one prototype locked from CodeView, at load time, with no
change to the DWARF path and no format-specific branch in `sink.types`–`sink.srcmap` or `locks`.

Then thicken. Each row below is breadth over an already-working spine, so each is independently
shippable and independently measurable:

| Phase | Content | Exit criterion |
|---|---|---|
| D2 | DWARF breadth: `dwarf.sections` fully (compressed, dSYM, external debug files), `dwarf.adapt` fully — mostly `gimli` wiring plus Ghidra's refusals | §6c matrix green — v2–v5, 32/64-bit, both endians, all `DW_FORM`s; `dwarf_split.elf` refused exactly as Ghidra refuses it; `dwarf_stripped.elf` declines; §6g negatives all report-and-continue |
| D3 | `dwarf.types` + `sink.types` built out (categories, composites, typedefs, enums, unions) | `type` snapshot parity on `dwarf_types.elf`, bitfields and cycles included |
| D4 | `dwarf.funcs` fully: locals, location expressions, register mappings (§4), the seven-fixup chain | `proto`/`local` parity on all DWARF fixtures, `-O2` included; each fixup has a test showing it fire |
| D5 | `sink.srcmap` + `dwarf.lines`, **and** CodeView's line tables (`OMFSrcModuleLine`) | `srcline` + `comment` parity on `dwarf4.elf`/`dwarf5.elf` and `cv_pe.exe` |
| D6 | measurement | §6f: `ccompare` on paired debug/no-debug binaries, the two effects reported separately |
| D7 | `cv` breadth: COFF debug, `DebugMisc`, separate `.dbg` (`DbgLoader`) | full `cv_pe.exe` parity; the reader is driven by blob + segment map, not a PE header (§5) |
| D8 | PDB spine (`pdb.adapt`): the `pdb` crate wired in — streams, DBI, enough TPI for one signature — after the §3a.1 adoption gate passes | one function named and one prototype locked from a real `.pdb`, end to end — the spine pattern again, not the whole reader |
| D9 | PDB breadth (`pdb.adapt`, `pdb.applicator`, `pdb.analyzer`): the applicators, `PdbSourceLinesApplicator`, `BlockCommentsManager`. The 326-ID catalogue is the crate's; ours is the coverage measurement and the skip-with-report gaps | `proto`/`type`/`local`/`srcline`/`comment` parity on `pdb_pe.exe`; unknown record IDs skip with a report (§0a) |
| D10 | Go (`go`) | `go_hello.elf` parity: names, source lines, RTTI types |
| D11 | PEF (`pef`) | only if a PEF loader exists; else recorded as unreachable |
| D12 | opt-in extras (§1) | source interleaving and `-gembed-source`, behind the native flag, no golden touched |

**Cross-cutting, every phase, not a phase of its own** (§3a): a perf-log row measured the existing
way; the `#![deny(clippy::indexing_slicing, clippy::unwrap_used)]` module attribute in place from
D0; depth caps and visited sets on every traversal the phase adds; and a fuzz target for each new
reader entry point from the phase that introduces it. These are exit criteria for each row above,
not a D12 cleanup — a robustness pass bolted on at the end is how the properties get lost.

Two properties this ordering buys. Every phase from D0 onward has a **working end-to-end path**, so
a regression is always attributable to the phase that caused it rather than to an unfinished layer.
And the format-neutrality of the substrate is proven at D1 by construction, when it costs one
fixture, instead of being discovered at D8 when it costs a refactor.

The DOS-era formats of §5 are a **later stage**, sequenced after D7 so they inherit a
container-agnostic CodeView reader and a complete DWARF reader; they get their own plan then.

## 8. Honest scope — what this does not buy

- **Nothing for the DOS-era corpus as it stands.** Zero debug info in any of it (§2). Those
  binaries are FID and cspec territory, which is the correct tool for stripped 1990s game code. §5
  is what changes that, and only for binaries that actually carry debug data.
- **Nothing for stripped modern binaries**, which is most of what anyone reverse-engineers.
- **No MSDIA path** — Windows-only by construction (§3); we port the refusal.
- **No stabs** — Ghidra has none either (§0); parity by omission.
- **Third-party coverage is a real dependency, not a footnote.** The offload policy trades 67k lines
  we would have written for a coverage question we do not control: if the `pdb` crate does not decode
  a record Ghidra applies, that fact is ours to detect and work around (§3a.1). The mitigation makes
  gaps visible and survivable, not absent. A parity claim on PDB is therefore a *measured coverage*
  claim, and the plan says so at `D9` rather than implying completeness.
- **Not a decompiler-quality win by itself.** Debug info makes output *readable* (real names, real
  types, `file:line` comments); it makes it *structurally* better only where the declared prototype
  differs from the recovered one. Expect the readability win to be large and the `ccompare` win to
  be modest.

The strongest reason to do it anyway is diagnostic: a `-g` binary is ground truth. Every parameter,
type and stack slot the compiler recorded is a statement mosura's recovery can be checked
against — for the first time, without Ghidra in the loop.
