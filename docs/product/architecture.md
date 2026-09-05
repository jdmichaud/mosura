# mosura as a product — library, C API, session store, CLI

*Design draft, 2026-09-05. Branch `product-api-design`. Nothing here is implemented; the
header next to this file (`mosura.h`) is the first draft of the C surface and will change. The
document decides the shape; the numbered phases at the end are the order to build it in.*

## 0. What this document decides

1. **Five crates, one public surface.** `mosura-core` (today's `crates/mosura`, the
   Ghidra-shaped internals, free to keep moving), `mosura-api` (internal: sessions, operations,
   options, tables — Rust-testable, not a promised surface), `mosura-capi` (the **one public
   surface**: `extern "C"` one-liners over `mosura-api`, shipped as `libmosura` + `mosura.h`),
   `mosura` (the safe Rust binding over the C ABI, the same thing a Python binding is), and
   `mosura-cli` (the `mosura` binary, porcelain written against that binding). The CLI reaches
   nothing except through the C ABI, so C coverage is structural (§6.6).
2. **One extensibility spine: an operation registry with schema-described parameters and
   results.** Adding a capability registers one operation; the CLI, the C API, a future daemon,
   and a future wasm build all dispatch over the same registry and get it for free. The C symbol
   set stops growing with the feature set.
3. **All results are tables with a declared schema**, and one schema definition yields the C
   accessors, the TSV/JSON/text renderings, and the on-disk flat file. Fields are appended, never
   renumbered; old clients read new tables.
4. **The session store is flat at rest** (JD's option 2): a directory of immutable,
   content-addressed, mmap-able table files. Reading a session is a memory map; writing is a
   rename. The pipeline's *working* data model (Funcdata) is **not** flattened — it stays the
   faithful port — and the document argues why that loses nothing that matters.
5. **The CLI links the library directly. There is no state-owning daemon.** A `mosura serve`
   front-end may exist later for a UI; it owns no data, it opens the same session store.
6. **Environment variables are gone from the library.** Every knob is an option key in a
   registry; the CLI reads flags and config files; a wasm host passes a config struct.
7. **Spec data is embedded** in the library (the vendored Ghidra subset, our `specs/`, the FID
   databases), with an override directory resolved first, and `mosura data export <dir>` dumps
   the embedded data into that directory to jump-start it — JD's decision, 2026-09-05.

## 1. Where we start from

### 1.1 What exists

| layer | code | what it is | product-relevant state |
| --- | --- | --- | --- |
| SLEIGH engine | `sleigh/` | `.sla` tables → disassembly, raw p-code, emulation, FID fingerprints | a parsed `Spec` per language (0.5–1 s to parse in a debug build; `speccache` leaks it as `&'static`) |
| language registry | `lang.rs`, `paths.rs` | language id → `.sla`/`.pspec`/`.cspec`, Ghidra tree or vendored copy | paths derived from `CARGO_MANIFEST_DIR` and `GHIDRA_SRC` |
| loaders + identification | `analysis/loader/`, `codegen_fingerprint`, `fid/` | bytes → `Program`; compiler evidence; library-function identification | FID databases live under `oracle/fid/db` |
| auto-analysis | `analysis/` | `Program` → converged `Program` (listing, functions, references, jump tables, prototypes, foreign scope) | tens of seconds on the subject binary; the whole-program prototype pass ~2 min (3023 functions, 117.7 s in one round) |
| decompiler | `decompile/` | `Program` + entry → `Funcdata` (SSA graph, types, structure) → C | 0.05–0.5 s per function; the graph is arena-indexed (`VarnodeId`/`OpId`/`BlockId` are `u32`) |
| emit | `decompile/emit/` | `Funcdata × θ × witnesses → C`; the arms registry; report pass | `EmitChoices` is already reflective (`axes()`, `set(name, value)`) |
| recompile | `recompile/` | compiler driver (a `CompilerSpec` as data + `Invocation`), content-addressed object cache, symbolic relink, instruction normalization, alignment + divergence taxonomy, build-flag recovery, gates, gcc ground truth | `.rc-cache`: 36 MB, ~3000 entries × (`.c`, `.obj`, `.log`) |
| orchestration | the survey driver example (4,568 lines), `examples/recompile_check.rs` (602), the round scripts, python | whole-program passes, TU synthesis (prelude, declarations, pragmas), manifests, rounds, verdict comparison | TSV files with git-stamped names; a shell script sequencing three binaries |

45 example programs (9,604 lines) are the entire user interface today. About 35 distinct
environment variables are read across the crate (plus `CARGO_MANIFEST_DIR` at compile time);
`debug.rs` has already collapsed 80 of them into one `MOSURA_DEBUG=topic,…` switch, and
`overrides.rs` shows the thread-local pattern that replaced two more.

### 1.2 What is already right, and is kept

- **Arena ids in the IR.** The Varnode/PcodeOp/Block graph is index-based, not pointer-based.
  That is the precondition for a frozen, flat IR record later (§5.5), and it is already true.
- **`EmitChoices` is a name-addressed option set**, enumerable and settable by string, with a
  `tag()` for stamping. §4.2 generalizes exactly this pattern to every knob.
- **The toolchain is a trait with a content-addressed cache** (`Toolchain`, `Cached`); the
  compiler is described as data (`CompilerSpec`, `Invocation`). The session store's compile
  cache is this cache, relocated.
- **Determinism is the house culture**: git-stamped manifests, caches keyed on the oracle
  root's fingerprint, `-dirty` stamps, `adjudicated` outputs kept out of the cache. Content
  addressing in §5.4 is that culture made structural.
- **`Snapshot` v1** is a line-oriented, sorted, lenient text rendering of the `Program`. It
  becomes the `TEXT` rendering of the program tables, and the analysis goldens keep gating.
- **The debug facility** (`debug!(Topic::X, …)`) is one sink away from a log callback.

### 1.3 The owner's list (root `TODO.md`)

The productisation items there — a clean C API, a CLI, a daemon, a web UI, wasm, no environment
variables, vendored specs with a custom-files folder resolved first, the FID database out of
`oracle/`, a generalized recompile tool — are all addressed below. The daemon is addressed by
*not* building one as a state owner (§6.1).

## 2. Goals and non-goals

**Goals.** Every capability reachable from any language through one library. Extensible
without touching the ABI for ordinary growth. A work session that lives on disk and is picked up
at the cost of a memory map. The corpus rounds — mosura's distinctive capability, byte-exact
recompilation — run through the CLI, not through example binaries and shell scripts. No
environment variables. A core that can build for wasm once three seams are cut (§8, phase 5).

**Non-goals.** Rewriting the decompiler's working data model into flat arrays (§5.1 says why).
A GUI. ABI stability promises before a 1.0: the header is versioned so that we *can* evolve it,
not so that we promise not to. Replacing the review discipline: an operation body orchestrates
core calls and decides nothing about renderings or facts; those stay in core under the existing
rules.

## 3. The shape: five crates and one store

```
      ┌──────────────── front-ends: own interaction, own NO state ────────────────────────┐
      │  mosura-cli (porcelain)      [later: mosura serve, wasm module]      python, C, … │
      └───────────┬──────────────────────────────────────────────────────────────┬────────┘
                  │ safe Rust                                                     │
           ┌──────▼──────┐                                                        │
           │   mosura    │  the Rust binding: handles → structs, status → Result  │
           └──────┬──────┘                                                        │
                  │ C ABI ───────────────────────────────────────────────────────┘
           ┌──────▼──────┐
           │ mosura-capi │  THE public surface: extern "C" one-liners, panic/pointer boundary,
           └──────┬──────┘  cbindgen → mosura.h, libmosura.{so,a}
                  │ Rust, internal
           ┌──────▼──────┐
           │ mosura-api  │  sessions, operation registry, options registry, tables, store
           └──────┬──────┘
                  │ Rust, internal types
           ┌──────▼──────┐        ┌──────────────────────────────┐
           │ mosura-core │        │ session store (a directory)   │
           │  the port   │        │ immutable content-addressed  │
           └─────────────┘        │ .tbl files, mmap-able         │
                                  └──────────────────────────────┘
```

**`mosura-core`** is today's crate. Its public Rust surface (`mosura::decompile::…`) remains the
*port's* surface: it mirrors Ghidra, changes as the port advances, and promises nothing to
outside callers. Domain logic promoted out of the examples (the TU synthesis, the program-level
passes, the round metrics) lands *here*, not in the api crate, because it decides renderings and
facts and therefore belongs under the port's review rules.

**`mosura-api`** owns the session store, the operation registry, the options registry, the
table/schema machinery, and the operation bodies (orchestration). It is **internal**: `pub` so
that it is unit-tested in Rust without FFI, but nothing outside `mosura-capi` links it, and it
promises nothing. Keeping it separate from `mosura-capi` is what keeps the C layer one-liners.

**`mosura-capi`** is the product surface, and the only one. `extern "C"` one-liners over
`mosura-api` plus the memory/error/panic boundary; `cbindgen` produces `mosura.h`; the crate
builds `libmosura.{so,a}`.

**`mosura`** is the safe Rust binding over the C ABI: handle types with `Drop` calling
`mosura_release`, `mosura_status` mapped to `Result`, views mapped to borrowed slices with the
handle's lifetime. Mechanical (~1–2k lines), the same shape a Python or Zig binding takes, and it
is what a Rust user of the shipped library depends on. It calls the capi functions as ordinary
Rust functions (the crate is a dependency), so the CLI build involves no dynamic linking; the
`.so` path is exercised by the C smoke test.

**`mosura-cli`** is porcelain over the binding: a hand-designed command tree, plus the plumbing
command `mosura call <op>` that reaches every operation with no porcelain at all. Because it can
only call what the C ABI exposes, anything the CLI can do, every language can do (§6.6).

The store is not a crate; it is a *format* (§5) that `mosura-api` reads and writes, and that any
language can read directly because it is flat.

## 4. The extensibility spine

### 4.1 Operations

An operation is a named, documented, versioned unit of capability:

```rust
pub struct Op {
    pub name: &'static str,          // "program.analyze", "function.decompile", "round.compare"
    pub doc: &'static str,
    pub since: Version,              // the api version that introduced it
    pub tier: Tier,                  // Product | Dev (oracle tooling, censuses, probes)
    pub params: &'static [ParamSpec],// option keys it accepts, with types and defaults
    pub result: SchemaId,            // the table it returns
    pub cache: Cache,                // Pure { key_from: &[Input] } | Effect
    pub run: fn(&mut Session, &Options) -> Result<Table, Error>,
}
```

Everything dispatches over the registry:

- `mosura call program.analyze --input <digest> --analysis.disable=x` (CLI plumbing);
- `mosura_call(session, "program.analyze", params, &table)` (C);
- a future `mosura serve` speaks `{op, params} → table` over a socket with no protocol design of
  its own; a wasm build exports the same dispatcher through `postMessage`.

`mosura ops` lists the registry with parameter and result schemas; `mosura ops --dev` includes
the dev tier. A **pure** operation declares which inputs form its cache key (§5.4); its result is
stored in the session and served from there on the next call with the same key. `round.run` is
a fold over pure operations and is itself not cached.

Typed convenience entry points exist beside the generic call for the handful of hot paths where
per-call overhead matters or where a handle is the natural object (open a program, decompile a
function, read bytes). They are thin: each is also a registered operation, so `mosura ops` lists
everything and `mosura call` reaches everything.

### 4.2 Options

One registry of option keys replaces the environment variables:

```rust
pub struct OptionSpec { key: &'static str, ty: OptType, default: &'static str, doc: &'static str, since: Version, affects: Affects }
```

- Keys are dotted, lower-case: `load.loader=native`, `analysis.disable=…`, `cspec.x86-32=watcom`,
  `emit.return-width=storage` (the existing `EmitChoices` axes become `emit.*`), `debug.topics=…`,
  `toolchain.watcom-10.0a-dos.install=<dir>`.
- `Options::set(key, value)` validates against the registry and rejects unknown keys loudly (the
  `MOSURA_DEBUG` unknown-topic rule, generalized).
- `affects` records whether a key changes results (`Result`), only diagnostics (`Diagnostic`), or
  only locations of external tools (`Environment`). Only `Result` keys enter cache keys; a
  diagnostic switch never invalidates a cache, and a tool path never changes a digest (the
  toolchain's *identity* — compiler binary digest, prelude — does, as `Toolchain::id` does today).
- The canonical string of the `Result` subset is the option digest: `EmitChoices::tag()` for
  everything.
- Where values come from: the CLI merges *machine config* (`~/.config/mosura/config.toml`:
  `Environment` keys only — where Watcom is installed), *session config* (a table in the session:
  the defaults for this work), and *flags*. The library itself reads none of these; it receives an
  `Options`. A wasm host builds the same struct from its own configuration.

The per-thread override cell in `overrides.rs` and the per-process `MOSURA_DEBUG` static both
become fields of the `Options` the operation receives; nothing global remains except the spec
cache, which is a cache.

### 4.3 Tables and schemas

Every result is a table: rows of a fixed record type with a declared schema.

```rust
pub struct Schema { name: &'static str, version: u32, columns: &'static [Column] }
pub struct Column { name: &'static str, ty: ColType }   // U8..U64, I64, F64, Bool, Str, Bytes, List(U32|U64)
```

One declaration drives three surfaces:

1. **C access** — generic accessors by row and column (`mosura_table_u64(t, row, col, &v)`, …),
   a schema query, and a bulk column accessor (`mosura_table_column(t, col, &view, &stride)`)
   that hands a numeric column out zero-copy for array-oriented clients (numpy, Julia, Zig).
2. **Renderings** — `render(TSV | JSON | TEXT)`. The 40-odd bespoke TSV writers in the examples
   become this one function; `TEXT` is the human form (and, for the program tables, reproduces the
   `Snapshot` v1 golden format so `analysis_parity` keeps gating).
3. **The flat file** — the `.tbl` format (§5.3). A table in memory *is* the mapped file plus a
   schema; writing is a copy.

Evolution rule: columns are appended; a column is never removed or retyped; the schema version
bumps on append. A reader with an older schema reads the prefix of each row (`row_size` is in
the file header); a reader with a newer schema fills absent columns with defaults. Nested data is
normalized into a second table with a key column (the CSR pattern of §5.5), not embedded.

Text results (a function's C) are one-row tables with a `text` column; `render(TEXT)` prints
them bare. This keeps `mosura_call` uniform.

### 4.4 What stays opaque

`Funcdata`, `Program`, `Spec` and every other core type are opaque handles in the C API. No
struct layout of the port is ever exposed; the port must keep moving. What *is* exposed of the
IR is either a rendering (`print_raw`, JSON) or, later, the frozen record of §5.5, which is a
table set with its own schema versions — a *projection* of the working graph, not the graph.

### 4.5 Versioning and ABI rules

- `mosura_abi_version()` at runtime, `MOSURA_API_VERSION_*` in the header; a client checks the
  major at start-up.
- Every C struct passed by pointer begins with `uint32_t size; uint32_t version;` and has an
  `_INIT` macro (`mosura_ctx_config`); the library reads only the fields the given size covers.
- Handles are opaque and released with one `mosura_release(void*)`; owned buffers are a
  `mosura_bytes` with `mosura_bytes_dispose`; borrowed views are a `mosura_view` valid while
  the handle that produced them lives (tables are immutable, so a column view is stable).
- Errors are a status code plus a thread-local message (`mosura_last_error()`), never a panic:
  every `extern "C"` and every operation body runs under `catch_unwind` and reports
  `MOSURA_ERR_INTERNAL` with the panic text. The per-function catch that
  `analysis/decompiler.rs` already performs is the same idea at the boundary.
- Operations and option keys carry `since`; deprecation is a flag in the registry, never
  removal within a major.
- Naming: `mosura_<noun>_<verb>`; UTF-8 strings with explicit lengths; little-endian only in
  files.

## 5. The session store

### 5.1 Flat at rest, not flat everywhere

JD's option 2 — arrange the data so it can be written and re-read as-is, the way the Zig
compiler's cache works — is the right target for the *durable* data. It is worth being exact
about what Zig actually does, because it decides how much rework this is:

- Zig's cache is **content-hash manifests plus immutable artifact files**. A cache entry is
  keyed on the digest of every input (sources, flags, the compiler's own build id) and the
  artifact is written once and never modified. That part transfers to mosura wholesale (§5.4).
- Zig's IRs (`Zir`, `Air`, the `InternPool`) are **struct-of-arrays with `u32` indices, and
  extra variable-length data lives in shared side arrays** (`extra: []u32`, `string_bytes`).
  That is why serializing them is a `memcpy`. They were *designed* that way, and they are
  immutable once a pass produces them; the pass's working state (scopes, hash maps) is never
  serialized.

mosura's working graph is a faithful port of Ghidra's C++ data model, and the pipeline mutates
it continuously — ops inserted and destroyed, varnodes created, descend lists rewritten,
`Datatype` trees rebuilt, `HashMap`s keyed by op. A mmap-able representation is hostile to that
(it needs allocators and free lists inside the blob), and the codebase is 133k lines that
mirror `funcdata*.cc` on purpose. Flattening the *working* representation would be a rewrite of
the port against the port's own governing principle, mid-port. Not recommended.

What is *reused*, and therefore worth freezing, is a shorter list:

| artifact | cost to produce | who reuses it | freeze? |
| --- | --- | --- | --- |
| parsed SLEIGH `Spec` | 0.5–1 s per language (debug) | every process start | **yes, at build time** (§5.7) |
| loaded + analyzed `Program` | tens of seconds to minutes on a real binary | every function decompile, every program pass, every CLI query | **yes** — and it is table-shaped already (§5.6) |
| per-function results: C text, TU, emit decisions, prototype, verdicts, divergence rows, normalized instruction streams | seconds per function through the compiler | rounds, comparisons, gates, the UI | **yes** — all tables |
| compiler objects | ~1 s each through dosemu | every re-verify of identical source | **yes** — exists (`Cached`), moves into the store |
| the decompiled `Funcdata` graph | 0.05–0.5 s | the printer, in the same process; IR viewers | **as a projection, later** (§5.5 tier B) |
| pipeline working state | — | nobody after the pass | never |

Re-decompiling a function is about a tenth of recompiling it; caching the graph would save a
tenth of the loop at the cost of the rewrite above. The graph is therefore recomputed from its
cached inputs (the program tables) and only its *products* are stored. Where the graph itself is
wanted as data — an IR viewer, cross-language tooling, IR diffs between mosura versions — a
read-only frozen record (§5.5) is produced by a projection at the end of the pipeline, which is
the Zig shape applied where it fits: an immutable output of a pass.

One place where flattening *is* the faithful move: `Datatype` is a boxed tree today, while
Ghidra's `TypeFactory` owns every type and hands out pointers — an intern table. An interned
type table with `u32` ids is both flat and closer to the reference. Candidate, not prerequisite.

### 5.2 Layout

```
<session>/                      (default ./.mosura, or -S <dir>)
  manifest.tbl                  session identity: format version, mosura build id, created, config digest
  config.tbl                    session-level option defaults (Result keys only)
  inputs/<sha256>               the binaries as given, content-addressed; inputs.tbl names them
  specs/<sha256>.tbl            frozen SLEIGH specs (also shipped pre-frozen in the library, §5.7)
  program/<key>/                one table set per (input, load options, analysis options, build id)
      manifest.tbl  blocks.tbl  bytes.blob  functions.tbl  bodies.tbl  symbols.tbl  references.tbl
      listing.tbl  relocations.tbl  entry_points.tbl  comments.tbl  compiler.tbl  fid.tbl  foreign.tbl
      protos.tbl  proto_slots.tbl  facts.tbl  annotations.tbl
  functions/<key>/              one table set per (program key, entry, decompile+emit options)
      c.tbl  tu.tbl  prototype.tbl  locals.tbl  calls.tbl  jumptables.tbl  report.tbl  recovered.tbl
      [ir/…  the frozen IR record, tier B]
  compile/<key>.{c,obj,log}     the toolchain cache, keyed on (toolchain id, flags, source) as today
  rounds/<name>/                verdicts.tbl  divergences.tbl  manifest.tbl  gates.tbl  (+ the round's options)
  lock                          writers only (§5.4)
```

Everything under a `<key>` directory is immutable once its `manifest.tbl` exists. `rounds/` is
the only human-named tree; a round records the keys it was computed from.

### 5.3 The `.tbl` file

```
offset  size   field
0       8      magic  "MOSTBL01"          (format version in the magic)
8       4      header_len
12      4      schema_version
16      4      ncols
20      4      row_size                    bytes, multiple of 8
24      4      flags                       bit 0: rows sorted by column 0 (binary search allowed)
28      4      reserved
32      8      nrows
40      8      rows_off                    8-aligned
48      8      blob_off                    8-aligned
56      8      blob_len
64      32     content digest              blake3 of rows + blob
96      var    schema name (u32 len + UTF-8), then ncols × { name (u32 len + UTF-8), type u8, offset_in_row u16, size u16 }
rows_off        nrows × row_size            POD, little-endian; Str/Bytes/List columns are { u32 blob_off, u32 len }
blob_off        blob_len bytes              strings (UTF-8, not NUL-terminated), byte ranges, u32/u64 lists
```

A reader maps the file, checks magic and digest (optionally), and views rows in place. Column
types are the closed set of §4.3. There is deliberately no nesting and no pointer: a row refers
to another table by a key column, and variable-length per-row data is a `(offset, len)` into
the blob — the "extra array" of Zig, one per file. Large binary payloads (the memory image) are
a sibling `.blob` referenced by `(offset, len)` from `blocks.tbl`, so the image is never copied
into a table.

### 5.4 Keys, immutability, atomicity

- **Key** = `blake3(mosura build id ‖ op name ‖ input digests ‖ canonical Result-options string
  ‖ annotations digest)`. The build id is the git commit (or `-dirty` plus a tree hash), as the
  manifests stamp today. Invalidation is by key, never by mtime.
- **Immutability.** A table set is written to `<key>.tmp/`, fsynced, and renamed to `<key>/`.
  Readers never see a partial set; concurrent producers of the same key race harmlessly (the
  second rename fails, the content is identical).
- **Lock.** A single lock file serializes only the mutable pointers (`rounds/<name>` creation,
  `config.tbl`). Reads take no lock.
- **Provenance.** Each set's `manifest.tbl` lists its inputs (keys, digests, option strings), so
  `mosura cache explain <key>` answers "what produced this" and a stale result is diagnosable
  rather than mysterious — the failure class `docs/measurement-rules.md` exists for.
- **Garbage.** `mosura cache gc` removes sets unreachable from any round or from the current
  config; nothing is deleted implicitly. The `/data` hygiene rules apply unchanged.

### 5.5 What gets frozen, in tiers

**Tier A — table-shaped state (build first).** The `Program` (§5.6), the per-function
products, the compile cache, the specs. Everything a CLI invocation would otherwise recompute.

**Tier B — the frozen IR record (optional, later).** A projection `freeze(&Funcdata) → IrRecord`
at the end of the pipeline, read-only:

```
varnodes.tbl   { space u32, offset u64, size u32, flags u32, addlflags u32, def_op u32, type u32, nzm u64, consume u64 }
vn_descend     CSR: offsets in varnodes.tbl + one flat u32 list of op ids
ops.tbl        { opcode u16, flags u32, pc_space u32, pc_off u64, uniq u32, block u32, output u32, inputs (List<u32>) }
blocks.tbl     { ops (List<u32>), in_edges (List<u32>), out_edges (List<u32>) }
types.tbl      interned { kind u8, size u32, sub u32, count u64, fields (List<u32>) }  — the intern table of §5.1
structure.tbl  { kind u8, flags u32, parent u32, components (List<u32>), out_edges (List<u32>), labels (List<u32>) }
```

It is the binary, indexable form of what `print_raw()` and the IR dumps print today. Consumers:
an IR viewer, cross-language tools, IR diffing across mosura versions (an `ir_parity` for our own
history). The emit layer *could* later read it instead of the live graph; that is a separate
decision, not part of this design.

**Never.** Pipeline working state, `HighVariable` covers, the merge machinery, rule-pool state.

### 5.6 The `Program` in tables

The `Program` is already a set of address-keyed collections; the tables are their direct images:

| table | row | notes |
| --- | --- | --- |
| `blocks` | name, start, end, r/w/x, bytes (offset,len into `bytes.blob`) | `Memory` |
| `functions` | entry, name, kind (user/library/asm/foreign), body (List of range ids) | `FunctionManager` |
| `bodies` | fn, first, last | the address-set ranges, CSR |
| `symbols` | addr, name, type, primary, external | `SymbolTable` |
| `references` | from, to, type, op_index | `ReferenceManager` |
| `listing` | addr, len, kind (insn/data), flow_kind, ends_flow, call_target, flows (List) | `Listing`; instruction *text* is not stored — it is a deterministic decode of bytes under the language, produced on demand |
| `relocations`, `entry_points`, `comments`, `indirect_branches`, `noreturn`, `defined_data`, `flow_overrides` | as today | |
| `compiler` | language, cspec, compiler, version, signature, evidence | the `identify` facts |
| `fid`, `foreign` | fn, match/library, score / band | |
| `protos`, `proto_slots` | fn, slot, space, offset, size, is_output, model | `recovered_protos` |
| `facts` | fn, kind, payload | derived per-function marks: `tail_return_writes`, `sret`, `sret_callers` |
| `annotations` | kind, addr, payload, author, when | **user inputs** (renames, prototypes, noreturn, cspec per function, foreign confirmations, flags overrides) — kept separate from derived facts because they are *inputs* to the key, not outputs |

Thawing a `Program` for analysis (which needs the mutable struct) rebuilds its hash indexes from
the tables — O(n log n) over ~10^5 rows, milliseconds, not the minute the analysis costs. The
decompiler's reads (memory, functions, references) can later go straight to the mapped tables.
"As fast as disk" is exact for the tables; the in-memory indexes are either rebuilt in
milliseconds or, where it matters, replaced by sorted arrays and binary search (`flags` bit 0).

### 5.7 Frozen SLEIGH specs at build time

The `.sla` parse is the one fixed cost every CLI invocation would pay. The `Spec` freezes to the
same SoA + CSR form (constructors, decision trees as a node table, templates, symbols; the
`userops` map as a table). Two choices, in order:

1. **Thaw at load** — the frozen file is read into today's `Spec` structs (a linear pass; the
   cost was the parse and symbol resolution, not the allocation). No engine change; the 254/254
   disasm goldens are untouched.
2. **Read in place** — later, if start-up still matters, the engine reads the mapped form
   directly. The goldens make that refactor safe; it is not needed to ship.

`build.rs` freezes the vendored subset and embeds it (`include_bytes!`), so `mosura_ctx_new`
needs no path and pays no parse. A custom spec directory (JD's TODO) is resolved first and
frozen into the session's `specs/` on first use. **Jump start (JD, 2026-09-05):**
`mosura data export <dir>` (C: `mosura_ctx_export_data`) writes the embedded data — the
`.ldefs`/`.sla`/`.pspec`/`.cspec` tree, our `specs/`, the FID databases — into the override
directory as the source files they were built from, byte-identical to the vendored originals, so
a user edits a copy rather than authoring from nothing. The exported tree then wins over the
embedded one exactly as any override does; `mosura data list` shows which files are in effect
and where each came from.

**Size call (open).** The used SLEIGH tables are a few megabytes and our own FID databases
3.7 MB — both embed. Ghidra's vendored FID databases are 76 MB: embedding them into every copy of
the library is possible but heavy, so the recommendation is a cargo feature (`fid-ghidra`, off by
default), with an optional data pack in the override directory as the alternative.

### 5.8 Parallelism and processes

Functions are independent; content-addressed immutable files make N processes over one session
safe without coordination beyond the rename discipline. The corpus round parallelizes by
function with no daemon and no shared memory. The one process that wants to stay warm — the
DOS-hosted compiler under dosemu, ~1 s per session — is already amortized by *batching within
one invocation* (`Cached` groups 200 units), which is where it belongs: a toolchain-driver
concern, not an architecture concern.

### 5.9 What option 2 costs, stated plainly

The agreement above is with **flat at rest**; the pushback went against **flat everywhere**
(§5.1). Here is the bill for the part that is agreed.

**Rewrite: none of the existing logic; new code only.**

| piece | what is written | touches existing code? | rough size |
| --- | --- | --- | --- |
| table framework: schemas, `.tbl` writer/reader, TSV/JSON/TEXT renderers | new | no | ~2k lines |
| `Program::freeze/thaw` | one table per collection (§5.6), thaw rebuilds the maps | adds two methods; the struct and every loader/analyzer are untouched | ~2–3k lines incl. schemas |
| `Spec` freeze/thaw | SoA + CSR of the nested constructor/decision/template structs | adds two functions; the engine is untouched | ~1.5–2k lines |
| per-function products | rows written from what is already text or TSV today | no | small |
| frozen IR record (tier B, optional) | a projection at the end of the pipeline | no | ~1–2k lines |

Against the 130k-line rewrite that flat-everywhere would be, this is a contained addition.

**Performance: no degradation anywhere that runs hot.** The translation JD asks about is the
thaw, and it runs once per load, linearly:

- A `Program` thaw rebuilds hash indexes over ~10^5 rows (the subject's listing holds over 100k
  instructions). A hash insert costs tens of nanoseconds; the thaw is on the order of 10 ms. The
  analysis it replaces is tens of seconds to minutes. Today there is no persistence at all, so
  every invocation pays the minutes.
- A `Spec` thaw allocates today's structs from arrays, single-digit milliseconds, against the
  0.5–1 s parse it replaces.
- The hot loops — decode, heritage, the rule pool, the printer — run on today's structures,
  unchanged, because the working representation is not flattened.
- The freeze runs once per producing operation and is a linear pass over data the operation
  already holds; it is invisible next to the operation.

Zero-copy "read in place", where today's code would read the mapped tables directly with no
thaw at all, is the step that *would* require adapters throughout the engine and the analysis;
it is listed as optional in §5.7 and is not needed for either speed or the product.

**The price that is real: format discipline.** An on-disk format outlives the process that wrote
it, so every schema becomes a compatibility decision — append-only columns, versions in headers,
readers tolerant of unknown schemas (§4.3). A daemon has no such cost because its state dies
with it. This is the genuine trade of option 2, and it is worth paying because "a session I can
pick up tomorrow, from another process, in another language" is the feature. **JD's ruling
(2026-09-05): no backward compatibility before 1.0.** A development session is disposable; the
version field stays only so that a stale file is REFUSED rather than misread, and the stage
fingerprint below makes old sets unreachable on its own. The append-only discipline starts at 1.0.

**Invalidation granularity, or the development loop.** Keying every cached table on the whole
build id (§5.4) is correct and simple, but it means editing the printer re-runs the analysis
(a minute or two on the subject) on the next invocation — the loop this project most wants fast. The
fix is Zig's per-unit fingerprint applied per stage: each operation declares which **stage
fingerprint** it depends on — `analysis` (a hash of the analysis modules' sources), `decompile`
(the decompiler's), `emit`, `recompile` — and the key uses those instead of the whole build id.
A printer edit then invalidates `functions/` and `rounds/` and keeps `program/`. The fingerprints
are computed in `build.rs` from the file list of each module tree; the whole build id remains in
every manifest for provenance.

**Disk.** Sessions grow with rounds (per-function products × rounds). `mosura cache gc` is not
optional, and the `/data` hygiene rules apply to session directories as they do to build trees.

## 6. CLI architecture

### 6.1 Direct link versus daemon

| property | CLI links the library, flat session on disk | CLI talks to a daemon over a wire protocol |
| --- | --- | --- |
| start-up | mmap + embedded specs: milliseconds | socket connect: milliseconds — after the daemon is up |
| expensive state | on disk, shared by every process, survives reboots | in one process's memory; lost on exit; one machine |
| crash isolation | a decompiler panic kills one invocation, is caught at the boundary anyway | a panic kills every client's state unless the daemon forks |
| parallelism | free: N processes, immutable files | serialized through the daemon or re-implemented inside it |
| other languages | read the C API *or the files directly* (the format is flat) | speak the protocol; a second surface to version |
| what it costs to build | the store (§5) and the freeze/thaw of `Program` | the store anyway (a daemon that cannot persist is a cache with a lifetime), plus protocol, lifecycle, discovery, auth |
| what it uniquely offers | — | hot in-memory objects with no flat form; push notifications to a UI |

The only things a daemon offers that the flat session does not are (a) keeping objects hot that
have no flat form — which is the working `Funcdata`, whose reuse is worth a tenth of the loop
(§5.1) — and (b) pushing changes to an interactive UI. (b) is a front-end concern: a later
`mosura serve` is a thin server over `mosura-api` that opens the same session and owns nothing;
if a UI is ever built, that is where its WebSocket lives. **Decision: the CLI links the library;
no daemon owns state.** This is JD's stated preference, and the table is why it is also the
right call on the merits.

### 6.2 The command tree

Porcelain, hand-designed; every leaf is an operation, and `mosura call <op>` reaches the rest.

```
mosura identify <bin>                                   what is this file (container, loader, compiler evidence, language, cspec, FID)
mosura -S <dir> init                                    create a session (default ./.mosura)
mosura load <bin> [--loader default|native|le] [--language ID] [--cspec ID]
mosura analyze [--disable a,b] [--progress]
mosura functions | symbols | refs | blocks | listing <range> | relocs | entries   [--format text|tsv|json]
mosura read <addr> <len>
mosura disasm <bin>|--bytes … --language ID --base ADDR                           (SLEIGH only, no program)
mosura lift   …                                                                   (raw p-code)
mosura decompile <fn>|--all [--format c|raw|ir|json] [--stage NAME] [--trace] [--emit.KEY=VALUE …]
mosura emit <fn>|--all [--tu] [--arms-off a,b] [--out DIR]                        (translation units for a toolchain)
mosura annotate <kind> <addr> <payload>                                           (rename, prototype, noreturn, cspec, foreign …)
mosura toolchain add <name> --spec watcom-10.0a-dos --install <dir>              (per-machine location, per-session choice)
mosura recompile <fn>|--all --toolchain <name> [--round NAME]                     (emit → compile → verify → verdict + divergences)
mosura round run <name> [--toolchain …] [--baseline NAME]                         (today's round script)
mosura round compare <a> <b>                                                      (today's verdict-comparison script: EXACT, WGSS, ups/downs)
mosura gates <round> [--baseline NAME]                                            (corpus-gates.tsv, text + verdict gates)
mosura fid identify | fid build …
mosura data export <dir> | data list                                              (dump the embedded spec/FID data into the override dir; what is in effect)
mosura cache explain <key> | cache gc
mosura ops [--dev] | schema <table> | call <op> [--key value …]                   (discoverability + plumbing)
mosura dev …                                                                      (dev tier: oracle captures, censuses, probes)
```

A session is a directory; `-S` names it, the default is `./.mosura` (the `.git` convention). A
session may hold several inputs (the subject and the ground-truth corpus side by side); operations name
the input by label or digest, defaulting to the only one.

### 6.3 Configuration without environment variables

Three sources, merged in order, each producing `Options` (§4.2): machine config
(`~/.config/mosura/config.toml`, `Environment` keys only: tool install paths), session config
(`config.tbl`: result-affecting defaults for this work), flags. The library sees the merged
`Options` and nothing else. `mosura config` shows the effective set and where each value came
from. The one environment variable the CLI may honour is `MOSURA_CONFIG` to relocate the machine
config file; the library never reads the environment.

### 6.4 The dev tier

"Dev tooling" means the tools that exist to develop mosura against its oracles, not to use
mosura: the Ghidra oracle captures and the rule-trace diff, the divergence censuses over the subject
corpus, the oracle sweep, the MVE fixture generators (compile a small C program under dosemu to
make a test fixture), the gcc ground-truth runs, the perf harness. About half of today's 45
examples are this kind, and they are also where the filesystem and process-spawning code of the
core concentrates (`oraclecache`, `groundtruth`, `twin`, `datatest`, `golden`).

They become operations with `tier: Dev` — same registry, same tables, same store, so a census
that used to re-derive everything in its own 4,000 lines reads the session the product wrote —
but they live in their own crate, `mosura-dev-ops`, which registers into the same registry and
is compiled into the CLI only under a cargo feature (`dev-tools`). A release build of `mosura`
has no dev tier at all; a developer build has `mosura dev <op>`. One binary name, one registry,
one command tree, and the product library never compiles the oracle code — which is also
precisely the code the wasm build must exclude (§8, phase 5). The alternative, a separate
`mosura-dev` binary, buys the same separation at the cost of a second target to keep in step; the
feature flag is the smaller mechanism for the same result.

### 6.5 The corpus round through the CLI

The round script today: smoke → the survey driver (emit) → `recompile_check` → the verdict-comparison script.
Tomorrow:

```
mosura -S subject.mos round run f9 --toolchain watcom-10.0a-dos --baseline f8   # emit, compile (cached), verify, gates
mosura -S subject.mos round compare f8 f9                                        # the verdict table: EXACT, WGSS, ups, downs
```

with `functions/<key>/` and `compile/` making the second run of an unchanged function free, and
`rounds/f9/manifest.tbl` recording the build id and options — the stamp the manifests carry
today, structural. The run rule from the round runbook (repeat until stable, never
two Watcom rounds concurrently) becomes a property of the toolchain driver (one dosemu session at
a time per install directory, enforced by a lock on the install path).

### 6.6 What "exercise the API" means here

The CLI is the API's first client, and it must not be able to cheat. **Decision (JD,
2026-09-05): the CLI is written against the C ABI**, through the safe Rust binding (`mosura`, §3),
the way any other language would use the library.

Why this and not a Rust API with a parity test (the first draft's recommendation): a parity
test proves that a C twin *exists*, not that it carries everything the Rust function carries,
and not that it is pleasant to use. A CLI that can only reach the C ABI proves both, every day,
by the people who most want it to work — completeness by construction, and maintenance pressure
on the C surface that no test provides. The advantages the Rust route had were real but small:
Rust types inside the CLI, panics surfacing as panics, no binding to maintain. Each has an
answer:

- The binding is mechanical and is itself a deliverable: it is the Rust binding of the product,
  and writing it is the first ergonomics test of the C ABI.
- The CLI depends on `mosura-capi` as an ordinary crate and calls its `extern "C"` functions
  directly, so there is no dynamic-linking step in the CLI build; the `.so` path is covered by
  the C smoke test.
- For development, `mosura_ctx_config.abort_on_panic = 1` makes the boundary re-raise instead
  of catching, so a decompiler panic dies with its backtrace exactly as it does today; the
  release CLI leaves it off and reports `MOSURA_ERR_INTERNAL`.
- Anything the C ABI cannot express — a closure parameter, a borrowed Rust struct — is a design
  smell surfaced early, which is the point: it has to become data or stay internal.

The C ABI *mechanics* across a real foreign boundary are still exercised by what they exist for:
a C smoke program and a Python `ctypes` script in-tree run the same scenario as the CLI's
integration tests (identify → load → analyze → decompile → tables).

## 7. Migration

### 7.1 Examples → operations

| example(s) | becomes | tier |
| --- | --- | --- |
| `identify` | `identify` | product |
| `dumpc`, `dump`, `dump_all`, `dump_all_ir`, `dumpraw`, `dumpcf`, `dumpkind`, `dumptypes`, `dumptm`, `dumpstacksyms`, `dumpsched`, `dumpseams`, `dumpaxis`, `dumpfp`, `dumpref`, `dumplea`, `dumpnc`, `dumpprobe`, `dumpwc` | `function.decompile` with `--format` / `--stage` / `--table` selecting the view (C, raw, per-stage IR, types, scope, structure, schedule, report) | product; the odd probes as dev tables |
| `dumpdis`, `lift`, `dumpmem`, `dumpobj`, `omfdump`, `le_funcs`, `bytesat` | `sleigh.disassemble`, `sleigh.lift`, `program.read`, `program.tables` | product |
| `trace` | `function.decompile --trace` → `trace` table (rule firings; feeds `trace-diff`) | dev |
| `fidnames` | `fid.identify`, `fid.build` | product |
| the survey driver | `program.passes` (prototype pass, tail-return marks, param-order evidence, global widths — promoted into core), `function.emit` (TU synthesis promoted into `core::recompile::tu`), `round.run` | product |
| `recompile_check` | `function.verify`, `round.run` | product |
| `recompile_census`, `recompile_search`, `recompile_select`, the oracle sweep example, `over_decode`, `terminator_rate`, `watsched_census`, `watsched_split_census`, `foreign_propose`, `mz_noreturn` | dev operations returning tables (or deleted where the finding is recorded and the tool is spent) | dev |
| `corpus_gates` | `gates` | product |
| `gt_recompile`, `gt_recompile_probe`, `watcom_mve_fixtures` | `dev.groundtruth.*`, `dev.mve.*` | dev |
| `perf_corpus` | `dev.bench` | dev |

The round, verdict-comparison and smoke scripts, the python classifiers → `round run`,
`round compare`, `gates`, and dev census operations. `xtask baseline` stays an xtask (it
regenerates committed goldens; that is repository maintenance, not product).

### 7.2 Environment variables → option keys

The switches commit (master 6b504a5, 2026-09-05) already collapsed the nine result-affecting
knobs into one table (`switches.rs`: `Switch::ALL`, `on()`, `turn_off()`, `non_default()` → the
manifest's `arms:` stamp) with `--arms-off <name>` as their command-line face. What remains, by
class, and where each goes:

| class | today (master 6b504a5) | becomes | affects |
| --- | --- | --- | --- |
| result-affecting | the switch table's legacy variables (one read), the two thread-local overrides (`overrides.rs`: disabled analyzers, forced x86-32 cspec), the callee-effects knob | a `Knobs` value carried on `Program`/`Funcdata`; `--arms-off` fills it; later the `emit.*`/`passes.*`/`analysis.*`/`load.*` option keys | result |
| diagnostics | `debug.rs` topics; the op-action trace and its function filter; the call-arity and merge watches; the ancestor-op-use pc; the raw-IR dump; the fixpoint check; the two probe wideners | one `debug::Config` set by the front-end (`--debug <spec>`), watches as its parameters; later `debug.*` option keys | diagnostic |
| locations | the Ghidra tree, the FID directory, the user-provided binaries, the compile-time manifest dir | embedded data + override dirs (`ctx.spec_dirs`, `ctx.fid_dirs`); the developer config for dev-tier locations | environment |
| tests, xtask, scripts | toolchain installs, sample binaries, the baseline-update mode, the Ghidra checkout | `dev-config.toml` (gitignored, committed example) and script flags | — |

Each step is a mechanical migration with the identity gate (`docs/measurement-rules.md` §10):
the emitted tree is byte-identical before and after. No legacy fallback survives: the round and
diff scripts switch to flags in the same change, and a final guard test fails on any `std::env`
read in the library outside test modules and the developer-config reader.

### 7.3 The executable plan

The work packages, their order, gates and file-level detail are in
[`plan-2026-09-05.md`](plan-2026-09-05.md) (WP0 review items → WP1 these docs → WP2 knobs →
WP3 diagnostics → WP4 developer config → WP8 no subject name in the repository → WP5 resource
provider → WP6 closure), which also carries the decisions taken in discussion.

## 8. Staging

Each phase lands green with the corpus unchanged where it touches emission; the phases are
ordered so that every one delivers something usable.

**Phase 0 — seams in core (no behaviour change).**
Resource provider (embedded vendored specs + our `specs/` + FID databases, override directory
first; `paths.rs` becomes dev-only). `Options` object threaded to every env-var read site
(§7.2); `debug!` gains a sink. Promote the TU synthesis and the program passes out of
the survey driver into core (`recompile::tu`, `analysis::interface`), gated on a byte-identical
emitted tree. This phase is where most of the risk is retired, and it is all internal.

**Phase 1 — `mosura-api`.** Options registry, tables + schemas + `.tbl`, operation registry,
session store with `Program::freeze/thaw`, and the first operations: `identify`, `program.load`,
`program.analyze`, the program tables, `sleigh.disassemble/lift`, `function.decompile`,
`function.emit`. `Snapshot` v1 becomes the TEXT rendering (gate: `analysis_parity` unchanged).

**Phase 2 — `mosura-capi`, the `mosura` binding, and `mosura-cli`, in that order.** The C
header generated; the binding; the command tree of §6.2 for the phase-1 operations, written
against the binding; the C smoke and Python clients. Retire the `dump*`/`identify`/`lift`
examples (their outputs become CLI integration goldens).

**Phase 3 — recompile through the CLI.** Toolchains, the compile cache in the store, `verify`,
`round run/compare`, `gates`. Retire `recompile_check`, the survey driver, and the round scripts.
From here the corpus rounds are CLI runs — the "more systemic approach" JD asked for.

**Phase 4 — dev tier.** The `mosura-dev-ops` crate behind the `dev-tools` feature: the
censuses, oracle sweep, ground-truth and MVE tools as `dev` operations; delete the spent ones.

**Phase 5 — later.** Frozen specs at build time (start-up), the frozen IR record (tier B), the
type intern table, `mosura serve`, the wasm build (three seams: the resource provider, the
`Toolchain` host callback, no `std::env`/`std::fs` outside them; `oraclecache`/`groundtruth`/
`datatest`/`golden` behind a `dev` feature).

## 9. Decisions for JD, and assumptions made here

Decided 2026-09-05, in discussion:

1. **The CLI is written against the C ABI** through the safe Rust binding (§6.6). The Rust-API
   route with a parity test was the draft's recommendation; JD's argument — coverage by
   construction, and maintenance pressure on the C surface over time — is the better one.
2. **Sessions hold several inputs.** A session is the folder mosura keeps its work in; several
   inputs means one folder can hold the subject next to the ground-truth programs, or two builds of
   one program, sharing the compile cache and the specs. With one input the commands never need
   to name it.
3. **Dev tooling: same registry, own crate, behind a cargo feature** (§6.4); the release binary
   has no dev tier.
4. **Embedded spec data + override directory + `mosura data export`** to jump-start the
   override directory (§5.7).
5. **No on-disk backward compatibility before 1.0** (§5.9).
6. **The repository names no subject binary.** The binaries we study are inputs; everything
   that is about one of them lives in a subject profile outside the repository, declared in the
   developer config; the repository speaks of "the subject". Enforced by a guard test.
7. **fable-b implements directly**; the worker/review model is retired.

Still the owner's:

- **Names.** `libmosura` / `mosura.h`; session directory `.mosura`; option keys as dotted
  lower-case; `dev-config.toml`.
- **The FID data-pack size call** (§5.7).
- Whether shell scripts may keep environment variables as their parameter mechanism
  (recommended: flags with developer-config defaults).
- Whether neutral specimen identifiers (`FUN_xxxxxxxx`) may stay in code comments once the
  subject's name is gone (recommended: yes — they are the provenance of a witness).

Assumptions taken to keep moving: the C API is not ABI-stable before 1.0 but is versioned from
the first commit; the `.tbl` format is little-endian only; the frozen IR record is optional and
after the rest; `Funcdata`'s working representation is untouched by this work.
