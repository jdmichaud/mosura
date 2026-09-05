# mosura as a product — library, C API, session store, CLI

*Design draft, 2026-09-05. Branch `product-api-design`. Nothing here is implemented; the
header next to this file (`mosura.h`) is the first draft of the C surface and will change. The
document decides the shape; the numbered phases at the end are the order to build it in.*

## 0. What this document decides

1. **Four crates.** `mosura-core` (today's `crates/mosura`, the Ghidra-shaped internals, free to
   keep moving), `mosura-api` (the product surface: sessions, operations, options, tables),
   `mosura-capi` (a mechanical `extern "C"` projection of `mosura-api`, shipped as
   `libmosura` + `mosura.h`), `mosura-cli` (the `mosura` binary, porcelain over `mosura-api`).
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
   databases), with an override directory resolved first — JD's TODO item on vendoring.

## 1. Where we start from

### 1.1 What exists

| layer | code | what it is | product-relevant state |
| --- | --- | --- | --- |
| SLEIGH engine | `sleigh/` | `.sla` tables → disassembly, raw p-code, emulation, FID fingerprints | a parsed `Spec` per language (0.5–1 s to parse in a debug build; `speccache` leaks it as `&'static`) |
| language registry | `lang.rs`, `paths.rs` | language id → `.sla`/`.pspec`/`.cspec`, Ghidra tree or vendored copy | paths derived from `CARGO_MANIFEST_DIR` and `GHIDRA_SRC` |
| loaders + identification | `analysis/loader/`, `codegen_fingerprint`, `fid/` | bytes → `Program`; compiler evidence; library-function identification | FID databases live under `oracle/fid/db` |
| auto-analysis | `analysis/` | `Program` → converged `Program` (listing, functions, references, jump tables, prototypes, foreign scope) | tens of seconds on WAR2; the whole-program prototype pass ~2 min (3023 functions, 117.7 s in round f8) |
| decompiler | `decompile/` | `Program` + entry → `Funcdata` (SSA graph, types, structure) → C | 0.05–0.5 s per function; the graph is arena-indexed (`VarnodeId`/`OpId`/`BlockId` are `u32`) |
| emit | `decompile/emit/` | `Funcdata × θ × witnesses → C`; the arms registry; report pass | `EmitChoices` is already reflective (`axes()`, `set(name, value)`) |
| recompile | `recompile/` | compiler driver (a `CompilerSpec` as data + `Invocation`), content-addressed object cache, symbolic relink, instruction normalization, alignment + divergence taxonomy, build-flag recovery, gates, gcc ground truth | `.rc-cache`: 36 MB, ~3000 entries × (`.c`, `.obj`, `.log`) |
| orchestration | `examples/war2_survey.rs` (4,568 lines), `examples/recompile_check.rs` (602), `scripts/war2-*.sh`, python | whole-program passes, TU synthesis (prelude, declarations, pragmas), manifests, rounds, verdict comparison | TSV files with git-stamped names; a shell script sequencing three binaries |

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

## 3. The shape: four crates and one store

```
                 ┌───────────── front-ends: own interaction, own NO state ─────────────┐
                 │  mosura-cli (porcelain)   [later: mosura serve, wasm module, bindings]  │
                 └───────────────┬────────────────────────────────────┬─────────────────┘
                                 │ Rust                               │ C ABI (any language)
                          ┌──────▼───────┐                     ┌──────▼───────┐
                          │  mosura-api  │◄────────────────────┤ mosura-capi  │  one-liners, cbindgen → mosura.h
                          │ sessions, ops│                     └──────────────┘
                          │ options,     │
                          │ tables, store│
                          └──────┬───────┘
                                 │ Rust, internal types
                          ┌──────▼───────┐        ┌──────────────────────────────┐
                          │ mosura-core  │        │ session store (a directory)   │
                          │ the port     │        │ immutable content-addressed  │
                          └──────────────┘        │ .tbl files, mmap-able         │
                                                  └──────────────────────────────┘
```

**`mosura-core`** is today's crate. Its public Rust surface (`mosura::decompile::…`) remains the
*port's* surface: it mirrors Ghidra, changes as the port advances, and promises nothing to
outside callers. Domain logic promoted out of the examples (the TU synthesis, the program-level
passes, the round metrics) lands *here*, not in the api crate, because it decides renderings and
facts and therefore belongs under the port's review rules.

**`mosura-api`** is the product. It owns: the session store, the operation registry, the options
registry, the table/schema machinery, and the operation bodies (orchestration). It exposes a
safe Rust API — the Rust binding of the product — and is the only thing the CLI links.

**`mosura-capi`** is `extern "C"` one-liners over `mosura-api` plus the memory/error/panic
boundary. `cbindgen` produces `mosura.h`; the crate builds `libmosura.{so,a}`. A parity test
requires every registered operation and every api entry point to have its C twin, so the C API
cannot lag (§6.6).

**`mosura-cli`** is porcelain: a hand-designed command tree over operations, plus the plumbing
command `mosura call <op>` that reaches every operation with no porcelain at all.

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
function, read bytes). They are thin: each is also a registered operation, so the parity test
(§6.6) has one list to check.

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
frozen into the session's `specs/` on first use.

### 5.8 Parallelism and processes

Functions are independent; content-addressed immutable files make N processes over one session
safe without coordination beyond the rename discipline. The corpus round parallelizes by
function with no daemon and no shared memory. The one process that wants to stay warm — the
DOS-hosted compiler under dosemu, ~1 s per session — is already amortized by *batching within
one invocation* (`Cached` groups 200 units), which is where it belongs: a toolchain-driver
concern, not an architecture concern.

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
mosura round run <name> [--toolchain …] [--baseline NAME]                         (today's war2-round.sh)
mosura round compare <a> <b>                                                      (today's war2-verdicts.sh: EXACT, WGSS, ups/downs)
mosura gates <round> [--baseline NAME]                                            (corpus-gates.tsv, text + verdict gates)
mosura fid identify | fid build …
mosura cache explain <key> | cache gc
mosura ops [--dev] | schema <table> | call <op> [--key value …]                   (discoverability + plumbing)
mosura dev …                                                                      (dev tier: oracle captures, censuses, probes)
```

A session is a directory; `-S` names it, the default is `./.mosura` (the `.git` convention). A
session may hold several inputs (WAR2 and the ground-truth corpus side by side); operations name
the input by label or digest, defaulting to the only one.

### 6.3 Configuration without environment variables

Three sources, merged in order, each producing `Options` (§4.2): machine config
(`~/.config/mosura/config.toml`, `Environment` keys only: tool install paths), session config
(`config.tbl`: result-affecting defaults for this work), flags. The library sees the merged
`Options` and nothing else. `mosura config` shows the effective set and where each value came
from. The one environment variable the CLI may honour is `MOSURA_CONFIG` to relocate the machine
config file; the library never reads the environment.

### 6.4 The dev tier

The Ghidra oracle captures, the sweep, the censuses, the MVE fixture generators, the perf
harness: registered as operations with `tier: Dev`, hidden from top-level help, reachable as
`mosura dev <op>`. Same registry, same tables, same store — a census that used to write its own
TSV now returns a table. They stay in the product binary (they are small and shell out to the
oracle tools; nothing links Ghidra), which keeps one build and one parity list.

### 6.5 The corpus round through the CLI

`scripts/war2-round.sh` today: smoke → `war2_survey` (emit) → `recompile_check` → `war2-verdicts.sh`.
Tomorrow:

```
mosura -S war2.mos round run f9 --toolchain watcom-10.0a-dos --baseline f8   # emit, compile (cached), verify, gates
mosura -S war2.mos round compare f8 f9                                        # the verdict table: EXACT, WGSS, ups, downs
```

with `functions/<key>/` and `compile/` making the second run of an unchanged function free, and
`rounds/f9/manifest.tbl` recording the build id and options — the stamp the manifests carry
today, structural. The run rule from `docs/war2-remeasure-runbook` (repeat until stable, never
two Watcom rounds concurrently) becomes a property of the toolchain driver (one dosemu session at
a time per install directory, enforced by a lock on the install path).

### 6.6 What "exercise the API" means here

The CLI is the API's first client, and it must not be able to cheat. Two ways to guarantee that:

- **Strict:** write the CLI against the C ABI through a safe wrapper, the way a third-party Rust
  user would. Completeness of the C API is then structural. Cost: FFI plumbing on every CLI
  feature, a third surface (the wrapper) to maintain, worse debugging.
- **Recommended:** the CLI uses `mosura-api` (Rust). `mosura-capi` is one-liners over the same
  crate, and a **parity test** asserts that every registered operation and every public api entry
  point has its C twin — the compile-enforced-boundary style the arms registry already uses. The
  C ABI *mechanics* (pointers, lengths, ownership) are exercised by what they exist for: a
  foreign-language client. A C smoke program and a Python `ctypes` script in-tree run the same
  scenario as the CLI's integration tests (identify → load → analyze → decompile → tables).

The recommended route gives the API's *design* the same exercise (the CLI can only do what the
api crate offers, and the api crate is the C API modulo syntax) without slowing the CLI with FFI.

## 7. Migration

### 7.1 Examples → operations

| example(s) | becomes | tier |
| --- | --- | --- |
| `identify` | `identify` | product |
| `dumpc`, `dump`, `dump_all`, `dump_all_ir`, `dumpraw`, `dumpcf`, `dumpkind`, `dumptypes`, `dumptm`, `dumpstacksyms`, `dumpsched`, `dumpseams`, `dumpaxis`, `dumpfp`, `dumpref`, `dumplea`, `dumpnc`, `dumpprobe`, `dumpwc` | `function.decompile` with `--format` / `--stage` / `--table` selecting the view (C, raw, per-stage IR, types, scope, structure, schedule, report) | product; the odd probes as dev tables |
| `dumpdis`, `lift`, `dumpmem`, `dumpobj`, `omfdump`, `le_funcs`, `bytesat` | `sleigh.disassemble`, `sleigh.lift`, `program.read`, `program.tables` | product |
| `trace` | `function.decompile --trace` → `trace` table (rule firings; feeds `trace-diff`) | dev |
| `fidnames` | `fid.identify`, `fid.build` | product |
| `war2_survey` | `program.passes` (prototype pass, tail-return marks, param-order evidence, global widths — promoted into core), `function.emit` (TU synthesis promoted into `core::recompile::tu`), `round.run` | product |
| `recompile_check` | `function.verify`, `round.run` | product |
| `recompile_census`, `recompile_search`, `recompile_select`, `war2_oracle_sweep`, `over_decode`, `terminator_rate`, `watsched_census`, `watsched_split_census`, `foreign_propose`, `mz_noreturn` | dev operations returning tables (or deleted where the finding is recorded and the tool is spent) | dev |
| `corpus_gates` | `gates` | product |
| `gt_recompile`, `gt_recompile_probe`, `watcom_mve_fixtures` | `dev.groundtruth.*`, `dev.mve.*` | dev |
| `perf_corpus` | `dev.bench` | dev |

`scripts/war2-round.sh`, `war2-verdicts.sh`, `war2-smoke.sh`, the python classifiers → `round run`,
`round compare`, `gates`, and dev census operations. `xtask baseline` stays an xtask (it
regenerates committed goldens; that is repository maintenance, not product).

### 7.2 Environment variables → option keys

| today | key | affects |
| --- | --- | --- |
| `GHIDRA_SRC`, `CARGO_MANIFEST_DIR` (paths) | none — specs embedded; `ctx.spec_dirs` override | environment |
| `MOSURA_FID_DIR` | `ctx.fid_dirs` | environment |
| `MOSURA_WATCOM`, `WATCOM_WCC386`, `DUMPWC_WATCOM`, `MOSURA_VC6_EXE`, `MOSURA_BC45_EXE` | `toolchain.<name>.install` | environment |
| `MOSURA_X86_32_CSPEC` | `load.cspec` | result |
| `MOSURA_DISABLE_ANALYZERS` | `analysis.disable` | result |
| `MOSURA_PROTO_PASS`, `MOSURA_GLOBAL_WIDTH`, `MOSURA_CONS_REACH`, `MOSURA_CONS_PROBE`, `MOSURA_CONSISTENCY`, `MOSURA_KERNEL_*`, `MOSURA_AGG`, `MOSURA_AOU_PC`, `MOSURA_SHARED_RET`, `MOSURA_RETSPLIT`, `MOSURA_PROBE_FULL` | `passes.*` and `emit.*` keys — each one a documented option with a default equal to today's default-on/off | result |
| `MOSURA_DEBUG`, `MOSURA_TRACE`, `MOSURA_TRACE_FUNC`, `MOSURA_OPACTION`, `MOSURA_MERGE_WATCH`, `MOSURA_WATCH_CALL`, `MOSURA_CALLEE_EFFECTS`, `MOSURA_RECOVER_FIXPOINT` | `debug.topics`, `debug.trace`, `debug.watch.*` | diagnostic |
| `MOSURA_GT_RAW`, `MOSURA_GT_BASELINE`, `WAR2_EXE`, `CALLCS`, `HOME`, `PATH` | dev operations' parameters / removed | — |

Each row is a mechanical migration with an identity gate: the emitted tree is byte-identical
before and after (the repo's existing identity-chain discipline).

## 8. Staging

Each phase lands green with the corpus unchanged where it touches emission; the phases are
ordered so that every one delivers something usable.

**Phase 0 — seams in core (no behaviour change).**
Resource provider (embedded vendored specs + our `specs/` + FID databases, override directory
first; `paths.rs` becomes dev-only). `Options` object threaded to every env-var read site
(§7.2); `debug!` gains a sink. Promote the TU synthesis and the program passes out of
`war2_survey.rs` into core (`recompile::tu`, `analysis::interface`), gated on a byte-identical
emitted tree. This phase is where most of the risk is retired, and it is all internal.

**Phase 1 — `mosura-api`.** Options registry, tables + schemas + `.tbl`, operation registry,
session store with `Program::freeze/thaw`, and the first operations: `identify`, `program.load`,
`program.analyze`, the program tables, `sleigh.disassemble/lift`, `function.decompile`,
`function.emit`. `Snapshot` v1 becomes the TEXT rendering (gate: `analysis_parity` unchanged).

**Phase 2 — `mosura-cli` and `mosura-capi` together.** The command tree of §6.2 for the phase-1
operations; the C header generated; the parity test; the C smoke and Python clients. Retire the
`dump*`/`identify`/`lift` examples (their outputs become CLI integration goldens).

**Phase 3 — recompile through the CLI.** Toolchains, the compile cache in the store, `verify`,
`round run/compare`, `gates`. Retire `recompile_check`, `war2_survey`, and the round scripts.
From here the corpus rounds are CLI runs — the "more systemic approach" JD asked for.

**Phase 4 — dev tier.** The censuses, oracle sweep, ground-truth and MVE tools as `dev`
operations; delete the spent ones.

**Phase 5 — later.** Frozen specs at build time (start-up), the frozen IR record (tier B), the
type intern table, `mosura serve`, the wasm build (three seams: the resource provider, the
`Toolchain` host callback, no `std::env`/`std::fs` outside them; `oraclecache`/`groundtruth`/
`datatest`/`golden` behind a `dev` feature).

## 9. Decisions for JD, and assumptions made here

Decisions that are genuinely the owner's:

1. **CLI → `mosura-api` with an enforced C parity test (recommended, §6.6), or CLI → C ABI.**
2. **Sessions hold several inputs** (recommended) or one binary per session.
3. **Dev tooling in the product binary under `mosura dev`** (recommended) or a separate
   `mosura-dev` binary.
4. **Embedded spec data with an override directory** (recommended) or an installed data directory
   located by the machine config.
5. **Names.** `libmosura` / `mosura.h`; session directory `.mosura`; option keys as dotted
   lower-case.

Assumptions taken to keep moving: the C API is not ABI-stable before 1.0 but is versioned from
the first commit; the `.tbl` format is little-endian only; the frozen IR record is optional and
after the rest; `Funcdata`'s working representation is untouched by this work.
