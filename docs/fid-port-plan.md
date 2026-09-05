# FID (Function ID) port plan — identifying standard-library / runtime functions

**Goal.** Give mosura Ghidra's ability to name statically-linked runtime and standard-library
functions in a stripped binary — `strcpy`, `printf`, the CRT startup code, the Watcom/gcc/MSVC
runtimes — by fingerprinting each function's body and matching it against a signature database.
This is a **faithful port of Ghidra's FID subsystem** (`Ghidra/Features/FunctionID/`, 73 java
files). We invent no fingerprinting scheme; we port Ghidra's, so mosura's hashes are
**byte-identical to Ghidra's** and it identifies the same functions.

Distinct from the existing `analysis/codegen_fingerprint.rs` / `loader/compiler_version.rs`, which
identify the **compiler/toolchain of the whole binary**. FID identifies an **individual function**.
Same word "fingerprint," opposite granularity — complementary, both live in the analysis lane.

**Branch/worktree:** `fid-port` @ `/home/jd/projects/mosura/mosura-fid`, cut from `master`
`aad9f87`. Sibling of `ghidra/`, so `ghidra_src` (dev-config.toml) resolves by the usual `../ghidra` default (a
`/tmp` worktree silently drops to 15 vendored languages — see the vendored-language ratchet note
in `AGENTS.md`).

---

## 1. What Ghidra actually does (the mechanism, in one page)

Three pillars, each a separate port:

1. **Hash** (`hash/`). For one function, walk its body's instructions in ascending address order.
   Per instruction, AND the raw bytes with the SLEIGH **instruction mask** (opcode-fixed bits;
   operand value bits zeroed) and feed those masked bytes to two running FNV-1a-64 digests. Then
   per operand mix in the resolved operand objects — the **full** digest always substitutes a
   placeholder for scalars/addresses (so it is position- and value-independent: the same code
   relocated anywhere hashes the same), while the **specific** digest folds in real small scalar
   values. Output is a `FidHashQuad`: `{codeUnitSize, fullHash, specificHashAdditionalSize,
   specificHash}`.
2. **Database** (`db/`). Five tables — functions, libraries, strings, and two relation sets —
   keyed for lookup by full hash. A library record pins one `languageID` + `compilerSpecID`, so
   matching never crosses architectures.
3. **Match** (`service/`, `cmd/`). Look up candidates by **full hash only**; score each by body
   size, whether the specific hash also matched, and how many of its callers/callees also matched
   (the relation tables); reject below a threshold; collapse surviving names; apply.

The three are independent enough to land and gate separately.

---

## 2. Ground already taken

**Stage 0 — SLEIGH operand/mask exposure: ✅ LANDED, on `master` as `2f69f51`.**
(The plan previously cited `c5dbd8a`; that is the pre-rebase SHA and is now reachable only from
tag `pre-master-rebase-2026-08-05`. `2f69f51` is the live one.)

FID hashes from **disassembly** structure, not p-code — masking keys off the SLEIGH constructor
pattern, so p-code is not a faithful substitute. `sleigh::disassemble_fingerprint` returns, per
instruction, an `InstructionFingerprint { instruction_mask, operands[{value_mask, objects,
is_scalar, is_address}], is_call }` — faithful ports of Ghidra's `getInstructionMask`,
`getOperandValueMask`, `getOpObjects`, `getOperandType`, `getFlowType().isCall()`. Purely
additive (0 deletions), so the decompiler is provably unperturbed. Spike:
`crates/mosura/tests/sleigh_fingerprint.rs`, 7/7.

**Four residuals** recorded at Stage 0, all expected hash-neutral for x86, all of which the Stage 3
byte-equality gate will confirm or refute: (1) branch/call targets surface as `Scalar{addr}` rather
than `Address` — hash-neutral for `|val| ≥ 256` since both fold to the placeholder, and the
`is_address` bit is correct; (2) directly-printed `inst_start`/`inst_next` operands surface no
opObject (not reached by x86 relative branches); (3) the `mainSubGroups` empty-mask fallback keys
on the sub-node subtree rather than Ghidra's flat name map (benign for x86); (4) delay-slot mask
length = full consumed length (moot — no supported arch has delay slots).

The critical path is therefore **open**. Nothing else is blocked on another lane.

---

## 3. The database question — answered: we can tap Ghidra's directly

The user's instinct was right, and it is better than the previous revision of this plan assumed.

**Ghidra's shipped FID databases are now embedded in this repo**, at
`third_party/ghidra-data/FunctionID/` — the **packed** `.fidb` form upstream publishes, 76 MB,
all ten sha256-verified byte-identical to the values `fetchDependencies.gradle` pins. They are
**external data files the mosura binary reads at runtime**: not compiled in, not a build input;
absent, the FID analyzer is inert. Provenance and format notes:
[`third_party/ghidra-data/README.md`](../third_party/ghidra-data/README.md).

The pinned `ghidra` checkout also holds them **unpacked** at
`ghidra/Ghidra/Features/FunctionID/build/data/*.fidbf` (204 MB) — useful as a decode
cross-check while writing the reader, but not what we ship:

| file | size | file | size |
| --- | --- | --- | --- |
| `vsOlder_x86.fidbf` | 41.0 MB | `vsOlder_x64.fidbf` | 28.6 MB |
| `vs2012_x86.fidbf` | 19.6 MB | `vs2012_x64.fidbf` | 18.0 MB |
| `vs2015_x86.fidbf` | 21.8 MB | `vs2015_x64.fidbf` | 19.9 MB |
| `vs2017_x86.fidbf` | 12.2 MB | `vs2017_x64.fidbf` | 10.7 MB |
| `vs2019_x86.fidbf` | 17.1 MB | `vs2019_x64.fidbf` | 15.3 MB |

204 MB total. `vsOlder` covers Visual Studio 1998 → 2010 (`data/building_fid.txt`).

**And both container layers are tractable — verified on the bytes, not assumed.** Ghidra has two
forms: `.fidb` (packed, what upstream ships and what we embed) and `.fidbf`
(`FidFile.java:46`, `FID_RAW_DATABASE_FILE_EXTENSION` — the raw `LocalBufferFile`); the module
build unpacks one to the other (`FunctionID/build.gradle:46`). Since we embed the packed form,
the reader does both steps at load:

1. **Unpack** (`ItemSerializer.java:43-90`). The `.fidb` header reads, byte for byte:
   `ac ed 00 05` (Java `ObjectOutputStream` magic + version), `77 44` (`TC_BLOCKDATA`, 68 bytes),
   then `writeLong(0x2e30212634e92c20)` = `ItemSerializer.MAGIC_NUMBER` at offset 6 exactly as
   `MAGIC_NUMBER_POS` declares, `writeInt(1)` = `FORMAT_VERSION`, `writeUTF("Function ID
   Database")` ×2 (item name, content type), `writeInt(fileType)`, `writeLong(length)` — then a
   plain single-entry DEFLATE'd ZIP stream. Confirmation the read is right: `vs2017_x86.fidb`'s
   length field is `0x00ba8000` = 12,222,464, which is **exactly** the size of the corresponding
   unpacked `vs2017_x86.fidbf`. No Java deserialization is involved — the header is a fixed
   shape with two length-prefixed strings, and `flate2` is already a workspace dependency.
2. **Decode**. The inflated payload is the raw `LocalBufferFile`: first 8 bytes
   `2f 30 31 2c 34 29 2c 2a` = `LocalBufferFile.MAGIC_NUMBER 0x2f30312c34292c2a`, then buffer
   size `0x4000` (16 KiB). On top of that sits Ghidra's `db` B-tree with the five FID tables.

This is worth doing early, because it buys two things at once:

- **MSVC x86/x64 coverage for free** — thousands of CRT/MFC/ATL functions, no ingest pipeline
  needed, working identification before we have built a single database of our own.
- **A byte-exact hash oracle of enormous size.** The records *are* Ghidra's hash quads. Hash an
  MSVC binary with mosura, look the quad up in Ghidra's own DB, and either it hits or our hasher is
  wrong. That is a far stronger gate than a hand-rolled dump script over a handful of functions,
  and it costs no Java at test time.

**Scope of the reader** (read-only, no write path): `LocalBufferFile` header + buffer index →
`DBParms` → `MasterTable` → `Schema`/`Field` decode → `Table` B-tree traversal
(`LongKeyInteriorNode`/`LongKeyRecordNode`, the `VarKey*`/`FixedKey*` variants as the FID schemas
require) → `ChainedBuffer` for spilled records → `FieldIndexTable` for the full-hash secondary
index. Ghidra's whole `db` package is 13.6 kLOC *including the write path*; the read-only subset
is a small fraction of that. It is mechanical, self-checking (a wrong decode fails loudly), and it
is a port, not an invention.

### Licence — checked 2026-08-07, clear to embed

The databases are **not** in the `ghidra` repo. `gradle/support/fetchDependencies.gradle:117-175`
downloads them, with a pinned sha256 per file, from
`github.com/NationalSecurityAgency/ghidra-data` at tag `Ghidra_${RELEASE_VERSION}`, into
`dependencies/fidb/` (the packed `.fidb`, 79 MB total); the module build unpacks those to
`build/data/*.fidbf`.

- **`ghidra-data` is Apache-2.0** — plain, unmodified text, no copyright-holder line and no
  appended terms; the repo states it "is governed by the same licensing and contribution
  guidelines as Ghidra."
- **No third-party encumbrance.** `Ghidra/Features/FunctionID/build/LICENSE.txt` enumerates the
  module's third-party files, and **the list is empty**. Ghidra's `NOTICE` adds the usual NSA
  framing (U.S. Federal Government work is public domain in the U.S.; everything else Apache-2.0).
- **`ghidra-data` ships no `NOTICE` file**, so Apache-2.0 §4(d) — the NOTICE-propagation clause —
  has nothing to propagate from it. We attribute Ghidra's anyway; we already do.
- **mosura is itself Apache-2.0** (workspace `Cargo.toml`, `README.md` §License), so there is no
  compatibility question at all.
- **Content is hashes plus symbol names, not Microsoft code.** The DBs were built by ingesting
  statically-linked MSVC libraries (`FunctionID.html:43-46`), but a FID record holds two 64-bit
  one-way digests, a code-unit count, flags and a name — nothing from which the original library
  code can be reconstructed. NSA distributes them under Apache-2.0 on that basis.

**Obligations we take on by redistributing** (Apache-2.0 §4): ship the licence text, retain
attribution, and **state that we changed the files** — a converted/native-store DB is a derivative
work, so the conversion must be declared. mosura already has the exact pattern for this:
`third_party/ghidra/` carries `LICENSE` + `NOTICE` + a provenance `README.md` naming the pinned
tag and commit. FID data goes in beside it the same way, recording the `ghidra-data` tag and each
file's upstream sha256 (they are pinned upstream, so the provenance is exact).

*Not legal advice — this is a read of the licence texts in the checkout and upstream, and it is
about redistribution only. Reading the files from a local Ghidra checkout carries no obligation at
all.*

### Container decision

- **Read** the packed `.fidb` natively (Stage 2), verbatim as upstream ships them. Faithful, and
  it is the user's explicit ask.
- **Write** our own DBs (Stage 6) in a **mosura-native** store, not a byte-replica of the
  BufferFile B-tree. Byte-replicating the write path buys zero identification fidelity — the
  *hashes* are what identify, and they are identical either way. The record **schema** is ported
  faithfully; only the envelope differs.
- Both feed one internal `FidDb` trait, so the matcher never knows which it is reading.

### Shipping — settled

The ten packed `.fidb` are **committed** at `third_party/ghidra-data/FunctionID/` (76 MB) and read
**at runtime by path** — external data, not compiled in, not a build input. No DB attached ⇒ the
analyzer is inert (Stage 5), so a consumer who strips them loses identification and nothing else.

Consequences to keep in view:
- **Path resolution** follows the existing `crates/mosura/src/paths.rs` shape (env override → repo
  tree), so a user can point at their own DB directory.
- **Clone weight.** 76 MB of binary blobs in git history. They are write-once (pinned to a Ghidra
  release), so there is no churn — but a pin bump rewrites all ten. If that becomes painful,
  git-lfs or a fetch script is the escape hatch; not worth pre-optimizing for a once-a-release
  change.
- **Integrity is gated**: `FunctionID/SHA256SUMS` is committed alongside and matches upstream's
  gradle pins file-for-file.
- Any DB mosura *emits* (Stage 6/7) is a generated artifact — stamp its input hash, never
  hand-edit.

---

## 4. Coverage — "all currently supported compilers and targets"

The supported matrix at `aad9f87`, and where each column's signatures must come from:

| Target (loader → language, cspec) | Compiler runtime | Signature source |
| --- | --- | --- |
| PE x86-32 / x86-64 (`pe.rs`) | **MSVC** 1998–2019 | **the embedded `.fidb`** (Stage 2) — free |
| LE x86-32 (`le.rs`), MZ x86-16 (`mz.rs`) | **Open Watcom** 10.0a/10.6/11.0/ow2 | our ingest — `clib3r`/`math3r` from `setup-watcom-dosemu.sh` |
| ELF x86-64 (`gcc`) | gcc/glibc | our ingest — `libc.a` + CRT |
| ELF x86-32 / EM_386 (`gcc`) | gcc/glibc | our ingest |
| ELF AArch64 (`AARCH64:LE:64:v8A`) | gcc/glibc | our ingest |
| ELF RISC-V 64 (`RISCV:LE:64:default`) | gcc/glibc | our ingest |
| ELF 68k (`68000:BE:32:Coldfire`) | gcc/newlib | our ingest — **big-endian, first non-LE column** |
| COM z80 (`z80:LE:16:default`) | sdcc | our ingest — sdcc runtime; smallest, good early proof |
| PE x86-32 | Borland BC++ 4.5 | our ingest (lowest priority) |

**Checked upstream, 2026-08-07: there is nothing else to tap.** The `ghidra-data` repo's
`FunctionID/` directory holds exactly eleven entries — the ten MSVC databases and a `FID.md`
readme — on **both** the `master` and `main` branches. No gcc, no Watcom, no Borland, no sdcc,
and nothing for any non-x86 architecture. `FID.md` documents only how to install the databases,
not any further set. So the free ride ends at MSVC.

Ghidra ships signatures for **exactly one** of these nine rows. The other eight are the real work,
and they are all served by the same Stage 6 ingest + the self-compiled-ground-truth setup already
in `docs/ground-truth-corpus.md`. Honest scoping: **coverage grows one runtime at a time.** First
useful milestone is Watcom clib (the subject north-star) plus one gcc/glibc target.

The library record pins `languageID` + `compilerSpecID`, so a DB never matches across
architectures — the matcher is arch-safe by construction, and adding a column is additive.

### Prior art next door: how `the RE tracker` named the Watcom CRT in the subject binary

`../the RE tracker` already labelled 161 Watcom CRT routines inside `the subject binary`. It is worth being
precise about how, because it looks at first glance like a counter-example to "Ghidra ships
nothing for Watcom" — and it is in fact the strongest evidence for this plan's Stage 6/7.

**It did not use FID.** There is no reference to FID, `.fidb`, or FLIRT anywhere in that project.
Ghidra's FID analyzer runs during auto-analysis, but with only MSVC databases loaded it has
nothing to say about a Watcom binary. So the agent wrote its own scheme from scratch —
`tools/ghidra/identify_crt.py`, 978 lines of Python (`analysis/crt-identification.md`):

1. parse the Watcom 10.0a OMF `.LIB` files (`CLIB3R`/`MATH387R`/`CPLX3R`) record by record;
2. rebuild each module's `_TEXT` from its `LEDATA`/`LIDATA` payloads;
3. mark every byte touched by a `FIXUPP` as a **wildcard** — a relocation mask;
4. slice function bodies by `PUBDEF` offset (next public, or segment end), trimming padding;
5. take the longest unmasked run (≥ 6 bytes) as a search anchor, scan the subject's code region, verify
   the whole body modulo the mask;
6. push names into Ghidra over MCP.

Result: **161 unique matches**, 175/533 `CLIB3R` publics covered, 3 ambiguous, 3 collapsed.

**Why this validates the plan rather than replacing it.**
- The 978 lines exist *because* nothing shipped for Watcom. That is the same gap §4 describes.
- Its founding premise — the CRT bytes in `the subject binary` are **byte-identical** to the bodies in the
  `.LIB`, because the same toolchain pre-compiled them — is exactly the premise Stage 7's Watcom
  column rests on, now demonstrated on the real target. That is a large de-risking.
- Its signature source, the OMF `.LIB`, is exactly what Stage 6 ingest consumes. mosura already
  parses OMF (`scripts/extract-omf-code.py` walks the LEDATA/LEDATA32 stream for the
  codegen-fingerprint probes) — Stage 6 needs the `PUBDEF`/`SEGDEF`/`FIXUPP` records too.

**Where FID is stronger, in exactly the places that tool reported as gaps.** Its unresolved cases
are not incidental — they are the cases a hash-plus-relations matcher is built for:
- **3 ambiguous** (`__STKOVERFLOW_` 5 hits, `__sigabort_` 8 hits, `itoa_` 2 hits) and **3 va-args
  trampolines collapsed onto one VA** (`sscanf_`/`fscanf_`/`fprintf_`, 33 bytes differing only in
  a masked `call` target). FID's **relation scoring** is precisely the discriminator: which
  callers and callees also matched. `forceRelation` exists for this shape.
- **30 bodies had "no usable anchor"** and 71 were "too short to fingerprint" — a contiguous
  ≥6-byte literal run is a brittle requirement. FID hashes the whole masked stream and floors at
  4 code units, so it needs no literal run at all.
- Exact byte search is all-or-nothing across library versions; FID's full/specific hash split
  exists so operand-level differences degrade the score instead of destroying the match.

**Where it is stronger:** for one known-version target it needs no database at all — lib straight
to binary. That is a good reason to keep it as an independent cross-check, not to replace it.

**The shared blind spot, worth stating plainly.** Compiler-emitted intrinsics (`__I8RS`, `__U8D`,
`__I8M`, the 386 codegen helpers) are emitted by `wcc386` directly into each user `.OBJ`, never
linked from a library. No amount of `.LIB` ingest will find them — FID included. The route is to
ingest a **self-compiled** program that provokes them, which is what `docs/ground-truth-corpus.md`
already builds.

**What we do NOT take from it — a standing constraint.**

- **`the subject binary` is not part of mosura's verification.** It is a user-supplied binary that can go
  away at any time, so no gate may depend on it. It serves as a **development guide** (a rich,
  real Watcom target to steer against while building) and as **post-release validation** — never
  as a test that must pass for the tree to be green. Stage 7's Watcom gate is built on
  **self-compiled** binaries whose CRT content we control and know: we own the source, the
  toolchain, and the link, so the expected name set is derivable from our own build, not from
  anyone's tracker. Same rule as the rest of `docs/ground-truth-corpus.md`.
- **`the RE tracker`'s data is a lead, not an oracle.** Its numbers (161 matched, 175/533 covered,
  the 152 `crt-known` tracker rows) come from a byte-search heuristic with its own documented
  failure modes — ambiguous hits, collapsed trampolines, an anchor-length floor. Useful for
  orientation and for cross-reading a result that looks wrong; never load-bearing. Anything from
  there that we care about gets re-derived from a source we own.

What survives from the comparison is the **mechanism knowledge**, which is what mattered: OMF
`.LIB` → PUBDEF-sliced bodies → FIXUPP-masked bytes is the shape of the Watcom signature source,
and the byte-identity premise is worth confirming ourselves on a self-compiled link.

---

## 5. Stages

Each lands independently and gated on `fid-port`. Ghidra paths below are under
`Ghidra/Features/FunctionID/src/main/java/ghidra/feature/fid/` unless noted.

### Stage 0 — SLEIGH operand/mask exposure ✅ LANDED (`2f69f51`)
See §2.

### Stage 1 — the hasher `FidHashQuad` ✅ LANDED
`crates/mosura/src/analysis/fid/{mod,hash}.rs` + `tests/fid_hash_vectors.rs` (13/13). Additive:
a new module plus one `pub mod` line, so nothing else in the tree changes (lib suite 545/545,
clippy clean, decompile_corpus 7/7 with 62/62 datatests).

One finding worth carrying forward: `E8` with a **zero** displacement (`call $+5`, the classic
PIC idiom) is **not a call** — `ia.sinc:2964` declares a separate, more specific `simm32=0`
constructor whose semantics are `goto`, not `call`, so FID does not subtract it from
`codeUnitSize`. The first version of the call test used a zero displacement and therefore
measured nothing; it now asserts the special case explicitly.

The port, as landed:
Port `hash/MessageDigestFidHasher.java` + `hash/FunctionBodyFunctionExtentGenerator.java` +
`Framework/Generic/…/generic/hash/FNV1a64MessageDigest.java` + the x86 skipper
(`Processors/x86/…/X86InstructionSkipper.java`) → new module `crates/mosura/src/analysis/fid/hash.rs`.

- **Digest**: FNV-1a 64 — basis `0xcbf29ce484222325`, prime `0x100000001b3`, `wrapping_mul` on
  `u64`. Ints/longs fed **big-endian, MSB first**. `digestLong` returns the raw state (no
  truncation). *Not* SHA, despite the class name.
- **Extent**: every instruction in the function body, ascending address, linear (not follow-flow);
  data units excluded; fewer than 4 code units ⇒ `None`.
- **Masking** (the crux, `MessageDigestFidHasher.java:102-205`): per code unit, AND raw bytes with
  the instruction mask, feed masked bytes to *both* digests; per operand, seed `(ii+1)*7777` and
  mix the opObjects. **Full** hash always uses placeholder `0xfeeddead` for scalars/addresses and
  `(off+7654321)*98777` for registers; **specific** hash folds the real scalar
  (`(val+1234567)*67999`) when it qualifies — a whole non-address scalar, or a partial one with
  `|val| < 256`, and not overlapping a relocation. `hasRelocation` (`:58-80`) narrows the operand
  byte range by the mask's nonzero span.
- **Outputs**: `codeUnitSize = codeUnitIndex − callCount` (i16),
  `specificHashAdditionalSize = min(specificCount, 127)` (i8), `fullHash`/`specificHash` (u64).
- **x86 skipper**: exact-byte match against the 17 VS/Intel multi-byte NOP patterns
  (`X86InstructionSkipper.java:33-71`); skipped units are neither hashed nor counted. Non-x86
  languages skip nothing.
- **Endianness**: the 68k column is the first big-endian target. Ghidra's hasher consumes *raw
  instruction bytes*, so it is endian-agnostic by construction — but the analysis-lane read paths
  are LE-hardcoded (`docs/multi-arch-plan.md`). Assert this rather than assume it, at the 68k
  column's gate.

### Stage 2 — read Ghidra's `.fidb` ✅ LANDED
`analysis/fid/{packed,bufferfile,db}.rs` + `tests/fid_packed.rs` (5/5) + `tests/fid_db_read.rs`
(6/6). Two gates, both independent of any expectation we authored:
- **2a, unpack** — our bytes are **byte-identical** to the `.fidbf` Ghidra's own build produces
  from the same file. Added a ZIP CRC-32 check off the streamed entry's data descriptor; without
  it a flipped bit inflates to same-length garbage and the corruption test passed when it should
  not have.
- **2b, decode** — every master-table record stores the count Ghidra wrote for that table;
  walking the B-tree must arrive at exactly that number. Across all ten databases and every
  primary table that is ~1.4 M records, and it lands exactly. Plus: the five FID schemas pinned
  field-for-field, library records checked to describe the architecture their filename claims,
  and function records required to cross-reference into the strings and libraries tables.

Index tables are deliberately not decoded (var-key structures; the full-hash lookup is served by
an in-memory index built from the functions table). Attempting one is an explicit error.

The port, as landed:
New module `analysis/fid/fidbf.rs` (unpack + buffer-file + `db` decode) and `analysis/fid/db.rs`
(the FID schema on top). Port `Framework/FileSystem/…/store/local/ItemSerializer.java` (the packed
wrapper, §3 step 1), `Framework/DB/…/db/buffers/LocalBufferFile.java`, the read-only slice of
`db/{DBHandle,MasterTable,Schema,Field,Table,*Node,ChainedBuffer,FieldIndexTable}.java`, and the
FID tables `db/{FunctionsTable,LibrariesTable,StringsTable,RelationsTable,FunctionRecord}.java`.

- **Function record** (`FunctionsTable.java:47-60`): `{code_unit_size:i16, full_hash:u64,
  spec_hash_add_size:i8, specific_hash:u64, library_id, name_id, entry_point, domain_path_id,
  flags:u8}`; **indexed on `full_hash` and `name_id`** (so the secondary-index decode is
  required, not optional). Flags: `HAS_TERMINATOR=1, AUTO_PASS=2, AUTO_FAIL=4, FORCE_SPECIFIC=8,
  FORCE_RELATION=16`.
- **Library record**: `{family, version, variant, tool_version, language_id, language_version:i32,
  language_minor:i32, compiler_spec_id}` — one language + cspec per library.
- **Strings** interned (names and paths by id).
- **Relations**: two membership sets keyed by a "hash smash" (`db/FidDBUtils.java:32-48`) —
  superior key = `caller_key * FNV_PRIME ^ callee_full_hash`, inferior key =
  `callee_key * FNV_PRIME ^ caller_full_hash`; inferior stored only for non-inter-library
  relations. No columns — presence *is* the relation.
- Same schema is what Stage 6's native writer emits; one `FidDb` trait over both.

### Stage 3 — the byte-exact hash gate ✅ LANDED (x86 at full parity; other arches ratcheted)
`oracle/fid/FidHashDump.java` + `scripts/capture-fid-hashes.sh` → 93 committed goldens /
**292 quads** over the self-compiled corpus, and `tests/fid_hash_parity.rs` requires mosura to
reproduce them. The dump records each function's **body address ranges** alongside its quad, so
the test hashes exactly the instructions Ghidra hashed — that isolates the *hasher* from
function-boundary recovery, which is a real question but a different one.

**Result: 216/292, with `gcc-x86-64` at 52/52 and `watcom-x86-32` at 83/84.** x86 is held at
full parity (a hard assertion); every other column is a ratchet that may rise and never fall.

**⭐ The finding this gate existed to produce: two of the hasher's inputs are ANALYSIS output,
not decode output.** Both were wrong in the obvious, plausible way, and only byte-comparison
against Ghidra could show it:

1. **`OperandType.ADDRESS`.** `InstructionDB.getOperandType` (`:398-419`) takes the SLEIGH
   prototype's `getOpType` and then ORs `ADDRESS` in **from the operand's primary reference**.
   So `LEA RAX,[0x402fe0]` reports `isScalar && isAddress`, and the hasher *suppresses* the
   value instead of folding it into the specific hash — deliberately, so where a global sits
   cannot change a function's signature. Reading the bit off SLEIGH alone silently folded every
   such address in. Fixed by [`OperandAddressQuery`], fed from the program's references.
2. **`getFlowType().isCall()`.** `InstructionDB.getFlowType` (`:321`) is
   `getModifiedFlowType(proto.getFlowType(this), flowOverride)` — so a tail `jmp` an analyzer
   turned into a call *is* a call, and gets subtracted from `codeUnitSize`. Re-deriving from
   p-code alone left the size one too high on every tail call. Fixed via `CodeUnitInput::is_call`
   fed from [`crate::analysis::flowtype::overridden_flow_props`].

Both are the class already recorded as `reftype-is-post-override-not-the-instruction`: a
property that looks like it belongs to the instruction actually belongs to the analysis.

**Stage-0 residuals, now adjudicated by real evidence:**
- **#1 (branch/call target surfaces as `Scalar` not `Address`) — CONFIRMED HARMLESS.** Ghidra's
  `Address` arm and our `Scalar` arm with `|val| ≥ 256` perform *identical* arithmetic and
  neither increments `specificCount`. Verified on AArch64 `bl`.
- **#3 (empty-operand-mask fallback) — WAS a real bug, now FIXED (see §8 R7).** For
  `mov x29,sp` Ghidra gives the `sp` operand an all-zero value mask and an instruction mask of
  `e0ffffff`; mosura gave a non-empty mask and cleared the wrong bits. Resolved by gating the
  fallback on nesting depth, as Ghidra's `mainSubGroups` does.

Two further known gaps, both decode-side rather than hasher-side:
`inlineparam.watcom-x86-32` (Ghidra hashes 6 code units where we decode 11 — the MZ
inline-call-parameter class) and the `watcom-le` column (1 function).

The port, as originally specified:
Stage 1 × Stage 2 meet here. Take real MSVC-built PEs, run mosura's hasher over the functions, and
require the quads to be **present in Ghidra's own database**. Plus a `FidHashDump` Ghidra script
(~30 lines: emit `entry, name, codeUnitSize, fullHash, specificHashAdditionalSize, specificHash`
per function) run over the self-compiled corpus, committed as goldens under `oracle/fid/hashes/`
— this is what covers Watcom/gcc/68k/z80, which Ghidra ships no DB for.

Ten watch-outs any mismatch will be one of: FNV not SHA; 64-bit wrapping multiply; big-endian int
feed; `digestLong` = raw state; `0xfeeddead` is signed; operand order matters but opObject order
does not; `applyMask` only touches `mask.length` bytes; calls are hashed but subtracted from the
size; NOPs skipped entirely; full uses the placeholder where specific uses the real scalar.

**Nothing downstream is trustworthy until this is green.** It is also where the four Stage-0
residuals get their verdict.

### Stage 4 — the matcher / scorer (faithful)
Port `service/FidProgramSeeker.java` (+ `service/HashMatch.java`, `service/MatchNameAnalysis.java`,
`service/NameVersions.java`, `cmd/ApplyFidEntriesCommand.java:105-120`) → `analysis/fid/match.rs`.

- **Candidates**: full-hash lookup only; the specific hash *refines the score*, it never fetches.
- **scoreMatch** (`FidProgramSeeker.java:314-372`): `autoFail` ⇒ reject; `functionScore =
  codeUnitSize` (floored to 24 if `autoPass`) `+ 0.67 * specificAddSize` (only when the specific
  hash matched); `forceSpecific` ⇒ reject unless specific matched; `childScore = Σ` callee
  code-units having a superior relation; `parentScore = Σ` caller code-units having an inferior
  relation (skipped at ≥ 500 parents); `forceRelation` ⇒ reject if `childScore == 0`;
  **reject if `function + child + parent < 14.6`**.
- **Cull**: sort by overall score descending, keep only those tied at the top (strict `<` breaks);
  one survivor ⇒ singleton, else multi-match.
- **Name collapse** (`MatchNameAnalysis`): raw / leading-underscore-stripped /
  demangled-without-template / demangled-base variants; a single common base ⇒ one name.
- **Apply gate** (`ApplyFidEntriesCommand.java:110-120`): every match is already ≥ 14.6; if the
  names will not collapse to one, the top score must additionally be ≥ **30**
  (`MULTINAME_SCORE_THRESHOLD`); never overwrite a USER or IMPORTED symbol; skip thunks.

### Stage 5 — the analyzer
`FidAnalyzer` at the existing `FUNCTION_ID` priority band (`analysis/priority.rs:27`, value 800 —
the slot Ghidra reserves for exactly this, already present and unused). Faithful port of
`analyzer/FidAnalyzer.java`: run the seeker over recovered functions against the attached DBs,
apply per Stage 4's gate, rename `FUN_xxxx` → the library name and add the plate comment. **Inert
when no DB is attached** — no DB, no behaviour change, exactly like the no-return pass on an empty
corpus.

At the end of this stage MSVC identification works end to end, with zero ingest written.

### Stage 6 — library ingest ✅ LANDED
`analysis/fid/{ingest,store,build}.rs`, `cargo xtask fid-build`, and
**[`docs/fid-building-databases.md`](fid-building-databases.md)** — the operational recipe, one
page, per-compiler commands runnable as written. Gates: `tests/fid_ingest.rs` (7/7) and
`tests/fid_roundtrip.rs` (2/2), both Ghidra-free.

The round trip is the meaningful one: hash a committed ground-truth binary's functions, ingest
them under the names its `.truth` file records (derived at build time from the compiler's own
`nm`/`objdump` — never from Ghidra, never from mosura), write the database, read it back, then
identify against the same **stripped** binary. Every name above the score threshold comes back
and nothing is invented, across x86-64, x86-32 Watcom and RISC-V.

Databases are the mosura-native `.mfid`: plain text, sorted, and **deterministic** — record
order and keys derive from content, not input order, so a rebuild diff shows real change. The
schema is Ghidra's; only the container differs.

The port, as originally specified:
Port `service/FidServiceLibraryIngest.java` → `analysis/fid/ingest.rs`.

Input = analyzed programs (one per object file of a `.a`/`.lib`). Per function: skip
external/thunk/default-named/under-4-code-units; hash; dedup on `generateHash()`
(specific + full + name + children, `:95-120`); commit the record; emit `DIRECT_CALL` relations for
non-very-common children; defer by-name calls; after all programs `resolveNamedRelations()` links
`INTRA_`/`INTER_LIBRARY_CALL`.
- **Commonality**: a supplied common-symbols list marks very-common children (skipped as
  distinguishers); a name reaching more than 12 specific hashes adds no relations
  (`MAXIMUM_NUMBER_OF_NAME_RESOLUTION_RELATIONS`). Ghidra's own
  `data/common_symbols_win32.txt` / `_win64.txt` are in the checkout as the reference shape.
- **auto-\*/force-\* flags** are a *separate post-pass* (`ghidra_scripts/RemoveFunctions.java`
  semantics: by full-hash lists and name regexes), not core ingest — port as a small config-driven
  pass.

### Stage 7 — signature DBs for EVERY supported compiler and architecture (the payoff)

**User directive 2026-08-07: the track is not done until every supported compiler × target
column has a signature database and a passing recall gate.** No column is optional and none is
"nice to have"; the order below is sequencing, not scope.

| # | Target (loader → language, cspec) | Runtime to ingest | Source of signatures |
| --- | --- | --- | --- |
| 1 | LE x86-32 (`le.rs`), MZ x86-16 (`mz.rs`) | **Open Watcom** 10.0a/10.6/11.0/ow2 | ingest `clib3r`/`math3r` (OMF `.LIB`) |
| 2 | ELF x86-64, `gcc` | **gcc/glibc** | ingest `libc.a` + CRT |
| 3 | PE x86-32 / x86-64 (`pe.rs`) | **MSVC** 1998–2019 | the embedded `.fidb` — no ingest |
| 4 | ELF x86-32 (EM_386), `gcc` | gcc/glibc | ingest |
| 5 | ELF AArch64 (`AARCH64:LE:64:v8A`) | gcc/glibc | ingest |
| 6 | ELF RISC-V 64 (`RISCV:LE:64:default`) | gcc/glibc | ingest |
| 7 | ELF 68k (`68000:BE:32:Coldfire`) | gcc/newlib | ingest — **big-endian**, first non-LE column |
| 8 | COM z80 (`z80:LE:16:default`) | sdcc | ingest the sdcc runtime — smallest, a good early proof |
| 9 | PE x86-32 | Borland BC++ 4.5 | ingest |

MSVC is listed third rather than first only because it needs no ingest — it is really the
*earliest* one to go green (it unblocks the end-to-end test below the moment Stage 5 lands).
R7 (the empty-operand-mask fallback) used to block rows 5–7 from Ghidra interoperability; it has
landed, along with two further mask-path fixes. Current byte-identical parity against Ghidra's own
hasher, per `tests/fid_hash_parity.rs` — **308/320**:

| column | quads | column | quads |
| --- | --- | --- | --- |
| gcc-x86-64 | 52/52 | gcc-aarch64 | 52/56 |
| watcom-x86-32 | 83/84 | gcc-m68k | 37/41 |
| borland-x86-16 | 24/25 | gcc-riscv64 | 57/58 |
| sdcc-z80 | 3/3 | watcom-le | 0/1 |

Each column is ratcheted at its measured value: it may improve, never regress.

**Every column's gate is the same shape, and it is Ghidra-free:**

> compile a program we own against that runtime → strip it → run mosura's FID over it →
> assert the expected runtime function names come back, and that **zero** wrong names do.

Ground truth is our own build (map file / unstripped symbols), so the gate needs no Ghidra at
test time and no user-supplied binary — only our code, our toolchains, and the committed
databases. This is the test that measures the actual product claim, as distinct from the
port-fidelity gates of Stages 1–3.

Each column ships: its database (or its fetch recipe), its regeneration command, its recall
gate, and its measured recall/precision numbers stamped with the commit that produced them.

---

## 6. Dependency graph

```
Stage 0 ✅ ──▶ Stage 1 (hasher) ──┐
                                  ├──▶ Stage 3 (BYTE-EXACT GATE) ──▶ Stage 4 (match) ──▶ Stage 5 (analyzer)
               Stage 2 (.fidbf) ──┘                                                            │
                                                       Stage 6 (ingest) ──▶ Stage 7 (DBs) ─────┘
```

Stages 1 and 2 are **independent and parallelizable**. Stage 3 is the choke point. Stage 6 needs
1 + 2's schema; Stage 7 needs 6; the analyzer is useful with Ghidra's DBs alone (MSVC) before any
of our own exist.

---

## 7. The test spine (anti-regression, per the standing rule)

Every stage lands with its own gate, and no stage's gate is allowed to weaken a previous one.

| Stage | Test | Kind | Fails when |
| --- | --- | --- | --- |
| 0 ✅ | `tests/sleigh_fingerprint.rs` | unit, 7/7 | masks/opObjects drift from the encoding |
| 1 | `tests/fid_hash_vectors.rs` | unit, hand-derived | FNV/masking/endianness/wrapping bug |
| 2 | `tests/fid_fidbf_read.rs` | decode | buffer-file/B-tree/schema decode wrong |
| 2 | table-count + spot-record goldens vs a Ghidra dump | golden | silent decode drift |
| **3** | **`tests/fid_hash_parity.rs`** | **byte-exact vs Ghidra** | **any hasher divergence** |
| 3 | `oracle/fid/hashes/*.golden` (FidHashDump) | golden | divergence on non-MSVC columns |
| 4 | `tests/fid_match_scoring.rs` | unit, table-driven | any threshold/scoring drift |
| 5 | `tests/fid_analyzer_inert.rs` | regression | analyzer perturbs output with no DB attached |
| 5 | full existing suite unchanged | regression | the new pass leaks into other analyses |
| 6 | `tests/fid_omf_ingest.rs` | unit | OMF PUBDEF/SEGDEF/FIXUPP slicing wrong |
| 7 | `tests/fid_recall.rs` per column, **self-compiled** | end-to-end ratchet | recall drops / a false name appears |

Three properties that make this a real spine rather than a checklist:

1. **The MSVC gate is self-verifying and huge.** Ghidra's shipped DBs hold on the order of
   hundreds of thousands of real hash quads. "Our hash of this function is in Ghidra's DB" is a
   gate no amount of plausible-looking wrong code survives.
2. **Ground truth we own.** For every non-MSVC column the recall gate compiles from source we
   own, strips it, and checks the recovered names against names we *know* — no Ghidra needed, and
   no user-supplied binary. **No gate may depend on a binary that can go away** (§4): mosura's
   tree must stay green on a clean clone plus its own toolchains, forever.
3. **Precision is gated as hard as recall.** A recall ratchet alone rewards guessing. Each
   column's gate asserts a false-name count of **zero** against known truth — a wrong name on a
   runtime function is worse than no name.

Additionally: every emitted DB is commit-stamped with its input hash (the generated-artifact rule),
and any measurement quoted in this doc is stale unless stamped `@sha == HEAD`.

---

## 8. Risks and open questions

- **R1 — Stage-0 residuals (medium, contained).** The four documented residuals could perturb
  hashes on some encoding we have not hit. Stage 3 is designed to find exactly this, against a
  corpus far larger than we could hand-build. Contained because the fix is local to the accessor.
- **R7 — the empty-operand-mask fallback (RESOLVED).** It was the AArch64 and m68k gap after
  all, and later the x86-16 one. `combine_operand_mask` was already returning Ghidra's answer;
  the *fallback* then overwrote it. Ghidra's is conditional — `mainSubGroups.get(sym.getName())`
  is allowed to miss — and the map holds only groups whose parent is the main group, so an
  operand qualifies exactly when it belongs to the constructor that IS the main group. x86
  constructors sit directly in the root table (so the fallback fires, supplying `rm8`'s mod/rm
  mask); m68k and AArch64 wrap the root in a flow-through constructor, so theirs sit a level
  deeper and it correctly misses. Landed in `steals_pattern_bits`.

  Two further mask-path defects fell out of the same investigation: a pattern block carrying a
  byte offset is committed **twice** by Ghidra and its own offset ignored when laying bytes down
  (m68k 12/41 → 37/41), and operand scalars must be **sign-extended from their own token-field
  width** (x86-16 17/25 → 24/25).

  ⚠️ Two earlier revisions of this entry were wrong — one blamed the fallback and was
  "disproven" by instrumentation that had the operand indices transposed, the other blamed
  `combine_operand_mask`'s recursion. Both are recorded here because the pattern is instructive:
  every wrong turn came from reasoning about the mask machinery instead of dumping it.
  `oracle/fid/FidMaskGroupDump.java` and `FidPatternTrace.java` exist for that.
- **R8 — mosura's references do not record an operand index (open).** They store `op_index = -1`,
  so `getPrimaryReference(opIndex)` cannot be asked directly and `tests/fid_hash_parity.rs`
  reconstructs the operand by value. Exact for whole-scalar operands (the only ones whose
  ADDRESS bit reaches a hash), but recording the real index in the reference analyzers would
  make it faithful rather than reconstructed.
- **R2 — operand-object fidelity per architecture (mostly closed).** Byte-identical hashes need
  mosura's Scalar/Register/Address split and signed scalar values to match Ghidra's *per
  language*. **Every column now has its own FidHashDump goldens**, including the two that had
  none (z80 and x86-16 — and both disagreed with Ghidra the moment they were first measured,
  which is exactly why "do not extrapolate x86 parity" was the right instinct).

  Still open on this axis, both currently inert for the digest: Ghidra emits `Address(N)` where
  we emit `Scalar(N)` for branch/call targets, and sets `addr=true` on memory operands where we
  say false. Neither changes a hash today (see §8 #1); both are real if opObjects are ever
  consumed elsewhere.
- **R3 — 68k big-endian (medium).** First non-LE column; the hasher is endian-agnostic on raw
  bytes but the analysis read paths are LE-hardcoded. Prove, don't assume.
- **R4 — licensing: ✅ RESOLVED 2026-08-07, clear to embed.** `ghidra-data` is Apache-2.0, the
  FunctionID module declares no third-party files, and mosura is Apache-2.0 too. See §3
  "Licence" for the obligations (licence text, attribution, and declaring the conversion as a
  change). Size is settled too: the 76 MB packed set is committed at
  `third_party/ghidra-data/FunctionID/` and read at runtime (§3 "Shipping").
- **R5 — relocation awareness (low).** `hasRelocation` needs the loader's relocation table
  queryable by operand byte range. Statically-linked libraries — the common FID case — usually
  have none, so scalar handling falls to the OperandType and `|val| < 256` rules.
- **R6 — DB provenance (low, but it caps the payoff).** Our DBs are only as good as the runtime
  libraries ingested and the names in them. Self-compiled or symbol-bearing vendor `.lib`/`.a` are
  fine; a stripped runtime is useless — no names to attach.
- **DB distribution: ✅ SETTLED.** The packed `.fidb` are committed and read at runtime as
  external data (§3 "Shipping").

---

## 9. Constants appendix (verified against this checkout, Ghidra 12.0.3)

| constant | value | source |
| --- | --- | --- |
| FNV-1a basis / prime | `0xcbf29ce484222325` / `0x100000001b3` | `FNV1a64MessageDigest.java:21-22` ✔ |
| min code units (SHORT_HASH) | `4` | `FidService.java:45` ✔ |
| MEDIUM_HASH (autoPass floor) | `24` | `FidService.java:46` ✔ |
| SCORE_THRESHOLD | `14.6f` | `FidService.java:47` ✔ |
| MULTINAME_SCORE_THRESHOLD | `30` | `FidService.java:48` ✔ |
| specific-count score weight | `0.67` | `FidProgramSeeker.java:361` |
| MAX_NUM_PARENTS_FOR_SCORE | `500` | `FidProgramSeeker.java:49` |
| operand seed | `(ii+1)*7777` | `MessageDigestFidHasher.java:140` ✔ |
| scalar mix (specific) | `(val+1234567)*67999` | `MessageDigestFidHasher.java:168` ✔ |
| register mix | `(off+7654321)*98777` | `MessageDigestFidHasher.java:174` ✔ |
| scalar/address placeholder | `0xfeeddead` (i32 `-17958739`) | `MessageDigestFidHasher.java:149,169` ✔ |
| mask-failure fill byte | `0xA5` | `MessageDigestFidHasher.java` |
| specificHashAdditionalSize cap | `127` | `MessageDigestFidHasher.java` |
| relation smash | `key*FNV_PRIME ^ other.fullHash` | `FidDBUtils.java:32-48` |
| record flags | terminator=1 autoPass=2 autoFail=4 forceSpecific=8 forceRelation=16 | `FunctionRecord.java:30-34` |
| name-resolution relation cap | `12` | `FidServiceLibraryIngest.java:41` |
| BufferFile magic | `0x2f30312c34292c2a` | `LocalBufferFile.java:36` ✔ (matches the shipped `.fidbf` headers) |

✔ = re-read from the checkout on 2026-08-07. Unmarked rows carry over from the earlier study and
are re-verified as their stage is written.

---

## 10. First move

**Stage 1 and Stage 2 in parallel**, converging on the Stage 3 byte-exact gate:

1. `analysis/fid/hash.rs` — the FNV-1a-64 digest and the masking loop, with hand-derived unit
   vectors from instruction encodings we can read off by hand.
2. `analysis/fid/fidbf.rs` — the read-only `LocalBufferFile` + `db` decode, proven by opening
   `vs2017_x86.fidbf` and enumerating the libraries table.

Then point them at each other on a real MSVC binary. That single assertion — *mosura's quad for
this function is present in Ghidra's own database* — converts the whole hasher from "carefully
ported" to "proven," and everything after it is mechanical.
