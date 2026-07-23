# FID (Function ID) port plan — identifying standard-library functions

**Goal.** Give mosura Ghidra's ability to name statically-linked standard-library functions in a
stripped binary — `strcpy`, `printf`, the CRT startup code, MFC/ATL, the Watcom/gcc/MSVC/Borland
runtimes — by fingerprinting each function's body and matching it against a signature database.
This is a **faithful port of Ghidra's FID subsystem** (`Ghidra/Features/FunctionID/`, ~9.2 kLOC,
52 files). We invent no fingerprinting scheme; we port Ghidra's, so mosura's hashes are
**byte-identical to Ghidra's** and it identifies the same functions.

This is distinct from the existing `codegen_fingerprint.rs` / `compiler_version.rs`, which
identify the **compiler/toolchain of the whole binary**. FID identifies an **individual
function**. Same word "fingerprint," opposite granularity — the two are complementary and both
belong in the analysis lane.

> Source study is complete: the exact algorithm for all three pillars (hash / match / db+ingest)
> is captured below with `ghidra/…:line` citations. Read this plan against
> `Ghidra/Features/FunctionID/src/main/java/ghidra/feature/fid/`.

---

## 0. The gating dependency — SLEIGH must expose operand masks (Stage 0, CRITICAL PATH)

FID's hash is computed from **disassembly-level** operand structure, not p-code. Per instruction
Ghidra's hasher (`hash/MessageDigestFidHasher.java`) needs:

| Ghidra API | what it gives | mosura today |
| --- | --- | --- |
| `prototype.getInstructionMask()` | byte-mask of the opcode-fixed bits (operand bits = 0) | **not exposed** (exists internally as `engine.rs` `Pattern.mask`) |
| `prototype.getOperandValueMask(ii)` | byte-mask of operand `ii`'s value bits | **not exposed** |
| `instruction.getOpObjects(ii)` | the operand's `Scalar`/`Register`/`Address` objects | **not exposed** (engine resolves them to render `body`) |
| `instruction.getOperandType(ii)` | operand type flags (scalar/address/register) | **not exposed** |
| `instruction.getFlowType().isCall()` | is this a call | derivable from p-code `CALL`/`CALLIND`, but Ghidra uses the disasm flow type |

mosura's `sleigh::Instruction` (`crates/mosura/src/sleigh/mod.rs:26`) carries only
`{address, bytes, mnemonic, body, pcode, ops}`. The masks/opObjects **exist inside the engine**
(`engine.rs`: `Pattern.mask`, the constructor/decision tree, operand handles used to render
`body`) but are not surfaced. **The p-code is NOT a faithful substitute** — Ghidra's masking keys
off the SLEIGH constructor pattern, not the lifted semantics; hashing off p-code would produce
different hashes and defeat the whole point.

**Therefore Stage 0 is a small, read-only, additive SLEIGH accessor** — and `crates/mosura/src/sleigh/`
is the **decompiler agent's** lane, which this agent must not modify. Options, in preference order:

1. **Coordinated read-only API (recommended).** Ask the decompiler agent to add an additive,
   behavior-neutral accessor that, per disassembled instruction, returns: the instruction mask
   bytes, per-operand value-mask bytes, and per-operand resolved objects (scalar value + type,
   register offset, or address) — i.e. a Rust mirror of `getInstructionMask` /
   `getOperandValueMask` / `getOpObjects` / `getOperandType`. This is data the engine already
   computes; exposing it changes no decompiler output. Define the exact struct here and hand it
   over as a one-page contract.
2. **Fallback — derive in-lane from engine internals** *if* the engine already makes the matched
   constructor + `Pattern.mask` reachable from the analysis lane (Stage 0 spike verifies this).
   The instruction mask is the AND of the matched constructor chain's pattern masks; operand value
   masks are the complement over each operand's field bits. Higher risk of drift from Ghidra;
   only if option 1 is refused.

**Stage 0 gate:** a spike that, for a handful of x86 instructions, produces `getInstructionMask`/
`getOperandValueMask`/`getOpObjects` equal to Ghidra's (dump both, diff). Nothing downstream is
byte-faithful until this is green. **This is the make-or-break of the whole track** — surface it
to the user + decompiler agent before Stage 1.

---

## 1. Faithful-port scope, and the one deliberate deviation

**Ported byte-faithfully (the identification is identical to Ghidra):**
- the hash algorithm (FNV-1a 64, operand masking, full/specific hashes, code-unit counting);
- the record **schema** (function record fields, library record fields, relation model);
- the matching + scoring + name-disambiguation algorithm and every threshold constant;
- the library-ingest algorithm (extent → hash → record + call relations, dedup, commonality).

**The one deviation — the on-disk container.** Ghidra's `.fidb`/`.fidbf` is its proprietary
BufferFile B-tree, packed inside a Java-ObjectStream+ZIP wrapper (`db/FidFile.java`,
`ItemSerializer`). Byte-replicating that format buys **zero identification fidelity** — it only
buys interop with Ghidra's *shipped* `.fidb`, and Ghidra ships FID DBs **only for Windows Visual
Studio 1998–2015** (`data/building_fid.txt:12-25`), *none* of which are even in the checkout
(downloaded separately) and *none* cover our primary targets (Watcom, gcc/glibc, Borland). So we
port the **schema + algorithm** faithfully and serialize it in a mosura-native store (a simple
columnar/`bincode` file or SQLite). The hashes inside are identical to Ghidra's; only the envelope
differs. A `.fidb` reader (ObjectStream+ZIP+BufferFile decode) is a **separable optional
follow-on** if we ever want to consume Ghidra's Windows DBs — parked, not on the critical path.

This respects "don't invent anything": the *logic* is Ghidra's verbatim; the *serialization* is a
framework detail we're not obligated to replicate to identify functions.

---

## 2. Staged bricks

Each stage lands independently, gated, on `analysis-port`. Ghidra source paths are under
`Ghidra/Features/FunctionID/src/main/java/ghidra/feature/fid/` unless noted.

### Stage 0 — SLEIGH operand/mask exposure (see §0). CRITICAL PATH, cross-lane.
Deliver the one-page API contract; get the accessor (option 1) or prove the in-lane derivation
(option 2); spike-verify against Ghidra for a few instructions. **Blocks everything.**

### Stage 1 — the hasher: `FidHashQuad` (faithful, byte-identical)
Port `hash/MessageDigestFidHasher.java` + `hash/FunctionBodyFunctionExtentGenerator.java` +
`generic/hash/FNV1a64MessageDigest.java` + the x86 skipper
(`Processors/x86/…/X86InstructionSkipper.java`). New module `analysis/fid/hash.rs`.
- **Digest**: FNV-1a 64-bit — basis `0xcbf29ce484222325`, prime `0x100000001b3`, `wrapping_mul`
  on `u64`. Ints/longs fed **big-endian, MSB-first**. `digestLong` returns the raw state (no
  truncation). NOT SHA.
- **Extent**: every instruction in the function body, ascending address order (linear, not
  follow-flow); data units excluded; min 4 code units or return `None`.
- **Masking** (the crux, `MessageDigestFidHasher.java:102-205`): per code unit, AND the raw bytes
  with the instruction mask (zero operand bits), feed the masked bytes to *both* digests; per
  operand, seed `(ii+1)*7777` and mix opObjects — **full** hash always uses placeholder
  `0xfeeddead` for scalars/addresses + `(off+7654321)*98777` for registers; **specific** hash
  folds the real scalar (`(val+1234567)*67999`) when it qualifies (whole non-address scalar, or
  partial with `|val|<256`, and not overlapping a relocation). `hasRelocation`
  (`:58-80`) narrows the operand range by the mask's nonzero byte span.
- **Outputs**: `codeUnitSize = codeUnitIndex − callCount` (i16), `specificHashAdditionalSize =
  min(specificCount,127)` (i8), `fullHash`/`specificHash` (u64).
- **x86 skipper**: exact-byte match against the 17 VS/Intel multi-byte NOP patterns
  (`X86InstructionSkipper.java:33-71`); skipped units are neither hashed nor counted. Non-x86
  languages skip nothing.
- **Gate**: `FidHashDump` Ghidra oracle (§4) → mosura reproduces the quad byte-identically for the
  self-compiled corpus + a few real binaries. This is the highest-value gate in the track.

### Stage 2 — the record store (faithful schema, mosura-native serialization)
Port the schema from `db/FunctionsTable.java`, `db/LibrariesTable.java`, `db/StringsTable.java`,
`db/RelationsTable.java`, `db/FunctionRecord.java` into `analysis/fid/db.rs`.
- **Function record**: `{code_unit_size:i16, full_hash:u64, spec_hash_add_size:i8,
  specific_hash:u64, library_id, name_id, entry_point, domain_path_id, flags:u8}`; indices on
  full_hash + name_id. Flags: `HAS_TERMINATOR=1, AUTO_PASS=2, AUTO_FAIL=4, FORCE_SPECIFIC=8,
  FORCE_RELATION=16`.
- **Library record**: `{family, version, variant, tool_version, language_id,
  language_version:i32, language_minor:i32, compiler_spec_id}` — one language+compilerspec per
  library.
- **Strings** interned (names + paths by id).
- **Relations**: two membership sets keyed by a "hash smash" (`db/FidDBUtils.java:32-48`) —
  superior key = `caller_key * FNV_PRIME ^ callee_full_hash`, inferior key =
  `callee_key * FNV_PRIME ^ caller_full_hash`; inferior stored only for non-inter-library
  relations. No columns — presence = relation exists.

### Stage 3 — the matcher/scorer (faithful)
Port `service/FidProgramSeeker.java` (+ `service/HashMatch.java`, `service/MatchNameAnalysis.java`,
`service/NameVersions.java`, `cmd/ApplyFidEntriesCommand.java:105-120`) into `analysis/fid/match.rs`.
- **Candidates**: full-hash lookup only; specific hash *refines score*, doesn't fetch.
- **scoreMatch** (`FidProgramSeeker.java:314-372`): `autoFail`→reject; `functionScore =
  codeUnitSize (floored to 24 if autoPass) + 0.67*specificAddSize (only if specific hash matched)`;
  `forceSpecific`→reject unless specific matched; `childScore = Σ callee code-units with a
  superior relation`; `parentScore = Σ caller code-units with an inferior relation` (skip if ≥500
  parents); `forceRelation`→reject if childScore==0; **reject if
  `function+child+parent < 14.6`**.
- **Cull**: sort by overallScore desc, keep only matches tied at the top score (strict `<` break);
  1 → singleton, else multi-match.
- **Name collapse** (`MatchNameAnalysis`): raw / leading-underscore-stripped / demangled-no-template
  / demangled-base variants; single common base ⇒ one name.
- **Apply gate** (`ApplyFidEntriesCommand.java:110-120`): every match already ≥ `14.6`; if names
  can't collapse to one, top score must additionally be ≥ **`30`** (`MULTINAME_SCORE_THRESHOLD`);
  never overwrite a USER/IMPORTED symbol; skip thunks.
- **Gate**: end-to-end — compile a program with a known runtime, strip it, build a DB from the
  runtime (Stage 4), confirm FID recovers the library-function names (self-compiled ground truth:
  we KNOW the answer).

### Stage 4 — library ingest (faithful DB builder)
Port `service/FidServiceLibraryIngest.java` into `analysis/fid/ingest.rs`.
- Input = analyzed programs (one per object file of a `.a`/`.lib`). Per function: skip
  external/thunk/default-named/<4-code-unit; hash; dedup on `generateHash()` (specific+full+name+
  children, `:95-120`); commit record; emit `DIRECT_CALL` relations for non-very-common children;
  defer by-name calls; after all programs `resolveNamedRelations()` links `INTRA_/INTER_LIBRARY_CALL`.
- **Commonality**: a supplied common-symbols list marks very-common children (skipped as
  distinguishers); name→>12-specific-hashes ⇒ add no relations
  (`MAXIMUM_NUMBER_OF_NAME_RESOLUTION_RELATIONS`).
- **auto-*/force-* flags** are a *separate post-pass* (`ghidra_scripts/RemoveFunctions.java`
  semantics: by full-hash lists + name regexes), not core ingest — port as a small config-driven
  pass.

### Stage 5 — signature DBs for our supported runtimes (the payoff)
This is where the self-compiled-ground-truth setup pays off. For each supported runtime, obtain the
runtime library, disassemble+analyze each object with mosura, ingest → a mosura signature DB:
- **Watcom** (clib3r/math3r/etc.) — from the versions we now compile (10.0a/10.6/11.0/ow2 via the
  wired toolchains); the LIB386 libs are already extracted by `setup-watcom-dosemu.sh`.
- **gcc/glibc** (x86-64/aarch64/riscv64/m68k) — the cross toolchains are installed; `libc.a`/CRT.
- **MSVC** (VC6/VS2005 CRT/MFC) — from the extracted VC toolchains; overlaps Ghidra's shipped set,
  useful as a cross-check of hash fidelity.
- **Borland** (BC++ 4.5 runtime).
Ship the small ones committed under `oracle/fid/` (like the codegen probes); document regeneration
via the same compiler pipeline. Honest scoping: coverage grows incrementally per runtime; start
with Watcom (the WAR2 north-star) + one gcc/glibc target.

### Stage 6 — the analysis-lane analyzer
A `FidAnalyzer` at the existing `FUNCTION_ID` priority band (`priority.rs:27`, value 800 — the slot
Ghidra reserves for exactly this). Faithful port of `analyzer/FidAnalyzer.java`: run the seeker over
recovered functions with the attached DBs, apply matches per Stage 3's gate, rename `FUN_xxxx` →
the library name + plate comment. Wire behind attached-DB availability (no DB ⇒ inert, like the
no-return pass on an empty corpus).

---

## 3. Dependency graph

```
Stage 0 (SLEIGH masks) ──▶ Stage 1 (hasher) ──▶ Stage 2 (store) ──▶ Stage 4 (ingest) ──▶ Stage 5 (DBs)
                                     │                                     │
                                     └────────────▶ Stage 3 (matcher) ◀────┘ ──▶ Stage 6 (analyzer)
```
Stage 0 blocks all. Stage 1 is the faithful-critical core (byte-identical gate). Stages 2–4 can
proceed once 1 is green; 5 needs 4; 6 needs 3+5.

---

## 4. Oracle strategy (proving byte-identical to Ghidra)

The FID hash is fully deterministic, so the oracle is Ghidra's own hasher. The Ghidra checkout +
JDK are present (the DEV dist was deleted but is rebuildable via `setup-ghidra.sh`; a headless
harness only needs the FunctionID module on the classpath).
- **`FidHashDump` script** (Ghidra ghidra_script, ~30 lines): for each function in an analyzed
  program, emit `entry, name, codeUnitSize, fullHash, specificHashAdditionalSize, specificHash`.
  Run once over the self-compiled corpus + a couple real binaries → committed goldens under
  `oracle/fid/hashes/`.
- **mosura gate**: `analysis/fid/hash.rs` reproduces every quad byte-identically. Any mismatch is a
  masking/endianness/wrapping bug — the ten watch-outs in the hash spec (FNV not SHA; 64-bit
  wrapping mul; big-endian int feed; `digestLong` = raw state; `0xfeeddead` signed; operand order
  matters / opObject order doesn't; `applyMask` only touches `mask.length` bytes; calls hashed but
  subtracted; NOPs skipped; full uses placeholder, specific uses real scalar).
- **Matching gate**: self-compiled ground truth — we compile, strip, and KNOW the names, so a
  recovered-name check needs no Ghidra. Optionally cross-check against Ghidra's FID run on the same
  binary for match-set parity.

---

## 5. Constants appendix (port these exactly)

| constant | value | source |
| --- | --- | --- |
| FNV-1a basis / prime | `0xcbf29ce484222325` / `0x100000001b3` | `FNV1a64MessageDigest.java:21-22` |
| min code units (SHORT_HASH) | `4` | `FidService.java:45` |
| MEDIUM_HASH (autoPass floor) | `24` | `FidService.java:46` |
| SCORE_THRESHOLD | `14.6f` | `FidService.java:47` |
| MULTINAME_SCORE_THRESHOLD | `30` | `FidService.java:48` |
| specific-count score weight | `0.67` | `FidProgramSeeker.java:361` |
| MAX_NUM_PARENTS_FOR_SCORE | `500` | `FidProgramSeeker.java:49` |
| operand seed / scalar mix / register mix | `(ii+1)*7777` / `(val+1234567)*67999` / `(off+7654321)*98777` | `MessageDigestFidHasher.java:147,171,175` |
| scalar/address placeholder | `0xfeeddead` (i32 `-17958739`) | `MessageDigestFidHasher.java` |
| mask-failure fill byte | `0xA5` | `MessageDigestFidHasher.java:196` |
| specificHashAdditionalSize cap | `127` | `MessageDigestFidHasher.java:215` |
| relation smash | `key*FNV_PRIME ^ other.fullHash` | `FidDBUtils.java:32-48` |
| flags | terminator=1 autoPass=2 autoFail=4 forceSpecific=8 forceRelation=16 | `FunctionRecord.java:30-34` |
| name-resolution relation cap | `12` | `FidServiceLibraryIngest.java:41` |

---

## 6. Risks / open questions

1. **Stage 0 (SLEIGH masks) is the whole ballgame.** If the decompiler agent can't/won't expose
   the operand masks and the in-lane derivation proves lossy, the *faithful* hash isn't reachable
   and the track stalls at the hasher. Resolve this FIRST, with the user + decompiler agent.
2. **Operand-object fidelity.** Byte-identical hashes require mosura's operand resolution
   (Scalar/Register/Address split, `getOperandType`, signed scalar value) to match Ghidra's per
   language. x86 first (best-tested); other arches follow as their operand exposure is verified.
3. **Relocation awareness.** `hasRelocation` needs the loader's relocation table at the operand
   byte range. mosura's ELF/PE loaders parse relocations; confirm they're queryable by address
   range (they are for the dynamic path). Static-linked libs (the common FID case) usually have
   none, so scalar handling falls to the OperandType / `|val|<256` rules.
4. **DB provenance.** Our signature DBs are only as good as the runtime libraries we ingest and the
   names in them. Self-compiled/known-name libs are ideal; vendor `.lib`/`.a` with symbols are
   fine; stripped runtimes are useless (no names to attach).
5. **Scope of coverage.** This is incremental per runtime, not a big-bang. First useful milestone:
   Watcom clib (feeds the WAR2 north-star — recovering named runtime functions in WAR2) + one
   gcc/glibc target, both self-compiled-validated.

---

## 7. First move

Land **Stage 0**: write the one-page SLEIGH-accessor contract (exact Rust struct for
instruction-mask + per-operand value-mask + opObjects + operand-type + call-flow), run the spike to
see whether the engine already reaches that data from the analysis lane, and take it to the user +
decompiler agent. Everything else is faithful mechanical porting once the operand masks are in
hand.
