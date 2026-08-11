---
name: fid-port-track
description: "FID (Ghidra Function ID) port track — plan in docs/fid-port-plan.md; Stage 0 landed, Ghidra's shipped .fidbf DBs ARE in the checkout"
metadata:
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-07T13:23:33.972Z
---

**Track: port Ghidra's FID (Function ID)** — identify statically-linked stdlib/runtime functions in
stripped binaries (Ghidra FID / IDA FLIRT equivalent) across all supported compiler runtimes.
User-opened 2026-07-23, re-opened + replanned **2026-08-07**: "we should be able to tap that
database directly and embed it with mosura" → **faithful port**, byte-identical hashes.

Full plan = **`docs/fid-port-plan.md`** (rewritten 2026-08-07). Branch **`fid-port`** @
`/home/jd/projects/mosura/mosura-fid`, cut from `master` `aad9f87` — **sibling of `ghidra/` on
purpose** so `GHIDRA_SRC`'s `../ghidra` default resolves (see
[[worktree-needs-ghidra-src-or-ratchet-lies]]). Tasks #1–#7 = stages 1–7.

**Distinct from `codegen_fingerprint`/`compiler_version`** — those ID the whole-binary COMPILER;
FID IDs an individual FUNCTION. Same word, opposite granularity.

**⭐ THE 2026-08-07 FINDING — Ghidra's shipped FID databases, now EMBEDDED in the repo.**
`third_party/ghidra-data/FunctionID/*.fidb` (packed form, 10 files / 76 MB, all sha256-verified
against the gradle pins, + `SHA256SUMS` + `LICENSE` + provenance README). **USER DECISION
2026-08-07: committed, and read AT RUNTIME BY PATH as external data — not compiled in, not a
build input.** Two payoffs: MSVC x86/x64 coverage with zero ingest written, and **a byte-exact
hash oracle of hundreds of thousands of real quads** ("our quad is present in Ghidra's own DB").

**⚠️ Two containers, don't confuse them.** `.fidb` = PACKED (what upstream ships / what we
embed); `.fidbf` = the raw `LocalBufferFile` (magic `0x2f30312c34292c2a`, 16 KiB buffers) that
Ghidra's module build unpacks to (`FunctionID/build.gradle:46`) — the checkout has those at
`build/data/` (204 MB), useful only as a decode cross-check. The packed wrapper
(`ItemSerializer.java:43-90`) is NOT real Java deserialization: `ac ed 00 05` + `77 44`
TC_BLOCKDATA, magic `0x2e30212634e92c20` at offset 6, version 1, 2× writeUTF, fileType,
**writeLong(unpacked length)** — then a plain single-entry DEFLATE'd ZIP. Proof the read is
right: vs2017_x86's length field `0xba8000` = 12,222,464 = exactly its `.fidbf` size. `flate2` is
already a workspace dep.

**⭐ CHECKED UPSTREAM 2026-08-07 — there is NOTHING else to tap.** `ghidra-data`'s `FunctionID/`
holds exactly 10 MSVC `.fidb` + `FID.md`, on **both** the `master` and `main` branches. No gcc,
no Watcom, no Borland, no sdcc, nothing non-x86. Don't re-check this hoping otherwise.

**Licence ✅ CLEAR TO EMBED (checked 2026-08-07).** The `.fidb` are NOT in the ghidra repo —
`gradle/support/fetchDependencies.gradle:117+` downloads them (sha256-pinned each) from the
SEPARATE repo `github.com/NationalSecurityAgency/ghidra-data` @ tag `Ghidra_<ver>` into
`dependencies/fidb/` (packed, 79 MB; unpacked 204 MB). ghidra-data = plain Apache-2.0, no
appended terms, **no NOTICE file** (so §4(d) has nothing to propagate);
`Features/FunctionID/build/LICENSE.txt` lists third-party files and the list is **EMPTY**; mosura
is Apache-2.0 too. A record is 2 one-way digests + count + flags + name — no MSVC code is
recoverable. Redistribution obligations = licence text + attribution + **declare the conversion
as a change**; follow the existing `third_party/ghidra/` pattern (LICENSE+NOTICE+provenance
README naming the pinned tag). Remaining constraint is SIZE, not permission.

**Stage 0 ✅ LANDED on master as `2f69f51`** (`sleigh::disassemble_fingerprint` →
`InstructionFingerprint`; additive, 0 deletions; `tests/sleigh_fingerprint.rs` 7/7). ⚠️ the old
SHA `c5dbd8a` is PRE-REBASE and reachable only from tag `pre-master-rebase-2026-08-05` — cite
`2f69f51` ([[landed-means-reachable-from-a-ref]]).

**Coverage reality:** Ghidra ships signatures for **1 of our 9 supported compiler×target columns**
(MSVC PE only). Watcom, gcc/glibc ×5 arches, sdcc/z80, Borland all need our own Stage-6 ingest —
that is the bulk of the work, served by [[self-compiled-ground-truth]].

**Key faithful facts** (verified ✔ against Ghidra 12.0.3, 2026-08-07): FNV-1a 64 (basis
`0xcbf29ce484222325` ✔, prime `0x100000001b3`, wrapping, ints fed big-endian, `digestLong` = raw
state — NOT SHA); full hash masks all operands (scalar placeholder `0xfeeddead` ✔, registers
`(off+7654321)*98777` ✔), specific hash folds real small scalars (`(val+1234567)*67999` ✔),
operand seed `(ii+1)*7777` ✔; extent = body instructions ascending, min 4 code units ✔;
`codeUnitSize = count − callCount`; x86 NOP skipper (17 patterns). Match: full-hash candidates
only, score = codeUnitSize (floor 24 if autoPass ✔) + 0.67·specificAddSize + Σ relation
code-units, reject < 14.6 ✔, multi-name gate 30 ✔.

**Test spine** (the user's standing anti-regression requirement): per-stage gates, and each
column's recall gate asserts **zero false names**, not just recall — a recall-only ratchet rewards
guessing.

Status: replanned, not implemented. See [[war2-issues-become-source-tests]],
[[ghidra-dependency-pin]].
