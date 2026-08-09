# Building FID signature databases

How to give mosura the ability to name a runtime's functions. One page, one recipe per
compiler column, every command runnable as written.

Background on the port itself is [`fid-port-plan.md`](fid-port-plan.md); this document is
purely operational.

---

## The idea in one paragraph

FID identifies a function by **hashing its body** and looking that hash up in a signature
database. A database is built by feeding mosura the runtime library *with its symbols intact*:
for each function it records the hash, the name, and which other functions it calls. Later,
in a **stripped** binary, the same body hashes to the same value, the lookup hits, and the
name comes back. Ghidra ships databases for Visual Studio only, so every other runtime we
support — Watcom, gcc/glibc, sdcc, Borland — needs one built here.

---

## What you need

| | |
| --- | --- |
| **The runtime library, with symbols** | `.lib` / `.a` / a directory of `.obj` / `.o` files. Stripped input is useless: no names to attach. |
| **A mosura build** | `cargo build --release` |
| **Nothing else** | No Ghidra, no network. |

---

## The command

```sh
cargo xtask fid-build \
    --family  "Open Watcom" \
    --version "10.0a" \
    --variant "Release" \
    --common-symbols oracle/fid/common-symbols/watcom.txt \
    --out     oracle/fid/db/watcom-10.0a-x86-32.mfid.gz \
    --dir     /path/to/extracted/clib3r-objects
```

- `--dir` takes every file in a directory; you can also list files individually.
- `--family` / `--version` / `--variant` become the library record. `--variant` is
  conventionally `Release` or `Debug` — build both when the runtime ships both, since their
  bodies differ.
- `--common-symbols` is optional but recommended; see below.
- All inputs must share one language and compiler spec. Mixed input is skipped with a message
  rather than silently merged: a library record pins one language, and that is what stops a
  match ever crossing architectures.

It prints what it did:

```
fid-build: 214 input file(s) -> oracle/fid/db/watcom-10.0a-x86-32.mfid.gz
  ingested  1893
  relations 4102
  excluded  310    Duplicate
  excluded  88     FailsMinimumShortHashLength
  excluded  12     IsThunk
```

Those numbers are the health check. `ingested` far below the number of public symbols in the
library usually means the symbols did not survive extraction — check that first.

---

## Getting the object files out of a library archive

The ingest wants individual objects, because each one is a program mosura can analyze.

| format | extract with |
| --- | --- |
| Unix `.a` (gcc, sdcc) | `ar x libc.a` |
| OMF `.LIB` (Watcom, Borland) | `wlib -x -b clib3r.lib` (Open Watcom's `wlib`) |
| COFF `.LIB` (MSVC) | `lib /extract:` per member, or `7z x` |

Extract into an empty directory and point `--dir` at it.

---

## The common-symbols list

A caller/callee edge only helps identification when it is **distinguishing**. Nearly every
function calls `memcpy`; recording that fact tells the matcher nothing and costs a relation
per call site. Listing such symbols suppresses those relations.

Format — one symbol per line, `#` for comments:

```
# Routines so common that calling them identifies nothing.
memcpy
memset
malloc
free
```

Ghidra's own lists are the reference shape and are worth reading:
`../ghidra/Ghidra/Features/FunctionID/data/common_symbols_win32.txt`. Ghidra built theirs by
running an ingest, taking the ~70 most common child symbols it reported, and merging across
libraries. You can do the same: build once without a list, look at what dominates, write the
list, rebuild.

---

## Attaching the database

`.mfid.gz` / `.mfid` files are read from the FID database directory, alongside Ghidra's
`.fidb`:

```sh
# default: third_party/ghidra-data/FunctionID
export MOSURA_FID_DIR=/path/to/databases
```

A database is attached to a program only when its `language` and `compilerspec` match, so
several columns can live in one directory without interfering.

---

## The format: sorted text, gzipped on disk

Both axes on the same 40,911-function database (Ghidra's `vs2017_x64`), measured in the same
configurations so the comparison is honest:

| artifact | on disk | load |
| --- | ---: | ---: |
| Ghidra `.fidb` (packed) | 3,849,100 | 67 ms |
| Ghidra `.fidbf` (unpacked B-tree) | 10,682,368 | — |
| mosura `.mfid` (plain text) | 7,153,017 | 29 ms |
| **mosura `.mfid.gz` (what we ship)** | **2,053,183** | **50 ms** |

**We ship compressed.** Plain text loads ~20 ms faster per database, but costs 3.5× the bytes —
and those bytes are paid in the **release tarball**, which ships working files with nothing else
compressing them. Twenty milliseconds a database is not worth 5 MB a database on every
download. (Git would have compressed the stored object either way; the tarball is the case that
decides it.)

Even compressed, loading beats `.fidb`: that format pays for DEFLATE *and* a B-tree walk across
651 buffers with node and chained-buffer decode, where this is inflate plus a linear scan.

`read_file` detects gzip **by magic, not by extension**, so a hand-written or hand-edited plain
`.mfid` still loads — useful when inspecting or diffing one.

---

## Versions: one database per toolchain build

**A signature identifies one build of one library.** FID hashes the function body, so code from
glibc 2.41 and glibc 2.39 hash differently and a database built from one will not recognise the
other. This is inherent to the technique, not a limitation of this implementation — it is why
Ghidra ships **ten** databases (vs2012 / vs2015 / vs2017 / vs2019 / vsOlder × x86 / x64) rather
than one, and why the matcher queries *every* attached database at once.

So the practical question per runtime is how closed its version set is:

| runtime | version set | outlook |
| --- | --- | --- |
| Watcom | 9.01, 10.0a, 10.5, 10.6, 11.0 under `~/.dosemu/drive_c/`, plus Open Watcom 2 — closed, small, all held | **complete across VERSIONS** |
| Borland, sdcc | bounded | complete columns achievable |
| MSVC | Ghidra already ships 1998–2019 | done |
| gcc / glibc | effectively unbounded — every distro build differs | **no database shipped** (see below) |

"Complete" has two axes and they are easy to confuse. Across **versions**, Watcom and Borland are
closed sets and every one is held. Across **libraries**, each column once ingested the C run-time
only — the separately-shipped math, emulator and graphics libraries were missing, so any program
doing float work had functions no database could name. That is closed too, per column, in
[`fid-library-coverage.md`](fid-library-coverage.md), which also records what stays deliberately
excluded (application frameworks, other-OS targets) and why.

Name a database for what it actually contains — `watcom-10.0a-x86-32.mfid`, not `watcom.mfid`
— and build every version you can obtain. They coexist in one directory and are all consulted.

---

## The database format

`.mfid` is deliberately plain text, sorted, and self-describing — these are generated
artifacts that get regenerated and reviewed, and a diff should show real change:

```
mosura-fid 1
language x86:LE:32:default
compilerspec watcom
library Open Watcom|10.0a|Release
# f codeUnitSize fullHash specAddSize specificHash flags name
f 12 a1b2c3d4e5f60718 3 0011223344556677 1 strlen_
s 1a2b3c4d5e6f7081
i 90a1b2c3d4e5f607
```

`f` is a function record, `s` and `i` are relation keys (superior = caller→callee, inferior =
callee→caller; the key's presence *is* the relation).

**Regeneration is deterministic**: record order and keys are derived from content, not from
input order, and the gzip level is fixed, so the same inputs always produce a byte-identical
file — compressed or not. `tests/fid_ingest.rs`
asserts this by ingesting the same library forwards and backwards.

The *schema* is Ghidra's, ported faithfully. Only the container differs — Ghidra writes a
packed B-tree (`.fidb`), which we read but gain nothing from writing, since the hashes inside
are identical either way.

---

## Using the databases to date a binary

The databases answer a second question besides "what is this function": **which build of the
runtime was this linked against**. `analysis/fid/detect.rs` scores a program against every
database of its language and reports them ranked.

That matters because in-band version markers are often absent or too coarse. Borland stopped
embedding a version string after Turbo C 1.5 — its later libraries carry only `__turboCrt` and
`__turboFloat` — and a copyright year cannot separate Turbo C 1.5 from 2.0, since both say
1988. A signature is byte-exact and comes from the runtime build itself.

Measured on binaries whose provenance we know because we compiled them:

```
uber program built by Turbo C 2.0, large model:
   borland-tc2.0-cl    167 matched  score 7293   <- right release AND memory model
   borland-tc2.01-cl   155 matched  score 6597   <- adjacent point release, close as expected
   borland-tc2.0-cm     39 matched  score 1302   <- wrong memory model, far weaker
   borland-tc1.5-cl      9 matched  score  275

probe built by MSVC 6, against Ghidra's 1998-2019 databases:
   vsOlder_x86           8 matched  score  462   -> Visual Studio 1998
```

Discrimination is gated across the whole set: `tests/fid_detect_versions.rs` scores every
database against all the others on its own signatures, and all 71 win. The hard adjacent pairs
separate clearly — `tc2.0` 4992 against `tc2.01` 4576, `watcom-10.6` 7088 against `11.0` 1739.

**One genuine exception, and it is a fact about the releases rather than a limit of the
method**: Borland C++ 4.52's 32-bit runtime is **940 of 941 functions identical** to 4.5's — it
is a patch release that barely touched `CW32.LIB`. No signature can separate them, the two
score exactly equal, and `is_ambiguous` says so. Their 16-bit models *do* differ (9560 against
7210), so only the flat 32-bit column is affected.

It is a **vote, not a lookup**: releases share code, so several databases match something and
what separates them is how much. `VersionReport::is_ambiguous` flags a top-two gap under 5% —
two adjacent point releases genuinely may be indistinguishable in a small binary, and saying so
beats picking one. A database holding several libraries (Ghidra's `vsOlder` spans 1998-2010) is
labelled from the libraries the winning records actually belong to, not from whichever is
stored first.

---

## Verifying a new database

Do not trust a database you have not tested against a binary whose contents you know.

1. **Compile a probe** against that runtime. `oracle/fid/src/crtprobe.c` (MSVC, gcc) and
   `oracle/fid/src/watprobe.c` (Watcom) exist for this: each calls a known set of library
   routines. `scripts/build-fid-probes.sh [column]` builds them.
2. **Strip it.**
3. **Identify** and check the names against what the source calls.

⚠️ **Then check the gate can fail.** A recall gate measures nothing if its answer is fixed in
advance, and that is easy to miss because it looks green either way. The Watcom probe was written
twice for this reason: the first version, built from `crtprobe.c`, named the same 17 functions
against the databases from *before* and *after* the OMF relocation fix. `watprobe.c` calls
routines that read static tables — the shape that fix repaired — and scores 30 before, 38 after.
Run a candidate gate against a known-bad input before trusting it.

That is what `tests/fid_identify.rs` does for the MSVC column and `tests/fid_watcom_identify.rs`
for Watcom, and it is the shape every column's gate takes (`fid-port-plan.md` §5 Stage 7). It is
also the only *non-self-referential* evidence a column has: `fid_detect_versions` scores each
database against its own records, and `fid_database_drift` proves a database reproduces from its
libraries — neither can tell you it matches a real linked program. Assert **both** directions:

- **recall** — the routines the probe calls must come back;
- **precision** — the identified set must be exactly what you expect. A name you did not
  anticipate should fail the test and be examined, because a wrong name on a runtime function
  is worse than no name at all.

---

## Per-column recipes

**To rebuild everything, run `./scripts/rebuild-fid-db.sh`** — it holds all 85 recipes, and
`-n` checks that every source library is present without building anything. The sections below
explain *why* each column is built the way it is and how to obtain the libraries in the first
place; the script is what actually reproduces the committed set. Keep the two in step: a recipe
that lives only in prose cannot be checked, and the one gap this audit missed — the Watcom 16-bit
math libraries — survived precisely because nothing could state what the column was supposed to
contain.

### MSVC (x86-32 / x86-64) — nothing to build

Ghidra ships these and they are committed at `third_party/ghidra-data/FunctionID/`, covering
Visual Studio 1998 through 2019. Rebuild the probe and run the gate:

```sh
./scripts/build-fid-probes.sh msvc6
cargo test --release -p mosura --test fid_identify
```

### Open Watcom (x86-32 LE / x86-16 MZ)

```sh
# 1. extract the runtime (setup-watcom-dosemu.sh already unpacks the LIB386 libraries)
mkdir -p /tmp/clib3r && cd /tmp/clib3r
wlib -x -b "$WATCOM/lib386/dos/clib3r.lib"

# 2. build
cargo xtask fid-build --family "Open Watcom" --version 10.0a --variant Release \
    --out oracle/fid/db/watcom-10.0a-x86-32.mfid --dir /tmp/clib3r
```

⚠️ Watcom decorates its symbols (`strlen_`, `_strcpy_`); the names in the database are the
names in the library, so expect the trailing underscore.

### gcc / glibc (x86-64, x86-32, AArch64, RISC-V 64, 68k) — recipe only, nothing shipped

⚠️ **No glibc database is committed, deliberately.** A glibc signature set identifies only the
exact distro build it came from, and there are effectively unlimited such builds, so a committed
one would mostly be dead weight that still has to be loaded and scored on every vote. The recipe
below is here for building one against a runtime you actually care about. The 71 committed
databases are Borland (64), Watcom (6) and sdcc (1).

```sh
mkdir -p /tmp/libc && cd /tmp/libc
ar x /usr/lib/x86_64-linux-gnu/libc.a          # or the cross toolchain's libc.a

cargo xtask fid-build --family glibc --version "$(ldd --version | head -1)" --variant Release \
    --out oracle/fid/db/glibc-x86-64.mfid --dir /tmp/libc
```

Every column is now measured against Ghidra's own hasher (`tests/fid_hash_parity.rs`, 308/320
byte-identical). x86-64 and z80 are exact; the rest carry small ratcheted gaps — aarch64 52/56,
m68k 37/41, riscv64 57/58, x86-16 24/25, watcom-x86-32 83/84. A database from a column with a
gap is internally consistent and identifies correctly against itself; the residual functions are
the ones that would not match a Ghidra-built database.

### Open Watcom 2

Built from the source tree rather than a shipped release:

```sh
cargo xtask fid-build --family Watcom --version ow2 --variant Release \
    --out oracle/fid/db/watcom-ow2-x86-32.mfid.gz \
    /data/open-watcom-v2/bld/clib/library/msdos.386/ms_r/clib3r.lib
```

⚠️ **Provenance caveat.** Every other database here comes from a runtime the vendor *shipped*,
which is what a target binary was actually linked against. This one comes from a local build of
a rolling source project. Real OW2 binaries are linked against official release snapshots, and
if their code generation differs from this build's, the signatures will not match. It is worth
having — OW2's library source moves slowly, and it closes the one version we could detect but
not identify — but validate it against a binary built by an official OW2 release before
trusting it.

### sdcc (z80)

```sh
cargo xtask fid-build --family sdcc --version 4.5.0 --variant z80 \
    --out oracle/fid/db/sdcc-4.5.0-z80.mfid.gz /usr/share/sdcc/lib/z80/z80.lib
```

Point it straight at the library: `z80.lib` is a Unix `ar` archive of SDCC `.rel` objects — an
**ASCII** record format, a third object container alongside ELF and OMF — and
`loader/rel.rs` reads both the archive and the members. Relocations against external symbols
are applied, as for OMF: without them every cross-module call targets address 0 and the
library records **no relations at all** (0 against 376), leaving the 19% of functions that
score below 14.6 on body size alone unidentifiable.

### Borland / Turbo C (x86-16 and x86-32)

Two routes, and it is worth understanding why there are two.

**Objects** — ingest the library's OMF modules directly (the default):

```sh
./scripts/build-borland-db.sh objects /path/to/CS.LIB tc2.0 cs
```

Names come from `PUBDEF`. The modules are unlinked, so a cross-module reference reads as zero —
the real target lives in a `FIXUPP` record only a linker consumes — and the loader applies those
fixups itself, a port of Ghidra's `OmfLoader.processRelocations`: every location type (byte,
16-bit offset, segment base, 16:16 far pointer, 32-bit offset), every target method (segment,
group, external), segment-relative as well as self-relative. External targets point at a named
slot in a synthetic `EXTERNAL` block.

Far calls matter more than their share suggests: they are segment-relative rather than
self-relative, and leaving them unpatched cost the far models nearly every caller/callee
relation (9–27, against 193–310 for the near models). Relations are what carry a small function
over the 14.6 score threshold, and about a quarter of a Borland runtime scores below it on body
size alone — so those functions were unidentifiable despite having a signature. With far fixups
applied the far models sit in line with the near ones (303–377).

⚠️ **Do not narrow this back to "the encodings a call uses."** That is what it was, and it made
*data* references keep a zero displacement — which changes the SLEIGH constructor, not just the
value, so byte-identical code hashed differently in the library and in the linked program. It
cost WAR2 ten CRT names while every internal check stayed green. See
[`fid-library-coverage.md`](fid-library-coverage.md).

#### Getting the libraries out of a Borland install set

The four Turbo C releases ship uncompressed floppies, so `7z e <disk>.img '*.LIB'` is enough.
Everything later packs its files into `.CA1`/`.CA2`/`.CA3` archives — which are **ordinary ZIPs
behind a 4-byte prefix**, split across disks as volumes that concatenate:

```sh
# stage every disk of one product into a directory, then
./scripts/extract-borland-ca.sh <staged-dir> <output-dir>
```

`7z` rejects a `.CA` file only because of those four leading bytes. Strip them from each volume,
append in order, and it reads as a ZIP.

Worth recording what does **not** work, since each cost a detour: `INSTALL /b` is a
black-and-white colour switch, not a batch mode; piping keystrokes into dosemu does not reach a
DOS program's INT 16h keyboard reads, so the installer hangs; Borland's own `UNPACK.COM` (1989)
recognises the format but cannot read the later revision; and their `UNZIP.EXE` rejects it.

#### Where the libraries actually live (and why that matters)

Regenerating every Borland column takes ~15 minutes **if the libraries are staged** and the best
part of an hour if they are not, so they are staged persistently:

| path | contents |
| --- | --- |
| `/data/tools/borland_turbo_c/` | the 17 original media archives (742 MB) — the source of truth |
| `/data/borland/src/` | those archives extracted (1.6 GB) |
| `/data/borland/work/<product>/` | per-product disk images unpacked to flat directories |
| `/data/borland/work/<product>-lib/` | the `.CA`-extracted libraries, for the products that use them |
| `/data/borland/BC45/LIB/` | BC++ 4.5, which predates this layout |

⚠️ **This layout exists because the extracted toolchains were once staged under `/tmp` and got
cleaned, which read as "the media is gone" when the media was intact the whole time.** If a
library is missing, re-extract from `/data/tools/borland_turbo_c/` — nothing is unrecoverable.

Three traps when re-extracting:

- The media directories **nest one level deeper than the archive name**, so a glob misses the
  disk images; use `find`.
- **C++ Builder 5 is a raw Mode 2 Form 1 CD image.** Its sectors need slicing at bytes
  `24..2072` (offset 16 is Mode 1 and yields nothing) before `7z` can read the filesystem.
- Turbo C floppies carry `.LIB` files uncompressed; everything later needs
  `extract-borland-ca.sh` first.

**Linked** — let the vendor's linker resolve everything:

```sh
./scripts/build-borland-db.sh linked /path/to/toolchain tc2.0 l
```

`cargo xtask omf-uber` generates a program referencing every C-callable public, TCC compiles
it, TLINK links it, and mosura analyses the executable. A DOS `.EXE` has no symbol table, so
names come from the linker map (`tcc -M`), passed with `--map`; map addresses are relative to
the load image, which the MZ loader places at segment `0x1000`.

⚠️ This route is **not** currently the better one. It names correctly (256 functions via 434
map addresses) and analysis recovers 497 call references, but only 14 survive into stored
relations — the loss is in ingest's child attribution, not in the linking. It also covers fewer
functions than the library holds, since the linker drops unreferenced modules and symbols that
are not legal C identifiers cannot be referenced from generated C. Use `objects`.

## Troubleshooting

| symptom | cause |
| --- | --- |
| `ingested 0` | the inputs have no symbols, or no file could be analyzed. Check `nm`/`wlib -l` output. |
| everything `FailsMinimumShortHashLength` | function bodies were not recovered — the objects analyzed but no code was disassembled. |
| database builds but identifies nothing | language/compilerspec mismatch. Compare the `language` line in the `.mfid` against what mosura reports for the target binary. |
| identifies the *wrong* name | check the precision half of your gate first, then whether two runtime versions were ingested into one database. |
