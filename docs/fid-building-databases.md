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
| Watcom | 9.01, 10.0a, 10.5, 10.6, 11.0 (+ Open Watcom 2) — closed, small, **all installed** under `~/.dosemu/drive_c/` | a **complete** column is achievable |
| Borland, sdcc | bounded | complete columns achievable |
| MSVC | Ghidra already ships 1998–2019 | done |
| gcc / glibc | effectively unbounded — every distro build differs | **best-effort per toolchain**, never complete |

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

It is a **vote, not a lookup**: releases share code, so several databases match something and
what separates them is how much. `VersionReport::is_ambiguous` flags a top-two gap under 5% —
two adjacent point releases genuinely may be indistinguishable in a small binary, and saying so
beats picking one. A database holding several libraries (Ghidra's `vsOlder` spans 1998-2010) is
labelled from the libraries the winning records actually belong to, not from whichever is
stored first.

---

## Verifying a new database

Do not trust a database you have not tested against a binary whose contents you know.

1. **Compile a probe** against that runtime. `oracle/fid/src/crtprobe.c` exists for this: it
   calls a known set of library routines and compiles under MSVC, Watcom and gcc.
2. **Strip it.**
3. **Identify** and check the names against what the source calls.

That is exactly what `tests/fid_identify.rs` does for the MSVC column, and it is the shape
every column's gate takes (`fid-port-plan.md` §5 Stage 7). Assert **both** directions:

- **recall** — the routines the probe calls must come back;
- **precision** — the identified set must be exactly what you expect. A name you did not
  anticipate should fail the test and be examined, because a wrong name on a runtime function
  is worse than no name at all.

---

## Per-column recipes

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

### gcc / glibc (x86-64, x86-32, AArch64, RISC-V 64, 68k)

```sh
mkdir -p /tmp/libc && cd /tmp/libc
ar x /usr/lib/x86_64-linux-gnu/libc.a          # or the cross toolchain's libc.a

cargo xtask fid-build --family glibc --version "$(ldd --version | head -1)" --variant Release \
    --out oracle/fid/db/glibc-x86-64.mfid --dir /tmp/libc
```

⚠️ AArch64, RISC-V and 68k currently hash *differently from Ghidra* — see
[`fid-port-plan.md`](fid-port-plan.md) §8 R7 (the empty-operand-mask fallback). A database
built for those columns is internally consistent and will identify functions correctly against
itself, but is not interoperable with Ghidra until R7 lands.

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

Names come from `PUBDEF`. The modules are unlinked, so a cross-module call reads
`call 0000:0000` — the real target lives in a `FIXUPP` record only a linker consumes — and the
loader applies those fixups itself, pointing each call at a named slot in a synthetic
`EXTERNAL` block. All three encodings are handled: near 16-bit (`call rel16`), near 32-bit
(`call rel32`), and the **16:16 far pointer** the medium/large/huge memory models use.

Far calls matter more than their share suggests: they are segment-relative rather than
self-relative, and leaving them unpatched cost the far models nearly every caller/callee
relation (9–27, against 193–310 for the near models). Relations are what carry a small function
over the 14.6 score threshold, and about a quarter of a Borland runtime scores below it on body
size alone — so those functions were unidentifiable despite having a signature. With far fixups
applied the far models sit in line with the near ones (303–377).

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

**Objects** — ingest the library's OMF modules directly:

```sh
./scripts/build-borland-db.sh objects /path/to/CS.LIB tc2.0 cs
```

Names come from `PUBDEF`, which is authoritative. But the modules are **unlinked**: a
cross-module call still reads `call 0000:0000`, because the real target lives in a `FIXUPP`
record that only a linker consumes. The loader patches *self-relative* (near) fixups so those
calls reach a named external slot; **far** calls are fixed up as segment-relative 16:16
pointers and are not patched, so the far memory models (`cm`/`cl`/`ch`) end up with very few
relations — 9–27 against 193–310 for the near models.

That matters because relations are what carry a *small* function over the 14.6 score
threshold. Measured on Turbo C 2.0: **27% of the small model and 22% of the large model score
below 14.6 on their own body**, so in the far models most of that quarter is unidentifiable
even though its signature is in the database.

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

**Linked** — let the vendor's linker resolve everything:

```sh
./scripts/build-borland-db.sh linked /path/to/toolchain tc2.0 l
```

`cargo xtask omf-uber` generates a program referencing every C-callable public in the library,
TCC compiles it, TLINK links it, and mosura analyses the **executable**, where every call is
real. This needs no relocation patching at all — the tool that is supposed to resolve those
calls does it.

A DOS `.EXE` carries no symbol table, so the names come from the linker map (`tcc -M`), passed
with `--map`. Map addresses are relative to the start of the load image, which the MZ loader
places at segment `0x1000`.

⚠️ **Status: the linked route is not yet better.** It produces correctly-named functions (256
from Turbo C 2.0 large, via 434 map addresses) and analysis does recover the call graph — 497
call references in that image — but only 14 of them survive into stored relations, fewer than
the object route's 20. The loss is in ingest's child resolution, not in the linking, and is an
open thread. Use the `objects` route until it is closed.

⚠️ Also note the linker only pulls in what is referenced, so a linked build covers fewer
functions than the library holds (256 against 344) — `omf-uber` forces every *C-callable*
public, but symbols that are not legal C identifiers (`@`-decorated internals, C++ mangling)
cannot be referenced from generated C and are skipped.

---

## Troubleshooting

| symptom | cause |
| --- | --- |
| `ingested 0` | the inputs have no symbols, or no file could be analyzed. Check `nm`/`wlib -l` output. |
| everything `FailsMinimumShortHashLength` | function bodies were not recovered — the objects analyzed but no code was disassembled. |
| database builds but identifies nothing | language/compilerspec mismatch. Compare the `language` line in the `.mfid` against what mosura reports for the target binary. |
| identifies the *wrong* name | check the precision half of your gate first, then whether two runtime versions were ingested into one database. |
