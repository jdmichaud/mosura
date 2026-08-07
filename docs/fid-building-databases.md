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
    --out     oracle/fid/db/watcom-10.0a-x86-32.mfid \
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
fid-build: 214 input file(s) -> oracle/fid/db/watcom-10.0a-x86-32.mfid
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

`.mfid` files are read from the FID database directory, alongside Ghidra's `.fidb`:

```sh
# default: third_party/ghidra-data/FunctionID
export MOSURA_FID_DIR=/path/to/databases
```

A database is attached to a program only when its `language` and `compilerspec` match, so
several columns can live in one directory without interfering.

---

## Why the format is text, and what it costs

Measured on Ghidra's `vs2017_x64` (40,911 functions + 116,129 relations) converted to `.mfid`:

| artifact | bytes | vs `.fidb` |
| --- | ---: | --- |
| Ghidra `.fidb` (packed, DEFLATE'd) | 3,849,100 | — |
| Ghidra `.fidbf` (unpacked B-tree) | 10,682,368 | 2.8× |
| mosura `.mfid` (plain text) | 7,153,017 | 1.9× |
| `.mfid` + gzip -9 | 2,053,183 | 0.53× |
| `.mfid` + zstd -19 | 1,428,081 | 0.37× |

Raw text is ~1.9× Ghidra's *packed* form — but that compares compressed against uncompressed.
Like-for-like it is already smaller (7.2 MB of text against 10.7 MB of B-tree, which carries
node headers and slack), and compressed it wins outright: hex digits and symbol names have far
less entropy than an already-DEFLATE'd image.

Git also compresses objects, so a committed `.mfid` costs roughly its gzip size in the pack.
And because records are **sorted**, a rebuild that changes fifty functions produces a small
delta git packs well — where a rebuilt binary B-tree is a whole new blob every time. For an
artifact that is regenerated and reviewed, sorted text is the cheaper choice over the repo's
life.

If a column ever produces an unreasonably large database, transparent `.mfid.zst` reading is a
small change. Measure the column first.

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
| Open Watcom | 10.0a, 10.6, 11.0, OW2 — closed, small, all obtainable | a **complete** column is achievable |
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
input order, so the same inputs always produce a byte-identical file. `tests/fid_ingest.rs`
asserts this by ingesting the same library forwards and backwards.

The *schema* is Ghidra's, ported faithfully. Only the container differs — Ghidra writes a
packed B-tree (`.fidb`), which we read but gain nothing from writing, since the hashes inside
are identical either way.

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

The z80 runtime ships as `.rel` objects, which mosura's COM loader does not read. Build the
probe as a `.com` and ingest that instead — a small, self-contained first proof.

### Borland (x86-32 PE)

As Watcom: extract with `wlib` (Borland's `.LIB` is also OMF), then `fid-build`.

---

## Troubleshooting

| symptom | cause |
| --- | --- |
| `ingested 0` | the inputs have no symbols, or no file could be analyzed. Check `nm`/`wlib -l` output. |
| everything `FailsMinimumShortHashLength` | function bodies were not recovered — the objects analyzed but no code was disassembled. |
| database builds but identifies nothing | language/compilerspec mismatch. Compare the `language` line in the `.mfid` against what mosura reports for the target binary. |
| identifies the *wrong* name | check the precision half of your gate first, then whether two runtime versions were ingested into one database. |
