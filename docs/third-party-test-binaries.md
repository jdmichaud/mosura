# Third-party material in this repository

A factual inventory of everything committed here that mosura's authors did not write, why it is
present, and what it is used for. Written so the question "does this repo contain material that
isn't ours?" has a checkable answer rather than an assumption.

Two categories, kept apart because their situations are not the same.

## 1. Open-source, redistributed under its own licence

| what | where | licence / provenance |
| --- | --- | --- |
| Ghidra — the language definitions and decompiler datatests mosura is a port of | `third_party/ghidra/` | Apache 2.0; `LICENSE`, `NOTICE` and `README.md` alongside, pinned to `Ghidra_12.0.3_build` (`09f14c92`) |
| Ghidra's shipped Function ID databases | `third_party/ghidra-data/FunctionID/*.fidb` (79 MB) | Apache 2.0, from `NationalSecurityAgency/ghidra-data` tag `Ghidra_12.0.3`; provenance in that directory's `README.md` |
| `6502.sla` | `crates/mosura/tests/fixtures/sla/` | compiled from Ghidra's own `6502.slaspec` (Apache 2.0) |

Nothing in this category needs any further justification: it is redistributed as its upstream
licence allows, with the licence text and the pin recorded next to it.

## 2. Fragments of, and programs linked against, historical proprietary toolchains

These are **test fixtures for reverse-engineering research**: mosura's whole purpose is to read
executables produced by compilers of this era, and a loader or a compiler-identification rule can
only be validated against real output from the compiler in question. Each file below is either a
program built from **our own source** (in `oracle/*/src/`) that necessarily links the vendor's
run-time, or a small slice of a vendor-produced binary retained as an identification marker.

| file | bytes | vendor material inside | why it is here — what fails without it |
| --- | --- | --- | --- |
| `oracle/analysis-corpus/watcom_hello.exe` | 15995 | Watcom C/C++32 run-time, © WATCOM International Corp. 1988-1994 | the Watcom banner-detection gate and the codegen-fingerprint reference (`analysis_parity.rs`, `codegen_fingerprint.rs`) |
| `oracle/fid/binaries/watprobe.watcom10.0a-x86-32.exe` | 27762 | same run-time | `fid_watcom_identify` — proves the Watcom FID column names real functions |
| `oracle/fid/binaries/bcprobe.bc4.5-cs-x86-16.exe` | 34540 | Borland C++ 4.5 run-time, © 1994 Borland Intl. | `fid_borland_identify` (small model) |
| `oracle/fid/binaries/bcprobe.bc4.5-cl-x86-16.exe` | 37810 | same run-time, large model | `fid_borland_identify` (large model) |
| `oracle/fid/binaries/crtprobe.msvc6-x86-32.exe` | 24576 | Microsoft Visual C++ 6.0 run-time | `fid_identify`, `fid_detect` |
| `oracle/analysis-corpus/markers/msvc6_rich.bin` | 1024 | a 1 KB slice of an MSVC 6-produced PE | the Rich-header version marker gate (`analysis_parity.rs`) |
| `oracle/analysis-corpus/markers/msvc8_rich.bin` | 1024 | a 1 KB slice of an MSVC 8-produced PE | as above, VS 2005 build id |
| `oracle/analysis-corpus/markers/borland45_banner.bin` | 58 | the Borland C++ 4.5 banner string | the Borland era-marker gate |
| `oracle/analysis-corpus/mingw_hello.exe` | 244084 | MinGW-w64 run-time + `libgcc` | the PE64 loader golden and several analyzer references |
| `oracle/analysis-corpus/mingw_hello32.exe` | 229835 | as above, 32-bit | the PE32 loader golden |

The last two are open-source run-times (MinGW-w64's is permissive; `libgcc` carries the GCC Runtime
Library Exception), so they belong in category 1 in substance; they are listed here only because
they are vendor run-times rather than our code.

### The maintainers' position

These files are retained for **interoperability and reverse-engineering research** — validating a
reimplementation of Ghidra's loaders and compiler identification against genuine output of the
compilers concerned. The products are long discontinued and unavailable commercially. No ownership
is claimed over any of this material, no licence to it is granted or implied by this repository's
licence, and it is not redistributed as a substitute for the original products: none of these files
is usable as a compiler, and each is a few kilobytes of test input. Any rights holder who would
prefer a file removed need only ask, and it will be.

Note that "abandonware" is a description of commercial reality, not a legal status, and the
paragraph above is the maintainers' rationale rather than legal advice.

### What is derived data, not vendor material

Worth distinguishing, because it is easy to assume otherwise:

- **`data/fid/*.mfid.gz` (96 databases) contain no vendor code.** Each record is a size, two
  hashes and a function *name* — the same nature as Ghidra's own shipped `.fidb`. They are built
  from vendor libraries but contain none of their instructions.
- **`oracle/codegen-probes/watcom/*.obj`** (430–689 bytes each) are *our* probe source compiled by
  the vendor's compiler — the compiler's output for our input, not their library.
- **`oracle/ground-truth/*`** is built with `option nodefaultlib` and a hand-written `_cstart_`, so
  it links no vendor run-time. One file, `callclob.watcom-x86-32`, does contain the Watcom banner
  *string* — because `oracle/ground-truth/src/callclob.c` declares it as a string literal on
  purpose, to exercise banner detection. That is our source quoting a notice, not their code.
- **The banner strings quoted in `loader/watcom.rs`, `loader/metaware.rs`,
  `loader/compiler_version.rs` and the docs** are short factual identifiers, reproduced so the
  detectors can match them and so a reader can check the detector against the real thing.

### Media that is deliberately *not* committed

Everything needed to *rebuild* the above lives outside the repository and is referenced by path
only — see [`dependencies.md`](dependencies.md). That includes every compiler distribution
(Watcom, MetaWare High C, Microsoft C 7.0), the Phar Lap 386|LINK SDK, the FlashTek X-32VM SDK and
its manual, and every copyrighted game binary used as analysis ground truth. Those are
user-provided, skip-if-absent, and no part of them is in git.
