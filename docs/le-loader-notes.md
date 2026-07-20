# LE (Linear Executable) loader — design notes

**Status: loader implemented** (`crates/mosura/src/analysis/loader/le.rs`), validated
against the ground truth below by `le_war2_objects` in `tests/analysis_parity.rs` (the two
objects + the entry, parsed from the real file bytes). Ghidra has no LE/LX loader, so there
is no Ghidra oracle — this is the first loader mosura builds **beyond** Ghidra, done
**natively** (not via the ELF-wrapper workaround), grounded in the LE/LX spec + the
warcraft2-re RE result recorded here.

## Standing decision: default = Ghidra, opt-in = LE loader (the two-oracle policy)

The bound-exe dilemma — Ghidra has no LE oracle, so loading the real LE objects has nothing
Ghidra to validate against — is resolved by a **two-behaviour CLI policy** (agreed):

- **Default behaviour = match Ghidra.** A bound DOS/4GW exe (e.g. WAR2.EXE) loads as the
  16-bit MZ stub, exactly as Ghidra does. The committed war2 goldens and the Ghidra-parity
  gates stay on this path — the "validated against Ghidra" guarantee is **unchanged** for the
  default. The CLI emits a **warning** that the file has bound LE content the default view
  does not cover, and names the opt-in flag.
- **Opt-in behaviour (`--le` or similar) = the native LE loader.** The user consciously steps
  off the Ghidra path to load the real 32-bit game image. **"Optional" ≠ "unvalidated":** this
  path is validated against the **`warcraft2-re` reverse-engineering ground truth** (its proper
  oracle, since Ghidra has none), holding the same faithful / 0-spurious bar — just against a
  different reference.

So the rule is: **default validated against Ghidra; `--le` validated against the RE ground
truth.** This is also the standing precedent for any future format Ghidra cannot open: default
to Ghidra parity, offer a documented extension behind a flag, validated against its own oracle.

**Native-LE analysis (task #8, done):** the 32-bit (`x86:LE:32:default`) analysis pipeline runs
over the LE objects via the library entry `analysis::analyze_le_file` — the opt-in `--le` view
(the flag + warning land later **with the CLI**; analysis is a library API today). The default
container dispatch keeps a bound exe on the Ghidra-parity MZ-stub path (its goldens + gates
UNTOUCHED). The native-LE path is validated against the warcraft2-re RE ground truth (Ghidra has
no LE loader) as a clean subset in `le_war2_analysis`: 541 functions discovered (watcall cspec
from task #7, `_cstart_` entry 0x601F8), the no-spurious-reference invariant (every recovered
reference targets mapped obj1/obj2 memory), and 0 spurious COMPUTED_JUMP.

**Switch recovery (task #2 — the "beat Ghidra on WAR2" win, LANDED).** The *real* protected-mode
computed jumps are the Watcom **`jmp CS:[reg*4 + disp]` inline jump tables** (`fn_79130`/`793e0`/
`7a5b0` decompressor family and ~15 more across the image). The root cause of them not resolving
was **unapplied LE relocations**: both the `jmp cs:[...]` table displacement *and* every table
entry are LE fixup records that relocate by the object's `reloc_base` (obj1 `+0x10000`). With the
raw (unrelocated) bytes, the tables read garbage and the switch-gated code — including the
decompressor, reached only through those switches — stayed dark (function count `~541`).
`load_le` now applies the fixups (`apply_le_fixups`, below), so the tables read their real
absolute targets, mosura's standard `JumpBasic` recovers them, and discovery reaches `~1279`
functions. This is grounded in **the binary's own fixup records** (Ghidra has no LE loader, so
its MZ-stub `war2.snapshot` 20 COMPUTED_JUMP — artifacts of misreading the 32-bit code — are not
used). Validated in `le_war2_analysis` as a clean subset (every COMPUTED_JUMP target mapped, none
invented; the two decode-loop dispatches assert EXACTLY: `0x795d5 → {0x795e0,0x79cb0,0x7a400,
0x7a4a0}`, `0x7a7d5 → {0x7a7e0,0x7af10,0x7b6c0,0x7b7b0}`). No decompiler/sleigh change was needed:
post-fixup the dispatch is the standard `LOAD(ram, table+idx*4); BRANCHIND`, and the `CS` prefix
is a correct no-op under the flat model once the base is baked into the (relocated) displacement.

**LE fixups / relocations (`apply_le_fixups`).** The loader applies the LE **Fixup Page Table**
(`LE+0x68`, `num_pages+1` u32 page→record offsets) + **Fixup Record Table** (`LE+0x6c`, packed
`SRC FLAGS SRCOFF/CNT OBJECT TARGETOFF [ADDITIVE] [SRCOFF-list]` records). WAR2 is 100% *internal*
(target-type 0) *32-bit-offset* (`SRC=0x07`) fixups — 17517 of them, 0 imports — each patched to
`objects[obj].reloc_base + target_offset`. Imports/selectors are not sized/applied (no LE test
binary uses them). This mirrors how `elf.rs` applies relocations at load; it is the beyond-Ghidra
`--le` path, so the oracle is the binary's fixup bytes. Only the `--le` path is affected — the
default MZ-stub / Ghidra-parity path and its `war2` goldens are byte-identical.

## Why native, not an ELF32 wrapper

`warcraft2-re` gets results today by extracting the LE objects and synthesising a fake ELF32
to feed Ghidra (`tools/ghidra/make_war2_elf.py`). That is a pragmatic workaround for Ghidra's
missing LE loader — **not** a clean design:

- it fabricates a container the binary isn't, discarding the LE's real structure (fixup,
  import, and resident-name tables, the page map);
- it is binary-specific and manual (hand-computed page offsets, hardcoded vbases/entry);
- it conflates *what the file is* (LE) with *what loader happened to exist* (ELF-only).

The clean, maintainable design is a native `loader/le.rs` alongside `elf.rs`/`pe.rs`/`mz.rs`,
dispatched by format, producing the LE's objects-as-blocks directly.

## Validation without a Ghidra oracle

"No Ghidra loader" ≠ "no oracle". A native LE loader is validated against:

1. **The LE/LX spec** — a documented format, so a faithful implementation is not an
   approximation. Refs (from `~/projects/warcraft2-re/README.md`):
   - https://faydoc.tripod.com/formats/exe-LE.htm
   - OS/2 OMF & LX Object Formats, Rev 8 (bitsavers PDF)
   - http://justsolve.archiveteam.org/wiki/Linear_Executable
2. **`warcraft2-re` ground truth as the golden** — the human RE work establishes the correct
   load result; mosura's LE loader must reproduce exactly these objects (see below). This is a
   concrete parity target, arguably *more* faithful to the binary than Ghidra's ELF hack.
3. **Runtime/disasm sanity** (once A4 lands) — does the loaded image disassemble into the
   ~1100 expected functions from a sensible entry point.

## WAR2.EXE specifics (the reference case)

`~/WAR2.EXE` is **DOS/4GW Pro–bound** (Tenberry). Quirks (from
`~/projects/warcraft2-re/analysis/ghidra-setup.md`):

- `e_lfanew` (MZ field at `0x3C`) is deliberately invalid (`0x9B40000`) so DOS doesn't treat
  it as a "new EXE"; the DOS/4GW stub finds its embedded LE via `BW` markers. **Dispatch must
  detect the embedded LE, not trust `e_lfanew`.**
- LE header at file `0x37CF4`. Its `Data Pages Offset` field (LE+`0x80`) reads `0x25400`,
  which is meaningless in the bound file. The real page region is computed from EOF:
  `pages_start = file_size - (n_pages-1)*page_size - last_page_size = 0xD6627 - 123*0x1000 - 0xF83 = 0x5A6A4`.
- Two objects (the golden the loader must reproduce):

  | Object | Role        | Virtual base | Size      | Perms |
  | ------ | ----------- | ------------ | --------- | ----- |
  | obj1   | code `_TEXT`| `0x10000`    | `0x6C4A0` | R+X   |
  | obj2   | data `_DATA`| `0x80000`    | `0x2B300` | R+W   |

- Entry: LE+`0x1C` init-EIP is an **offset within the init object**, not a virtual address;
  absolute entry = `obj1_vbase + 0x501F8 = 0x601F8` (`_cstart_`, a Watcom CRT init thunk;
  first 2 bytes `EB 76` jump over an inline banner string).
- **The inline banner (file `0xAA89C`, right after the `EB 76`) identifies the compiler +
  version era**: `WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International
  Corp. 1988-1994. All rights reserved.` — vendor wording + copyright year range are the
  version fingerprint (classic "WATCOM International Corp." ≤10.x era; later versions use
  Sybase / Open Watcom wordings). The 16-bit DOS/4GW stub carries its own banner
  (`WATCOM C Run-Time system ... 1988-1993`). Ghidra has **no** Watcom detection outside
  the OMF loader's translator comment, and **no watcom cspec at all** — so Watcom
  detection/versioning and the watcall cspec are two-oracle extensions (tasks #8/#9),
  grounded in open-watcom-v2 source, validated vs warcraft2-re.
- Page alignment `0x1000`. Loads as `x86:LE:32:default`, image base `0x10000`.
- The LE loader-section region (`0x37CF4`..`0x5A6A4`) holds fixup/import/resident-name tables.
  The loader **applies the fixups** (`apply_le_fixups`, see the switch-recovery section) — they
  relocate the internal references (incl. the cs:-relative jump tables); the fixup page/record
  tables live here.

## Prerequisites in mosura before LE is worth doing

- **32-bit ELF / `x86:LE:32:default`** support generally (the LE objects are 32-bit i386).
- The A2 loader framework + snapshot are format-agnostic already; `le.rs` slots in like the
  others.
- Reach Ghidra parity on the ELF/PE/MZ + analysis pipeline first (the stated gate).

## Pointers

- Sibling project: `~/projects/warcraft2-re` — `analysis/ghidra-setup.md`,
  `tools/ghidra/make_war2_elf.py`, `tools/ghidra/make_war2_objects.py`.
- Memory: [[war2-dos4gw-le]].
