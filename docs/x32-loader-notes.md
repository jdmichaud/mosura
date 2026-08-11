# X-32 (FlashTek 32-bit DOS extender) loader — design notes

**Status: implemented.** `crates/mosura/src/analysis/loader/x32.rs`, gated by
`crates/mosura/tests/x32_loader.rs` (8 tests, 7 of which need no user-provided binary).
Compiler-side work (detection, cspec, FID) is a separate track:
[`metaware-highc-support.md`](metaware-highc-support.md).

On the real sample the native view recovers **751 functions** where the Ghidra-parity default view
sees 3 (the extender stub):

```sh
cargo run --release --example fidnames -- --native <exe>   # 751 functions
cargo run --release --example fidnames -- <exe>            # 3 — the 16-bit stub, as Ghidra sees it
```

A second container Ghidra cannot open, following the standing precedent set by
[`le-loader-notes.md`](le-loader-notes.md): **default dispatch matches Ghidra (the 16-bit MZ
stub), a native loader is offered as an opt-in view, validated against its own oracle.** Nothing
here is specific to one binary — the format is what is being loaded, and every constant below is
*read from the container*, not baked in.

## How Ghidra structures this, and what it implies for us

Worth recording, because it settles what belongs in code and what belongs in data:

- **Container layout is code, always.** Every Ghidra format is a Java `Loader` in
  `Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/` (`ElfLoader`, `PeLoader`,
  `MzLoader`, `NeLoader`, `CoffLoader`, `OmfLoader`, `MachoLoader`, `BinaryLoader`, …). No XML
  describes a container's byte layout. There is **no** `LeLoader`/`LxLoader` there — hence
  `le.rs`, and hence this loader must be code too.
- **Container → language/cspec selection is XML data**, in
  `Ghidra/Processors/<proc>/data/languages/<proc>.opinion`. The loader supplies its name plus
  `primary`/`secondary` keys and `QueryOpinionService` resolves the rest, e.g. from `x86.opinion`:

  ```xml
  <constraint loader="Old-style DOS Executable (MZ)" compilerSpecID="default">
      <constraint primary="23117" processor="x86" endian="little" size="16" variant="Real Mode"/>
  ```

  (`23117` = `0x5A4D` = `MZ`.) The PE block's `secondary="clang"|"borlandcpp"|"golang"` is the
  `CompilerOpinion` refinement that `pe_opinion.rs` ports.
- **The language and the calling convention are XML** (`.ldefs`/`.pspec`/`.cspec`, + compiled `.sla`).

So: **a new container is code; a new calling convention is data.** This loader is code
(`loader/x32.rs`); High C support is a `.cspec` + a detection rule + FID databases, and is kept
out of here.

## What the container is

A 32-bit DOS program bound to the **FlashTek X-32 / X-32VM** extender. In-band tells (in the
real-mode stub): `DOS extender Copyright 1991-1994 by Doug Huffman`, `__X386_VM_DISABLED`,
`DGROUP relative address`. It carries **no LE/LX header**, so `le.rs` correctly refuses it
(`no LE header found`) and the default dispatch sees only the extender stub — a few functions of
real-mode loader, none of the 32-bit program.

**The container does not imply the compiler.** X-32 was a general-purpose extender that several
toolchains could link against. The loader must therefore not assume High C (or anything else);
it maps memory and hands the compiler question to the ordinary detection path. Both samples below
happen to carry High C runtime evidence, which is a fact about the samples, not about X-32.

## Layout (grounded on two independent samples)

Samples used for derivation — user-provided, not committed, referred to here only by hash:

| | size | sha256 (prefix) |
| --- | --- | --- |
| sample A | 325075 | `2e22dab11d4ae283…` |
| sample B | 98645 | `2278aa1a449e9904…` |

| Region | How it is located | sample A | sample B |
| --- | --- | --- | --- |
| extender stub | `file[0 .. inner MZ)` | `0x53d` B | `0x53d` B (byte-identical) |
| inner MZ | first `MZ` at offset > 0 whose `e_cp`/`e_cblp` image closes exactly to EOF | `@0x53d`, hdr 160 B, 32 relocs, `cs:ip=0074:0000` | same |
| inner image | `inner + e_cparhdr*16` | `@0x5dd` | `@0x5dd` |
| **32-bit image start** | **`u16` at `image+0x00`, in paragraphs** | `0x6b9` → `image+0x6b90` (file `0x716d`) | `0x431` → `image+0x4310` (file `0x48ed`) |
| descriptor table | `image+0x18`, byte size = `u16` at `image+0x02` | `0x118` (35 × 8 B) | same |
| 16-bit X-32 runtime | `image[0 .. 32-bit image start)` | `0x6b90` B | `0x4310` B |
| **32-bit flat image** | `[32-bit image start .. EOF)`, mapped at flat **base 0** | `0x48466` B | `0x13868` B |
| **32-bit entry** | `imm32` of the transfer idiom (below) | `0xd` | `0xd` |
| memsz / end-of-BSS | `u32` at `image+0x12c` (a flat address) | `0x48610` | `0x147e0` |

### Why base 0 is read, not assumed

The descriptor table at `image+0x18` is a real GDT/LDT image. Every descriptor has base 0, and
the 32-bit code descriptor (`ff ff 00 00 00 fb cf 00` — `G=1`, `D/B=1`, limit `0xfffff` pages)
is a flat 4 GB segment based at 0. So "flat base 0" is a **checkable property of the container**,
and the loader verifies it rather than hardcoding it: if a sample ever carries a non-zero
descriptor base, that is the base to use.

### The 32-bit entry point — parsed from the transfer idiom

The entry is *not* a header field. The last thing the 16-bit runtime does is fake a far return
into the 32-bit code selector:

```
2e 66 ff 36 <disp16>     pushl %cs:[disp16]     ; selector slot — filled at load time
66 68 <imm32>            pushl <imm32>          ; the 32-bit ENTRY offset
66 cb                    lretl
```

`lretl` pops EIP from the top of stack, so the **second** push is the entry; the first is the
selector (the slot is uninitialized in the file — samples A and B both hold the same `0x33002b`
garbage there — because the runtime allocates the selector via `int 31h` and stores it before the
return). Both samples yield entry `0xd`, which is exactly the byte after a 13-byte
NULL-code-pointer handler deliberately placed at flat 0, and it disassembles as real startup:

```
   d: 8c db                mov  %ds,%ebx
   f: b9 73 37 02 00       mov  $0x23773,%ecx     ; per-program flat address
  14: 66 b8 05 35          mov  $0x3505,%ax
  18: cd 21                int  $0x21             ; DOS get-interrupt-vector
```

**Do not hardcode `0xd`, and do not hardcode the slot offset.** Both samples happen to put the
entry slot at `32-bit image start - 0x3bb8`, which is an artefact of one runtime build being
end-aligned in the 16-bit region — exactly the kind of constant that breaks on the next sample.
Parse the idiom; if it is absent, **refuse to load** rather than guess an entry.

### No fixups for the 32-bit image

The inner MZ's relocation table covers only the real-mode portion: every relocation's segment
lies strictly below the 32-bit image start (sample A `0x000..0x6ad` < `0x6b9`; sample B
`0x000..0x425` < `0x431`). The 32-bit code references absolute flat addresses directly. So the
loader applies **no** fixups — and that is a load-time **invariant to assert**, not an assumption:
a relocation at or above the 32-bit image start means the format understanding is wrong.

This is the one real difference from `le.rs`, whose whole switch-table story was the fixup pass.
Here `relocation_table` stays empty and `set_relocatable` stays false.

## Design

### 1. `loader/x32.rs`, mirroring `loader/le.rs`

Same three-function shape, so the two read as siblings:

| `le.rs` | `x32.rs` |
| --- | --- |
| `is_le_header(data, off) -> bool` | `is_x32_image(data) -> bool` — inner MZ + paragraph field + descriptor table + the idiom |
| `detect_le(data) -> Option<usize>` | `detect_x32(data) -> Option<X32Layout>` — the table above, or `None` |
| `load_le(data) -> Result<Program>` | `load_x32(data) -> Result<Program>` |

`load_x32` reuses, verbatim in shape, what `load_le` already does: `SpaceManager::standard()` +
a 4-byte `ram` space, `Memory::add_block`, `Program::new(.., "x86:LE:32:default", cspec, ..)`,
the compiler-opinion call, and the entry → `entry_points` + `symbol_table.add_with_primary` +
`function_manager.create_function` sequence. One block (`flat_text`, RWX, length = memsz, file
bytes zero-padded), because the container describes one flat segment — the same "no partial block"
treatment `le.rs` documents for its objects.

**Extract, don't duplicate:** `le.rs`'s private `u16le`/`u32le` move to a shared
`loader/read.rs` used by both (plus a `u8at`, and its own unit test). That is the only change to existing loader code.

### 2. Dispatch — the two-oracle policy, generalised once (agreed)

`load_container` keeps an X-32 file on the Ghidra-parity MZ path (unchanged behaviour, no golden
churn — the same reason `le.rs` is not wired in for a bound exe). On the opt-in side, instead of a
second bespoke entry point beside `analyze_le_file`:

```rust
pub fn analyze_native_file(path: &Path) -> Result<Program, AnalysisError>
```

walks a **registry of beyond-Ghidra container detectors** (LE, X-32, …), takes the first that
claims the file, and applies the shared `with_compiler_version` refinement. `analyze_le_file`
becomes a thin wrapper that forces the LE entry, so every existing test, caller and golden is
untouched. A third format then touches one list, not N call sites — and the eventual CLI gets one
`--native` flag with one warning path instead of one flag per format.

### 3. `paths.rs` + `docs/dependencies.md`

Add `x32_exe()` via the existing `user_binary` helper (`MOSURA_X32_EXE`, `$HOME`-relative
default), and a row in the user-provided-binaries table with size + sha256. Skip-if-absent, like
every other external. No absolute path and no product name anywhere in the tree.

## Tests — the loader is provable without any user-provided binary

The real samples are copyrighted and absent on a clean clone, so they can only ever be a
skip-if-absent extra. The gate that actually proves the loader is a **synthetic X-32 builder** in
test code — the positive-control discipline `over_decode --self-test` already sets here.

`build_x32(stub_len, sixteen_len, entry, payload, bss_end)` assembles a real container: a stub, an
inner MZ header whose image closes to EOF, the image header (paragraph field + descriptor table
with base-0 flat descriptors), a 16-bit region ending in the transfer idiom carrying `entry`, then
`payload` as the flat image.

Every gate runs over a **three-case matrix** — `(0x540, 0x6b90, entry 0xd)`, `(0x200, 0x4310,
entry 0x320)`, `(0x100, 0x1000, entry 0x2a)` — so a loader that hardcoded either constant both
real samples agree on (entry `0xd`, slot at `flat - 0x3bb8`) fails.

Gates, as implemented:

1. **Detection** — a built container is detected; the negative controls are not: a bare 16-bit MZ,
   a DOS/4GW-bound LE, an ELF, a PE, a truncated/garbage stub. (`is_le_header`'s discipline: a
   wrong detection is worse than none.)
2. **Layout** — one RWX block at 0, length `memsz`, file bytes present and zero tail; blocks and
   entry match what was built.
3. **Entry** — equals the planted `entry`, with the `entry` symbol + function. Parameterised over
   **at least two `entry` values and two `sixteen_bit_len`s**, so a hardcoded `0xd` or a hardcoded
   slot delta fails the test.
4. **Analysis** — plant a small call graph in `payload` (entry calls two functions, one reached
   only through a second call) and assert auto-analysis discovers them: the loader is only useful
   if the pipeline runs over what it maps.
5. **Refusal** — paragraph field past EOF, missing transfer idiom, and a relocation at or above the
   32-bit image start each produce `LoadError`, not a garbage map.
6. **Default dispatch unchanged** — `loader::load` on an X-32 file still yields
   `x86:LE:16:Real Mode`, i.e. the Ghidra-parity stub view. This is the gate that keeps the
   two-oracle policy honest: the native view must stay opt-in.
7. **Registry routing** — `native_loader_name` returns `X-32` for a built container and `None`
   for a plain DOS MZ (which the default dispatch owns).
8. **Real-binary extra (skip-if-absent)** — `MOSURA_X32_EXE`: the derived layout, >100 functions
   recovered, the entry inside mapped memory, and every recovered reference targeting mapped
   memory — the clean-subset invariants `le_war2_analysis` uses, since there is no Ghidra golden
   to diff.

## Open items

- **`image+0x12c` as memsz** has two-sample support and a plausible reading (sample A's value is
  exactly the end of the range its own startup `rep stosd`-clears). The loader therefore *sanity
  checks* it rather than trusting it — the value must be at least the file image size and within
  1 GB of the base — and silently falls back to the file image size when it is not. So a third
  sample with a different meaning for that field degrades to a file-sized map instead of a wrong
  one.
- **The transfer idiom is one runtime build's encoding.** Refusing to load when it is absent keeps
  that honest; a second runtime version extends the pattern set with its own evidence.
- **No Ghidra oracle**, by construction. The oracles here are the container's own metadata,
  agreement across two independent samples, and the synthetic fixtures.
