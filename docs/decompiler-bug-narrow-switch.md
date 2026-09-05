# Decompiler bug (CLOSED): narrowed (`short`/`char`) switch jump table not recovered

> **STATUS: CLOSED.** Fixed by the faithful `Heritage::guardReturns` port (heritage.cc:1652), which
> retired `recover_return`'s hardcoded x86-64 `RAX:8`/`XMM0:8` return candidates in favour of
> candidates queried from the compiler spec. The `RAX:8` candidate was the cause: appended to every
> RETURN pre-heritage, on x86-32 it is an 8-byte read at register offset 0 spanning **EAX and ECX** —
> a range no instruction writes. It forced a spurious 8-byte heritage location whose batch
> read-normalization rewrote the narrow accesses to EAX, severing the guard's `SUBPIECE(x,0)` from
> the table index's `INT_AND`/`INT_ZEXT` of the same low bits. `JumpBasic` was never the problem.
> Verified causally: re-adding that single 8-byte read on top of the port reopens the gap.
>
> `sw_short` now recovers all 8 targets, and **all four** predicted the subject dispatch sites recover
> (see the table below). `tests/ground_truth_parity.rs::narrow_switch_recovery_gap` now asserts
> full recovery for both functions. The rest of this document is kept as the diagnosis record.

**Owner: decompiler track** (jump-table / JumpBasic recovery — `crates/mosura/src/decompile/`).
Surfaced by the subject binary native-LE analysis (`analysis_parity::le_subjects_analysis`) and reduced to a
self-compiled Open Watcom ground-truth per the `issues-become-source-tests (subject-profile note)` standing rule.
Classified **MIS-PORT / GAP**: mosura recovers a `switch(int)` jump table but NOT the same switch
on a narrowed sub-`int` value; **Ghidra recovers both** — confirmed on the exact reduced bytes via
the libdecomp oracle (`oracle/capture --c`).

## Symptom

A dense `switch` whose selector is a **narrowed** value — an 8- or 16-bit quantity that is
compared at its narrow width and then zero-extended to index the table — is left as a bare
unrecovered `BRANCHIND` (0 jump-table targets, 0 `COMPUTED_JUMP`). The identical switch on a
full 32-bit `int` recovers normally. The distinguishing instruction is the narrowing between the
bounds guard and the table index:

```
  cmp    AX, 7          ; guard compares the NARROW value (AX / AL)
  ja     default
  movzx  EAX, AX        ; <-- narrowing: table index = ZEXT(low 16)   (Watcom also emits AND EAX,0xffff / AND EAX,0xff)
  jmp    dword [EAX*4 + table]
```

Ghidra's `JumpBasic` ties the guard's compared variable (`SUBPIECE(x,0)`) to the widened table
index (`INT_ZEXT`/`INT_AND` of the same low bits) and bounds the table; mosura's recovery does
not connect them, so the switch variable is never bounded and no table is built.

## Repro (self-contained)

Binary: `oracle/ground-truth/narrowsw.watcom-x86-32` (committed, Open Watcom ELF32 i386).
Source `oracle/ground-truth/src/narrowsw.c`:

```c
int sw_int(int x)   { switch (x)            { case 0..7: return 11..18; default: return -1; } }
int sw_short(int xx){ short x=(short)xx; switch (x) { case 0..7: return 11..18; default: return -1; } }
```

| function   | switch var | dispatch `BRANCHIND` | mosura recovers | Ghidra recovers |
|------------|-----------|----------------------|-----------------|-----------------|
| `sw_int`   | 32-bit    | `0x0804812b`         | 8 targets ✅    | 8 targets       |
| `sw_short` | 16-bit    | `0x08048193`         | 0 → **8 ✅**    | 8 targets ✅    |

Pinned by `tests/ground_truth_parity.rs::narrow_switch_recovery_gap`, which now asserts full
recovery for both functions.

### mosura (gap)

`decompile_function` on `sw_short` @ `0x0804818a` returns a `Funcdata` whose `jump_tables()` is
empty; the analysis switch analyzer therefore emits no `COMPUTED_JUMP` and the case bodies are not
reached through the table.

### Ghidra (CORRECT — the reference), via `oracle/capture <ghidra> narrowsw_sw_short.xml --c`

```c
switch(*pxVar1) {
case 0: return 0xb;
...
case 7: return 0x58;
default: return 0xffffffff;
}
```

(Reproduce the fixture from the committed binary: the function bytes at `0x8048126` as the entry
`bytechunk` plus the table dwords at `0x8048106` as a `readonly` `bytechunk`, `arch="x86:LE:32:default:gcc"`.)

## Why it matters (the subject)

This one gap accounts for **4 of the 9** unrecovered the subject binary protected-mode dispatches
(`le_subjects_analysis`), all clean bounded jump tables whose tables are already correctly
fixup-relocated (verified: every entry is a valid in-image code address) — the miss is purely the
narrowed-selector recovery, not a loader/fixup problem and not the `CS:` segment prefix (this flat
ELF32 reproduces it without a prefix):

| the subject site  | selector           | guard / narrowing                    | cases | recovered now |
|------------|--------------------|--------------------------------------|-------|---------------|
| `0x0513a8` | `*(short*)`        | `cmp AX,7; ja; and EAX,0xffff`       | 8     | 8 ✅          |
| `0x058afb` | `(short)-3`        | `sub EAX,3; cmp AX,4; ja; and 0xffff`| 5     | 5 ✅          |
| `0x06af52` | `*(uchar*)`        | `cmp AL,9; ja; and EAX,0xff`         | 10    | 8             |
| `0x0199b7` | `(uchar)`          | `cmp CL,3; ja; xor EAX,EAX; mov AL,CL`| 4    | 4 ✅          |

All four recover after the fix (the subject recovered dispatch sites 8 → 12); `0x06af52` recovers 8 of its
10 cases, so that one site keeps a residual worth a follow-up.

## Boundary / not in this bug

- The **loader is not implicated** — the subject tables read correct, fixup-relocated targets.
- **Unguarded** byte-dispatch tables (the subject `0x10b7e`, `0x7b973`, `0x7b986`) are a separate, NON-gap:
  Ghidra also refuses them ("Could not recover jumptable ... Too many branches") — mosura == Ghidra.
- The two true `jmp eax` masked computed-gotos (the subject `0x797e4`, `0x7a9a4`, the decompressor decode
  loop) are a **different** function-specific gap: mosura recovers the isolated
  `and eax,0xf0; add eax,base; jmp eax` construct fine (verified minimal, incl. `SHRD`/`ROR`-fed
  and 16-slot), but fails it inside the nested decompressor where Ghidra recovers it. Not
  reducible to a C source construct (hand-written assembly); tracked separately, lower priority.
