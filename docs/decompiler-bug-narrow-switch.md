# Decompiler bug → decompiler agent: narrowed (`short`/`char`) switch jump table not recovered

**Owner: decompiler track** (jump-table / JumpBasic recovery — `crates/mosura/src/decompile/`).
Surfaced by the WAR2.EXE native-LE analysis (`analysis_parity::le_war2_analysis`) and reduced to a
self-compiled Open Watcom ground-truth per the `war2-issues-become-source-tests` standing rule.
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
| `sw_short` | 16-bit    | `0x08048193`         | **0 targets ❌**| 8 targets ✅    |

Pinned by `tests/ground_truth_parity.rs::narrow_switch_recovery_gap` (control stays recovered; the
gap is asserted still-open so the eventual fix trips the test).

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

## Why it matters (WAR2)

This one gap accounts for **4 of the 9** unrecovered WAR2.EXE protected-mode dispatches
(`le_war2_analysis`), all clean bounded jump tables whose tables are already correctly
fixup-relocated (verified: every entry is a valid in-image code address) — the miss is purely the
narrowed-selector recovery, not a loader/fixup problem and not the `CS:` segment prefix (this flat
ELF32 reproduces it without a prefix):

| WAR2 site  | selector           | guard / narrowing                    | cases |
|------------|--------------------|--------------------------------------|-------|
| `0x0513a8` | `*(short*)`        | `cmp AX,7; ja; and EAX,0xffff`       | 8     |
| `0x058afb` | `(short)-3`        | `sub EAX,3; cmp AX,4; ja; and 0xffff`| 5     |
| `0x06af52` | `*(uchar*)`        | `cmp AL,9; ja; and EAX,0xff`         | 10    |
| `0x0199b7` | `(uchar)`          | `cmp CL,3; ja; xor EAX,EAX; mov AL,CL`| 4    |

Fixing the narrowed-selector recovery should recover all four (and any future `switch` on a
`char`/`short`/`enum`).

## Boundary / not in this bug

- The **loader is not implicated** — the WAR2 tables read correct, fixup-relocated targets.
- **Unguarded** byte-dispatch tables (WAR2 `0x10b7e`, `0x7b973`, `0x7b986`) are a separate, NON-gap:
  Ghidra also refuses them ("Could not recover jumptable ... Too many branches") — mosura == Ghidra.
- The two true `jmp eax` masked computed-gotos (WAR2 `0x797e4`, `0x7a9a4`, the decompressor decode
  loop) are a **different** function-specific gap: mosura recovers the isolated
  `and eax,0xf0; add eax,base; jmp eax` construct fine (verified minimal, incl. `SHRD`/`ROR`-fed
  and 16-slot), but fails it inside the nested decompressor where Ghidra recovers it. Not
  reducible to a C source construct (hand-written assembly); tracked separately, lower priority.
