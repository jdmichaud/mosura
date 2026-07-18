# Decompiler bug report → main/decompiler agent: `resolve_call_output` OOB panic

**Owner: decompiler track (`master`).** Surfaced by the analysis track when rebasing
`analysis-port` onto `master @9dd2443`. This is a latent panic in the decompiler pipeline —
the analysis side has isolated it (per-function `catch_unwind` in the A6 bridge, faithful to
Ghidra's `DecompilerSwitchAnalyzer` error handling) so analysis is green, but the underlying
decompiler crash should be fixed at the source.

## Symptom

Decompiling GCC's CRT helper `deregister_tm_clones` / `register_tm_clones` (the
`__TMC_END__` transactional-memory-clones idiom, ending in `jmp *%rax` where `rax` is a
resolved constant) panics:

```
index out of bounds: the len is 1 but the index is 2
  panic_bounds_check
  resolve_call_output
  apply                 (src/decompile/action.rs:170)
  decompile             (src/decompile/pipeline.rs:765)
```

The panic site is `Funcdata::block` (`src/decompile/funcdata.rs:225`, `&self.blocks[id.0]`):
`resolve_call_output` indexes block **2** on a CFG that has only **1** block.

This did not panic on the analysis track's previous base (`4049e5d`); it appears after the
`master` decompiler evolution since then (the `resolve_call_output` / block-structure path).
The x86-64 decompiler datatest corpus does not include this function shape, so the decompiler
suite stays green — only the analysis bridge, which decompiles real ELF functions like the
CRT helpers, reaches it.

## Self-contained repro (no analysis harness)

`deregister_tm_clones`, `.text` @ `0x401080` in `oracle/analysis-corpus/basic.elf`
(`x86:LE:64:default`, `longMode=1`). Raw bytes:

```
b8 18 40 40 00 48 3d 18 40 40 00 74 13 b8 00 00 00 00 48 85 c0 74 09 bf 18 40 40 00 ff e0 66 90 c3
```

Disassembly:
```
401080  mov    eax, 0x404018
401085  cmp    rax, 0x404018
40108b  je     4010a0
40108d  mov    eax, 0x0
401092  test   rax, rax
401095  je     4010a0
401097  mov    edi, 0x404018
40109c  jmp    rax            ; resolved-constant indirect jump (the TMC idiom)
40109e  xchg   ax, ax
4010a0  ret
```

Feed these bytes through `raw_funcdata_flow_image` + `pipeline::decompile` at base `0x401080`
(same as `tests/jumptable_recovery.rs::tables`) to reproduce the panic directly.

## Likely area

`resolve_call_output` assumes ≥3 blocks (or a specific successor layout) that this
single-/few-block CFG doesn't have. It should bounds-check / handle the degenerate CFG the way
Ghidra does (Ghidra decompiles these CRT helpers without error; the `jmp rax` resolves and no
switch/extra block is required).

## Analysis-side mitigation already in place

`src/analysis/decompiler.rs::decompile_function` wraps `pipeline::decompile` in
`catch_unwind` and returns `None` on failure (logging the entry), so one function's decompiler
panic never aborts the analysis pass. This is faithful to Ghidra's `DecompilerSwitchAnalyzer`
(a per-function decompile failure is caught and logged, not fatal) and is worth **keeping** as
a safety net even after the root cause is fixed — but it is masking this crash, so the
decompiler fix is still wanted.
