---
name: corpus-windows-x64-fixtures
description: "3-4 corpus fixtures are Windows x64 ABI (not SysV); mosura has no Windows param model, so their interleaved param order is out of scope."
metadata: 
  node_type: memory
  type: project
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

The decompile corpus (Ghidra datatests, x86:LE:64) is **59 gcc/SysV + 3-4 Windows x64**.
The Windows fixtures (`arch="x86:LE:64:default:windows"`): **mixfloatint, modulo2,
injectoverride, statuscmp** (grep `windows"` in `ghidra/.../datatests/*.xml`).

KEY GOTCHA: Windows x64 binds args **position-by-position** (arg1->RCX/XMM0, arg2->RDX/XMM1,
arg3->R8/XMM2, arg4->R9/XMM3) via `<group>` tags that put one int reg + one XMM reg in the
SAME group — so the recovered param order **interleaves float/int in source order**
(mixfloatint oracle: `float8 param_1, int4 param_2, float8 param_3, int4 param_4, ...`).
This is NOT a SysV bug to chase — mosura's `fspec::sysv_input` is hardcoded SysV (gcc): float
regs XMM0..7 (groups 0-7), then RDI..R9 (8-13), then stack (14), `resource_start [0,8,15]`.
SysV recovery is group-ordered (all floats first), which is correct for the 59 gcc fixtures
(e.g. floatcast `float4 param_1, float4 param_2, int4 param_3, int4 param_4` — source declared
floats first). Reproducing the Windows interleave needs a **Windows x64 ParamList model with
`<group>`-interleaved float+int entries + arch-driven convention selection** — a separate,
unported subsystem, genuinely out of scope for SysV param work.

Established in Task #7 ([[direction-faithful-port]]). mixfloatint applying the SysV model
over-recovers (9 params) but the print-time used-backed filter keeps it regression-free.
