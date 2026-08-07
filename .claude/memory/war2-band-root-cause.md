---
name: war2-band-root-cause
description: "ANSWERED 2026-07-28: WAR2's 0-16% byte-match band is NOT the codegen/regalloc wall. Root cause = hardcoded x86-64 `RSP=0x20` in stackvars.rs, so stack recovery is INERT on x86:LE:32 (ESP=0x10). 0/1286 functions get a stack local; 98.3% emit `*(unassigned + -N)`. Decompiler-reachable, board task #7."
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-29T07:41:58.286Z
---

# WAR2's 0-16% byte-match band — root cause found (read-only study, task #5)

For weeks the band was labelled "codegen/regalloc". **That label was never a measurement** — it is
`compare.py`'s `cause_guess()` DEFAULT branch, emitted whenever no decompiler "smell" matches. The
assumption survived because a fallback string was read as a diagnosis.

## The root cause (empirically confirmed, not inferred)

`stackvars.rs:29` — `const RSP: u64 = 0x20; // x86-64 register RSP` — a hardcoded x86-64 register
offset where **Ghidra reads `<stackpointer register="ESP" space="ram"/>` from the cspec**. Duplicated
at `alias.rs:26` and `directwrite.rs:158`.

Ghidra's `ia.sinc` defines TWO register files:
- `@ifdef IA64`: `offset=0 size=8 [RAX RCX RDX RBX RSP RBP RSI RDI]` → RSP/ESP at **0x20**
- `@else` (what `x86:LE:32` uses): `offset=0 size=4 [EAX ECX EDX EBX ESP EBP ESI EDI]` → **ESP=0x10,
  EBP=0x14**, and 0x20 is past the GP block entirely.

So on WAR2 `recover_stack` seeds a register that does not exist, never propagates the stack pointer,
and creates **zero stack varnodes**. IR proof (`FUN_00034668`, prologue `55 89 e5`):
`u0x10015:4 = INT_ADD r0x10:4 #0xfffffffc:4` then `STORE #0x1:8 r0x10:4 r0x14:4` — r0x10=ESP,
r0x14=EBP, both untracked.

## Measured
- **0 of 1286** WAR2 functions recover a stack local — vs **24 of 62** x86-64 fixtures. Inert, not degraded.
- **1241/1286 (98.3%)** emit `*(<unassigned local> + -N)` where a frame slot belongs.
- Functions WITHOUT that shape average **13.4% match vs 3.7%** with it.
- 850/1286 (66%) originals have an EBP frame.

## Why it cannot be register allocation (the discriminator)
Band: median 3%, p75 5%, p90 8%, max 75%. **Same-size candidates (cand within ±10% of orig, n=162)
average 4.6% — barely above the 3.7% of different-size ones.** Register permutation over an identical
instruction sequence would score far higher, so the sequences themselves differ. 31.2% of candidates
are <50% of the original's size (code missing), 3.9% >2x.

Per-function: **00376** (42%, same-size) matches instruction-for-instruction except the missing
`push ebp; mov ebp,esp`/`pop ebp` frame. **00027** (3%, median) stores through uninitialized `iVar1`
at -4/-8/-0xc (the spill slots) and lost a loop's table read entirely — not the original program.

## Verdict
The band is **decompiler-reachable**, not the compiler-matching wall. **Honest ceiling: fixing it will
NOT alone deliver byte-exactness** — the already-clean functions still sit at 13.4%. It removes the
structural blocker that makes the genuine codegen/regalloc question *unmeasurable*.

## ⭐ MEASURED OUTCOME of the fix (2026-07-29, state-asserted both sides)
The prediction above was RIGHT that the band is decompiler-reachable and RIGHT about the honest
ceiling. Landing the cspec stack pointer (+ its unblocker, see [[rule-indirect-collapse-unblocks-stackptr]])
**dents the band, it does not break it**:
- status: EXACT 1→1, **RELOC_EXACT 0→2**, MISMATCH 1214→1193, COMPILE_FAIL 71→90, DECOMPILE_FAIL 0→0
- paired band (1173 fns measurable in BOTH): mean 4.04→3.95%, **median 3→2%**, p75 5→5%, p90 9→8%,
  **p99 25→30%**, max 75→73%; buckets 16-31 36→45, 32-47 1→4, **48-63 0→6**
- per-function **improved 415, worsened 513, unchanged 245** — genuinely MIXED, not a clean win.
The tail opens (a 48-63% bucket appears from nothing; two functions reach RELOC_EXACT) while the
median slips. **Do not quote "0→240 stack locals, −38% emitted lines" as a byte-match win** — those
are IR-shape wins; the byte-match payoff is the tail, not the median.
The +19 COMPILE_FAIL is ONE fixable emitter defect, not diffuse rot: **18 × `spacebase * pVar10;`**,
mosura's `stack` spacebase pseudo-type leaking into printc as a C *type name* (types.rs:150, whose
comment "never declared in C output" is now false). Ghidra prints `BADSPACEBASE` there
(printc.cc:3387) precisely because it is a bug state, and avoids it at printc.cc:1057 by resolving the
stack *symbol* instead. Several existing classes improved (E1052 37→35, E1079 11→7, E1018 7→5).

## Follow-ons
- **Board task #7** = the fix: source the stack pointer from the cspec via the existing
  `analysis::cspec` plumbing (same route that retired `fspec::sysv_*`). x86-64 keeps 0x20, just
  spec-sourced ⇒ corpus must stay byte-identical; movement means the change is wrong.
- Secondary/harness: `compile.sh`'s frame-flag detection tests only prologue `558bec`, missing
  `5589e5` (the other encoding of `mov ebp,esp`) — 65 functions vs 39 get the wrong flags.

Related: [[war2-byte-exact-campaign]], [[adaptations-inventory]], [[faithful-type-of-wrong-ir]],
[[numbers-stale-unless-sha-stamped]].
