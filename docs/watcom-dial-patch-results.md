# The Watcom dial-patch experiment — results

Companion to [`watcom-dial-patch-experiment.md`](watcom-dial-patch-experiment.md) (the brief).
Baseline at handoff: **zc26 = 764 EXACT / WGSS 0.4801**, tree clean at `172b1aa`; this work runs
in worktree `/data/wt-dialpatch` on branch `dial-patch`, off `61378c0`.

Run by a separate agent (Opus 5), 2026-08-22, per §9 of the brief.

---

## 0. Pre-registration

Recorded **before** the corresponding measurement, per brief §6 ("pre-register the ceiling and the
specimens") and memory `experiment-discipline`.

### PR-1 — Dial A, table order (registered before any corpus run)

The brief's Dial A names `DoubleRegs[]` in `bld/cg/intel/386/c/386rgtbl.c` as the allocation-order
dial and asks for a patch that changes the *order*, not a wholesale disable.

- **Prediction A1.** If the shipped 10.x compilers all carry the same allocation-order table, the
  table-order leg of the interim-build hypothesis is dead on direct evidence and no table-order
  patch is justified as a hypothesis test.
- **Prediction A2.** A patch that swaps two entries of that table is only a valid *dial* if the
  table is not also the parameter-passing table. If it is, the patch is a wholesale change to the
  calling convention and, per §6, can support at most an invariance reading — it must be rejected
  as an instrument rather than run against the corpus.

### PR-2 — declaration-order ceiling (registered before the census below was run)

After the Dial-A reconnaissance produced the finding in §3, the follow-on question is how much
EXACT is reachable by changing the order in which locals are DECLARED in our emitted C.

- **Specimens.** The six strict regalloc-only SAME_SHAPE functions are the pass/fail set:
  `FUN_0005fb24`, `FUN_0002724c`, `FUN_0001798c`, `FUN_000464b4`, `FUN_0006a720`, `FUN_00073936`.
- **Prediction B1.** Of those six, the three with ≥2 permutable register temps and a clean
  two-register swap (`FUN_000464b4`, `FUN_0005fb24`, `FUN_0001798c`) have a byte-exact
  declaration order; `FUN_0002724c` (one local) and `FUN_00073936` (two-instruction function,
  uninitialised read) do not; `FUN_0006a720` is unknown.
  *(B1 was checked before the census and is reported in §3.3.)*
- **Prediction B2 — the ceiling.** Over the whole SAME_SHAPE ∩ regalloc candidate set restricted
  to functions with 2..4 permutable locals, I predict **15–35 %** of candidates have some
  byte-exact declaration order. Below 10 % would make the lever marginal; above 50 % would mean
  declaration order is the dominant residue in this class.
- **Prediction B3 — MISMATCH set.** Over `MISMATCH` functions carrying a regalloc class (which by
  construction also carry other classes), I predict **under 5 %** reachable, because the other
  classes are not addressed by reordering declarations.
- **What would falsify the finding.** If reordering declarations changed nothing anywhere, or if
  the exact orders found were not reproducible on a re-run, the mechanism claim in §3 is wrong.

### PR-3 — Dial B, scheduler (registered before any Dial-B patch)

- **Prediction C1.** `InsStallable`'s operand-class weights are small immediates in the compiled
  binary and can be changed without collateral effect on any other transform — i.e. Dial B, unlike
  Dial A's table, is a genuinely isolated dial.
- **Prediction C2.** If the subject's scheduler priority differs from 10.0a's by those weights, patching
  them should reorder the watsched holdout windows (`FUN_00073328`, `FUN_00019344`,
  `FUN_0004b750`'s 6th call site) toward the original. If the holdouts do not move, the operand
  weights are not the difference.
- **Screening gate, registered before any Dial-B patch is compiled.** Several one-byte weight
  variants are possible. To avoid "tune until something moves", they are screened at *probe*
  scale on a fixed specimen set and **at most one** earns a corpus round. The specimen set is the
  five pure adjacent-transposition functions, each SAME_SHAPE with exactly two divergence rows —
  `FUN_000249a0`, `FUN_0004b750`, `FUN_00068bca`, `FUN_0006b496`, `FUN_00073328` — plus
  `FUN_00019344` as an EXACT **control that must not break**.
  A variant earns a corpus round only if it **converts ≥3 of the 5** specimens to EXACT **and**
  leaves the control EXACT. If no variant clears that bar, the result is reported as a null and
  no corpus round is run.
- **Prediction C3.** I expect no variant to clear the bar. `FUN_00073328`'s transposed pair is
  `MOV EDX,[EBP+0xc]` / `MOV EAX,[EBP+0x8]` — two operands of the *same* class, so no operand
  weight can separate them; that pair falls through to the scheduler's last tie-break,
  `curr->ins->id > best->ins->id` (source order), which is ours, not the compiler's. If a single
  weight cannot even in principle move one of the five, the "operand weights" hypothesis cannot
  be the whole of pile-B member #11.

### PR-4 — Dial A, tie order (registered before the corpus run)

The live Dial-A hypothesis after the table-order leg died (§2) is the brief's own §4 "tie-order"
version. The located predicate is `GiveBestReg`'s equal-score test (`regalloc.c:855–861`,
10.0a file offset `0x59ea3`); the minimal order-changing edit is `JG` → `JGE`, which makes the
**last** entry of the register table win an equal-score tie instead of the first.

- **Prediction D1 (isolation).** The parameter-passing convention is unaffected: incoming
  arguments still arrive in EAX, EDX, EBX, ECX.
- **Prediction D2 (breadth).** Because `saves == best_saves` is the *common* case (most candidate
  registers score 0), this edit will not be a narrow tie flip — it will shift allocation toward
  the tail of the table across most functions, including allocating EBP as a general temp.
- **Prediction D3 (the discriminating test).**
  - *Under the interim-build/dial hypothesis* (the subject's compiler broke allocation ties the other
    way): the patched corpus should convert a substantial share of the regalloc residue, i.e.
    EXACT should RISE, and in particular the strict regalloc-only specimens should flip.
  - *Under the declaration-order model established in §3* (the tie is decided by the order the
    temps reach the allocator, which our C controls): the patch should convert essentially
    nothing and should destroy a large fraction of the existing 764 EXACT, because those 764 are
    exact under the stock first-wins rule.
  I predict the second: **EXACT falls sharply (I pre-register "below 300"), WGSS falls, and none
  of the six strict specimens converts.** If EXACT instead rises, the declaration-order model is
  wrong and the interim-build hypothesis is alive.
- **Interpretation limit, registered in advance.** Per brief §6, a change this broad can support
  only a directional/invariance reading. A large fall refutes "the subject's compiler broke ties
  last-wins"; it does **not** by itself prove no tie-break dial differs, only that this one, in
  this direction, is not it.

---

## 1. Where the register tables actually are in 10.0a

Method per brief §5: read the predicate out of OW 1.0.0 source, derive the *byte* shape, search
the binary, corroborate independently.

`hw_reg_set` on a 32-bit host is one `unsigned` — `cghwreg.h` defines `HW_1(x)` as empty unless
`HW_NEED_64`, which no Intel target sets, so the struct has only member `_0`, and
`HW_DEFINE_SIMPLE(r, p0, p1, …)` gives `r_0 = p0 + (p1 << 16)`. With the bit assignments in
`bld/cg/intel/h/cgi86reg.h` each table entry is therefore one little-endian u32:

| reg | value | bytes |
| --- | --- | --- |
| `HW_EAX` | `0x01000003` | `03 00 00 01` |
| `HW_EDX` | `0x080000c0` | `c0 00 00 08` |
| `HW_ECX` | `0x04000030` | `30 00 00 04` |
| `HW_EBX` | `0x0200000c` | `0c 00 00 02` |
| `HW_ESI` | `0x10000100` | `00 01 00 10` |
| `HW_EDI` | `0x20000200` | `00 02 00 20` |
| `HW_BP` | `0x00000400` | `00 04 00 00` |
| `HW_SP` | `0x00000800` | `00 08 00 00` |
| `HW_EMPTY` | `0` | `00 00 00 00` |

Searching `BINB/WCC386.EXE` (541,364 bytes, sha256 `c3666de9…`) for each OW 1.0.0 table's byte
signature finds **ten of them, at consecutive addresses, in source order**. All offsets in this
document are **file** offsets; the runtime address is `file − 0x2200` (§4.2 — this corrects
`.claude/memory/wcc386-disassembly-notes.md`, which said the two were equal):

```
0x7b790  Reg64Order      EAX,EBX,ESI,EDI,EDX,ECX,BP,SP
0x7b820  ByteRegs        AL,AH,DL,DH,BL,BH,CL,CH
0x7b844  WordOrSegReg    AX,DX,BX,CX,SI,DI,DS,ES,FS,GS,CS,SS
0x7b878  WordRegs        AX,DX,BX,CX,SI,DI
0x7b894  TwoByteRegs     AX,DX,BX,CX
0x7b8a8  SegRegs         DS,ES,FS,GS,CS,SS
0x7ba3c  ABCDRegs        EAX,EDX,EBX,ECX
0x7ba50  <the 4-byte allocation table>
0x7ba74  QuadReg         EDX+EAX, ECX+EBX, …
0x7bacc  ST0Reg / STIReg / STParmReg
```

Eight of those are distinctive whole-table signature matches at consecutive, source-ordered
addresses; the last row lumps three small FP tables whose 8-byte signatures are not distinctive on
their own (`ST0Reg`'s matches 61 places image-wide) and rests on contiguity with `QuadReg`. Eight
independent matches in source order settles the encoding beyond doubt.

(`BP` and `SP` are the names `cgi86reg.h` gives masks `0x400` and `0x800`; there is no separate
`HW_EBP`/`HW_ESP`. Where this document writes `EBP, ESP` it means those same two entries.)

### The table the campaign has been assuming is not 10.0a's table

The brief §4 states `DoubleRegs[] = { EAX, EDX, ECX, EBX, ESI, EDI, EBP, ESP }` — the OW 1.0.0
order — as "the register list a 4-byte temp draws from". **In 10.0a it is not.** The byte
signature for that order returns **zero hits** in the whole 541 KB image, while `ABCDRegs` ends
at `0x7ba50` and `QuadReg` begins at `0x7ba74`, leaving room for exactly one nine-entry table
between them. That table reads:

```
0x7ba50  EAX, EDX, EBX, ECX, ESI, EDI, BP, SP, EMPTY      <-- EBX BEFORE ECX
```

OW 1.0.0 has **two** tables there — `DoubleRegs` (EAX,EDX,**ECX,EBX**,…) for general temps and
`DoubleParmRegs` (EAX,EDX,**EBX,ECX**,…) for parameters. 10.0a has **one**, in the
`DoubleParmRegs` order, and it is the target of `RegSets[RL_DOUBLE]` *and* of `ParmSets[U4]`,
`ParmSets[I4]`, `ParmSets[FS]`, `Parm8087[U4]`, `Parm8087[I4]` (pointers at `0x7bb54`, `0x7bce4`,
`0x7bce8`, `0x7bcf4`, `0x7bd10`, `0x7bd14`).

**So for byte-exactness work the 10.0a allocation order for 4-byte values is
EAX, EDX, EBX, ECX, ESI, EDI, BP, SP.** Every model note that quotes the OW 1.0.0 `DoubleRegs`
order for 10.0a is wrong at positions 2 and 3.

### Dating the drift — the table order is invariant across the subject's whole era

The same signature scan run over every Watcom revision staged on this machine (a scan for *any*
run of E-register words terminated by `HW_EMPTY`, so it finds the table whatever its order):

| revision | offset | 4-byte allocation order |
| --- | --- | --- |
| 8.5a | `0x72ee0` | EAX, EDX, **EBX, ECX**, ESI, EDI, BP, SP |
| 9.5b | `0x96a24` | EAX, EDX, **EBX, ECX**, ESI, EDI, BP, SP |
| 10.0 beta | `0x76330` | EAX, EDX, **EBX, ECX**, ESI, EDI, BP, SP |
| **10.0a** | `0x7ba50` | EAX, EDX, **EBX, ECX**, ESI, EDI, BP, SP |
| 10.6 | `0x81e74` | EAX, EDX, **EBX, ECX**, ESI, EDI, BP, SP |
| 11.0 | `0x94ef4` + `0x94f18` | **two** tables: EAX,EDX,**ECX,EBX**,… *and* EAX,EDX,**EBX,ECX**,… |
| OW 1.0.0 (source) | — | `DoubleRegs` EAX,EDX,**ECX,EBX**,… + `DoubleParmRegs` EAX,EDX,**EBX,ECX**,… |

(7.0, 9.01 and 10.5's staged `WCC386.EXE` are loader stubs — the payload lives elsewhere — so
they return no table; they bracket nothing that 8.5a and 9.5b do not already bracket.)

**The `DoubleRegs`/`DoubleParmRegs` split, and with it the ECX-before-EBX general allocation
order, first appears in Watcom 11.0** — after the subject. Four shipped compilers spanning 1991–1995,
including the 10.0 beta and 10.0a themselves, carry one table in one order.

> **Conclusion (Dial A, table-order leg): REFUTED on direct binary evidence.**
> An "interim build with a different `DoubleRegs` order" would have to sit inside a window in
> which four consecutive shipped revisions did not move that table. The leg was previously
> *cancelled* on an inferential argument (near-symmetric substitution counts, brief §2 item 2);
> it is now refuted on measurement of the binaries themselves. This does not touch the
> *tie-order* version of Dial A, which §4 tests.

## 2. The table-order patch, built and then rejected as an instrument

For completeness the patch the brief asks for was written and validated:
`/data/dialpatch/patch_dialA_ebx_ecx.py` swaps entries 2 and 3 at `0x7ba58`/`0x7ba5c`
(`0c 00 00 02` ⇄ `30 00 00 04`), turning 10.0a's order into OW 1.0's `DoubleRegs` order.
Idempotent, asserts the whole nine-entry pre-image, applied to a copy at `/data/dialpatch/WATCOM`.

```
sha256  stock    c3666de94f6fa6800f452dae8acf45505ecdb62f0ade2cc27cc86c2d9e8e2b6b
sha256  patched  56762043161f21b7b044038671ad1a05a1d5d8852d85f76c824e0547a2e0ff19
```

**Isolation validation (brief §5.5) failed, and that is the result.** A four-argument probe
compiled stock and patched:

```
stock                      patched
  MOV ESI,EBX                MOV ESI,ECX
  MOV EDI,ECX                MOV EDI,EBX
  MOV [g],EAX                MOV [g],EAX
  MOV [g],EDX                MOV [g],EDX
  MOV [g],EBX                MOV [g],ECX      <- third argument now arrives in ECX
  MOV [g],ECX                MOV [g],EBX      <- fourth argument now arrives in EBX
```

The patched compiler passes the third and fourth register arguments in the opposite registers.
This is the static evidence of §1 confirmed dynamically: in 10.0a the allocation table **is** the
parameter table. Swapping two of its entries is therefore not a dial on allocation — it is a
change to the calling convention, i.e. exactly the "wholesale toggle tests a strawman" failure
brief §6 warns about. **No corpus run was made with it**, because the delta would have measured
the ABI change, not the tie-break.

This is the same class of error the no-fold experiment made once; catching it in the probe
battery rather than in the corpus numbers is what §5.5 is for.

## 3. What the clean Dial-A specimens actually are

Brief §8 names the pass/fail set: the functions whose *only* divergence class is regalloc. Read
off the zc26 measurement (`classes` column of `/data/be2/zc26-rec.tsv`), that set is exactly the
briefed one — **6 functions, 38 rows**, all SAME_SHAPE:

```
02458  0005fb24  regalloc=11   sim 0.784
00739  0002724c  regalloc=10   sim 0.655
00262  0001798c  regalloc=6    sim 0.700
01678  000464b4  regalloc=6    sim 0.846
02675  0006a720  regalloc=4    sim 0.789
02880  00073936  regalloc=1    sim 0.500
```

Dumping their divergence rows shows every one is a **pairwise role swap between two registers,
with no consistent direction** — `EBX`⇄`EDX` in `0001798c`, `DL`⇄`DH` in `000464b4`,
`ESI`⇄`EDI` in `0005fb24` (first-defined temp takes the *later* table entry) but `ESI`→`EDI` in
`0006a720` (the *earlier* one). A fixed table-order preference cannot produce both directions;
this is a tie *order* signature, as the brief's §4 note says.

### The finding: the tie is decided by DECLARATION order, and that is on our side of the fence

`FUN_000464b4` has two symmetric `unsigned char` temps. Its recovered C declares
`xVar2` then `xVar3`, and assigns `xVar2 = 0; xVar3 = 0;`. Four variants were compiled against
**stock** 10.0a:

| variant | declarations | assignments | verdict | rows |
| --- | --- | --- | --- | --- |
| baseline (zc26) | `xVar2, xVar3` | `xVar2=0; xVar3=0;` | SAME_SHAPE 0.846 | 6 |
| both swapped | `xVar3, xVar2` | `xVar3=0; xVar2=0;` | SAME_SHAPE 0.949 | 2 |
| **declarations only** | **`xVar3, xVar2`** | **`xVar2=0; xVar3=0;`** | **EXACT** | **0** |
| assignments only | `xVar2, xVar3` | `xVar3=0; xVar2=0;` | SAME_SHAPE 0.897 | 4 |

Swapping **only the declaration order** of two locals — not one statement touched, not one
character of the body changed — converts the function to byte-exact against the original.
The two axes are independent and do different things:

- **declaration order decides which physical register each temp gets** (the role swap);
- **statement order decides the emission order of the initialising instructions** (the two
  `XOR` positions), which is the scheduler, and is what
  `allocator-model-thread`'s "statement order changes scheduling, NOT roles — 464b4" already
  recorded.

Mechanism (the front-end link, marked "inferred" in an earlier revision of this document, has
since been traced through OW 1.0.0 source — see `docs/declorder-irorder-results.md` §1): local
declaration order sets the order the front end creates the auto symbols
(`cdecl2.c:623` appends to the symbol chain, `cgen2.c:1670` walks it forward, `makeaddr.c:590`
creates the `N_TEMP`), and **two prepends then cancel** — `AllocName` (`namelist.c:97`) puts
`Names[N_TEMP]` in reverse creation order, and `RoughSortTemps` (`dataflo.c:112-121`) walks that
list forward while `AddConflictNode` (`conflict.c:61`) prepends, restoring creation order. So
`ConfList` is in **declaration order, head = first declared**; that order is
the input permutation to `SortConflicts`' diminishing-gap sort, whose comparator is a strict `>`
on `savings` — so the order of an equal-`savings` run in the output is a deterministic function of
that input permutation (not a stable copy of it); `AssignConflicts` then walks the sorted list
head-to-tail and `GiveBestReg` (`regalloc.c:843–868`) walks `RegSets[tree->idx]` **in table
order**, taking the strict-max `CountRegMoves` score. On a score tie it keeps the **first** entry
unless the later candidate is already inside `GivenRegisters` and the incumbent is not — the
secondary preference whose own patch site is named in §6. So, absent that preference, the
conflict processed first takes the earlier table entry. The
front-end link (declaration order → symbol creation order) is inferred from the measurements
above rather than traced through 10.0a's own code.

This is not a new axis — `byte-exact-status.md` recorded "local declaration order steers Watcom's
register allocator" and `allocator-model-thread` carries it as *refuted on the 3320c probe only*,
with the note that "the first-use-order declaration axis proposed there was **never sized
corpus-wide — an open item**". §3.3 closes that open item.

### 3.1 Two specimens the record lists as UNRESOLVED are now converted

`allocator-model-thread`'s UNRESOLVED list contains "464b4 (DL/DH roles pinned to the wrong temp
under every probed variant)" and "5fb24 (ESI↔EDI on near-tied derived pointers)". Both convert:

| function | baseline | declaration order that is byte-exact | verdict |
| --- | --- | --- | --- |
| `FUN_000464b4` | SAME_SHAPE 0.846 | `uVar1, xVar3, xVar2` (also `xVar2,uVar1,xVar3`; `xVar2,xVar3,uVar1`) | **EXACT** |
| `FUN_0005fb24` | SAME_SHAPE 0.784 | `piVar2, iVar1` (a straight reversal) | **EXACT** |
| `FUN_0001798c` | SAME_SHAPE 0.700 | `iVar2, iVar1` (a straight reversal) | **EXACT** |

`FUN_0006a720` (3 locals, 6 permutations) is **not** reachable — best stays SAME_SHAPE 0.789;
`FUN_0002724c` has a single local, so the axis does not apply; `FUN_00073936` is the parked
`MOV [mem],DS` lost-source artifact.

Note what this does to the brief's own pass/fail design: §8 offered these six as the set a
correct Dial-A patch would convert "with zero collateral". Three of them convert with **no
compiler patch at all**, under stock 10.0a. They can no longer serve as evidence for a dial.

### 3.2 Prediction B1: held

Registered: the three with ≥2 permutable temps and a clean two-register swap would be reachable,
`FUN_0002724c` and `FUN_00073936` would not, `FUN_0006a720` unknown. Outcome exactly that.

### 3.3 The ceiling — the open item, sized

Method: for each candidate function, rewrite the local declaration block in every permutation
(freezing stack-resident locals, whose declaration order *is* their frame layout) and recompile
against stock 10.0a. Batched one permutation-round at a time so a round is one dosemu session.
This is fitted to the oracle and is therefore a **ceiling**, not a landable result: it bounds
what a perfect model-inverse emitter arm could win.

| candidate set | candidates | byte-exact order exists |
| --- | --- | --- |
| SAME_SHAPE ∩ regalloc, 2–4 movable locals | 12 | **3 (25 %)** |
| all SAME_SHAPE, 2–6 movable locals | 19 | **3 (16 %)** |
| MISMATCH ∩ regalloc, sim ≥ 0.85, 2–4 locals | 6 | **0** |
| MISMATCH ∩ regalloc, any sim, 2–4 locals (60-function even-stride sample) | 60 | **0** |

**Prediction B2 (15–35 %): held** — 25 % on the registered set. **Prediction B3 (< 5 % on
MISMATCH): held** — 0 of 60.

*Instrument defect, disclosed.* The freeze regex in the first run of the harness was
`Stack_|^local_|^in_|^unaff_|^extraout_`, which matches Ghidra's underscored stack names
(`auStack_98`) but **not** the corpus's second stack-local family (`iStack00000004`,
`pxStack0000000c` — 307 occurrences in zc26). Exactly one candidate across all four sets was
affected — `FUN_0006dd90`, in the 60-function MISMATCH sample — and it reached no EXACT under any
permutation, so the 12/3, 19/3, 6/0 and 60/0 results above stand as measured. The harness in
`held-patches/declorder_ceiling.py` now matches `Stack` without the underscore; §3.5 reports the
MISMATCH sample re-run under the corrected instrument, which lands on the same result.

Beyond the three conversions the axis also moves similarity without reaching EXACT: the
`FUN_0003320c`/`33254`/`3333c`/`33380`/`333c4` sibling family each go 0.500 → 0.727, and
`FUN_00047c6c` 0.485 → 0.749. Across the 60-function MISMATCH sample the total similarity gain
available is +0.327 spread over 4 functions.

**Sized honestly, the whole declaration-order axis is worth about +3 EXACT and a small WGSS
gain.** It is real, it is on our side of the fence, and it is small. It does not need a compiler
patch, and it is not a route to "tens of functions".

### 3.4 Reconciling with the existing FINDING in `byte-exact-status.md`

That section proposes two things this measurement settles.

- It proposes sizing the axis by *"emit with first-use-ordered declarations and diff the EXACT
  count"*, and describes printc's current order as "the decompiler's internal variable-numbering
  order — an artifact of SSA/merge processing". **printc already emits first-use order.**
  `printc.rs` pushes a local into `p.decls` the moment it is first named during body emission
  (`self.decls.push((n.clone(), declared, None))` in the local-naming path), and the final sort
  only moves *stack* locals — `(None, None) => Ordering::Equal` under a stable sort leaves
  register/temp locals in insertion order. The `iVarN` numbering follows the same walk, which is
  why the two descriptions look different but are the same order. So the cheap heuristic the
  finding proposes is already in place; there is no first-use arm left to build.
- The sizing done here is stronger than the one proposed: instead of diffing one heuristic order,
  it searches **every** permutation per function, so §3.3's numbers are an upper bound over all
  declaration orders, not the score of one candidate. The headroom above what printc already does
  is the +3 EXACT above.

The finding's own framing still holds and is worth keeping: the axis is semantics-preserving, the
compiler distinguishes it, and it is high-dimensional (n! orders) so an enumerate-and-measure arm
cannot cover it. What has changed is that the remaining prize is now measured rather than
estimated, and it is small.

---

### 3.5 The MISMATCH sample, re-run under the corrected instrument

Fixing the freeze regex changes the candidate list (`FUN_0006dd90` and its family are now frozen
rather than permuted), and because the 60-function sample is an even stride over that list, the
sample membership shifts. The re-run is therefore a *fresh* 60-function sample, not the same one
re-scored — which makes it an independent replication rather than a correction:

```
candidates: 60 functions with 2..4 movable locals, verdict in ['MISMATCH'],
            class filter = regalloc, sim floor = 0.0
=== CEILING: 0 of 60 candidate functions have a byte-exact declaration order ===
```

**0 of 60 again**, on a different 60 functions. Similarity gains: 7 of 60 functions move, total
+0.375 (pre-fix sample: 4 of 60, +0.327 — different members, so the two totals are not directly
comparable; both say the same thing, which is that the gains are small and thinly spread).
`FUN_0006dd90` is correctly absent from the corrected candidate set.

Prediction B3 (< 5 % of MISMATCH reachable) therefore holds on two independent samples.

## 4. Dial A, tie order — the patch that was actually justified, measured once

### 4.1 The source predicate

`GiveBestReg` (`bld/cg/c/regalloc.c:843–868`) walks `RegSets[tree->idx]` **in table order**,
scores each candidate with `CountRegMoves`, and replaces the incumbent on:

```c
                    if( ( saves > best_saves )
                     || ( saves == best_saves
                       && HW_Subset( GivenRegisters, reg )
                       && !HW_Subset( GivenRegisters, best ) ) ) {
                        best = reg;
                        best_saves = saves;
                    }
```

Strict `>`, so on a pure score tie the **first** (earliest table) entry wins. The minimal
order-changing edit — the brief's §4 "tie-order" dial, and the one the near-symmetric
substitution argument explicitly does *not* refute — is `>` → `>=`, making the **last** entry win.

### 4.2 The located site, with independent corroboration

At file offset `0x59ea3`, disassembled with mosura's own decoder (`examples/dumpraw`):

```
59e9c  MOV ECX,dword ptr [ESP]        ; best_saves
59e9f  MOV EDX,EAX
59ea1  CMP EAX,ECX                    ; saves vs best_saves
59ea3  JG  0x59ec8                    ; saves >  best_saves  -> take      <-- the patch site
59ea5  JNZ 0x59ecd                    ; saves != best_saves  -> skip
59ea7  MOV EDX,dword ptr [0x7f884]    ; GivenRegisters
59ead  AND EDX,ESI                    ;  & reg
59eaf  CMP EDX,ESI
59eb1  JNZ 0x59ecd                    ; !HW_Subset(Given,reg)  -> skip
59eb3  MOV EDX,dword ptr [0x7f884]    ; GivenRegisters  (SAME address, second time)
59eb9  AND EDX,EBP                    ;  & best
59ebb  CMP EDX,EBP
59ebd  SETNZ DL                       ; !HW_Subset(Given,best)
59ec0  AND EDX,0xff
59ec6  JZ  0x59ecd                    ; HW_Subset(Given,best) -> skip
59ec8  MOV EBP,ESI                    ; best = reg
59eca  MOV dword ptr [ESP],EAX        ; best_saves = saves
59ecd  CMP byte ptr [ESP + 0x1c],0x1  ; the loop's following  if( greed != TRUE )
```

Corroboration independent of the source reading: the *same* absolute address `0x7f884` is loaded
twice, matching the two `HW_Subset( GivenRegisters, … )` calls, and the join falls straight into
`regalloc.c:863`'s `greed != TRUE` test. There is no other site in the image with that shape.

**File↔address correction.** `.claude/memory/wcc386-disassembly-notes.md` records "Load base:
file offset == address" for this image. That is wrong for the code/rodata region by `0x2200`:
the four-byte allocation table sits at **file** `0x7ba50`, and the accessor at file `0x4052b` is
`MOV EAX,0x79850 ; RET`, while file `0x79850` holds unrelated encoding tables. Six pointer slots
(`RegSets[RL_DOUBLE]` and five `ParmSets`/`Parm8087` entries) all store `0x79850`. So
**VA = file − 0x2200** here. The earlier derivation matched string *file offsets* that happen to
appear as dwords; those dwords are pointers to different strings 0x2200 further on (the dword
`0x755dc` points at the `__GETDS`/`__EPI` symbol blob at file `0x777dc`, not at the `-of` help
text at file `0x755dc`). All patch offsets in this document are **file** offsets, verified by
disassembling the file at that offset, so they are unaffected.

### 4.3 The patch

`/data/dialpatch/patch_dialA_tieorder.py` — idempotent, asserts a four-byte pre-image window
(`39 c8 7f 23`, i.e. the `CMP` plus the jump, so a wrong file cannot be half-patched), copies the
target to `.stock` before writing, applied only to the copy at `/data/dialpatch/WATCOM`.

| file offset | before | after | effect |
| --- | --- | --- | --- |
| `0x59ea3` | `7f` (`JG rel8`) | `7d` (`JGE rel8`) | equal-score ties take the **later** table entry |

The `rel8` displacement `0x23` is unchanged, so nothing moves.

```
sha256  stock    c3666de94f6fa6800f452dae8acf45505ecdb62f0ade2cc27cc86c2d9e8e2b6b
sha256  patched  7934c9d2c8daf2b928da6ca39e66a2765a877b5d20c9e471c8a50fab5b94d4eb
```

### 4.4 Isolation battery (brief §5.5)

| probe | stock vs patched | reading |
| --- | --- | --- |
| four register arguments | incoming args still EAX, EDX, EBX, ECX; only the *temps* holding them move (ESI/EDI → EDI/EBP) | **Prediction D1 held** — the calling convention is untouched, so unlike the table-order patch this is a real allocation dial |
| single-temp function | temp moves EDX → EBP | **Prediction D2 held** — `saves == best_saves` is the common case, so the edit is broad, not a narrow tie flip; it shifts allocation toward the tail of the table and will hand out EBP |

D2 is the honest limit on this patch, registered before the run: it is a *directional* change of
a real dial, but a broad one, so per §6 it supports a directional/invariance reading only.

### 4.5 The corpus measurement

Same recovered tree as the baseline (`/data/be2/zc26/recovered`, byte-identical C — the sources
are identical *by construction*, so any movement is the compiler), `recover` flags, **separate
cache** `/data/be2/cache-dialA-tieorder`.

**Controls first**, because the recorded `zc26-rec.tsv` baseline was produced by a previous
session's binary. Two were run, and they rule out different things:

| control | cache | what it rules out | result |
| --- | --- | --- | --- |
| `zc26-stockcontrol-rec.tsv` | shared `/data/be2/cache` (100 % hits) | build / scoring drift | 0 flips |
| `zc26-stockfresh-rec.tsv` | fresh `/data/be2/cache-stockfresh`, all 2,797 units compiled | cache effects — every object was produced by a live stock `WCC386.EXE` invocation | 0 flips |

```
== zc26-rec.tsv -> zc26-stockfresh-rec.tsv
  flips: 0
  wgss:  0 functions moved, net +0.000
```

764 EXACT / WGSS 0.4801 in all three. The first control alone would have been weak — it is a
cache replay by construction, so a byte-identical result is what it produces whether or not the
compiler path works. The second re-exercises the compiler on every unit. Together they place the
movement below on the patched byte and nothing else: not the build, not the harness, not the
cache.

```
$ bash scripts/corpus-verdicts.sh /data/be2/zc26-rec.tsv /data/be2/zc26-dialA-tieorder-rec.tsv
== census: zc26 (stock 10.0a)              == census: zc26 + tie-order patch
  WGSS 0.4801                                WGSS 0.3156
      1 COMPILE_FAIL                             1 COMPILE_FAIL
    764 EXACT                                  432 EXACT
   1966 MISMATCH                              2270 MISMATCH
      1 SAME_CODE                                1 SAME_CODE
     65 SAME_SHAPE                              93 SAME_SHAPE
```

Flip census, 386 flips:

| direction | count |
| --- | --- |
| EXACT → MISMATCH | 270 |
| EXACT → SAME_SHAPE | 62 |
| SAME_SHAPE → MISMATCH | 44 |
| MISMATCH → SAME_SHAPE | 10 |
| **anything → EXACT** | **0** |

The six strict regalloc-only specimens under the patch: `FUN_0001798c` SAME_SHAPE 0.700 → 0.500,
`FUN_000464b4` 0.846 → MISMATCH 0.359, `FUN_0005fb24` 0.784 → MISMATCH 0.566, `FUN_0002724c`
0.655 → MISMATCH 0.379, `FUN_0006a720` 0.789 → MISMATCH 0.273, `FUN_00073936` 0.500 → MISMATCH
0.250. **None converted; all six got worse.**

### 4.6 Verdict against the pre-registration

- **D1 (isolation): held.** Calling convention unaffected.
- **D2 (breadth): held.** Broad, tail-of-table shift, EBP allocated as a temp.
- **D3 (direction): held decisively.** EXACT fell, WGSS fell, no specimen converted. The
  registered numeric threshold "below 300" was **not** met — EXACT landed at 432, not under 300.
  The direction was right and the magnitude estimate was too aggressive; recording that rather
  than rounding it into a win.

> **Conclusion (Dial A, tie-order leg): REFUTED, in this direction.**
> If the subject's compiler had broken equal-score register ties last-wins, the six clean specimens were
> the functions that should have converted. Not one did, and across 2,797 functions **not a
> single function anywhere gained EXACT**. Combined with §1 (the table order did not move across
> the whole era) and §3 (three of the six specimens convert with no compiler patch at all), the
> register-allocation dial is not where the subject residue lives.
>
> Registered limit, restated: this refutes *this* dial in *this* direction. It does not prove no
> allocation dial whatsoever differs — e.g. the `GivenRegisters`-reuse preference could have been
> absent in an earlier build, which is a narrower edit (`0x59ea5`, `75` → `EB`) and a separate
> hypothesis. It was not run: one well-justified patch per dial, measured once.

### 4.7 The pre-registered F2 co-move check — FAILED, and that refutes the unification

`byte-exact-families.md` recorded this before the experiment ran, and the brief (§2 item 3, §8)
makes it the double-confirmation for a positive Dial-A result:

> if the interim build's difference is result-register-assignment preference, patching the
> allocation dial toward the subject's preference should move F2's rows **together with** the
> `regalloc MOV>MOV` class. If the regalloc rows move and F2 does not (or vice versa), the
> unification is wrong.

F2's dial-patch-relevant half is the `selection MOV>LEA` signature (the `SHL>LEA` half was
already fixed by `-5r`). Counted over the full divergence tables, baseline (`zc26-div.tsv`,
regenerated with this build) against the tie-order patched run:

| class | baseline rows | patched rows | delta | base fns | patch fns |
| --- | --- | --- | --- | --- | --- |
| F2 `selection MOV>LEA` | 177 | 186 | **+9 (+5.1 %)** | 138 | 147 |
| `selection LEA>MOV` | 120 | 117 | −3 | 91 | 90 |
| `regalloc MOV>MOV` | 6,602 | 12,330 | **+5,728 (+86.8 %)** | 1,327 | 2,014 |
| `regalloc` (all) | 13,556 | 28,536 | +14,980 | 1,504 | 2,217 |
| all rows | 77,737 | 100,081 | +22,344 | 2,032 | 2,364 |

**The regalloc class nearly doubled; F2 did not move.** The +9 rows F2 gained are consistent with
ordinary cascade from functions that broke elsewhere, not with a response to the dial.

The prediction was written to be falsifiable in exactly this way, so it should be read at its
word: **F2 is not the same dial as the regalloc class, and the unification recorded in
`byte-exact-families.md` and `compiler-identity (subject-profile note)` is refuted.**

Registered limit: this is an *invariance* reading, and a sound one. The patch moved the
allocation dial hard — hard enough to double the regalloc class and destroy 332 EXACT functions.
F2 sat through that essentially unchanged. Whatever decides F2's `MOV>LEA` rows, it is not the
register-allocation tie-break. (It does **not** follow that F2 is recoverable — F2's own
disposition, "no ordinary C makes 10.0a emit the original's `ADD EDX,k ; MOV EAX,EDX`", is
untouched by this and stays open.)

### 4.8 A useful by-product: how much of our EXACT mass rides on the tie-break

432 of the 764 EXACT functions are byte-identical under **both** compilers, and no function
outside that set became EXACT. So **432 functions contain no allocation tie whose direction
matters, and 332 do** — those 332 are byte-exact today partly *because* 10.0a's first-wins rule
happens to agree with the original's. That is a blast-radius number for any future allocator
lever: it is the population a source-side reordering arm can help *or* break.

---

## 5. Dial B — the instruction scheduler

### 5.1 The priority chain, located whole

`ScheduleIns` (`inssched.c:766`) is a bottom-up list scheduler whose priority chain is, in order:
min `StallCost`; max `height`; the `INS_INDEX_ADJUST` + `DataDependant` special case; max
`stallable` (= `InsStallable`); `sequence == last_seq` (avoid `fxch`); and finally
`curr->ins->id > best->ins->id` — "choose the one that came last in the source order".

The whole chain is in the 10.0a binary at file `0x66143`–`0x661c4`, and maps one-to-one onto the
source (`dag->height` at +0x14, `dag->stallable` at +0x10 masked to a byte, `dag->ins` at +0x04,
`ins->sequence` at +0x3a, `ins->id` at +0x34). Each line below is labelled with the address of
its FIRST instruction, and elides intermediate loads:

```
66143  TEST ECX,ECX / JZ ... / CMP EAX,[EBP-0x1c] / JGE / JNZ  ; best == NULL || curr_cost < best_cost
6615a  MOV EAX,[EDI+0x14] / CMP EAX,[ECX+0x14] / JLE           ; curr->height > best->height
66169  MOV EAX,[EDI+0x4] / TEST byte [EAX+0x40],0x80 / CALL 0x659be
                                                               ; INS_INDEX_ADJUST + DataDependant
66180  MOV EAX,[EDI+0x10] / AND 0xff / CMP / JA                ; curr->stallable > best->stallable
66197  MOV EAX,[EDI+0x4] / MOV AX,[EAX+0x3a] / CMP AX,[EBP-0x4] ; sequence == last_seq
661b7  MOV EAX,[EAX+0x34] / CMP EAX,[EDX+0x34] / JLE           ; curr->ins->id > best->ins->id
661c2  MOV ECX,EDI                                             ; best = curr
```

`InsStallable` itself is at file `0x656d2`, also verified by disassembly. 10.0a strength-reduced
the shared `+3` into a loop-carried `LEA`, so the indexed-operand and indexed-result bonuses
share one immediate:

```
656f1  CMP CL,0x3 / JC 0x656ff / JBE 0x6570b     ; switch( op->n.class )
656f8  CMP CL,0x4 / JZ 0x65706                   ;   N_INDEXED
656ff  CMP CL,0x1 / JZ 0x6570f                   ;   N_MEMORY
65706  MOV EDX,[EBP-0x4]                         ; N_INDEXED : += 3
6570b  INC EDX / INC EDX                         ; N_REGISTER: += 2   <- weight site
6570f  INC EDX                                   ; N_MEMORY  : += 1   <- weight site
65714  LEA EDI,[EDX+0x3]                         ; the shared +3      <- weight site
```

The brief's claim that the weights are `N_INDEXED +3, N_REGISTER +2, N_MEMORY +1` is **correct**,
verified against both OW 1.0.0 source and the 10.0a machine code. **Prediction C1 held**: they
are small immediates, editable in place with no instruction changing length, and — unlike Dial
A's table — nothing else consumes them.

### 5.2 The specimen set

The five pure adjacent-transposition functions, each SAME_SHAPE with exactly two divergence rows
(`operand-form=2`), plus `FUN_00019344` as an EXACT control:

```
00643  000249a0  orig  MOV EAX,ESI  /  MOV EDX,0x19            ours: constant first
01873  0004b750  orig  MOV EAX,ECX  /  MOV EDX,0x2             ours: constant first
02654  00068bca  orig  MOV EDX,[EAX*4+0xa867c] / MOV EBX,[ESP+8]
02701  0006b496  orig  MOV EDX,[EAX+0x874]     / MOV EBX,[ESP+8]
02867  00073328  orig  MOV EDX,[EBP+0xc]       / MOV EAX,[EBP+8]
```

### 5.3 Screen: four operand-weight variants, all null

`/data/dialpatch/patch_dialB_weights.py`, each an in-place edit at `InsStallable`, each with its
own cache dir:

| variant | edit | specimens converted | control |
| --- | --- | --- | --- |
| `reg0` | `0x6570b` `42 42` → `90 90` (N_REGISTER 2→0) | **0 of 5** | EXACT held |
| `reg1` | `0x6570b` `42 42` → `42 90` (N_REGISTER 2→1) | **0 of 5** | EXACT held |
| `idx1` | `0x65716` `03` → `01` (N_INDEXED 3→1) | **0 of 5** | EXACT held |
| `idx5` | `0x65716` `03` → `05` (N_INDEXED 3→5) | **0 of 5** | EXACT held |

Every one of the five transposed pairs stayed transposed under every weight setting. The only
movement was collateral: `FUN_000249a0` picked up unrelated `extra`/`missing` rows under `reg0`
and `reg1`. **No variant cleared the pre-registered ≥3-of-5 bar, so no corpus round was run.**

### 5.4 Diagnostic: which key actually decides these pairs

A null on the weights leaves the question of which key does decide. Two further **diagnostic**
patches (explicitly not corpus candidates — they exist to answer "which key", not "is this the
original's setting"):

- `idorder` — `0x661bd` `7e` → `7d` (`JLE`→`JGE`): reverse the final source-order tie-break so
  the instruction that came **first** in source order wins.
- `reg0+idorder` — both together: remove the `stallable` separation *and* reverse the source key.

| patch | `000249a0` | `0004b750` | `00068bca` | `0006b496` | `00073328` | control `00019344` |
| --- | --- | --- | --- | --- | --- | --- |
| stock | SS 0.968 | SS 0.957 | SS 0.667 | SS 0.778 | SS 0.714 | **EXACT** |
| `idorder` | SS 0.935 | SS 0.915 | SS 0.667 | SS 0.778 | **EXACT** | broken → SS 0.930 |
| `reg0+idorder` | MM 0.887 | SS 0.745 | SS 0.667 | SS 0.778 | **EXACT** | broken → SS 0.930 |

Reading, and it is a clean partition of the class:

1. **Pairs whose two instructions have equal `stallable` are decided by the source-order key.**
   `FUN_00073328`'s pair is two `[EBP+disp]` loads — same operand class, so no weight can ever
   separate them — and it converts to **EXACT** the moment the `ins->id` tie-break is reversed.
   The same is true of the `XOR reg,reg` pairs in the control and the two constant loads in
   `FUN_0004b750`, which flip (and break) for the same reason. **Prediction C3's mechanism held
   exactly.** `ins->id` is assigned as the code generator builds instructions, so these orders
   are a function of the IR our C produces — not of a scheduler dial.
2. **Register-copy-vs-constant pairs are separated by `stallable` itself** — `MOV reg,reg` scores
   2 (one `N_REGISTER` operand), `MOV reg,const` scores 0 — and `stallable` sits *above* the
   source-order key in the chain. They move only when BOTH the separation is removed and the key
   is reversed: under `reg0` alone `FUN_0004b750`'s site A is still divergent, under `idorder`
   alone it is still divergent, and only under `reg0+idorder` does it flip. **Consequence: under
   stock weights no instruction-creation order can flip a register/constant pair**, because the
   scheduler decides them before it ever reaches the id key.
3. **Indexed-load-vs-stack-load pairs move under nothing.** `FUN_00068bca` and `FUN_0006b496` sit
   at 0.667/0.778 under all six compilers tried, including `reg0+idorder`. They are separated
   still earlier, by `StallCost` or `height`.

> **Correction, 2026-08-22 (later the same day).** An earlier revision of this section lumped
> register-copy-vs-constant pairs together with case 3 as "unmoved by the weights *and* unmoved by
> the source key … separated by `StallCost` or `height`". That was wrong on both counts, and the
> recorded divergence tables say so: `dialB-reg0-div.tsv` and `dialB-idorder-div.tsv` each still
> carry `0x4b767`, while `dialB-combo-div.tsv` does not. The mistake mattered — it is what led the
> follow-on handoff to treat the whole arg-setup class as instruction-creation order and therefore
> reachable from C. Only the equal-`stallable` subset is.

### 5.5 The finding that closes the class

`FUN_0004b750` under `reg0+idorder` went from 2 divergence rows to 12. Disassembling the
function's ORIGINAL bytes gives six `MOV EAX,ECX` / `MOV EDX,imm` argument-setup sites:

```
4b767  MOV EAX,ECX ; MOV EDX,0x2      <- register copy FIRST      (1 site)
4b77a  MOV EDX,0x2 ; MOV EAX,ECX      <- constant first
4b786  MOV EDX,0x1 ; MOV EAX,ECX      <- constant first
4b79c  MOV EDX,0x2 ; MOV EAX,ECX      <- constant first
4b7b2  MOV EDX,0x3 ; MOV EAX,ECX      <- constant first
4b7c8  MOV EDX,0x6 ; MOV EAX,ECX      <- constant first           (5 sites)
```

At **five** of the six sites the original emits the **constant first** — i.e. it follows stock
10.0a's rule exactly — and at the **sixth** (`0x4b767`) it emits the register copy first. Under
the combined patch `0x4b767` disappears from the divergences (fixed) and all five constant-first
sites appear (broken): it fixed the sixth and broke the other five.

(The 12 rows are 6 transposed pairs, not 6 argument-setup sites: five are the constant/register
pairs above, and the sixth is `0x4b758 MOV EBX,0x18` ⇄ `MOV EDX,0x87cd8`, a constant-vs-constant
pair — also equal-`stallable`, and also broken by `idorder` alone, which is why that variant
shows `operand-form=4` for this function.)

The two site shapes are identical. **No global setting of any scheduler dial can produce both
orders**, because a dial cannot distinguish them. This is brief §6's "a dial that can only be
all-on or all-off can match NEITHER mixed state", demonstrated on this class rather than argued.

> **Conclusion (Dial B): the operand weights are REFUTED, and the arg-setup MOV-pair class is
> reclassified out of compiler identity.**
> The weights are the brief's named Dial-B candidate and they are verified correct in 10.0a; no
> setting of them moves any specimen. The pairs that *can* be moved are moved by the **source
> order** key, which is downstream of our C. And the class contains a function where the original
> follows 10.0a's rule at five sites and deviates at one — which no dial can reproduce.
>
> Correction to the record: `allocator-model-thread` attributes this class to
> "`InsStallable`: register operand +2 → placed nearest the consumer". That attribution does not
> survive contact with the compiler — setting that weight to 0 or 1 leaves every pair where it
> was. Pile-B member #11 ("call-site MOV-pair placement") should not be counted as evidence for
> the interim build.
>
> What is *not* settled: whether our emitter can reach the required IR order. Earlier probes
> found no pragma/argument/temp shape that moves `FUN_00073328`'s pair, and that remains true —
> but the reason is now known to be IR-generation order, not scheduler policy, which is a
> narrower and more tractable target.

---

## 6. Where this leaves the interim-build hypothesis

The brief put the prior at "40 % to move EXACT by ≥30, 35 % to move it by <10, 25 % to move
nothing", and said either result would be decisive. The outcome is the third, with a mechanism:

| leg of the hypothesis | status after this run | evidence |
| --- | --- | --- |
| **LEA fold** | already reclassified before this run | `watcom-nofold-patch.md` |
| **`DoubleRegs` allocation order** | **REFUTED** | the order is identical in 8.5a, 9.5b, 10.0 beta, 10.0a and 10.6; the split that introduces the other order first appears in 11.0 (§1) |
| **allocation tie-break** | **REFUTED in the tested direction** | one-byte `JG`→`JGE`: 764 → 432 EXACT, WGSS 0.4801 → 0.3156, **zero** functions gained EXACT, all six clean specimens got worse (§4) |
| **load scheduling / scheduler priority** | **operand weights refuted; class reclassified** | four weight variants move nothing; the movable pairs move on the *source-order* key; one function follows 10.0a's rule at 5 of 6 identical sites (§5) |
| **F2 unified with the regalloc dial** | **REFUTED** — the pre-registered co-move check failed | the regalloc `MOV>MOV` class grew +86.8 % under the patch while F2's `MOV>LEA` rows moved +5.1 % (§4.7) |
| **callee-save policy** | untouched — not tested here | — |

Four of the six legs are now closed, and every leg tested in this run closed *against* the
hypothesis — on direct measurement rather than on inference. The register-allocation dial in particular is not
where the subject residue lives: its cleanest specimens convert with **no compiler patch at all**,
by reordering local declarations in our own emitted C (§3).

**The single most useful correction for anyone continuing:** 10.0a's 4-byte allocation order is
`EAX, EDX, EBX, ECX, ESI, EDI, BP, SP`, not the OW 1.0 `DoubleRegs` order, and that table is
also the parameter table. Any model note or lever reasoning that quotes `ECX` before `EBX` for
10.0a is wrong at positions 2 and 3.

### What is worth doing next, in order

1. **Nothing further with a patched compiler on Dial A.** It is closed. The remaining narrow
   variant (removing the `GivenRegisters`-reuse preference, `0x59ea5` `75`→`EB`) is a distinct
   hypothesis with no evidence behind it; opening it would be tuning, not testing.
2. **The declaration-order axis is real, sized, and small** (§3.3): about +3 EXACT plus a little
   WGSS. If it is built, it belongs in the recovered arm as a model-inverse — infer the original
   declaration order from the registers the original chose, the way `param_orders_from_evidence`
   infers declared parameter order from argument setup — not as a blind reordering, which §4.7
   shows would put 332 currently-EXACT functions at risk.
3. **The 332 number in §4.8 is the thing to remember before building any allocator lever**: that
   is how many of our EXACT functions are riding on a tie whose direction happens to agree.

## 7. Artifacts

Everything is under `/data/dialpatch` (scratch) and reproducible from this document.

| path | what |
| --- | --- |
| `stock/WCC386.EXE` | pristine 10.0a compiler, read-only, sha256 `c3666de9…` |
| `WATCOM/` | the working copy that gets patched; restored to stock, verified |
| `patch_dialA_ebx_ecx.py` | table-order patch (built, **rejected** in the isolation battery) |
| `patch_dialA_tieorder.py` | the measured Dial-A patch, `0x59ea3` `7f`→`7d` |
| `patch_dialB_weights.py` | the four `InsStallable` weight variants |
| `patch_dialB_idorder.py` | the source-order tie-break diagnostic, `0x661bd` `7e`→`7d` |
| `find_regtables.py`, `maptables.py`, `census_doubleregs.py`, `findrefs.py` | the binary-search instruments used in §1 |
| `permute.py`, `declorder_ceiling.py` | the declaration-order probe and the ceiling census |
| `f2_comove.py` | the pre-registered F2 co-move count (§4.7) |
| `/data/be2/zc26-div.tsv` | baseline divergence table, regenerated with this build (§4.7) |
| `/data/be2/zc26-dialA-tieorder-rec.tsv`, `…-div.tsv` | the Dial-A corpus measurement |
| `/data/be2/zc26-stockcontrol-rec.tsv`, `zc26-stockfresh-rec.tsv` | the two stock controls (§4.5) |
| `/data/dialpatch/dialB-*.tsv`, `dialB-screen.log` | the Dial-B screen and diagnostics (§5.3–5.5) |
| `/data/dialpatch/ceiling*/` and `ceiling-*.log` | the declaration-order ceiling censuses (§3.3) |
| `/data/be2/cache-dialA-tieorder`, `cache-dialB-*`, `cache-declorder`, `cache-stockfresh` | the separate caches, one per compiler |
| `/data/ow100-src` | Open Watcom 1.0.0 source, extracted from `/data/tools/watcom/open_watcom_1.0.0-src.zip` |

The reference install at `the RE tracker/tmp/watcom-experiments/watcom_10.0a/WATCOM` was never
written to; its sha256 is unchanged.
