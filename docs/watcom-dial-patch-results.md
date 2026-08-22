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
- **Prediction C2.** If WAR2's scheduler priority differs from 10.0a's by those weights, patching
  them should reorder the watsched holdout windows (`FUN_00073328`, `FUN_00019344`,
  `FUN_0004b750`'s 6th call site) toward the original. If the holdouts do not move, the operand
  weights are not the difference.

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
  - *Under the interim-build/dial hypothesis* (WAR2's compiler broke allocation ties the other
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
  only a directional/invariance reading. A large fall refutes "WAR2's compiler broke ties
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

Searching `BINB/WCC386.EXE` (541,364 bytes, sha256 `c3666de9…`; this image loads at base 0, so
file offset == address — `.claude/memory/wcc386-disassembly-notes.md`) for each OW 1.0.0 table's
byte signature finds **ten of them, at consecutive addresses, in source order**:

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

Ten independent hits at consecutive, source-ordered addresses settles the encoding beyond doubt.

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
EAX, EDX, EBX, ECX, ESI, EDI, EBP, ESP.** Every model note that quotes the OW 1.0.0 `DoubleRegs`
order for 10.0a is wrong at positions 2 and 3.

### Dating the drift — the table order is invariant across WAR2's whole era

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
order, first appears in Watcom 11.0** — after WAR2. Four shipped compilers spanning 1991–1995,
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

Mechanism, stated as far as it is traced: local declaration order sets the order the front end
creates the auto symbols, which sets the order `AddConflictNode` creates conflict nodes
(`conflict.c:61–63`, a LIFO prepend, so `ConfList` is in reverse creation order); that order is
the input permutation to `SortConflicts`' shellsort, which is unstable and only swaps on strict
`>`, so it fixes the relative order *within* every equal-`savings` run; `AssignConflicts` then
walks the sorted list head-to-tail and `GiveBestReg` (`regalloc.c:843–868`) walks
`RegSets[tree->idx]` **in table order**, taking the strict-max `CountRegMoves` score and, on a
tie, the **first** entry. So the conflict processed first takes the earlier table entry. The
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

Beyond the three conversions the axis also moves similarity without reaching EXACT: the
`FUN_0003320c`/`33254`/`3333c`/`33380`/`333c4` sibling family each go 0.500 → 0.727, and
`FUN_00047c6c` 0.485 → 0.749. Across the 60-function MISMATCH sample the total similarity gain
available is +0.327 spread over 4 functions.

**Sized honestly, the whole declaration-order axis is worth about +3 EXACT and a small WGSS
gain.** It is real, it is on our side of the fence, and it is small. It does not need a compiler
patch, and it is not a route to "tens of functions".

---

*(§4 — the tie-order corpus measurement — follows when the run completes)*
