# Decompiler bug: a guarded store is hoisted out of its guard (WRONG CODE) — FIXED

**CLASSIFIED AGAINST GHIDRA AND FIXED (2026-08-17): a MIS-PORT in the print path.** Surfaced by
the FUN_0006c6f0 byte-exact hand-convergence (see
[`byte-exact-source-forms.md`](byte-exact-source-forms.md)).

## Classification and fix

Oracle run per the mandated forced-callee recipe (all eight callees created first,
`5ee67=EAX+EDX+EBX` forced): **Ghidra guards both specimens.** It renders the side-effecting
block INSIDE the short-circuit's second arm as a comma expression:

```c
if ((_DAT_000a8770[0xb] == 0) ||
   (iVar7 = _DAT_000a8770[0xb] + -1, _DAT_000a8770[0xb] = iVar7, iVar7 != 0)) {
```

mosura's IR and partition were CORRECT the whole time — the store sat in its own basic block
between the two CBRANCHes, the same graph Ghidra has (verified with `--raw` + `MOSURA_DEBUG=structure`
against the oracle's `DumpBlocks` fields). The defect was purely in printing, and the merge of
the two conditions was never the problem — Ghidra merges them too.

The mechanism, from `PrintC::emitBlockCondition` (printc.cc:2836-2869) and
`emitBlockBasic` (:2680-2720):

* the **statements pass** (`no_branch` arm, :2840-2845) descends into `getBlock(0)` ONLY — the
  left spine, which executes unconditionally — so only those statements print above the `if`;
* the **condition pass** emits block 0 under the incoming modifiers and block 1 with
  `setMod(comma_separate)` — "Notice comma_separate placed only on second block" — so a
  side-effecting second block prints as `(stmt, stmt, cond)` inside its paren, guarded by the
  short-circuit.

mosura had the whole `comma_separate` machinery ported (loop headers used it) but wired neither
half for `if` conditions: `emit_structured_body`'s CondAnd/CondOr arm emitted BOTH components'
statements above the test, and `render_cond_expr` rendered operand 1 under the inherited
modifier. Both fixed in `printc.rs` to Ghidra's contract. Both specimens now emit guarded code
— specimen 1 in exactly Ghidra's comma form, specimen 2 as nested `if`s (correct, and closer to
the original's block shape than Ghidra's rendering).

**Blast radius, measured (sb18 → sb19):** 219 functions' emitted C changed; every one was
MISMATCH or COMPILE_FAIL, **zero EXACT functions were affected, and zero verdicts moved in any
direction**. So no byte-exact function was ever silently wrong through this mechanism, and the
fix regressed nothing.

**The post-store re-read (wrong VALUE) — also classified and FIXED (2026-08-17).** Specimen 2's
condition re-read the just-stored slot and re-applied the `-1` (`slot + -1` computing `old-2`
where the machine computes `old-1`). Not the mergesnip gap this note first guessed: the site's
LOAD result is a plain unique with ONE consumer, and the defect was in the implied/explicit
classification — three unported pieces of Ghidra's `ActionMarkImplied`, now real:

* `checkImpliedCover`'s LOAD-vs-STORE and load/call-crossing arms (coreaction.cc:3384-3406) with
  faithful `isPossibleAlias`/`isPossibleAliasStep` (:3279/:3303) — a LOAD whose value would
  print past a possibly-aliasing STORE (or any call) must be explicit;
* `Cover::rebuild`'s extension through implied consumers (cover.cc:487) — the crossing test must
  see where the expression actually PRINTS, which is the consumers' use sites; with the
  `contain(op,2)` boundary exclusion that keeps `iRam = iRam + 1` legally inline;
* `ActionMarkImplied::apply`'s descendants-first traversal (coreaction.cc:3416) replacing
  mosura's flat per-varnode loops — the order is load-bearing, because the extended cover
  depends on the consumers' own just-made decisions.

The conservative mosura-only "multi-use LOADs are always explicit" stand-in retired with it.
mosura now emits Ghidra's exact semantics at the site: `iVar4 = slot; slot = iVar4 + -1;
if (iVar4 + -1 < 1)`. Corpus: EXACT 585 -> 592 (7 wins, 0 losses), 4 more MISMATCH ->
SAME_SHAPE, nothing regressed. With both fixes in, every defect this document filed is closed.

---

The original filing follows, kept for the record.

This is the most serious class in the campaign: the emitted C is not merely shaped differently
from the original, it **computes something different**. Every other finding from that session is
a byte-shape question; this one is a correctness question, and it is invisible to a reader — the
C looks entirely plausible.

## Symptom

The subject stores through a pointer only on the taken side of a test. mosura emits the store
**unconditionally, before the test**. When the guard is false, the recompiled program writes a
value the original never writes.

## Specimen 1 — `FUN_0006c6f0` @ `0x6c8e2` (WAR2.EXE)

Original, `p = piRam000a8770`, field `p[0xb]` at `0x2c`:

```
6c8e2:  mov  0x2c(%eax),%edx      ; edx = p[0xb]
6c8eb:  test %edx,%edx
6c8ed:  je   0x6c8f8              ; zero -> skip the store ENTIRELY
6c8ef:  mov  %edx,%ebx
6c8f1:  sub  %ebp,%ebx            ; ebx = edx - 1
6c8f3:  mov  %ebx,0x2c(%eax)      ; store, only reachable when edx != 0
6c8f6:  je   0x6c935
```

mosura emits:

```c
iVar4 = piRam000a8770[0xb];
iRam000a8764 = 1;
piRam000a8770[0xb] = iVar4 + -1;          /* <-- unconditional */
if ((iVar4 == 0) || (iVar4 != 1)) {
```

When `p[0xb] == 0` the original leaves the field at `0`; mosura writes `-1`. The field is a
struct member read elsewhere in the program, so this is an observable behavioural difference,
not a dead store.

Note also the emitted condition `(iVar4 == 0) || (iVar4 != 1)`, which reduces to `iVar4 != 1`.
That disjunction is the fingerprint of the two original branches (`je 0x6c8f8`, `je 0x6c935`)
being **merged into one condition** — and the store, which lived between them, was lifted above
the merged test. The merge is very likely the mechanism; the store is the damage.

## Specimen 2 — same function @ `0x6c7af` (the `0x155` loop)

```
6c7af:  cmp  0x558(%eax),%esi     ; p[i+0x156] vs -1
6c7b5:  je   0x6c80f              ; equal -> skip
6c7b7:  mov  0x658(%eax),%ebp     ; p[i+0x196]
6c7bd:  add  %esi,%ebp            ; += -1
6c7bf:  mov  %ebp,0x658(%eax)     ; store, guarded
6c7c5:  cmp  %ebp,%edi
6c7c7:  jl   0x6c80f
```

mosura emits:

```c
piRam000a8770[iRam000a874c + 0x196] = piRam000a8770[iRam000a874c + 0x196] + -1;   /* unconditional */
if ((piRam000a8770[iRam000a874c + 0x156] != -1) && (piRam000a8770[iRam000a874c + 0x196] + -1 < 1)) {
```

Same shape: `if (A) { store; if (B) … }` came out as `store; if (A && B) …`. The second specimen
also shows the read being repeated inside the condition rather than reusing the stored value,
which is how the `+ -1` ends up written twice.

## Why the byte comparison found it and review would not

Both sites are inside a 1,963-byte function among 39 locals; the C reads naturally. What exposed
them was the instruction-level alignment: the original's store sits *after* a conditional branch
and mosura's *before* it, so the aligner reported a `missing`/`extra` pair at a fixed offset that
did not move under any register-allocation change. Hand-writing the guarded form is what
collapsed those rows — which is also the confirmation that the guard, not the shape, was the
difference.

## Suggested first step (do this before writing any fix)

Ask the oracle whether Ghidra guards the store, using the WAR2 recipe — **callee first, then the
caller**, or every call defaults to no-parameters and the block structure changes underneath the
question (that trap is documented in the script header):

```
WAR2_MANIFEST=<manifest.tsv> GHIDRA_DIST=<dist> \
  scripts/ghidra-decompile-war2.sh 0006c6f0
```

If Ghidra guards it, this is a MIS-PORT with a specific suspect: whatever merges the two branch
conditions is running without checking that the block between them is free of side effects. If
Ghidra hoists it too, it is a shared limitation and the byte-exact campaign needs its own guard
rather than a port fix.

## Partial family fix that did NOT fix the filed specimens (2026-08-17)

Removing the five non-Ghidra post-fullloop dead-code sweeps (and giving `condnegate_pool` its
Ghidra-discipline `RuleEarlyRemoval`) un-hoisted the same emitted SHAPE in 14 other functions —
e.g. `FUN_00038a0c`, where `call; if (A && B)` became `if (A) { call; if (B) }` — worth +14
EXACT. Mechanism there: a late sweep emptied a block, the empty block was merged away, and the
structurer then saw one combined condition. **Both specimens above are unchanged**, so this
function's hoist is produced upstream of the late sweeps; classify against Ghidra before
hunting further (recipe below).

## Blast radius

Unknown and worth measuring before the fix, because the corpus sweep is cheap: the emitted
pattern is `<store>; if ((X) && (Y))` or `<store>; if ((X) || (Y))` where the store's target is
re-read inside the condition. A grep over an emit tree bounds the population, and any function
matching it is a candidate for silently wrong recompiled code — including functions currently
counted as byte-exact only because the divergent store happens not to change the bytes.
