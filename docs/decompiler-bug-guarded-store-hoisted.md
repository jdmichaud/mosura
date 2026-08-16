# Decompiler bug → decompiler agent: a guarded store is hoisted out of its guard (WRONG CODE)

**Owner: decompiler track.** Surfaced by the FUN_0006c6f0 byte-exact hand-convergence
(see [`byte-exact-source-forms.md`](byte-exact-source-forms.md)). **Not yet classified against
Ghidra** — the oracle comparison is the first thing the fix should do, and the recipe is at the
bottom.

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

## Blast radius

Unknown and worth measuring before the fix, because the corpus sweep is cheap: the emitted
pattern is `<store>; if ((X) && (Y))` or `<store>; if ((X) || (Y))` where the store's target is
re-read inside the condition. A grep over an emit tree bounds the population, and any function
matching it is a candidate for silently wrong recompiled code — including functions currently
counted as byte-exact only because the divergent store happens not to change the bytes.
