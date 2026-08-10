# Function-discovery backlog

Open items for mosura's function-discovery pipeline, as of 2026-08-06. Written down because this
track has produced several findings that are cheap to lose and expensive to re-derive.

**Standing scope rule (user, 2026-08-06):** *WAR2 is one example among many. mosura will be run
against all kinds of binaries, and we must be able to identify functions produced by **all Watcom
compilers under all options that affect function shape**. The test suite has to reflect that.* So
every item below is judged on whether it generalises, not on whether it moves the WAR2 number.

Current WAR2 state @ `be85c85` (the diagnostic, not the goal): **3018 functions; 2108 of the expert
tracker's 2120 = 99.4%; 12 genuinely missing; 3 entries inside a tracker body (unchanged).**

Previous state @ `556cdb3`: 2900 / 2078 / 42 missing / 3 inside. Both rows were measured with the
**same harness in the same session**, and the harness reproduced the `556cdb3` row to the digit
before the new row was believed — so the delta is a code change, not a scoring change.

### ⭐⭐ ROOT CAUSE FOUND 2026-08-06 — a COMMAND QUEUE modelled as a CHANGE CHANNEL

**`FunctionStartAnalyzer.java:835-859` raises no change notification.** It calls, on the per-program
**singleton** manager (`:949`):

```java
analysisManager.disassemble(doNowDisassembly);      // -> schedule(new DisassembleCommand(...), :1128)
analysisManager.createFunction(funcResult, false);  // -> schedule(new CreateFunctionCmd(...),  :1132)
```

`schedule` (`:860`) pushes onto the **command queue**. `codeDefined` (`:262-272`) is a *separate*
mechanism raised only when the listing actually changed, and Ghidra's comment at `:385` flags that
disassembly deliberately does **not** go through change events.

**mosura models both commands as change-channel notifications** (`sched.code_defined` /
`sched.function_defined`). ⚠️ **A command executes regardless of subscribers; a notification reaches
only analyzers registered in that manager.** `analysis/mod.rs:246` builds a *second* manager
(`fs_mgr`) holding only the four `FunctionStartAnalyzer`s + `PossibleDelayedFunctionCreator` —
**no `Disassembler`, no `FunctionCreator`.** Measured on `fnpattern`:

```
code_defined(08048120)  -> consumers=1, and it is "Function Start Search After Code" — no disassembler
function_defined(...)   -> consumers=0 — FunctionCreator, Constant Propagation, Decompiler Switch,
                                          External Jump Flow Override, Create Address Tables all miss it
```

**One substitution produces BOTH symptoms this track has been chasing separately:**

1. **The listing hole.** The request evaporates. WAR2 **374/3018 (12.4%)** undisassembled body ends;
   6 corpus functions with the *entire* body undisassembled; `retboundary` unable to fail; §9 #2/#3.
   `analyze()` is the single common driver, so `analyze_le_file` hits the identical hole.
2. **The infinite re-fire loop.** mosura fires `code_defined` on the **REQUEST**; Ghidra fires it on
   the **RESULT**. Requesting disassembly at bytes that never decode re-notifies the
   Instruction-typed `AfterCode` analyzer forever — the measured WAR2 loop. **So `SCHEDULED` and
   `PROPOSED` are accommodations for the wrong channel, not for any Ghidra behaviour.** They
   dissolve when the channel is corrected and do not need defending.

✅ **`SCHEDULED` (`function_start.rs:494`) is EXONERATED** — `08048120` measured passing through it;
its comment's claim is true as written. It was the lead hypothesis and it was wrong.

**`consumers=0` also means a pattern-discovered function's CALLEES are never discovered** — a
cascade, and the right shape to explain the 8 addresses Ghidra finds and mosura misses. ⚠️ Not yet
claimed for `0004de58`; that stays open until the fix exists and the oracle is re-run.

**Faithful target:** give `Scheduling` a command channel executing regardless of subscribers, matching
`AutoAnalysisManager.schedule(cmd, priority)`. Step 1 (bounded, gated on the six corpus addresses):
register `Disassembler` + `FunctionCreator` in `fs_mgr`. Collapsing the two-manager split is the real
retirement — Ghidra has one manager per program — but `analysis/mod.rs:239-245` documents a real
ordering constraint, so it is its own step.

### ⭐⭐ CAUSE B (independent of the above) — `r.min`-only range iteration DROPS ENTRIES

⚠️ **Not confined to pattern-discovered functions, and it broke the Cause-A framing.** Widening the
entry-coverage scan to the WHOLE corpus (not just the gcc-x86-64 + watcom-x86-32 columns) gives
**19 functions with the entire body uncovered**, not 6:

```
  5   Watcom pattern-discovered   fnpattern@08048120 retorphan@0804812c wprobe@08048666
                                  wprologue_sf@080485e3 wprobe@08048112
  1   noret.gcc-x86-64@00404000   block EXTERNAL, UNINITIALIZED, not in truth — Ghidra makes the
                                  same degenerate stub. Excluded on PRINCIPLE, not by exception.
 13   aarch64 / m68k              <not-in-truth>, no inbound refs, 4-12 byte bodies — the already
                                  carved-out spurious entries from unrecovered computed dispatches
                                  (`byte_pattern_carve_out` arm 2). Pre-existing recorded gap.
```

**`wprobe@08048112` = `p_leaf_` is CALL-REACHABLE**, which is what breaks the framing:

```
refs=["UNCONDITIONAL_CALL <- 0804856c [cu=true fn=Some(08048548)]"]
804856c:  e8 a1 fb ff ff    call 0x8048112     <- a plain direct call inside main_, decoded
```

A function reached by an ordinary `call`, from an instruction that **is** in the listing, has its
entire body undisassembled. So *"pattern-discovered functions are absent from the listing"* was too
narrow — it was this file's framing and the wider survey refuted it.

**The mechanism.** `wprobe`'s truth has three functions at three CONSECUTIVE addresses —
`08048110 sink_`, `08048111 __CHK`, `08048112 p_leaf_` — which coalesce into one `AddressSet` range:

```
[dbg-fncreate] TARGET 08048112 IS in the set; its range is 08048111..08048112;
               only r.min=08048111 will be processed -> dropped=true
```

`FunctionCreator::added` (`analyzers/mod.rs:310`) does `for r in set.ranges() { ... r.min ... }` and
`Disassembler::added` (`analyzers/mod.rs:160`) does `set.ranges().map(|r| r.min)`. **Both discard
every address in a range except the first.** Ghidra does neither:

- `CreateFunctionCmd.java:158` — `AddressIterator iter = origEntries.getAddresses(true);` — *every* address.
- `DisassembleCommand.java:235-266` — `while (!subRangeSet.isEmpty()) { Address nextAddr = subRangeSet.getMinAddress(); ... subRangeSet.delete(nextAddr, nextAddr); ... }` — it **DRAINS** each range one address at a time.

Taking the minimum once and dropping the rest is a mis-port, not a design choice. ⚠️ **Reach is wider
than Cause A**: any two requested addresses that are adjacent collapse, *and* a requested address
collapses into any already-notified decoded extent it abuts, since the Disassembler notifies its own
full `decoded` extent back into the same pending set.

**Two causes, one symptom — they must land as SEPARATE changes** or the WAR2 delta is unattributable.
Cause A accounts for the four pattern-discovered orphans; Cause B accounts for `p_leaf_`.

**Prediction on the record before either landed:** Cause B alone moves the listing figure (374/3018)
non-trivially and leaves the function COUNT roughly unchanged (it changes what gets *disassembled*,
not what gets *discovered*); Cause A alone moves the count upward *and* the listing figure.
**Falsifiers, named in advance:** B moving the count a lot, or A not moving it at all.

#### ✅ CAUSE B CLOSED for the three ANALYZERS — `3c4ca64` (gates, RED) + `3bb4f82` (fix)

`SharedReturnAnalyzer`, `DecompilerSwitchAnalyzer`, `ConstantPropagationAnalyzer`. (The
`Disassembler` / `FunctionCreator` half stays in `held-patches/listing-command-channel.patch`,
blocked on the fall-through override model — this landing does not touch it, so the two remain
separately attributable.) Suite 629 / 0 / 3 — 625 plus the four gates, ignored count unchanged.

**Reading Ghidra's source first changed what the fix is: only ONE of the three was the plain
widening this section anticipated.**

| analyzer | what Ghidra actually does | verdict |
|---|---|---|
| `SharedReturnAnalyzer` | `symbolTable.getSymbols(set, SymbolType.FUNCTION, true)` (SharedReturnAnalysisCmd.java:66, :80) — every function symbol in the set, ascending | the plain widening |
| `DecompilerSwitchAnalyzer` | `findLocations` (:237) walks the *instructions* in the set; `findFunctions` (:184) maps each through `getFunctionContaining` | widening **+ a missing guard**: `r.min` was handed to `decompile_function` as a function entry with no check that a function was there |
| `ConstantPropagationAnalyzer` | `findLocationsRemoveFunctionBodies` (:248) — three passes: every OVERLAPPING function's entry (bodies leave the set), then call-referenced destinations, and **only then** each remaining range's minimum | **not a widening at all**: mosura had implemented pass 3 alone, applied to the raw set |

⚠️ **`getFunctionsOverlapping` is a body query and mosura's bodies are EMPTY during analysis**
(`compute_function_bodies` runs after the worklist converges — `function_start.rs:1031`), so a
literal body-intersection test returns NOTHING. Pass 1 tests the entry point as well, which is
what Ghidra's always-populated body guarantees. This is the "same rule + same tool ≠ same answer"
trap in its purest form: the port was right and the *program state* was different.

**Two OPEN divergences this landing deliberately did not touch**, because either would make the
Cause-B delta unattributable:

1. **Both `ConstantPropagationAnalyzer` (:117) and `DecompilerSwitchAnalyzer` (:68) are
   `INSTRUCTION_ANALYZER`s in Ghidra**; mosura registers both as `Function` analyzers. So Ghidra
   feeds them the newly-decoded *extent* and derives function starts from it, while mosura feeds
   them function entries and each analyzer re-derives the extent (`ConstantPropagation` never had
   passes 1-2; `DecompilerSwitch` spans `[entry, next entry)` instead of reading the listing).
   Priorities differ too: Ghidra `REFERENCE_ANALYSIS.before()×4` and `CODE_ANALYSIS`, mosura
   `REFERENCE` and `REFERENCE.after()`.
2. **`analyzeSet` (ConstantPropagationAnalyzer.java:389) is unported** — the single-threaded slog
   over whatever `findLocations` leaves behind. It needs `flow_constants` to return its analyzed
   set (it returns only call destinations today), since the loop deletes each result from the todo
   set to terminate.

### ⭐ THE 12, ANSWERED BY THE GHIDRA ORACLE 2026-08-06 — 8 are a RECALL GAP, not a scope question

Asked Ghidra directly rather than reasoning about what it would do: `analyzeHeadless` whole-image on
`warcraft2-re/tmp/WAR2_reloc.elf`, **no `-processor`** (that flag forces cspec `windows` on an ELF
and costs 201 functions). Validity: `TOTAL 2145`, reproducing the recorded baseline exactly;
`COMPILER_SPEC gcc`, `LANGUAGE x86:LE:32:default` by auto-detect.

```
  0004de58  YES   <- every mosura guard arm PASSES and no function appears: a defect with no
                     remaining faithful explanation. Sharpest lead in the track.
  0004e19d  YES   <- REFUTES "declined faithfully; Ghidra declines them identically"
  00060270  YES      00064427  YES      00067f40  YES
  00070aa6  YES      00072f08  YES      00077619  YES
  ------------------------------------------------------------------------------
  000671a8   no   <- mosura and Ghidra AGREE
  00067204   no      0006734c   no
  00064bdb   no   <- the pointer table: TWO oracles agree, the TRACKER is wrong
```

**8 of the 12 are functions Ghidra finds and mosura does not — a straight recall gap against the
oracle, not a beyond-Ghidra scope question.** Earlier framing of the remaining gap as needing a
deliberate departure from Ghidra (with no oracle to check against) was wrong for two thirds of it.

**The four "matched but declined" split 1/3, so neither blanket claim made today was right.**
`0004e19d` is a real defect; `000671a8` / `00067204` / `0006734c` genuinely agree with Ghidra. The
honest statement is *"one was a defect, three agree"*. ⚠️ This is the
[[oracle-same-question-not-just-same-tool]] trap in its exact form: our rule is a faithful port, and
we inferred Ghidra's *answer* from it while Ghidra's **program state** differed. The rule being
faithful never implied the outcome would match.

`00064bdb` is now confirmed wrong in the tracker from two independent sides — mosura marks it
`DefinedData`, Ghidra creates no function, and its bytes are a dword pointer table.

**Consequence for priority:** the listing-population item is now backed by an **oracle disagreement
on 8 real addresses**, not only by six corpus fixtures.

### ⚠️ THE "THIRD FAMILY" CLAIM BELOW IS RETRACTED — corrected 2026-08-06, same day

**4 of the 7 already match the committed pattern file at offset 0.** The claim that this shape is
"not modelled at all" was derived from *my prologue shape classifier*, not from replaying the bytes
through `x86watcom_patterns.xml` with the real matcher. Replayed through `SequenceSearchState` — the
engine the analyzer actually uses — `0004e19d`, `000671a8`, `00067204` and `0006734c` all match
**family (3), the ESP-frame family**, whose 2/3/4-push variants (`0x5. 0x5. 100000.1 0xec ......00`)
cover `<push run> + sub esp` in *both* the `83` and `81` encodings because `100000.1` matches both.
That family is `x86gcc_patterns.xml`'s own, carried over verbatim, and its header comment already
says it exists for exactly this: *"Watcom's optimized codegen drops the frame pointer entirely and
addresses locals off ESP."*

**The no-frame family is therefore not missing, and it is already gated** — `retorphan`'s orphan
(`4665c2b`) is `56 57 55 83 ec 14`, this very shape, built with default flags and recovered.

So for those 4 the question is **not "what pattern do we add" but "why does a pattern that matches
at offset 0 produce no function"** — the candidates are all downstream of the match: `after="defined"`
(`checkAfterName`), `validcode="6"` (six valid fall-through instructions), or `applyActionToSet`
finding DefinedData. **A fourth family would leave all of that untouched and recover none of the 4.**

⚠️ **And that is a different defect class from the one triaged here.** If `after="defined"` or
`validcode="6"` is declining matched candidates, it is doing so *everywhere in the binary*, not just
at these 4 — so do not close the 12 on the assumption a pattern covers them, and treat the 900 as
possibly under-counted for the same reason.

Two further corrections to the table below:
- **`00072f08` DOES set up a frame.** `enter 0x1c,0` *is* `push ebp ; mov ebp,esp ; sub esp,0x1c` in
  one instruction. It is unmatched because no pattern mentions `c8`, not because it lacks a frame.
- **`00064427` is a one-byte push run** (`52`) plus an absolute load — it shares only the "no frame"
  property, and a pattern wide enough for it (`0x5.` + `8b 15`) is a much weaker anchor needing its
  own precision argument.

**The genuine unmodelled gap is 3 sub-shapes, not a family**: push-run + `mov r32,[esp+disp8]`
(stack-arg load, no `sub esp`), push + `mov r32,[abs32]`, and push-run + `enter`. All three are
reproducible on self-compiled code except `enter`, which no Open Watcom v2 build emits.

The methodological lesson is the same one A3 taught the same day: **a shape classifier tells you what
bytes look like; only the matcher tells you what the pattern file covers.** Replay through the
matcher before declaring a gap. See [[could-it-have-come-out-otherwise]].

### ~~⭐ THE 12, TRIAGED @ `be85c85` — a THIRD prologue family, and it is the DEFAULT one~~ (see retraction above)

Full per-entry dump (bytes, refs, containment) taken 2026-08-06. **7 of the 12 share one shape that
the pattern set does not model at all**: a callee-save push run followed by a stack adjust or a
stack-argument load, with **no frame setup** — no `89 e5`, no `8b ec`, no `push ebp`:

```
0004de58   56 57 55 8b 4c 24 10      push esi,edi,ebp ; mov ecx,[esp+0x10]
0004e19d   56 57 55 81 ec c0 02 00   push esi,edi,ebp ; sub esp,0x2c0
00064427   52 8b 15 84 90 08 00      push edx         ; mov edx,[0x89084]
000671a8   56 57 83 ec 10            push esi,edi     ; sub esp,0x10
00067204   51 56 57 83 ec 10         push ecx,esi,edi ; sub esp,0x10
0006734c   51 52 83 ec 10            push ecx,edx     ; sub esp,0x10
00072f08   51 52 c8 1c 00 00         push ecx,edx     ; enter 0x1c,0
```

Both families we DO model end in a frame setup: save-first is `<pushes> 89 e5`, frame-first is
`55 89 e5`. **This one never sets up a frame at all** — and that is not an exotic case, it is what
`wcc386` emits **by default**, since `-of+` is what turns the frame pointer ON. The
`QUESTION-for-warcraft2-re-agent.md` table recorded it a week ago without recognising it as a
family: *"Watcom 10.0a, default flags | no `55 89 e5` at all (frame pointer omitted)"*.

Under the standing scope rule this is the **highest-value remaining gap in the whole track**: it is
the default configuration of every Watcom compiler, so it is missing from every default-built
Watcom binary, not just from WAR2. WAR2 mostly hides it because WAR2 was built with `-of+`.

⚠️ **Precision is the whole difficulty and must be measured, not argued.** `51 52 83 ec 10` is a
weak anchor — a two-byte push run plus a common `sub esp` — where the modelled families get a
distinctive `89 e5` to key on. This one is only safe if the follow-on (`83 ec` / `81 ec` / `c8` /
a `[esp+N]` load) is part of the pattern, and only a **self-compiled** fixture can tell us the
false-positive rate, because precision is unmeasurable on WAR2 (§5).

**The other 5 are not one story:**
- `00064bdb` — the bytes are a **dword pointer table** (`a9 4c 06 00`, `b6 4c 06 00`, `17 4d 06 00`
  = `0x00064ca9`, `0x00064cb6`, `0x00064d17`), so the tracker's entry sits in switch-table data.
  Likely the same embedded-table shape as A3's `0006ecb4`.
- `00077619` — reached by a **ConditionalJump** and starts `3b 35 ... 73 3e` (`cmp`/`jae`); that is
  a branch target, not an entry.
- `00060270` (`fb 83 e4 fc 89 e3` — `sti ; and esp,~3 ; mov ebx,esp`) and `00067f40`
  (`53 56 57 06 9c fa 1e 07` — pushes then `push es ; pushf ; cli ; push ds ; pop es`) are
  real-mode/interrupt-flavoured startup code.
- `00070aa6` — a genuine 11-byte leaf (`call ; mov [abs],eax ; ret`), no inbound reference.

### The 900 mosura has that the tracker does not (@ `be85c85`)

```
save-first 779 · frame-first 101 · no-frame 11 · push-run-only 9      465 with NO inbound reference
```

86.6% save-first, against the tracker's own 84.6% of framed functions. ⚠️ Not comparable to the
earlier 872 as a set: this count is shift-tolerant on both sides and that one was not.

**That distribution argument is weak on its own and was never enough** — the pattern set keys on
prologue shape, so "the entries it finds have the expected prologue shapes" is close to circular,
and 465 of the 900 have no inbound reference at all.

### ⭐ INDEPENDENT CORROBORATION @ `be85c85` — they end like functions

So measure a property the pattern set does **not** key on: does the computed body end in a
**terminator** (`ret`/`retf`/`jmp rel`/`jmp indirect`)? Real functions do. An entry minted inside a
data table generally does not. Run it over both populations with the same code:

```
IN-TRACKER (expert-verified)   2111/2118 end in a terminator   99.7%   <- SUPERSEDED
NOT-IN-TRACKER (pattern-only)   899/900  end in a terminator   99.9%   <- SUPERSEDED
SUSPECT (no inbound ref AND no terminator):  1
```

**The pattern-only population is indistinguishable from the expert-verified one** — marginally
better, in fact. The single suspect is `0002ad98`, whose bytes are `56 55 89 e5 89 d6 89 ca` —
`push esi ; push ebp ; mov ebp,esp ; mov esi,edx ; mov ecx,edx`, a well-formed save-first prologue.

What makes this evidence and not another distribution argument is the **control**: the same measure
run over the 2118 functions an expert byte-matched establishes what "real" scores, so the number has
something to fail against. On its own, "99.9% end in a `ret`" would be nearly vacuous — most byte
runs reach a `c3` eventually. ⚠️ It corroborates that these are *functions*; it says nothing about
whether their **boundaries** are right, which is a separate measurement.

⚠️ Every number in this file is STALE unless stamped with a commit that is an ancestor of HEAD. A
WAR2 run is ~224s and only the lead runs it; do not quote an unstamped figure.

### ⭐ SCORE SHIFT-TOLERANTLY AGAINST THIS TRACKER — a naive entry comparison overstates the gap by 50

The expert tracker records **save-first functions at the `push ebp`, i.e. MID-PROLOGUE**, with the
callee-save run before it. That is the same `push ebp`-anchoring artifact
`warcraft2-re/analysis/function-boundary-correction.md` documents and corrected for 132 rows — and
50 further rows the correction pass missed. mosura sits at the TRUE entry, so an equality test on
entry addresses scores those 50 as misses when mosura is the more correct of the two:

```
mosura 0001380c [53 51 52 56 57 55 89 e5]   tracker 00013811   delta 5
mosura 000142e8 [53 51 52 55 89 e5 81 ec]   tracker 000142eb   delta 3
mosura 00017850 [53 51 56 57 55 89 e5 83]   tracker 00017854   delta 4
```

**A function counts as recovered when mosura has an entry within 1-7 bytes BEFORE the tracker's,
with a save-first run between them.** Scoring naively:

```
                                          naive   shift-tolerant
tracker functions                          2120            2120
  matched                                  2028            2078
  MISSING                                    92              42
```

The 50-function difference is not a code change — it is the same binary measured correctly. Any
figure in this file or in a report that predates 2026-08-06 and says "92 missing" is the naive
number. See [[war2-tracker-anchors-mid-prologue]].

---


## 1. Function bodies over-extend — ⛔ REFUTED 2026-08-06, NOT A DEFECT

**There was no over-extension.** The item existed because 51 tracker functions mosura "missed" all
lay inside a mosura body and none in open space — a distribution that looked diagnostic. It was an
artifact of the naive entry comparison described at the top of this file.

**The histogram that settled it** (lead, WAR2 @ `556cdb3`): of the 51, **44 had a single-byte push
immediately before them** — `57` push edi ×23, `52` push edx ×13, `56` push esi ×8 — and 7 had no
code unit ending there. A push is not a fall-through signature, which killed the "flow ran past the
end" reading. Reading the bytes instead:

```
bytes at tracker_entry-2:   56 57 | 55 89 e5 83 ec ...
                            ^^^^^   ^^^^^^^^ the tracker's recorded entry
```

The tracker's entry is at the `55`, mid-prologue. Testing for a mosura function slightly earlier:

```
"swallowed" missing entries                   51
  with a mosura function 1-7 bytes BEFORE     50   <- the SAME function, at its TRUE entry
  genuinely absent                             1
```

So mosura was not swallowing them — mosura was **right and the oracle was late**, and right
*because* of the save-first pattern family (§3, §4). The 51 do not exist as a defect; the real
gap is 42.

**What to take from it, beyond the number:**
- the naive comparison overstated the gap by 50 — the shift-tolerant rule at the top of this file
  is now the scoring method, and [[war2-tracker-anchors-mid-prologue]] carries it;
- "all 51 inside a body, zero in open space" felt like a mechanism fingerprint and was a
  measurement artifact. A distribution can be an artifact just as a count can;
- three separate mechanisms (no-return fall-through, opcode-vs-reftype, re-decode-vs-listing) were
  each consistent with that distribution. Consistency with the evidence is not the same as being
  the cause of it — see §9, where they now live on their own merits.

**Do not reopen without a fresh measurement.** The remaining 7 ("no code unit ends here") are a
thread into §6, not into this item.

## 2b. THE 42, SPLIT BY REPLAYING THEIR BYTES THROUGH THE PATTERN FILE (2026-08-06)

The lead's per-entry diagnostics (`war2-survey/analysis-gap/the38.tsv`) ruled out the two obvious
explanations for the shaped-but-missing entries: **0 of 33 lie inside a mosura function body**
(not the containment guard) and **0 of 33 are covered by another code unit** (not offcut), while
29 of 33 have an instruction decoded at exactly the right address.

That framed the question as "what *declines* them?". **Replaying each entry's bytes through the
real pattern file answers it differently, and splits the set in two** — no WAR2 run needed, the
bytes are in the TSV:

```
ANCHORED by the pattern file (mark at offset 0)   19
NOT ANCHORED                                       23
```

**⭐ 15 of the 33 "shaped" entries are NOT ANCHORED, and nothing declines them — no pattern
matches.** Every one is `55 89 e5` followed by ordinary code:

```
55 89 e5 31 c0    xor eax,eax     x3        55 89 e5 e8 ..    call            x4
55 89 e5 b8 ..    mov eax,imm32   x5        55 89 e5 80 3d    cmp byte ptr    x1
55 89 e5 66 c7    mov word ptr    x1        55 89 e5 8b 15    mov r,[abs32]   x1
```

These are **exactly the §2 residual** — the bare frame-first prologue that would need a naked
24-bit `0x5589e5`, which the lead RULED OUT on 2026-08-06 and which the unit test
`frame_first_family_covers_the_bare_prologue` pins. (`8b 15` is `mod=00`, so x86gcc #6's
`01...101` correctly does not match it; #6 wants `mov r,[ebp+disp8]`.) **So they are an owned
decision, not a defect**, and the "what declines them" question does not apply to them at all.

**⭐ The real shaped-but-declined set is 19, not 33** — 14 save-first, 4 saves+`sub esp`, and
`00074bdb`. For these the pattern DOES fire at offset 0 and no function is created, which is the
genuine open question.

⚠️ **`00074bdb` was misclassified as `frameless` by the diagnostics.** Its bytes are
`55 8b ec 53 56 57 8b 45` — frame-first in the **`8b ec`** encoding of `mov ebp,esp`, which Watcom
emits for 44 tracker functions. The classifier keyed on `89 e5` only. Worth fixing before the
shape counts are quoted again.

### The conditional-reference hypothesis is REFUTED, and the code names the surviving path

Ref dump on the 15 (lead, 2026-08-06): **not one carries a conditional reference.** 11 of 15 are
referenced only from data (`obj2_data` — function-pointer table members), 1 from a parameter, and
**3 have no inbound reference at all** (`0002a1f0`, `0002a274`, `0002a75c`). So
`PossibleDelayedFunctionCreator`'s drop rule (`function_start.rs:1058`) is not the veto, and the
hoped-for tie-back to over-decode via a spurious `jcc` is not there.

**The Data references are a red herring by construction.** In
`check_already_in_function_above_with` the reference loop does
`if t.is_data() && !matches!(t, Read | Write) { continue; }` — a plain `Data` ref is explicitly
*skipped*, never a veto. So the 11 data-referenced entries are in exactly the same position as the
3 with no references at all: **all 15 reach the same arm.**

**The surviving path, read from the code rather than guessed.** All 15 measure
`inside_mosura_fn=False` (so `function_containing(addr)` is `None`) and `cu_at_entry=True`. In
`check_already_in_function_above_with`:

- **if a function contains `addr-1`** → returns `function_containing(addr).is_some_and(…)` →
  `None` → **false** → the proposal is NOT vetoed, and something else must drop it;
- **if no function contains `addr-1`** → the fall-through arm (Ghidra `:512`) fires: *"an
  instruction that falls through into here makes this part of that flow, not a start"* → **true**
  → **the proposal is refused.**

That arm is a faithful port and is correct in general. It goes wrong only when the preceding
instruction **should not have fallen through**.

⭐ **And there is a known reason for exactly that on WAR2:** a `call` to a non-returning function
falls through, because `noreturn::analyze` **never runs on WAR2** — the LE loader names its blocks
`objN_text`/`objN_data`, so the analyzer returns early (`noreturn.rs:128-137`) and flags nothing.
That is the same inertness recorded at §9 divergence #1: the `falls_through` fix landed at
`0de3523` is correct and is **switched off on this target**. If the instruction ending at these
entries is a `call`, the chain is: no-return inert → decoder runs past the call → an instruction
ends exactly at the entry → `check_already_in_function_above` refuses the proposal → the function
is never created. **Hypothesis, not conclusion** — it needs the dump below.

### The decisive dump (needs WAR2 — lead), 3 columns per entry

For the 3 with no references first (no confounders), then the other 12:

1. **is there a mosura function containing `entry - 1`?** — this selects which arm runs, and the
   TSV's `host` column answers it for the entry, not for `entry-1`;
2. **does a mosura instruction END exactly at `entry`?** — the arm's literal condition;
3. **what is that instruction?** — specifically whether it is a `call` (`e8`/`ff /2`), which is
   what would tie this to the no-return inertness above.

If (1) is *no* and (2) is *yes*, the mechanism is settled. If (3) is a `call`, the fix already
exists and only needs `noreturn` to run on an LE image.

### Superseded: what to measure next (needs WAR2 — lead)

For the **19 anchored** addresses only, the two paths differ and the diagnostics should separate
them:

- the 14 save-first + `00074bdb` are `possiblefuncstart`, so they reach
  `PossibleDelayedFunctionCreator`, which drops a proposal with **any conditional reference to it**
  (`function_start.rs:1058`, Ghidra's own rule at `:1001`). **Inbound reference types for those 15
  addresses is the decisive dump** — a spurious `jcc` into the entry would veto it;
- the 4 `saves+sub` are family (3) `funcstart after="defined" validcode="6"`, and all four have
  **no code unit at the entry**, so they are gated by the pre-requisite plus
  `PseudoDisassembler::check_valid_subroutine` rather than by the delayed creator. Different
  mechanism, different fix.

Do **not** merge the two halves in one measurement; they fail differently by construction.

## 2. Bare frame-first prologue is unmatched (17 functions) — ✅ CLOSED `556cdb3`; residual RULED OUT

`55 89 e5` **without** a following `sub esp`. Our set inherited Ghidra's gcc anchors
(`0x5589e583ec`, `0x5589e581ec....0000`) which require it — but per the warcraft2-re census
**81% of framed WAR2 functions have no `sub esp`** (save-first 891 without / 426 with; frame-first
187 without / 52 with). Needs the precision guards in §3 to avoid over-matching, since bare
`55 89 e5` is a common 3-byte sequence.

**Landed:** this was not a missing *invention*, it was an incomplete *inheritance*. Ghidra ships
**six** frame-first patterns and this file had taken two — the two that require `sub esp`. The four
left behind (`0x5589e5..83ec`, `0x5589e5....83ec`, `0x5589e5 01010... 01010...`,
`0x5589e58b 01...101`) are exactly the bare shape. All six are now stated, in both `mov ebp,esp`
encodings, with #5 tightened to Watcom's save order (the saves *after* a frame setup obey the same
order as the ones before — measured on both `-of+` fixtures). 73 → 99 patterns. Gated by
`function_start.rs::frame_first_family_covers_the_bare_prologue`; fixture function sets unmoved.

**Still open, and deliberately:** a frame setup followed by ordinary code with no recognised filler
before it — `55 89 e5 40` (inc eax), `55 89 e5 e8` (call), both present in `wprologue`. Covering
those needs a naked 24-bit `0x5589e5`, which **no Ghidra x86 pattern file states**; every one of
Ghidra's frame-first patterns either adds discriminating bytes or is paired with the filler that
ends the previous function. The unit test pins the residual so adding one is a deliberate act.

**Measured on WAR2 @ `556cdb3` (lead, 224s):** the four completed patterns recover **2**, and cost
**nothing** in precision — exactly what restoring what Ghidra already ships and validated should
look like.

```
functions            2898 -> 2900   (+2)
missing vs tracker     94 -> 92
bare frame-first miss  17 -> 15
IN-BODY intrusions      3 -> 3      unchanged, identical depths [37,59,65]
not-in-tracker        872 -> 872    no new spurious
not-in-Ghidra         923 -> 923
```

**RULING (lead, 2026-08-06): do NOT add the naked `0x5589e5`. UPHELD after §1 was refuted.**

The ruling was first argued from a premise that turned out to be false — "51 of the 92 are behind
§1, so pattern work is the wrong order". §1 does not exist and the gap is 42, not 92, so that
argument is void. The ruling stands on the argument that never depended on it: no Ghidra x86
pattern file states a bare `0x5589e5` anywhere — every one of its frame-first patterns either adds
discriminating bytes or is paired with the filler ending the previous function — so writing one is
an invention, and the fixtures are far too small to bound the false-positive rate of a 3-byte match
on a 443 KB image. ~15 of the 42 are bare frame-first; that is the whole prize, against an
unmeasurable precision cost.

**Revisit only with a way to measure precision** — §5's matrix, not a WAR2 count (precision is
undecidable there: a hit in the tracker's 28.6% gap could be either). Leave
`frame_first_family_covers_the_bare_prologue`'s residual assertion exactly as it is — it is what
makes adding the naked pattern a deliberate act rather than a drift.

## 3. Tighten the pattern with two measured invariants (free precision) — ✅ LANDED

From warcraft2-re's census of 1317 save-first functions — both are zero-recall-cost:

- **The callee-save push order is rigid**: `ebx(53), ecx(51), edx(52), esi(56), edi(57)`.
  Subsequences allowed, reordering never — **1317 conforming, 0 nonconforming**. Watcom 10.0a
  under `-od` reproduces the same order independently.
- **The run never exceeds 5** (there are only five callee-saves besides EBP). A run of 6+ before
  `55 89 e5` is a false positive by construction.

Our current patterns accept any `0x50`–`0x57` run of length 1–5, so enforcing the order is strictly
tighter at no cost.

**Landed:** the save-first family is now the 31 non-empty ordered subsequences × the two `mov
ebp,esp` encodings (62 patterns), gated by
`function_start.rs::save_first_family_enforces_watcoms_push_order` — the ground-truth fixtures
cannot see this property, since `wprologue` and `fnpattern` are both `-of+`, i.e. frame-first.
A third independent confirmation of the order came free: Open Watcom v2's own saves in
`wprologue.watcom-x86-32` read `53 51 52 56`, `51 56 57`, `56 57`. Fixture function sets unmoved
(fnpattern 5, wprologue 15, lestruct 4).

## 4. Save-first regression fixture (closes a real gate gap) — ✅ LANDED `cd70db7`

`oracle/ground-truth/src/wprologue.c` gates recall 15/15 and precision 0-spurious — but only for
**frame-first**, because modern Open Watcom emits frame-first while WAR2 is save-first. The
save-first family currently has **no gate**.

Verified recipes (from warcraft2-re, and I reproduced Recipe A first try — it emits
`53 52 55 89 e5`, byte-identical to WAR2 `0x00010bd0`):

```
Recipe A  wcc386 -4r -fpi87 -s -onatx   (source uses alloca)   <- optimized, short-form sub esp
Recipe B  wcc386 -4r -fpi87 -s -od      (no alloca)            <- push runs 3-6 on demand
```

**The operative flag is `-of+`, and it must be REMOVED.** `-of`/`-of+` requests a *traceable* frame,
which forces `55 89 e5` to offset 0. A frame required for *addressing* (alloca, `-od`) is emitted
after the saves. With neither, the optimizer omits the frame pointer and EBP becomes a plain
callee-save — which is the "no `55 89 e5` at all" case.

Note: these reproduce the **shape**, not WAR2's provenance. 891 of WAR2's 1317 save-first functions
have no `sub esp`, so its frame was traceability-only, emitted after the saves — which 10.0a's
`GenProlog` (`bld/cg/intel/c/i86proc.c`) never does. That unresolved difference is warcraft2-re's
`cgflag:ecx-pre-frameptr-save` blocker (~1235 of their rows). A fixture gating the shape is all a
regression gate needs.

**Landed:** `wprologue_sf.watcom-x86-32` via `build_watcom wprologue_sf "-4r -fpi87 -od"` — Recipe
B, on the **native** OW2 toolchain, no dosemu. `src/wprologue_sf.c` is a one-line
`#include "wprologue.c"` so the twins cannot drift; all 15 inherited functions come out save-first,
run lengths 2..5, `p_leaf_` = `53 51 52 56 57 55 89 e5`. (Recipe A also works natively — OW's own
`#pragma aux __doalloca` from `bld/hdr/linux/h/malloc.h` supplies `alloca`, since the corpus
toolchain root has `binl/` only and no headers.)

Two things had to be fixed before the gate measured anything, **both of which apply to every §5
matrix cell**:
- the fixture needed an ORPHAN (`sf_orphan_fn_`, plus `sf_trail_fn_` called from the asm stub to
  keep it off the section edge). Without one, recall is vacuous: every function in `wprologue.c` is
  called from `main`, and it scored 15/15 recall + 0 spurious with the byte-pattern analyzers OFF;
- the fixture could not reach the Watcom pattern file at all — see §5.

Gate: `ground_truth_parity::watcom_save_first_shape_spec`. cspec=watcom 17/17 + 0 spurious ·
orphan gone with the byte-pattern search off · cspec=gcc misses the entry and marks it **+2**,
which is the prologue shift reproduced end to end on a self-compiled binary for the first time
(`src/fnpattern.c` property 1 records that as something this corpus "CANNOT" do).

## 5. ⭐ Generalise across the Watcom matrix (STANDING SCOPE RULE)

The pattern set is currently specified by one binary. It must cover the axes that actually change
prologue shape, and the corpus must gate each:

| axis | values | why it changes the shape |
| --- | --- | --- |
| **frame mode** | `-of+` / `-od` / neither | frame-first vs save-first vs frame-pointer-omitted — the §4 finding |
| **calling convention** | `-4r`/`-5r` (register, `__watcall`) vs `-4s`/`-5s` (stack, `__cdecl`) | register-based args change callee-save pressure, hence the push run; stack-based changes the whole entry |
| **stack checking** | default vs `-s` | **without `-s` Watcom emits a stack-probe call in the prologue** — a different entry shape entirely. WAR2 used `-s`; most binaries do not |
| **optimization** | `-od` / `-onat` / `-onatx` / `-ox` | frame-pointer omission, and whether saves are hoisted |
| **compiler version** | 9.0x, 10.0/10.0a, 10.5, 10.6, 11.0, OW 1.x, OW 2.0 | measured divergence already: OW2 emits frame-first where WAR2-era emits save-first |
| **target** | `-bt=dos/os2/linux/nt` | ⛔ MEASURED INERT — identical object bytes across all four; affects the runtime/format, not codegen (cell 5) |
| **FP model** | `-fpi87` / `-fpi` / `-fpc` | inline x87 vs emulated calls in the body |

**Tooling already exists for this** — no blocker:
- `scripts/setup-watcom-dosemu.sh <ver> --compile <file.c>` stages 10.0a/10.5/10.6/11.0 from the
  archives under `/data/tools/watcom` and compiles (verified: 10.0a, 10.6, 11.0 each reproduce
  their committed `<rev>.code` byte-identically).
- Native Open Watcom v2 at `/data/open-watcom-v2/bld/cc/386/linuxx64/binbuild/wcc386.exe`.
- `~/tools/open-watcom` is the `GT_WATCOM` root the ground-truth `build_watcom` column uses.

Suggested shape: a small prologue-spec source compiled across the matrix, each cell contributing a
fixture whose truth comes from the compiler (symbol table for ELF, linker map for LE/DOS), gating
**recall and precision per cell**. Cells that need dosemu can be committed as artifacts the way
`oracle/codegen-probes/watcom/<rev>.{obj,code}` already are, so CI never needs the historical
toolchain.

### ⭐ CELL 1 ✅ LANDED `a59a886` — stack checking (`-s` vs default): a NEW PROLOGUE SHIFT, 10 bytes

**This cell is the demonstrated case for the standing scope rule, not an assertion of it.** WAR2
could never have shown this defect: WAR2 was built with `-s`, and `-s` is not the default, so the
entire stack-probe family is invisible from that binary alone. The failure mode was also *wrong
address* rather than *missing* — the same class that motivated this whole pattern file — so it
silently produced wrong extents, which block byte-exact recompilation. That is exactly the user's
point that WAR2 is one example among many.

Measured on native OW2, 2026-08-06, **before writing any pattern** (the shapes, then the set).

**Without `-s` every framed function begins with a stack probe.** `wcc386` emits
`push <framesize>; call __CHK` — and where it sits depends on the frame mode:

```
-of+          55 89 e5  68 <imm32>  e8 <rel32>        frame, THEN probe
-od / -oc     68 <imm32>  e8 <rel32>  53 51 52 56 57  55 89 e5    <- probe FIRST, at offset 0
-onatx        (omitted for small frames — no probe at all)
```

**These functions are not invisible. They are found at the WRONG ADDRESS**, which is worse.
`p_frame_` at `08048366` under `-od`:

```
08048366  68 48 00 00 00   push 0x48        <- THE TRUE ENTRY
0804836b  e8 97 fd ff ff   call __CHK
08048370  53 51 52 56 57   push ebx/ecx/edx/esi/edi   <- our save-first family matches HERE, +10
08048375  55 89 e5         push ebp; mov ebp,esp
```

This is **the same defect that motivated this entire pattern file** — `x86gcc_patterns.xml`
anchoring at the `55`, five bytes late — reappearing one level up with the stack probe as the new
prefix. A wrong entry means a wrong extent, so it also blocks byte-exact recompilation (§1's
argument, which survives §1's refutation).

Not one of the file's 99 patterns starts with `0x68`, so nothing anchors the true entry today.

**Why WAR2 never showed this:** WAR2 was built with `-s`. **Most binaries are not** — `-s` is not
the default — so this is the clearest evidence yet for the standing scope rule.

**Proposed shape, NOT yet written** (precision hazard first): the naive anchor
`0x68 ........ 0xe8 ........` is `push imm32; call rel32`, which is an extremely common ordinary
code sequence — every cdecl call with one immediate argument. It must NOT be stated bare. Two
candidate forms, both to be measured:
- probe-first: `0x68 ........ 0xe8 ........` followed by a callee-save push or `0x55`, marking the
  `68` — 15 bytes with 8 wildcarded;
- frame-then-probe: `0x5589e5 0x68 ........ 0xe8 ........`, which is already strongly anchored.

The overlap rule then does the rest: with both the probe pattern (true entry) and the save-first
pattern (+10) matching, `create_functions` keeps the LOWEST — exactly how the save-first family
fixed the original shift.

**LANDED `a59a886`, SUITE-VERIFIED at `18dccdc` (622 passed / 0 failed, default parallelism)** — 8 patterns (99 → 107): two frame-then-probe forms, stated plainly because
`55 89 e5` ahead of the probe already anchors them, and six probe-first forms carrying
`after="defined"` + `validcode="6"` + `possiblefuncstart`. Gate:
`ground_truth_parity::watcom_stack_probe_shape_spec` — recall, precision, **that the anchor is the
probe and not the push run ten bytes in**, and attribution via the analyzer toggle. Measured under
`cspec=watcom` across every Watcom fixture: **zero spurious anywhere**; revert-checked, both +10
shifts return without the family.

⚠️ **Stamp cells suite-verified, not just gate-verified.** Cell 1 was landed and reported on its
own gate; the full suite was red for two commits before anyone noticed, because the break — a
process-global env race in the test harness, not the patterns — was invisible to the fast
per-fixture runs the cell work uses. Fixed at `18dccdc` (see `analysis::overrides`). The standing
practice from here is to checkpoint after **each** cell so the red window is one cell wide at
worst.

### What the trailing-push guard buys — measured, and the fixture cannot see it

The lead's condition before trusting the probe-first form. Raw byte scan for
`68 ?? ?? ?? ?? e8` and how many are followed by a callee-save/`ebp` push:

| binary | bytes | `68..e8` | +save | guard removes |
| --- | ---: | ---: | ---: | ---: |
| `wprobe.watcom-x86-32` | 4,492 | 15 | 15 | **0** |
| `mingw_hello32.exe` (gcc/mingw, cdecl) | 229,835 | 1 | 0 | **1** |
| every other x86-32 fixture | — | 0 | 0 | 0 |

- **On the fixture the guard buys nothing** — all 15 sequences are real stack probes and all 15
  pass it. That is the correct behaviour and it means **the fixture cannot demonstrate the guard's
  precision value**, only its zero recall cost.
- **On real-world code it removed 1 of 1**: mingw's single `push imm32; call rel32` is not
  followed by a save push, so the guard removed exactly the false positive it exists for.
- ⚠️ **Sample size 1.** And the reason is itself worth recording: **gcc/mingw passes arguments with
  `mov [esp+N]`, not `push`**, so gcc-compiled cdecl code barely produces this sequence at all. The
  codegen that would stress it is push-args — Watcom `-4s`/`-5s` or MSVC — **which the corpus does
  not contain**. Cell 2 is therefore the right place to stress this guard, not a WAR2 run.

**Standing caveat:** the probe-first form's false-positive rate is bounded by measurement on
`wprobe` and by a single real-world case. A WAR2 run would raise confidence; cell 2 would raise it
more, on a binary where precision is decidable.

**Build note for this cell:** `build_watcom` hardcodes `-s`, so a no-`-s` cell needs it moved into
the overridable options, and the link needs a `__CHK` stub in the `_cstart` asm — without one
`wlink` fails with `E2028: __CHK is an undefined reference`, which is itself the proof that the
axis changes code generation.

### ✅ CELL 2 CHECKED — calling convention (`-4s` stack vs `-4r` register): **NO NEW SHAPE, no fixture**

Measured 2026-08-06, then **deliberately not turned into a fixture** — the stop rule is that a cell
gets a fixture only if it exposes a shape we would otherwise miss, because a corpus that grows
without adding discriminating power is a maintenance cost dressed as coverage.

A `wcall` fixture was actually built (`wprologue.c` + orphan, `-4s`) and measured across all three
optimization settings, then deleted:

```
-4s -of+    17/17 recovered, 0 spurious      (16 with the byte-pattern search off)
-4s -od     17/17 recovered, 0 spurious      (16 with it off)
-4s -oc     17/17 recovered, 0 spurious      (16 with it off)
```

Full recall with **no new patterns**. The convention changes callee-save *pressure* — and so the
length of the push run — but not the *shape* of the entry, and the existing families already span
the lengths:

```
-4s -of+   55 89 e5 8b 45 08      frame + frame-relative load     x86gcc #6
           55 89 e5 53 8b 5d 08   frame + ONE save + load         family (4), filler-paired
           55 89 e5 53 56 57 …    frame + saves                   x86gcc #5 (53,56,57 conforming)
-4s -od    53 56 57 55 89 e5 …    save-first, conforming run      family (1)
```

The `16 with the search off` column matters: the orphan is pattern-discovered in every variant, so
this is a real measurement of the pattern set and not a vacuous pass.

**What the axis DOES move is the symbol interface, not the prologue.** Under `-4s` wcc386 emits
**bare** symbol names — `main`, not `main_` — so a `-4s` cell cannot share a `_cstart` stub with
any `-4r` cell. That is a build-time obstacle worth knowing before someone tries; it is not a
pattern-set gap.

**Consequence for §5's ranking:** the convention axis was listed as "yes, changes the entry shape".
Measured, it does not. Cross-checked against all three optimization settings, so this is not a
single-cell accident.

### ⛔ CELL 3 CHECKED — optimization / frame-pointer omission: **A BOUND, not a gap. No fixture.**

Measured 2026-08-06 with the orphan **deliberately frameless**, because cell 2's clean pass had
shown that a framed orphan leaves this family untested. Under `-onatx` wcc386 omits the frame
pointer entirely — **there is no `55 89 e5` anywhere in the binary**.

```
wnoframe (wprologue.c + a frameless orphan, -onatx):   12 / 17 recovered
  MISSED  p_leaf_ p_push1_ p_thru_ p_global_ nf_orphan_fn_
  with the byte-pattern search OFF:                    12   <- the patterns contribute ZERO
```

All five missed functions have **zero inbound references** — `-onatx` inlined their call sites, so
the standalone bodies are unreferenced and only a byte pattern could reach them. Their entry bytes:

```
p_leaf_        40 c3              inc eax ; ret          <- a 2-byte function
p_push1_       52 8d 14 40 e8     push edx ; lea ; call
p_thru_        e9 5b fe ff ff     jmp                    <- a tail thunk, no prologue
p_global_      52 8b 15 …         push edx ; mov edx,[abs32]
nf_orphan_fn_  6b db 07           imul ebx,ebx,7         <- no prologue AT ALL
```

**None of these is distinguishable from mid-function code**, because that is precisely what
frame-pointer omission does: it deletes the prologue. There is no byte sequence to anchor, and any
pattern loose enough to match `push reg; <arithmetic>` would fire continuously inside every
function body in the image.

**So this is a BOUND on what the pattern set can ever do, not a gap to be closed.** A byte-pattern
analyzer finds a function only when its entry has a *distinctive shape*; optimization removes the
shape. Ghidra has the identical limitation — its frameless family (3) anchors only the subset that
still carries `sub esp` (`push*; sub esp; mov [esp+v],reg`), and those forms **are** covered here:
`p_frame_`, `p_bigframe_` and `p_frame_saves_` all came back.

**No fixture.** A gate asserting 12/17 would lock a defect in as expected behaviour, and one
asserting 17/17 would fail forever. The finding is the deliverable.

**⚠️ TRIGGER — revive this cell as a precision tripwire if, and only if, someone adds a frameless
pattern that is not anchored on `sub esp`.** `wprobe` already gates the guarded
`0x68........e8........` forms, so today's precision risk is covered and this fixture would add
nothing. But `wnoframe` is the binary where an over-matching *frameless* form would show up
loudest — every function in it lacks a prologue, so a pattern claiming to find frameless entries
has nothing legitimate to match there. If you are reading this because you are about to add such a
pattern: rebuild the cell (`wprologue.c` + a frameless orphan, `-onatx`) and gate precision on it
before landing. The argument does not need re-deriving; the condition does.

### ✅ THE BOUND WAS CHECKED AGAINST THE 42 — and it is small. Discovery is NOT finished.

Measured by the lead on WAR2, 2026-08-06:

```
genuinely missing (shift-tolerant)   42
   15  frame-first                      <- our families describe these
   14  save-first                       <- our families describe these
    4  saves + `sub esp`                <- our families describe these
    9  FRAMELESS (no prologue shape)
  with NO inbound reference in Ghidra   37
  FRAMELESS *and* no inbound reference   4   <- structurally unrecoverable, by us OR Ghidra
```

**Only 4 of 42 are cell 3's unrecoverable class.** The other **38 carry a prologue shape our
families already describe**, so they are declined for some *other* reason — the containment guard
and `PseudoDisassembler` validation being the obvious suspects, unmeasured as yet. That is a live
question, not a closed one.

⚠️ **This inverts the reading three dissolved items were pointing at.** §1, §6 and cell 3 each
turned out to be "not a defect", and the natural inference — *discovery is finished, the residue is
structural* — is **wrong for 38 of 42**. Recorded explicitly because the inference was tempting,
was nearly acted on, and only a measurement stopped it. Cf.
[[absolute-vs-differential-wrongcode]]: a run of negative results is not itself evidence.

Original note, superseded in degree but not in kind: WAR2's census splits
**save-first 1317 / frame-first 239 / no-frame 564**. If any of the 42 genuinely-missing functions
are frameless-optimized with no inbound edge, they are **unrecoverable by pattern work of any
kind** and further pattern effort aimed at them is wasted. That is a cheap thing to check and it
would bound the remaining discovery work.

### ✅ CELL 5 CHECKED — target (`-bt=`): **INERT for codegen. No fixture, no patterns.**

Measured 2026-08-06 the cheapest way available — compare the OBJECT, not the linked binary, so the
target's runtime and startup are out of the comparison entirely:

```
wcc386 wp.c -bt={linux,dos,os2,nt} -s <opts>   ->  1 distinct object md5, every time
  -of+        4 targets -> 1 hash      (identical, byte for byte)
  -onatx      4 targets -> 1 hash
  -od         4 targets -> 1 hash
  -4s -of+    4 targets -> 1 hash
```

**`-bt=` cannot change the entry shape because it does not change the emitted code at all** for
32-bit flat-model compilation. It selects the run-time library and the executable format — i.e.
what the *linker* pulls in and what `_cstart_` looks like — not what `wcc386` generates per
function. Four targets × four option sets, always one hash.

That is a stronger result than a fixture would have given: it is not "we checked some prologues and
they matched", it is "the compiler emits identical bytes", which settles every prologue in the
translation unit at once. The §5 table listed this axis as "maybe — affects the runtime and entry
conventions"; the runtime half is true and irrelevant to a pattern set, the codegen half is false.

⚠️ Scope of the claim: 32-bit flat model (`wcc386`). A 16-bit compiler (`wcc`) has real memory
models and this would need re-measuring there — but 16-bit is outside the language mosura targets
(`x86:LE:32:default`).

### ✅ PREREQUISITE (a) RESOLVED — declare the compiler from the build, don't ask the image

The routing problem that generated three by-name skips and the `overrides` module is closed, and
the resolution reframes it: **"fix corpus-wide compiler detection" was the wrong goal, because
detection cannot succeed here even in principle.**

`compiler_spec_id` decides `watcom` vs `gcc` from the C run-time's copyright banner — the only
in-band evidence an ELF32 i386 carries, since a `wcc386 -bt=linux` image is header-identical to a
gcc one. The corpus links `option nodefaultlib` with a hand-written `_cstart_`, so **its binaries
contain no such evidence and detection correctly reports `gcc`.** That is a property of the
fixtures, not a defect in the detector; no improvement to it can recover a fact the file does not
contain.

What the corpus *does* have is its **build-derived truth**: every `.truth` carries a `compiler`
field that `build.sh` writes from the recipe which produced the binary, never hand-authored. So the
corpus now **declares** the compiler from the build rather than interrogating the image, through
`analysis::analyze_file_as(path, cspec)`.

**Two of the three by-name skips are retired** — `wprologue_sf` and `wprobe` are now gated by the
generic `ground_truth_parity` loop itself:

```
[wprobe]        funcs 18/18 recovered (0 spurious) … compiler(truth)=watcom, mosura(cspec)=watcom
[wprologue_sf]  funcs 17/17 recovered (0 spurious) … compiler(truth)=watcom, mosura(cspec)=watcom
```

`noret`'s skip stays and is **not** cspec-caused: it is the only dynamically-linked fixture, so its
PLT stubs and `EXTERNAL` slot are real functions that an `nm`-derived truth cannot express. A
different problem with a different fix.

**What became of the `overrides` module, checked rather than assumed.** It did not disappear, and
here is the exact reason:

- `force_x86_32_cspec` now has **one caller in the whole crate** — `analyze_file_as` — and is
  `pub(crate)` so a future test cannot reach around the public API and reintroduce ad-hoc routing.
  It went from a test backdoor to private plumbing for a documented entry point.
- `disable_analyzers` remains, and always will: it is the **analyzer-ablation** switch (Ghidra's
  own `ANALYSIS_PROPERTIES` model), the only way to attribute a discovery to the analyzer that
  made it. Nothing to do with compiler routing, and it is what proves a fixture's recall is not
  vacuous. Removing it would delete the measurement, not the workaround.

So the module survives with its two halves on opposite footings: the cspec half is now
implementation detail, the ablation half is a permanent measuring instrument.

⚠️ **Production detection is unchanged and should stay that way.** A real Watcom binary links a
real CRT and carries the banner, so detection already works where evidence exists. The corpus was
always the artificial case.

### Two prerequisites every matrix cell inherits (learned building §4's cell)

**(a) A cell cannot reach the Watcom pattern file by default.** The `(language, compiler)` decision
tree picks the pattern file, and `loader::watcom::compiler_spec_id` decides the compiler from the
**run-time copyright banner** — a string in the C run-time, not in anything the compiler emits. The
corpus links `option nodefaultlib` with a hand-written `_cstart_`, so **no ground-truth binary
carries the banner and every one detects as `cspec=gcc`** (measured: `wprologue`, `wprologue_sf`,
`fnpattern`). Until §4 this meant `specs/patterns/x86watcom_patterns.xml` had **zero fixture
coverage of any kind**, and any gate written against a Watcom-compiled fixture was silently
measuring Ghidra's `x86gcc_patterns.xml`. `MOSURA_X86_32_CSPEC=watcom|gcc` routes one binary
through both; it is inert when unset. Every new cell needs the same routing, or a linked CRT.

**(b) A cell needs an orphan, or its recall proves nothing.** If every function is call-reachable,
the reference-driven analyzers recover them all and the pattern set is never load-bearing —
measured on `wprologue_sf` before its orphan existed: 15/15 recall and 0 spurious with the
byte-pattern analyzers OFF. `src/fnpattern.c` properties 2-5 are the specification for this.

### The `compiler version` axis is already partly answered — in the direction that helps

The rigid save order `ebx ecx edx esi edi` is **Watcom codegen, not a WAR2-era artifact**. Three
independent sources agree: warcraft2-re's WAR2 census (1317 conforming / 0 nonconforming, Watcom
10.0a), Watcom 10.0a under `-od` compiled directly, and **native Open Watcom v2** — whose saves in
our own `wprologue.watcom-x86-32` read `53 51 52 56`, `51 56 57`, `56 57`, and in
`fnpattern.watcom-x86-32` read `52`, `56 57`. Two decades of compiler versions, same order. The
same holds for saves emitted *after* a frame setup (§2), so the ordering guard should survive the
whole version axis rather than needing a per-cell measurement.

⚠️ Do **not** tune the pattern set against WAR2's function count. Precision is unmeasurable there
(the tracker covers 71.4% of the code object, so a hit in a gap is undecidable). Precision is only
measurable on a self-compiled binary where every function is known — that is what the matrix is for.


### §5 cell 6 — compiler VERSION: **MEASURED INERT for entry shape** (lead, dosemu)

The last axis, and the one that needed dosemu. Same probe (`src/wprologue.c`), same flags
(`-4r -fpi87 -s -od`), compiled by four historical Watcom releases under dosemu2:

| version | year | code bytes | md5 (first 16) | save-first | frame-first |
| --- | --- | ---: | --- | ---: | ---: |
| 9.01  | 1992 | 1214 | `ab520f9cbf196669` | 13 | 13 |
| 10.0a | 1994 | 1214 | `a9cdf26b9b3be55f` | 13 | 13 |
| 10.6  | 1995 | 1214 | `a9cdf26b9b3be55f` | 13 | 13 |
| 11.0  | 1997 | 1202 | `cb970f6a5a28a9e6` | 13 | 13 |

**10.0a and 10.6 are BYTE-IDENTICAL.** 11.0 first diverges at offset `0x75` — `fc` vs `f8`, a
stack-slot assignment inside a *body*, not a prologue — and emits the same 13 prologues with the
same push runs (`53 51 52 56 57 55 89 e5`, `53 51 56 57 55 89 e5`, `51 56 57 55 89 e5`,
`56 57 55 89 e5`).

**9.01 (2026-08-06, lead) extends the axis back to the first 386 generation and does not break it.**
Same 1214 code bytes as 10.0a and **exactly 6 differing bytes**, every one the same substitution
(`0x05` ↔ `0x28`) at `0x24b, 0x25a, 0x2a6, 0x2ba, 0x32b, 0x33a`. All six are a **SIB base/index swap
in array addressing inside a body**:

```
9.01    249:  89 54 05 d4     mov %edx,-0x2c(%ebp,%eax,1)
10.0a   249:  89 54 28 d4     mov %edx,-0x2c(%eax,%ebp,1)
```

Same effective address, base and index exchanged — a pure encoding choice, in `p_frame` /
`p_bigframe` / `p_frame_saves` bodies, **zero bytes in any prologue**. Prologue counts are identical
(13 save-first, 13 frame-first). The 10.0a row was **regenerated from scratch** for this comparison
and reproduced `a9cdf26b9b3be55f` to the digit, so the table is self-verifying rather than recalled.

So across **9.01 → 10.0a → 10.6 → 11.0 → Open Watcom v2** — 1992 to the present, the entire lifetime
of the compiler — no release produces an entry shape another does not. Every difference this project
has found traces to **flags**, never the version: frame-first vs save-first is `-of+`, the ten-byte
shift is `-s`, and the push order is identical across three decades. **No per-version fixture is
warranted** under the §5 stop rule — one per release would multiply maintenance while gating
identical shapes.

⚠️ 9.01 is a **floppy set**, not an ISO, so `setup-watcom-dosemu.sh` does not cover it; it needs
`INSTALL.EXE` under dosemu. The working procedure and its two traps are in
`docs/watcom-codegen-fingerprint.md` — this is the path to 7.0 / 8.5a / 9.5b as well.

⚠️ Scope: this is the **entry** shape, which is all the pattern set sees. 11.0's body codegen does
differ (12 bytes shorter here), so nothing reasoning about bodies may cite this row.

### ⭐⭐ RE-CONFIRMED 2026-08-09 ACROSS SIX REVISIONS, INCLUDING BOTH SIDES OF THE 10.0a EXCURSION

The version set widened on master (7.0 / 8.5a / 9.5b / 10.5 / the 10.0 beta were added), and
10.0a became **known** to be a one-release excursion in BODY codegen — byte-identical neighbours on
each side, different in the middle (`docs/watcom-10.0-beta-codegen.md`). WAR2 is 10.0a. So the one
revision this campaign targets is the one that provably deviates from its neighbours, and the
question "does it also deviate in ENTRY shape?" had to be re-asked rather than assumed.

**It does not.** `src/wprologue.c`, same flags (`-4r -fpi87 -s -od`), compiled by every revision that
would build it, comparing the **prologue byte sequences** — not file positions:

```
  revision      code   13 prologues, identical sequence to 10.0a?   whole-probe diffs
  9.01          1214                    YES                                6
  9.5b          1214                    YES                                0
  10.0 beta     1214                    YES                                0
  10.0a         1214                    YES                                -
  10.6          1214                    YES                                0
  11.0          1202                    YES                              607
  OW2           1234                    YES                              631
```

All **seven** emit **13 prologues with byte-identical sequences**, 1992 → 2002+.

⭐ **AND THE EXCURSION DOES NOT APPEAR ON THIS PROBE AT ALL.** 9.5b, the 10.0 **beta**, 10.0a and 10.6
are byte-identical over the *whole* of `wprologue.c` — 0 differences, not merely equal prologues.
The 10.0a excursion is real (`docs/watcom-10.0-beta-codegen.md`) but it is **construct-specific**:
it lives in the byte-compare promotion that `watcom_cg.c`'s `cmpbyte` exercises, and `wprologue.c`
does not contain that construct. So "10.0a is an excursion" is a statement about a *particular
construct*, not about its codegen generally — which makes the entry-shape result stronger, not
weaker. 9.01 differs by 6 bytes (the known SIB base/index swaps, none in a prologue); 11.0 and OW2
differ substantially in bodies and not at all in prologues.

⚠️ The 10.0 beta is the load-bearing row here and it was missing from the first cut of this table —
it is 10.0a's *immediate* neighbour and the entire basis of the excursion finding. It runs under
wine, not dosemu: `wine 'C:\WBETA\BINNT\WCC386.EXE' -4r -fpi87 -s -od WP.C`.

⚠️ **A POSITIONAL BYTE DIFF IS THE TRAP HERE, AND IT NEARLY GOT REPORTED.** 11.0 is 12 bytes shorter,
so every byte after the first size change is SHIFTED; diffing by offset showed "37 differences inside
a prologue" for 11.0 and 36 for ow2 — pure artifact. Compare the extracted prologue SEQUENCES, never
file offsets, whenever the code sizes differ. Same family as [[gauge-counting-traps]].

⚠️ **NOT covered, and the span is 9.01→ow2, not 7.0→ow2:** 7.0 (`wcc386.exe` not found in the staged
tree), 8.5a (rejects the probe source, 1 error — a 1991 compiler), 10.5 ("Loader read error" under
dosemu). Three revisions unmeasured; do not claim the full lineage.

**Consequence:** precise RELEASE detection (era → 10.0a) buys this track little, since the pattern
set keys on entry shape and entry shape does not move. It remains valuable for recompilation, where
body codegen is the whole point.

**§5 is COMPLETE — one axis of six moved the entry shape:** stack checking, the one WAR2's own build
flags hid.

## 6. Over-decode — ⛔ CLOSED 2026-08-06, NOT A DEFECT

**mosura decodes nothing it should not.** Measured absolutely on WAR2 @ `77c8351`, with the
tool's positive control passing first:

```
self-test: A1, A2, A3, A4 each detect a planted violation and stay silent when clean
== WAR2.EXE ==   instructions 132356   decoded bytes 387761
  obj1_text  00010000..0007c49f  exec=true
  obj2_data  00080000..000ab2ff  exec=false
A1 non-executable decode         starts=0  bytes=0  runs=0
A2 offcut starts                 0
A3 flow into mid-instruction     1        0006ecb4 -> 0006ecec
A4 fixup target mid-instruction  0  (of 17511 relocations; ~3178 code-targeted)
A5 unreachable starts            81 (runs 81)
```

### ⭐ A3's ONE SITE, IDENTIFIED 2026-08-06 — and the "embedded switch table" framing was WRONG

A3 was carried for weeks as *"a `jmp` over a case table embedded in a function body"*, with the
follow-up filed as **"needs Watcom 10.0a under dosemu, because native OW2 places case tables before
functions under all four opt settings."** Reading WAR2's actual bytes retires that. **The site is
not a switch table and no compiler flag is involved.**

```
0006ec80  80 18 00 00  f4 19 00 00  80 1b 00 00  23 1d 00 00     0x1880 0x19f4 0x1b80 0x1d23
0006eca0  e3 26 00 00  33 29 00 00  a6 2b 00 00  40 2e 00 00     0x26e3 0x2933 0x2ba6 0x2e40
0006ecb0  00 31 00 00  e9 33 00 00  00 37 00 00  46 3a 00 00     0x3100 0x33e9 0x3700 0x3a46
0006ece0  00 62 00 00 | 53 51 52 83 3d cc 9f 08 00 00 75 1c
                        ^ the real function starts at 0006ece3 (save-first: push ebx,ecx,edx)
```

A **monotonically ascending lookup table** — 0x1880, 0x19f4, 0x1b80 … 0x6200, a curve of some kind
— sitting in the code segment, ending at `0006ece3` where a real function begins.

**The reported edge is a coincidence of encoding.** At `0006ecb4` the table's dword is
`e9 33 00 00`, and `e9` is `jmp rel32`. Decoded as an instruction that is `jmp +0x33`, whose target
is `0x6ecb4 + 5 + 0x33 = 0x6ecec` — precisely the address A3 reported, and mid-instruction because
the real code stream there is offset differently.

So A3 is **data-in-the-code-segment decoded as code**, not a compiler layout choice. The correct
question is *why anything decoded that table*, and the correct fixture is a `const` lookup table the
linker places in the text segment — reproducible with any compiler, no dosemu required. That is a
strictly easier fixture than the one this item was blocked on.

**`00064bdb` (§ the 12) is the same class**: its bytes are dword pointers `0x00064ca9`, `0x00064cb6`,
`0x00064d17` — a pointer table in the code segment, with a tracker "function" recorded inside it.
Two of the track's open items are one phenomenon.

⚠️ The lesson is the recurring one: the hypothesis named a *mechanism* (compiler emits table
mid-function) and the follow-up work was scoped to reproduce that mechanism — a dosemu compile
matrix — when four lines of `readelf` + a byte dump refuted it. **Read the bytes at the site before
scoping work to reproduce a shape.** See [[could-it-have-come-out-otherwise]].

- **A1 = 0** — not one instruction outside what the LE object table itself marks executable;
  `obj2_data` untouched.
- **A2 = 0** — no offcut start in 132,356 instructions.
- **A4 = 0 against a live fixup table** — and this is the check that settles it, because it is the
  only one where the **file itself supplies both the address and the claim that it is code**.
  Every code-targeted fixup lands exactly on an instruction boundary in our decode. Neither inert
  (unlike on the ELF fixtures, which have no relocation table) nor differential.

So "7,322 extra instruction starts / 104.4% of Ghidra's code coverage" was never over-decode on
our side. It was measuring **Ghidra's UNDER-decode** — the differential named a difference that
was a defect on neither side, and the item existed only because the difference was read as ours.
Three hypotheses were killed chasing it (`mustTerminate`, the flow-disassembler bounds, the
address-table thread) before anyone asked whether the premise was sound.

**This is the third item on this track to dissolve under measurement** — §1, the no-return
diagnosis, and now §6 — and in every case the culprit was a differential or a derived summary,
never the binary. The standing consequence is recorded at the top of this file and in
[[absolute-vs-differential-wrongcode]]: **before hunting a defect stated as a differential, build
an absolute measure and give it a positive control.** `docs/over-decode-measure.md` +
`examples/over_decode` are that measure, and are reusable.

⚠️ The run above printed A4's denominator as the **total** relocation count. That overstates its
coverage — A4 only examines fixups whose target is in executable memory (on `lestruct`: 3 of 9).
Fixed after the fact; the current build prints `(of N CODE-TARGETED fixups; M relocations total)`.
The conclusion is unaffected (0 offcut is 0 either way) but the denominator was wrong, and a zero
has to carry the denominator it was measured against.

### Residuals, both small and both real

- **A3 = 1** — `0006ecb4 -> 0006ecec`, one flow edge landing mid-instruction, in 132,356
  instructions. A genuine self-consistency violation that no comparison artifact can explain.
  The tool now dumps the source bytes, the instruction the target lands inside, and the offset
  into it, so **one run diagnoses it** rather than costing a round trip for bytes.
- **A5 = 81 unreachable starts** — probably the byte-pattern search *working*: `Function Start
  Search` exists to create functions with no inbound flow, so it populates A5 by construction.
  Before treating any of it as signal, ablate the four FSS analyzers and subtract. Only starts
  that are neither pattern-discovered nor flow-reachable are interesting.
- **A4 measured and clean** (see above). The first run predated it, which was provable from the
  self-test line naming only A1-A3 — that line is a build identifier as well as a control.

**Part B (provenance by ablation) deliberately NOT built.** Its precondition was "A1 shows
something to attribute"; A1 is 0, so it would attribute nothing.

## 7. Handed to warcraft2-re, awaiting their verdict

`war2-survey/analysis-gap/mosura-discovered-functions.{csv,md}` — **872 functions in neither the
tracker nor Ghidra** (763 save-first = 87.5%, matching the target's own 84.6% distribution; 71,697
bytes against ~126,770 of measured gap). They accepted the offer. Their verdict feeds back as
either a recall win to keep or a precision problem to fix.

**⭐ SECOND THING TO HAND BACK (2026-08-06): 50 boundary corrections.** §1's refutation produced
50 tracker rows whose recorded entry is at the `push ebp`, mid-prologue, with the save-first run
before it — rows their own `function-boundary-correction.md` pass (which corrected 132) missed.
mosura has each at the true entry, 1-7 bytes earlier, with the bytes to prove it. Concrete and
actionable for them, and it is evidence flowing the other way for once: our pattern set correcting
their oracle. The lead is folding it into the existing CSV rather than opening a new thread.

Also pending from their reply: **Watcom's own shipped `CLIB3R.LIB` is save-first** (`write_`,
`__CMain`, verified inside WAR2 with 0 unmasked mismatches). So a frame-first-only pattern set
misses Watcom CRT code in **any** binary — independent support for §5.

## 8. Function bodies UNDER-extend at a computed jump — ✅ FIXED `6abd1ae`, CONFIRMED ON WAR2

**Landed and measured.** Fixture: **53 of 53** computed-jump targets lay outside their containing
body before (narrowsw 16/16, switchcall 14/14, dispatch 7/7, tables 12/12, compgoto 4/4 — total,
across two compilers and two architectures); **0 of 53** after. Gate
`switch_case_bodies_are_inside_the_function_body`, vacuity-checked.

**WAR2 before/after, with the prediction made BEFORE the run** (*"extents grow, `INSIDE` unchanged"*):

```
                  funcs  matched  missing  inside   body_bytes    not_tracker_term
  0acd3a0 before   3018     2108       12       3      380,247    899/900
  6abd1ae after    3018     2108       12       3      392,081    899/900
                                                       +11,834  (+3.1%)
```

**Exactly one number moved, the one predicted to move.** ~88.5% of WAR2's code object is now inside
a function body, up from ~85.8%.

⚠️ **The suite was RED at `6abd1ae`** — `nfprologue` was still asserting recall of three orphans that
`50bea92` had correctly made unrecoverable, so the corpus loop failed from the moment of the backout.
Fixed in `2a2f705`. **The WAR2 figures above are unaffected**: the failure is a fixture-recall
assertion in the corpus loop and touches no analysis path `analyze_le_file` uses. Recorded rather
than silently re-stamped, because "confirmed on WAR2" was written here before that was known. This lands on the campaign's actual goal rather than on a function
count: a function with the wrong extent cannot be byte-exactly recompiled, and every one of those
case bodies was previously outside its function.

⚠️ **The root cause is sharper than this item's original framing** (which was mine): it is not
merely "the walk doesn't follow `Branchind`". *Both* walks are **opcode-driven**, and a `BRANCHIND`
names no static target at all — the jump table lives in the **reference set**, which neither walk
consulted. Fixed with Ghidra's own `dontFollow` predicate (`follows_flow_ref`), stated once and
shared by both walks rather than restated twice.

**Deliberately NOT fixed, deferred to §9:** Ghidra's walk is reference-driven throughout, mosura's
is opcode-driven, and they diverge wherever a reftype has been overridden (see
[[reftype-is-post-override-not-the-instruction]]). Consulting references for computed jumps is
purely additive — it closes this gap without altering any flow the opcode walk already followed —
so the outright conversion belongs in its own change with its own gate. Recorded on
`follows_flow_ref`.

### Original statement of the item



Split out of §1 at the lead's request (2026-08-06): §1 is "bodies run past the real end", this is
"bodies stop short of it". Opposite signs, so **never fix them in the same change** — a WAR2 delta
mixing the two cannot be attributed per function.

Ghidra's `FollowFlow` follows computed jumps by default (`followComputedJump = true`,
`FollowFlow.java:42`; `CreateFunctionCmd`'s `dontFollow` list contains COMPUTED_**CALL** and
INDIRECTION but **not** COMPUTED_JUMP), so a switch's case bodies are inside the Ghidra body.
mosura's walk pushes a target only for `Branch`/`Cbranch` and never for `Branchind`
(`analyzers/mod.rs:300-306`, `function_start.rs::flow_body`), so every recovered switch's case
bodies are outside the body unless some other edge happens to reach them.

Not yet measured. The natural gauge is a fixture with a recovered jump table — `narrowsw`,
`switchcall`, `dispatch`, `tables` — asserting the case bodies are inside the function's extent.
Note the same wrong-extent-blocks-byte-exactness argument as §1 applies here.

## 9. Divergences in mosura's body walk

### ⭐ #4 MEASURED 2026-08-06 — premise confirmed, but the "faithful" conversion is NOT SAFE

Measured across every gcc-x86-64 and watcom-x86-32 fixture, over all opcode-derived branch targets
inside function bodies:

```
opcode-derived branch targets                    372
  reftype is a CALL kind (#4's tail call)          5
  with NO matching flow reference at all         211
```

**#4 is real** — 5 sites where the walk pushes a target whose reftype is `UNCONDITIONAL_CALL`
(`tailjmp.watcom-x86-32` ×2, the fixture built for exactly this; `tailcall.gcc-x86-64` ×2;
`tables.gcc-x86-64` ×1). Ghidra's `dontFollow` refuses those; mosura's opcode path takes them.

⚠️ **But 211 of 372 branch targets carry no flow reference at all.** mosura's reference manager does
not record ordinary intra-function branches the way Ghidra's does. So **converting the walk to be
reference-driven — the "faithful" shape, and what §8 deferred here — would shrink bodies by more
than half the branch edges.** That conversion is not safely available until the reference set is
complete, which is a far larger job than this item's framing implies. Anyone attempting it on the
strength of that framing should read this first.

**The scoped fix that IS available:** keep the opcode path, but refuse a target when a reference
from that instruction to it carries a call-type reftype. That applies Ghidra's `dontFollow` rule to
the opcode path and consults references only to **veto**, so it does not depend on the reference set
being complete.

⚠️ **Open question gating even that:** `compute_function_bodies` already stops at a known function's
entry, so if the tail-call target is itself a discovered function the divergence is **masked** and
the change would be inert. Measure that before writing it — an inert change cannot have a gate that
fails. (Asked and answered in advance this time, unlike family (6).)

### The original three (surfaced by §1, independent of it)

§1 dissolved, but these did not: each is a genuine difference from Ghidra's body computation,
found by reading both sides, and each survives the refutation on its own merits. **None of them
caused §1**, so none has a WAR2 prediction attached — treat them as correctness work with the
burden of proof on whoever lands one.

Ghidra's path is `CreateFunctionCmd.getFunctionBody(program, entry, includeOtherFunctions=false,
monitor)` → `new FollowFlow(program, entry, dontFollow, false, false, true).getFlowAddressSet()`,
with `dontFollow = {COMPUTED_CALL, CONDITIONAL_CALL, UNCONDITIONAL_CALL, INDIRECTION}`.
(`Ghidra/Features/Base/.../CreateFunctionCmd.java:613`,
`Ghidra/Framework/SoftwareModeling/.../block/FollowFlow.java`.) mosura's equivalent walk exists
**twice** — `analyzers/mod.rs::compute_function_bodies` and
`analyzers/function_start.rs::flow_body` — and they must not drift apart.

**✅ 1. The no-return fall-through — LANDED `0de3523`. Real drift; NOT the cause of the 51.**
Fixed by de-duplication: all three walks now share `analyzers::falls_through`, so the copies
cannot drift again. Gated by `ground_truth_parity::noreturn_call_bounds_the_body` against a new
dynamically-linked fixture, `noret.gcc-x86-64` — the only corpus binary that makes
`noreturn::analyze` run at all. **WAR2 delta 0 by construction** (see below). Landing it exposed a
SECOND defect, invisible until the fixture existed: `noreturn::analyze` ran once before
disassembly, leaving its PLT-thunk propagation dead (it walks `function_manager.functions()`, and
there are none yet), so only the EXTERNAL `abort` was flagged and never the PLT stub — which is
how every call to a dynamically-imported no-return function actually looks. Re-run after the
worklist converges; flagged 1 -> 2. Fix #1 alone left the gate RED.
Original refutation, kept because it is why this carries no WAR2 prediction:
Measured before building anything: `noreturn::analyze` selects its name list from the memory map
and **returns early unless a `.dynsym`, `.plt` or `EXTERNAL` block exists** (`noreturn.rs:128-137`).
WAR2 is a DOS/4GW LE image whose loader names its blocks `objN_text`/`objN_data` (`loader/le.rs:219`)
— none of the three. Confirmed empirically on all four fast fixtures, including the LE path WAR2
uses: **`noreturn_flagged = 0` everywhere** (fnpattern, wprologue, wprologue_sf, lestruct). With
nothing flagged, `falls` is identical with and without the check, so this cannot account for a
single one of the 51. It is still a genuine defect for ELF/PE targets and still worth closing —
but not here, and not as this item's fix. Detail of the drift, for whoever does close it:
Ghidra asks `currentInstr.getFallThrough()` (`FollowFlow.java:556`), which is null after a call to
a non-returning function. mosura's *disassembler* does exactly this and consults
`program.is_noreturn` (`analyzers/mod.rs:130`, comment: "Ghidra's followFlow consults
Function.isNoReturn"). But `compute_function_bodies`, **170 lines further down the same file**
(:298), recomputes `falls` from the opcode alone:

```rust
let falls = !matches!(last, Some(OpCode::Return | OpCode::Branch | OpCode::Branchind));
```

with no no-return check — and `flow_body` has the same omission. So on a target where the analyzer
*does* run, the decoder stops after `call <noreturn>` and the body walk steps over it. On WAR2 the
analyzer never runs, so this is latent, not active.

### ~~2. The listing, not a re-decode~~ / ~~3. No instruction at the entry ⇒ a one-byte body~~
### ⭐ STRUCK AND REPLACED — they are ONE symptom, and #3's literal port is a REGRESSION

Both items were measured across the 194 functions of the gcc-x86-64 + watcom-x86-32 corpus
(2026-08-06). They are not two divergences. **They fire on exactly the same six functions**, and in
every case the undefined-byte count equals the ENTIRE body:

```
functions examined                                  194
#3 no defined instruction at the entry                6
#2 bodies covering UNDEFINED bytes                    6   (592 bytes)

fnpattern.watcom-x86-32   @08048120   body  89B   <- byte-pattern-discovered orphan
retorphan.watcom-x86-32   @0804812c   body  88B   <- byte-pattern-discovered orphan
wprobe.watcom-x86-32      @08048112   body  46B
wprobe.watcom-x86-32      @08048666   body 210B
wprologue_sf.watcom-x86-32@080485e3   body 158B
noret.gcc-x86-64          @00404000   body   1B   <- already degenerate, agrees with Ghidra
```

⚠️ **PORTING #3 LITERALLY WOULD COLLAPSE FIVE REAL 46-210 BYTE FUNCTIONS TO ONE BYTE EACH.** It is
not merely inert — as stated it is actively wrong, and it would land the day §8 established that a
wrong extent is what blocks byte-exact recompilation. Do not re-derive it from
`CreateFunctionCmd.java:616` and port it in good faith; the Ghidra line is correct **for Ghidra**,
whose listing is populated at those addresses. Ours is not, and that is the whole of the difference.

**THE REAL ITEM — pattern-discovered functions are absent from the listing.** Five of the six are
recovered by the byte-pattern search, and their bytes were never disassembled into the listing.
Ghidra's `FunctionStartAnalyzer` schedules disassembly for its matches and the manager disassembles
at function creation, so by the time `getFunctionBody` runs there IS an instruction at the entry and
`getInstructionAt != null` covers the whole function — **both #2 and #3 are vacuous by construction
in Ghidra.** Fix the listing and they dissolve; port them without fixing it and the tree gets worse.

This is a **discovery** defect, not bookkeeping. Anything reading the listing is blind in those
regions, including `checkAfterName`'s `"instruction"` and `"defined"` prerequisites — which is
exactly why the `retboundary` fixture could not fail on 2026-08-06 (`code_unit_containing(entry-1)`
was `None`), and it is **plausibly** why the four WAR2 entries at §"the 12" report
`pred=None`/`at_addr=None` — **a hypothesis, not a measured link.** Those four are candidates that
were never *created*, so pattern-discovered-function disassembly does not apply to them directly;
the claim needs their PREDECESSORS to be undecoded *because* neighbouring pattern-discovered
functions went undisassembled, and nobody has measured that. Ghidra's own answer on those four
addresses is the observation that settles it.
**Same root cause, three symptoms, two of which were met and treated separately before anyone
connected them.**

Gate for the replacement item: the six addresses above. Unlike #2 and #3, that is a test that can
fail. The seed exists — `create_functions` calls `sched.function_defined(&created)` — so the open
question is where the scheduled disassembly is dropped; measure that before writing anything.

#### ⭐ ANSWERED 2026-08-06 — see **CAUSE A** and **CAUSE B** at the top of this file

The question this paragraph poses ("where is the scheduled disassembly dropped?") is answered there:
a Ghidra COMMAND queue modelled as a change channel, plus `r.min`-only range iteration. Not repeated
here. What follows is only what is NOT in those two sections: the built fix, its gate, and the
blocker that stopped it landing.

##### The fix EXISTS, BUILDS, and TURNS THE GATE GREEN — and is deliberately NOT committed

`held-patches/listing-command-channel.patch` (388 lines, applies cleanly to `2c534db`). Five steps:

1. `Scheduling::disassemble()` / `create_function()`, name-routed to the `"Disassembly"` and
   `"Function"` executors — Ghidra's commands (`:1128` / `:1132` -> `schedule` `:860`). Seed sets
   only; they never mix with a decoded extent.
2. **`Disassembler` stops subscribing to `Instruction`.** Nothing in Ghidra subscribes disassembly
   to `codeDefined`; it is only ever a scheduled command. The self-notification that the old
   comments called "what terminates the loop" was the loop's *cause*. It still EMITS
   `code_defined(decoded)` — the genuine notification `AfterCode` consumes.
3. Both executors iterate every address of their set, ⚠️ **bounded by Ghidra's short-range branch**:

   ```java
   subRangeSet.delete(nextAddr, nextAddr);                    // :245 — deleted FIRST
   long addrsLeft = subRangeSet.getNumAddresses();            // :261
   if (addrsLeft <= 4) { seedSet.add(nextAddr); continue; }   // :262
   ```

   `addrsLeft` is counted AFTER the delete, so the cut admits a range of **five** addresses, not
   four: `addrs_left == r.max - r.min`. (First cut of this port had `< 4` and would have silently
   dropped four of any five adjacent entries — the very bug being fixed.) A SHORT range contributes
   every address as a seed; a LONG one is flow-disassembled from its minimum. **Seeding every
   address of a LONG range instead is not a safe generalisation: measured, it turns the war2 MZ
   over-decode count from 8 to 53 on its own.**
4. `Disassembler` + `FunctionCreator` registered in `fs_mgr`. `FunctionCreator` also raises
   `function_defined` for the functions it ACTUALLY created (Ghidra's
   `handleFunctionAddedOrBodyChanged` -> `functionDefined`, `:392-395`) — "actually" is load-bearing;
   re-announcing an existing entry never reaches a fixpoint.
5. **`SCHEDULED` and `PROPOSED` DELETED**, no replacement. Convergence verified by running, not
   assumed: the re-fire loop does not return, because a command echoes nothing to its requester.

Result: `recovered_functions_are_in_the_listing` **5 -> 0**; full workspace suite green *except* the
blocker below. The loader seed stays `function_defined` — that set is built from functions the
loader already created, so it is genuinely a notification, and converting it to a command starves
every other FUNCTION analyzer (caught by `a6_tests` immediately).

##### ⛔ BLOCKER — §9 #5, the inline-parameter thunk. The fix produces WRONG CODE on the war2 MZ stub

`analysis_parity::pe_mz_convergence_parity` goes **8 -> 53** misaligned decodes. Attributed by
experiment: disabling only the four byte-pattern analyzers makes it pass, so all 45 are the pattern
search's disassembly finally happening. The mechanism, and why it BLOCKS rather than moves a bound,
is §9 #5 below — mosura destroys a real instruction Ghidra has. A faithful port lands and only wrong
code blocks it; this is that exception.

##### Gate

`ground_truth_parity::recovered_functions_are_in_the_listing`, committed **`#[ignore]`d and RED** so
its ability to fail is proved by git history rather than by a revert-check. Population 386,
violations 5, exclusions computed (not by name), `examined > 0` so it cannot pass on an empty
population. It NAMES its violations, so each cause's contribution stays separately visible.

##### Residual: the same `r.min` mis-port is in THREE more analyzers — NOT fixed, NOT gated

- `ConstantPropagationAnalyzer` (`analyzers/mod.rs:439`)
- `DecompilerSwitchAnalyzer` (`switch.rs:46`)
- `SharedReturnAnalyzer` (`shared_return.rs:342`)

Each skips adjacent entries exactly as `FunctionCreator` did, so on any binary with consecutive
function entries they silently run on the first only. ⚠️ The last two treat `r.min` as a function
ENTRY, so per-address iteration there needs an "is a function entry" guard (`SharedReturnAnalyzer`
already has one, `switch.rs` does not) — a blind widening would decompile at non-entry addresses.

**⭐ 4. THE LIVE CANDIDATE — the body walk reads the OPCODE where Ghidra reads the REFERENCE TYPE.**
Ghidra's `dontFollow` list is expressed in `RefType`s, and a **tail call** (`jmp <function>`) carries
an `UNCONDITIONAL_CALL` reftype after `SharedReturnAnalyzer` has run — so `FollowFlow` refuses to
follow it. mosura's walk instead re-derives the decision from the raw p-code opcode: an unconditional
`jmp` is `OpCode::Branch`, so `falls` is false (correct) **but the branch target is still pushed onto
the worklist**, and if that target is a function mosura has not yet discovered, the walk runs through
the whole callee and swallows it. This is exactly the class recorded in
[[reftype-is-post-override-not-the-instruction]]: *reftypes are analysis OUTPUT; re-deriving flow
from the instruction discards every override the analyzers computed.* It also needs no no-return
flag, which is what makes it the surviving candidate after #1 was refuted.

**⭐ 5. INLINE CALL PARAMETERS ARE DECODED AS CODE — measured 2026-08-06, and it CORRUPTS the
listing.** The same class as #4, found on the war2 MZ stub while attributing the listing fix's
effect there. The image has a thunk family at `0x13a38 / 0x13a47 / 0x13a4c / 0x13a51`, each a
`CALL 0x13a56`, and the dispatcher pops its own return address and reads a word THROUGH it:

```
00013a56  5b        POP BX                    ; BX = the RETURN ADDRESS
00013a57  2e8b0f    MOV CX, word ptr CS:[BX]  ; read the word the call is FOLLOWED BY
…
00013a69  ff2ef20a  JMPF [0xaf2]
```

So every call site in this family is followed by a **2-byte inline parameter, not code**, and
control resumes 2 bytes further on. Ghidra's listing resumes exactly there. mosura's `falls_through`
re-derives fall-through from the opcode, has no way to express "resumes at return+2", and decodes
the parameter word as an instruction:

```
00015171  M G  e8dde8    CALL 0x13a51
00015174  M .  5b        POP BX          <- the inline parameter, decoded as code
00015176  M G  ff46e2    INC word ptr [BP + -0x1e]   <- both agree again, 2 bytes later
```

It is not merely extra. Where the parameter bytes are `be 39`, mosura's 3-byte decode at `00013a54`
spans `00013a56` and **destroys `POP BX` — the dispatcher's own entry, which Ghidra HAS.** That
settles the direction of the error without an oracle run.

Worth 45 of the 53 code units by which the listing fix moved `pe_mz_convergence_parity`'s war2
over-decode count (8 -> 53); 3 of the 9 clusters are inside functions the pattern search newly
reached, so before that fix these bytes were never decoded at all. **The listing fix did not cause
this; it stopped hiding it.** Closing it needs a fall-through override model, which mosura does not
have. (The ninth cluster, `00018f26`, is a `0000` padding over-run and is NOT explained by this —
see **the ninth cluster, ANSWERED AND CLOSED** below.)

##### ✅ THE NINTH CLUSTER, ANSWERED AND CLOSED — `MAX_REPEAT_PATTERN_LENGTH`

Not the thunk, and not a heuristic: `Disassembler.MAX_REPEAT_PATTERN_LENGTH = 16`
(Disassembler.java:82) driving `RepeatInstructionByteTracker`, checked at :1067. Ghidra counts
consecutive instructions whose bytes are **all the same value** and terminates the block once the
run exceeds 16. Nothing about the decode itself stops the walk — 50 bytes of `00` are 25 perfectly
valid `ADD byte ptr [BX+SI],AL`.

⚠️ **The framing in this file was off by two.** `00018f26` is not "a run of `0x00` bytes"; the
zero-fill runs `00018f00`..`00018f31` (50 bytes) and `00018f26` is simply *where Ghidra's limit
lands*. The interesting number is 16, not the address. Read through mosura's MZ-stub loader
(`analyze_file`), not raw file offsets — an MZ image is not mapped at its file offset, and reading
it that way makes the bytes at these addresses look like ordinary code.

Measured, mosura vs the committed golden `war2.snapshot`, both starting the run at `00018f04`:

```
Ghidra   00018f04 .. 00018f24   17 instructions, then nothing until func 00018f34
mosura   00018f04 .. 00018f32   23 filler + `87 db` at 00018f32, straight into the next function
```

**17, not 16** — the tripping instruction is KEPT. `exceedsRepeatBytePattern` only records a parse
conflict (:1068); `processInstruction` still runs and `block.addInstruction(inst)` (:1254) still
adds it; the block ends afterwards on `block.hasInstructionError()` (:1076). Getting that backwards
leaves the last filler instruction undecoded on every such run.

Ported in `crates/mosura/src/analysis/repeat_instruction.rs` + the `Disassembler` walk. mosura's
listing at these addresses is now identical to the golden. Gated by
`disassembler_bounds_tests::walk_stops_after_a_run_of_repeated_byte_instructions` (synthetic,
x86-64 — the mechanism is architecture-independent) plus the tracker's own arithmetic tests;
vacuity-checked by disabling the bound. No corpus regressions.

Note a consequence worth knowing: `getRepeatedByte` returns a value for **any one-byte
instruction**, so a run of 17+ `NOP`s trips the limit too. That is Ghidra's behaviour, not an
approximation.

The four cluster comparisons, `M` = mosura, `G` = the committed Ghidra golden `war2.snapshot`:

```
00013a51  M G  e80200    CALL 0x13a56
00013a54  M .  be395b    MOV SI,0x5b39   <- the inline parameter, spanning 3a54..3a56
00013a56  . G  5b        POP BX          <- THE DISPATCHER'S OWN ENTRY. Ghidra has it; mosura
                                            does not — the bogus decode SWALLOWED it.
00015171  M G  e8dde8    CALL 0x13a51
00015174  M .  5b        POP BX          <- parameter word
00015176  M G  ff46e2    INC word ptr [BP + -0x1e]   <- both agree again, 2 bytes later
000154b2  M G  e883e5    CALL 0x13a38
000154b5  M .  5b        POP BX
000154b7  M .  8946fc    MOV word ptr [BP + -0x4],AX
00017514  M G  e821c5    CALL 0x13a38
00017517  M .  5b        POP BX
```

**The swallowed `POP BX` at `00013a56` is what makes this a BLOCKER rather than a tolerance
question.** It is not extra code; it is a real instruction Ghidra has and mosura destroys, and it is
the entry of the routine being called. A faithful port lands and only wrong code blocks it — this
is that exception. A raised bound that quotes the defect it holds is a reasonable record for an
extent-neutral regression; it is not acceptable for a destroyed instruction, which is the exact
failure byte-exact recompilation is defined against.

##### ⚠️ The oracle probe on these addresses was run against a DIFFERENT IMAGE — do not re-use it

An oracle run reported, for probes `00013a4a` / `000154b5` / `00017517` / `00017525`, that Ghidra
has instructions **starting earlier** (`00013a48`, `000154b1`, `00017512`, `00017522`) and containing
the probe — which would have made these genuinely misaligned decodes inside Ghidra instructions.
**It was run on the warcraft2-re ELF32 wrapper of the LE body; every measurement above is on the
16-bit MZ STUB** (`pe_mz_convergence_parity` uses `analyze_file`, which keeps a bound exe on the
Ghidra-parity MZ-stub path). Different images, different address spaces.

Checked rather than assumed — decoding those four start addresses in the MZ image:

```
00013a48: 0c00    len=2  covers 13a48..13a49   OR AL,0x0        <- does NOT reach probe 13a4a
000154b1: 04e8    len=2  covers 154b1..154b2   ADD AL,0xe8      <- does NOT reach 154b5
00017512: 0050e8  len=3  covers 17512..17514   ADD [BX+SI-0x18],DL  <- does NOT reach 17517
00017522: 226892  len=3  covers 17522..17524   AND CH,[BX+SI-0x6e]  <- does NOT reach 17525
```

Not one of them covers its probe, so the report cannot describe this image. (`0004de58` is an
LE-body tracker address and has no meaning in the MZ stub at all.) This is
[[oracle-same-question-not-just-same-tool]] and [[war2-exact-reference-mismatch]]: same tool, same
offsets, different binary. **The HOLD decision does not depend on it** — the swallowed `POP BX`
above is measured wholly within the MZ image against its own committed golden, and stands alone.

### Landing conditions for any of them

- **#1 is DONE (`0de3523`).** The rest of this bullet is kept as the record of what it took: Every ground-truth binary measures
  `noreturn_flagged = 0`: the gcc x86-64 column is static/freestanding (`readelf -S`: `.text`, no
  `.dynsym`/`.plt`), the Watcom column links `option nodefaultlib`, and WAR2 goes through
  `analyze_le_file` (`examples/war2_survey.rs:210`) whose blocks are `objN_text`/`objN_data`. So
  `noreturn::analyze` never runs anywhere, and an MVE would pass with the fix reverted. Fixing #1
  means first building a dynamically-linked ELF fixture that calls `abort`/`exit` — which is worth
  having regardless, since `noreturn.rs` is **currently ungated entirely**.
- **One change per measurable effect.** #1, #2, #4 and §8 point in different directions; bundling
  any two makes a WAR2 delta unattributable per function.

### ⭐ NEXT ITEM — a FALL-THROUGH OVERRIDE MODEL. This is what unblocks the listing fix.

**The honest size of the remaining work, and it is not a tweak.** mosura has no way to express "this
call resumes at return+2". `falls_through` (`analyzers/mod.rs:90`) re-derives fall-through from the
p-code opcode plus one `is_noreturn` check; Ghidra's `Instruction.getFallThrough()` returns **what
analysis decided** — a per-instruction override the analyzers computed. Same class as #4 and
[[reftype-is-post-override-not-the-instruction]]: *re-deriving flow from the instruction discards
every override the analyzers computed.*

Until it exists, §9 #5 stands and the listing fix (`held-patches/listing-command-channel.patch`)
cannot land: decoding those bytes without it produces wrong code, not merely extra code.

Scope, in the order a next session should take it:

1. Carry a fall-through override on the code unit (Ghidra: `Instruction.setFallThrough` /
   `getFallThrough`, and `FollowFlow` reading it) rather than recomputing from the opcode. Read
   Ghidra's actual model before designing one — do not invent a mosura-shaped equivalent.
2. Then find what SETS it for this idiom. The war2 MZ thunks are recognised by the callee popping
   its own return address; that is an analysis result, not a decode result, so the setter is an
   analyzer, not the disassembler.
3. An MVE first, per directive 6 — a self-compiled program whose callee pops the return address and
   resumes past an inline word. `oracle/ground-truth/src/` has no such fixture, and one is needed
   before any fix, since the only current repro is a survey binary that cannot be shipped.

⚠️ Do **not** attempt this by special-casing the `0x13a56` shape. A pattern that matches one
dispatcher is the anti-pattern this project names explicitly.

---

## Corrections to earlier claims in this repo's notes

- `status=source-done` in `decomp-tracker.csv` does **not** mean byte-matched. It means "faithful C
  authored, byte-diverges by a documented blocker" (byte-exact is `matched`/`matched-fixups`,
  267 rows of 2120). Anything reasoning from "source-done ⇒ byte-identical" is wrong.
- "94% of WAR2 prologues open with a push run" conflates families: `push ebp` is `0x55`, inside
  `0x50`–`0x57`, so frame-first and most frameless functions satisfy it too. The real split is
  **save-first 1317 / frame-first 239 / no-frame 564**; save-first is 84.6% of *framed* functions.
- **"92 missing" / "94 missing" / "51 blocked by over-extended bodies" are all NAIVE-COMPARISON
  figures and are wrong.** The tracker anchors save-first functions mid-prologue at the `push ebp`;
  50 of the apparent misses are the same functions recovered at their TRUE entry. Shift-tolerant,
  the gap is **42** and mosura is at **2078/2120 = 98.0%**. Anything reasoning from the older
  numbers — including the original argument for prioritising §1 — is reasoning from an artifact.
- Ghidra's cold analysis of WAR2 is **2145**, not 1944. The 1944 figure comes from passing
  `-processor "x86:LE:32:default"` to `analyzeHeadless`, which bypasses the ELF opinion and lands
  compiler spec `windows` on an ELF — worth 201 functions. Never pass `-processor` for this image.
