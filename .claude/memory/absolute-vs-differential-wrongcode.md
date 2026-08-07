---
name: absolute-vs-differential-wrongcode
description: "⭐ 2026-07-29: a differential (before/after) gauge cannot see a defect present on BOTH sides. Measured against GHIDRA per-function, mosura drops calls in 92/1286 WAR2 functions (246 calls). ⚠️ The earlier '455 fns / 41%' figure was WRONG — an objdump linear sweep is a useless reference."
metadata: 
  node_type: memory
  type: project
  originSessionId: 99103a08-9d06-430b-8446-4ca5e3757106
  modified: 2026-07-29T08:57:14.959Z
---

# Measure wrong code against the BINARY, not against the previous build

## ⭐ THE MIRROR HALF (2026-08-06): a differential also INVENTS defects that exist on neither side

The section below is about false *negatives* — a defect on both sides is invisible. The opposite
failure has now cost this project three items in one week, all on the function-discovery track:

| item | the differential said | the truth |
| --- | --- | --- |
| §1 "bodies over-extend" | 51 missing functions, all inside a mosura body, 0 in open space | the tracker anchors save-first entries mid-prologue; **50 were the same functions at their TRUE entry** ([[war2-tracker-anchors-mid-prologue]]) |
| the no-return diagnosis | a drift that "explained the distribution" | `noreturn::analyze` never runs on WAR2 — **the mechanism could not fire at all** |
| §6 "7,322 extra instruction starts" | 104.4% of Ghidra's code coverage, i.e. we over-decode | measured absolutely: **A1 = 0**, nothing outside the LE object table's executable range. It was measuring **GHIDRA's under-decode** |

**Every time the culprit was the differential or a derived summary — never the binary.** Three
hypotheses died inside §6 alone before anyone questioned its premise.

**How to apply.** Before hunting a defect that is stated as a differential, build an **absolute**
measure — one that references only the binary and our own output — and **give it a positive
control**. `docs/over-decode-measure.md` + `crates/mosura/examples/over_decode.rs` are that
measure and are reusable: A1 non-executable decode, A2 offcut starts, A3 flow into
mid-instruction, A4 fixup target mid-instruction, A5 unreachable starts. Every corpus fixture
reports zero on all of them, so **a zero is indistinguishable from a broken tool** — hence
`--self-test`, which plants one violation per predicate and runs automatically before any
measurement. It doubles as a build identifier: the run that closed §6 printed `A1, A2, A3 …`,
which is how we knew it predated A4.

Corollaries learned the same way: **a DISTRIBUTION can be an artifact just as a count can** (the
51's "0 in open space" was the most convincing evidence on the track and was produced by the
classifier, not the binary), and **two people agreeing is not independent confirmation when both
are reasoning from the same derived summary**. Dump the bytes.


A before/after scan (candidate vs baseline) can only see **incremental** loss. Any defect present
on *both* sides is invisible to it, no matter how large. This is not a subtlety — it hid a
92-function call-dropping class for the whole campaign.

## The numbers (WAR2, 1286 functions, 2026-07-29)
Reference = **Ghidra's own per-function decompilation** of all 1286 (see
[[war2-per-function-ghidra-oracle]]), which is the right absolute reference:
- GHIDRA emits **3909** calls · mosura emits **3705** (**94.8%**)
- **mosura emits FEWER calls than Ghidra in 92 of 1286 functions — 246 calls missing**
- worst specimens: `0003dd60` Ghidra 31 → mosura 0 · `0006af2c` 18 → 1 · `00051298` 12 → 2
- the stack-pointer patch adds **12** more to that 246 (so ~5% worse, not negligible)

The differential scan had reported "5 functions, 23 calls" — it can only see *incremental* loss, so
the 92-function class already present on both sides was structurally invisible to it.

## ⚠️ A RETRACTED NUMBER — and why the reference matters more than the gauge
An earlier version of this note claimed **"455 functions, mosura emits 41% of the binary's calls,
~5,000 missing."** That was WRONG. It came from counting `call` mnemonics in an **objdump linear
sweep** of each function's bytes (8953), which decodes padding and inline data as instructions and
so wildly overstates the true call count. It was labelled an upper bound and then quoted as a
headline anyway.
**Lesson: "measure against the binary" is right, but a linear disassembly sweep is not a usable
proxy for the binary.** Use Ghidra's per-function output (now one command away) or hand-verified
disassembly. Cross-check any new gauge against a function you have verified BY HAND before quoting
it — `FUN_0001bd30` (Ghidra 4 calls, mosura 1) is the fixture that caught both counting bugs.

## Counting traps, both hit for real
1. **`extern` declarations match a call regex.** `extern int func_0x1ba38();` matches
   `func_0x[0-9a-f]+\s*\(` exactly like a call site does. Exclude lines starting with `extern`.
2. **An "own definition line" filter that allows leading whitespace eats CALL lines.** A filter like
   `^\s*\S[^;]*\bFUN_[0-9a-f]+\s*\(` matches every INDENTED line containing a `FUN_xxxx()` call,
   silently dropping most call sites — it reported Ghidra emitting 1 call for a function that
   emits 4. Require **column 0** (`not line[0].isspace()`) AND the function's OWN name.
3. **Linear sweep over raw bytes overcounts** — see the retraction above; don't use it at all.

## The worked example that proved it
`FUN_0001bd30` has 4 real calls (`0x1bc90`, `0x1ba38` in-loop, `0x1ec50`, `0x1ba38` tail).
**Baseline mosura emits 1** — the three loop-body CALLs are already destroyed, and the whole loop
body renders as a single assignment. With the stack-pointer patch it emits 0. The patch was blamed;
the patch contributed one of four.

Root shape (from the original bytes): `1bd43 mov [ebp-0xc],edx` (=0, prologue) then
`1bdaa mov [ebp-0xc],esi` — a **loop-carried write of a live value into the same slot** — then
`1bdb4 mov ebx,[ebp-0xc]` / `1bdb9 je`. The loop-carried store is dead in BOTH builds, so the slot's
loop-carried definition is missing; once stack recovery lets the LOAD resolve, it folds to the
prologue constant and the last branch is pruned.

## The rule
Per [[goal-is-the-binary-not-ghidra]], the binary is the authority. For any "did we lose real code?"
question, measure **absolutely** — emitted vs Ghidra's per-function output
([[war2-per-function-ghidra-oracle]], `scripts/ghidra-decompile-war2.sh --all`) or vs hand-verified
disassembly — never emitted vs the last build. Keep the differential scan too: it is the right tool
for ATTRIBUTION ("did this change cause it"), and useless for DETECTION.

Related: [[war2-stackptr-wrong-code]], [[print-raw-has-no-dead-filter]],
[[measurement-determinism-first]], [[numbers-stale-unless-sha-stamped]].
