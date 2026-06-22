> **Superseded** by [`port-plan.md`](port-plan.md) (the faithful-port plan). Kept for history — this describes the approximation-era feature work.

# Decompiler stage — port plan

Companion to [`testing-baseline.md`](testing-baseline.md). That doc covers stage 1b
(the SLEIGH engine: bytes → instructions + raw p-code), now **done** — 6 architectures
at 100% disasm+p-code. This doc plans **stage 4, the decompiler**: raw p-code → C.

The philosophy is unchanged: **Ghidra-as-golden-oracle, characterization testing,
bottom-up, ratchet-driven.** What makes it tractable is that Ghidra's decompiler is a
*pipeline of discrete transformations*, and `decomp_dbg` can dump the program state
after each — so every phase has its own oracle, exactly like disasm/p-code did.

---

## 1. Reference architecture (what we're porting)

Ghidra's decompiler (`Features/Decompiler/src/decompile/cpp`) runs an **ordered action
pipeline** over a `Funcdata` (one function). The `decompile` action group
(`coreaction.cc: ActionDatabase::buildDefaultGroups`) is, in order:

```
base → protorecovery → deindirect → localrecovery → deadcode →
typerecovery → stackptrflow → blockrecovery → stackvars → … → (emit C)
```

The transformations that matter, and their Ghidra owners:

| Phase | Ghidra | What it does |
|---|---|---|
| **IR + CFG** | `Funcdata`, `BlockBasic`, `PcodeOp`, `Varnode` | structured ops, basic blocks, edges |
| **Heritage (SSA)** | `ActionHeritage`, `Heritage` | dominator tree, phi (`MULTIEQUAL`) placement, varnode versioning |
| **Dead code** | `ActionDeadCode` | remove unreachable / unused varnodes & ops |
| **Simplification** | `ActionPool` + ~200 `Rule`s (`ruleaction.cc`) | constant folding, copy/algebraic propagation |
| **Type recovery** | `ActionInferTypes`, `TypeFactory` | int widths/signedness, pointers, structs |
| **Variable merge** | `Merge`, `HighVariable` | SSA varnodes → C variables |
| **Structuring** | `BlockGraph::collapse` (`block.cc`) | CFG → if/else/while/for/switch; `goto` for the rest |
| **C emission** | `PrintC` (`printc.hh`) | structured blocks + folded expressions → C text |

## 2. The oracle, per phase

`decomp_dbg` (already built by `scripts/setup-oracle.sh`) is a scriptable console; we
drive it with command files and capture stdout, the way `oracle/capture.cc` already does
for disasm/p-code. Relevant commands (`ifacedecomp.cc`):

| mosura phase | oracle command(s) |
|---|---|
| CFG | `graph controlflow`, `print tree block` (pre-structuring) |
| dominators | `graph dom` |
| SSA / data-flow | `print tree varnode`, `graph dataflow` |
| high variables | `print high` |
| structured blocks | `print tree block` (post-structuring) |
| final C | `decompile` then print |

**Intermediate-phase capture.** A full `decompile` shows only the *final* state. To get
a clean oracle for an *intermediate* phase, register a **partial action group** in a
small `decomp_dbg` script (the action DB already supports custom groups — cf. `firstpass`
= just `base`). E.g. a `base+heritage` group dumps SSA *before* simplification. This is
the one piece of new oracle tooling D0/D1 need.

## 3. mosura's pipeline & IR

```
raw p-code (stage 1b)
  → Funcdata { ops: Vec<PcodeOp>, vars, blocks }     # D0
  → CFG (BlockBasic + edges)                          # D0
  → SSA (dominators, phi, versioning)                 # D1
  → dead code + simplification rules                  # D2
  → high variables + types                            # D3
  → structured blocks                                 # D4
  → C (PrintC)                                         # D5
```

**Prerequisite refactor (D0):** stage 1b currently emits p-code as `Vec<String>`; `emu`
parses it back. The decompiler needs first-class `PcodeOp { seq, opcode, out:
Option<Varnode>, ins: Vec<Varnode> }` / `Varnode { space, offset, size }`. We add these
to the engine and keep a text renderer so the disasm/p-code goldens stay byte-exact; `emu`
then consumes the structured form directly (deleting its text parser).

## 4. Milestones

Each milestone is independently oracle-verifiable and adds a ratchet. **x86-64 first**
(82% of the datatest corpus), simplest functions first.

- ✅ **D0 — Structured IR + Funcdata + CFG. DONE.** `sleigh::pcode` (`Varnode`,
  `PArg`, `PcodeOp`) replaced the `Vec<String>` p-code; the engine emits structured
  ops + a text view, so the 254/254 disasm+p-code goldens stay byte-exact and `emu`
  dropped its text parser. `decomp::cfg` builds `Funcdata` (flattened op stream) +
  basic blocks (leaders at branch targets + post-control-flow ops) + succ/pred
  edges; `tests/decomp_cfg.rs` verifies a straight-line fn (no back-edge, RETURN
  block) and a loop (5 blocks, back-edge, all reachable). *Remaining: cross-check
  block boundaries against `graph controlflow` by extending `oracle/capture.cc`.*
- ✅ **D1 — Heritage (SSA). DONE.** `decomp::ssa`: Cooper–Harvey–Kennedy dominator
  tree, dominance frontiers, phi (`MULTIEQUAL`) placement at iterated frontiers, and
  Cytron renaming (`Funcdata::ssa(live_out)`) producing the reaching def of every
  heritaged use + filled phi args. `live_out` gives minimal return recovery (the
  return register is a synthetic use at `RETURN`). `tests/decomp_ssa.rs` checks the
  idom tree is rooted at entry and the loop-carried value flows through a phi.
  *Heritages register/unique; overlapping varnodes treated as distinct (correct
  per-location, refine for D3). Oracle cross-check vs `graph dom` deferred.*
- ✅ **D2 — Dead-code elimination DONE** (`decomp::simplify::dead_code`, mark-sweep
  over SSA def-use). Prunes the dead flag computations: `sem` 47→14 ops (result
  chain preserved via `live_out=RAX`), loop 65→20 (`CBRANCH` + its flags kept).
  *Remaining: the value-propagation `Rule`s (constant folding, copy propagation,
  `MULTIEQUAL`/`COPY` collapse) grow coverage-driven, oracle `print tree varnode`.*
- 🟡 **D3 — Variable merge + stack recovery (D3-lite + stack done).** (a) Loop-header
  phis grouped by `(space, offset)` so overlapping sub-registers (`EAX`/`RAX`)
  collapse to one variable. (b) **Stack-variable recovery** (`cfg::recover_stack`, a
  minimal `ActionStackPtrFlow`): `INT_ADD(RBP, k)` marks a unique as stack-slot `k`'s
  address; LOAD/STORE through it become COPY from/to a heritaged `stack` space, and
  the dead address arithmetic + prologue fall to DCE. So **`-O0` frames decompile** —
  `int f(int a,int b){return a+b;}` at `-O0` (params spilled to `[RBP-4]`/`[RBP-8]`)
  → `return param_2 + param_1;`. *Remaining: RSP-relative slots (no frame pointer),
  full byte-coverage `HighVariable`, non-int types; oracle `print high`.*
- 🟡 **D4 — Control-flow structuring. SELECT + IF + LOOPS done (loop-aware
  structurer).** `structure()` recurses over the CFG and emits, per block: `?:`
  ternary for a diamond `phi` (`phi_expr`); `if`/`else` for a `CBRANCH`; and at a
  self-loop header, a `do/while` via `loop_parts` — out-of-SSA (phis → vars, init
  from the pre-header arg, update from the back-edge), parallel-copy sequentialization
  (`order_updates`), update-substitution so the condition/return use post-update
  values, then it continues structuring the exit. A **guarded `while`** (gcc rotates
  `while(n>0){…}` into `if(n>0) do{…}while(…) else return 0`) recovers cleanly. Five
  shapes decompile exactly: straight-line, `?:`, `if`/`else`, do-while, guarded
  while. Condition rules normalize the full signed set + `x&x`, `0!=cmp`, `a<=b`.
  Sub-register return overlap handled by trying `EAX` then `RAX` (`ret_def`).
  **General `while` loops also done** — a single back-edge `latch→header` with the
  condition at the header (`H≠L`) emits `while (cond) { updates }` (no subst, cond over
  pre-update values, continue-edge by reachability to the latch); a `-O0`
  `for(i=0;i<n;i++) s+=i` over stack variables recovers exactly. *Remaining: loop
  bodies with side effects (a call/store statement, e.g. `forloop1`'s `printf`) need
  per-block statement emission; nested loops; oracle `print tree block`.*
- 🟡 **D5 — C emission. THIN SLICE DONE.** `decomp::cprint` folds a straight-line
  single-`RETURN` function's SSA into C expressions (transparent casts, constant
  folding, starter identities `x*1`/`x+0`/`x>>0`) and emits it. End-to-end, `sem`
  (bytes → C) yields `return ((-5 + (param_1 + (param_1 * 2))) + (param_2 >> 2))` —
  **semantically exact** to `a*3+(b>>2)-5`. And a CMOV conditional `pick(a,b)` →
  `return ((param_1 < param_2) ? (param_1 + 1) : (param_2 + param_2))` — ternary
  recovered, signed-less flag idiom (`SBORROW(a,b) != ((a-b)<0)`) normalized to
  `a < b`, negated-ternary swapped (`cprint::simplify`). Both in
  `tests/decomp_emit.rs`. *Remaining: statement structuring (D4) for branchy/loopy
  functions, declarations, and the `tree-sitter-c` structural comparator to score
  the datatest stringmatches; residual algebra (`a+a*2`→`a*3`) is more D2 rules.*
- **D6 — Iterate to parity.** Deeper types (structs/arrays/prototypes), more rules, more
  arches → drive `EXPECTED_DATATEST_PASS` toward the oracle's **599**.

**Thin vertical slice.** After D1, push the *simplest* datatest end-to-end through
stub D2–D5 (no rules, trivial structuring, minimal emit) to validate the whole pipeline
early; then deepen each phase. Avoids a big-bang integration at D5.

## 5. C comparison mode (decision needed)

The datatest goldens are exact-text `<stringmatch>` substring assertions written against
Ghidra's C (with its variable names), but decompiled C varies in naming and whitespace, so
exact text is the wrong bar (consistent with `testing-baseline.md` §6, which already chose
*structural* equivalence).

**DECIDED (2026-06-21): structural AST comparison.** Parse mosura's C and compare its
structure (control flow + expression trees) against each assertion **modulo identifier
names / whitespace / braces** — PASS if isomorphic. The rejected alternatives were
token-stream normalization (cheaper, weaker — brace/ordering false-fails) and exact-text
(only carries trivial functions).

**Use an existing Rust C parser — don't hand-roll** (user steer, 2026-06-21). Candidates:
- **`tree-sitter` + `tree-sitter-c`** — robust, error-tolerant CST; forgiving of Ghidra's
  C dialect (`undefined4`, `uVar1`, casts); easy to walk for a name-insensitive structural
  compare. *Leaning this way* for robustness.
- **`lang-c`** — pure-Rust C11 typed AST; cleaner tree but stricter (may need Ghidra's
  synthetic types pre-declared).

Final pick is deferred to D5 (build-when-needed); the comparator wraps whichever crate
behind a `c_ast::structurally_eq(a, b)` so the choice stays swappable.

## 6. Decisions to confirm

1. **Structured-p-code refactor now (D0).** Replace `Vec<String>` p-code with
   `PcodeOp`/`Varnode`; keep a text renderer for existing goldens. *(Recommended — it's a
   hard prerequisite and also cleans up `emu`.)*
2. **Foundation-first + thin slice**, not pure bottom-up: solidify IR/CFG/SSA (D0–D1)
   against oracle dumps, then a minimal end-to-end slice, then deepen. *(Recommended.)*
3. **Per-phase oracle via `decomp_dbg` partial action groups** (new harness tooling in
   D0). *(Recommended.)*
4. **C parity = structural AST comparison** (§5), not exact text. **DECIDED 2026-06-21.**
5. **Scope order:** x86-64 datatests first, simplest first; defer non-covered arches
   (Toy/8051/68000) and deep type recovery to D6.

## 7. Risks

- **SSA + structuring are the hard cores** — get them oracle-exact before emission, or C
  diffs become un-debuggable.
- **The rule set is unbounded** (~200 rules) — treat like stage-1b features: add only what
  a failing datatest needs, log what's deferred, never silently approximate.
- **Type recovery is deep** — start shallow (sizes/pointers); structs/arrays are D6.
- **First green datatest is at D5** — the thin slice mitigates integration risk.