# Switch / jump-table recovery — port plan

Recover `switch` statements from indirect jumps. The 5 switch datatests (switchind,
switchhide, switchmulti, ifswitch, switchloop) score ~0.36–0.50: mosura lifts the
`BRANCHIND` but treats it as a CFG dead-end, so the entire switch body is dropped (e.g.
switchind emits the prologue + the call *after* the switch, and nothing in between).
Ghidra recovers `switch(x){ case 0: …; case 1: …; }`.

## Reference architecture (Ghidra `jumptable.cc`, ~2,861 lines)

The pipeline, given a `CPUI_BRANCHIND` op:

1. **Recover the address table.** A `JumpModel` matches the index→target computation and
   produces the list of case target addresses:
   - `JumpModelTrivial` — a tiny direct table.
   - `JumpBasic` — the common form: `target = *(table_base + index*ptrsize)` with a guard
     `if (index <= maxcase)`; recovers `table_base`, the index Varnode, and the bounds.
   - `JumpBasic2` / `JumpBasicOverride` / `JumpAssisted` — variants (offset tables,
     overridden, compiler-assisted).
   - The recovery **emulates** the index→target expression with `EmulateFunction`
     (`executeLoad`/`executeBranchind`/`getVarnodeValue`) over each index value
     `0..maxcase`, **reading the jump table out of the binary image** — so it needs the
     loaded bytes (the datatest `<bytechunk>`).
2. **`sanityCheck`** the recovered addresses (in-range, land on instruction starts).
3. **`recoverLabels`** — map each table slot back to its case value(s) (incl. the
   `case 4: case 5: case 10:` fall-through grouping and `default`).
4. **CFG** — wire the `BRANCHIND` block to all recovered targets (mosura's `cfg.rs`
   currently gives `BRANCHIND` no successors — `is_branch`/edge wiring needs the table).
5. **Structuring** — `BlockSwitch` (`blockaction.cc`): collapse the multiway region into
   a switch node; PrintC emits `switch(x){case N: … break/return; default: …}`.

## mosura's substrate

- `BRANCHIND` is lifted (switchind has exactly 1). `cfg.rs` wires edges per opcode —
  `BRANCHIND` → none today.
- mosura has no emulator over the structured SSA (the `sleigh::emu` p-code interpreter is
  text/line based and separate); the table recovery needs index→address evaluation with
  access to the binary bytes (available via the `Funcdata` bytes / the datatest chunk).
- Structuring lives in `cprint::structure`/`loop_parts`; a switch node is a new shape.

## Milestones

- **S1 — table recovery (JumpBasic). ✅ DONE** (`decomp::jumptable`). `recover(fd, ssa,
  image, indop)` traces the `BRANCHIND` target on the SSA — `target = (base +) sext(*(base
  + index*esize))`, both absolute and table-relative forms — reads the table out of the
  image (the datatest chunks), and returns the index `Def` + the case target addresses.
  Tested: switchind's 11 targets recovered exactly. Foundation — no score movement yet
  (that is S2+S3).
- **S2 — CFG edges. ✅ DONE.** `Funcdata::build_image` takes the whole binary image,
  recovers jump tables on a scratch SSA, adds the targets as block leaders, and wires the
  `BRANCHIND`→targets edges (`cut_and_wire`). Only for loop-free functions — a switch in
  a loop keeps its old CFG (the cyclic case bodies aren't structurable yet).
- **S3 — switch structuring + emission. ✅ DONE.** `Stmt::Switch` + `decompile_switch`:
  the prologue, then a case per distinct target block (case values grouped; the most-
  shared target is the `default`); each case body is its side effects + terminator.
  ifswitch 0.36→0.88, switchind 0.46→0.62, switchhide ↑; corpus 0.684→0.698, 25→26.
  KNOWN: case calls carry a spurious stale-RSP arg (Ghidra has none — prototype/arg
  recovery); a case target mosura's linear disasm mis-aligns on is dropped (e.g.
  switchind's case 4/5/10 at the 16-byte-aligned 0x100048).
- **S4 — variants.** `JumpBasic2`/offset tables/`switchhide` (the hidden/guarded forms),
  `ifswitch` (a switch lowered partly to if-chains), `switchloop` (switch in a loop).

## Risks / order

- S1 is the bulk: the table-recovery + emulation + reading the image. It is self-contained
  (a recognizer over SSA + a table read), in the style of `divrecover` but bigger.
- Reading the jump table requires the binary bytes at the table address — confirm the
  datatest `<bytechunk>` covers the `.rodata` table (it should; the addresses are in the
  image). If a table lives outside the chunk, that datatest can't be recovered offline.
- Unlike array indexing, this is a clean Ghidra-matching gain (no out-correcting trap).
- Comparator note: a recovered `switch`/`case` skeleton is high-value structurally (the
  `switch`/`case`/`break` keywords are kept), so S1–S3 should move the 5 datatests well.
