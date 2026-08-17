//! C emission — Ghidra's `PrintC` (`printc.cc`). Walks the structured-block tree
//! ([`structure`](super::structure)), renders each op as a C expression (inlining
//! single-use values, naming the [`merge`](super::merge) HighVariables), and emits
//! statements + control flow.
//!
//! This increment handles expressions, variable naming, the function signature, and the
//! linear case (basic blocks / lists). Structured control flow (`if`/`while`) emission,
//! casts, and faithful types are the next increments. The return value is located
//! heuristically (the last write to a return register) until P6 ActionReturnRecovery wires
//! it to RETURN.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use super::block::BlockId;
use super::emit::{EmitChoices, ReturnWidth};
use super::funcdata::Funcdata;
use super::merge::HighVariables;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::Address;
use super::structure::{structure, FlowKind, GotoRecord, Structured};
use super::types::Datatype;
use super::varnode::VarnodeId;

/// The exit basic block of a structured block (where its terminating CBRANCH lives).
fn exit_basic(s: &Structured, idx: usize) -> Option<BlockId> {
    match &s.blocks[idx].kind {
        FlowKind::Basic(b) => Some(*b),
        _ => exit_basic(s, *s.blocks[idx].components.last()?),
    }
}

/// The entry basic block of a structured block (where a case/label starts).
fn entry_basic(s: &Structured, idx: usize) -> Option<BlockId> {
    match &s.blocks[idx].kind {
        FlowKind::Basic(b) => Some(*b),
        _ => entry_basic(s, *s.blocks[idx].components.first()?),
    }
}

/// Whether a short-circuit operand is an oriented leaf — a basic-block leaf whose terminating CBRANCH
/// was oriented (`fallthru_true`) by the branch-negation stage (Ghidra `BlockCondition::negateCondition`
/// distributed the NOT to it), so its negation is materialized positive in the IR and it prints
/// directly. A nested compound returns false (its own leaves are flipped recursively). The compound
/// analogue of [`Structured::is_oriented`], read at print to XOR the pending negation off the leaf.
fn operand_oriented(f: &super::funcdata::Funcdata, s: &Structured, idx: usize) -> bool {
    if matches!(s.blocks[idx].kind, FlowKind::CondAnd | FlowKind::CondOr) {
        return false;
    }
    exit_basic(s, idx)
        .and_then(|bid| {
            f.block(bid).ops.iter().rev().copied().find(|&op| f.op(op).code() == OpCode::Cbranch)
        })
        .is_some_and(|cbr| f.op(cbr).is_fallthru_true())
}


/// Ghidra `CastStrategyC::isSubpieceCast` (`cast.cc`): a SUBPIECE prints as a C truncation cast
/// `(outtype)x` (rather than the functional `SUB<n><m>(x,off)`) exactly when it slices at offset 0
/// and both operands are scalar — input `int`/`uint`/`unknown`/`pointer`, output additionally
/// allowing `float`. Keyed purely on the type metatypes: Ghidra never consults the nonzero-mask or
/// how wide the value is actually used (mosura's former `effective_width` gate did, a non-faithful
/// adaptation that suppressed the cast whenever the used width already fit the slice).
fn is_subpiece_cast(outtype: &Datatype, intype: &Datatype, offset: u64) -> bool {
    if offset != 0 {
        return false;
    }
    if !matches!(
        intype,
        Datatype::Int(_) | Datatype::Char | Datatype::Uint(_) | Datatype::Unknown(_) | Datatype::Pointer(..)
    ) {
        return false;
    }
    if !matches!(
        outtype,
        Datatype::Int(_) | Datatype::Char | Datatype::Uint(_) | Datatype::Unknown(_) | Datatype::Pointer(..) | Datatype::Float(_)
    ) {
        return false;
    }
    if let Datatype::Pointer(insz, _) = intype {
        if let Datatype::Pointer(outsz, _) = outtype {
            if outsz < insz {
                return true; // Cast from far pointer to near pointer
            }
        }
        if !(outtype.is_int_meta() || matches!(outtype, Datatype::Uint(_))) {
            return false; // other casts don't make sense for pointers
        }
    }
    true
}

/// The 64-bit name of an x86-64 integer register by offset (for `extraout_*` etc.).
fn reg64_name(offset: u64) -> Option<&'static str> {
    Some(match offset {
        0x0 => "RAX",
        0x38 => "RDI",
        0x30 => "RSI",
        0x10 => "RDX",
        0x08 => "RCX",
        0x80 => "R8",
        0x88 => "R9",
        _ => return None,
    })
}

struct PrintC<'a> {
    f: &'a Funcdata,
    h: HighVariables,
    names: HashMap<u32, String>,
    reg_space: Option<super::space::SpaceId>,
    ram_space: Option<super::space::SpaceId>,
    stack_space: Option<super::space::SpaceId>,
    /// The recovered `ScopeLocal` stack-symbol layout (`varmap::recover_scope`), computed once. Ghidra's
    /// `TypeSpacebase`/`opPtrsub` naming resolves a `PTRSUB(RSP, off)` against this symbol table.
    stack_syms: Vec<super::varmap::StackSymbol>,
    /// `(frame offset, width)` of symbols already emitted as a declaration, so a symbol referenced by
    /// many `PTRSUB`s (and/or a direct `stack`-space varnode at the same slot) is declared exactly
    /// once — keyed by width too, so two differently-sized slots at one offset (a `recover_stack`
    /// granularity artefact, e.g. stackreturn's 8- and 4-byte `-0x10` slots) stay distinct.
    stack_declared: std::collections::HashSet<i64>,
    var_counter: u32,
    ret_val: Option<VarnodeId>,
    /// WhileDo block index → (initializer value, iterator op, loop variable) for `for`-loops.
    for_loops: HashMap<usize, (Option<VarnodeId>, OpId, VarnodeId)>,
    /// Ops emitted in a `for` header (initializer/iterator) — suppressed in their block.
    suppressed: HashSet<OpId>,
    /// Pointer base → element size, for bases accessed uniformly as an array (so the access
    /// renders `base[i]`). Non-uniform bases (struct-like) are absent and stay `*(base+k)`.
    array_elem: HashMap<VarnodeId, u32>,
    /// The unstructured branches cut by the collapse driver, keyed by the source basic block
    /// whose exit emits them (in insertion = cut order).
    gotos: HashMap<BlockId, Vec<GotoRecord>>,
    /// Basic blocks that are goto targets (emitted with a label).
    labels: HashSet<BlockId>,
    /// Local variable declarations `(name, type, stack_offset)`, collected as names are assigned and
    /// emitted at the top of the body in Ghidra's declaration order. Ghidra `emitScopeVarDecls`
    /// (printc.cc:2265) walks the ScopeLocal symbol map, which is keyed by storage Address, so stack
    /// locals declare in ascending-address order (most-negative frame offset first). `stack_offset`
    /// is the signed frame offset for a `stack` local, `None` for a register/temp local; the emit
    /// sort orders stack locals by it. (No corpus fixture mixes register and stack locals in one
    /// decl block, so register-vs-stack precedence is unexercised; register temps keep first-use
    /// order via the stable sort.)
    decls: Vec<(String, Datatype, Option<i64>)>,
    /// Per-varnode: is this a register value written into an addrtied stack slot across a call (the
    /// input of an INDIRECT whose output is the slot)? Such a value is *explicit* — Ghidra renders
    /// the write to the addrtied variable even though the value is computed in a register merged
    /// into the slot (the memory-increment `iStack_NN = iStack_NN + 1`).
    slot_write: Vec<bool>,
    /// HighVariable representative → the frame offset of its `stack` member, so every member of the
    /// HighVariable (including merged register versions) is named `xStack_NN` by that offset.
    high_stack_off: HashMap<u32, u64>,
    /// HighVariable representative → the `ram` address of its global member, so a value merged into
    /// a global's HighVariable (e.g. `iRam.. = COPY(param_1 + 1)` after `merge_copy`) is named and
    /// materialized by that global's address `iRam<addr>` — the ram analogue of `high_stack_off`.
    high_ram_off: HashMap<u32, u64>,
    /// The stack space's address size in bits minus one — the sign bit a raw `stack` offset is
    /// extended from to get a FRAME offset (Ghidra `sign_extend(start, addr.getAddrSize()*8-1)`,
    /// varmap.cc:557). On a 32-bit target a frame slot's raw offset is the wrapped `0xffffffdc`, not
    /// `-0x24`; without the extension nothing matches the recovered symbol cover.
    stack_sign_bit: u32,
    /// Frame offset → name for a slot that the recovered `ScopeLocal` cover does NOT contain. Ghidra
    /// always has a Symbol here (`ScopeLocal` covers everything it gathered) and names it once; this
    /// memo keeps mosura's uncovered slots to ONE name each, so the declaration site and every
    /// reference cannot disagree the way two independent print-time synthesizers did.
    unmapped_stack_names: HashMap<i64, String>,
    /// Varnodes forced explicit (named, not inlined) regardless of use count — the recovered
    /// stack-array base varnodes, so a single-use base still renders by its array name (`axStack_98`)
    /// instead of via its address-computation (`&xStack_98`).
    force_explicit: HashSet<VarnodeId>,
    /// Recovered-parameter storage → 1-based parameter index, from the faithful prototype recovery
    /// (`fspec::recover_input_params`, Ghidra `ActionInputPrototype`/`fillinMap`). An input Varnode
    /// at one of these locations names `param_N`. This is XMM-aware (a `float8` in `XMM0` is a real
    /// parameter), unlike the old GP-only register table, and carries the convention's ordering.
    param_index: HashMap<Address, u32>,
    /// Frozen HighVariable representative per Varnode (`high_of[v] = h.high(v)` snapshot), so the
    /// `&self` explicitness test can compare two Varnodes' HighVariables without the `&mut` the
    /// union-find `high()` needs. Used by [`Self::is_explicit`]'s cross-high COPY arm.
    high_of: Vec<u32>,
    /// HighVariable representative → its member Varnodes (the frozen [`Self::high_of`] classes).
    high_members: HashMap<u32, Vec<VarnodeId>>,
    /// Ops marked non-printing by Ghidra's `ActionCopyMarker` (shadow assignments and redundant
    /// COPYs), frozen in-pipeline by [`super::merge::ActionCopyMarker`] at Ghidra's slot. Consumed,
    /// never re-derived — the marks and the Covers behind them are decided before any CAST exists.
    nonprinting: &'a HashSet<OpId>,
    /// Ghidra's `comma_separate` print modifier (`PrintLanguage::modifiers`, printlanguage.hh:154 —
    /// "Statements within condition"). While set, a block's statements are emitted INSIDE the
    /// enclosing parentheses: joined by `, ` with no line break (`PrintC::emitBlockBasic`,
    /// printc.cc:2707/2716) and with no terminating `;` (`PrintC::emitStatement`, printc.cc:2291).
    /// Set/cleared around a condition-block emit exactly where Ghidra does `pushMod();
    /// setMod(comma_separate); … popMod();`.
    comma_separate: bool,
}

impl PrintC<'_> {
    fn type_of(&self, v: VarnodeId) -> Datatype {
        // A varnode's type is its inferred HighVariable type — the same value Ghidra's prototype
        // recovery reads (`FuncProto::updateInputTypes`/`updateOutputTypes`, fspec.cc:4076/4159:
        // `vn->getHigh()->getType()`) and the C printer declares for the symbol. Ghidra applies no
        // downgrade to `undefined` for stripped binaries — an int/uint that inference recovers stays
        // int/uint (naming a variable `iVar`/`uVar`, and avoiding the spurious `(int4)` cast that a
        // `undefined`-typed symbol would need when widened). Absent inference gives `undefined<N>`.
        // Ghidra reads the *variable's* type here (`vn->getHigh()->getType()`), not the type
        // propagation committed onto the one Varnode — a C declaration names a variable. That is the
        // frozen high-facing channel; see `merge::FrozenHighs::type_of`.
        super::merge::high_type_read_facing(self.f, v)
    }

}

impl<'a> PrintC<'a> {
    /// Whether a varnode is printed as its own named variable (vs inlined into its use).
    ///
    /// The Ghidra chain (`ActionMarkExplicit::baseExplicit` + `ActionMarkImplied`,
    /// coreaction.cc:3007/3416) lives in [`super::merge::explicit_leading`] /
    /// [`super::merge::explicit_trailing`], shared with the merge-time classifier that gates the
    /// COPY/speculative merges (`mergeTestBasic`). The arms here are printc-only additions layered
    /// on that core — each only ADDS explicitness, so merge-explicit ⊆ print-explicit and every
    /// value the merge left un-merged materializes in the output.
    fn is_explicit(&self, v: VarnodeId) -> bool {
        let vn = self.f.vn(v);
        if vn.is_constant() {
            return false;
        }
        // A Varnode created AFTER the classification froze — the uniques `ActionSetCasts` introduces
        // when it rewires an op's output through a CAST — was never seen by `ActionMarkImplied`.
        // Ghidra's `setImplied()` at that point (coreaction.cc:2594) is FINAL: `ActionMarkExplicit`
        // ran at 5719 over the pre-cast graph, `ActionSetCasts` is 5735, and nothing re-derives
        // explicitness afterwards. Its own flag is therefore the whole answer, and the recomputed
        // chain below must not override it — `explicit_leading`'s `def->isCall()` arm
        // (Ghidra `baseExplicit`, coreaction.cc:3015) is right for a REAL call output but must not
        // claim the synthetic unique that a cast on a call's result leaves the call writing, or the
        // call renders twice: once as its own statement and again inlined into the cast.
        //
        // This is an early exit, not a reordering: the arms below keep their exact relative order, so
        // the `explicit_leading` copymarker `Some(false)` case still short-circuits ahead of
        // `high_ram_off` as documented there. The two paths are disjoint — a post-freeze Varnode is a
        // fresh unique, never addrtied, never a SUBPIECE of an addrtied whole.
        if self.f.classified_upto.is_some_and(|n| v.0 as usize >= n) {
            return vn.is_explicit();
        }
        // a recovered stack-array base is always named (even single-use) so it renders `axStack_98`
        if self.force_explicit.contains(&v) {
            return true;
        }
        // A register value written into an addrtied stack slot across a call — Ghidra materializes
        // the write to the addrtied variable, so the producing op renders as `xStack_NN = …` at its
        // natural position, even when the value is computed in a register merged into the slot (the
        // memory-increment `iStack_NN = iStack_NN + 1`).
        if self.slot_write[v.0 as usize] {
            return true;
        }
        // input / addrtied (with the SUBPIECE-of-addrtied internal-copymarker sub-case). This leading
        // chain is CAST-INVARIANT (constant/input/addrtied structure, not use-counts) and its
        // `Some(false)` copymarker case must short-circuit before `high_ram_off` (revisit's
        // `iRam.._2_2_` high-piece), so it stays computed here rather than frozen.
        if let Some(e) = super::merge::explicit_leading(self.f, v) {
            return e;
        }
        // A value merged into a global's HighVariable is that global (Ghidra `baseExplicit`'s
        // `numInstances() > 1` rule for the addrtied case): it materializes the store `iRam.. = ..`
        // and must not be inlined into the hidden same-high COPY that carries it there.
        if self.high_ram_off.contains_key(&self.high_of[v.0 as usize]) {
            return true;
        }
        // The TRAILING classification chain (written/marker/use-count + `checkImpliedCover`) is the
        // cast-sensitive part; it is now FROZEN on the pre-cast graph by `super::merge::ActionMarkImplied`
        // and read from the flag, so the CAST ops `ActionSetCasts` inserts don't perturb the
        // use-count/cover classification (Ghidra order: markImplied 5720 < setCasts 5735). A CAST
        // output setcasts creates is `setImplied` at creation, so it reads implied here.
        vn.is_explicit()
    }

    /// Ghidra `PcodeOp::isMoveable` (op.cc:178): can `op` be moved down in its block to just
    /// before `point` without changing meaning? Mirrors Ghidra's checks: special ops other than
    /// LOAD don't move; same block only; the output may not be read before `point`; walking the
    /// intervening ops — INDIRECT passes through, STORE blocks a moving LOAD / address-tied
    /// operands, CALLs block unless the op touches no address-tied or persistent storage, any
    /// other special op blocks; and an intervening def may not overlap an address-tied input.
    fn is_moveable(&self, op: OpId, point: OpId) -> bool {
        if op == point {
            return true; // no movement necessary
        }
        let f = self.f;
        let special = |o: OpId| {
            matches!(
                f.op(o).code(),
                OpCode::Load
                    | OpCode::Store
                    | OpCode::Branch
                    | OpCode::Cbranch
                    | OpCode::Branchind
                    | OpCode::Call
                    | OpCode::Callind
                    | OpCode::Callother
                    | OpCode::Return
                    | OpCode::Indirect
                    | OpCode::Multiequal
            )
        };
        let mut moving_load = false;
        if special(op) {
            if f.op(op).code() == OpCode::Load {
                moving_load = true; // LOAD moves with additional restrictions
            } else {
                return false; // don't move special ops
            }
        }
        if f.op(op).parent.is_none() || f.op(op).parent != f.op(point).parent {
            return false; // not in the same block
        }
        let parent = f.op(op).parent.expect("checked");
        let ops = &f.block(parent).ops;
        let Some(opos) = ops.iter().position(|&o| o == op) else { return false };
        let Some(ppos) = ops.iter().position(|&o| o == point) else { return false };
        if ppos < opos {
            return false;
        }
        // The output cannot move past an op that reads it.
        if let Some(out) = f.op(op).output {
            for &read in &f.vn(out).descend {
                if f.op(read).parent != Some(parent) {
                    continue;
                }
                if ops.iter().position(|&o| o == read).is_some_and(|rp| rp <= ppos) {
                    return false; // read before (or at) `point`
                }
            }
        }
        // Crossing a CALL is allowed only for a normal op touching no address-tied or
        // persistent storage.
        let not_tied = |v: VarnodeId| !f.vn(v).is_addrtied() && !f.vn(v).is_persist();
        let cross_calls = !special(op)
            && f.op(op).output.is_some_and(not_tied)
            && (0..f.op(op).num_inputs())
                .all(|i| f.op(op).input(i).is_some_and(|v| f.vn(v).is_constant() || not_tied(v)));
        let tied_list: Vec<VarnodeId> = (0..f.op(op).num_inputs())
            .filter_map(|i| f.op(op).input(i))
            .filter(|&v| f.vn(v).is_addrtied())
            .collect();
        let overlaps = |a: VarnodeId, b: VarnodeId| {
            let (va, vb) = (f.vn(a), f.vn(b));
            va.loc.space == vb.loc.space
                && va.loc.offset < vb.loc.offset + vb.size as u64
                && vb.loc.offset < va.loc.offset + va.size as u64
        };
        for &op2 in &ops[opos + 1..=ppos] {
            if special(op2) {
                match f.op(op2).code() {
                    OpCode::Load => {
                        if f.op(op).output.is_some_and(|o| f.vn(o).is_addrtied()) {
                            return false;
                        }
                    }
                    OpCode::Store => {
                        if moving_load || !tied_list.is_empty() {
                            return false;
                        }
                        if f.op(op).output.is_some_and(|o| f.vn(o).is_addrtied()) {
                            return false;
                        }
                    }
                    OpCode::Indirect => {} // let through
                    OpCode::Call | OpCode::Callind => {
                        if !cross_calls {
                            return false;
                        }
                    }
                    _ => return false,
                }
            }
            if let Some(out2) = f.op(op2).output {
                if moving_load && f.vn(out2).is_addrtied() {
                    return false;
                }
                if tied_list.iter().any(|&v| overlaps(v, out2)) {
                    return false;
                }
            }
        }
        true
    }

    /// Ghidra `PrintC::pushPartialSymbol` (printc.cc:1947) → `PrintLanguage::unnamedField`
    /// (printlanguage.cc:719): a `VariablePiece` that does not span its `VariableGroup` is not a
    /// variable of its own — it renders off the name of the piece that spans the group.
    ///
    /// `allow_cast` is Ghidra's parameter of the same name. With it set, a piece starting at the
    /// group's own offset is a truncation Ghidra writes as a cast (`CastStrategyC::isSubpieceCast`,
    /// cast.cc:411, which accepts offset 0 and nothing else); otherwise the piece renders as the
    /// artificial field `._<off>_<size>_`. The plain variable-occurrence path passes `false`
    /// (printc.cc:1886) — which is what an assignment target is, and a cast is not an lvalue.
    ///
    /// Returning `Some` also keeps the piece out of `decls`: the group is one declared variable.
    fn partial_symbol(&mut self, v: VarnodeId, allow_cast: bool) -> Option<String> {
        let pieces = self.f.highs.as_ref().map(|h| h.pieces())?;
        let (_, off, size) = pieces.at(v)?;
        if pieces.spans_group(v) {
            return None;
        }
        let base = pieces.group_base(v)?;
        if base == v {
            return None;
        }
        let ty = self.type_of(v).name();
        let base_name = self.name_of(base);
        Some(if off == 0 && allow_cast {
            format!("({ty}){base_name}")
        } else {
            format!("{base_name}._{off}_{size}_")
        })
    }

    /// [`Self::name_of`] for an assignment target: a partial symbol renders without the cast form,
    /// as Ghidra's plain variable-occurrence path does (`allowCast=false`, printc.cc:1886).
    fn lvalue_of(&mut self, v: VarnodeId) -> String {
        self.partial_symbol(v, false).unwrap_or_else(|| self.name_of(v))
    }

    /// The name of `v`'s variable, assigning one on first use.
    fn name_of(&mut self, v: VarnodeId) -> String {
        let vn = self.f.vn(v);
        let is_reg = Some(vn.loc.space) == self.reg_space;
        if vn.is_input() {
            if let Some(&n) = self.param_index.get(&vn.loc) {
                return format!("param_{n}");
            }
        }
        // A HighVariable containing a parameter's input instance IS that parameter — Ghidra names
        // the HighVariable (the input instance attaches the param symbol to the whole variable),
        // not each Varnode. Without this, a phi merged with its param initializer splits into two
        // names with no connecting assignment (switchloop's accumulator: `uVar2` read-uninitialized
        // while `param_1` goes unused).
        if let Some(members) = self.high_members.get(&self.high_of[v.0 as usize]) {
            for &m in members {
                let mv = self.f.vn(m);
                if mv.is_input() {
                    if let Some(&n) = self.param_index.get(&mv.loc) {
                        return format!("param_{n}");
                    }
                }
            }
        }
        // Ghidra `PrintC::pushPartialSymbol` (printc.cc:1947) → `PrintLanguage::unnamedField`
        // (printlanguage.cc:719): a `VariablePiece` that does not span its `VariableGroup` is not a
        // variable of its own. It renders off the group's base name — as a truncating cast when it
        // starts at the group's own offset (`CastStrategyC::isSubpieceCast`, cast.cc:411, which
        // accepts offset 0 only), and as the artificial field `._<off>_<size>_` otherwise. Returning
        // here also keeps the piece out of `decls`: the group is one declared variable, not three.
        if let Some(s) = self.partial_symbol(v, true) {
            return s;
        }
        // A direct global — a constant-address access in `ram` — is named by its address:
        // Ghidra `ScopeInternal::buildVariableName`'s persist branch (database.cc:2455), the type's
        // `printNameBase` stem + the capitalized space name + the address.
        //
        // This DELEGATES rather than formatting here, and the delegation is the fix: the field width
        // is `2*addr.getAddrSize()` (:2466) — 16 on an 8-byte ram space, 8 on a 4-byte one — and this
        // site hardcoded 16, which is right on x86-64 by coincidence and wrong on every 32-bit
        // target. `varmap::build_internal_variable_name` is the SAME Ghidra function, already ported
        // for the stack space and already reading the width off the space. The faithful mechanism was
        // in the tree the whole time, so the correction is a deletion, not a second implementation.
        if Some(vn.loc.space) == self.ram_space {
            let ty = self.type_of(v);
            return super::varmap::build_internal_variable_name(&self.f.spaces, vn.loc.space, vn.loc.offset, &ty);
        }
        // a value merged into a global's HighVariable (e.g. the `param_1 + 1` that `merge_copy`
        // unified with `iRam..`) is named by that global's address, too.
        if let Some(&off) = self.high_ram_off.get(&self.h.high(v)) {
            if let Some(ram) = self.ram_space {
                let ty = self.type_of(v);
                return super::varmap::build_internal_variable_name(&self.f.spaces, ram, off, &ty);
            }
        }
        // A register value CREATED by a call side effect (an INDIRECT whose output carries the
        // `indirect_creation` flag) is Ghidra's `extraout_<reg>` (database.cc:2492 —
        // `(flags & Varnode::indirect_creation) != 0`). A value merely RELAYED across the call by
        // an INDIRECT (its input is the live pre-call value) is NOT a creation and is named as an
        // ordinary local/merged variable, NOT `extraout_`. Gating on the same `is_indirect_creation`
        // predicate ported at 804d274 (Ghidra's TypeOpIndirect creation guard) keeps a relayed
        // pointer (e.g. a stack base carried in a register across a call) from mis-rendering as an
        // artifact register.
        if is_reg && vn.is_indirect_creation() {
            if let Some(def) = vn.def {
                if self.f.op(def).code() == OpCode::Indirect {
                    if let Some(r) = reg64_name(vn.loc.offset) {
                        return format!("extraout_{r}");
                    }
                }
            }
        }
        let id = self.h.high(v);
        if let Some(n) = self.names.get(&id) {
            return n.clone();
        }
        // Ghidra names an ordinary local `<printNameBase>Var<index>` — `ScopeInternal::
        // buildVariableName`'s final branch (database.cc:2517: `ct->printNameBase(s); s << "Var" <<
        // dec << index++;`). The stem is `Datatype::printNameBase` (type.hh:273), which PREPENDS `p`
        // per pointer level (:424) and `a` per array level (:457) and then RECURSES into what is
        // pointed at, so a `char *` local is `pcVar1` and a `uint *` local is `puVar1`. A local in the
        // recovered `stack` space is named by its frame offset (`xStack_28`) instead of a running
        // counter.
        let ty = self.type_of(v);
        let prefix = ty.print_name_base();
        // Name by the frame offset when this varnode is (or is merged with) a `stack` slot, so a
        // register version merged into the slot shares the slot's `xStack_NN` name.
        let stack_off = self
            .high_stack_off
            .get(&id)
            .copied()
            .or_else(|| (Some(vn.loc.space) == self.stack_space).then_some(vn.loc.offset));
        if let Some(off) = stack_off {
            let foff = self.frame_off(off);
            // Ghidra drives ALL stack naming off the recovered `ScopeLocal` symbol table (`opPtrsub`).
            // A direct `stack`-space slot that falls inside a recovered ARRAY is that array's element
            // `axStack_<start>[index]` (the array, not a per-slot scalar, is declared) — the same
            // symbol a `PTRSUB` to this address resolves to, so the two views share one declaration.
            if let Some(sym) = self.spacebase_sym_at(foff) {
                if let Some((_, index)) = sym.array_index(foff) {
                    self.declare_stack(sym.start, &sym.name, sym.ty.clone());
                    let elem_name = format!("{}[{index}]", sym.name);
                    self.names.insert(id, elem_name.clone());
                    return elem_name;
                }
            }
            let n = self.stack_slot_name(foff, &ty);
            self.names.insert(id, n.clone());
            // The DECLARATION carries the Symbol's type, not this reference's — Ghidra declares the
            // `ScopeLocal` Symbol, and a reference of a different width renders against it
            // (`PrintC::pushPartialSymbol`, printc.cc:1947). A slot the cover does not contain has no
            // Symbol, so the reference's type is all there is.
            let declared = self
                .spacebase_sym_at(foff)
                .filter(|s| s.start == foff)
                .map_or(ty, |s| s.ty.clone());
            self.declare_stack(foff, &n, declared);
            return n;
        }
        self.var_counter += 1;
        let n = format!("{prefix}Var{}", self.var_counter);
        self.names.insert(id, n.clone());
        // a genuine local — declared at the body top (register/temp locals have no frame offset).
        self.decls.push((n.clone(), ty, None));
        n
    }

    /// Render a varnode as a C expression with its operator precedence (16 = atomic).
    fn render_var(&mut self, v: VarnodeId) -> (String, u8) {
        let vn = self.f.vn(v);
        if vn.is_constant() {
            // A float-typed constant prints as a C float literal (Ghidra `pushConstant` →
            // `push_float`, printc.cc): `0.0`, `1.5`, `INFINITY`/`NAN` — not the raw integer bits.
            // Constant typing (ActionInferTypes now types constants) supplies the float type.
            let dt = self.type_of(v);
            if let Datatype::Float(sz) = dt {
                return (super::float::push_float(vn.constant_value(), sz), 16);
            }
            // A `char`-typed constant prints as a C character literal (Ghidra `pushConstant`'s
            // `isCharPrint()` test, printc.cc:1751 → `pushCharConstant`). This is the same switch
            // the float arm above stands for; `char` is simply the other metatype that does not
            // print as a plain integer.
            if matches!(dt, Datatype::Char) {
                if let Some(s) = push_char_constant(vn.constant_value(), vn.size) {
                    return (s, 16);
                }
            }
            return (render_const(vn.constant_value(), vn.size), 16);
        }
        if self.is_explicit(v) {
            return (self.name_of(v), 16);
        }
        match vn.def {
            Some(def) => self.render_op(def),
            None => (self.name_of(v), 16),
        }
    }

    /// Render `v` as an operand of an operator of precedence `parent`, parenthesizing when
    /// the sub-expression binds looser (`right` operands also parenthesize at equal
    /// precedence, for left-associativity).
    fn operand(&mut self, v: VarnodeId, parent: u8, right: bool) -> String {
        let (s, p) = self.render_var(v);
        if p < parent || (right && p == parent) {
            format!("({s})")
        } else {
            s
        }
    }

    /// The cast an op requires of its input `slot` (Ghidra `TypeOp::getInputCast` → `castStandard`),
    /// or `None` if the operand's type already satisfies the op. Only the comparisons are wired:
    /// the signed/unsigned ones force a signedness cast (`care_uint_int`), which is what renders
    /// Ghidra's `(int4)param_1 < 10`; equality reconciles silently. Other ops (arithmetic, logic)
    /// use Ghidra's lenient default and effectively never cast in the primitive lattice, so they
    /// are left transparent here.
    fn get_input_cast(&self, op: OpId, slot: usize) -> Option<Datatype> {
        // Delegates to the shared `cast::input_cast` (Ghidra `TypeOp::getInputCast`), which reads the
        // committed `Varnode::ty` — the same decision `ActionSetCasts` will use to INSERT the CAST op
        // in-pipeline. The `checkIntPromotionForCompare` gate (cast.cc) is omitted: NO_PROMOTION for
        // operands >= 4 bytes (every operand here); sub-4-byte promotion-forced casts are skipped.
        super::cast::input_cast(self.f, op, slot)
    }

    /// Whether constant input `slot` should print with an explicit `U` suffix (Ghidra's
    /// `CastStrategy::markExplicitUnsigned`): the op inherits sign, the constant reads as
    /// unsigned/undefined and non-negative, and neither the other operand nor the consuming op
    /// already forces the unsignedness.
    fn mark_explicit_unsigned(&self, op: OpId, slot: usize) -> bool {
        let o = self.f.op(op);
        let code = o.code();
        if !inherits_sign(code) {
            return false;
        }
        let first_only = inherits_sign_first_only(code);
        if slot == 1 && first_only {
            return false;
        }
        let v = o.input(slot).unwrap();
        let vn = self.f.vn(v);
        if !vn.is_constant() {
            return false;
        }
        // A constant that renders as a small negative is signed in Ghidra (typed INT, rendered
        // `-N`) and never prints unsigned — guard the sign directly at the print, independent of
        // whatever unsigned type inference may have left on a negative literal.
        if render_const(vn.constant_value(), vn.size).starts_with('-') {
            return false;
        }
        // the constant's effective (read-facing) type — the type the op forces on it, else its
        // inferred type (constants now carry one, Ghidra `getHighTypeReadFacing`)
        let dt = self.get_input_cast(op, slot).unwrap_or_else(|| self.type_of(v));
        if !matches!(dt, Datatype::Uint(_) | Datatype::Unknown(_)) {
            return false;
        }
        if o.num_inputs() == 2 && !first_only {
            let other = o.input(1 - slot).unwrap();
            let om = self.get_input_cast(op, 1 - slot).unwrap_or_else(|| self.type_of(other));
            if matches!(om, Datatype::Uint(_) | Datatype::Unknown(_)) {
                return false; // the other side already forces the unsigned interpretation
            }
        }
        if let Some(out) = o.output {
            if self.is_explicit(out) {
                return false;
            }
            let desc = &self.f.vn(out).descend;
            if desc.len() == 1 && !inherits_sign(self.f.op(desc[0]).code()) {
                return false; // the consuming op would force the type anyway
            }
        }
        true
    }

    /// Render input `slot` of `op`. The operand cast the op requires ([`get_input_cast`]) is now a
    /// real `CPUI_CAST` op that [`super::setcasts::ActionSetCasts`]'s `castInput` inserted into the
    /// IR, so it renders through the [`OpCode::Cast`] arm here — printc no longer wraps at render
    /// time (Stage 3 of the IR-cast-model port). What stays a pure print concern is Ghidra's
    /// `markExplicitUnsigned`: a constant that adopts an explicit `U` suffix ([`mark_explicit_unsigned`])
    /// rather than a cast op.
    fn cast_operand(&mut self, op: OpId, slot: usize, prec: u8, right: bool) -> String {
        let v = self.f.op(op).input(slot).unwrap();
        if self.f.vn(v).is_constant() && self.mark_explicit_unsigned(op, slot) {
            let vn = self.f.vn(v);
            return render_const_unsigned(vn.constant_value(), vn.size);
        }
        self.operand(v, prec, right)
    }

    /// Sign-extend a raw `stack`-space offset into a FRAME offset (Ghidra `sign_extend(start,
    /// addr.getAddrSize()*8-1)`, varmap.cc:557). Every conversion from a Varnode's/PTRSUB's stored
    /// offset to the signed offset the `ScopeLocal` cover is keyed by goes through here.
    fn frame_off(&self, raw: u64) -> i64 {
        let bit = self.stack_sign_bit;
        if bit >= 63 {
            raw as i64
        } else {
            let sh = 63 - bit;
            ((raw << sh) as i64) >> sh
        }
    }

    /// The name of the stack local at frame offset `off`. The name belongs to the recovered
    /// `ScopeLocal` symbol and was built once from THAT symbol's data-type
    /// (`varmap::build_variable_name`, Ghidra `ScopeLocal::buildVariableName` varmap.cc:548) — never
    /// re-derived from whatever type the referencing Varnode happens to carry. `ty` is only consulted
    /// for a slot the cover does not contain, and the result is memoized so that slot too has exactly
    /// one name.
    ///
    /// An uncovered slot goes through the same `buildVariableName`, so a stack address outside the
    /// prototype's `<localrange>` — a caller-allocated parameter slot, which `MapState` refuses to map
    /// (varmap.cc:900) — falls through to Ghidra's `ScopeInternal` form `xStack00000004` rather than
    /// being dressed up as a recovered local.
    fn stack_slot_name(&mut self, off: i64, ty: &Datatype) -> String {
        if let Some(sym) = self.spacebase_sym_at(off) {
            if sym.start == off {
                return sym.name;
            }
        }
        if let Some(n) = self.unmapped_stack_names.get(&off) {
            return n.clone();
        }
        // Unreachable: a frame offset only ever arrives here from a `stack`-space Varnode or from a
        // spacebase `PTRSUB`, and both require the space to exist.
        let Some(stk) = self.stack_space else { return format!("{}Stack", ty.print_name_base()) };
        // The cover is keyed by the SIGNED frame offset; `buildVariableName` takes the Address, so
        // fold it back into the space's own offset range (`AddrSpace::wrapOffset`, space.hh:383).
        let raw = self.f.spaces.get(stk).wrap_offset(off as u64);
        let n = super::varmap::build_variable_name(
            &self.f.spaces,
            stk,
            raw,
            ty,
            &self.f.proto_model.localrange,
        );
        self.unmapped_stack_names.insert(off, n.clone());
        n
    }

    /// If `off` is `idx * size` (a scaled array index), return `idx`.
    fn scaled_index(&self, off: VarnodeId, size: u32) -> Option<VarnodeId> {
        let def = self.f.vn(off).def?;
        let o = self.f.op(def);
        if o.code() == OpCode::IntMult && o.num_inputs() == 2 {
            let c = o.input(1)?;
            if self.f.vn(c).is_constant() && self.f.vn(c).constant_value() == size as u64 {
                return o.input(0);
            }
        }
        None
    }

    /// Decompose a load/store address into `(base, index-fits-an-array-of `size`)`. The base
    /// is the pointer; the bool is whether the offset is a clean array index (a constant
    /// multiple of `size`, or a variable scaled by `size`, or zero).
    fn addr_base(&self, addr: VarnodeId, size: u32) -> (VarnodeId, bool) {
        if let Some(def) = self.f.vn(addr).def {
            let o = self.f.op(def);
            if o.code() == OpCode::IntAdd && o.num_inputs() == 2 {
                let (base, off) = (o.input(0).unwrap(), o.input(1).unwrap());
                let ok = (self.f.vn(off).is_constant()
                    && size > 0
                    && self.f.vn(off).constant_value().is_multiple_of(size as u64))
                    || self.scaled_index(off, size).is_some();
                return (base, ok);
            }
        }
        (addr, true) // direct deref — element 0
    }

    /// Infer which pointer bases are accessed uniformly as an array (Ghidra's pointee
    /// inference, from the access pattern): a base qualifies only if every access through it
    /// uses the same element size and lands on a clean array index. Struct-like bases (mixed
    /// sizes/offsets) are excluded and keep `*(base + k)`.
    fn detect_arrays(&self) -> HashMap<VarnodeId, u32> {
        let mut info: HashMap<VarnodeId, Option<u32>> = HashMap::new();
        for op in self.f.op_ids() {
            let o = self.f.op(op);
            let (addr, size) = match o.code() {
                OpCode::Load => (o.input(1), o.output.map(|v| self.f.vn(v).size)),
                OpCode::Store => (o.input(1), o.input(2).map(|v| self.f.vn(v).size)),
                _ => continue,
            };
            let (Some(addr), Some(size)) = (addr, size) else { continue };
            if size == 0 {
                continue;
            }
            let (base, ok) = self.addr_base(addr, size);
            // Ghidra renders `base[i]` only when the base is genuinely *array*-typed; a plain
            // pointer prints `*(T *)(base + off)`. (Array typing comes from pointer-arithmetic
            // inference, #2/#10 — not yet produced, so this currently yields the pointer form.)
            if !matches!(self.type_of(base), Datatype::Array(..)) {
                continue;
            }
            let e = info.entry(base).or_insert(Some(size));
            if !(ok && *e == Some(size)) {
                *e = None; // mixed element size or non-array offset — disqualify
            }
        }
        info.into_iter().filter_map(|(b, s)| s.map(|sz| (b, sz))).collect()
    }

    /// Render a memory access `*addr` of `size` bytes holding a value of type `vty` — `base[i]`
    /// for a detected array base (non-zero index), else `*addr`, with a `(vty *)` cast on the
    /// address when it is not already a pointer to a value of the right size (Ghidra's
    /// `TypeOpLoad`/`TypeOpStore::getInputCast` on the pointer operand → `*(xunknown4 *)(addr)`).
    fn render_mem(&mut self, addr: VarnodeId, size: u32, vty: &Datatype) -> (String, u8) {
        if let Some(def) = self.f.vn(addr).def {
            let o = self.f.op(def).clone();
            // A LOAD/STORE through a PTRADD/PTRSUB is array/field access (Ghidra `opLoad`/`opStore`
            // → `checkArrayDeref` → the subscript/member token absorbs the dereference) — but only
            // when the access width matches the element. A sub/over-element access (e.g. a 1-byte
            // store through an `xunknown8 *`) keeps the pointer form with a cast, which Ghidra gets
            // from the `force_pointer` mod / the ActionSetCasts CAST on the LOAD/STORE pointer.
            if o.code() == OpCode::Ptradd {
                let elemsize = o.input(2).map(|v| self.f.vn(v).constant_value()).unwrap_or(0);
                if elemsize == size as u64 {
                    let (base, index) = (o.input(0).unwrap(), o.input(1).unwrap());
                    let b = self.operand(base, 16, false);
                    let i = self.render_var(index).0;
                    return (format!("{b}[{i}]"), 16);
                }
                return (format!("*({} *){}", vty.name(), self.operand(addr, 14, false)), 15);
            }
            if o.code() == OpCode::Ptrsub {
                return (self.render_ptrsub(def, true), 16);
            }
            if o.code() == OpCode::IntAdd && o.num_inputs() == 2 {
                let (base, off) = (o.input(0).unwrap(), o.input(1).unwrap());
                if let Some(&elem) = self.array_elem.get(&base) {
                    if self.f.vn(off).is_constant() && elem > 0 {
                        let c = self.f.vn(off).constant_value();
                        if c != 0 && c.is_multiple_of(elem as u64) {
                            let b = self.operand(base, 16, false);
                            return (format!("{b}[{}]", c / elem as u64), 16);
                        }
                    } else if let Some(idx) = self.scaled_index(off, elem) {
                        let b = self.operand(base, 16, false);
                        let i = self.render_var(idx).0;
                        return (format!("{b}[{i}]"), 16);
                    }
                }
            }
        }
        // A deref of an address that is genuinely a pointer to a value of the right size prints
        // `*addr`; otherwise Ghidra casts the address to `(vty *)` first. An address produced by
        // integer arithmetic is int-natured (Ghidra's `arithmeticOutputStandard`) and always
        // casts, even though type propagation back through the LOAD leaves a pointer temp-type on
        // it — mosura's `type_of` would otherwise see that pointer and wrongly skip the cast.
        let arithmetic_addr = self
            .f
            .vn(addr)
            .def
            .map(|d| {
                use OpCode::*;
                matches!(
                    self.f.op(d).code(),
                    IntAdd | IntSub | IntMult | IntAnd | IntOr | IntXor | IntLeft | IntRight | IntSright
                )
            })
            .unwrap_or(false);
        let addr_is_ptr = !arithmetic_addr
            && matches!(&self.type_of(addr), Datatype::Pointer(_, p) if p.size() == size);
        if addr_is_ptr {
            (format!("*{}", self.operand(addr, 15, false)), 15)
        } else {
            // cast the address to the access type (Ghidra `*(int4 *)`, or `*(xunknown4 *)` when
            // inference recovered no type for the access).
            (format!("*({} *){}", vty.name(), self.operand(addr, 14, false)), 15)
        }
    }

    /// The recovered `ScopeLocal` stack symbol containing frame offset `off`, if any (Ghidra's
    /// `TypeSpacebase::getSubType` symbol lookup, deferred to print time).
    fn spacebase_sym_at(&self, off: i64) -> Option<super::varmap::StackSymbol> {
        self.stack_syms
            .iter()
            .find(|s| s.start <= off && off < s.start + s.size as i64)
            .cloned()
    }

    /// Ghidra `PrintC::opPtrsub` TYPE_SPACEBASE case (printc.cc:1057): render a `PTRSUB(RSP, off)` off
    /// the recovered stack-symbol table. An array symbol drops the `&` and decays to its name (with an
    /// element `[index]` when the access lands inside it); a scalar symbol is `&<prefix>Stack_NN`.
    /// `deref` = the PTRSUB is a LOAD/STORE pointer (`valueon`), so the symbol value/element is used;
    /// otherwise the address is taken. The referenced symbol is declared exactly once.
    fn render_spacebase_ptrsub(&mut self, off: i64, deref: bool) -> String {
        match self.spacebase_sym_at(off) {
            Some(sym) => {
                if let Some((_, index)) = sym.array_index(off) {
                    // Array symbol: `axStack_<start>` decays to a pointer (drop `&`).
                    let name = sym.name.clone();
                    self.declare_stack(sym.start, &name, sym.ty.clone());
                    if deref {
                        format!("{name}[{index}]") // element access (Ghidra pushSymbol + [0]/[i])
                    } else if index == 0 {
                        name // pointer-decay of the array base (`pxVar1 = axStack_68`)
                    } else {
                        format!("{name} + {index}") // address of an interior element
                    }
                } else {
                    // Scalar symbol: the Symbol's own name (`&xStack_NN` / the slot value).
                    let ty = sym.ty.clone();
                    let name = self.stack_slot_name(off, &ty);
                    self.declare_stack(off, &name, ty);
                    if deref { name } else { format!("&{name}") }
                }
            }
            // No mapped symbol (Ghidra `pushUnnamedLocation`): name by the raw frame slot. The slot's
            // width is unknown here, so the name takes the `undefined1` stem Ghidra's `defaultType`
            // carries (`MapState`'s `getBase(1,TYPE_UNKNOWN)`, varmap.cc:1261).
            None => {
                let name = self.stack_slot_name(off, &Datatype::Unknown(1));
                if deref { name } else { format!("&{name}") }
            }
        }
    }

    /// Declare a recovered stack symbol at frame offset `start` exactly once (Ghidra declares the
    /// `ScopeLocal` symbols in the function body; the sort at emission orders them by frame address).
    ///
    /// Keyed by `start` ALONE, because `ScopeLocal::restructure` produces a DISJOINT cover — one
    /// Symbol per stack address, of one type. Keying by `(start, width)` instead let a slot read at
    /// two widths be declared twice, which only stayed legal C while the two print-time name
    /// synthesizers happened to disagree about the slot's stem (`iStack_ffffffe8` alongside
    /// `xStack_ffffffe8`). Naming from the Symbol collapsed the two names onto one and wcc386
    /// correctly rejected the redefinition — the disagreement had been MASKING the duplicate.
    /// Measured: 3 WAR2 functions (FUN_00041290, FUN_000441ec, FUN_0004d794).
    fn declare_stack(&mut self, start: i64, name: &str, ty: Datatype) {
        if self.stack_declared.insert(start) {
            self.decls.push((name.to_string(), ty, Some(start)));
        }
    }

    /// Render a `PTRSUB(base, off)` (Ghidra `opPtrsub`). The result already carries any leading `&`
    /// (an address-of a struct field or scalar stack local) or none (an array decay), so the caller
    /// uses it verbatim. `deref` = the PTRSUB is used as a LOAD/STORE pointer (the field/element value
    /// is wanted); otherwise its address value is wanted. Pointer-to-spacebase ⇒ the ScopeLocal name;
    /// pointer-to-struct ⇒ `base->field_0x<off>`; pointer-to-array ⇒ element 0.
    fn render_ptrsub(&mut self, op: OpId, deref: bool) -> String {
        let base = self.f.op(op).input(0).unwrap();
        let off = self.f.op(op).input(1).map(|v| self.f.vn(v).constant_value()).unwrap_or(0);
        // Spacebase: the base is the stack pointer (`is_spacebase()` — keyed on the varnode flag, not
        // `type_of`, because the RSP input's HighVariable is storage-merged with integer frame-adjust
        // versions so its printed type is not the locked `Pointer(Spacebase)`). Resolve the offset to a
        // ScopeLocal symbol. The offset varnode is pointer-width, so on a 32-bit target it holds the
        // wrapped `0xffffffdc` rather than `-0x24` — [`frame_off`] applies Ghidra's sign extension.
        // ActionConstantPtr's global reference: `PTRSUB(#0 <ram spacebase>, #addr)` — the base
        // is a CONSTANT carrying the spacebase flag, unlike the stack arm below whose base is
        // the stack-pointer register. Renders as the address of the global at `addr`, named by
        // the same persist branch a direct ram varnode uses (`buildVariableName`'s stem + space
        // + address) — the survey's declaration safety net picks the name up like any other
        // `<prefix>Ram<hex>` reference.
        if self.f.vn(base).is_constant() && self.f.vn(base).is_spacebase() {
            let ram = self.ram_space.unwrap_or(self.f.vn(base).loc.space);
            let pointee = self
                .f
                .op(op)
                .output
                .map(|o| self.type_of(o))
                .and_then(|t| t.ptr_to().cloned())
                .unwrap_or(Datatype::Unknown(1));
            let addr = self.f.spaces.get(ram).wrap_offset(off);
            let name = super::varmap::build_internal_variable_name(&self.f.spaces, ram, addr, &pointee);
            return if deref { name } else { format!("&{name}") };
        }
        if self.f.vn(base).is_spacebase() {
            let foff = self.frame_off(off);
            return self.render_spacebase_ptrsub(foff, deref);
        }
        let b = self.operand(base, 16, false);
        let inner = match self.type_of(base).ptr_to() {
            Some(Datatype::Array(..)) => format!("{b}[0]"),
            Some(_) => format!("{b}->field_0x{off:x}"),
            None => format!("*{b}"),
        };
        if deref { inner } else { format!("&{inner}") }
    }

    /// Render an op as a C expression with its precedence.
    fn render_op(&mut self, op: super::op::OpId) -> (String, u8) {
        let o = self.f.op(op);
        let a = |i: usize| o.input(i).unwrap();
        let bin = |s: &mut Self, sym: &str, prec: u8| {
            // route operands through the cast rule so a signed compare prints `(int4)x` etc.;
            // ops with no required cast (most) fall through to a plain operand
            let l = s.cast_operand(op, 0, prec, false);
            let r = s.cast_operand(op, 1, prec, true);
            (format!("{l} {sym} {r}"), prec)
        };
        match o.code() {
            // COPY and ZEXT (the implicit x86 32→64 zero-extension) stay transparent
            OpCode::Copy | OpCode::IntZext => self.render_var(a(0)),
            // SUBPIECE (Ghidra `PrintC::opSubpiece`, printc.cc:843): a truncation renders as a C
            // cast when `CastStrategyC::isSubpieceCast` holds (offset 0 + scalar in/out metatypes),
            // otherwise as the functional `SUB<insize><outsize>(x, off)` (`opFunc`,
            // `TypeOpSubpiece::getOperatorName`). The cast target is the output type.
            OpCode::Subpiece => {
                let in0 = a(0);
                let off =
                    if self.f.vn(a(1)).is_constant() { self.f.vn(a(1)).constant_value() } else { 1 };
                let out_ty = self.type_of(o.output.unwrap());
                let in_ty = self.type_of(in0);
                if is_subpiece_cast(&out_ty, &in_ty, off) {
                    (format!("({}){}", out_ty.name(), self.operand(in0, 14, false)), 14)
                } else {
                    let insize = self.f.vn(in0).size;
                    let outsize = self.f.vn(o.output.unwrap()).size;
                    (format!("SUB{insize}{outsize}({},{off})", self.render_var(in0).0), 16)
                }
            }
            OpCode::IntSext => {
                let n = self.f.vn(o.output.unwrap()).size;
                // the widening renders `(int{n})`; the input itself may also need a `(int{m})`
                // cast (e.g. from undefined), giving Ghidra's `(int8)(int4)x`
                (format!("(int{n}){}", self.cast_operand(op, 0, 14, false)), 14)
            }
            OpCode::IntMult => bin(self, "*", 13),
            OpCode::IntDiv | OpCode::IntSdiv => bin(self, "/", 13),
            OpCode::IntRem | OpCode::IntSrem => bin(self, "%", 13),
            // A frame-pointer-relative address is now a `PTRSUB(RSP, off)` (the typed spacebase
            // pointer), named off the ScopeLocal table by `render_ptrsub`; a plain `INT_ADD` is just
            // addition. (The print-time `stack_addr` INT_ADD adaptation is retired — task #22-A.)
            OpCode::IntAdd => bin(self, "+", 12),
            OpCode::IntSub => bin(self, "-", 12),
            OpCode::IntLeft => bin(self, "<<", 11),
            OpCode::IntRight | OpCode::IntSright => bin(self, ">>", 11),
            OpCode::IntLess | OpCode::IntSless => bin(self, "<", 10),
            OpCode::IntLessequal | OpCode::IntSlessequal => bin(self, "<=", 10),
            OpCode::IntEqual => bin(self, "==", 9),
            OpCode::IntNotequal => bin(self, "!=", 9),
            OpCode::IntAnd => bin(self, "&", 8),
            OpCode::IntXor | OpCode::BoolXor => bin(self, "^", 7),
            OpCode::IntOr => bin(self, "|", 6),
            OpCode::BoolAnd => bin(self, "&&", 5),
            OpCode::BoolOr => bin(self, "||", 4),
            OpCode::IntNegate => (format!("~{}", self.operand(a(0), 15, false)), 15),
            OpCode::Int2comp => (format!("-{}", self.operand(a(0), 15, false)), 15),
            OpCode::BoolNegate => (format!("!{}", self.operand(a(0), 15, false)), 15),
            // floating point: arithmetic and comparisons as operators
            OpCode::FloatAdd => bin(self, "+", 12),
            OpCode::FloatSub => bin(self, "-", 12),
            OpCode::FloatMult => bin(self, "*", 13),
            OpCode::FloatDiv => bin(self, "/", 13),
            OpCode::FloatLess => bin(self, "<", 10),
            OpCode::FloatLessequal => bin(self, "<=", 10),
            OpCode::FloatEqual => bin(self, "==", 9),
            OpCode::FloatNotequal => bin(self, "!=", 9),
            OpCode::FloatNeg => (format!("-{}", self.operand(a(0), 15, false)), 15),
            // float intrinsics Ghidra prints as named calls
            OpCode::FloatNan => (format!("NAN({})", self.render_var(a(0)).0), 16),
            OpCode::FloatAbs => (format!("ABS({})", self.render_var(a(0)).0), 16),
            OpCode::FloatSqrt => (format!("SQRT({})", self.render_var(a(0)).0), 16),
            OpCode::FloatCeil => (format!("ceil({})", self.render_var(a(0)).0), 16),
            OpCode::FloatFloor => (format!("floor({})", self.render_var(a(0)).0), 16),
            OpCode::FloatRound => (format!("round({})", self.render_var(a(0)).0), 16),
            // conversions render as a cast to the output float type (Ghidra `opFloatInt2Float`/
            // `opFloatFloat2Float` → a type cast named by `Datatype::name()`, i.e. `float4`/`float8`/
            // `float10` — the same core float names the declarations use, not C's `float`/`double`).
            OpCode::FloatInt2float | OpCode::FloatFloat2float => {
                let ty = Datatype::Float(self.f.vn(o.output.unwrap()).size).name();
                let in0 = a(0);
                (format!("({ty}){}", self.operand(in0, 14, false)), 14)
            }
            OpCode::FloatTrunc => {
                let n = self.f.vn(o.output.unwrap()).size;
                let in0 = a(0);
                (format!("(int{n}){}", self.operand(in0, 14, false)), 14)
            }
            // CPUI_CAST (Ghidra `PrintC::opTypeCast`, printc.cc:448): a cast op renders `(dt)x`
            // where `dt = op->getOut()->getHighTypeDefFacing()` — the cast-to type carried on the
            // output varnode. Precedence 14 (unary cast), operand at 14, exactly like the IntSext /
            // FloatInt2float cast renders above. mosura will begin inserting these in the
            // ActionSetCasts port (`castInput`, coreaction.cc:2655); until then SLEIGH never emits a
            // CAST and no rule creates one, so this arm is byte-neutral scaffolding.
            OpCode::Cast => {
                let in0 = a(0);
                let out = o.output.unwrap();
                let ty = self.type_of(out);
                (format!("({}){}", ty.name(), self.operand(in0, 14, false)), 14)
            }
            OpCode::Load => {
                let (addr, sz) = (a(1), self.f.vn(o.output.unwrap()).size);
                let vty = self.type_of(o.output.unwrap());
                self.render_mem(addr, sz, &vty)
            }
            // PTRADD/PTRSUB used as a value (not a LOAD/STORE pointer): C pointer arithmetic
            // scales by the element implicitly, so `base + index` (Ghidra `opPtradd` non-value
            // case → `binary_plus`); PTRSUB takes the address of the sub-component.
            OpCode::Ptradd => {
                let (base, index) = (a(0), a(1));
                let l = self.operand(base, 12, false);
                let r = self.operand(index, 12, true);
                (format!("{l} + {r}"), 12)
            }
            // `render_ptrsub` returns the address expression already carrying any leading `&` (a scalar
            // stack local / struct field) or none (an array decay), so it is used verbatim.
            OpCode::Ptrsub => (self.render_ptrsub(op, false), 15),
            OpCode::Call => {
                // input 0 is the (constant) call target — name it func_0x<addr>, like Ghidra
                let name = match o.input(0) {
                    Some(t) => format!("func_0x{:08x}", self.f.vn(t).loc.offset),
                    None => "func".to_string(),
                };
                if std::env::var_os("MOSURA_CALLARGS").is_some() {
                    let facts: Vec<String> = (1..o.num_inputs())
                        .map(|i| {
                            let v = a(i);
                            let vn = self.f.vn(v);
                            format!(
                                "{}+{:#x}/{}{}{}{}",
                                self.f.spaces.get(vn.loc.space).name,
                                vn.loc.offset,
                                vn.size,
                                if vn.is_written() { " w" } else { "" },
                                if vn.is_input() { " in" } else { "" },
                                if vn.is_constant() { " c" } else { "" }
                            )
                        })
                        .collect();
                    eprintln!("CALLARGS {name} op={} args=[{}]", op.0, facts.join(" | "));
                }
                let args: Vec<String> = (1..o.num_inputs()).map(|i| self.render_var(a(i)).0).collect();
                (format!("{name}({})", args.join(", ")), 16)
            }
            OpCode::Callind => {
                // `PrintC::opCallind` (printc.cc) pushes `function_call`, then `dereference`, then
                // the target — and NO cast. Any cast is the type system's, inserted by
                // ActionSetCasts through the base `TypeOp::getInputCast` against the `code *`
                // local type of slot 0. Hardcoding `(code *)` here produced it even when the
                // target was ALREADY a code pointer, and the redundant cast is not cosmetic: the
                // C it yields loads the pointer into a register and calls the register, where the
                // original is a single memory-indirect `call [mem]`.
                //
                // A CONSTANT target is the exception, and it is also Ghidra's: `pushConstant`'s
                // TYPE_PTR arm routes a code-pointer constant to `pushPtrCodeConstant`
                // (printc.cc), which prints the FUNCTION NAME when the address resolves in the
                // global scope and returns false otherwise — falling through to the ordinary
                // constant rendering, which carries the pointer type as a cast. mosura has no
                // global function lookup at this point, so it takes the second path: an explicit
                // `(code *)` on the constant, which is what makes `(*(code *)0x1006ca)()` valid C.
                let t0 = a(0);
                let args: Vec<String> = (1..o.num_inputs()).map(|i| self.render_var(a(i)).0).collect();
                if self.f.vn(t0).is_constant() {
                    let tgt = self.operand(t0, 16, false);
                    (format!("(*(code *){tgt})({})", args.join(", ")), 16)
                } else {
                    let tgt = self.operand(t0, 15, false);
                    (format!("(*{tgt})({})", args.join(", ")), 16)
                }
            }
            // PIECE (CONCAT) — heritage refinement / Ghidra's `guard` rejoin two pieces; printed
            // functionally as `CONCAT<s0><s1>(hi, lo)` (`TypeOpPiece::getOperatorName`, `typeop.cc`).
            OpCode::Piece => {
                let (s0, s1) = (self.f.vn(a(0)).size, self.f.vn(a(1)).size);
                let hi = self.render_var(a(0)).0;
                let lo = self.render_var(a(1)).0;
                (format!("CONCAT{s0}{s1}({hi},{lo})"), 16)
            }
            // CALLOTHER (Ghidra `PrintC::opCallother`, printc.cc:673, functional display): a
            // user-defined p-code op renders `<userop-name>(in1,..,inN)` — input 0 is the userop
            // index constant, skipped; the name comes from the `.sla` userop table
            // (`TypeOpCallother::getOperatorName` → `UserOpSymbol` name). A `define pcodeop` always
            // has display 0 (functional), so this is the only form for SLEIGH userops. Fallback to
            // Ghidra's `CALLOTHER[index]` form (identifier-safe) if the index is unresolved.
            OpCode::Callother => {
                let index = o.input(0).map(|v| self.f.vn(v).constant_value());
                let name = index
                    .and_then(|i| self.f.userops.get(&i).cloned())
                    .unwrap_or_else(|| format!("CALLOTHER_{}", index.unwrap_or(0)));
                let args: Vec<String> = (1..o.num_inputs()).map(|i| self.render_var(a(i)).0).collect();
                (format!("{name}({})", args.join(",")), 16)
            }
            // INT_SBORROW (Ghidra `TypeOpIntSborrow::getOperatorName`, typeop.cc:1372): the signed-
            // subtraction-overflow predicate renders `SBORROW<in0-size>(a,b)` via `opFunc`.
            OpCode::IntSborrow => {
                let sz = self.f.vn(a(0)).size;
                let l = self.render_var(a(0)).0;
                let r = self.render_var(a(1)).0;
                (format!("SBORROW{sz}({l},{r})"), 16)
            }
            // POPCOUNT (Ghidra `TypeOpPopcount`, typeop.cc:2558, a `TypeOpFunc` named "POPCOUNT"):
            // renders `POPCOUNT(x)` via `opFunc`.
            OpCode::Popcount => (format!("POPCOUNT({})", self.render_var(a(0)).0), 16),
            // INT_CARRY / INT_SCARRY (Ghidra `TypeOpIntCarry`/`TypeOpIntScarry`, typeop.cc:1345/
            // 1358 — `TypeOpFunc`s whose operator name is `CARRY`/`SCARRY` + the input size):
            // exactly the SBORROW shape above. These used to fall through to the placeholder
            // below — the `INT_CARRY(...)` internal-name leak of docs/compilable-c-remediation.md
            // Phase 5; the closed prelude defines CARRY1/2/4 and SCARRY1/2/4.
            OpCode::IntCarry => {
                let sz = self.f.vn(a(0)).size;
                let l = self.render_var(a(0)).0;
                let r = self.render_var(a(1)).0;
                (format!("CARRY{sz}({l},{r})"), 16)
            }
            OpCode::IntScarry => {
                let sz = self.f.vn(a(0)).size;
                let l = self.render_var(a(0)).0;
                let r = self.render_var(a(1)).0;
                (format!("SCARRY{sz}({l},{r})"), 16)
            }
            // The placeholder for an op printc cannot render. Ghidra has NO counterpart: its
            // token table is total, so reaching here is a mosura port gap by definition. The
            // MOSURA_ prefix is load-bearing — the survey's contract detector flags it, so a new
            // gap becomes a manifest-reported defect instead of a silent internal name.
            other => (format!("MOSURA_UNRENDERED_{}(...)", other.name()), 16),
        }
    }

    /// The function's return value: the value wired into a RETURN by return recovery (its
    /// second input), or `None` for a void function.
    fn return_value(&self) -> Option<VarnodeId> {
        self.f
            .op_ids()
            .find(|&op| self.f.op(op).code() == OpCode::Return && self.f.op(op).num_inputs() > 1)
            .and_then(|op| self.f.op(op).input(1))
    }

    /// Render an assignment statement body (`lhs = rhs`, no terminator) for an op.
    fn render_assign(&mut self, op: OpId) -> String {
        let outv = self.f.op(op).output.unwrap();
        let lhs = self.lvalue_of(outv);
        let rhs = self.render_op(op).0;
        format!("{lhs} = {rhs}")
    }

    /// Find the loop variable: a MULTIEQUAL in the loop head `head` whose tail-slot input is a
    /// usable iterate statement in `tail` — Ghidra `BlockWhileDo::findLoopVariable`
    /// (block.cc:3164). Returns `(phi, iterate)`.
    ///
    /// ⭐ THE SEARCH AND THE VALIDATION ARE ONE LOOP, and that is the whole point. Reaching a head
    /// phi is NOT enough to commit to it: Ghidra checks that phi's tail-slot input immediately and
    /// `continue`s the walk when it is a marker, is not defined in the tail, or cannot be moved to
    /// the end. mosura previously returned the FIRST head phi and validated only that one, so a
    /// single unusable candidate anywhere on the walk lost the `for`.
    ///
    /// The unusable candidate is not exotic. When the loop BOUND is a global the body modifies, the
    /// bound is heritaged, carries its own phi in the head, and — because the walk is LIFO over
    /// `INT_LESS(i, bound)` — is reached BEFORE the register induction variable. Instrumenting the
    /// WAR2 specimens printed the selected phi's storage as `space="ram"` in all seven: mosura was
    /// validating `DAT_000948b6`, the loop bound, as the induction variable.
    ///
    /// The walk is Ghidra's bounded 4-deep DFS over operands (`path[4]`, `count == 3` refuses to
    /// descend further), truncating at calls and markers, with no visited-set — the depth bound is
    /// what terminates it.
    fn find_loop_variable(
        &self,
        cond_var: VarnodeId,
        head: BlockId,
        tail: BlockId,
        last: OpId,
        slot: usize,
    ) -> Option<(OpId, OpId)> {
        let def = self.f.vn(cond_var).def?;
        if self.f.op(def).is_call() || self.f.op(def).is_marker() {
            return None;
        }
        let mut path: Vec<(OpId, usize)> = vec![(def, 0)];
        while let Some(&mut (cur, ref mut ind)) = path.last_mut() {
            let i = *ind;
            *ind += 1;
            let Some(&next) = self.f.op(cur).inrefs.get(i) else {
                path.pop();
                continue;
            };
            let Some(defop) = self.f.vn(next).def else { continue };
            if self.f.op(defop).code() == OpCode::Multiequal {
                if self.f.op(defop).parent != Some(head) {
                    continue;
                }
                let Some(itvn) = self.f.op(defop).input(slot) else { continue };
                let Some(iterate) = self.f.vn(itvn).def else { continue };
                if self.f.op(iterate).parent == Some(tail) {
                    if self.f.op(iterate).is_marker() {
                        continue; // no iteration in the tail — keep looking
                    }
                    if !self.is_moveable(iterate, last) {
                        continue; // not the final statement — keep looking
                    }
                    return Some((defop, iterate));
                }
            } else {
                if path.len() == 4 {
                    continue;
                }
                if self.f.op(defop).is_call() || self.f.op(defop).is_marker() {
                    continue;
                }
                path.push((defop, 0));
            }
        }
        None
    }

    /// Ghidra's typed `FlowBlock::lastOp` (block.hh:239 + overrides): only structured kinds that
    /// forward a last op have one — a basic block (its last op), a List (its last component,
    /// block.cc:2960), a short-circuit Condition (its second operand, block.cc:3016). A `BlockIf`
    /// with a then-body has none (block.cc:3119 — only the degenerate if-goto forwards), and a
    /// Switch (or any other composite) inherits the null base. This typing is what makes Ghidra's
    /// `BlockWhileDo::finalTransform` (block.cc:3356) decline the for-loop when the loop body ends
    /// in a switch or an if.
    fn structured_last_op(&self, s: &Structured, idx: usize) -> Option<OpId> {
        match &s.blocks[idx].kind {
            FlowKind::Basic(b) => self.f.block(*b).ops.last().copied(),
            FlowKind::List => self.structured_last_op(s, *s.blocks[idx].components.last()?),
            FlowKind::CondAnd | FlowKind::CondOr => {
                self.structured_last_op(s, s.blocks[idx].components[1])
            }
            _ => None,
        }
    }

    /// Is the loop variable involved as an input in the iterator statement? — Ghidra
    /// `BlockWhileDo::testIterateForm` (block.cc:3287).
    ///
    /// Walks the iterate statement's operand tree looking for a Varnode in the loop variable's
    /// HighVariable, **truncating at every explicit Varnode**: an explicit operand is a named
    /// variable in its own right, so the loop variable reached only *through* one is not what this
    /// statement iterates. That truncation is the whole test. On `FUN_00016764`'s list walk the
    /// iterate statement is `piVar2 = (int *)(iVar1 + 0x60)` where `iVar1 = *piVar2` is explicit —
    /// the walk stops at `iVar1`, never reaches `piVar2`, and Ghidra prints a plain `while` with a
    /// comma-separated condition instead of a `for`.
    fn test_iterate_form(&self, loop_var: VarnodeId, iterate: OpId) -> bool {
        let high = self.high_of[loop_var.0 as usize];
        let mut path = vec![(iterate, 0usize)];
        while let Some((op, slot)) = path.pop() {
            let Some(&vn) = self.f.op(op).inrefs.get(slot) else { continue };
            path.push((op, slot + 1));
            if self.f.vn(vn).is_annotation() {
                continue;
            }
            if self.high_of[vn.0 as usize] == high {
                return true;
            }
            if self.is_explicit(vn) {
                continue; // Truncate at explicit
            }
            let Some(def) = self.f.vn(vn).def else { continue };
            path.push((def, 0));
        }
        false
    }

    /// If the WhileDo with header `cond_idx` and body `body_idx` is a `for`-loop, return its
    /// `(initializer, iterator)` ops — Ghidra `BlockWhileDo::finalTransform` (block.cc:3356) +
    /// `findLoopVariable` (block.cc:3164) + `findInitializer` (block.cc:3223): the body's typed
    /// last op names the loop *tail*, which must flow only to the head; the iterator is the
    /// condition phi's input along the tail's edge, defined in the tail as its last statement
    /// (Ghidra moves a non-last iterate op there when moveable; mosura requires it in place). The
    /// initializer needs a two-in head (`findInitializer`'s `sizeIn() != 2` bail) with the other
    /// phi input defined in the pre-loop block.
    fn for_parts(
        &self,
        s: &Structured,
        cond_idx: usize,
        body_idx: usize,
    ) -> Option<(Option<VarnodeId>, OpId, VarnodeId)> {
        // `BlockWhileDo::finalTransform` derives its two anchors INDEPENDENTLY (block.cc:3362-3372):
        //     FlowBlock *copyBl = getFrontLeaf();
        //     BlockBasic *head = (BlockBasic *)copyBl->subBlock(0);   // the loop's FRONT leaf
        //     PcodeOp *cbranch = getBlock(0)->lastOp();               // the condition's LAST op
        // `head` is where the loop-carried MULTIEQUAL lives and whose in-edges index `slot`; the
        // cbranch is the exit test. They are the same basic block ONLY when the condition is a
        // single basic block — for a short-circuit condition `BlockCondition::lastOp`
        // (block.cc:3016) is block(1)'s last op, so the test sits in the second operand while the
        // phi stays in the first. Deriving both from the exit block fused them and lost the
        // for-loop on every compound condition: on FUN_00013edc the `uVar2` phi is in the front
        // leaf at 0x13f31 (which carries the `puVar1 != 0` test) while the `uVar2 < 8` CBRANCH is
        // in the block at 0x13f35, which holds no MULTIEQUAL at all.
        let head = entry_basic(s, cond_idx)?;
        // Ghidra takes the typed `lastOp` and requires it to BE the CBRANCH (block.cc:3372),
        // rather than scanning backwards for the nearest one.
        let cbranch = self.structured_last_op(s, cond_idx)?;
        if self.f.op(cbranch).code() != OpCode::Cbranch {
            return None;
        }
        // The body must have a typed last op; its block is the loop tail, flowing only to head.
        let mut last = self.structured_last_op(s, body_idx)?;
        let tail = self.f.op(last).parent?;
        if self.f.block(tail).out_edges.len() != 1 || self.f.block(tail).out_edges[0] != head {
            return None;
        }
        // The iterate statement must appear after this point (skip a trailing branch).
        if self.f.op(last).code().is_branch() {
            let pos = self.f.block(tail).ops.iter().position(|&o| o == last)?;
            last = *self.f.block(tail).ops.get(pos.checked_sub(1)?)?;
        }
        let cond_var = self.f.op(cbranch).input(1)?;
        // `findLoopVariable` (block.cc:3164) searches for the phi and validates its tail-slot
        // iterate in ONE walk, continuing past any candidate that fails — see the function.
        let slot = self.f.block(head).in_edges.iter().position(|&p| p == tail)?;
        let (phi, iterate) = self.find_loop_variable(cond_var, head, tail, last, slot)?;
        let phi_out = self.f.op(phi).output?;
        // `BlockWhileDo::testIterateForm` (block.cc:3287), run by `finalizePrinting` after
        // `finalTransform` has already accepted the loop variable: the LOOP VARIABLE ITSELF must be
        // an input of the iterate statement. `findLoopVariable` above only established that the
        // exit test reaches the phi — the iterate op it picked up on the way may compute the next
        // value from something else entirely, and then there is no `for` to print.
        if !self.test_iterate_form(phi_out, iterate) {
            return None;
        }
        // findInitializer: only a two-in head has one; the other phi input's def must sit in the
        // pre-loop block that flows only into the loop. (A folded-constant initializer has no def
        // op — carry the varnode.)
        let mut init_var = None;
        if self.f.block(head).in_edges.len() == 2 {
            let init_slot = 1 - slot;
            let initvn = self.f.op(phi).input(init_slot)?;
            // Ghidra `findInitializer` (block.cc:3223): a *written* initializer's def must be a
            // NON-MARKER op sitting in the pre-loop block (the head's init-slot in-edge), which flows
            // only to the loop. Otherwise there is no for-initializer and the loop stays a plain
            // while — never emit a raw phi/marker as the init (`for (x = MULTIEQUAL(...); ...)`). A
            // folded-constant initializer has no def op; mosura carries the varnode as before.
            let ok = match self.f.vn(initvn).def {
                None => true,
                Some(def) => {
                    let db = self.f.op(def).parent;
                    !self.f.op(def).is_marker()
                        && db == self.f.block(head).in_edges.get(init_slot).copied()
                        && db.is_some_and(|b| self.f.block(b).out_edges.len() == 1)
                }
            };
            if ok {
                init_var = Some(initvn);
            }
        }
        Some((init_var, iterate, phi_out))
    }

    /// Find all `for`-loops in the structure tree and record their parts.
    fn detect_for_loops(&mut self, s: &Structured, idx: usize) {
        // `BlockWhileDo::finalTransform` (block.cc:3358) bails on `hasOverflowSyntax()` before
        // looking for a loop variable: the overflow form has no `while (…)` header to hoist an
        // initializer or iterator into, so there is no for-loop to recover.
        let is_plain_whiledo =
            matches!(s.blocks[idx].kind, FlowKind::WhileDo) && !s.blocks[idx].has_overflow_syntax();
        if is_plain_whiledo {
            let comps = s.blocks[idx].components.clone();
            if let Some((init_var, iterate, phi_out)) = self.for_parts(s, comps[0], comps[1]) {
                self.for_loops.insert(idx, (init_var, iterate, phi_out));
                self.suppressed.insert(iterate);
                // a non-constant initializer is a real op in the pre-loop block — suppress it
                if let Some(d) = init_var.and_then(|iv| self.f.vn(iv).def) {
                    self.suppressed.insert(d);
                }
            }
        }
        for &c in &s.blocks[idx].components.clone() {
            self.detect_for_loops(s, c);
        }
    }

    /// The boolean tested by a condition block — the CBRANCH operand for a basic block, or
    /// the joined operands of a short-circuit `&&`/`||`.
    /// Render a (possibly short-circuit) condition, pushing a pending negation inward via
    /// De Morgan (Ghidra's print-time negation): `!(a && b)` → `!a || !b`, `!(a || b)` →
    /// `!a && !b`, recursing so the leading `!` never survives on a compound condition.
    fn render_cond_expr(&mut self, s: &Structured, idx: usize, neg: bool) -> String {
        let comps = s.blocks[idx].components.clone();
        match s.blocks[idx].kind {
            FlowKind::CondAnd | FlowKind::CondOr => {
                let is_and = matches!(s.blocks[idx].kind, FlowKind::CondAnd);
                // De Morgan swaps the connective under negation
                let conn = if is_and != neg { "&&" } else { "||" };
                // A leaf whose CBRANCH was oriented (Ghidra's BlockCondition::negateCondition
                // distributed the NOT to it — its negation is materialized positive in the IR) prints
                // directly, so flip the pending negation off for that operand. Nested compounds return
                // false here and flip their own leaves recursively. `cond_flip` (from ruleBlockOr's
                // swapped-sense fold) XORs in the per-side negation mosura deferred rather than
                // swapping CFG edges (Ghidra's `negateCondition` on `bl`/`orblock`).
                let (f0, f1) = s.blocks[idx].cond_flip;
                // Operand 0 renders under the INCOMING modifier (only-branch for an `if`,
                // comma_separate for a loop header) — its statements either hoisted above the
                // `if` by the statements pass or comma'd in place by the loop. Operand 1 ALWAYS
                // renders under `comma_separate`: Ghidra `PrintC::emitBlockCondition`
                // (printc.cc:2853-2858) does `unsetMod(only_branch); setMod(comma_separate)` for
                // getBlock(1) only, which is what keeps a side-effecting second block guarded —
                // `(a) || (stmt, stmt, b)` — instead of hoisted.
                let a = self.render_cond_operand(s, comps[0], neg ^ operand_oriented(self.f, s, comps[0]) ^ f0);
                let saved = self.comma_separate;
                self.comma_separate = true;
                let b = self.render_cond_operand(s, comps[1], neg ^ operand_oriented(self.f, s, comps[1]) ^ f1);
                self.comma_separate = saved;
                format!("{a} {conn} {b}")
            }
            _ => {
                // Under `comma_separate` this leaf IS a `BlockBasic` being emitted inside the
                // parens (`PrintC::emitBlockBasic`, printc.cc:2699-2720): its statements print
                // first, comma-separated, and the CBRANCH is simply the last statement of the
                // block — which is the condition expression rendered below. Ghidra never needs
                // to splice them because the branch is an op like any other; mosura renders the
                // condition separately, so the join is explicit here. Emitted BEFORE the
                // condition, matching both Ghidra's op order and the order the hoisting arm used
                // (so no variable's first-use naming moves).
                let mut stmts = String::new();
                if self.comma_separate {
                    self.emit_structured(s, idx, 0, &mut stmts);
                }
                let cvar = exit_basic(s, idx)
                    .and_then(|bid| {
                        self.f.block(bid).ops.iter().rev().copied().find(|&op| self.f.op(op).code() == OpCode::Cbranch)
                    })
                    .and_then(|cbr| self.f.op(cbr).input(1));
                let cond = match cvar {
                    Some(v) if neg => self.render_negated(v),
                    Some(v) => self.render_var(v).0,
                    None => if neg { "!(1)".into() } else { "1".into() },
                };
                if stmts.is_empty() { cond } else { format!("{stmts}, {cond}") }
            }
        }
    }

    /// A short-circuit operand, parenthesized (Ghidra's `(a) && (b)` style).
    fn render_cond_operand(&mut self, s: &Structured, idx: usize, neg: bool) -> String {
        format!("({})", self.render_cond_expr(s, idx, neg))
    }

    /// The condition of an `if`/`while`, negated when the body is on the false edge. The
    /// negation is pushed into the expression (Ghidra's print-time boolean negation) rather
    /// than wrapped in `!(...)`: `!(!x)` cancels, `==`/`!=` flip, `&&`/`||` De Morgan.
    fn render_condition(&mut self, s: &Structured, cond_idx: usize, negated: bool) -> String {
        self.render_cond_expr(s, cond_idx, negated)
    }

    /// The condition of a loop whose condition block is emitted INSIDE the parentheses — Ghidra
    /// `pushMod(); setMod(comma_separate); condBlock->emit(this); popMod();`
    /// (`PrintC::emitBlockWhileDo`, printc.cc:3046-3053).
    ///
    /// The returned string is everything Ghidra puts between the parens: the condition block's own
    /// statements, comma-separated, followed by the branch condition. The caller must therefore NOT
    /// also emit the condition block above the loop — that hoist is the defect this replaces. It
    /// ran the statements ONCE, before the loop, so a loop whose test re-reads memory each
    /// iteration could never advance, and on `FUN_00016764` it moved a load above the initialization
    /// of the very pointer it dereferences (a use-before-def).
    ///
    /// A `CondAnd`/`CondOr` condition needs no special case here: the mod is a printer-wide
    /// modifier, so it is inherited by both operand blocks exactly as in
    /// `PrintC::emitBlockCondition`'s `comma_separate` arm (printc.cc:2843-2869), which emits
    /// block 0 under the incoming mods and sets `comma_separate` again for block 1.
    fn render_condition_comma(&mut self, s: &Structured, cond_idx: usize, negated: bool) -> String {
        let saved = self.comma_separate;
        self.comma_separate = true;
        let cond = self.render_cond_expr(s, cond_idx, negated);
        self.comma_separate = saved;
        cond
    }

    /// Render the logical negation of boolean `v`, folding double negation and flipping
    /// equality (Ghidra's print-time negation); falls back to `!(...)`.
    fn render_negated(&mut self, v: VarnodeId) -> String {
        if let Some(def) = self.f.vn(v).def {
            let code = self.f.op(def).code();
            match code {
                OpCode::BoolNegate => {
                    let inner = self.f.op(def).input(0).unwrap();
                    return self.render_var(inner).0; // !(!x) => x
                }
                // The equality flip `!(a == b)` => `a != b` is Ghidra's print-time `negatetoken`
                // (printlanguage.cc:549, `tok->negate`: `==`↔`!=`, printc.cc:133-134) — a pure token
                // flip, no operand reorder. Operands route through `cast_operand` so both sides keep
                // their `(int4)` cast, matching the un-negated path.
                //
                // The order-comparison flips (`<`/`<=`) are NOT here: Ghidra's `negatetoken` for those
                // is `<`↔`>=`, `<=`↔`>` (printc.cc:129-132) — but the branch-negation stage
                // (ActionOrientBranches / ActionPreferComplement / compound `BlockCondition::
                // negateCondition`) now materializes every oriented order comparison into normal form
                // in the IR (`RuleBoolNegate` + `RuleIntLessEqual`), so no `<`/`<=` condition reaches
                // print still negated. The old print-time `!(a<=b)=>b<a` / `!(c<x)=>x<c+1` reorder-
                // and-increment shortcut (a mosura-only form Ghidra never used — it materializes
                // instead) is retired; a genuinely-unmaterialized order comparison falls through to
                // the `!(...)` fallback below.
                OpCode::IntEqual | OpCode::IntNotequal => {
                    let sym = if code == OpCode::IntEqual { "!=" } else { "==" };
                    let l = self.cast_operand(def, 0, 9, false);
                    let r = self.cast_operand(def, 1, 9, true);
                    return format!("{l} {sym} {r}");
                }
                // De Morgan: `!(a && b)` => `!a || !b`, `!(a || b)` => `!a && !b`, pushing the
                // negation into each operand. This is the print-time analogue of Ghidra's
                // `ActionNormalizeBranches` (blockaction.cc:2117), which flips a CBRANCH condition
                // in place — but ONLY when `opFlipInPlaceTest` reports the flip *normalizes* (return
                // 0), i.e. every operand is a lone-descended, flippable boolean. We apply the same
                // gate: distribute only when normalizing, otherwise keep the compact `!(...)`. So
                // `BOOL_AND(a!=10, b!=0x14)` prints as `a==10 || b==0x14` (orcompare), while a
                // condition that reuses a shared sub-boolean stays `!(...)` (pointerrel).
                OpCode::BoolAnd | OpCode::BoolOr if op_flip_normalizes(self.f, def) == 0 => {
                    let conn = if code == OpCode::BoolAnd { "||" } else { "&&" };
                    let l = self.f.op(def).input(0).unwrap();
                    let r = self.f.op(def).input(1).unwrap();
                    let ls = self.render_negated_demorgan(l);
                    let rs = self.render_negated_demorgan(r);
                    return format!("{ls} {conn} {rs}");
                }
                _ => {}
            }
        }
        format!("!{}", self.operand(v, 15, false))
    }

    /// A De-Morgan operand for [`render_negated`]: the negation of `v`, parenthesized only when it
    /// is itself a compound boolean (`BOOL_AND`/`BOOL_OR`) so the nested connective keeps its
    /// grouping. Simple comparisons (the common case) print bare — `a == 10 || b == 0x14`.
    fn render_negated_demorgan(&mut self, v: VarnodeId) -> String {
        let s = self.render_negated(v);
        let compound = self
            .f
            .vn(v)
            .def
            .is_some_and(|d| matches!(self.f.op(d).code(), OpCode::BoolAnd | OpCode::BoolOr));
        if compound {
            format!("({s})")
        } else {
            s
        }
    }

    /// Emit a structured block (and its children) as C, then any unconditional `goto` the collapse
    /// cut from this node — `PrintC::emitBlockGoto` (printc.cc:2767) prints
    /// `bl->getBlock(0)` with `no_branch` and follows it with `emitGotoStatement`, so the goto sits
    /// AFTER the whole body at the body's own indentation, not inside it.
    fn emit_structured(&mut self, s: &Structured, idx: usize, indent: usize, out: &mut String) {
        self.emit_structured_body(s, idx, indent, out);
        let Some(records) = s.node_gotos.get(&idx) else { return };
        let pad = "  ".repeat(indent);
        for r in records {
            // Ghidra's `emitGotoStatement` (printc.cc:2303): `break` for `f_break_goto` (scopeBreak
            // reclassified a loop-exit goto), else `goto LABEL`.
            if r.is_break {
                let _ = writeln!(out, "{pad}break;");
            } else {
                let _ = writeln!(out, "{pad}goto {};", self.lab_name(r.target));
            }
        }
    }

    fn emit_structured_body(&mut self, s: &Structured, idx: usize, indent: usize, out: &mut String) {
        let pad = "  ".repeat(indent);
        let fb = &s.blocks[idx];
        let (kind, comps, negated) = (fb.kind.clone(), fb.components.clone(), fb.negated);
        match kind {
            FlowKind::Basic(bid) => self.emit_basic(bid, indent, out),
            // A short-circuit condition's statements pass. Ghidra `PrintC::emitBlockCondition`'s
            // `no_branch` arm (printc.cc:2840-2845) descends into getBlock(0) ONLY — the left
            // spine, which executes unconditionally. The SECOND block's statements are guarded by
            // the short-circuit and print INSIDE the condition's second paren instead
            // (`comma_separate` placed only on the second block, :2856-2858; see
            // `render_cond_expr`). Emitting both components here hoisted block 1's guarded stores
            // above the test — the wrong-code family of
            // docs/decompiler-bug-guarded-store-hoisted.md (classified against Ghidra 2026-08-17:
            // Ghidra emits `(a) || (stmt, stmt, b)`).
            FlowKind::CondAnd | FlowKind::CondOr => {
                self.emit_structured(s, comps[0], indent, out);
            }
            FlowKind::Switch => {
                let head = exit_basic(s, comps[0]);
                let head_pc = head.and_then(|b| {
                    self.f.block(b).ops.iter().rev().copied().find(|&op| self.f.op(op).code() == OpCode::Branchind).map(|op| self.f.op(op).seqnum.pc.offset)
                });
                let idx = head
                    .and_then(|b| self.switch_index(b))
                    .map(|v| self.render_var(v).0)
                    // Placeholder for a switch whose index recovery failed — a mosura jumptable
                    // gap (Ghidra's emitBlockSwitch always has an operand). MOSURA_ prefix =
                    // contract-detector visible; the fix that retires it is recovery work.
                    .unwrap_or_else(|| "MOSURA_SWITCH_INDEX_UNRECOVERED".to_string());
                // emit the switch-head block's statements first (Ghidra `emitBlockSwitch`:
                // `getSwitchBlock()->emit` with `no_branch`) — the head may carry statements that
                // collapsed into it (e.g. the entry block once its bounds guard is folded away);
                // the BRANCHIND and the inlined index computation are skipped by `emit_basic`.
                self.emit_structured(s, comps[0], indent, out);
                // the entry addresses of the case blocks, so a recovered target can be matched to
                // the case block it enters (Ghidra `getIndexByBlock`) even when the block start
                // shifted past the target (leading case instructions optimized away)
                let case_addrs: Vec<u64> = comps[1..]
                    .iter()
                    .filter_map(|&c| entry_basic(s, c))
                    .filter_map(|cb| self.f.block_range(cb).map(|(a, _)| a))
                    .collect();
                let _ = writeln!(out, "{pad}switch ({idx}) {{");
                for &case in &comps[1..] {
                    if let (Some(pc), Some(cb)) = (head_pc, entry_basic(s, case)) {
                        let addr = self.f.block_range(cb).map(|(a, _)| a).unwrap_or(0);
                        // the folded-in out-of-range target prints as `default:` (Ghidra
                        // `BlockSwitch` CaseOrder.isdefault), never a case value
                        if self.f.switch_defaults.get(&pc) == Some(&addr) {
                            let _ = writeln!(out, "{pad}default:");
                        } else {
                            for v in self.case_labels(pc, addr, &case_addrs) {
                                let _ = writeln!(out, "{pad}case {v}:");
                            }
                        }
                    }
                    self.emit_structured(s, case, indent + 1, out);
                    // a case that breaks to the switch's merge ends with `break;`; one that
                    // returns is already terminal
                    let terminal = exit_basic(s, case)
                        .and_then(|eb| self.f.block(eb).ops.last().map(|&o| self.f.op(o).code()))
                        .map(|c| c == OpCode::Return)
                        .unwrap_or(false);
                    if !terminal {
                        let _ = writeln!(out, "{}break;", "  ".repeat(indent + 1));
                    }
                }
                let _ = writeln!(out, "{pad}}}");
            }
            FlowKind::List => {
                for c in comps {
                    self.emit_structured(s, c, indent, out);
                }
            }
            FlowKind::If | FlowKind::IfElse => self.emit_if(s, idx, indent, out, false),
            // Ghidra `PrintC::emitBlockWhileDo` overflow branch (printc.cc:3017): a condition
            // block too complex to fold into `while (…)` is printed as an infinite loop whose
            // condition statements run at the TOP OF THE BODY, followed by the break test —
            //     while( true ) { <cond stmts> if (<break cond>) break; <body> }
            // so they re-execute every iteration. `negated` already carries the break sense
            // (structure.rs `rule_while_do`, blockaction.cc:1539). `BlockWhileDo::finalTransform`
            // (block.cc:3358) declines the for-loop rewrite here, so `for_loops` is not consulted.
            FlowKind::WhileDo if s.blocks[idx].has_overflow_syntax() => {
                let bpad = "  ".repeat(indent + 1);
                let _ = writeln!(out, "{pad}while( true ) {{");
                self.emit_structured(s, comps[0], indent + 1, out);
                let cond = self.render_condition(s, comps[0], negated);
                let _ = writeln!(out, "{bpad}if ({cond}) break;");
                self.emit_structured(s, comps[1], indent + 1, out);
                let _ = writeln!(out, "{pad}}}");
            }
            FlowKind::WhileDo => {
                if let Some((init_var, iterate, phi_out)) = self.for_loops.get(&idx).copied() {
                    // `PrintC::emitForLoop` (printc.cc:2966-2986) emits, in order: the label
                    // statement, the (optional) initializer, `;`, the CONDITION BLOCK, `;`, the
                    // iterate statement — the whole header under one `setMod(comma_separate)`
                    // (printc.cc:2974). So the condition block's statements print between the two
                    // semicolons, exactly as they do inside a `while (…)`; there is no emit of
                    // `comps[0]` above the loop. Hoisting them ran them once: `forcomma`'s walk
                    // loaded the node key once and then copied that one value forever while the
                    // pointer walked away from it.
                    if let Some(b) = entry_basic(s, comps[0]) {
                        if self.labels.remove(&b) {
                            let name = self.lab_name(b);
                            let _ = writeln!(out, "{}{}:", "  ".repeat(indent.saturating_sub(1)), name);
                        }
                    }
                    let init_s = match init_var {
                        Some(iv) => {
                            let lhs = self.lvalue_of(phi_out);
                            let rhs = match self.f.vn(iv).def {
                                Some(d) => self.render_op(d).0, // the initializer's expression
                                None => self.render_var(iv).0,  // a folded constant / input
                            };
                            format!("{lhs} = {rhs}")
                        }
                        None => String::new(),
                    };
                    let cond = self.render_condition_comma(s, comps[0], negated);
                    let iter_s = self.render_assign(iterate);
                    let _ = writeln!(out, "{pad}for ({init_s}; {cond}; {iter_s}) {{");
                    self.emit_structured(s, comps[1], indent + 1, out);
                    let _ = writeln!(out, "{pad}}}");
                } else {
                    // `PrintC::emitBlockWhileDo` opens with `emitAnyLabelStatement(bl)`
                    // (printc.cc:3013) and `BlockWhileDo::markLabelBumpUp` (block.cc:3316) marks
                    // the sub-blocks — "whiledos steal lower blocks labels" — so a label on the
                    // loop's front leaf prints ABOVE the `while`, not from inside the condition
                    // block. Without the steal the label lands inside the parentheses once the
                    // condition is emitted there (`LAB_000590d2:` in FUN_00059060). The other two
                    // arms head with the same call, but their condition block is still emitted
                    // outside the parens, so stealing there would only move whitespace.
                    if let Some(b) = entry_basic(s, comps[0]) {
                        if self.labels.remove(&b) {
                            let name = self.lab_name(b);
                            let _ = writeln!(out, "{}{}:", "  ".repeat(indent.saturating_sub(1)), name);
                        }
                    }
                    // `PrintC::emitBlockWhileDo`'s non-overflow branch (printc.cc:3046-3053):
                    // the condition block is emitted INSIDE the parens under `comma_separate`,
                    // so its statements re-execute every iteration. There is no separate emit of
                    // `comps[0]` above the `while` — see [`Self::render_condition_comma`].
                    let cond = self.render_condition_comma(s, comps[0], negated);
                    let _ = writeln!(out, "{pad}while ({cond}) {{");
                    self.emit_structured(s, comps[1], indent + 1, out);
                    let _ = writeln!(out, "{pad}}}");
                }
            }
            FlowKind::DoWhile => {
                let _ = writeln!(out, "{pad}do {{");
                self.emit_structured(s, comps[0], indent + 1, out);
                let cond = self.render_condition(s, comps[0], negated);
                let _ = writeln!(out, "{pad}}} while ({cond});");
            }
            // Ghidra PrintC::emitBlockInfLoop (printc.cc:3097): a loop with no exit.
            FlowKind::InfLoop => {
                let _ = writeln!(out, "{pad}do {{");
                self.emit_structured(s, comps[0], indent + 1, out);
                let _ = writeln!(out, "{pad}}} while( true );");
            }
        }
    }

    /// Emit a `FlowKind::If` / `FlowKind::IfElse`, collapsing `else { if … }` into `else if …`.
    ///
    /// Faithful port of `PrintC::emitBlockIf`'s pending-brace handling (printc.cc:2882-2943): when
    /// an `if`/`else`'s else-arm is itself an `if` (`FlowBlock::t_if`), Ghidra prints the `else`
    /// keyword and emits the nested `if` in "pending brace" mode — the nested `if`'s opening brace
    /// is only issued if its condition block emits a leading statement; otherwise the `if` glues
    /// onto the `else` on one line (`else if (…)`). `else_if` is true when this block sits in that
    /// else-position and the caller has just written the bare `else` keyword (no trailing newline).
    /// ccompare normalizes `else { if … }` and `else if …` to the same token skeleton, so this
    /// changes no corpus score — it makes the emitted C match Ghidra's exact rendering.
    fn emit_if(&mut self, s: &Structured, idx: usize, indent: usize, out: &mut String, else_if: bool) {
        let fb = &s.blocks[idx];
        let (comps, negated) = (fb.components.clone(), fb.negated);
        let has_else = matches!(fb.kind, FlowKind::IfElse);

        // Ghidra emits the condition block (with `no_branch`) before deciding the merge; buffer its
        // leading statements so the pending-brace decision can see whether anything printed.
        let stmt_indent = indent + if else_if { 1 } else { 0 };
        let mut cond_stmts = String::new();
        self.emit_structured(s, comps[0], stmt_indent, &mut cond_stmts);
        let cond = self.render_condition(s, comps[0], negated);
        let merged = else_if && cond_stmts.is_empty();

        // `body_indent` is where the `if` and its closing brace sit: on a clean merge the `if` glues
        // onto the caller's `else` at the outer indent; otherwise (top-level, or the pending brace
        // fired) it sits one level in, under the just-opened `else {`.
        let body_indent = if merged { indent } else { stmt_indent };
        let bpad = "  ".repeat(body_indent);

        if else_if && !merged {
            let _ = writeln!(out, " {{"); // pending brace fired: continue the caller's "else" → "else {"
        }
        if !merged {
            out.push_str(&cond_stmts);
            let _ = writeln!(out, "{bpad}if ({cond}) {{");
        } else {
            let _ = writeln!(out, " if ({cond}) {{"); // "else if (…)" on one line
        }
        self.emit_structured(s, comps[1], body_indent + 1, out);
        let _ = writeln!(out, "{bpad}}}");
        if has_else {
            let else_arm = comps[2];
            let _ = write!(out, "{bpad}else");
            if matches!(s.blocks[else_arm].kind, FlowKind::If | FlowKind::IfElse) {
                self.emit_if(s, else_arm, body_indent, out, true);
            } else {
                let _ = writeln!(out, " {{");
                self.emit_structured(s, else_arm, body_indent + 1, out);
                let _ = writeln!(out, "{bpad}}}");
            }
        }
        if else_if && !merged {
            // close the "else {" opened above when the pending brace fired
            let _ = writeln!(out, "{}}}", "  ".repeat(indent));
        }
    }

    /// Emit one basic block's statements (skipping control-flow and inlined ops).
    fn emit_basic(&mut self, b: super::block::BlockId, indent: usize, out: &mut String) {
        let pad = "  ".repeat(indent);
        if self.labels.contains(&b) {
            let _ = writeln!(out, "{}{}:", "  ".repeat(indent.saturating_sub(1)), self.lab_name(b));
        }
        // Ghidra's per-block `separator` (printc.cc:2694): the `, ` of `comma_separate` goes
        // BETWEEN two statements of one basic block, never before the first — and it is local to
        // `emitBlockBasic`, so two blocks emitted back to back do not get one.
        let mut separator = false;
        for op in self.f.block(b).ops.clone() {
            if self.suppressed.contains(&op) {
                continue; // emitted in a for-loop header (initializer / iterator)
            }
            if self.nonprinting.contains(&op) {
                continue; // Ghidra opMarkNonPrinting (ActionCopyMarker): shadow / redundant COPY
            }
            // Ghidra `PrintC::emitBlockBasic` (printc.cc:2703-2705): an op whose output is IMPLIED
            // emits no statement at all — it is folded into the use that consumes it. This is
            // uniform across opcodes, with no per-op special case; the arms below therefore render
            // only values that materialize as their own statement.
            //
            // Without it a call whose result takes a cast prints twice: `ActionSetCasts` leaves the
            // call writing an implied unique and the CAST producing the named value, so the call arm
            // emitted `xVar = func();` for the unique AND the cast statement re-rendered the call
            // inlined as its operand.
            //
            // The test is printc's own classification rather than the raw `isImplied` flag: its
            // print-only arms can only ADD explicitness, so this skips a subset of what Ghidra skips,
            // and it stays consistent with the classification `render_var` consults when deciding to
            // inline versus name a value.
            if let Some(outv) = self.f.op(op).output {
                if !self.is_explicit(outv) {
                    continue;
                }
            }
            let o = self.f.op(op);
            let stmt: Option<String> = match o.code() {
                OpCode::Cbranch | OpCode::Branch | OpCode::Branchind | OpCode::Multiequal | OpCode::Indirect => None,
                OpCode::Return => match o.input(1) {
                    Some(v) => {
                        let e = self.render_var(v).0; // wired return value (inlined when single-use)
                        Some(format!("return {e}"))
                    }
                    None => Some("return".to_string()),
                },
                OpCode::Store => {
                    let (addr, vv) = (o.input(1).unwrap(), o.input(2).unwrap());
                    let sz = self.f.vn(vv).size;
                    let vty = self.type_of(vv);
                    let lhs = self.render_mem(addr, sz, &vty).0;
                    let val = self.render_var(vv).0;
                    Some(format!("{lhs} = {val}"))
                }
                OpCode::Call | OpCode::Callind => {
                    // a call is a statement (it has a side effect). Its return value is always a
                    // named variable (Ghidra `baseExplicit`: a CALL output is explicit) — emit
                    // `xVar = func(…)` whenever the result is used; a void/unused call is a bare
                    // `func(…);`.
                    let out_vn = o.output;
                    let uses = out_vn.map(|v| self.f.vn(v).descend.len());
                    match (out_vn, uses) {
                        (Some(outv), Some(n)) if n >= 1 => {
                            let lhs = self.lvalue_of(outv);
                            let rhs = self.render_op(op).0;
                            Some(format!("{lhs} = {rhs}"))
                        }
                        _ => {
                            let e = self.render_op(op).0;
                            Some(e)
                        }
                    }
                }
                _ => {
                    let mut stmt = None;
                    if let Some(outv) = o.output {
                        // A COPY or SUBPIECE between two Varnodes of the SAME HighVariable is a hidden
                        // internal copy (Ghidra `Merge::markInternalCopies` → `opMarkNonPrinting`,
                        // merge.cc:1461 for COPY / merge.cc:1508-1523 for SUBPIECE): `x = x` /
                        // `x = (int2)x` is redundant, so it is not emitted. This hides the `guardReturns`
                        // terminal COPY that holds a global to the end of the function (same-high, no
                        // reader) and, under the mainloop re-heritage, the write-masked narrow piece
                        // markers `removeRevisitedMarkers` leaves at the whole's address (same high as
                        // the whole once its source merges in). Ghidra's SUBPIECE arm keys on the
                        // VariablePiece group + offset; mosura's HighVariable identity (`high_of`) is the
                        // faithful stand-in, exactly as for the existing COPY arm.
                        let hidden = matches!(o.code(), OpCode::Copy | OpCode::Subpiece)
                            && o.input(0).is_some_and(|inv| {
                                self.high_of[outv.0 as usize] == self.high_of[inv.0 as usize]
                            });
                        if !hidden && self.is_explicit(outv) {
                            let lhs = self.lvalue_of(outv);
                            let rhs = self.render_op(op).0;
                            stmt = Some(format!("{lhs} = {rhs}"));
                        }
                    }
                    stmt
                }
            };
            // Ghidra `PrintC::emitBlockBasic`'s separator logic (printc.cc:2706-2720) +
            // `emitStatement` (printc.cc:2288): under `comma_separate` statements are joined by
            // `, ` inside the enclosing parens and carry no `;`; otherwise each takes its own
            // `tagLine`-prefixed, `;`-terminated line.
            if let Some(stmt) = stmt {
                if self.comma_separate {
                    if separator {
                        out.push_str(", ");
                    }
                    out.push_str(&stmt);
                } else {
                    let _ = writeln!(out, "{pad}{stmt};");
                }
                separator = true;
            }
        }
        // Unstructured branches cut from this block by the collapse driver, in cut order —
        // Ghidra's BlockIfGoto (`if (cond) goto LAB;`, the false edge falls through) followed by
        // any BlockGoto/BlockMultiGoto (unconditional `goto LAB;`).
        if let Some(records) = self.gotos.get(&b).cloned() {
            for GotoRecord { target, negated, conditional, is_break } in records {
                let cbr = self
                    .f
                    .block(b)
                    .ops
                    .iter()
                    .rev()
                    .copied()
                    .find(|&op| self.f.op(op).code() == OpCode::Cbranch)
                    .filter(|_| conditional);
                let cond = cbr.and_then(|op| self.f.op(op).input(1));
                // Ghidra's `emitGotoStatement` (printc.cc:2303): a `break` keyword for `f_break_goto`
                // (scopeBreak reclassified a loop-exit goto), else `goto LABEL`.
                let stmt = if is_break { "break".to_string() } else { format!("goto {}", self.lab_name(target)) };
                match cond {
                    Some(cond) => {
                        let c = if negated { self.render_negated(cond) } else { self.render_var(cond).0 };
                        let _ = writeln!(out, "{pad}if ({c}) {stmt};");
                    }
                    None => {
                        let _ = writeln!(out, "{pad}{stmt};");
                    }
                }
            }
        }
    }

    /// The index variable of a switch head. A table `ActionSwitchNorm` normalized has its
    /// `BRANCHIND` folded onto the unnormalized switch variable (`foldInNormalization`,
    /// jumptable.cc:1546) — read it directly, like Ghidra's `BlockSwitch` printing the
    /// `getSwitchVarnode()`. Otherwise (normalization declined) fall back to the print-time
    /// heuristics: trace the BRANCHIND through the table lookup if the lookup survived, else the
    /// dominating bound check `index <(=) count`.
    fn switch_index(&self, head: BlockId) -> Option<VarnodeId> {
        let bi = self.f.block(head).ops.iter().rev().copied().find(|&op| self.f.op(op).code() == OpCode::Branchind)?;
        let bi_pc = self.f.op(bi).seqnum.pc.offset;
        if self.f.jumptables.iter().any(|jt| jt.op_addr == bi_pc && jt.normalized) {
            return self.f.op(bi).input(0);
        }
        if let Some(v) = self.trace_table_index(self.f.op(bi).input(0)?) {
            return Some(v);
        }
        // fallback: the range check guarding the switch — `index <= count-1` / `index < count`
        let pc = self.f.op(bi).seqnum.pc.offset;
        let num_cases = self.f.switch_targets.get(&pc).map(|t| t.len())?;
        for i in 0..self.f.num_ops() as u32 {
            let o = self.f.op(OpId(i));
            let c = match o.input(1) {
                Some(b) if self.f.vn(b).is_constant() => self.f.vn(b).constant_value() as usize,
                _ => continue,
            };
            let hit = (o.code() == OpCode::IntLessequal && c + 1 == num_cases) || (o.code() == OpCode::IntLess && c == num_cases);
            if hit {
                return o.input(0);
            }
        }
        None
    }

    /// Trace `RAX = base + ext(load(base + index*scale))` ⇒ `index`, when the lookup survives.
    fn trace_table_index(&self, mut v: VarnodeId) -> Option<VarnodeId> {
        for _ in 0..10 {
            let def = self.f.vn(v).def?;
            let o = self.f.op(def);
            match o.code() {
                OpCode::Load => {
                    let addr = o.input(1)?;
                    if let Some(ad) = self.f.vn(addr).def {
                        if self.f.op(ad).code() == OpCode::IntAdd {
                            for k in 0..self.f.op(ad).num_inputs() {
                                if let Some(pd) = self.f.op(ad).input(k).and_then(|p| self.f.vn(p).def) {
                                    if self.f.op(pd).code() == OpCode::IntMult {
                                        return self.f.op(pd).input(0);
                                    }
                                }
                            }
                        }
                    }
                    return Some(addr);
                }
                OpCode::IntAdd => {
                    v = (0..o.num_inputs()).filter_map(|k| o.input(k)).find(|&iv| self.f.vn(iv).def.is_some())?;
                }
                OpCode::IntSext | OpCode::IntZext | OpCode::Subpiece | OpCode::Copy => v = o.input(0)?,
                _ => return None,
            }
        }
        None
    }

    /// The case values that dispatch to the case block at `case_addr` (Ghidra
    /// `getLabelByIndex(getIndexByBlock(block,j))`). Each recovered target is attributed to the
    /// case block it enters — the first case block at or after the target address, since a case
    /// block can start a few bytes past its recovered target (leading instructions get CSE'd /
    /// hoisted out). A table `ActionSwitchNorm` normalized carries the real case labels — the
    /// unnormalized switch-variable values `buildLabels` recovered (switchloop `case 1..9`);
    /// otherwise fall back to the position-index heuristic (exact only for the canonical 0-based
    /// dense form).
    fn case_labels(&self, head_pc: u64, case_addr: u64, case_addrs: &[u64]) -> Vec<i64> {
        let Some(targets) = self.f.switch_targets.get(&head_pc) else { return Vec::new() };
        let labels = self
            .f
            .jumptables
            .iter()
            .find(|jt| jt.op_addr == head_pc && jt.normalized && jt.labels.len() == targets.len())
            .map(|jt| &jt.labels);
        targets
            .iter()
            .enumerate()
            .filter_map(|(i, &t)| {
                let owner = case_addrs.iter().copied().filter(|&a| a >= t).min()?;
                (owner == case_addr).then(|| labels.map_or(i as i64, |l| l[i]))
            })
            .collect()
    }

    /// A label name for a goto target basic block, by its entry address.
    fn lab_name(&self, b: BlockId) -> String {
        let addr = self.f.block_range(b).map(|(a, _)| a).unwrap_or(0);
        format!("LAB_{addr:08x}")
    }
}

/// Render a constant: small negatives as signed decimal (Ghidra prints `0xff..fb` as `-5`),
/// otherwise decimal for small values and hex for the rest.
/// Faithful port of Ghidra's `Funcdata::opFlipInPlaceTest` (funcdata_op.cc:1221): trace a boolean
/// to the set of ops that would need flipping to negate it, and report whether the flip
/// *normalizes*. Returns 0 if it normalizes (a net win — flip), 1 if ambivalent, 2 if it does not
/// normalize (leave alone). We use it as the gate for print-time De Morgan distribution in
/// [`PrintC::render_negated`] (the analogue of `ActionNormalizeBranches`); a BOOL_AND/BOOL_OR is
/// distributed only when this returns 0. A non-lone-descended or non-flippable operand (e.g. a
/// shared sub-boolean, or a FLOAT_LESS that has no in-place complement) yields 2.
fn op_flip_normalizes(f: &Funcdata, op: OpId) -> i32 {
    let lone = |vn: VarnodeId| -> bool {
        let d = &f.vn(vn).descend;
        d.len() == 1 && d[0] == op
    };
    match f.op(op).code() {
        OpCode::IntEqual | OpCode::FloatEqual => 1,
        OpCode::BoolNegate | OpCode::IntNotequal | OpCode::FloatNotequal => 0,
        OpCode::IntSless | OpCode::IntLess => {
            let vn = f.op(op).input(0).unwrap();
            if !f.vn(vn).is_constant() {
                1
            } else {
                0
            }
        }
        OpCode::IntSlessequal | OpCode::IntLessequal => {
            let vn = f.op(op).input(1).unwrap();
            if f.vn(vn).is_constant() {
                1
            } else {
                0
            }
        }
        OpCode::BoolOr | OpCode::BoolAnd => {
            let vn0 = f.op(op).input(0).unwrap();
            if !lone(vn0) || !f.vn(vn0).is_written() {
                return 2;
            }
            let subtest1 = op_flip_normalizes(f, f.vn(vn0).def.unwrap());
            if subtest1 == 2 {
                return 2;
            }
            let vn1 = f.op(op).input(1).unwrap();
            if !lone(vn1) || !f.vn(vn1).is_written() {
                return 2;
            }
            let subtest2 = op_flip_normalizes(f, f.vn(vn1).def.unwrap());
            if subtest2 == 2 {
                return 2;
            }
            subtest1 // the front of AND/OR must be normalizing
        }
        _ => 2,
    }
}

/// Ops whose constant operands inherit the operation's signedness (Ghidra's `inherits_sign`):
/// an untyped/unsigned constant here prints with a `U` suffix unless the other side forces it.
fn inherits_sign(c: OpCode) -> bool {
    use OpCode::*;
    matches!(
        c,
        IntEqual | IntNotequal | IntSless | IntSlessequal | IntLess | IntLessequal | IntAdd | IntSub
            | Int2comp | IntMult | IntDiv | IntSdiv | IntRem | IntSrem | IntNegate | IntXor | IntAnd
            | IntOr | IntLeft | IntRight | IntSright
    )
}

/// Ops where only the first parameter inherits the sign (Ghidra's `inherits_sign_zero`): the
/// shift amount and the modulus second operand never take a `U`.
fn inherits_sign_first_only(c: OpCode) -> bool {
    use OpCode::*;
    matches!(c, IntLeft | IntRight | IntSright | IntRem | IntSrem)
}

/// Render a constant with an explicit unsigned `U` suffix (Ghidra's `setUnsignedPrint`).
fn render_const_unsigned(val: u64, size: u32) -> String {
    let masked = if size == 0 || size >= 8 { val } else { val & ((1u64 << (8 * size)) - 1) };
    if masked < 10 {
        format!("{masked}U")
    } else {
        format!("0x{masked:x}U")
    }
}

/// Ghidra's `PrintLanguage::mostNaturalBase` — pick base 10 for "round" numbers (a run of
/// trailing 0s or 9s in decimal), base 16 otherwise. Decides how a constant above the small-decimal
/// threshold prints.
fn most_natural_base(val: u64) -> u32 {
    if val == 0 {
        return 10;
    }
    let setdig = val % 10;
    let mut countdec = 0;
    let mut tmp = val;
    if setdig == 0 || setdig == 9 {
        countdec = 1;
        tmp /= 10;
        while tmp != 0 && tmp % 10 == setdig {
            countdec += 1;
            tmp /= 10;
        }
    }
    match countdec {
        0 => 16,
        1 => {
            if tmp > 1 || setdig == 9 {
                16
            } else {
                10
            }
        }
        2 => {
            if tmp > 10 {
                16
            } else {
                10
            }
        }
        3 => {
            if tmp > 100 {
                16
            } else {
                10
            }
        }
        _ => 10,
    }
}

/// Ghidra `PrintC::pushCharConstant` (`printc.cc:1606`): render a `char`-typed constant as a C
/// character literal. `None` means "print it as an integer instead", which is Ghidra's own fallback
/// and not a mosura opt-out.
///
/// WHICH OF GHIDRA'S BRANCHES ARE UNREACHABLE HERE, and why — none of them is dropped, each is
/// structurally absent. Every one of Ghidra's early exits is gated on a `displayFormat` obtained
/// from a `Symbol` or a `HighVariable`'s type (printc.cc:1611-1621): mosura models neither, so
/// `displayFormat` is 0 on every constant. That leaves exactly two live branches:
///   · a 1-byte value `>= 0x80` is NOT a unicode code-point — it is part of some multi-byte or
///     code-page encoding — so Ghidra prints it as an integer (printc.cc:1629). `None` here.
///   · everything else is a code-point, single-quoted, escaped by `printUnicode` (printc.cc:1426).
/// The equate path (`pushEquate`) and the wide-char `L` prefix are likewise unreachable: mosura has
/// no equate symbols, and its `Datatype::Char` is 1 byte by construction.
fn push_char_constant(val: u64, size: u32) -> Option<String> {
    let masked = if size == 0 || size >= 8 { val } else { val & ((1u64 << (8 * size)) - 1) };
    if size == 1 && masked >= 0x80 {
        return None; // Not a code-point — Ghidra pushes it as an integer.
    }
    Some(format!("'{}'", print_unicode(masked as u32)))
}

/// Ghidra `PrintC::printUnicode` (`printc.cc:1426`) + `PrintLanguage::unicodeNeedsEscape`
/// (`printlanguage.cc:411`): the named C escapes, then a generic `\xNN` for anything else that
/// needs escaping, then the character itself.
fn print_unicode(cp: u32) -> String {
    let needs_escape = if cp < 0x20 {
        true // C0 control characters
    } else if cp < 0x7f {
        matches!(cp, 92 | 0x22 | 0x27) // back-slash, double quote, single quote
    } else if cp < 0x100 {
        cp <= 0xa0 // DEL + the C1 control characters; A1-FF are printable
    } else {
        true // mosura's char constants never reach here (1 byte); Ghidra escapes by code-point class
    };
    if !needs_escape {
        return char::from_u32(cp).map(String::from).unwrap_or_else(|| char_hex_escape(cp));
    }
    match cp {
        0 => "\\0".into(),
        7 => "\\a".into(),
        8 => "\\b".into(),
        9 => "\\t".into(),
        10 => "\\n".into(),
        11 => "\\v".into(),
        12 => "\\f".into(),
        13 => "\\r".into(),
        92 => "\\\\".into(),
        0x22 => "\\\"".into(),
        0x27 => "\\'".into(),
        _ => char_hex_escape(cp),
    }
}

/// Ghidra `PrintC::printCharHexEscape` (`printc.cc:1512`): `\xNN` / `\xNNNN` / `\xNNNNNNNN`,
/// zero-padded to the width the code-point needs.
fn char_hex_escape(cp: u32) -> String {
    if cp < 256 {
        format!("\\x{cp:02x}")
    } else if cp < 65536 {
        format!("\\x{cp:04x}")
    } else {
        format!("\\x{cp:08x}")
    }
}

fn render_const(val: u64, size: u32) -> String {
    let signed = if size == 0 || size >= 8 {
        val as i64
    } else {
        let sh = 64 - 8 * size;
        ((val << sh) as i64) >> sh
    };
    if signed < 0 && signed > -0x10000 {
        // Ghidra `push_integer` prints a signed negative as `-` + the *magnitude* rendered in its
        // own most-natural base (printc.cc:1288: `print_negsign`, then the same ≤10-decimal /
        // `mostNaturalBase` choice applied to the magnitude) — so `-0x10`, not `-16`.
        let mag = signed.unsigned_abs();
        return if mag <= 10 || most_natural_base(mag) == 10 {
            format!("-{mag}")
        } else {
            format!("-0x{mag:x}")
        };
    }
    // Ghidra `push_integer`: small values (≤10) always decimal, otherwise the most natural base.
    if val <= 10 || most_natural_base(val) == 10 {
        format!("{val}")
    } else {
        format!("0x{val:x}")
    }
}

/// Decompile `f` to C text.
/// One parameter as `print_c` declares it: its convention storage, its size, and the input Varnode
/// backing it (`None` for a slot Ghidra materializes — see [`rendered_param_slots`]).
pub struct RenderedParam {
    pub addr: Address,
    pub size: u32,
    pub vn: Option<VarnodeId>,
}

/// The parameter list `print_c` renders, in declaration order.
///
/// Ghidra `ActionInputPrototype::apply` (coreaction.cc:4707) + `FuncProto::updateInputTypes`
/// (fspec.cc): every *used* trial becomes a parameter, in convention order. A trial the map marked
/// used but with no backing input Varnode is Ghidra's `isUnref() && isUsed()` case, and Ghidra
/// MATERIALIZES it —
/// ```text
///     vn = data.newVarnode(paramtrial.getSize(), paramtrial.getAddress());
///     vn = data.setInputVarnode(vn);
/// ```
/// — unless an existing input Varnode is in the way (`hasInputIntersection`, varnode.cc:1536), in
/// which case it is marked no-use and dropped. Numbering is by FINAL POSITION: `updateInputTypes`
/// writes each emitted parameter to `store->setInput(count, ...)` with a `count` that advances only
/// for parameters it emits, so the list is `param_1 .. param_N` with no gaps.
///
/// This print-time recovery used to SKIP the unreferenced slots, which silently renumbered the
/// signature: a function whose only argument arrives in EBX (watcall slot 3) printed as
/// `f(uint4 param_3)` — one parameter, correctly NAMED but declared in POSITION 1. Recompiled,
/// Watcom passes position 1 in EAX, so the argument lands in the wrong register and the function
/// cannot be byte-identical. WAR2's `FUN_0001b750` is the minimal case: the original is
/// `and ebx,0xff ; call [ebx*4+0x814b0]` and ours was `and eax,0xff ; call [eax*4+0x814b0]`.
/// 432 of 3023 emitted WAR2 functions carried such a renumbered signature.
///
/// `addr` is Ghidra's `ParameterPieces::addr`, the true storage. Plain C text cannot express it, so
/// a backend that must reproduce the original register assignment reads it here and declares it —
/// Watcom spells that `#pragma aux <name> parm [<regs>]`.
pub fn rendered_param_slots(f: &Funcdata) -> Vec<RenderedParam> {
    let proto = super::fspec::recover_func_proto(f);
    let find_used_input = |addr: Address, size: u32| -> Option<VarnodeId> {
        let mut fallback = None;
        for i in 0..f.num_varnodes() as u32 {
            let v = VarnodeId(i);
            let vn = f.vn(v);
            if vn.is_input() && !vn.descend.is_empty() && vn.loc == addr {
                if vn.size == size {
                    return Some(v);
                }
                fallback.get_or_insert(v);
            }
        }
        fallback
    };
    let has_input_intersection = |addr: Address, size: u32| -> bool {
        (0..f.num_varnodes() as u32).any(|i| {
            let vn = f.vn(VarnodeId(i));
            vn.is_input()
                && vn.loc.space == addr.space
                && vn.loc.offset < addr.offset + size as u64
                && addr.offset < vn.loc.offset + vn.size as u64
        })
    };
    let mut out = Vec::new();
    for slot in proto.params.iter() {
        if let Some(v) = find_used_input(slot.addr, slot.size) {
            out.push(RenderedParam { addr: slot.addr, size: slot.size, vn: Some(v) });
        } else if !has_input_intersection(slot.addr, slot.size) {
            out.push(RenderedParam { addr: slot.addr, size: slot.size, vn: None });
        }
    }
    out
}


/// Widen a recovered type to the width of the storage the value actually occupies.
///
/// The declared return type of a C function decides how wide a value the compiler leaves in the
/// return register: `int f()` produces a full 32-bit value, `bool f()` or `char f()` produce a
/// byte and leave the rest alone. So a recovered type NARROWER than the value the binary
/// actually produces is not a cosmetic difference — it deletes the widening instruction from the
/// recompiled function.
///
/// This is exactly what happens to a comparison result. Type inference sees a `SETcc` feeding
/// the return and settles on `bool`, which is true about the *value*; but the original function
/// zero-extends it to 32 bits (`AND EAX,0xff`), which is what C does when the declared type is
/// `int`. Emitting `bool` there loses that instruction in every such function — 86 of them in
/// the WAR2 survey, 9 of which have no other defect at all.
///
/// The rule triggers only when the IR itself says the value is wider than its type, so a
/// function that genuinely returns a byte (its returned Varnode *is* one byte) is untouched.
/// Signedness is preserved where it is known; a boolean or character widens to `int`, which is
/// the type C promotion would have given it in the original source.
/// How wide the emitted return type should be — an EMISSION CHOICE, selected by
/// [`EmitChoices::return_width`].
///
/// A function may compute a narrow value and return it in a wide register, and C forces a single
/// declaration to stand for both facts. The three answers differ in what the compiler is then made
/// to materialize:
///
/// - [`ReturnWidth::Value`] — the returned Varnode's own width, which is what the reference
///   decompiler prints. The compiler materializes only the bytes the value occupies.
/// - [`ReturnWidth::Recovered`] (default) — how much of the return storage the recovery found the
///   function to produce ([`Funcdata::output_storage_size`]).
/// - [`ReturnWidth::Storage`] — the convention's whole return-storage entry, whatever the recovery
///   credited. Recovers a zero-extension the original performs (`XOR EAX,EAX ; MOV AL,[m]`), and
///   invents one on a function that genuinely returns a byte.
///
/// Which is right is a property of the original and is not derivable from the IR, so it is searched
/// per function rather than decided here — see [`EmitChoices`] for the rules an axis must satisfy,
/// and `docs/byte-exact-status.md` for what each currently measures.
fn return_width(f: &Funcdata, vn: &super::varnode::Varnode, choices: &EmitChoices) -> u32 {
    let w = match choices.return_width {
        // What the reference decompiler prints: the value's own width, nothing widened.
        ReturnWidth::Value => vn.size,
        // How much of the return storage the recovery found this function to produce.
        ReturnWidth::Recovered => f.output_storage_size.unwrap_or(vn.size),
        // The convention's whole return-storage entry, whatever the recovery credited.
        ReturnWidth::Storage => f
            .proto_model
            .output
            .as_ref()
            .and_then(|out| {
                out.entry.iter().find(|e| e.justified_contain(vn.loc, vn.size) == Some(0)).map(|e| e.size)
            })
            .unwrap_or(vn.size),
    };
    w.max(vn.size)
}

fn widen_to_storage(ty: &Datatype, width: u32) -> Datatype {
    if width == 0 || ty.size() >= width {
        return ty.clone();
    }
    match ty {
        Datatype::Bool | Datatype::Char | Datatype::Int(_) => Datatype::Int(width),
        Datatype::Uint(_) => Datatype::Uint(width),
        // `undefined<N>` is a value of KNOWN WIDTH and unknown interpretation, so widening it is
        // the same question as widening an integer and has the same answer. Excluding it made this
        // choice inert on the type that dominates a stripped binary: across WAR2's 3023 functions
        // the storage arm changed 4 translation units, because nearly every recovered return type
        // is `undefined<N>` and fell into the catch-all below.
        Datatype::Unknown(_) => Datatype::Unknown(width),
        // Anything else (pointer, float, aggregate) narrower than its storage is not a promotion
        // question and is left for the type recovery to answer.
        other => other.clone(),
    }
}

/// Emit C for `f` under the reference rendering — the decompiler's own choices.
///
/// This is what every caller outside the byte-exact search wants, and what the whole test suite
/// uses: with [`EmitChoices::default`] the output is what it was before emission became
/// parameterized, so the port is unaffected by θ existing.
pub fn print_c(f: &Funcdata) -> String {
    print_c_with(f, &EmitChoices::default())
}

/// Emit C for `f` under an explicit choice vector — the `IR × θ → C` byte-exact recovery needs.
///
/// Every θ renders the same recovered program; see [`EmitChoices`] for the rules that keep that
/// true, and for why an axis is not a place to repair a decompilation defect.
pub fn print_c_with(f: &Funcdata, choices: &EmitChoices) -> String {
    let reg_space = f.spaces.by_name("register");

    // Parameters: the recovered function prototype (Ghidra `ActionInputPrototype` →
    // `FuncProto::deriveInputMap` → `ParamListStandard::fillinMap`, ported as
    // `fspec::recover_input_params`). This walks the calling convention's resource list — the float
    // registers `XMM0..7` then the integer registers `RDI..R9` then the stack overflow area — and
    // keeps the storage locations the convention deems used, *in convention order*. Slot `i` is
    // `param_{i+1}`. Replaces the former GP-only register table, which ignored XMM float parameters
    // and so mis-numbered the integer parameters that follow them.
    //
    // A slot is rendered only when backed by a *used* input Varnode (one with descendants). The
    // unreferenced "hole" slots that `fillinMap` synthesizes ahead of a used resource have no
    // backing Varnode at print time — Ghidra's `ActionInputPrototype` materializes them with
    // `newVarnode`/`setInputVarnode`, but this print-time recovery does not — so they are skipped,
    // keeping spurious leading params out of the signature when the body never reads them. The
    // param *number* stays the slot's convention position, so a lone used `RDX` still prints
    // `param_3`.
    let rendered = rendered_param_slots(f);
    let mut param_index: HashMap<Address, u32> = HashMap::new();
    let mut sig_params: Vec<(u32, Option<VarnodeId>, u32)> = Vec::new();
    for (i, r) in rendered.iter().enumerate() {
        let n = i as u32 + 1;
        if r.vn.is_some() {
            param_index.insert(r.addr, n);
        }
        sig_params.push((n, r.vn, r.size));
    }

    // Stage 0 (ir-cast-model): the render-time type re-inference is retired — types are read from the
    // committed `Varnode::ty` (`type_of`), which the final in-pipeline `ActionInferTypes` pass makes
    // authoritative. Parameter type-locks (Ghidra `ActionPrototypeTypes`) live in the in-pipeline
    // inference now, not a print-time `locks` map.

    // Pre-compute the addrtied-HighVariable info. `slot_write` marks a register value that is written
    // into an addrtied stack slot across a call — it is the input of an INDIRECT whose output is the
    // slot (the memory-increment `iStack_NN = iStack_NN + 1` whose value lives in a register). Such a
    // value is *explicit* and named like the slot, the way Ghidra renders the write to an addrtied
    // variable. This is the precise across-call-slot-write pattern, not every member of a stack
    // HighVariable (which would spill intermediate register arithmetic into stray statements).
    // `high_stack_off` names the merged HighVariable by its stack frame offset.
    // The HighVariables frozen by `merge::ActionMergeType` at Ghidra's merge slot (coreaction.cc:5727,
    // before `ActionSetCasts` at :5735). Consumed, never re-derived: recomputing `merge(f)` here would
    // run over the post-cast graph — a different varnode set than the one Ghidra merges — which is the
    // defect this freeze exists to fix. A missing value means the pipeline did not reach that slot, and
    // must fail loudly rather than silently fall back to the post-cast view.
    let t0 = std::time::Instant::now();
    let mut h = f
        .highs
        .as_ref()
        .expect("printc requires the HighVariables frozen by ActionMergeType; run pipeline::decompile")
        .union_find()
        .clone();
    // The CAST varnodes `ActionSetCasts` inserted after the freeze are not in it. Ghidra allocates a
    // fresh HighVariable for every new Varnode (`Funcdata::newVarnode`), so each becomes its own
    // singleton class — which is precisely what the cast varnodes are: a cast is not the same C
    // variable as its operand.
    h.extend_to(f.num_varnodes());
    if super::action::perf::enabled() {
        super::action::perf::record("print", "merge", t0.elapsed());
    }
    // Freeze the HighVariable representative of every Varnode, so the `&self` explicitness test can
    // compare two Varnodes' HighVariables (the cross-high COPY arm) without the `&mut` `h.high` needs.
    let high_of: Vec<u32> = (0..f.num_varnodes() as u32).map(|i| h.high(VarnodeId(i))).collect();
    // A global's HighVariable → its ram address, so a value merged into it is named/materialized by
    // that address (the ram analogue of `high_stack_off`, populated below). A HighVariable that also
    // holds a `stack` member is named by the stack slot instead (a stack local initialized from a
    // global stays `fStack_18`, not the global's `fRam..`), so those reps are excluded.
    let mut high_ram_off: HashMap<u32, u64> = HashMap::new();
    if let Some(ram) = f.spaces.by_name("ram") {
        let stack = f.spaces.by_name("stack");
        let mut stack_reps: HashSet<u32> = HashSet::new();
        if stack.is_some() {
            for i in 0..f.num_varnodes() as u32 {
                if Some(f.vn(VarnodeId(i)).loc.space) == stack {
                    stack_reps.insert(h.high(VarnodeId(i)));
                }
            }
        }
        for i in 0..f.num_varnodes() as u32 {
            let v = VarnodeId(i);
            if f.vn(v).loc.space == ram && f.vn(v).is_addrtied() && !stack_reps.contains(&h.high(v)) {
                high_ram_off.entry(h.high(v)).or_insert(f.vn(v).loc.offset);
            }
        }
    }
    let mut high_stack_off: HashMap<u32, u64> = HashMap::new();
    let mut slot_write = vec![false; f.num_varnodes()];
    if let Some(stk) = f.spaces.by_name("stack") {
        for i in 0..f.num_varnodes() as u32 {
            let v = VarnodeId(i);
            if f.vn(v).loc.space == stk {
                high_stack_off.entry(h.high(v)).or_insert(f.vn(v).loc.offset);
            }
        }
        for op in f.op_ids() {
            if f.op(op).code() == OpCode::Indirect {
                if let (Some(out), Some(inp)) = (f.op(op).output, f.op(op).input(0)) {
                    if f.vn(out).loc.space == stk && f.vn(inp).loc.space != stk {
                        slot_write[inp.0 as usize] = true;
                    }
                }
            }
        }
    }
    

    let mut p = PrintC {
        f,
        h,
        names: HashMap::new(),
        reg_space,
        ram_space: f.spaces.by_name("ram"),
        stack_space: f.spaces.by_name("stack"),
        stack_syms: super::varmap::recover_scope(f),
        stack_declared: std::collections::HashSet::new(),
        var_counter: 0,
        ret_val: None,
        for_loops: HashMap::new(),
        suppressed: HashSet::new(),
        array_elem: HashMap::new(),
        gotos: HashMap::new(),
        labels: HashSet::new(),
        decls: Vec::new(),
        slot_write,
        high_stack_off,
        high_ram_off,
        stack_sign_bit: f
            .spaces
            .by_name("stack")
            .map(|s| f.spaces.get(s).addr_size.saturating_mul(8).saturating_sub(1))
            .unwrap_or(63),
        unmapped_stack_names: HashMap::new(),
        force_explicit: HashSet::new(),
        param_index,
        high_of: high_of.clone(),
        high_members: {
            let mut m: HashMap<u32, Vec<VarnodeId>> = HashMap::new();
            for (i, &rep) in high_of.iter().enumerate() {
                m.entry(rep).or_default().push(VarnodeId(i as u32));
            }
            m
        },
        // Ghidra ActionCopyMarker (Merge::markInternalCopies, coreaction.cc:5729 — after all
        // merging, before ActionSetCasts): shadow assignments and redundant same-source COPYs are
        // marked non-printing. Frozen at that slot by `merge::ActionCopyMarker` and consumed here;
        // recomputing it now would run over the post-cast graph, whose COPY/PIECE/SUBPIECE outputs
        // `castOutput` has rewired to fresh uniques in fresh HighVariables.
        nonprinting: f
            .nonprinting
            .as_ref()
            .expect("printc requires the non-printing marks frozen by ActionCopyMarker; run pipeline::decompile"),
        comma_separate: false,
    };
    let t0 = std::time::Instant::now();
    p.array_elem = p.detect_arrays();
    p.ret_val = p.return_value();
    if super::action::perf::enabled() {
        super::action::perf::record("print", "detect_arrays+anchor", t0.elapsed());
    }

    let ret = p.return_value();
    // Return type: the returned Varnode's inferred HighVariable type — Ghidra's
    // `ActionOutputPrototype` → `FuncProto::updateOutputTypes` (fspec.cc:4159), which sets the output
    // type to `triallist[0]->getHigh()->getType()` when the prototype is not output-locked (the
    // stripped-binary case). No downgrade to `undefined`; `void` when there is no returned value.
    let ret_ty = ret.map_or("void".to_string(), |v| {
        // Width comes from the CONVENTION's return storage, not from the returned Varnode.
        // Later pipeline stages legitimately narrow that Varnode — a comparison result reaching a
        // RETURN ends up one byte wide even though the recovered output trial is the full
        // four-byte register — and a narrower declared type deletes the widening the original
        // performs. The convention is the stable statement of how wide a returned value is.
        let vn = f.vn(v);
        widen_to_storage(&p.type_of(v), return_width(f, vn, choices)).name()
    });
    // Signature parameters in convention order, each typed from its backing input Varnode.
    let plist: Vec<String> = sig_params
        .iter()
        .map(|&(n, v, sz)| match v {
            Some(v) => format!("{} param_{}", p.type_of(v).name(), n),
            None => format!("{} param_{}", super::types::Datatype::Unknown(sz).name(), n),
        })
        .collect();

    let t0 = std::time::Instant::now();
    // Consume the structure `ActionFinalStructure` left on the Funcdata (Ghidra: printc emits
    // `fd->getStructure()`, printc.cc:2660) — nothing runs between that slot and here, so it is
    // exactly what a fresh build would produce. The rebuild arm covers callers that print
    // without the full pipeline (probes, tests); the leaf-count check turns a missed
    // `structure_reset` into a loud rebuild instead of silently emitting a stale tree.
    let cached_valid = f.structure.as_ref().is_some_and(|c| {
        c.blocks.iter().filter(|b| matches!(b.kind, FlowKind::Basic(_))).count() == f.num_blocks()
    });
    debug_assert!(
        f.structure.is_none() || cached_valid,
        "stale structure cache: a CFG mutation missed structure_reset"
    );
    let s = if cached_valid { f.structure.clone().unwrap() } else { structure(f) };
    if super::action::perf::enabled() {
        super::action::perf::record("print", "structure", t0.elapsed());
    }
    // ⛔ THE STRUCTURED-TREE INVARIANT: every basic block the CFG has must be REACHED by the tree,
    // because a block the tree does not reach is never emitted. This is a HARD GATE, not a warning,
    // and it is deliberately the strongest one in the project — losing a block is worse than a panic
    // BECAUSE a panic is loud. A dropped block that still has an in-edge at least fails to compile
    // (`goto LAB_x` with no `LAB_x:`, wcc386 E1018). A dropped block with NO surviving in-edge
    // produces no goto, no compiler error, and a program that builds and is simply WRONG.
    //
    // `debug_assert` puts it on every corpus fixture and every unit test automatically. All 68 corpus
    // scans are clean (MISSING=0), so this holds today on x86-64; the known failures are x86-32/WAR2
    // functions, enumerated as an accepted baseline in task #5 and driven to zero under C1. The
    // assert is NOT scoped to only-clean functions to keep anything quiet — see
    // [`super::structure::reached_basic_blocks`].
    //
    // Release builds compile the assert out, so the WAR2 survey does not abort; it records
    // `blocks_cfg`/`blocks_reached` per function instead, which is how the population is censused.
    // `MOSURA_BLOCKSET=1` enumerates the missing blocks in any build.
    if cfg!(debug_assertions) || std::env::var("MOSURA_BLOCKSET").is_ok() {
        let reached = super::structure::reached_basic_blocks(&s);
        if reached.len() != f.num_blocks() {
            let missing: Vec<String> = (0..f.num_blocks())
                .filter(|b| !reached.contains(b))
                .map(|b| match f.block(super::block::BlockId(b as u32)).ops.first() {
                    Some(&op) => format!("blk{b}@{:#x}", f.op(op).seqnum.pc.offset),
                    None => format!("blk{b}@empty"),
                })
                .collect();
            let msg = format!(
                "structured tree lost {} of {} basic blocks in {}: [{}] — these are never emitted, \
                 so any in-edge renders as a goto to an undefined label and any block without one \
                 vanishes silently. See task #5 / structure::reached_basic_blocks.",
                missing.len(),
                f.num_blocks(),
                f.name,
                missing.join(" ")
            );
            if std::env::var("MOSURA_BLOCKSET").is_ok() {
                eprintln!(
                    "BLOCKSET {}: cfg={} reached={} MISSING={} [{}]",
                    f.name,
                    f.num_blocks(),
                    reached.len(),
                    missing.len(),
                    missing.join(" ")
                );
            }
            debug_assert!(false, "{}", msg);
        } else if std::env::var("MOSURA_BLOCKSET").is_ok() {
            eprintln!("BLOCKSET {}: cfg={} reached={} MISSING=0 []", f.name, f.num_blocks(), reached.len());
        }
    }
    p.gotos = s.gotos.clone();
    p.labels = s.labels.clone();
    for &root in &s.roots {
        p.detect_for_loops(&s, root);
    }
    // emit the body first so every local has been named (and recorded in `p.decls`), then assemble
    // signature + declarations + body, as Ghidra does.
    let t0 = std::time::Instant::now();
    let mut body = String::new();
    // `PrintC::emitBlockGraph` (printc.cc:2746), reached from printc.cc:2660 with
    // `fd->getStructure()`: emit EVERY top-level component, not just the entry's. A collapse that
    // could not reduce the graph to a single node is normal (see [`Structured::roots`]); emitting
    // only the first drops the others' whole subtrees, which is how WAR2 FUN_00077dcb lost four of
    // its eight basic blocks and a live CALL while its siblings kept jumping to labels in them.
    for &root in &s.roots {
        p.emit_structured(&s, root, 1, &mut body);
    }
    if super::action::perf::enabled() {
        super::action::perf::record("print", "emit", t0.elapsed());
    }
    let mut out = String::new();
    // An empty parameter list renders `(void)`, not `()` — Ghidra `PrintC::emitPrototypeInputs`
    // (printc.cc:2227): when `numParams() == 0` it prints the `void` keyword.
    let params = if plist.is_empty() { "void".to_string() } else { plist.join(", ") };
    let _ = writeln!(out, "{ret_ty} {}({})", f.name, params);
    out.push_str("{\n");
    // Ghidra emits local declarations in storage-Address order (`emitScopeVarDecls`); for stack
    // locals that is ascending frame address — most-negative offset first. A stable sort orders the
    // stack locals by offset and leaves register/temp locals (no offset) in first-use order.
    p.decls.sort_by(|a, b| match (a.2, b.2) {
        (Some(oa), Some(ob)) => oa.cmp(&ob),
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    for (name, ty, _) in &p.decls {
        match ty {
            // a recovered stack array declares the element type then the subscript: `T name [N];`
            // (Ghidra `xunknown4 axStack_98 [36]`) — the element type is its inferred type.
            Datatype::Array(elem, count) => {
                let _ = writeln!(out, "  {} {} [{}];", elem.name(), name, count);
            }
            _ => {
                let _ = writeln!(out, "  {} {};", ty.name(), name);
            }
        }
    }
    if !p.decls.is_empty() {
        out.push('\n');
    }
    out.push_str(&body);
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::build::raw_funcdata_flow;
    use crate::decompile::pipeline;
    use crate::sleigh::engine::Spec;
    use crate::{datatest, paths};

    #[test]
    fn emits_c_for_a_straight_line_function() {
        let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
        if !sla.exists() {
            return;
        }
        let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
        let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
        let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_sem.xml")).unwrap();
        let mut f = raw_funcdata_flow(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
        pipeline::decompile(&mut f);

        let c = print_c(&f);
        // well-formed: a signature line, balanced braces, and a return statement
        assert!(c.contains("func("), "has a signature:\n{c}");
        assert_eq!(c.matches('{').count(), c.matches('}').count(), "balanced braces:\n{c}");
        assert!(c.contains("return"), "has a return:\n{c}");
        // the body exactly matches Ghidra (modulo type names)
        assert!(c.contains("return param_1 * 3 + -5 + (param_2 >> 2);"), "body:\n{c}");
    }

    #[test]
    fn emits_structured_control_flow() {
        let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
        if !sla.exists() {
            return;
        }
        let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
        let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
        let dt = datatest::parse_file(&paths::datatests_dir().join("threedim.xml")).unwrap();
        let mut f = raw_funcdata_flow(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
        pipeline::decompile(&mut f);
        let c = print_c(&f);
        // threedim has a loop — the structurer recovers a for/while, well-nested
        assert!(c.contains("while (") || c.contains("for ("), "structured loop expected:\n{c}");
        assert_eq!(c.matches('{').count(), c.matches('}').count(), "balanced braces:\n{c}");
    }

    /// Stage 2 (WAR2): a `CPUI_CALLOTHER` (user-defined p-code op) must render as its SLEIGH userop
    /// name applied to the operands (Ghidra `PrintC::opCallother`, printc.cc:673), NOT leak the raw
    /// `CALLOTHER(...)` catch-all that the pre-fix printer emitted (the top COMPILE_FAIL feeder in
    /// the WAR2 survey: `E1063 Missing operand` on the `...`). The userop index→name map is threaded
    /// from the `.sla` (`Spec::userops`) onto the `Funcdata`.
    #[test]
    fn callother_renders_as_userop_name() {
        let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
        if !sla.exists() {
            return;
        }
        let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
        let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
        // `in eax, dx ; ret` (ED C3): EAX = in(DX), returned in the SysV result register.
        let mut f = raw_funcdata_flow(&spec, "func", &[0xED, 0xC3], 0x1000, &ctx);
        pipeline::decompile(&mut f);
        let c = print_c(&f);
        assert!(c.contains("in("), "CALLOTHER should render as the `in` userop name:\n{c}");
        assert!(!c.contains("CALLOTHER(...)"), "raw CALLOTHER catch-all must not leak:\n{c}");

        // `rdtsc ; ret` (0F 31 C3): the no-argument `rdtsc` userop.
        let mut f2 = raw_funcdata_flow(&spec, "func", &[0x0F, 0x31, 0xC3], 0x1000, &ctx);
        pipeline::decompile(&mut f2);
        let c2 = print_c(&f2);
        assert!(c2.contains("rdtsc()"), "CALLOTHER should render as `rdtsc()`:\n{c2}");
    }

    /// WAR2 E1079/E1080: a pointer-typed value fed to an integral op (`&`, `-`, …) must be cast,
    /// not left bare (`wcc386` rejects `ptr & -4` / `-ptr`). Ghidra's base `TypeOp::getInputCast`
    /// (`castStandard(reqtype, cur, false, true)`, care_ptr_uint=true) inserts the cast; mosura's
    /// render-time port must too. `mov %rdi,%rax ; and $0xf,%eax ; add (%rdi),%rax ; ret`
    /// (`48 89 f8 83 e0 0f 48 03 07 c3`, gcc -O1 of `*p + ((long)p & 0xf)`): RDI is dereferenced
    /// (=> pointer) AND masked (=> fed to INT_AND). Pre-fix mosura emitted `param_1 & 0xf` (bare
    /// pointer in `&` = E1079); post-fix it casts the operand.
    #[test]
    fn pointer_in_integral_op_is_cast() {
        let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
        if !sla.exists() {
            return;
        }
        let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
        let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
        let bytes = [0x48, 0x89, 0xf8, 0x83, 0xe0, 0x0f, 0x48, 0x03, 0x07, 0xc3];
        let mut f = raw_funcdata_flow(&spec, "func", &bytes, 0x1000, &ctx);
        pipeline::decompile(&mut f);
        let c = print_c(&f);
        // The pointer `param_1` fed to `&` must carry an integral cast (Ghidra `(uint)param_1`),
        // not be left bare (`param_1 & 0xfU`, the E1079 pre-fix rendering). x86-64's 8-byte
        // pointer casts to `uint8`; WAR2's 4-byte pointer would render `(uint)`.
        assert!(
            c.contains("(uint8)param_1 & 0xf"),
            "pointer param_1 fed to `&` must be cast (E1079), got:\n{c}"
        );
    }

    /// `extraout_<reg>` names ONLY a register value CREATED by a call side effect (Ghidra
    /// `database.cc:2492`, gated on `Varnode::indirect_creation`). A value merely RELAYED across a
    /// call by a guarding INDIRECT (its input is the live pre-call value — e.g. a stack base carried
    /// in a caller-clobbered register) is NOT a creation and must be named as an ordinary local, not
    /// `extraout_`. In `partialsplit`, the else-block store target is such a relay (RDI = INDIRECT of
    /// the RSP-derived base, `indirect_creation=false`); the isolated oracle (`oracle/capture --c`)
    /// names it `puVar3`, never `extraout_`. Pre-fix mosura mis-rendered it `*extraout_RDI`.
    #[test]
    fn relayed_indirect_register_is_not_named_extraout() {
        let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
        if !sla.exists() {
            return;
        }
        let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
        let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
        let dt = datatest::parse_file(&paths::datatests_dir().join("partialsplit.xml")).unwrap();
        let mut f = raw_funcdata_flow(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
        pipeline::decompile(&mut f);
        let c = print_c(&f);
        // The relayed INDIRECT-output register must not surface as an `extraout_` artifact — the
        // isolated Ghidra oracle names it a local pointer (`puVar3`), with no `extraout_` anywhere.
        assert!(!c.contains("extraout_"), "relayed INDIRECT must not be named extraout_:\n{c}");
    }

    /// Ghidra `PrintC::pushCharConstant` / `printUnicode` (printc.cc:1606/1426). The escape table is
    /// exactly the kind of thing that is wrong in one entry and never noticed, so it is pinned here
    /// rather than only observed through a fixture.
    #[test]
    fn char_constants_render_as_c_character_literals() {
        // The named C escapes, in Ghidra's order.
        for (val, want) in [
            (0u64, "'\\0'"),
            (7, "'\\a'"),
            (8, "'\\b'"),
            (9, "'\\t'"),
            (10, "'\\n'"),
            (11, "'\\v'"),
            (12, "'\\f'"),
            (13, "'\\r'"),
            (92, "'\\\\'"),
            (0x22, "'\\\"'"),
            (0x27, "'\\\''"),
        ] {
            assert_eq!(push_char_constant(val, 1).as_deref(), Some(want), "val={val:#x}");
        }
        // A control character with no named escape falls to the generic hex form, zero-padded.
        assert_eq!(push_char_constant(1, 1).as_deref(), Some("'\\x01'"));
        assert_eq!(push_char_constant(0x1f, 1).as_deref(), Some("'\\x1f'"));
        // DEL is a C1-adjacent control character and is escaped (printlanguage.cc:426).
        assert_eq!(push_char_constant(0x7f, 1).as_deref(), Some("'\\x7f'"));
        // Printable ASCII prints as itself.
        assert_eq!(push_char_constant(0x41, 1).as_deref(), Some("'A'"));
        assert_eq!(push_char_constant(0x20, 1).as_deref(), Some("' '"));
        assert_eq!(push_char_constant(0x7e, 1).as_deref(), Some("'~'"));
        // At 0x80 and above a single byte is not a code-point — Ghidra prints an integer instead,
        // and `None` is how that decision comes back here (printc.cc:1629).
        assert_eq!(push_char_constant(0x80, 1), None);
        assert_eq!(push_char_constant(0xff, 1), None);
    }
}
