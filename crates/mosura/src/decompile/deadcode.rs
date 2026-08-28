//! Dead-code elimination — Ghidra's `ActionDeadCode` (`coreaction.cc`).
//!
//! Liveness is seeded from side-effecting ops (returns, branches, stores, calls all
//! consume their inputs) and propagated backward: a consumed varnode keeps its defining
//! op, whose inputs are in turn consumed. Ops that are never reached — dead computations,
//! and the ops the rule pool collapsed — are removed.
//!
//! Ghidra tracks *which bits* are consumed (so an op computing only unused bits can go);
//! this is the whole-varnode core (consume = all-or-nothing). The consume-bits refinement
//! and addrtied/persistent live-out roots are later additions.

use super::block::BlockId;
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::varnode::VarnodeId;

/// Does this op have a side effect that makes it (and its inputs) live regardless of
/// whether its output is used?
fn is_sink(code: OpCode) -> bool {
    use OpCode::*;
    matches!(
        code,
        Return | Branch | Cbranch | Branchind | Store | Call | Callind | Callother
    )
}

/// Remove ops whose results are never consumed.
pub fn dead_code(f: &mut Funcdata) {
    // INSTRUMENT (`MOSURA_DEADCODE_DEBUG=1`): the flags dead-code decides on, per spacebase varnode,
    // BEFORE this pass runs — which auto-live roots exist and whether the directwrite-driven
    // addrforce clear is about to strip them (the W4 dropped-store investigation).
    if crate::debug::on(crate::debug::Topic::Pipeline) {
        for i in 0..f.num_varnodes() as u32 {
            let vn = f.vn(VarnodeId(i));
            if f.spaces.get(vn.loc.space).kind == super::space::SpaceKind::Spacebase && vn.is_written() {
                debug!(crate::debug::Topic::Pipeline,
                    "deadcode-in s{:#x}:{} def={:?} addrforce={} directwrite={} autolive={} pending_clear={}",
                    vn.loc.offset, vn.size, vn.def.map(|d| f.op(d).seqnum.pc.offset), vn.is_addr_force(),
                    vn.is_direct_write(), vn.is_auto_live(), f.directwrite_pending_clear
                );
            }
        }
    }
    // Ghidra clears the `addrforce` attribute of any varnode that is not a direct write at the top
    // of every `ActionDeadCode::apply` (coreaction.cc:3944) — so a value forced into its storage
    // stays auto-live only if a legitimate input feeds it. mosura runs this only on the deadcode
    // immediately following an `ActionDirectWrite` pass (the flag), because its rotated pipeline has
    // extra deadcodes Ghidra lacks (see `Funcdata::directwrite_pending_clear`). Persistent effect:
    // once stripped, the varnode is no longer auto-live below.
    if f.directwrite_pending_clear {
        for i in 0..f.num_varnodes() as u32 {
            let vn = f.vn(VarnodeId(i));
            if vn.is_addr_force() && !vn.is_direct_write() {
                f.vn_mut(VarnodeId(i)).clear_addr_force();
            }
        }
        f.directwrite_pending_clear = false;
    }

    let n_ops = f.num_ops();
    let mut live_op = vec![false; n_ops];
    let mut live_vn = vec![false; f.num_varnodes()];
    let mut worklist: Vec<VarnodeId> = Vec::new();

    // seed: side-effecting ops are live and consume all their inputs
    for i in 0..n_ops as u32 {
        let op = OpId(i);
        if is_sink(f.op(op).code()) {
            live_op[i as usize] = true;
            for &v in &f.op(op).inrefs {
                if !live_vn[v.0 as usize] {
                    live_vn[v.0 as usize] = true;
                    worklist.push(v);
                }
            }
        }
    }

    // The return value reaches the caller through the RETURN op (ActionReturnRecovery wired
    // it as an input), so the RETURN sink above already keeps it — no live-out register seed.

    // (A blanket "every written ram varnode is live" root used to sit here. Ghidra has no such
    // rule: a global's live-out visibility is carried by the GUARD STRUCTURE heritage builds —
    // the persist branch of `guardReturns` (heritage.cc:1676-1691) reads the LAST version into a
    // `markReturnCopy` COPY whose output is `addrForce` (an auto-live root below), and
    // `guardCalls`' INDIRECTs relay versions across calls — so the final write chain is live and
    // a SUPERSEDED intermediate write dies like any other dead value. Both guards are ported
    // (`heritage::guard_returns`/`guard_calls`), making the blanket redundant for the live-out
    // and wrong for the intermediates: on WAR2 FUN_00021b84's `mov byte [0x8196c], 1` site it
    // kept two superseded byte-stores (`uRam._0_1_ = 0;` / `= 1;`) that Ghidra's output does not
    // have, and their covers then forced the 3-byte piece between them explicit — the
    // non-legalizable `._1_3_` partial of the E1032 family.)

    // Auto-live roots (Ghidra `Varnode::isAutoLive` = addrforce | autolive_hold): a varnode forced
    // into its storage is exempt from removal even when nothing reads it. `Heritage::guardCalls`
    // sets addrforce on the INDIRECT that carries an aliased *mapped* stack local across a call;
    // seeding it here keeps that INDIRECT chain, and the backward consume preserves the write-only
    // spill store feeding it — the precise gate that distinguishes a real local from the
    // return-address / call-mechanism pushes (which are below the alias boundary, never guarded).
    for i in 0..f.num_varnodes() as u32 {
        let vn = f.vn(VarnodeId(i));
        if vn.is_written() && vn.is_auto_live() && !live_vn[i as usize] {
            live_vn[i as usize] = true;
            worklist.push(VarnodeId(i));
        }
    }

    // Pre-live roots — Ghidra `ActionDeadCode::apply`'s "Set pre-live registers" block
    // (coreaction.cc:3950-3961). Every Varnode in a space whose dead-code removal is NOT yet
    // allowed is marked FULLY CONSUMED. `Heritage::deadRemovalAllowed` (heritage.cc:2829) is
    // `pass > deadcodedelay`, so a space stays protected until it has actually been through
    // heritage: until then its Varnodes are still free, nothing links them to their reaching defs,
    // and "nothing reads this" is not evidence of deadness — it is evidence that SSA has not been
    // built yet. Ghidra's own comment on the guard is "Mark consumed if we have NOT heritaged".
    //
    // Ghidra tests `doesDeadcode()` rather than `isHeritaged()`; the two flags are set and cleared
    // together at every site in space.cc (:78, :95, :359, :399, :406), so this is that predicate.
    //
    // Inert while mosura primed heritage to COMPLETION before the first dead-code sweep — every
    // space was already heritaged, so the guard never fired. Reducing the prime to Ghidra's single
    // pass (which is what gives the stack-pointer placeholder its resolution window) makes the
    // ram/stack spaces genuinely un-heritaged during mainloop iteration 1, and this is what stops
    // their Varnodes being deleted as "unread" in that window.
    for i in 0..f.spaces.num_spaces() {
        let spc = super::space::SpaceId(i as u32);
        if !f.spaces.get(spc).is_heritaged() || super::heritage::dead_removal_allowed(f, spc) {
            continue;
        }
        for v in 0..f.num_varnodes() as u32 {
            if f.vn(VarnodeId(v)).loc.space == spc && !live_vn[v as usize] {
                live_vn[v as usize] = true;
                worklist.push(VarnodeId(v));
            }
        }
    }

    // propagate backward: a consumed varnode keeps its def op, whose inputs are consumed
    while let Some(vn) = worklist.pop() {
        // Ghidra's `case CPUI_INDIRECT` (coreaction.cc:3650-3662) additionally marks the op an
        // INDIRECT guards (its `iop`) fully consumed when that op is an overlapping COPY. In Ghidra
        // one sweep computes both the consume masks and the removal decision, so that single
        // `pushConsumed(~0, indop->getOut(), …)` is what keeps the COPY from being destroyed while
        // live INDIRECTs still point at it. mosura splits the action in two — the mask half is
        // `consume::calc_consume`, and *this* whole-varnode sweep is the removal half — so the same
        // branch has to be applied to this sweep's liveness, which is what the removal actually
        // reads. Without it, dead-code destroys the guarded COPY, its INDIRECTs strand in a
        // marker-only block, `ActionDoNothing` removes that block while their outputs are still
        // read, and the faithful "deleting op with descendants" assert fires
        // (Ghidra throws the same, funcdata_block.cc:311).
        if let Some((Some(full), _src)) = super::consume::indirect_source(f, vn) {
            if !live_vn[full.0 as usize] {
                live_vn[full.0 as usize] = true;
                worklist.push(full);
            }
        }
        let Some(def) = f.vn(vn).def else { continue };
        if live_op[def.0 as usize] {
            continue;
        }
        live_op[def.0 as usize] = true;
        for &v in &f.op(def).inrefs {
            if !live_vn[v.0 as usize] {
                live_vn[v.0 as usize] = true;
                worklist.push(v);
            }
        }
    }

    // remove the dead ops from their blocks and detach them from the graph
    for b in 0..f.num_blocks() as u32 {
        let blk = BlockId(b);
        let (kept, dead): (Vec<OpId>, Vec<OpId>) =
            f.block(blk).ops.iter().partition(|&&op| live_op[op.0 as usize]);
        f.set_block_ops(blk, kept);
        for op in dead {
            f.op_destroy(op);
        }
    }
}

/// The pipeline action wrapper (Ghidra's `ActionDeadCode`).
pub struct ActionDeadCode;

impl super::action::Action for ActionDeadCode {
    fn name(&self) -> &str {
        "deadcode"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let before = (0..data.num_ops() as u32).filter(|&i| !data.op(OpId(i)).is_dead()).count();
        // Ghidra's `ActionDeadCode::apply` is ONE pass: it computes the consume masks, runs the
        // `neverConsumed` sweep, and removes unreached ops. mosura's two halves are
        // `consume::calc_consume` (masks + neverConsumed, coreaction.cc:3925/4046) and the
        // whole-varnode sweep below; they are composed HERE so that every pipeline instance of
        // "deadcode" behaves like Ghidra's one action. (They used to run as separate members at
        // separate slots — `consume` between nzmask and infertypes, the sweep after the pools —
        // neither at Ghidra's :5503; docs/compilable-c-remediation.md CORRECTION 2 records what
        // that did to rule outcomes.)
        super::consume::calc_consume(data);
        dead_code(data);
        let after = (0..data.num_ops() as u32).filter(|&i| !data.op(OpId(i)).is_dead()).count();
        (before - after) as u32
    }
}
