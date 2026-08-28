//! Call-mechanism stack modelling — the return-address-push half of what Ghidra's
//! `ActionStackPtrFlow` handles. A forward symbolic pass tracks each location's value as an
//! offset from the entry stack pointer so each x86 `call`'s return-address push can be
//! neutralized (RSP net-unchanged across the call, the callee's `ret` popping the slot) and
//! its constant return-address store landed at the real pushed `stack` slot.
//!
//! The *general* stack LOAD/STORE resolution is NOT done here: it is Ghidra's in-pool
//! mechanism — `RuleLoadVarnode`/`RuleStoreVarnode`'s spacebase-register branch
//! (`checkSpacebase`/`correctSpacebase`, ruleaction.cc:4173-4334, actprop2) converts a
//! `RSP_input [+ const]` LOAD/STORE into a direct addrtied `stack`-space COPY inside the
//! iterating mainloop, and the next iteration's `ActionHeritage` gives the slot SSA form.
//! (This module's pre-heritage symbolic tracker used to convert them all — a loose superset
//! of `correctSpacebase` that also resolved COPY/MULTIEQUAL-of-RSP, over-resolving the
//! indexed/derived accesses Ghidra deliberately keeps indirect; task #22-B cancelled it.)
//!
//! Tracking from the entry RSP unifies frame-pointer (RBP) and frameless (RSP) frames —
//! `mov rbp, rsp` simply copies the current offset into RBP. It runs pre-heritage (reads
//! aren't yet linked to defs), which is why the value is tracked by location rather than
//! followed through the def graph.

use std::collections::HashMap;

use super::action::Action;
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::{Address, SpaceId};
use super::varnode::VarnodeId;

/// Ghidra `CompilerSpec`'s `<stackpointer>` register, carried on [`Funcdata::stack_pointer`]. This
/// used to be `const RSP: u64 = 0x20`, an x86-64 constant — which made this whole pass INERT on
/// `x86:LE:32`, where the register file puts ESP at `0x10` (Ghidra `ia.sinc`, `@else` branch) and
/// `0x20` is past the general-purpose block. A seed matching no register does not fail loudly; it
/// simply never propagates, so no stack Varnode is ever created and every frame slot renders as an
/// offset from an unmodelled register.
fn stack_pointer(f: &Funcdata) -> Option<(SpaceId, u64)> {
    f.stack_pointer.map(|a| (a.space, a.offset))
}

type Loc = (SpaceId, u64);

fn loc_of(f: &Funcdata, v: VarnodeId) -> Loc {
    let vn = f.vn(v);
    (vn.loc.space, vn.loc.offset)
}

/// The stack offset this op's output holds, if it computes `entry_rsp + constant`.
fn symbolic_value(f: &Funcdata, o: &super::op::PcodeOp, sval: &HashMap<Loc, i64>) -> Option<i64> {
    let tracked = |v: VarnodeId| sval.get(&loc_of(f, v)).copied();
    let cval = |v: VarnodeId| f.vn(v).is_constant().then(|| f.vn(v).constant_value() as i64);
    match o.code() {
        OpCode::Copy => tracked(o.input(0)?),
        OpCode::IntAdd => {
            let (a, b) = (o.input(0)?, o.input(1)?);
            if let (Some(av), Some(bc)) = (tracked(a), cval(b)) {
                return Some(av + bc);
            }
            if let (Some(bv), Some(ac)) = (tracked(b), cval(a)) {
                return Some(bv + ac);
            }
            None
        }
        OpCode::IntSub => {
            let (a, b) = (o.input(0)?, o.input(1)?);
            Some(tracked(a)? + cval(b).map(|c| -c)?)
        }
        _ => None,
    }
}

/// Detect each CALL's return-address push — the x86 `call` SLEIGH emits
/// `RSP = RSP - N; STORE RSP, <next-insn>; CALL`. Returns, for every call that has both the push
/// (`RSP = RSP - N`) and the constant return-address store, the push op and the push amount `N`.
///
/// [`recover_stack`] uses this to model the call mechanism faithfully (the spirit of Ghidra's
/// `ActionStackPtrFlow`, `coreaction.cc`): it keeps the return-address store — Ghidra keeps it, and
/// it survives as `xStack_NN = <retaddr>` when the pushed slot is an aliased mapped local
/// (`wayoffarray`), or is removed by dead-code otherwise — but neutralizes the push to an identity
/// COPY *after* converting the store, so the store lands at the real pushed slot while RSP is
/// net-unchanged across the call (the callee's `ret` pops those `N` bytes; the default prototype
/// marks the stack pointer `unaffected`).
fn call_push_restores(f: &Funcdata) -> HashMap<OpId, (OpId, OpId, i64)> {
    let mut out = HashMap::new();
    let Some(sp) = stack_pointer(f) else { return out };
    let is_rsp = |v: VarnodeId, f: &Funcdata| {
        let vn = f.vn(v);
        (vn.loc.space, vn.loc.offset) == sp
    };
    let calls: Vec<_> = f
        .op_ids()
        .filter(|&op| matches!(f.op(op).code(), OpCode::Call | OpCode::Callind))
        .collect();
    for call in calls {
        let pc = f.op(call).seqnum.pc;
        // Scan backward over the ops emitted by the same `call` instruction for its push/store.
        let mut store: Option<OpId> = None;
        let mut push: Option<(OpId, i64)> = None;
        let mut i = call.0 as usize;
        while i > 0 {
            i -= 1;
            let op = OpId(i as u32);
            if f.op(op).seqnum.pc != pc {
                break; // left this instruction's micro-ops
            }
            match f.op(op).code() {
                // the return-address store: STORE [RSP], <constant return address>
                OpCode::Store
                    if store.is_none()
                        && f.op(op).input(1).is_some_and(|a| is_rsp(a, f))
                        && f.op(op).input(2).is_some_and(|v| f.vn(v).is_constant()) =>
                {
                    store = Some(op);
                }
                // the push: RSP = RSP - <const>
                OpCode::IntSub
                    if push.is_none()
                        && f.op(op).output.is_some_and(|o| is_rsp(o, f))
                        && f.op(op).input(0).is_some_and(|a| is_rsp(a, f))
                        && f.op(op).input(1).is_some_and(|c| f.vn(c).is_constant()) =>
                {
                    let amt = f.vn(f.op(op).input(1).unwrap()).constant_value() as i64;
                    push = Some((op, amt));
                }
                _ => {}
            }
        }
        debug!(crate::debug::Topic::StackVars, "match call@{:x} store={:?} push={:?}", pc.offset, store.is_some(), push.is_some());
        if let (Some(s), Some((p, amt))) = (store, push) {
            out.insert(call, (s, p, amt));
        }
    }
    out
}

/// Model the call mechanism's return-address push (per [`call_push_restores`]), propagating the
/// stack pointer over the CFG: each block's entry stack state is a processed predecessor's exit
/// state (the pre-heritage analog of the SSA MULTIEQUAL phi-join Ghidra's `StackSolver` relies
/// on), so the stack pointer no longer drifts across independent blocks the flat op order
/// interleaves. Only each call's return-address STORE is converted to its `stack` slot; every
/// other stack LOAD/STORE is left for the in-pool `RuleLoadVarnode`/`RuleStoreVarnode`
/// spacebase-register branch (see the module docs).
pub fn recover_stack(f: &mut Funcdata) {
    let (Some(_reg), Some(stack)) = (f.spaces.by_name("register"), f.spaces.by_name("stack")) else {
        return;
    };
    // No compiler spec ⇒ no stack pointer ⇒ nothing to recover, exactly as an empty `proto_model`
    // recovers no prototype.
    let Some(sp) = stack_pointer(f) else { return };
    let nblk = f.num_blocks();
    if nblk == 0 {
        return;
    }
    let call_restores = call_push_restores(f);
    let retaddr_stores: std::collections::HashSet<OpId> =
        call_restores.values().map(|&(store, _, _)| store).collect();
    let entry_sval = HashMap::from([(sp, 0i64)]);
    let mut sval_out: Vec<Option<HashMap<Loc, i64>>> = vec![None; nblk];

    // Process blocks in reverse postorder so each block's forward-edge predecessors are processed
    // before it (the loop back-edge predecessor is processed after the header, which already has the
    // loop-invariant stack pointer from the pre-header). Any block unreachable from the entry is
    // visited last with the entry seed.
    let mut order: Vec<usize> = super::dominator::postorder(f);
    order.reverse();
    let mut in_order = vec![false; nblk];
    for &b in &order {
        in_order[b] = true;
    }
    order.extend((0..nblk).filter(|&b| !in_order[b]));

    for b in order {
        let bid = super::block::BlockId(b as u32);
        // Entry state: a processed predecessor's exit state; the entry block (no preds) seeds RSP=0.
        let mut sval: HashMap<Loc, i64> = {
            let preds: Vec<usize> = f.block(bid).in_edges.iter().map(|e| e.0 as usize).collect();
            preds.iter().find_map(|&p| sval_out[p].clone()).unwrap_or_else(|| entry_sval.clone())
        };
        let ops = f.block(bid).ops.clone();
        for op in ops {
            if f.op(op).is_dead() {
                continue;
            }
            let o = f.op(op).clone();
            match o.code() {
                // ONLY each call's return-address store is converted here (the call-mechanism
                // model); a general stack STORE stays a STORE for the in-pool RuleStoreVarnode.
                OpCode::Store if retaddr_stores.contains(&op) => {
                    if let (Some(addr), Some(val)) = (o.input(1), o.input(2)) {
                        if let Some(&c) = sval.get(&loc_of(f, addr)) {
                            debug!(crate::debug::Topic::StackVars, "store@{:x} slot={:x}", o.seqnum.pc.offset, c);
                            let size = f.vn(val).size;
                            f.op_set_all_input(op, &[val]);
                            f.op_set_opcode(op, OpCode::Copy);
                            f.new_output(op, size, Address::new(stack, c as u64));
                            continue;
                        }
                    }
                }
                OpCode::Call | OpCode::Callind => {
                    // The return-address store (one of the ops above, already converted to its
                    // `stack`-space slot) is kept; now neutralize the push to an identity COPY so RSP
                    // is net-unchanged across the call, and add the push amount back to the tracked
                    // RSP (modelling the callee's `ret` pop). Done here, after the store conversion,
                    // so the store lands at the real pushed slot rather than the pre-push one.
                    if let Some(&(_, push, amt)) = call_restores.get(&op) {
                        let base = f.op(push).input(0).unwrap();
                        f.op_set_opcode(push, OpCode::Copy);
                        f.op_set_all_input(push, &[base]);
                        if let Some(v) = sval.get_mut(&sp) {
                            *v += amt;
                        }
                        // Record the cancelled push so the extrapop consumers (the KNOWN-case
                        // INT_ADD and the unknown-case solver guess) model only the delta BEYOND
                        // the return-address pop this rewrite already restored. Without it the
                        // ret-pop counts twice (see `CallSpec::push_neutralized`).
                        f.call_specs.entry(op).or_default().push_neutralized = Some(amt);
                    }
                }
                _ => {}
            }
            // propagate the stack-offset value through the op's output
            if let Some(out) = o.output {
                let outloc = loc_of(f, out);
                match symbolic_value(f, &o, &sval) {
                    Some(v) => {
                        sval.insert(outloc, v);
                    }
                    None => {
                        sval.remove(&outloc);
                    }
                }
            }
        }
        sval_out[b] = Some(sval);
    }
}

// ---------------------------------------------------------------------------
// Ghidra `ActionStackPtrFlow` (coreaction.cc:481) and its `StackSolver` (coreaction.cc:33).
//
// This is the consuming half of `ActionExtraPopSetup` (pipeline.rs). That action marks every
// call whose stack effect is unknown with an `INDIRECT` on the stack pointer; on its own that
// leaves the stack pointer permanently indeterminate after every call. `analyzeExtraPop` is what
// resolves those marks: it builds a linear system over every reference to the stack pointer,
// solves it, and rewrites *each* solved stack-pointer definition into `sp_input + <constant>` —
// turning the INDIRECTs back into concrete adds and recording the recovered per-call
// `effectiveExtraPop`. The two actions are one mechanism and only work landed together.
// ---------------------------------------------------------------------------

/// Ghidra's `StackEqn` (coreaction.cc:25): `var1 - var2 = rhs`.
#[derive(Clone, Copy)]
struct StackEqn {
    var1: i32,
    var2: i32,
    rhs: i32,
}

/// Ghidra's sentinel for "no solution yet" (coreaction.cc:69, a literal `65535` throughout).
const NO_SOLN: i32 = 65535;

/// Ghidra `StackSolver` (coreaction.cc:33): solves for the stack-pointer change across calls
/// whose `extrapop` is unknown.
#[derive(Default)]
struct StackSolver {
    /// Equations from ops that explicitly change the stack pointer.
    eqs: Vec<StackEqn>,
    /// Guessed equations, for the underdetermined part of the system.
    guess: Vec<StackEqn>,
    /// The indexed variable set: one entry per reference to the stack pointer.
    vnlist: Vec<VarnodeId>,
    /// Per variable, the index of the companion input for an `INDIRECT`-produced variable.
    companion: Vec<i32>,
    /// Per variable, its solution (or [`NO_SOLN`]).
    soln: Vec<i32>,
    /// Variables for which no equation could be formed.
    missedvariables: i32,
}

impl StackSolver {
    /// Ghidra `StackSolver::propagate` (coreaction.cc:67): given a solution for one variable, walk
    /// the equations solving every variable it reaches.
    fn propagate(&mut self, varnum: i32, val: i32) {
        if self.soln[varnum as usize] != NO_SOLN {
            return; // this variable is already specified
        }
        self.soln[varnum as usize] = val;
        let mut workstack: Vec<i32> = vec![varnum];
        while let Some(varnum) = workstack.pop() {
            // Ghidra `lower_bound` into the var1-sorted equation list, then walks the run of
            // equations sharing var1.
            let mut top = self.eqs.partition_point(|e| e.var1 < varnum);
            while top < self.eqs.len() && self.eqs[top].var1 == varnum {
                let var2 = self.eqs[top].var2;
                if self.soln[var2 as usize] == NO_SOLN {
                    self.soln[var2 as usize] =
                        self.soln[varnum as usize].wrapping_sub(self.eqs[top].rhs);
                    workstack.push(var2);
                }
                top += 1;
            }
        }
    }

    /// Ghidra `StackSolver::duplicate` (coreaction.cc:96): mirror every equation (multiply by -1)
    /// so `propagate` can traverse them in either direction, then sort by `var1`.
    fn duplicate(&mut self) {
        let size = self.eqs.len();
        for i in 0..size {
            let e = self.eqs[i];
            self.eqs.push(StackEqn { var1: e.var2, var2: e.var1, rhs: e.rhs.wrapping_neg() });
        }
        // Ghidra uses `stable_sort` with `StackEqn::compare` (var1 only).
        self.eqs.sort_by_key(|e| e.var1);
    }

    /// Ghidra `StackSolver::solve` (coreaction.cc:112): propagate from the known input variable,
    /// then use the guesses to resolve the subsystems that are not uniquely determined.
    fn solve(&mut self) {
        self.soln.clear();
        self.soln.resize(self.vnlist.len(), NO_SOLN);
        self.duplicate();
        self.propagate(0, 0); // the input value of the stack pointer is 0 by definition
        let size = self.guess.len();
        let mut lastcount = size as i32 + 2;
        loop {
            let mut count = 0;
            for i in 0..size {
                let (var1, var2, rhs) =
                    (self.guess[i].var1, self.guess[i].var2, self.guess[i].rhs);
                let (s1, s2) = (self.soln[var1 as usize], self.soln[var2 as usize]);
                if s1 != NO_SOLN && s2 == NO_SOLN {
                    self.propagate(var2, s1.wrapping_sub(rhs));
                } else if s1 == NO_SOLN && s2 != NO_SOLN {
                    self.propagate(var1, s2.wrapping_add(rhs));
                } else if s1 == NO_SOLN && s2 == NO_SOLN {
                    count += 1;
                }
            }
            if count == lastcount {
                break;
            }
            lastcount = count;
            if count == 0 {
                break;
            }
        }
    }

    /// Ghidra `StackSolver::build` (coreaction.cc:147): collect every reference to the stack
    /// pointer as a variable and read its defining op for an equation.
    ///
    /// Returns `Err` where Ghidra throws `LowlevelError` ("Input value of stackpointer is not
    /// used"), which the caller turns into a warning header and a bail-out.
    fn build(&mut self, f: &Funcdata, sb_addr: Address, sb_size: u32) -> Result<(), &'static str> {
        // Ghidra range-queries the live `VarnodeLocSet` (`beginLoc(size,spacebase)`), which is
        // ordered by `VarnodeCompareLocDef`: address, size, then input < written < free, then
        // create index. Address and size are pinned here, so the order is class-then-create-index.
        let mut all: Vec<(u8, u32, VarnodeId)> = (0..f.num_varnodes() as u32)
            .map(VarnodeId)
            .filter(|&v| f.vn(v).loc == sb_addr && f.vn(v).size == sb_size)
            .map(|v| {
                let vn = f.vn(v);
                let class = if vn.is_input() {
                    0
                } else if vn.is_written() {
                    1
                } else {
                    2
                };
                (class, vn.create_index, v)
            })
            .collect();
        all.sort();
        for (class, _, v) in all {
            if class == 2 {
                break; // Ghidra stops at the first free varnode
            }
            self.vnlist.push(v);
            self.companion.push(-1);
        }
        self.missedvariables = 0;
        if self.vnlist.is_empty() {
            return Ok(());
        }
        if !f.vn(self.vnlist[0]).is_input() {
            return Err("Input value of stackpointer is not used");
        }
        // Index lookup for `othervn`. Ghidra does `lower_bound(vnlist, othervn, comparePointers)`
        // — a search by raw pointer over a list ordered by location, so it finds the index only
        // because the value is present; looking the index up directly is what that computes.
        let index: std::collections::HashMap<VarnodeId, i32> =
            self.vnlist.iter().enumerate().map(|(i, &v)| (v, i as i32)).collect();

        for i in 1..self.vnlist.len() {
            let vn = self.vnlist[i];
            let Some(op) = f.vn(vn).def else {
                self.missedvariables += 1;
                continue;
            };
            let i = i as i32;
            match f.op(op).code() {
                OpCode::IntAdd => {
                    let mut othervn = f.op(op).input(0).expect("INT_ADD input 0");
                    let mut constvn = f.op(op).input(1).expect("INT_ADD input 1");
                    if f.vn(othervn).is_constant() {
                        std::mem::swap(&mut constvn, &mut othervn);
                    }
                    if !f.vn(constvn).is_constant() || f.vn(othervn).loc != sb_addr {
                        self.missedvariables += 1;
                        continue;
                    }
                    let Some(&var2) = index.get(&othervn) else {
                        self.missedvariables += 1;
                        continue;
                    };
                    self.eqs.push(StackEqn { var1: i, var2, rhs: f.vn(constvn).constant_value() as i32 });
                }
                OpCode::Copy => {
                    let othervn = f.op(op).input(0).expect("COPY input");
                    if f.vn(othervn).loc != sb_addr {
                        self.missedvariables += 1;
                        continue;
                    }
                    let Some(&var2) = index.get(&othervn) else {
                        self.missedvariables += 1;
                        continue;
                    };
                    self.eqs.push(StackEqn { var1: i, var2, rhs: 0 });
                }
                OpCode::Indirect => {
                    let othervn = f.op(op).input(0).expect("INDIRECT before-value");
                    if f.vn(othervn).loc != sb_addr {
                        self.missedvariables += 1;
                        continue;
                    }
                    let Some(&var2) = index.get(&othervn) else {
                        self.missedvariables += 1;
                        continue;
                    };
                    self.companion[i as usize] = var2;
                    // Ghidra reads the iop annotation (`getIn(1)`); mosura models it as
                    // `guarded_op`. If the INDIRECT is due to a call whose extrapop has since been
                    // filled in (by deindirect), the change is known and becomes a hard equation.
                    if let Some(call) = f.op(op).guarded_op() {
                        if f.call_specs.contains_key(&call) {
                            // Ghidra double-checks the CALLEE prototype's extrapop here, because
                            // `ActionDeindirect` may have resolved an indirect call to a known
                            // callee and filled it in since. mosura carries one prototype model per
                            // function rather than per call site, so the check reads that; under
                            // `analyze_extra_pop`'s gate it is UNKNOWN by construction and this
                            // branch is inert until per-call-site models land.
                            let ep = f.proto_model.extrapop;
                            if ep != super::fspec::EXTRAPOP_UNKNOWN {
                                self.eqs.push(StackEqn { var1: i, var2, rhs: ep });
                                continue;
                            }
                        }
                    }
                    // Ghidra's literal guess (coreaction.cc:219): the call pops 4 bytes. It is
                    // what cancels the `RSP = RSP - 4` the x86 `call` p-code performs, leaving the
                    // stack pointer net-unchanged across a call that pops no arguments.
                    // Ghidra's guess assumes the call's `RSP -= 4` push is still in the IR, so
                    // `+4` restores it. `recover_stack` may have already cancelled the push
                    // (rewritten to an identity COPY) — the INDIRECT's input then renames to the
                    // PRE-push value and the modeled delta beyond it is 0, not 4. Subtract the
                    // cancelled amount or every post-call solution is +4 (the E1082 family).
                    let neutralized = f
                        .op(op)
                        .guarded_op()
                        .and_then(|call| f.call_specs.get(&call))
                        .and_then(|cs| cs.push_neutralized)
                        .unwrap_or(0);
                    let rhs = 4 - neutralized as i32;
                    if crate::debug::on(crate::debug::Topic::StackVars) {
                        let d2 = f.vn(othervn).def.map(|d| (f.op(d).code(), f.op(d).seqnum.pc.offset));
                        debug!(crate::debug::Topic::StackVars, "guess var{i} = var{var2} + {rhs} (var2 def={d2:x?})");
                    }
                    self.guess.push(StackEqn { var1: i, var2, rhs });
                }
                OpCode::Multiequal => {
                    for j in 0..f.op(op).num_inputs() {
                        let othervn = f.op(op).input(j).expect("phi input");
                        if f.vn(othervn).loc != sb_addr {
                            self.missedvariables += 1;
                            continue;
                        }
                        let Some(&var2) = index.get(&othervn) else {
                            self.missedvariables += 1;
                            continue;
                        };
                        self.eqs.push(StackEqn { var1: i, var2, rhs: 0 });
                    }
                }
                OpCode::IntAnd => {
                    // A function aligning its stack pointer. Ghidra treats it as a copy.
                    let mut othervn = f.op(op).input(0).expect("INT_AND input 0");
                    let mut constvn = f.op(op).input(1).expect("INT_AND input 1");
                    if f.vn(othervn).is_constant() {
                        std::mem::swap(&mut constvn, &mut othervn);
                    }
                    if !f.vn(constvn).is_constant() || f.vn(othervn).loc != sb_addr {
                        self.missedvariables += 1;
                        continue;
                    }
                    let Some(&var2) = index.get(&othervn) else {
                        self.missedvariables += 1;
                        continue;
                    };
                    self.eqs.push(StackEqn { var1: i, var2, rhs: 0 });
                }
                _ => self.missedvariables += 1,
            }
        }
        Ok(())
    }
}

/// Ghidra `ActionStackPtrFlow::analyzeExtraPop` (coreaction.cc:261): where `extrapop` is not
/// explicit, do the full linear analysis to recover the stack-pointer change across each call.
///
/// Every solved stack-pointer definition is rewritten to `sp_input + <solution>`, which is what
/// converts the `INDIRECT`s [`ActionExtraPopSetup`](super::pipeline::ActionExtraPopSetup) planted
/// into concrete adds; each such INDIRECT also yields its call's recovered `effectiveExtraPop`.
fn analyze_extra_pop(f: &mut Funcdata, sb_addr: Address, sb_size: u32) {
    // Ghidra gates on the *evaluation* model for called functions (`evalfp_called`, falling back to
    // `defaultfp`): the analysis is only needed when that model's extrapop is unknown.
    if f.proto_model.extrapop != super::fspec::EXTRAPOP_UNKNOWN {
        return;
    }
    let mut solver = StackSolver::default();
    if let Err(e) = solver.build(f, sb_addr, sb_size) {
        // Ghidra emits `warningHeader("Stack frame is not setup normally: " + err.explain)` and
        // returns; mosura has no warning-header channel on Funcdata, so only the bail-out lands.
        let _ = e;
        return;
    }
    if solver.vnlist.is_empty() {
        return;
    }
    solver.solve();

    let invn = solver.vnlist[0];
    // Ghidra prints its "Unable to track spacebase fully" warning header once; mosura has no
    // warning-header channel on Funcdata, so the untrackable variables are simply skipped.
    for i in 1..solver.vnlist.len() {
        let vn = solver.vnlist[i];
        let soln = solver.soln[i];
        if soln == NO_SOLN {
            continue;
        }
        let op = f.vn(vn).def.expect("solver variables past 0 are written");
        debug!(crate::debug::Topic::StackVars, "var{i} def={:?}@{:x} soln={soln}", f.op(op).code(), f.op(op).seqnum.pc.offset);
        if f.op(op).code() == OpCode::Indirect {
            if let Some(call) = f.op(op).guarded_op() {
                if f.call_specs.contains_key(&call) {
                    let comp = solver.companion[i];
                    let soln2 = if comp >= 0 { solver.soln[comp as usize] } else { 0 };
                    if let Some(cs) = f.call_specs.get_mut(&call) {
                        cs.effective_extrapop = Some(soln.wrapping_sub(soln2));
                    }
                }
            }
        }
        let sz = f.vn(invn).size;
        let k = f.new_const(sz, mask_value(soln as i64 as u64, sz));
        f.op_set_opcode(op, OpCode::IntAdd);
        f.op_set_all_input(op, &[invn, k]);
    }
}

/// Ghidra's `calc_mask(sz)` applied to a solution value.
fn mask_value(v: u64, size: u32) -> u64 {
    if size >= 8 {
        v
    } else {
        v & ((1u64 << (8 * size)) - 1)
    }
}

/// Ghidra `ActionStackPtrFlow::isStackRelative` (coreaction.cc:329): is `vn` the stack-pointer
/// input plus a constant (or the input itself)?
fn is_stack_relative(f: &Funcdata, spcbasein: VarnodeId, vn: VarnodeId) -> Option<u64> {
    if spcbasein == vn {
        return Some(0);
    }
    if !f.vn(vn).is_written() {
        return None;
    }
    let addop = f.vn(vn).def?;
    if f.op(addop).code() != OpCode::IntAdd {
        return None;
    }
    if f.op(addop).input(0) != Some(spcbasein) {
        return None;
    }
    let constvn = f.op(addop).input(1)?;
    if !f.vn(constvn).is_constant() {
        return None;
    }
    Some(f.vn(constvn).constant_value())
}

/// Ghidra `ActionStackPtrFlow::adjustLoad` (coreaction.cc:353): the LOAD's matching STORE is
/// known, so turn the LOAD into a COPY of what was stored.
fn adjust_load(f: &mut Funcdata, loadop: OpId, storeop: OpId) -> bool {
    let mut vn = f.op(storeop).input(2).expect("STORE value");
    if f.vn(vn).is_constant() {
        let (sz, off) = (f.vn(vn).size, f.vn(vn).constant_value());
        vn = f.new_const(sz, off);
    } else if f.vn(vn).is_free() {
        return false;
    }
    f.op_remove_input(loadop, 1);
    f.op_set_opcode(loadop, OpCode::Copy);
    f.op_set_input(loadop, 0, vn);
    true
}

/// Ghidra `ActionStackPtrFlow::repair` (coreaction.cc:378): trace back from a LOAD for the STORE
/// through the same stack-relative pointer; if found and it stored a constant, make the LOAD a COPY.
fn repair(f: &mut Funcdata, id: SpaceId, spcbasein: VarnodeId, loadop: OpId, constz: u64) -> u32 {
    let loadsize = f.op(loadop).output.map(|o| f.vn(o).size).unwrap_or(0) as u64;
    let mut curblock = match f.op(loadop).parent {
        Some(b) => b,
        None => return 0,
    };
    let mut iter = match f.block(curblock).ops.iter().position(|&o| o == loadop) {
        Some(p) => p,
        None => return 0,
    };
    loop {
        if iter == 0 {
            // Can trace back into the predecessor only if there is exactly one path in.
            if f.block(curblock).in_edges.len() != 1 {
                return 0;
            }
            curblock = f.block(curblock).in_edges[0];
            iter = f.block(curblock).ops.len();
            continue;
        }
        iter -= 1;
        let curop = f.block(curblock).ops[iter];
        if f.op(curop).is_call() {
            return 0; // don't trace aliasing through a call
        }
        if f.op(curop).code() == OpCode::Store {
            let ptrvn = f.op(curop).input(1).expect("STORE pointer");
            let datavn = f.op(curop).input(2).expect("STORE value");
            let Some(constnew) = is_stack_relative(f, spcbasein, ptrvn) else {
                return 0; // any other kind of STORE we can't solve aliasing for
            };
            let datasize = f.vn(datavn).size as u64;
            if constnew == constz && loadsize == datasize {
                return u32::from(adjust_load(f, loadop, curop)); // the matching store
            }
            if constnew <= constz + (loadsize - 1) && constnew + (datasize - 1) >= constz {
                return 0; // overlapping store, so the value is not what we traced
            }
        } else if let Some(outvn) = f.op(curop).output {
            if f.vn(outvn).loc.space == id {
                return 0; // stack already traced, too late
            }
        }
    }
}

/// Ghidra `ActionStackPtrFlow::checkClog` (coreaction.cc:432): find stack-pointer \e clogs — a
/// constant addition to the stack pointer where the constant itself comes from the stack — and
/// hand each to [`repair`].
fn check_clog(f: &mut Funcdata, id: SpaceId, sb_addr: Address, sb_size: u32) -> u32 {
    let mut all: Vec<(u8, u32, VarnodeId)> = (0..f.num_varnodes() as u32)
        .map(VarnodeId)
        .filter(|&v| f.vn(v).loc == sb_addr && f.vn(v).size == sb_size)
        .map(|v| {
            let vn = f.vn(v);
            let class = if vn.is_input() {
                0
            } else if vn.is_written() {
                1
            } else {
                2
            };
            (class, vn.create_index, v)
        })
        .collect();
    all.sort();
    if all.is_empty() {
        return 0;
    }
    let spcbasein = all[0].2;
    if !f.vn(spcbasein).is_input() {
        return 0;
    }
    let mut clogcount = 0;
    for &(_, _, outvn) in &all[1..] {
        if !f.vn(outvn).is_written() {
            continue;
        }
        let addop = f.vn(outvn).def.expect("written");
        if f.op(addop).code() != OpCode::IntAdd {
            continue;
        }
        let mut y = f.op(addop).input(1).expect("INT_ADD input 1");
        if !f.vn(y).is_written() {
            continue; // y must not be a constant
        }
        // y is not constant, so x (in position 0) isn't either.
        let mut x = f.op(addop).input(0).expect("INT_ADD input 0");
        let constx = match is_stack_relative(f, spcbasein, x) {
            Some(c) => Some(c),
            None => {
                std::mem::swap(&mut x, &mut y); // swap x and y and try again
                is_stack_relative(f, spcbasein, x)
            }
        };
        if constx.is_none() {
            continue;
        }
        let Some(mut loadop) = f.vn(y).def else { continue };
        if f.op(loadop).code() == OpCode::IntMult {
            let Some(constvn) = f.op(loadop).input(1) else { continue };
            if !f.vn(constvn).is_constant() {
                continue;
            }
            let sz = f.vn(constvn).size;
            if f.vn(constvn).constant_value() != mask_value(u64::MAX, sz) {
                continue; // must multiply by -1
            }
            y = f.op(loadop).input(0).expect("INT_MULT input 0");
            if !f.vn(y).is_written() {
                continue;
            }
            loadop = f.vn(y).def.expect("written");
        }
        if f.op(loadop).code() != OpCode::Load {
            continue;
        }
        let ptrvn = f.op(loadop).input(1).expect("LOAD pointer");
        let Some(constz) = is_stack_relative(f, spcbasein, ptrvn) else { continue };
        clogcount += repair(f, id, spcbasein, loadop, constz);
    }
    clogcount
}

/// Ghidra `ActionStackPtrFlow` (coreaction.cc:481, group `stackptrflow`, universalAction slot
/// 5656): repair stack-pointer clogs, then — once no clog remains — run the linear analysis that
/// resolves the stack-pointer change across calls whose `extrapop` is unknown.
#[derive(Default)]
pub struct ActionStackPtrFlow {
    /// Ghidra's `analysis_finished`: the extrapop analysis runs at most once per function.
    analysis_finished: bool,
}

impl Action for ActionStackPtrFlow {
    fn name(&self) -> &str {
        "stackptrflow"
    }
    fn reset(&mut self, _data: &mut Funcdata) {
        self.analysis_finished = false;
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        if self.analysis_finished {
            return 0;
        }
        let Some(stack) = data.spaces.by_name("stack") else {
            self.analysis_finished = true; // no stack to do analysis on
            return 0;
        };
        let Some(&(sb_addr, sb_size)) = data.spaces.get(stack).spacebase.first() else {
            self.analysis_finished = true;
            return 0;
        };
        let numchange = check_clog(data, stack, sb_addr, sb_size);
        if numchange == 0 {
            analyze_extra_pop(data, sb_addr, sb_size);
            self.analysis_finished = true;
        }
        // Ghidra's apply returns 0; the clog repairs are reported through `count += 1`, which
        // mosura's harness derives from the returned change count.
        u32::from(numchange > 0)
    }
}

#[cfg(test)]
mod stackptrflow_tests {
    use super::*;
    use crate::decompile::op::SeqNum;
    use crate::decompile::space::SpaceManager;

    /// A function whose stack pointer flows: input -> `-4` -> INDIRECT(call) -> phi.
    /// Returns (funcdata, sp address, sp size).
    fn sp_fixture() -> (Funcdata, Address, u32) {
        let mut spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let sp = Address::new(reg, 0x10);
        spaces.set_spacebase(stack, sp, 4);
        let ram = spaces.by_name("ram").unwrap();
        let f = Funcdata::new("t", Address::new(ram, 0), spaces);
        (f, sp, 4)
    }

    fn seq(f: &Funcdata, off: u64) -> SeqNum {
        let ram = f.spaces.by_name("ram").unwrap();
        SeqNum { pc: Address::new(ram, off), uniq: off as u32 }
    }

    /// `StackSolver` solves a straight chain of stack-pointer adds: each `sp = sp + k` gets the
    /// running total as its solution, and the input is 0 (Ghidra `StackSolver::solve`, propagate
    /// from variable 0).
    #[test]
    fn solver_chains_constant_adds() {
        let (mut f, sp, size) = sp_fixture();
        let v0 = f.new_input(size, sp);
        let k = f.new_const(size, 0xfffffffc); // -4
        let add1 = f.new_op(OpCode::IntAdd, seq(&f, 0), vec![v0, k]);
        let v1 = f.new_output(add1, size, sp);
        let k2 = f.new_const(size, 0xfffffff8); // -8
        let add2 = f.new_op(OpCode::IntAdd, seq(&f, 4), vec![v1, k2]);
        f.new_output(add2, size, sp);

        let mut s = StackSolver::default();
        s.build(&f, sp, size).expect("input stack pointer is used");
        assert_eq!(s.vnlist.len(), 3);
        s.solve();
        assert_eq!(s.soln[0], 0);
        assert_eq!(s.soln[1], -4);
        assert_eq!(s.soln[2], -12);
    }

    /// A COPY of the stack pointer is an equation with rhs 0 — the copy carries the same offset.
    #[test]
    fn solver_treats_copy_as_zero_offset() {
        let (mut f, sp, size) = sp_fixture();
        let v0 = f.new_input(size, sp);
        let k = f.new_const(size, 0xfffffff0); // -16
        let add = f.new_op(OpCode::IntAdd, seq(&f, 0), vec![v0, k]);
        let v1 = f.new_output(add, size, sp);
        let cp = f.new_op(OpCode::Copy, seq(&f, 4), vec![v1]);
        f.new_output(cp, size, sp);

        let mut s = StackSolver::default();
        s.build(&f, sp, size).expect("input stack pointer is used");
        s.solve();
        assert_eq!(s.soln[1], -16);
        assert_eq!(s.soln[2], -16, "a COPY carries the offset unchanged");
    }

    /// An `INT_AND` on the stack pointer — a function aligning its frame — is also treated as a
    /// copy (Ghidra coreaction.cc:236, "Treat this as a copy").
    #[test]
    fn solver_treats_alignment_and_as_copy() {
        let (mut f, sp, size) = sp_fixture();
        let v0 = f.new_input(size, sp);
        let k = f.new_const(size, 0xfffffff0);
        let and = f.new_op(OpCode::IntAnd, seq(&f, 0), vec![v0, k]);
        f.new_output(and, size, sp);

        let mut s = StackSolver::default();
        s.build(&f, sp, size).expect("input stack pointer is used");
        s.solve();
        assert_eq!(s.soln[1], 0, "alignment is treated as a copy, not an offset");
    }

    /// The whole mechanism end to end: an `INDIRECT` on the stack pointer standing for a call with
    /// unknown extrapop is rewritten by `analyze_extra_pop` into `sp_input + <solution>`, and the
    /// call's recovered `effective_extrapop` is recorded. This is what makes
    /// `ActionExtraPopSetup`'s marks resolve rather than leaving the stack pointer indeterminate.
    #[test]
    fn analyze_extra_pop_resolves_indirect_to_add() {
        let (mut f, sp, size) = sp_fixture();
        f.proto_model.extrapop = crate::decompile::fspec::EXTRAPOP_UNKNOWN;
        let v0 = f.new_input(size, sp);
        let target = f.new_const(4, 0x1000);
        let call = f.new_op(OpCode::Call, seq(&f, 0), vec![target]);
        f.call_specs.insert(call, crate::decompile::fspec::CallSpec::default());
        let ind = f.new_op(OpCode::Indirect, seq(&f, 0), vec![v0]);
        f.op_mut(ind).guarded_op = Some(call);
        let out = f.new_output(ind, size, sp);
        // Give the INDIRECT output a reader so it is not free.
        let use_op = f.new_op(OpCode::Copy, seq(&f, 4), vec![out]);
        f.new_output(use_op, size, Address::new(f.spaces.by_name("register").unwrap(), 0x40));

        analyze_extra_pop(&mut f, sp, size);

        assert_eq!(f.op(ind).code(), OpCode::IntAdd, "the INDIRECT is resolved to an add");
        assert_eq!(f.op(ind).input(0), Some(v0), "rebased on the stack-pointer input");
        let k = f.op(ind).input(1).expect("the solved constant");
        assert!(f.vn(k).is_constant());
        assert_eq!(f.vn(k).constant_value(), 4, "Ghidra's guess: the call pops 4 bytes");
        assert_eq!(
            f.call_specs[&call].effective_extrapop,
            Some(4),
            "the recovered per-call stack change is recorded"
        );
    }

    /// The analysis is gated on the prototype model's extrapop being unknown (Ghidra
    /// coreaction.cc:267): with a known extrapop there is nothing to solve, so the graph is
    /// untouched.
    #[test]
    fn analyze_extra_pop_is_inert_for_known_extrapop() {
        let (mut f, sp, size) = sp_fixture();
        f.proto_model.extrapop = 8; // e.g. x86-64-gcc's __stdcall
        let v0 = f.new_input(size, sp);
        let k = f.new_const(size, 0xfffffffc);
        let add = f.new_op(OpCode::IntAdd, seq(&f, 0), vec![v0, k]);
        f.new_output(add, size, sp);
        let before = f.op(add).input(1);

        analyze_extra_pop(&mut f, sp, size);

        assert_eq!(f.op(add).input(1), before, "a known extrapop needs no linear analysis");
    }

    /// Guard against the placement defect this port was first written with: `ActionExtraPopSetup`
    /// must run where the CFG already exists, or `op_insert_before` finds no parent block and the
    /// INDIRECT is stranded away from the CALL it guards.
    #[test]
    fn extra_pop_setup_needs_a_built_cfg() {
        let (mut f, _sp, _size) = sp_fixture();
        let ram = f.spaces.by_name("ram").unwrap();
        let target = f.new_const(4, 0x1000);
        let call = f.new_op(OpCode::Call, SeqNum { pc: Address::new(ram, 0), uniq: 0 }, vec![target]);
        assert_eq!(f.num_blocks(), 0);
        assert_eq!(f.op(call).parent, None, "with no CFG an op has no parent block to insert into");
    }
}
