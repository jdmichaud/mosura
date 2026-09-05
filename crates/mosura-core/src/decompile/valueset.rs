//! Value-set analysis — Ghidra's `ValueSet` / `ValueSetRead` / `Widener` / `ValueSetSolver`
//! (rangeutil.cc:1493-2605). A data-flow system is built backward from a set of *sink* Varnodes
//! (the pointers of indexed stack LOAD/STOREs), every Varnode in the system gets a `CircleRange`
//! of possible values (or of offsets relative to the stack pointer — the `type_code == 1` sets),
//! constraints are lifted from the conditional branches dominating the system's reads, and the
//! ranges are iterated to a fixed point in Bourdoncle's recursive-component order, with a
//! widening strategy that either freezes early (`WidenerNone`) or widens against branch
//! *landmarks* (`WidenerFull`). Consumed by `heritage::analyze_new_load_guards`, which turns the
//! range a LOAD's pointer may take into the stack range its `LoadGuard` protects.
//!
//! Ghidra keeps the solver's per-Varnode state on the Varnode (`Varnode::valueSet`, the `mark`
//! flag) and on the op (`PcodeOp::isMark` for the read sites); mosura keeps it in the solver:
//! `vs_of` is `getValueSet`, `vn_mark`/`op_mark` are the marks. Nodes link by arena index, the
//! `next`/`part_head` pointers of the C++ becoming `Option<usize>`.

use std::collections::{HashMap, HashSet};

use super::circlerange::CircleRange;
use super::dominator::Dominators;
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::varnode::VarnodeId;

/// Ghidra `ValueSet::MAX_STEP` (rangeutil.cc:1493).
const MAX_STEP: i32 = 32;

/// Ghidra `ValueSet::Equation`: a constraint on one input slot of the defining op.
#[derive(Clone, Debug)]
struct Equation {
    slot: i32,
    type_code: i32,
    range: CircleRange,
}

/// Ghidra `ValueSet` (rangeutil.hh:113). `op_code == None` is `CPUI_MAX` (a constant or input).
#[derive(Clone, Debug)]
pub struct ValueSet {
    type_code: i32,
    num_params: i32,
    count: i32,
    op_code: Option<OpCode>,
    left_is_stable: bool,
    right_is_stable: bool,
    /// `None` for the simulated root node of the topological ordering.
    vn: Option<VarnodeId>,
    range: CircleRange,
    equations: Vec<Equation>,
    part_head: Option<usize>,
    next: Option<usize>,
}

impl ValueSet {
    fn empty_root() -> ValueSet {
        ValueSet {
            type_code: 0,
            num_params: 0,
            count: 0,
            op_code: None,
            left_is_stable: false,
            right_is_stable: false,
            vn: None,
            range: CircleRange::default(),
            equations: Vec::new(),
            part_head: None,
            next: None,
        }
    }

    /// Ghidra `ValueSet::setVarnode` (rangeutil.cc:1503).
    fn set_varnode(&mut self, f: &Funcdata, v: VarnodeId, t_code: i32) {
        self.type_code = t_code;
        self.vn = Some(v);
        let vn = f.vn(v);
        if self.type_code != 0 {
            self.op_code = None;
            self.num_params = 0;
            self.range.set_value(0, vn.size as i32); // Treat as offset of 0 relative to special value
            self.left_is_stable = true;
            self.right_is_stable = true;
        } else if vn.is_written() {
            let op = vn.def.expect("written varnode has a def");
            let opc = f.op(op).code();
            if opc == OpCode::Indirect {
                // Treat CPUI_INDIRECT as CPUI_COPY
                self.num_params = 1;
                self.op_code = Some(OpCode::Copy);
            } else {
                self.op_code = Some(opc);
                self.num_params = f.op(op).num_inputs() as i32;
            }
            self.left_is_stable = false;
            self.right_is_stable = false;
        } else if vn.is_constant() {
            self.op_code = None;
            self.num_params = 0;
            self.range.set_value(vn.constant_value(), vn.size as i32);
            self.left_is_stable = true;
            self.right_is_stable = true;
        } else {
            // Some other form of input
            self.op_code = None;
            self.num_params = 0;
            self.type_code = 0;
            self.range.set_full(vn.size as i32);
            self.left_is_stable = false;
            self.right_is_stable = false;
        }
    }

    /// Ghidra `ValueSet::setFull` (rangeutil.hh:138).
    fn set_full(&mut self, f: &Funcdata) {
        let size = self.vn.map_or(1, |v| f.vn(v).size as i32);
        self.range.set_full(size);
        self.type_code = 0;
    }

    /// Ghidra `ValueSet::addEquation` (rangeutil.cc:1549): ordered on slot.
    fn add_equation(&mut self, slot: i32, type_code: i32, constraint: CircleRange) {
        let mut pos = 0;
        while pos < self.equations.len() {
            if self.equations[pos].slot > slot {
                break;
            }
            pos += 1;
        }
        self.equations.insert(pos, Equation { slot, type_code, range: constraint });
    }

    /// Ghidra `ValueSet::addLandmark` (rangeutil.hh:141).
    fn add_landmark(&mut self, type_code: i32, constraint: CircleRange) {
        self.add_equation(self.num_params, type_code, constraint);
    }

    /// Ghidra `ValueSet::doesEquationApply` (rangeutil.hh:375).
    fn does_equation_apply(&self, num: usize, slot: i32) -> bool {
        if num < self.equations.len() {
            let e = &self.equations[num];
            if e.slot == slot && e.type_code == self.type_code {
                return true;
            }
        }
        false
    }

    /// Ghidra `ValueSet::getLandMark` (rangeutil.cc:1743).
    fn get_landmark(&self) -> Option<&CircleRange> {
        // Any equation can serve as a landmark. We prefer the one restricting the value of an
        // input branch, as these usually give a tighter approximation of the stable point.
        self.equations.iter().find(|e| e.type_code == self.type_code).map(|e| &e.range)
    }

    pub fn get_count(&self) -> i32 {
        self.count
    }
    pub fn get_range(&self) -> &CircleRange {
        &self.range
    }
    pub fn get_type_code(&self) -> i32 {
        self.type_code
    }
    pub fn get_varnode(&self) -> Option<VarnodeId> {
        self.vn
    }
    pub fn is_left_stable(&self) -> bool {
        self.left_is_stable
    }
    pub fn is_right_stable(&self) -> bool {
        self.right_is_stable
    }
}

/// Ghidra `Partition` (rangeutil.hh:161): a recursive component of the iteration order.
#[derive(Clone, Debug, Default)]
struct Partition {
    start_node: Option<usize>,
    stop_node: Option<usize>,
    is_dirty: bool,
}

/// Ghidra `ValueSetRead` (rangeutil.hh:178): the value set as seen at one read site.
#[derive(Clone, Debug)]
pub struct ValueSetRead {
    type_code: i32,
    slot: i32,
    op: OpId,
    range: CircleRange,
    equation_constraint: CircleRange,
    equation_type_code: i32,
    left_is_stable: bool,
    right_is_stable: bool,
}

impl ValueSetRead {
    /// Ghidra `ValueSetRead::setPcodeOp` (rangeutil.cc:1781).
    fn new(op: OpId, slot: i32) -> ValueSetRead {
        ValueSetRead {
            type_code: 0,
            slot,
            op,
            range: CircleRange::default(),
            equation_constraint: CircleRange::default(),
            equation_type_code: -1,
            left_is_stable: false,
            right_is_stable: false,
        }
    }

    /// Ghidra `ValueSetRead::addEquation` (rangeutil.cc:1793).
    fn add_equation(&mut self, slot: i32, type_code: i32, constraint: CircleRange) {
        if self.slot == slot {
            self.equation_type_code = type_code;
            self.equation_constraint = constraint;
        }
    }

    pub fn get_type_code(&self) -> i32 {
        self.type_code
    }
    pub fn get_range(&self) -> &CircleRange {
        &self.range
    }
    pub fn is_left_stable(&self) -> bool {
        self.left_is_stable
    }
    pub fn is_right_stable(&self) -> bool {
        self.right_is_stable
    }
}

/// Ghidra `Widener` (rangeutil.hh:204): the strategy that accelerates (or cuts short) iteration.
pub trait Widener {
    /// Ghidra `determineIterationReset`: the count a component head restarts at on entry.
    fn determine_iteration_reset(&self, value_set: &ValueSet) -> i32;
    /// Ghidra `checkFreeze`: is the value set done changing?
    fn check_freeze(&self, value_set: &ValueSet) -> bool;
    /// Ghidra `doWidening`: replace `range` given the newly computed `new_range`; `false` means
    /// constrained widening failed (the caller sets the value set full).
    fn do_widening(&self, value_set: &ValueSet, range: &mut CircleRange, new_range: &CircleRange) -> bool;
}

/// Ghidra `WidenerFull` (rangeutil.hh:236): widen against a landmark at `widen_iteration`, give
/// up (full range) at `full_iteration`.
pub struct WidenerFull {
    widen_iteration: i32,
    full_iteration: i32,
}

impl Default for WidenerFull {
    fn default() -> Self {
        WidenerFull { widen_iteration: 2, full_iteration: 5 }
    }
}

impl Widener for WidenerFull {
    fn determine_iteration_reset(&self, value_set: &ValueSet) -> i32 {
        if value_set.get_count() >= self.widen_iteration {
            return self.widen_iteration; // Reset to point just after any widening
        }
        0 // Delay widening, if we haven't performed it yet
    }

    fn check_freeze(&self, value_set: &ValueSet) -> bool {
        value_set.get_range().is_full()
    }

    fn do_widening(&self, value_set: &ValueSet, range: &mut CircleRange, new_range: &CircleRange) -> bool {
        if value_set.get_count() < self.widen_iteration {
            *range = *new_range;
            return true;
        } else if value_set.get_count() == self.widen_iteration {
            if let Some(landmark) = value_set.get_landmark() {
                let left_is_stable = range.get_min() == new_range.get_min();
                *range = *new_range; // Preserve any new step information
                if landmark.contains_range(range) {
                    range.widen(landmark, left_is_stable);
                    return true;
                } else {
                    let mut constraint = *landmark;
                    constraint.invert();
                    if constraint.contains_range(range) {
                        range.widen(&constraint, left_is_stable);
                        return true;
                    }
                }
            }
        } else if value_set.get_count() < self.full_iteration {
            *range = *new_range;
            return true;
        }
        false // Indicate that constrained widening failed (set to full)
    }
}

/// Ghidra `WidenerNone` (rangeutil.hh:254): no widening; all change ceases at `freeze_iteration`.
pub struct WidenerNone {
    freeze_iteration: i32,
}

impl Default for WidenerNone {
    fn default() -> Self {
        WidenerNone { freeze_iteration: 3 }
    }
}

impl Widener for WidenerNone {
    fn determine_iteration_reset(&self, value_set: &ValueSet) -> i32 {
        if value_set.get_count() >= self.freeze_iteration {
            return self.freeze_iteration; // Reset to point just after any widening
        }
        value_set.get_count()
    }

    fn check_freeze(&self, value_set: &ValueSet) -> bool {
        if value_set.get_range().is_full() {
            return true;
        }
        value_set.get_count() >= self.freeze_iteration
    }

    fn do_widening(&self, _value_set: &ValueSet, range: &mut CircleRange, new_range: &CircleRange) -> bool {
        *range = *new_range;
        true
    }
}

/// Ghidra `ValueSetSolver` (rangeutil.hh:274).
pub struct ValueSetSolver {
    /// Storage for all the current value sets (`valueNodes`), arena-indexed.
    value_nodes: Vec<ValueSet>,
    /// Additional, after iteration, add-on value sets (`readNodes`, keyed by the read op).
    read_nodes: HashMap<OpId, ValueSetRead>,
    /// Value sets in iteration order.
    order_partition: Partition,
    /// Storage for the Partitions establishing components.
    record_storage: Vec<Partition>,
    /// Values treated as inputs.
    root_nodes: Vec<usize>,
    /// Stack used to generate the topological ordering.
    node_stack: Vec<usize>,
    depth_first_index: i32,
    num_iterations: i32,
    max_iterations: i32,
    /// `Varnode::getValueSet`.
    vs_of: HashMap<VarnodeId, usize>,
    /// `Varnode::isMark` — membership in the system.
    vn_mark: HashSet<VarnodeId>,
    /// `PcodeOp::isMark` on the special read sites.
    op_mark: HashSet<OpId>,
}

impl Default for ValueSetSolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ValueSetSolver {
    pub fn new() -> ValueSetSolver {
        ValueSetSolver {
            value_nodes: Vec::new(),
            read_nodes: HashMap::new(),
            order_partition: Partition::default(),
            record_storage: Vec::new(),
            root_nodes: Vec::new(),
            node_stack: Vec::new(),
            depth_first_index: 0,
            num_iterations: 0,
            max_iterations: 0,
            vs_of: HashMap::new(),
            vn_mark: HashSet::new(),
            op_mark: HashSet::new(),
        }
    }

    /// Ghidra `Varnode::getValueSet` for a Varnode in the system.
    fn vs(&self, v: VarnodeId) -> usize {
        self.vs_of[&v]
    }

    /// Ghidra `ValueSetSolver::newValueSet` (rangeutil.cc:1953).
    fn new_value_set(&mut self, f: &Funcdata, v: VarnodeId, t_code: i32) -> usize {
        let mut vs = ValueSet::empty_root();
        vs.set_varnode(f, v, t_code);
        self.value_nodes.push(vs);
        let idx = self.value_nodes.len() - 1;
        self.vs_of.insert(v, idx);
        idx
    }

    /// Ghidra `ValueSetSolver::partitionPrepend(ValueSet*, Partition&)` (rangeutil.hh:389).
    fn partition_prepend_node(&mut self, vertex: usize, part: &mut Partition) {
        self.value_nodes[vertex].next = part.start_node; // Attach new vertex to beginning of list
        part.start_node = Some(vertex); // Change the first value set to be the new vertex
        if part.stop_node.is_none() {
            part.stop_node = Some(vertex);
        }
    }

    /// Ghidra `ValueSetSolver::partitionPrepend(const Partition&, Partition&)` (rangeutil.hh:400).
    fn partition_prepend_part(&mut self, head: &Partition, part: &mut Partition) {
        let stop = head.stop_node.expect("prepended partition has a stop node");
        self.value_nodes[stop].next = part.start_node;
        part.start_node = head.start_node;
        if part.stop_node.is_none() {
            part.stop_node = head.stop_node;
        }
    }

    /// Ghidra `ValueSetSolver::partitionSurround` (rangeutil.cc:1963): save to permanent storage
    /// and mark the starting node as the component head.
    fn partition_surround(&mut self, part: &Partition) {
        self.record_storage.push(part.clone());
        let idx = self.record_storage.len() - 1;
        let start = part.start_node.expect("partition has a start node");
        self.value_nodes[start].part_head = Some(idx);
    }

    /// Ghidra `ValueSetEdge`: the successor ValueSets of `vertex` in visiting order — the
    /// simulated root's edges are the root nodes; a real node's are the marked outputs of the
    /// ops reading its Varnode.
    fn successors(&self, f: &Funcdata, vertex: usize) -> Vec<usize> {
        match self.value_nodes[vertex].vn {
            None => self.root_nodes.clone(),
            Some(v) => {
                let mut out = Vec::new();
                for &op in &f.vn(v).descend {
                    if let Some(o) = f.op(op).output {
                        if self.vn_mark.contains(&o) {
                            out.push(self.vs(o));
                        }
                    }
                }
                out
            }
        }
    }

    /// Ghidra `ValueSetSolver::component` (rangeutil.cc:1974).
    fn component(&mut self, f: &Funcdata, vertex: usize, part: &mut Partition) {
        for succ in self.successors(f, vertex) {
            if self.value_nodes[succ].count == 0 {
                self.visit(f, succ, part);
            }
        }
        self.partition_prepend_node(vertex, part);
        self.partition_surround(part);
    }

    /// Ghidra `ValueSetSolver::visit` (rangeutil.cc:1991).
    fn visit(&mut self, f: &Funcdata, vertex: usize, part: &mut Partition) -> i32 {
        self.node_stack.push(vertex);
        self.depth_first_index += 1;
        self.value_nodes[vertex].count = self.depth_first_index;
        let mut head = self.depth_first_index;
        let mut is_loop = false;
        for succ in self.successors(f, vertex) {
            let min = if self.value_nodes[succ].count == 0 {
                self.visit(f, succ, part)
            } else {
                self.value_nodes[succ].count
            };
            if min <= head {
                head = min;
                is_loop = true;
            }
        }
        if head == self.value_nodes[vertex].count {
            self.value_nodes[vertex].count = 0x7fff_ffff; // Set to "infinity"
            let mut element = self.node_stack.pop().expect("node stack nonempty");
            if is_loop {
                while element != vertex {
                    self.value_nodes[element].count = 0;
                    element = self.node_stack.pop().expect("node stack nonempty");
                }
                let mut comp_part = Partition::default(); // empty partition
                self.component(f, vertex, &mut comp_part);
                self.partition_prepend_part(&comp_part, part);
            } else {
                self.partition_prepend_node(vertex, part);
            }
        }
        head
    }

    /// Ghidra `ValueSetSolver::establishTopologicalOrder` (rangeutil.cc:2042) — Bourdoncle's
    /// recursive strategy.
    fn establish_topological_order(&mut self, f: &Funcdata) {
        for vs in self.value_nodes.iter_mut() {
            vs.count = 0;
            vs.next = None;
            vs.part_head = None;
        }
        self.value_nodes.push(ValueSet::empty_root());
        let root = self.value_nodes.len() - 1;
        self.depth_first_index = 0;
        let mut order = Partition::default();
        self.visit(f, root, &mut order);
        // Remove simulated root
        order.start_node = self.value_nodes[order.start_node.expect("root was prepended")].next;
        self.order_partition = order;
    }

    /// Ghidra `ValueSetSolver::generateTrueEquation` (rangeutil.cc:2066).
    fn generate_true_equation(&mut self, vn: Option<VarnodeId>, op: OpId, slot: i32, type_code: i32, range: &CircleRange) {
        match vn {
            Some(v) => {
                let idx = self.vs(v);
                self.value_nodes[idx].add_equation(slot, type_code, *range);
            }
            None => {
                // Special read site
                if let Some(r) = self.read_nodes.get_mut(&op) {
                    r.add_equation(slot, type_code, *range);
                }
            }
        }
    }

    /// Ghidra `ValueSetSolver::generateFalseEquation` (rangeutil.cc:2084).
    fn generate_false_equation(&mut self, vn: Option<VarnodeId>, op: OpId, slot: i32, type_code: i32, range: &CircleRange) {
        let mut false_range = *range;
        false_range.invert();
        self.generate_true_equation(vn, op, slot, type_code, &false_range);
    }

    /// Ghidra `ValueSetSolver::applyConstraints` (rangeutil.cc:2105).
    fn apply_constraints(&mut self, f: &Funcdata, dom: &Dominators, vn: VarnodeId, type_code: i32, range: &CircleRange, cbranch: OpId) {
        let Some(split_point) = f.op(cbranch).parent else { return };
        let sp = split_point.0 as usize;
        let outs = &f.blocks()[sp].out_edges;
        if outs.len() < 2 {
            return;
        }
        // out_edges on a CBRANCH block: [fallthrough (false), taken (true)]
        let (true_block, false_block) = if f.op(cbranch).is_boolean_flip() {
            (outs[0].0 as usize, outs[1].0 as usize)
        } else {
            (outs[1].0 as usize, outs[0].0 as usize)
        };
        // Check if the only path to trueBlock or falseBlock is via a splitPoint out-edge induced by the condition
        let true_is_restricted = restricted_by_conditional(f, dom, true_block, sp);
        let false_is_restricted = restricted_by_conditional(f, dom, false_block, sp);

        if f.vn(vn).is_written() {
            let idx = self.vs(vn);
            if self.value_nodes[idx].op_code == Some(OpCode::Multiequal) {
                self.value_nodes[idx].add_landmark(type_code, *range); // Leave landmark for widening
            }
        }
        for &op in &f.vn(vn).descend {
            let mut out_vn: Option<VarnodeId> = None;
            if !self.op_mark.contains(&op) {
                // If this is not a special read site
                out_vn = f.op(op).output; // Make sure there is a Varnode in the system
                let Some(o) = out_vn else { continue };
                if !self.vn_mark.contains(&o) {
                    continue;
                }
            }
            let Some(cur) = f.op(op).parent else { continue };
            let mut cur_block = Some(cur.0 as usize);
            let slot = (0..f.op(op).num_inputs()).find(|&i| f.op(op).input(i) == Some(vn)).unwrap_or(0) as i32;
            if f.op(op).code() == OpCode::Multiequal {
                let cb = cur.0 as usize;
                if cb == true_block {
                    // If its possible that both the true and false edges can reach trueBlock
                    // then the only input we can restrict is a MULTIEQUAL input along the exact true edge
                    if true_is_restricted || f.blocks()[cb].in_edges[slot as usize].0 as usize == sp {
                        self.generate_true_equation(out_vn, op, slot, type_code, range);
                    }
                    continue;
                } else if cb == false_block {
                    if false_is_restricted || f.blocks()[cb].in_edges[slot as usize].0 as usize == sp {
                        self.generate_false_equation(out_vn, op, slot, type_code, range);
                    }
                    continue;
                } else {
                    cur_block = Some(f.blocks()[cb].in_edges[slot as usize].0 as usize); // MULTIEQUAL input is really only from one in-block
                }
            }
            loop {
                match cur_block {
                    Some(b) if b == true_block => {
                        if true_is_restricted {
                            self.generate_true_equation(out_vn, op, slot, type_code, range);
                        }
                        break;
                    }
                    Some(b) if b == false_block => {
                        if false_is_restricted {
                            self.generate_false_equation(out_vn, op, slot, type_code, range);
                        }
                        break;
                    }
                    Some(b) if b == sp => break,
                    None => break,
                    Some(b) => cur_block = immed_dom(dom, b),
                }
            }
        }
    }

    /// Ghidra `ValueSetSolver::constraintsFromPath` (rangeutil.cc:2185).
    fn constraints_from_path(
        &mut self,
        f: &Funcdata,
        dom: &Dominators,
        type_code: i32,
        lift: &mut CircleRange,
        mut start_vn: VarnodeId,
        mut end_vn: VarnodeId,
        cbranch: OpId,
    ) {
        while start_vn != end_vn {
            let Some(def) = f.vn(start_vn).def else { return };
            match lift.pull_back(f, def, false) {
                Some(v) => start_vn = v,
                None => return, // Couldn't pull all the way back to our value set
            }
        }
        loop {
            self.apply_constraints(f, dom, end_vn, type_code, lift, cbranch);
            if !f.vn(end_vn).is_written() {
                break;
            }
            let op = f.vn(end_vn).def.expect("written varnode has a def");
            if f.op(op).is_call() || f.op(op).is_marker() {
                break;
            }
            match lift.pull_back(f, op, false) {
                Some(v) => end_vn = v,
                None => break,
            }
            if !self.vn_mark.contains(&end_vn) {
                break;
            }
        }
    }

    /// Ghidra `ValueSetSolver::constraintsFromCBranch` (rangeutil.cc:2210).
    fn constraints_from_cbranch(&mut self, f: &Funcdata, dom: &Dominators, cbranch: OpId) {
        let Some(mut vn) = f.op(cbranch).input(1) else { return }; // Get Varnode deciding the condition
        while !self.vn_mark.contains(&vn) {
            if !f.vn(vn).is_written() {
                break;
            }
            let op = f.vn(vn).def.expect("written varnode has a def");
            if f.op(op).is_call() || f.op(op).is_marker() {
                break;
            }
            let num = f.op(op).num_inputs();
            if num == 0 || num > 2 {
                break;
            }
            vn = f.op(op).input(0).expect("input 0");
            if num == 2 {
                let in1 = f.op(op).input(1).expect("input 1");
                if f.vn(vn).is_constant() {
                    vn = in1;
                } else if !f.vn(in1).is_constant() {
                    // If we reach here, both inputs are non-constant
                    self.generate_relative_constraint(f, dom, op, cbranch);
                    return;
                }
                // If we reach here, vn is non-constant, other input is constant
            }
        }
        if self.vn_mark.contains(&vn) {
            let mut lift = CircleRange::from_bool(true);
            let start_vn = f.op(cbranch).input(1).expect("CBRANCH condition");
            self.constraints_from_path(f, dom, 0, &mut lift, start_vn, vn, cbranch);
        }
    }

    /// Ghidra `ValueSetSolver::generateConstraints` (rangeutil.cc:2248).
    fn generate_constraints(&mut self, f: &Funcdata, dom: &Dominators, worklist: &[VarnodeId], reads: &[OpId]) {
        let mut block_mark: HashSet<usize> = HashSet::new();
        let mut block_list: Vec<usize> = Vec::new();
        // Collect all blocks that contain a system op (input) or dominate a container
        let mut walk_up = |start: Option<usize>, block_mark: &mut HashSet<usize>, block_list: &mut Vec<usize>| {
            let mut cur = start;
            while let Some(b) = cur {
                if !block_mark.insert(b) {
                    break;
                }
                block_list.push(b);
                cur = immed_dom(dom, b);
            }
        };
        for &v in worklist {
            let Some(op) = f.vn(v).def else { continue };
            let Some(bl) = f.op(op).parent else { continue };
            let b = bl.0 as usize;
            if f.op(op).code() == OpCode::Multiequal {
                for j in 0..f.blocks()[b].in_edges.len() {
                    let cur = f.blocks()[b].in_edges[j].0 as usize;
                    walk_up(Some(cur), &mut block_mark, &mut block_list);
                }
            } else {
                walk_up(Some(b), &mut block_mark, &mut block_list);
            }
        }
        for &r in reads {
            let Some(bl) = f.op(r).parent else { continue };
            walk_up(Some(bl.0 as usize), &mut block_mark, &mut block_list);
        }
        block_mark.clear();

        let mut final_mark: HashSet<usize> = HashSet::new();
        // Now go through input blocks to the previously calculated blocks
        for &b in &block_list {
            for j in 0..f.blocks()[b].in_edges.len() {
                let split_point = f.blocks()[b].in_edges[j].0 as usize;
                if final_mark.contains(&split_point) {
                    continue;
                }
                if f.blocks()[split_point].out_edges.len() != 2 {
                    continue;
                }
                let Some(&last_op) = f.blocks()[split_point].ops.last() else { continue };
                if f.op(last_op).code() == OpCode::Cbranch {
                    final_mark.insert(split_point);
                    self.constraints_from_cbranch(f, dom, last_op); // Try to generate constraints from this splitPoint
                }
            }
        }
    }

    /// Ghidra `ValueSetSolver::checkRelativeConstant` (rangeutil.cc:2316).
    fn check_relative_constant(&self, f: &Funcdata, mut vn: VarnodeId) -> Option<(i32, u64)> {
        let mut value: u64 = 0;
        loop {
            if self.vn_mark.contains(&vn) {
                let vs = &self.value_nodes[self.vs(vn)];
                if vs.type_code != 0 {
                    return Some((vs.type_code, value));
                }
            }
            if !f.vn(vn).is_written() {
                return None;
            }
            let op = f.vn(vn).def.expect("written varnode has a def");
            match f.op(op).code() {
                OpCode::Copy | OpCode::Indirect => vn = f.op(op).input(0)?,
                OpCode::IntAdd | OpCode::Ptrsub => {
                    let const_vn = f.op(op).input(1)?;
                    if !f.vn(const_vn).is_constant() {
                        return None;
                    }
                    value = value.wrapping_add(f.vn(const_vn).constant_value())
                        & super::nzmask::calc_mask(f.vn(const_vn).size);
                    vn = f.op(op).input(0)?;
                }
                _ => return None,
            }
        }
    }

    /// Ghidra `ValueSetSolver::generateRelativeConstraint` (rangeutil.cc:2351).
    fn generate_relative_constraint(&mut self, f: &Funcdata, dom: &Dominators, comp_op: OpId, cbranch: OpId) {
        let mut opc = f.op(comp_op).code();
        match opc {
            OpCode::IntLess => opc = OpCode::IntSless, // Treat unsigned pointer comparisons as signed relative to the base register
            OpCode::IntLessequal => opc = OpCode::IntSlessequal,
            OpCode::IntSless | OpCode::IntSlessequal | OpCode::IntEqual | OpCode::IntNotequal => {}
            _ => return,
        }
        let Some(in_vn0) = f.op(comp_op).input(0) else { return };
        let Some(in_vn1) = f.op(comp_op).input(1) else { return };
        let mut lift = CircleRange::from_bool(true);
        let (type_code, vn) = if let Some((tc, value)) = self.check_relative_constant(f, in_vn0) {
            let vn = in_vn1;
            if !lift.pull_back_binary(opc, value, 1, f.vn(vn).size as i32, 1) {
                return;
            }
            (tc, vn)
        } else if let Some((tc, value)) = self.check_relative_constant(f, in_vn1) {
            let vn = in_vn0;
            if !lift.pull_back_binary(opc, value, 0, f.vn(vn).size as i32, 1) {
                return;
            }
            (tc, vn)
        } else {
            return; // Neither side looks like a relative constant
        };

        let mut end_vn = vn;
        while !self.vn_mark.contains(&end_vn) {
            if !f.vn(end_vn).is_written() {
                return;
            }
            let op = f.vn(end_vn).def.expect("written varnode has a def");
            match f.op(op).code() {
                OpCode::Copy | OpCode::Ptrsub => end_vn = f.op(op).input(0).expect("input 0"),
                OpCode::IntAdd => {
                    // Can pull-back through INT_ADD
                    if !f.op(op).input(1).is_some_and(|c| f.vn(c).is_constant()) {
                        return; // if second param is constant
                    }
                    end_vn = f.op(op).input(0).expect("input 0");
                }
                _ => return,
            }
        }
        self.constraints_from_path(f, dom, type_code, &mut lift, vn, end_vn, cbranch);
    }

    /// Ghidra `ValueSetSolver::establishValueSets` (rangeutil.cc:2416): build the data-flow
    /// system backward from `sinks`; `reads` are the add-on sites whose input value sets are
    /// wanted; `stack_reg` (if any) is the stack pointer, the *relative* base.
    pub fn establish_value_sets(
        &mut self,
        f: &Funcdata,
        dom: &Dominators,
        sinks: &[VarnodeId],
        reads: &[OpId],
        stack_reg: Option<VarnodeId>,
        indirect_as_copy: bool,
    ) {
        let mut worklist: Vec<VarnodeId> = Vec::new();
        let mut work_pos = 0usize;
        if let Some(sr) = stack_reg {
            let idx = self.new_value_set(f, sr, 1); // Establish stack pointer as special
            self.vn_mark.insert(sr);
            worklist.push(sr);
            work_pos += 1;
            self.root_nodes.push(idx);
        }
        for &v in sinks {
            self.new_value_set(f, v, 0);
            self.vn_mark.insert(v);
            worklist.push(v);
        }
        while work_pos < worklist.len() {
            let v = worklist[work_pos];
            work_pos += 1;
            let vn = f.vn(v);
            if !vn.is_written() {
                if vn.is_constant() {
                    // Constant inputs to binary ops should not be treated as root nodes as they
                    // get picked up during iteration by the other input, except in the case of a
                    // a PTRSUB from a spacebase constant.
                    let lone_unary = vn.descend.first().is_some_and(|&d| f.op(d).num_inputs() == 1);
                    if vn.is_spacebase() || lone_unary {
                        let idx = self.vs(v);
                        self.root_nodes.push(idx);
                    }
                } else {
                    let idx = self.vs(v);
                    self.root_nodes.push(idx);
                }
                continue;
            }
            let op = vn.def.expect("written varnode has a def");
            match f.op(op).code() {
                // Distinguish ops where we can never predict an integer range
                OpCode::Indirect => {
                    if indirect_as_copy || f.op(op).is_indirect_store() {
                        let in_vn = f.op(op).input(0).expect("INDIRECT input 0");
                        if !self.vn_mark.contains(&in_vn) {
                            self.new_value_set(f, in_vn, 0);
                            self.vn_mark.insert(in_vn);
                            worklist.push(in_vn);
                        }
                    } else {
                        let idx = self.vs(v);
                        self.value_nodes[idx].set_full(f);
                        self.root_nodes.push(idx);
                    }
                }
                OpCode::Call
                | OpCode::Callind
                | OpCode::Callother
                | OpCode::Load
                | OpCode::New
                | OpCode::Segmentop
                | OpCode::Cpoolref
                | OpCode::FloatAdd
                | OpCode::FloatDiv
                | OpCode::FloatMult
                | OpCode::FloatSub
                | OpCode::FloatNeg
                | OpCode::FloatAbs
                | OpCode::FloatSqrt
                | OpCode::FloatInt2float
                | OpCode::FloatFloat2float
                | OpCode::FloatTrunc
                | OpCode::FloatCeil
                | OpCode::FloatFloor
                | OpCode::FloatRound => {
                    let idx = self.vs(v);
                    self.value_nodes[idx].set_full(f);
                    self.root_nodes.push(idx);
                }
                _ => {
                    for i in 0..f.op(op).num_inputs() {
                        let in_vn = f.op(op).input(i).expect("input in range");
                        if self.vn_mark.contains(&in_vn) || f.vn(in_vn).is_annotation() {
                            continue;
                        }
                        self.new_value_set(f, in_vn, 0);
                        self.vn_mark.insert(in_vn);
                        worklist.push(in_vn);
                    }
                }
            }
        }
        for &op in reads {
            for slot in 0..f.op(op).num_inputs() {
                let v = f.op(op).input(slot).expect("input in range");
                if self.vn_mark.contains(&v) {
                    self.read_nodes.insert(op, ValueSetRead::new(op, slot as i32));
                    self.op_mark.insert(op); // Mark read ops for equation generation stage
                    break; // Only 1 read allowed
                }
            }
        }
        self.generate_constraints(f, dom, &worklist, reads);
        self.op_mark.clear(); // Clear marks on read ops

        self.establish_topological_order(f);
        // (Ghidra clears the Varnode marks here; mosura's marks are the solver's own and are
        // still consulted by `iterate`/`successors` during `solve`.)
    }

    /// Ghidra `ValueSet::iterate` (rangeutil.cc:1611): recalculate node `idx` from its inputs.
    /// Returns `true` when the value set changed.
    fn iterate(&mut self, f: &Funcdata, idx: usize, widener: &dyn Widener) -> bool {
        let Some(v) = self.value_nodes[idx].vn else { return false };
        if !f.vn(v).is_written() {
            return false;
        }
        if widener.check_freeze(&self.value_nodes[idx]) {
            return false;
        }
        if self.value_nodes[idx].count == 0 && self.compute_type_code(f, idx) {
            self.value_nodes[idx].set_full(f);
            return true;
        }
        self.value_nodes[idx].count += 1; // Count this iteration
        let mut res = CircleRange::default();
        let op = f.vn(v).def.expect("written varnode has a def");
        let num_params = self.value_nodes[idx].num_params;
        let op_code = self.value_nodes[idx].op_code;
        let out_size = f.vn(v).size as i32;
        let mut eq_pos = 0usize;
        let in_set = |s: &Self, i: usize| -> usize { s.vs(f.op(op).input(i).expect("input in range")) };
        let constrained = |s: &Self, eq: usize, input_range: &CircleRange| -> CircleRange {
            let mut range_copy = *input_range;
            if range_copy.intersect(&s.value_nodes[idx].equations[eq].range) != 0 {
                range_copy = s.value_nodes[idx].equations[eq].range;
            }
            range_copy
        };
        if op_code == Some(OpCode::Multiequal) {
            let mut pieces;
            for i in 0..num_params {
                let in_idx = in_set(self, i as usize);
                let in_range = self.value_nodes[in_idx].range;
                if self.value_nodes[idx].does_equation_apply(eq_pos, i) {
                    let range_copy = constrained(self, eq_pos, &in_range);
                    pieces = res.circle_union(&range_copy);
                    eq_pos += 1; // Equation was used
                } else {
                    pieces = res.circle_union(&in_range);
                }
                if pieces == 2 && res.minimal_container(&in_range, MAX_STEP) {
                    // Could not get clean union, force it
                    break;
                }
            }
            let range = self.value_nodes[idx].range;
            if res.circle_union(&range) != 0 {
                // Union with the previous iteration's set
                res.minimal_container(&range, MAX_STEP);
            }
            if !range.is_empty() && !res.is_empty() {
                self.value_nodes[idx].left_is_stable = range.get_min() == res.get_min();
                self.value_nodes[idx].right_is_stable = range.get_end() == res.get_end();
            }
        } else if num_params == 1 {
            let in1 = in_set(self, 0);
            let in_size = f.vn(self.value_nodes[in1].vn.expect("system node")).size as i32;
            let in_range = self.value_nodes[in1].range;
            let opc = op_code.expect("written varnode has an opcode");
            if self.value_nodes[idx].does_equation_apply(eq_pos, 0) {
                let range_copy = constrained(self, eq_pos, &in_range);
                if !res.push_forward_unary(opc, &range_copy, in_size, out_size) {
                    self.value_nodes[idx].set_full(f);
                    return true;
                }
                // eq_pos += 1 (unused afterwards)
            } else if !res.push_forward_unary(opc, &in_range, in_size, out_size) {
                self.value_nodes[idx].set_full(f);
                return true;
            }
            self.value_nodes[idx].left_is_stable = self.value_nodes[in1].left_is_stable;
            self.value_nodes[idx].right_is_stable = self.value_nodes[in1].right_is_stable;
        } else if num_params == 2 {
            let in1 = in_set(self, 0);
            let in2 = in_set(self, 1);
            let in_size = f.vn(self.value_nodes[in1].vn.expect("system node")).size as i32;
            let opc = op_code.expect("written varnode has an opcode");
            if self.value_nodes[idx].equations.is_empty() {
                let (r1, r2) = (self.value_nodes[in1].range, self.value_nodes[in2].range);
                if !res.push_forward_binary(opc, &r1, &r2, in_size, out_size, MAX_STEP) {
                    self.value_nodes[idx].set_full(f);
                    return true;
                }
            } else {
                let mut range1 = self.value_nodes[in1].range;
                let mut range2 = self.value_nodes[in2].range;
                if self.value_nodes[idx].does_equation_apply(eq_pos, 0) {
                    if range1.intersect(&self.value_nodes[idx].equations[eq_pos].range) != 0 {
                        range1 = self.value_nodes[idx].equations[eq_pos].range;
                    }
                    eq_pos += 1;
                }
                if self.value_nodes[idx].does_equation_apply(eq_pos, 1)
                    && range2.intersect(&self.value_nodes[idx].equations[eq_pos].range) != 0
                {
                    range2 = self.value_nodes[idx].equations[eq_pos].range;
                }
                if !res.push_forward_binary(opc, &range1, &range2, in_size, out_size, MAX_STEP) {
                    self.value_nodes[idx].set_full(f);
                    return true;
                }
            }
            self.value_nodes[idx].left_is_stable =
                self.value_nodes[in1].left_is_stable && self.value_nodes[in2].left_is_stable;
            self.value_nodes[idx].right_is_stable =
                self.value_nodes[in1].right_is_stable && self.value_nodes[in2].right_is_stable;
        } else if num_params == 3 {
            let in1 = in_set(self, 0);
            let in2 = in_set(self, 1);
            let in3 = in_set(self, 2);
            let in_size = f.vn(self.value_nodes[in1].vn.expect("system node")).size as i32;
            let opc = op_code.expect("written varnode has an opcode");
            let mut range1 = self.value_nodes[in1].range;
            let mut range2 = self.value_nodes[in2].range;
            if self.value_nodes[idx].does_equation_apply(eq_pos, 0) {
                if range1.intersect(&self.value_nodes[idx].equations[eq_pos].range) != 0 {
                    range1 = self.value_nodes[idx].equations[eq_pos].range;
                }
                eq_pos += 1;
            }
            if self.value_nodes[idx].does_equation_apply(eq_pos, 1)
                && range2.intersect(&self.value_nodes[idx].equations[eq_pos].range) != 0
            {
                range2 = self.value_nodes[idx].equations[eq_pos].range;
            }
            let range3 = self.value_nodes[in3].range;
            if !res.push_forward_trinary(opc, &range1, &range2, &range3, in_size, out_size, MAX_STEP) {
                self.value_nodes[idx].set_full(f);
                return true;
            }
            self.value_nodes[idx].left_is_stable =
                self.value_nodes[in1].left_is_stable && self.value_nodes[in2].left_is_stable;
            self.value_nodes[idx].right_is_stable =
                self.value_nodes[in1].right_is_stable && self.value_nodes[in2].right_is_stable;
        } else {
            return false; // No way to change this value set
        }

        if res == self.value_nodes[idx].range {
            return false;
        }
        if self.value_nodes[idx].part_head.is_some() {
            let mut range = self.value_nodes[idx].range;
            if !widener.do_widening(&self.value_nodes[idx], &mut range, &res) {
                self.value_nodes[idx].set_full(f);
            } else {
                self.value_nodes[idx].range = range;
            }
        } else {
            self.value_nodes[idx].range = res;
        }
        true
    }

    /// Ghidra `ValueSet::computeTypeCode` (rangeutil.cc:1567): `true` flags an indeterminate
    /// combination of relative inputs.
    fn compute_type_code(&mut self, f: &Funcdata, idx: usize) -> bool {
        let v = self.value_nodes[idx].vn.expect("system node");
        let op = f.vn(v).def.expect("written varnode has a def");
        let mut rel_count = 0;
        let mut last_type_code = 0;
        for i in 0..self.value_nodes[idx].num_params {
            let in_idx = self.vs(f.op(op).input(i as usize).expect("input in range"));
            if self.value_nodes[in_idx].type_code != 0 {
                rel_count += 1;
                last_type_code = self.value_nodes[in_idx].type_code;
            }
        }
        if rel_count == 0 {
            self.value_nodes[idx].type_code = 0;
            return false;
        }
        // Only certain operations can propagate a relative value set
        match self.value_nodes[idx].op_code {
            Some(OpCode::Ptrsub | OpCode::Ptradd | OpCode::IntAdd | OpCode::IntSub) => {
                if rel_count == 1 {
                    self.value_nodes[idx].type_code = last_type_code;
                } else {
                    return true;
                }
            }
            Some(OpCode::Cast | OpCode::Copy | OpCode::Indirect | OpCode::Multiequal) => {
                self.value_nodes[idx].type_code = last_type_code;
            }
            _ => return true,
        }
        false
    }

    /// Ghidra `ValueSetSolver::solve` (rangeutil.cc:2524): iterate in the established order,
    /// looping through components until a fixed point (or `max` iterations).
    pub fn solve(&mut self, f: &Funcdata, max: i32, widener: &dyn Widener) {
        self.max_iterations = max;
        self.num_iterations = 0;
        for vs in self.value_nodes.iter_mut() {
            vs.count = 0;
        }
        let mut component_stack: Vec<usize> = Vec::new();
        let mut cur_component: Option<usize> = None;
        let mut cur_set = self.order_partition.start_node;

        while let Some(cs) = cur_set {
            self.num_iterations += 1;
            if self.num_iterations > self.max_iterations {
                break; // Quit if max iterations exceeded
            }
            if let Some(ph) = self.value_nodes[cs].part_head {
                if Some(ph) != cur_component {
                    component_stack.push(ph);
                    cur_component = Some(ph);
                    self.record_storage[ph].is_dirty = false;
                    // Reset component counter upon entry
                    let start = self.record_storage[ph].start_node.expect("component start");
                    let reset = widener.determine_iteration_reset(&self.value_nodes[start]);
                    self.value_nodes[start].count = reset;
                }
            }
            if let Some(cc) = cur_component {
                if self.iterate(f, cs, widener) {
                    self.record_storage[cc].is_dirty = true;
                }
                if self.record_storage[cc].stop_node != Some(cs) {
                    cur_set = self.value_nodes[cs].next;
                } else {
                    let mut cc = cc;
                    loop {
                        if self.record_storage[cc].is_dirty {
                            self.record_storage[cc].is_dirty = false;
                            cur_set = self.record_storage[cc].start_node;
                            if component_stack.len() > 1 {
                                // Mark parent as dirty if we are restarting dirty child
                                let parent = component_stack[component_stack.len() - 2];
                                self.record_storage[parent].is_dirty = true;
                            }
                            break;
                        }
                        component_stack.pop();
                        if component_stack.is_empty() {
                            cur_component = None;
                            cur_set = self.value_nodes[cs].next;
                            break;
                        }
                        cc = *component_stack.last().expect("nonempty");
                        cur_component = Some(cc);
                        if self.record_storage[cc].stop_node != Some(cs) {
                            cur_set = self.value_nodes[cs].next;
                            break;
                        }
                    }
                }
            } else {
                self.iterate(f, cs, widener);
                cur_set = self.value_nodes[cs].next;
            }
        }
        // Calculate any follow-on value sets (`ValueSetRead::compute`)
        let ops: Vec<OpId> = self.read_nodes.keys().copied().collect();
        for op in ops {
            let slot = self.read_nodes[&op].slot as usize;
            let v = f.op(op).input(slot).expect("read slot in range");
            let vs = &self.value_nodes[self.vs(v)];
            let (tc, mut range, l, r) = (vs.type_code, vs.range, vs.left_is_stable, vs.right_is_stable);
            let rn = self.read_nodes.get_mut(&op).expect("read node");
            rn.type_code = tc;
            rn.left_is_stable = l;
            rn.right_is_stable = r;
            if tc == rn.equation_type_code && range.intersect(&rn.equation_constraint) != 0 {
                range = rn.equation_constraint;
            }
            rn.range = range;
        }
    }

    pub fn get_num_iterations(&self) -> i32 {
        self.num_iterations
    }

    /// Ghidra `ValueSetSolver::getValueSetRead` (rangeutil.hh:322), keyed by the read op.
    pub fn get_value_set_read(&self, op: OpId) -> Option<&ValueSetRead> {
        self.read_nodes.get(&op)
    }

    /// Every ValueSet in the system (Ghidra `beginValueSets..endValueSets`), for diagnostics.
    pub fn value_sets(&self) -> impl Iterator<Item = &ValueSet> {
        self.value_nodes.iter().filter(|vs| vs.vn.is_some())
    }
}

/// Ghidra `FlowBlock::getImmedDom` — `None` for the entry block.
fn immed_dom(dom: &Dominators, b: usize) -> Option<usize> {
    let d = *dom.idom.get(b)?;
    if d == b || d == usize::MAX {
        None
    } else {
        Some(d)
    }
}

/// Ghidra `FlowBlock::restrictedByConditional` (block.cc:405): can `block` be reached only
/// through an out-edge of the conditional block `cond`?
fn restricted_by_conditional(f: &Funcdata, dom: &Dominators, block: usize, cond: usize) -> bool {
    let ins = &f.blocks()[block].in_edges;
    if ins.len() == 1 {
        return true; // Its impossible for any path to come through sibling to this
    }
    if immed_dom(dom, block) != Some(cond) {
        return false; // This is not dominated by conditional block at all
    }
    let mut seen_cond = false;
    for e in ins {
        let mut in_block = Some(e.0 as usize);
        if in_block == Some(cond) {
            if seen_cond {
                return false; // Coming in from cond block on multiple direct edges
            }
            seen_cond = true;
            continue;
        }
        while let Some(b) = in_block {
            if b == block {
                break;
            }
            if b == cond {
                return false; // Must have come through sibling
            }
            in_block = immed_dom(dom, b);
        }
    }
    true
}
