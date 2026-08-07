//! Built-in analyzers (A4+) — the passes that plug into the [`AutoAnalysisManager`].
//!
//! A4 ports the core of Ghidra's disassembly + function discovery: recursive-descent
//! disassembly driving the SLEIGH engine ([`Disassembler`]) and function creation at
//! entry points and call targets ([`FunctionCreator`]).

pub mod address_table;
pub mod demangler;
pub mod eh_frame;
pub mod external_jump;
pub mod function_start;
pub mod noreturn;
pub mod relocation_seed;
pub mod shared_return;
pub mod switch;

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::manager::Scheduling;
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, CodeUnit, Program, RefType, SymbolType};
use crate::decompile::opcode::OpCode;
use crate::decompile::space::{Address, SpaceId};
use crate::sleigh::engine::Spec;
use crate::sleigh::pcode::PArg;

/// Longest code unit the flow walk back-probes for when testing whether an address lies inside
/// an existing one (Ghidra queries an interval-indexed listing; mosura probes backward). Covers
/// the longest x86 instruction and the pointer/scalar data units the markup analyzers create.
const MAX_CODE_UNIT_LEN: u64 = 16;

/// Ghidra `Disassembler.getInitializedMemory` (Disassembler.java:387): the loaded + initialized
/// address set, with an uninitialized `EXTERNAL` block excluded (it is uninitialized here, so it
/// never enters the set in the first place).
fn initialized_memory(program: &Program) -> AddressSet {
    let mut set = AddressSet::new();
    for b in program.memory.blocks().filter(|b| b.is_initialized()) {
        set.add_range(b.start().space, b.start().offset, b.end().offset);
    }
    set
}

/// Recursive-descent disassembler (Ghidra's disassembly analyzer + `followFlow`):
/// from each seeded address it decodes instructions with the SLEIGH engine, following
/// fall-through and static branch targets within the function, laying down
/// [`CodeUnit::Instruction`]s. Static **call** targets are scheduled as new functions
/// (calls themselves fall through — the callee is a separate flow).
pub struct Disassembler {
    spec: Spec,
    ctx: Vec<u32>,
    ram: SpaceId,
}

impl Disassembler {
    /// Load the SLEIGH tables for the program's language, or `None` if unavailable.
    pub fn for_program(program: &Program) -> Option<Disassembler> {
        let (spec, ctx) = crate::lang::load(&program.language_id)?;
        Some(Disassembler { spec, ctx, ram: program.default_space })
    }

    /// Offset of a `ram`-space first input of a flow op (a static target), if any.
    fn static_target(op: &crate::sleigh::pcode::PcodeOp) -> Option<u64> {
        static_target(op)
    }
}

/// Offset of a `ram`-space first input of a flow op (a static target), if any.
pub(crate) fn static_target(op: &crate::sleigh::pcode::PcodeOp) -> Option<u64> {
    match op.ins.first() {
        Some(PArg::Var(v)) if v.space == "ram" => Some(v.offset),
        _ => None,
    }
}

/// Does control fall through past `insn` — Ghidra's `Instruction.getFallThrough()`.
///
/// **One definition, three callers, deliberately.** This decision is made by the disassembler's
/// linear walk, by [`compute_function_bodies`], and by
/// `function_start::flow_body`. It used to be written out at each site, and
/// the copies drifted: the disassembler consulted `is_noreturn` (citing Ghidra's `followFlow`)
/// while both body walks derived the answer from the opcode alone, so a body walked straight past
/// a `call <noreturn>` into whatever followed — six bytes of alignment padding in
/// `noret.gcc-x86-64`, and in general into the next function. Gated by
/// `ground_truth_parity::noreturn_call_bounds_the_body`.
///
/// Ghidra's rule: flow continues unless the instruction ends the flow (return / unconditional
/// branch / indirect jump), **or** it is a direct call to a function marked no-return
/// (`NoReturnFunctionAnalyzer`, whose result `FollowFlow` reads through
/// `Instruction.getFallThrough()`). An indirect call's target is not known here, so it is left
/// falling through — as Ghidra does.
pub(crate) fn falls_through(
    program: &Program,
    insn: &crate::sleigh::Instruction,
    ram: SpaceId,
) -> bool {
    let last = insn.ops.last().and_then(|o| OpCode::from_u32(o.opcode));
    if matches!(last, Some(OpCode::Return | OpCode::Branch | OpCode::Branchind)) {
        return false;
    }
    if matches!(last, Some(OpCode::Call)) {
        let target = insn.ops.iter().rev().find_map(|o| {
            matches!(OpCode::from_u32(o.opcode), Some(OpCode::Call))
                .then(|| static_target(o))
                .flatten()
        });
        if let Some(t) = target {
            if program.is_noreturn(Address::new(ram, t)) {
                return false;
            }
        }
    }
    true
}

/// Does a body walk follow this flow reference? — Ghidra `FollowFlow.shouldFollowFlow`
/// (FollowFlow.java:715) under `CreateFunctionCmd.getFunctionBody`'s `dontFollow` set
/// (CreateFunctionCmd.java:622):
///
/// ```java
/// FlowType[] dontFollow = { RefType.COMPUTED_CALL, RefType.CONDITIONAL_CALL,
///     RefType.UNCONDITIONAL_CALL, RefType.INDIRECTION };
/// ```
///
/// **`COMPUTED_JUMP` is deliberately NOT in that list**, which is why a switch's case bodies are
/// inside Ghidra's function body: `getFlowsFromInstruction` (:743) reads
/// `instr.getReferencesFrom()` and follows every flow reference this predicate admits.
///
/// ⚠️ THE STRUCTURAL DIFFERENCE THIS DOES NOT CLOSE. Ghidra's walk is **reference-driven** — it
/// asks the listing what an instruction references. mosura's is **opcode-driven**: it derives
/// static targets from the p-code. The two agree on ordinary branches and disagree wherever
/// analysis has overridden a reftype (an `UNCONDITIONAL_CALL` ref can sit on a `jmp`); consulting
/// references here is additive, so it closes the computed-jump gap without changing any flow the
/// opcode walk already followed. Converting the walk to be reference-driven outright is a separate
/// change with a much wider blast radius — see `docs/function-discovery-backlog.md` §9.
pub(crate) fn follows_flow_ref(t: RefType) -> bool {
    if !t.is_flow() {
        return false;
    }
    !matches!(
        t,
        RefType::ComputedCall
            | RefType::ConditionalCall
            | RefType::UnconditionalCall
            | RefType::Indirection
    )
}

impl Analyzer for Disassembler {
    fn name(&self) -> &str {
        "Disassembly"
    }
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Instruction
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::DISASSEMBLY
    }
    fn added(&self, program: &mut Program, set: &AddressSet, sched: &mut Scheduling) -> bool {
        let ram = self.ram;
        // Seeds are the start of each pending range (function/branch entry addresses).
        let mut work: Vec<u64> = set.ranges().map(|r| r.min).collect();
        let mut call_targets = AddressSet::new();
        // The extent this walk actually laid down. Ghidra's `codeDefined` event carries the whole
        // newly-disassembled address set, which is what an INSTRUCTION analyzer's "added" set is
        // (`AutoAnalysisManager.codeDefined`); mosura previously only ever notified *seed*
        // addresses, so an INSTRUCTION analyzer saw entry points rather than code. The
        // "Function Start Search After Code" pass re-checks patterns whose pre-requisite is
        // "follows an instruction", so it needs the real extent.
        let mut decoded = AddressSet::new();
        let mut decoded_any = false;
        // Ghidra `Disassembler.getInitializedMemory` (Disassembler.java:387) — the walk's
        // universe. Note `restrictToExecuteMemory` defaults to **false** (:384), so it is
        // LOADED+INITIALIZED memory that bounds disassembly, not executable memory.
        let initialized = initialized_memory(program);
        while let Some(a) = work.pop() {
            let addr = Address::new(ram, a);
            // Ghidra Disassembler.java:612-626. An Instruction already at this address means it
            // was previously disassembled — skip silently. Defined Data at the address, or an
            // *offcut* position inside any existing code unit, is a conflict Ghidra marks and
            // skips. mosura tested only `code_unit_at` (the exact start), so a walk could lay an
            // instruction across a defined data object; `code_unit_containing` closes that.
            if program.listing.code_unit_containing(addr, MAX_CODE_UNIT_LEN).is_some() {
                continue;
            }
            // :913 — a block start outside initialized memory is a memory-constraint error.
            if !initialized.contains(addr) {
                continue;
            }
            let window = program.memory.read_window(addr, 16); // max x86-64 instruction length
            let Some(insn) = self.spec.disassemble_ctx(&window, a, &self.ctx).into_iter().next() else {
                continue;
            };
            let ilen = insn.bytes.len() as u64;
            if ilen == 0 {
                continue;
            }
            // Control falls through unless the instruction ends the flow, or is a direct call to
            // a no-return function (`falls_through` — the single definition all three walks use).
            let last = insn.ops.last().and_then(|o| OpCode::from_u32(o.opcode));
            let falls = falls_through(program, &insn, ram);
            // Record indirect branches as switch candidates for the A6 switch analyzer.
            if matches!(last, Some(OpCode::Branchind)) {
                program.indirect_branches.insert(a);
            }
            // Flow references (Ghidra creates these as the instruction is laid down).
            for op in &insn.ops {
                let opcode = OpCode::from_u32(op.opcode);
                match opcode {
                    // A target equal to the instruction itself is a halt idiom
                    // (SLEIGH lifts `hlt` to `BRANCH <self>`), not a real flow edge —
                    // Ghidra emits no reference for it.
                    Some(OpCode::Branch | OpCode::Cbranch) => {
                        if let Some(t) = Self::static_target(op).filter(|&t| t != a) {
                            work.push(t);
                            let rt = if matches!(opcode, Some(OpCode::Cbranch)) {
                                RefType::ConditionalJump
                            } else {
                                RefType::UnconditionalJump
                            };
                            program.reference_manager.add(addr, Address::new(ram, t), rt, -1);
                        }
                    }
                    Some(OpCode::Call) => {
                        if let Some(t) = Self::static_target(op).filter(|&t| t != a) {
                            call_targets.add_range(ram, t, t);
                            program.reference_manager.add(
                                addr,
                                Address::new(ram, t),
                                RefType::UnconditionalCall,
                                -1,
                            );
                        }
                    }
                    // Ghidra `SleighInstructionPrototype.getDynamicOperandRefType`: an
                    // indirect BRANCHIND/CALLIND/RETURN whose flow target is the operand's
                    // *static* memory address — a `[mem]` operand lifts to a `ram` varnode,
                    // e.g. a PLT stub's `jmp *[GOT]` → `BRANCHIND (ram,slot)` — gets an
                    // INDIRECTION reference to that pointer slot. (A register/table target
                    // has no static `ram` operand here and is recovered by the decompiler
                    // switch analyzer; the *resolved* target is referenced by the
                    // SymbolicPropogator with the computed flow type.)
                    Some(OpCode::Branchind | OpCode::Callind | OpCode::Return) => {
                        if let Some(t) = Self::static_target(op) {
                            let to = Address::new(ram, t);
                            if program.memory.contains(to) {
                                program.reference_manager.add(addr, to, RefType::Indirection, -1);
                            }
                        }
                    }
                    _ => {}
                }
            }
            // Ghidra `Listing.addInstructions` refuses a unit that overlaps an existing one
            // (`CodeUnitInsertionException`); the block-start conflict check (:620-626) is the
            // same rule seen from the other end. Without this a walk starting in undefined bytes
            // can still run *into* a defined object.
            if (1..ilen).any(|k| program.listing.code_unit_at(Address::new(ram, a + k)).is_some()) {
                continue;
            }
            program.listing.define(addr, CodeUnit::Instruction { length: ilen as u32 });
            decoded.add_range(ram, a, a + ilen - 1);
            decoded_any = true;
            if falls {
                // :1140 (`endBlockEarly`) — do not follow fall-through out of initialized memory.
                let ft = a + ilen;
                if initialized.contains(Address::new(ram, ft)) {
                    work.push(ft);
                }
            }
        }
        if !call_targets.is_empty() {
            sched.function_defined(&call_targets);
        }
        // Ghidra's disassembly analyzer is itself an INSTRUCTION analyzer, so it is re-notified by
        // its own output too; a second pass over already-decoded addresses skips every one of them
        // at the `code_unit_containing` guard above and adds nothing to `decoded`, which is what
        // terminates the loop.
        if !decoded.is_empty() {
            sched.code_defined(&decoded);
        }
        decoded_any
    }
}

/// Create a function at each seeded address (entry points, call targets) and schedule it
/// for disassembly (Ghidra's `CreateFunctionCmd` + function analyzer). Idempotent: an
/// existing function (e.g. a loader-named one) keeps its name; a fresh target gets the
/// default `FUN_<addr>` name + symbol.
pub struct FunctionCreator {
    ram: SpaceId,
}

impl FunctionCreator {
    pub fn new(program: &Program) -> FunctionCreator {
        FunctionCreator { ram: program.default_space }
    }
}

impl Analyzer for FunctionCreator {
    fn name(&self) -> &str {
        "Function"
    }
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Function
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::FUNCTION
    }
    fn added(&self, program: &mut Program, set: &AddressSet, sched: &mut Scheduling) -> bool {
        let mut to_disasm = AddressSet::new();
        for r in set.ranges() {
            let addr = Address::new(self.ram, r.min);
            // Ghidra creates a function at a direct call target as long as it lies in the
            // program's memory — even uninitialized data (a degenerate, un-disassembled
            // stub); but not at an unmapped address (e.g. a 16-bit offset below the loaded
            // segments). It need not be executable. Data *entry points* are filtered out
            // before seeding (see `analyze`).
            if !program.memory.contains(addr) {
                continue;
            }
            let name = format!("FUN_{:08x}", r.min);
            program.function_manager.create_function(addr, &name, AddressSet::new());
            if !program.symbol_table.has_symbol_at(addr) {
                program.symbol_table.add_with_primary(addr, &name, SymbolType::Function, true);
            }
            to_disasm.add_range(self.ram, r.min, r.min);
        }
        sched.code_defined(&to_disasm);
        true
    }
}

/// Compute each function's body (Ghidra `Function.getBody`): the address set of code
/// units reachable from the entry by intra-function flow (fall-through + branch targets,
/// not calls), not crossing into another function's entry. Run after disassembly.
pub fn compute_function_bodies(spec: &Spec, ctx: &[u32], program: &mut Program) {
    use std::collections::{BTreeSet, HashSet};
    let ram = program.default_space;
    let entries: BTreeSet<u64> =
        program.function_manager.functions().map(|f| f.entry_point().offset).collect();

    let mut bodies: Vec<(u64, AddressSet)> = Vec::new();
    for &entry in &entries {
        let mut body = AddressSet::new();
        let mut visited: HashSet<u64> = HashSet::new();
        let mut work = vec![entry];
        while let Some(a) = work.pop() {
            if !visited.insert(a) {
                continue;
            }
            // Stop at another function's entry — it owns its own code.
            if a != entry && entries.contains(&a) {
                continue;
            }
            let window = program.memory.read_window(Address::new(ram, a), 16);
            let Some(insn) = spec.disassemble_ctx(&window, a, ctx).into_iter().next() else {
                continue;
            };
            let ilen = insn.bytes.len() as u64;
            if ilen == 0 {
                continue;
            }
            body.add_range(ram, a, a + ilen - 1); // inclusive [a, a+ilen)
            let falls = falls_through(program, &insn, ram);
            for op in &insn.ops {
                if matches!(OpCode::from_u32(op.opcode), Some(OpCode::Branch | OpCode::Cbranch)) {
                    if let Some(t) = Disassembler::static_target(op).filter(|&t| t != a) {
                        work.push(t);
                    }
                }
            }
            // The flow references this instruction carries — how Ghidra's `FollowFlow` finds
            // every target, and the only route to a computed jump's cases (the p-code for a
            // `BRANCHIND` names no static target; the jump table lives in the reference set).
            // The flow references this instruction carries — how Ghidra's `FollowFlow` finds
            // every target, and the only route into a computed jump's cases (the p-code for a
            // `BRANCHIND` names no static target; the jump table lives in the reference set).
            for r in program.reference_manager.refs_from(Address::new(ram, a)) {
                if follows_flow_ref(r.ref_type) && r.to.space == ram && r.to.offset != a {
                    work.push(r.to.offset);
                }
            }
            if falls {
                work.push(a + ilen);
            }
        }
        // External thunks / no-code functions get Ghidra's degenerate one-byte body.
        if body.is_empty() {
            body.add_range(ram, entry, entry);
        }
        bodies.push((entry, body));
    }
    for (entry, body) in bodies {
        program.function_manager.set_body(Address::new(ram, entry), body);
    }
}

/// `ConstantPropagationAnalyzer.removeUninitializedBlocks` (ConstantPropagationAnalyzer.java:220)
/// — uninitialized memory has no bytes, so it can hold no instruction and is dropped from the
/// set before any location is chosen.
///
/// Ghidra also skips *byte-mapped* blocks (`block.isMapped()`, :230), because those report
/// `isInitialized() == false` while still yielding bytes. mosura's loaders build flat images with
/// no byte-mapped blocks, so there is no such block to skip.
fn remove_uninitialized_blocks(program: &Program, set: &mut AddressSet) {
    let mut uninitialized = AddressSet::new();
    for block in program.memory.blocks() {
        if block.is_initialized() {
            continue;
        }
        uninitialized.add_range(block.start().space, block.start().offset, block.end().offset);
    }
    if !uninitialized.is_empty() {
        *set = set.subtract(&uninitialized);
    }
}

/// `ConstantPropagationAnalyzer.findLocationsRemoveFunctionBodies`
/// (ConstantPropagationAnalyzer.java:248) — reduce `set` to the list of addresses constant
/// propagation should *start* from, removing from `set` everything each start already accounts
/// for. Three passes, in Ghidra's order:
///
/// 1. every function OVERLAPPING the set contributes its **entry point** (:259-264), and its
///    whole body leaves the set (:268). This is the pass the `r.min` reading was missing, and the
///    one that makes coalesced adjacent entries all survive.
/// 2. of what remains, every reference DESTINATION that has at least one **call** reference to it
///    becomes a start and leaves the set (:271-293).
/// 3. of what still remains, each range's **minimum** becomes a start and leaves the set
///    (:296-306) — the fallback, and the only one mosura previously implemented.
///
/// Returns the start locations, ascending.
///
/// ⚠️ **`getFunctionsOverlapping` is a body query and mosura's bodies are empty during analysis.**
/// Ghidra maintains a function's body incrementally, so it is always current and always contains
/// the entry point; mosura computes bodies in one pass *after* the worklist converges
/// (`analyze` -> `compute_function_bodies`; see `function_start.rs:1031`), so during analysis
/// `f.body()` is empty for nearly every function and a literal body-intersection test would return
/// NOTHING. The entry-point test below restores exactly what Ghidra's always-populated body
/// guarantees — that a function whose entry is in the set overlaps the set — rather than adding a
/// condition Ghidra does not have.
fn find_locations_remove_function_bodies(program: &Program, set: &mut AddressSet) -> Vec<Address> {
    use std::collections::BTreeSet;
    let mut locations: BTreeSet<(u32, u64)> = BTreeSet::new();

    // 1 — functions overlapping the set: entry point in, body out.
    let mut in_body = AddressSet::new();
    for f in program.function_manager.functions() {
        let entry = f.entry_point();
        if !set.contains(entry) && f.body().intersect(set).is_empty() {
            continue;
        }
        locations.insert((entry.space.0, entry.offset));
        in_body = in_body.union(f.body());
        in_body.add(entry);
    }
    *set = set.subtract(&in_body);

    // 2 — call destinations in what remains.
    let mut out_of_body = AddressSet::new();
    for dest in program.reference_manager.destinations_in(set) {
        if program.reference_manager.refs_to(dest).any(|r| r.ref_type.is_call()) {
            locations.insert((dest.space.0, dest.offset));
            out_of_body.add(dest);
        }
    }
    *set = set.subtract(&out_of_body);

    // 3 — the minimum of each remaining range.
    let mut out_of_body = AddressSet::new();
    for r in set.ranges() {
        locations.insert((r.space.0, r.min));
        out_of_body.add_range(r.space, r.min, r.min);
    }
    *set = set.subtract(&out_of_body);

    locations.into_iter().map(|(s, o)| Address::new(SpaceId(s), o)).collect()
}

/// Constant-propagation reference analyzer (Ghidra `ConstantPropagationAnalyzer`): runs
/// the [`SymbolicPropogator`](crate::analysis::symbolic) over each function to recover
/// data references (READ/WRITE/DATA) from resolved memory operands. Runs at REFERENCE
/// priority, after disassembly + function creation.
pub struct ConstantPropagationAnalyzer {
    spec: Spec,
    ctx: Vec<u32>,
    ram: SpaceId,
}

impl ConstantPropagationAnalyzer {
    pub fn for_program(program: &Program) -> Option<ConstantPropagationAnalyzer> {
        let (spec, ctx) = crate::lang::load(&program.language_id)?;
        Some(ConstantPropagationAnalyzer { spec, ctx, ram: program.default_space })
    }
}

impl Analyzer for ConstantPropagationAnalyzer {
    fn name(&self) -> &str {
        "Constant Propagation"
    }
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Function
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::REFERENCE
    }
    fn added(&self, program: &mut Program, set: &AddressSet, sched: &mut Scheduling) -> bool {
        // Function entries bound each propagation walk to its own function.
        let entries: std::collections::HashSet<u64> = program
            .function_manager
            .functions()
            .filter(|f| f.entry_point().space == self.ram)
            .map(|f| f.entry_point().offset)
            .collect();
        // Resolved COMPUTED_CALL destinations become functions (Ghidra
        // `ConstantPropagationAnalyzer.findFunctionLocations` makes a function at each
        // call-reference destination — the analog of the disassembler seeding a direct-call
        // target). Seeding the Function analyzer re-runs disassembly + constant propagation on
        // the new function, driving the worklist to a fixpoint. New-only (not already a
        // function entry) so an already-known target doesn't re-trigger endlessly.
        // `added` (ConstantPropagationAnalyzer.java:178-186) copies the set, drops uninitialized
        // memory, then reduces it to a set of START LOCATIONS with
        // `findLocationsRemoveFunctionBodies` (:248-307). Taking `r.min` off the *raw* set
        // implemented only that method's LAST step (:296-303) — the fallback for whatever is left
        // once function bodies and call destinations have been removed. Applied to the raw set it
        // drops entries: an `AddressSet` coalesces adjacent ranges, so functions at consecutive
        // entries collapse into one range and only the first was ever propagated
        // (`docs/function-discovery-backlog.md`, CAUSE B).
        let mut unanalyzed = set.clone();
        remove_uninitialized_blocks(program, &mut unanalyzed);
        let locations = find_locations_remove_function_bodies(program, &mut unanalyzed);

        let mut new_funcs = AddressSet::new();
        for loc in locations {
            let dests =
                crate::analysis::symbolic::flow_constants(&self.spec, &self.ctx, program, loc, &entries);
            for d in dests {
                if !entries.contains(&d) {
                    new_funcs.add_range(self.ram, d, d);
                }
            }
        }
        if !new_funcs.is_empty() {
            sched.function_defined(&new_funcs);
        }
        true
    }
}

#[cfg(test)]
mod disassembler_bounds_tests {
    use super::*;
    use crate::analysis::manager::Scheduling;
    use crate::analysis::program::CodeUnit;
    use crate::decompile::space::{SpaceKind, SpaceManager};

    /// Build a one-block x86-64 program whose `.text` holds `bytes` at `0x401000`.
    fn program_with(bytes: Vec<u8>, execute: bool, initialized: bool) -> Program {
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
        let base = Address::new(ram, 0x40_1000);
        let mut p = Program::new(spaces, ram, "x86:LE:64:default", "gcc", base, false, 64);
        let len = bytes.len() as u64;
        p.memory.add_block(".text", base, len, true, false, execute, initialized.then_some(bytes));
        p
    }

    fn run_disassembler(p: &mut Program, seed: u64) {
        let Some(d) = Disassembler::for_program(p) else { return };
        let ram = p.default_space;
        let mut set = AddressSet::new();
        set.add_range(ram, seed, seed);
        let mut sched = Scheduling::default();
        d.added(p, &set, &mut sched);
    }

    /// THE BOUND (Ghidra `Disassembler`, Disassembler.java:612-626): the flow walk must not
    /// decode over an existing code unit. Ghidra skips a block start that already holds an
    /// Instruction, and treats *defined Data* at the address — or an offcut position inside any
    /// code unit — as a conflict it marks and skips.
    ///
    /// mosura's exact-start `code_unit_at` check already covers the case where the fall-through
    /// lands precisely ON a data unit's first byte. What it did NOT cover is the offcut case
    /// below, which is the one that matters — measured, not assumed: this test passed before the
    /// fix, the next one did not.
    ///
    /// The fixture is deliberately synthetic rather than compiled: with the analyzer ordering
    /// mosura has (Disassembler at priority 300, AddressTableAnalyzer at 899) the walk always
    /// runs *before* any data is defined, so a compiled binary cannot present this state to the
    /// disassembler at all. Laying the data unit down directly is the only way to test the bound.
    ///
    /// The walk here falls through to an address that is NOT a code-unit start but lies in the
    /// path of one: the decoded instruction would OVERLAP a defined data object. Ghidra rejects
    /// that twice over — the block-start conflict check treats an offcut position inside any code
    /// unit as a conflict (:620-626), and `listing.addInstructions` refuses an overlapping unit.
    /// mosura tested only `code_unit_at` (the exact start), so it laid the instruction down on
    /// top of the data.
    ///
    /// Layout: `xor eax,eax` at 0x401000 falls through to 0x401002, where an 8-byte `mov`
    /// decodes and would run to 0x401009 — straight through a data object defined at 0x401004.
    #[test]
    fn walk_does_not_overlap_defined_data() {
        if crate::lang::load("x86:LE:64:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        let bytes = vec![
            0x31, 0xc0, // 0x401000: xor eax,eax  (falls through)
            0x48, 0x8b, 0x04, 0x25, 0x00, 0x10, 0x40, 0x00, // 0x401002: an 8-byte mov
            0x90, // 0x40100a
        ];
        let mut p = program_with(bytes, true, true);
        let ram = p.default_space;
        // A data object starting INSIDE the instruction that would be decoded at 0x401002.
        p.listing.define(
            Address::new(ram, 0x40_1004),
            CodeUnit::Data { length: 6, type_name: "undefined *".into() },
        );
        p.defined_data.push((Address::new(ram, 0x40_1004), "undefined *".into(), 6));

        run_disassembler(&mut p, 0x40_1000);

        let overlapping: Vec<(u64, u32)> = p
            .listing
            .code_units()
            .filter_map(|(a, u)| match u {
                CodeUnit::Instruction { length } => Some((a.offset, *length)),
                _ => None,
            })
            .filter(|(a, len)| *a < 0x40_100a && a + u64::from(*len) > 0x40_1004)
            .collect();
        assert!(
            overlapping.is_empty(),
            "the walk laid instruction(s) {overlapping:x?} across the defined data object at \
             0x401004..0x40100a — Ghidra treats an offcut position inside a code unit as a \
             conflict (Disassembler.java:620-626) and refuses the overlapping unit"
        );
    }

    /// THE OTHER BOUND (Disassembler.java:913 block start, :1140 `endBlockEarly` fall-through):
    /// the walk proceeds only within LOADED + INITIALIZED memory (`getInitializedMemory`, :387;
    /// note `restrictToExecuteMemory` defaults to **false**, Disassembler.java:384, so it is
    /// initialized memory that bounds it, not executable memory).
    ///
    /// Here the fall-through leaves the initialized block entirely. mosura stopped by accident —
    /// `read_window` returns nothing past the block, so the decode failed — but nothing asserted
    /// it, and the accident does not hold for a walk running from one initialized block into an
    /// adjacent one. This pins the intent.
    #[test]
    fn walk_stops_at_end_of_initialized_memory() {
        if crate::lang::load("x86:LE:64:default").is_none() {
            return;
        }
        // `xor eax,eax` then `nop` — the walk falls through off the end of the block.
        let mut p = program_with(vec![0x31, 0xc0, 0x90], true, true);
        let ram = p.default_space;
        run_disassembler(&mut p, 0x40_1000);
        assert!(p.listing.code_unit_at(Address::new(ram, 0x40_1002)).is_some(), "nop decoded");
        assert!(
            p.listing.code_unit_at(Address::new(ram, 0x40_1003)).is_none(),
            "the walk ran past the end of initialized memory"
        );
    }
}

#[cfg(test)]
mod constant_propagation_location_tests {
    use super::*;
    use crate::analysis::manager::Scheduling;
    use crate::decompile::space::{SpaceKind, SpaceManager};

    /// CAUSE B (`docs/function-discovery-backlog.md`): `ConstantPropagationAnalyzer.added`
    /// (ConstantPropagationAnalyzer.java:178-186) reduces the set to start locations with
    /// `findLocationsRemoveFunctionBodies` (:248), whose FIRST pass contributes the entry point of
    /// every function overlapping the set (:259-264). Reading `r.min` off the raw set implemented
    /// only that method's LAST pass (:296-303) — the fallback for what is left once bodies and
    /// call destinations have been removed — so two functions at adjacent entries, which coalesce
    /// into a single `AddressSet` range, lost the second one entirely.
    ///
    /// Layout: a bare `ret` at `0x401000` (function A, the range minimum) and a rip-relative load
    /// at `0x401001` (function B) that resolves to `0x401018`. Only propagating from A stops at
    /// the `ret` and recovers nothing; the READ reference is the proof that B ran.
    #[test]
    fn adjacent_function_entries_are_all_propagated_from() {
        if crate::lang::load("x86:LE:64:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
        let base = Address::new(ram, 0x40_1000);
        let mut p = Program::new(spaces, ram, "x86:LE:64:default", "gcc", base, false, 64);
        let mut img = vec![0u8; 0x1000];
        // 0x401000: c3                       ret
        // 0x401001: 48 8b 05 10 00 00 00     mov rax,[rip+0x10]   -> reads 0x401018
        // 0x401008: c3                       ret
        img[..9].copy_from_slice(&[0xc3, 0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00, 0xc3]);
        p.memory.add_block(".text", base, 0x1000, true, false, true, Some(img));
        for off in [0x40_1000u64, 0x40_1001] {
            p.function_manager.create_function(
                Address::new(ram, off),
                &format!("FUN_{off:08x}"),
                AddressSet::new(),
            );
        }

        let mut set = AddressSet::new();
        set.add_range(ram, 0x40_1000, 0x40_1000);
        set.add_range(ram, 0x40_1001, 0x40_1001);
        assert_eq!(set.ranges().count(), 1, "the two entries must coalesce for this to bite");

        let a = ConstantPropagationAnalyzer::for_program(&p).unwrap();
        a.added(&mut p, &set, &mut Scheduling::default());

        let reads: Vec<u64> = p
            .reference_manager
            .references()
            .filter(|r| r.ref_type == RefType::Read)
            .map(|r| r.to.offset)
            .collect();
        assert!(
            reads.contains(&0x40_1018),
            "no READ reference to 0x401018: constant propagation never started at the function at \
             0x401001, because it shares a coalesced range with the one at 0x401000 and only the \
             range minimum was used. Got {reads:x?}"
        );
    }
}
