//! Built-in analyzers (A4+) — the passes that plug into the [`AutoAnalysisManager`].
//!
//! A4 ports the core of Ghidra's disassembly + function discovery: recursive-descent
//! disassembly driving the SLEIGH engine ([`Disassembler`]) and function creation at
//! entry points and call targets ([`FunctionCreator`]).

pub mod address_table;
pub mod demangler;
pub mod eh_frame;
pub mod external_jump;
pub mod find_noreturn;
pub mod function_start;
pub mod noreturn;
pub mod relocation_seed;
pub mod shared_return;
pub mod thunk;
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

/// `Disassembler.MAX_REPEAT_PATTERN_LENGTH` (Disassembler.java:82) — the longest run of
/// consecutive instructions with the same repeated byte value a block may contain before it is
/// terminated. See [`crate::analysis::repeat_instruction`]; the limit admits one MORE instruction
/// than its value, because the tripping instruction is still added.
pub(crate) const MAX_REPEAT_PATTERN_LENGTH: i32 = 16;

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
    spec: &'static Spec,
    ctx: &'static [u32],
    ram: SpaceId,
}

impl Disassembler {
    /// Load the SLEIGH tables for the program's language, or `None` if unavailable.
    pub fn for_program(program: &Program) -> Option<Disassembler> {
        let (spec, ctx) = crate::lang::load_cached(&program.language_id)?;
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
///
/// ⭐ **A FLOW OVERRIDE OUTRANKS THE INSTRUCTION.** Ghidra never asks the bytes directly:
/// `getDefaultFallThrough()` (InstructionDB.java:926) asks `getFlowType()`, and `getFlowType()`
/// (:321) is `getModifiedFlowType(proto.getFlowType(this), flowOverride)`. So when analysis has
/// set an override on this instruction the answer comes from
/// [`overridden_flow_props`](crate::analysis::flowtype::overridden_flow_props), not from the
/// opcode reading below — re-deriving flow from the instruction discards exactly what the
/// analyzers computed (`reftype-is-post-override-not-the-instruction`).
///
/// ⚠️ The opcode reading is kept for the un-overridden case and is a SEPARATE, pre-existing
/// divergence from Ghidra, which classifies through `SleighInstructionPrototype`'s flow flags
/// ([`crate::analysis::flowtype::has_fallthrough`]) — the two disagree on any instruction with
/// an internal p-code loop, e.g. `rep movs` (see `shared_return.rs`'s
/// `instruction_falls_through`). Routing only the overridden case through the faithful path
/// keeps this change's blast radius to the addresses an analyzer actually overrides;
/// converting the base derivation is its own change.
pub(crate) fn falls_through(
    program: &Program,
    addr: Address,
    insn: &crate::sleigh::Instruction,
    ram: SpaceId,
) -> bool {
    let ov = program.flow_override_at(addr);
    if ov != crate::analysis::flowtype::FlowOverride::None {
        let next = addr.offset + insn.bytes.len() as u64;
        return crate::analysis::flowtype::overridden_flow_props(&insn.ops, addr.offset, next, ov)
            .fallthrough;
    }
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
        // ⚠️ NOT `Instruction`. Ghidra subscribes disassembly to no change channel whatsoever —
        // it is only ever a `DisassembleCommand` scheduled onto the manager
        // (`AutoAnalysisManager.disassemble`, :1128), and `AutoAnalysisManager.codeDefined`
        // (:262-272) announces instructions that were laid down, to *other* analyzers.
        // Subscribing this to `Instruction` made it re-receive its own decoded extent, which is
        // how seed addresses came to share an accumulator with decoded code — see
        // [`Scheduling::disassemble`]. Requests arrive by name through that command instead.
        AnalyzerType::OneTime
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::DISASSEMBLY
    }
    fn added(&self, program: &mut Program, set: &AddressSet, sched: &mut Scheduling) -> bool {
        let ram = self.ram;
        // Ghidra `DisassembleCommand.doDisassembly` (DisassembleCommand.java:235-266) drains each
        // range one address at a time — `while (!subRangeSet.isEmpty()) { Address nextAddr =
        // subRangeSet.getMinAddress(); … subRangeSet.delete(nextAddr, nextAddr); … }` — and
        // branches on how much of the range is left:
        //
        // ```java
        // subRangeSet.delete(nextAddr, nextAddr);                    // :245
        // …
        // long addrsLeft = subRangeSet.getNumAddresses();            // :261
        // if (addrsLeft <= 4) { seedSet.add(nextAddr); continue; }   // :262
        // ```
        //
        // ⚠️ `addrsLeft` is counted AFTER `nextAddr` has been deleted (:245), so the cut admits a
        // range of FIVE addresses, not four: `addrsLeft == r.max - r.min`.
        //
        // **A SHORT range contributes every one of its addresses as a seed; a LONG one is
        // disassembled by FLOW from its minimum**, with the decoded extent then deleted from the
        // range (:288-297). Taking `r.min` for every range implemented only the second half, so
        // two requested entries that happen to be adjacent collapsed into one: `wprobe`'s `__CHK`
        // @`08048111` swallowed `p_leaf_` @`08048112`, whose 46-byte body then never entered the
        // listing even though `main_` calls it directly.
        //
        // ⚠️ Seeding every address of a LONG range instead is not a harmless generalisation — it
        // walks into inter-function padding. Measured on the war2 MZ stub: 8 misaligned decodes
        // (the tracked bound) became 53, with 0 spurious functions, i.e. pure over-decode. The
        // `<= 4` cut is the line that governs it, and it is Ghidra's.
        const MAX_ADDRS_LEFT: u64 = 4; // `addrsLeft <= 4` (:262)
        let mut work: Vec<u64> = set
            .ranges()
            .flat_map(|r| {
                // `addrsLeft` after deleting the range's minimum.
                let addrs_left = r.max - r.min;
                let last = if addrs_left <= MAX_ADDRS_LEFT { r.max } else { r.min };
                r.min..=last
            })
            .collect();
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
        // `repeatInstructionByteTracker` (Disassembler.java:113), reset per BLOCK (:911). mosura's
        // walk has no explicit block object: a block is a straight-line run, and because the
        // fall-through is pushed LAST onto a LIFO worklist it is always the next address popped —
        // so "the previous decode ended exactly here" is the same predicate as "same block".
        let mut repeat_tracker =
            crate::analysis::repeat_instruction::RepeatInstructionByteTracker::new(
                MAX_REPEAT_PATTERN_LENGTH,
            );
        let mut prev_block_end: Option<u64> = None;
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
            let Some(insn) = self.spec.disassemble_ctx(&window, a, self.ctx).into_iter().next() else {
                continue;
            };
            let ilen = insn.bytes.len() as u64;
            if ilen == 0 {
                continue;
            }
            // Control falls through unless the instruction ends the flow, or is a direct call to
            // a no-return function (`falls_through` — the single definition all three walks use).
            let last = insn.ops.last().and_then(|o| OpCode::from_u32(o.opcode));
            let falls = falls_through(program, addr, &insn, ram);
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
            // :1067 — the repeated-byte run check. Ghidra performs it BEFORE adding the
            // instruction but only records a parse conflict; `processInstruction` adds the
            // instruction anyway (:1254) and the block ends afterwards on
            // `block.hasInstructionError()` (:1076). So the tripping instruction is KEPT and only
            // its fall-through is abandoned — which is why a limit of 16 leaves 17 instructions.
            if prev_block_end != Some(a) {
                repeat_tracker.reset();
            }
            let exceeded = repeat_tracker.exceeds_repeat_byte_pattern(&insn.bytes);
            prev_block_end = Some(a + ilen);
            if falls && !exceeded {
                // :1140 (`endBlockEarly`) — do not follow fall-through out of initialized memory.
                let ft = a + ilen;
                if initialized.contains(Address::new(ram, ft)) {
                    work.push(ft);
                }
            }
        }
        if !call_targets.is_empty() {
            // A COMMAND: make a function at each call target (Ghidra `createFunction`, :1132).
            sched.create_function(&call_targets);
        }
        // The genuine `codeDefined` NOTIFICATION (AutoAnalysisManager.java:262-272): these
        // instructions were actually laid down. It carries the decoded EXTENT, and it is consumed
        // by the `Instruction` analyzers that re-check byte patterns whose pre-requisite is
        // "follows an instruction". This is the only place mosura raises it, and nothing
        // subscribes disassembly to it — see [`Scheduling::disassemble`].
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
        let mut created = AddressSet::new();
        // EVERY address, not each range's minimum — Ghidra's `CreateFunctionCmd` iterates
        // `origEntries.getAddresses(true)` (CreateFunctionCmd.java:158). Two entries that happen
        // to be adjacent coalesce into one `AddressSet` range, and taking `r.min` created a
        // function at only the first of them and scheduled only that one for disassembly.
        for off in set.ranges().flat_map(|r| r.min..=r.max) {
            let addr = Address::new(self.ram, off);
            // Ghidra creates a function at a direct call target as long as it lies in the
            // program's memory — even uninitialized data (a degenerate, un-disassembled
            // stub); but not at an unmapped address (e.g. a 16-bit offset below the loaded
            // segments). It need not be executable. Data *entry points* are filtered out
            // before seeding (see `analyze`).
            if !program.memory.contains(addr) {
                continue;
            }
            let is_new = program.function_manager.function_at(addr).is_none();
            let name = format!("FUN_{off:08x}");
            program.function_manager.create_function(addr, &name, AddressSet::new());
            if !program.symbol_table.has_symbol_at(addr) {
                program.symbol_table.add_with_primary(addr, &name, SymbolType::Function, true);
            }
            to_disasm.add_range(self.ram, off, off);
            if is_new {
                created.add_range(self.ram, off, off);
            }
        }
        // A COMMAND, not a notification: these entries still need decoding.
        sched.disassemble(&to_disasm);
        // ...and the NOTIFICATION that they now exist, which is what every other FUNCTION
        // analyzer (constant propagation, the decompiler switch analyzer, the address-table
        // analyzer) subscribes to. Ghidra raises it from the program change event a created
        // function produces — `handleFunctionAddedOrBodyChanged` → `functionDefined`
        // (AutoAnalysisManager.java:392-395). **Only functions this call actually created**:
        // re-announcing an existing entry re-triggers every FUNCTION analyzer, whose follow-on
        // work re-enters this one, and the worklist never reaches a fixpoint.
        if !created.is_empty() {
            sched.function_defined(&created);
        }
        true
    }
}

/// Compute each function's body (Ghidra `Function.getBody`): the address set of code
/// units reachable from the entry by intra-function flow (fall-through + branch targets,
/// not calls), not crossing into another function's entry. Run after disassembly.
/// Thunk resolution (`CreateFunctionCmd.fixupFunctionBody`'s `resolveThunk`, :667) is interleaved
/// here: bodies are walked, thunks are resolved against them, and if that created any function the
/// walk repeats so the thunk's body stops at its new target and the target gets a body of its own.
/// The repeat runs at most once per newly-created generation and terminates because each round
/// strictly grows a bounded function set; after the first call every thunk is already resolved, so
/// later calls do a single walk. See `thunk.rs` for why the veto inside must read non-thunk bodies.
pub fn compute_function_bodies(spec: &Spec, ctx: &[u32], program: &mut Program) {
    loop {
        walk_function_bodies(spec, ctx, program);
        if thunk::resolve_thunks(program, spec, ctx).is_empty() {
            return;
        }
    }
}

/// One body-computation pass — the walk itself, with the function set held fixed.
fn walk_function_bodies(spec: &Spec, ctx: &[u32], program: &mut Program) {
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
            let falls = falls_through(program, Address::new(ram, a), &insn, ram);
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

thread_local! {
    /// `(function count, code-unit count)` at the last body refresh; `None` = "no refresh yet
    /// this run".
    static BODIES_FRESH_AT: std::cell::Cell<Option<(usize, usize)>> =
        const { std::cell::Cell::new(None) };
}

/// Reset the per-run body-refresh memo. Called once per analysis run, so a fresh program never
/// inherits the previous program's state (the harness analyses many programs per thread).
pub fn reset_body_refresh_memo() {
    BODIES_FRESH_AT.with(|c| c.set(None));
}

/// ⭐ Bring every function's body up to date before asking a **body question** —
/// `getFunctionContaining`, `getFunctionsOverlapping`, or "subtract the function bodies from this
/// set".
///
/// **Why this exists.** In Ghidra a function's body is computed when the function is created and
/// maintained as code units appear, so it is *always current*; mosura computes bodies once, after
/// the whole worklist has converged (`analyze` -> [`compute_function_bodies`]), so during analysis
/// every body is EMPTY. Every ported body query therefore silently answers "nothing" unless the
/// bodies are brought up to date first. This call is that bookkeeping — it restores what Ghidra's
/// incremental maintenance guarantees, rather than adding a condition Ghidra does not have.
///
/// Three callers, and they are why the memo key is what it is:
///
///  - `FunctionStartAction.applyActionToSet` (:302) and `PossibleDelayedFunctionCreator` (:1007)
///    refuse a pattern-proposed start that lands *inside* an existing function. Measured: on
///    `fnpattern.watcom-x86-32` Ghidra refuses `lead_fn_+5`, `trail_fn_+5` and `main_+5`; mosura
///    created all four before this existed.
///  - [`ConstantPropagationAnalyzer`], whose `findLocationsRemoveFunctionBodies` pass 1
///    (ConstantPropagationAnalyzer.java:259-268) **subtracts the bodies** from its added set. On
///    the INSTRUCTION channel that set is a decoded EXTENT, so with empty bodies the subtraction
///    removes only the single entry-point address and pass 3 (:296-303) then starts constant
///    propagation at `entry + 1` — an offcut address inside the first instruction of every
///    function. On the FUNCTION channel the set was entry points only, so passes 2 and 3 were
///    inert and this never showed.
///  - [`switch::DecompilerSwitchAnalyzer`], whose `findFunctions`
///    (DecompilerSwitchAnalyzer.java:184) maps each candidate location through
///    `getFunctionContaining`.
///
/// **Memoized on `(function count, code-unit count)`.** [`compute_function_bodies`] re-walks and
/// re-decodes every function, so it is O(all code); this sits at the top of an `added()` that can
/// run several times per program. Both halves of the key are load-bearing: a body grows when a
/// function is created *and* when code is laid down inside an existing one (the disassembler's
/// walk lays down code without creating any function, and nothing recomputes bodies afterwards),
/// so keying on the function count alone leaves a body stale exactly when new code was decoded —
/// which is the case the constant propagator's channel now depends on. The marker is thread-local,
/// the correct granularity: the test harness analyses different programs on different threads.
pub fn refresh_function_bodies(program: &mut Program) {
    let key = (program.function_manager.function_count(), program.listing.len());
    if BODIES_FRESH_AT.with(|c| c.get()) == Some(key) {
        return;
    }
    if let Some((spec, ctx)) = crate::lang::load_cached(&program.language_id) {
        compute_function_bodies(spec, ctx, program);
    }
    // Re-read: computing bodies defines no code units and creates no function, but reading the
    // key back keeps the memo honest if that ever changes.
    let key = (program.function_manager.function_count(), program.listing.len());
    BODIES_FRESH_AT.with(|c| c.set(Some(key)));
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
/// (`analyze` -> `compute_function_bodies`; see [`refresh_function_bodies`]), so during analysis
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
    spec: &'static Spec,
    ctx: &'static [u32],
    ram: SpaceId,
}

impl ConstantPropagationAnalyzer {
    pub fn for_program(program: &Program) -> Option<ConstantPropagationAnalyzer> {
        let (spec, ctx) = crate::lang::load_cached(&program.language_id)?;
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
                crate::analysis::symbolic::flow_constants(self.spec, self.ctx, program, loc, &entries);
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
        if crate::lang::load_cached("x86:LE:64:default").is_none() {
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

    /// ⭐ THE THIRD BOUND — `Disassembler.MAX_REPEAT_PATTERN_LENGTH` (:82, checked at :1067).
    /// A run of identical filler bytes decodes perfectly well as instructions, so nothing about
    /// the decode ends the walk; Ghidra counts consecutive same-repeated-byte instructions and
    /// terminates the block once the run exceeds 16.
    ///
    /// **This is the ninth over-decode cluster of `docs/function-discovery-backlog.md` §9** — the
    /// one deliberately left unexplained because it is not the inline-parameter thunk. Measured on
    /// the war2 MZ stub against the committed Ghidra golden: 50 bytes of `00` at `00018f00`, both
    /// listings start the run at `00018f04`, Ghidra keeps through `00018f24` and stops, mosura ran
    /// on through `00018f32` and into the next function at `00018f34`. 17 instructions, not 16 —
    /// the tripping instruction is still added (`processInstruction`, :1254) and only its
    /// fall-through is abandoned.
    ///
    /// Synthetic rather than the survey binary, and x86-64 rather than 16-bit, because the
    /// mechanism is architecture-independent: `00 00` is a two-byte instruction that falls through
    /// on both.
    #[test]
    fn walk_stops_after_a_run_of_repeated_byte_instructions() {
        if crate::lang::load_cached("x86:LE:64:default").is_none() {
            return;
        }
        // `xor eax,eax` then 40 bytes of 0x00 — `00 00` is `ADD byte ptr [RAX],AL`, 2 bytes,
        // falling through, so without the bound the walk consumes all 20 of them.
        let mut bytes = vec![0x31, 0xc0];
        bytes.extend(std::iter::repeat_n(0u8, 40));
        let mut p = program_with(bytes, true, true);
        let ram = p.default_space;
        run_disassembler(&mut p, 0x40_1000);

        let starts: Vec<u64> = p
            .listing
            .code_units()
            .filter(|(a, u)| a.space == ram && matches!(u, CodeUnit::Instruction { .. }))
            .map(|(a, _)| a.offset)
            .filter(|&o| o >= 0x40_1002)
            .collect();
        let mut starts = starts;
        starts.sort_unstable();

        // The run begins at 0x401002; a limit of 16 admits 17 instructions, the last at
        // 0x401002 + 16*2 = 0x401022, and 0x401024 must not be decoded.
        assert_eq!(
            starts.len(),
            17,
            "expected 17 filler instructions (limit 16 + the tripping one), got {starts:08x?}"
        );
        assert_eq!(*starts.last().unwrap(), 0x40_1022, "last kept instruction");
        assert!(
            p.listing.code_unit_at(Address::new(ram, 0x40_1024)).is_none(),
            "the walk ran past the repeated-byte limit"
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
        if crate::lang::load_cached("x86:LE:64:default").is_none() {
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
        if crate::lang::load_cached("x86:LE:64:default").is_none() {
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

    /// ⭐ **THE CHANNEL GATE (task #7).** `ConstantPropagationAnalyzer` is an
    /// `INSTRUCTION_ANALYZER` (ConstantPropagationAnalyzer.java:117): its added set is a decoded
    /// EXTENT, and `findLocationsRemoveFunctionBodies` (:248) derives the start locations from it
    /// — function entries first (:259-264), then call destinations (:271-293), then **the minimum
    /// of every range that is left** (:296-303). That last pass is the only route by which
    /// constant propagation reaches code that is decoded and belongs to NO function, which is
    /// precisely what `AddressTableAnalyzer` produces (it disassembles a pointer table's targets
    /// and creates no function at them, AddressTableAnalyzer.java:282).
    ///
    /// On the `Function` channel the added set was function entry points, so pass 1 consumed it
    /// whole and passes 2 and 3 were structurally unreachable — code in no function was never
    /// propagated through.
    ///
    /// **Both halves of the fix are measured here, and the second is why they cannot be
    /// separated.** Pass 1 SUBTRACTS each overlapping function's BODY (:264-268). mosura's bodies
    /// are empty during analysis, so without [`refresh_function_bodies`] the subtraction removes
    /// only the single entry-point ADDRESS: the whole extent minus `{0x401000}` stays ONE range,
    /// its minimum is `0x401001` — an OFFCUT address inside the first instruction — and that
    /// becomes the only pass-3 location. The orphan at `0x401008` is never reached, and constant
    /// propagation runs over a garbage decode instead. Hence the two assertions: the orphan's
    /// reference must appear, and no reference may originate from an address that is not an
    /// instruction start.
    ///
    /// Layout — `f` is a function, the code at `0x401008` is decoded but in no function:
    /// ```text
    /// 0x401000  48 8b 05 f9 0f 00 00   mov rax,[rip+0xff9]   -> READ 0x402000   } f's body
    /// 0x401007  c3                     ret                                      }
    /// 0x401008  48 8b 0d 01 10 00 00   mov rcx,[rip+0x1001]  -> READ 0x402010   } no function
    /// 0x40100f  c3                     ret                                      }
    /// ```
    /// Decoding the offcut `0x401001` yields `8b 05 f9 0f 00 00` (`mov eax,[rip+0xff9]`), whose
    /// rip-relative base lands on the same `0x401007`, so the broken path produces a READ to
    /// `0x402000` **from `0x401001`** and stops at the `ret` — which is exactly what the second
    /// assertion names.
    #[test]
    #[ignore = "RED until the analyzer channel is fixed (task #7) — see the note above"]
    fn constant_propagation_reaches_decoded_code_that_is_in_no_function() {
        if crate::lang::load_cached("x86:LE:64:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        super::reset_body_refresh_memo(); // thread-local, and tests share threads
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
        let base = Address::new(ram, 0x40_1000);
        let mut p = Program::new(spaces, ram, "x86:LE:64:default", "gcc", base, false, 64);
        let mut img = vec![0u8; 0x2000];
        img[..0x10].copy_from_slice(&[
            0x48, 0x8b, 0x05, 0xf9, 0x0f, 0x00, 0x00, // mov rax,[rip+0xff9] -> 0x402000
            0xc3, // ret
            0x48, 0x8b, 0x0d, 0x01, 0x10, 0x00, 0x00, // mov rcx,[rip+0x1001] -> 0x402010
            0xc3, // ret
        ]);
        p.memory.add_block(".text", base, 0x2000, true, false, true, Some(img));
        p.function_manager.create_function(base, "f", AddressSet::new());

        // Decode both — the function by its own seed, the orphan the way `AddressTableAnalyzer`
        // reaches a pointer target: a disassembly seed with no function created at it.
        let d = Disassembler::for_program(&p).unwrap();
        let mut seeds = AddressSet::new();
        seeds.add_range(ram, 0x40_1000, 0x40_1000);
        seeds.add_range(ram, 0x40_1008, 0x40_1008);
        let mut sched = Scheduling::default();
        d.added(&mut p, &seeds, &mut sched);
        assert!(
            p.listing.code_unit_at(Address::new(ram, 0x40_1008)).is_some(),
            "the orphan must be decoded for this fixture to measure anything"
        );

        // The decoded EXTENT, as `codeDefined` carries it — one contiguous range.
        let mut extent = AddressSet::new();
        extent.add_range(ram, 0x40_1000, 0x40_100f);
        assert_eq!(extent.ranges().count(), 1, "one range is what makes the entry+1 minimum bite");

        let cp = ConstantPropagationAnalyzer::for_program(&p).unwrap();
        cp.added(&mut p, &extent, &mut Scheduling::default());

        let reads: Vec<u64> = p
            .reference_manager
            .references()
            .filter(|r| r.ref_type == RefType::Read)
            .map(|r| r.to.offset)
            .collect();
        assert!(
            reads.contains(&0x40_2010),
            "no READ reference to 0x402010: constant propagation never started at 0x401008, the \
             code that is decoded and inside no function. That is pass 3 of \
             findLocationsRemoveFunctionBodies (:296-303), and it is reachable only when the added \
             set is a decoded extent. Got {reads:x?}"
        );

        let offcut: Vec<u64> = p
            .reference_manager
            .references()
            .map(|r| r.from.offset)
            .filter(|&a| p.listing.code_unit_at(Address::new(ram, a)).is_none())
            .collect();
        assert!(
            offcut.is_empty(),
            "reference(s) made from {offcut:x?}, which is not an instruction start: pass 1 removed \
             only the entry-point ADDRESS instead of the function's BODY, so the range minimum \
             pass 3 picked was 0x401001 — inside the first instruction. Bodies must be current \
             before a body query (`refresh_function_bodies`)"
        );
    }
}

#[cfg(test)]
mod flow_override_tests {
    use super::*;
    use crate::analysis::flowtype::FlowOverride;
    use crate::decompile::space::{SpaceKind, SpaceManager};

    /// `call 0x401010` at `0x401000`, then a `nop`.
    fn program_with_a_call() -> (Program, Address) {
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
        let base = Address::new(ram, 0x40_1000);
        let mut p = Program::new(spaces, ram, "x86:LE:64:default", "gcc", base, false, 64);
        let mut img = vec![0x90u8; 0x100];
        img[..5].copy_from_slice(&[0xe8, 0x0b, 0x00, 0x00, 0x00]); // call 0x401010
        p.memory.add_block(".text", base, 0x100, true, false, true, Some(img));
        (p, base)
    }

    /// ⭐ THE MECHANISM STEP 2 DEPENDS ON. Ghidra decides fall-through on `getFlowType()`
    /// (InstructionDB.java:926 -> :321), which is the prototype's flow type with the
    /// instruction's FLOW OVERRIDE applied — so `FlowOverride::CallReturn` on a `call` makes it
    /// a `CALL_TERMINATOR`, which has no fall-through. That is how
    /// `FindNoReturnFunctionsAnalyzer.setNoFallThru` (:218) stops the decode after a call to a
    /// non-returning function; it sets no "fall-through override" at all.
    ///
    /// ⚠️ **This is the only thing that can fail about the flow-override model right now, and it
    /// is why the test exists.** Measured across the whole Watcom ground-truth corpus, exactly 2
    /// overrides are set (both on `tailjmp`, both on `JMP`) and **zero** of them change a
    /// fall-through answer — a `JMP` has none either way. The one live setter,
    /// `SharedReturnAnalyzer`, only ever overrides jumps. Until an analyzer overrides a CALL the
    /// model is inert on every available binary, so a corpus gate would measure nothing.
    #[test]
    fn a_call_return_override_stops_a_call_falling_through() {
        let Some((spec, ctx)) = crate::lang::load_cached("x86:LE:64:default") else {
            return; // SLEIGH tables unavailable
        };
        let (mut p, at) = program_with_a_call();
        let ram = p.default_space;
        let window = p.memory.read_window(at, 16);
        let insn = spec.disassemble_ctx(&window, at.offset, ctx).into_iter().next().unwrap();
        assert_eq!(insn.bytes.len(), 5, "expected a 5-byte call, got {}", insn.mnemonic);

        assert!(
            falls_through(&p, at, &insn, ram),
            "a plain call falls through — without this the override below proves nothing"
        );

        assert!(p.set_flow_override(at, FlowOverride::CallReturn), "override newly set");
        assert!(
            !falls_through(&p, at, &insn, ram),
            "CALL_RETURN makes the flow CALL_TERMINATOR, which has no fall-through — \
             falls_through re-derived the answer from the opcode and ignored the override"
        );

        // `InstructionDB.setFlowOverride` :622 — setting the same override again is a no-op,
        // which is what `processFunctionJumpReferences`'s "already overridden" guard (:417)
        // reads.
        assert!(!p.set_flow_override(at, FlowOverride::CallReturn), "re-setting reports no change");
        assert!(p.set_flow_override(at, FlowOverride::None), "clearing reports a change");
        assert!(falls_through(&p, at, &insn, ram), "cleared override restores fall-through");
    }

    /// The guard's other half: an override on an instruction that already has NO fall-through
    /// must not invent one, and `CALL_RETURN` on a plain `jmp` keeps it non-falling. This is the
    /// only case `SharedReturnAnalyzer` actually produces today (2 instances corpus-wide), and it
    /// is why that analyzer's change is invisible in the listing.
    #[test]
    fn a_call_return_override_on_a_jump_changes_no_fall_through() {
        let Some((spec, ctx)) = crate::lang::load_cached("x86:LE:64:default") else {
            return;
        };
        let (mut p, at) = program_with_a_call();
        let ram = p.default_space;
        // Overwrite the call with `jmp 0x401010` (e9 rel32) — same length, no fall-through.
        p.memory = {
            let mut spaces = SpaceManager::standard();
            let r2 = spaces.add("ram", SpaceKind::Processor, 8, 1);
            assert_eq!(r2, ram);
            let mut m = crate::analysis::program::Memory::new();
            let mut img = vec![0x90u8; 0x100];
            img[..5].copy_from_slice(&[0xe9, 0x0b, 0x00, 0x00, 0x00]);
            m.add_block(".text", at, 0x100, true, false, true, Some(img));
            m
        };
        let window = p.memory.read_window(at, 16);
        let insn = spec.disassemble_ctx(&window, at.offset, ctx).into_iter().next().unwrap();

        assert!(!falls_through(&p, at, &insn, ram), "a plain jmp does not fall through");
        p.set_flow_override(at, FlowOverride::CallReturn);
        assert!(!falls_through(&p, at, &insn, ram), "and still does not with the override");
    }
}

#[cfg(test)]
mod thunk_resolution_tests {
    use super::*;
    use crate::analysis::manager::Scheduling;
    use crate::decompile::space::{SpaceKind, SpaceManager};

    /// ⭐ **THE THUNK GATE.** Ghidra creates a function at the target of a function whose entry
    /// is a lone unconditional jump, and it does so **before** that function's body is ever
    /// computed:
    ///
    /// - `CreateFunctionCmd.createFunction` (CreateFunctionCmd.java:365) — *"check for a thunk
    ///   first"* → `resolveThunk(entry, body, monitor)`, called before `listing.createFunction`.
    /// - `CreateFunctionCmd.fixupFunctionBody` (:667) runs the same check on every body
    ///   recomputation — *"function could now be a thunk, since someone is calling this because
    ///   of a potential body flow change"* — again before `func.setBody`.
    /// - `resolveThunk` → `CreateThunkFunctionCmd.getThunkedAddr` (CreateThunkFunctionCmd.java:548)
    ///   → `getSimpleFlow` (:815): a non-conditional jump (or terminal call) with exactly one
    ///   non-indirect flow returns that flow as the thunked address.
    /// - `CreateThunkFunctionCmd.getReferencedFunction` (:360-375): with no function AT and no
    ///   function CONTAINING the thunked address, it runs
    ///   **`new CreateFunctionCmd(referencedFunctionAddr).applyTo(program)`** — that call is what
    ///   creates the function.
    ///
    /// mosura has no thunk model at all (`function_start.rs:766` says so outright), so
    /// [`compute_function_bodies`] follows the `jmp` and the target is **swallowed into the
    /// jumping function's body**; the overlap refusal then declines a function there forever.
    ///
    /// **The fixture is WAR2's own `_cstart_` shape, reduced.** WAR2.EXE's entry `0x601f8` is
    /// `EB 76` — a short jump over the inline Watcom copyright banner
    /// (`analysis/loader/watcom.rs:5`) — and `0x601f8 + 2 + 0x76 = 0x60270` exactly. Ghidra
    /// creates `FUN_00060270`; mosura does not. Because the whole span between the two is a
    /// *string*, no function entry lies in it, so `SharedReturnAnalysisCmd`'s
    /// `assumeContiguousFunctions` forward arm (`destAddr >= functionAfterSrc`) cannot fire for
    /// it in Ghidra either — thunk resolution is the only mechanism that reaches it.
    ///
    /// ```text
    /// 0x401000  eb 06                  jmp 0x401008     } the thunk entry, its whole body
    /// 0x401002  'B' 'A' 'N' 'N' 00 00                   } inline banner, never decoded
    /// 0x401008  31 c0                  xor eax,eax      } the thunked function
    /// 0x40100a  c3                     ret              }
    /// ```
    ///
    /// Only `0x401000` is created as a function, exactly as a loader marks an entry point.
    #[test]
    fn a_jump_only_entry_creates_a_function_at_its_thunked_address() {
        let Some((spec, ctx)) = crate::lang::load_cached("x86:LE:32:default") else {
            return; // SLEIGH tables unavailable
        };
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 4, 1);
        let base = Address::new(ram, 0x40_1000);
        let mut p = Program::new(spaces, ram, "x86:LE:32:default", "gcc", base, false, 32);
        let mut img = vec![0u8; 0x1000];
        img[..0x0b].copy_from_slice(&[
            0xeb, 0x06, // jmp 0x401008
            b'B', b'A', b'N', b'N', 0x00, 0x00, // inline banner (data, never decoded)
            0x31, 0xc0, // xor eax,eax
            0xc3, // ret
        ]);
        p.memory.add_block(".text", base, 0x1000, true, false, true, Some(img));
        p.function_manager.create_function(base, "entry", AddressSet::new());

        let d = Disassembler::for_program(&p).unwrap();
        let mut seeds = AddressSet::new();
        seeds.add_range(ram, 0x40_1000, 0x40_1000);
        d.added(&mut p, &seeds, &mut Scheduling::default());
        let target = Address::new(ram, 0x40_1008);
        assert!(
            p.listing.code_unit_at(target).is_some(),
            "the jump target must be decoded for this fixture to measure anything"
        );

        compute_function_bodies(spec, ctx, &mut p);

        assert!(
            p.function_manager.function_at(target).is_some(),
            "no function at the thunked address 0x401008: the entry at 0x401000 is a lone \
             unconditional jump, so Ghidra's CreateFunctionCmd.resolveThunk creates a function \
             at its target before any body walk runs. Functions: {:x?}",
            p.function_manager.functions().map(|f| f.entry_point().offset).collect::<Vec<_>>()
        );
        // ⭐ Ghidra's MEASURED shape, not merely "the target is elsewhere": the oracle reports
        // WAR2's `fn@0x601f8` with `isThunk = true` and `body = [[000601f8, 000601f9]]` — two
        // bytes, just the `EB 76`. The committed MZ golden says the same for its own thunks
        // (`goldens/analysis/war2.snapshot`: `fnbody 00017c4c 00017c4c:00017c4e`). Reproducing
        // that shape is why no thunk *relationship* needs modelling: once the target is a
        // function, the body walk stops at it and the minimal body falls out.
        let thunk_body = p.function_manager.function_at(base).unwrap().body().clone();
        let ranges: Vec<(u64, u64)> = thunk_body.ranges().map(|r| (r.min, r.max)).collect();
        assert_eq!(
            ranges,
            vec![(0x40_1000, 0x40_1001)],
            "the thunk's body must be exactly its own 2-byte jmp; it swallowed its target instead"
        );
    }

    /// ⭐ **THE GUARD'S FALSIFIER.** `CreateThunkFunctionCmd.getReferencedFunction` declines when
    /// `getFunctionContaining(thunkedAddr)` is non-null (CreateThunkFunctionCmd.java:360-364) — it
    /// refuses to mint a function in the middle of real code. That veto is only a guard if it can
    /// fire, and in mosura it very nearly could not: run thunk resolution before the body walk and
    /// every body is EMPTY, so the query can only answer `None` and the veto silently permits
    /// (measured in-pipeline: `bodies non-empty: 0 of 157`). This test is what that arm has to
    /// fail against.
    ///
    /// ```text
    /// 0x401000  31 c0        xor eax,eax   } function A — a REAL function, not a thunk
    /// 0x401002  eb 02        jmp 0x401006  }   (its first instruction is not a jump)
    /// 0x401004  90 90                      }   skipped by the jump
    /// 0x401006  c3           ret           } still A's body, reached by A's own jump
    /// 0x401010  e9 f1 ff ff ff  jmp 0x401006  } function T — a thunk INTO A's body
    /// ```
    ///
    /// `0x401006` belongs to A, so Ghidra creates nothing there and T stays unresolved. The
    /// sibling-thunk carve-out must not reach this case: A is not a thunk, so its body counts.
    #[test]
    fn a_thunk_into_a_real_functions_body_creates_nothing() {
        let Some((spec, ctx)) = crate::lang::load_cached("x86:LE:32:default") else {
            return; // SLEIGH tables unavailable
        };
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 4, 1);
        let base = Address::new(ram, 0x40_1000);
        let mut p = Program::new(spaces, ram, "x86:LE:32:default", "gcc", base, false, 32);
        let mut img = vec![0u8; 0x1000];
        img[..0x07].copy_from_slice(&[
            0x31, 0xc0, // xor eax,eax
            0xeb, 0x02, // jmp 0x401006
            0x90, 0x90, // skipped
            0xc3, // ret
        ]);
        // 0x401010: e9 rel32 -> 0x401006 (next = 0x401015, so rel32 = -0xf)
        img[0x10..0x15].copy_from_slice(&[0xe9, 0xf1, 0xff, 0xff, 0xff]);
        p.memory.add_block(".text", base, 0x1000, true, false, true, Some(img));
        p.function_manager.create_function(base, "A", AddressSet::new());
        let thunk = Address::new(ram, 0x40_1010);
        p.function_manager.create_function(thunk, "T", AddressSet::new());

        let d = Disassembler::for_program(&p).unwrap();
        let mut seeds = AddressSet::new();
        seeds.add_range(ram, 0x40_1000, 0x40_1000);
        seeds.add_range(ram, 0x40_1010, 0x40_1010);
        d.added(&mut p, &seeds, &mut Scheduling::default());

        compute_function_bodies(spec, ctx, &mut p);

        let target = Address::new(ram, 0x40_1006);
        assert!(
            p.function_manager.function_at(base).unwrap().body().contains(target),
            "the fixture is wrong unless 0x401006 is genuinely inside A's body"
        );
        assert!(
            p.function_manager.function_at(target).is_none(),
            "0x401006 belongs to the real function at 0x401000, so getFunctionContaining vetoes \
             the thunk at 0x401010 and Ghidra creates nothing there. Functions: {:x?}",
            p.function_manager.functions().map(|f| f.entry_point().offset).collect::<Vec<_>>()
        );
    }

    /// The INSTRUMENT's gate (task #4): [`thunk::report`] must name the arm that decided each
    /// entry, and its raw-decode column must see a jump at an entry the *listing* cannot describe.
    ///
    /// This is what makes the WAR2 report readable as evidence rather than as a table. It is
    /// deliberately built on the two arms that decide the interesting WAR2 cases —
    /// `TargetInsideFunctionBody` (the veto) and `NoInstructionAtEntry` (an entry that never
    /// reached the listing) — plus the two jump encodings the crude probe could not both handle:
    /// `eb` (2-byte) and `e9` (5-byte). SLEIGH decodes both, so `raw_uncond_jump_target` is
    /// encoding-blind by construction.
    ///
    /// ```text
    /// 0x401000  31 c0           xor eax,eax     } A, a real function (entry is not a jump)
    /// 0x401002  eb 02           jmp 0x401006    }
    /// 0x401006  c3              ret             } still A's body
    /// 0x401010  e9 f1 ff ff ff  jmp 0x401006    } T, a thunk INTO A's body -> vetoed
    /// 0x401020  eb 02           jmp 0x401024    } U, never seeded: not in the listing
    /// ```
    #[test]
    fn the_report_names_the_arm_that_decided_each_entry() {
        let Some((spec, ctx)) = crate::lang::load_cached("x86:LE:32:default") else {
            return; // SLEIGH tables unavailable
        };
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 4, 1);
        let base = Address::new(ram, 0x40_1000);
        let mut p = Program::new(spaces, ram, "x86:LE:32:default", "gcc", base, false, 32);
        let mut img = vec![0u8; 0x1000];
        img[..0x07].copy_from_slice(&[0x31, 0xc0, 0xeb, 0x02, 0x90, 0x90, 0xc3]);
        img[0x10..0x15].copy_from_slice(&[0xe9, 0xf1, 0xff, 0xff, 0xff]); // -> 0x401006
        img[0x20..0x22].copy_from_slice(&[0xeb, 0x02]); // -> 0x401024, never disassembled
        p.memory.add_block(".text", base, 0x1000, true, false, true, Some(img));
        for (off, name) in [(0x40_1000u64, "A"), (0x40_1010, "T"), (0x40_1020, "U")] {
            p.function_manager.create_function(Address::new(ram, off), name, AddressSet::new());
        }
        let d = Disassembler::for_program(&p).unwrap();
        let mut seeds = AddressSet::new();
        seeds.add_range(ram, 0x40_1000, 0x40_1000);
        seeds.add_range(ram, 0x40_1010, 0x40_1010);
        d.added(&mut p, &seeds, &mut Scheduling::default()); // U is deliberately NOT seeded
        compute_function_bodies(spec, ctx, &mut p);

        let report = thunk::report(&p, spec, ctx);
        let at = |off: u64| report.iter().find(|c| c.entry.offset == off).expect("entry in report");

        // A: real code at the entry — the ordinary decline, and no raw jump.
        assert_eq!(at(0x40_1000).outcome, thunk::Outcome::FlowNotJumpOrTerminalCall);
        assert_eq!(at(0x40_1000).raw_uncond_jump_target, None);
        // T: `e9 rel32` resolves, and the veto names the function that owns the target.
        assert_eq!(at(0x40_1010).raw_uncond_jump_target, Some(0x40_1006));
        assert_eq!(at(0x40_1010).thunked.map(|a| a.offset), Some(0x40_1006));
        assert_eq!(
            at(0x40_1010).outcome,
            thunk::Outcome::TargetInsideFunctionBody(Address::new(ram, 0x40_1000)),
            "the veto must name A as the owner of 0x401006"
        );
        // U: never disassembled, so resolution stops at the first guard — but the raw decode still
        // reports the `eb` jump, which is the whole point of reading memory rather than the
        // listing. A report that only asked the listing would show nothing here.
        assert_eq!(at(0x40_1020).outcome, thunk::Outcome::NoInstructionAtEntry);
        assert_eq!(at(0x40_1020).raw_uncond_jump_target, Some(0x40_1024));
        assert_eq!(at(0x40_1020).thunked, None);
        // Nothing is left to create at the fixpoint — the invariant the WAR2 report rests on.
        assert!(report.iter().all(|c| c.outcome != thunk::Outcome::WouldCreate));
    }
}
