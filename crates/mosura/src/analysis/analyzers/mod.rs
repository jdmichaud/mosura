//! Built-in analyzers (A4+) — the passes that plug into the [`AutoAnalysisManager`].
//!
//! A4 ports the core of Ghidra's disassembly + function discovery: recursive-descent
//! disassembly driving the SLEIGH engine ([`Disassembler`]) and function creation at
//! entry points and call targets ([`FunctionCreator`]).

pub mod switch;

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::manager::Scheduling;
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, CodeUnit, Program, RefType, SymbolType};
use crate::decompile::opcode::OpCode;
use crate::decompile::space::{Address, SpaceId};
use crate::sleigh::engine::Spec;
use crate::sleigh::pcode::PArg;

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
        match op.ins.first() {
            Some(PArg::Var(v)) if v.space == "ram" => Some(v.offset),
            _ => None,
        }
    }
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
        let mut decoded_any = false;
        while let Some(a) = work.pop() {
            let addr = Address::new(ram, a);
            if program.listing.code_unit_at(addr).is_some() {
                continue; // already disassembled
            }
            let window = program.memory.read_window(addr, 16); // max x86-64 instruction length
            let Some(insn) = self.spec.disassemble_ctx(&window, a, &self.ctx).into_iter().next() else {
                continue;
            };
            let ilen = insn.bytes.len() as u64;
            if ilen == 0 {
                continue;
            }
            // Control falls through unless the instruction ends in a return / unconditional
            // branch / indirect jump (Ghidra's flow classification).
            let last = insn.ops.last().and_then(|o| OpCode::from_u32(o.opcode));
            let falls = !matches!(last, Some(OpCode::Return | OpCode::Branch | OpCode::Branchind));
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
            program.listing.define(addr, CodeUnit::Instruction { length: ilen as u32 });
            decoded_any = true;
            if falls {
                work.push(a + ilen);
            }
        }
        if !call_targets.is_empty() {
            sched.function_defined(&call_targets);
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
            let last = insn.ops.last().and_then(|o| OpCode::from_u32(o.opcode));
            let falls = !matches!(last, Some(OpCode::Return | OpCode::Branch | OpCode::Branchind));
            for op in &insn.ops {
                if matches!(OpCode::from_u32(op.opcode), Some(OpCode::Branch | OpCode::Cbranch)) {
                    if let Some(t) = Disassembler::static_target(op).filter(|&t| t != a) {
                        work.push(t);
                    }
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
    fn added(&self, program: &mut Program, set: &AddressSet, _sched: &mut Scheduling) -> bool {
        // Function entries bound each propagation walk to its own function.
        let entries: std::collections::HashSet<u64> = program
            .function_manager
            .functions()
            .filter(|f| f.entry_point().space == self.ram)
            .map(|f| f.entry_point().offset)
            .collect();
        for r in set.ranges() {
            crate::analysis::symbolic::flow_constants(
                &self.spec,
                &self.ctx,
                program,
                Address::new(self.ram, r.min),
                &entries,
            );
        }
        true
    }
}
