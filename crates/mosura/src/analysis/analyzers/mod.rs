//! Built-in analyzers (A4+) — the passes that plug into the [`AutoAnalysisManager`].
//!
//! A4 ports the core of Ghidra's disassembly + function discovery: recursive-descent
//! disassembly driving the SLEIGH engine ([`Disassembler`]) and function creation at
//! entry points and call targets ([`FunctionCreator`]).

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
            // Ghidra `createEntryFunction`: only create a function in executable memory —
            // data entry points (e.g. `__bss_start`) are not functions.
            if !program.memory.block_at(addr).is_some_and(|b| b.is_execute()) {
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
        for r in set.ranges() {
            crate::analysis::symbolic::flow_constants(
                &self.spec,
                &self.ctx,
                program,
                Address::new(self.ram, r.min),
            );
        }
        true
    }
}
