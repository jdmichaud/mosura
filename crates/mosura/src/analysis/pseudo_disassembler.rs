//! `PseudoDisassembler` — a port of Ghidra's
//! `Framework/SoftwareModeling/.../ghidra/app/util/PseudoDisassembler.java`, together with
//! `RepeatInstructionByteTracker.java` from the same package.
//!
//! A *pseudo* disassembler decodes instructions and follows their flow **without committing
//! anything to the program**. It answers one question for the analyzers that speculate about
//! an address: *is there plausible code here?* [`PseudoDisassembler::is_valid_code`] is the
//! guard `AddressTable.getFunctionEntries` (AddressTable.java:785) applies to every entry of
//! a candidate address table before any of that table's targets is disassembled — it is what
//! stops "a data word that looks like an address" from becoming code.
//!
//! Ported here: `checkValidSubroutine` (PseudoDisassembler.java:650), `checkPseudoBody`
//! (:953), `getNextTarget` (:553), `checkNonReturning` (:909), `isReallyReturn` (:943), and
//! the `isValidCode` entry point (:372).
//!
//! **Not ported, and why.** (a) The `PseudoDisassemblerContext` flows a context-register value
//! along each edge; mosura's SLEIGH driver takes one fixed context vector, the same
//! accommodation `analyzers::compute_function_bodies` already makes, and x86 has no
//! flow-sensitive context register. (b) Delay slots (:736-755) — x86 has none and mosura's
//! `sleigh::Instruction` carries no delay-slot depth. (c) The `EXTERNAL` uninitialized-block
//! escape at :706-716 is ported; the `getReferencedFunction` arm of `checkNonReturning`
//! (:921-933, an indirect call through a pointer slot to a no-return function) is not — it can
//! only make `is_valid_code` *stricter*, never laxer, so its absence cannot over-create.

use crate::analysis::flowtype::{flow_props, FlowProps};
use crate::analysis::program::{AddressSet, Program, SymbolType};
use crate::decompile::opcode::OpCode;
use crate::decompile::space::{Address, SpaceId};
use crate::sleigh::engine::Spec;
use crate::sleigh::pcode::PArg;
use crate::sleigh::Instruction;

/// `PseudoDisassembler.DEFAULT_MAX_INSTRUCTIONS` (:56).
const DEFAULT_MAX_INSTRUCTIONS: usize = 4000;

/// `PseudoDisassembler.MAX_REPEAT_BYTES_LIMIT` (:68) — "only let 4 consecutive instructions
/// with the same repeated bytes".
const MAX_REPEAT_BYTES_LIMIT: i32 = 4;

/// Longest x86-64 instruction — the decode window and the `getCodeUnitContaining` back-probe.
const MAX_INSN_LEN: u64 = 16;

/// `RepeatInstructionByteTracker` (RepeatInstructionByteTracker.java:25-84) — trips when more
/// than `limit` consecutive instructions each consist of a single repeated byte value, and it
/// is the *same* value throughout (a run of `00 00 …` or `ff ff …` decoded as instructions).
struct RepeatInstructionByteTracker {
    limit: i32,
    count: i32,
    value: u8,
}

impl RepeatInstructionByteTracker {
    fn new(limit: i32) -> RepeatInstructionByteTracker {
        RepeatInstructionByteTracker { limit, count: 0, value: 0 }
    }

    fn reset(&mut self) {
        self.count = 0;
    }

    /// `PseudoInstruction.getRepeatedByte` (PseudoInstruction.java:149): the byte value
    /// repeated across every byte of the instruction, or `None` if they vary.
    fn repeated_byte(insn: &Instruction) -> Option<u8> {
        let b0 = *insn.bytes.first()?;
        if insn.bytes.len() == 1 || insn.bytes.iter().all(|&b| b == b0) {
            Some(b0)
        } else {
            None
        }
    }

    fn exceeds_repeat_byte_pattern(&mut self, insn: &Instruction) -> bool {
        if self.limit <= 0 {
            return false;
        }
        match RepeatInstructionByteTracker::repeated_byte(insn) {
            None => self.count = 0,
            Some(b) if self.value == b => {
                self.count += 1;
                if self.count > self.limit {
                    self.count = 0;
                    return true;
                }
            }
            Some(b) => {
                self.value = b;
                self.count = 1;
            }
        }
        false
    }
}

/// Ghidra `PseudoDisassembler`, bound to one program's language tables.
pub struct PseudoDisassembler {
    spec: Spec,
    ctx: Vec<u32>,
    ram: SpaceId,
    /// `setRespectExecuteFlag` (:113). Ghidra's field default is `false`; every caller in the
    /// address-table path leaves it at the default, so the execute-set checks at :851 and :962
    /// are inert there. Kept as a field so the flag, and the code it gates, stay visible.
    respect_execute_flag: bool,
    /// `setMaxInstructions` (:96).
    max_instructions: usize,
}

impl PseudoDisassembler {
    /// Build the pseudo-disassembler, or `None` if the SLEIGH tables for the program's
    /// language are unavailable.
    pub fn for_program(program: &Program) -> Option<PseudoDisassembler> {
        let (spec, ctx) = crate::lang::load(&program.language_id)?;
        Some(PseudoDisassembler {
            spec,
            ctx,
            ram: program.default_space,
            respect_execute_flag: false,
            max_instructions: DEFAULT_MAX_INSTRUCTIONS,
        })
    }

    pub fn set_respect_execute_flag(&mut self, respect: bool) {
        self.respect_execute_flag = respect;
    }

    /// Decode one instruction without committing it (`PseudoDisassembler.disassemble`, :146).
    fn disassemble(&self, program: &Program, addr: Address) -> Option<Instruction> {
        let window = program.memory.read_window(addr, MAX_INSN_LEN as usize);
        let insn = self.spec.disassemble_ctx(&window, addr.offset, &self.ctx).into_iter().next()?;
        if insn.bytes.is_empty() {
            return None;
        }
        Some(insn)
    }

    /// `isValidCode(entryPoint)` (:372) — "check that this entry point leads to valid code:
    /// may have multiple entries into the body; the intent is that it be valid code, not nice
    /// code; hit no bad instructions". `checkValidSubroutine(entryPoint, true, false)`.
    pub fn is_valid_code(&self, program: &Program, entry_point: Address) -> bool {
        self.check_valid_subroutine(program, entry_point, true, false)
    }

    /// `checkValidSubroutine(entryPoint, procContext, allowExistingInstructions, mustTerminate,
    /// requireContiguous=false)` (:650).
    fn check_valid_subroutine(
        &self,
        program: &Program,
        entry_point: Address,
        allow_existing_instructions: bool,
        must_terminate: bool,
    ) -> bool {
        // `if (!entryPoint.isMemoryAddress()) return false;`
        if !program.memory.contains(entry_point) {
            return false;
        }
        let mut body = AddressSet::new();
        let mut instr_starts = AddressSet::new();
        let exec_set = execute_set(program);

        let mut target = Some(entry_point);

        let mut target_list: Vec<Address> = Vec::new();
        let mut untried_target_list: Vec<Address> = Vec::new();
        let mut did_terminate = false;
        let mut did_call_valid_subroutine = false;

        // ":673 — if entry point starts with 00 byte instruction, assume not valid"
        // (`memory.getLong(entryPoint) == 0`; a short read is the MemoryAccessException arm).
        let head = program.memory.read_window(entry_point, 8);
        if head.len() < 8 || head.iter().all(|&b| b == 0) {
            return false;
        }

        let mut repeat_tracker = RepeatInstructionByteTracker::new(MAX_REPEAT_BYTES_LIMIT);

        for _ in 0..self.max_instructions {
            let Some(t) = target else { break };

            let Some(insn) = self.disassemble(program, t) else {
                // ":706 — if the target is in the external section, which is uninitialized,
                // ignore it! it is probably a JUMP to an external function."
                let block = program.memory.block_at(t);
                match block {
                    Some(b) if !b.is_initialized() && b.name() == "EXTERNAL" => {}
                    _ => return false,
                }
                target_list.retain(|a| *a != t);
                target = next_target(&body, &mut untried_target_list);
                repeat_tracker.reset();
                continue;
            };

            // ":726 — check if we are getting into bad instruction runs"
            if repeat_tracker.exceeds_repeat_byte_pattern(&insn) {
                return false;
            }

            let ilen = insn.bytes.len() as u64;
            let max_addr = Address::new(self.ram, t.offset + ilen - 1);
            let next_addr = Address::new(self.ram, t.offset + ilen);
            body.add_range(self.ram, t.offset, max_addr.offset);
            instr_starts.add(t);

            let flow = flow_props(&insn.ops, t.offset, next_addr.offset);
            let flows = static_flows(&insn, self.ram);

            // ":757 — if (flowType.isTerminal()) didTerminate |= isReallyReturn(instr);"
            if flow.terminal {
                did_terminate |= is_really_return(&insn);
            }

            let mut new_target: Option<Address> = None;
            let mut fall_thru: Option<Address> = None;
            if flow.fallthrough {
                // ":765 — a call to a no-return function does not fall through."
                if check_non_returning(program, flow, &flows) {
                    target = next_target(&body, &mut untried_target_list);
                    repeat_tracker.reset();
                    continue;
                }
                new_target = Some(next_addr);
                fall_thru = new_target;
            } else {
                // ":774 — check if any forward jump reference is targeted right after this
                // instruction.
                if target_list.contains(&next_addr) {
                    new_target = Some(next_addr);
                } else if flow.jump {
                    // ":779 — if this is a jump, and jumps forward only some number of bytes,
                    // make that the new target.
                    new_target = flows.iter().copied().find(|a| !body.contains(*a));
                }
                if new_target.is_none() {
                    new_target = next_target(&body, &mut untried_target_list);
                    repeat_tracker.reset();
                }
            }

            // ":800 — if this is a jump, add its targets to the list of valid forward
            // reference continuation points.
            if flow.jump {
                if !flows.is_empty() {
                    for a in &flows {
                        // ":806 — if the jump target is the same as the fall-through.
                        // (Instructions with delay slots are allowed; x86 has none.)
                        if fall_thru == Some(*a) {
                            return false;
                        }
                        // ":812 — if this code jumps to an existing function, allow it.
                        if program.function_manager.function_at(*a).is_some() {
                            did_call_valid_subroutine = true;
                            new_target = next_target(&body, &mut untried_target_list);
                            repeat_tracker.reset();
                            continue;
                        }
                        target_list.push(*a);
                        untried_target_list.push(*a);
                    }
                } else if flow.computed {
                    did_terminate = true;
                }
            }
            if flow.call || (flow.jump && flow.computed) {
                // ":832 — if the instruction has no static flows, fall back to its first
                // reference (the resolved indirect target).
                let mut call_flows = flows.clone();
                if call_flows.is_empty() {
                    if let Some(r) = program.reference_manager.refs_from(t).next() {
                        call_flows.push(r.to);
                    }
                }
                for f in &call_flows {
                    // ":844 — does this reference a valid function?
                    if program
                        .symbol_table
                        .primary_at(*f)
                        .is_some_and(|s| s.symbol_type() == SymbolType::Function)
                    {
                        did_call_valid_subroutine = true;
                    }
                    // ":850 — if respecting the execute flag, make sure we did not flow into
                    // non-execute memory.
                    if self.respect_execute_flag && !exec_set.is_empty() && !exec_set.contains(*f) {
                        if let Some(block) = program.memory.block_at(*f) {
                            if block.is_read() && block.name() != "EXTERNAL" {
                                return false;
                            }
                        }
                    }
                }
            }
            target = new_target;
        }

        // ":881 — get rid of anything on the target list that is in the body of an instruction.
        // With `maxInstructions > 0` (always, here) the else-arm removes every remaining target
        // too, so `remaining` always ends up empty; the *first* arm is the live guard — a jump
        // landing inside an instruction rather than at its start invalidates the whole run.
        let mut remaining: Vec<Address> = Vec::new();
        for t in target_list {
            if body.contains(t) {
                if !instr_starts.contains(t) {
                    return false;
                }
            } else if self.max_instructions == 0 {
                remaining.push(t);
            }
        }

        // ":899 — if the target list is empty, and we are at a terminal instruction.
        if remaining.is_empty() && (did_terminate || !must_terminate || did_call_valid_subroutine) {
            return self.check_pseudo_body(
                program,
                entry_point,
                &body,
                &instr_starts,
                allow_existing_instructions,
                did_call_valid_subroutine,
                &exec_set,
            );
        }
        false
    }

    /// `checkPseudoBody` (:953) — the body of the followed flow must not break any rules.
    #[allow(clippy::too_many_arguments)]
    fn check_pseudo_body(
        &self,
        program: &Program,
        entry: Address,
        body: &AddressSet,
        starts: &AddressSet,
        allow_existing_instructions: bool,
        did_call_valid_subroutine: bool,
        exec_set: &AddressSet,
    ) -> bool {
        // ":960 — check that the body does not wander into non-executable memory.
        if self.respect_execute_flag && !exec_set.is_empty() && !body.subtract(exec_set).is_empty() {
            return false;
        }

        // ":969 — existing defined Data anywhere in the body disqualifies it.
        if program.defined_data.iter().any(|(a, _, len)| {
            let last = a.offset + u64::from((*len).max(1)) - 1;
            body.ranges().any(|r| r.space == a.space && a.offset <= r.max && last >= r.min)
        }) {
            return false;
        }

        // ":973 — don't allow offcut references (a reference into the body that is not an
        // instruction start). `canHaveOffcutEntry` is the ARM/Thumb low-bit mode; x86 is false.
        let strictly_body = body.subtract(starts);
        if !program.reference_manager.destinations_in(&strictly_body).is_empty() {
            return false;
        }

        // ":986 — if existing instructions are allowed, don't worry about multiple entry
        // points either. This is the `isValidCode` exit.
        if allow_existing_instructions {
            return true;
        }

        if program
            .listing
            .code_units()
            .any(|(a, u)| matches!(u, crate::analysis::program::CodeUnit::Instruction { .. }) && body.contains(a))
        {
            return false;
        }

        // ":994 — don't allow one instruction.
        if !did_call_valid_subroutine && starts.min_address() == starts.max_address() {
            return false;
        }

        // ":999 — any internal reference destination that is not the entry point makes it a
        // bad subroutine.
        program.reference_manager.destinations_in(body).iter().all(|d| *d == entry)
    }
}

/// `getNextTarget` (:553) — the first untried target not already inside the followed body.
fn next_target(body: &AddressSet, untried: &mut Vec<Address>) -> Option<Address> {
    let idx = untried.iter().position(|a| !body.contains(*a))?;
    Some(untried.remove(idx))
}

/// `Instruction.getFlows()` — the instruction's static flow destinations. Mirrors
/// `analyzers::Disassembler::static_target`: a flow op's `ram`-space first input, excluding a
/// self-target (SLEIGH lifts `hlt` to `BRANCH <self>` and mosura creates no reference for it,
/// so it is not one of Ghidra's flows either).
fn static_flows(insn: &Instruction, ram: SpaceId) -> Vec<Address> {
    let mut out = Vec::new();
    for op in &insn.ops {
        let is_flow = matches!(
            OpCode::from_u32(op.opcode),
            Some(OpCode::Branch | OpCode::Cbranch | OpCode::Call)
        );
        if !is_flow {
            continue;
        }
        if let Some(PArg::Var(v)) = op.ins.first() {
            if v.space == "ram" && v.offset != insn.address {
                let a = Address::new(ram, v.offset);
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
    }
    out
}

/// `isReallyReturn` (:943) — the instruction's p-code contains a `RETURN`.
fn is_really_return(insn: &Instruction) -> bool {
    insn.ops.iter().any(|o| matches!(OpCode::from_u32(o.opcode), Some(OpCode::Return)))
}

/// `checkNonReturning` (:909) — a call whose (static) destination is a function flagged
/// "No Return". See the module note for the unported indirect arm.
fn check_non_returning(program: &Program, flow: FlowProps, flows: &[Address]) -> bool {
    if !flow.call {
        return false;
    }
    flows.first().is_some_and(|a| program.is_noreturn(*a))
}

/// The union of the executable memory blocks (Ghidra `Memory.getExecuteSet`).
fn execute_set(program: &Program) -> AddressSet {
    let mut set = AddressSet::new();
    for b in program.memory.blocks().filter(|b| b.is_execute()) {
        set.add_range(b.start().space, b.start().offset, b.end().offset);
    }
    set
}
