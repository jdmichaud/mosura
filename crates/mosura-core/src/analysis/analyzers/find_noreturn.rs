//! `FindNoReturnFunctionsAnalyzer` — a port of Ghidra's
//! `app/plugin/core/analysis/FindNoReturnFunctionsAnalyzer.java`, the analyzer Ghidra calls
//! **"Non-Returning Functions - Discovered"**.
//!
//! ⚠️ **This is not the same analyzer as [`super::noreturn`]**, which is "Non-Returning
//! Functions - *Known*" (`NoReturnFunctionAnalyzer.java`) and matches library function names
//! against Ghidra's own data files. That one is inert on every binary in this corpus — no listed
//! name is reached by a direct call anywhere. This one needs no names at all: it *infers*
//! non-return from what the disassembly looks like after each call.
//!
//! **Its evidence is bad code.** `checkNonReturningIndicators` walks the fall-through chain after
//! a call looking for signs that the bytes there are not really code — a function entry sitting
//! at the fall-through, an instruction that *contains* the next function's entry, data, a data or
//! call reference into it, an `INT3`. When enough call sites of the same target look like that
//! (`OPTION_DEFAULT_EVIDENCE_THRESHOLD`, **3**), the target is marked non-returning and every
//! call to it gets `FlowOverride.CALL_RETURN`, which is what stops the fall-through.
//!
//! That inversion is the point, and it is why `<subject-profile>/notes/function-discovery-backlog.md` §9 #5 was
//! framed the wrong way round: the mis-decode mosura produces after the subject MZ stub's
//! inline-parameter thunks is not a defect Ghidra avoids, it is the *signal* Ghidra reads.
//!
//! # What is ported, and what is not
//!
//! Ported: `added`'s two-pass detect (:117-122), `detectNoReturn` (:335), the six indicators of
//! `checkNonReturningIndicators` (:514), `getAllFlows` (:600), `hasInconsistentRefsTo` (:635),
//! `setFunctionNonReturning` (:198) and `setNoFallThru` (:218).
//!
//! **NOT ported — `targetOnlyCallsNoReturn` (:424)**, the fallback that marks a target whose
//! every path only ever calls non-returning functions. It walks Ghidra's `SimpleBlockModel`,
//! a basic-block model mosura's analysis layer does not have. It runs *only* when the evidence
//! did not reach the threshold, and it can only ADD marks, so omitting it is conservative: this
//! analyzer marks a subset of what Ghidra marks and never a superset. `had_suspicious_functions`
//! is still tracked, because it drives the second detect pass, which IS ported.
//!
//! **NOT ported — the repair** (`repairDamagedLocations` -> `ClearFlowAndRepairCmd`, :139-147,
//! and `findRepairLocations` :274). Marking a function non-returning stops *future* fall-through;
//! it does not remove the wrong code unit that is already on the ground, and the wrong code unit
//! is what §9 #5's gate measures. That is its own subsystem.

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::flowtype::FlowOverride;
use crate::analysis::manager::Scheduling;
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, CodeUnit, Program, RefType};
use crate::decompile::space::{Address, SpaceId};
use crate::sleigh::engine::Spec;

use std::collections::BTreeSet;

/// `OPTION_DEFAULT_EVIDENCE_THRESHOLD` (:56) — how many call sites of one target must look
/// non-returning before it is marked.
const EVIDENCE_THRESHOLD: usize = 3;

/// Longest instruction the listing is probed backward for (`getInstructionContaining`).
const MAX_INSN_LEN: u64 = 16;

/// How far `checkNonReturningIndicators`' fall-through chain is followed. Ghidra's loop is
/// unbounded — it ends when an instruction is not a pure fall-through — and cannot spin, because
/// the chain is strictly increasing through a finite listing. mosura decodes rather than reads a
/// listing, so a bound keeps a pathological image from walking a whole segment.
const MAX_CHAIN: usize = 64;

pub struct FindNoReturnFunctionsAnalyzer {
    spec: &'static Spec,
    ctx: &'static [u32],
    ram: SpaceId,
    /// `isX86` (:83) — gates the `INT3`-after-call indicator (:574).
    is_x86: bool,
}

impl FindNoReturnFunctionsAnalyzer {
    pub fn for_program(program: &Program) -> Option<FindNoReturnFunctionsAnalyzer> {
        let (spec, ctx) = crate::lang::load_cached(&program.language_id)?;
        // `checkForX86` (:157): `program.getLanguage().getProcessor().equals(x86)` — the
        // processor is the first field of the language id.
        let is_x86 = program.language_id.split(':').next() == Some("x86");
        Some(FindNoReturnFunctionsAnalyzer { spec, ctx, ram: program.default_space, is_x86 })
    }

    /// Decode the instruction at `addr`, or `None` if nothing decodes there.
    fn decode(&self, program: &Program, addr: Address) -> Option<crate::sleigh::Instruction> {
        crate::analysis::analyzers::decode_listed(program, self.spec, self.ctx, addr)
    }

    /// `Instruction.getFlowType()` at `addr` — the classified flow with the instruction's flow
    /// override applied, which is where a call that has already been overridden stops looking
    /// like one that falls through.
    fn flow_at(
        &self,
        program: &Program,
        addr: Address,
        insn: &crate::sleigh::Instruction,
    ) -> crate::analysis::flowtype::FlowProps {
        let next = addr.offset + insn.bytes.len() as u64;
        crate::analysis::flowtype::overridden_flow_props(
            &insn.ops,
            addr.offset,
            next,
            program.flow_override_at(addr),
        )
    }

    /// `Instruction.getFallThrough()` at `addr` — `None` when the flow type has none.
    fn fall_through(
        &self,
        program: &Program,
        addr: Address,
        insn: &crate::sleigh::Instruction,
    ) -> Option<Address> {
        self.flow_at(program, addr, insn)
            .fallthrough
            .then(|| Address::new(addr.space, addr.offset + insn.bytes.len() as u64))
    }

    /// `getFunctionAfter` (:697) — the entry of the first function at or after `addr`. Ghidra's
    /// version memoizes across calls; the memo changes no answer.
    fn function_after(&self, program: &Program, addr: Address) -> Option<Address> {
        program
            .function_manager
            .functions()
            .map(|f| f.entry_point())
            .filter(|e| e.space == addr.space && e.offset >= addr.offset)
            .min_by_key(|e| e.offset)
    }

    /// `getAllFlows` (:600) — the instruction's flow destinations. For an indirect call with no
    /// flows, the target read through a `READ` reference that lands on a function.
    fn all_flows(
        &self,
        program: &Program,
        addr: Address,
        insn: &crate::sleigh::Instruction,
    ) -> Vec<Address> {
        let flows: Vec<Address> = insn
            .ops
            .iter()
            .filter(|o| {
                matches!(
                    crate::decompile::opcode::OpCode::from_u32(o.opcode),
                    Some(
                        crate::decompile::opcode::OpCode::Call
                            | crate::decompile::opcode::OpCode::Branch
                            | crate::decompile::opcode::OpCode::Cbranch
                    )
                )
            })
            .filter_map(super::static_target)
            .map(|t| Address::new(self.ram, t))
            .collect();
        if !flows.is_empty() {
            return flows;
        }
        let props = self.flow_at(program, addr, insn);
        if !props.call || !props.computed {
            return flows;
        }
        for r in program.reference_manager.refs_from(addr) {
            if r.ref_type == RefType::Read && program.function_manager.function_at(r.to).is_some() {
                return vec![r.to];
            }
        }
        flows
    }

    /// `hasInconsistentRefsTo` (:635) — a READ/WRITE reference into `addr` from *earlier in the
    /// same function* as the call, or any CALL reference into it. Ghidra's comment explains the
    /// same-function restriction: a stray data reference from elsewhere is more likely bad
    /// disassembly than evidence.
    fn has_inconsistent_refs_to(
        &self,
        program: &Program,
        addr: Address,
        calling_func: Option<Address>,
    ) -> bool {
        for r in program.reference_manager.refs_to(addr) {
            if matches!(r.ref_type, RefType::Read | RefType::Write) {
                match calling_func {
                    Some(entry) => {
                        let from_fn = program
                            .function_manager
                            .function_containing(r.from)
                            .map(|f| f.entry_point());
                        if r.from.offset < addr.offset && from_fn == Some(entry) {
                            return true; // "Data Reference from same function after call"
                        }
                    }
                    // "only consider references after call if the call location is not in a
                    // function"
                    None => return true,
                }
            }
            if r.ref_type.is_call() {
                return true; // "Call Reference after call"
            }
        }
        false
    }

    /// `checkNonReturningIndicators` (:514) — does the disassembly after this call look like the
    /// callee never came back? The six indicators, in Ghidra's order.
    fn check_nonreturning_indicators(
        &self,
        program: &Program,
        call_addr: Address,
        call_insn: &crate::sleigh::Instruction,
    ) -> bool {
        let mut fall_thru = self.fall_through(program, call_addr, call_insn);
        let calling_func =
            program.function_manager.function_containing(call_addr).map(|f| f.entry_point());
        // `getFunctionAfter(fallThru)` is evaluated ONCE, before the loop — the chain walk does
        // not re-query it (:530).
        let next_func_addr = fall_thru.and_then(|ft| self.function_after(program, ft));

        for _ in 0..MAX_CHAIN {
            let Some(ft) = fall_thru else { break };

            // "Function defined after call" (:535).
            if next_func_addr == Some(ft) {
                return true;
            }
            // "Falls into data after call" (:542) — no code unit, or a data one.
            match program.listing.code_unit_at(ft) {
                None | Some(CodeUnit::Data { .. }) => return true,
                Some(CodeUnit::Instruction { .. }) => {}
            }
            // ⭐ "Function defined in instruction after call" (:552) — the code unit at the
            // fall-through CONTAINS the next function's entry. This is the indicator the
            // inline-parameter thunk trips: the over-decode of the parameter word runs past the
            // callee's own entry.
            if let Some(nf) = next_func_addr {
                if let Some((cu_start, cu_len)) = program.listing.code_unit_containing(ft, MAX_INSN_LEN)
                {
                    if cu_start == ft && nf.space == ft.space && nf.offset > ft.offset
                        && nf.offset < cu_start.offset + cu_len
                    {
                        return true;
                    }
                }
            }
            // "inconsistent (data/call) references at fallthru after call" (:560).
            if self.has_inconsistent_refs_to(program, ft, calling_func) {
                return true;
            }
            // "Data after call" (:565) — a DEFINED data item, as distinct from the code-unit
            // test above.
            if program.defined_data.iter().any(|(a, _, _)| *a == ft) {
                return true;
            }
            // x86 only: "INT3 interrupt after call" (:574).
            let Some(fall_insn) = self.decode(program, ft) else { break };
            if self.is_x86 && fall_insn.mnemonic.eq_ignore_ascii_case("INT3") {
                return true;
            }
            // Follow the chain only while the instruction is a PURE fall-through
            // (`FlowType.isFallthrough()` is `== FALL_THROUGH`, RefType.java:578 — not
            // `hasFallthrough`), so a branch or call ends the walk.
            let props = self.flow_at(program, ft, &fall_insn);
            let pure_fallthrough =
                props.fallthrough && !props.jump && !props.call && !props.terminal;
            fall_thru =
                pure_fallthrough.then(|| self.fall_through(program, ft, &fall_insn)).flatten();
        }
        false
    }

    /// `detectNoReturn` (:335). Returns whether any target looked suspicious without reaching the
    /// threshold — Ghidra runs the whole detection a second time when it did, so a target marked
    /// late can supply evidence for another.
    fn detect_noreturn(
        &self,
        program: &Program,
        noreturn_set: &mut BTreeSet<u64>,
        set: &AddressSet,
    ) -> bool {
        let mut checked: BTreeSet<u64> = BTreeSet::new();
        let mut had_suspicious = false;

        // `getReferenceSourceIterator(checkSet, true)` — every reference SOURCE in the set,
        // ascending.
        let mut sources: Vec<u64> = program
            .reference_manager
            .references()
            .map(|r| r.from)
            .filter(|a| a.space == self.ram && set.contains(*a))
            .map(|a| a.offset)
            .collect();
        sources.sort_unstable();
        sources.dedup();

        for off in sources {
            let addr = Address::new(self.ram, off);
            if !checked.insert(off) {
                continue;
            }
            let Some(insn) = self.decode(program, addr) else { continue };
            if program.listing.code_unit_at(addr).is_none() {
                continue; // getInstructionAt == null
            }
            // "if not a call, or has no fallthru" (:360).
            let props = self.flow_at(program, addr, &insn);
            if !props.call || !props.fallthrough {
                continue;
            }
            if !self.check_nonreturning_indicators(program, addr, &insn) {
                continue;
            }
            let flows = self.all_flows(program, addr, &insn);
            if flows.is_empty() {
                continue;
            }
            for target in flows {
                let mut count = 1usize;
                let mut sites: Vec<Address> = program
                    .reference_manager
                    .refs_to(target)
                    .filter(|r| r.ref_type.is_call())
                    .map(|r| r.from)
                    .collect();
                sites.sort_by_key(|a| (a.space.0, a.offset));
                for from in sites {
                    if !checked.insert(from.offset) {
                        continue;
                    }
                    // "call is already on the list; done here so all other calls don't get
                    // re-checked" — note the `checked` insert above still happened.
                    if noreturn_set.contains(&target.offset) {
                        continue;
                    }
                    if program.listing.code_unit_at(from).is_none() {
                        continue;
                    }
                    let Some(oinsn) = self.decode(program, from) else { continue };
                    if !self.check_nonreturning_indicators(program, from, &oinsn) {
                        continue;
                    }
                    count += 1;
                    if count >= EVIDENCE_THRESHOLD {
                        noreturn_set.insert(target.offset);
                        break;
                    }
                }
                if count < EVIDENCE_THRESHOLD {
                    // `targetOnlyCallsNoReturn` would run here — see the module note; it needs a
                    // basic-block model mosura does not have, and can only add marks.
                    had_suspicious = true;
                }
            }
        }
        had_suspicious
    }

    /// `setNoFallThru` (:218) — every CALL reference to `entry` whose source instruction still
    /// has a fall-through gets `FlowOverride.CALL_RETURN`. **This, and not any fall-through
    /// override, is how Ghidra stops the decode after a non-returning call.**
    fn set_no_fall_thru(&self, program: &mut Program, entry: Address) -> Vec<Address> {
        let sites: Vec<Address> = program
            .reference_manager
            .refs_to(entry)
            .filter(|r| r.ref_type.is_call())
            .map(|r| r.from)
            .collect();
        let mut overridden = Vec::new();
        for from in sites {
            if program.listing.code_unit_at(from).is_none() {
                continue;
            }
            let Some(insn) = self.decode(program, from) else { continue };
            if self.fall_through(program, from, &insn).is_none() {
                continue;
            }
            if program.set_flow_override(from, FlowOverride::CallReturn) {
                overridden.push(from);
            }
        }
        overridden
    }

    /// `findRepairLocations` (:302): the DEFAULT fall-through of every call to the
    /// non-returning `entry` — the address where wrong code was laid before the verdict
    /// existed. A location is a repair seed only if nothing else justifies it: it is not the
    /// entry itself, not an entry point, and NO flow reference targets it. A seed that holds
    /// no instruction is dropped (Ghidra clears only an error bookmark there, which mosura
    /// does not model). `skipNOPS` (:341) is not ported — the corpus' inline parameters are
    /// never NOP runs; noted rather than silently skipped.
    fn find_repair_locations(&self, program: &Program, entry: Address) -> AddressSet {
        let mut clear_inst = AddressSet::new();
        for (from, len) in program
            .reference_manager
            .refs_to(entry)
            .filter(|r| r.ref_type.is_call())
            .filter_map(|r| program.listing.instruction_at(r.from).map(|(l, _)| (r.from, l)))
            .collect::<Vec<(Address, u32)>>()
        {
            // `instr.getFallThrough()` is null once the CALL_RETURN override is applied, so
            // Ghidra falls back to the DEFAULT fall-through offset (:317-325) — the byte
            // after the call, where the wrong decode starts.
            let ft = Address::new(from.space, from.offset + u64::from(len));
            // :329 — never the entry being marked.
            if ft == entry {
                continue;
            }
            // :334-338 — an entry point is never a repair seed.
            if program.entry_points.contains(&ft) {
                continue;
            }
            // :340 — a location some flow still targets was not created by this bad flow.
            if program.reference_manager.refs_to(ft).any(|r| r.ref_type.is_flow()) {
                continue;
            }
            if program.listing.instruction_at(ft).is_some() {
                clear_inst.add_range(ft.space, ft.offset, ft.offset);
            }
        }
        clear_inst
    }
}

impl Analyzer for FindNoReturnFunctionsAnalyzer {
    fn name(&self) -> &str {
        "Non-Returning Functions - Discovered"
    }
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Instruction
    }
    fn priority(&self) -> AnalysisPriority {
        // Ghidra: `setPriority(AnalysisPriority.DISASSEMBLY.after())` (:92).
        AnalysisPriority::DISASSEMBLY.after()
    }
    fn added(&self, program: &mut Program, set: &AddressSet, sched: &mut Scheduling) -> bool {
        let mut noreturn_set: BTreeSet<u64> = BTreeSet::new();

        // "run again with the new known noReturnSet" (:117-122).
        if self.detect_noreturn(program, &mut noreturn_set, set) {
            self.detect_noreturn(program, &mut noreturn_set, set);
        }
        if noreturn_set.is_empty() {
            return false;
        }

        let mut created = AddressSet::new();
        let mut marked: Vec<Address> = Vec::new();
        for off in noreturn_set {
            let entry = Address::new(self.ram, off);
            // `setFunctionNonReturning` (:198): create the function if there is none, then flag
            // it. `Function.setNoReturn(true)` is `noreturn_functions` here.
            if program.function_manager.function_at(entry).is_none() {
                let name = format!("FUN_{:08x}", entry.offset);
                if crate::analysis::analyzers::create_function_with_body(program, entry, &name) {
                    created.add_range(entry.space, entry.offset, entry.offset);
                } else {
                    continue;
                }
            }
            program.noreturn_functions.insert((entry.space.0, entry.offset));
            self.set_no_fall_thru(program, entry);
            // `fixCallingFunctionBody` (:715) recomputes each calling function's body, which in
            // mosura is `compute_function_bodies`' job and already runs to convergence; the
            // bookmark half has no mosura equivalent.
            marked.push(entry);
        }
        // `repairDamagedLocations` (:138-147) — a SECOND loop, after every entry is marked:
        // clear the wrong code laid at each call site's fall-through before the no-return
        // verdict existed, and re-disassemble the flows that entered it. The protected set is
        // the no-return entries themselves (:144 passes `noReturnSet`; the manager's
        // protected-locations store, :175, has no mosura counterpart — the pattern search's
        // `code_locations` are computed but never registered).
        let mut protected = AddressSet::new();
        for e in &marked {
            protected.add_range(e.space, e.offset, e.offset);
        }
        for e in &marked {
            let damaged = self.find_repair_locations(program, *e);
            if !damaged.is_empty() {
                crate::analysis::analyzers::clearflow::clear_flow_and_repair(
                    program, &damaged, &protected, sched,
                );
            }
        }
        if !created.is_empty() {
            sched.function_defined(&created);
        }
        true
    }
}
