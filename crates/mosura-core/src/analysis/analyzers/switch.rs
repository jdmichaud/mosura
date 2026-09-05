//! `DecompilerSwitchAnalyzer` (A6) — a port of Ghidra's
//! `app/plugin/core/analysis/DecompilerSwitchAnalyzer`.
//!
//! An `INSTRUCTION_ANALYZER`: it takes the newly decoded extent, keeps the computed jumps in it
//! (`findLocations`), maps each to its containing function (`findFunctions`), then runs the ported
//! decompiler ([`crate::analysis::decompiler`]) on each and reads back the recovered jump tables
//! ([`Funcdata::jump_tables`]). Each switch's indirect `BRANCHIND` becomes `COMPUTED_JUMP`
//! references to the case targets, and those targets are scheduled as code — so switch bodies,
//! reachable only through the table, get disassembled and structured into the function.

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::manager::Scheduling;
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, Program, RefType};
use crate::decompile::space::{Address, SpaceId};

pub struct DecompilerSwitchAnalyzer {
    ram: SpaceId,
}

impl DecompilerSwitchAnalyzer {
    pub fn new(program: &Program) -> DecompilerSwitchAnalyzer {
        DecompilerSwitchAnalyzer { ram: program.default_space }
    }

    /// `findLocations` (DecompilerSwitchAnalyzer.java:237) — walk the **instructions in the added
    /// set** and keep every address whose flow type `isJump() && isComputed()` (:252).
    ///
    /// mosura records exactly that predicate at decode time: the disassembler inserts into
    /// `program.indirect_branches` when an instruction's last p-code op is `BRANCHIND`
    /// (`analyzers/mod.rs`), which is what makes a flow type computed-and-jump. So the listing
    /// walk is that recorded set intersected with the added set, rather than a re-decode of every
    /// instruction in the extent.
    ///
    /// Two clauses of Ghidra's loop are absent, and they are absent for opposite reasons — both
    /// trace back to mosura having no p-code injection library, but only one is a deviation:
    ///
    ///  - ⚠️ **`hasUnrecoverableCallOther` (:259, :282) is deliberately NOT ported.** It drops a
    ///    candidate whose branch target is computed from a `CALLOTHER` output — but only when that
    ///    `CALLOTHER` has no p-code injection (`hasPcodeInject`, :333). With no injection library
    ///    the ported filter would answer "no injection" for every `CALLOTHER` and drop candidates
    ///    Ghidra keeps. Omitting a filter that only ever *removes* candidates leaves the set a
    ///    superset of Ghidra's, which is the safe direction; porting it half-way would not be.
    ///    This one IS a deviation, owned here.
    ///  - **`isCallFixup` (:253) is omitted and that is EXACTLY equivalent, not a deviation.** It
    ///    admits a *call* whose target function carries a call-fixup (:377 — `flowType.isCall()`
    ///    and some call reference whose target has `getCallFixup() != null`). A call fixup is an
    ///    injected p-code replacement; mosura defines none anywhere, so `getCallFixup()` is null
    ///    for every function and the clause can never admit anything. Its absence removes no
    ///    candidate that Ghidra would have kept. If an injection library ever lands, this clause
    ///    has to land with it.
    fn find_locations(&self, program: &Program, set: &AddressSet) -> Vec<u64> {
        let mut locations: Vec<u64> = program
            .indirect_branches
            .iter()
            .copied()
            .filter(|&b| set.contains(Address::new(self.ram, b)))
            .collect();
        locations.sort_unstable();
        locations
    }

    /// `findFunctions` (DecompilerSwitchAnalyzer.java:184) — map each location to the function
    /// **containing** it (`getFunctionContaining`, :429/:441), de-duplicated, ascending.
    ///
    /// The caller runs [`refresh_function_bodies`](crate::analysis::analyzers::refresh_function_bodies)
    /// first: this is a body query and mosura's bodies are empty until they are recomputed.
    ///
    /// ⚠️ **A location inside no function is DROPPED, where Ghidra decompiles it anyway.** Ghidra
    /// falls back to `UndefinedFunction.findFunctionUsingSimpleBlockModel` (:444), which needs the
    /// basic-block model the analysis layer does not have yet (task #10); `handleSimpleBlock`
    /// (:456) and `resolveComputableFlow` (:469) need it too. Until then a computed jump in code
    /// that is decoded but in no function — the state `AddressTableAnalyzer` produces — has no
    /// route into switch recovery. This is the same gap that keeps this analyzer at
    /// `REFERENCE_ANALYSIS.after()` rather than Ghidra's `CODE_ANALYSIS`; see [`Analyzer::priority`].
    fn find_functions(&self, program: &Program, locations: &[u64]) -> Vec<u64> {
        let mut entries: Vec<u64> = locations
            .iter()
            .filter_map(|&loc| program.function_manager.function_containing(Address::new(self.ram, loc)))
            .map(|f| f.entry_point().offset)
            .collect();
        entries.sort_unstable();
        entries.dedup();
        entries
    }
}

impl Analyzer for DecompilerSwitchAnalyzer {
    fn name(&self) -> &str {
        "Decompiler Switch"
    }
    /// ⭐ **`INSTRUCTION_ANALYZER`** (DecompilerSwitchAnalyzer.java:68) — the newly disassembled
    /// **extent**, not a set of function entries.
    ///
    /// mosura registered this on the `Function` channel, which asks a different question: "which
    /// functions were just created", instead of "which computed jumps were just decoded". The two
    /// diverge whenever code is decoded *into a function that already exists* — which is exactly
    /// what this analyzer itself provokes, by scheduling a recovered switch's case targets for
    /// disassembly (and what `AddressTableAnalyzer` and the relocation seeds provoke later, both
    /// of which run after this one). Those case bodies create no new function, so on the `Function`
    /// channel nothing re-delivered them and a computed jump first decoded in that round was never
    /// examined.
    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Instruction
    }
    fn priority(&self) -> AnalysisPriority {
        // ⚠️ Ghidra's value is `AnalysisPriority.CODE_ANALYSIS` (:69) = 400, i.e. BEFORE function
        // creation (500). It can afford that because `findFunctions` falls back to
        // `UndefinedFunction.findFunctionUsingSimpleBlockModel` (:444) when no function contains
        // the location — it decompiles a function that does not exist yet. mosura has no
        // basic-block model in the analysis layer (task #10), so at 400 every location decoded
        // before its function was created would map to nothing and be dropped, and the extent is
        // drained, so nothing re-delivers it. Held at `REFERENCE_ANALYSIS.after()` — after
        // disassembly (300), function creation (500) and reference recovery (600) — until the
        // block model lands. Deviation owned and recorded, not grandfathered.
        AnalysisPriority::REFERENCE.after()
    }
    fn added(&self, program: &mut Program, set: &AddressSet, sched: &mut Scheduling) -> bool {
        let ram = self.ram;
        let locations = self.find_locations(program, set);
        if locations.is_empty() {
            return true; // (:102) `if (locations.isEmpty()) return true;`
        }
        // `findFunctions` asks `getFunctionContaining`, a body query — see the note there. After
        // the early return, so an extent with no computed jump in it (the common case) does not
        // pay for a body recompute.
        crate::analysis::analyzers::refresh_function_bodies(program);
        let mut case_targets = AddressSet::new();
        for entry_off in self.find_functions(program, &locations) {
            let entry = Address::new(ram, entry_off);
            let Some(mut f) = crate::analysis::decompiler::decompile_function(program, entry) else {
                continue;
            };
            for jt in f.jump_tables() {
                let from = Address::new(ram, jt.op_addr);
                for t in jt.targets {
                    // COMPUTED_JUMP from the BRANCHIND to each case target.
                    program.reference_manager.add(from, Address::new(ram, t), RefType::ComputedJump, -1);
                    case_targets.add_range(ram, t, t);
                }
            }
        }
        // The case targets are reachable code (only through the table) — disassemble them.
        if !case_targets.is_empty() {
            sched.disassemble(&case_targets);
        }
        true
    }
}

#[cfg(test)]
mod find_functions_tests {
    use super::*;
    use crate::analysis::program::AddressSet;
    use crate::decompile::space::{SpaceKind, SpaceManager};

    /// A bare x86-64 program with one 4 KiB `.text` block at `0x401000` — no bytes are decoded
    /// here, the selection under test reads only the function manager and `indirect_branches`.
    fn program() -> Program {
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
        let base = Address::new(ram, 0x40_1000);
        let mut p = Program::new(spaces, ram, "x86:LE:64:default", "gcc", base, false, 64);
        p.memory.add_block(".text", base, 0x1000, true, false, true, Some(vec![0; 0x1000]));
        p
    }

    /// Create a function at `off` owning `[off, end]` — a real body, because `findFunctions` is a
    /// `getFunctionContaining` query and the analyzer refreshes bodies before asking it.
    fn make_function(p: &mut Program, off: u64, end: u64) {
        let ram = p.default_space;
        let mut body = AddressSet::new();
        body.add_range(ram, off, end);
        p.function_manager.create_function(Address::new(ram, off), &format!("FUN_{off:08x}"), body);
    }

    fn set_of(p: &Program, offs: &[u64]) -> AddressSet {
        let mut s = AddressSet::new();
        for &o in offs {
            s.add_range(p.default_space, o, o);
        }
        s
    }

    /// `findLocations` (:237) reads the LISTING, not the function set: a candidate is an
    /// instruction **in the added set** whose flow type is a computed jump. The added set is a
    /// decoded extent, so what selects a function is the computed jump landing in its body — the
    /// function's own entry need never appear in the set at all.
    ///
    /// This is the channel defect in miniature. On the `Function` channel the set was "entries
    /// created this round"; here the extent covers the switch instruction and nothing else, and
    /// the owning function is still found.
    #[test]
    fn a_computed_jump_in_the_extent_selects_its_containing_function() {
        let mut p = program();
        make_function(&mut p, 0x40_1010, 0x40_101f);
        make_function(&mut p, 0x40_1020, 0x40_102f);
        p.indirect_branches.insert(0x40_1025);

        let a = DecompilerSwitchAnalyzer::new(&p);
        let set = set_of(&p, &[0x40_1025]); // the extent holds the jump, neither entry
        let locations = a.find_locations(&p, &set);

        assert_eq!(locations, vec![0x40_1025]);
        assert_eq!(
            a.find_functions(&p, &locations),
            vec![0x40_1020],
            "the computed jump at 0x401025 is inside the function at 0x401020"
        );
    }

    /// `findLocations` is bounded by the added set (:246, `getInstructions(set, true)`): a computed
    /// jump decoded in an earlier round, outside this extent, is not re-examined. Without this the
    /// analyzer would re-decompile every switch-bearing function on every round.
    #[test]
    fn a_computed_jump_outside_the_extent_is_not_a_location() {
        let mut p = program();
        make_function(&mut p, 0x40_1000, 0x40_10ff);
        p.indirect_branches.insert(0x40_1005); // decoded earlier, not in this extent

        let a = DecompilerSwitchAnalyzer::new(&p);
        let set = set_of(&p, &[0x40_1080, 0x40_1081]);

        assert!(a.find_locations(&p, &set).is_empty());
    }

    /// `findFunctions` (:184) collects into a `HashSet<Function>` (:107): several computed jumps in
    /// one function decompile it ONCE.
    #[test]
    fn several_computed_jumps_in_one_function_decompile_it_once() {
        let mut p = program();
        make_function(&mut p, 0x40_1000, 0x40_10ff);
        p.indirect_branches.insert(0x40_1010);
        p.indirect_branches.insert(0x40_1020);

        let a = DecompilerSwitchAnalyzer::new(&p);
        let set = set_of(&p, &[0x40_1010, 0x40_1020]);
        let locations = a.find_locations(&p, &set);

        assert_eq!(locations, vec![0x40_1010, 0x40_1020]);
        assert_eq!(a.find_functions(&p, &locations), vec![0x40_1000]);
    }

    /// A location that no function contains is dropped rather than attributed to the nearest entry
    /// below it. The previous selection spanned each function `[entry, next entry)`, so a computed
    /// jump in code that belongs to no function was charged to whatever function happened to
    /// precede it; `getFunctionContaining` (:429) answers null there.
    ///
    /// ⚠️ This is where Ghidra runs `UndefinedFunction.findFunctionUsingSimpleBlockModel` (:444)
    /// and mosura stops — see [`DecompilerSwitchAnalyzer::find_functions`]. The assertion records
    /// the current, deliberate behaviour so the day the block model lands (task #10) this test
    /// fails and names what changed.
    #[test]
    fn a_computed_jump_in_no_function_is_dropped_pending_the_block_model() {
        let mut p = program();
        make_function(&mut p, 0x40_1000, 0x40_100f); // ends well below the jump
        p.indirect_branches.insert(0x40_1080);

        let a = DecompilerSwitchAnalyzer::new(&p);
        let set = set_of(&p, &[0x40_1080]);
        let locations = a.find_locations(&p, &set);

        assert_eq!(locations, vec![0x40_1080]);
        assert!(
            a.find_functions(&p, &locations).is_empty(),
            "0x401080 is inside no function body — it must not be charged to the function at \
             0x401000 that merely precedes it"
        );
    }
}
