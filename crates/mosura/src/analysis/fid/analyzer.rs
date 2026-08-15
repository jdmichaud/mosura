//! `FidAnalyzer` — a port of `analyzer/FidAnalyzer.java` plus the applying half of
//! `cmd/ApplyFidEntriesCommand.java`.
//!
//! Runs at the `FUNCTION_ID` priority band (800), the slot Ghidra reserves for exactly this
//! and which mosura has carried unused since the priorities were ported. For each recovered
//! function: hash it, look the quad up in the attached databases, score the candidates against
//! its callers and callees, and — if the result clears the apply gate — replace the default
//! `FUN_xxxxxxxx` name with the library name.
//!
//! **Inert with no database attached.** No `.fidb` matching the program's language and
//! compiler spec means no query service, and the analyzer returns without touching the
//! program. That is the same shape as the no-return pass on an empty corpus: absent data is a
//! reason to do nothing, not an error.

use std::collections::HashMap;

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::manager::Scheduling;
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, Program};
use crate::decompile::space::Address;

use super::hash::{
    CodeUnitInput, FidHashQuad, FidHasher, OperandAddressQuery, RelocationQuery, Skipper,
};
use super::matcher::{apply_markup, HashFamily, Seeker};
use super::query::FidQueryService;

/// The program's relocation table as an inclusive-range query
/// (`RelocationTable.getRelocations(AddressSet)`).
struct ProgramRelocations<'a>(&'a Program);

impl RelocationQuery for ProgramRelocations<'_> {
    fn any_in_range(&self, min_offset: u64, max_offset: u64) -> bool {
        self.0
            .relocation_table
            .relocations()
            .any(|r| r.address.offset >= min_offset && r.address.offset <= max_offset)
    }
}

/// The analysis-derived half of `OperandType.ADDRESS` (`InstructionDB.java:398-419`).
///
/// mosura's references record `op_index = -1`, so the operand is identified by value: the
/// ADDRESS bit belongs to the operand whose scalar *is* the referenced address. Exact for
/// whole-scalar operands, which are the only ones whose ADDRESS bit reaches a hash. See
/// `docs/fid-port-plan.md` §8 R8.
struct ProgramOperandAddresses<'a>(&'a Program);

impl OperandAddressQuery for ProgramOperandAddresses<'_> {
    fn operand_is_address(
        &self,
        instruction_address: u64,
        op_index: usize,
        objects: &[crate::sleigh::OpObject],
    ) -> bool {
        // ⚠️ Indexed, not a scan. This asks "are there references out of THIS instruction", once
        // per operand of every instruction FID hashes; `references()` walks all >20k of them, and
        // `perf` put this at 2.75% of a whole WAR2 run. A reference's `from` is an instruction
        // address, so it is always in the program's default space — the previous offset-only test
        // could not match anything else in practice.
        let from = crate::decompile::space::Address::new(self.0.default_space, instruction_address);
        self.0.reference_manager.refs_from(from).any(|r| {
            if !self.0.memory.contains(r.to) {
                return false;
            }
            if r.op_index >= 0 {
                return r.op_index == op_index as i32;
            }
            objects.iter().any(|o| {
                matches!(o, crate::sleigh::OpObject::Scalar { signed_value }
                    if *signed_value as u64 == r.to.offset)
            })
        })
    }
}

/// Hash one function's body out of the program.
///
/// The extent is `listing.getInstructions(body, true)` — the recorded body's instructions in
/// ascending address order (`FunctionBodyFunctionExtentGenerator.java:45-48`), not a re-derived
/// flow walk.
pub fn hash_function(program: &Program, entry: Address) -> Option<FidHashQuad> {
    let function = program.function_manager.function_at(entry)?;
    // `load_cached`, not `load`: the uncached path re-parses the whole `.sla` on every call,
    // which is ~1.5 s per function and made a 394-module library ingest take ten minutes.
    // Caching also makes the tables a per-process constant, which is the determinism argument
    // in `lang::load_cached`'s own documentation.
    let (spec, ctx) = crate::lang::load_cached(&program.language_id)?;
    let skipper = Skipper::for_language(&program.language_id);

    // Collect the body's instruction starts, ascending.
    let mut starts: Vec<Address> = Vec::new();
    for range in function.body().ranges() {
        let mut offset = range.min;
        while offset <= range.max {
            match program.listing.code_unit_at(Address::new(program.default_space, offset)) {
                Some(unit) => {
                    let len = u64::from(unit.length()).max(1);
                    if matches!(unit, crate::analysis::program::listing::CodeUnit::Instruction { .. })
                    {
                        starts.push(Address::new(program.default_space, offset));
                    }
                    offset += len;
                }
                // Not a code-unit boundary — the body covers bytes the listing has not
                // defined; step past them rather than mis-decode.
                None => offset += 1,
            }
        }
    }
    if starts.is_empty() {
        return None;
    }

    // Decode each instruction from its own bytes, as the listing recorded it.
    let mut decoded = Vec::with_capacity(starts.len());
    for start in starts {
        // ⚠️ **Bounded by the LISTING's recorded length, not a fixed 16-byte window.** A 16-byte
        // window makes SLEIGH decode every instruction that fits in it — ~5 on x86 — and
        // `.next()` throws four of them away. Doubly so here, because the window is decoded
        // TWICE (once for p-code, once for the fingerprint). `perf --children` put
        // `hash_function -> disassemble_ctx` at ~7.4% of a whole WAR2 run.
        //
        // Fourth instance of this class after b6754d2, 90dd655 and the thunk entry probe; the
        // bound is the same one 90dd655 established (symbolic.rs:521). The comment above already
        // claimed "from its own bytes, as the listing recorded it" — this makes it true.
        let ilen = match program.listing.instruction_at(start) {
            Some((len, _)) if len > 0 => len as usize,
            // No recorded length (should not happen: `starts` came from the listing) — fall back
            // to the old window rather than skip the instruction and change the hash.
            _ => 16,
        };
        let window = program.memory.read_window(start, ilen);
        if window.is_empty() {
            continue;
        }
        let insn = spec.disassemble_ctx(&window, start.offset, ctx).into_iter().next()?;
        let fp = spec.disassemble_fingerprint(&window, start.offset, ctx).into_iter().next()?;
        decoded.push((insn, fp));
    }

    let units: Vec<CodeUnitInput> = decoded
        .iter()
        .map(|(insn, fp)| {
            let next = insn.address + insn.bytes.len() as u64;
            let addr = Address::new(program.default_space, insn.address);
            // `InstructionDB.getFlowType()` = getModifiedFlowType(proto flow, flowOverride):
            // the flow analysis settled on, which outranks the bytes.
            let props = crate::analysis::flowtype::overridden_flow_props(
                &insn.ops,
                insn.address,
                next,
                program.flow_override_at(addr),
            );
            CodeUnitInput {
                min_address: insn.address,
                max_address: next - 1,
                bytes: &insn.bytes,
                fingerprint: Some(fp),
                is_call: Some(props.call),
            }
        })
        .collect();

    FidHasher::new(skipper).hash(
        &units,
        &ProgramRelocations(program),
        &ProgramOperandAddresses(program),
    )
}

/// Ghidra's default function name (`SymbolUtilities.getDefaultFunctionName`).
/// One definition of "still unidentified", shared with the recompile tooling, which asks the
/// same question to decide what belongs in its denominator. Two copies of the placeholder-name
/// format would drift the moment the generator changed.
use crate::analysis::program::function::Function as ProgramFunction;
fn is_default_name(name: &str) -> bool {
    ProgramFunction::name_is_default(name)
}

/// The name FID decided for each function, and the matches behind it.
#[derive(Debug, Clone)]
pub struct FidResult {
    pub entry: Address,
    /// The name to apply, or `None` when FID recognised the function but the matches could not
    /// be narrowed to a single name. Ghidra declines to rename in that case and still records
    /// the finding as a plate comment, so a `None` here is a RESULT, not the absence of one.
    pub name: Option<String>,
    /// The plate comment Ghidra's `generateComment` produces. Never empty for a returned result.
    pub plate: String,
    pub score: f32,
    /// True when several records tied and their names collapsed to one.
    pub multiple: bool,
}

/// Run the seeker over every function of the program and return what it would apply.
///
/// Separated from [`FidAnalyzer::added`] so a test can inspect the decisions without mutating
/// a program.
pub fn search_program(program: &Program, service: &FidQueryService) -> Vec<FidResult> {
    if service.is_empty() {
        return Vec::new();
    }

    // Hash every function once; the family of a function needs its neighbours' quads too.
    let mut quads: HashMap<(u32, u64), FidHashQuad> = HashMap::new();
    let entries: Vec<Address> =
        program.function_manager.functions().map(|f| f.entry_point()).collect();
    for entry in &entries {
        if let Some(q) = hash_function(program, *entry) {
            quads.insert((entry.space.0, entry.offset), q);
        }
    }

    // The call graph, from the reference manager: who calls whom.
    let mut callees: HashMap<(u32, u64), Vec<Address>> = HashMap::new();
    let mut callers: HashMap<(u32, u64), Vec<Address>> = HashMap::new();
    for r in program.reference_manager.references() {
        if !r.ref_type.is_call() {
            continue;
        }
        let Some(from_fn) = program.function_manager.function_containing(r.from) else { continue };
        let from = from_fn.entry_point();
        if program.function_manager.function_at(r.to).is_none() {
            continue;
        }
        callees.entry((from.space.0, from.offset)).or_default().push(r.to);
        callers.entry((r.to.space.0, r.to.offset)).or_default().push(from);
    }

    let seeker = Seeker::new(service);
    let mut results = Vec::new();
    for entry in entries {
        let key = (entry.space.0, entry.offset);
        let Some(&hash) = quads.get(&key) else { continue };

        let family = HashFamily {
            hash: Some(hash),
            children: callees
                .get(&key)
                .map(|v| {
                    v.iter().filter_map(|a| quads.get(&(a.space.0, a.offset)).copied()).collect()
                })
                .unwrap_or_default(),
            parents: callers
                .get(&key)
                .map(|v| {
                    v.iter().filter_map(|a| quads.get(&(a.space.0, a.offset)).copied()).collect()
                })
                .unwrap_or_default(),
        };

        let Some(result) = seeker.process_matches(&family) else { continue };
        let markup = apply_markup(&result);
        if markup.plate.is_empty() {
            continue; // below the apply gate entirely — nothing to say about this function
        }
        let score = result
            .matches()
            .iter()
            .map(super::matcher::HashMatch::overall_score)
            .fold(f32::MIN, f32::max);
        results.push(FidResult {
            entry,
            name: markup.name,
            plate: markup.plate,
            score,
            multiple: result.matches().len() > 1,
        });
    }
    results
}

/// The auto-analysis pass.
pub struct FidAnalyzer {
    service: FidQueryService,
}

impl FidAnalyzer {
    /// Build the analyzer with the databases matching this program, taken from
    /// [`crate::paths::fid_db_dirs`] — BOTH the vendored Ghidra databases and mosura's own.
    pub fn for_program(program: &Program) -> FidAnalyzer {
        FidAnalyzer {
            service: FidQueryService::load_matching_all(
                &crate::paths::fid_db_dirs(),
                &program.language_id,
                &program.compiler_spec_id,
            ),
        }
    }

    pub fn with_service(service: FidQueryService) -> FidAnalyzer {
        FidAnalyzer { service }
    }

    pub fn service(&self) -> &FidQueryService {
        &self.service
    }
}

impl Analyzer for FidAnalyzer {
    fn name(&self) -> &str {
        "Function ID"
    }

    fn analysis_type(&self) -> AnalyzerType {
        AnalyzerType::Function
    }

    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::FUNCTION_ID
    }

    /// No attached database ⇒ nothing to say. Ghidra's analyzer likewise does nothing when no
    /// FID database is active.
    fn can_analyze(&self, _program: &Program) -> bool {
        !self.service.is_empty()
    }

    fn added(&self, program: &mut Program, _set: &AddressSet, _sched: &mut Scheduling) -> bool {
        if self.service.is_empty() {
            return false;
        }
        let results = search_program(program, &self.service);

        let mut applied = false;
        for result in results {
            // `ApplyFidEntriesCommand`: never overwrite a name a user or an importer supplied.
            // mosura's symbol model carries no source field, so the test is the practical one —
            // only a default `FUN_xxxxxxxx` name is replaced. A binary that kept its symbols
            // keeps them.
            let Some(function) = program.function_manager.function_at(result.entry) else {
                continue;
            };
            if !is_default_name(function.name()) {
                continue;
            }
            // The plate comment goes on whether or not a name does — `applyMarkup` is called with
            // a null name for an ambiguous match, so "recognised but could not be narrowed" is
            // recorded rather than silently dropped.
            program.comments.insert(
                (result.entry.offset, crate::analysis::program::CommentKind::Plate),
                result.plate.clone(),
            );
            applied = true;
            let Some(name) = result.name.as_deref() else { continue };
            program.function_manager.set_name(result.entry, name);
            program.symbol_table.add_symbol(
                result.entry,
                name,
                crate::analysis::program::symbol::SymbolType::Function,
            );
        }
        applied
    }
}
