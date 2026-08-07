//! `FunctionStartAnalyzer` — a port of
//! `Features/BytePatterns/.../ghidra/app/analyzers/FunctionStartAnalyzer.java` together with its
//! three siblings (`FunctionStartPreFuncAnalyzer`, `FunctionStartPostAnalyzer`,
//! `FunctionStartDataPostAnalyzer`) and the pattern-file lookup in `Patterns.java`.
//!
//! This is the only discovery route in the pipeline that needs **no inbound edge**. Every other
//! pass follows something: a direct call, a shared-return `jmp`, a run of pointers in data, an LE
//! fixup slot. This one recognises a function by the *shape of its prologue bytes*, matching a
//! processor/compiler-specific pattern file
//! (`Processors/<proc>/data/patterns/*.xml`) with the [`bytesearch`](crate::analysis::bytesearch)
//! engine. On WAR2 it is worth 243 functions that nothing else reaches.
//!
//! Ghidra registers the same analyzer four times, differing only in *when* it runs and over
//! *what* set — see [`FunctionStartKind`]. A pattern can carry a pre-requisite ("must follow
//! defined data", "must follow an instruction"), which is false on the first sweep and true once
//! the surrounding program has been laid down; the later passes are what re-check them.
//!
//! # Beyond-Ghidra: the Watcom pattern set
//!
//! `patternconstraints.xml` maps `(language, compiler)` to a pattern file and has **no `watcom`
//! entry** — Ghidra ships no Watcom compiler spec at all. Ghidra only reaches WAR2's prologues
//! because auto-detect labels the warcraft2-re ELF wrapper `gcc`; mosura's loader correctly says
//! `watcom`, so a strictly faithful port would contribute exactly zero here. The
//! `(language, compiler) -> file` lookup below is a faithful port; the *mapping entry* for
//! `watcom`, and the pattern file it names, are mosura's, living in `specs/patterns/` — Ghidra's
//! own extension point (`Application.findModuleSubDirectories("data/patterns")` merges the
//! constraint files of every module, so an added module dir is how Ghidra itself is extended).
//! Their oracle is the warcraft2-re expert tracker, not Ghidra. See `specs/patterns/README.md`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::analysis::analyzer::{Analyzer, AnalyzerType};
use crate::analysis::bytesearch::pattern::{read_patterns, Match, Pattern, PatternFactory};
use crate::analysis::bytesearch::{
    DittedBitSequence, MemoryBytePatternSearcher, SequenceSearchState,
};
use crate::analysis::manager::Scheduling;
use crate::analysis::priority::AnalysisPriority;
use crate::analysis::program::{AddressSet, CodeUnit, Program, RefType, SymbolType};
use crate::analysis::pseudo_disassembler::PseudoDisassembler;
use crate::decompile::space::Address;

/// `FunctionStartAction.MUST_HAVE_VALID_INSTRUCTIONS_NO_MIN` (:203).
const MUST_HAVE_VALID_INSTRUCTIONS_NO_MIN: i32 = -1;
/// `FunctionStartAction.VALID_INSTRUCTIONS_NO_MAX` (:204).
const VALID_INSTRUCTIONS_NO_MAX: i32 = -1;
/// `FunctionStartAction.NO_VALID_INSTRUCTIONS_REQUIRED` (:205).
const NO_VALID_INSTRUCTIONS_REQUIRED: i32 = 0;

/// Longest code unit probed for when asking "is this address inside an existing one"
/// (`getCodeUnitContaining`); mosura's listing is a start-address map, so containment is a
/// bounded backward probe. Matches `analyzers::MAX_CODE_UNIT_LEN`.
const MAX_CODE_UNIT_LEN: u64 = 16;

/// Which of Ghidra's four registrations this instance is. They share `FunctionStartAnalyzer`'s
/// whole body and differ only in name, analyzer type, priority, and which pattern-constraints
/// file they read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FunctionStartKind {
    /// `FunctionStartPreFuncAnalyzer` (:24) — "Function Start Pre Search", a BYTE analyzer at
    /// `BLOCK_ANALYSIS.before()`, driven by `prepatternconstraints.xml`: patterns "better found
    /// before any code is disassembled".
    PreSearch,
    /// `FunctionStartAnalyzer` (:99) — "Function Start Search", a BYTE analyzer at
    /// `CODE_ANALYSIS.after().after()`.
    Search,
    /// `FunctionStartPostAnalyzer` (:24) — "Function Start Search After Code", an INSTRUCTION
    /// analyzer at `DATA_TYPE_PROPOGATION.before().before()`; runs only when some pattern has a
    /// code or data pre-requisite.
    AfterCode,
    /// `FunctionStartDataPostAnalyzer` (:24) — "Function Start Search After Data", a DATA
    /// analyzer at the same priority; runs only when some pattern has a data pre-requisite.
    AfterData,
}

impl FunctionStartKind {
    fn name(self) -> &'static str {
        match self {
            FunctionStartKind::PreSearch => "Function Start Pre Search",
            FunctionStartKind::Search => "Function Start Search",
            FunctionStartKind::AfterCode => "Function Start Search After Code",
            FunctionStartKind::AfterData => "Function Start Search After Data",
        }
    }

    fn analyzer_type(self) -> AnalyzerType {
        match self {
            FunctionStartKind::PreSearch | FunctionStartKind::Search => AnalyzerType::Byte,
            FunctionStartKind::AfterCode => AnalyzerType::Instruction,
            FunctionStartKind::AfterData => AnalyzerType::Data,
        }
    }

    fn priority(self) -> AnalysisPriority {
        match self {
            FunctionStartKind::PreSearch => AnalysisPriority::BLOCK.before(),
            FunctionStartKind::Search => AnalysisPriority::CODE.after().after(),
            FunctionStartKind::AfterCode | FunctionStartKind::AfterData => {
                AnalysisPriority::DATA_TYPE_PROPAGATION.before().before()
            }
        }
    }

    /// `Patterns.DEFAULT_PATTERNCONSTRAINTS_XML` (:32) vs
    /// `FunctionStartPreFuncAnalyzer.initializePatternDecisionTree` (:37).
    fn constraints_file(self) -> &'static str {
        match self {
            FunctionStartKind::PreSearch => "prepatternconstraints.xml",
            _ => "patternconstraints.xml",
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Match actions (FunctionStartAnalyzer's inner classes)
// ---------------------------------------------------------------------------------------------

/// `FunctionStartAction` (:201) — the attributes of a `<funcstart>`/`<possiblefuncstart>` tag.
#[derive(Clone, Debug)]
pub struct FunctionStartAction {
    /// `afterName` (:207) — the required predecessor kind (`function`/`instruction`/`data`/
    /// `pointer`/`defined`).
    after_name: Option<String>,
    /// `validCodeMin` (:208).
    valid_code_min: i32,
    /// `validCodeMax` (:209).
    valid_code_max: i32,
    /// `label` (:210).
    label: Option<String>,
    /// `isThunk` (:211).
    is_thunk: bool,
    /// `noreturn` (:212).
    noreturn: bool,
    /// `sectionNamePattern` (:213) — required memory-block name, as a full-match regex.
    section_name_pattern: Option<regex::Regex>,
    /// `validFunction` (:214) — `validcode="function"`.
    valid_function: bool,
    /// `contiguous` (:215).
    contiguous: bool,
}

impl Default for FunctionStartAction {
    fn default() -> FunctionStartAction {
        FunctionStartAction {
            after_name: None,
            valid_code_min: NO_VALID_INSTRUCTIONS_REQUIRED,
            valid_code_max: VALID_INSTRUCTIONS_NO_MAX,
            label: None,
            is_thunk: false,
            noreturn: false,
            section_name_pattern: None,
            valid_function: false,
            contiguous: true,
        }
    }
}

/// `MatchAction` (MatchAction.java:24) — Ghidra's four implementations, all inner classes of
/// `FunctionStartAnalyzer`, as one enum.
#[derive(Clone, Debug)]
pub enum Action {
    /// `CodeBoundaryAction` (:173) — "there is code here": schedule disassembly, and protect it.
    CodeBoundary,
    /// `FunctionStartAction` (:201) — "a function starts here".
    FunctionStart(Box<FunctionStartAction>),
    /// `PossibleFunctionStartAction` (:683) — "a function *probably* starts here": deferred to
    /// [`PossibleDelayedFunctionCreator`], which re-checks once disassembly has settled.
    PossibleFunctionStart(Box<FunctionStartAction>),
    /// `ContextAction` (:709) — set a context register at the match. mosura's SLEIGH driver takes
    /// one fixed context vector per language (the same accommodation
    /// [`PseudoDisassembler`](crate::analysis::pseudo_disassembler) documents), so this is parsed
    /// and recorded but inert. No x86 pattern file uses `<setcontext>`; it is an ARM/MIPS device.
    SetContext { name: String, value: u64 },
}

/// Parses `<funcstart>`/`<possiblefuncstart>` attributes (`restoreXmlAttributes`, :566) and, as a
/// side effect, records which *kinds* of pre-requisite the file uses — the flags that decide
/// whether the After-Code / After-Data analyzers run at all (:576-589).
#[derive(Default)]
struct Factory {
    /// `hasDataConstraints` (:72).
    has_data_constraints: bool,
    /// `hasCodeConstraints` (:73).
    has_code_constraints: bool,
    /// `hasFunctionStartConstraints` (:74).
    has_function_start_constraints: bool,
}

impl Factory {
    fn restore_xml_attributes(&mut self, el: roxmltree::Node) -> FunctionStartAction {
        let mut a = FunctionStartAction::default();
        for attr in el.attributes() {
            let name = attr.name().to_ascii_lowercase();
            let value = attr.value();
            match name.as_str() {
                "after" => {
                    a.after_name = Some(value.to_string());
                    if value.starts_with("func") || value.starts_with("inst") {
                        self.has_code_constraints = true;
                    } else if value.starts_with("data") || value.starts_with("ptr") {
                        self.has_data_constraints = true;
                    } else if value.starts_with("def") {
                        self.has_code_constraints = true;
                        self.has_data_constraints = true;
                    }
                    // Ghidra logs an error for any other value and leaves the constraint set; the
                    // `checkAfterName` chain then matches none of its arms and passes.
                }
                "validcode" => {
                    if value == "0" || value == "false" {
                        a.valid_code_min = NO_VALID_INSTRUCTIONS_REQUIRED;
                    } else if value.eq_ignore_ascii_case("true")
                        || value.eq_ignore_ascii_case("subroutine")
                    {
                        a.valid_code_min = MUST_HAVE_VALID_INSTRUCTIONS_NO_MIN;
                    } else if value.eq_ignore_ascii_case("function") {
                        a.valid_function = true;
                        self.has_function_start_constraints = true;
                        a.valid_code_min = NO_VALID_INSTRUCTIONS_REQUIRED;
                    } else {
                        a.valid_code_min = value.parse().unwrap_or(NO_VALID_INSTRUCTIONS_REQUIRED);
                    }
                    if a.valid_code_max == VALID_INSTRUCTIONS_NO_MAX {
                        a.valid_code_max = a.valid_code_min;
                    }
                }
                "validcodemax" => {
                    a.valid_code_max = value.parse().unwrap_or(VALID_INSTRUCTIONS_NO_MAX);
                    if a.valid_code_min == NO_VALID_INSTRUCTIONS_REQUIRED {
                        a.valid_code_min = MUST_HAVE_VALID_INSTRUCTIONS_NO_MIN;
                    }
                }
                "contiguous" => a.contiguous = !value.eq_ignore_ascii_case("false"),
                "label" => a.label = Some(value.to_string()),
                "thunk" => a.is_thunk = true,
                // Java `Pattern.matches` is a FULL match, so the anchors are part of the port.
                "section" => a.section_name_pattern = regex::Regex::new(&format!("^(?:{value})$")).ok(),
                "noreturn" => a.noreturn = true,
                _ => {}
            }
        }
        a
    }
}

impl PatternFactory for Factory {
    type Action = Action;

    /// `getMatchActionByName(nm)` (:957).
    fn match_action_by_name(&mut self, node: roxmltree::Node) -> Option<Action> {
        match node.tag_name().name() {
            "funcstart" => {
                Some(Action::FunctionStart(Box::new(self.restore_xml_attributes(node))))
            }
            "possiblefuncstart" => {
                Some(Action::PossibleFunctionStart(Box::new(self.restore_xml_attributes(node))))
            }
            "codeboundary" => Some(Action::CodeBoundary),
            "setcontext" => Some(Action::SetContext {
                name: node.attribute("name").unwrap_or("").to_string(),
                value: node
                    .attribute("value")
                    .and_then(|v| {
                        let t = v.trim();
                        match t.strip_prefix("0x") {
                            Some(h) => u64::from_str_radix(h, 16).ok(),
                            None => t.parse().ok(),
                        }
                    })
                    .unwrap_or(0),
            }),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Pattern file lookup (Patterns.java + the ProgramDecisionTree constraints)
// ---------------------------------------------------------------------------------------------

/// `Application.findModuleSubDirectories("data/patterns")` (Patterns.java:42) — every module's
/// pattern directory. Ghidra walks its installed modules; mosura's equivalents are the SLEIGH
/// processor tree (`<processors>/<proc>/data/patterns`) and its own `specs/patterns`, which is
/// where the beyond-Ghidra Watcom mapping lives (see the module note).
fn pattern_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(rd) = std::fs::read_dir(crate::paths::processors_dir()) {
        let mut procs: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path().join("data/patterns"))
            .filter(|p| p.is_dir())
            .collect();
        procs.sort();
        dirs.extend(procs);
    }
    let mosura = crate::paths::specs_dir().join("patterns");
    if mosura.is_dir() {
        dirs.push(mosura);
    }
    dirs
}

/// `LanguageConstraint.isSatisfied` (LanguageConstraint.java:33) — colon-separated tokens compared
/// pairwise, with `*` matching any one token; both ids must have the same token count.
fn language_matches(constraint: &str, language_id: &str) -> bool {
    let a: Vec<&str> = constraint.split(':').collect();
    let b: Vec<&str> = language_id.split(':').collect();
    a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| *x == "*" || x == y)
}

/// `CompilerConstraint.isSatisfied` (CompilerConstraint.java:26) — `id` is an exact match on the
/// compiler-spec id. (`name`, the `compilerName.contains(program.getCompiler())` arm, needs the
/// program's *toolchain* string, which mosura's `Program` does not carry; no pattern-constraints
/// file in the tree uses it.)
fn compiler_matches(node: roxmltree::Node, compiler_spec_id: &str) -> bool {
    match node.attribute("id") {
        Some(id) => id == compiler_spec_id,
        None => false,
    }
}

/// `Patterns.findPatternFiles(program, decisionTree)` (:73) — the pattern files whose
/// `(language, compiler)` path in the merged decision tree is satisfied by this program.
fn find_pattern_files(program: &Program, constraints_file: &str) -> Vec<PathBuf> {
    let dirs = pattern_dirs();
    let mut names: Vec<String> = Vec::new();
    for dir in &dirs {
        let path = dir.join(constraints_file);
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let Ok(doc) = roxmltree::Document::parse(&text) else { continue };
        for lang in doc.root_element().children().filter(|n| n.is_element()) {
            if lang.tag_name().name() != "language" {
                continue;
            }
            if !language_matches(lang.attribute("id").unwrap_or(""), &program.language_id) {
                continue;
            }
            for comp in lang.children().filter(|n| n.is_element()) {
                match comp.tag_name().name() {
                    "compiler" if compiler_matches(comp, &program.compiler_spec_id) => {
                        for pf in comp.children().filter(|n| n.is_element()) {
                            if pf.tag_name().name() == "patternfile" {
                                if let Some(t) = pf.text() {
                                    names.push(t.trim().to_string());
                                }
                            }
                        }
                    }
                    // A `<patternfile>` directly under `<language>` is the node-level default the
                    // decision tree falls back to when no child constraint matched (DecisionTree
                    // class doc); none of the shipped files use one, but the shape is free.
                    "patternfile" if !lang.children().any(|c| c.is_element() && c.tag_name().name() == "compiler" && compiler_matches(c, &program.compiler_spec_id)) => {
                        if let Some(t) = comp.text() {
                            names.push(t.trim().to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    // `Patterns.getPatternFile(patternDirs, name)` (:88) — first directory that has it wins.
    let mut out = Vec::new();
    for name in names {
        if let Some(p) = dirs.iter().map(|d| d.join(&name)).find(|p| p.is_file()) {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// The analyzer
// ---------------------------------------------------------------------------------------------

/// `FunctionStartAnalyzer` (:47).
pub struct FunctionStartAnalyzer {
    kind: FunctionStartKind,
    patterns: Vec<Pattern<Action>>,
    root: SequenceSearchState,
    /// `executableBlocksOnly` (:67) — the `Search Data Blocks` option's default is `false`, i.e.
    /// executable blocks only (:56, :892).
    executable_blocks_only: bool,
    pdis: Option<PseudoDisassembler>,
}

impl FunctionStartAnalyzer {
    /// Build one registration, or `None` when it does not apply — `canAnalyze` (:765) plus the
    /// subclasses' extra tests (`FunctionStartPostAnalyzer.canAnalyze`:33,
    /// `FunctionStartDataPostAnalyzer.canAnalyze`:33).
    pub fn for_program(program: &Program, kind: FunctionStartKind) -> Option<FunctionStartAnalyzer> {
        let files = find_pattern_files(program, kind.constraints_file());
        if files.is_empty() {
            return None; // `Patterns.hasPatternFiles` is false
        }
        let mut factory = Factory::default();
        let mut patterns: Vec<Pattern<Action>> = Vec::new();
        for f in &files {
            let Ok(text) = std::fs::read_to_string(f) else { continue };
            if let Err(e) = read_patterns(&text, &mut patterns, &mut factory) {
                // Ghidra `readPatterns` (:938) logs and returns null — the analyzer is disabled.
                eprintln!("mosura: pattern file error ({}): {e}", f.display());
                return None;
            }
        }
        if patterns.is_empty() {
            return None; // `initialize` (:929)
        }
        match kind {
            FunctionStartKind::AfterCode => {
                if !factory.has_code_constraints && !factory.has_data_constraints {
                    return None;
                }
            }
            FunctionStartKind::AfterData => {
                if !factory.has_data_constraints {
                    return None;
                }
            }
            _ => {}
        }
        let mut seqs: Vec<DittedBitSequence> = patterns.iter().map(|p| p.seq.clone()).collect();
        let root = SequenceSearchState::build_state_machine(&mut seqs);
        Some(FunctionStartAnalyzer {
            kind,
            patterns,
            root,
            executable_blocks_only: true,
            pdis: PseudoDisassembler::for_program(program),
        })
    }
}

/// The analyzer's running state (`funcResult`/`potentialFuncResult`/… , :81-86). Ghidra keeps
/// these as mutable analyzer fields and comments that "these should go away after analysis"; here
/// they are a local of one `added` call, which is what that comment asks for.
#[derive(Default)]
struct RunState {
    /// `funcResult` (:81) — discovered function starts.
    func_result: AddressSet,
    /// `potentialFuncResult` (:82).
    potential_func_result: AddressSet,
    /// `disassemResult` (:83).
    disassem_result: AddressSet,
    /// `codeLocations` (:84).
    code_locations: AddressSet,
    /// `postreqFailedResult` (:85).
    postreq_failed_result: AddressSet,
}

impl Analyzer for FunctionStartAnalyzer {
    fn name(&self) -> &str {
        self.kind.name()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.kind.analyzer_type()
    }
    fn priority(&self) -> AnalysisPriority {
        self.kind.priority()
    }

    /// `added(program, set, monitor, log)` (:795).
    fn added(&self, program: &mut Program, set: &AddressSet, sched: &mut Scheduling) -> bool {
        refresh_function_bodies(program);
        let mut st = RunState::default();
        // `checkForExecuteBlock(program) && executableBlocksOnly` (:807).
        let has_execute = program.memory.blocks().any(|b| b.is_execute());
        let mut searcher = MemoryBytePatternSearcher::new(&self.root, &self.patterns);
        searcher.set_search_executable_only(has_execute && self.executable_blocks_only);

        let pdis = self.pdis.as_ref();
        searcher.search(program, Some(set), &mut |program, addr, m: &Match<Action>| {
            for action in &m.pattern.actions {
                apply_action(action, program, addr, &mut st, pdis);
            }
        });

        // :836-844 — disassemble known function starts now, delay the possible ones. Both are
        // `analysisManager.disassemble(...)`, i.e. a scheduled `DisassembleCommand`; Ghidra's
        // split only changes *when* within the queue, and mosura has one disassembly command.
        //
        // The thread-local dedupe that used to stand here is RETIRED. It existed because this
        // request was raised as `code_defined`, which re-notified the `Instruction`-typed
        // `AfterCode`/`AfterData` registrations — including on a `codeboundary` match over bytes
        // that never decode, which was therefore re-proposed on every re-entry forever (measured
        // on WAR2: `AfterCode` re-running indefinitely at ~22ms a turn, always
        // `disasm=375 funcs=4`). A command is delivered to the disassembler and echoes nothing
        // back to the requester, so the cycle has no driver left to hold off.
        if !st.disassem_result.is_empty() {
            sched.disassemble(&st.disassem_result);
        }
        // :846 `setProtectedLocations(codeLocations)` — mosura has no analyzer that clears code,
        // so there is nothing to protect it from; the set is still computed above so the port
        // stays structurally complete.
        let _ = &st.code_locations;

        if !st.potential_func_result.is_empty() {
            // :848 — a pattern may have said this is definitely a function start, so it is not
            // "potential" any more.
            let potential = st.potential_func_result.subtract(&st.func_result);
            // :853 — kick off a later analyzer to create the functions after the fallout from
            // disassembly has settled.
            //
            // The `PROPOSED` thread-local that used to stand here is RETIRED for the same reason
            // as `SCHEDULED` above: the delayed creator's work re-triggered this
            // `Instruction`-typed pass, which proposed the same addresses again, in a lockstep
            // ping-pong (measured on `fnpattern.watcom-x86-32`: 570,619 invocations each of
            // "Function Start Search delayed" and "Function Start Search After Code" in 15
            // seconds, against 6 of Disassembly). The creator's own :1006 guard — "a function
            // containing the potential start appeared during analysis" — is what makes a
            // re-proposal a no-op once the function exists, and that guard only works when the
            // function was actually created and its bytes decoded, which is exactly what the
            // command route now delivers.
            if !potential.is_empty() {
                sched.schedule_one_time(PossibleDelayedFunctionCreator::NAME, &potential);
            }
        }

        if !st.func_result.is_empty() {
            // :857 — `analysisManager.createFunction(funcResult, false)`.
            create_functions(program, &st.func_result, sched);
        }
        true
    }
}

/// Apply one match action (the `apply` methods of the four inner classes).
fn apply_action(
    action: &Action,
    program: &mut Program,
    addr: Address,
    st: &mut RunState,
    pdis: Option<&PseudoDisassembler>,
) {
    match action {
        // `CodeBoundaryAction.apply` (:176).
        Action::CodeBoundary => match code_unit_containing(program, addr) {
            CuKind::UndefinedData => {
                st.disassem_result.add(addr);
                st.code_locations.add(addr);
            }
            CuKind::Instruction => st.code_locations.add(addr),
            CuKind::DefinedData => {}
            CuKind::None => {}
        },
        // `FunctionStartAction.apply` (:218).
        Action::FunctionStart(a) => {
            if !check_pre_requisites(a, program, addr, st, pdis) {
                return;
            }
            let mut result = std::mem::take(&mut st.func_result);
            apply_action_to_set(a, program, addr, &mut result, st);
            st.func_result = result;
        }
        // `PossibleFunctionStartAction.apply` (:685).
        Action::PossibleFunctionStart(a) => {
            if !check_pre_requisites(a, program, addr, st, pdis) {
                return;
            }
            let mut result = std::mem::take(&mut st.potential_func_result);
            apply_action_to_set(a, program, addr, &mut result, st);
            st.potential_func_result = result;
        }
        // `ContextAction.apply` (:723) — see [`Action::SetContext`].
        Action::SetContext { .. } => {}
    }
}

/// What `Listing.getCodeUnitContaining(addr)` returns, reduced to the three cases the actions
/// distinguish. Ghidra's listing yields an *undefined* `Data` unit for any mapped byte that has
/// nothing defined at it, which is the "nothing here yet" case.
enum CuKind {
    Instruction,
    DefinedData,
    UndefinedData,
    None,
}

fn code_unit_containing(program: &Program, addr: Address) -> CuKind {
    if !program.memory.contains(addr) {
        return CuKind::None;
    }
    match program.listing.code_unit_containing(addr, MAX_CODE_UNIT_LEN) {
        Some((start, _)) => match program.listing.code_unit_at(start) {
            Some(CodeUnit::Instruction { .. }) => CuKind::Instruction,
            Some(CodeUnit::Data { .. }) => CuKind::DefinedData,
            None => CuKind::UndefinedData,
        },
        None => CuKind::UndefinedData,
    }
}

/// `FunctionStartAction.checkPreRequisites(program, addr)` (:229).
fn check_pre_requisites(
    a: &FunctionStartAction,
    program: &Program,
    addr: Address,
    st: &mut RunState,
    pdis: Option<&PseudoDisassembler>,
) -> bool {
    // :231 — required section name.
    if let Some(re) = &a.section_name_pattern {
        match program.memory.block_at(addr) {
            None => return false,
            Some(b) => {
                if !re.is_match(b.name()) {
                    return false;
                }
            }
        }
    }

    // :247 — `validcode="function"`: there must already be a function here.
    //
    // NOT PORTED, and why: Ghidra also drops an `AddressSetPropertyMap` breadcrumb here (:252) so
    // that `FunctionStartFuncAnalyzer` — a fifth registration, at `FUNCTION_ANALYSIS.before()
    // .before()` — can re-check only these addresses once functions exist. Every shipped
    // `validcode="function"` pattern (the six x86 `__i686.get_pc_thunk.*` entries) does nothing
    // but apply a LABEL: `applyActionToSet` reaches an instruction that is already in a function,
    // so it adds nothing to any result set. The omission therefore cannot change the function set,
    // only the naming of six gcc PIC thunks.
    if a.valid_function && program.function_manager.function_at(addr).is_none() {
        st.postreq_failed_result.add(addr);
        return false;
    }

    if !check_after_name(a, program, addr) {
        st.postreq_failed_result.add(addr);
        return false;
    }

    // :263 — do we require some number of valid instructions?
    if a.valid_code_min != 0 {
        let Some(pd) = pdis else { return false };
        // Ghidra constructs a fresh `PseudoDisassembler` here (:264), so the bound starts at the
        // default; mosura shares one instance, so it is set on every path.
        pd.set_max_instructions(if a.valid_code_max > 0 {
            a.valid_code_max as usize
        } else {
            crate::analysis::pseudo_disassembler::DEFAULT_MAX_INSTRUCTIONS
        });
        if a.valid_code_min == MUST_HAVE_VALID_INSTRUCTIONS_NO_MIN {
            // :274 — follow branches too, and the flow must terminate.
            return pd.check_valid_subroutine(program, addr, true, true, a.contiguous).0;
        }
        // :281 — disassemble only fall-through; must reach `validCodeMin` instructions.
        let (mut isvalid, instr_count) =
            pd.check_valid_subroutine(program, addr, true, false, a.contiguous);
        if (instr_count as i32) < a.valid_code_min {
            isvalid = false;
        }
        return isvalid;
    }

    true
}

/// `FunctionStartAction.applyActionToSet(program, addr, resultSet, match)` (:293).
fn apply_action_to_set(
    a: &FunctionStartAction,
    program: &mut Program,
    addr: Address,
    result_set: &mut AddressSet,
    st: &mut RunState,
) {
    // :296 — `addr.getOffset() % language.getInstructionAlignment()`. mosura's SLEIGH layer does
    // not surface `instructionAlignment`; every language that ships a pattern file is x86, whose
    // alignment is 1, so the test is exact here and would need the field only for a future
    // fixed-width-instruction pattern set.
    let alignment: u64 = 1;
    if !addr.offset.is_multiple_of(alignment) {
        return;
    }

    let func_containing = program.function_manager.function_containing(addr).map(|f| f.entry_point());

    match code_unit_containing(program, addr) {
        CuKind::UndefinedData => {
            st.disassem_result.add(addr);
            st.code_locations.add(addr);
            result_set.add(addr);
        }
        CuKind::Instruction => {
            if func_containing.is_none() {
                // :317 — could this already be in a function, or part of another code flow?
                if !check_already_in_function_above(program, addr) {
                    result_set.add(addr);
                }
            }
            st.code_locations.add(addr);
        }
        CuKind::DefinedData | CuKind::None => {}
    }

    // :331 — make the function non-returning.
    if let Some(entry) = func_containing {
        if a.noreturn {
            program.noreturn_functions.insert((entry.space.0, entry.offset));
        }
        // :335 `CreateThunkFunctionCmd` — no pattern file in the tree sets `thunk="…"`, and
        // mosura has no thunk model, so this arm is recorded rather than executed.
        let _ = a.is_thunk;
    }

    // :342 — the pattern wants a name here, make it.
    if let Some(label) = &a.label {
        set_function_label(program, addr, label);
    }
}

/// `setFunctionLabel(program, addr, labelStr)` (:354).
fn set_function_label(program: &mut Program, addr: Address, label: &str) {
    if program.symbol_table.symbols_at(addr).any(|s| s.name().contains(label)) {
        return;
    }
    program.symbol_table.add_with_primary(addr, label, SymbolType::Label, true);
}

/// `checkAfterName(program, addr)` (:383) — "check that this pattern occurs after something
/// defined".
fn check_after_name(a: &FunctionStartAction, program: &Program, addr: Address) -> bool {
    let Some(name) = &a.after_name else { return true };
    if addr.offset == 0 {
        return true; // `addr.previous() == null`
    }
    let addr_to_check = Address::new(addr.space, addr.offset - 1);
    // :389 — the previous address is not in memory, so `addr` must be at the start of a block.
    if !program.memory.contains(addr_to_check) {
        return true;
    }
    // :394 — or this is the start of a defined memory block.
    match program.memory.block_at(addr) {
        None => return true,
        Some(b) => {
            if b.start() == addr {
                return true;
            }
        }
    }

    if name.starts_with("func") {
        // :403 — if this place is already in a function, we shouldn't start one.
        let Some(func_above) = function_above(program, addr) else { return false };
        !check_already_in_function_above_with(program, addr, Some(func_above))
    } else if name.starts_with("inst") {
        matches!(code_unit_containing(program, addr_to_check), CuKind::Instruction)
    } else if name.starts_with("data") {
        matches!(code_unit_containing(program, addr_to_check), CuKind::DefinedData)
    } else if name.starts_with("ptr") {
        pure_data_references_only(program, addr)
    } else if name.starts_with("def") {
        match code_unit_containing(program, addr_to_check) {
            CuKind::Instruction => !check_already_in_function_above(program, addr),
            CuKind::DefinedData => true,
            _ => pure_data_references_only(program, addr),
        }
    } else {
        true
    }
}

/// `pureDataReferencesOnly(program, addrToCheck)` (:458).
fn pure_data_references_only(program: &Program, addr: Address) -> bool {
    let mut any = false;
    for r in program.reference_manager.refs_to(addr) {
        any = true;
        let t = r.ref_type;
        if t.is_flow() {
            return false;
        }
        if matches!(t, RefType::Read | RefType::Write) {
            return false;
        }
        if t == RefType::Data {
            continue;
        }
        return false;
    }
    any
}

/// `getFunctionAbove(program, addr)` (:540) — the function containing `addr - 1`.
fn function_above(program: &Program, addr: Address) -> Option<Address> {
    if addr.offset == 0 {
        return None;
    }
    program
        .function_manager
        .function_containing(Address::new(addr.space, addr.offset - 1))
        .map(|f| f.entry_point())
}

/// `checkAlreadyInFunctionAbove(program, addr)` (:485).
fn check_already_in_function_above(program: &Program, addr: Address) -> bool {
    let above = function_above(program, addr);
    check_already_in_function_above_with(program, addr, above)
}

/// `checkAlreadyInFunctionAbove(program, addr, funcAbove)` (:494) — true when `addr` is already
/// part of the function immediately above it. Being in a *different* function is deliberately
/// not enough: that is the shape of a shared return, i.e. a genuine separate function.
fn check_already_in_function_above_with(
    program: &Program,
    addr: Address,
    func_above: Option<Address>,
) -> bool {
    if addr.offset == 0 {
        return false; // `addrBefore == null`
    }
    let addr_before = Address::new(addr.space, addr.offset - 1);
    if let Some(above) = func_above {
        return program
            .function_manager
            .function_containing(addr)
            .is_some_and(|f| f.entry_point() == above);
    }

    // :512 — no function above, but an instruction that FALLS THROUGH into here makes this part
    // of that flow, not a start. Ghidra:
    //
    //     Instruction instr = getListing().getInstructionContaining(addrBefore);
    //     if (instr != null && addr.equals(instr.getFallThrough())) { return true; }
    //
    // ⚠️ The fall-through test is the whole rule, and this port used to omit it — it vetoed on
    // ADJACENCY, i.e. on any instruction merely *ending* at `addr`. `getFallThrough()` is null
    // after a `ret`, so Ghidra does not veto a prologue that follows an epilogue and mosura did.
    // Measured on WAR2: 6 tracker functions sit immediately after a `pop…pop; ret` with no
    // function recognised above them, were proposed by the pattern set, and were refused here.
    // The comment above this code already said "falls through"; the code did not implement it.
    // Same drift class as `falls_through`'s own creation: a decision stated once and re-derived
    // incorrectly elsewhere, which is why this consults the shared helper rather than restating.
    if let Some((start, len)) = program.listing.code_unit_containing(addr_before, MAX_CODE_UNIT_LEN)
    {
        if matches!(program.listing.code_unit_at(start), Some(CodeUnit::Instruction { .. }))
            && start.offset + len == addr.offset
            && instruction_falls_through(program, start)
        {
            return true;
        }
    }
    // :517 — any reference to here other than a pure (non-read/write) data reference means some
    // other flow already owns this location.
    for r in program.reference_manager.refs_to(addr) {
        let t = r.ref_type;
        if t.is_data() && !matches!(t, RefType::Read | RefType::Write) {
            continue;
        }
        return true;
    }
    false
}


/// Does the instruction at `start` fall through — Ghidra's `Instruction.getFallThrough() != null`.
///
/// The listing stores only a length, so the instruction is re-decoded to ask. Conservative on
/// failure: an instruction we cannot decode is treated as falling through, which preserves the
/// previous (over-strict) refusal rather than inventing a new function on a decode failure.
fn instruction_falls_through(program: &Program, start: Address) -> bool {
    let Some((spec, ctx)) = crate::lang::load_cached(&program.language_id) else { return true };
    let window = program.memory.read_window(start, MAX_CODE_UNIT_LEN as usize);
    match spec.disassemble_ctx(&window, start.offset, ctx).into_iter().next() {
        Some(insn) => super::falls_through(program, start, &insn, start.space),
        None => true,
    }
}

// ---------------------------------------------------------------------------------------------
// Function creation (CreateFunctionCmd)
// ---------------------------------------------------------------------------------------------

/// `CreateFunctionCmd.applyTo` (CreateFunctionCmd.java:148) for a set of entry points, with
/// `findEntryPoint=false`.
///
/// The ascending iteration (:158 `origEntries.getAddresses(true)`) and the
/// `OverlappingFunctionException` at :380 together give a property this port depends on: when two
/// patterns fire inside one function — the true entry and, a few bytes in, the `push ebp;
/// mov ebp,esp` the Watcom save-first prologue also contains — the LOWER address is created first,
/// its computed body covers the higher one, and the second creation is REFUSED because Ghidra's
/// listing forbids overlapping function bodies. mosura's `FunctionManager` has no such invariant,
/// so the rule is applied explicitly here: an entry that falls inside a body created earlier in
/// this same command is skipped.
fn create_functions(program: &mut Program, entries: &AddressSet, sched: &mut Scheduling) {
    let ram = program.default_space;
    let starts: Vec<u64> =
        entries.ranges().flat_map(|r| r.min..=r.max).collect::<BTreeSet<u64>>().into_iter().collect();
    let mut known: BTreeSet<u64> =
        program.function_manager.functions().map(|f| f.entry_point().offset).collect();
    let mut created = AddressSet::new();
    let mut bodies = AddressSet::new();
    for off in starts {
        let addr = Address::new(ram, off);
        if !program.memory.contains(addr) {
            continue;
        }
        // The overlapping-body refusal (see the doc comment).
        if bodies.contains(addr) {
            continue;
        }
        // Only a function this command actually creates counts as created. Ghidra's command
        // raises `functionAdded` per created function (`CreateFunctionCmd.applyTo` counts
        // `didCreate`); reporting an already-existing entry as new instead re-triggers every
        // FUNCTION analyzer, whose `codeDefined` re-triggers this analyzer, forever.
        if program.function_manager.function_at(addr).is_some() {
            known.insert(off);
            bodies = bodies.union(&flow_body(program, addr, &known));
            continue;
        }
        let name = format!("FUN_{off:08x}");
        program.function_manager.create_function(addr, &name, AddressSet::new());
        if !program.symbol_table.has_symbol_at(addr) {
            program.symbol_table.add_with_primary(addr, &name, SymbolType::Function, true);
        }
        known.insert(off);
        bodies = bodies.union(&flow_body(program, addr, &known));
        created.add(addr);
    }
    if !created.is_empty() {
        // The new functions still need disassembly + the follow-on function analyzers, which is
        // what `functionDefined` drives (mosura's `FunctionCreator` re-seeds the disassembler).
        sched.function_defined(&created);
    }
}

/// The address set an entry's flow covers — `CreateFunctionCmd`'s automatic body computation,
/// using the same intra-function walk as
/// [`compute_function_bodies`](super::compute_function_bodies): fall-through plus branch targets,
/// never calls, stopping at another function's entry.
fn flow_body(program: &Program, entry: Address, entries: &BTreeSet<u64>) -> AddressSet {
    use crate::decompile::opcode::OpCode;
    let mut body = AddressSet::new();
    // `load_cached`, not `load`: the uncached one re-reads and re-parses the whole `.sla` on
    // every call, and this runs once per proposed function start.
    let Some((spec, ctx)) = crate::lang::load_cached(&program.language_id) else {
        body.add(entry);
        return body;
    };
    let ram = program.default_space;
    let mut visited: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut work = vec![entry.offset];
    while let Some(a) = work.pop() {
        if !visited.insert(a) {
            continue;
        }
        if a != entry.offset && entries.contains(&a) {
            continue;
        }
        let window = program.memory.read_window(Address::new(ram, a), MAX_CODE_UNIT_LEN as usize);
        let Some(insn) = spec.disassemble_ctx(&window, a, ctx).into_iter().next() else { continue };
        let ilen = insn.bytes.len() as u64;
        if ilen == 0 {
            continue;
        }
        body.add_range(ram, a, a + ilen - 1);
        // The one definition of Ghidra's `Instruction.getFallThrough()` — see `falls_through`.
        let falls = super::falls_through(program, Address::new(ram, a), &insn, ram);
        for op in &insn.ops {
            if matches!(OpCode::from_u32(op.opcode), Some(OpCode::Branch | OpCode::Cbranch)) {
                if let Some(crate::sleigh::pcode::PArg::Var(v)) = op.ins.first() {
                    if v.space == "ram" && v.offset != a {
                        work.push(v.offset);
                    }
                }
            }
        }
        // …and the flow references, which is how a computed jump's cases are reached. Shares
        // `super::follows_flow_ref` with `compute_function_bodies` rather than restating Ghidra's
        // `dontFollow` set a second time — these two walks have drifted apart before.
        // …and the flow references, which is how a computed jump's cases are reached. Shares
        // `super::follows_flow_ref` with `compute_function_bodies` rather than restating Ghidra's
        // `dontFollow` set a second time — these two walks have drifted apart before.
        for r in program.reference_manager.refs_from(Address::new(ram, a)) {
            if super::follows_flow_ref(r.ref_type) && r.to.space == ram && r.to.offset != a {
                work.push(r.to.offset);
            }
        }
        if falls {
            work.push(a + ilen);
        }
    }
    if body.is_empty() {
        body.add(entry);
    }
    body
}

thread_local! {
    /// Function count at the last body refresh; `usize::MAX` = "no refresh yet this run".
    static BODIES_FRESH_AT: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
}

/// Reset this analyzer's per-run memos. Called once per analysis run, so a fresh program never
/// inherits the previous program's state (the harness analyses many programs per thread).
pub fn reset_body_refresh_memo() {
    BODIES_FRESH_AT.with(|c| c.set(usize::MAX));
}

/// Bring every function's body up to date before asking `getFunctionContaining`.
///
/// **Why this exists.** In Ghidra a function's body is computed when the function is created and
/// is therefore always current; `FunctionStartAction.applyActionToSet` (:302) and
/// `PossibleDelayedFunctionCreator` (:1007) both lean on `getFunctionContaining` to refuse a
/// proposal that lands *inside* a function that already exists — which is what stops the
/// `push ebp; mov ebp,esp` inside a Watcom save-first prologue from becoming a second entry a few
/// bytes into every such function. mosura computes bodies once, after the whole worklist has
/// converged (`analyze` -> `compute_function_bodies`), so during analysis every body is EMPTY and
/// that guard silently never fires.
///
/// Measured, not assumed. On `fnpattern.watcom-x86-32`, Ghidra creates one extra entry
/// (`08048136`, the orphan's `55`) and refuses `lead_fn_+5`, `trail_fn_+5` and `main_+5` because
/// each is inside an existing function; mosura created all four. On `dispatch.gcc-m68k` and
/// `tables.gcc-m68k` Ghidra's function set is IDENTICAL with the Function Start Search analyzers
/// on and off, while mosura gained 3 and 8 entries. (`compgoto.gcc-m68k` is the case where Ghidra
/// really does gain three — 2 functions with the search off, 5 with it on — so that one is a
/// Ghidra property, not a port defect.)
/// **Memoized on the function count.** `compute_function_bodies` walks every function and
/// re-derives its body, so it is O(all functions). This runs at the top of every `added()`, and
/// each pass that creates functions provokes another `added()` — on a large program that is
/// quadratic (WAR2: ~1965 functions re-walked per call). Ghidra has no such call at all: its
/// bodies are maintained incrementally as code units are created, so this refresh is mosura's
/// own bookkeeping and skipping a redundant one changes no Ghidra-visible behaviour.
///
/// Bodies here can only go stale when the function *set* changes: within the search the only
/// mutations are function creation (`create_functions`) and scheduled disassembly, and the latter
/// is applied by the manager's disassembly pass, which recomputes bodies itself. So a refresh is
/// needed exactly when the count has moved since the last one. The marker is thread-local, which
/// is also the correct granularity — the test harness analyses different programs on different
/// threads.
fn refresh_function_bodies(program: &mut Program) {
    let n = program.function_manager.functions().count();
    if BODIES_FRESH_AT.with(|c| c.get()) == n {
        return;
    }
    if let Some((spec, ctx)) = crate::lang::load_cached(&program.language_id) {
        super::compute_function_bodies(spec, ctx, program);
    }
    BODIES_FRESH_AT.with(|c| c.set(n));
}

/// `PossibleDelayedFunctionCreator` (FunctionStartAnalyzer.java:987) — "one time analyzer used to
/// delay function creation until disassembly has settled". A `possiblefuncstart` match only
/// *proposes* a start; this pass, running after data analysis, drops any proposal that turned out
/// to be referenced conditionally or to lie inside a function that meanwhile appeared.
pub struct PossibleDelayedFunctionCreator;

impl PossibleDelayedFunctionCreator {
    pub const NAME: &'static str = "Function Start Search delayed";
}

impl Analyzer for PossibleDelayedFunctionCreator {
    fn name(&self) -> &str {
        PossibleDelayedFunctionCreator::NAME
    }
    fn analysis_type(&self) -> AnalyzerType {
        // Ghidra schedules this one explicitly (`scheduleOneTimeAnalysis`, :854) rather than
        // subscribing it to a program-change channel.
        AnalyzerType::OneTime
    }
    fn priority(&self) -> AnalysisPriority {
        // `AnalysisPriority.DATA_ANALYSIS.after()` (:990).
        AnalysisPriority::DATA.after()
    }

    /// `added(addedProgram, addedSet, …)` (:994).
    fn added(&self, program: &mut Program, set: &AddressSet, sched: &mut Scheduling) -> bool {
        refresh_function_bodies(program);
        let ram = program.default_space;
        let mut function_starts = AddressSet::new();
        for off in set.ranges().flat_map(|r| r.min..=r.max).collect::<BTreeSet<u64>>() {
            let address = Address::new(ram, off);
            // :1001 — if there are any conditional references, then this can't be a function start.
            if program.reference_manager.refs_to(address).any(|r| {
                matches!(r.ref_type, RefType::ConditionalJump | RefType::ConditionalCall)
            }) {
                continue;
            }
            // :1006 — a function containing the potential start appeared during analysis.
            if let Some(f) = program.function_manager.function_containing(address) {
                let _ = f; // (Ghidra bookmarks the overlap; mosura has no bookmark model.)
                continue;
            }
            function_starts.add(address);
        }
        // :1022 — `new CreateFunctionCmd(functionStarts, false).applyTo(...)`.
        if !function_starts.is_empty() {
            create_functions(program, &function_starts, sched);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_constraint_tokenises_and_wildcards() {
        assert!(language_matches("x86:LE:32:default", "x86:LE:32:default"));
        assert!(!language_matches("x86:LE:64:default", "x86:LE:32:default"));
        assert!(language_matches("x86:LE:32:*", "x86:LE:32:default"));
        // Token counts must agree — a prefix is not a match.
        assert!(!language_matches("x86:LE:32", "x86:LE:32:default"));
    }

    /// The pattern-file lookup must resolve for the two configurations this track turns on:
    /// x86-32 + `gcc` (the faithful Ghidra mapping, which the ground-truth Watcom ELF column
    /// lands on) and x86-32 + `watcom` (mosura's own mapping, which WAR2 lands on).
    #[test]
    fn pattern_files_resolve_for_x86_32() {
        use crate::decompile::space::{SpaceKind, SpaceManager};
        let mk = |cspec: &str| {
            let mut spaces = SpaceManager::standard();
            let ram = spaces.add("ram", SpaceKind::Processor, 4, 1);
            Program::new(
                spaces,
                ram,
                "x86:LE:32:default",
                cspec,
                Address::new(ram, 0x1000),
                false,
                32,
            )
        };
        let gcc = find_pattern_files(&mk("gcc"), "patternconstraints.xml");
        assert_eq!(
            gcc.iter().map(|p| p.file_name().unwrap().to_string_lossy().to_string()).collect::<Vec<_>>(),
            vec!["x86gcc_patterns.xml"],
            "the faithful (x86:LE:32:default, gcc) -> x86gcc_patterns.xml mapping must resolve"
        );
        let watcom = find_pattern_files(&mk("watcom"), "patternconstraints.xml");
        assert_eq!(
            watcom
                .iter()
                .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
                .collect::<Vec<_>>(),
            vec!["x86watcom_patterns.xml"],
            "mosura's beyond-Ghidra (x86:LE:32:default, watcom) mapping must resolve"
        );
    }

    /// Every function-start address a pattern file proposes for one byte sequence.
    fn marks(file: &std::path::Path, bytes: &[u8]) -> BTreeSet<u64> {
        let text = std::fs::read_to_string(file).unwrap();
        let mut factory = Factory::default();
        let mut pats: Vec<Pattern<Action>> = Vec::new();
        read_patterns(&text, &mut pats, &mut factory).unwrap();
        let mut seqs: Vec<DittedBitSequence> = pats.iter().map(|p| p.seq.clone()).collect();
        let machine = SequenceSearchState::build_state_machine(&mut seqs);
        let mut hits = Vec::new();
        machine.apply(bytes, bytes.len(), &mut hits);
        hits.iter()
            .filter(|h| {
                pats[h.seq_index].actions.iter().any(|a| {
                    matches!(a, Action::FunctionStart(_) | Action::PossibleFunctionStart(_))
                })
            })
            .map(|h| h.offset + pats[h.seq_index].mark_offset as u64)
            .collect()
    }

    /// THE PROLOGUE SHIFT, and the property the Watcom pattern set exists for.
    ///
    /// The bytes are WAR2's `FUN_00016ed4` verbatim (`53 51 52 56 57 55 89 e5 83 ec 04 …` — push
    /// ebx/ecx/edx/esi/edi, push ebp, mov ebp,esp, sub esp,4), preceded by the previous function's
    /// `ret`. Watcom's save-first prologue puts a run of register saves BEFORE the frame setup;
    /// `x86gcc_patterns.xml`'s `0x5589e583ec` anchors at the `55`, i.e. **five bytes past the true
    /// entry**. Verified against the real image for all 104 shifted entries Ghidra reports on
    /// WAR2: 104/104, distances 1-5, no exceptions.
    ///
    /// The assertion is a differential on the two real, committed pattern files — it fails if the
    /// Watcom file loses its push-run family, or if the mark lands anywhere but the first push.
    #[test]
    fn save_first_prologue_marks_the_first_push() {
        let bytes = [
            0xc3, // the previous function's RET
            0x53, 0x51, 0x52, 0x56, 0x57, // push ebx/ecx/edx/esi/edi   <- the true entry, +1
            0x55, 0x89, 0xe5, // push ebp ; mov ebp,esp                 <- +6
            0x83, 0xec, 0x04, // sub esp,4
            0x89, 0xc3, 0x31, 0xd2, // mov ebx,eax ; xor edx,edx
        ];
        let gcc = crate::paths::processors_dir().join("x86/data/patterns/x86gcc_patterns.xml");
        let watcom = crate::paths::specs_dir().join("patterns/x86watcom_patterns.xml");

        let g = marks(&gcc, &bytes);
        assert!(
            !g.contains(&1),
            "x86gcc_patterns.xml unexpectedly marks the true entry — the whole premise of the \
             Watcom pattern set is that it does not"
        );
        assert!(
            g.contains(&6),
            "x86gcc_patterns.xml must anchor at the `55` (5 bytes late); got {g:?}"
        );

        let w = marks(&watcom, &bytes);
        assert!(
            w.contains(&1),
            "the Watcom pattern set must mark the FIRST PUSH — the true entry; got {w:?}"
        );
        assert_eq!(
            w.iter().copied().min(),
            Some(1),
            "and it must be the LOWEST proposal, because `create_functions` resolves overlapping \
             proposals in favour of the lowest address; got {w:?}"
        );
    }

    /// WATCOM'S PUSH ORDER IS PART OF THE SPEC — the save-first family accepts a subsequence of
    /// `ebx ecx edx esi edi` and nothing else.
    ///
    /// The measured invariant (warcraft2-re's census of WAR2's 1317 save-first functions: 1317
    /// conforming, 0 nonconforming; independently reproduced by Watcom 10.0a under `-od` and by
    /// Open Watcom v2 in `wprologue.watcom-x86-32`) is a property of the *pattern file*, and the
    /// ground-truth fixtures cannot see it: `wprologue` and `fnpattern` are both built `-of+`, so
    /// their prologues are frame-FIRST and this family never fires on them. This is its gate.
    #[test]
    fn save_first_family_enforces_watcoms_push_order() {
        /// `ebx ecx edx esi edi` — the order Watcom's codegen emits saves in.
        const ORDER: [u8; 5] = [0x53, 0x51, 0x52, 0x56, 0x57];
        let watcom = crate::paths::specs_dir().join("patterns/x86watcom_patterns.xml");
        // `c3` (the previous function's ret) then the run, then the frame setup; the entry is +1.
        let probe = |run: &[u8], mov: &[u8]| -> BTreeSet<u64> {
            let mut bytes = vec![0xc3u8];
            bytes.extend_from_slice(run);
            bytes.push(0x55);
            bytes.extend_from_slice(mov);
            bytes.extend_from_slice(&[0x83, 0xec, 0x04, 0x89, 0xc3, 0x31, 0xd2]);
            marks(&watcom, &bytes)
        };

        // RECALL — all 31 non-empty ordered subsequences, in both encodings of `mov ebp,esp`.
        for mov in [&[0x89u8, 0xe5][..], &[0x8b, 0xec][..]] {
            for mask in 1u32..32 {
                let run: Vec<u8> =
                    (0..5).filter(|i| mask & (1 << i) != 0).map(|i| ORDER[i]).collect();
                assert!(
                    probe(&run, mov).contains(&1),
                    "conforming save run {run:02x?} + {mov:02x?} must mark the first push"
                );
            }
        }

        // PRECISION (a) — reordering never occurs, so a reordered run is not a prologue.
        for run in [
            &[0x51u8, 0x53][..],       // ecx before ebx
            &[0x52, 0x51][..],         // edx before ecx
            &[0x56, 0x52][..],         // esi before edx
            &[0x57, 0x56][..],         // edi before esi
            &[0x53, 0x52, 0x51][..],   // ebx edx ecx
            &[0x57, 0x53, 0x51][..],   // edi first
        ] {
            assert!(
                !probe(run, &[0x89, 0xe5]).contains(&1),
                "reordered run {run:02x?} must NOT mark a function start"
            );
        }

        // PRECISION (b) — only the five callee-saves appear in the run. The old `01010...` form
        // also admitted eax (0x50), esp (0x54) and a second ebp (0x55).
        for run in [&[0x50u8, 0x53][..], &[0x54, 0x53][..], &[0x55, 0x53][..], &[0x53, 0x50][..]] {
            assert!(
                !probe(run, &[0x89, 0xe5]).contains(&1),
                "run {run:02x?} contains a non-callee-save push and must NOT mark a start"
            );
        }

        // PRECISION (c) — the run never exceeds 5, because there are only five callee-saves
        // besides EBP. A 6-push run necessarily repeats or leaves the set, so it cannot match;
        // the conforming 5-run one byte in still does, and `create_functions` picks the lowest
        // match, so the extra byte does not silently move an entry.
        let six = probe(&[0x53, 0x53, 0x51, 0x52, 0x56, 0x57], &[0x89, 0xe5]);
        assert!(!six.contains(&1), "a 6-push run must NOT mark a function start; got {six:?}");
        assert!(six.contains(&2), "the conforming 5-run inside it must still mark; got {six:?}");
    }

    /// THE BARE FRAME-FIRST PROLOGUE — a frame setup with **no `sub esp`**, which is 81% of
    /// WAR2's framed functions (save-first 891 without / 426 with, frame-first 187 / 52).
    ///
    /// The Watcom file originally took two of `x86gcc_patterns.xml`'s six frame-first patterns —
    /// the two that require `sub esp`. The four left behind are precisely the bare shape. This
    /// pins all six, in both encodings of `mov ebp,esp`, and pins the two boundaries of the
    /// family: the push pair obeys Watcom's save order, and a *naked* `0x5589e5` is still not a
    /// pattern (no Ghidra x86 file states one; it would be an unmeasurable invention).
    ///
    /// Like [`save_first_family_enforces_watcoms_push_order`], no ground-truth fixture can see
    /// this: every function in them is reachable by a call or by family (4)'s filler pairing, so
    /// their recall and precision are identical with and without these patterns.
    #[test]
    fn frame_first_family_covers_the_bare_prologue() {
        let watcom = crate::paths::specs_dir().join("patterns/x86watcom_patterns.xml");
        // `5b` (pop ebx) is deliberately NOT one of family (4)'s prepatterns, so nothing here is
        // matched by the filler pairing and every hit is the frame-first family's own doing.
        let probe = |tail: &[u8], mov: &[u8]| -> BTreeSet<u64> {
            let mut bytes = vec![0x5bu8, 0x55];
            bytes.extend_from_slice(mov);
            bytes.extend_from_slice(tail);
            marks(&watcom, &bytes)
        };

        for mov in [&[0x89u8, 0xe5][..], &[0x8b, 0xec][..]] {
            // x86gcc #1/#2 — with `sub esp` (the two this file already had).
            assert!(probe(&[0x83, 0xec, 0x10], mov).contains(&1), "#1 sub esp,imm8");
            assert!(probe(&[0x81, 0xec, 0x40, 0x06, 0x00, 0x00], mov).contains(&1), "#2 imm32");
            // x86gcc #3/#4 — `sub esp` one or two bytes later. NEW.
            assert!(probe(&[0x53, 0x83, 0xec, 0x10], mov).contains(&1), "#3 one byte then sub");
            assert!(probe(&[0x53, 0x51, 0x83, 0xec, 0x10], mov).contains(&1), "#4 two then sub");
            // x86gcc #5 — frame, then two register saves, NO `sub esp`. NEW, and the shape
            // `wprologue` itself emits (`55 89 e5 56 57`, `55 89 e5 53 51`).
            assert!(probe(&[0x56, 0x57, 0x8b, 0x45, 0xfc], mov).contains(&1), "#5 esi,edi");
            assert!(probe(&[0x53, 0x51, 0x8b, 0x45, 0xfc], mov).contains(&1), "#5 ebx,ecx");
            // x86gcc #6 — frame, then a frame-relative load, NO `sub esp`. NEW.
            assert!(probe(&[0x8b, 0x45, 0xfc], mov).contains(&1), "#6 mov r32,[ebp+disp8]");
            // #5 obeys Watcom's save order here too — the saves AFTER a frame setup are the same
            // rigid sequence as the ones before it (measured on both `-of+` fixtures).
            assert!(
                !probe(&[0x57, 0x56, 0x8b, 0x45, 0xfc], mov).contains(&1),
                "a reordered save pair (edi before esi) must not mark a frame-first start"
            );
        }

        // THE RESIDUAL, pinned deliberately. A frame setup followed by ordinary code, with no
        // recognised filler before it, is NOT matched — `55 89 e5 40` (inc eax) and
        // `55 89 e5 e8` (call) both occur in `wprologue`. Covering them needs a naked 24-bit
        // `0x5589e5`, which no Ghidra x86 pattern file states. If that ever changes, change this
        // assertion deliberately rather than discovering the over-match on a real binary.
        for tail in [&[0x40u8, 0x89, 0xec, 0x5d, 0xc3][..], &[0xe8, 0x74, 0xfe, 0xff, 0xff][..]] {
            let m = probe(tail, &[0x89, 0xe5]);
            assert!(
                !m.contains(&1),
                "a naked `55 89 e5` followed by {tail:02x?} is matched — the frame-first family \
                 has grown a 24-bit pattern; got {m:?}"
            );
        }
    }

    /// THE ABOVE-FUNCTION GUARD TESTS FALL-THROUGH, NOT ADJACENCY (`checkAlreadyInFunctionAbove`
    /// :512) — the local gate for `be85c85`, whose only gate until now was a WAR2 run.
    ///
    /// Ghidra:
    ///
    /// ```java
    /// Instruction instr = getListing().getInstructionContaining(addrBefore);
    /// if (instr != null && addr.equals(instr.getFallThrough())) { return true; }
    /// ```
    ///
    /// `getFallThrough()` is null after a `ret`, so an epilogue immediately followed by the next
    /// function's prologue is NOT a veto. This port vetoed on mere adjacency and so refused every
    /// pattern-only function that begins one byte past a `c3` — 6 tracker functions on WAR2.
    ///
    /// THE ARM UNDER TEST IS THE `funcAbove == None` ONE. When a function *is* recognised above,
    /// the first arm returns `function_containing(addr) == above` and this code never runs; the
    /// third case below pins that, so the test cannot silently drift onto the other arm.
    ///
    /// Both signs are asserted: `ret` must not veto, `nop` (which does fall through) must.
    #[test]
    fn above_guard_vetoes_on_fall_through_not_on_adjacency() {
        use crate::analysis::program::FunctionManager;
        use crate::decompile::space::{SpaceKind, SpaceManager};
        if crate::lang::load("x86:LE:32:default").is_none() {
            return;
        }
        // `<one byte of preceding instruction> | 53 83 ec 10 …` — the orphan entry is base+1.
        let build = |last: u8| {
            let mut spaces = SpaceManager::standard();
            let ram = spaces.add("ram", SpaceKind::Processor, 4, 1);
            let base = Address::new(ram, 0x40_1000);
            let mut p = Program::new(spaces, ram, "x86:LE:32:default", "watcom", base, false, 32);
            let code = vec![last, 0x53, 0x83, 0xec, 0x10, 0x5b, 0xc3];
            p.memory.add_block(".text", base, code.len() as u64, true, false, true, Some(code));
            // The preceding byte is a DECODED instruction that is in no function — the state the
            // address-table analyzer leaves behind (it disassembles a pointer target and
            // deliberately creates no function there).
            p.listing.define(base, CodeUnit::Instruction { length: 1 });
            (p, ram, Address::new(ram, 0x40_1001))
        };

        // `c3` = RET. Its fall-through is null, so Ghidra does not veto.
        let (p, _ram, orphan) = build(0xc3);
        assert!(
            !check_already_in_function_above_with(&p, orphan, None),
            "a RET above must NOT veto a function start — `getFallThrough()` is null after it"
        );

        // `90` = NOP. It really does fall through into `addr`, so Ghidra vetoes.
        let (p, _ram, orphan) = build(0x90);
        assert!(
            check_already_in_function_above_with(&p, orphan, None),
            "a NOP above DOES fall through into the address, so the guard must still veto — \
             the fix must not have deleted the rule"
        );

        // The other arm: with a function recognised above, `funcAbove` decides and the
        // fall-through test is never consulted. `addr` is not in that function, so no veto.
        let (mut p, ram, orphan) = build(0x90);
        let above = Address::new(ram, 0x40_1000);
        p.function_manager = FunctionManager::new();
        p.function_manager.create_function(above, "above", AddressSet::new());
        assert!(
            !check_already_in_function_above_with(&p, orphan, Some(above)),
            "with a function above, the guard asks only whether `addr` is inside THAT function"
        );
    }

    /// The same defect at the ANALYZER level, on the path WAR2 actually took: a
    /// `funcstart after="defined"` pattern (family (3) of `x86watcom_patterns.xml`, the ESP-frame
    /// family) whose predecessor is a decoded `ret` belonging to no function.
    ///
    /// `checkAfterName`'s `"defined"` arm (:437) reaches `checkAlreadyInFunctionAbove` whenever the
    /// byte before the candidate is an instruction, so the pre-requisite itself is what the
    /// adjacency bug rejected — the candidate never even had to be disassembled first. That is the
    /// shape the previous fixture attempt (`retboundary`) could not reach: it needed the preceding
    /// block DECODED but NOT a function, which is exactly what `AddressTableAnalyzer` produces
    /// (`AddressTableAnalyzer.java:282` "For Now, Never make functions from address tables") and
    /// what a single-entry pointer table never triggers.
    ///
    /// Layout — a leaf reached only through data, then the orphan one byte later:
    ///
    /// ```text
    /// 401000  8b 44 24 04     mov  eax,[esp+4]     leaf, decoded, in NO function
    /// 401004  6b c0 0b        imul eax,eax,11      (matches no pattern in the file)
    /// 401007  c3              ret                  <- ends exactly at the orphan
    /// 401008  53              push ebx             <- THE ORPHAN. Family (3) pattern
    /// 401009  83 ec 10        sub  esp,0x10           `0x5. 0x83 0xec … 100010.1 01...100
    /// 40100c  89 44 24 04     mov  [esp+4],eax         ..100100 0.....00`, after="defined"
    /// ```
    #[test]
    fn after_defined_start_survives_a_ret_that_belongs_to_no_function() {
        use crate::analysis::manager::Scheduling;
        use crate::decompile::space::{SpaceKind, SpaceManager};
        if crate::lang::load("x86:LE:32:default").is_none() {
            return;
        }
        let build = |last: u8| {
            let mut spaces = SpaceManager::standard();
            let ram = spaces.add("ram", SpaceKind::Processor, 4, 1);
            let base = Address::new(ram, 0x40_1000);
            let mut p = Program::new(spaces, ram, "x86:LE:32:default", "watcom", base, false, 32);
            #[rustfmt::skip]
            let code = vec![
                0x8b, 0x44, 0x24, 0x04,       // mov eax,[esp+4]
                0x6b, 0xc0, 0x0b,             // imul eax,eax,11
                last,                         // ret (or nop, for the twin)
                // --- the orphan, at +8 ---
                0x53,                         // push ebx
                0x83, 0xec, 0x10,             // sub esp,0x10
                0x89, 0x44, 0x24, 0x04,       // mov [esp+4],eax
                0x89, 0x44, 0x24, 0x08,       // mov [esp+8],eax
                0x8b, 0x44, 0x24, 0x04,       // mov eax,[esp+4]
                0x83, 0xc4, 0x10,             // add esp,0x10   (>= validcode="6" by here)
                0x5b,                         // pop ebx
                0xc3,                         // ret
            ];
            let len = code.len() as u64;
            p.memory.add_block(".text", base, len, true, false, true, Some(code));
            // The leaf, decoded and in no function — `AddressTableAnalyzer`'s output shape.
            p.listing.define(base, CodeUnit::Instruction { length: 4 });
            p.listing.define(Address::new(ram, 0x40_1004), CodeUnit::Instruction { length: 3 });
            p.listing.define(Address::new(ram, 0x40_1007), CodeUnit::Instruction { length: 1 });
            let mut set = AddressSet::new();
            set.add_range(ram, base.offset, base.offset + len - 1);
            (p, ram, set)
        };

        let run = |last: u8| -> bool {
            reset_body_refresh_memo();
            let (mut p, ram, set) = build(last);
            let a = FunctionStartAnalyzer::for_program(&p, FunctionStartKind::AfterCode)
                .expect("the watcom pattern file must resolve for (x86:LE:32:default, watcom)");
            let mut sched = Scheduling::default();
            a.added(&mut p, &set, &mut sched);
            p.function_manager.function_at(Address::new(ram, 0x40_1008)).is_some()
        };

        assert!(
            run(0xc3),
            "an ESP-frame prologue one byte past a RET must become a function — the RET does not \
             fall through, so `checkAlreadyInFunctionAbove` must not veto its `after=\"defined\"`"
        );
        assert!(
            !run(0x90),
            "one byte past a NOP the SAME prologue must still be refused: that instruction really \
             does fall through into it, so it is part of that flow, not a new function"
        );
    }

    /// The overlap rule that makes a family of shifted-by-one push-run patterns safe to state.
    /// A 5-push prologue matches the 5-push pattern at the entry, the 4-push pattern one byte in,
    /// and so on; `CreateFunctionCmd` iterates ascending and Ghidra's listing refuses a function
    /// whose body overlaps an existing one, so exactly one function is created, at the lowest
    /// address. Without this, every save-first function would come back as up to five functions.
    #[test]
    fn create_functions_keeps_only_the_lowest_of_overlapping_entries() {
        use crate::analysis::manager::Scheduling;
        use crate::decompile::space::{SpaceKind, SpaceManager};
        if crate::lang::load("x86:LE:32:default").is_none() {
            return;
        }
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 4, 1);
        let base = Address::new(ram, 0x40_1000);
        let mut p =
            Program::new(spaces, ram, "x86:LE:32:default", "watcom", base, false, 32);
        // push ebx; push ecx; push ebp; mov ebp,esp; sub esp,4; mov ebp,esp... ; leave; ret
        let code =
            vec![0x53, 0x51, 0x55, 0x89, 0xe5, 0x83, 0xec, 0x04, 0x31, 0xc0, 0xc9, 0xc3];
        p.memory.add_block(".text", base, code.len() as u64, true, false, true, Some(code));

        let mut entries = AddressSet::new();
        entries.add(base); // the true entry
        entries.add(Address::new(ram, 0x40_1001)); // the 1-push pattern, one byte in
        entries.add(Address::new(ram, 0x40_1002)); // the frame-first pattern, two bytes in
        let mut sched = Scheduling::default();
        create_functions(&mut p, &entries, &mut sched);

        let got: Vec<u64> =
            p.function_manager.functions().map(|f| f.entry_point().offset).collect();
        assert_eq!(got, vec![0x40_1000], "only the lowest entry may become a function");
    }


}
