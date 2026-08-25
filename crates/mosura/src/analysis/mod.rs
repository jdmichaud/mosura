//! The **auto-analysis port** (A0+; plan `docs/analysis-port-plan.md`).
//!
//! A faithful port of Ghidra's auto-analysis — the subsystem that takes a binary
//! *file* and decides *what to decompile*: loaders, the priority-worklist analyzer
//! framework, disassembly + function discovery, references + `SymbolicPropogator`,
//! and the decompiler-driven switch/parameter analyzers. Distinct from the
//! decompiler port (`crate::decompile`), which works on one already-located
//! function.
//!
//! **A0 (this module today): the oracle contract + harness only.** [`snapshot`]
//! defines the canonical converged-`Program` view captured from Ghidra and
//! committed under `goldens/analysis/`; [`analyze_binary`] is the entry point
//! mosura's analyzers will implement, returning [`Unimplemented`] until A1–A4
//! land. `tests/analysis_parity.rs` holds the red baseline against the goldens.

pub mod interface;
pub mod analyzer;
pub mod analyzers;
pub mod bytesearch;
pub mod codegen_fingerprint;
pub mod cspec;
pub mod decompiler;
pub mod fid;
pub mod flowtype;
pub mod loader;
pub mod manager;
pub mod overrides;
pub mod priority;
pub mod program;
pub mod pseudo_disassembler;
pub mod repeat_instruction;
pub mod scope;
pub mod snapshot;
pub mod symbolic;

pub use program::Program;
pub use snapshot::Snapshot;

use std::path::Path;

/// An error from [`analyze_binary`].
#[derive(Debug)]
pub enum AnalysisError {
    Io(std::io::Error),
    Load(loader::LoadError),
}
impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalysisError::Io(e) => write!(f, "io: {e}"),
            AnalysisError::Load(e) => write!(f, "load: {e}"),
        }
    }
}
impl std::error::Error for AnalysisError {}
impl From<std::io::Error> for AnalysisError {
    fn from(e: std::io::Error) -> Self {
        AnalysisError::Io(e)
    }
}
impl From<loader::LoadError> for AnalysisError {
    fn from(e: loader::LoadError) -> Self {
        AnalysisError::Load(e)
    }
}

/// Run mosura's auto-analysis over a binary file and produce its converged
/// [`Snapshot`], to be diffed against the Ghidra golden.
///
/// Returns the **loader-stage** snapshot (memory map + loader functions/entries/symbols),
/// the state the loader-detail goldens are captured at. The auto-analysis passes
/// ([`analyze`]) run separately and produce a converged state that A4–A7 will gate against
/// their own goldens (A4's partial analysis matches no converged golden yet).
pub fn analyze_binary(path: &Path) -> Result<Snapshot, AnalysisError> {
    let data = std::fs::read(path)?;
    let program = loader::load_path(path, &data)?;
    Ok(program.snapshot())
}

/// Load a binary and run the full auto-analysis pipeline ([`analyze`]), returning the
/// converged [`Program`].
pub fn analyze_file(path: &Path) -> Result<Program, AnalysisError> {
    let data = std::fs::read(path)?;
    let mut program = loader::load_path(path, &data)?;
    analyze(&mut program);
    Ok(program)
}

/// Load and analyse a binary, **declaring** its x86-32 compiler spec instead of detecting it.
///
/// # Why this exists — detection cannot answer for a freestanding binary
///
/// `loader::watcom::compiler_spec_id` decides `watcom` vs `gcc` from the C run-time's copyright
/// banner, which is the only in-band evidence an ELF32 i386 carries: a `wcc386 -bt=linux` image is
/// header-identical to a gcc one. The ground-truth corpus links `option nodefaultlib` with a
/// hand-written `_cstart_`, so **its binaries contain no such evidence and detection correctly
/// reports `gcc`**. That is a property of the fixtures, not a defect in detection — no amount of
/// improving the detector can recover a fact the file does not contain.
///
/// What the corpus *does* have is its **build-derived truth**: `oracle/ground-truth/*.truth`
/// carries a `compiler` field written by `build.sh` from the recipe that produced the binary,
/// never hand-authored. So the corpus declares the compiler from the build rather than asking the
/// image, and this is the entry point that lets it.
///
/// Not a test-only hook: declaring a known compiler spec is a legitimate thing for any caller with
/// out-of-band knowledge (a build system, a project file, a user override). The switch is scoped
/// to this call on this thread — see [`overrides`] for why that matters.
pub fn analyze_file_as(path: &Path, x86_32_cspec: Option<&str>) -> Result<Program, AnalysisError> {
    let _guard = overrides::force_x86_32_cspec(x86_32_cspec);
    analyze_file(path)
}

/// Load a DOS/4GW-bound Linear Executable via the **native LE loader** and run the full
/// auto-analysis pipeline over its 32-bit objects — the opt-in `--le` path for a bound exe
/// (docs/le-loader-notes.md). The default container dispatch ([`analyze_file`]) keeps a bound
/// exe on the Ghidra-parity MZ-stub path; this is the two-oracle native-LE view, validated
/// against the warcraft2-re RE ground truth (Ghidra has no LE loader). The CLI flag + warning
/// that select this land later with the CLI; today it is a library entry point.
pub fn analyze_le_file(path: &Path) -> Result<Program, AnalysisError> {
    let data = std::fs::read(path)?;
    // Same compiler-version refinement as every `loader::load` path — LE is Watcom's home
    // container (the one with no header version field), so the banner-era marker matters most here.
    let mut program = loader::with_compiler_version(&data, loader::load_le(&data)?);
    analyze(&mut program);
    Ok(program)
}

/// The beyond-Ghidra container loaders, in the order [`analyze_native_file`] tries them.
///
/// One list rather than one entry point per format. Adding a container Ghidra cannot open then
/// touches this line and nothing else, and the eventual CLI gets a single `--native` flag with a
/// single warning path instead of a flag per format.
///
/// Each entry is `(name, claims, load)`. `claims` must be strict: a container that guesses wrong
/// is worse than one that declines, because the caller's fallback is the Ghidra-parity view,
/// which is always correct even when it is only the 16-bit stub.
type NativeLoader = (&'static str, fn(&[u8]) -> bool, fn(&[u8]) -> Result<Program, loader::LoadError>);
const NATIVE_LOADERS: &[NativeLoader] = &[
    ("LE", |d| loader::detect_le(d).is_some(), loader::load_le),
    ("X-32", loader::is_x32_image, loader::load_x32),
];

/// Load a binary with the **native** (beyond-Ghidra) loader that claims it, and run the full
/// auto-analysis pipeline. The opt-in half of the two-oracle policy
/// (`docs/le-loader-notes.md`, `docs/x32-loader-notes.md`): the default dispatch
/// ([`analyze_file`]) keeps a DOS-extender-bound executable on the Ghidra-parity MZ-stub path,
/// while this view loads the real 32-bit image and is validated against the container's own
/// metadata, since Ghidra has no loader to diff against.
///
/// Returns the first loader that claims the file. `Unsupported` when none does — deliberately,
/// so a caller asking for the native view of a file that has none is told, rather than silently
/// handed the stub.
pub fn analyze_native_file(path: &Path) -> Result<Program, AnalysisError> {
    let data = std::fs::read(path)?;
    for (_name, claims, load) in NATIVE_LOADERS {
        if claims(&data) {
            let mut program = loader::with_compiler_version(&data, load(&data)?);
            analyze(&mut program);
            return Ok(program);
        }
    }
    Err(AnalysisError::Load(loader::LoadError::Unsupported(
        "no native (beyond-Ghidra) loader claims this file; the default dispatch handles it".into(),
    )))
}

/// Which native loader claims `data`, without loading it — for a CLI that wants to warn that the
/// default view does not cover the file's real content.
pub fn native_loader_name(data: &[u8]) -> Option<&'static str> {
    NATIVE_LOADERS.iter().find(|(_, claims, _)| claims(data)).map(|(n, _, _)| *n)
}

/// Run the auto-analysis pipeline over a loaded [`Program`] (A3 framework + A4 analyzers):
/// recursive-descent disassembly from the loader's functions and entry points, creating
/// code units and discovering functions at call targets, to a fixpoint.
pub fn analyze(program: &mut Program) {
    use crate::analysis::manager::AutoAnalysisManager;
    use crate::analysis::program::AddressSet;

    // A7 Task 3: flag the known non-returning library functions (exit/abort/longjmp/…) by
    // name before disassembly, so a direct call to one stops linear fall-through (Ghidra
    // NoReturnFunctionAnalyzer, FORMAT_ANALYSIS — before disassembly). Faithful name lists
    // from Ghidra's data/ElfFunctionsThatDoNotReturn + PEFunctionsThatDoNotReturn.
    analyzers::function_start::reset_body_refresh_memo();
    analyzers::noreturn::analyze(program);

    let mut mgr = AutoAnalysisManager::new();
    // No Disassembler is registered — Ghidra has no such analyzer. Disassembly happens only
    // through `Scheduling::disassemble`, a scheduled `DisassembleCommand` that the queue
    // executes regardless of what is registered (AutoAnalysisManager.java:1128, :860).
    //
    // `FunctionCreator` IS registered, but as the `function_defined` CONSUMER that turns the
    // loader's entry-point seed below into functions; `Scheduling::create_function` commands
    // execute from the queue without consulting this registration.
    mgr.add_analyzer(Box::new(analyzers::FunctionCreator::new(program)), program);
    if let Some(cp) = analyzers::ConstantPropagationAnalyzer::for_program(program) {
        mgr.add_analyzer(Box::new(cp), program);
    }
    // A6: decompiler-driven switch recovery (COMPUTED_JUMP refs from recovered jump tables).
    mgr.add_analyzer(Box::new(analyzers::switch::DecompilerSwitchAnalyzer::new(program)), program);
    // A6: external-jump flow override — a PLT tail-call `jmp *[GOT]` into the EXTERNAL block
    // becomes COMPUTED_CALL_TERMINATOR (Ghidra OperandReferenceAnalyzer.checkForExternalJump).
    mgr.add_analyzer(Box::new(analyzers::external_jump::ExternalJumpAnalyzer::new()), program);
    // "Non-Returning Functions - Discovered" (Ghidra `FindNoReturnFunctionsAnalyzer`, an
    // INSTRUCTION_ANALYZER at `DISASSEMBLY.after()`). Distinct from `analyzers::noreturn`, which
    // is the *Known* one and matches library names; this one infers non-return from the shape of
    // the disassembly after each call. Inside the manager loop, as in Ghidra: its indicators want
    // functions and references, which arrive on later rounds of the same fixpoint.
    if let Some(nr) = analyzers::find_noreturn::FindNoReturnFunctionsAnalyzer::for_program(program) {
        mgr.add_analyzer(Box::new(nr), program);
    }
    // Address tables — runs of pointers in data whose targets are code (Ghidra
    // AddressTableAnalyzer, a BYTE_ANALYZER at DATA_TYPE_PROPOGATION.before()). It creates no
    // function; it disassembles the pointed-to code, and the call targets *inside* that code
    // become functions the ordinary way. This is the only route into a subgraph whose sole
    // inbound edges are DATA references (war2-survey/analysis-gap/REPORT.md §7).
    if let Some(at) = analyzers::address_table::AddressTableAnalyzer::for_program(program) {
        mgr.add_analyzer(Box::new(at), program);
    }
    // BEYOND-GHIDRA (oracle: the warcraft2-re tracker + the `lestruct` ground-truth MVE, never
    // Ghidra, which cannot do this): seed disassembly at the loader's relocation targets. The
    // LE->ELF conversion Ghidra is fed bakes in the patched values and discards the fixup
    // records, so an isolated code pointer stored between non-pointer struct fields is invisible
    // to any run-of-pointers heuristic but named exactly by the fixup table. Runs AFTER the
    // address-table analyzer and adds only seeds it did not produce.
    if let Some(rs) = analyzers::relocation_seed::RelocationSeedAnalyzer::for_program(program) {
        mgr.add_analyzer(Box::new(rs), program);
    }
    // Seed disassembly from the loader's functions + entry points. Entry points are
    // filtered to executable memory here (Ghidra `createEntryFunction`'s `isExecute`
    // check — a data export like `__bss_start` is not a function); call targets found
    // during disassembly are *not* gated this way (Ghidra makes a function at every
    // direct call target, even one pointing into data).
    // ⭐ U1 of the manager unification: the PLT sweep runs BEFORE the fixpoint, as Ghidra
    // disassembles the PLT during LOAD (`ElfProgramBuilder.processGotPlt` →
    // `ElfDefaultGotPltMarkup.processLinkageTable`) — before any analyzer sees the program.
    // This is what lets `SharedReturnAnalyzer` run INSIDE the one manager at its faithful
    // priority: its precondition (PLT stubs decoded when PLT functions are created) becomes a
    // load-order fact instead of a staged-pass ordering constraint. The sweep drives
    // `mgr.run` itself, so its decode fall-out reaches the registered analyzers exactly as
    // before — just first.
    plt_linear_sweep(&mut mgr, program);

    let mut seed = AddressSet::new();
    for f in program.function_manager.functions() {
        let e = f.entry_point();
        seed.add_range(e.space, e.offset, e.offset);
    }
    for e in &program.entry_points {
        if program.memory.block_at(*e).is_some_and(|b| b.is_execute()) {
            seed.add_range(e.space, e.offset, e.offset);
        }
    }
    // A NOTIFICATION, correctly: the loader has already created these functions (the set is built
    // from `function_manager.functions()` above), so this is Ghidra's `functionDefined` for
    // loader-created functions. The entry points that are NOT yet functions are created by
    // `FunctionCreator` when it receives this same set.
    //
    // The INSTRUCTION analyzers — constant propagation, the external-jump override, the decompiler
    // switch analyzer — are not fed from here and must not be: they consume the decoded EXTENT
    // (Ghidra `codeDefined`), which the disassembler raises once `FunctionCreator` has scheduled
    // these entries for decoding. Handing them entry points is the defect this seeding used to
    // paper over.
    mgr.scheduling().function_defined(&seed);
    // Seed the BYTE analyzers with the loaded blocks — Ghidra's `AutoAnalysisManager.blockAdded`
    // fires for every block the loader lays down, which is how a BYTE_ANALYZER like
    // `AddressTableAnalyzer` gets the whole image as its "added" set.
    let mut blocks = AddressSet::new();
    for b in program.memory.blocks() {
        blocks.add_range(b.start().space, b.start().offset, b.end().offset);
    }
    mgr.scheduling().block_added(&blocks);
    mgr.run(program);

    // Re-run the no-return analysis now that functions and references exist. The call above
    // happens before disassembly, which is right for flagging *symbols* but leaves
    // `analyze`'s PLT-thunk propagation dead: that loop walks
    // `function_manager.functions()`, and at that point there are none. So a
    // `call <plt stub>` — which is how every call to a dynamically-imported `abort`/`exit`
    // actually looks — saw an unflagged target and kept falling through. Ghidra has no such
    // gap: `NoReturnFunctionAnalyzer` runs at FUNCTION_ANALYSIS priority, after functions
    // exist, and a thunk inherits its thunked function's no-return via `Function.isThunk`.
    // Runs before `compute_function_bodies` so the body walk sees the completed set.
    analyzers::noreturn::analyze(program);

    // Compute function bodies once disassembly has converged (Ghidra `Function.getBody`).
    if let Some((spec, ctx)) = crate::lang::load_cached(&program.language_id) {
        analyzers::compute_function_bodies(spec, ctx, program);
    }

    // A7 Task 2: GCC exception-frame analysis — the `.eh_frame_hdr` FDE table's INDIRECTION
    // (function start) + DATA (FDE) references (Ghidra GccExceptionAnalyzer →
    // EhFrameHeaderSection → FdeTable).
    analyzers::eh_frame::analyze(program);

    // A7 Task 1: shared-return tail calls (Ghidra SharedReturnAnalyzer + SharedReturnAnalysisCmd).
    // Still STAGED, deliberately — the LAST link of the manager unification, not the second:
    // an in-manager registration at the faithful 398 priority was measured to create a
    // spurious `128bc` on war2 MZ, because SR is the most sequence-sensitive consumer and
    // mosura's main-phase cascade order still differs from Ghidra's until call-following
    // lands (which itself waits on no-return detection parity). Order of the campaign:
    // pattern-phase unification → call-following → THEN this pass moves in-manager.
    shared_return_pass(program);

    // Function Start Search — Ghidra's byte-pattern function discovery: the only route that needs
    // NO inbound edge to a function, since it recognises a prologue by its bytes. Registered four
    // times, once per pipeline point (`FunctionStartAnalyzer` + its Pre/AfterCode/AfterData
    // subclasses). Each is `None` when no pattern file matches the program's (language, compiler),
    // so this is inert wherever Ghidra ships no patterns.
    //
    // **Ordering is load-bearing and must stay AFTER `shared_return_pass`.** Ghidra runs
    // `SharedReturnAnalyzer` at `CODE_ANALYSIS.before().before()` (SharedReturnAnalyzer.java:70)
    // and `FunctionStartAnalyzer` at `CODE_ANALYSIS.after().after()`
    // (FunctionStartAnalyzer.java:111) — shared-return strictly first. That is not incidental: it
    // is what puts PLT[0] in a function before the pattern scan, so the scan's "already inside a
    // function" guard (FunctionStartAnalyzer.java:403) rejects a match at PLT[0]+6. mosura defers
    // the PLT sweep and the shared-return scan out of the manager loop (see their notes above), so
    // running the pattern scan inside that loop inverts Ghidra's order and creates a spurious
    // function mid-PLT-stub — `basic.elf` 0x401026, caught by `analysis_parity`'s 0-spurious gate.
    let mut fs_mgr = AutoAnalysisManager::new();
    let mut any = false;
    for kind in [
        analyzers::function_start::FunctionStartKind::PreSearch,
        analyzers::function_start::FunctionStartKind::Search,
        analyzers::function_start::FunctionStartKind::AfterCode,
        analyzers::function_start::FunctionStartKind::AfterData,
    ] {
        if let Some(fs) = analyzers::function_start::FunctionStartAnalyzer::for_program(program, kind)
        {
            fs_mgr.add_analyzer(Box::new(fs), program);
            any = true;
        }
    }
    if any {
        // The command executors are built into the queue itself: `FunctionStartAnalyzer` asks
        // the manager to disassemble its matches and create its functions (:836-859, through
        // `AutoAnalysisManager.getAnalysisManager(program)` — a per-program SINGLETON, :949),
        // and a scheduled command executes REGARDLESS of what is registered
        // (AutoAnalysisManager.java:860, :752). Before the queue port these requests were
        // routed to analyzers registered by name, and while the executors were absent from
        // this manager every request the pattern search made was silently dropped:
        // `function_defined` reached ZERO consumers, so a pattern-discovered function was
        // never disassembled, never constant-propagated, and its callees were never
        // discovered — `docs/function-discovery-backlog.md` §9, gated by
        // `ground_truth_parity::recovered_functions_are_in_the_listing`. The delayed creator
        // rides inside its one-shot command (FunctionStartAnalyzer.java:853-854), never
        // registered.
        //
        // `FunctionCreator` is registered as the `function_defined` CONSUMER: it re-issues
        // disassembly for functions the pattern passes create inline.
        fs_mgr.add_analyzer(Box::new(analyzers::FunctionCreator::new(program)), program);
        // In Ghidra's ONE manager, code the pattern phase decodes re-triggers
        // `FindNoReturnFunctionsAnalyzer` like any other extent; mosura's second manager was
        // dropping those notifications, so a no-return dispatcher whose CALLERS are only
        // reached in this phase (war2's `13a56` inline-parameter family — its callers and
        // sibling functions all materialize here) was never examined and the repair never
        // ran. Registered here, its indicators see this phase's decoded extents WITH this
        // phase's functions in place.
        if let Some(nr) = analyzers::find_noreturn::FindNoReturnFunctionsAnalyzer::for_program(program)
        {
            fs_mgr.add_analyzer(Box::new(nr), program);
        }
        // Ghidra's `AutoAnalysisManager.blockAdded` fires for every loader block — that is how a
        // BYTE_ANALYZER gets the whole image as its "added" set.
        let mut fs_blocks = AddressSet::new();
        for b in program.memory.blocks() {
            fs_blocks.add_range(b.start().space, b.start().offset, b.end().offset);
        }
        fs_mgr.scheduling().block_added(&fs_blocks);
        fs_mgr.run(program);
        if let Some((spec, ctx)) = crate::lang::load_cached(&program.language_id) {
            analyzers::compute_function_bodies(spec, ctx, program);
        }
        // ⛔ NO SHARED-RETURN EVENT IS DELIVERED FOR THIS BLOCK'S FUNCTIONS — 47815f9 REVERTED.
        //
        // Ghidra does raise `functionDefined` for every created function
        // (`handleFunctionAddedOrBodyChanged` -> `functionTasks.notifyAdded`,
        // AutoAnalysisManager.java:392-395, :280-290) and `SharedReturnAnalyzer` is on that list,
        // so a delivery here is the right SHAPE. Delivering it as ONE batch of everything this
        // block created is not, and it produced a spurious function on the WAR2 MZ image:
        // `pe_mz_convergence_parity` failed with `war2: spurious functions vs Ghidra: [1d74e]`.
        //
        // WHAT WAS MEASURED (task #11), so this is not re-derived from scratch next time:
        //   * Ghidra's golden has NO function at 1d74e because 1d74e is INTERIOR to FUN_0001d76a:
        //     `fnbody 0001d76a 0001d74e:0001d790` — the body MIN is below its own entry. The
        //     `EB C0` at 1d78c is intra-function flow, and Ghidra keeps `ref 0001d78c 0001d74e
        //     UNCONDITIONAL_JUMP` un-retyped.
        //   * mosura's body for 1d76a at scan time is `1d74e:1d790` — BYTE-IDENTICAL to Ghidra's.
        //     The body walk is faithful; so are `build_jump_scan_set`, the cursors,
        //     `checkIfCouldHaveFallThruTo` (nothing falls into 1d74e: a 25-byte hole precedes it)
        //     and the create path. Every component checks out against the Java.
        //   * The set delivered here contained BOTH 1d76a and 1d7b5. `checkBelowFunction(1d76a)`
        //     deletes its single-range body from `jumpScanSet` (SharedReturnAnalysisCmd.java:327),
        //     removing 1d78c — and then `checkAboveFunction(1d7b5)` adds
        //     `[prevFunction.entry, 1d7b5]` = `[1d76a, 1d7b5]` and PUTS IT BACK (:304). Measured by
        //     ablation: dropping 1d7b5 alone makes `scan.contains(1d78c)` false; dropping any of
        //     the other four leaves it true.
        //   * ⚠️ FINER GRANULARITY DOES NOT FIX IT. A singleton set of just {1d7b5} still yields
        //     `scan.contains(1d78c) == true`. Do not re-land this with a per-function loop.
        //   * Both 1d76a and 1d7b5 are created by `fs_mgr.run` itself (140 functions, and
        //     `compute_function_bodies` creates none), so the set is honestly "what this block
        //     created" — the composition is not an accounting bug here.
        //
        // WHY IT CANNOT BE FIXED LOCALLY: given this set, Ghidra's own algorithm creates 1d74e too.
        // The divergence is that Ghidra never HAS this set — its `CreateFunctionCmd`s go through
        // the COMMAND QUEUE and interleave with analyzer runs by priority, so shared return sees a
        // different sequence of states. That is `command-queue-modelled-as-change-channel`, i.e.
        // tasks #6/#10, and the re-land belongs there. Reverting restores
        // `shared_return_schedule_tests::a_function_created_by_the_pattern_search_still_gets_shared_return`
        // to the RED `#[ignore]` it was committed as, which is exactly where an unmet gate belongs.
    }

    // Function ID — name library functions from the signature databases (Ghidra `FidAnalyzer` at
    // the FUNCTION_ID priority band, plus the applying half of `ApplyFidEntriesCommand`). Hashes
    // each recovered function, scores the candidates against its callers and callees, and
    // replaces `FUN_xxxxxxxx` with the library name when the result clears the apply gate.
    //
    // ⚠️ THE WHOLE SUBSYSTEM WAS PREVIOUSLY UNREACHABLE. It had tests, but they construct the
    // analyzer directly, so nothing in the pipeline ever consulted a database and `analyze()`
    // returned no library names at all — FID answered "which compiler built this" and never
    // "here is a function".
    //
    // Runs HERE — after every function-creating stage, including Function Start Search — rather
    // than as an analyzer registered inside the manager. Registered there it fires once, on the
    // round where the set it was notified about appeared. Measured on the MSVC6 probe that was
    // with 58 of the eventual 62 functions and, more importantly, before reference recovery had
    // finished; FID scores a candidate against its CALLERS AND CALLEES, so an incomplete call
    // graph sinks every candidate below the apply gate. Same databases, three placements:
    //     inside the manager        -> 0 names
    //     after the fixpoint        -> 7 names (Function Start Search had not run yet)
    //     here, before the demangler-> 9 names
    // This is the same reason `noreturn` is re-run after the fixpoint above.
    //
    // ⚠️ IT IS NOT FREE WHEN IT CANNOT HELP, which is worth stating because the obvious
    // assumption is that it is. Deciding whether a database matches requires OPENING it (the
    // language and compiler spec live in its library records), so a program with no matching
    // database still pays to unpack every candidate: analysing a gcc x86-64 ELF went
    // 0.93 s -> 3.17 s against Ghidra's ten shipped Visual Studio databases, all discarded.
    // `FidQueryService::load_matching` is memoised per process to bound that — first call pays,
    // the rest are free (repeat analysis of the same language: 3.34 s then 0.15 s), which is what
    // the ingest loops need since they analyse thousands of objects in one process. A single CLI
    // analysis of an unmatched program still pays it once.
    {
        let analyzer = fid::analyzer::FidAnalyzer::for_program(program);
        let set = AddressSet::new();
        let mut sched = crate::analysis::manager::Scheduling::default();
        crate::analysis::analyzer::Analyzer::added(&analyzer, program, &set, &mut sched);
    }

    // A7 Task 6: GNU/Itanium C++ demangler (Ghidra GnuDemanglerAnalyzer, a BYTE_ANALYZER at
    // ~DATA_TYPE_PROPAGATION priority — i.e. late). Applies the demangled name to each
    // mangled symbol, keeping the mangled name as a secondary label. Runs last, once the
    // symbol set is final.
    analyzers::demangler::analyze(program);
}

/// Run the shared-return analysis over the full converged function set (Ghidra
/// `SharedReturnAnalysisCmd.applyTo` driven by `SharedReturnAnalyzer`). If it creates a new
/// function (a contiguous-function boundary-crossing tail call, e.g. `basic`'s PLT[0]),
/// recover that function's references and recompute bodies so the new code is fully analyzed.
///
/// **To a fixpoint.** In Ghidra `SharedReturnAnalyzer` is a `FUNCTION_ANALYZER`
/// (SharedReturnAnalyzer.java:65) and its `createFunction` goes through
/// `AutoAnalysisManager.createFunction`, so every function it creates raises a
/// FUNCTION_ANALYSIS event that re-enters the analyzer with the new function as the "added"
/// set — a tail call into a function that itself ends in a tail call is chased all the way
/// down. mosura runs this pass outside the manager loop (see the note at the call site: it
/// moves in-manager only after call-following restores Ghidra's cascade order), so the
/// re-entry is the explicit loop here: each round feeds the previous round's new functions
/// back in as the added set, after their references and bodies have been recovered.
fn shared_return_pass(program: &mut Program) {
    use crate::analysis::analyzer::Analyzer;
    use crate::analysis::program::AddressSet;
    let Some(sr) = analyzers::shared_return::SharedReturnAnalyzer::for_program(program) else {
        return;
    };
    // The first round's "added" set is every current function (the destination functions to
    // examine); each later round's is only what the previous round created.
    let mut added = AddressSet::new();
    for f in program.function_manager.functions() {
        let e = f.entry_point();
        added.add_range(e.space, e.offset, e.offset);
    }
    loop {
        let before: std::collections::HashSet<(u32, u64)> = program
            .function_manager
            .functions()
            .map(|f| (f.entry_point().space.0, f.entry_point().offset))
            .collect();
        let mut sched = crate::analysis::manager::Scheduling::default();
        sr.added(program, &added, &mut sched);
        // If new functions were created (e.g. PLT[0]), recover the references of *only the new*
        // functions (the constant propagator emits the READ at `0x401020 → 0x403ff0`) and
        // recompute bodies. Re-running the propagator over already-analyzed functions would
        // re-introduce the raw flow references that later analyzers (external-jump) had already
        // retyped, so the new-function set is isolated here.
        let new_entries: Vec<crate::decompile::space::Address> = program
            .function_manager
            .functions()
            .map(|f| f.entry_point())
            .filter(|e| !before.contains(&(e.space.0, e.offset)))
            .collect();
        if new_entries.is_empty() {
            return; // fixpoint
        }
        let mut next = AddressSet::new();
        for e in &new_entries {
            next.add_range(e.space, e.offset, e.offset);
        }
        if let Some(cp) = analyzers::ConstantPropagationAnalyzer::for_program(program) {
            let mut s = crate::analysis::manager::Scheduling::default();
            cp.added(program, &next, &mut s);
        }
        if let Some((spec, ctx)) = crate::lang::load_cached(&program.language_id) {
            analyzers::compute_function_bodies(spec, ctx, program);
        }
        added = next;
    }
}

/// Ghidra `ElfDefaultGotPltMarkup.processPLTSection` head size — the assumed PLT head
/// (`PLT[0]`, the lazy-resolver stub) skipped by the linear sweep; it is reached only via
/// the flow from each entry's resolve tail (`push; jmp PLT[0]`), so its internal padding
/// never gets seeded. (x86; ARM/AARCH64 use 0, but mosura's ELF path is x86-64.)
const ASSUMED_PLT_HEAD_SIZE: u64 = 16;

/// Linearly disassemble the `.plt` section (Ghidra `ElfDefaultGotPltMarkup.disassemble`,
/// from `processPLTSection`): seed at `pltBlock.start + 16` (skipping the head) and, while
/// any address in the range is undecoded, seed disassembly at the lowest gap and run to a
/// fixpoint (flow-following), then advance past what was decoded — exactly Ghidra's
/// `while (!set.isEmpty()) { disassemble(set.getMinAddress()); set.delete(disset); }`. The
/// head (`PLT[0]`) is decoded only by the flow reaching it from a resolve tail, so its
/// padding is never seeded directly (Ghidra leaves it undefined too).
fn plt_linear_sweep(mgr: &mut crate::analysis::manager::AutoAnalysisManager, program: &mut Program) {
    use crate::analysis::program::AddressSet;
    use crate::decompile::space::Address;
    let ram = program.default_space;
    let Some((block_start, end)) =
        program.memory.blocks().find(|b| b.name() == ".plt").map(|b| (b.start().offset, b.end().offset))
    else {
        return; // no .plt section (e.g. statically linked / non-ELF)
    };
    let start = block_start + ASSUMED_PLT_HEAD_SIZE;
    // Bounded by the number of code units the range can hold.
    let mut a = start;
    while a <= end {
        if program.listing.code_unit_at(Address::new(ram, a)).is_some() {
            // Skip the already-decoded instruction.
            let len = program.listing.code_unit_at(Address::new(ram, a)).map(|c| c.length()).unwrap_or(1);
            a += u64::from(len.max(1));
            continue;
        }
        // Seed this gap and let the flow disassembler (+ follow-on analyzers) run.
        let mut s = AddressSet::new();
        s.add_range(ram, a, a);
        mgr.scheduling().disassemble(&s);
        mgr.run(program);
        // Advance: if the gap decoded, step past it; otherwise move on by one byte.
        let len = program.listing.code_unit_at(Address::new(ram, a)).map(|c| c.length()).unwrap_or(0);
        a += u64::from(len.max(1));
    }
}

#[cfg(test)]
mod a4_tests {
    use super::*;

    #[test]
    fn freestanding_recursive_descent_disassembly() {
        let data = std::fs::read(crate::paths::analysis_corpus_dir().join("freestanding.elf"))
            .expect("freestanding.elf");
        let mut program = loader::load(&data).expect("load");
        let funcs_before = program.function_manager.function_count();
        analyze(&mut program);

        // Disassembly happened (code units laid down)…
        assert!(!program.listing.is_empty(), "no code units produced — SLEIGH tables present?");
        // …covering every function's entry (recursive descent reached them all).
        for f in program.function_manager.functions() {
            assert!(
                program.listing.code_unit_at(f.entry_point()).is_some(),
                "no code unit at function {}",
                f.name()
            );
        }
        // freestanding's 3 functions are all loader-known; none newly discovered.
        assert_eq!(program.function_manager.function_count(), funcs_before);

        // _start calls add + sum_to → two UNCONDITIONAL_CALL references to them.
        let call_targets: std::collections::BTreeSet<u64> = program
            .reference_manager
            .references()
            .filter(|r| r.ref_type == crate::analysis::program::RefType::UnconditionalCall)
            .map(|r| r.to.offset)
            .collect();
        assert!(
            call_targets.contains(&0x0040_1000) && call_targets.contains(&0x0040_1014),
            "expected call refs to add(0x401000) + sum_to(0x401014), got {call_targets:x?}"
        );
    }
}

#[cfg(test)]
mod a6_tests {
    use super::*;
    use std::collections::BTreeSet;

    /// A6: the decompiler-driven switch analyzer recovers `switchtab`'s jump table and
    /// emits exactly Ghidra's COMPUTED_JUMP edges (BRANCHIND → the 7 case targets).
    #[test]
    fn switch_analyzer_matches_ghidra_computed_jumps() {
        if crate::lang::load_cached("x86:LE:64:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        let p = analyze_file(&crate::paths::analysis_corpus_dir().join("switchtab.elf")).unwrap();
        let snap = p.snapshot();
        let golden = crate::analysis::snapshot::parse(
            &std::fs::read_to_string(crate::paths::analysis_goldens_dir().join("switchtab.snapshot"))
                .unwrap(),
        );
        let cj = |s: &crate::analysis::snapshot::Snapshot| -> BTreeSet<(u64, u64)> {
            s.refs.iter().filter(|r| r.kind == "COMPUTED_JUMP").map(|r| (r.from, r.to)).collect()
        };
        let (mine, gold) = (cj(&snap), cj(&golden));
        assert_eq!(mine, gold, "switch COMPUTED_JUMP edges must match Ghidra exactly");
        assert_eq!(mine.len(), 7, "7 case targets");
    }
}

#[cfg(test)]
mod a5_tests {
    use super::*;

    /// The SymbolicPropogator recovers data references on a real binary: every data
    /// reference target lies in mapped memory, and basic's GOT-relative reads are found.
    #[test]
    fn basic_recovers_data_references() {
        use crate::analysis::program::RefType;
        let data = std::fs::read(crate::paths::analysis_corpus_dir().join("basic.elf")).unwrap();
        let mut p = loader::load(&data).unwrap();
        analyze(&mut p);

        let data_refs: Vec<_> = p
            .reference_manager
            .references()
            .filter(|r| matches!(r.ref_type, RefType::Read | RefType::Write | RefType::Data))
            .collect();
        assert!(data_refs.len() >= 5, "expected several data refs, got {}", data_refs.len());
        // Every recovered reference targets mapped memory (the makeReference gate).
        for r in &data_refs {
            assert!(p.memory.contains(r.to), "ref to unmapped {:08x}", r.to.offset);
        }
    }
}




#[cfg(test)]
mod a6_typed_refs {
    use super::*;

    /// A6 indirect-flow + parameter analysis emit Ghidra's *exact* reference types on
    /// basic, not just the (from,to) pairs the recall gate checks: the PLT tail-call's
    /// COMPUTED_CALL_TERMINATOR, PLT[0]'s INDIRECTION, and the two pointer-argument PARAMs
    /// (with no stray DATA at the param-set instructions).
    #[test]
    fn basic_indirect_flow_and_param_types_match_ghidra() {
        if crate::lang::load_cached("x86:LE:64:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        let p = analyze_file(&crate::paths::analysis_corpus_dir().join("basic.elf")).unwrap();
        let typed = |from: u64, to: u64| -> Vec<&'static str> {
            let ram = p.default_space;
            use crate::decompile::space::Address;
            p.reference_manager
                .references()
                .filter(|r| r.from == Address::new(ram, from) && r.to == Address::new(ram, to))
                .map(|r| r.ref_type.name())
                .collect()
        };
        // Task 1: the PLT `jmp *[GOT]` resolving to the external printf is a tail call.
        assert_eq!(typed(0x40_1030, 0x40_5008), vec!["COMPUTED_CALL_TERMINATOR"]);
        // Task 2: PLT[0]'s `jmp *[GOT]` to the resolver slot is an INDIRECTION.
        assert_eq!(typed(0x40_1026, 0x40_3ff8), vec!["INDIRECTION"]);
        // Task 3: pointer arguments at the two call sites are PARAM — and only PARAM (the
        // speculative DATA ref the scalar analyzer would skip is dropped).
        assert_eq!(typed(0x40_1054, 0x40_1168), vec!["PARAM"]);
        assert_eq!(typed(0x40_1194, 0x40_2004), vec!["PARAM"]);
    }
}

#[cfg(test)]
mod a7_shared_return {
    use super::*;

    /// A7 Task 1 — the SharedReturnAnalyzer recovers PLT[0] as a function and retypes its
    /// inbound resolve-tail jump as a call (Ghidra SharedReturnAnalysisCmd).
    #[test]
    fn basic_shared_return_recovers_plt0() {
        if crate::lang::load_cached("x86:LE:64:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        let p = analyze_file(&crate::paths::analysis_corpus_dir().join("basic.elf")).unwrap();
        let ram = p.default_space;
        use crate::decompile::space::Address;

        // FUN_00401020 (PLT[0]) is now a function — the contiguous-function boundary-crossing
        // backward jump from the printf@plt resolve tail created it.
        assert!(
            p.function_manager.function_at(Address::new(ram, 0x40_1020)).is_some(),
            "FUN_00401020 (PLT[0]) must be recovered as a function"
        );

        let typed = |from: u64, to: u64| -> Vec<&'static str> {
            p.reference_manager
                .references()
                .filter(|r| r.from == Address::new(ram, from) && r.to == Address::new(ram, to))
                .map(|r| r.ref_type.name())
                .collect()
        };
        // The resolve-tail `jmp 0x401020` is retyped JUMP → CALL (CALL_TERMINATOR flow →
        // UNCONDITIONAL_CALL reference, per RefType.CALL_TERMINATOR's doc).
        assert_eq!(typed(0x40_103b, 0x40_1020), vec!["UNCONDITIONAL_CALL"]);
        // The READ inside PLT[0] (`push 0x403ff0(%rip)`) is recovered once the function exists.
        assert_eq!(typed(0x40_1020, 0x40_3ff0), vec!["READ"]);
    }
}

#[cfg(test)]
mod a7_eh_frame {
    use super::*;
    use std::collections::BTreeSet;

    /// A7 Task 2 — the EH-frame analyzer recovers the `.eh_frame_hdr` FDE-table references
    /// (Ghidra GccExceptionAnalyzer → EhFrameHeaderSection → FdeTable): the 6 INDIRECTION refs
    /// to the protected functions, exactly matching the golden, with no spurious additions.
    #[test]
    fn basic_eh_frame_hdr_indirection_refs() {
        if crate::lang::load_cached("x86:LE:64:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        let p = analyze_file(&crate::paths::analysis_corpus_dir().join("basic.elf")).unwrap();
        let snap = p.snapshot();
        let golden = crate::analysis::snapshot::parse(
            &std::fs::read_to_string(crate::paths::analysis_goldens_dir().join("basic.snapshot")).unwrap(),
        );
        let indir = |s: &crate::analysis::snapshot::Snapshot| -> BTreeSet<(u64, u64)> {
            // The .eh_frame_hdr table's INDIRECTION refs (the FDE initial_loc → function).
            s.refs
                .iter()
                .filter(|r| r.kind == "INDIRECTION" && (0x40_2008..=0x40_2043).contains(&r.from))
                .map(|r| (r.from, r.to))
                .collect()
        };
        let (mine, gold) = (indir(&snap), indir(&golden));
        assert_eq!(mine, gold, ".eh_frame_hdr INDIRECTION refs must match Ghidra exactly");
        assert_eq!(mine.len(), 6, "6 FDE-table entries");
    }

    /// A7 Task 5 — the EH-frame analyzer defines the data units Ghidra's
    /// `EhFrameHeaderSection`/`FdeTable` create (the `eh_frame_hdr` struct, the encoded
    /// `eh_frame_ptr` + `fde_count` `dword`s, a `fde_table_entry` per FDE-table row) **and**
    /// the field-level `.eh_frame` CIE/FDE markup (`Cie.create`/`FrameDescriptionEntry.create`:
    /// length/id `dword`s, version `byte`, augmentation `string`, code/data-align
    /// `uleb128`/`sleb128`, RA `byte`, aug-data-length `uleb128`, FDE-encoding `dwfenc`, the
    /// CFI `byte[]`s, the FDE pc_begin/pc_range, and the end-of-frame `dword`). Verified
    /// against the Ghidra oracle (`getDefinedData`) for basic.elf, scoped to the two EH-frame
    /// blocks (`0x402008..=0x402128`) — the rest of `defined_data` is loader markup.
    #[test]
    fn basic_eh_frame_defines_data_units() {
        if crate::lang::load_cached("x86:LE:64:default").is_none() {
            return;
        }
        let p = analyze_file(&crate::paths::analysis_corpus_dir().join("basic.elf")).unwrap();
        let mut mine: Vec<(u64, String, u32)> = p
            .defined_data
            .iter()
            .map(|(a, ty, len)| (a.offset, ty.clone(), *len))
            .filter(|(a, _, _)| (0x40_2008..=0x40_2128).contains(a))
            .collect();
        mine.sort();
        let expect: Vec<(u64, String, u32)> = vec![
            (0x402008, "eh_frame_hdr".into(), 4),
            (0x40200c, "dword".into(), 4),
            (0x402010, "dword".into(), 4),
            (0x402014, "fde_table_entry".into(), 8),
            (0x40201c, "fde_table_entry".into(), 8),
            (0x402024, "fde_table_entry".into(), 8),
            (0x40202c, "fde_table_entry".into(), 8),
            (0x402034, "fde_table_entry".into(), 8),
            (0x40203c, "fde_table_entry".into(), 8),
            (0x402048, "dword".into(), 4),
            (0x40204c, "dword".into(), 4),
            (0x402050, "byte".into(), 1),
            (0x402051, "string".into(), 3),
            (0x402054, "uleb128".into(), 1),
            (0x402055, "sleb128".into(), 1),
            (0x402056, "byte".into(), 1),
            (0x402057, "uleb128".into(), 1),
            (0x402058, "dwfenc".into(), 1),
            (0x402059, "byte[7]".into(), 7),
            (0x402060, "dword".into(), 4),
            (0x402064, "dword".into(), 4),
            (0x402068, "dword".into(), 4),
            (0x40206c, "qword".into(), 8),
            (0x402074, "dword".into(), 4),
            (0x402078, "dword".into(), 4),
            (0x40207c, "byte".into(), 1),
            (0x40207d, "string".into(), 3),
            (0x402080, "uleb128".into(), 1),
            (0x402081, "sleb128".into(), 1),
            (0x402082, "byte".into(), 1),
            (0x402083, "uleb128".into(), 1),
            (0x402084, "dwfenc".into(), 1),
            (0x402085, "byte[7]".into(), 7),
            (0x40208c, "dword".into(), 4),
            (0x402090, "dword".into(), 4),
            (0x402094, "dword".into(), 4),
            (0x402098, "qword".into(), 8),
            (0x4020a0, "dword".into(), 4),
            (0x4020a4, "dword".into(), 4),
            (0x4020a8, "dword".into(), 4),
            (0x4020ac, "dword".into(), 4),
            (0x4020b0, "uleb128".into(), 1),
            (0x4020b1, "byte[23]".into(), 23),
            (0x4020c8, "dword".into(), 4),
            (0x4020cc, "dword".into(), 4),
            (0x4020d0, "dword".into(), 4),
            (0x4020d4, "dword".into(), 4),
            (0x4020d8, "uleb128".into(), 1),
            (0x4020d9, "byte[15]".into(), 15),
            (0x4020e8, "dword".into(), 4),
            (0x4020ec, "dword".into(), 4),
            (0x4020f0, "dword".into(), 4),
            (0x4020f4, "dword".into(), 4),
            (0x4020f8, "uleb128".into(), 1),
            (0x4020f9, "byte[15]".into(), 15),
            (0x402108, "dword".into(), 4),
            (0x40210c, "dword".into(), 4),
            (0x402110, "dword".into(), 4),
            (0x402114, "dword".into(), 4),
            (0x402118, "uleb128".into(), 1),
            (0x402119, "byte[15]".into(), 15),
            (0x402128, "dword".into(), 4),
        ];
        assert_eq!(mine, expect, "eh_frame data units must match the Ghidra oracle");
    }
}

#[cfg(test)]
mod a7_diag_noreturn {
    use super::*;
    #[test]
    #[ignore]
    fn cnv_noreturn_count() {
        let path = crate::paths::cnv_exe();
        if !path.exists() { eprintln!("no cnv"); return; }
        let p = analyze_file(&path).unwrap();
        eprintln!("cnv noreturn-flagged: {}", p.noreturn_functions.len());
        eprintln!("cnv functions: {}", p.function_manager.function_count());
        // sanity: every flagged address is in mapped memory
        use crate::decompile::space::Address;
        let ram = p.default_space;
        for (s,o) in &p.noreturn_functions {
            assert!(p.memory.contains(Address::new(crate::decompile::space::SpaceId(*s), *o)) || *s != ram.0);
        }
    }
}

#[cfg(test)]
mod shared_return_schedule_tests {
    use super::*;
    use crate::analysis::program::AddressSet;
    use crate::decompile::space::{Address, SpaceKind, SpaceManager};

    /// ⭐ **THE GATE for the missing shared-return invocation (task #3).** A function the Function
    /// Start Search block creates at [`analyze`]'s `:260-308` is exactly what makes a tail-call
    /// destination qualify — and nothing runs shared return again after that block, so the
    /// destination is never created.
    ///
    /// In Ghidra there is no gap: a pattern-created function raises a change record →
    /// `handleFunctionAddedOrBodyChanged` → `functionDefined(entry)` → `functionTasks.notifyAdded`
    /// (AutoAnalysisManager.java:392-395, :280-290), and `functionTasks` is the FUNCTION_ANALYZER
    /// list (:158) that `SharedReturnAnalyzer` is on (SharedReturnAnalyzer.java:66). Delivery is
    /// not priority-gated: `FunctionStartAnalyzer` runs LATER than shared return
    /// (`CODE_ANALYSIS.after().after()` vs `.before().before()`) and still re-triggers it, on the
    /// round after.
    ///
    /// The fixture is the `0x67f40` shape reduced — a backward jump whose verdict flips when an
    /// intervening function appears:
    ///
    /// ```text
    /// 0x401000  P  31 c0              xor eax,eax     } the entry function; the jnz is
    /// 0x401002     0f 85 f8 02 00 00  jnz 0x401300    }   CONDITIONAL, so the shared-return
    /// 0x401008     c3                 ret             }   scan skips it as a source
    /// 0x401100  D  31 c0 c3           xor eax,eax; ret   <- the destination, no function yet
    /// 0x4011fe     c3 90                                 <- gcc x86-64 PREpattern (RET; NOP)
    /// 0x401200  X  55 48 89 e5 c3                        <- POSTpattern (PUSH RBP; MOV RBP,RSP)
    /// 0x401300  S  e9 fb fd ff ff     jmp 0x401100    } reached only by the jnz
    /// ```
    ///
    /// `S` is a backward jump, and the contiguous-function test is `destAddr < functionBeforeSrc`:
    ///
    /// - while `X` does not exist, `getFunctionBefore(0x401300)` is `P` at `0x401000` and
    ///   `0x401100 < 0x401000` is false — `shared_return_pass` at `:245` correctly declines;
    /// - once the pattern search creates `X`, `getFunctionBefore(0x401300)` is `0x401200` and
    ///   `0x401100 < 0x401200` holds — so the destination must be created.
    ///
    /// Nothing else can supply the answer: `X` has no inbound flow, `D` is reached only by the
    /// `jmp`, and `D`'s predecessor byte is undecoded so `checkIfCouldHaveFallThruTo` does not
    /// veto it.
    #[test]
    #[ignore = "RED: the invocation this gate needs does not exist yet (task #3)"]
    fn a_function_created_by_the_pattern_search_still_gets_shared_return() {
        if crate::lang::load_cached("x86:LE:64:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
        let base = Address::new(ram, 0x40_1000);
        let mut p = Program::new(spaces, ram, "x86:LE:64:default", "gcc", base, false, 64);
        let mut img = vec![0u8; 0x1000];
        img[0x000..0x009].copy_from_slice(&[
            0x31, 0xc0, // xor eax,eax
            0x0f, 0x85, 0xf8, 0x02, 0x00, 0x00, // jnz 0x401300
            0xc3, // ret
        ]);
        img[0x100..0x103].copy_from_slice(&[0x31, 0xc0, 0xc3]); // D
        img[0x1fe..0x205].copy_from_slice(&[
            0xc3, 0x90, // prepattern: RET; NOP
            0x55, 0x48, 0x89, 0xe5, 0xc3, // X: PUSH RBP; MOV RBP,RSP; RET
        ]);
        img[0x300..0x305].copy_from_slice(&[0xe9, 0xfb, 0xfd, 0xff, 0xff]); // S: jmp 0x401100
        p.memory.add_block(".text", base, 0x1000, true, false, true, Some(img));
        p.entry_points.push(base);
        p.function_manager.create_function(base, "entry", AddressSet::new());

        analyze(&mut p);

        let at = |off: u64| p.function_manager.function_at(Address::new(ram, off)).is_some();
        // The fixture only measures the schedule if the pattern search really does create X here.
        assert!(
            at(0x40_1200),
            "fixture broken: the gcc x86-64 funcstart pattern (RET;NOP + PUSH RBP;MOV RBP,RSP) did \
             not create a function at 0x401200, so there is no late creation to re-trigger on. \
             Functions: {:x?}",
            p.function_manager.functions().map(|f| f.entry_point().offset).collect::<Vec<_>>()
        );
        assert!(
            at(0x40_1100),
            "no function at the tail-call destination 0x401100: the pattern search created \
             0x401200 AFTER `shared_return_pass` ran, and nothing delivers Ghidra's \
             `functionDefined` event for it, so the backward jump at 0x401300 — whose \
             `destAddr < functionBeforeSrc` test only passes once 0x401200 exists — is never \
             re-examined. Functions: {:x?}",
            p.function_manager.functions().map(|f| f.entry_point().offset).collect::<Vec<_>>()
        );
    }
}
