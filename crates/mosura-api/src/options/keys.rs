//! The hand-written option keys of api 0.1 (the generated ones — `emit.<axis>`, `knobs.off`,
//! `emit.arms-off`, `debug.topics` — take their value lists from the core in `registry.rs`).

use super::{Affects, OptType, OptionSpec};

pub const LOAD_LOADER: &str = "load.loader";
pub const LOAD_LANGUAGE: &str = "load.language";
pub const LOAD_BASE: &str = "load.base";
pub const LOAD_CSPEC_X86_32: &str = "load.cspec-x86-32";
pub const ANALYSIS_DISABLE: &str = "analysis.disable";
pub const ANALYSIS_SWITCH_TABLE_REFS: &str = "analysis.switch-table-refs";
pub const ANALYSIS_DATA_POINTER_FUNCTIONS: &str = "analysis.data-pointer-functions";
pub const KNOBS_OFF: &str = "knobs.off";
pub const DECOMPILE_GLOBAL_SCOPE: &str = "decompile.global-scope";
pub const DECOMPILE_PROTO_SCOPE: &str = "decompile.proto-scope";
pub const EMIT_ARMS_OFF: &str = "emit.arms-off";
pub const DEBUG_TOPICS: &str = "debug.topics";
pub const DEBUG_WATCH_CALL: &str = "debug.watch-call";
pub const DEBUG_MERGE_WATCH: &str = "debug.merge-watch";
pub const DEBUG_AOU_PC: &str = "debug.aou-pc";
pub const DEBUG_GT_RAW: &str = "debug.gt-raw";
pub const DEBUG_OPACTION: &str = "debug.opaction";
pub const DEBUG_TRACE_FUNC: &str = "debug.trace-func";
pub const DEBUG_FIXPOINT: &str = "debug.fixpoint";

pub const TOOLCHAIN_SPEC: &str = "toolchain.spec";
pub const TOOLCHAIN_INSTALL: &str = "toolchain.install";
pub const COMPILE_CACHE: &str = "compile.cache";
pub const VERIFY_TABLE_WINDOW: &str = "verify.table-window";
pub const EQUIV_SEEDS: &str = "equiv.seeds";
pub const ROUND_SCOPE: &str = "round.scope";
pub const ROUND_SCOPE_FILE: &str = "round.scope-file";
pub const ROUND_BASELINE: &str = "round.baseline";
pub const ROUND_EXPECT: &str = "round.expect";
pub const ROUND_EXCLUDE_FOREIGN: &str = "round.exclude-foreign";
pub const GATES_BASELINE: &str = "gates.baseline";
pub const FID_DB: &str = "fid.db";

pub const LOADERS: &[&str] = &["default", "native", "le", "x32", "com", "raw", "xml"];
pub const ROUND_SCOPES: &[&str] = &["user", "all", "list"];
pub const GLOBAL_SCOPES: &[&str] = &["application", "standalone"];

const SINCE: &str = "0.1";

macro_rules! spec {
    ($key:expr, $ty:expr, $default:expr, $affects:expr, $doc:expr) => {
        OptionSpec { key: $key, ty: $ty, default: $default, doc: $doc, since: SINCE, affects: $affects }
    };
}

pub fn hand_written() -> Vec<OptionSpec> {
    vec![
        spec!(LOAD_LOADER, OptType::Enum(LOADERS), "default", Affects::Result, "which loader claims the input: the container dispatch (default), the beyond-Ghidra native loaders, the LE view, X-32, .com, a raw image (with load.language and load.base), or a Ghidra <binaryimage> datatest"),
        spec!(LOAD_LANGUAGE, OptType::Str, "", Affects::Result, "the SLEIGH language id of a raw image (load.loader=raw), e.g. x86:LE:32:default"),
        spec!(LOAD_BASE, OptType::Hex, "", Affects::Result, "the load address of a raw image (load.loader=raw)"),
        spec!(LOAD_CSPEC_X86_32, OptType::Str, "", Affects::Result, "declare the x86-32 compiler spec at load time (watcom, highc, …) instead of detecting it"),
        spec!(ANALYSIS_DISABLE, OptType::List(&[]), "", Affects::Result, "analyzers to leave out of auto-analysis, by name (an ablation)"),
        spec!(ANALYSIS_SWITCH_TABLE_REFS, OptType::Bool, "false", Affects::Result, "Ghidra's `Switch Table References` option (off by default there too): a computed call or jump names the table of code pointers at its operand, whose entries become references, code and functions — for table-driven programs whose tables sit inline in the code"),
        spec!(ANALYSIS_DATA_POINTER_FUNCTIONS, OptType::Bool, "false", Affects::Result, "create a function at a code pointer stored in data (a menu/record handler reached only through a pointer in a data structure) — a deviation from Ghidra, which disassembles the target but makes no function from a data pointer; off by default"),
        spec!(DECOMPILE_GLOBAL_SCOPE, OptType::Enum(GLOBAL_SCOPES), "application", Affects::Result, "application: every loaded address is a global (the whole-program emit); standalone: only what the function's own image says"),
        spec!(DECOMPILE_PROTO_SCOPE, OptType::Scope, "all", Affects::Result, "which recovered prototypes a decompile consults: all, none, or a list of callee addresses"),
        // input keys: WHAT an operation runs on; they enter a cache key as input digests
        spec!("input", OptType::Str, "", Affects::Input, "the session input a program operation runs on: a label or a digest (the only input when omitted)"),
        spec!("program", OptType::Str, "", Affects::Input, "the program key a function operation runs on (the last opened program when omitted)"),
        spec!("entry", OptType::Hex, "", Affects::Input, "the function's entry address"),
        spec!("table", OptType::Str, "", Affects::Input, "a table name (program.tables, function.decompile format=table:<name>)"),
        spec!("addr", OptType::Hex, "", Affects::Input, "an address (program.read, program.disassemble)"),
        spec!("len", OptType::U64, "", Affects::Input, "a byte count (program.read, program.disassemble)"),
        spec!("lang", OptType::Str, "", Affects::Input, "a SLEIGH language id (the sleigh.* operations)"),
        spec!("bytes", OptType::Str, "", Affects::Input, "raw bytes as hex (the sleigh.* operations)"),
        spec!("base", OptType::Hex, "", Affects::Input, "the address of the first byte (the sleigh.* operations)"),
        spec!("ctx", OptType::Str, "", Affects::Input, "context register settings, `name=value;…` (the sleigh.* operations)"),
        spec!("format", OptType::Str, "", Affects::Input, "what to return: c, raw, or table:<name> (function.decompile)"),
        spec!("toolchain", OptType::Str, "", Affects::Input, "the session toolchain an operation compiles with (toolchain.open's name)"),
        spec!("object", OptType::Str, "", Affects::Input, "a session input holding a compiled object (function.verify)"),
        spec!("round", OptType::Str, "", Affects::Input, "a round name (round.run, round.show, round.gates, round.export)"),
        spec!("a", OptType::Str, "", Affects::Input, "the baseline round of a comparison (round.compare)"),
        spec!("b", OptType::Str, "", Affects::Input, "the candidate round of a comparison (round.compare)"),
        spec!("label", OptType::Str, "", Affects::Input, "free text recorded with a round"),
        spec!("out", OptType::Str, "", Affects::Input, "an output file path (round.export: the verdict TSV)"),
        spec!("divergences", OptType::Str, "", Affects::Input, "a divergence TSV path (round.export writes it, round.import reads it)"),
        spec!("verdicts", OptType::Str, "", Affects::Input, "a verdict TSV path (round.import)"),
        spec!("manifest", OptType::Str, "", Affects::Input, "an emit manifest path, for its `# arms:` line (round.import)"),
        spec!(TOOLCHAIN_SPEC, OptType::Str, "", Affects::Result, "the compiler spec a toolchain is opened with (toolchain.specs lists them)"),
        spec!(TOOLCHAIN_INSTALL, OptType::Str, "", Affects::Environment, "where the toolchain is installed on this machine (the WATCOM directory, or a native compiler command)"),
        spec!(COMPILE_CACHE, OptType::Str, "", Affects::Environment, "the compile cache directory (default: <session>/compile); slots are keyed on toolchain id, flags and source"),
        spec!(VERIFY_TABLE_WINDOW, OptType::Hex, "0x20000", Affects::Result, "how far around a function the jump-table correspondence search looks (bytes)"),
        spec!(EQUIV_SEEDS, OptType::U64, "128", Affects::Result, "how many random machine states the differential run compares (function.equiv); more seeds = more coverage, and the verdict can strengthen from DIFFERS to SAME or the reverse"),
        spec!(ROUND_SCOPE, OptType::Enum(ROUND_SCOPES), "user", Affects::Result, "which functions a round measures: user (not library/asm), all, or the list in round.scope-file"),
        spec!(ROUND_SCOPE_FILE, OptType::Str, "", Affects::Input, "a TSV whose first two columns are idx and va: the functions of round.scope=list (a smoke set)"),
        spec!(ROUND_BASELINE, OptType::Str, "", Affects::Input, "the previous round the verdict gates compare against (no EXACT lost, no new failure)"),
        spec!(ROUND_EXPECT, OptType::Str, "", Affects::Input, "a TSV `idx va name expected_verdict`: the smoke-drift gate (every listed function must keep its verdict)"),
        spec!(ROUND_EXCLUDE_FOREIGN, OptType::Str, "", Affects::Input, "a foreign-scope confirmation file: its foreign functions leave the denominator (a DIFFERENT series; stamped)"),
        spec!(GATES_BASELINE, OptType::Str, "", Affects::Environment, "the corpus-gates.tsv of the subject profile (text gates 4-6, verdict gate 7)"),
        spec!(FID_DB, OptType::Str, "", Affects::Input, "one FID database directory to search instead of every database the resource provider holds (fid.identify)"),
        spec!("key", OptType::Str, "", Affects::Input, "a session config key (session.config.set)"),
        spec!("value", OptType::Str, "", Affects::Input, "a session config value; empty removes the key (session.config.set)"),
        // diagnostics
        spec!(DEBUG_WATCH_CALL, OptType::Hex, "", Affects::Diagnostic, "trace the arity changes of every CALL to this target address"),
        spec!(DEBUG_MERGE_WATCH, OptType::Hex, "", Affects::Diagnostic, "trace the unions that touch this merge-group id"),
        spec!(DEBUG_AOU_PC, OptType::Hex, "", Affects::Diagnostic, "trace the ancestor-op-use walk of the op at this pc"),
        spec!(DEBUG_GT_RAW, OptType::Str, "", Affects::Diagnostic, "dump the raw IR of this ground-truth function before recompiling it"),
        spec!(DEBUG_OPACTION, OptType::Str, "", Affects::Diagnostic, "record every op mutation (all) or those of one named action — Ghidra's OPACTION_DEBUG"),
        spec!(DEBUG_TRACE_FUNC, OptType::Str, "", Affects::Diagnostic, "scope the op-action trace to one function of a whole-program run"),
        spec!(DEBUG_FIXPOINT, OptType::Bool, "false", Affects::Diagnostic, "run the recovery's third-render fixpoint check in release builds too"),
    ]
}
