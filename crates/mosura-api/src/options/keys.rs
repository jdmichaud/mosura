//! The hand-written option keys of api 0.1 (the generated ones — `emit.<axis>`, `knobs.off`,
//! `emit.arms-off`, `debug.topics` — take their value lists from the core in `registry.rs`).

use super::{Affects, OptType, OptionSpec};

pub const LOAD_LOADER: &str = "load.loader";
pub const LOAD_LANGUAGE: &str = "load.language";
pub const LOAD_BASE: &str = "load.base";
pub const LOAD_CSPEC_X86_32: &str = "load.cspec-x86-32";
pub const ANALYSIS_DISABLE: &str = "analysis.disable";
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

pub const LOADERS: &[&str] = &["default", "native", "le", "x32", "com", "raw", "xml"];
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
