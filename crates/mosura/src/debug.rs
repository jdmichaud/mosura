//! THE DEBUG FACILITY: one place every diagnostic of the crate is switched from — and the CALLER
//! switches it. A front-end parses its `--debug <spec>` flag with [`parse_spec`] (or hands its whole
//! argument list to [`from_args`]) and calls [`configure`] once at start-up; each subsystem owns a
//! [`Topic`], and a diagnostic print is written `debug!(Topic::X, "..", ..)` — the text reaches the
//! configured [`Sink`] (stderr when none is set), prefixed `[x]`, only when its topic is on. A
//! print never reaches the emitted text, so the survey's trees do not move.
//!
//! Nothing here reads the environment (2026-09-05, the environment-variable removal, WP3). Before
//! R6 every print site read its own environment variable (80 names, 141 reads); R6 collapsed them
//! into one `MOSURA_DEBUG` read; this step makes even that one a value the caller passes, together
//! with the watch parameters that had stayed as variables of their own: the call-arity watch, the
//! merge watch, the ancestor-op-use pc, the raw-IR dump of one ground-truth function, the recovery
//! fixpoint check, the op-action trace and its function filter.
//!
//! Process-wide, deliberately: the configuration is set once by the front-end and read from every
//! thread. It is not per-function state — that is [`crate::switches::Knobs`], for the knobs that
//! change RESULTS; a diagnostic is about what the operator wants to SEE of this run.
//!
//! The spec grammar (`--debug <spec>`): `;`-separated parts. A part without `=` is a comma-separated
//! list of topic names (`types,structure`), `all`, or a bare flag (`fixpoint`, `opaction`). With
//! `=`: `topics=<list>`, `watch-call=<hex va>`, `merge-watch=<hex id>`, `aou-pc=<hex pc>`,
//! `gt-raw=<function>`, `opaction=<action name>`, `trace-func=<function>`. An unknown topic, key or
//! malformed value is an ERROR, never a silent no-op.
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

/// The subsystems a diagnostic print can belong to — one per subsystem, not one per print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Topic {
    /// emit/arms/sparse_switch (was `MOSURA_SPARSE_DEBUG`) and the sparse-compare witness.
    SparseSwitch,
    /// emit/arms/struct_copy (was `MOSURA_STRUCTCOPY_DEBUG`).
    StructCopy,
    /// emit/arms/frame_fill (was `MOSURA_FRAME_DEBUG`).
    FrameFill,
    /// emit/arms/sum_order (the `[sumord]` print).
    SumOrder,
    /// printc's statement walk (was `MOSURA_STMT_PC`, `_BLOCKSET`, `_SWITCH_DEBUG`, `_STORE_DEBUG`,
    /// `_ILV_DEBUG`, `_COND_DEBUG`, `_CALLARGS`).
    Printc,
    /// recompile/recovery (was `MOSURA_EMIT_DEBUG`) and the interleave census.
    Recover,
    /// decompile/structure (was `MOSURA_STRUCT`, `_COMPLEX`, `_SWD_DEBUG`, `_COLLAPSE`, `_CFG`).
    Structure,
    /// decompile/jumpbasic (was `MOSURA_JT_DEBUG`).
    JumpTable,
    /// argument recovery: decompile/recover, analysis/decompiler, heritage (was `MOSURA_ARG_DEBUG`,
    /// `_MONO`; the trial pipeline's `_PARAMDOUBLE_DEBUG`, `_UJP_DEBUG`).
    Args,
    /// decompile/varargs (was `MOSURA_VARARGS_DEBUG`).
    Varargs,
    /// decompile/blockjoin (was `MOSURA_RETSPLIT_DEBUG`).
    RetSplit,
    /// analysis/decompiler's callee effects (was `MOSURA_EFFECTS_DEBUG`).
    Effects,
    /// decompile/varmap, restrictlocal (was `MOSURA_VARMAP`).
    Varmap,
    /// decompile/stackvars (was `MOSURA_SPFLOW_DEBUG`, `_RSDEBUG`).
    StackVars,
    /// decompile/heritage (was `MOSURA_RESTART_DEBUG`).
    Heritage,
    /// decompile/constantptr, ptrarith, setcasts, varnodeprops, subvarflow (was `_CONSTPTR_DEBUG`,
    /// `_DISTRIB`, `_PTRFIT`, `_ALIAS_DEBUG`, `_SUBVAR`).
    Pointers,
    /// decompile/pipeline (was `MOSURA_INSTR_ALIAS`), deadcode, condexe and funcdata's check/watch prints.
    Pipeline,
    /// recompile/watsched (was `MOSURA_ZAP_DEBUG`, `_SCHED_DEBUG`).
    Watsched,
    /// recompile/groundtruth (was `MOSURA_GT_DEBUG`).
    GroundTruth,
    /// analysis/cspec.
    Cspec,
    /// analysis/manager and analysis/analyzers (was `MOSURA_ANALYSIS_TRACE`, `_CP_PROBE`).
    Analysis,
    /// decompile/merge (was `MOSURA_IMPLIED_DEBUG`).
    Merge,
    /// the survey's own env-gated diagnostics (examples/corpus_emit.rs: was `MOSURA_KERNEL_SHADOW`,
    /// `_SHARED_RET_DEBUG`, `_SHADOW_DEBUG`, `_EXTENT`, `_AUX_DEBUG`, `_AGG_DEBUG`; the raw-IR dump is `raw-ir`,
    /// the survey's zapcheck driver prints under `watsched` with the mechanism it exercises) — its normal output (the manifest, the summaries) is not a diagnostic and
    /// stays plain.
    Survey,
    /// decompile/action's timing accumulator and its `perf::dump` table (was `MOSURA_PERF`); its own
    /// topic so a timing run does not switch the pipeline diagnostics on.
    Perf,
    /// decompile/infertypes' propagation trace (was `MOSURA_TYPEPROP`): one line per propagation
    /// step -- its own topic so it does not drown the sparse `pointers` prints.
    Types,
    /// decompile/subvarflow's replacement trace (was `MOSURA_SUBVAR`): one line per node -- its own
    /// topic for the same reason.
    Subvar,
    /// decompile/rules' `RuleBoolNegate`: one line per firing, with the comparison's reader count
    /// and whether every reader is a BOOL_NEGATE -- Ghidra's `RuleBoolNegate` requires that (it
    /// rewrites the PRODUCER, so a comparison with a non-negate reader must not be flipped), and
    /// ours has no such test. The line says what Ghidra would have done, so the corpus census of
    /// the missing refusal is one emit rather than a trace-diff per fixture.
    BoolNegate,
    /// decompile/printc's `for`-loop recognition: one line per candidate `while`-do saying which
    /// gate of `BlockWhileDo::finalTransform`'s chain accepted or declined it, and on what op or
    /// varnode. The decline sites ARE the gates -- nothing here re-derives the decision, because a
    /// diagnostic that re-computes what it reports is a second implementation that can drift.
    ForLoop,
    /// the survey's raw-IR dump (was `MOSURA_RAW_IR`): every function's raw IR on stdout -- its own
    /// topic so `survey` alone stays readable.
    RawIr,
}

impl Topic {
    pub const ALL: &'static [Topic] = &[
        Topic::SparseSwitch, Topic::StructCopy, Topic::FrameFill, Topic::SumOrder, Topic::Printc, Topic::Recover,
        Topic::Structure, Topic::JumpTable, Topic::Args, Topic::Varargs, Topic::RetSplit, Topic::Effects,
        Topic::Varmap, Topic::StackVars, Topic::Heritage, Topic::Pointers, Topic::Pipeline, Topic::Watsched,
        Topic::GroundTruth, Topic::Cspec, Topic::Analysis, Topic::Merge, Topic::Survey, Topic::Perf, Topic::Types, Topic::Subvar, Topic::BoolNegate, Topic::ForLoop, Topic::RawIr,
    ];
    /// The topic of this kebab-case name (`--debug <name>`), if any.
    pub fn by_name(name: &str) -> Option<Topic> {
        Topic::ALL.iter().copied().find(|t| t.name() == name)
    }

    /// The kebab-case name used in `--debug` specs and as the print prefix.
    pub fn name(self) -> &'static str {
        match self {
            Topic::SparseSwitch => "sparse-switch",
            Topic::StructCopy => "struct-copy",
            Topic::FrameFill => "frame-fill",
            Topic::SumOrder => "sum-order",
            Topic::Printc => "printc",
            Topic::Recover => "recover",
            Topic::Structure => "structure",
            Topic::JumpTable => "jump-table",
            Topic::Args => "args",
            Topic::Varargs => "varargs",
            Topic::RetSplit => "ret-split",
            Topic::Effects => "effects",
            Topic::Varmap => "varmap",
            Topic::StackVars => "stack-vars",
            Topic::Heritage => "heritage",
            Topic::Pointers => "pointers",
            Topic::Pipeline => "pipeline",
            Topic::Watsched => "watsched",
            Topic::GroundTruth => "ground-truth",
            Topic::Cspec => "cspec",
            Topic::Analysis => "analysis",
            Topic::Merge => "merge",
            Topic::Survey => "survey",
            Topic::Perf => "perf",
            Topic::Types => "types",
            Topic::Subvar => "subvar",
            Topic::BoolNegate => "boolnegate",
            Topic::ForLoop => "for-loop",
            Topic::RawIr => "raw-ir",
        }
    }
}

/// Severity of a line handed to the [`Sink`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Something the library could not do as asked (a database it skipped, a function whose
    /// pipeline failed): shown by default, never gated by a topic.
    Warn,
    /// A topic's diagnostic line.
    Debug,
}

/// Where diagnostic text goes: `(level, topic name — empty for a warning, message)`. When no sink
/// is configured the text goes to stderr, `[topic] message` for a diagnostic and `mosura: message`
/// for a warning.
pub type Sink = Arc<dyn Fn(Level, &str, &str) + Send + Sync>;

/// Everything the caller can switch on. Built by [`parse_spec`] from a `--debug` spec, or by hand;
/// handed to [`configure`].
#[derive(Clone, Default)]
pub struct Config {
    topics: [bool; 32],
    /// `watch-call=<hex va>`: name the caller that changes the arity of a CALL to this target
    /// (`Funcdata::op_set_all_input` / `op_remove_input`) — the probe for silently vanishing
    /// arguments.
    pub watch_call: Option<u64>,
    /// `merge-watch=<hex id>`: trace the unions that touch this merge-group id (`merge.rs`).
    pub merge_watch: Option<u32>,
    /// `aou-pc=<hex pc>`: trace the ancestor-op-use walk of the op at this pc (`recover.rs`).
    pub aou_pc: Option<u64>,
    /// `gt-raw=<function>`: dump the raw IR of this ground-truth function before recompiling it.
    pub gt_raw: Option<String>,
    /// `fixpoint`: run the recovery's third-render fixpoint check in release builds too
    /// (`recompile::recovery`; debug builds always run it).
    pub recover_fixpoint: bool,
    /// `opaction` / `opaction=<action>`: Ghidra's `OPACTION_DEBUG` — record every op mutation of
    /// every action (empty string) or of the one action named (`Funcdata::debug_activate`).
    pub opaction: Option<String>,
    /// `trace-func=<function>`: scope the op-action trace to one function of a whole-program run.
    pub trace_func: Option<String>,
    /// Where the text goes; stderr when `None`.
    pub sink: Option<Sink>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("topics", &self.topics())
            .field("watch_call", &self.watch_call)
            .field("merge_watch", &self.merge_watch)
            .field("aou_pc", &self.aou_pc)
            .field("gt_raw", &self.gt_raw)
            .field("recover_fixpoint", &self.recover_fixpoint)
            .field("opaction", &self.opaction)
            .field("trace_func", &self.trace_func)
            .field("sink", &self.sink.as_ref().map(|_| "custom"))
            .finish()
    }
}

impl Config {
    pub fn enable(&mut self, topic: Topic) {
        self.topics[topic as usize] = true;
    }
    pub fn enable_all(&mut self) {
        for t in Topic::ALL {
            self.topics[*t as usize] = true;
        }
    }
    pub fn is_on(&self, topic: Topic) -> bool {
        self.topics[topic as usize]
    }
    /// The topics switched on, in `Topic::ALL` order.
    pub fn topics(&self) -> Vec<Topic> {
        Topic::ALL.iter().copied().filter(|t| self.topics[*t as usize]).collect()
    }
}

/// One bit per topic — the check every `debug!` site pays, an atomic load.
static TOPIC_BITS: AtomicU32 = AtomicU32::new(0);
/// The rest of the configuration — read only when something is on or watched.
static CONFIG: RwLock<Option<Config>> = RwLock::new(None);
const _: () = assert!(Topic::ALL.len() <= 32, "the topic bitmask is a u32");

/// Install the configuration for this process. Call once at start-up (a second call replaces the
/// first; the last one wins — documented as process-wide, see the module doc).
pub fn configure(cfg: Config) {
    let mut bits = 0u32;
    for t in Topic::ALL {
        if cfg.topics[*t as usize] {
            bits |= 1u32 << (*t as u32);
        }
    }
    *CONFIG.write().unwrap_or_else(|e| e.into_inner()) = Some(cfg);
    TOPIC_BITS.store(bits, Ordering::Release);
}

/// Whether `topic`'s diagnostics are on.
pub fn on(topic: Topic) -> bool {
    TOPIC_BITS.load(Ordering::Relaxed) & (1u32 << (topic as u32)) != 0
}

fn with_config<R>(f: impl FnOnce(Option<&Config>) -> R) -> R {
    let guard = CONFIG.read().unwrap_or_else(|e| e.into_inner());
    f(guard.as_ref())
}

/// Deliver one diagnostic line (the `debug!` macro's back end): to the sink, else stderr.
pub fn emit(topic: Topic, msg: String) {
    match with_config(|c| c.and_then(|c| c.sink.clone())) {
        Some(sink) => sink(Level::Debug, topic.name(), &msg),
        None => eprintln!("[{}] {}", topic.name(), msg),
    }
}

/// Deliver one warning (the `warn!` macro's back end): to the sink, else stderr. A library does
/// not write to stderr on its own; this is the one path a message the operator should see takes.
pub fn warn(msg: String) {
    match with_config(|c| c.and_then(|c| c.sink.clone())) {
        Some(sink) => sink(Level::Warn, "", &msg),
        None => eprintln!("mosura: {msg}"),
    }
}

pub fn watch_call() -> Option<u64> {
    with_config(|c| c.and_then(|c| c.watch_call))
}
pub fn merge_watch() -> Option<u32> {
    with_config(|c| c.and_then(|c| c.merge_watch))
}
pub fn aou_pc() -> Option<u64> {
    with_config(|c| c.and_then(|c| c.aou_pc))
}
/// Whether the raw IR of `function` was asked for (`gt-raw=<function>`).
pub fn gt_raw(function: &str) -> bool {
    with_config(|c| c.is_some_and(|c| c.gt_raw.as_deref() == Some(function)))
}
pub fn recover_fixpoint() -> bool {
    with_config(|c| c.is_some_and(|c| c.recover_fixpoint))
}
pub fn opaction() -> Option<String> {
    with_config(|c| c.and_then(|c| c.opaction.clone()))
}
pub fn trace_func() -> Option<String> {
    with_config(|c| c.and_then(|c| c.trace_func.clone()))
}

/// Parse a `--debug` spec (grammar in the module doc). Every mistake is an `Err` naming what is
/// known, never a silent no-op.
pub fn parse_spec(spec: &str) -> Result<Config, String> {
    fn known() -> String {
        Topic::ALL.iter().map(|t| t.name()).collect::<Vec<_>>().join(",")
    }
    fn topics(cfg: &mut Config, list: &str) -> Result<(), String> {
        for tok in list.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            if tok == "all" {
                cfg.enable_all();
                continue;
            }
            match Topic::by_name(tok) {
                Some(t) => cfg.enable(t),
                None => return Err(format!("unknown debug topic `{tok}` (known: {}, all)", known())),
            }
        }
        Ok(())
    }
    fn hex(key: &str, v: &str) -> Result<u64, String> {
        u64::from_str_radix(v.trim().trim_start_matches("0x"), 16)
            .map_err(|_| format!("`{key}` wants a hex value, got `{v}`"))
    }
    let mut cfg = Config::default();
    for part in spec.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        match part.split_once('=') {
            None => match part {
                "fixpoint" => cfg.recover_fixpoint = true,
                "opaction" => cfg.opaction = Some(String::new()),
                list => topics(&mut cfg, list)?,
            },
            Some((key, value)) => match key.trim() {
                "topics" => topics(&mut cfg, value)?,
                "watch-call" => cfg.watch_call = Some(hex("watch-call", value)?),
                "merge-watch" => {
                    cfg.merge_watch = Some(
                        u32::try_from(hex("merge-watch", value)?)
                            .map_err(|_| format!("`merge-watch` wants a 32-bit id, got `{value}`"))?,
                    )
                }
                "aou-pc" => cfg.aou_pc = Some(hex("aou-pc", value)?),
                "gt-raw" => cfg.gt_raw = Some(value.trim().to_string()),
                "opaction" => cfg.opaction = Some(value.trim().to_string()),
                "trace-func" => cfg.trace_func = Some(value.trim().to_string()),
                "fixpoint" => cfg.recover_fixpoint = matches!(value.trim(), "1" | "true" | "on"),
                other => {
                    return Err(format!(
                        "unknown debug key `{other}` (known: topics, watch-call, merge-watch, aou-pc, gt-raw, opaction, trace-func, fixpoint)"
                    ))
                }
            },
        }
    }
    Ok(cfg)
}

/// The one line a front-end needs: take `--debug <spec>` / `--debug=<spec>` out of `args`,
/// [`configure`] from it (the last occurrence wins), and return the remaining arguments. An
/// invalid spec is an `Err` for the front-end to report.
pub fn from_args(args: Vec<String>) -> Result<Vec<String>, String> {
    let mut rest = Vec::with_capacity(args.len());
    let mut spec: Option<String> = None;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--debug" {
            spec = Some(it.next().ok_or_else(|| "`--debug` wants a spec (e.g. `--debug types,structure`)".to_string())?);
        } else if let Some(v) = a.strip_prefix("--debug=") {
            spec = Some(v.to_string());
        } else {
            rest.push(a);
        }
    }
    if let Some(s) = spec {
        configure(parse_spec(&s)?);
    }
    Ok(rest)
}

/// A diagnostic print under a topic: `debug!(Topic::X, "fmt", args..)` — delivered (to the sink,
/// else stderr, prefixed with the topic's name) only when the topic is on.
#[macro_export]
macro_rules! debug {
    ($topic:expr, $($arg:tt)*) => {
        if $crate::debug::on($topic) {
            $crate::debug::emit($topic, format!($($arg)*));
        }
    };
}

/// A warning the operator should see regardless of topics: `warn!("fmt", args..)` — delivered to
/// the sink, else stderr as `mosura: ..`. The library's only sanctioned unconditional print.
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::debug::warn(format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_names_round_trip_and_all_selects_everything() {
        let c = parse_spec("sparse-switch, struct-copy").unwrap();
        assert!(c.is_on(Topic::SparseSwitch) && c.is_on(Topic::StructCopy) && !c.is_on(Topic::Printc));
        let all = parse_spec("all").unwrap();
        assert!(Topic::ALL.iter().all(|t| all.is_on(*t)));
        for t in Topic::ALL {
            assert_eq!(Topic::by_name(t.name()), Some(*t), "unique name {}", t.name());
        }
        assert!(parse_spec("").unwrap().topics().is_empty());
    }

    /// The spec grammar: topics as bare lists, the watches as `key=value`, bare flags, and every
    /// mistake an error that names what is known (never a silent no-op).
    #[test]
    fn spec_grammar_parses_every_key_and_rejects_the_unknown() {
        let c = parse_spec("types,structure;watch-call=0x1234;merge-watch=1f;aou-pc=0x10;gt-raw=main;opaction;trace-func=FUN_1;fixpoint").unwrap();
        assert_eq!(c.topics(), vec![Topic::Structure, Topic::Types]);
        assert_eq!(c.watch_call, Some(0x1234));
        assert_eq!(c.merge_watch, Some(0x1f));
        assert_eq!(c.aou_pc, Some(0x10));
        assert_eq!(c.gt_raw.as_deref(), Some("main"));
        assert_eq!(c.opaction.as_deref(), Some(""));
        assert_eq!(c.trace_func.as_deref(), Some("FUN_1"));
        assert!(c.recover_fixpoint);
        assert_eq!(parse_spec("opaction=heritage").unwrap().opaction.as_deref(), Some("heritage"));
        assert_eq!(parse_spec("topics=perf").unwrap().topics(), vec![Topic::Perf]);
        assert!(parse_spec("nope").unwrap_err().contains("unknown debug topic `nope`"));
        assert!(parse_spec("watch-call=zz").unwrap_err().contains("hex"));
        assert!(parse_spec("merge-watch=100000000").unwrap_err().contains("32-bit"));
        assert!(parse_spec("bogus=1").unwrap_err().contains("unknown debug key `bogus`"));
    }

    /// `from_args` strips the flag in both spellings, configures the process, and errors on a bad
    /// spec; `configure` is what `on()` reads (a dedicated topic, restored afterwards).
    #[test]
    fn from_args_strips_the_flag_and_configures() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(!on(Topic::BoolNegate));
        let rest = from_args(s(&["prog", "x", "--debug", "boolnegate", "y"])).unwrap();
        assert_eq!(rest, s(&["prog", "x", "y"]));
        assert!(on(Topic::BoolNegate));
        let rest = from_args(s(&["a", "--debug=boolnegate;watch-call=0x42"])).unwrap();
        assert_eq!(rest, s(&["a"]));
        assert_eq!(watch_call(), Some(0x42));
        assert!(from_args(s(&["--debug"])).is_err());
        assert!(from_args(s(&["--debug", "no-such-topic"])).is_err());
        configure(Config::default());
        assert!(!on(Topic::BoolNegate) && watch_call().is_none());
    }
}
