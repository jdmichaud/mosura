//! THE DEBUG FACILITY (review R6): one place every diagnostic print of the crate is switched from.
//!
//! `MOSURA_DEBUG=topic,topic,..` (or `all`) is read ONCE per process into a static; each subsystem
//! owns a [`Topic`], and a diagnostic print is written `debug!(Topic::X, "..", ..)` — the text
//! goes to stderr, prefixed `[x]`, only when its topic is on. Before R6 every print site read its
//! own environment variable (`MOSURA_SPARSE_DEBUG`, `MOSURA_ARG_DEBUG`, .. — 80 names, 141 reads
//! outside paths.rs); the migrations replace those reads with [`on`], text verbatim, one
//! subsystem per commit. A print never reaches the emitted text, so the survey's trees do not move
//! (the identity chain says so once per migration batch).
//!
//! Topic names are the kebab-case of the variant (`sparse-switch`, `struct-copy`, ..); an unknown
//! name in `MOSURA_DEBUG` is reported once on stderr and ignored, never a silent no-op.
use std::sync::OnceLock;

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
    /// the survey's own env-gated diagnostics (examples/war2_survey.rs: was `MOSURA_KERNEL_SHADOW`,
    /// `_SHARED_RET_DEBUG`, `_SHADOW_DEBUG`, `_RAW_IR`, `_EXTENT`, `_AUX_DEBUG`, `_AGG_DEBUG`,
    /// `_ZAP_DEBUG`) — its normal output (the manifest, the summaries) is not a diagnostic and
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
}

impl Topic {
    pub const ALL: &'static [Topic] = &[
        Topic::SparseSwitch, Topic::StructCopy, Topic::FrameFill, Topic::SumOrder, Topic::Printc, Topic::Recover,
        Topic::Structure, Topic::JumpTable, Topic::Args, Topic::Varargs, Topic::RetSplit, Topic::Effects,
        Topic::Varmap, Topic::StackVars, Topic::Heritage, Topic::Pointers, Topic::Pipeline, Topic::Watsched,
        Topic::GroundTruth, Topic::Cspec, Topic::Analysis, Topic::Merge, Topic::Survey, Topic::Perf, Topic::Types, Topic::Subvar,
    ];
    /// The kebab-case name used in `MOSURA_DEBUG` and as the print prefix.
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
        }
    }
}

fn parse(spec: &str) -> [bool; 32] {
    let mut on = [false; 32];
    for tok in spec.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if tok == "all" {
            for t in Topic::ALL {
                on[*t as usize] = true;
            }
            continue;
        }
        match Topic::ALL.iter().find(|t| t.name() == tok) {
            Some(t) => on[*t as usize] = true,
            None => eprintln!(
                "MOSURA_DEBUG: unknown topic `{tok}` (known: {}, all)",
                Topic::ALL.iter().map(|t| t.name()).collect::<Vec<_>>().join(",")
            ),
        }
    }
    on
}

static TOPICS: OnceLock<[bool; 32]> = OnceLock::new();

/// Whether `topic`'s diagnostics are on — `MOSURA_DEBUG`, read once per process.
pub fn on(topic: Topic) -> bool {
    TOPICS.get_or_init(|| parse(&std::env::var("MOSURA_DEBUG").unwrap_or_default()))[topic as usize]
}

/// A diagnostic print under a topic: `debug!(Topic::X, "fmt", args..)` — stderr, prefixed with the
/// topic's name, only when the topic is on.
#[macro_export]
macro_rules! debug {
    ($topic:expr, $($arg:tt)*) => {
        if $crate::debug::on($topic) {
            eprintln!("[{}] {}", $topic.name(), format!($($arg)*));
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_names_round_trip_and_all_selects_everything() {
        let on = parse("sparse-switch, struct-copy");
        assert!(on[Topic::SparseSwitch as usize] && on[Topic::StructCopy as usize] && !on[Topic::Printc as usize]);
        let all = parse("all");
        assert!(Topic::ALL.iter().all(|t| all[*t as usize]));
        for t in Topic::ALL {
            assert_eq!(Topic::ALL.iter().find(|u| u.name() == t.name()), Some(t), "unique name {}", t.name());
        }
        assert!(parse("").iter().all(|b| !b));
    }
}
