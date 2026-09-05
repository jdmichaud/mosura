//! THE EMIT SWITCHES: one place every knob that changes WHAT A TREE CONTAINS is read from.
//!
//! Review R6 made this move for diagnostics — before it, "every print site read its own
//! environment variable (80 names, 141 reads)", and [`crate::debug`] replaced them with one table,
//! one resolution and one name space. **The knobs that change the EMITTED TEXT never got the same
//! treatment**, and they matter more: a print cannot make a tree differ from its baseline, and
//! these can.
//!
//! What that cost, before this module (2026-09-04): nine knobs changed what the survey emitted,
//! each read at its own site with its own spelling of "off" (`!= Ok("0")`, `!= Ok("recovered")`,
//! `== Ok("0")`), and **not one of them reached the manifest's `arms:` line.** So the line said
//! which ARMS a tree was built with while a tree built with `MOSURA_KERNEL_NET=0` carried an
//! identical line and a materially different emit — the stamp promised what it could not deliver,
//! which is the one thing a self-describing tree exists for.
//!
//! THE RULE: **a knob is registered here iff it can change a tree.** A knob that only changes what
//! is PRINTED to stderr is a [`crate::debug`] topic; a knob that only widens a `--only` probe
//! (`MOSURA_PROBE_FULL`, `MOSURA_CONS_PROBE`) never produces a tree and stays where it is.
//!
//! Registering is the whole job: [`Switch::ALL`] gives the name to `--arms-off`, [`on`] answers at
//! the site, and [`non_default`] puts it in the stamp — so a registered knob cannot be silently
//! unstamped, and `tests::every_emit_knob_is_registered` fails on a raw `env::var("MOSURA_..")`
//! read outside this file that is not a known diagnostic.
//!
//! LEGACY NAMES are kept: each switch answers to the environment variable it was read from before,
//! with that site's own off-value, so the round scripts that set `MOSURA_GLOBAL_WIDTH=recovered`
//! keep working. New knobs should use `--arms-off <name>` and add no variable at all.
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

/// One knob that changes an emitted tree. The render arms are NOT here — they are the arm
/// registry's own list ([`crate::decompile::emit::arms::registry::Recovered::ARMS`]), which owns a
/// typed `Sites` per arm and clears it to switch off; this table is every OTHER class, where "off"
/// means the code does not run at all. The two lists are joined for validation in one place
/// (`war2_survey`'s `--arms-off`) and never authored twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Switch {
    /// The global-width arm: declare a Ram global at the width the ORIGINAL's own stores prove.
    GlobalWidth,
    /// Contract-directed drift: a call's arity adopted across preserving calls (Order Y).
    ConsReach,
    /// The call-network kernel of the consistency pass.
    KernelNet,
    /// The stack-append kernel of the consistency pass.
    KernelStackApp,
    /// The shared-return arm: a function whose returns were split renders the shared tail.
    SharedRet,
    /// The consistency pass itself — the candidate adoption that resolves contradicted call shapes.
    Consistency,
    /// The whole-program prototype pass (pass 1), which pass 2's callers consult.
    ProtoPass,
    /// Ghidra's `ActionReturnSplit` in the port (`decompile::blockjoin`) — a measurement switch for
    /// the shared-return investigation, not a doctrine change.
    RetSplit,
    /// The frame aggregate (frame-fill's declaration effect).
    Agg,
    /// ARGUMENT CARRY: the register arguments a call passes beyond its callee's arity move to the
    /// NEXT call. An IR MUTATION, not a render arm — it rewrites the ops before the printer sees
    /// them, so it has no `Sites` to clear and cannot be inert on an empty witness set.
    ArgumentCarry,
    /// The caller-side clobber witness: a register this function saves without touching is added to
    /// its callees' declared `modify`. Rewrites the recovered CONTRACT, not a rendering.
    CalleeClobbers,
}

impl Switch {
    pub const ALL: &'static [Switch] = &[
        Switch::GlobalWidth,
        Switch::ConsReach,
        Switch::KernelNet,
        Switch::KernelStackApp,
        Switch::SharedRet,
        Switch::Consistency,
        Switch::ProtoPass,
        Switch::RetSplit,
        Switch::Agg,
        Switch::ArgumentCarry,
        Switch::CalleeClobbers,
    ];

    /// The switch's name, as `--arms-off` and the stamp spell it.
    pub fn name(self) -> &'static str {
        match self {
            Switch::GlobalWidth => "global-width",
            Switch::ConsReach => "cons-reach",
            Switch::KernelNet => "kernel-net",
            Switch::KernelStackApp => "kernel-stackapp",
            Switch::SharedRet => "shared-ret",
            Switch::Consistency => "consistency",
            Switch::ProtoPass => "proto-pass",
            Switch::RetSplit => "ret-split",
            Switch::Agg => "frame-agg",
            Switch::ArgumentCarry => "argument-carry",
            Switch::CalleeClobbers => "callee-clobbers",
        }
    }

    /// The variable this knob was read from before the table, and the value that meant OFF there.
    /// Kept so existing round scripts keep working; `None` for a switch that never had one.
    fn legacy(self) -> Option<(&'static str, &'static str)> {
        Some(match self {
            Switch::GlobalWidth => ("MOSURA_GLOBAL_WIDTH", "recovered"),
            Switch::ConsReach => ("MOSURA_CONS_REACH", "0"),
            Switch::KernelNet => ("MOSURA_KERNEL_NET", "0"),
            Switch::KernelStackApp => ("MOSURA_KERNEL_STACKAPP", "0"),
            Switch::SharedRet => ("MOSURA_SHARED_RET", "0"),
            Switch::Consistency => ("MOSURA_CONSISTENCY", "0"),
            Switch::ProtoPass => ("MOSURA_PROTO_PASS", "0"),
            Switch::RetSplit => ("MOSURA_RETSPLIT", "0"),
            Switch::Agg => ("MOSURA_AGG", "0"),
            Switch::ArgumentCarry | Switch::CalleeClobbers => return None,
        })
    }

    fn bit(self) -> u32 {
        1 << (self as u8 as u32)
    }

    /// The switch of this name, for `--arms-off`.
    pub fn by_name(name: &str) -> Option<Switch> {
        let n = name.replace('_', "-");
        Switch::ALL.iter().copied().find(|s| s.name() == n)
    }
}

/// Switched off by the environment — resolved ONCE, like `MOSURA_DEBUG`.
static ENV_OFF: OnceLock<u32> = OnceLock::new();
/// Switched off by `--arms-off`, which the caller applies while parsing its arguments.
static CLI_OFF: AtomicU32 = AtomicU32::new(0);

fn env_off() -> u32 {
    *ENV_OFF.get_or_init(|| {
        let mut m = 0;
        for s in Switch::ALL {
            if let Some((var, off)) = s.legacy() {
                if std::env::var(var).as_deref() == Ok(off) {
                    m |= s.bit();
                }
            }
        }
        m
    })
}

/// Whether the knob is ON — i.e. its code runs. Every switch defaults ON: this table holds the
/// adaptations the product emits, and an off value is always a deliberate measurement.
pub fn on(s: Switch) -> bool {
    (env_off() | CLI_OFF.load(Ordering::Relaxed)) & s.bit() == 0
}

/// Switch one off by name (`--arms-off`). Errors on an unknown name rather than ignoring it.
pub fn turn_off(name: &str) -> Result<(), String> {
    let s = Switch::by_name(name).ok_or_else(|| format!("unknown switch `{name}`"))?;
    CLI_OFF.fetch_or(s.bit(), Ordering::Relaxed);
    Ok(())
}

/// Every switch not in its default state, for the manifest stamp — the whole point of the table.
pub fn non_default() -> Vec<&'static str> {
    let m = env_off() | CLI_OFF.load(Ordering::Relaxed);
    Switch::ALL.iter().copied().filter(|s| m & s.bit() != 0).map(|s| s.name()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table is the name space: no duplicate names, and every switch answers to its own name.
    #[test]
    fn names_are_unique_and_resolve() {
        let mut seen: Vec<&str> = Vec::new();
        for s in Switch::ALL {
            assert!(!seen.contains(&s.name()), "duplicate switch name {}", s.name());
            seen.push(s.name());
            assert_eq!(Switch::by_name(s.name()), Some(*s));
        }
        assert_eq!(Switch::ALL.len(), 11);
        assert!(Switch::by_name("no-such-switch").is_none());
    }

    /// A knob that changes a tree must be in the table, or the manifest's `arms:` line lies about
    /// how the tree was built. This is the guard that keeps the class from growing back: it scans
    /// the emit path for raw environment reads and fails on any that is not a known DIAGNOSTIC
    /// (a print, a trace, a watch — nothing that reaches the emitted text) or this file's own.
    #[test]
    fn every_emit_knob_is_registered() {
        const DIAGNOSTIC: &[&str] = &[
            "MOSURA_DEBUG",
            "MOSURA_TRACE",
            "MOSURA_TRACE_FUNC",
            "MOSURA_WATCH_CALL",
            "MOSURA_MERGE_WATCH",
            "MOSURA_OPACTION",
            "MOSURA_GT_RAW",
            "MOSURA_AOU_PC",
            "MOSURA_RECOVER_FIXPOINT",
            "MOSURA_PROBE_FULL",
            "MOSURA_CONS_PROBE",
        ];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files: Vec<std::path::PathBuf> = Vec::new();
        let mut stack = vec![root.join("src"), root.join("examples")];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    files.push(p);
                }
            }
        }
        let mut unregistered: Vec<String> = Vec::new();
        for p in files {
            // The FACILITY files: each owns a documented accessor for its own class of knob and is
            // the one place its variables are read — `debug` the diagnostic topics, `paths` the
            // tree locations, `overrides` the analysis overrides (a forced cspec, a disabled
            // analyzer), which change a tree and are therefore stamped, but carry VALUES rather
            // than being on/off and so live with their own thread-scoped guard rather than here.
            if p.file_name().is_some_and(|n| {
                n == "switches.rs" || n == "debug.rs" || n == "paths.rs" || n == "overrides.rs"
            }) {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(&p) else { continue };
            for (i, line) in src.lines().enumerate() {
                let Some(rest) = line.split("env::var(\"MOSURA_").nth(1) else { continue };
                let Some(name) = rest.split('"').next() else { continue };
                let full = format!("MOSURA_{name}");
                if DIAGNOSTIC.contains(&full.as_str()) {
                    continue;
                }
                if Switch::ALL.iter().any(|s| s.legacy().is_some_and(|(v, _)| v == full)) {
                    unregistered.push(format!(
                        "{}:{} reads {full} directly — call switches::on() instead",
                        p.display(),
                        i + 1
                    ));
                } else {
                    unregistered.push(format!(
                        "{}:{} reads {full}, which is neither a switch nor a known diagnostic",
                        p.display(),
                        i + 1
                    ));
                }
            }
        }
        assert!(unregistered.is_empty(), "unregistered emit knobs:\n  {}", unregistered.join("\n  "));
    }
}
