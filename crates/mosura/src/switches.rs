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
//! Registering is the whole job: [`Switch::ALL`] gives the name to `--arms-off`, [`Knobs::on`]
//! answers at the site, and [`Knobs::stamp_parts`] puts it in the stamp — so a registered knob
//! cannot be silently unstamped, and `tests::every_emit_knob_is_registered` fails on ANY raw
//! `env::var("MOSURA_..")` / `env::var_os("MOSURA_..")` read in the library or the examples (the
//! diagnostics are a caller-configured [`crate::debug::Config`] since WP3, and the dev tier's
//! locations come from `dev-config.toml` through [`crate::devcfg`] since WP4).
//!
//! THE KNOBS ARE A VALUE, NOT A PROCESS STATE (2026-09-05, the environment-variable removal): a
//! front-end builds one [`Knobs`] from its flags (`--arms-off`, `--cspec`, `--disable-analyzers`),
//! the loader and the analysis carry it on the [`Program`](crate::analysis::Program), and every
//! [`Funcdata`](crate::decompile::Funcdata) decompiled from that program carries a copy — so a
//! knob is read where it applies and nowhere else. No environment variable is read for any knob,
//! and none is kept as a fallback: the process-global bitmask and the thread-local overrides this
//! replaced both existed to work around environment reads racing parallel tests, and a value
//! passed down needs no workaround.

/// One knob that changes an emitted tree. The render arms are NOT here — they are the arm
/// registry's own list ([`crate::decompile::emit::arms::registry::Recovered::ARMS`]), which owns a
/// typed `Sites` per arm and clears it to switch off; this table is every OTHER class, where "off"
/// means the code does not run at all. The two lists are joined for validation in one place
/// (`corpus_emit`'s `--arms-off`) and never authored twice.
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
    /// Callee-effects modelling in the analysis→decompiler bridge
    /// (`analysis::decompiler::record_callee_effects`): each direct call's recovered reads and
    /// writes, applied at the call. Review item of 2026-09-05: `MOSURA_CALLEE_EFFECTS=0` switched it
    /// off — CHANGING THE TREE — while escaping `every_emit_knob_is_registered`, because the site
    /// read it with `env::var_os` and the guard only matched `env::var(`. Registered here; the guard
    /// now matches both spellings.
    CalleeEffects,
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
        Switch::CalleeEffects,
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
            Switch::CalleeEffects => "callee-effects",
        }
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

/// The result-affecting knobs of one run, as a value: which switches are off, which analyzers
/// are disabled, which x86-32 compiler spec is declared. Built by the front-end from its flags,
/// carried on the [`Program`](crate::analysis::Program) from the loader on (the compiler-spec
/// decision is made while loading, so the loader takes it too), copied onto every
/// [`Funcdata`](crate::decompile::Funcdata) the program decompiles. `Default` is every switch ON,
/// nothing disabled, nothing declared — the product's own behaviour; an off value is always a
/// deliberate measurement, and [`Self::stamp_parts`] puts it in the manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Knobs {
    off: u32,
    /// Analyzer names the manager skips, comma-separated as the flag spells them — Ghidra's
    /// per-analyzer enablement option, the ablation instrument that attributes a discovery to
    /// the analyzer that made it (`ground_truth_parity`'s attribution assertions).
    pub disabled_analyzers: Option<String>,
    /// The x86-32 compiler spec to DECLARE instead of detecting (`watcom` | `gcc` | `highc`): a
    /// caller with out-of-band knowledge (a build recipe, a project file, a hypothesis under
    /// test) states the compiler the image itself does not reveal.
    pub x86_32_cspec: Option<String>,
}

impl Knobs {
    /// Declare the x86-32 compiler spec (builder form; the field is public too).
    pub fn with_x86_32_cspec(mut self, id: Option<&str>) -> Self {
        self.x86_32_cspec = id.map(str::to_string);
        self
    }

    /// Disable analyzers by name, comma-separated (builder form; the field is public too).
    pub fn with_disabled_analyzers(mut self, list: Option<&str>) -> Self {
        self.disabled_analyzers = list.map(str::to_string);
        self
    }

    /// Whether the knob is ON — i.e. its code runs.
    pub fn on(&self, s: Switch) -> bool {
        self.off & s.bit() == 0
    }

    /// Switch one off by name (`--arms-off`). Errors on an unknown name rather than ignoring it.
    pub fn turn_off(&mut self, name: &str) -> Result<(), String> {
        let s = Switch::by_name(name).ok_or_else(|| format!("unknown switch `{name}`"))?;
        self.off |= s.bit();
        Ok(())
    }

    /// Every switch not in its default state.
    pub fn non_default(&self) -> Vec<&'static str> {
        Switch::ALL.iter().copied().filter(|s| self.off & s.bit() != 0).map(|s| s.name()).collect()
    }

    /// Everything off its default, as the manifest's `arms:` stamp spells it: the switch names,
    /// then `cspec=<id>` for a declared compiler spec, then `disabled-analyzers=<list>`. A tree
    /// built under any of these differs from the baseline, so the stamp must say so.
    pub fn stamp_parts(&self) -> Vec<String> {
        let mut parts: Vec<String> = self.non_default().into_iter().map(str::to_string).collect();
        if let Some(c) = &self.x86_32_cspec {
            parts.push(format!("cspec={c}"));
        }
        if let Some(d) = &self.disabled_analyzers {
            parts.push(format!("disabled-analyzers={d}"));
        }
        parts
    }
}

/// Every raw `MOSURA_*` environment read in `src`, as `(1-based line, variable name)`. Both
/// spellings — `env::var("MOSURA_..")` and `env::var_os("MOSURA_..")` — because the guard that
/// matched only the first let `MOSURA_CALLEE_EFFECTS` change trees unstamped (review, 2026-09-05).
/// A function of the text so the guard's own eyesight is testable.
pub fn raw_env_reads(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        for needle in ["env::var(\"MOSURA_", "env::var_os(\"MOSURA_"] {
            let mut rest = line;
            while let Some(pos) = rest.find(needle) {
                let after = &rest[pos + needle.len()..];
                if let Some(name) = after.split('"').next() {
                    out.push((i + 1, format!("MOSURA_{name}")));
                }
                rest = after;
            }
        }
    }
    out
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
        assert_eq!(Switch::ALL.len(), 12);
        assert!(Switch::by_name("no-such-switch").is_none());
    }

    /// A knob that changes a tree must be in the table, or the manifest's `arms:` line lies about
    /// how the tree was built. This is the guard that keeps the class from growing back: it scans
    /// the emit path for raw environment reads and fails on any that is not a known DIAGNOSTIC
    /// (a print, a trace, a watch — nothing that reaches the emitted text) or this file's own.
    /// The guard's eyesight, pinned (review item, 2026-09-05): a read spelled `env::var_os` is a
    /// read. Before this test the scanner matched `env::var("MOSURA_` only, and
    /// `MOSURA_CALLEE_EFFECTS` — which changes the emitted tree — sat unregistered and unstamped
    /// behind a `var_os`. Both spellings, several per line.
    #[test]
    fn the_scanner_sees_both_spellings() {
        let src = "let a = std::env::var(\"MOSURA_FOO\");\n\
                   let b = std::env::var_os(\"MOSURA_BAR\").is_some();\n\
                   let c = 1;\n\
                   env::var(\"MOSURA_X\"); env::var_os(\"MOSURA_Y\");\n";
        let reads = raw_env_reads(src);
        assert_eq!(
            reads,
            vec![
                (1, "MOSURA_FOO".to_string()),
                (2, "MOSURA_BAR".to_string()),
                (4, "MOSURA_X".to_string()),
                (4, "MOSURA_Y".to_string()),
            ],
            "the var_os read on line 2 is the one the old guard missed"
        );
    }

    /// The value semantics the knobs exist for: independent instances, `Default` = all on, the
    /// stamp spells every non-default part, and an unknown name is an error rather than a no-op.
    #[test]
    fn knobs_are_a_value_with_a_stamp() {
        let all_on = Knobs::default();
        assert!(Switch::ALL.iter().all(|s| all_on.on(*s)));
        assert!(all_on.stamp_parts().is_empty());
        let mut k = Knobs::default();
        k.turn_off("ret-split").unwrap();
        k.turn_off("callee_effects").unwrap(); // `_` accepted like `-`
        assert!(!k.on(Switch::RetSplit) && !k.on(Switch::CalleeEffects) && k.on(Switch::Agg));
        assert!(all_on.on(Switch::RetSplit), "another instance is untouched");
        assert!(k.turn_off("no-such-switch").is_err());
        k.x86_32_cspec = Some("watcom".into());
        k.disabled_analyzers = Some("Function Start Search".into());
        assert_eq!(
            k.stamp_parts(),
            vec!["ret-split", "callee-effects", "cspec=watcom", "disabled-analyzers=Function Start Search"]
        );
    }

    /// A knob that changes a tree must be in the table, or the manifest's `arms:` line lies about
    /// how the tree was built; a diagnostic is a `debug::Config` field the caller sets. So NO
    /// `MOSURA_*` environment read may exist in the library or the examples: this guard scans them
    /// and fails on any, naming file:line. (This file is exempt because its scanner test carries
    /// the pattern as test data.)
    #[test]
    fn every_emit_knob_is_registered() {
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
            if p.file_name().is_some_and(|n| n == "switches.rs") {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(&p) else { continue };
            for (line, full) in raw_env_reads(&src) {
                unregistered.push(format!(
                    "{}:{} reads {full} from the environment — a knob is a `Knobs` value, a diagnostic a `debug::Config` field",
                    p.display(),
                    line
                ));
            }
        }
        assert!(unregistered.is_empty(), "unregistered emit knobs:\n  {}", unregistered.join("\n  "));
    }
}
