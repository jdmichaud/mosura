//! `CompilerDriver` — generic compiler-driving logic over a [`CompilerSpec`].
//!
//! Everything a particular compiler needs is in its spec; everything the DRIVING needs — write the
//! sources, build the invocation, run it, collect the objects, split the diagnostics — is here and
//! is the same for all of them. The DOS-hosted Watcom baseline had its own `WatcomDos` type until
//! 2026-09-03; it is now [`spec::watcom_10_0a_dos`] plus this file, which is the point of the
//! factoring: that compiler stopped being a special case and became one row of data.
//!
//! Its behaviours were PORTED, not inherited -- the batching, the isolation retry, the
//! adjudication rule -- and the log SPLIT was re-expressed as spec data ([`LogSplit`]) rather than
//! copied. Two live tests written against the old type (a rejected unit carries ITS OWN
//! diagnostic; a unit after a failing one still compiles) pass against this driver unchanged,
//! which is what makes the port's faithfulness a measurement rather than a claim.
//!
//! ## Off by default (design §0)
//!
//! Constructing a driver does not run anything, and nothing in the default emit path constructs
//! one. mosura builds, tests and gates with no compiler installed. That is not a convention to be
//! remembered — the gate has no compiler to invoke, so a compiler-assisted number cannot enter it
//! by accident.
//!
//! ## Why an invocation is LABELLED (design §1)
//!
//! JD's requirement is that we write the deterministic algorithm and treat the compiler as a last
//! resort — the risk being not mosura's runtime but our own temptation to compile-and-pick where a
//! deduction is merely harder to write. A rule that is only written down is not enforcement, so
//! every invocation carries a [`DriverRole`], and the one role that represents skipped work
//! ([`DriverRole::RuntimeLastResort`]) is COUNTED. The count is a debt: it is expected to fall as
//! algorithms reclaim decisions, and if it only grows we can see that we are doing the feared
//! thing.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::spec::{CompilerSpec, Invocation, LogSplit};
use super::{CompileOutput, CompileUnit, Toolchain};

/// Why the compiler is being run. Recorded on every invocation; see the module note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverRole {
    /// Checking recovered output against the target — `recompile_check`. The compiler is the
    /// authority on what it emits, so this is not a shortcut and never was.
    Validation,
    /// Offline, to LEARN a deterministic rule that will then ship without it. The compiler helping
    /// us do the hard work rather than skip it.
    DevelopmentAssistance,
    /// Deciding output at runtime because the answer is not deterministically recoverable from the
    /// bytes. A genuine information limit, and the only role that is debt.
    RuntimeLastResort {
        /// What is information-limited here, in a form a reviewer can judge as a genuine limit
        /// rather than an unwritten algorithm.
        limit: String,
    },
}

/// Count of [`DriverRole::RuntimeLastResort`] invocations this process has made — the debt.
static LAST_RESORT_COUNT: AtomicU64 = AtomicU64::new(0);

/// How many last-resort invocations have happened. Zero is the target and a legitimate answer.
pub fn last_resort_debt() -> u64 {
    LAST_RESORT_COUNT.load(Ordering::Relaxed)
}

/// Whether the compiler ANSWERED about a unit: it produced the object, or it said something
/// about it. Anything else means the environment failed, not the source.
///
/// This is a pure function and pinned in the gate because getting it wrong is invisible. The
/// cache stores only adjudicated entries, so marking an unjudged unit `true` writes a false
/// COMPILE_FAIL into the cache as a property of the SOURCE, where it survives every later run —
/// and no compiler-free test can see it, because by construction no compiler ran. A dosemu
/// hiccup or a full disk mid-round is exactly the case.
pub fn adjudicated_from(object: Option<&[u8]>, log: &str) -> bool {
    object.is_some() || !log.trim().is_empty()
}

/// Reset the debt counter (tests).
pub fn reset_last_resort_debt() {
    LAST_RESORT_COUNT.store(0, Ordering::Relaxed);
}

/// A compiler, driven.
pub struct CompilerDriver {
    /// Units per session. Batching is what makes a corpus run possible under an emulator; the
    /// isolation retry in `compile_batch` is what keeps it honest when a session dies.
    pub batch_size: usize,
    spec: CompilerSpec,
    /// The compiler's installation, as the invocation's `{install}` placeholder.
    install_dir: PathBuf,
    /// Scratch directory: sources in, objects out.
    work_dir: PathBuf,
    role: DriverRole,
    own_work_dir: bool,
}

impl Drop for CompilerDriver {
    fn drop(&mut self) {
        if self.own_work_dir {
            let _ = std::fs::remove_dir_all(&self.work_dir);
        }
    }
}

impl CompilerDriver {
    /// Build a driver. Creates the work directory; runs nothing.
    pub fn new(
        spec: CompilerSpec,
        install_dir: impl AsRef<Path>,
        work_dir: impl AsRef<Path>,
        role: DriverRole,
    ) -> std::io::Result<Self> {
        let work_dir = work_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&work_dir)?;
        if let DriverRole::RuntimeLastResort { .. } = role {
            LAST_RESORT_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Self {
            spec,
            install_dir: install_dir.as_ref().to_path_buf(),
            work_dir,
            role,
            own_work_dir: false,
            batch_size: 200,
        })
    }

    /// Delete the work directory on drop.
    pub fn owning_work_dir(mut self) -> Self {
        self.own_work_dir = true;
        self
    }

    pub fn spec(&self) -> &CompilerSpec {
        &self.spec
    }

    pub fn role(&self) -> &DriverRole {
        &self.role
    }

    fn subst(&self, s: &str, unit: Option<&CompileUnit>, script: &str) -> String {
        let mut out = s
            .replace("{install}", &self.install_dir.to_string_lossy())
            .replace("{work}", &self.work_dir.to_string_lossy())
            .replace("{script}", script);
        if let Some(u) = unit {
            let flags = if u.flags.is_empty() { self.spec.flags.clone() } else { u.flags.clone() };
            let obj = self.spec.object_names_for(&u.key).first().cloned().unwrap_or_default();
            out = out
                .replace("{flags}", &flags.join(" "))
                .replace("{src}", &self.spec.source_name_for(&u.key))
                .replace("{obj}", &obj)
                .replace("{key}", &u.key);
        }
        if let Some(log) = &self.spec.log_name {
            out = out.replace("{log}", log);
        }
        out
    }

    /// Write each unit's source (prelude + body) and clear any stale object.
    fn stage(&self, units: &[CompileUnit]) {
        for u in units {
            let mut text = String::with_capacity(self.spec.prelude.len() + u.source.len() + 1);
            text.push_str(&self.spec.prelude);
            text.push('\n');
            text.push_str(&u.source);
            let _ = std::fs::write(self.work_dir.join(self.spec.source_name_for(&u.key)), text);
            for n in self.spec.object_names_for(&u.key) {
                let _ = std::fs::remove_file(self.work_dir.join(n));
            }
        }
        if let Some(log) = &self.spec.log_name {
            let _ = std::fs::remove_file(self.work_dir.join(log));
        }
    }

    /// Build the batch script's text. Public for the fixture tests: this is spec-driven logic and
    /// is checked WITHOUT a compiler (design §3).
    pub fn script_text(&self, units: &[CompileUnit]) -> Option<String> {
        let Invocation::Script { ending, preamble, per_unit, .. } = &self.spec.invocation else {
            return None;
        };
        let mut s = String::new();
        for line in preamble {
            s.push_str(&self.subst(line, None, ""));
            s.push_str(ending.as_str());
        }
        for u in units {
            s.push_str(&self.subst(per_unit, Some(u), ""));
            s.push_str(ending.as_str());
        }
        Some(s)
    }

    /// The argv the driver would run. Public for the same reason as [`Self::script_text`].
    pub fn command_line(&self, unit: Option<&CompileUnit>) -> Vec<String> {
        match &self.spec.invocation {
            Invocation::Script { name, command, .. } => {
                command.iter().map(|a| self.subst(a, unit, name)).collect()
            }
            Invocation::Native { command } => {
                // A `{flags}` argument expands to several argv entries, not one.
                let mut out = Vec::new();
                for a in command {
                    if a == "{flags}" {
                        let flags = unit
                            .map(|u| {
                                if u.flags.is_empty() {
                                    self.spec.flags.clone()
                                } else {
                                    u.flags.clone()
                                }
                            })
                            .unwrap_or_else(|| self.spec.flags.clone());
                        out.extend(flags);
                    } else {
                        out.push(self.subst(a, unit, ""));
                    }
                }
                out
            }
        }
    }

    /// Run one session and return each unit's OWN diagnostics, positionally.
    fn run(&self, units: &[CompileUnit]) -> Vec<String> {
        match &self.spec.invocation {
            Invocation::Script { name, log_split, .. } => {
                if let Some(text) = self.script_text(units) {
                    let _ = std::fs::write(self.work_dir.join(name), text);
                }
                let argv = self.command_line(None);
                let Some((prog, args)) = argv.split_first() else {
                    return vec![String::new(); units.len()];
                };
                let _ = std::process::Command::new(prog)
                    .args(args)
                    .current_dir(&self.work_dir)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
                self.split_log(units, &self.log_text(), log_split)
            }
            Invocation::Native { .. } => {
                // One process per unit, so the unit's diagnostics are simply its own output --
                // captured, not discarded: for a native compiler there is no log FILE, and
                // throwing stderr away would leave a genuine rejection looking like a silent
                // abort (`adjudicated_from` would return false and the verdict would never cache).
                units
                    .iter()
                    .map(|u| {
                        let argv = self.command_line(Some(u));
                        let Some((prog, args)) = argv.split_first() else { return String::new() };
                        match std::process::Command::new(prog)
                            .args(args)
                            .current_dir(&self.work_dir)
                            .output()
                        {
                            Ok(out) => {
                                let mut t = String::from_utf8_lossy(&out.stdout).into_owned();
                                t.push_str(&String::from_utf8_lossy(&out.stderr));
                                t
                            }
                            Err(_) => String::new(),
                        }
                    })
                    .collect()
            }
        }
    }

    /// Attribute a session log to its units. Spec-driven and pure, so the gate tests it without
    /// a compiler (design §3); `text` is passed in for exactly that reason.
    pub fn split_log(&self, units: &[CompileUnit], text: &str, split: &LogSplit) -> Vec<String> {
        let LogSplit::PerUnit { terminator, banners } = split else {
            return vec![text.to_string(); units.len()];
        };
        let mut out = vec![String::new(); units.len()];
        let mut current = String::new();
        for line in text.lines() {
            if banners.iter().any(|b| line.starts_with(b.as_str())) {
                continue;
            }
            current.push_str(line);
            current.push('\n');
            if let Some((name, _)) = line.split_once(terminator.as_str()) {
                let stem = name.trim().rsplit(['\\', '/']).next().unwrap_or("").to_ascii_uppercase();
                // The terminator carries the file NAME; match it against the source name the spec
                // would have produced, so a spec whose sources are not `{key}.C` still attributes.
                let hit = units.iter().position(|u| {
                    let src = self.spec.source_name_for(&u.key).to_ascii_uppercase();
                    // Exact on the STEM, never a prefix: `T0` must not claim `T01`'s block.
                    !stem.is_empty() && src.split('.').next() == Some(stem.as_str())
                });
                if let Some(i) = hit {
                    out[i] = std::mem::take(&mut current);
                } else {
                    current.clear();
                }
            }
        }
        // Whatever is left belongs to the unit that stopped the session.
        if !current.trim().is_empty() {
            if let Some(i) = out.iter().position(|s| s.is_empty()) {
                out[i] = current;
            }
        }
        out
    }

    fn read_object(&self, key: &str) -> Option<Vec<u8>> {
        self.spec
            .object_names_for(key)
            .into_iter()
            .find_map(|n| std::fs::read(self.work_dir.join(n)).ok())
    }

    fn log_text(&self) -> String {
        self.spec
            .log_name
            .as_ref()
            .and_then(|n| std::fs::read_to_string(self.work_dir.join(n)).ok())
            .unwrap_or_default()
    }
}

impl Toolchain for CompilerDriver {
    fn id(&self) -> String {
        // The prelude changes the emitted bytes, so it is part of the identity — the property
        // `the_prelude_is_part_of_the_toolchain_identity` pins for the Watcom driver.
        let mut h = super::cache::Fnv::new();
        h.write(self.spec.prelude.as_bytes());
        h.write(self.spec.flags.join(" ").as_bytes());
        format!("{}-{}", self.spec.id, h.hex())
    }

    fn compile_batch(&self, units: &[CompileUnit]) -> Vec<CompileOutput> {
        let mut results: Vec<CompileOutput> = units
            .iter()
            .map(|u| CompileOutput {
                key: u.key.clone(),
                object: None,
                log: String::new(),
                // Nothing has judged this unit yet. The loop sets it only where the compiler
                // answered; a unit that reaches isolation still silent keeps `false`, so its
                // non-answer is never cached as a fact about the source.
                adjudicated: false,
            })
            .collect();

        // Index list, so failure isolation can re-run a subset without losing positions. One
        // aborted session must not condemn the units that merely shared it: they are retried in
        // smaller groups, and alone, before anything is concluded about them.
        let mut pending: Vec<usize> = (0..units.len()).collect();
        let mut group = self.batch_size.max(1);
        while !pending.is_empty() {
            let mut next_round: Vec<usize> = Vec::new();
            for chunk in pending.chunks(group) {
                let batch: Vec<CompileUnit> = chunk.iter().map(|&i| units[i].clone()).collect();
                self.stage(&batch);
                let logs = self.run(&batch);
                for (&i, log) in chunk.iter().zip(logs) {
                    let object = self.read_object(&units[i].key);
                    if adjudicated_from(object.as_deref(), &log) {
                        results[i].object = object;
                        results[i].log = log;
                        results[i].adjudicated = true;
                    } else {
                        next_round.push(i);
                    }
                }
            }
            if group == 1 {
                // Already alone and still silent: not a rejection, a non-compile. Say so in the
                // log for the reader, and leave `adjudicated` false so it is not cached.
                for i in next_round {
                    if results[i].log.trim().is_empty() {
                        results[i].log = "no object and no diagnostic (compiler aborted)".into();
                    }
                }
                break;
            }
            group = (group / 8).max(1);
            pending = next_round;
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::super::spec;
    use super::*;

    fn unit(key: &str, flags: &[&str]) -> CompileUnit {
        CompileUnit {
            key: key.into(),
            source: "void p(void){}".into(),
            flags: flags.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn drv(spec: CompilerSpec) -> CompilerDriver {
        let work = std::env::temp_dir().join(format!("mosura-drv-{}", std::process::id()));
        CompilerDriver::new(spec, "/opt/watcom", work, DriverRole::Validation).unwrap()
    }

    /// The DOS-hosted baseline's batch file, byte for byte -- CRLF, the four environment lines,
    /// the drive change, one `WCC386` line per unit redirecting to the log.
    ///
    /// The literal below IS the text the retired `WatcomDos::run_session` built inline, kept here
    /// when that type was deleted. So this no longer compares two implementations; it pins the
    /// spec against the hand-written original, which is the useful half and was always the point:
    /// an edit that changes what the compiler is actually told fails HERE, in a compiler-free
    /// test, instead of silently in a round. Compiler-free, so it runs IN the gate.
    #[test]
    fn the_watcom_script_matches_the_hand_written_batch_file() {
        let d = drv(spec::watcom_10_0a_dos(""));
        let text = d
            .script_text(&[unit("T00000", &["-5r", "-s"]), unit("T00001", &[])])
            .expect("the Watcom spec is a Script invocation");
        let expected = "@echo off\r\n\
             SET WATCOM=F:\\\r\n\
             SET PATH=F:\\BINB;F:\\BIN;F:\\BINP\r\n\
             SET INCLUDE=F:\\H\r\n\
             G:\r\n\
             WCC386 -5r -s T00000.C >>WCCOUT.TXT\r\n\
             WCC386 -5r -fpi87 -s -onatx T00001.C >>WCCOUT.TXT\r\n";
        assert_eq!(text, expected);
    }

    /// A unit with no flags of its own takes the spec's profile; one with flags overrides it.
    /// (Pinned by the line-per-unit difference in the test above; asserted here directly.)
    #[test]
    /// Note the fallback is the one place the driver deliberately differed from the retired
    /// `WatcomDos`, which passed a flagless unit NO flags at all. Benign, because the profile it falls back to
    /// is `buildconfig::watcom_10_0a().base` (pinned by the test above) and `recompile_check`
    /// sets flags per unit anyway -- but it is a real behavioural difference, so it is stated
    /// here rather than left inside a claim that the driver reproduces WatcomDos.
    fn unit_flags_override_the_spec_profile_and_empty_falls_back() {
        let d = drv(spec::watcom_10_0a_dos(""));
        let t = d.script_text(&[unit("A", &["-zz"])]).unwrap();
        assert!(t.contains("WCC386 -zz A.C"), "unit flags win: {t}");
        let t2 = d.script_text(&[unit("B", &[])]).unwrap();
        assert!(t2.contains("WCC386 -5r -fpi87 -s -onatx B.C"), "spec profile fills in: {t2}");
    }

    /// The wrapper command: the two `-d` flags are install-then-work, in that order, because the
    /// emulator maps them to F: and G: positionally and the batch file names those drives.
    #[test]
    fn the_watcom_invocation_maps_install_to_f_and_work_to_g() {
        let d = drv(spec::watcom_10_0a_dos(""));
        let argv = d.command_line(None);
        let i = argv.iter().position(|a| a == "/opt/watcom").expect("install dir present");
        let j = argv.iter().position(|a| a.contains("mosura-drv-")).expect("work dir present");
        assert!(i < j, "install must precede work (F: then G:): {argv:?}");
        assert_eq!(argv.first().map(String::as_str), Some("dosemu"));
        assert_eq!(argv.last().map(String::as_str), Some("G:\\_BUILD.BAT"));
    }

    /// THE CONFIGURABILITY CLAIM (design §4): swapping the spec must absorb the dosemu->native
    /// change with no code change. Same driver, same units; a Script spec yields a batch file and
    /// an emulator command, a Native spec yields neither and one argv per unit.
    #[test]
    fn a_spec_swap_absorbs_the_dosemu_to_native_invocation_change() {
        let dos = drv(spec::watcom_10_0a_dos(""));
        assert!(dos.script_text(&[unit("A", &[])]).is_some(), "DOS spec is script-driven");

        let native = drv(spec::open_watcom_2_native("wcc386", ""));
        assert!(native.script_text(&[unit("A", &[])]).is_none(), "native spec writes no script");
        let argv = native.command_line(Some(&unit("A", &[])));
        assert_eq!(argv.first().map(String::as_str), Some("wcc386"));
        assert!(argv.contains(&"A.c".to_string()), "native names the source directly: {argv:?}");
        assert!(!argv.iter().any(|a| a == "dosemu"), "no emulator: {argv:?}");
    }

    /// THE GENERALIZATION CLAIM (design §4): a foreign toolchain, native, ELF not OMF, its own
    /// flags -- and `{flags}` expands to SEVERAL argv entries, not one quoted blob.
    #[test]
    fn the_gcc_spec_is_native_elf_and_expands_flags_as_separate_argv() {
        let d = drv(spec::gcc_native("gcc", ""));
        assert_eq!(d.spec().object_format, spec::ObjectFormat::Elf);
        let argv = d.command_line(Some(&unit("t", &[])));
        assert_eq!(argv.first().map(String::as_str), Some("gcc"));
        for f in ["-m32", "-c", "-O2", "-fno-pic"] {
            assert!(argv.iter().any(|a| a == f), "{f} is its own argv entry: {argv:?}");
        }
        assert!(argv.contains(&"t.o".to_string()), "ELF object name: {argv:?}");
    }

    /// The prelude is a compiler input, so it is part of the identity -- the property
    /// `watcom.rs` pins for the DOS driver, carried over. Without it a cached COMPILE_FAIL from a
    /// prelude-less run is served forever to runs that HAVE the prelude (measured).
    #[test]
    fn the_prelude_and_flags_are_part_of_the_driver_identity() {
        let a = drv(spec::watcom_10_0a_dos("struct p8 { int a; int b; };")).id();
        let b = drv(spec::watcom_10_0a_dos("")).id();
        assert_ne!(a, b, "a changed prelude is a changed toolchain identity");
        let mut s = spec::watcom_10_0a_dos("");
        s.flags = vec!["-od".into()];
        assert_ne!(drv(s).id(), b, "a changed flag profile is a changed identity");
    }

    /// The debt counter (design §1): only the last-resort role counts. Validation and
    /// development-assistance are legitimate uses of the compiler and are not debt.
    #[test]
    fn only_the_last_resort_role_is_counted_as_debt() {
        reset_last_resort_debt();
        let w = std::env::temp_dir().join(format!("mosura-debt-{}", std::process::id()));
        let s = || spec::watcom_10_0a_dos("");
        let _ = CompilerDriver::new(s(), "/i", &w, DriverRole::Validation).unwrap();
        let _ = CompilerDriver::new(s(), "/i", &w, DriverRole::DevelopmentAssistance).unwrap();
        assert_eq!(last_resort_debt(), 0, "legitimate roles are not debt");
        let _ = CompilerDriver::new(
            s(),
            "/i",
            &w,
            DriverRole::RuntimeLastResort { limit: "non-deterministic tie".into() },
        )
        .unwrap();
        assert_eq!(last_resort_debt(), 1, "a last-resort invocation is debt and is counted");
        reset_last_resort_debt();
    }

    /// The adjudication rule, pinned as a truth table because getting it wrong is INVISIBLE to a
    /// compiler-free gate: the cache stores only adjudicated entries, so a `true` here on a unit
    /// nothing judged writes a false COMPILE_FAIL into the cache as a fact about the source, and
    /// it survives every later run. The no-object-no-log row is the one that matters.
    #[test]
    fn only_an_answered_unit_is_adjudicated() {
        assert!(!adjudicated_from(None, ""), "no object and no diagnostic is NOT a verdict");
        assert!(!adjudicated_from(None, "   \n\t "), "whitespace is not the compiler speaking");
        assert!(adjudicated_from(None, "foo.c(3): Error! E1009"), "a rejection is a verdict");
        assert!(adjudicated_from(Some(&[0x80, 0x00]), ""), "an object is a verdict");
        assert!(adjudicated_from(Some(&[0x80]), "warning"), "both is still a verdict");
    }

    /// A session log belongs to the unit it names, not to everyone in the batch. Without this,
    /// one unit's error makes `adjudicated_from` true for every unit that shared the session.
    #[test]
    fn the_session_log_is_split_per_unit() {
        let d = drv(spec::watcom_10_0a_dos("typedef int int4;"));
        let Invocation::Script { log_split, .. } = &d.spec().invocation.clone() else {
            panic!("the DOS spec is a Script invocation")
        };
        let units = [unit("T0", &[]), unit("T1", &[]), unit("T2", &[])];
        let text = concat!(
            "WATCOM C32 Optimizing Compiler Version 10.0a\n",
            "Copyright by WATCOM International Corp. 1988, 1994.\n",
            "T0.C: 12 lines, 0 warnings, 0 errors\n",
            "T1.C(4): Error! E1009: Expecting ';' but found '}'\n",
            "T1.C: 4 lines, 0 warnings, 1 error\n",
            "T2.C: 9 lines, 0 warnings, 0 errors\n",
        );
        let logs = d.split_log(&units, text, log_split);
        assert!(logs[0].contains("T0.C: 12 lines"), "T0 keeps its own summary");
        assert!(!logs[0].contains("E1009"), "T0 must not inherit T1's error");
        assert!(logs[1].contains("E1009"), "T1 keeps its error");
        assert!(logs[2].contains("T2.C: 9 lines"));
        assert!(!logs[2].contains("E1009"));
        for l in &logs {
            assert!(!l.contains("Copyright"), "the banner belongs to the session, not a unit");
        }
    }

    /// The case the split exists for: a session that dies partway leaves the units after the
    /// abort with NOTHING -- and nothing must stay unadjudicated, so the retry sees them and the
    /// cache never learns a false verdict about them.
    #[test]
    fn a_unit_killed_as_collateral_is_left_unadjudicated() {
        let d = drv(spec::watcom_10_0a_dos("typedef int int4;"));
        let Invocation::Script { log_split, .. } = &d.spec().invocation.clone() else {
            panic!("the DOS spec is a Script invocation")
        };
        let units = [unit("T0", &[]), unit("T1", &[])];
        // T0 compiled; then the session died -- T1 was never reached.
        let logs = d.split_log(&units, "T0.C: 12 lines, 0 warnings, 0 errors\n", log_split);
        assert!(logs[1].trim().is_empty(), "T1 got no diagnostics of its own");
        assert!(
            !adjudicated_from(None, &logs[1]),
            "a unit with no object and no diagnostics of its OWN was not judged"
        );
        assert!(adjudicated_from(None, &logs[0]), "T0 was judged");
    }

    /// A spec with no per-unit structure hands the whole log over -- honest only because such a
    /// session holds one unit. Pinned so the `Whole` arm cannot silently become the batch default.
    #[test]
    fn a_whole_log_spec_gives_every_unit_the_same_text() {
        let d = drv(spec::gcc_native("cc", "typedef int int4;"));
        let units = [unit("T0", &[]), unit("T1", &[])];
        let logs = d.split_log(&units, "error: boom\n", &LogSplit::Whole);
        assert_eq!(logs, vec!["error: boom\n".to_string(); 2]);
    }

    /// The DOS spec's flag profile and `buildconfig::watcom_10_0a().base` are the same four
    /// options in two places, so they can drift apart silently -- and the drift would be nearly
    /// invisible: `recompile_check` sets flags PER UNIT from buildconfig, so the spec's list is
    /// only consulted for a unit that carries none. It would take a differently-compiled unit,
    /// somewhere, to notice. Pinned here rather than wiring the layers together, because the
    /// duplication is the honest description: one is the WAR2 build profile, the other is this
    /// compiler's default when a caller expresses no preference.
    #[test]
    fn the_dos_spec_profile_matches_the_war2_build_profile() {
        let spec_flags = spec::watcom_10_0a_dos("").flags;
        let base = crate::recompile::buildconfig::watcom_10_0a().base;
        assert_eq!(spec_flags, base, "the spec profile and the WAR2 build profile have drifted");
    }

}
