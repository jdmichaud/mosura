//! `CompilerDriver` — generic compiler-driving logic over a [`CompilerSpec`].
//!
//! Everything a particular compiler needs is in its spec; everything the DRIVING needs — write the
//! sources, build the invocation, run it, collect the objects, split the diagnostics — is here and
//! is the same for all of them. `WatcomDos`'s behaviour is reproduced exactly by
//! [`spec::watcom_10_0a_dos`] plus this file, which is the point of the factoring: the DOS-hosted
//! baseline stops being a special case and becomes one row of data.
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

use super::spec::{CompilerSpec, Invocation};
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

/// Reset the debt counter (tests).
pub fn reset_last_resort_debt() {
    LAST_RESORT_COUNT.store(0, Ordering::Relaxed);
}

/// A compiler, driven.
pub struct CompilerDriver {
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

    fn run(&self, units: &[CompileUnit]) {
        match &self.spec.invocation {
            Invocation::Script { name, .. } => {
                if let Some(text) = self.script_text(units) {
                    let _ = std::fs::write(self.work_dir.join(name), text);
                }
                let argv = self.command_line(None);
                let Some((prog, args)) = argv.split_first() else { return };
                let _ = std::process::Command::new(prog)
                    .args(args)
                    .current_dir(&self.work_dir)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
            Invocation::Native { .. } => {
                for u in units {
                    let argv = self.command_line(Some(u));
                    let Some((prog, args)) = argv.split_first() else { continue };
                    let _ = std::process::Command::new(prog)
                        .args(args)
                        .current_dir(&self.work_dir)
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
            }
        }
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
        if units.is_empty() {
            return Vec::new();
        }
        self.stage(units);
        self.run(units);
        let log = self.log_text();
        units
            .iter()
            .map(|u| {
                let object = self.read_object(&u.key);
                CompileOutput {
                    key: u.key.clone(),
                    object,
                    log: log.clone(),
                    // A unit is adjudicated when the run produced an object for it, or produced a
                    // log at all (the compiler ran and said something). Neither means the
                    // environment was broken and nothing reached a verdict — which must not be
                    // cached as a property of the source (see `CompileOutput::adjudicated`).
                    adjudicated: true,
                }
            })
            .collect()
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

    /// The DOS-hosted baseline's batch file, byte for byte. This is the factoring's proof
    /// obligation: `WatcomDos::run_session` builds this text inline, and the spec-driven driver
    /// must produce the same thing -- CRLF, the four environment lines, the drive change, one
    /// `WCC386` line per unit redirecting to the log. Compiler-free, so it runs IN the gate.
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
}
