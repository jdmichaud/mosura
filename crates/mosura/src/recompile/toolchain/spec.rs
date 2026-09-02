//! `CompilerSpec` — a compiler described as DATA, the recompile-side twin of the cspec.
//!
//! mosura already models the target compiler as data for DECOMPILING: `specs/x86-32-watcom.cspec`
//! tells the decompiler how Watcom passes arguments, and nothing about that convention is written
//! in Rust. This is the same idea for RECOMPILING. What a compiler needs in order to be driven —
//! how its source file must be named, what wrapper starts it, what its command line looks like,
//! where its object lands, what format that object is in — is description, not logic. Held as
//! data, a new compiler is a new [`CompilerSpec`]; only a genuinely new OUTPUT FORMAT needs new
//! code (see [`ObjectFormat`]).
//!
//! The variation that is real, and therefore modelled, is the INVOCATION STYLE. Watcom 10.0a is a
//! DOS program: it is reached through an emulator, and a batch of units is one emulator session
//! driven by a script, because a session costs about a second and per-unit sessions would make a
//! corpus run untenable. gcc and Open Watcom 2 are native: one process per unit, no script, no
//! emulator. Those are not two settings of one template — they are two shapes — so
//! [`Invocation`] is an enum rather than a pile of optional fields.
//!
//! NOT in scope here: choosing to run a compiler at all. The driver is off by default and the
//! gate runs with no toolchain present (design §0); [`super::driver::DriverRole`] records WHY an
//! invocation happened and counts the last-resort ones as debt.

/// How the object code is packaged, and therefore how the code bytes are recovered from it.
///
/// This is the one axis that cannot be pure data: a format needs a reader. Adding a compiler that
/// emits an existing format is a spec; adding one that emits a new format is a spec plus a reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFormat {
    /// Intel OMF (`.obj`) — Watcom 10.0a and Open Watcom 2 on DOS/OS2 targets.
    Omf,
    /// ELF relocatable (`.o`) — gcc, and Open Watcom 2 targeting Linux.
    Elf,
}

/// Line ending the compiler's own control files require.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineEnding {
    Lf,
    /// DOS. A batch file with LF-only line endings is not parsed by COMMAND.COM — measured, and
    /// the failure is silent (the session runs and compiles nothing).
    Crlf,
}

impl LineEnding {
    pub fn as_str(self) -> &'static str {
        match self {
            LineEnding::Lf => "\n",
            LineEnding::Crlf => "\r\n",
        }
    }
}

/// How to actually start the compiler on a batch of units.
#[derive(Debug, Clone)]
pub enum Invocation {
    /// A script is written into the work directory and a wrapper command runs it: the whole batch
    /// is one wrapper session. This is what a DOS-hosted compiler under an emulator needs, and the
    /// batching is not an optimization but the difference between a usable and an unusable
    /// corpus run.
    Script {
        /// File the script is written to, in the work directory (e.g. `_BUILD.BAT`).
        name: String,
        ending: LineEnding,
        /// Lines emitted once, before the per-unit lines (environment, drive change). `{install}`
        /// and `{work}` are substituted.
        preamble: Vec<String>,
        /// One line per unit. Placeholders: `{flags}` `{src}` `{key}` `{log}`.
        per_unit: String,
        /// The wrapper command. Placeholders: `{install}` `{work}` `{script}`.
        command: Vec<String>,
        /// How to attribute the session log back to the units. See [`LogSplit`].
        log_split: LogSplit,
    },
    /// One process per unit, run directly. Placeholders: `{flags}` `{src}` `{obj}` `{work}`.
    ///
    /// No `log_split` here on purpose: one process per unit means its output IS that unit's
    /// diagnostics, captured directly, so there is nothing to attribute.
    Native { command: Vec<String> },
}

/// How a batch session's single log is attributed back to the units that were in it.
///
/// This matters for correctness, not tidiness. A unit is cached as a verdict about its SOURCE only
/// when the compiler answered about that unit; handing every unit a copy of the whole session log
/// makes "the compiler said something" true for all of them the moment it is true for any of them,
/// so a unit that died as collateral in someone else's aborted session gets cached as a genuine
/// compile failure. See `driver::adjudicated_from`.
#[derive(Debug, Clone)]
pub enum LogSplit {
    /// The whole log belongs to every unit. Honest only for a single-unit session.
    Whole,
    /// The compiler prints a block per file ending in a line that contains `terminator`, preceded
    /// by that file's stem (`wcc386`: `FOO.C: 68 lines, 0 warnings, 0 errors`). Attributing by
    /// scanning for that terminator, rather than assuming one block per unit, is what survives a
    /// unit aborting mid-file.
    PerUnit {
        /// Substring marking the end of a unit's block; the text before it is the file name.
        terminator: String,
        /// Line prefixes that belong to the session rather than any unit (banner, copyright).
        banners: Vec<String>,
    },
}

/// A compiler, described.
#[derive(Debug, Clone)]
pub struct CompilerSpec {
    /// Stable identity. Part of the compile cache key, so it must change whenever the emitted
    /// bytes could: vendor, version, and anything else that alters codegen.
    pub id: String,
    /// Source file name for a unit. Placeholder: `{key}`. Watcom under DOS needs 8.3 and returns
    /// its object lower-cased whatever the source case (measured), hence [`Self::object_names`].
    pub source_name: String,
    /// Candidate object file names, most likely first. Placeholders: `{key}` (verbatim),
    /// `{key_lower}`, `{key_upper}`.
    ///
    /// The case variants are not defensive padding: dosemu2 names the object after the source's
    /// 8.3 stem and commonly LOWER-CASES it, so `WCC386 T00000.C` produces `t00000.obj` — a
    /// lower-cased stem as well as a lower-cased extension. The list also clears the previous
    /// run's objects, which matters as much as the read: leaving a stale `t00000.obj` while
    /// looking for `T00000.OBJ` would score a failed compile against an earlier run's object.
    pub object_names: Vec<String>,
    /// Text prepended to every unit's source. Part of the identity: a changed prelude is a changed
    /// compiler as far as the emitted bytes are concerned.
    pub prelude: String,
    /// Default flag profile. A unit may override.
    pub flags: Vec<String>,
    /// Where the compiler's diagnostics land, in the work directory, when it writes them to a file
    /// rather than to its standard streams.
    pub log_name: Option<String>,
    pub object_format: ObjectFormat,
    pub invocation: Invocation,
}

impl CompilerSpec {
    pub fn source_name_for(&self, key: &str) -> String {
        self.source_name.replace("{key}", key)
    }

    pub fn object_names_for(&self, key: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for n in &self.object_names {
            let s = n
                .replace("{key_lower}", &key.to_lowercase())
                .replace("{key_upper}", &key.to_uppercase())
                .replace("{key}", key);
            if !out.contains(&s) {
                out.push(s);
            }
        }
        out
    }
}

/// Watcom C/C++32 10.0a, hosted under dosemu2 — WAR2's own compiler, the recompile baseline.
///
/// The details here are all measured, not guessed: the batch file must be CRLF or COMMAND.COM
/// does not parse it; the source must be 8.3 and is written upper-case; the object comes back
/// lower-cased regardless; `F:` is the install and `G:` the work directory, in the order the two
/// `-d` flags are given.
pub fn watcom_10_0a_dos(prelude: impl Into<String>) -> CompilerSpec {
    CompilerSpec {
        id: "watcom-10.0a-dos".into(),
        source_name: "{key}.C".into(),
        object_names: ["{key}.obj", "{key}.OBJ", "{key_lower}.obj", "{key_lower}.OBJ",
                       "{key_upper}.obj", "{key_upper}.OBJ"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        prelude: prelude.into(),
        // WAR2's profile (buildconfig::watcom_10_0a). `-d1+` is added per-unit where the original
        // has a frame prologue, so it is not part of the default set.
        flags: ["-5r", "-fpi87", "-s", "-onatx"].iter().map(|s| s.to_string()).collect(),
        log_name: Some("WCCOUT.TXT".into()),
        object_format: ObjectFormat::Omf,
        invocation: Invocation::Script {
            name: "_BUILD.BAT".into(),
            ending: LineEnding::Crlf,
            preamble: vec![
                "@echo off".into(),
                "SET WATCOM=F:\\".into(),
                "SET PATH=F:\\BINB;F:\\BIN;F:\\BINP".into(),
                "SET INCLUDE=F:\\H".into(),
                "G:".into(),
            ],
            per_unit: "WCC386 {flags} {src} >>{log}".into(),
            command: ["dosemu", "-td", "-d", "{install}", "-d", "{work}", "-E", "G:\\{script}"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            log_split: LogSplit::PerUnit {
                terminator: ".C: ".into(),
                banners: ["WATCOM C", "Copyright", "WATCOM is"].iter().map(|s| s.to_string()).collect(),
            },
        },
    }
}

/// Open Watcom 2, running NATIVELY. The configurability stress case (design §4): same vendor and
/// the same OMF output, but no emulator and no script — one process per unit. If a spec swap
/// absorbs this, the invocation style really is data.
pub fn open_watcom_2_native(cc: impl Into<String>, prelude: impl Into<String>) -> CompilerSpec {
    CompilerSpec {
        id: "open-watcom-2-native".into(),
        source_name: "{key}.c".into(),
        object_names: ["{key}.o", "{key}.obj", "{key_lower}.o", "{key_lower}.obj"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        prelude: prelude.into(),
        flags: ["-5r", "-fpi87", "-s", "-onatx"].iter().map(|s| s.to_string()).collect(),
        log_name: None,
        object_format: ObjectFormat::Omf,
        invocation: Invocation::Native {
            command: vec![cc.into(), "{flags}".into(), "-fo={obj}".into(), "{src}".into()],
        },
    }
}

/// gcc — the generalization case (design §4): a foreign toolchain, native, ELF not OMF, its own
/// flags. Proves the driver is not Watcom-shaped.
pub fn gcc_native(cc: impl Into<String>, prelude: impl Into<String>) -> CompilerSpec {
    CompilerSpec {
        id: "gcc-native".into(),
        source_name: "{key}.c".into(),
        object_names: vec!["{key}.o".into()],
        prelude: prelude.into(),
        flags: ["-m32", "-c", "-O2", "-fno-pic"].iter().map(|s| s.to_string()).collect(),
        log_name: None,
        object_format: ObjectFormat::Elf,
        invocation: Invocation::Native {
            command: vec![cc.into(), "{flags}".into(), "-o".into(), "{obj}".into(), "{src}".into()],
        },
    }
}
