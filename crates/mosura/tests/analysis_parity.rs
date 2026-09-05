//! A0/A2 — the auto-analysis parity harness (plan `docs/analysis-port-plan.md` §3).
//!
//! Two gates, scored separately (the plan's per-phase model):
//! - **memory map** (A2 loader): mosura's loader blocks vs the **loader-stage**
//!   (`-noanalysis`) golden `<name>.loaded.snapshot` — the loader's own output, before
//!   analysis adds artificial blocks (e.g. PE's `tdb`);
//! - **functions** (A4): mosura's functions vs the converged `<name>.snapshot`. 0 until
//!   disassembly/discovery lands.
//!
//! Mandatory corpus is the committed ELFs; PE (`cnv.exe`) is user-provided and skipped
//! if absent (its binary isn't redistributable, but its golden is committed).

use std::path::PathBuf;

use mosura::analysis::{self, snapshot};
use mosura::conformance::Tally;
use mosura::paths::{analysis_corpus_dir, analysis_goldens_dir, cnv_exe, comcom32_exe};

/// Committed ELF corpus (always present). `aarch64`, `riscv`, and `m68k` are the
/// non-x86 fixtures (freestanding ARM64 / RV64GC / big-endian 32-bit m68k ELFs) —
/// validate the function-listing pipeline on those ISAs.
const MANDATORY: &[&str] = &["freestanding", "basic", "aarch64", "riscv", "m68k"];

/// Process-level memo for `analyze_file`, for the corpus loops only.
///
/// ⚠️ WHY THIS EXISTS, AND WHY IT IS NOT A BEHAVIOUR CHANGE. Four separate tests in this file
/// each loop over [`MANDATORY`] and call `analyze_file(<name>.elf)` from scratch, so every
/// corpus binary was analyzed **four times** per run. Analysis is a pure function of the file
/// for a given build — same path in, same `Program` out — so analyzing once per process and
/// sharing the result is observationally identical and is the single largest avoidable cost in
/// this test binary (it was ~230 s of a ~10 min suite; a subject analysis alone is ~4 min).
///
/// ⚠️ Scope is deliberately narrow: **only the repeated corpus loops use this.** Any test that
/// depends on analysis being re-run — a mutation, an env/override, or a per-test cspec — must
/// keep calling `analysis::analyze_file` directly, or the memo would hand it a `Program`
/// produced under different conditions. Cached by path only, so a test that varies anything
/// other than the path MUST NOT use it.
///
/// Cargo runs tests in threads within one process, hence the `Mutex`; the `Arc` avoids cloning
/// a `Program` that holds thousands of functions.
fn cached_analyze(path: &std::path::Path) -> std::sync::Arc<mosura::analysis::program::Program> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, Arc<mosura::analysis::program::Program>>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(hit) = cache.lock().unwrap().get(path) {
        return Arc::clone(hit);
    }
    // Analyze OUTSIDE the lock: these take seconds, and holding the mutex would serialise
    // every test thread behind the first one — turning a parallel suite into a sequential one.
    let prog = Arc::new(analysis::analyze_file(path).unwrap());
    let mut guard = cache.lock().unwrap();
    Arc::clone(guard.entry(path.to_path_buf()).or_insert(prog))
}

/// (name, binary path, mandatory?, loader-stage golden) — externals are user-provided, skipped if
/// absent; the configured subjects (dev-config `[[subject]]`) join with the golden their profile
/// holds (`analysis.loaded.snapshot`).
fn corpus() -> Vec<(String, PathBuf, bool, PathBuf)> {
    let goldens = analysis_goldens_dir();
    let mut v: Vec<(String, PathBuf, bool, PathBuf)> = MANDATORY
        .iter()
        .map(|n| (n.to_string(), analysis_corpus_dir().join(format!("{n}.elf")), true, goldens.join(format!("{n}.loaded.snapshot"))))
        .collect();
    v.push(("cnv".into(), cnv_exe(), false, goldens.join("cnv.loaded.snapshot"))); // PE, user-provided (binaries.cnv)
    v.push(("comcom32".into(), comcom32_exe(), false, goldens.join("comcom32.loaded.snapshot"))); // MZ (binaries.comcom32)
    for s in mosura::devcfg::subjects() {
        if let Some(g) = s.file("analysis.loaded.snapshot") {
            v.push((format!("subject {}", s.id), s.path.clone(), false, g));
        }
    }
    v
}

#[test]
fn memory_map_parity() {
    let goldens = analysis_goldens_dir();
    let mut blocks = Tally::default();
    let mut evaluated = Vec::new();

    for (name, path, mandatory, golden_path) in corpus() {
        if !path.exists() {
            assert!(!mandatory, "mandatory corpus binary missing: {}", path.display());
            eprintln!("  skip {name}: {} not present", path.display());
            continue;
        }
        let golden = snapshot::parse(
            &std::fs::read_to_string(&golden_path)
                .unwrap_or_else(|e| panic!("loader-stage golden for {name}: {e}")),
        );
        let produced = analysis::analyze_binary(&path).unwrap_or_else(|e| panic!("analyze {name}: {e}"));
        let ok = produced.blocks == golden.blocks;
        if !ok {
            eprintln!("  [{name}] memory map differs: {} blocks vs golden {}", produced.blocks.len(), golden.blocks.len());
        }
        blocks.record(ok);
        evaluated.push(name);
    }

    eprintln!("memory-map parity: {blocks} ({:?})", evaluated);
    assert!(evaluated.iter().any(|n| n == "freestanding") && evaluated.iter().any(|n| n == "basic"), "ELF corpus must run");
    assert_eq!(blocks.passed, blocks.total, "every evaluated binary's memory map must match its loader-stage golden");
}

/// PE robustness (cnv, ~1MB / 1808 functions). `#[ignore]`d — full analysis takes ~140s
/// and cnv's converged golden is too large to commit, so this is opt-in
/// (`cargo test -- --ignored`). Asserts analysis completes without panic and every
/// recovered reference targets mapped memory (the no-spurious-reference invariant).
#[test]
#[ignore = "slow (~140s); run with --ignored"]
fn pe_robustness_cnv() {
    let path = cnv_exe();
    if !path.exists() {
        eprintln!("skip: cnv.exe absent ({})", path.display());
        return;
    }
    let program = analysis::analyze_file(&path).unwrap();
    assert!(program.function_manager.function_count() > 1000, "cnv should recover its functions");
    for r in program.reference_manager.references() {
        assert!(program.memory.contains(r.to), "cnv: reference to unmapped {:08x}", r.to.offset);
    }
    eprintln!("cnv: {} functions, analysis clean", program.function_manager.function_count());
}

/// PE compiler detection — a faithful port of Ghidra `PeLoader.CompilerOpinion.getOpinion`
/// (`loader::pe_opinion`). mosura's loader-stage snapshot must reproduce, for the corpus PE
/// (cnv.exe, a Clang binary), BOTH the compiler-spec id (the Opinion secondary → cspec, header
/// `compiler=`) AND the `Compiler` info property (the opinion label, header `compilerinfo=`)
/// that the analyzeHeadless golden records. This is the only PE compiler the corpus exercises
/// end-to-end (no MinGW/VS/Borland toolchain to build fixtures with); the rest of the opinion
/// is a faithful line-by-line port of the source. Skipped if cnv.exe is absent (user-provided).
#[test]
fn pe_compiler_opinion() {
    let path = cnv_exe();
    if !path.exists() {
        eprintln!("skip pe_compiler_opinion: cnv.exe absent");
        return;
    }
    let golden = snapshot::parse(
        &std::fs::read_to_string(analysis_goldens_dir().join("cnv.loaded.snapshot")).unwrap(),
    );
    let snap = analysis::analyze_binary(&path).unwrap();
    assert_eq!(
        snap.compiler, golden.compiler,
        "cnv: compiler-spec id (opinion secondary → cspec) must match Ghidra"
    );
    assert_eq!(
        snap.compiler_info, golden.compiler_info,
        "cnv: Compiler info property (opinion label) must match Ghidra"
    );
    assert_eq!(golden.compiler, "clangwindows");
    assert_eq!(golden.compiler_info, "clang:unknown");
    eprintln!(
        "cnv PE opinion: cspec={} compiler={} (faithful CompilerOpinion.getOpinion → Clang)",
        snap.compiler, snap.compiler_info
    );
}

/// A3 — golden-validate the **Gcc** branch of the PE CompilerOpinion against real MinGW output.
/// `mingw_hello.exe` is our own `src/mingw_hello.c` built with `x86_64-w64-mingw32-gcc -O2`
/// (redistributable — our source — so unlike cnv it is committed and always present). Ghidra's
/// analyzeHeadless golden records `compiler=windows compilerinfo=gcc:unknown`: the `Gcc` family
/// carries no size-64 secondary in the x86.opinion PE block, so it resolves to the block's
/// default `windows` cspec, and the opinion label is `gcc:unknown`. `get_opinion` reaches `Gcc`
/// via the disambiguation path — `e_lfanew==0x80` (GccVs) + the `…DOS mode.\r\r\n$` stub error
/// (GccVs) + `asm==GccVsClang` + a nonzero `PointerToSymbolTable` (VS would be 0). Second
/// non-Clang PE compiler exercised end-to-end (cnv covers Clang); the rest of the opinion stays
/// a faithful line-by-line port.
#[test]
fn pe_compiler_opinion_gcc() {
    let path = analysis_corpus_dir().join("mingw_hello.exe");
    let golden = snapshot::parse(
        &std::fs::read_to_string(analysis_goldens_dir().join("mingw_hello.loaded.snapshot")).unwrap(),
    );
    let snap = analysis::analyze_binary(&path).unwrap();
    assert_eq!(snap.compiler, golden.compiler, "mingw: compiler-spec id (opinion secondary → cspec) must match Ghidra");
    assert_eq!(snap.compiler_info, golden.compiler_info, "mingw: Compiler info property (opinion label) must match Ghidra");
    assert_eq!(golden.compiler, "windows");
    assert_eq!(golden.compiler_info, "gcc:unknown");
    eprintln!(
        "mingw PE opinion: cspec={} compiler={} (faithful CompilerOpinion.getOpinion → Gcc)",
        snap.compiler, snap.compiler_info
    );
}

/// A3 (32-bit) — the same Gcc opinion on a **32-bit** PE, exercising the new `PeFile32` loader
/// path. `mingw_hello32.exe` is `src/mingw_hello.c` built with `i686-w64-mingw32-gcc -O2`.
/// Ghidra's golden is `lang=x86:LE:32:default compiler=windows compilerinfo=gcc:unknown` — the
/// i386 x86.opinion PE block resolves `Gcc` to the default `windows` cspec (via `cspec_x86`).
/// Asserting `lang` too confirms the loader took the 32-bit dispatch, not the 64-bit one.
#[test]
fn pe_compiler_opinion_gcc32() {
    let path = analysis_corpus_dir().join("mingw_hello32.exe");
    let golden = snapshot::parse(
        &std::fs::read_to_string(analysis_goldens_dir().join("mingw_hello32.loaded.snapshot")).unwrap(),
    );
    let snap = analysis::analyze_binary(&path).unwrap();
    assert_eq!(snap.lang, golden.lang, "mingw32: language id must match Ghidra");
    assert_eq!(snap.compiler, golden.compiler, "mingw32: compiler-spec id (i386 opinion secondary → cspec) must match Ghidra");
    assert_eq!(snap.compiler_info, golden.compiler_info, "mingw32: Compiler info property must match Ghidra");
    assert_eq!(golden.lang, "x86:LE:32:default");
    assert_eq!(golden.compiler, "windows");
    assert_eq!(golden.compiler_info, "gcc:unknown");
    eprintln!(
        "mingw32 PE opinion: lang={} cspec={} compiler={} (32-bit PeFile32 path → Gcc)",
        snap.lang, snap.compiler, snap.compiler_info
    );
}

/// A3 Stage 2 — golden-validate the **Borland** branch against a real Borland C++ 4.5 PE
/// (`bcc32.exe`/`tlink32.exe` from the BC45 CD, run under wine). Borland's runtime is
/// proprietary, so the binary is not committed (like `cnv.exe`): set `MOSURA_BC45_EXE` to a
/// `bcc32`-built PE to run this; the Ghidra golden (`bc45_hello.loaded.snapshot`) is committed.
///
/// A faithful-port subtlety: Ghidra labels this **C++** compiler's output `borland:pascal`
/// (cspec `borlanddelphi`), because `getOpinion` keys on `e_lfanew==0x100` (→ BorlandPascal) and
/// the `"…must be run under Win32"` DOS-stub error, not the source language — so `return
/// offset_choice` gives BorlandPascal. mosura's port reproduces Ghidra exactly, which is the bar.
#[test]
fn pe_compiler_opinion_borland() {
    let Some(path) = mosura::devcfg::binary("bc45") else {
        eprintln!("skip pe_compiler_opinion_borland: set binaries.bc45 in dev-config.toml to a Borland C++ 4.5 PE");
        return;
    };
    if !path.exists() {
        eprintln!("skip pe_compiler_opinion_borland: {} absent", path.display());
        return;
    }
    let golden = snapshot::parse(
        &std::fs::read_to_string(analysis_goldens_dir().join("bc45_hello.loaded.snapshot")).unwrap(),
    );
    let snap = analysis::analyze_binary(&path).unwrap();
    assert_eq!(snap.lang, golden.lang, "borland: language id must match Ghidra");
    assert_eq!(snap.compiler, golden.compiler, "borland: compiler-spec id (i386 opinion secondary → cspec) must match Ghidra");
    assert_eq!(snap.compiler_info, golden.compiler_info, "borland: Compiler info property must match Ghidra");
    assert_eq!(golden.lang, "x86:LE:32:default");
    assert_eq!(golden.compiler, "borlanddelphi");
    assert_eq!(golden.compiler_info, "borland:pascal");
    eprintln!(
        "borland PE opinion: lang={} cspec={} compiler={} (faithful CompilerOpinion → BorlandPascal via e_lfanew=0x100)",
        snap.lang, snap.compiler, snap.compiler_info
    );
}

/// A3 Stage 2 — golden-validate the **VisualStudio** branch against a real MSVC 6.0 PE
/// (`CL.EXE`/`LINK.EXE` from the VC98 tree, run under wine). MSVC's runtime is proprietary, so
/// the binary is not committed (like `cnv.exe`): set `MOSURA_VC6_EXE` to a `cl`-built PE; the
/// Ghidra golden (`vc6_hello.loaded.snapshot`) is committed. `get_opinion` reaches VisualStudio
/// via the **"DanS" Rich header** — `link.exe` writes it at file offset 0x80, and with
/// `e_lfanew=0xd0` (>0x80, so not the GccVs `==0x80` fast path) the `(val1 ^ val2) == 'DanS'`
/// check fires. The i386 block resolves VisualStudio to the default `windows` cspec.
#[test]
fn pe_compiler_opinion_msvc() {
    let Some(path) = mosura::devcfg::binary("vc6") else {
        eprintln!("skip pe_compiler_opinion_msvc: set binaries.vc6 in dev-config.toml to an MSVC 6.0 PE");
        return;
    };
    if !path.exists() {
        eprintln!("skip pe_compiler_opinion_msvc: {} absent", path.display());
        return;
    }
    let golden = snapshot::parse(
        &std::fs::read_to_string(analysis_goldens_dir().join("vc6_hello.loaded.snapshot")).unwrap(),
    );
    let snap = analysis::analyze_binary(&path).unwrap();
    assert_eq!(snap.lang, golden.lang, "msvc: language id must match Ghidra");
    assert_eq!(snap.compiler, golden.compiler, "msvc: compiler-spec id must match Ghidra");
    assert_eq!(snap.compiler_info, golden.compiler_info, "msvc: Compiler info property must match Ghidra");
    assert_eq!(golden.lang, "x86:LE:32:default");
    assert_eq!(golden.compiler, "windows");
    assert_eq!(golden.compiler_info, "visualstudio:unknown");
    eprintln!(
        "msvc PE opinion: lang={} cspec={} compiler={} (faithful CompilerOpinion → VisualStudio via DanS Rich header)",
        snap.lang, snap.compiler, snap.compiler_info
    );
}

/// Compiler **version** detection (beyond-Ghidra second oracle, `loader::compiler_version`) over
/// the committed fixtures — validated against the version each real toolchain embeds. GCC's exact
/// version is fixed in the committed binary (built with mingw GCC 14); Watcom's era comes from the
/// runtime banner.
#[test]
fn compiler_version_committed_fixtures() {
    use mosura::analysis::loader::compiler_version::{detect, Family, Precision};
    let cases: &[(&str, Family, &str, Precision)] = &[
        ("mingw_hello.exe", Family::Gcc, "14-win32", Precision::Exact), // GCC on PE
        ("mingw_hello32.exe", Family::Gcc, "14-win32", Precision::Exact),
        ("basic.elf", Family::Gcc, "14.2.0", Precision::Exact), // GCC on ELF (.comment) — same detector
        ("clang_hello.elf", Family::Clang, "19.1.7", Precision::Exact), // Clang on ELF — wins over the gcc-CRT marker
        ("watcom_hello.exe", Family::Watcom, "1988-1994", Precision::Era), // Watcom on LE/MZ
    ];
    for (name, fam, ver, prec) in cases {
        let path = analysis_corpus_dir().join(name);
        let data = std::fs::read(&path).unwrap();
        let id = detect(&data).unwrap_or_else(|| panic!("no version marker in {name}"));
        assert_eq!(id.family, *fam, "{name} family");
        assert_eq!(id.version, *ver, "{name} version");
        assert_eq!(id.precision, *prec, "{name} precision");
        // End-to-end: the loader pipeline records the same version on the snapshot.
        let snap = analysis::analyze_binary(&path).unwrap();
        assert_eq!(snap.compiler_version, id.label(), "{name} pipeline compilerversion");
        eprintln!("{name}: {} [{:?}] — {}", id.label(), id.precision, id.evidence);
    }
}

/// Compiler version detection over the proprietary-runtime fixtures (not committed, like cnv):
/// MSVC's **exact build** from the Rich header (`8168` → 6.0) and Borland's **era + true family**
/// from the startup banner (`borland:c++:1994` — the C++ that Ghidra's e_lfanew heuristic misses).
/// Set `MOSURA_VC6_EXE` / `MOSURA_BC45_EXE`; skip-if-absent.
#[test]
fn compiler_version_proprietary_fixtures() {
    use mosura::analysis::loader::compiler_version::{detect, Family};
    // `[binaries]` keys in dev-config.toml; none has a default, so each skips unless set.
    let cases: &[(&str, Family, &str)] = &[
        ("vc6", Family::Msvc, "msvc:6.0"),           // VC6: Rich header → exact build
        ("vc5", Family::Msvc, "msvc:link-5.0"),      // VC5: pre-Rich → linker version
        ("vc4", Family::Msvc, "msvc:link-3.0"),      // VC4: pre-Rich → linker version
        ("bc45", Family::Borland, "borland:c++:1994"),
    ];
    for (key, fam, label) in cases {
        let Some(path) = mosura::devcfg::binary(key) else {
            eprintln!("skip binaries.{key}: not set in dev-config.toml");
            continue;
        };
        if !path.exists() {
            eprintln!("skip binaries.{key}: {} absent", path.display());
            continue;
        }
        let data = std::fs::read(&path).unwrap();
        let id = detect(&data).unwrap_or_else(|| panic!("no version marker via binaries.{key}"));
        assert_eq!(id.family, *fam, "binaries.{key} family");
        assert_eq!(id.label(), *label, "binaries.{key} label");
        eprintln!("binaries.{key}: {} [{:?}] — {}", id.label(), id.precision, id.evidence);
    }
}

/// A3-V Phase 3 — real-compiler version detection gated **in CI without the proprietary
/// toolchain**. The full MSVC/Borland binaries can't be committed (proprietary runtime), so the
/// `compiler_version_proprietary_fixtures` checks above only run on the author's machine
/// (skip-if-absent). These committed **marker fragments** carry the exact bytes the real compiler
/// emitted — the Rich header (build-id metadata) and the Borland startup banner (a copyright
/// string), *no runtime code* — so the detector's real-output path always runs. The pre-Rich
/// MSVC path (linker version + runtime string) stays covered by the synthetic unit tests in
/// `compiler_version.rs`.
#[test]
fn compiler_version_marker_fragments() {
    use mosura::analysis::loader::compiler_version::detect;
    let dir = analysis_corpus_dir().join("markers");
    let cases: &[(&str, &str)] = &[
        ("msvc6_rich.bin", "msvc:6.0"),               // real VC6 Rich header (build 8168)
        ("msvc8_rich.bin", "msvc:8.0"),               // real VS2005 Rich header (build 50727)
        ("borland45_banner.bin", "borland:c++:1994"), // real BC++ 4.5 startup banner
    ];
    for (name, label) in cases {
        let data = std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("marker {name}: {e}"));
        assert_eq!(detect(&data).map(|id| id.label()).as_deref(), Some(*label), "{name}");
    }
}

/// A2 — the loader's **dynamic-link path on big-endian 32-bit** (m68k). `m68k.elf` is
/// freestanding/static; this is the dynamic analog of `basic.elf` (same source, cross-arch),
/// exercising what static fixtures never do: `PT_INTERP`, `.dynamic`/`.dynsym`, `.rela.plt`
/// (RELA + m68k `JMP_SLOT`), the `.plt` (m68k memory-indirect `jmp ([disp,PC])` thunks) and the
/// synthetic **EXTERNAL** block. The proof that all of it composed correctly on a BE/32 target:
/// mosura resolves the PLT thunks through the GOT to the EXTERNAL block and **names** those
/// imports from `.dynsym` — `printf` and `__libc_start_main`. It also recovers every real source
/// function, and creates no function in unmapped memory.
#[test]
fn m68k_dynamic_link_path() {
    let p = analysis::analyze_file(&analysis_corpus_dir().join("m68k_dyn.elf"))
        .expect("analyze dynamic m68k ELF");

    let named: std::collections::BTreeMap<u64, String> = p
        .function_manager
        .functions()
        .map(|f| {
            let a = f.entry_point();
            (a.offset, p.symbol_table.primary_at(a).map(|s| s.name().to_string()).unwrap_or_default())
        })
        .collect();
    let names: std::collections::BTreeSet<&str> = named.values().map(String::as_str).collect();

    // dynamic-specific: named external functions resolved from .dynsym via the PLT thunks
    assert!(p.memory.blocks().any(|b| b.name() == "EXTERNAL"), "no EXTERNAL block");
    for ext in ["printf", "__libc_start_main"] {
        assert!(names.contains(ext), "missing named external {ext}; got {names:?}");
    }
    // every real source function is recovered
    for src in ["main", "add", "sum_to"] {
        assert!(names.contains(src), "missing source function {src}; got {names:?}");
    }
    // invariant: no function seeded in unmapped memory
    for a in p.function_manager.functions().map(|f| f.entry_point()) {
        assert!(p.memory.contains(a), "function at unmapped {:#x}", a.offset);
    }
}

/// PE/MZ convergence — extends the A4/A5 checks beyond ELF. mosura must create no
/// function Ghidra lacks (HARD, every format), and its disassembly must stay within a
/// small, bounded misalignment of Ghidra's. comcom32 (MZ) is exact; the subject (16-bit DOS) has
/// a handful of over-decodes where mosura runs past a function into inter-function padding
/// that Ghidra's later data analysis (A6/A7) would claim — bounded and tracked here. cnv
/// (PE) is smoke-tested in [`analysis_robustness`] (its converged golden is too large to
/// commit). All skip-if-absent (user-provided binaries).
#[test]
fn pe_mz_convergence_parity() {
    use std::collections::BTreeSet;
    let goldens = analysis_goldens_dir();
    // (name, path, max tolerated misaligned decodes)
    //
    // ⚠️ the subject's bound is 46, NOT a round number and NOT a tolerance bump — it is the measured
    // count of a NAMED, FILED defect, and it must be re-measured rather than nudged.
    //
    // WHAT IT HOLDS: §9 #5, the inline-parameter call thunk in the 16-bit MZ stub. The subject MZ
    // stub has a thunk family (0x13a38/47/4c/51) all calling 0x13a56, whose dispatcher pops its
    // own return address and reads the word THROUGH it — so each call is followed by a 2-byte
    // inline parameter, not code. mosura decodes the parameter; at 0x13a54 that 3-byte decode
    // spans 0x13a56 and swallows the dispatcher's own `POP BX`.
    //
    // WHY IT IS NOT WRONG-CODE-THAT-BLOCKS: Ghidra decodes those bytes too. Its
    // FindNoReturnFunctionsAnalyzer USES the overlap as evidence (checkNonReturningIndicators
    // :552 — "the code unit at the fall-through contains the next function's entry"), concludes
    // the callee never returns, then REPAIRS via ClearFlowAndRepairCmd. mosura now does the first
    // three steps (93d244c marks + overrides, so no FUTURE decode runs into a parameter); the
    // repair is what removes units already on the ground, and it needs a basic-block model —
    // task #10, 1022 lines on infrastructure the analysis layer does not have.
    //
    // WHY IT IS ACCEPTED HERE: this is the MZ stub — 16-bit real-mode DOS/4GW loader code. The
    // byte-exact campaign targets the LE body (`analyze_le_file`), where the same patch takes
    // listing holes 374 -> 0, missing tracker functions 12 -> 9, at unchanged precision. Holding
    // an LE-body improvement on an MZ-stub regression was a category error.
    //
    // 53 -> 46 when 186dbf2 landed MAX_REPEAT_PATTERN_LENGTH (the ninth cluster, a separate
    // cause). The remaining 46 are the eight thunk clusters. CLOSED BY: task #10.
    //
    // 46 -> 43 when the task #10 repair began landing: `FindNoReturnFunctionsAnalyzer`
    // registered in the pattern-phase manager detects the `13a56` dispatcher (Ghidra marks
    // the same entry, oracle-verified), and `ClearFlowAndRepairCmd` (`clearflow.rs`) clears
    // the three decoded inline parameters `13a4a/13a4f/13a54` and re-disassembles the
    // repaired flow (+1 instruction). The rest of the family's damage needs no-return
    // DETECTION PARITY (Ghidra marks all 6 family members; the batch structure fragments
    // mosura's indicator evidence) — the open half of task #10.
    // (name, binary, max misaligned decodes, converged golden, the MZ thunk cluster to assert if any):
    // the committed corpus binary, plus every configured subject whose profile carries the
    // converged golden (`analysis.snapshot`; `analysis.max_misaligned`, `analysis.mz_thunk_cluster`).
    let mut cases: Vec<(String, PathBuf, usize, PathBuf, Option<Vec<u64>>)> =
        vec![("comcom32".into(), comcom32_exe(), 0, goldens.join("comcom32.snapshot"), None)];
    for s in mosura::devcfg::subjects() {
        if let Some(g) = s.file("analysis.snapshot") {
            cases.push((
                format!("subject {}", s.id),
                s.path.clone(),
                s.expect_u64("analysis.max_misaligned").unwrap_or(0) as usize,
                g,
                s.expect_list_u64("analysis.mz_thunk_cluster"),
            ));
        }
    }
    let mut evaluated = 0;
    for (name, path, max_misaligned, golden_path, thunk_cluster) in &cases {
        let name = name.as_str();
        let max_misaligned = *max_misaligned;
        if !path.exists() || !golden_path.exists() {
            eprintln!("  skip {name}: binary or golden absent");
            continue;
        }
        let golden = snapshot::parse(&std::fs::read_to_string(&golden_path).unwrap());
        let snap = cached_analyze(path).snapshot();

        let mf: BTreeSet<u64> = snap.functions.iter().map(|f| f.entry).collect();
        let gf: BTreeSet<u64> = golden.functions.iter().map(|f| f.entry).collect();
        let spurious_fns: Vec<_> = mf.difference(&gf).collect();
        assert!(spurious_fns.is_empty(), "{name}: spurious functions vs Ghidra: {spurious_fns:x?}");

        // ⭐ THE THUNK CLUSTER, against Ghidra's own committed golden — the only place in the
        // corpus where `CreateFunctionCmd.resolveThunk` (`analysis/analyzers/thunk.rs`) fires, and
        // therefore the only non-the subject-LE evidence that the port is right rather than merely
        // harmless. `analysis.snapshot (subject profile)` records two jump-only entries thunking to one target:
        //     func 00017c4c thunk_FUN_11bd_61ee    fnbody 00017c4c 00017c4c:00017c4e
        //     func 00017c50 thunk_FUN_11bd_61ee    fnbody 00017c50 00017c50:00017c52
        //     func 00017dbe FUN_11bd_61ee          fnbody 00017dbe 00017dbe:00017e11
        // Ghidra keeps each thunk's body to its own jump and gives the target a function of its
        // own; mosura's body walk previously followed the jump and swallowed 0x17dbe instead.
        // Bodies are asserted, not just entries: recovering the target while leaving the thunk
        // with a swallowing body would be a half-port.
        if let Some(cluster) = thunk_cluster {
            for &entry in cluster {
                assert!(
                    mf.contains(&entry),
                    "{name}: missing thunk-cluster function {entry:08x} — Ghidra has it"
                );
                let gold_body = golden.bodies.iter().find(|b| b.entry == entry);
                let mine_body = snap.bodies.iter().find(|b| b.entry == entry);
                assert_eq!(
                    mine_body.map(|b| &b.ranges),
                    gold_body.map(|b| &b.ranges),
                    "{name}: body mismatch at {entry:08x} — the thunk must own only its own jump"
                );
            }
        }

        let mi: BTreeSet<u64> = snap.code_units.iter().copied().collect();
        let gi: BTreeSet<u64> = golden.code_units.iter().copied().collect();
        let misaligned = mi.difference(&gi).count();
        assert!(
            misaligned <= max_misaligned,
            "{name}: {misaligned} misaligned decodes (max {max_misaligned}) — over-decode regressed"
        );

        // A6 computed-flow subset invariant: every COMPUTED_JUMP / COMPUTED_CALL mosura
        // recovers (decompiler switch analyzer + symbolic indirect-call resolution) must be
        // one Ghidra also has — 0 spurious, on a real PE/MZ. the subject (16-bit real-mode DOS/4GW
        // stub) currently recovers 0 of its 20 COMPUTED_JUMP / 2 COMPUTED_CALL: those switch
        // sources sit in protected-mode LE code that mosura's 16-bit function discovery does
        // not reach, so the switch instructions are never disassembled (not a switch-analyzer
        // failure). The gate locks the clean-subset property; recall here is honestly 0.
        for kind in ["COMPUTED_JUMP", "COMPUTED_CALL"] {
            let mine: BTreeSet<(u64, u64)> =
                snap.refs.iter().filter(|r| r.kind == kind).map(|r| (r.from, r.to)).collect();
            let gold: BTreeSet<(u64, u64)> =
                golden.refs.iter().filter(|r| r.kind == kind).map(|r| (r.from, r.to)).collect();
            let spurious: Vec<_> = mine.difference(&gold).collect();
            assert!(spurious.is_empty(), "{name}: spurious {kind} vs Ghidra: {spurious:x?}");
            eprintln!(
                "  [{name}] {kind} {}/{} (0 spurious)",
                mine.intersection(&gold).count(),
                gold.len()
            );
        }
        eprintln!(
            "  [{name}] funcs {}/{} (0 spurious), insns {}/{} ({misaligned} misaligned ≤ {max_misaligned})",
            mf.intersection(&gf).count(), gf.len(), mi.intersection(&gi).count(), gi.len()
        );
        evaluated += 1;
    }
    eprintln!("PE/MZ convergence: {evaluated} binary(ies) evaluated");
}

/// A2 — loader-stage references. mosura's loader must emit no reference Ghidra's
/// `-noanalysis` loader doesn't (HARD subset), with a recall ratchet. Today mosura emits
/// the dynamic-relocation references (GOT/PLT slot → EXTERNAL symbol); the rest of
/// Ghidra's loader-stage refs come from ELF header / program-header / dynamic-table /
/// init-array data-structure markup (the documented remaining sub-project).
#[test]
fn loader_reference_parity() {
    use std::collections::BTreeSet;
    let goldens = analysis_goldens_dir();
    let corpus_dir = analysis_corpus_dir();
    let mut recall = Tally::default();
    for name in MANDATORY {
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.loaded.snapshot"))).unwrap(),
        );
        // analyze_binary is the load-only (loader-stage) snapshot.
        let snap = analysis::analyze_binary(&corpus_dir.join(format!("{name}.elf"))).unwrap();
        let mine: BTreeSet<(u64, u64, String)> =
            snap.refs.iter().map(|r| (r.from, r.to, r.kind.clone())).collect();
        let gold: BTreeSet<(u64, u64, String)> =
            golden.refs.iter().map(|r| (r.from, r.to, r.kind.clone())).collect();
        let spurious: Vec<_> = mine.difference(&gold).collect();
        assert!(spurious.is_empty(), "{name}: loader emitted refs Ghidra doesn't: {spurious:x?}");
        let matched = mine.intersection(&gold).count();
        eprintln!("  [{name}] loader-ref recall {matched}/{} (0 spurious)", gold.len());
        for _ in 0..matched {
            recall.record(true);
        }
        for _ in 0..(gold.len() - matched) {
            recall.record(false);
        }
    }
    eprintln!("loader-reference parity: {recall} (0 spurious)");
    // freestanding 4/4 (exact) + basic 32/36 + aarch64 3/3 + riscv 3/3 + m68k 3/3 (exact) = 45.
    // The remaining 4 (basic PLT) need loader-stage PLT disassembly with INDIRECTION typing — A6
    // indirect-flow territory.
    assert!(recall.passed >= 45, "loader-reference recall regressed below 45");
}

/// A4 — disassembly parity. Every instruction mosura decodes must match a Ghidra
/// instruction at the same address (HARD subset: no misaligned/spurious decodes), and we
/// ratchet recall. Missing instructions live in functions mosura doesn't yet reach (PLT
/// stubs, GOT-indirect).
#[test]
fn disassembly_parity() {
    use std::collections::BTreeSet;
    let goldens = analysis_goldens_dir();
    let corpus_dir = analysis_corpus_dir();
    let mut recall = Tally::default();
    for name in MANDATORY {
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.snapshot"))).unwrap(),
        );
        let snap = cached_analyze(&corpus_dir.join(format!("{name}.elf"))).snapshot();
        let mine: BTreeSet<u64> = snap.code_units.iter().copied().collect();
        let gold: BTreeSet<u64> = golden.code_units.iter().copied().collect();
        let misaligned: Vec<_> = mine.difference(&gold).collect();
        assert!(
            misaligned.is_empty(),
            "{name}: mosura decoded {} instruction(s) Ghidra didn't (misaligned?): {misaligned:x?}",
            misaligned.len()
        );
        let matched = mine.intersection(&gold).count();
        eprintln!("  [{name}] code-unit recall {matched}/{} (0 misaligned)", gold.len());
        for _ in 0..matched {
            recall.record(true);
        }
        for _ in 0..(gold.len() - matched) {
            recall.record(false);
        }
    }
    eprintln!("disassembly parity: {recall} (0 misaligned decodes)");
    // freestanding 40/40 + basic 106/106 + aarch64 39/39 + riscv 66/66 + m68k 31/31 = 282
    // instructions, 0 misaligned. basic reached 106/106 once the A6 PLT linear sweep
    // (ElfDefaultGotPltMarkup.processPLTSection) decodes the lazy-resolve stubs (PLT[0] + each
    // entry's `push; jmp PLT[0]` tail). aarch64 / riscv / m68k (freestanding ARM64 / RV64GC /
    // big-endian 32-bit m68k Coldfire) are exact — the SLEIGH engine lifts all three.
    assert!(recall.passed >= 282, "disassembly recall regressed below 282");
}

/// A7 Task 6 — GNU/Itanium C++ demangler parity. On the `cppsym` fixture (namespaced +
/// overloaded + const-method functions whose mangled names land in `.symtab`), mosura's
/// demangler analyzer must reproduce Ghidra's applied names exactly: each function symbol
/// renamed to the demangled **simple** name (`getName()`), the original mangled name kept
/// as a secondary label. Compared as `func (entry,name)` and `sym (addr,name,kind)` sets —
/// a HARD subset (0 spurious) with full recall on the demangled names.
#[test]
fn demangler_parity() {
    use std::collections::BTreeSet;
    let goldens = analysis_goldens_dir();
    let corpus_dir = analysis_corpus_dir();
    let golden =
        snapshot::parse(&std::fs::read_to_string(goldens.join("cppsym.snapshot")).unwrap());
    let snap = cached_analyze(&corpus_dir.join("cppsym.elf")).snapshot();

    // Function names (the demangled simple name is applied to the function).
    let mine_fn: BTreeSet<(u64, String)> =
        snap.functions.iter().map(|f| (f.entry, f.name.clone())).collect();
    let gold_fn: BTreeSet<(u64, String)> =
        golden.functions.iter().map(|f| (f.entry, f.name.clone())).collect();
    let spurious_fn: Vec<_> = mine_fn.difference(&gold_fn).collect();
    assert!(spurious_fn.is_empty(), "cppsym: spurious func names vs Ghidra: {spurious_fn:?}");
    assert_eq!(mine_fn, gold_fn, "cppsym: function names must match Ghidra exactly");

    // Symbols: the demangled simple name (Function) + the retained mangled name (Label).
    let mine_sym: BTreeSet<(u64, String, String)> =
        snap.symbols.iter().map(|s| (s.addr, s.name.clone(), s.kind.clone())).collect();
    let gold_sym: BTreeSet<(u64, String, String)> =
        golden.symbols.iter().map(|s| (s.addr, s.name.clone(), s.kind.clone())).collect();
    let spurious_sym: Vec<_> = mine_sym.difference(&gold_sym).collect();
    assert!(spurious_sym.is_empty(), "cppsym: spurious symbols vs Ghidra: {spurious_sym:?}");
    let matched = mine_sym.intersection(&gold_sym).count();
    eprintln!("  [cppsym] demangler sym recall {matched}/{} (0 spurious)", gold_sym.len());
    // Every Ghidra symbol must be reproduced (the 4 demangled Functions + 4 mangled Labels +
    // the .bss data labels) — full demangler parity on the fixture.
    assert_eq!(mine_sym, gold_sym, "cppsym: symbols must match Ghidra exactly");
}

/// Z80 CP/M `.COM` — mosura's first non-ELF (raw flat) corpus fixture, on its own gate (the
/// `.com` container doesn't fit the ELF `MANDATORY` loop). Validates the function listing as a
/// clean subset of the analyzeHeadless golden (captured via `BinaryLoader` + a manual
/// `z80:LE:16:default` processor / `0x100` base / entry pre-script — see
/// `scripts/capture-analysis.sh`). Function/code-unit/reference/body comparison is
/// address-based — as for the MZ corpus in [`pe_mz_convergence_parity`], Ghidra's dynamic
/// default names (`FUN_ram_XXXX`) are internal rendering, not string-compared — plus the
/// loader-stage block and the explicit processor-spec RST/NMI symbols (exact).
#[test]
fn z80_com_parity() {
    use std::collections::BTreeSet;
    let corpus = analysis_corpus_dir().join("z80.com");
    let goldens = analysis_goldens_dir();

    // --- converged: functions / code-units / references / bodies, 0 spurious / 0 misaligned ---
    let golden = snapshot::parse(&std::fs::read_to_string(goldens.join("z80.snapshot")).unwrap());
    let snap = cached_analyze(&corpus).snapshot();

    let mf: BTreeSet<u64> = snap.functions.iter().map(|f| f.entry).collect();
    let gf: BTreeSet<u64> = golden.functions.iter().map(|f| f.entry).collect();
    let spurious_fns: Vec<_> = mf.difference(&gf).collect();
    assert!(spurious_fns.is_empty(), "z80: spurious functions vs Ghidra: {spurious_fns:x?}");
    assert_eq!(mf, gf, "z80: function set must match Ghidra (4 functions: crt0/helper/compute/main)");

    let mi: BTreeSet<u64> = snap.code_units.iter().copied().collect();
    let gi: BTreeSet<u64> = golden.code_units.iter().copied().collect();
    let misaligned: Vec<_> = mi.difference(&gi).collect();
    assert!(misaligned.is_empty(), "z80: {} misaligned decode(s): {misaligned:x?}", misaligned.len());
    assert_eq!(mi, gi, "z80: code-unit set must match Ghidra");

    let mr: BTreeSet<(u64, u64)> = snap.refs.iter().map(|r| (r.from, r.to)).collect();
    let gr: BTreeSet<(u64, u64)> = golden.refs.iter().map(|r| (r.from, r.to)).collect();
    let spurious_refs: Vec<_> = mr.difference(&gr).collect();
    assert!(spurious_refs.is_empty(), "z80: spurious refs vs Ghidra: {spurious_refs:x?}");
    assert_eq!(mr, gr, "z80: reference set must match Ghidra (6 flow refs, no spurious param/data ref)");

    let bodies: std::collections::BTreeMap<u64, Vec<(u64, u64)>> =
        snap.bodies.iter().map(|b| (b.entry, b.ranges.clone())).collect();
    for gb in &golden.bodies {
        assert_eq!(bodies.get(&gb.entry), Some(&gb.ranges), "z80: function {:x} body differs", gb.entry);
    }
    eprintln!(
        "z80 .COM converged: funcs {}/{}, code-units {}/{}, refs {}/{}, bodies {} (0 spurious/misaligned)",
        mf.len(), gf.len(), mi.len(), gi.len(), mr.len(), gr.len(), golden.bodies.len()
    );

    // --- loader-stage: block + processor-spec RST/NMI symbols + entry addresses (exact) ---
    let golden_l = snapshot::parse(&std::fs::read_to_string(goldens.join("z80.loaded.snapshot")).unwrap());
    let snap_l = analysis::analyze_binary(&corpus).unwrap();
    assert_eq!(snap_l.blocks, golden_l.blocks, "z80: loader memory map must match (one 0x100 TPA block)");
    // The pspec default symbols (RST0..RST7 + NMI_ISR) — a HARD exact match, 0 spurious.
    let ms: BTreeSet<(u64, String, String)> =
        snap_l.symbols.iter().map(|s| (s.addr, s.name.clone(), s.kind.clone())).collect();
    let gs: BTreeSet<(u64, String, String)> =
        golden_l.symbols.iter().map(|s| (s.addr, s.name.clone(), s.kind.clone())).collect();
    assert_eq!(ms, gs, "z80: loader symbols (RST/NMI processor-spec defaults) must match Ghidra exactly");
    // Entry addresses: the 8 RST + NMI vectors + the 0x100 TPA entry.
    let me: BTreeSet<u64> = snap_l.entries.iter().map(|e| e.addr).collect();
    let ge: BTreeSet<u64> = golden_l.entries.iter().map(|e| e.addr).collect();
    assert_eq!(me, ge, "z80: loader entry-point addresses must match Ghidra");
    eprintln!("z80 .COM loader-stage: block + {} RST/NMI symbols + {} entries (exact)", gs.len(), ge.len());
}

/// Native-LE analysis of the configured subjects (task #8/#2, two-oracle). The DEFAULT view of a
/// DOS-extender-bound subject stays the Ghidra MZ-stub (its goldens + gates are untouched); this
/// validates the opt-in native-LE path (`analyze_le_file`) — the 32-bit protected-mode objects —
/// against the subject profile's expectations (`le.*` in `expect.toml`: the facts the RE ground
/// truth established, Ghidra having no LE loader). Validated as a clean subset: the reference
/// invariant (every recovered reference targets mapped memory, 0 spurious) + the recovered
/// protected-mode switches + the cspec + the entry. Skips when no configured subject carries
/// `le.entry`, saying so.
///
/// SWITCH RECOVERY (task #2): the *real* protected-mode computed jumps are the Watcom
/// `jmp CS:[reg*4 + disp]` inline jump tables — cs:-relative dispatches. Both the table
/// displacement and every table entry are LE relocation ("fixup") records; `loader/le.rs` applies
/// them (`apply_le_fixups`), so the tables read their real absolute targets and the switch-gated
/// code is discovered. The switch targets are therefore anchored in the binary's *own fixup
/// records*. The `le.dispatch_<from>` expectations assert dispatches EXACTLY; the whole set is a
/// clean subset: every COMPUTED_JUMP target is mapped, none invented.
#[test]
fn le_subjects_analysis() {
    use mosura::analysis::program::RefType;
    let mut ran = 0;
    for s in mosura::devcfg::subjects() {
        let (Some(entry), Some(cspec)) = (s.expect_u64("le.entry"), s.expect("le.cspec")) else { continue };
        if !s.path.exists() {
            eprintln!("skip subject {}: binary absent", s.id);
            continue;
        }
        ran += 1;
        let id = &s.id;
        let prog = analysis::analyze_le_file(&s.path).expect("native-LE analysis of the subject");
        let ram = prog.default_space;
        let at = |o: u64| mosura::decompile::space::Address::new(ram, o);

        // The LE path's compiler spec (the watcall convention for a Watcom subject).
        assert_eq!(prog.compiler_spec_id, cspec, "subject {id}: native-LE cspec");
        assert!(prog.entry_points.iter().any(|a| a.offset == entry), "subject {id}: entry {entry:#x}");
        // Function discovery reached the switch-gated 32-bit code — a ratchet floor, not the exact count.
        let nfuncs = prog.function_manager.function_count();
        if let Some(min) = s.expect_u64("le.min_functions") {
            assert!(nfuncs as u64 > min, "subject {id}: switch-gated discovery, got {nfuncs} (floor {min})");
        }
        // Functions reachable only through the recovered cs: switches.
        for f in s.expect_list_u64("le.switch_gated").unwrap_or_default() {
            assert!(prog.function_manager.function_at(at(f)).is_some(), "subject {id}: fn_{f:x} discovered via a recovered switch");
        }
        // ⭐ The entry THUNK's target: the entry is a short jump over an inline banner; Ghidra creates
        // the target as its own function through `CreateFunctionCmd.resolveThunk` ->
        // `CreateThunkFunctionCmd.getReferencedFunction` (`analysis/analyzers/thunk.rs`). Without that
        // port the body walk follows the `jmp` and swallows the target into the entry function.
        if let Some(t) = s.expect_u64("le.thunk_target") {
            assert!(prog.function_manager.function_at(at(t)).is_some(), "subject {id}: the entry thunk's target {t:#x} must be its own function");
        }
        // Clean subset — the no-spurious-reference invariant: every recovered reference targets
        // mapped memory. No relocation or switch target may point outside the image.
        for r in prog.reference_manager.references() {
            assert!(prog.memory.contains(r.to), "subject {id}: reference to unmapped {:08x}", r.to.offset);
        }
        // The recovered protected-mode switches (COMPUTED_JUMP), all anchored in the subject's own
        // fixup records. Every target mapped (0 spurious); the named dispatches resolve EXACTLY.
        let cj: Vec<(u64, u64)> = prog
            .reference_manager
            .references()
            .filter(|r| r.ref_type == RefType::ComputedJump)
            .map(|r| (r.from.offset, r.to.offset))
            .collect();
        if let Some(min) = s.expect_u64("le.min_computed_jumps") {
            assert!(cj.len() as u64 >= min, "subject {id}: recovered protected-mode switches, got {}", cj.len());
        }
        let mut dispatches: Vec<u64> = cj.iter().map(|(f, _)| *f).collect();
        dispatches.sort();
        dispatches.dedup();
        if let Some(min) = s.expect_u64("le.min_dispatches") {
            assert!(dispatches.len() as u64 >= min, "subject {id}: distinct switch dispatches, got {}", dispatches.len());
        }
        let targets_of = |disp: u64| {
            let mut t: Vec<u64> = cj.iter().filter(|(f, _)| *f == disp).map(|(_, to)| *to).collect();
            t.sort();
            t
        };
        for (k, v) in s.expectations().entries() {
            let Some(from) = k.strip_prefix("le.dispatch_").and_then(mosura::devcfg::parse_u64) else { continue };
            let want = mosura::devcfg::parse_u64_list(v).unwrap_or_else(|| panic!("subject {id}: `{k}` is not a list of addresses"));
            assert_eq!(targets_of(from), want, "subject {id}: dispatch {from:#x} resolves to its fixup-relocated case targets");
        }
        eprintln!(
            "subject {id} native-LE: {nfuncs} functions, {} COMPUTED_JUMP from {} dispatches (0 unmapped/spurious), cspec {cspec}",
            cj.len(),
            dispatches.len()
        );
    }
    if ran == 0 {
        eprintln!("skip le_subjects_analysis: no configured subject carries le.entry/le.cspec expectations");
    }
}

/// Watcom compiler detection (two-oracle — `loader::watcom`). Beyond Ghidra (which reports
/// `unknown` for Watcom binaries): the loader reads the Watcom C run-time copyright banner and
/// records the era as the `Compiler` info property. Validated against the SECOND oracle — real
/// Watcom-toolchain output — not Ghidra: (1) `watcom_hello.exe`, a committed DOS/4GW LE freshly
/// built with a real Watcom 10.0a toolchain (see oracle/analysis-corpus/src/watcom_hello.c);
/// (2) the subject binary if present (user-provided); and the no-false-positive case on a non-Watcom MZ
/// (DJGPP comcom32). The banner is an era fingerprint (year range), not a precise release — see
/// the `watcom` module note.
#[test]
fn watcom_detection() {
    // (1) The fresh 10.0a-built LE fixture — committed, so this always runs.
    let fixture = analysis_corpus_dir().join("watcom_hello.exe");
    let data = std::fs::read(&fixture).expect("watcom_hello.exe fixture");
    let info = mosura::analysis::loader::watcom::detect(&data).expect("watcom banner in fixture");
    assert_eq!(info.compiler_label(), "watcom:1988-1994");
    assert_eq!(info.product, "C/C++");
    assert_eq!(info.bitness, "32");
    // Through the loader dispatch (a standalone DOS/4GW LE) the Compiler property is set, and
    // the beyond-Ghidra `watcom` compiler spec (the watcall convention) is selected.
    let prog = mosura::analysis::loader::load(&data).expect("load watcom_hello.exe");
    assert_eq!(prog.compiler, "watcom:1988-1994", "fresh Watcom LE fixture → watcom era");
    assert_eq!(prog.compiler_spec_id, "watcom", "Watcom LE → watcall cspec (not the gcc placeholder)");
    eprintln!("watcom_hello.exe: {} cspec={} ({})", prog.compiler, prog.compiler_spec_id, info.banner);

    // (2) The configured subjects (dev-config `[[subject]]`, `analysis.compiler` in the profile):
    // the default dispatch detects the compiler, and the LE dispatch too where the subject is one.
    for s in mosura::devcfg::subjects() {
        let (Some(expected), true) = (s.expect("analysis.compiler"), s.path.exists()) else { continue };
        let d = std::fs::read(&s.path).unwrap();
        assert_eq!(mosura::analysis::loader::load(&d).unwrap().compiler, expected, "subject {}: default dispatch", s.id);
        if s.expect("le.entry").is_some() {
            assert_eq!(mosura::analysis::loader::load_le(&d).unwrap().compiler, expected, "subject {}: LE dispatch", s.id);
        }
        eprintln!("subject {}: {expected} detected", s.id);
    }

    // (3) No false positive: a non-Watcom MZ (DJGPP comcom32) has no Watcom banner.
    let comcom = comcom32_exe();
    if comcom.exists() {
        let d = std::fs::read(&comcom).unwrap();
        assert!(mosura::analysis::loader::watcom::detect(&d).is_none(), "DJGPP must not match Watcom");
        assert_eq!(mosura::analysis::loader::load(&d).unwrap().compiler, "unknown", "non-Watcom → unknown");
        eprintln!("comcom32 (DJGPP): no Watcom banner (compiler=unknown)");
    }
}

/// Task 4 — native LE (Linear Executable) loader, validated against each configured subject's
/// profile (`le.header_offset`, `le.image_base`, `le.code_object`, `le.data_object`, `le.entry`,
/// `le.entry_bytes` in `expect.toml` — the RE ground truth; Ghidra has no LE loader, so there is no
/// Ghidra golden). Skips when no configured subject carries `le.header_offset`. This loader is NOT
/// wired into a bound exe's default dispatch (it stays on the MZ path for the Ghidra-parity gates)
/// — it is exercised directly here.
#[test]
fn le_subjects_objects() {
    use mosura::analysis::loader;
    use mosura::analysis::program::SymbolType;
    let mut ran = 0;
    for s in mosura::devcfg::subjects() {
        let Some(header_offset) = s.expect_u64("le.header_offset") else { continue };
        if !s.path.exists() {
            eprintln!("skip subject {}: binary absent", s.id);
            continue;
        }
        ran += 1;
        let id = &s.id;
        let data = std::fs::read(&s.path).unwrap();
        // A bound DOS-extender exe: e_lfanew is deliberately invalid, so the LE is found by
        // scanning, not the standalone-dispatch path.
        let le_off = loader::detect_le(&data).expect("embedded LE header detected");
        assert_eq!(le_off as u64, header_offset, "subject {id}: LE header at the RE-confirmed file offset");

        let prog = loader::load_le(&data).expect("LE load");
        assert_eq!(prog.language_id, "x86:LE:32:default");
        if let Some(base) = s.expect_u64("le.image_base") {
            assert_eq!(prog.image_base.offset, base, "subject {id}: image base = first object's virtual base");
        }
        // The objects (RE ground truth): code R+X, data R+W, each "start,virtual size".
        let blocks: Vec<_> = prog.memory.blocks().collect();
        if let Some(code) = s.expect_list_u64("le.code_object") {
            let b = blocks.iter().find(|b| b.is_execute()).expect("a code object");
            assert_eq!((b.start().offset, b.end().offset), (code[0], code[0] + code[1] - 1), "subject {id}: code object");
            assert!(b.is_read() && !b.is_write() && b.is_execute(), "subject {id}: code object R+X");
        }
        if let Some(dat) = s.expect_list_u64("le.data_object") {
            let b = blocks.iter().find(|b| !b.is_execute()).expect("a data object");
            assert_eq!((b.start().offset, b.end().offset), (dat[0], dat[0] + dat[1] - 1), "subject {id}: data object");
            assert!(b.is_read() && b.is_write() && !b.is_execute(), "subject {id}: data object R+W");
        }
        if s.expect_list_u64("le.code_object").is_some() && s.expect_list_u64("le.data_object").is_some() {
            assert_eq!(blocks.len(), 2, "subject {id}: exactly the two objects");
        }
        // Entry = obj base + init-EIP; its first bytes as the profile records them (the jump thunk
        // over an inline banner string — verified file bytes).
        if let Some(entry) = s.expect_u64("le.entry") {
            let e = prog.entry_points.iter().find(|a| a.offset == entry).expect("the entry point");
            assert_eq!(prog.symbol_table.primary_at(*e).map(|s| s.symbol_type()), Some(SymbolType::Function));
            if let Some(bytes) = s.expect("le.entry_bytes") {
                let want: Vec<Option<u8>> = bytes.split(',').map(|b| u8::from_str_radix(b.trim(), 16).ok()).collect();
                let got: Vec<Option<u8>> = (0..want.len() as u64)
                    .map(|i| prog.memory.byte_at(mosura::decompile::space::Address::new(e.space, entry + i)))
                    .collect();
                assert_eq!(got, want, "subject {id}: entry begins with the recorded bytes");
            }
        }
        eprintln!("  [subject {id}] LE loader: objects + entry match the profile's ground truth");
    }
    if ran == 0 {
        eprintln!("skip le_subjects_objects: no configured subject carries le.header_offset");
    }
}

/// A4 — converged function-set parity. Every function mosura discovers must be a Ghidra
/// function (HARD subset: no spurious functions), with a recall ratchet. The missing
/// remainder is reached only via PLT-stub disassembly / GOT pointer-following.
#[test]
fn function_parity() {
    use std::collections::BTreeSet;
    let goldens = analysis_goldens_dir();
    let corpus_dir = analysis_corpus_dir();
    let mut recall = Tally::default();
    for name in MANDATORY {
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.snapshot"))).unwrap(),
        );
        let snap = cached_analyze(&corpus_dir.join(format!("{name}.elf"))).snapshot();
        let mine: BTreeSet<u64> = snap.functions.iter().map(|f| f.entry).collect();
        let gold: BTreeSet<u64> = golden.functions.iter().map(|f| f.entry).collect();
        let spurious: Vec<_> = mine.difference(&gold).collect();
        assert!(
            spurious.is_empty(),
            "{name}: mosura created {} function(s) Ghidra didn't: {spurious:x?}",
            spurious.len()
        );
        let matched = mine.intersection(&gold).count();
        eprintln!("  [{name}] function recall {matched}/{}", gold.len());
        for _ in 0..matched {
            recall.record(true);
        }
        for _ in 0..(gold.len() - matched) {
            recall.record(false);
        }
    }
    eprintln!("function parity: {recall}");
    // freestanding 3/3 + basic 15/16 + aarch64 3/3 + riscv 3/3 + m68k 3/3 = 27. basic reached
    // 15 once A7's SharedReturnAnalyzer recovered FUN_00401020 (PLT[0]) from the resolve-tail
    // `jmp 0x401020` crossing the printf@plt boundary. The remaining basic miss is
    // __gmon_start__@0x405010 (a weak external). aarch64 / riscv / m68k recover all 3 functions each.
    assert!(recall.passed >= 27, "function recall regressed below 27");
}

/// A4 — function-body parity. For every function mosura *and* Ghidra both have, the body
/// (the address ranges the function owns, Ghidra `Function.getBody`) must match **exactly**
/// — a HARD assert, plus a ratchet on how many bodies are validated.
#[test]
fn function_body_parity() {
    use std::collections::BTreeMap;
    let goldens = analysis_goldens_dir();
    let corpus_dir = analysis_corpus_dir();
    let mut validated = 0usize;
    for name in MANDATORY {
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.snapshot"))).unwrap(),
        );
        let snap = cached_analyze(&corpus_dir.join(format!("{name}.elf"))).snapshot();
        let mine: BTreeMap<u64, Vec<(u64, u64)>> =
            snap.bodies.iter().map(|b| (b.entry, b.ranges.clone())).collect();
        let mut matched = 0usize;
        for b in &golden.bodies {
            if let Some(mr) = mine.get(&b.entry) {
                assert_eq!(*mr, b.ranges, "{name}: function {:08x} body differs from Ghidra", b.entry);
                matched += 1;
            }
        }
        eprintln!("  [{name}] function bodies {matched}/{} exact (the rest are undiscovered functions)", golden.bodies.len());
        validated += matched;
    }
    eprintln!("function-body parity: {validated} exact bodies");
    // freestanding 3 + basic 15 + aarch64 3 + riscv 3 + m68k 3 = 27 bodies validated exactly
    // (basic +1: FUN_00401020 / PLT[0] recovered by the A7 SharedReturnAnalyzer, body
    // 00401020:0040102b).
    assert!(validated >= 27, "function-body validation regressed below 27");
}

/// A5 — references parity. mosura's analysis must never invent a reference Ghidra
/// doesn't have (a HARD subset gate over references **from executable code**), and we
/// ratchet how many of Ghidra's code references it recovers. The missing remainder is
/// A6-level analysis (computed calls, parameters, indirection) + deeper propagation.
#[test]
fn reference_parity() {
    use std::collections::BTreeSet;
    let goldens = analysis_goldens_dir();
    let corpus_dir = analysis_corpus_dir();
    let mut recall = Tally::default();
    for name in MANDATORY {
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.snapshot"))).unwrap(),
        );
        let program = cached_analyze(&corpus_dir.join(format!("{name}.elf")));
        let snap = program.snapshot();

        // References whose source is executable memory — what disassembly + the
        // SymbolicPropogator are responsible for (compared on (from, to); Ghidra refines
        // some types to PARAM/INDIRECTION/CALL via A6 analyzers we haven't ported).
        let exec: Vec<(u64, u64)> = program
            .memory
            .blocks()
            .filter(|b| b.is_execute())
            .map(|b| (b.start().offset, b.end().offset))
            .collect();
        let in_code = |a: u64| exec.iter().any(|&(s, e)| a >= s && a <= e);
        let mine: BTreeSet<(u64, u64)> =
            snap.refs.iter().filter(|r| in_code(r.from)).map(|r| (r.from, r.to)).collect();
        let gold: BTreeSet<(u64, u64)> =
            golden.refs.iter().filter(|r| in_code(r.from)).map(|r| (r.from, r.to)).collect();

        let false_positives: Vec<_> = mine.difference(&gold).collect();
        assert!(
            false_positives.is_empty(),
            "{name}: mosura invented {} reference(s) absent from Ghidra: {false_positives:x?}",
            false_positives.len()
        );
        let matched = mine.intersection(&gold).count();
        eprintln!("  [{name}] code-ref recall {matched}/{} (0 false positives)", gold.len());
        for _ in 0..matched {
            recall.record(true);
        }
        for _ in 0..(gold.len() - matched) {
            recall.record(false);
        }
    }
    eprintln!("reference parity: {recall} (recovered code refs, 0 false positives)");
    // Ratchet: freestanding 4/4 + basic 32/33 + aarch64 7/7 + riscv 7/7 + m68k 7/7 = 57
    // recovered. A7 Task 1 (SharedReturn) added the `0x401020 → 0x403ff0 READ` inside PLT[0]
    // (recovered once FUN_00401020 exists) and retyped `0x40103b → 0x401020` to
    // UNCONDITIONAL_CALL (type validated in the a7_shared_return test). The remaining basic miss
    // is `0x401004 → 0x405010` (the __gmon_start__ weak-external code-ref — investigated in the
    // A7 close-out). aarch64 / riscv / m68k each have 7 exec-from code refs (2 jumps + 2 calls +
    // 3 ELF-header DATA), exact, with no spurious link-register return-address DATA ref: AArch64
    // `bl`'s inst_start and RISC-V `jal`'s inst_next PC-constant are both excluded (the PC-marker
    // guard, symbolic.rs); m68k's `bsr`/`jsr` push the return address via STORE (also excluded).
    assert!(recall.passed >= 57, "code-reference recall regressed below 57");
}

/// A7 Task 2 — `.eh_frame_hdr` reference parity. The GCC exception-frame analyzer emits
/// references whose source is the `.eh_frame_hdr` *data* section (not executable code, so
/// they fall outside [`reference_parity`]'s exec-from filter): the FDE-table INDIRECTION
/// refs to each protected function plus the DATA refs to the FDEs and the eh_frame pointer.
/// HARD subset (0 spurious) with a recall ratchet, compared on (from, to, kind).
#[test]
fn eh_frame_reference_parity() {
    use std::collections::BTreeSet;
    let goldens = analysis_goldens_dir();
    let corpus_dir = analysis_corpus_dir();
    let mut recall = Tally::default();
    for name in MANDATORY {
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.snapshot"))).unwrap(),
        );
        let program = cached_analyze(&corpus_dir.join(format!("{name}.elf")));
        let snap = program.snapshot();
        // The `.eh_frame_hdr` block range (skip binaries without one, e.g. freestanding).
        let Some((lo, hi)) = program
            .memory
            .block_by_name(".eh_frame_hdr")
            .map(|b| (b.start().offset, b.end().offset))
        else {
            continue;
        };
        let from_ehh = |from: u64| from >= lo && from <= hi;
        let mine: BTreeSet<(u64, u64, String)> =
            snap.refs.iter().filter(|r| from_ehh(r.from)).map(|r| (r.from, r.to, r.kind.clone())).collect();
        let gold: BTreeSet<(u64, u64, String)> =
            golden.refs.iter().filter(|r| from_ehh(r.from)).map(|r| (r.from, r.to, r.kind.clone())).collect();
        let spurious: Vec<_> = mine.difference(&gold).collect();
        assert!(spurious.is_empty(), "{name}: spurious .eh_frame_hdr refs vs Ghidra: {spurious:x?}");
        let matched = mine.intersection(&gold).count();
        eprintln!("  [{name}] .eh_frame_hdr-ref recall {matched}/{} (0 spurious)", gold.len());
        for _ in 0..matched {
            recall.record(true);
        }
        for _ in 0..(gold.len() - matched) {
            recall.record(false);
        }
    }
    eprintln!("eh_frame-reference parity: {recall} (0 spurious)");
    // basic: the eh_frame_ptr DATA ref + 6 FDE-table entries × (INDIRECTION + DATA) = 13.
    assert!(recall.passed >= 13, "eh_frame-reference recall regressed below 13");
}

/// A7 Task 5 — defined-data-unit parity. mosura's data-markup analysis must never define a
/// data unit Ghidra doesn't (a HARD subset gate over `Listing.getDefinedData`, compared on
/// `(addr, type-name, len)`), with a recall ratchet. Today mosura defines only the GCC
/// exception-frame data units (`eh_frame_hdr`, the encoded `eh_frame_ptr`/`fde_count`
/// `dword`s, and `fde_table_entry[]`); the rest of Ghidra's defined data — ELF-structure
/// markup (`Elf64_Ehdr`/`Phdr`/`Sym`/`Rela`/`Dyn`, dynamic `string-utf8` entries) and the
/// `.eh_frame` CIE/FDE field markup — comes from the loader / `EhFrameSection`, deferred.
#[test]
fn data_unit_parity() {
    use std::collections::BTreeSet;
    let goldens = analysis_goldens_dir();
    let corpus_dir = analysis_corpus_dir();
    let mut recall = Tally::default();
    for name in MANDATORY {
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.snapshot"))).unwrap(),
        );
        let snap = cached_analyze(&corpus_dir.join(format!("{name}.elf"))).snapshot();
        let mine: BTreeSet<(u64, String, u32)> =
            snap.data.iter().map(|d| (d.addr, d.type_name.clone(), d.len)).collect();
        let gold: BTreeSet<(u64, String, u32)> =
            golden.data.iter().map(|d| (d.addr, d.type_name.clone(), d.len)).collect();
        let spurious: Vec<_> = mine.difference(&gold).collect();
        assert!(
            spurious.is_empty(),
            "{name}: mosura defined {} data unit(s) absent from Ghidra: {spurious:?}",
            spurious.len()
        );
        let matched = mine.intersection(&gold).count();
        eprintln!("  [{name}] data-unit recall {matched}/{} (0 spurious)", gold.len());
        for _ in 0..matched {
            recall.record(true);
        }
        for _ in 0..(gold.len() - matched) {
            recall.record(false);
        }
    }
    eprintln!("data-unit parity: {recall} (0 spurious)");
    // basic 99/99 + freestanding 3/3 + aarch64 3/3 + riscv 3/3 + m68k 3/3 = 111 — FULL data-unit
    // parity on the ELF corpus. .eh_frame_hdr/.eh_frame units + the ELF-loader markup: ElfN_Ehdr/
    // Phdr/Sym/Rela/Dyn, .gnu.hash/.gnu.version/.dynstr/.interp, the GNU notes (NoteGnuProperty/
    // Element, GnuBuildId, NoteAbiTag), the .init_array/.fini_array + GOT/.got.plt `pointer`
    // units, and the sized-OBJECT-symbol `undefined<size>` units (_IO_stdin_used, completed.0).
    // aarch64 / riscv / m68k: ElfN_Ehdr + ElfN_Phdr[n] + GnuBuildId — the arch-neutral markup,
    // class-parameterized (m68k emits the 32-bit `Elf32_Ehdr` (52) + `Elf32_Phdr[3]` (96) units).
    assert!(recall.passed >= 111, "data-unit recall regressed below 111");
}

#[test]
fn loader_detail_parity() {
    let goldens = analysis_goldens_dir();
    let mut detail = Tally::default();
    let mut evaluated = Vec::new();
    for (name, path, mandatory, golden_path) in corpus() {
        if !path.exists() {
            assert!(!mandatory, "mandatory corpus binary missing: {}", path.display());
            continue;
        }
        let golden = snapshot::parse(
            &std::fs::read_to_string(&golden_path)
                .unwrap_or_else(|e| panic!("loader-stage golden for {name}: {e}")),
        );
        let p = analysis::analyze_binary(&path).unwrap_or_else(|e| panic!("analyze {name}: {e}"));
        let ok = p.functions == golden.functions
            && p.entries == golden.entries
            && p.symbols == golden.symbols;
        if !ok {
            eprintln!(
                "  [{name}] detail differs: func {}/{}, entry {}/{}, sym {}/{}",
                p.functions.len(), golden.functions.len(),
                p.entries.len(), golden.entries.len(),
                p.symbols.len(), golden.symbols.len(),
            );
        }
        detail.record(ok);
        evaluated.push(name);
    }
    eprintln!("loader-detail parity: {detail} ({evaluated:?})");
    assert!(evaluated.iter().any(|n| n == "freestanding") && evaluated.iter().any(|n| n == "basic"), "ELF corpus must run");
    assert_eq!(detail.passed, detail.total, "every evaluated binary's loader detail must match its golden");
}
