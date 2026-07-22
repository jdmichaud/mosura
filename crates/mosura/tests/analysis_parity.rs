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
use mosura::paths::{analysis_corpus_dir, analysis_goldens_dir, cnv_exe, comcom32_exe, war2_exe};

/// Committed ELF corpus (always present). `aarch64`, `riscv`, and `m68k` are the
/// non-x86 fixtures (freestanding ARM64 / RV64GC / big-endian 32-bit m68k ELFs) —
/// validate the function-listing pipeline on those ISAs.
const MANDATORY: &[&str] = &["freestanding", "basic", "aarch64", "riscv", "m68k"];

/// (name, binary path, mandatory?) — externals are user-provided, skipped if absent.
fn corpus() -> Vec<(&'static str, PathBuf, bool)> {
    let mut v: Vec<(&str, PathBuf, bool)> = MANDATORY
        .iter()
        .map(|n| (*n, analysis_corpus_dir().join(format!("{n}.elf")), true))
        .collect();
    v.push(("cnv", cnv_exe(), false)); // PE, user-provided (MOSURA_CNV_EXE)
    v.push(("comcom32", comcom32_exe(), false)); // MZ (MOSURA_COMCOM32_EXE)
    v.push(("war2", war2_exe(), false)); // MZ (DOS/4GW stub), user-provided (MOSURA_WAR2_EXE)
    v
}

#[test]
fn memory_map_parity() {
    let goldens = analysis_goldens_dir();
    let mut blocks = Tally::default();
    let mut evaluated = Vec::new();

    for (name, path, mandatory) in corpus() {
        if !path.exists() {
            assert!(!mandatory, "mandatory corpus binary missing: {}", path.display());
            eprintln!("  skip {name}: {} not present", path.display());
            continue;
        }
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.loaded.snapshot")))
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
    assert!(evaluated.contains(&"freestanding") && evaluated.contains(&"basic"), "ELF corpus must run");
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
    let Some(path) = std::env::var_os("MOSURA_BC45_EXE").map(PathBuf::from) else {
        eprintln!("skip pe_compiler_opinion_borland: set MOSURA_BC45_EXE to a Borland C++ 4.5 PE");
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
    let Some(path) = std::env::var_os("MOSURA_VC6_EXE").map(PathBuf::from) else {
        eprintln!("skip pe_compiler_opinion_msvc: set MOSURA_VC6_EXE to an MSVC 6.0 PE");
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
        ("mingw_hello.exe", Family::Gcc, "14-win32", Precision::Exact),
        ("mingw_hello32.exe", Family::Gcc, "14-win32", Precision::Exact),
        ("watcom_hello.exe", Family::Watcom, "1988-1994", Precision::Era),
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
    let cases: &[(&str, Family, &str)] = &[
        ("MOSURA_VC6_EXE", Family::Msvc, "msvc:6.0"),
        ("MOSURA_BC45_EXE", Family::Borland, "borland:c++:1994"),
    ];
    for (env, fam, label) in cases {
        let Some(path) = std::env::var_os(env).map(PathBuf::from) else {
            eprintln!("skip {env}: not set");
            continue;
        };
        if !path.exists() {
            eprintln!("skip {env}: {} absent", path.display());
            continue;
        }
        let data = std::fs::read(&path).unwrap();
        let id = detect(&data).unwrap_or_else(|| panic!("no version marker via {env}"));
        assert_eq!(id.family, *fam, "{env} family");
        assert_eq!(id.label(), *label, "{env} label");
        eprintln!("{env}: {} [{:?}] — {}", id.label(), id.precision, id.evidence);
    }
}

/// PE/MZ convergence — extends the A4/A5 checks beyond ELF. mosura must create no
/// function Ghidra lacks (HARD, every format), and its disassembly must stay within a
/// small, bounded misalignment of Ghidra's. comcom32 (MZ) is exact; war2 (16-bit DOS) has
/// a handful of over-decodes where mosura runs past a function into inter-function padding
/// that Ghidra's later data analysis (A6/A7) would claim — bounded and tracked here. cnv
/// (PE) is smoke-tested in [`analysis_robustness`] (its converged golden is too large to
/// commit). All skip-if-absent (user-provided binaries).
#[test]
fn pe_mz_convergence_parity() {
    use std::collections::BTreeSet;
    let goldens = analysis_goldens_dir();
    // (name, path, max tolerated misaligned decodes)
    let cases: [(&str, PathBuf, usize); 2] =
        [("comcom32", comcom32_exe(), 0), ("war2", war2_exe(), 8)];
    let mut evaluated = 0;
    for (name, path, max_misaligned) in &cases {
        let name = *name;
        let max_misaligned = *max_misaligned;
        let golden_path = goldens.join(format!("{name}.snapshot"));
        if !path.exists() || !golden_path.exists() {
            eprintln!("  skip {name}: binary or golden absent");
            continue;
        }
        let golden = snapshot::parse(&std::fs::read_to_string(&golden_path).unwrap());
        let snap = analysis::analyze_file(path).unwrap().snapshot();

        let mf: BTreeSet<u64> = snap.functions.iter().map(|f| f.entry).collect();
        let gf: BTreeSet<u64> = golden.functions.iter().map(|f| f.entry).collect();
        let spurious_fns: Vec<_> = mf.difference(&gf).collect();
        assert!(spurious_fns.is_empty(), "{name}: spurious functions vs Ghidra: {spurious_fns:x?}");

        let mi: BTreeSet<u64> = snap.code_units.iter().copied().collect();
        let gi: BTreeSet<u64> = golden.code_units.iter().copied().collect();
        let misaligned = mi.difference(&gi).count();
        assert!(
            misaligned <= max_misaligned,
            "{name}: {misaligned} misaligned decodes (max {max_misaligned}) — over-decode regressed"
        );

        // A6 computed-flow subset invariant: every COMPUTED_JUMP / COMPUTED_CALL mosura
        // recovers (decompiler switch analyzer + symbolic indirect-call resolution) must be
        // one Ghidra also has — 0 spurious, on a real PE/MZ. war2 (16-bit real-mode DOS/4GW
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
        let snap = analysis::analyze_file(&corpus_dir.join(format!("{name}.elf"))).unwrap().snapshot();
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
    let snap = analysis::analyze_file(&corpus_dir.join("cppsym.elf")).unwrap().snapshot();

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
    let snap = analysis::analyze_file(&corpus).unwrap().snapshot();

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

/// war2 native-LE analysis (task #8/#2, two-oracle). The DEFAULT war2 view stays the Ghidra
/// MZ-stub (its goldens + gates are untouched); this validates the opt-in native-LE path
/// (`analyze_le_file`) — the 32-bit protected-mode objects (obj1 code @0x10000, obj2 data
/// @0x80000, entry _cstart_ 0x601F8) — against the warcraft2-re RE ground truth (Ghidra has no
/// LE loader). Validated as a clean subset: the reference invariant (every recovered reference
/// targets mapped memory, 0 spurious) + the recovered protected-mode switches + watcall + entry.
/// Skipped if WAR2.EXE is absent (user-provided).
///
/// SWITCH RECOVERY (task #2 — the "beat Ghidra on WAR2" win): the *real* protected-mode
/// computed jumps are the Watcom `jmp CS:[reg*4 + disp]` inline jump tables — WAR2's cs:-relative
/// dispatches. Both the table displacement and every table entry are LE relocation ("fixup")
/// records; `loader/le.rs` now applies them (`apply_le_fixups`), so the tables read their real
/// absolute targets and the switch-gated code (incl. the decompressor family fn_79130/793e0/7a5b0)
/// is discovered — function count jumps ~541 → ~1279. The switch targets are therefore anchored
/// in the binary's *own fixup records* (Ghidra has no LE loader — its MZ-stub `war2.snapshot`
/// 20 COMPUTED_JUMP are artifacts of misreading the 32-bit code and are not used here). The two
/// decompressor decode-loop dispatches are asserted EXACTLY (4-way each), and the whole set is a
/// clean subset: every COMPUTED_JUMP target is mapped, none invented.
#[test]
fn le_war2_analysis() {
    use mosura::analysis::program::RefType;
    let path = war2_exe();
    if !path.exists() {
        eprintln!("skip le_war2_analysis: WAR2.EXE absent");
        return;
    }
    let prog = analysis::analyze_le_file(&path).expect("native-LE analysis of WAR2.EXE");
    let ram = prog.default_space;
    let at = |o: u64| mosura::decompile::space::Address::new(ram, o);

    // The watcall convention (task #7) is the LE path's compiler spec.
    assert_eq!(prog.compiler_spec_id, "watcom", "native-LE war2 uses the watcall cspec");
    // The _cstart_ entry (docs/le-loader-notes.md: obj1_vbase 0x10000 + 0x501F8).
    assert!(
        prog.entry_points.iter().any(|a| a.offset == 0x601f8),
        "native-LE war2 has the _cstart_ entry 0x601F8"
    );
    // Function discovery reached the switch-gated 32-bit code (was ~541 before fixups; the
    // default MZ path recovers ~none). A ratchet floor, not the exact count.
    let nfuncs = prog.function_manager.function_count();
    assert!(nfuncs > 1200, "native-LE war2 discovers its switch-gated functions, got {nfuncs}");
    // The decompressor family — reachable only through the recovered cs: switches.
    for f in [0x79130u64, 0x793e0, 0x7a5b0] {
        assert!(
            prog.function_manager.function_at(at(f)).is_some(),
            "native-LE war2: decompressor fn_{f:x} discovered via recovered switch"
        );
    }
    // Clean subset — the no-spurious-reference invariant: every recovered reference targets
    // mapped memory (obj1/obj2). No relocation or switch target may point outside the image.
    for r in prog.reference_manager.references() {
        assert!(prog.memory.contains(r.to), "native-LE war2: reference to unmapped {:08x}", r.to.offset);
    }

    // The recovered protected-mode switches (COMPUTED_JUMP), all anchored in WAR2's own fixup
    // records. Every target mapped (0 spurious); the two decompressor decode-loop dispatches
    // resolve EXACTLY to their fixup-relocated 4-entry tables.
    let cj: Vec<(u64, u64)> = prog
        .reference_manager
        .references()
        .filter(|r| r.ref_type == RefType::ComputedJump)
        .map(|r| (r.from.offset, r.to.offset))
        .collect();
    assert!(cj.len() >= 40, "native-LE war2: recovered protected-mode switches, got {}", cj.len());
    let mut dispatches: Vec<u64> = cj.iter().map(|(f, _)| *f).collect();
    dispatches.sort();
    dispatches.dedup();
    assert!(dispatches.len() >= 8, "native-LE war2: distinct switch dispatches, got {}", dispatches.len());
    let targets_of = |disp: u64| {
        let mut t: Vec<u64> = cj.iter().filter(|(f, _)| *f == disp).map(|(_, to)| *to).collect();
        t.sort();
        t
    };
    // fn_793e0 decode-loop: `jmp CS:[ECX*4 + 0x694d0]` (fixup-relocated table @0x794d0).
    assert_eq!(
        targets_of(0x795d5),
        vec![0x795e0, 0x79cb0, 0x7a400, 0x7a4a0],
        "fn_793e0 dispatch resolves to its 4 fixup-relocated case targets"
    );
    // fn_7a5b0 decode-loop: `jmp CS:[ECX*4 + 0x6a6d0]` (fixup-relocated table @0x7a6d0).
    assert_eq!(
        targets_of(0x7a7d5),
        vec![0x7a7e0, 0x7af10, 0x7b6c0, 0x7b7b0],
        "fn_7a5b0 dispatch resolves to its 4 fixup-relocated case targets"
    );
    eprintln!(
        "war2 native-LE: {nfuncs} functions, {} COMPUTED_JUMP from {} dispatches (0 unmapped/spurious), \
         decompressor recovered, watcall cspec",
        cj.len(),
        dispatches.len()
    );
}

/// Watcom compiler detection (two-oracle — `loader::watcom`). Beyond Ghidra (which reports
/// `unknown` for Watcom binaries): the loader reads the Watcom C run-time copyright banner and
/// records the era as the `Compiler` info property. Validated against the SECOND oracle — real
/// Watcom-toolchain output — not Ghidra: (1) `watcom_hello.exe`, a committed DOS/4GW LE freshly
/// built with a real Watcom 10.0a toolchain (see oracle/analysis-corpus/src/watcom_hello.c);
/// (2) WAR2.EXE if present (user-provided); and the no-false-positive case on a non-Watcom MZ
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

    // (2) WAR2.EXE ground truth (user-provided): both the LE and the default MZ dispatch detect it.
    let war2 = war2_exe();
    if war2.exists() {
        let d = std::fs::read(&war2).unwrap();
        assert_eq!(mosura::analysis::loader::load_le(&d).unwrap().compiler, "watcom:1988-1994");
        assert_eq!(mosura::analysis::loader::load(&d).unwrap().compiler, "watcom:1988-1994");
        eprintln!("WAR2.EXE: watcom:1988-1994 (LE + MZ)");
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

/// Task 4 — native LE (Linear Executable) loader. WAR2.EXE is a DOS/4GW-bound LE; Ghidra
/// has no LE loader, so there is no Ghidra golden — this validates `loader::le` against the
/// warcraft2-re reverse-engineering ground truth recorded in `docs/le-loader-notes.md`: the
/// two objects (virtual base / size / perms) + the absolute entry. Skipped if WAR2.EXE is
/// absent (user-provided). This loader is NOT wired into war2's default dispatch (the bound
/// exe stays on the MZ path for the Ghidra-parity gates) — it is exercised directly here.
#[test]
fn le_war2_objects() {
    use mosura::analysis::loader;
    use mosura::analysis::program::SymbolType;
    let path = war2_exe();
    if !path.exists() {
        eprintln!("skip le_war2_objects: WAR2.EXE not present");
        return;
    }
    let data = std::fs::read(&path).unwrap();
    // Bound DOS/4GW exe: e_lfanew is deliberately invalid, so the LE is found by scanning,
    // not the standalone-dispatch path.
    let le_off = loader::detect_le(&data).expect("embedded LE header detected");
    assert_eq!(le_off, 0x37CF4, "LE header at the RE-confirmed file offset");

    let prog = loader::load_le(&data).expect("LE load");
    assert_eq!(prog.language_id, "x86:LE:32:default");
    assert_eq!(prog.image_base.offset, 0x10000, "image base = first object's virtual base");

    // The two objects (warcraft2-re ground truth): obj1 code _TEXT, obj2 data _DATA.
    let blocks: Vec<_> = prog.memory.blocks().collect();
    assert_eq!(blocks.len(), 2, "WAR2 LE has exactly two objects");
    let code = blocks.iter().find(|b| b.is_execute()).expect("a code object");
    assert_eq!(code.start().offset, 0x10000);
    assert_eq!(code.end().offset, 0x10000 + 0x6c4a0 - 1, "code object virtual size 0x6C4A0");
    assert!(code.is_read() && !code.is_write() && code.is_execute(), "code object R+X");
    let dataobj = blocks.iter().find(|b| !b.is_execute()).expect("a data object");
    assert_eq!(dataobj.start().offset, 0x80000);
    assert_eq!(dataobj.end().offset, 0x80000 + 0x2b300 - 1, "data object virtual size 0x2B300");
    assert!(dataobj.is_read() && dataobj.is_write() && !dataobj.is_execute(), "data object R+W");

    // Entry = obj1 base + init-EIP = 0x10000 + 0x501F8 = 0x601F8 (Watcom _cstart_ thunk,
    // first bytes `EB 76` jumping over an inline banner string — verified file bytes).
    let entry = prog.entry_points.iter().find(|a| a.offset == 0x601f8).expect("entry 0x601F8");
    assert_eq!(prog.symbol_table.primary_at(*entry).map(|s| s.symbol_type()), Some(SymbolType::Function));
    let eb = prog.memory.byte_at(*entry);
    let eb2 = prog.memory.byte_at(mosura::decompile::space::Address::new(entry.space, 0x601f9));
    assert_eq!((eb, eb2), (Some(0xeb), Some(0x76)), "entry begins with the EB 76 jump thunk");
    eprintln!("  [war2] LE loader: 2 objects + entry 0x601F8 match warcraft2-re ground truth");
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
        let snap = analysis::analyze_file(&corpus_dir.join(format!("{name}.elf"))).unwrap().snapshot();
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
        let snap = analysis::analyze_file(&corpus_dir.join(format!("{name}.elf"))).unwrap().snapshot();
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
        let program = analysis::analyze_file(&corpus_dir.join(format!("{name}.elf"))).unwrap();
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
        let program = analysis::analyze_file(&corpus_dir.join(format!("{name}.elf"))).unwrap();
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
        let snap = analysis::analyze_file(&corpus_dir.join(format!("{name}.elf"))).unwrap().snapshot();
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
    for (name, path, mandatory) in corpus() {
        if !path.exists() {
            assert!(!mandatory, "mandatory corpus binary missing: {}", path.display());
            continue;
        }
        let golden = snapshot::parse(
            &std::fs::read_to_string(goldens.join(format!("{name}.loaded.snapshot")))
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
    assert!(evaluated.contains(&"freestanding") && evaluated.contains(&"basic"), "ELF corpus must run");
    assert_eq!(detail.passed, detail.total, "every evaluated binary's loader detail must match its golden");
}
