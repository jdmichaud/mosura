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
use mosura::paths::{analysis_corpus_dir, analysis_goldens_dir};

/// Committed ELF corpus (always present). `aarch64` is the first non-x86 fixture
/// (freestanding ARM64 ELF) — validates the function-listing pipeline on AArch64.
const MANDATORY: &[&str] = &["freestanding", "basic", "aarch64"];

/// (name, binary path, mandatory?) — externals are user-provided, skipped if absent.
fn corpus() -> Vec<(&'static str, PathBuf, bool)> {
    let mut v: Vec<(&str, PathBuf, bool)> = MANDATORY
        .iter()
        .map(|n| (*n, analysis_corpus_dir().join(format!("{n}.elf")), true))
        .collect();
    v.push(("cnv", PathBuf::from("/home/jd/cnv.exe"), false)); // PE, user-provided
    v.push(("comcom32", PathBuf::from("/home/jd/.local/share/comcom32/comcom32.exe"), false)); // MZ
    v.push(("war2", PathBuf::from("/home/jd/WAR2.EXE"), false)); // MZ (DOS/4GW stub), user-provided
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
    let path = "/home/jd/cnv.exe";
    if !std::path::Path::new(path).exists() {
        eprintln!("skip: {path} absent");
        return;
    }
    let program = analysis::analyze_file(std::path::Path::new(path)).unwrap();
    assert!(program.function_manager.function_count() > 1000, "cnv should recover its functions");
    for r in program.reference_manager.references() {
        assert!(program.memory.contains(r.to), "cnv: reference to unmapped {:08x}", r.to.offset);
    }
    eprintln!("cnv: {} functions, analysis clean", program.function_manager.function_count());
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
    let cases: &[(&str, &str, usize)] = &[
        ("comcom32", "/home/jd/.local/share/comcom32/comcom32.exe", 0),
        ("war2", "/home/jd/WAR2.EXE", 8),
    ];
    let mut evaluated = 0;
    for &(name, path, max_misaligned) in cases {
        let golden_path = goldens.join(format!("{name}.snapshot"));
        if !std::path::Path::new(path).exists() || !golden_path.exists() {
            eprintln!("  skip {name}: binary or golden absent");
            continue;
        }
        let golden = snapshot::parse(&std::fs::read_to_string(&golden_path).unwrap());
        let snap = analysis::analyze_file(std::path::Path::new(path)).unwrap().snapshot();

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
    // freestanding 4/4 (exact) + basic 32/36 + aarch64 3/3 (exact) = 39. The remaining 4
    // (basic PLT) need loader-stage PLT disassembly with INDIRECTION typing — A6 indirect-flow
    // territory.
    assert!(recall.passed >= 39, "loader-reference recall regressed below 39");
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
    // freestanding 40/40 + basic 106/106 + aarch64 39/39 = 185 instructions, 0 misaligned.
    // basic reached 106/106 once the A6 PLT linear sweep (ElfDefaultGotPltMarkup.
    // processPLTSection) decodes the lazy-resolve stubs (PLT[0] + each entry's `push; jmp
    // PLT[0]` tail). aarch64 (freestanding ARM64) is exact — the SLEIGH engine lifts AArch64.
    assert!(recall.passed >= 185, "disassembly recall regressed below 185");
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
    let path = std::path::Path::new("/home/jd/WAR2.EXE");
    if !path.exists() {
        eprintln!("skip le_war2_objects: WAR2.EXE not present");
        return;
    }
    let data = std::fs::read(path).unwrap();
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
    // freestanding 3/3 + basic 15/16 + aarch64 3/3 = 21. basic reached 15 once A7's
    // SharedReturnAnalyzer recovered FUN_00401020 (PLT[0]) from the resolve-tail `jmp
    // 0x401020` crossing the printf@plt boundary. The remaining basic miss is
    // __gmon_start__@0x405010 (a weak external). aarch64 recovers all 3 of its functions.
    assert!(recall.passed >= 21, "function recall regressed below 21");
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
    // freestanding 3 + basic 15 + aarch64 3 = 21 bodies validated exactly (basic +1:
    // FUN_00401020 / PLT[0] recovered by the A7 SharedReturnAnalyzer, body 00401020:0040102b).
    assert!(validated >= 21, "function-body validation regressed below 21");
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
    // Ratchet: freestanding 4/4 + basic 32/33 + aarch64 7/7 = 43 recovered. A7 Task 1
    // (SharedReturn) added the `0x401020 → 0x403ff0 READ` inside PLT[0] (recovered once
    // FUN_00401020 exists) and retyped `0x40103b → 0x401020` to UNCONDITIONAL_CALL (type
    // validated in the a7_shared_return test). The remaining basic miss is `0x401004 →
    // 0x405010` (the __gmon_start__ weak-external code-ref — investigated in the A7 close-out).
    // aarch64's 7 exec-from code refs (2 jumps + 2 calls + the 3 ELF-header DATA refs) are
    // exact, with no spurious self-`bl` DATA ref (the inst_start PC-constant guard, symbolic.rs).
    assert!(recall.passed >= 43, "code-reference recall regressed below 43");
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
    // basic 99/99 + freestanding 3/3 + aarch64 3/3 = 105 — FULL data-unit parity on the ELF
    // corpus. .eh_frame_hdr/.eh_frame units + the ELF-loader markup: Elf64_Ehdr/Phdr/Sym/Rela/
    // Dyn, .gnu.hash/.gnu.version/.dynstr/.interp, the GNU notes (NoteGnuProperty/Element,
    // GnuBuildId, NoteAbiTag), the .init_array/.fini_array + GOT/.got.plt `pointer` units, and
    // the sized-OBJECT-symbol `undefined<size>` units (_IO_stdin_used, completed.0). aarch64
    // (freestanding ARM64): Elf64_Ehdr + Elf64_Phdr[3] + GnuBuildId — the arch-neutral markup.
    assert!(recall.passed >= 105, "data-unit recall regressed below 105");
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
