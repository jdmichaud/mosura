//! Ground-truth parity (task #3) — validate mosura's analysis against a self-compiled corpus
//! whose oracle is the KNOWN source/build, NOT Ghidra (which is often wrong).
//!
//! Covers the installed compiler×arch matrix (gcc x86-64/aarch64/riscv64/m68k, sdcc z80, Open
//! Watcom x86-32) × a program set (arith, dispatch, tables, strdata, fnptr, z80prog, watprog).
//! For each committed stripped binary + its build-derived `.truth` (the toolchain's own
//! `nm`/`objdump` for ELF, or sdcc's linker map + relocated listing for the raw z80 .COM —
//! `oracle/ground-truth/build.sh`), mosura's analysis of the *stripped* artifact must be a CLEAN
//! SUBSET of the real functions (0 spurious) with full recall of the call-reachable functions,
//! and every real switch dispatch must be recovered. The `.truth` files + stripped binaries are
//! committed, so this runs offline (no toolchain) — the toolchains are dev-oracle (regeneration
//! only), per `docs/dependencies.md`.

use std::collections::BTreeSet;

use mosura::analysis::{self, decompiler::decompile_function, program::RefType};
use mosura::decompile::printc::print_c;
use mosura::decompile::space::Address;
use mosura::paths::ground_truth_dir;

struct Truth {
    program: String,
    compiler: String,
    funcs: Vec<(u64, String)>, // (entry addr, name) — from the symbol table
    switches: Vec<u64>,        // indirect-jump dispatch addresses — from objdump
}

fn parse_truth(text: &str) -> Truth {
    let (mut program, mut compiler) = (String::new(), String::new());
    let (mut funcs, mut switches) = (Vec::new(), Vec::new());
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# mosura-ground-truth") {
            for tok in rest.split_whitespace() {
                if let Some(p) = tok.strip_prefix("program=") {
                    program = p.to_string();
                }
            }
        } else if let Some(c) = line.strip_prefix("compiler ") {
            compiler = c.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("func ") {
            let mut it = rest.split_whitespace();
            let addr = u64::from_str_radix(it.next().unwrap(), 16).unwrap();
            let _size = it.next();
            let name = it.next().unwrap_or("").to_string();
            funcs.push((addr, name));
        } else if let Some(rest) = line.strip_prefix("switch ") {
            switches.push(u64::from_str_radix(rest.trim(), 16).unwrap());
        }
    }
    Truth { program, compiler, funcs, switches }
}

#[test]
fn ground_truth_parity() {
    let dir = ground_truth_dir();
    if !dir.exists() {
        eprintln!("skip ground_truth_parity: {} absent", dir.display());
        return;
    }
    let mut truths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "truth"))
        .collect();
    truths.sort();

    let mut evaluated = 0;
    for truth_path in truths {
        let bin = truth_path.with_extension(""); // strip `.truth` → the stripped binary
        if !bin.exists() {
            eprintln!("  skip {}: stripped binary absent", truth_path.display());
            continue;
        }
        let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
        let prog = analysis::analyze_file(&bin).expect("analyze ground-truth binary");

        let truth_addrs: BTreeSet<u64> = truth.funcs.iter().map(|(a, _)| *a).collect();
        let mine: BTreeSet<u64> =
            prog.function_manager.functions().map(|f| f.entry_point().offset).collect();

        // (1) 0 spurious — every function mosura recovers is a real function in the ground truth.
        let spurious: Vec<_> = mine.difference(&truth_addrs).map(|a| format!("{a:08x}")).collect();
        assert!(
            spurious.is_empty(),
            "{}: mosura recovered functions absent from the ground truth: {spurious:?}",
            truth.program
        );

        // (2) Full recall of the call-reachable functions. gcc splits cold paths into `<fn>.cold`
        // symbols reached by a *jump*, not a *call*; on the stripped artifact, flow analysis
        // correctly folds those into the parent, so they are not expected as separate functions.
        let primary: BTreeSet<u64> =
            truth.funcs.iter().filter(|(_, n)| !n.ends_with(".cold")).map(|(a, _)| *a).collect();
        let missing: Vec<_> = primary.difference(&mine).map(|a| format!("{a:08x}")).collect();
        assert!(
            missing.is_empty(),
            "{}: mosura missed call-reachable functions: {missing:?}",
            truth.program
        );

        // (3) Every real switch dispatch is recovered (a COMPUTED_JUMP source, or at least a
        // disassembled BRANCHIND site).
        let cj_srcs: BTreeSet<u64> = prog
            .reference_manager
            .references()
            .filter(|r| r.ref_type == RefType::ComputedJump)
            .map(|r| r.from.offset)
            .collect();
        for &sw in &truth.switches {
            assert!(
                cj_srcs.contains(&sw) || prog.indirect_branches.contains(&sw),
                "{}: switch dispatch {sw:08x} not recovered",
                truth.program
            );
        }

        let cold = truth.funcs.len() - primary.len();
        eprintln!(
            "  [{}] funcs {}/{} recovered (0 spurious; {cold} .cold folded), {}/{} switch recovered, compiler(truth)={}, mosura(cspec)={}",
            truth.program,
            mine.len(),
            primary.len(),
            truth.switches.len(),
            truth.switches.len(),
            truth.compiler,
            prog.compiler_spec_id,
        );
        evaluated += 1;
    }
    assert!(evaluated > 0, "no ground-truth binaries evaluated (corpus missing?)");
    eprintln!("ground-truth parity: {evaluated} binary(ies) vs source-derived oracle (not Ghidra)");
}

/// Narrowed-switch jump-table recovery — the source-reduced repro of the unrecovered WAR2.EXE
/// protected-mode switch dispatches (`analysis_parity::le_war2_analysis`; sites 0x513a8 / 0x58afb
/// / 0x6af52 / 0x199b7). `narrowsw` (Open Watcom, `src/narrowsw.c`) is a differential pair Watcom
/// compiles to jump tables — the ONLY difference is the sub-`int` narrowing of the switch variable
/// between the guard and the table index. `sw_int` (`switch(int x)`) lowers to
/// `cmp EAX,7; ja; jmp [EAX*4+table]`; `sw_short` (`short x=..; switch(x)`) lowers to
/// `cmp AX,7; ja; movzx EAX,AX; jmp [EAX*4+table]`.
/// mosura's decompiler recovers `sw_int` but NOT `sw_short`; Ghidra's decompiler recovers BOTH
/// (confirmed on these exact bytes via the libdecomp `oracle/capture --c`). So `sw_short` is a
/// faithful-port GAP in the DECOMPILER lane (jumptable/JumpBasic: the narrow guard variable
/// `SUBPIECE(x,0)` is not tied to the widened table index `ZEXT`/`AND` of the same low bits) —
/// filed in `docs/decompiler-bug-narrow-switch.md`. This test PINS the differential: the control
/// stays recovered, and the gap is asserted as still-open so that closing it (the decompiler fix)
/// trips this test — the signal to update the handoff + flip the sentinel. Skipped if the corpus
/// binary is absent (regeneration-only toolchain).
#[test]
fn narrow_switch_recovery_gap() {
    let bin = ground_truth_dir().join("narrowsw.watcom-x86-32");
    if !bin.exists() {
        eprintln!("skip narrow_switch_recovery_gap: {} absent", bin.display());
        return;
    }
    let prog = analysis::analyze_file(&bin).expect("analyze narrowsw");
    // Dispatch sites from the build-derived truth (objdump `jmp *`): sw_int @ 0x804812b,
    // sw_short @ 0x8048193; both are disassembled BRANCHIND candidates.
    let (sw_int_disp, sw_short_disp) = (0x0804812bu64, 0x08048193u64);
    assert!(prog.indirect_branches.contains(&sw_int_disp), "sw_int BRANCHIND disassembled");
    assert!(prog.indirect_branches.contains(&sw_short_disp), "sw_short BRANCHIND disassembled");

    let cj_targets = |disp: u64| -> BTreeSet<u64> {
        prog.reference_manager
            .references()
            .filter(|r| r.ref_type == RefType::ComputedJump && r.from.offset == disp)
            .map(|r| r.to.offset)
            .collect()
    };

    // CONTROL: the 32-bit-variable switch is fully recovered — 8 COMPUTED_JUMP case targets.
    // (Regression gate: mosura must keep recovering the plain dense switch.)
    assert_eq!(
        cj_targets(sw_int_disp).len(),
        8,
        "sw_int (32-bit switch) must recover its 8-case jump table"
    );

    // GAP CLOSED: the narrowed (16-bit) switch now recovers its 8 case targets too, matching
    // Ghidra. The fix was the faithful `Heritage::guardReturns` port (heritage.cc:1652), and
    // specifically the RETIREMENT of the hardcoded x86-64 `RAX:8` return candidate that
    // `recover_return` used to append to every RETURN pre-heritage. On x86-32 that 8-byte read at
    // register offset 0 spans EAX *and* ECX — a range no instruction ever writes. It forced a
    // spurious 8-byte heritage location whose batch read-normalization rewrote the narrow accesses
    // to EAX, severing the guard's `SUBPIECE(x,0)` from the table index's `INT_AND`/`INT_ZEXT` of
    // the same low bits, which is exactly what `JumpBasic` needs to bound the table. Verified
    // causally: re-adding that one 8-byte read on top of the port reopens the gap.
    assert_eq!(
        cj_targets(sw_short_disp).len(),
        8,
        "sw_short (narrowed 16-bit switch) must recover its 8-case jump table"
    );
    eprintln!("narrow-switch: sw_int and sw_short both recover 8 targets (gap closed)");
}

/// WAR2 `Merge::trimOpInput` INDIRECT-panic regression — the source-reduced repro of the survey's
/// DECOMPILE_FAIL class (all 117 WAR2 panics were this one bug: `merge.rs:1205` index-out-of-bounds,
/// docs/decompiler-bug-merge-indirect-trim-panic.md, fixed in `b6ec467`). `war2gates` (Open Watcom,
/// `src/war2gates.c`) mimics WAR2 `FUN_00011954`: `trim_shape` is three sequential register-arg
/// calls in one block with two global stores, whose chained call-guard INDIRECTs force merge-marker's
/// non-MULTIEQUAL trim. Pre-fix mosura (`ef65486`) panics on exactly this compiled shape; the fixed
/// pipeline decompiles it. This is the ground-truth (self-compiled Watcom, NOT Ghidra) gate for the
/// panic, per `war2-issues-become-source-tests`. Skipped if the corpus binary is absent
/// (regeneration-only toolchain).
#[test]
fn war2_trim_shape_no_panic() {
    let bin = ground_truth_dir().join("war2gates.watcom-x86-32");
    let truth_path = ground_truth_dir().join("war2gates.watcom-x86-32.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip war2_trim_shape_no_panic: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let trim_shape = truth
        .funcs
        .iter()
        .find(|(_, n)| n == "trim_shape_")
        .map(|(a, _)| *a)
        .expect("truth lists trim_shape_");

    let prog = analysis::analyze_file(&bin).expect("analyze war2gates");
    // decompile_function catches a pipeline panic and returns None (the A6 bridge's isolation,
    // faithful to Ghidra's DecompilerSwitchAnalyzer). Pre-fix this function panicked at
    // merge.rs:1205 (trimOpInput indexing in_edges[slot] for an INDIRECT in the entry block) → None;
    // the fix ports Ghidra's non-MULTIEQUAL branch and it decompiles → Some.
    let f = decompile_function(&prog, Address::new(prog.default_space, trim_shape));
    assert!(
        f.is_some(),
        "trim_shape (WAR2 FUN_00011954 repro @ {trim_shape:#x}) must decompile without panicking \
         — the merge.rs:1205 trimOpInput regression is back"
    );
    eprintln!("war2 trim-panic gate: trim_shape @ {trim_shape:#x} decompiles cleanly (pre-fix: merge.rs:1205 OOB)");
}

/// WAR2 for-loop raw-marker leak regression — the source-reduced repro of the E1063 class the
/// survey exposed (e.g. FUN_0002bd14): a `for`-loop whose induction variable's entry value comes
/// from a PHI (an earlier loop modified it), not from a def in the pre-loop block. mosura's
/// for-recovery lacked Ghidra's `BlockWhileDo::findInitializer` (block.cc:3223) checks (a written
/// initializer's def must be a NON-MARKER op in the pre-loop block that flows only to the loop), so
/// it emitted the phi raw as the for-init — `for (n = MULTIEQUAL(...); ...)`, which wcc386/gcc
/// reject. `forphi` (Open Watcom, `src/forphi.c`) `scan` reproduces the shape; pre-fix it leaks
/// `MULTIEQUAL(...)`, the fix renders `for (; cond; iter)`. Ground-truth (self-compiled, NOT
/// Ghidra) gate, per `war2-issues-become-source-tests`. Skipped if the corpus binary is absent.
#[test]
fn war2_forphi_no_marker_leak() {
    let bin = ground_truth_dir().join("forphi.watcom-x86-32");
    let truth_path = ground_truth_dir().join("forphi.watcom-x86-32.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip war2_forphi_no_marker_leak: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let scan = truth
        .funcs
        .iter()
        .find(|(_, n)| n == "scan_")
        .map(|(a, _)| *a)
        .expect("truth lists scan_");
    let prog = analysis::analyze_file(&bin).expect("analyze forphi");
    let f = decompile_function(&prog, Address::new(prog.default_space, scan)).expect("scan_ decompiles");
    let c = print_c(&f);
    assert!(
        !c.contains("MULTIEQUAL(") && !c.contains("INDIRECT("),
        "raw SSA marker leaked into C (findInitializer regression) — scan_ @ {scan:#x}:\n{c}"
    );
    eprintln!("war2 forphi gate: scan_ renders its for-loop without a raw phi/marker init");
}

/// A while-condition that carries a STATEMENT must print inside the parentheses, not above the
/// loop. Ghidra's `PrintC::emitBlockWhileDo` non-overflow arm sets `comma_separate` around
/// `condBlock->emit(this)` (printc.cc:3046-3054), so the condition block's statements join with
/// `, ` inside the parens and re-execute every iteration. Hoisting them above the `while` runs
/// them once: in `loopcomma`'s list walk that is a use-before-def and a test that can never
/// change — wrong code, not formatting. `walk` (Open Watcom, `src/loopcomma.c`) is the shape.
#[test]
fn loop_comma_condition_inline() {
    let bin = ground_truth_dir().join("loopcomma.watcom-x86-32");
    let truth_path = ground_truth_dir().join("loopcomma.watcom-x86-32.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip loop_comma_condition_inline: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let walk = truth
        .funcs
        .iter()
        .find(|(_, n)| n == "walk_")
        .map(|(a, _)| *a)
        .expect("truth lists walk_");
    let prog = analysis::analyze_file(&bin).expect("analyze loopcomma");
    let f = decompile_function(&prog, Address::new(prog.default_space, walk))
        .expect("walk_ decompiles");
    let c = print_c(&f);

    // The loop-test load must be part of the condition. Locate the `while (` header and require
    // the assignment to sit inside its parentheses.
    let header = c
        .lines()
        .find(|l| l.trim_start().starts_with("while ("))
        .unwrap_or_else(|| panic!("walk_ recovered no while-loop — structuring regression:\n{c}"));
    assert!(
        header.contains('=') && header.contains(','),
        "while-condition statement was HOISTED above the loop (comma_separate regression): the \
         header carries no assignment, so the loop test cannot update — walk_ @ {walk:#x}\n\
         header: {header}\n{c}"
    );
    eprintln!("loopcomma gate: walk_ prints its condition statement inside the parens — {header}");
}
