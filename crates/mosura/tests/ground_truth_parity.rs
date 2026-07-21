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

use mosura::analysis::{self, program::RefType};
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
