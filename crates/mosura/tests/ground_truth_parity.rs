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
use mosura::analysis::overrides;
use mosura::decompile::printc::print_c;
use mosura::decompile::space::Address;
use mosura::paths::ground_truth_dir;

struct Truth {
    program: String,
    compiler: String,
    funcs: Vec<(u64, String)>, // (entry addr, name) — from the symbol table
    /// `(entry, size)` for every function the truth gives a size for (gcc's `nm -S`; Watcom
    /// emits none, so those are 0 and contribute no extent).
    sizes: Vec<(u64, u64)>,
    /// Entries of [`Truth::funcs`] whose reachability class is `dataptr`: the build step found
    /// the address NOWHERE in the disassembly of an executable section, and DID find it stored
    /// as a pointer-sized word in a data section. They are reachable only through a function
    /// pointer in data — see [`data_pointer_function_discovery`] and `build.sh`'s
    /// `derive_truth_elf`. A `.truth` generated before that field existed lists none, which
    /// leaves it exactly as it was.
    data_pointer_only: BTreeSet<u64>,
    switches: Vec<u64>, // indirect-jump dispatch addresses — from objdump
}

fn parse_truth(text: &str) -> Truth {
    let (mut program, mut compiler) = (String::new(), String::new());
    let (mut funcs, mut switches) = (Vec::new(), Vec::new());
    let mut sizes: Vec<(u64, u64)> = Vec::new();
    let mut data_pointer_only = BTreeSet::new();
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
            let size = it.next().and_then(|s| u64::from_str_radix(s, 16).ok()).unwrap_or(0);
            if size > 0 {
                sizes.push((addr, size));
            }
            let name = it.next().unwrap_or("").to_string();
            if it.next() == Some("dataptr") {
                data_pointer_only.insert(addr);
            }
            funcs.push((addr, name));
        } else if let Some(rest) = line.strip_prefix("switch ") {
            switches.push(u64::from_str_radix(rest.trim(), 16).unwrap());
        }
    }
    Truth { program, compiler, funcs, sizes, data_pointer_only, switches }
}

/// The four Function Start Search analyzers, by the names the manager registers them under.
const BYTE_PATTERN_ANALYZERS: &str = "Function Start Pre Search,Function Start Search,\
Function Start Search After Code,Function Start Search After Data";

/// Filter the spurious set down to entries the byte-pattern search does NOT explain.
///
/// Ghidra's **Function Start Search** recognises a function by its prologue bytes, with no
/// inbound reference required. That power costs entries the build truth does not list, and the
/// two classes below were each measured against Ghidra itself (`analyzeHeadless`, with and
/// without the search, via a `-preScript` that clears its `ANALYSIS_PROPERTIES` option — the same
/// switch `MOSURA_DISABLE_ANALYZERS` provides here):
///
/// 1. **Inter-function padding.** `floats.gcc-aarch64` 0x40015c and `dispatch.gcc-aarch64`
///    0x40019c sit in the alignment padding between two functions, inside neither. Ghidra creates
///    both (5 functions with the search on, 4 with it off). Identical behaviour, not a defect.
///
/// 2. **Inside a function that has an unrecovered computed dispatch.** On `compgoto.gcc-m68k`
///    Ghidra itself splits `cgoto` into four (2 functions with the search off, 5 with it on —
///    0x800000cc/d8/e2, which it names `caseD_2/1/0`). On `dispatch.gcc-m68k` and
///    `tables.gcc-m68k` Ghidra's set is UNCHANGED by the search while mosura gains 3 and 8: there
///    the cause is upstream of this analyzer — mosura does not recover those m68k jump tables, so
///    the case bodies are never disassembled, and a pattern that Ghidra refuses (the bytes are
///    already instructions inside a function) mosura accepts (the bytes are undefined). Closing
///    that needs m68k jump-table recovery, not a change here.
///
/// The carve-out is deliberately narrow in three ways: it applies **only** to addresses that
/// disappear when the byte-pattern analyzers are switched off (so it can never excuse a
/// regression from any other pass), only within the two classes above, and only when the truth
/// file supplies function sizes (gcc's `nm -S`; the Watcom column has none, so nothing there can
/// be excused). The second run is skipped entirely when nothing is spurious.
fn byte_pattern_carve_out(
    bin: &std::path::Path,
    truth: &Truth,
    spurious: &BTreeSet<u64>,
) -> BTreeSet<u64> {
    if spurious.is_empty() {
        return BTreeSet::new();
    }
    // Which of these does the byte-pattern search account for? Re-analyze with it off.
    let without: BTreeSet<u64> = {
        // Per-thread, NOT `std::env` — see `analysis::overrides`. Mutating the process
        // environment here leaked into whatever another test was analysing in parallel.
        let _guard = overrides::disable_analyzers(BYTE_PATTERN_ANALYZERS);
        let p = if bin.extension().is_some_and(|x| x == "watcom-le") {
            analysis::analyze_le_file(bin).expect("analyze")
        } else {
            analysis::analyze_file(bin).expect("analyze")
        };
        p.function_manager.functions().map(|f| f.entry_point().offset).collect()
    };

    let switch_owner = |a: u64| -> Option<(u64, u64)> {
        truth.sizes.iter().copied().find(|(e, sz)| *e <= a && a < e + sz)
    };
    spurious
        .iter()
        .copied()
        .filter(|&a| {
            if without.contains(&a) {
                return true; // not the byte-pattern search's doing at all
            }
            match switch_owner(a) {
                // (1) in no function's extent — inter-function padding.
                None => false,
                // (2) inside a function that carries an unrecovered computed dispatch.
                Some((e, sz)) => !truth.switches.iter().any(|s| (e..e + sz).contains(s)),
            }
        })
        .collect()
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
        if bin.file_name().is_some_and(|n| n == "noret.gcc-x86-64") {
            eprintln!("  skip noret: gated by noreturn_call_bounds_the_body (dynamic ELF, PLT)");
            continue;
        }
        // `nfprologue`'s three functions are UNREFERENCED — nothing calls them and their addresses
        // are stored nowhere — so the only route to them is a prologue byte pattern, and the shape
        // they carry is deliberately NOT covered (see specs/patterns/x86watcom_patterns.xml family
        // (6): it was written, measured on WAR2 at a 26% terminator rate against a ~99.8% baseline,
        // and backed out). This loop's recall assertion demands "call-reachable" functions, which
        // these are not — the truth classifier calls them `code` only because it has two classes
        // and they are not `dataptr`. Skipped here and gated by
        // `no_frame_prologue_shape_is_uncovered`, exactly as `noret` is gated by its own test.
        //
        // ⚠️ NOT a general licence: this is the only fixture whose functions are unreachable BY
        // DESIGN. Do not extend the skip to a fixture that merely fails — that is the difference
        // between recording a known gap and hiding a regression.
        if bin.file_name().is_some_and(|n| n == "nfprologue.watcom-x86-32") {
            eprintln!("  skip nfprologue: gated by no_frame_prologue_shape_is_uncovered (uncovered shape)");
            continue;
        }
        let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
        // The `.watcom-le` column is a bound MZ+LE (DOS-extender) executable. `analyze_file`
        // dispatches a bound exe down the Ghidra-parity MZ-stub path, which is the right default
        // (Ghidra has no LE loader); the LE objects are reached through `analyze_le_file`.
        // Route by the truth file's `compiler` field, which `build.sh` writes from the recipe
        // that produced the binary. Detection cannot answer this for a freestanding image — the
        // corpus links `option nodefaultlib`, so no Watcom run-time banner exists to find and
        // `compiler_spec_id` correctly says `gcc`. Declaring the build's own answer is what
        // retired the by-name skips this loop used to need for `wprologue_sf` and `wprobe`.
        let declared = (truth.compiler == "watcom" && bin.extension().is_some_and(|x| x == "watcom-x86-32"))
            .then_some("watcom");
        let prog = if bin.extension().is_some_and(|x| x == "watcom-le") {
            analysis::analyze_le_file(&bin).expect("analyze LE ground-truth binary")
        } else {
            analysis::analyze_file_as(&bin, declared).expect("analyze ground-truth binary")
        };

        let truth_addrs: BTreeSet<u64> = truth.funcs.iter().map(|(a, _)| *a).collect();
        let mine: BTreeSet<u64> =
            prog.function_manager.functions().map(|f| f.entry_point().offset).collect();

        // (1) 0 spurious — every function mosura recovers is a real function in the ground truth,
        // except for the one class described by `byte_pattern_carve_out`.
        let spurious: BTreeSet<u64> = mine.difference(&truth_addrs).copied().collect();
        let unexplained = byte_pattern_carve_out(&bin, &truth, &spurious);
        let unexplained: Vec<_> = unexplained.iter().map(|a| format!("{a:08x}")).collect();
        assert!(
            unexplained.is_empty(),
            "{}: mosura recovered functions absent from the ground truth: {unexplained:?}",
            truth.program
        );

        // (2) Full recall of the **call-reachable** functions — which is what this assertion has
        // always covered, and the two classes below fall outside it by construction, not by
        // exception. Both are derived from the build artifact, never named here:
        //
        //  - `<fn>.cold` — gcc splits cold paths into these and reaches them by a *jump*, not a
        //    *call*; on the stripped artifact flow analysis correctly folds them into the parent.
        //  - reachability class `dataptr` (`build.sh`'s `derive_truth_elf`) — the address appears
        //    nowhere in the disassembly of an executable section and does appear as a stored
        //    pointer in data. There is no call to reach it by. Ghidra, given the same binary,
        //    deliberately creates no function at such a target either: `AddressTableAnalyzer`
        //    :281,294 ("For Now, Never make functions from address tables"),
        //    `OperandReferenceAnalyzer.createFunctions` :617 ("don't ever create functions from
        //    pointed to code"), `DataOperandReferenceAnalyzer.createFunctions` :39 ("don't ever
        //    create a function from a data pointer") — all three are no-op bodies. Verified on
        //    `datafnptr`: Ghidra ends with six functions and none is a pointer-table target.
        //    Demanding them here would require mosura to invent functions Ghidra does not, which
        //    is exactly what `analysis_parity`'s "0 spurious vs Ghidra" gate forbids.
        //
        // The properties a `dataptr` symbol DOES carry — its code is disassembled, and whatever
        // that code calls becomes a function — are asserted by `data_pointer_function_discovery`.
        let primary: BTreeSet<u64> = truth
            .funcs
            .iter()
            .filter(|(a, n)| !n.ends_with(".cold") && !truth.data_pointer_only.contains(a))
            .map(|(a, _)| *a)
            .collect();
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

        let cold = truth.funcs.iter().filter(|(_, n)| n.ends_with(".cold")).count();
        let dataptr = truth.data_pointer_only.len();
        eprintln!(
            "  [{}] funcs {}/{} recovered (0 spurious; {cold} .cold folded, {dataptr} data-pointer-only), {}/{} switch recovered, compiler(truth)={}, mosura(cspec)={}",
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

/// Shared-return TAIL-CALL function discovery — the source-reduced repro of the WAR2 auto-analysis
/// gap (`war2-survey/analysis-gap/REPORT.md`): a function reachable ONLY by an unconditional `jmp`
/// is never created, and its whole call sub-tree is lost with it. `tailjmp` (Open Watcom,
/// `src/tailjmp.c` + `src/tailjmp_cstart.asm`, built WITHOUT `-oc` so the `call X; ret` -> `jmp X`
/// rewrite survives) carries both arms of Ghidra `SharedReturnAnalysisCmd.applyTo`'s
/// `assumeContiguousFunctions` rule: `tail_lo_` reached by a BACKWARD jump past its caller's own
/// entry (WAR2 0x69032->0x67f40, 0x77dc1->0x72301, 0x7a66b->0x79330), and `fwd_landing_` reached by
/// a FORWARD jump over `gap_fn_`'s entry (WAR2 0x601f8->0x60270).
///
/// Pre-fix (`b9d8466`) mosura missed BOTH — `ground_truth_parity` reported
/// `tailjmp: mosura missed call-reachable functions: ["0804810f", "08048116"]`. The cause was an
/// invented gate in `SharedReturnAnalyzer::could_have_fall_thru_to` ("a location inside an existing
/// function's body must have a fall-through predecessor"), which has no counterpart in Ghidra and
/// vetoes every tail-call destination, since flow follows the `jmp` and the destination therefore
/// always lands inside the JUMPING function's body.
///
/// The recall half is already covered by `ground_truth_parity`; this test pins the MECHANISM —
/// that the destinations came from the shared-return rule, i.e. that the jump was also given
/// Ghidra's `FlowOverride.CALL_RETURN` and so its reference reads `UNCONDITIONAL_CALL`. Without
/// that retype the functions could only have appeared by some non-Ghidra route.
#[test]
fn tail_jump_shared_return() {
    let bin = ground_truth_dir().join("tailjmp.watcom-x86-32");
    let truth_path = ground_truth_dir().join("tailjmp.watcom-x86-32.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip tail_jump_shared_return: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let entry_of = |name: &str| -> u64 {
        truth
            .funcs
            .iter()
            .find(|(_, n)| n == name)
            .map(|(a, _)| *a)
            .unwrap_or_else(|| panic!("truth lists {name}"))
    };
    let prog = analysis::analyze_file(&bin).expect("analyze tailjmp");
    let ram = prog.default_space;

    for (name, arm) in [("tail_lo_", "backward"), ("fwd_landing_", "forward")] {
        let entry = entry_of(name);
        assert!(
            prog.function_manager.function_at(Address::new(ram, entry)).is_some(),
            "{name} @ {entry:#x} ({arm} tail-call arm) must be recovered — it is reachable ONLY by \
             the shared-return `jmp` (SharedReturnAnalysisCmd assumeContiguousFunctions)"
        );
        // Every inbound reference is the tail-call jump, and each must carry the CALL_RETURN
        // override's reference type (RefType.CALL_TERMINATOR flow -> UNCONDITIONAL_CALL reference).
        let inbound: Vec<(u64, &'static str)> = prog
            .reference_manager
            .refs_to(Address::new(ram, entry))
            .map(|r| (r.from.offset, r.ref_type.name()))
            .collect();
        assert!(!inbound.is_empty(), "{name}: no inbound reference at all");
        assert!(
            inbound.iter().all(|(_, t)| *t == "UNCONDITIONAL_CALL"),
            "{name} @ {entry:#x}: the tail-call jump must be retyped by FlowOverride.CALL_RETURN \
             (UNCONDITIONAL_CALL), got {inbound:x?}"
        );
    }
    eprintln!(
        "tailjmp gate: tail_lo_ (backward) + fwd_landing_ (forward) recovered as shared-return \
         tail calls, both inbound jumps retyped UNCONDITIONAL_CALL"
    );
}

/// DATA-POINTER function discovery — the source-reduced repro of the second WAR2 auto-analysis
/// gap (`war2-survey/analysis-gap/REPORT.md` §7): code reachable ONLY through a function pointer
/// stored in data is never disassembled, so neither it nor anything it calls ever becomes a
/// function. On WAR2 that is 24.7% of the code object — 109,338 bytes in 23 regions >2KB whose
/// only inbound edges from outside are `DATA` references, and 783 of 815 missing functions with
/// no reference in mosura's reference set at all.
///
/// `datafnptr` (Open Watcom, `src/datafnptr.c` + `src/datafnptr_cstart.asm`) has two arms:
/// ARM A a RUN of four function pointers in writable `.data` (`g_table`, dispatched
/// `call [edx*4+g_table]` with an index constant propagation cannot resolve), ARM B a LONE
/// pointer (`g_solo`, `call [g_solo]`). Nothing calls any target directly.
///
/// PRE-FIX (`8a13977`) `ground_truth_parity` reported
/// `datafnptr: mosura missed call-reachable functions: ["08048106", "08048110", "0804811d",
/// "08048127", "0804812e"]` — the four table targets plus `deep_helper`, the helper that only
/// `tab_h0` calls. ARM B was ALREADY green (mosura's ConstantPropagationAnalyzer reads the lone
/// pointer and emits a COMPUTED_CALL), which is what isolates the gap to the indexed table.
///
/// The fix is the faithful port of Ghidra `AddressTableAnalyzer` + `AddressTable` +
/// `PseudoDisassembler.isValidCode`. This test pins the MECHANISM, in both directions:
///  1. the four table targets are DISASSEMBLED and carry a `DATA` reference from their slot;
///  2. `deep_helper` becomes a function — the CASCADE, i.e. the direct-call discovery that runs
///     inside the newly decoded code (Ghidra `FunctionAnalyzer`, "Subroutine References");
///  3. NO function is created at any table target — Ghidra creates none either, and inventing
///     them is precisely the false-positive failure mode a data-driven analyzer has.
#[test]
fn data_pointer_function_discovery() {
    use mosura::analysis::program::CodeUnit;
    let bin = ground_truth_dir().join("datafnptr.watcom-x86-32");
    let truth_path = ground_truth_dir().join("datafnptr.watcom-x86-32.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip data_pointer_function_discovery: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let entry_of = |name: &str| -> u64 {
        truth
            .funcs
            .iter()
            .find(|(_, n)| n == name)
            .map(|(a, _)| *a)
            .unwrap_or_else(|| panic!("truth lists {name}"))
    };
    // (0) The build step's own reachability derivation must agree with the shape this test
    // assumes. `derive_truth_elf` marks a symbol `dataptr` when its address appears nowhere in
    // the disassembly of an executable section and does appear as a stored pointer in data —
    // i.e. exactly "no call can reach it". If a compiler change ever gives one of these a code
    // reference, the program has stopped reproducing the defect and this test must be revisited
    // rather than silently passing. `deep_helper_` is deliberately NOT in this set: it is
    // `code`-reachable (from `tab_h0`), so the generic recall assertion still demands it, which
    // is what makes the cascade a hard gate.
    let dataptr_names: BTreeSet<&str> = truth
        .funcs
        .iter()
        .filter(|(a, _)| truth.data_pointer_only.contains(a))
        .map(|(_, n)| n.as_str())
        .collect();
    assert_eq!(
        dataptr_names,
        ["tab_h0_", "tab_h1_", "tab_h2_", "tab_h3_", "solo_target_"].into_iter().collect(),
        "datafnptr no longer has exactly the five data-pointer-only symbols this test is about"
    );

    let prog = analysis::analyze_file(&bin).expect("analyze datafnptr");
    let ram = prog.default_space;
    let at = |o: u64| Address::new(ram, o);

    // (1) ARM A — every address-table target is disassembled, and reached by a DATA reference
    // out of the pointer slot that holds it (the reference `AddressTable.makeTable` creates).
    for name in ["tab_h0_", "tab_h1_", "tab_h2_", "tab_h3_"] {
        let target = entry_of(name);
        assert!(
            matches!(prog.listing.code_unit_at(at(target)), Some(CodeUnit::Instruction { .. })),
            "{name} @ {target:#x} was never disassembled — it is reachable ONLY through the \
             function-pointer table in .data (Ghidra AddressTableAnalyzer)"
        );
        let inbound: Vec<(u64, &'static str)> =
            prog.reference_manager.refs_to(at(target)).map(|r| (r.from.offset, r.ref_type.name())).collect();
        assert!(
            inbound.iter().any(|(_, k)| *k == "DATA"),
            "{name} @ {target:#x}: no DATA reference from its table slot, got {inbound:x?}"
        );
        // (3) …and NO function was created at it — matching Ghidra exactly.
        assert!(
            prog.function_manager.function_at(at(target)).is_none(),
            "{name} @ {target:#x}: a function was created at an address-table target. Ghidra \
             never does (AddressTableAnalyzer.processAddressTable:282-296) — this is the \
             false-positive failure mode that breaks analysis_parity's 0-spurious gate"
        );
    }

    // (2) THE CASCADE — `deep_helper` is called only from `tab_h0`, i.e. only from inside the
    // data-reachable subgraph. It must come back as a function, by the ordinary direct-call
    // route, now that the code calling it is decoded.
    let deep = entry_of("deep_helper_");
    assert!(
        prog.function_manager.function_at(at(deep)).is_some(),
        "deep_helper @ {deep:#x} must be recovered: it is called ONLY from tab_h0, which is \
         itself reachable only through the data pointer table. This is the WAR2 shape — 1547 \
         UNCONDITIONAL_CALL references into functions mosura never decoded"
    );
    let callers: Vec<u64> = prog
        .reference_manager
        .refs_to(at(deep))
        .filter(|r| r.ref_type.name() == "UNCONDITIONAL_CALL")
        .map(|r| r.from.offset)
        .collect();
    assert!(
        !callers.is_empty(),
        "deep_helper @ {deep:#x}: recovered, but with no inbound direct call — it can only have \
         arrived by some route other than decoding tab_h0"
    );

    // ARM B — the CONTROL. A lone pointer (no run, so no address table) is resolved by the
    // constant propagator, and was already green before this port; asserted so the two arms
    // stay distinguishable if either mechanism regresses.
    let solo = entry_of("solo_target_");
    assert!(
        prog.function_manager.function_at(at(solo)).is_some(),
        "solo_target @ {solo:#x} (ARM B, lone data pointer) must stay recovered via the \
         constant propagator's COMPUTED_CALL"
    );

    eprintln!(
        "datafnptr gate: 4 address-table targets disassembled (0 functions created at them), \
         deep_helper @ {deep:#x} recovered by cascade, solo_target @ {solo:#x} by constant \
         propagation"
    );
}

/// DATA-POINTER seeding from the LOADER'S RELOCATION RECORDS — the LE-format gate for the
/// beyond-Ghidra `RelocationSeedAnalyzer`.
///
/// `lestruct.watcom-le` (Open Watcom, `wlink format os2 le`) stores each function pointer ALONE,
/// inside a `struct node { int tag; handler fn; }`, so three mechanisms are closed at once and
/// only the linker's fixup table can find the targets: no two pointer-sized words are ever
/// adjacent (no run for `AddressTable.getEntry` to accumulate), the tags are below
/// `MINIMUM_SAFE_ADDRESS`, and `g_nodes[i & 3].fn(x)` is opaque to constant propagation. It is
/// the ONLY Linear Executable in the corpus, and the only fixture carrying relocation records.
///
/// PRE-FIX (`3002257`) mosura recovered only `[_cstart_, run_, main_]` with 17 code units and
/// `0x10006..0x1002d` — `deep_le`, `h0`, `h1`, `h2` — entirely undisassembled.
///
/// NOTE the obvious version of this MVE does NOT work: `datafnptr` rebuilt as an LE passes
/// unfixed, because the address-table analyzer handles a pointer RUN in LE memory exactly as it
/// does in ELF. That negative result is why `lestruct.c` exists and why it looks the way it does.
///
/// The assertions mirror `data_pointer_function_discovery`: the pointed-to code is DISASSEMBLED,
/// no function is created at any of it (Ghidra's discipline for every data-derived address), and
/// the helper reachable only from inside that code IS created by cascade.
#[test]
fn data_pointer_le_seeding() {
    use mosura::analysis::program::CodeUnit;
    let bin = ground_truth_dir().join("lestruct.watcom-le");
    let truth_path = ground_truth_dir().join("lestruct.watcom-le.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip data_pointer_le_seeding: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let entry_of = |name: &str| -> u64 {
        truth.funcs.iter().find(|(_, n)| n == name).map(|(a, _)| *a).expect("truth lists the symbol")
    };

    // The build step's own reachability derivation must still describe the shape this test is
    // about — see `derive_truth_elf`'s LE sibling in build.sh, whose two documented limitations
    // this assertion is what pins.
    let dataptr: BTreeSet<&str> = truth
        .funcs
        .iter()
        .filter(|(a, _)| truth.data_pointer_only.contains(a))
        .map(|(_, n)| n.as_str())
        .collect();
    assert_eq!(
        dataptr,
        ["h0_", "h1_", "h2_"].into_iter().collect(),
        "lestruct no longer has exactly the three data-pointer-only symbols this test is about"
    );

    let prog = analysis::analyze_le_file(&bin).expect("analyze lestruct.watcom-le");
    let ram = prog.default_space;
    let at = |o: u64| Address::new(ram, o);

    for name in ["h0_", "h1_", "h2_"] {
        let t = entry_of(name);
        assert!(
            matches!(prog.listing.code_unit_at(at(t)), Some(CodeUnit::Instruction { .. })),
            "{name} @ {t:#x} was never disassembled — it is stored as an ISOLATED pointer inside a \
             struct, so no pointer-run heuristic can reach it and only the LE fixup table names it"
        );
        assert!(
            prog.function_manager.function_at(at(t)).is_none(),
            "{name} @ {t:#x}: a function was created at a data-pointer target — Ghidra never does \
             (AddressTableAnalyzer.java:281,294) and neither may we"
        );
    }

    let deep = entry_of("deep_le_");
    assert!(
        prog.function_manager.function_at(at(deep)).is_some(),
        "deep_le @ {deep:#x} must be recovered: it is called ONLY from h0, which is itself \
         reachable only through a stored pointer. This is the cascade the whole mechanism is for"
    );
    eprintln!(
        "lestruct gate: 3 isolated data pointers disassembled (0 functions created at them), \
         deep_le @ {deep:#x} recovered by cascade"
    );
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

/// The same rule on the OTHER emitter: a FOR-header whose condition block carries a STATEMENT must
/// print it between the two semicolons, not above the loop. `PrintC::emitForLoop` (printc.cc:2974)
/// sets the same `comma_separate` mod around `condBlock->emit(this)` that `emitBlockWhileDo`'s
/// non-overflow arm sets (printc.cc:3046-3054), and for the same reason — the statement re-executes
/// every iteration. `loopcomma` deliberately keeps its walked pointer GLOBAL so it stays a WhileDo;
/// `forcomma` makes it a LOCAL so a `for` is recovered and this emitter is reached. Hoisting here
/// loads the node key once and then copies that one value forever while the pointer walks away
/// from it — wrong code, not formatting. `walk` (Open Watcom, `src/forcomma.c`) is the shape.
#[test]
fn for_comma_condition_inline() {
    let bin = ground_truth_dir().join("forcomma.watcom-x86-32");
    let truth_path = ground_truth_dir().join("forcomma.watcom-x86-32.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip for_comma_condition_inline: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let walk = truth
        .funcs
        .iter()
        .find(|(_, n)| n == "walk_")
        .map(|(a, _)| *a)
        .expect("truth lists walk_");
    let prog = analysis::analyze_file(&bin).expect("analyze forcomma");
    let f = decompile_function(&prog, Address::new(prog.default_space, walk))
        .expect("walk_ decompiles");
    let c = print_c(&f);

    // The loop MUST come back as a `for` — with a `while` this program would be re-testing the
    // already-fixed `emitBlockWhileDo` and the gate would pass vacuously (forcomma.c property 4).
    let header = c
        .lines()
        .find(|l| l.trim_start().starts_with("for ("))
        .unwrap_or_else(|| {
            panic!("walk_ recovered no for-loop — this gate tests emitForLoop and cannot run:\n{c}")
        });
    // The condition is the middle of the three clauses; the loaded value must be assigned there.
    let cond = header
        .split(';')
        .nth(1)
        .unwrap_or_else(|| panic!("for-header has no condition clause:\n{header}"));
    assert!(
        cond.contains('=') && cond.contains(','),
        "for-condition statement was HOISTED above the loop (emitForLoop comma_separate gap): the \
         condition clause carries no assignment, so the loop test cannot update — walk_ @ \
         {walk:#x}\nheader: {header}\n{c}"
    );
    eprintln!("forcomma gate: walk_ prints its condition statement inside the for-header — {header}");
}

/// For-recovery must not give up on the FIRST loop-head phi it finds. Ghidra's
/// `BlockWhileDo::findLoopVariable` (block.cc:3164) `continue`s past a head MULTIEQUAL whose
/// tail-slot input is a marker / not in the tail / not moveable, and keeps walking; mosura's
/// `find_loop_phi` returned the first one and `for_parts` validated only that. A loop whose BOUND
/// is a global the body modifies puts a wrong candidate first on the walk — the bound is
/// heritaged, gets a head phi, and the LIFO operand walk reaches it before the register induction
/// variable. Instrumenting the WAR2 specimens showed the selected phi was `space="ram"` (the
/// bound) in all 7. `cbound_walk` (Open Watcom, `src/loopphi.c`) is the shape; its call is
/// deliberately DIRECT so the separate indirect-call clobber defect cannot also decline the loop.
#[test]
fn for_recovery_backtracks_past_wrong_phi() {
    let bin = ground_truth_dir().join("loopphi.watcom-x86-32");
    let truth_path = ground_truth_dir().join("loopphi.watcom-x86-32.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip for_recovery_backtracks_past_wrong_phi: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let walk = truth
        .funcs
        .iter()
        .find(|(_, n)| n == "cbound_walk_")
        .map(|(a, _)| *a)
        .expect("truth lists cbound_walk_");
    let prog = analysis::analyze_file(&bin).expect("analyze loopphi");
    let f = decompile_function(&prog, Address::new(prog.default_space, walk))
        .expect("cbound_walk_ decompiles");
    let c = print_c(&f);
    assert!(
        c.lines().any(|l| l.trim_start().starts_with("for (")),
        "the counted loop was not recovered as a `for`: find_loop_phi settled for the first \
         loop-head phi — the RAM loop BOUND — instead of continuing past it to the register \
         induction variable (Ghidra findLoopVariable, block.cc:3164) — cbound_walk_ @ {walk:#x}\n{c}"
    );
    eprintln!("loopphi gate: cbound_walk_ recovered its for-loop past the bound's phi");
}

/// An INDIRECT call must not clobber the loop variable. mosura has no `ActionDefaultParams`
/// (coreaction.hh:659 / coreaction.cc:2311), so no call site gets its own prototype and
/// `Heritage::guardCalls` asks the CONTAINING FUNCTION's model what a call kills instead of the
/// CALL's. When that kills the induction variable's register, the loop-head MULTIEQUAL's tail
/// input becomes an INDIRECT — a marker — and the real update, left with no consumer but the call
/// argument it also feeds, is inlined and emitted as no statement at all. The loop then cannot
/// terminate. WAR2's FUN_00057034 is the specimen; `walk` (Open Watcom, `src/callclob.c`) is the
/// shape. NOTE the infinite-loop scan predicate cannot certify this — FUN_00057034's condition
/// reads a global bound, inside that predicate's documented blind spot — so this reads the
/// emitted loop directly.
#[test]
fn indirect_call_does_not_clobber_loop_variable() {
    let bin = ground_truth_dir().join("callclob.watcom-x86-32");
    let truth_path = ground_truth_dir().join("callclob.watcom-x86-32.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip indirect_call_does_not_clobber_loop_variable: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let walk = truth.funcs.iter().find(|(_, n)| n == "walk_").map(|(a, _)| *a).expect("truth lists walk_");
    let prog = analysis::analyze_file(&bin).expect("analyze callclob");
    let f = decompile_function(&prog, Address::new(prog.default_space, walk)).expect("walk_ decompiles");
    let c = print_c(&f);

    // Find the loop header and the induction variable it tests.
    let header = c
        .lines()
        .find(|l| {
            let t = l.trim_start();
            (t.starts_with("for (") || t.starts_with("while (")) && !t.contains("true")
        })
        .unwrap_or_else(|| panic!("walk_ recovered no counted loop:\n{c}"));
    let iv = regex_ident_before_lt(header)
        .unwrap_or_else(|| panic!("could not read the induction variable from: {header}\n{c}"));

    // THE DEFECT: the update exists only as a call argument, so nothing assigns `iv` in the loop.
    let body: String = c
        .lines()
        .skip_while(|l| !std::ptr::eq(*l, header) && *l != header)
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with('}'))
        .collect::<Vec<_>>()
        .join("\n");
    let assigned_in_header = header.contains(&format!("{iv} = "));
    let assigned_in_body = body.contains(&format!("{iv} = "));
    assert!(
        assigned_in_header || assigned_in_body,
        "the loop variable `{iv}` is never assigned in the loop — the update was folded into a \
         call argument and no statement was emitted, so this loop cannot terminate. An indirect \
         call must not clobber it (ActionDefaultParams unported) — walk_ @ {walk:#x}\n\
         header: {header}\nbody:\n{body}\n\n{c}"
    );
    eprintln!("callclob gate: `{iv}` is updated inside the loop — {header}");
}

/// `x` from a loop header of the form `... (x < ...)` / `... (x != ...)`.
fn regex_ident_before_lt(header: &str) -> Option<String> {
    let cond = if header.trim_start().starts_with("for (") {
        header.split(';').nth(1)?
    } else {
        let s = header.find('(')? + 1;
        let e = header.rfind(')')?;
        header.get(s..e)?
    };
    let pos = cond.find(" < ").or_else(|| cond.find(" != "))?;
    let lhs = cond[..pos].trim().trim_start_matches('(').trim();
    let id: String = lhs.chars().rev().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
    let id: String = id.chars().rev().collect();
    if id.is_empty() { None } else { Some(id) }
}

/// FUNCTION-START BYTE-PATTERN discovery — the source-reduced repro of the WAR2 auto-analysis gap
/// that Ghidra's four **Function Start Search** analyzers close (`FunctionStartAnalyzer` +
/// `ghidra.util.bytesearch` + `Processors/x86/data/patterns/*.xml`; 243 functions on WAR2).
///
/// `fnpattern` (Open Watcom, `src/fnpattern.c`, built `-of+`) contains `orphan_fn_`: a function
/// that NOTHING references — no call, no jump, no stored pointer — sitting between two
/// ordinarily-called functions. Every other discovery route mosura has needs an inbound edge
/// (`tailjmp` a jump, `datafnptr` a pointer run in data, `lestruct` an LE fixup slot), so the only
/// thing that can say "a function starts here" is the shape of its prologue bytes.
///
/// PRE-FIX (`c567bca`) `ground_truth_parity` reported
/// `fnpattern: mosura missed call-reachable functions: ["08048120"]`, and the orphan's bytes were
/// never even disassembled. This test pins the MECHANISM rather than just the recall: that the
/// orphan really is unreferenced (so it cannot have come back by any other route), that its entry
/// is EXACT rather than a few bytes into the prologue, and that switching the byte-pattern
/// analyzers off puts it back to missing.
#[test]
fn function_start_pattern_search() {
    let bin = ground_truth_dir().join("fnpattern.watcom-x86-32");
    let truth_path = ground_truth_dir().join("fnpattern.watcom-x86-32.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip function_start_pattern_search: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let orphan = truth
        .funcs
        .iter()
        .find(|(_, n)| n == "orphan_fn_")
        .map(|(a, _)| *a)
        .expect("truth lists orphan_fn_");

    let prog = analysis::analyze_file(&bin).expect("analyze fnpattern");
    let ram = prog.default_space;
    let at = |o: u64| Address::new(ram, o);

    // (0) The fixture still reproduces the shape: NOTHING references the orphan. If a compiler
    // change ever gives it an inbound edge the program has stopped reproducing the defect, and
    // this test must be revisited rather than silently passing.
    let inbound: Vec<(u64, &'static str)> =
        prog.reference_manager.refs_to(at(orphan)).map(|r| (r.from.offset, r.ref_type.name())).collect();
    assert!(
        inbound.is_empty(),
        "orphan_fn_ @ {orphan:#x} has inbound references {inbound:x?} — it is supposed to be \
         reachable ONLY by its prologue byte pattern"
    );

    // (1) It came back as a function...
    assert!(
        prog.function_manager.function_at(at(orphan)).is_some(),
        "orphan_fn_ @ {orphan:#x} must be recovered by the byte-pattern search — nothing else can \
         reach it"
    );
    // (2) ...at the EXACT entry. A prologue pattern that anchors a few bytes in (the Watcom
    // save-first shift) would create an entry inside the body instead; neither may exist.
    for d in 1..12u64 {
        assert!(
            prog.function_manager.function_at(at(orphan + d)).is_none(),
            "a function was created at orphan_fn_ + {d} — the pattern anchored past the true entry"
        );
    }

    // (3) THE ATTRIBUTION — with the byte-pattern analyzers off it goes back to missing, so the
    // recovery is theirs and not some other pass's.
    let without = {
        let _guard = overrides::disable_analyzers(BYTE_PATTERN_ANALYZERS);
        analysis::analyze_file(&bin).expect("analyze fnpattern")
    };
    assert!(
        without.function_manager.function_at(at(orphan)).is_none(),
        "orphan_fn_ is recovered even with the byte-pattern search disabled — this fixture is no \
         longer isolating that analyzer"
    );
    eprintln!(
        "fnpattern gate: orphan_fn_ @ {orphan:#x} recovered by prologue byte pattern alone \
         (0 inbound references, exact entry, absent when the search is disabled)"
    );
}


/// THE ABOVE-FUNCTION GUARD MUST TEST FALL-THROUGH, NOT ADJACENCY — the local gate for `be85c85`
/// (`FunctionStartAnalyzer.java:512`), whose only gate until now was a WAR2 run.
///
/// ```java
/// Instruction instr = program.getListing().getInstructionContaining(addrBefore);
/// if (instr != null && addr.equals(instr.getFallThrough())) { return true; }
/// ```
///
/// `getFallThrough()` is null after a `ret`, so Ghidra does not veto a prologue that merely
/// FOLLOWS an epilogue. mosura vetoed on any instruction ENDING at the address and so refused
/// 6 WAR2 tracker functions outright (the fix moved that run 2900 -> 3018 functions, 42 -> 12
/// missing, body intrusions unchanged at 3).
///
/// `retorphan` (Open Watcom, `src/retorphan.c`, built with the corpus default `-oc`) puts the
/// three conditions the guard's second arm needs in one program, which is the hard part and what
/// defeated the earlier `retboundary` attempt:
///
///  1. an instruction ending EXACTLY at the candidate entry AND ALREADY DECODED — `tab_h3_`'s
///     `ret`, decoded because `AddressTableAnalyzer` disassembles a pointer run's targets;
///  2. NO function above it — because that same analyzer deliberately creates none
///     (AddressTableAnalyzer.java:282), and `tab_h3_`'s own bytes match no prologue pattern;
///  3. the candidate reachable ONLY by the byte-pattern search.
///
/// Assertion (1) below is the ANTI-VACUITY check: `retboundary` failed precisely because the
/// preceding block was never decoded at all, so the arm under test never ran and the orphan came
/// back with the fix and without it. If a toolchain change ever undoes the decoded-but-not-a-
/// function state, this test says so instead of passing for the wrong reason.
///
/// ⭐ AND IT HAS ALREADY EARNED ITS KEEP — READ THIS BEFORE EDITING ANY PATTERN FILE.
/// **A new byte pattern can turn an unrelated, still-passing gate into a test of the wrong
/// branch.** Measured, same day this test was written: a candidate no-frame pattern
/// (`0x52 0x8b 00...101`, a run-length-1 form of family (6)) matched `tab_h3_` — the
/// address-table target this fixture needs to stay decoded-but-NOT-a-function — and created a
/// function there. Nothing looked wrong: `tab_h3_` is a REAL function, so `ground_truth_parity`'s
/// 0-spurious assertion passed, every other gate passed, and this test would have passed too. But
/// with a function above it, `getFunctionAbove` returns `Some`, `checkAlreadyInFunctionAbove`
/// answers from its FIRST arm, and the fall-through logic this test exists to pin is never
/// executed. Assertion (1) is what caught it, and it is why the family carries a minimum run
/// length of 2.
///
/// The general shape, which is not specific to patterns: **a change that adds discovery anywhere
/// can silently move an unrelated test onto a different code path, and a green suite will not tell
/// you.** The only defence is a test that asserts the state its subject depends on, not just its
/// subject's result.
///
/// PRE-FIX (`be85c85` reverted, measured on this binary): `orphan_fn_` @0804812c is absent from
/// the function set, while `tab_h0_..tab_h3_` stay decoded-and-in-no-function identically.
#[test]
fn above_function_guard_tests_fall_through() {
    use mosura::analysis::program::CodeUnit;

    let bin = ground_truth_dir().join("retorphan.watcom-x86-32");
    let truth_path = ground_truth_dir().join("retorphan.watcom-x86-32.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip above_function_guard_tests_fall_through: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let addr_of = |name: &str| -> u64 {
        truth
            .funcs
            .iter()
            .find(|(_, n)| n == name)
            .map(|(a, _)| *a)
            .unwrap_or_else(|| panic!("truth lists {name}"))
    };
    let orphan = addr_of("orphan_fn_");
    let tab_h3 = addr_of("tab_h3_");

    // The corpus routes `.watcom-x86-32` through the build's own `compiler` field, so the gate
    // measures the file the run actually uses (`x86watcom_patterns.xml`), not the gcc one.
    let prog = analysis::analyze_file_as(&bin, Some("watcom")).expect("analyze retorphan");
    let ram = prog.default_space;
    let at = |o: u64| Address::new(ram, o);

    // (0) The fixture still reproduces the shape: nothing references the orphan, so no other
    // discovery route can reach it, and the byte before it is a `ret` (fall-through = null).
    let inbound: Vec<(u64, &'static str)> = prog
        .reference_manager
        .refs_to(at(orphan))
        .map(|r| (r.from.offset, r.ref_type.name()))
        .collect();
    assert!(
        inbound.is_empty(),
        "orphan_fn_ @ {orphan:#x} has inbound references {inbound:x?} — it must be reachable ONLY \
         by its prologue byte pattern"
    );
    assert_eq!(
        prog.memory.byte_at(at(orphan - 1)),
        Some(0xc3),
        "the byte before orphan_fn_ must be `c3` (RET) — the instruction whose fall-through is \
         null is the whole premise"
    );

    // (1) ANTI-VACUITY — the arm under test is only reached when the preceding instruction is
    // DECODED and belongs to NO function. Both halves are asserted; either one silently going
    // false is what made the previous attempt at this fixture measure nothing.
    let (start, len) = prog
        .listing
        .code_unit_containing(at(orphan - 1), 16)
        .expect("the instruction before orphan_fn_ must be DECODED — otherwise the fall-through \
                 arm of checkAlreadyInFunctionAbove never runs and this test measures nothing");
    assert!(
        matches!(prog.listing.code_unit_at(start), Some(CodeUnit::Instruction { .. }))
            && start.offset + len == orphan,
        "the code unit before orphan_fn_ must be an INSTRUCTION ending exactly at {orphan:#x}; \
         got start {:#x} len {len}",
        start.offset
    );
    assert!(
        prog.function_manager.function_containing(at(orphan - 1)).is_none(),
        "the `ret` before orphan_fn_ is inside a function — `getFunctionAbove` is then `Some` and \
         the first arm answers instead, so the fall-through test is never consulted"
    );
    assert!(
        prog.function_manager.function_at(at(tab_h3)).is_none(),
        "a function was created at tab_h3_ @ {tab_h3:#x}; address tables must never make functions \
         (AddressTableAnalyzer.java:282) and its prologue must match no pattern"
    );

    // (2) It came back as a function, at the EXACT entry.
    assert!(
        prog.function_manager.function_at(at(orphan)).is_some(),
        "orphan_fn_ @ {orphan:#x} must be recovered — the `ret` above it does not fall through, so \
         `checkAlreadyInFunctionAbove` must not veto its `after=\"defined\"` pre-requisite"
    );
    for d in 1..12u64 {
        assert!(
            prog.function_manager.function_at(at(orphan + d)).is_none(),
            "a function was created at orphan_fn_ + {d} — the pattern anchored past the true entry"
        );
    }

    // (3) ATTRIBUTION — with the byte-pattern analyzers off the orphan goes back to missing, while
    // the decoded-but-not-a-function state above it survives. That splits the two mechanisms: the
    // decode is the address table's, the function is the pattern search's.
    let without = {
        let _guard = overrides::disable_analyzers(BYTE_PATTERN_ANALYZERS);
        analysis::analyze_file_as(&bin, Some("watcom")).expect("analyze retorphan")
    };
    assert!(
        without.function_manager.function_at(at(orphan)).is_none(),
        "orphan_fn_ is recovered with the byte-pattern search disabled — this fixture is no longer \
         isolating that analyzer"
    );
    assert!(
        without.listing.code_unit_containing(at(orphan - 1), 16).is_some(),
        "the `ret` above the orphan is decoded only when the pattern search runs — the preceding \
         block is supposed to be decoded by the ADDRESS TABLE analyzer, independently"
    );
    eprintln!(
        "retorphan gate: orphan_fn_ @ {orphan:#x} recovered one byte past a `ret` that belongs to \
         no function (decoded by the address table, 0 inbound refs, exact entry)"
    );
}

/// §8 — A FUNCTION BODY MUST INCLUDE ITS SWITCH CASE BODIES (the computed-jump flow).
///
/// Ghidra's body walk is `CreateFunctionCmd.getFunctionBody` -> `FollowFlow`, and
/// `FollowFlow.getFlowsFromInstruction` (FollowFlow.java:743) reads `instr.getReferencesFrom()`
/// and follows every flow reference that survives `shouldFollowFlow` (:715). The `dontFollow` set
/// `CreateFunctionCmd` passes (:622) is
///
/// ```java
/// { RefType.COMPUTED_CALL, RefType.CONDITIONAL_CALL, RefType.UNCONDITIONAL_CALL,
///   RefType.INDIRECTION }
/// ```
///
/// — **`COMPUTED_JUMP` is not in it**, so a recovered switch's case bodies are inside Ghidra's
/// function body.
///
/// mosura's two body walks were opcode-driven and pushed a target only for `Branch`/`Cbranch`
/// with a *static* p-code target. A `BRANCHIND` names no static target — the jump table lives in
/// the REFERENCE set, which the walks never consulted — so every case body fell outside.
///
/// PRE-FIX, measured over these same fixtures: **53 of 53** computed-jump targets outside the
/// containing body (narrowsw 16/16, switchcall 14/14, dispatch 7/7, tables 12/12, compgoto 4/4).
/// Not a partial gap — total, across two compilers and two architectures. A wrong extent can
/// never recompile byte-exact, which is why this one bears on the campaign's actual goal.
///
/// `sparseswitch` is in the list deliberately even though it recovers no computed jump here: it
/// keeps the fixture set honest about which programs actually exercise the path, so a future
/// change that stops recovering the tables shows up as `0 targets` rather than as a silent pass.
#[test]
fn switch_case_bodies_are_inside_the_function_body() {
    let cases: &[(&str, Option<&str>)] = &[
        ("narrowsw.watcom-x86-32", Some("watcom")),
        ("switchcall.watcom-x86-32", Some("watcom")),
        ("dispatch.gcc-x86-64", None),
        ("tables.gcc-x86-64", None),
        ("sparseswitch.gcc-x86-64", None),
        ("compgoto.gcc-x86-64", None),
    ];
    let mut total = 0usize;
    let mut checked_fixtures = 0usize;
    for (name, cspec) in cases {
        let bin = ground_truth_dir().join(name);
        if !bin.exists() {
            eprintln!("skip {name}: absent");
            continue;
        }
        let prog = analysis::analyze_file_as(&bin, *cspec).expect("analyze");
        let ram = prog.default_space;
        checked_fixtures += 1;
        let mut outside: Vec<String> = Vec::new();
        let mut here = 0usize;
        for f in prog.function_manager.functions() {
            let entry = f.entry_point();
            for a in f.body().ranges().flat_map(|r| r.min..=r.max) {
                for r in prog.reference_manager.refs_from(Address::new(ram, a)) {
                    if !matches!(
                        r.ref_type,
                        RefType::ComputedJump | RefType::ConditionalComputedJump
                    ) {
                        continue;
                    }
                    here += 1;
                    if !f.body().contains(r.to) {
                        outside.push(format!("{:08x} -> {:08x}", entry.offset, r.to.offset));
                    }
                }
            }
        }
        total += here;
        assert!(
            outside.is_empty(),
            "{name}: {} of {here} computed-jump targets lie OUTSIDE the body of the function that \
             jumps to them: {outside:?} — Ghidra's `dontFollow` omits COMPUTED_JUMP, so the case \
             bodies belong to the function",
            outside.len()
        );
    }
    assert!(checked_fixtures > 0, "no switch fixture was available — this gate measured nothing");
    assert!(
        total > 0,
        "not one computed-jump reference was found across {checked_fixtures} fixtures; the switch \
         tables have stopped being recovered, so this gate can no longer fail"
    );
    eprintln!("§8 gate: {total} computed-jump targets, all inside their function's body");
}

/// THE NO-FRAME PROLOGUE SHAPE IS UNCOVERED, DELIBERATELY — a refutation, kept as a gate.
///
/// `nfprologue.watcom-x86-32` holds three functions reachable by nothing but their prologue bytes,
/// in the shape `wcc386` emits BY DEFAULT (`-of+` is what turns the frame pointer on): a
/// callee-save push run followed by neither a frame setup nor a stack adjust.
///
/// ```text
/// nf_stackarg_   56 57 55 8b 6c 24 10    push esi,edi,ebp ; mov ebp,[esp+0x10]
/// nf_stackarg2_  56 57 8b 7c 24 0c       push esi,edi     ; mov edi,[esp+0xc]
/// nf_absload_    53 51 52 8b 0d <abs32>  push ebx,ecx,edx ; mov ecx,[abs32]
/// ```
///
/// A pattern family covering exactly these two follow-ons was written, recovered all three here,
/// and was **backed out** — see `specs/patterns/x86watcom_patterns.xml` family (6) for the full
/// account. On WAR2 it added 53 functions, recovered none of the entries it was written for, moved
/// `MATCHED` against the expert tracker by zero, and only **26%** of its additions ended in a
/// terminator against a ~99.8% baseline from two other populations. The mechanism, measured: it
/// also matches ordinary mid-function code (`push ecx,edx ; mov eax,[esp+8]` — stack arguments for
/// a call; `push esi,edi ; mov eax,[abs32]` — pushes then a global read), because unlike every
/// other family in that file it has no FRAME-SETUP anchor, and "some pushes then a memory access"
/// occurs everywhere in a real binary.
///
/// ⚠️ SO THIS TEST ASSERTS THE ORPHANS ARE **NOT** FOUND. That is not an aspiration to fix by
/// re-adding the family — it is the record of a measured refutation, so the next person to notice
/// the gap finds the reason before repeating the work. If you cover this shape, cover it with an
/// anchor that distinguishes a prologue from mid-function code, and re-measure the terminator rate
/// on WAR2 before believing it.
///
/// The deeper lesson, and the reason the fixture is kept rather than deleted: **the corpus could
/// not see this defect.** Over the 16 committed Watcom binaries the family produced zero marks
/// outside this very fixture — they are small freestanding programs with almost no stack-passed
/// arguments and few globals. A self-compiled gate measures the shapes its author thought of.
#[test]
fn no_frame_prologue_shape_is_uncovered() {
    let bin = ground_truth_dir().join("nfprologue.watcom-x86-32");
    let truth_path = ground_truth_dir().join("nfprologue.watcom-x86-32.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip no_frame_prologue_shape_is_uncovered: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let addr_of = |name: &str| -> u64 {
        truth.funcs.iter().find(|(_, n)| n == name).map(|(a, _)| *a).unwrap_or_else(|| panic!("truth lists {name}"))
    };
    let orphans = [
        ("nf_stackarg_", addr_of("nf_stackarg_"), &[0x56u8, 0x57, 0x55, 0x8b][..]),
        ("nf_stackarg2_", addr_of("nf_stackarg2_"), &[0x56, 0x57, 0x8b, 0x7c][..]),
        ("nf_absload_", addr_of("nf_absload_"), &[0x53, 0x51, 0x52, 0x8b][..]),
    ];

    let prog = analysis::analyze_file_as(&bin, Some("watcom")).expect("analyze nfprologue");
    let ram = prog.default_space;
    let at = |o: u64| Address::new(ram, o);

    for (name, a, want) in &orphans {
        // The fixture still reproduces the shape — if a compiler change reintroduces a frame setup
        // or drops the push run, this stops characterising anything and must fail loudly.
        let got = prog.memory.read_window(at(*a), want.len());
        assert_eq!(
            &got[..], *want,
            "{name} @ {a:#x} no longer starts with the no-frame shape this fixture characterises;              got {got:02x?} — rebuild with default flags, NOT `-of+`"
        );
        // Nothing references it, so only a prologue pattern could ever find it.
        let inbound: Vec<(u64, &'static str)> = prog
            .reference_manager
            .refs_to(at(*a))
            .map(|r| (r.from.offset, r.ref_type.name()))
            .collect();
        assert!(inbound.is_empty(), "{name} @ {a:#x} has inbound references {inbound:x?}");
        // THE RECORDED GAP.
        assert!(
            prog.function_manager.function_at(at(*a)).is_none(),
            "{name} @ {a:#x} IS now recovered — the no-frame shape has been covered by something.              That may be right, but it is a change of position: re-measure the WAR2 terminator              rate (the backed-out family scored 26% against a ~99.8% baseline) before keeping it,              and update this test deliberately rather than deleting the assertion"
        );
    }
    eprintln!(
        "nfprologue: 3/3 no-frame orphans deliberately NOT recovered (family (6) refuted on WAR2)"
    );
}

/// The **prologue-shape specification** for the beyond-Ghidra Watcom function-start pattern set
/// (`specs/patterns/x86watcom_patterns.xml`). That file has no Ghidra oracle — Ghidra ships no
/// Watcom compiler spec — so this fixture is its oracle.
///
/// It exists because **precision is unmeasurable on WAR2**: the expert tracker covers 71.4% of the
/// code object, so a pattern hit in a gap may be a real function the tracker lacks or may be noise,
/// and the binary cannot tell them apart. Tuning the pattern against WAR2's function count is
/// therefore chasing a number with no specification behind it. Here every function comes from the
/// compiler's own symbol table, so both properties are decidable: the search must find **every**
/// real entry (recall) and create **nothing else** (precision).
///
/// `wprologue` is built `-of+` on purpose — traceable stack frames. Without it wcc386 omits the
/// frame pointer and addresses locals off ESP, emitting prologues (`53 51 83 ec`, `53 51 52 56 b8`)
/// with no `89 e5` anywhere, which look nothing like the target. Note the fixture still cannot
/// reproduce WAR2's exact shape: modern Open Watcom emits frame-FIRST (`55 89 e5` then the saves)
/// where WAR2's Watcom 10.0a emits save-FIRST (saves then `55 89 e5`) — the artifact
/// `warcraft2-re/analysis/function-boundary-correction.md` documents. It gates the pattern set's
/// precision on a fully-known binary, which is what it is for; the save-first shape is specified by
/// the 2120 measured tracker entries instead.
#[test]
fn watcom_prologue_shape_spec() {
    let bin = ground_truth_dir().join("wprologue.watcom-x86-32");
    let truth_path = ground_truth_dir().join("wprologue.watcom-x86-32.truth");
    if !bin.exists() {
        eprintln!("skip watcom_prologue_shape_spec: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let prog = analysis::analyze_file(&bin).expect("analyze wprologue");
    let mine: std::collections::BTreeSet<u64> =
        prog.function_manager.functions().map(|f| f.entry_point().offset).collect();
    let known: std::collections::BTreeSet<u64> = truth.funcs.iter().map(|(a, _)| *a).collect();

    let missed: Vec<String> = known.difference(&mine).map(|a| format!("{a:08x}")).collect();
    assert!(missed.is_empty(), "wprologue RECALL: pattern set missed real prologues: {missed:?}");

    let spurious: Vec<String> = mine.difference(&known).map(|a| format!("{a:08x}")).collect();
    assert!(
        spurious.is_empty(),
        "wprologue PRECISION: pattern set invented entries that are not functions: {spurious:?}"
    );
}

/// §5 CELL 1 — **stack checking**: a function compiled without `-s` starts at its stack probe,
/// and the pattern set must anchor there rather than ten bytes later.
///
/// # Why this cell exists
///
/// `-s` suppresses Watcom's stack-overflow probe. WAR2 was built with it; **most binaries are
/// not, because it is not the default** — so this is the axis most likely to matter on a binary
/// that is not WAR2, which is the standing scope rule's whole point. Without `-s`, wcc386 opens
/// every framed function with `push <framesize>; call __CHK`:
///
/// ```text
/// -of+        55 89 e5  68 <imm32>  e8 <rel32>                   frame, THEN probe
/// -od / -oc   68 <imm32> e8 <rel32>  53 51 52 56 57  55 89 e5    probe FIRST, at offset 0
/// ```
///
/// # The defect, and why it is worse than a miss
///
/// These functions are not invisible — they are found at the **wrong address**. Measured on this
/// fixture before the stack-probe family existed, with the true entries missed and entries
/// created exactly ten bytes into each:
///
/// ```text
/// MISSED ["08048112", "08048666"]   EXTRA ["0804811c", "08048670"]
/// ```
///
/// `08048666` is `probe_orphan_fn_`; the `08048670` beside it is family (1) matching at the first
/// callee-save push, past the probe. That is precisely the defect this pattern file was created
/// to fix — `x86gcc_patterns.xml` anchoring at the `55`, five bytes late — reintroduced one level
/// up. A wrong entry is a wrong extent, and a wrong extent can never recompile byte-exact, so
/// this costs more than a missing function does.
#[test]
fn watcom_stack_probe_shape_spec() {
    let bin = ground_truth_dir().join("wprobe.watcom-x86-32");
    let truth_path = ground_truth_dir().join("wprobe.watcom-x86-32.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip watcom_stack_probe_shape_spec: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let known: BTreeSet<u64> = truth.funcs.iter().map(|(a, _)| *a).collect();
    let orphan = truth
        .funcs
        .iter()
        .find(|(_, n)| n == "probe_orphan_fn_")
        .map(|(a, _)| *a)
        .expect("truth lists probe_orphan_fn_");

    let run = |analyzers_off: bool| -> BTreeSet<u64> {
        // The corpus cannot reach the `watcom` pattern file on its own — no ground-truth binary
        // carries a Watcom run-time banner. See `watcom_save_first_shape_spec` for the detail.
        // Per-thread overrides, NOT `std::env`: see `analysis::overrides`.
        let _a = analyzers_off.then(|| overrides::disable_analyzers(BYTE_PATTERN_ANALYZERS));
        let p = analysis::analyze_file_as(&bin, Some("watcom")).expect("analyze wprobe");
        assert_eq!(p.compiler_spec_id, "watcom", "MOSURA_X86_32_CSPEC did not take effect");
        p.function_manager.functions().map(|f| f.entry_point().offset).collect()
    };

    // (0) The orphan really is unreferenced, so recall is a statement about the pattern set and
    // not about some other discovery route.
    let probe = analysis::analyze_file_as(&bin, Some("watcom")).expect("analyze wprobe");
    let inbound: Vec<(u64, &'static str)> = probe
        .reference_manager
        .refs_to(Address::new(probe.default_space, orphan))
        .map(|r| (r.from.offset, r.ref_type.name()))
        .collect();
    assert!(
        inbound.is_empty(),
        "probe_orphan_fn_ @ {orphan:#x} has inbound references {inbound:x?} — it must be \
         reachable ONLY by its prologue byte pattern"
    );

    // (1) RECALL + PRECISION on a fully-known binary.
    let mine = run(false);
    let missed: Vec<String> = known.difference(&mine).map(|a| format!("{a:08x}")).collect();
    assert!(
        missed.is_empty(),
        "wprobe RECALL: the pattern set missed stack-probe prologues: {missed:?}"
    );
    let spurious: Vec<String> = mine.difference(&known).map(|a| format!("{a:08x}")).collect();
    assert!(
        spurious.is_empty(),
        "wprobe PRECISION: entries that are not functions: {spurious:?}. `push imm32; call rel32` \
         is an ordinary code sequence, so the probe-first patterns carry `after=\"defined\"` + \
         `validcode=\"6\"`; a hit here means those guards are not holding"
    );

    // (2) THE ANCHOR IS THE PROBE, not the push run ten bytes in. This is the property the cell
    // exists for, and it is what a naive "did we find a function near here" check would miss.
    for d in 1..12u64 {
        assert!(
            !mine.contains(&(orphan + d)),
            "an entry was created at probe_orphan_fn_ + {d} — the pattern anchored past the \
             stack probe, which is the shift this cell exists to prevent"
        );
    }

    // (3) ATTRIBUTION — with the byte-pattern search off the orphan is gone, so its recovery
    // belongs to the pattern set.
    assert!(
        !run(true).contains(&orphan),
        "probe_orphan_fn_ is recovered with the byte-pattern search disabled — this fixture no \
         longer isolates that analyzer"
    );

    eprintln!(
        "wprobe gate: {}/{} recovered, 0 spurious; orphan {orphan:#x} anchored AT its stack \
         probe (not +10) and absent when the byte-pattern search is off",
        mine.len(),
        known.len()
    );
}

/// A function body must END at a call that never returns — and this is the only fixture in the
/// corpus that can say so, because it is the only one where `analyzers/noreturn.rs` runs at all.
///
/// # The coverage hole this closes
///
/// `noreturn::analyze` selects its name list from the memory map and returns early unless a
/// `.dynsym`, `.plt` or `EXTERNAL` block exists (`noreturn.rs:128-137`). Every other artifact here
/// is freestanding — the gcc columns link `-nostdlib -static`, the Watcom columns
/// `option nodefaultlib` — and WAR2 is a DOS/4GW LE image with `objN_text`/`objN_data` objects.
/// Measured on all of them: **`noreturn_functions` is empty**. So an entire analyzer had zero
/// coverage on every target, and a test asserting any no-return behaviour would have passed
/// whether or not the code beneath it worked. `src/noret.c` is built dynamically for this reason
/// alone.
///
/// # The defect it pins
///
/// Ghidra asks `Instruction.getFallThrough()` (`FollowFlow.java:556`), which is null after a call
/// to a non-returning function, so a body stops there. mosura's `compute_function_bodies` derived
/// fall-through from the p-code opcode alone, with no `is_noreturn` consultation — even though the
/// *disassembler's* walk 170 lines above it in the same file does exactly that and cites Ghidra
/// for it (`analyzers/mod.rs:130`). Two copies of one walk; one had lost the rule. Measured before
/// the fix: `a_dies`'s body ran to `0x40103f`, six bytes of inter-function alignment padding past
/// its real end at `0x401039`.
///
/// The extents are the **compiler's own** — `nm -S` sizes carried in the truth file — so this
/// asserts mosura's computed body against the build, not against a hand-written address.
#[test]
fn noreturn_call_bounds_the_body() {
    let bin = ground_truth_dir().join("noret.gcc-x86-64");
    let truth_path = ground_truth_dir().join("noret.gcc-x86-64.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip noreturn_call_bounds_the_body: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let prog = analysis::analyze_file(&bin).expect("analyze noret");
    let ram = prog.default_space;

    // (0) ANTI-VACUITY, and the reason this fixture exists. If nothing is flagged no-return then
    // `falls` is identical with and without the rule under test, and every assertion below would
    // pass on unfixed code. Assert the mechanism is live before asserting its effect.
    let flagged: Vec<String> =
        prog.noreturn_functions.iter().map(|(_, o)| format!("{o:08x}")).collect();
    assert!(
        !flagged.is_empty(),
        "no function is flagged no-return, so this fixture cannot test anything — has the \
         dynamic-link recipe or `noreturn::analyze`'s block-name gate changed?"
    );
    let abort_at: Vec<u64> = prog
        .symbol_table
        .symbols()
        .filter(|s| s.name() == "abort")
        .map(|s| s.address().offset)
        .collect();
    assert!(!abort_at.is_empty(), "the `abort` import is not in the symbol table");
    assert!(
        abort_at.iter().any(|a| prog.is_noreturn(Address::new(ram, *a))),
        "`abort` @ {abort_at:x?} is not flagged no-return, but {flagged:?} are — the fixture's \
         own no-return call is not the one being exercised"
    );

    // (1) THE PROPERTY. Every function's computed body must lie within the extent the compiler
    // recorded for it. `a_dies` is the one that can fail: its last flow is `call abort`, and a
    // body that walks past it runs into the alignment padding that belongs to no function.
    let mut over: Vec<String> = Vec::new();
    for &(entry, size) in &truth.sizes {
        if size == 0 {
            continue;
        }
        let Some(f) = prog.function_manager.function_at(Address::new(ram, entry)) else { continue };
        let last = entry + size - 1;
        if let Some(max) = f.body().ranges().map(|r| r.max).max() {
            if max > last {
                over.push(format!("{entry:08x}: body ends {max:08x}, compiler says {last:08x}"));
            }
        }
    }
    assert!(
        over.is_empty(),
        "function bodies extend past the extent the compiler recorded: {over:?}"
    );
    eprintln!(
        "noret gate: {} no-return flagged (abort @ {abort_at:x?}); all {} bodies within their \
         compiler-recorded extents",
        flagged.len(),
        truth.sizes.len()
    );
}

/// The **save-first** half of the prologue-shape specification — and the only gate anywhere on
/// `specs/patterns/x86watcom_patterns.xml`, whose 62 save-first patterns are 85% of that file.
///
/// # Why this did not exist before, and what had to change for it to
///
/// Two independent things made the save-first family ungateable, and both are measured here
/// rather than argued:
///
/// 1. **No corpus binary could reach the Watcom pattern file.** The pattern-file decision tree is
///    keyed on `(language, compiler)`, and `loader::watcom::compiler_spec_id` decides the compiler
///    from the *run-time* copyright banner — a string in the C run-time, not in compiler output.
///    The corpus links `option nodefaultlib` with a hand-written `_cstart_`, so no ground-truth
///    binary carries the banner and every one detects as `gcc`. Verified: `wprologue`,
///    `wprologue_sf` and `fnpattern` all report `cspec=gcc`. Any gate written against a
///    Watcom-compiled fixture was therefore silently measuring Ghidra's `x86gcc_patterns.xml`.
///    `MOSURA_X86_32_CSPEC` (see that function's docs) routes the same binary through both.
///
/// 2. **Recall was vacuous.** Every function in `wprologue.c` is called from `main`, so the
///    reference-driven analyzers recover all of them and the pattern set is never load-bearing.
///    Measured on this fixture before `sf_orphan_fn_` was added: 15/15 recall and 0 spurious with
///    the byte-pattern analyzers switched OFF. `src/wprologue_sf.c` therefore adds an ORPHAN — a
///    save-first function nothing references — the way `fnpattern.c` does for frame-first.
///
/// # What it asserts
///
/// The four legs below are the measured behaviour of the fixture, and each is a different claim:
///
/// | routing | result |
/// | --- | --- |
/// | `watcom` (the correct spec) | 17/17 recall, 0 spurious |
/// | `watcom`, byte-pattern analyzers off | the orphan is GONE — the recovery is theirs |
/// | `gcc` (Ghidra's own set) | misses the orphan, and creates an entry 2 bytes in |
///
/// That last row is the **prologue shift**, reproduced end to end on a self-compiled binary for
/// the first time. `src/fnpattern.c` property 1 records that it "CANNOT be gated by this corpus"
/// and falls back to a byte-level differential over the two pattern files; with the routing hook
/// it can be, through the real analysis pipeline, on a binary where every function is known.
#[test]
fn watcom_save_first_shape_spec() {
    let bin = ground_truth_dir().join("wprologue_sf.watcom-x86-32");
    let truth_path = ground_truth_dir().join("wprologue_sf.watcom-x86-32.truth");
    if !bin.exists() || !truth_path.exists() {
        eprintln!("skip watcom_save_first_shape_spec: {} absent", bin.display());
        return;
    }
    let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
    let known: BTreeSet<u64> = truth.funcs.iter().map(|(a, _)| *a).collect();
    let orphan = truth
        .funcs
        .iter()
        .find(|(_, n)| n == "sf_orphan_fn_")
        .map(|(a, _)| *a)
        .expect("truth lists sf_orphan_fn_");

    // Route the binary through a compiler spec, run the analysis, return the function set.
    let entries = |cspec: Option<&str>, analyzers_off: bool| -> (BTreeSet<u64>, String) {
        let _a = analyzers_off.then(|| overrides::disable_analyzers(BYTE_PATTERN_ANALYZERS));
        let p = analysis::analyze_file_as(&bin, cspec).expect("analyze wprologue_sf");
        let cspec = p.compiler_spec_id.clone();
        (p.function_manager.functions().map(|f| f.entry_point().offset).collect(), cspec)
    };

    // (0) The fixture still reproduces the shape: NOTHING references the orphan. If a compiler
    // change ever gives it an inbound edge, recall stops being a statement about the pattern set.
    let probe =
        analysis::analyze_file_as(&bin, Some("watcom")).expect("analyze wprologue_sf");
    let inbound: Vec<(u64, &'static str)> = probe
        .reference_manager
        .refs_to(Address::new(probe.default_space, orphan))
        .map(|r| (r.from.offset, r.ref_type.name()))
        .collect();
    assert!(
        inbound.is_empty(),
        "sf_orphan_fn_ @ {orphan:#x} has inbound references {inbound:x?} — it is supposed to be \
         reachable ONLY by its save-first prologue byte pattern"
    );

    // (1) The Watcom pattern set: full recall and nothing invented.
    let (mine, cspec) = entries(Some("watcom"), false);
    assert_eq!(cspec, "watcom", "MOSURA_X86_32_CSPEC did not take effect");
    let missed: Vec<String> = known.difference(&mine).map(|a| format!("{a:08x}")).collect();
    assert!(
        missed.is_empty(),
        "wprologue_sf RECALL: the Watcom pattern set missed real save-first prologues: {missed:?}"
    );
    let spurious: Vec<String> = mine.difference(&known).map(|a| format!("{a:08x}")).collect();
    assert!(
        spurious.is_empty(),
        "wprologue_sf PRECISION: the Watcom pattern set invented entries that are not \
         functions: {spurious:?}"
    );

    // (2) THE ATTRIBUTION — with the byte-pattern analyzers off the orphan goes back to missing,
    // so its recovery belongs to them and not to some other pass.
    let (without, _) = entries(Some("watcom"), true);
    assert!(
        !without.contains(&orphan),
        "sf_orphan_fn_ is recovered even with the byte-pattern search disabled — this fixture is \
         no longer isolating that analyzer"
    );

    // (3) THE PROLOGUE SHIFT. Ghidra's own x86gcc set has no pattern that starts at a push run,
    // so its `0x5589e5…` anchors at the `push ebp` INSIDE the prologue: it misses the true entry
    // and marks one N bytes in. This is the defect the whole Watcom pattern file exists to fix,
    // and asserting it here keeps the file's justification measured rather than remembered.
    let (as_gcc, cspec) = entries(Some("gcc"), false);
    assert_eq!(cspec, "gcc");
    assert!(
        !as_gcc.contains(&orphan),
        "x86gcc_patterns.xml unexpectedly marks the save-first entry {orphan:#x} — the premise of \
         the Watcom pattern set is that it does not"
    );
    let shifted: Vec<u64> = (1..8).map(|d| orphan + d).filter(|a| as_gcc.contains(a)).collect();
    assert!(
        !shifted.is_empty(),
        "x86gcc_patterns.xml marked neither the entry nor anything just past it; the shift this \
         fixture demonstrates has changed shape and its documentation needs revisiting"
    );

    eprintln!(
        "wprologue_sf gate: cspec=watcom {}/{} recovered, 0 spurious; orphan {orphan:#x} absent \
         with the byte-pattern search off; cspec=gcc misses it and marks {:x?} instead",
        mine.len(),
        known.len(),
        shifted
    );
}

/// ⭐ THE LISTING GATE — a recovered function's body must be IN THE LISTING.
///
/// Ghidra's whole function model assumes this. `CreateFunctionCmd.getFunctionBody`
/// (CreateFunctionCmd.java:616) reads `getInstructionAt(entry)` and walks the listing from there;
/// `checkAfterName`'s `"instruction"` and `"defined"` prerequisites
/// (FunctionStartAnalyzer.java) ask the listing what is at an address. Where mosura creates a
/// function whose bytes were never disassembled, every one of those queries answers `None` and
/// the tool is silently blind in that region — which is how `docs/function-discovery-backlog.md`
/// §9 #2 and #3 came to be filed as two separate divergences when they are one symptom, and why
/// the `retboundary` fixture could not fail.
///
/// The gate is deliberately stated over TRUTH FUNCTIONS ONLY, and both exclusions are principled
/// rather than fitted to what currently passes:
///
///  1. **An entry outside INITIALIZED memory.** Ghidra creates a degenerate, un-disassembled
///     function at a call target in an uninitialized block — `noret.gcc-x86-64`'s `EXTERNAL`
///     stub at 0x404000 is exactly that, and it agrees with Ghidra. There is nothing to
///     disassemble, so demanding an instruction there would be demanding a divergence.
///  2. **Entries that are not in the ground truth at all.** Those are governed by
///     [`byte_pattern_carve_out`], which already records why they exist: on the m68k/aarch64
///     columns mosura does not recover the jump tables, so it mints functions at case-body
///     addresses that Ghidra does not. They are 13 of the 19 uncovered entries in this corpus.
///     Demanding that mosura disassemble a function it should never have created would be
///     demanding MORE wrong work, and would wire this gate to a defect that belongs to jump-table
///     recovery. Recovering them is `analysis_parity`'s 0-spurious job, not this test's.
///
/// ⚠️ **`#[ignore]`d AND EXPECTED-RED — this is deliberate, do not "fix" it.** The fix exists
/// (`held-patches/listing-command-channel.patch`), builds, and turns this green, but it is BLOCKED
/// (see `docs/function-discovery-backlog.md` §9 #5). The test is committed in its FAILING state,
/// ignored so the workspace stays green, so that its ability to fail is proved **by git history**
/// rather than by a revert-check someone has to trust. Un-ignore it in the same commit that lands
/// the fix; it should go 5 -> 0 in one visible step.
///
/// ⚠️ ANTI-VACUITY. This must be RED at the commit that introduces it, on five addresses whose
/// causes are already measured and distinct — do not let it be "fixed" by narrowing the
/// population. Verbatim output at `2c534db`, `cargo test --release -p mosura --test
/// ground_truth_parity recovered_functions_are_in_the_listing`:
///
/// ```text
/// 5 recovered ground-truth function(s) of 386 have bytes that were never disassembled
/// into the listing:
///   fnpattern.watcom-x86-32 @08048120 orphan_fn_: entry_instruction=false body=89B
///        bytes_with_no_code_unit=89
///   retorphan.watcom-x86-32 @0804812c orphan_fn_: entry_instruction=false body=88B
///        bytes_with_no_code_unit=88
///   wprobe.watcom-x86-32 @08048112 p_leaf_: entry_instruction=false body=46B
///        bytes_with_no_code_unit=46
///   wprobe.watcom-x86-32 @08048666 probe_orphan_fn_: entry_instruction=false body=210B
///        bytes_with_no_code_unit=210
///   wprologue_sf.watcom-x86-32 @080485e3 sf_orphan_fn_: entry_instruction=false body=158B
///        bytes_with_no_code_unit=158
/// ```
///
/// Causes, per address: `08048120`, `0804812c`, `08048666`, `080485e3` are **cause A**;
/// `08048112` is **cause B**. It NAMES its violations rather than reporting a boolean, so each
/// fix's contribution is visible and the second change cannot be credited with the first's effect.
///
/// **Cause A** — `analysis::analyze` builds a SECOND `AutoAnalysisManager` for the byte-pattern
/// passes (mod.rs:246) in which neither `Disassembler` nor `FunctionCreator` is registered, so
/// their `code_defined` reaches no disassembler and their `function_defined` reaches **zero**
/// consumers. Ghidra has one manager per program (`AutoAnalysisManager.getAnalysisManager`,
/// :949) and the analyzer schedules COMMANDS onto it (`disassemble` :1128 / `createFunction`
/// :1132), which execute regardless of who subscribes; expressing them as change notifications
/// is what lets them evaporate.
///
/// **Cause B** — `Disassembler::added` and `FunctionCreator::added` iterate `set.ranges()` and
/// take only `r.min`, so adjacent requested addresses collapse. `wprobe` has three functions at
/// three consecutive addresses (`08048110 sink_`, `08048111 __CHK`, `08048112 p_leaf_`); the
/// last is dropped and never disassembled, even though `main_` calls it directly
/// (`0804856c: e8 a1 fb ff ff  call 0x8048112`). Ghidra iterates ADDRESSES
/// (`CreateFunctionCmd.java:158` `origEntries.getAddresses(true)`) and DRAINS each range one
/// address at a time (`DisassembleCommand.java:235-266`).
///
/// The two need separate commits: A changes which functions are DISCOVERED, B changes which
/// bytes are DECODED, and bundling them makes a WAR2 delta unattributable per function.
#[test]
#[ignore = "expected-RED: the fix is held in held-patches/listing-command-channel.patch, \
            blocked by docs/function-discovery-backlog.md §9 #5 (inline-parameter thunk)"]
fn recovered_functions_are_in_the_listing() {
    let dir = ground_truth_dir();
    if !dir.exists() {
        eprintln!("skip recovered_functions_are_in_the_listing: {} absent", dir.display());
        return;
    }
    let mut truths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "truth"))
        .collect();
    truths.sort();

    let (mut examined, mut evaluated) = (0usize, 0usize);
    let mut violations: Vec<String> = Vec::new();
    for truth_path in truths {
        let bin = truth_path.with_extension("");
        if !bin.exists() {
            continue;
        }
        let truth = parse_truth(&std::fs::read_to_string(&truth_path).unwrap());
        let truth_addrs: BTreeSet<u64> = truth.funcs.iter().map(|(a, _)| *a).collect();
        let declared = (truth.compiler == "watcom"
            && bin.extension().is_some_and(|x| x == "watcom-x86-32"))
        .then_some("watcom");
        let prog = if bin.extension().is_some_and(|x| x == "watcom-le") {
            analysis::analyze_le_file(&bin).expect("analyze LE ground-truth binary")
        } else {
            analysis::analyze_file_as(&bin, declared).expect("analyze ground-truth binary")
        };
        evaluated += 1;
        let ram = prog.default_space;

        // Exclusion 1, computed from the memory map — never from a name.
        let initialized: Vec<(u64, u64)> = prog
            .memory
            .blocks()
            .filter(|b| b.is_initialized())
            .map(|b| (b.start().offset, b.end().offset))
            .collect();
        let is_initialized =
            |o: u64| initialized.iter().any(|&(lo, hi)| lo <= o && o <= hi);

        for f in prog.function_manager.functions() {
            let entry = f.entry_point();
            // Exclusion 2 — see the doc comment.
            if !truth_addrs.contains(&entry.offset) || !is_initialized(entry.offset) {
                continue;
            }
            examined += 1;
            let entry_cu = prog.listing.code_unit_at(entry).is_some();
            let body = f.body();
            let uncovered = body
                .ranges()
                .flat_map(|r| r.min..=r.max)
                .filter(|&o| {
                    prog.listing.code_unit_containing(Address::new(ram, o), 16).is_none()
                })
                .count();
            if entry_cu && uncovered == 0 {
                continue;
            }
            let name = truth
                .funcs
                .iter()
                .find(|(a, _)| *a == entry.offset)
                .map(|(_, n)| n.clone())
                .unwrap_or_default();
            violations.push(format!(
                "{} @{:08x} {name}: entry_instruction={entry_cu} body={}B \
                 bytes_with_no_code_unit={uncovered}",
                bin.file_name().unwrap().to_string_lossy(),
                entry.offset,
                body.num_addresses(),
            ));
        }
    }
    assert!(evaluated > 0, "no ground-truth binaries evaluated (corpus missing?)");
    assert!(
        examined > 0,
        "the population is empty — this gate would pass vacuously; check the truth filter"
    );
    assert!(
        violations.is_empty(),
        "{} recovered ground-truth function(s) of {examined} have bytes that were never \
         disassembled into the listing:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
    eprintln!(
        "listing gate: {examined} recovered ground-truth functions across {evaluated} binaries, \
         every body fully in the listing"
    );
}
