//! IR-parity gate (port-plan.md §3). Compares the faithful `decompile` pipeline's IR
//! against Ghidra's own IR (`oracle/capture --ir <action>`, which runs Ghidra's pipeline
//! to the start of a named action and dumps `Funcdata::printRaw`).
//!
//! P0 establishes the plumbing and a structural check that mosura's lifted/loaded
//! Funcdata covers exactly the instruction addresses Ghidra's pre-heritage IR does. As
//! each phase lands (P1 heritage → …), this file grows a normalized op-graph diff at that
//! phase's breakpoint; that diff is the gate for moving on.
//!
//! Skips when the x86-64 `.sla` or the `oracle/capture` binary isn't present.

use std::collections::BTreeSet;

use mosura::decompile::build::raw_funcdata_flow;
use mosura::sleigh::engine::Spec;
use mosura::{datatest, paths};

fn x86_64() -> Option<(&'static Spec, Vec<u32>)> {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        eprintln!("skip: {} not found", sla.display());
        return None;
    }
    let spec = mosura::speccache::get(&sla)?;
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    Some((spec, ctx))
}

/// Run `oracle/capture <ghidra> <fixture> --ir <action>` (through the disk cache under
/// `build/oracle-cache/`) and return Ghidra's IR dump.
fn ghidra_ir(fixture: &std::path::Path, action: &str) -> Option<String> {
    let r = mosura::oraclecache::capture(fixture, &["--ir", action]);
    if r.is_none() {
        eprintln!("skip: oracle/capture not built");
    }
    r
}

/// The set of instruction addresses appearing in a `printRaw`-style dump — lines of the
/// form `0x<addr>:<uniq>:\t…`. Robust to Ghidra-vs-mosura formatting (register names,
/// operator rendering, zero-padding) since it keys only on the parsed instruction address.
fn instr_addrs(dump: &str) -> BTreeSet<u64> {
    dump.lines()
        .filter_map(|l| {
            let l = l.trim_start();
            let rest = l.strip_prefix("0x")?;
            let (hex, after) = rest.split_once(':')?;
            // require a second `:` (the uniq field) to avoid matching block-range lines
            after.split_once(':')?;
            u64::from_str_radix(hex, 16).ok()
        })
        .collect()
}

/// Ghidra's `printRaw` block headers: `Basic Block N 0x<start>-0x<stop>`. Returns the
/// sorted `(start, stop)` instruction ranges (with multiplicity).
fn ghidra_block_ranges(dump: &str) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = dump
        .lines()
        .filter_map(|l| {
            let rest = l.trim_start().strip_prefix("Basic Block ")?;
            let range = rest.split_whitespace().nth(1)?; // "0xSTART-0xSTOP"
            let (a, b) = range.split_once('-')?;
            let a = u64::from_str_radix(a.trim().strip_prefix("0x")?, 16).ok()?;
            let b = u64::from_str_radix(b.trim().strip_prefix("0x")?, 16).ok()?;
            Some((a, b))
        })
        .collect();
    v.sort_unstable();
    v
}

/// mosura's block ranges for a fixture, sorted, after building the CFG.
fn mosura_block_ranges(spec: &Spec, ctx: &[u32], fixture: &std::path::Path) -> Vec<(u64, u64)> {
    let dt = datatest::parse_file(fixture).expect("fixture");
    let mut f = raw_funcdata_flow(spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, ctx);
    mosura::decompile::cfg::build_cfg(&mut f);
    let mut got: Vec<(u64, u64)> = (0..f.num_blocks() as u32)
        .filter_map(|b| f.block_range(mosura::decompile::BlockId(b)))
        .collect();
    got.sort_unstable();
    got
}

fn fixture_path(name: &str) -> std::path::PathBuf {
    if name == "x86_64_sem" {
        paths::oracle_fixtures_dir().join("x86_64_sem.xml")
    } else {
        paths::datatests_dir().join(format!("{name}.xml"))
    }
}

#[test]
fn cfg_block_ranges_match_ghidra() {
    let Some((spec, ctx)) = x86_64() else { return };
    // Verified-aligned set: mosura's reachable instruction stream agrees with Ghidra's,
    // so the CFG *cutting* logic (leaders, edges, reachability prune) must reproduce
    // Ghidra's block ranges exactly. Regressions here are real cutting bugs.
    for name in ["x86_64_sem", "elseif"] {
        let fixture = fixture_path(name);
        if !fixture.exists() {
            continue;
        }
        let Some(ghidra) = ghidra_ir(&fixture, "heritage") else { return };
        let expected = ghidra_block_ranges(&ghidra);
        if expected.is_empty() {
            continue;
        }
        assert_eq!(mosura_block_ranges(&spec, &ctx, &fixture), expected, "block ranges differ for {name}");
    }
}

/// Survey (non-failing): which functions' CFGs match Ghidra and which still diverge. The
/// divergences are *instruction-stream* differences (mosura's lifter computes a different
/// jump target for one condconst instruction; ifswitch's switch case bodies are only
/// reachable once the jump table is resolved in P7) — not CFG-cutting bugs, so they're
/// catalogued rather than gated on.
#[test]
fn cfg_survey_instruction_stream_gap() {
    let Some((spec, ctx)) = x86_64() else { return };
    let names = [
        "x86_64_sem", "elseif", "condconst", "boolless", "twodim", "threedim", "ifswitch",
    ];
    let (mut matched, mut needs_flow) = (Vec::new(), Vec::new());
    for name in names {
        let fixture = fixture_path(name);
        if !fixture.exists() {
            continue;
        }
        let Some(ghidra) = ghidra_ir(&fixture, "heritage") else { return };
        let expected = ghidra_block_ranges(&ghidra);
        if expected.is_empty() {
            continue;
        }
        if mosura_block_ranges(&spec, &ctx, &fixture) == expected {
            matched.push(name);
        } else {
            needs_flow.push(name);
        }
    }
    eprintln!("CFG matches Ghidra: {matched:?}");
    eprintln!("instruction-stream divergence (lifter target / P7 jump-table): {needs_flow:?}");
    assert!(!matched.is_empty(), "no CFGs matched Ghidra");
}

/// Build a function all the way through heritage (raw load → CFG → dominators → SSA).
fn heritaged(spec: &Spec, ctx: &[u32], fixture: &std::path::Path) -> mosura::decompile::Funcdata {
    let dt = datatest::parse_file(fixture).expect("fixture");
    let mut f = raw_funcdata_flow(spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, ctx);
    mosura::decompile::cfg::build_cfg(&mut f);
    let dom = mosura::decompile::dominator::compute(&f);
    mosura::decompile::heritage::heritage(&mut f, &dom);
    f
}

#[test]
fn heritage_produces_valid_ssa() {
    use mosura::decompile::{OpCode, OpId};
    let Some((spec, ctx)) = x86_64() else { return };

    for name in ["x86_64_sem", "elseif", "twodim", "threedim"] {
        let fixture = fixture_path(name);
        if !fixture.exists() {
            continue;
        }
        let f = heritaged(&spec, &ctx, &fixture);

        // (a) every heritaged read links to a definition or a function input — no free
        //     varnodes are referenced (branch/call destinations and constants excepted).
        for b in 0..f.num_blocks() as u32 {
            for &op in &f.block(mosura::decompile::BlockId(b)).ops {
                let o = f.op(op);
                let is_dest_annot = matches!(
                    o.code(),
                    OpCode::Branch | OpCode::Cbranch | OpCode::Branchind
                        | OpCode::Call | OpCode::Callind | OpCode::Callother | OpCode::Return
                );
                for (slot, &vid) in o.inrefs.iter().enumerate() {
                    let vn = f.vn(vid);
                    if vn.is_constant() || (slot == 0 && is_dest_annot) {
                        continue;
                    }
                    assert!(
                        vn.is_written() || vn.is_input(),
                        "{name}: op {op:?} slot {slot} reads an unlinked free varnode"
                    );
                }
            }
        }

        // (b) single assignment: every written varnode's def actually outputs it.
        for i in 0..f.num_varnodes() as u32 {
            let vid = mosura::decompile::VarnodeId(i);
            if f.vn(vid).is_written() {
                let def = f.vn(vid).def.expect("written ⇒ has def");
                assert_eq!(f.op(def).output, Some(vid), "{name}: def/output mismatch");
            }
        }

        // (c) refinement: for the clean-overlap functions, no sub-register read is left
        //     mis-linked as a function input (normalizeReadSize turns it into SUBPIECE of
        //     a wider def). twodim/threedim's single gap each is fully closed.
        if name == "twodim" || name == "threedim" {
            use std::collections::{BTreeMap, BTreeSet};
            let mut written: BTreeMap<(u32, u64), BTreeSet<u32>> = BTreeMap::new();
            for i in 0..f.num_varnodes() as u32 {
                let vn = f.vn(mosura::decompile::VarnodeId(i));
                if vn.is_written() {
                    written.entry((vn.loc.space.0, vn.loc.offset)).or_default().insert(vn.size);
                }
            }
            let gap = (0..f.num_varnodes() as u32).filter(|&i| {
                let vn = f.vn(mosura::decompile::VarnodeId(i));
                vn.is_input()
                    && written.get(&(vn.loc.space.0, vn.loc.offset)).is_some_and(|s| s.iter().any(|&x| x != vn.size))
            }).count();
            assert_eq!(gap, 0, "{name}: read-size refinement should leave no overlap-gap inputs");
        }

        // (d) phi shape: a single-block function needs no phis; a branchy one does, and
        //     every MULTIEQUAL has one input per predecessor of its block.
        let count_phi = |f: &mosura::decompile::Funcdata| {
            (0..f.num_ops() as u32).filter(|&i| f.op(OpId(i)).code() == OpCode::Multiequal).count()
        };
        if f.num_blocks() == 1 {
            assert_eq!(count_phi(&f), 0, "{name}: single block must have no MULTIEQUAL");
        }
        for b in 0..f.num_blocks() as u32 {
            let blk = mosura::decompile::BlockId(b);
            let npreds = f.block(blk).in_edges.len();
            for &op in &f.block(blk).ops {
                if f.op(op).code() == OpCode::Multiequal {
                    assert_eq!(f.op(op).num_inputs(), npreds, "{name}: phi arity ≠ #preds");
                }
            }
        }
    }
}

#[test]
fn rule_pool_folds_constants() {
    use mosura::decompile::action::{Action, ActionPool};
    use mosura::decompile::rules::{eval_const, RuleCollectTerms, RuleConstFold, RuleEarlyRemoval, RuleIdentityEl, RulePropagateCopy, RuleTermOrder, RuleTrivialArith, RuleTrivialShift};
    use mosura::decompile::{OpCode, OpId};
    let Some((spec, ctx)) = x86_64() else { return };

    for name in ["x86_64_sem", "twodim", "threedim", "elseif"] {
        let fixture = fixture_path(name);
        if !fixture.exists() {
            continue;
        }
        let mut f = heritaged(&spec, &ctx, &fixture);
        let raw_ops = (0..f.num_ops() as u32).filter(|&i| !f.op(OpId(i)).is_dead()).count();

        // RuleEarlyRemoval reaps the ops the faithful N-ary RuleCollectTerms orphans when it
        // extracts a combined-coefficient INT_MULT (Ghidra creates the new op the same way).
        let mut pool = ActionPool::new("simplify").with(RuleEarlyRemoval).with(RuleTermOrder).with(RuleConstFold).with(RuleCollectTerms)
            .with(RuleTrivialArith).with(RuleIdentityEl).with(RuleTrivialShift).with(RulePropagateCopy);
        pool.apply(&mut f);

        // Completeness: no live *non-COPY* op with all-constant inputs and a foldable opcode
        // remains (constant folding ran to fixpoint). Ghidra's `RuleCollapseConstants` collapses
        // each such op to `out = COPY const` and leaves that COPY for RulePropagateCopy/dead-code,
        // so a surviving `COPY const` is the collapsed result, not an unfolded op.
        for i in 0..f.num_ops() as u32 {
            let op = OpId(i);
            if f.op(op).is_dead() || f.op(op).output.is_none() || f.op(op).num_inputs() == 0 {
                continue;
            }
            if f.op(op).code() == OpCode::Copy {
                continue;
            }
            let all_const = f.op(op).inrefs.iter().all(|&v| f.vn(v).is_constant());
            if all_const {
                let inputs: Vec<(u64, u32)> =
                    f.op(op).inrefs.iter().map(|&v| (f.vn(v).constant_value(), f.vn(v).size)).collect();
                let out_size = f.vn(f.op(op).output.unwrap()).size;
                assert!(
                    eval_const(f.op(op).code(), &inputs, out_size).is_none(),
                    "{name}: a foldable all-constant op survived the pool"
                );
            }
        }

        // Progress: the pool removed at least one op (folded/identity), where applicable.
        let live_ops = (0..f.num_ops() as u32).filter(|&i| !f.op(OpId(i)).is_dead()).count();
        assert!(live_ops <= raw_ops, "{name}: pool must not add live ops");
    }
}

#[test]
fn merge_groups_phi_versions_into_variables() {
    use mosura::decompile::merge::merge;
    use mosura::decompile::{pipeline, OpCode};
    let Some((spec, ctx)) = x86_64() else { return };

    for name in ["threedim", "elseif", "twodim"] {
        let fixture = fixture_path(name);
        if !fixture.exists() {
            continue;
        }
        let dt = datatest::parse_file(&fixture).expect("fixture");
        let mut f = raw_funcdata_flow(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
        pipeline::decompile(&mut f);
        let mut h = merge(&f);

        let mut had_phi = false;
        let mut live_vns: BTreeSet<mosura::decompile::VarnodeId> = BTreeSet::new();
        for b in 0..f.num_blocks() as u32 {
            for &op in &f.block(mosura::decompile::BlockId(b)).ops {
                let o = f.op(op);
                live_vns.extend(o.output);
                live_vns.extend(o.inrefs.iter().copied());
                if o.code() == OpCode::Multiequal {
                    had_phi = true;
                    let out = o.output.unwrap();
                    // Ghidra's `Merge::mergeOp` gates each phi-input merge on `mergeTestRequired`, and
                    // when the merge is forbidden it TRIMS the input (an inserted COPY) instead of
                    // merging — so a function input dragged into address-tied storage (elseif: `EDI`
                    // into the `s_f4` stack slot) stays a DISTINCT HighVariable, matching Ghidra, which
                    // merges a COPY of the param, not the param itself. Skip those required-trim inputs.
                    let stack = f.spaces.by_name("stack");
                    let tied_like = |v: mosura::decompile::VarnodeId| {
                        f.vn(v).is_addrtied() || Some(f.vn(v).loc.space) == stack
                    };
                    for &inv in &o.inrefs {
                        if f.vn(inv).is_constant() {
                            continue;
                        }
                        if f.vn(inv).is_input() && tied_like(out) && !tied_like(inv) {
                            continue; // required-trim: an input is not dragged into address-tied storage
                        }
                        assert!(h.same(out, inv), "{name}: phi output and input must be one variable");
                    }
                }
            }
        }

        if had_phi {
            let nonconst: Vec<_> = live_vns.iter().copied().filter(|&v| !f.vn(v).is_constant()).collect();
            assert!(
                h.count(nonconst.iter().copied()) < nonconst.len(),
                "{name}: merging phi versions must reduce the variable count"
            );
        }
    }
}

#[test]
fn merged_variables_have_no_internal_interference() {
    use mosura::decompile::cover::all_covers;
    use mosura::decompile::merge::merge;
    use mosura::decompile::{pipeline, OpCode, VarnodeId};
    use std::collections::HashMap;
    let Some((spec, ctx)) = x86_64() else { return };

    for name in ["x86_64_sem", "twodim", "threedim", "elseif"] {
        let fixture = fixture_path(name);
        if !fixture.exists() {
            continue;
        }
        let dt = datatest::parse_file(&fixture).expect("fixture");
        let mut f = raw_funcdata_flow(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
        pipeline::decompile(&mut f);
        let mut h = merge(&f);
        let covers = all_covers(&f);

        // group covered varnodes by their HighVariable
        let mut by_hv: HashMap<u32, Vec<VarnodeId>> = HashMap::new();
        for &v in covers.keys() {
            by_hv.entry(h.high(v)).or_default().push(v);
        }
        // correctness: within one variable, no two SSA versions are live at once — that
        // is exactly the property that lets them share one storage slot. (The cover logic
        // itself is ground-truth-tested in cover.rs.) Copy shadows are exempt, as in Ghidra's
        // own invariant (`Merge::verifyHighCovers`, merge.cc: "no internal intersections …
        // unless one is a COPY shadow of the other") — two COPYs of one value overlap
        // harmlessly because they carry the same bits (the mergeOp trim COPYs).
        for members in by_hv.values() {
            for i in 0..members.len() {
                for j in (i + 1)..members.len() {
                    assert!(
                        !covers[&members[i]].intersects(&covers[&members[j]])
                            || mosura::decompile::merge::copy_shadow(&f, members[i], members[j]),
                        "{name}: two SSA versions of one variable are simultaneously live"
                    );
                }
            }
        }
        // and merging actually collapsed versions: fewer variables than covered varnodes — but
        // only where there are redundant versions to collapse. A straight-line function whose SSA
        // SubVariableFlow has already reduced to minimal form has nothing to merge: with
        // RuleSubvarZext narrowing x86_64_sem's return to int4 (matching Ghidra `return EAX`),
        // by_hv == covers == 11, every covered varnode its own variable. Gate the collapse check on
        // the function having a phi (mergeable versions), mirroring the `if had_phi` guard on the
        // phi-merge test above; the interference invariant stays unconditional.
        let had_phi = (0..f.num_blocks() as u32).any(|b| {
            f.block(mosura::decompile::BlockId(b))
                .ops
                .iter()
                .any(|&op| f.op(op).code() == OpCode::Multiequal)
        });
        if had_phi {
            assert!(by_hv.len() < covers.len(), "{name}: merge should collapse versions");
        }
    }
}

#[test]
fn structuring_collapses_reducible_cfgs() {
    use mosura::decompile::structure::structure;
    let Some((spec, ctx)) = x86_64() else { return };
    let (mut full, mut stalled) = (Vec::new(), Vec::new());
    for name in ["x86_64_sem", "twodim", "threedim", "elseif", "condconst", "boolless"] {
        let fixture = fixture_path(name);
        if !fixture.exists() {
            continue;
        }
        let dt = datatest::parse_file(&fixture).expect("fixture");
        let mut f = raw_funcdata_flow(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
        mosura::decompile::cfg::build_cfg(&mut f);
        let s = structure(&f);
        let active = (0..s.blocks.len()).filter(|&b| s.blocks[b].active).count();
        if active == 1 {
            full.push(name);
        } else {
            stalled.push((name, active));
        }
    }
    eprintln!("fully structured: {full:?}");
    eprintln!("stalled (need goto/switch/irreducible handling): {stalled:?}");
    assert!(full.contains(&"x86_64_sem"), "a single-block function must structure trivially");
    assert!(full.len() >= 2, "reducible CFGs should fully structure");
}

#[test]
fn stack_recovery_collapses_the_frame() {
    use mosura::decompile::{pipeline, printc::print_c, OpId};
    let Some((spec, ctx)) = x86_64() else { return };
    let dt = datatest::parse_file(&fixture_path("twodim")).expect("fixture");
    let mut f = raw_funcdata_flow(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
    pipeline::decompile(&mut f);
    // The spilled-parameter frame collapses (47 live ops without stack recovery → ~31).
    let live = (0..f.num_ops() as u32).filter(|&i| !f.op(OpId(i)).is_dead()).count();
    assert!(live <= 36, "stack recovery should collapse the frame (got {live} live ops)");
    // and the parameters now flow directly into the body
    let c = print_c(&f);
    assert!(c.contains("param_1") && c.contains("param_2"), "params should flow through:\n{c}");
    assert!(!c.contains("+ -20"), "the spilled-param stack slots should be gone:\n{c}");
}

#[test]
fn raw_ir_covers_ghidra_instruction_addresses() {
    let Some((spec, ctx)) = x86_64() else { return };
    let fixture = paths::oracle_fixtures_dir().join("x86_64_sem.xml");
    let Some(ghidra) = ghidra_ir(&fixture, "heritage") else { return };

    let dt = datatest::parse_file(&fixture).expect("fixture");
    let f = raw_funcdata_flow(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);
    let mosura = f.print_raw();

    let g = instr_addrs(&ghidra);
    let m = instr_addrs(&mosura);
    assert!(!g.is_empty(), "Ghidra IR produced no addressed ops:\n{ghidra}");
    assert!(!m.is_empty(), "mosura IR produced no addressed ops");

    // Every instruction Ghidra lifts, mosura's loader also covers (and vice versa). This
    // validates the data model + load step against Ghidra's actual pre-heritage IR.
    assert_eq!(
        m, g,
        "instruction-address coverage differs\n  mosura-only: {:x?}\n  ghidra-only: {:x?}",
        m.difference(&g).collect::<Vec<_>>(),
        g.difference(&m).collect::<Vec<_>>()
    );
}
