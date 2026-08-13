//! Attribute every recompiled function's difference from the original, and census the causes.
//!
//! This is the instrument the byte-exact work runs on. It replaces "what percentage of bytes
//! agree" — a number that cannot distinguish a one-register miss from hand-written assembler —
//! with "which named thing differs, and how often across the population".
//!
//! Usage:
//!   recompile_census <binary> <manifest.tsv> <obj-dir> [--lang <id>] [--detail <idx>] [--limit n]
//!
//! The manifest supplies function identity (index, address, name, extent); the object directory
//! holds one compiled translation unit per function, named `<idx>.OBJ`. Both sides are decoded
//! with mosura's own SLEIGH engine, so nothing here is x86-specific.
use mosura::analysis;
use mosura::decompile::space::Address;
use mosura::recompile::insn::{NoReloc, NormInsn, normalize};
use mosura::recompile::{compare, load_object_function, DivergenceClass};
use std::collections::BTreeMap;
use std::path::Path;

struct Row {
    idx: String,
    va: u64,
    name: String,
    len: usize,
}

fn main() {
    let mut args = std::env::args().skip(1);
    let bin = args.next().expect("usage: recompile_census <binary> <manifest> <objdir>");
    let manifest = args.next().expect("manifest");
    let objdir = args.next().expect("objdir");
    let mut lang = "x86:LE:32:default".to_string();
    let mut detail: Option<String> = None;
    let mut limit = usize::MAX;
    let mut out_path: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--lang" => lang = args.next().expect("--lang <id>"),
            "--detail" => detail = Some(args.next().expect("--detail <idx>")),
            "--limit" => limit = args.next().expect("--limit n").parse().expect("n"),
            "--out" => out_path = Some(args.next().expect("--out <path>")),
            other => panic!("unknown argument {other}"),
        }
    }

    let rows = read_manifest(&manifest);
    // The LOADER, not the analyzer: this tool needs the fixup-applied image bytes and nothing
    // else, and the full auto-analysis pipeline costs a minute per run — which would put a
    // 60-second floor under an instrument meant to be run constantly.
    let data = std::fs::read(Path::new(&bin)).expect("read binary");
    let prog = analysis::loader::load_le(&data).expect("load binary");
    let space = prog.default_space;

    // Every symbol mosura emits is named after the address it was recovered from, so the naming
    // convention *is* the symbol table. A name that does not encode an address stays unresolved
    // and is reported rather than guessed at.
    let resolver = |sym: &str| -> Option<u64> {
        let s = sym.trim_start_matches('_').trim_end_matches('_');
        let hex = s
            .strip_prefix("func_0x")
            .or_else(|| s.strip_prefix("FUN_"))
            .or_else(|| s.rsplit_once("Ram").map(|(_, h)| h))
            .or_else(|| s.rsplit_once("_0x").map(|(_, h)| h))?;
        let hex: String = hex.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() < 4 {
            return None;
        }
        u64::from_str_radix(&hex, 16).ok()
    };

    let mut census: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut primary_census: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut class_totals: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut sim_sum = 0.0;
    let mut scored = 0usize;
    let mut out = String::from("idx\tva\tname\tverdict\tprimary\tsim\torig_insns\tcand_insns\tequal\tclasses\n");

    for row in rows.iter().take(limit) {
        if let Some(d) = &detail {
            if &row.idx != d {
                continue;
            }
        }
        let objp = format!("{objdir}/{}.OBJ", row.idx);
        let Ok(data) = std::fs::read(&objp) else {
            *census.entry("NO_OBJECT").or_default() += 1;
            out.push_str(&format!("{}\t{:08x}\t{}\tNO_OBJECT\t\t\t\t\t\t\n", row.idx, row.va, row.name));
            continue;
        };
        let cand = match load_object_function(&data, &row.name, row.va, &resolver) {
            Ok(c) => c,
            Err(e) => {
                *census.entry("OBJ_ERROR").or_default() += 1;
                out.push_str(&format!("{}\t{:08x}\t{}\tOBJ_ERROR\t{e}\t\t\t\t\t\n", row.idx, row.va, row.name));
                continue;
            }
        };

        let mut obytes = Vec::with_capacity(row.len);
        for i in 0..row.len {
            match prog.memory.byte_at(Address::new(space, row.va + i as u64)) {
                Some(b) => obytes.push(b),
                None => break,
            }
        }
        let orig = match normalize(&lang, &obytes, row.va, &NoReloc) {
            Ok(v) => trim_padding(v),
            Err(e) => panic!("{e}"),
        };
        let cbytes = cand.relinked_bytes();
        let cnorm = match normalize(&lang, &cbytes, row.va, &cand) {
            Ok(v) => trim_padding(v),
            Err(e) => panic!("{e}"),
        };

        let diff = compare(&orig, &cnorm);
        *census.entry(diff.verdict.as_str()).or_default() += 1;
        if let Some(p) = diff.primary {
            *primary_census.entry(p.as_str()).or_default() += 1;
        }
        for (c, n) in &diff.class_counts {
            if *c != DivergenceClass::Equal {
                *class_totals.entry(c.as_str()).or_default() += n;
            }
        }
        sim_sum += diff.similarity;
        scored += 1;

        let classes = diff
            .class_counts
            .iter()
            .filter(|(c, _)| **c != DivergenceClass::Equal)
            .map(|(c, n)| format!("{}={}", c.as_str(), n))
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&format!(
            "{}\t{:08x}\t{}\t{}\t{}\t{:.3}\t{}\t{}\t{}\t{}\n",
            row.idx,
            row.va,
            row.name,
            diff.verdict.as_str(),
            diff.primary.map(|p| p.as_str()).unwrap_or(""),
            diff.similarity,
            diff.orig_insns,
            diff.cand_insns,
            diff.equal_insns,
            classes
        ));

        if detail.is_some() {
            print_detail(&row.name, &orig, &cnorm, &diff, &cand);
        }
    }

    if detail.is_none() {
        eprintln!("\n=== verdicts ({scored} scored) ===");
        for (k, v) in census.iter() {
            eprintln!("{v:6}  {k}");
        }
        eprintln!("\n=== dominant cause per function ===");
        let mut p: Vec<_> = primary_census.iter().collect();
        p.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
        for (k, v) in p {
            eprintln!("{v:6}  {k}");
        }
        eprintln!("\n=== total divergences by class ===");
        let mut c: Vec<_> = class_totals.iter().collect();
        c.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
        for (k, v) in c {
            eprintln!("{v:8}  {k}");
        }
        eprintln!("\nmean instruction similarity: {:.4}", sim_sum / scored.max(1) as f64);
    }
    if let Some(p) = out_path {
        std::fs::write(&p, out).expect("write");
        eprintln!("rows written to {p}");
    }
}

/// Drop the alignment padding a linker leaves between functions.
///
/// The extent a function is recorded with runs to the next function's entry, which includes any
/// padding. At byte level that has to be pattern-matched and guessed at; at instruction level it
/// is simply the run of no-ops after the last control transfer, which is exactly what padding is.
fn trim_padding(mut v: Vec<NormInsn>) -> Vec<NormInsn> {
    while let Some(last) = v.last() {
        if is_padding(last) && v.len() > 1 {
            v.pop();
        } else {
            break;
        }
    }
    v
}

fn is_padding(i: &NormInsn) -> bool {
    i.is_nop()
}

fn print_detail(
    name: &str,
    orig: &[NormInsn],
    cand: &[NormInsn],
    diff: &mosura::recompile::FnDiff,
    c: &mosura::recompile::Candidate,
) {
    println!("=== {name} : {} ===", diff.verdict.as_str());
    println!(
        "orig {} insns / {} bytes    cand {} insns / {} bytes    similarity {:.3}",
        diff.orig_insns, diff.orig_bytes, diff.cand_insns, diff.cand_bytes, diff.similarity
    );
    if !c.fixups.is_empty() {
        println!("-- relocations resolved --");
        for f in &c.fixups {
            println!(
                "   +{:#05x} {:>2}b {}{} -> {}",
                f.offset,
                f.width,
                f.symbol.clone().unwrap_or_else(|| "<segment>".into()),
                if f.self_relative { " (rel)" } else { "" },
                f.resolved.map(|a| format!("{a:#x}")).unwrap_or_else(|| "UNRESOLVED".into())
            );
        }
    }
    if !c.unresolved.is_empty() {
        println!("-- UNRESOLVED symbols: {:?}", c.unresolved);
    }
    println!("-- alignment --");
    for op in &diff.ops {
        match op {
            mosura::recompile::AlignOp::Pair { oi, ci, class } => {
                let mark = if *class == DivergenceClass::Equal { " " } else { "~" };
                println!(
                    "{mark} {:08x}  {:<38} | {:<38} {}",
                    orig[*oi].addr,
                    orig[*oi].text,
                    cand[*ci].text,
                    if *class == DivergenceClass::Equal { "".into() } else { format!("[{}]", class.as_str()) }
                );
            }
            mosura::recompile::AlignOp::OrigOnly { oi } => {
                println!("- {:08x}  {:<38} | {:<38} [missing]", orig[*oi].addr, orig[*oi].text, "");
            }
            mosura::recompile::AlignOp::CandOnly { ci } => {
                println!("+ {:08x}  {:<38} | {:<38} [extra]", cand[*ci].addr, "", cand[*ci].text);
            }
        }
    }
    if !diff.reg_subst.is_empty() {
        println!(
            "-- register substitution ({}): {:?}",
            if diff.reg_subst_consistent { "consistent" } else { "INCONSISTENT" },
            diff.reg_subst
        );
    }
}

fn read_manifest(path: &str) -> Vec<Row> {
    let text = std::fs::read_to_string(path).expect("manifest");
    let mut rows = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 5 || f[0] == "idx" {
            continue;
        }
        let Ok(va) = u64::from_str_radix(f[1], 16) else { continue };
        let Ok(len) = f[4].parse::<usize>() else { continue };
        rows.push(Row { idx: f[0].to_string(), va, name: f[2].to_string(), len });
    }
    rows
}
