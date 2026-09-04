//! Scheduler fixed-point census (experiment, 2026-09-04): for every manifest function, how many
//! of its windows the scheduler model (`recompile::watsched`) predicts would MOVE while the
//! original sits in program order. A function compiled with `-or` is a fixed point of its own
//! scheduler window by window; one compiled without it is not. Prints one TSV row per function:
//! idx, va, insns, windows (>= 3 insns), non-fixed-point windows, max atoms displaced.
use mosura::recompile::insn::{normalize, NoReloc, SemArg};
use mosura::recompile::watsched::{schedule, windows};
use std::collections::HashSet;

fn main() {
    let manifest = std::env::args().nth(1).expect("manifest tsv");
    let text = std::fs::read_to_string(&manifest).expect("read manifest");
    let none: HashSet<u64> = HashSet::new();
    println!("idx\tva\tinsns\twindows\tmoving\tmax_moved\tunexplained");
    for line in text.lines() {
        let p: Vec<&str> = line.split('\t').collect();
        if p.len() < 9 || u64::from_str_radix(p[1], 16).is_err() {
            continue;
        }
        let va = u64::from_str_radix(p[1], 16).unwrap();
        let bytes: Vec<u8> = (0..p[8].len() / 2).filter_map(|i| u8::from_str_radix(&p[8][i * 2..i * 2 + 2], 16).ok()).collect();
        let insns = normalize("x86:LE:32:default", &bytes, va, &NoReloc).unwrap_or_default();
        let mut nwin = 0usize;
        let mut moving = 0usize;
        let mut max_moved = 0usize;
        // windows with SMALL predicted motion (the volatile model's confidence band) that no
        // absolute store in the window could explain as a barrier: the scheduler's residue
        let mut unexplained = 0usize;
        for w in windows(&insns) {
            if w.len() < 3 {
                continue;
            }
            nwin += 1;
            let Some(base) = schedule(&insns[w.clone()], &none) else { continue };
            let moved = base.iter().enumerate().filter(|&(pos, &orig)| base[..pos].iter().any(|&o| o > orig) || base[pos + 1..].iter().any(|&o| o < orig)).count();
            if moved > 0 {
                moving += 1;
                max_moved = max_moved.max(moved);
                let has_store = insns[w.clone()].iter().flat_map(|x| x.sem.iter()).any(|op| matches!(op.out, Some(SemArg::Mem(..))));
                if moved <= 3 && !has_store {
                    unexplained += 1;
                }
            }
        }
        println!("{}\t{:08x}\t{}\t{}\t{}\t{}\t{}", p[0], va, insns.len(), nwin, moving, max_moved, unexplained);
    }
}
