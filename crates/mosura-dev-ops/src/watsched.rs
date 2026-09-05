//! Two scheduler-model censuses over the current program's emission (the survey's function extents
//! and bytes), the 2026-09-04 parked lead on whether functions were compiled with `-or`.
//!
//! `dev.census.watsched` — for every emitted function, how many of its windows the scheduler model
//! (`recompile::watsched`) predicts would MOVE while the original sits in program order. A function
//! compiled with `-or` is a fixed point of its own scheduler window by window; one compiled without
//! it is not. (Was `examples/watsched_census.rs`.)
//!
//! `dev.census.split-store` — every constant dword store to a global in the original
//! (`MOV dword ptr [g],imm`, not a window leader) — the form Open Watcom's `LdStAlloc` splits into
//! `MOV r,imm ; MOV [g],r` ahead of the scheduler and `LdStCompress` merges back only if the pair
//! stayed adjacent. The model is asked whether it would separate the pair; a separated pair whose
//! original shows the merged form is evidence the function was compiled without `-or`. Also counts
//! windows whose predicted order is exactly a transposition of two adjacent register loads. With
//! `dev.only` the windows and predicted orders of the selected functions go to the log (a traced
//! run). (Was `examples/watsched_split_census.rs`.)

use std::collections::HashSet;

use mosura_api::ops::program::program_of;
use mosura_api::ops::{dispatch_inner, Cache, Op, Progress, Tier};
use mosura_api::{Error, Options, Result, Session, Table, TableBuilder};
use mosura_core::recompile::insn::{normalize, NoReloc, NormInsn, SemArg};
use mosura_core::recompile::watsched::{schedule, windows};

use crate::keys;
use crate::schemas::{SPLIT_STORE, WATSCHED_CENSUS};

const EMISSION_KEYS: &[&str] = &["program", keys::DEV_ONLY, "knobs.off", "decompile.global-scope", "decompile.proto-scope", "emit.arms-off", "emit.*"];

pub static WATSCHED: Op = Op {
    name: "dev.census.watsched",
    doc: "scheduler fixed-point census over the current program's emission: per function the windows (>= 3 insns), those the scheduler model predicts would move while the original sits in program order, the max atoms displaced, and the small unexplained motions (no store in the window)",
    since: "0.1",
    tier: Tier::Dev,
    params: EMISSION_KEYS,
    result: "watsched_census",
    cache: Cache::Transient,
    run: watsched,
};

pub static SPLIT_STORE_OP: Op = Op {
    name: "dev.census.split-store",
    doc: "split-store census over the current program's emission: per function the constant dword stores to globals, how many the scheduler model would separate from their split load (evidence of no -or), the first such pc and register, the adjacent-load transpositions, and buildconfig's unscheduled-load-pair rule; dev.only (emit indices) traces the windows to the log",
    since: "0.1",
    tier: Tier::Dev,
    params: EMISSION_KEYS,
    result: "split_store",
    cache: Cache::Transient,
    run: split_store,
};

/// The emitted functions' `(idx, va, bytes)` from the emission table's legacy row (`orig_hex`).
fn emitted(s: &mut Session, o: &Options) -> Result<Vec<(u32, u64, Vec<u8>)>> {
    let emission = dispatch_inner(s, "program.emit", o)?;
    let (c_idx, c_va, c_row) = (emission.col("idx").unwrap(), emission.col("va").unwrap(), emission.col("row").unwrap());
    let mut out = Vec::new();
    for r in 0..emission.rows() {
        let cols: Vec<&str> = emission.str(r, c_row)?.split('\t').collect();
        let hex = cols.get(8).copied().unwrap_or("");
        if hex.is_empty() {
            continue;
        }
        let bytes: Vec<u8> = (0..hex.len() / 2).filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()).collect();
        out.push((emission.u64(r, c_idx)? as u32, emission.u64(r, c_va)?, bytes));
    }
    Ok(out)
}

fn watsched(s: &mut Session, o: &Options, p: &mut dyn Progress) -> Result<Table> {
    let (_, program) = program_of(s, o)?;
    let lang = program.language_id.clone();
    let fns = emitted(s, o)?;
    let only = crate::list(o, keys::DEV_ONLY)?;
    let none: HashSet<u64> = HashSet::new();
    let mut t = TableBuilder::new(&WATSCHED_CENSUS);
    let total = fns.len() as u64;
    for (i, (idx, va, bytes)) in fns.iter().enumerate() {
        if !p.report(WATSCHED.name, i as u64, total) {
            return Err(Error::Cancelled);
        }
        if !only.is_empty() && !only.iter().any(|x| x.parse::<u32>().ok() == Some(*idx)) {
            continue;
        }
        let insns = normalize(&lang, bytes, *va, &NoReloc).unwrap_or_default();
        let (mut nwin, mut moving, mut max_moved, mut unexplained) = (0u64, 0u64, 0u64, 0u64);
        for w in windows(&insns) {
            if w.len() < 3 {
                continue;
            }
            nwin += 1;
            let Some(base) = schedule(&insns[w.clone()], &none) else { continue };
            let moved = base.iter().enumerate().filter(|&(pos, &orig)| base[..pos].iter().any(|&x| x > orig) || base[pos + 1..].iter().any(|&x| x < orig)).count() as u64;
            if moved > 0 {
                moving += 1;
                max_moved = max_moved.max(moved);
                // small predicted motion (the volatile model's confidence band) that no absolute
                // store in the window could explain as a barrier: the scheduler's residue
                let has_store = insns[w.clone()].iter().flat_map(|x| x.sem.iter()).any(|op| matches!(op.out, Some(SemArg::Mem(..))));
                if moved <= 3 && !has_store {
                    unexplained += 1;
                }
            }
        }
        t.row().u32(*idx).u64(*va).u64(insns.len() as u64).u64(nwin).u64(moving).u64(max_moved).u64(unexplained);
    }
    Ok(t.finish(false))
}

fn split_store(s: &mut Session, o: &Options, p: &mut dyn Progress) -> Result<Table> {
    let (_, program) = program_of(s, o)?;
    let lang = program.language_id.clone();
    let fns = emitted(s, o)?;
    let only = crate::list(o, keys::DEV_ONLY)?;
    let none: HashSet<u64> = HashSet::new();
    let lift = |bytes: &[u8], addr: u64| -> Vec<NormInsn> { normalize(&lang, bytes, addr, &NoReloc).unwrap_or_default() };
    // (register offset, MOV r,imm32 opcode, MOV [abs],r ModRM): the rover order is not known
    // here; prefer a callee-saved register the window never names, then any unnamed one
    let regs: [(u64, u8, u8, &str); 6] = [(0xc, 0xbb, 0x1d, "EBX"), (0x18, 0xbe, 0x35, "ESI"), (0x1c, 0xbf, 0x3d, "EDI"), (0x0, 0xb8, 0x05, "EAX"), (0x4, 0xb9, 0x0d, "ECX"), (0x8, 0xba, 0x15, "EDX")];
    let mut t = TableBuilder::new(&SPLIT_STORE);
    let total = fns.len() as u64;
    for (i, (idx, va, bytes)) in fns.iter().enumerate() {
        if !p.report(SPLIT_STORE_OP.name, i as u64, total) {
            return Err(Error::Cancelled);
        }
        if !only.is_empty() && !only.iter().any(|x| x.parse::<u32>().ok() == Some(*idx)) {
            continue;
        }
        let insns = lift(bytes, *va);
        let (mut stores, mut separated) = (0u64, 0u64);
        let mut first: Option<(u64, &str)> = None;
        // windows whose predicted order is exactly a transposition of two ADJACENT register loads
        // (`MOV r,[mem]` pairs the reorderer swaps by its InsStallable tie-break)
        let mut load_swaps = 0u64;
        let mut swap_pc: Option<u64> = None;
        for w in windows(&insns) {
            let win = &insns[w.clone()];
            if win.len() >= 2 {
                if let Some(order) = schedule(win, &none) {
                    let is_load = |x: &NormInsn| x.mnemonic == "MOV" && x.text.starts_with("MOV E") && x.text.contains("ptr [");
                    let mut k = 0usize;
                    let mut swapped: Option<usize> = None;
                    let mut others_ok = true;
                    while k < order.len() {
                        if k + 1 < order.len() && order[k] == k + 1 && order[k + 1] == k {
                            if swapped.is_some() || !(is_load(&win[k]) && is_load(&win[k + 1])) {
                                others_ok = false;
                            }
                            swapped = Some(k);
                            k += 2;
                        } else {
                            if order[k] != k {
                                others_ok = false;
                            }
                            k += 1;
                        }
                    }
                    if let (Some(sw), true) = (swapped, others_ok) {
                        load_swaps += 1;
                        if swap_pc.is_none() {
                            swap_pc = Some(win[sw].addr);
                        }
                    }
                }
            }
            if !only.is_empty() {
                let order = schedule(win, &none);
                mosura_core::debug::warn(format!("[window {:#x}..] {:?}\n   predicted order: {:?}", win[0].addr, win.iter().map(|x| x.text.as_str()).collect::<Vec<_>>(), order));
            }
            for (k, x) in win.iter().enumerate().skip(1) {
                let Some((g, imm)) = x.sem.iter().find_map(|op| match (&op.out, op.ins.as_slice()) {
                    (Some(SemArg::Mem(_, a, 4)), [SemArg::Const(c, _)]) if x.mnemonic == "MOV" => Some((*a, *c)),
                    _ => None,
                }) else { continue };
                stores += 1;
                // a register the window never names
                let named: HashSet<u64> = win.iter().flat_map(|y| y.regs.iter().map(|r| r.0 & !3)).collect();
                let Some(&(_, op_imm, modrm, name)) = regs.iter().find(|r| !named.contains(&r.0)) else { continue };
                let mut b = vec![op_imm];
                b.extend_from_slice(&(imm as u32).to_le_bytes());
                b.push(0x89);
                b.push(modrm);
                b.extend_from_slice(&(g as u32).to_le_bytes());
                let pair = lift(&b, x.addr);
                if pair.len() != 2 {
                    continue;
                }
                let mut spliced: Vec<NormInsn> = win[..k].to_vec();
                spliced.extend(pair);
                spliced.extend_from_slice(&win[k + 1..]);
                let Some(order) = schedule(&spliced, &none) else { continue };
                // positions of the load (k) and the store (k+1) in the predicted order
                let pl = order.iter().position(|&x| x == k);
                let ps = order.iter().position(|&x| x == k + 1);
                if let (Some(pl), Some(ps)) = (pl, ps) {
                    if ps != pl + 1 {
                        separated += 1;
                        if first.is_none() {
                            first = Some((x.addr, name));
                        }
                    }
                }
            }
        }
        let rule = mosura_core::recompile::buildconfig::unscheduled_load_pair(&insns);
        t.row().u32(*idx).u64(*va).u64(stores).u64(separated).u64(first.map_or(0, |f| f.0)).str(first.map_or("", |f| f.1)).u64(load_swaps).u64(swap_pc.unwrap_or(0)).str(&format!("{rule}"));
    }
    Ok(t.finish(false))
}
