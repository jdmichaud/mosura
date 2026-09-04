//! Split-store census (experiment, 2026-09-04): for every manifest function, every constant
//! dword store to a global in the original (`MOV dword ptr [g],imm`, not a window leader) —
//! the form Open Watcom's `LdStAlloc` splits into `MOV r,imm ; MOV [g],r` ahead of the
//! scheduler and `LdStCompress` merges back only if the pair stayed adjacent. The scheduler
//! model (`recompile::watsched::schedule`) is asked whether it would separate the pair; a
//! separated pair whose original shows the merged form is evidence the function was compiled
//! without `-or`. One TSV row per function: idx, va, stores, separated, first separated pc.
use mosura::recompile::insn::{normalize, NoReloc, NormInsn, SemArg};
use mosura::recompile::watsched::{schedule, windows};
use std::collections::HashSet;

fn lift(bytes: &[u8], addr: u64) -> Vec<NormInsn> {
    normalize("x86:LE:32:default", bytes, addr, &NoReloc).unwrap_or_default()
}

fn main() {
    let manifest = std::env::args().nth(1).expect("manifest tsv");
    // optional: only these manifest indices (comma-separated), for a traced run
    let only: Vec<String> = std::env::args().nth(2).map(|s| s.split(',').map(|x| x.to_string()).collect()).unwrap_or_default();
    let text = std::fs::read_to_string(&manifest).expect("read manifest");
    let none: HashSet<u64> = HashSet::new();
    // (register offset, MOV r,imm32 opcode, MOV [abs],r ModRM) — the rover order is not
    // known here; prefer a callee-saved register the window never names, then any unnamed one
    let regs: [(u64, u8, u8, &str); 6] = [(0xc, 0xbb, 0x1d, "EBX"), (0x18, 0xbe, 0x35, "ESI"), (0x1c, 0xbf, 0x3d, "EDI"), (0x0, 0xb8, 0x05, "EAX"), (0x4, 0xb9, 0x0d, "ECX"), (0x8, 0xba, 0x15, "EDX")];
    println!("idx\tva\tstores\tseparated\tfirst_pc\treg\tload_swaps\tswap_pc\trule");
    for line in text.lines() {
        let p: Vec<&str> = line.split('\t').collect();
        if p.len() < 9 || u64::from_str_radix(p[1], 16).is_err() {
            continue;
        }
        if !only.is_empty() && !only.iter().any(|o| o == p[0]) {
            continue;
        }
        let va = u64::from_str_radix(p[1], 16).unwrap();
        let bytes: Vec<u8> = (0..p[8].len() / 2).filter_map(|i| u8::from_str_radix(&p[8][i * 2..i * 2 + 2], 16).ok()).collect();
        let insns = lift(&bytes, va);
        let mut stores = 0usize;
        let mut separated = 0usize;
        let mut first: Option<(u64, &str)> = None;
        // windows whose predicted order is exactly a transposition of two ADJACENT register
        // loads (`MOV r,[mem]` pairs the reorderer swaps by its InsStallable tie-break) while
        // the original keeps program order
        let mut load_swaps = 0usize;
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
                    if swapped.is_some() && others_ok {
                        load_swaps += 1;
                        if swap_pc.is_none() {
                            swap_pc = Some(win[swapped.unwrap()].addr);
                        }
                    }
                }
            }
            let win = &insns[w.clone()];
            if !only.is_empty() {
                let order = schedule(win, &none);
                eprintln!("[window {:#x}..] {:?}", win[0].addr, win.iter().map(|x| x.text.as_str()).collect::<Vec<_>>());
                eprintln!("   predicted order: {:?}", order);
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
                let mut b = Vec::new();
                b.push(op_imm);
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
                let pl = order.iter().position(|&o| o == k);
                let ps = order.iter().position(|&o| o == k + 1);
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
        let rule = mosura::recompile::buildconfig::unscheduled_load_pair(&insns);
        println!("{}\t{:08x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}", p[0], va, stores, separated, first.map_or(String::new(), |f| format!("{:#x}", f.0)), first.map_or("", |f| f.1), load_swaps, swap_pc.map_or(String::new(), |a| format!("{a:#x}")), rule);
    }
}
