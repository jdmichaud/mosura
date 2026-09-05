//! The whole-program pre-passes of a corpus emit — the byte-evidence tables built ONCE over the
//! original binary before any function is emitted, and the survey's world order. Moved verbatim
//! out of the corpus emit driver (plan WP7 P0 c4, 2026-09-05): the entry list and the
//! decompiler-independent extent bounds, the landed/prototype/consistency world split, the
//! parameter-order evidence (with its cache text form), and the corpus-wide global widths.
//! Nothing here reads a file or the environment; the front-end owns the cache FILE.

use std::collections::{HashMap, HashSet};

use crate::analysis::program::Program;
use crate::recompile::pragma::WatcomRegs;

/// The functions of the program in address order, with the two derived views the passes and the
/// emit loop key on: the sorted entry offsets, and each entry's successor (the last one's is
/// `entry + 0x1000`) — the zap checker's ORIGINAL-instruction window and the pre-passes' fallback
/// extent.
pub struct Entries {
    pub list: Vec<(u64, String)>,
    pub offs: Vec<u64>,
    pub next: HashMap<u64, u64>,
}

impl Entries {
    pub fn of(prog: &Program) -> Entries {
        let mut list: Vec<(u64, String)> =
            prog.function_manager.functions().map(|f| (f.entry.offset, f.name().to_string())).collect();
        list.sort_by_key(|e| e.0);
        let offs: Vec<u64> = list.iter().map(|e| e.0).collect();
        let next: HashMap<u64, u64> = list
            .windows(2)
            .map(|w| (w[0].0, w[1].0))
            .chain(list.last().map(|l| (l.0, l.0 + 0x1000)))
            .collect();
        Entries { list, offs, next }
    }

    /// The decompiler-independent bounds on a function's extent.
    ///
    /// `next` is the upper bound: the next function's entry, or the end of the memory block
    /// containing it, whichever comes first. Both are facts the loader established.
    ///
    /// This replaces three invented constants, each of which would have truncated silently:
    ///   * `.min(*va + 8192)` -- no function may exceed 8 KB. Nothing checks this, and a larger
    ///     function would simply have been compared against its first 8 KB and reported as a
    ///     decompiler failure. Zero functions in the subject reach it, so it never fired; it was a
    ///     tripwire waiting for a bigger subject.
    ///   * `.min(0x7_c4a0)` -- this binary's code-section end, hardcoded into a tool that is
    ///     supposed to work on any binary. Correct here by coincidence, wrong everywhere else.
    ///   * `.unwrap_or(*va + 512)` -- an arbitrary extent for the LAST function, which has no
    ///     next entry. the subject's last function is 207 bytes, so this never fired either.
    ///
    /// The block end answers the same question the constants were guessing at, and answers it
    /// for whatever binary is loaded.
    ///
    /// The second bound is the function manager's own recorded body end, when it has one.
    ///
    /// Factored out of the OK path so the DECOMPILE_FAIL row records a real extent too: a
    /// failed function still weighs its full size in any corpus-level aggregate (the global
    /// similarity), and a recorded 0 reads as "excluded" downstream.
    pub fn extent_bounds(&self, prog: &Program, va: u64) -> (u64, Option<u64>) {
        let block_end = prog.memory.block_at(crate::decompile::space::Address::new(prog.default_space, va)).map(|b| b.end().offset + 1);
        let next_entry = self.offs.iter().copied().find(|&o| o > va);
        let next = match (next_entry, block_end) {
            (Some(n), Some(b)) => n.min(b),
            (Some(n), None) => n,
            (None, Some(b)) => b,
            (None, None) => va + 1,
        };
        let body_end = prog
            .function_manager
            .function_at(crate::decompile::space::Address::new(prog.default_space, va))
            .and_then(|f| f.body().max_address())
            .map(|a| a.offset + 1);
        (next, body_end)
    }
}

/// THE PER-SITE ZAP CHECKER's world order: the LANDED (prototype-less) program is PRIMARY — every
/// function decompiles from it first, and every definition-side global map (the caller-side parm
/// network, caller_calls, param-order evidence) is built from those landed funcdatas, so the
/// prototype pass cannot leak into fallen-back TUs through OTHER functions' changed signatures
/// (measured: 12360 fell back yet drifted SAME_SHAPE because its PREPENDED caller-side pragmas came
/// from pp-shaped callee definitions). The pp decompile is a per-TU UPGRADE, adopted only when (a)
/// the scheduler model keeps every call-bearing window of the original a fixed point under the
/// candidate declarations, and (b) the function's OWN parameter signature is unchanged. The
/// surgical-injection world (memory `consistency-over-score`): the LANDED program plus the recovered
/// prototypes, consulted only through `proto_scope` — set per forced function to exactly its
/// contradicted callees, cleared after each use.
pub struct Worlds {
    pub landed: Program,
    pub pp: Option<Program>,
    pub cons: Option<Program>,
}

impl Worlds {
    /// Split the program AFTER the prototype pass filled `recovered_protos`: the clone that keeps
    /// them is the pp world, the original with them cleared is the landed world.
    pub fn split(mut prog: Program) -> Worlds {
        let prog_pp: Option<Program> = if prog.recovered_protos.is_empty() {
            None
        } else {
            let base = prog.clone(); // carries the recovered prototypes
            prog.recovered_protos = std::collections::HashMap::new(); // the landed world
            Some(base)
        };
        let prog_cons: Option<Program> = prog_pp.as_ref().map(|pp| {
            let mut c = prog.clone();
            c.recovered_protos = pp.recovered_protos.clone();
            c.proto_scope = Some(std::collections::HashSet::new()); // consult NOTHING until scoped
            c
        });
        Worlds { landed: prog, pp: prog_pp, cons: prog_cons }
    }
}

/// PARAMETER-ORDER EVIDENCE, a pre-pass over the ORIGINAL bytes (docs/byte-exact-families.md, the
/// permutation family). The compiler materializes register arguments in REVERSE declared order, so
/// the setup sequence at each original call site is a readout of the parameter order its source
/// declared — a PER-SITE recovered choice our slot-order rendering gets wrong wherever the source's
/// order was not storage order. Per site, not per callee: different TUs may carry different
/// declaration orders for one callee, because the pragma and the permutation are emitted together
/// per TU. Callees whose own recovered storage is nondefault are EXCLUDED: their callers get the
/// contract pragma from the caller-side post-pass, one pragma per callee per TU, and the two
/// mechanisms must not both claim it. The exclusion needs each such callee's decompile.
///
/// The evidence is a pure function of the ORIGINAL binary and the code that reads it, so the
/// front-end caches it beside the manifest keyed by the emit stamp ([`Self::render`] /
/// [`Self::parse`]): a `--only` probe at the same stamp loads in milliseconds instead of paying the
/// minutes of the exclusion set's mini-decompiles.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParamOrders {
    /// call-site address → the recovered declaration order (argument-register offsets)
    pub site_orders: HashMap<u64, Vec<u64>>,
    /// callees whose own storage is nondefault (or that did not decompile)
    pub excluded: HashSet<u64>,
    /// every callee some site claims (the upgrade gate's network), excluded ones included
    pub networked: HashSet<u64>,
}

impl ParamOrders {
    /// The cache text: `<site>\t<reg,reg,..>` rows, `X\t<va>` excluded callees, `C\t<va>`
    /// order-claimed callees (all hex).
    pub fn parse(s: &str) -> ParamOrders {
    let mut m = std::collections::HashMap::new();
    let mut ex = std::collections::HashSet::new();
    let mut net = std::collections::HashSet::new();
    for line in s.lines() {
        let mut it = line.split('\t');
        match (it.next(), it.next()) {
            (Some("X"), Some(va)) => {
                if let Ok(v) = u64::from_str_radix(va, 16) {
                    ex.insert(v);
                    net.insert(v);
                }
            }
            // "C\t<callee>" — an order-claimed callee (the upgrade gate's network;
            // rows added when the zap checker landed, re-derived on stamp change).
            (Some("C"), Some(va)) => {
                if let Ok(v) = u64::from_str_radix(va, 16) {
                    net.insert(v);
                }
            }
            (Some(addr), Some(rest)) => {
                if let Ok(a) = u64::from_str_radix(addr, 16) {
                    let p: Vec<u64> = rest
                        .split(',')
                        .filter_map(|x| u64::from_str_radix(x, 16).ok())
                        .collect();
                    m.insert(a, p);
                }
            }
            _ => {}
        }
    }
        ParamOrders { site_orders: m, excluded: ex, networked: net }
    }

    pub fn render(&self) -> String {
    let mut body = String::new();
    for (a, p) in &self.site_orders {
        let hx: Vec<String> = p.iter().map(|x| format!("{x:x}")).collect();
        body.push_str(&format!("{a:x}\t{}\n", hx.join(",")));
    }
    for x in &self.excluded {
        body.push_str(&format!("X\t{x:x}\n"));
    }
    for c in &self.networked {
        if !self.excluded.contains(c) {
            body.push_str(&format!("C\t{c:x}\n"));
        }
    }
        body
    }

    /// Collect the evidence over every function of the program (`None` when the language does not
    /// have the four watcall argument registers — nothing to read).
    pub fn collect(prog: &Program, lang: &str, entries: &Entries, regs: &WatcomRegs) -> Option<ParamOrders> {
        if regs.arg_reg_offs.len() != 4 {
            return None;
        }
        let mut order_excluded: HashSet<u64> = Default::default();
        let mut order_networked: HashSet<u64> = HashSet::new();
    let entry_set: std::collections::HashSet<u64> = entries.list.iter().map(|e| e.0).collect();
    let mut sites = Vec::new();
    for (va, _) in &entries.list {
        let (next, body_end) = entries.extent_bounds(prog, *va);
        let end = match body_end {
            Some(b) => next.min(b),
            None => next,
        }
        .max(*va + 1);
        let region = prog.memory.read_window(crate::decompile::space::Address::new(prog.default_space, *va), (end - *va) as usize);
        let insns = crate::recompile::insn::normalize(
            lang,
            &region,
            *va,
            &crate::recompile::insn::NoReloc,
        )
        .unwrap_or_default();
        sites.extend(
            crate::recompile::buildconfig::call_setup_sites(&insns, &regs.arg_reg_offs)
                .into_iter()
                .filter(|s| entry_set.contains(&s.callee)),
        );
    }
    let mut orders = crate::recompile::buildconfig::param_orders_from_evidence(&sites);
    // An order that IS the convention's slot order renders identically — drop the no-ops.
    orders.retain(|_, p| p.as_slice() != &regs.arg_reg_offs[..p.len().min(regs.arg_reg_offs.len())]);
    // The callees still claimed by at least one site, for the nondefault exclusion.
    let claimed: std::collections::HashSet<u64> = sites
        .iter()
        .filter(|s| orders.contains_key(&s.call_addr))
        .map(|s| s.callee)
        .collect();
    order_networked.extend(claimed.iter().copied());
    // excluded callees are equally order-networked (their storage is nondefault)
    for callee in claimed {
        let nondefault = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::analysis::decompiler::decompile_function(prog, crate::decompile::space::Address::new(prog.default_space, callee))
        }))
        .ok()
        .flatten()
        .map(|f| crate::recompile::pragma::nondefault_parm_regs(&f, &regs.table).is_some())
        .unwrap_or(true);
        if nondefault {
            order_excluded.insert(callee);
        }
    }
        Some(ParamOrders { site_orders: orders, excluded: order_excluded, networked: order_networked })
    }
}

/// GLOBAL WIDTHS FROM THE ORIGINAL'S OWN INSTRUCTIONS (the `global-width` switch): the widest
/// STORE and the widest READ the original makes at each RAM address, corpus-wide — one function's
/// byte read is another function's dword store. `gsizes` declares a Ram global at the NARROWEST
/// access the decompiled function makes, which is right for a byte-only global and wrong when one
/// function touches an address at two widths (the narrow declaration TRUNCATES a store the original
/// makes wide). Both conditions are byte evidence: widen only where the original STORES wider than we
/// would AND READS wider than we would store.
pub struct GlobalWidths {
    pub store_w: HashMap<u64, u32>,
    pub read_w: HashMap<u64, u32>,
}

impl GlobalWidths {
    pub fn collect(prog: &Program, lang: &str, entries: &Entries) -> GlobalWidths {
    let mut sw: HashMap<u64, u32> = HashMap::new();
    let mut rw: HashMap<u64, u32> = HashMap::new();
    for (va, _) in &entries.list {
        let (next, body_end) = entries.extent_bounds(prog, *va);
        let end = match body_end {
            Some(b) => next.min(b),
            None => next,
        }
        .max(*va + 1);
        let region = prog.memory.read_window(crate::decompile::space::Address::new(prog.default_space, *va), (end - *va) as usize);
        let insns = crate::recompile::insn::normalize(
            lang,
            &region,
            *va,
            &crate::recompile::insn::NoReloc,
        )
        .unwrap_or_default();
        for x in &insns {
            for op in &x.sem {
                if let Some(crate::recompile::insn::SemArg::Mem(_, a, sz)) = &op.out {
                    let e = sw.entry(*a).or_insert(0);
                    *e = (*e).max(*sz);
                }
                for i in &op.ins {
                    if let crate::recompile::insn::SemArg::Mem(_, a, sz) = i {
                        let e = rw.entry(*a).or_insert(0);
                        *e = (*e).max(*sz);
                    }
                }
            }
        }
    }
        GlobalWidths { store_w: sw, read_w: rw }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cache text round-trips: per-site orders, excluded callees (`X`, also networked), and
    /// claimed-but-not-excluded callees (`C`); hex without padding.
    #[test]
    fn param_orders_cache_text_round_trips() {
        let mut po = ParamOrders::default();
        po.site_orders.insert(0x1234, vec![0x8, 0x0, 0x10]);
        po.site_orders.insert(0xabcd0, vec![0x4]);
        po.excluded.insert(0x5000);
        po.networked.insert(0x5000);
        po.networked.insert(0x6000);
        let text = po.render();
        assert!(text.lines().any(|l| l == "1234\t8,0,10"), "{text}");
        assert!(text.lines().any(|l| l == "X\t5000") && text.lines().any(|l| l == "C\t6000"), "{text}");
        assert!(!text.lines().any(|l| l == "C\t5000"), "an excluded callee is written once, as X");
        assert_eq!(ParamOrders::parse(&text), po);
        assert_eq!(ParamOrders::parse(""), ParamOrders::default());
        assert_eq!(ParamOrders::parse("garbage\n\tx\n"), ParamOrders::default(), "unparseable rows are skipped");
    }

    fn corpus_program() -> Option<Program> {
        let path = crate::paths::analysis_corpus_dir().join("basic.elf");
        if !path.exists() {
            eprintln!("skip: {} absent", path.display());
            return None;
        }
        crate::analysis::analyze_file(&path).ok()
    }

    /// The world split: the landed world has no prototypes, the pp world carries them, the
    /// consistency world carries them behind an EMPTY scope; no prototypes → no pp/cons worlds.
    #[test]
    fn worlds_split_keeps_the_prototypes_out_of_the_landed_world() {
        let Some(mut prog) = corpus_program() else { return };
        let w = Worlds::split(prog.clone());
        assert!(w.pp.is_none() && w.cons.is_none(), "no recovered prototypes: one world");
        let entry = prog.function_manager.functions().next().expect("a function").entry.offset;
        prog.recovered_protos.insert(entry, crate::decompile::fspec::FuncProto::default());
        let w = Worlds::split(prog);
        assert!(w.landed.recovered_protos.is_empty());
        let pp = w.pp.expect("pp world");
        assert!(pp.recovered_protos.contains_key(&entry) && pp.proto_scope.is_none());
        let cons = w.cons.expect("cons world");
        assert!(cons.recovered_protos.contains_key(&entry));
        assert_eq!(cons.proto_scope, Some(HashSet::new()), "consult nothing until scoped");
    }

    /// Entries: address order, the successor map (the last entry's successor is +0x1000), and the
    /// extent bounds' upper bound = the next entry or the block end, never past either.
    #[test]
    fn entries_are_sorted_with_successors_and_bounded_extents() {
        let Some(prog) = corpus_program() else { return };
        let e = Entries::of(&prog);
        assert!(!e.list.is_empty());
        assert!(e.offs.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(e.offs, e.list.iter().map(|x| x.0).collect::<Vec<_>>());
        let last = *e.offs.last().unwrap();
        assert_eq!(e.next[&last], last + 0x1000);
        for w in e.offs.windows(2) {
            assert_eq!(e.next[&w[0]], w[1]);
            let (next, body_end) = e.extent_bounds(&prog, w[0]);
            assert!(next <= w[1], "the upper bound never passes the next entry");
            assert!(next > w[0]);
            if let Some(b) = body_end {
                assert!(b > w[0]);
            }
        }
    }
}
