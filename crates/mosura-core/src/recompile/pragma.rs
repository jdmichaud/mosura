//! The Watcom `#pragma aux` vocabulary of the recompile — the function's OWN side: the
//! spec-built register table, the `parm [..]` list where the recovered storage is not Watcom's
//! positional default, and `own_contract` (the one pragma merging `far`, `parm`, and `modify`).
//! Moved verbatim out of the corpus emit driver (plan WP7 P0 c2, 2026-09-05); the caller side
//! (per-callee pragmas, the caller-side post-pass) follows in c6. Text and register offsets in,
//! text out; nothing here reads a file or a program beyond the language tables.

use std::collections::HashMap;

use crate::decompile::op::flags;
use crate::decompile::opcode::OpCode;

/// The register facts every pragma is spelled from, for one language: the Watcom name table
/// (`(sleigh offset, size, name)`), the watcall argument registers in convention order, and the
/// stack pointer's register-space offset — the three values the driver used to compute at three
/// places, now one value built once.
pub struct WatcomRegs {
    pub table: Vec<(u64, u32, &'static str)>,
    /// EAX, EDX, EBX, ECX — the watcall argument registers, by register-space offset.
    pub arg_reg_offs: Vec<u64>,
    /// The stack pointer's register-space offset, from the language tables rather than a constant.
    pub esp_off: Option<u64>,
}

impl WatcomRegs {
    pub fn for_lang(lang_id: &str) -> WatcomRegs {
        let table = watcom_reg_table(lang_id);
        let arg_reg_offs: Vec<u64> = ["eax", "edx", "ebx", "ecx"]
            .iter()
            .filter_map(|n| table.iter().find(|&&(_, sz, nm)| sz == 4 && nm == *n).map(|&(o, ..)| o))
            .collect();
        let esp_off = crate::lang::load_cached(lang_id).and_then(|(spec, _)| spec.register_offset("ESP"));
        WatcomRegs { table, arg_reg_offs, esp_off }
    }
}

/// Watcom register names for the parameter storage the decompiler recovered, keyed by SLEIGH
/// register offset. Built once from the language spec rather than hardcoded, so a register that
/// moves in the spec cannot silently mis-map.
pub fn watcom_reg_table(lang_id: &str) -> Vec<(u64, u32, &'static str)> {
    let Some(spec) = crate::lang::load_cached(lang_id) else { return Vec::new() };
    let mut t = Vec::new();
    // The watcall argument registers, in convention order, with the sub-register Watcom uses for a
    // narrow argument (open-watcom-v2 `owflat.h`: a byte argument travels in AL/DL/BL/CL).
    // (32-bit name, 16-bit name, 8-bit low, 8-bit high). ESI/EDI/EBP have NO 8-bit forms on x86:
    // naming one produces a pragma Watcom rejects, and a rejected pragma is not a local failure —
    // `E1122` aborted a whole dosemu batch once already and cost an entire measurement.
    for (e, w, b, hi) in [
        ("EAX", "ax", Some("al"), Some("ah")),
        ("EDX", "dx", Some("dl"), Some("dh")),
        ("EBX", "bx", Some("bl"), Some("bh")),
        ("ECX", "cx", Some("cl"), Some("ch")),
        // Not watcall argument registers, but a function whose parameters demonstrably arrive in
        // them is using a custom convention, and `#pragma aux ... parm [esi] [edi]` is how Watcom
        // is told so. `recover_input_params`' custom-register branch recovers these.
        ("ESI", "si", None, None),
        ("EDI", "di", None, None),
        ("EBP", "bp", None, None),
    ] {
        let Some(off) = spec.0.register_offset(e) else { continue };
        t.push((off, 4, Box::leak(e.to_lowercase().into_boxed_str()) as &'static str));
        t.push((off, 2, w));
        if let Some(b) = b {
            t.push((off, 1, b));
        }
        if let Some(hi) = hi {
            t.push((off + 1, 1, hi));
        }
    }
    t
}

/// The `parm [..]` list to declare, or `None` when the recovered storage already IS what Watcom
/// would assign by position — in which case the pragma would be a no-op and is left off.
///
/// Only all-register prototypes are handled: a mixed register/stack prototype needs the overflow
/// form and is left to the default, and an unmappable storage returns `None` rather than guessing.
pub fn nondefault_parm_regs(
    f: &crate::decompile::funcdata::Funcdata,
    table: &[(u64, u32, &'static str)],
) -> Option<String> {
    let slots = crate::decompile::printc::rendered_param_slots(f);
    if slots.is_empty() {
        return None;
    }
    let reg = f.spaces.by_name("register")?;
    let mut storages = Vec::new();
    for s in &slots {
        if s.addr.space != reg {
            return None;
        }
        storages.push((s.addr.offset, s.size));
    }
    nondefault_parm_from_storages(&storages, table)
}

/// The storage-list core of [`nondefault_parm_regs`], shared with the CALLER-side extern
/// pragmas: the `parm [..]` list for an ordered register-storage list, or `None` when the
/// list is exactly Watcom's positional default (the pragma would be a no-op), a register is
/// not in the table, or EBP/ESP appears.
pub fn nondefault_parm_from_storages(
    storages: &[(u64, u32)],
    table: &[(u64, u32, &'static str)],
) -> Option<String> {
    if storages.is_empty() {
        return None;
    }
    let mut names = Vec::new();
    for &(off, size) in storages {
        let n = table.iter().find(|&&(o, sz, _)| o == off && sz == size)?;
        // The frame and stack pointers are not argument storage under any Watcom convention, and
        // naming one in a `parm` list is rejected outright: `E1122: Illegal register modified by
        // '<name>' #pragma`, which fails the whole translation unit. Recovering a parameter in EBP
        // means the recovery is wrong, so drop the DECLARATION rather than emit a list that cannot
        // compile — a partial list would silently re-map the other parameters.
        if n.2 == "ebp" || n.2 == "esp" {
            return None;
        }
        names.push(n.2);
    }
    // What Watcom assigns by position, for these same sizes.
    let order = ["a", "d", "b", "c"];
    let default: Vec<String> = storages
        .iter()
        .enumerate()
        .map(|(i, s)| match (order.get(i), s.1) {
            (Some(p), 4) => format!("e{p}x"),
            (Some(p), 2) => format!("{p}x"),
            (Some(p), 1) => format!("{p}l"),
            _ => String::new(),
        })
        .collect();
    if default.iter().zip(&names).all(|(d, n)| d == n) {
        return None;
    }
    Some(names.iter().map(|n| format!("[{n}]")).collect::<Vec<_>>().join(" "))
}

/// The `parm [..]` clause for an ordered register-storage list, rendered EVEN WHEN the list is
/// Watcom's positional default — the witnessed form of [`nondefault_parm_from_storages`].
/// `None` only when a storage is unmappable or is the frame/stack pointer.
fn parm_from_storages_always(
    storages: &[(u64, u32)],
    table: &[(u64, u32, &'static str)],
) -> Option<Vec<&'static str>> {
    if storages.is_empty() {
        return None;
    }
    let mut names = Vec::new();
    for &(off, size) in storages {
        let n = table.iter().find(|&&(o, sz, _)| o == off && sz == size)?;
        if n.2 == "ebp" || n.2 == "esp" {
            return None;
        }
        names.push(n.2);
    }
    Some(names)
}

/// The WITNESSED caller-side `parm [..]` clause (`emit.caller-parm=witnessed`,
/// docs/tasklist-2026-09-08.md item 5).
///
/// A caller's declarator is `extern int f();`, so this clause is the only thing in the TU that
/// pins the callee's ARITY. Today's rule suppresses it whenever the recovered ORDER happens to be
/// Watcom's positional default, which throws the arity statement away with it — the second
/// subject's operator measured the stated rate at 1.9% of call sites for that reason, and stating
/// it at the default too took him to 5.1% with nothing stated wrong.
///
/// The suppression cannot simply be dropped. He simulated exactly that against 145 unambiguous
/// ground truths: 108 WRONG. What makes the relaxation safe is a WITNESS from the callee's own
/// bytes, and both halves of it are required (his confidence rule, part 2):
///
///   * every register the clause NAMES must be proven read-before-written, and
///   * no register the clause OMITS may be proven read — a callee beginning `MOV EBP,EAX` takes a
///     parameter that `parm [esi]` does not mention, so that clause is WITHDRAWN, not added.
///
/// `Funcdata::own_param_reads` is that proof, and it is `None` when the walk could not follow the
/// callee (a branch or a call) — which withholds, because "not proven" is not "none".
pub fn witnessed_parm_regs(
    f: &crate::decompile::funcdata::Funcdata,
    table: &[(u64, u32, &'static str)],
) -> Option<String> {
    let reg = f.spaces.by_name("register")?;
    let slots = crate::decompile::printc::rendered_param_slots(f);
    let mut storages = Vec::new();
    for s in &slots {
        // part 1: a whole register in the register space, or the clause is not backed
        if s.addr.space != reg || s.size != 4 {
            return None;
        }
        storages.push((s.addr.offset, s.size));
    }
    let reads: Vec<(u64, u32)> = f
        .own_param_reads
        .as_ref()?
        .iter()
        .filter(|(a, _)| a.space == reg)
        .map(|(a, sz)| (a.offset, *sz))
        .collect();
    witnessed_parm_from_storages(&storages, &reads, table)
}

/// The decision behind [`witnessed_parm_regs`], over storage lists: the clause for `storages`
/// when the proven read-before-write set `reads` names EXACTLY the argument registers the clause
/// does — every named one proven, no omitted one proven. `None` withholds.
pub fn witnessed_parm_from_storages(
    storages: &[(u64, u32)],
    reads: &[(u64, u32)],
    table: &[(u64, u32, &'static str)],
) -> Option<String> {
    let names = parm_from_storages_always(storages, table)?;
    // over the four watcall argument registers only: a callee reading ESI is not thereby taking
    // an ESI parameter under this convention
    let arg_names: std::collections::BTreeSet<&str> = ["eax", "edx", "ebx", "ecx"].into_iter().collect();
    let named: std::collections::BTreeSet<&str> = names.iter().copied().collect();
    let proven: std::collections::BTreeSet<&str> = reads
        .iter()
        .filter_map(|&(off, _)| table.iter().find(|&&(o, sz, _)| o == off && sz == 4).map(|t| t.2))
        .filter(|n| arg_names.contains(n))
        .collect();
    if named.iter().any(|n| !arg_names.contains(n)) || named != proven {
        return None;
    }
    Some(names.iter().map(|n| format!("[{n}]")).collect::<Vec<_>>().join(" "))
}

/// The default return register's family (EAX, AX, AL, AH): a value delivered there needs no
/// `value` clause — it is Watcom's default.
fn is_default_return(table: &[(u64, u32, &'static str)], off: u64) -> bool {
    table
        .iter()
        .find(|&&(_, sz, nm)| sz == 4 && nm == "eax")
        .is_some_and(|&(o, ..)| off >= o && off < o + 4)
}

/// The `value [reg]` clause for a result delivered in a register other than the default, named at
/// exactly that offset and size (a sub-register result returns by its own name). None for the
/// default family, for a storage the table cannot name (a 64-bit pair, memory), and for the frame
/// and stack pointers Watcom refuses in any clause.
fn value_clause(table: &[(u64, u32, &'static str)], off: u64, size: u32) -> Option<String> {
    if is_default_return(table, off) {
        return None;
    }
    let name = table.iter().find(|&&(o, sz, _)| o == off && sz == size).map(|t| t.2)?;
    if name == "ebp" || name == "esp" {
        return None;
    }
    Some(format!("value [{name}]"))
}


/// The function's own Watcom contract — its `parm` list where the recovered storage is not what
/// Watcom would assign by position, and its `modify` list where the decompiler established which
/// registers the function destroys. `None` when neither is needed.
///
/// The `modify` half is the expensive one to omit. Without it Watcom preserves every register it
/// uses that the default convention does not let it destroy, so a function whose original freely
/// clobbers EDX comes back with a `push edx`/`pop edx` pair around the whole body. Measured on
/// FUN_0002266c: 31 bytes against the original's 29, and with `modify [eax edx]` it matches
/// instruction for instruction. Across the survey the same shape shows up in aggregate as `pop`
/// -428 and `push` -207 against the originals — 39% of the entire instruction deficit.
///
/// `modify` (additive) rather than `modify exact`: the exact form also strips the SEGMENT registers
/// from the preserved set and Watcom starts saving GS.
pub fn own_contract(
    f: &crate::decompile::funcdata::Funcdata,
    table: &[(u64, u32, &'static str)],
    stack_convention: bool,
    cleanup: Option<u32>,
) -> Option<String> {
    let mut parts = Vec::new();
    // A FAR return (`RETF`, `Funcdata::far_return` from the original's bytes): `far` first.
    if f.far_return {
        parts.push("far".to_string());
    }
    // A STACK-BASED prototype is `parm []`. It used to short-circuit the whole declaration, so
    // these functions never got their `modify` list — the two are independent facts about the
    // contract and both belong in the same pragma.
    //
    // WHO POPS is a third, independent fact, and it is not a choice: Watcom's default is
    // callee-pops (`parm routine`), and a function whose original ends in a bare `RET` after
    // reading `[ESP+4]` is caller-pops. Emitting the default regardless put a `RET 4` where the
    // original has `RET` in 101 the subject functions — 13 of them one instruction from exact and
    // nothing else wrong. `recompile::callee_stack_cleanup` reads the contract off the function's
    // own return instruction; where it cannot tell (no return, or returns that disagree) the
    // default stands, because a guess here is wrong code in every caller.
    if stack_convention {
        parts.push(match cleanup {
            Some(0) => "parm caller []".to_string(),
            _ => "parm []".to_string(),
        });
    } else if let Some(p) = nondefault_parm_regs(f, table) {
        parts.push(format!("parm {p}"));
    }
    // THE RETURN REGISTER when it is not the default (docs/tasklist-2026-09-08.md item 11): a
    // function that delivers its result in EBX (the regout MVE's `add ebx,eax ; ret`) compiled
    // without `value [ebx]` returns it in EAX — measured SAME_SHAPE, `ADD EAX,EBX` against the
    // original's `ADD EBX,EAX` — and every caller then reads the wrong register. The storage is
    // the recovered prototype's, the same one the printer renders as the function's return.
    if let Some(slot) = crate::analysis::interface::prototype_of(f).output {
        if f.spaces.by_name("register") == Some(slot.addr.space) {
            if let Some(v) = value_clause(table, slot.addr.offset, slot.size) {
                parts.push(v);
            }
        }
    }
    // Only 4-byte general registers, named through the same spec-built table as `parm`.
    // M34 measured this list net-negative (15 regressions, 3 gains) because it OVER-DECLARED:
    // FUN_00010d70's original saves EBX, ECX, EDX and EBP, and we emitted `modify [eax ebx edx]`,
    // so Watcom skipped two saves and the function compiled 4 bytes short. The cause was a
    // sub-register offset mismatch in `callee_writes_cfg` — `mov ah,..` writes offset 1 while
    // `pop eax` restores offset 0, so a high-byte write slipped past the saved-and-restored filter
    // and was reported as destroying the whole register. Writes are normalized to their containing
    // register before that filter now, and this function's list is `[eax]`, which is right.
    if let Some(m) = f.own_modify.as_ref() {
        let regs: Vec<&str> = m
            .iter()
            // A SUB-REGISTER write modifies its containing 32-bit register: `mov ah,1` destroys
            // EAX, `xor dl,dl` destroys EDX. Requiring an exact 4-byte match dropped those from the
            // list entirely — FUN_00011ab8 writes AH and DL and declared only `modify [eax]`, so
            // Watcom still preserved EDX. Map an 8/16-bit offset back to the register that
            // contains it (AH sits at base+1, so try base and base-1).
            .filter_map(|off| {
                table
                    .iter()
                    .find(|&&(o, sz, _)| o == *off && sz == 4)
                    .or_else(|| table.iter().find(|&&(o, sz, _)| o + 1 == *off && sz == 4))
                    .map(|t| t.2)
            })
            // Watcom REJECTS the frame and stack pointers in a `modify` list —
            // `E1122: Illegal register modified by '<name>' #pragma` — and one such TU aborts the
            // whole dosemu batch, leaving every later function with a stale object.
            .filter(|r| *r != "ebp" && *r != "esp")
            .fold(Vec::new(), |mut acc, r| {
                // Dedup: a register and its sub-registers now map to the same name, and
                // `modify [eax eax]` is not something to hand a compiler.
                if !acc.contains(&r) {
                    acc.push(r);
                }
                acc
            });
        if !regs.is_empty() {
            parts.push(format!("modify [{}]", regs.join(" ")));
        }
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// ARGUMENT-ORDER RECOVERY for one function's recovered emit: apply each call site's own recovered
/// declaration order. The rendered argument list permutes and the TU declares the matching
/// `parm [..]` pragma. The pragma rebinds EVERY call to that callee in the TU, so all of a
/// callee's sites here must derive the SAME order and every one must qualify (its own evidence
/// present, arity matching, every argument reorder-safe) — one failing site vetoes the callee for
/// the whole TU. Returns the per-site permutations (for `recovery::recover`) and the per-callee
/// `parm [..]` clauses, merged into ONE `#pragma aux` per callee by [`callee_pragmas`]: Watcom treats
/// a second `#pragma aux` for the same symbol as a REPLACEMENT, so split emission would silently
/// drop whichever clause came first.
pub fn call_arg_orders(
    report: &crate::decompile::printc::EmitReport,
    self_va: u64,
    orders: &crate::recompile::passes::ParamOrders,
    regs: &WatcomRegs,
) -> (std::collections::HashMap<u64, Vec<usize>>, std::collections::BTreeMap<u64, String>) {
    let mut order_parms: std::collections::BTreeMap<u64, String> = Default::default();
    // ARGUMENT-ORDER RECOVERY: apply each site's own recovered declaration order.
    // The rendered argument list permutes and the TU declares the matching
    // `parm [..]` pragma. The pragma rebinds EVERY call to that callee in the TU,
    // so all of a callee's sites here must derive the SAME order and every one
    // must qualify (its own evidence present, arity matching, every argument
    // reorder-safe) — one failing site vetoes the callee for the whole TU.
    let mut call_arg_orders: std::collections::HashMap<u64, Vec<usize>> = Default::default();
    // Per-callee `parm [..]` clauses from param-order recovery — merged below with the
    // caller-pops and modify clauses into ONE `#pragma aux` per callee: Watcom treats a
    // second `#pragma aux` for the same symbol as a REPLACEMENT, so split emission
    // would silently drop whichever clause came first.
    {
        let mut by_callee: std::collections::BTreeMap<u64, Vec<(u64, &Vec<bool>)>> =
            Default::default();
        for (addr, callee, safe) in &report.port.call_order_candidates {
            by_callee.entry(*callee).or_default().push((*addr, safe));
        }
        for (callee, csites) in by_callee {
            if callee == self_va || orders.excluded.contains(&callee) {
                continue;
            }
            let mut tu_p: Option<&Vec<u64>> = None;
            let ok = csites.iter().all(|(addr, safe)| {
                let Some(p) = orders.site_orders.get(addr) else { return false };
                let n = p.len();
                if n > regs.arg_reg_offs.len() || safe.len() != n || !safe.iter().all(|&s| s) {
                    return false;
                }
                let mut sp: Vec<u64> = p.clone();
                sp.sort_unstable();
                let mut sd: Vec<u64> = regs.arg_reg_offs[..n].to_vec();
                sd.sort_unstable();
                if sp != sd {
                    return false;
                }
                match tu_p {
                    None => {
                        tu_p = Some(p);
                        true
                    }
                    Some(q) => q == p,
                }
            });
            let Some(p) = tu_p else { continue };
            if !ok {
                continue;
            }
            let n = p.len();
            let default = &regs.arg_reg_offs[..n];
            let perm: Vec<usize> =
                p.iter().map(|r| default.iter().position(|d| d == r).unwrap()).collect();
            for (addr, _) in &csites {
                call_arg_orders.insert(*addr, perm.clone());
            }
            let names: Vec<&str> = p
                .iter()
                .filter_map(|r| {
                    regs.table.iter().find(|&&(o, sz, _)| o == *r && sz == 4).map(|t| t.2)
                })
                .collect();
            if names.len() == n {
                order_parms.insert(callee, format!("parm [{}]", names.join("] [")));
            }
        }
    }
    (call_arg_orders, order_parms)
}

/// VARARG CALLEES: targets of calls the decompiler recovered as caller-cleaned
/// (`CallSpec::caller_cleans` — evidence: the callee's RET pops nothing AND the
/// original fallthrough is `ADD ESP,n`), each with its own recovered modify set
/// (`CallSpec::cdecl_modify`). The pragma is pre-rendered here because the register
/// NAMES come from the same spec-built table as every other contract
/// (`own_contract`'s); a blanket kill set was measured wrong in BOTH directions —
/// without `modify` Watcom assumes preserves-all and drops the 191b8 family's
/// prologue saves; with a uniform `modify [eax ebx ecx edx]` it invents saves the
/// 0x31c60 family's originals do not have (6 EXACT lost). Per-callee evidence is the
/// only shape that fits both.
/// ONE `#pragma aux` spec per callee, merging every recovered contract clause:
///   parm [..]        — param-order recovery (order_parms above), register callees;
///   parm caller []   — caller-cleaned (cdecl/vararg) callees;
///   modify [..]      — the callee's own recovered clobber set, EVERY callee that
///                      has one (`CallSpec::cdecl_modify`): a bare extern under
///                      Watcom's default (save = HW_FULL) claims preserves-all, and
///                      the recompiler hoists argument setups across calls the
///                      original could not (FUN_00011b9c / callee 0x1f734).
pub fn callee_pragmas(
    f: &crate::decompile::funcdata::Funcdata,
    insns: &[crate::recompile::insn::NormInsn],
    regs: &WatcomRegs,
    callee_clobbers: bool,
    order_parms: &std::collections::BTreeMap<u64, String>,
) -> std::collections::HashMap<u64, String> {
    // (parm, value, modify) per callee.
    let mut callee_aux: HashMap<u64, (Option<String>, Option<String>, Option<String>)> = HashMap::new();
    // EXACTNESS (contract-design Increment 2): recovered in the analysis
    // (CallSpec::cdecl_exact — an argument register surviving its own call on the
    // raw CFG, arity from the whole-program prototype recovery). One site's
    // testimony covers the TU's single declaration.
    let exact_callees: std::collections::HashSet<u64> = f
        .call_specs
        .iter()
        .filter(|(_, cs)| cs.cdecl_exact)
        .filter_map(|(&op, _)| {
            let t = f.op(op).input(0)?;
            let va = f.vn(t).loc.offset;
            (va != 0).then_some(va)
        })
        .collect();
    // DETERMINISTIC per-callee merge. `f.call_specs` is a HashMap, and the old
    // last-writer-wins fold made the TU's single pragma a RANDOM DRAW whenever two
    // sites of one callee carried different recovered specs (caller 0x3342c's
    // 0x63be5: one site caller_cleans+6-reg blanket, one site 5-reg transitive —
    // emitted `modify exact [eax]` or `[eax ecx]` depending on hash order; the
    // standing few-function jitter between byte-identical rounds). Merge instead:
    // sites in sorted op order, caller_cleans from ANY site that has it (cdecl
    // evidence anywhere is cdecl everywhere), modify = UNION of the sites' sets —
    // the one declaration must be sound for every site it covers.
    let mut merged: HashMap<u64, (bool, Option<std::collections::BTreeSet<u64>>)> =
        HashMap::new();
    let mut sites: Vec<u32> = f.call_specs.keys().map(|op| op.0).collect();
    sites.sort_unstable();
    for opi in sites {
        let op = crate::decompile::op::OpId(opi);
        let cs = &f.call_specs[&op];
        let Some(t) = f.op(op).input(0) else { continue };
        let va = f.vn(t).loc.offset;
        if va == 0 {
            continue;
        }
        crate::debug!(crate::debug::Topic::Survey, "callee {va:#x} caller_cleans={:?} cdecl_modify={:?}", cs.caller_cleans, cs.cdecl_modify.as_ref().map(|m| m.len()));
        let e = merged.entry(va).or_default();
        e.0 |= cs.caller_cleans.unwrap_or(0) > 0;
        if let Some(m) = cs.cdecl_modify.as_ref() {
            e.1.get_or_insert_with(Default::default).extend(m.iter().copied());
        }
    }
    // WHAT THIS TU'S C READS AS A CALL'S PRODUCT (docs/tasklist-2026-09-08.md items 8 and 11).
    // The declaration a caller compiles against must say so, or it contradicts the body beside
    // it: a callee whose recovered result is EBX is read as the call's value (regout's caller,
    // `pxVar1 = func_0x08048106(..)`, the store then went through EAX), and a register the call
    // creates (an INDIRECT creation the body reads as `extraout_<reg>`) is one the callee
    // writes — declaring it preserved lets Watcom keep a live value there across the call
    // (41 of 751 TUs on the second subject; 2 of 3023 here). The survival veto that narrows
    // `cdecl_modify` reads a post-call use of a register as "this caller was compiled against
    // a declaration preserving it"; a read of the callee's OUTPUT is the one post-call use that
    // is not that, so the pragma widens by exactly the products the C names: `value [reg]`
    // for a non-default result register (one per callee; sites that disagree declare none)
    // and `modify` over the result and the read creations. Nothing the C does not read is
    // added, so a TU without such reads is unchanged.
    let register = f.spaces.by_name("register");
    let mut creations: HashMap<crate::decompile::op::OpId, Vec<u64>> = HashMap::new();
    for opid in f.op_ids() {
        let o = f.op(opid);
        if o.is_dead() || o.code() != crate::decompile::opcode::OpCode::Indirect {
            continue;
        }
        let (Some(call), Some(out)) = (o.guarded_op, o.output) else { continue };
        let vn = f.vn(out);
        if Some(vn.loc.space) != register || !vn.is_indirect_creation() || vn.descend.is_empty() {
            continue;
        }
        creations.entry(call).or_default().push(vn.loc.offset & !3);
    }
    // per callee: the product registers (4-byte bases) and the result register (None = unseen,
    // Some(None) = the sites disagree)
    let mut products: HashMap<u64, (std::collections::BTreeSet<u64>, Option<Option<(u64, u32)>>)> =
        HashMap::new();
    let mut call_ops: Vec<crate::decompile::op::OpId> = f
        .op_ids()
        .filter(|&op| !f.op(op).is_dead() && f.op(op).code() == crate::decompile::opcode::OpCode::Call)
        .collect();
    call_ops.sort_unstable();
    for op in call_ops {
        let Some(t) = f.op(op).input(0) else { continue };
        let va = f.vn(t).loc.offset;
        if va == 0 {
            continue;
        }
        let e = products.entry(va).or_default();
        // The result's storage: the committed one (`CallSpec::output_storage` — the op's output
        // varnode may be a reassembled `unique`), else the output varnode when it is the register.
        let result = f
            .call_specs
            .get(&op)
            .and_then(|cs| cs.output_storage)
            .map(|(a, sz)| (a.space, a.offset, sz))
            .or_else(|| f.op(op).output.map(|out| { let vn = f.vn(out); (vn.loc.space, vn.loc.offset, vn.size) }));
        if let Some((space, off, size)) = result {
            if Some(space) == register && !is_default_return(&regs.table, off) {
                e.0.insert(off & !3);
                let v = (off, size);
                e.1 = match e.1 {
                    None => Some(Some(v)),
                    Some(Some(p)) if p == v => Some(Some(v)),
                    _ => Some(None),
                };
            }
        }
        if let Some(cs) = creations.get(&op) {
            e.0.extend(cs.iter().copied());
        }
    }
    // CALLER-SIDE CLOBBER WITNESS (`buildconfig::saved_for_callees`): a register this
    // function saves in its prologue and restores before its returns without ever
    // touching it was preserved for a callee DECLARED to clobber it — the declaration
    // the original compiled against, which the callee's own recovered clobber set
    // cannot show. Every callee of this TU with a clobber clause takes the register
    // (a caller's saves cannot say which callee); a TU with no clause at all gives
    // it to every callee. the subject's FUN_0004f850: EXACT with `ebx` in its callee's clause.
    let saved = if !callee_clobbers {
        Vec::new()
    } else {
        crate::recompile::buildconfig::saved_for_callees(&insns)
    };
    let any_modify = merged.values().any(|(_, m)| m.is_some());
    let mut merged = merged;
    if !saved.is_empty() {
        for (_, modify) in merged.values_mut() {
            if modify.is_some() || !any_modify {
                modify.get_or_insert_with(Default::default).extend(saved.iter().copied());
            }
        }
    }
    // every callee with a contract OR a product this TU reads
    let mut merged = merged;
    for (&va, (offs, _)) in &products {
        if !offs.is_empty() {
            merged.entry(va).or_default();
        }
    }
    for (va, (cleans, modify)) in merged {
        let e = callee_aux.entry(va).or_default();
        if cleans {
            e.0 = Some("parm caller []".to_string());
        }
        let mut modify = modify;
        if let Some((offs, value)) = products.get(&va) {
            if !offs.is_empty() {
                modify.get_or_insert_with(Default::default).extend(offs.iter().copied());
            }
            if let Some(Some((off, size))) = value {
                e.1 = value_clause(&regs.table, *off, *size);
            }
        }
        if let Some(m) = modify {
            let mut regs: Vec<&str> = m
                .iter()
                .filter_map(|off| {
                    regs.table.iter().find(|&&(o, sz, _)| o == *off && sz == 4).map(|t| t.2)
                })
                .filter(|r| *r != "ebp" && *r != "esp")
                .collect();
            // EAX is the return register — always in the contract even for a callee
            // whose body the walk saw writing nothing else.
            if !regs.contains(&"eax") {
                regs.push("eax");
            }
            regs.sort();
            regs.dedup();
            let kw = if exact_callees.contains(&va) { "modify exact" } else { "modify" };
            e.2 = Some(format!("{kw} [{}]", regs.join(" ")));
        }
    }
    // A callee can carry a recovered param order without any CallSpec entry (the
    // contract walks all failed) — its pragma must still be emitted.
    let mut callee_aux = callee_aux;
    for &va in order_parms.keys() {
        callee_aux.entry(va).or_default();
    }
    let vararg_callees: HashMap<u64, String> = callee_aux
        .into_iter()
        .filter_map(|(va, (cleans, value, modify))| {
            let parm = cleans.or_else(|| order_parms.get(&va).cloned());
            let parts: Vec<String> = [parm, value, modify].into_iter().flatten().collect();
            (!parts.is_empty()).then(|| (va, parts.join(" ")))
        })
        .collect();
    vararg_callees
}

/// The definition-side contract table the caller-side post-pass reads: each function's own
/// nondefault `parm [..]` declaration with its parameter widths (`None` = default order), and each
/// caller's per-callee argument widths at its call sites (`None` on disagreement between sites).
/// CALLER-SIDE REGISTER CONTRACTS, definition-side truth: the `parm [..]` pragma tells Watcom the
/// callee's true argument registers — but only in the callee's own TU; a caller compiles against a
/// bare `extern int func_0xNNN();` and Watcom binds the argument list POSITIONALLY to the default
/// order, inverting every call to a callee whose recovered storage is nonstandard (measured:
/// FUN_0003925c passed its table index in EAX where the original — and the callee's own pragma,
/// FUN_00038828 `parm [edx] [eax]` — take it in EDX). The pragma each caller needs is EXACTLY the
/// one the callee's own TU declares, so it is recorded per function and applied to every TU that
/// externs the callee in a post-pass after the loop, when the table is complete. A STACK-CONVENTION
/// callee (`parm []`) needs the same clause in every caller; only the callee-pops form is
/// propagated (the caller's `parm caller []` comes from its own call spec).
#[derive(Debug, Default, Clone)]
pub struct ContractTable {
    /// `emit.caller-parm=witnessed`: state a callee's `parm [..]` clause even when its recovered
    /// order is Watcom's positional default, gated on the callee's own read witness
    /// ([`witnessed_parm_regs`]). Default false = today's rule, the nondefault order only.
    pub witnessed: bool,
    pub parm_map: std::collections::BTreeMap<u64, Option<(String, Vec<u32>)>>,
    pub caller_calls: std::collections::BTreeMap<u64, std::collections::BTreeMap<u64, Option<Vec<u32>>>>,
}

impl ContractTable {
    /// Record one emitted function: its own declaration (`stack_decl` = `Some("[]")` for a
    /// callee-pops stack-convention function) and the argument widths at each of its call sites.
    pub fn record(&mut self, va: u64, f: &crate::decompile::funcdata::Funcdata, regs: &WatcomRegs, stack_decl: Option<String>) {
    self.parm_map.insert(
        va,
        (if self.witnessed { witnessed_parm_regs(&f, &regs.table) } else { None })
            .or_else(|| nondefault_parm_regs(&f, &regs.table))
            .or(stack_decl)
            .map(|decl| {
            let sizes = crate::decompile::printc::rendered_param_slots(&f)
                .iter()
                .map(|sl| sl.size)
                .collect();
            (decl, sizes)
        }),
    );
    {
        let m = self.caller_calls.entry(va).or_default();
        for opid in f.op_ids() {
            let op = f.op(opid);
            if op.code() != OpCode::Call || op.flags & (flags::DEAD | flags::MARKER) != 0 {
                continue;
            }
            let Some(t) = op.input(0) else { continue };
            let callee = f.vn(t).loc.offset;
            let sizes: Vec<u32> =
                (1..op.num_inputs()).filter_map(|i| op.input(i)).map(|v| f.vn(v).size).collect();
            match m.entry(callee) {
                std::collections::btree_map::Entry::Occupied(mut e) => {
                    if e.get().as_ref() != Some(&sizes) {
                        e.insert(None);
                    }
                }
                std::collections::btree_map::Entry::Vacant(v_) => {
                    v_.insert(Some(sizes));
                }
            }
        }
    }
    }

    /// The caller-side post-pass for one TU: prepend the pragma for every nonstandard callee it
    /// externs, or MERGE the `parm` clause into an existing `#pragma aux` line for that callee
    /// (Watcom treats a second pragma for one symbol as a REPLACEMENT; an existing line that already
    /// carries a `parm` clause wins outright). Gated per callee on arity AND width: every call site
    /// in this TU must pass exactly the pragma's parameter count, each argument no wider than the
    /// parameter's register (a stack-convention `[]` callee gates on arity only). `None` = nothing
    /// to patch; `caller_va` = the TU's function (its call-arity map), `None` when unknown.
    pub fn patch_caller(&self, src: &str, caller_va: Option<u64>) -> Option<String> {
    // A TU may ALREADY declare `#pragma aux` for this callee (build_tu's
    // recovered contract clauses: `parm caller []` and/or `modify [..]`). Watcom
    // treats a SECOND `#pragma aux` for the same symbol as a REPLACEMENT, so the
    // parm clause must be MERGED INTO the existing line, never prepended beside
    // it — the prepended form silently destroyed the order recovery of every
    // modify-annotated callee (measured: the nine-sibling 0x392xx family lost
    // EXACT, FUN_0003925c's `parm [edx] [eax]` replaced by `modify [eax edx]`).
    // An existing line that already carries a `parm` clause wins outright (the
    // per-site order recovery and the caller-cleaned contract both outrank the
    // definition-side default order).
    let mut prepend = String::new();
    let mut merges: Vec<(String, String)> = Vec::new();
    for cva in externed_callees(src) {
        let Some((decl, psizes)) = self.parm_map.get(&cva).and_then(|d| d.as_ref())
        else {
            continue;
        };
        // arity AND width gate: every call site in this TU must pass exactly
        // the pragma's parameter count, each argument at the parameter's own
        // width. A width mismatch is as fatal as an arity one — a 16-bit
        // `parm [bx]` meeting a 4-byte argument overflows it to the STACK
        // (measured: FUN_0002c8xx's `PUSH 0xc` where the original loads EBX).
        let Some(asizes) = caller_va
            .and_then(|va| self.caller_calls.get(&va))
            .and_then(|m| m.get(&cva))
            .cloned()
            .flatten()
        else {
            continue;
        };
        // Per slot the pragma register must be AT LEAST the argument's width:
        // a narrower argument binds the register's low part (measured EXACT —
        // the byte index into `parm [edx]`), while a narrower REGISTER
        // overflows the argument to the stack (the `parm [bx]` failure above).
        // A STACK-convention callee (`parm []`) takes every argument in a
        // 4-byte slot: the caller pushes the promoted value and the callee reads
        // its own width off the slot, so a `char` parameter meeting a 4-byte
        // argument is the normal case, not an overflow (FUN_00030dc8's `PUSH 0`
        // for FUN_00060ad0's byte parameter, one row from EXACT without the
        // clause) — arity gates, width does not.
        let stack_slots = decl == "[]";
        if !(asizes.len() == psizes.len()
            && (stack_slots || asizes.iter().zip(psizes).all(|(a, p)| a <= p)))
        {
            continue;
        }
        let tag = format!("#pragma aux func_0x{cva:08x} ");
        match src.lines().find(|l| l.starts_with(&tag)) {
            Some(l) if l.contains(" parm ") => {}
            Some(l) => merges.push((
                l.to_string(),
                format!("{tag}parm {decl} {}", &l[tag.len()..]),
            )),
            None => {
                prepend.push_str(&format!("#pragma aux func_0x{cva:08x} parm {decl};\n"))
            }
        }
    }
    if prepend.is_empty() && merges.is_empty() {
        return None;
    }
    let mut out = src.to_string();
    for (from, to) in &merges {
        out = out.replacen(from.as_str(), to.as_str(), 1);
    }
    Some(format!("{prepend}{out}"))
}
}

/// The callees a TU externs (`extern int func_0x<va>();` lines), by VA.
fn externed_callees(src: &str) -> Vec<u64> {
    let mut out = Vec::new();
    for line in src.lines() {
        if let Some(rest) = line.strip_prefix("extern ") {
            if let Some(pos) = rest.find("func_0x") {
                if let Ok(va) = u64::from_str_radix(
                    rest[pos + 7..].split(|c: char| !c.is_ascii_hexdigit()).next().unwrap_or(""),
                    16,
                ) {
                    out.push(va);
                }
            }
        }
    }
    out
}


#[cfg(test)]
mod tests {
    use super::*;

    fn regs() -> WatcomRegs {
        WatcomRegs::for_lang("x86:LE:32:default")
    }
    fn off(table: &[(u64, u32, &'static str)], name: &str) -> u64 {
        table.iter().find(|&&(_, _, n)| n == name).map(|&(o, ..)| o).unwrap_or_else(|| panic!("{name} in the table"))
    }

    /// The table is built from the language spec: the four sizes of EAX share its offset (AH one
    /// above), ESI/EDI/EBP have no 8-bit forms, the argument registers come in watcall order, and
    /// the stack pointer is a register of its own.
    #[test]
    fn the_register_table_comes_from_the_spec() {
        let r = regs();
        let eax = off(&r.table, "eax");
        assert_eq!(off(&r.table, "ax"), eax);
        assert_eq!(off(&r.table, "al"), eax);
        assert_eq!(off(&r.table, "ah"), eax + 1);
        assert!(!r.table.iter().any(|&(_, sz, n)| sz == 1 && (n.starts_with("si") || n.starts_with("di") || n.starts_with("bp"))));
        assert_eq!(r.arg_reg_offs, vec![eax, off(&r.table, "edx"), off(&r.table, "ebx"), off(&r.table, "ecx")]);
        let esp = r.esp_off.expect("ESP is a register");
        assert!(!r.arg_reg_offs.contains(&esp) && esp != off(&r.table, "ebp"));
        assert!(WatcomRegs::for_lang("no:such:language").table.is_empty());
    }

    /// `parm [..]` is declared only when the storage is NOT Watcom's positional default, and never
    /// with the frame or stack pointer or an unknown register.
    #[test]
    fn parm_list_only_when_the_storage_is_not_the_default() {
        let r = regs();
        let (eax, edx, ebx, ebp) = (off(&r.table, "eax"), off(&r.table, "edx"), off(&r.table, "ebx"), off(&r.table, "ebp"));
        assert_eq!(nondefault_parm_from_storages(&[], &r.table), None);
        assert_eq!(nondefault_parm_from_storages(&[(eax, 4), (edx, 4)], &r.table), None, "EAX, EDX is the default");
        assert_eq!(nondefault_parm_from_storages(&[(edx, 4), (eax, 4)], &r.table), Some("[edx] [eax]".into()));
        assert_eq!(nondefault_parm_from_storages(&[(eax, 1)], &r.table), None, "AL is the default byte slot");
        assert_eq!(nondefault_parm_from_storages(&[(edx, 1)], &r.table), Some("[dl]".into()));
        assert_eq!(nondefault_parm_from_storages(&[(ebx, 2), (eax, 4)], &r.table), Some("[bx] [eax]".into()));
        assert_eq!(nondefault_parm_from_storages(&[(ebp, 4)], &r.table), None, "EBP is rejected by Watcom");
        assert_eq!(nondefault_parm_from_storages(&[(0xdead_0000, 4)], &r.table), None, "unknown storage decides nothing");
    }

    /// One pragma merges the independent facts: `far`, the stack-convention `parm [..]` with who
    /// pops, and `modify` (sub-registers mapped to their container, EBP/ESP dropped, deduplicated).
    #[test]
    fn own_contract_merges_far_parm_and_modify_into_one_pragma() {
        let (spec, ctx) = crate::lang::load_cached("x86:LE:32:default").expect("language tables");
        let mut f = crate::decompile::build::raw_funcdata(spec, "f", &[0xc3], 0x1000, ctx);
        let r = regs();
        assert_eq!(own_contract(&f, &r.table, false, None), None, "nothing to declare");
        assert_eq!(own_contract(&f, &r.table, true, None), Some("parm []".into()));
        assert_eq!(own_contract(&f, &r.table, true, Some(0)), Some("parm caller []".into()), "caller pops");
        assert_eq!(own_contract(&f, &r.table, true, Some(8)), Some("parm []".into()), "the callee pops: the default");
        f.far_return = true;
        assert_eq!(own_contract(&f, &r.table, true, None), Some("far parm []".into()));
        let (eax, edx, ebp) = (off(&r.table, "eax"), off(&r.table, "edx"), off(&r.table, "ebp"));
        f.own_modify = Some(vec![edx + 1, eax, ebp, eax]); // DH, EAX, EBP, EAX again
        assert_eq!(own_contract(&f, &r.table, true, None), Some("far parm [] modify [edx eax]".into()));
        f.far_return = false;
        f.own_modify = Some(vec![ebp]);
        assert_eq!(own_contract(&f, &r.table, false, None), None, "a modify list of only EBP is nothing");
    }

    /// A result delivered in a register other than the default gets a `value [..]` clause between
    /// `parm` and `modify`; the default family (EAX/AX/AL) never does; EBP never does.
    #[test]
    fn own_contract_declares_a_nondefault_return_register() {
        let (spec, ctx) = crate::lang::load_cached("x86:LE:32:default").expect("language tables");
        let mut f = crate::decompile::build::raw_funcdata(spec, "f", &[0xc3], 0x1000, ctx);
        let r = regs();
        let (eax, ebx, ebp) = (off(&r.table, "eax"), off(&r.table, "ebx"), off(&r.table, "ebp"));
        let reg = f.spaces.by_name("register").unwrap();
        let ret = f
            .op_ids()
            .find(|&op| f.op(op).code() == crate::decompile::opcode::OpCode::Return)
            .expect("the RET's RETURN op");
        let at = |f: &mut crate::decompile::funcdata::Funcdata, o: u64, sz: u32| {
            f.new_varnode(sz, crate::decompile::space::Address::new(reg, o))
        };
        let v = at(&mut f, ebx, 4);
        f.op_insert_input(ret, 1, v);
        f.own_modify = Some(vec![ebx]);
        assert_eq!(own_contract(&f, &r.table, false, None), Some("value [ebx] modify [ebx]".into()));
        assert_eq!(own_contract(&f, &r.table, true, Some(0)), Some("parm caller [] value [ebx] modify [ebx]".into()), "between parm and modify");
        assert_eq!(value_clause(&r.table, eax, 4), None, "EAX is the default");
        assert_eq!(value_clause(&r.table, eax, 1), None, "AL is the default");
        assert_eq!(value_clause(&r.table, ebx, 1), Some("value [bl]".into()), "a sub-register returns by its own name");
        assert_eq!(value_clause(&r.table, ebp, 4), None, "EBP is rejected by Watcom");
        assert_eq!(value_clause(&r.table, eax, 8), None, "a 64-bit pair is the default EDX:EAX");
    }

    /// The WITNESSED caller-side clause (`emit.caller-parm=witnessed`, item 5): stated at the
    /// positional default too — the clause is the only thing pinning ARITY in a caller — but only
    /// when the callee's own bytes prove every named register is read and no omitted one is. The
    /// second half is the one that bites: a callee beginning `MOV EBP,EAX` reads EAX, so a clause
    /// naming only ESI is WITHDRAWN rather than added (the second subject's func_0x00008051).
    /// Dropping the witness entirely was measured at 108 wrong of 145 there, which is why the
    /// relaxation is exactly one predicate and not the whole suppression.
    #[test]
    fn the_witnessed_parm_clause_needs_both_halves_of_the_read_witness() {
        let r = regs();
        let g = |n: &str| (off(&r.table, n), 4u32);
        let (eax, edx, ebx, esi) = (g("eax"), g("edx"), g("ebx"), g("esi"));
        let w = |st: &[(u64, u32)], rd: &[(u64, u32)]| witnessed_parm_from_storages(st, rd, &r.table);
        // the order IS Watcom's default, so today's rule says nothing — and that silence is the
        // arity statement being thrown away with the order statement
        assert_eq!(nondefault_parm_from_storages(&[eax, edx], &r.table), None);
        // witness agrees with the clause: stated anyway, for the arity
        assert_eq!(w(&[eax, edx], &[eax, edx]), Some("[eax] [edx]".into()));
        // a register the clause OMITS is proven read: WITHDRAWN (the func_0x00008051 case)
        assert_eq!(w(&[esi], &[eax]), None, "a parameter the clause omits withdraws it");
        assert_eq!(w(&[eax, edx], &[eax, edx, ebx]), None, "an omitted third parameter withdraws it");
        // a register the clause NAMES is not proven read: withdrawn
        assert_eq!(w(&[eax, edx], &[eax]), None, "an unproven parameter withdraws the clause");
        // a non-argument register in the witness is not a parameter and does not withdraw
        assert_eq!(w(&[eax, edx], &[eax, edx, esi]), Some("[eax] [edx]".into()), "ESI is not an argument register");
        // a nondefault order is stated by both rules, and they agree
        assert_eq!(w(&[edx, eax], &[eax, edx]), Some("[edx] [eax]".into()));
        assert_eq!(nondefault_parm_from_storages(&[edx, eax], &r.table), Some("[edx] [eax]".into()));
        // EBP is never argument storage: no clause, under either rule
        assert_eq!(w(&[g("ebp")], &[g("ebp")]), None);
    }

    fn table() -> ContractTable {
        let mut c = ContractTable::default();
        c.parm_map.insert(0x2000, Some(("[edx] [eax]".to_string(), vec![4, 4])));
        c.parm_map.insert(0x3000, Some(("[]".to_string(), vec![1])));
        c.parm_map.insert(0x4000, None); // default order: nothing to declare
        let mut m = std::collections::BTreeMap::new();
        m.insert(0x2000, Some(vec![4u32, 4]));
        m.insert(0x3000, Some(vec![4u32]));
        m.insert(0x4000, Some(vec![4u32]));
        c.caller_calls.insert(0x1000, m);
        c
    }

    /// The caller-side post-pass on text: a callee's pragma is prepended where the TU has none,
    /// MERGED into an existing `modify` line, left alone when the line already carries `parm`;
    /// gated on arity (every site) and width (a narrower register overflows to the stack), the
    /// stack-convention `[]` gating on arity only; nothing without the caller's arity map.
    #[test]
    fn patch_caller_prepends_or_merges_under_the_arity_and_width_gates() {
        let c = table();
        let src = "extern int func_0x00002000();
extern int func_0x00004000();
int4 FUN_00001000(void)
{
  func_0x00002000(1, 2);
  return func_0x00004000(3);
}
";
        assert_eq!(c.patch_caller(src, Some(0x1000)), Some(format!("#pragma aux func_0x00002000 parm [edx] [eax];\n{src}")), "prepended for the nondefault callee only");
        assert_eq!(c.patch_caller(src, None), None, "no arity map, no patch");
        let with_modify = format!("#pragma aux func_0x00002000 modify [eax];\n{src}");
        assert_eq!(c.patch_caller(&with_modify, Some(0x1000)), Some(with_modify.replace("#pragma aux func_0x00002000 modify [eax];", "#pragma aux func_0x00002000 parm [edx] [eax] modify [eax];")), "merged into the existing line");
        let with_parm = format!("#pragma aux func_0x00002000 parm caller [] modify [eax];\n{src}");
        assert_eq!(c.patch_caller(&with_parm, Some(0x1000)), None, "an existing parm clause wins");
        // arity gate: the caller passes one argument where the pragma has two
        let mut c2 = table();
        c2.caller_calls.get_mut(&0x1000).unwrap().insert(0x2000, Some(vec![4]));
        assert_eq!(c2.patch_caller(src, Some(0x1000)), None);
        // width gate: a 2-byte register parameter meeting a 4-byte argument overflows
        let mut c3 = table();
        c3.parm_map.insert(0x2000, Some(("[dx] [eax]".to_string(), vec![2, 4])));
        assert_eq!(c3.patch_caller(src, Some(0x1000)), None);
        // a narrower ARGUMENT is fine
        c3.caller_calls.get_mut(&0x1000).unwrap().insert(0x2000, Some(vec![1, 4]));
        assert!(c3.patch_caller(src, Some(0x1000)).is_some());
        // the stack-convention callee gates on arity only: a byte parameter takes a 4-byte argument
        let src3 = "extern int func_0x00003000();
int4 FUN_00001000(void)
{
  return func_0x00003000(3);
}
";
        assert_eq!(c.patch_caller(src3, Some(0x1000)), Some(format!("#pragma aux func_0x00003000 parm [];\n{src3}")));
        // disagreeing sites (None) block the callee
        let mut c4 = table();
        c4.caller_calls.get_mut(&0x1000).unwrap().insert(0x2000, None);
        assert_eq!(c4.patch_caller(src, Some(0x1000)), None);
        assert_eq!(externed_callees(src), vec![0x2000, 0x4000]);
    }

    /// Argument-order recovery per TU: every site of a callee must carry the same recovered
    /// order, be reorder-safe and use the argument registers; the result is the per-site
    /// permutation and the callee's `parm [..]` clause; an excluded callee, the function itself,
    /// an unsafe site or disagreeing sites give nothing.
    #[test]
    fn call_arg_orders_permute_only_unanimous_safe_sites() {
        let r = regs();
        let (eax, edx, ebx) = (off(&r.table, "eax"), off(&r.table, "edx"), off(&r.table, "ebx"));
        let mut report = crate::decompile::printc::EmitReport::default();
        report.port.call_order_candidates = vec![(0x1010, 0x2000, vec![true, true]), (0x1020, 0x2000, vec![true, true]), (0x1030, 0x5000, vec![true, false]), (0x1040, 0x1000, vec![true])];
        let mut orders = crate::recompile::passes::ParamOrders::default();
        orders.site_orders.insert(0x1010, vec![edx, eax]);
        orders.site_orders.insert(0x1020, vec![edx, eax]);
        orders.site_orders.insert(0x1030, vec![edx, eax]);
        orders.site_orders.insert(0x1040, vec![eax]);
        let (perms, parms) = call_arg_orders(&report, 0x1000, &orders, &r);
        assert_eq!(perms.get(&0x1010), Some(&vec![1usize, 0]));
        assert_eq!(perms.get(&0x1020), Some(&vec![1usize, 0]));
        assert_eq!(perms.get(&0x1030), None, "an unsafe argument vetoes the site");
        assert_eq!(perms.get(&0x1040), None, "the function itself is never permuted");
        assert_eq!(parms.get(&0x2000).map(String::as_str), Some("parm [edx] [eax]"));
        assert_eq!(parms.len(), 1);
        // two sites of one callee disagreeing → nothing for that callee
        orders.site_orders.insert(0x1020, vec![eax, edx]);
        let (perms, parms) = call_arg_orders(&report, 0x1000, &orders, &r);
        assert!(perms.is_empty() && parms.is_empty());
        // an excluded callee → nothing; a register outside the argument set → nothing
        orders.site_orders.insert(0x1020, vec![edx, eax]);
        orders.excluded.insert(0x2000);
        assert!(call_arg_orders(&report, 0x1000, &orders, &r).1.is_empty());
        orders.excluded.clear();
        orders.site_orders.insert(0x1010, vec![ebx, eax]);
        orders.site_orders.insert(0x1020, vec![ebx, eax]);
        assert!(call_arg_orders(&report, 0x1000, &orders, &r).1.is_empty(), "EBX is not where a 2-arg default puts anything");
    }
}
