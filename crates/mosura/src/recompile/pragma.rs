//! The Watcom `#pragma aux` vocabulary of the recompile — the function's OWN side: the
//! spec-built register table, the `parm [..]` list where the recovered storage is not Watcom's
//! positional default, and `own_contract` (the one pragma merging `far`, `parm`, and `modify`).
//! Moved verbatim out of the corpus emit driver (plan WP7 P0 c2, 2026-09-05); the caller side
//! (per-callee pragmas, the caller-side post-pass) follows in c6. Text and register offsets in,
//! text out; nothing here reads a file or a program beyond the language tables.

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
}
