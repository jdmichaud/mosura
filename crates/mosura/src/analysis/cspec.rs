//! Calling-convention loading from the `.cspec` (analysis-side C0/C1) — a port of Ghidra's
//! `BasicCompilerSpec`/`ParamListStandard` XML decode for the *default prototype model*.
//!
//! Ghidra (`Ghidra/Framework/SoftwareModeling/.../program/model/lang/BasicCompilerSpec`
//! + the decompiler `ParamListStandard::decode`, `fspec.cc:1451`) reads the compiler spec's
//! `<default_proto><prototype>` and its `<input>`/`<output>` `<pentry>` resource lists,
//! turning each `<pentry>` into a storage resource (a `ParamEntry`). This module reproduces
//! that decode against the real `.cspec` XML (resolved from the processor `.ldefs`, see
//! [`crate::lang::resolve_cspec`]), building a [`fspec::ParamList`] — the same public type
//! the decompiler's prototype recovery consumes — without modifying the `decompile/fspec.rs`
//! definitions.
//!
//! C1 ([`integer_arg_registers`]) is the analysis-side slice of `ParamListStandard::assignMap`
//! that the `SymbolicPropogator`'s no-signature parameter recovery needs: the forward
//! arg→storage order for the integer/general register class.
//!
//! Scope: the GENERAL/FLOAT storage classes mosura's `fspec::type_class` models (the x86
//! corpus uses only `metatype="float"` and the default = `general`). Other Ghidra storage
//! classes (`ptr`/`hiddenret`/`class1..4`, `type.cc:string2typeclass`) and the full
//! `assignMap`/`fillinMap` allocator are decompiler-side and deferred (see
//! `docs/cspec-decompiler-brief.md`).

use crate::decompile::fspec::{type_class, ParamEntry, ParamList};
use crate::decompile::space::{SpaceId, SpaceManager};
use crate::sleigh::engine::Spec;

/// Build the `<default_proto>` **input** [`ParamList`] of `(language_id, compiler_spec_id)`
/// from its `.cspec` (Ghidra `ParamListStandard::decode` over the `<input>` element), or
/// `None` if the cspec / its default prototype can't be located. `spaces` supplies the
/// concrete `register`/`stack` [`SpaceId`]s the entries reference; `spec` resolves
/// `<register name=...>` to a register-space offset.
pub fn default_input_paramlist(
    spec: &Spec,
    language_id: &str,
    compiler_spec_id: &str,
    spaces: &SpaceManager,
) -> Option<ParamList> {
    let path = crate::lang::resolve_cspec(language_id, compiler_spec_id)?;
    let text = std::fs::read_to_string(path).ok()?;
    let doc = roxmltree::Document::parse(&text).ok()?;
    // <compiler_spec> … <default_proto> <prototype> <input> … </input> …
    let proto = doc
        .descendants()
        .find(|n| n.tag_name().name() == "default_proto")?
        .descendants()
        .find(|n| n.tag_name().name() == "prototype")?;
    let input = proto.children().find(|n| n.tag_name().name() == "input")?;
    decode_param_list(spec, spaces, input, false)
}

/// Decode an `<input>`/`<output>` element into a [`ParamList`] (Ghidra
/// `ParamListStandard::decode`, `fspec.cc:1451`): walk the `<pentry>` and `<group>` children
/// in order, assigning group ids exactly as Ghidra does — a flat `<pentry>` takes the next
/// group id and bumps `numgroup`; a `<group>` shares one `basegroup` across all its
/// `<pentry>` children (`parsePentry`/`parseGroup`, `fspec.cc:1226`/`1262`). `resource_start`
/// records each storage-class section boundary (split-float default) plus the trailing
/// `numgroup` sentinel (`fspec.cc:1240`/`1502`). Storage entries whose space mosura doesn't
/// model (e.g. `join`) are skipped — they never participate in register/stack arg recovery.
fn decode_param_list(
    spec: &Spec,
    spaces: &SpaceManager,
    list_elem: roxmltree::Node,
    is_output: bool,
) -> Option<ParamList> {
    let mut entry: Vec<ParamEntry> = Vec::new();
    let mut resource_start: Vec<u32> = Vec::new();
    let mut numgroup: u32 = 0;
    // Track the previous entry's storage class to push a section boundary on a class change
    // (`splitFloat` is the default; the class sequence must be non-increasing, FLOAT→GENERAL).
    let mut last_class: Option<u8> = None;

    for child in list_elem.children().filter(roxmltree::Node::is_element) {
        match child.tag_name().name() {
            "pentry" => {
                let group = numgroup;
                if let Some(pe) = decode_pentry(spec, spaces, child, group) {
                    if last_class != Some(pe.type_class) {
                        // FLOAT (1) precedes GENERAL (0): a new resource section starts here.
                        resource_start.push(group);
                        last_class = Some(pe.type_class);
                    }
                    entry.push(pe);
                }
                numgroup = group + 1;
            }
            "group" => {
                // All <pentry> in a <group> share one group id (`basegroup`).
                let basegroup = numgroup;
                for pe_node in child.children().filter(roxmltree::Node::is_element) {
                    if pe_node.tag_name().name() != "pentry" {
                        continue;
                    }
                    if let Some(pe) = decode_pentry(spec, spaces, pe_node, basegroup) {
                        // A grouped entry is treated as GENERAL for sectioning (fspec.cc:1236).
                        if last_class != Some(type_class::GENERAL) {
                            resource_start.push(basegroup);
                            last_class = Some(type_class::GENERAL);
                        }
                        entry.push(pe);
                    }
                }
                numgroup = basegroup + 1;
            }
            // <rule>/<modelrule> end the resource section (decompiler-side; not modeled here).
            "rule" | "modelrule" => break,
            _ => {}
        }
    }
    if entry.is_empty() {
        return None;
    }
    resource_start.push(numgroup); // trailing sentinel = numgroup (fspec.cc:1502)
    Some(ParamList { entry, resource_start, is_output })
}

/// Decode one `<pentry>` into a [`ParamEntry`] (Ghidra `ParamEntry::decode`, `fspec.cc:501`):
/// `minsize`/`maxsize` → `minsize`/`size`, `metatype` → storage class (`float` → FLOAT, else
/// the default GENERAL; `type.cc:string2typeclass`), `align` → the non-exclusion stride (0 =
/// exclusion / single slot), and the inner `<register>`/`<addr>` → the `(space, addressbase)`.
fn decode_pentry(
    spec: &Spec,
    spaces: &SpaceManager,
    pentry: roxmltree::Node,
    group: u32,
) -> Option<ParamEntry> {
    let minsize: u32 = pentry.attribute("minsize")?.parse().ok()?;
    let size: u32 = pentry.attribute("maxsize")?.parse().ok()?;
    let type_class = match pentry.attribute("metatype") {
        Some("float") => type_class::FLOAT,
        _ => type_class::GENERAL, // default (general) — the only other class in the x86 corpus
    };
    let alignment: u32 = pentry.attribute("align").and_then(|s| s.parse().ok()).unwrap_or(0);

    let storage = pentry.children().find(roxmltree::Node::is_element)?;
    let (space, addressbase) = match storage.tag_name().name() {
        "register" => {
            let name = storage.attribute("name")?;
            (spaces.by_name("register")?, spec.register_offset(name)?)
        }
        "addr" => {
            // <addr space="stack" offset="N"/>. Spaces mosura doesn't model (e.g. join) → skip.
            let space_name = storage.attribute("space")?;
            let offset: u64 = storage.attribute("offset")?.parse().ok()?;
            (spaces.by_name(space_name)?, offset)
        }
        _ => return None,
    };
    Some(ParamEntry { group, type_class, space, addressbase, size, minsize, alignment })
}

/// Forward arg→storage for the integer/general **register** class — the analysis-side slice
/// of Ghidra `ParamListStandard::assignMap` the `SymbolicPropogator` parameter recovery uses:
/// the ordered register offsets of the GENERAL register entries (SysV `RDI,RSI,RDX,RCX,R8,R9`
/// / MS-x64 `RCX,RDX,R8,R9`). Stack resources are excluded — `addParamReferences` skips stack
/// storage (`var.isStackStorage()`), and an x86-16 convention (whose only input pentry is the
/// stack area) therefore yields no registers, recovering nothing.
pub fn integer_arg_registers(list: &ParamList, reg_space: SpaceId) -> Vec<u64> {
    list.entry
        .iter()
        .filter(|e| e.type_class == type_class::GENERAL && e.space == reg_space)
        .map(|e| e.addressbase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(lang: &str, cspec: &str) -> Option<Vec<u64>> {
        let (spec, _ctx) = crate::lang::load(lang)?;
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let list = default_input_paramlist(&spec, lang, cspec, &spaces)?;
        Some(integer_arg_registers(&list, reg))
    }

    #[test]
    fn sysv_default_matches_fspec() {
        // The x86-64-gcc default_proto integer-arg registers, loaded from the .cspec, must
        // equal fspec::sysv_input's hardcoded SysV order (RDI,RSI,RDX,RCX,R8,R9).
        let Some(from_cspec) = load("x86:LE:64:default", "gcc") else {
            eprintln!("skip: ghidra tree not present");
            return;
        };
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let from_fspec = integer_arg_registers(&crate::decompile::fspec::sysv_input(&spaces).unwrap(), reg);
        assert_eq!(from_cspec, from_fspec, "cspec-loaded SysV regs must match fspec::sysv_input");
        assert_eq!(from_cspec.len(), 6, "SysV has 6 integer-arg registers");
    }

    #[test]
    fn msx64_default_is_rcx_rdx_r8_r9() {
        // The x86-64-win default_proto (__fastcall) — MS-x64 integer args RCX,RDX,R8,R9.
        let Some(regs) = load("x86:LE:64:default", "windows") else {
            eprintln!("skip: ghidra tree not present");
            return;
        };
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let s = &spaces;
        let off = |n: &str| {
            let (spec, _) = crate::lang::load("x86:LE:64:default").unwrap();
            spec.register_offset(n).unwrap()
        };
        let _ = (reg, s);
        assert_eq!(regs, vec![off("RCX"), off("RDX"), off("R8"), off("R9")]);
    }

    #[test]
    fn x86_16_default_has_no_register_args() {
        // x86-16 default_proto passes all args on the stack — no integer-arg registers, so
        // param recovery on a 16-bit binary (comcom32/war2) invents nothing (0 spurious).
        if crate::lang::resolve_cspec("x86:LE:16:Real Mode", "default").is_none() {
            eprintln!("skip: ghidra tree not present");
            return;
        }
        let regs = load("x86:LE:16:Real Mode", "default").unwrap_or_default();
        assert!(regs.is_empty(), "x86-16 default convention has no register args, got {regs:x?}");
    }
}
