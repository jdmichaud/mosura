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

use crate::decompile::fspec::{effect, type_class, EffectRecord, ParamEntry, ParamList, ProtoModel};
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
    let proto = default_prototype(&doc)?;
    let input = proto.children().find(|n| n.tag_name().name() == "input")?;
    decode_param_list(spec, spaces, input, false)
}

/// The `<default_proto>` **output** (return) [`ParamList`] of `(language_id, compiler_spec_id)` —
/// Ghidra `ParamListStandardOut::decode` over the `<output>` element (`fspec.cc:1776`, which just
/// runs `ParamListStandard::decode` with `is_output`). `None` when the cspec / its default prototype
/// / an `<output>` element can't be located.
pub fn default_output_paramlist(
    spec: &Spec,
    language_id: &str,
    compiler_spec_id: &str,
    spaces: &SpaceManager,
) -> Option<ParamList> {
    let path = crate::lang::resolve_cspec(language_id, compiler_spec_id)?;
    let text = std::fs::read_to_string(path).ok()?;
    let doc = roxmltree::Document::parse(&text).ok()?;
    let proto = default_prototype(&doc)?;
    let output = proto.children().find(|n| n.tag_name().name() == "output")?;
    decode_param_list(spec, spaces, output, true)
}

/// Decode the default-calling-convention [`ProtoModel`] of `(language_id, compiler_spec_id)` from
/// its `.cspec` (Ghidra `ProtoModel::decode`, `fspec.cc:2545`). `None` when the cspec / its default
/// prototype can't be located; otherwise the input/output ParamLists (each `None` only if that
/// element is absent) and the effect list built exactly as `ProtoModel::decode` does:
///   - each register `<pentry>` of an `<input killedbycall="true">`/`<output killedbycall="true">`
///     contributes an auto `killedbycall` record (`parsePentry`, `fspec.cc:1246`) — inert for x86-64
///     SysV, whose `<input>`/`<output>` set no such attribute;
///   - `<unaffected>`/`<killedbycall>` children add `unaffected`/`killedbycall` records;
///   - a prototype `<returnaddress>` (else the compiler-spec-level default `<returnaddress>`,
///     `fspec.cc:2689`) adds a `return_address` record;
///   - the whole list is sorted by `(space, offset)` (`EffectRecord::compareByAddress`).
/// Decode the compiler spec's `<stackpointer>` element (Ghidra `CompilerSpec::decode`,
/// `compiler.cc`: `<stackpointer register="ESP" space="ram"/>`) into the stack pointer register's
/// `(space, offset, size)`.
///
/// **Why this is read from the spec and not hardcoded.** Ghidra's `ia.sinc` defines two register
/// files for x86: under `@ifdef IA64` the 8-byte `[RAX RCX RDX RBX RSP RBP RSI RDI]` puts RSP at
/// `0x20`, while the `@else` 4-byte `[EAX ECX EDX EBX ESP EBP ESI EDI]` — the file `x86:LE:32` uses
/// — puts **ESP at `0x10`**, with `0x20` past the general-purpose block entirely. A constant that is
/// right for one is silently wrong for the other, and "silently" is the word: a stack-pointer offset
/// that matches no register does not fail, it just never propagates, so stack-frame recovery yields
/// nothing at all and every frame slot degenerates into an offset from an unmodelled register.
pub fn default_stack_pointer(
    spec: &Spec,
    language_id: &str,
    compiler_spec_id: &str,
    spaces: &SpaceManager,
) -> Option<(SpaceId, u64, u32)> {
    let path = crate::lang::resolve_cspec(language_id, compiler_spec_id)?;
    let text = std::fs::read_to_string(path).ok()?;
    let doc = roxmltree::Document::parse(&text).ok()?;
    let sp = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "stackpointer")?;
    let name = sp.attribute("register")?;
    Some((spaces.by_name("register")?, spec.register_offset(name)?, spec.register_size(name)?))
}

pub fn default_proto_model(
    spec: &Spec,
    language_id: &str,
    compiler_spec_id: &str,
    spaces: &SpaceManager,
) -> Option<ProtoModel> {
    let path = crate::lang::resolve_cspec(language_id, compiler_spec_id)?;
    let text = std::fs::read_to_string(path).ok()?;
    let doc = roxmltree::Document::parse(&text).ok()?;
    let proto = default_prototype(&doc)?;

    let mut input = None;
    let mut output = None;
    let mut effectlist: Vec<EffectRecord> = Vec::new();
    let mut saw_retaddr = false;

    for child in proto.children().filter(roxmltree::Node::is_element) {
        match child.tag_name().name() {
            "input" => {
                input = decode_param_list(spec, spaces, child, false);
                if child.attribute("killedbycall") == Some("true") {
                    push_auto_killedbycall(spec, spaces, child, &mut effectlist);
                }
            }
            "output" => {
                output = decode_param_list(spec, spaces, child, true);
                if child.attribute("killedbycall") == Some("true") {
                    push_auto_killedbycall(spec, spaces, child, &mut effectlist);
                }
            }
            "unaffected" => push_effect_records(spec, spaces, child, effect::UNAFFECTED, &mut effectlist),
            "killedbycall" => {
                push_effect_records(spec, spaces, child, effect::KILLEDBYCALL, &mut effectlist);
            }
            "returnaddress" => {
                push_effect_records(spec, spaces, child, effect::RETURN_ADDRESS, &mut effectlist);
                saw_retaddr = true;
            }
            _ => {}
        }
    }

    // Ghidra: if the model has no <returnaddress>, use the compiler-spec-level default one
    // (`ProtoModel::decode`, fspec.cc:2689 — `glb->defaultReturnAddr`).
    if !saw_retaddr {
        if let Some(ra) = doc
            .root_element()
            .children()
            .find(|n| n.tag_name().name() == "returnaddress")
        {
            push_effect_records(spec, spaces, ra, effect::RETURN_ADDRESS, &mut effectlist);
        }
    }

    // `sort(effectlist, EffectRecord::compareByAddress)` (fspec.cc:2693) — by (space, offset).
    effectlist.sort_by(|a, b| a.space.0.cmp(&b.space.0).then(a.offset.cmp(&b.offset)));
    Some(ProtoModel { input, output, effectlist })
}

/// Resolve the `<default_proto><prototype>` node of a parsed cspec document.
fn default_prototype<'a, 'input>(
    doc: &'a roxmltree::Document<'input>,
) -> Option<roxmltree::Node<'a, 'input>> {
    doc.descendants()
        .find(|n| n.tag_name().name() == "default_proto")?
        .descendants()
        .find(|n| n.tag_name().name() == "prototype")
}

/// Push a `killedbycall` [`EffectRecord`] per register `<pentry>` of a `killedbycall="true"` list —
/// Ghidra `EffectRecord(entry, killedbycall)` (`fspec.cc:2223`, the ParamEntry's `(space,base,size)`).
fn push_auto_killedbycall(
    spec: &Spec,
    spaces: &SpaceManager,
    list_elem: roxmltree::Node,
    effectlist: &mut Vec<EffectRecord>,
) {
    let reg = spaces.by_name("register");
    for pentry in list_elem.descendants().filter(|n| n.tag_name().name() == "pentry") {
        let group = 0; // group id is irrelevant to the EffectRecord (only space/offset/size are used)
        if let Some(pe) = decode_pentry(spec, spaces, pentry, group) {
            if Some(pe.space) == reg {
                effectlist.push(EffectRecord {
                    space: pe.space,
                    offset: pe.addressbase,
                    size: pe.size,
                    effect: effect::KILLEDBYCALL,
                });
            }
        }
    }
}

/// Decode each `<register>`/`<varnode>`/`<addr>` child of an effect-group element into an
/// [`EffectRecord`] of the group's effect type (Ghidra `EffectRecord::decode`, `fspec.cc:2256`,
/// which reads a `VarnodeData` giving `(space, offset, size)` — a register name resolves via the
/// sleigh register table).
fn push_effect_records(
    spec: &Spec,
    spaces: &SpaceManager,
    group_elem: roxmltree::Node,
    effect_type: u8,
    effectlist: &mut Vec<EffectRecord>,
) {
    for storage in group_elem.children().filter(roxmltree::Node::is_element) {
        if let Some((space, offset, size)) = decode_storage(spec, spaces, storage) {
            effectlist.push(EffectRecord { space, offset, size, effect: effect_type });
        }
    }
}

/// Resolve a storage element (`<register name=…>` or `<varnode/addr space=… offset=… size=…>`) to
/// `(space, offset, size)` — the `VarnodeData` a register name / explicit address decodes to.
fn decode_storage(
    spec: &Spec,
    spaces: &SpaceManager,
    node: roxmltree::Node,
) -> Option<(SpaceId, u64, u32)> {
    match node.tag_name().name() {
        "register" => {
            let name = node.attribute("name")?;
            Some((spaces.by_name("register")?, spec.register_offset(name)?, spec.register_size(name)?))
        }
        "varnode" | "addr" => {
            let space = spaces.by_name(node.attribute("space")?)?;
            let offset: u64 = node.attribute("offset")?.parse().ok()?;
            let size: u32 = node.attribute("size").and_then(|s| s.parse().ok()).unwrap_or(0);
            Some((space, offset, size))
        }
        _ => None,
    }
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
    fn watcall_default_is_eax_edx_ebx_ecx() {
        // The beyond-Ghidra x86-32-watcom cspec (`__watcall`) — Watcom's register convention
        // passes integer/pointer args in EAX, EDX, EBX, ECX (open-watcom-v2 owflat.h:519 /
        // asmins.c:935), then the stack. Validates the mosura-authored cspec loads + decodes.
        if crate::lang::resolve_cspec("x86:LE:32:default", "watcom").is_none() {
            eprintln!("skip: watcom cspec / ghidra tree not present");
            return;
        }
        let regs = load("x86:LE:32:default", "watcom").unwrap_or_default();
        let (spec, _) = crate::lang::load("x86:LE:32:default").unwrap();
        let off = |n: &str| spec.register_offset(n).unwrap();
        assert_eq!(
            regs,
            vec![off("EAX"), off("EDX"), off("EBX"), off("ECX")],
            "watcall arg registers must be EAX, EDX, EBX, ECX in order"
        );
    }

    #[test]
    fn watcall_convention_confirmed_against_wcc386() {
        // EMPIRICAL oracle: the arg-register loads a real Open Watcom `wcc386` emits for a
        // `__watcall` call — the ground truth the cspec models. These 47 bytes are the `caller`
        // routine of oracle/analysis-corpus/src/watcall_probe.c, compiled with OW 2.0 wcc386
        // (`~/tools/open-watcom-v2/rel/binl/wcc386 watcall_probe.c -bt=dos`), which calls
        // callee(0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555). Disassembled by
        // mosura's own engine, it must load the args into EAX, EDX, EBX, ECX (then push the 5th)
        // — confirming the watcall register order the cspec (`specs/x86-32-watcom.cspec`) declares.
        let caller: &[u8] = &[
            0x68, 0x14, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x53, 0x51, 0x52, 0x68,
            0x55, 0x55, 0x55, 0x55, 0xB9, 0x44, 0x44, 0x44, 0x44, 0xBB, 0x33, 0x33, 0x33, 0x33,
            0xBA, 0x22, 0x22, 0x22, 0x22, 0xB8, 0x11, 0x11, 0x11, 0x11, 0xE8, 0x00, 0x00, 0x00,
            0x00, 0x5A, 0x59, 0x5B, 0xC3,
        ];
        let Some((spec, ctx)) = crate::lang::load("x86:LE:32:default") else {
            eprintln!("skip: x86 sla not present");
            return;
        };
        let asm: Vec<String> = spec
            .disassemble_ctx(caller, 0x1000, &ctx)
            .into_iter()
            .map(|i| format!("{} {}", i.mnemonic.trim(), i.body.trim()))
            .collect();
        // The four register args, in watcall order, each carrying its sentinel immediate.
        for want in ["MOV EAX,0x11111111", "MOV EDX,0x22222222", "MOV EBX,0x33333333", "MOV ECX,0x44444444"] {
            assert!(asm.iter().any(|l| l == want), "watcall arg load {want:?} missing; got {asm:?}");
        }
        // And the order EAX < EDX < EBX < ECX (successive args to the four registers in turn).
        let pos = |m: &str| asm.iter().position(|l| l == m).unwrap();
        assert!(
            pos("MOV EAX,0x11111111") > pos("MOV ECX,0x44444444"),
            "wcc386 loads the registers in reverse (ECX..EAX) right before the call — order confirmed"
        );
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

    // ---- A1 premise check: cspec-derived model vs the hardcoded fspec SysV lists ---------------

    fn fmt_paramlist(pl: &ParamList) -> Vec<String> {
        let mut v: Vec<String> = pl
            .entry
            .iter()
            .map(|e| {
                format!(
                    "g{} class{} sp{} off{:#x} size{} min{} align{}",
                    e.group, e.type_class, e.space.0, e.addressbase, e.size, e.minsize, e.alignment
                )
            })
            .collect();
        v.push(format!("resource_start={:?} is_output={}", pl.resource_start, pl.is_output));
        v
    }

    fn fmt_efflist(el: &[EffectRecord]) -> Vec<String> {
        el.iter()
            .map(|e| format!("sp{} off{:#x} size{} eff{}", e.space.0, e.offset, e.size, e.effect))
            .collect()
    }

    /// PREMISE CHECK (A1): dump the cspec-derived input/output ParamLists + effect list AND the
    /// hardcoded `fspec::sysv_*` lists, field by field, so the lane (byte-identical vs mover) is
    /// visible. Prints to stderr; asserts only the input list matches (the one already claimed
    /// equal), and reports the effect-list divergence without failing.
    #[test]
    fn premise_dump_cspec_vs_hardcoded() {
        use crate::decompile::fspec;
        let Some((spec, _ctx)) = crate::lang::load("x86:LE:64:default") else {
            eprintln!("skip: ghidra tree not present");
            return;
        };
        let spaces = SpaceManager::standard();
        let Some(pm) = default_proto_model(&spec, "x86:LE:64:default", "gcc", &spaces) else {
            eprintln!("skip: no cspec proto model");
            return;
        };

        let hc_in = fspec::sysv_input(&spaces).unwrap();
        let hc_out = fspec::sysv_output(&spaces).unwrap();
        let hc_eff = fspec::sysv_effect_list(&spaces);

        eprintln!("=== INPUT: cspec vs hardcoded ===");
        eprintln!("cspec:    {:#?}", fmt_paramlist(pm.input.as_ref().unwrap()));
        eprintln!("hardcode: {:#?}", fmt_paramlist(&hc_in));
        eprintln!("=== OUTPUT: cspec vs hardcoded ===");
        eprintln!("cspec:    {:#?}", fmt_paramlist(pm.output.as_ref().unwrap()));
        eprintln!("hardcode: {:#?}", fmt_paramlist(&hc_out));
        eprintln!("=== EFFECT: cspec vs hardcoded ===");
        eprintln!("cspec:    {:#?}", fmt_efflist(&pm.effectlist));
        eprintln!("hardcode: {:#?}", fmt_efflist(&hc_eff));

        eprintln!(
            "INPUT identical:  {}",
            fmt_paramlist(pm.input.as_ref().unwrap()) == fmt_paramlist(&hc_in)
        );
        eprintln!(
            "OUTPUT identical: {}",
            fmt_paramlist(pm.output.as_ref().unwrap()) == fmt_paramlist(&hc_out)
        );
        eprintln!("EFFECT identical: {}", fmt_efflist(&pm.effectlist) == fmt_efflist(&hc_eff));

        // The input list is the one the existing test already asserts equal.
        assert_eq!(fmt_paramlist(pm.input.as_ref().unwrap()), fmt_paramlist(&hc_in));
    }
}
