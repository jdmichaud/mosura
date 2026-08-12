//! LE (Linear Executable) loader gates that need no user-provided binary.
//!
//! **Why this file exists.** The LE loader is the oldest beyond-Ghidra loader in the tree and the
//! one behind both WAR2 and Descent, but its only gates were `le_war2_objects` and
//! `le_war2_analysis` in `analysis_parity.rs` — and those are skip-if-absent on a copyrighted
//! binary. On a machine without it they "pass" in 0.00 s, so the loader had **no real coverage**,
//! while the newer X-32 loader had seven binary-free tests (`x32_loader.rs`). This closes that
//! asymmetry with the same synthetic-container discipline.
//!
//! The builder emits a real bound-DOS/4GW-shaped LE: an MZ stub whose `e_lfanew` is deliberately
//! invalid (so detection must *scan*, as it does for a real bound exe), an LE header, an object
//! table, a page map, and page data that closes exactly to end of file.
//!
//! See `docs/le-loader-notes.md` for the format derivation and the two-oracle policy.

use mosura::analysis::loader;

const PAGE: u32 = 0x1000;

struct Object {
    virtual_size: u32,
    base: u32,
    flags: u32,
    pages: u32,
}

/// Build a bound-DOS/4GW-shaped LE image.
///
/// * `stub_len` — bytes of MZ stub + bound extender in front of the LE header.
/// * `objects` — the object table to emit.
/// * `eip_object` / `eip` — the entry, 1-based object number and offset within it.
/// * `page_bytes` — file-backed page data, laid out contiguously and closing to EOF.
fn build_le(
    stub_len: usize,
    objects: &[Object],
    eip_object: u32,
    eip: u32,
    page_bytes: &[u8],
) -> Vec<u8> {
    let total_pages: u32 = objects.iter().map(|o| o.pages).sum();
    assert!(!page_bytes.is_empty() && page_bytes.len() as u32 <= total_pages * PAGE);

    // LE header (0xc4 bytes) + object table (24 per object) + page map (4 per page).
    let obj_table_off = 0xc4u32;
    let pagemap_off = obj_table_off + objects.len() as u32 * 24;
    let mut le = vec![0u8; pagemap_off as usize + total_pages as usize * 4];
    le[0..2].copy_from_slice(b"LE");
    // border/worder 0 (little-endian), format level 0
    le[0x08..0x0a].copy_from_slice(&2u16.to_le_bytes()); // cpu = 386
    le[0x0a..0x0c].copy_from_slice(&1u16.to_le_bytes()); // os = OS/2, what Watcom emits
    le[0x14..0x18].copy_from_slice(&total_pages.to_le_bytes());
    le[0x18..0x1c].copy_from_slice(&eip_object.to_le_bytes());
    le[0x1c..0x20].copy_from_slice(&eip.to_le_bytes());
    le[0x20..0x24].copy_from_slice(&(objects.len() as u32).to_le_bytes()); // stack object
    le[0x28..0x2c].copy_from_slice(&PAGE.to_le_bytes());
    // bytes used in the last physical page
    let last = page_bytes.len() as u32 % PAGE;
    le[0x2c..0x30].copy_from_slice(&(if last == 0 { PAGE } else { last }).to_le_bytes());
    le[0x40..0x44].copy_from_slice(&obj_table_off.to_le_bytes());
    le[0x44..0x48].copy_from_slice(&(objects.len() as u32).to_le_bytes());
    le[0x48..0x4c].copy_from_slice(&pagemap_off.to_le_bytes());
    // no fixups: fixup page table / record table offsets left 0

    let mut page_index = 1u32;
    for (i, o) in objects.iter().enumerate() {
        let b = obj_table_off as usize + i * 24;
        le[b..b + 4].copy_from_slice(&o.virtual_size.to_le_bytes());
        le[b + 4..b + 8].copy_from_slice(&o.base.to_le_bytes());
        le[b + 8..b + 12].copy_from_slice(&o.flags.to_le_bytes());
        le[b + 12..b + 16].copy_from_slice(&page_index.to_le_bytes());
        le[b + 16..b + 20].copy_from_slice(&o.pages.to_le_bytes());
        page_index += o.pages;
    }
    // identity page map: logical page i -> physical page i, flags 0 = valid
    for p in 0..total_pages {
        let b = pagemap_off as usize + p as usize * 4;
        le[b..b + 3].copy_from_slice(&[((p + 1) >> 8) as u8, ((p + 1) & 0xff) as u8, 0]);
    }

    // MZ stub. `e_lfanew` is left INVALID on purpose: that is what a bound DOS/4GW exe does, so
    // detection has to scan for the LE header rather than follow the pointer.
    let mut out = vec![0u8; stub_len];
    out[0..2].copy_from_slice(b"MZ");
    out[0x02..0x04].copy_from_slice(&0x50u16.to_le_bytes());
    out[0x04..0x06].copy_from_slice(&1u16.to_le_bytes());
    out[0x08..0x0a].copy_from_slice(&2u16.to_le_bytes());
    // Bound by default: e_lfanew invalid, so detection must scan. `build_le_standalone` below
    // writes the real offset instead, which is the other shape found in the wild.
    out[0x3c..0x40].copy_from_slice(&0x0badf00du32.to_le_bytes()); // invalid e_lfanew
    out.extend_from_slice(&le);
    out.extend_from_slice(page_bytes);
    out
}

/// As [`build_le`], but with a VALID `e_lfanew` pointing at the LE header — a **standalone** LE,
/// which is what a DOS/4GW program looks like when the extender ships as a separate `DOS4GW.EXE`
/// rather than bound into the image.
///
/// Both shapes exist in the wild and they take different paths through `loader::load_container`:
/// a standalone LE is dispatched straight to `load_le` by `is_le_header(data, e_lfanew)`, while a
/// bound one falls through to the 16-bit MZ stub and is only reachable via the opt-in native view.
/// Real examples: Worms (1995) ships standalone LEs beside `DOS4GW.EXE`; WAR2 and Descent are
/// bound and set `e_lfanew` to garbage on purpose.
fn build_le_standalone(
    stub_len: usize,
    objects: &[Object],
    eip_object: u32,
    eip: u32,
    page_bytes: &[u8],
) -> Vec<u8> {
    let mut out = build_le(stub_len, objects, eip_object, eip, page_bytes);
    out[0x3c..0x40].copy_from_slice(&(stub_len as u32).to_le_bytes());
    out
}

/// Two objects in WAR2's shape: code at 0x10000, data above it.
fn two_objects(code_pages: u32, data_pages: u32) -> Vec<Object> {
    vec![
        Object { virtual_size: code_pages * PAGE, base: 0x10000, flags: 0x2045, pages: code_pages },
        Object {
            virtual_size: data_pages * PAGE,
            base: 0x10000 + code_pages * PAGE,
            flags: 0x2043,
            pages: data_pages,
        },
    ]
}

/// Page data whose entry calls a function that calls a second one — so discovery has to walk.
fn call_graph_pages(entry_off: u32, pages: u32) -> (Vec<u8>, [u32; 2]) {
    let mut p = vec![0x90u8; (pages * PAGE) as usize];
    let (f1, f2) = (0x400u32, 0x800u32);
    let e = entry_off as usize;
    let rel1 = (f1 as i64 - (entry_off as i64 + 5)) as i32;
    p[e] = 0xe8;
    p[e + 1..e + 5].copy_from_slice(&rel1.to_le_bytes());
    p[e + 5] = 0xc3;
    let rel2 = (f2 as i64 - (f1 as i64 + 5)) as i32;
    p[f1 as usize] = 0xe8;
    p[f1 as usize + 1..f1 as usize + 5].copy_from_slice(&rel2.to_le_bytes());
    p[f1 as usize + 5] = 0xc3;
    p[f2 as usize..f2 as usize + 3].copy_from_slice(&[0x31, 0xc0, 0xc3]);
    (p, [f1, f2])
}

/// Vary the stub length and the entry, so nothing may be hardcoded from WAR2 (whose LE sits at
/// 0x37CF4 with entry `obj1:0x501F8`).
const CASES: &[(usize, u32)] = &[(0x200, 0x10), (0x1000, 0x120), (0x37c00, 0x20)];

#[test]
fn detects_a_bound_le_by_scanning() {
    for &(stub, entry) in CASES {
        let (pages, _) = call_graph_pages(entry, 3);
        let data = build_le(stub, &two_objects(2, 1), 1, entry, &pages);
        let off = loader::detect_le(&data).expect("LE header found by scan");
        assert_eq!(off, stub, "the LE header starts right after the stub");
        assert!(
            loader::le::is_le_header(&data, off),
            "and it validates as one"
        );
    }
}

#[test]
fn does_not_claim_other_containers() {
    let mut bare_mz = vec![0u8; 0x400];
    bare_mz[0..2].copy_from_slice(b"MZ");
    bare_mz[0x04..0x06].copy_from_slice(&2u16.to_le_bytes());
    bare_mz[0x08..0x0a].copy_from_slice(&2u16.to_le_bytes());
    let mut elf = vec![0u8; 0x400];
    elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    // The letters "LE" occurring in data must not be mistaken for a header: the fixed fields
    // (byte order, cpu, power-of-two page size, in-range object table) are what decide.
    let mut le_in_data = vec![0u8; 0x800];
    le_in_data[0..2].copy_from_slice(b"MZ");
    le_in_data[0x04..0x06].copy_from_slice(&2u16.to_le_bytes());
    le_in_data[0x08..0x0a].copy_from_slice(&2u16.to_le_bytes());
    for at in [0x100, 0x240, 0x3c8] {
        le_in_data[at..at + 4].copy_from_slice(b"LE\xff\xff");
    }

    for (name, d) in [
        ("bare 16-bit MZ", &bare_mz),
        ("ELF", &elf),
        ("\"LE\" bytes in data", &le_in_data),
        ("empty", &vec![]),
    ] {
        assert!(loader::detect_le(d).is_none(), "false positive on {name}");
    }
}

#[test]
fn maps_objects_at_their_relocation_bases() {
    for &(stub, entry) in CASES {
        let (pages, _) = call_graph_pages(entry, 3);
        let data = build_le(stub, &two_objects(2, 1), 1, entry, &pages);
        let prog = loader::load_le(&data).expect("LE load");

        assert_eq!(prog.language_id, "x86:LE:32:default");
        assert_eq!(prog.image_base.offset, 0x10000, "image base = lowest object base");
        let blocks: Vec<_> = prog.memory.blocks().collect();
        assert_eq!(blocks.len(), 2, "one block per object");
        let code = blocks.iter().find(|b| b.is_execute()).expect("a code object");
        let data_blk = blocks.iter().find(|b| !b.is_execute()).expect("a data object");
        assert_eq!(code.start().offset, 0x10000);
        assert_eq!(code.size(), 2 * u64::from(PAGE));
        assert_eq!(data_blk.start().offset, 0x10000 + 2 * u64::from(PAGE));

        // the entry is object-relative: absolute = object base + EIP
        assert_eq!(prog.entry_points.len(), 1);
        assert_eq!(prog.entry_points[0].offset, 0x10000 + u64::from(entry));
        assert!(prog.function_manager.function_at(prog.entry_points[0]).is_some());
    }
}

#[test]
fn entry_is_resolved_through_the_named_object() {
    // EIP is an offset *within* the EIP object, so pointing the entry at object 2 must land in
    // object 2's range — the rule that makes WAR2's 0x10000 + 0x501F8 come out right.
    let (pages, _) = call_graph_pages(0x10, 3);
    let objs = two_objects(2, 1);
    let data = build_le(0x400, &objs, 2, 0x40, &pages);
    let prog = loader::load_le(&data).expect("LE load");
    let want = 0x10000 + 2 * u64::from(PAGE) + 0x40;
    assert_eq!(prog.entry_points[0].offset, want, "entry resolved against object 2's base");
}

#[test]
fn auto_analysis_discovers_the_planted_call_graph() {
    for &(stub, entry) in CASES {
        let (pages, [f1, f2]) = call_graph_pages(entry, 3);
        let data = build_le(stub, &two_objects(2, 1), 1, entry, &pages);
        let mut prog = loader::load_le(&data).expect("LE load");
        mosura::analysis::analyze(&mut prog);
        let found: Vec<u64> =
            prog.function_manager.functions().map(|f| f.entry_point().offset).collect();
        for want in [u64::from(entry), u64::from(f1), u64::from(f2)] {
            let abs = 0x10000 + want;
            assert!(found.contains(&abs), "function {abs:#x} not discovered, got {found:x?}");
        }
    }
}

#[test]
fn native_dispatch_routes_le_and_the_default_stays_on_the_stub() {
    let (pages, _) = call_graph_pages(0x10, 3);
    let data = build_le(0x600, &two_objects(2, 1), 1, 0x10, &pages);
    assert_eq!(mosura::analysis::native_loader_name(&data), Some("LE"));
    // The two-oracle policy: the DEFAULT view of a bound exe is Ghidra's 16-bit MZ-stub reading.
    let prog = loader::load(&data).expect("default dispatch");
    assert_eq!(prog.language_id, "x86:LE:16:Real Mode");
}

#[test]
fn refuses_a_truncated_page_region() {
    // `num_pages` claims more page data than the file holds: the page region cannot close to EOF,
    // and mapping it would read past the end.
    let (pages, _) = call_graph_pages(0x10, 3);
    let mut data = build_le(0x300, &two_objects(2, 1), 1, 0x10, &pages);
    let le = 0x300usize;
    data[le + 0x14..le + 0x18].copy_from_slice(&999u32.to_le_bytes());
    assert!(loader::load_le(&data).is_err(), "an oversized page region must be refused");
}

/// A **standalone** LE must be claimed by the DEFAULT dispatch, not just by the opt-in view.
///
/// This is the other half of the two-oracle policy and the half that had no coverage: the policy
/// keeps a *bound* exe on the Ghidra-parity stub path because Ghidra cannot load the LE, but a
/// standalone LE has a valid `e_lfanew`, so `load_container` routes it to `load_le` directly. Worms
/// (1995) is a real binary of this shape — `WRMS.EXE`, `FMV/PLAY.EXE` and `BLACK.EXE` all have
/// `e_lfanew` pointing at an `LE` and load as `x86:LE:32:default watcom` with no flag at all.
#[test]
fn a_standalone_le_is_claimed_by_the_default_dispatch() {
    for &(stub, entry) in CASES {
        let (pages, [f1, f2]) = call_graph_pages(entry, 3);
        let data = build_le_standalone(stub, &two_objects(2, 1), 1, entry, &pages);

        // detection still finds it, now via e_lfanew rather than the scan
        assert_eq!(loader::detect_le(&data), Some(stub));

        // and the DEFAULT dispatch gives the 32-bit view, not the 16-bit stub
        let mut prog = loader::load(&data).expect("default dispatch loads a standalone LE");
        assert_eq!(
            prog.language_id, "x86:LE:32:default",
            "a standalone LE is Ghidra-parity-irrelevant: there is no reason to show the stub"
        );
        assert_eq!(prog.entry_points[0].offset, 0x10000 + u64::from(entry));

        // and analysis runs over it, as it does through the native path
        mosura::analysis::analyze(&mut prog);
        let found: Vec<u64> =
            prog.function_manager.functions().map(|f| f.entry_point().offset).collect();
        for want in [u64::from(entry), u64::from(f1), u64::from(f2)] {
            assert!(found.contains(&(0x10000 + want)), "function {want:#x} not discovered");
        }
    }
}

/// The bound and standalone shapes must not be confused for one another.
#[test]
fn bound_and_standalone_are_distinguished() {
    let (pages, _) = call_graph_pages(0x10, 3);
    let bound = build_le(0x400, &two_objects(2, 1), 1, 0x10, &pages);
    let standalone = build_le_standalone(0x400, &two_objects(2, 1), 1, 0x10, &pages);

    // both are LE to the native view
    assert_eq!(mosura::analysis::native_loader_name(&bound), Some("LE"));
    assert_eq!(mosura::analysis::native_loader_name(&standalone), Some("LE"));

    // but only the standalone one is claimed by the default dispatch
    assert_eq!(loader::load(&bound).unwrap().language_id, "x86:LE:16:Real Mode");
    assert_eq!(loader::load(&standalone).unwrap().language_id, "x86:LE:32:default");
}
