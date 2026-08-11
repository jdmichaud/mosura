//! X-32 loader gates, provable without any user-provided binary.
//!
//! The real X-32 samples are copyrighted and absent on a clean clone, so they can only ever be a
//! skip-if-absent extra. What actually proves the loader is a **synthetic container builder**:
//! the positive-control discipline `over_decode --self-test` sets, applied to a loader.
//!
//! Every gate is parameterised over more than one entry value and more than one 16-bit-region
//! length, because the two numbers most likely to get hardcoded are exactly the ones both real
//! samples agree on: entry `0xd`, and a selector slot at `flat - 0x3bb8`. A loader that baked in
//! either would pass a single-case test and fail here.
//!
//! See `docs/x32-loader-notes.md` for the format derivation.

use mosura::analysis::loader::{self, x32};

const DESC_TABLE_BYTES: u16 = 0x118; // 35 descriptors, what both real samples carry

/// Build a real X-32 container.
///
/// * `stub_len` — bytes of extender stub in front of the inner MZ.
/// * `sixteen_len` — bytes of 16-bit region; the transfer idiom is placed near its end.
/// * `entry` — the flat entry offset the idiom pushes.
/// * `payload` — the 32-bit flat image.
/// * `bss_end` — the value written to `image[0x12c]` (memory size); 0 to leave it absent.
fn build_x32(
    stub_len: usize,
    sixteen_len: usize,
    entry: u32,
    payload: &[u8],
    bss_end: u32,
) -> Vec<u8> {
    assert_eq!(sixteen_len % 16, 0, "the 32-bit image starts on a paragraph");
    assert!(sixteen_len > 0x200, "room for the header, descriptors and the idiom");

    // --- the inner image: header, descriptor table, 16-bit region, then the flat payload
    let mut img = vec![0u8; sixteen_len];
    img[0x00..0x02].copy_from_slice(&((sixteen_len / 16) as u16).to_le_bytes());
    img[0x02..0x04].copy_from_slice(&DESC_TABLE_BYTES.to_le_bytes());
    // A flat 32-bit code descriptor at base 0: limit 0xffff, access 0x9b (present, code),
    // flags 0xcf (granularity + D/B set, limit high nibble). Same bytes both samples carry.
    for i in 0..(DESC_TABLE_BYTES as usize / 8) {
        let o = 0x18 + i * 8;
        img[o..o + 8].copy_from_slice(&[0xff, 0xff, 0, 0, 0, 0x9b, 0xcf, 0]);
    }
    if bss_end != 0 {
        img[0x12c..0x130].copy_from_slice(&bss_end.to_le_bytes());
    }
    // The transfer idiom, near the end of the 16-bit region but at no fixed distance from it.
    let idiom = sixteen_len - 0x40;
    img[idiom..idiom + 4].copy_from_slice(&[0x2e, 0x66, 0xff, 0x36]); // pushl %cs:[disp16]
    img[idiom + 4..idiom + 6].copy_from_slice(&0x1234u16.to_le_bytes()); // the selector slot
    img[idiom + 6..idiom + 8].copy_from_slice(&[0x66, 0x68]); // pushl imm32
    img[idiom + 8..idiom + 12].copy_from_slice(&entry.to_le_bytes()); // THE ENTRY
    img[idiom + 12..idiom + 14].copy_from_slice(&[0x66, 0xcb]); // lretl
    img.extend_from_slice(payload);

    // --- the inner MZ header: 2 paragraphs, no relocations, image closing exactly to EOF
    let hdr_para = 2usize;
    let inner_len = hdr_para * 16 + img.len();
    let mut inner = vec![0u8; hdr_para * 16];
    inner[0..2].copy_from_slice(b"MZ");
    let pages = inner_len.div_ceil(512);
    let cblp = inner_len % 512;
    inner[0x02..0x04].copy_from_slice(&(cblp as u16).to_le_bytes());
    inner[0x04..0x06].copy_from_slice(&(pages as u16).to_le_bytes());
    inner[0x06..0x08].copy_from_slice(&0u16.to_le_bytes()); // e_crlc
    inner[0x08..0x0a].copy_from_slice(&(hdr_para as u16).to_le_bytes());
    inner[0x18..0x1a].copy_from_slice(&0x1cu16.to_le_bytes()); // e_lfarlc
    inner.extend_from_slice(&img);

    // --- the extender stub in front, itself an MZ
    let mut out = vec![0u8; stub_len];
    out[0..2].copy_from_slice(b"MZ");
    out[0x02..0x04].copy_from_slice(&0x50u16.to_le_bytes());
    out[0x04..0x06].copy_from_slice(&1u16.to_le_bytes());
    out[0x08..0x0a].copy_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&inner);
    out
}

/// A payload whose entry calls two functions, the second reachable only through the first.
/// Returns `(payload, entry_offset, [f1, f2])`.
fn call_graph_payload(entry: u32) -> (Vec<u8>, u32, [u32; 2]) {
    let mut p = vec![0x90u8; 0x400];
    let f1: u32 = 0x100;
    let f2: u32 = 0x200;
    // entry: call f1 ; ret
    let e = entry as usize;
    let rel1 = (f1 as i64 - (entry as i64 + 5)) as i32;
    p[e] = 0xe8;
    p[e + 1..e + 5].copy_from_slice(&rel1.to_le_bytes());
    p[e + 5] = 0xc3;
    // f1: call f2 ; ret
    let rel2 = (f2 as i64 - (f1 as i64 + 5)) as i32;
    p[f1 as usize] = 0xe8;
    p[f1 as usize + 1..f1 as usize + 5].copy_from_slice(&rel2.to_le_bytes());
    p[f1 as usize + 5] = 0xc3;
    // f2: xor eax,eax ; ret
    p[f2 as usize..f2 as usize + 3].copy_from_slice(&[0x31, 0xc0, 0xc3]);
    (p, entry, [f1, f2])
}

/// The parameter matrix: two entry values and two 16-bit lengths, so nothing can be hardcoded.
const CASES: &[(usize, usize, u32)] = &[
    // (stub_len, sixteen_len, entry)
    (0x540, 0x6b90, 0xd),   // both real samples' entry, one sample's region length
    (0x200, 0x4310, 0x320), // a different length and a different entry
    (0x100, 0x1000, 0x2a),  // small, to catch anything scaling off the samples
];

#[test]
fn detects_a_built_container_in_every_case() {
    for &(stub, sixteen, entry) in CASES {
        let (payload, _, _) = call_graph_payload(entry);
        let data = build_x32(stub, sixteen, entry, &payload, 0);
        assert!(x32::is_x32_image(&data), "not detected: stub={stub:#x} 16={sixteen:#x}");
        let l = x32::detect_x32(&data).expect("layout");
        assert_eq!(l.entry, entry, "entry parsed from the idiom");
        assert_eq!(l.base, 0, "flat base read from the descriptor table");
        assert_eq!(l.flat, stub + 32 + sixteen, "32-bit image start");
    }
}

#[test]
fn does_not_claim_other_containers() {
    // A wrong detection is worse than none: the caller's fallback (the Ghidra-parity stub view)
    // is always correct, so anything ambiguous must be declined.
    let mut bare_mz = vec![0u8; 0x400];
    bare_mz[0..2].copy_from_slice(b"MZ");
    bare_mz[0x04..0x06].copy_from_slice(&2u16.to_le_bytes());
    bare_mz[0x08..0x0a].copy_from_slice(&2u16.to_le_bytes());

    let mut elf = vec![0u8; 0x400];
    elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);

    let mut pe = vec![0u8; 0x400];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");

    // An inner MZ that closes to EOF but has no transfer idiom — the case that most resembles
    // an X-32 container without being one.
    let (payload, _, _) = call_graph_payload(0x10);
    let mut no_idiom = build_x32(0x200, 0x1000, 0x10, &payload, 0);
    let idiom_at = 0x200 + 32 + 0x1000 - 0x40;
    no_idiom[idiom_at..idiom_at + 14].fill(0x90);

    for (name, d) in [
        ("bare 16-bit MZ", &bare_mz),
        ("ELF", &elf),
        ("PE", &pe),
        ("empty", &vec![]),
        ("truncated stub", &vec![b'M', b'Z']),
        ("inner MZ without the idiom", &no_idiom),
    ] {
        assert!(!x32::is_x32_image(d), "false positive on {name}");
    }
}

#[test]
fn maps_one_flat_block_and_the_entry() {
    for &(stub, sixteen, entry) in CASES {
        let (payload, _, _) = call_graph_payload(entry);
        let bss_end = payload.len() as u32 + 0x1000;
        let data = build_x32(stub, sixteen, entry, &payload, bss_end);
        let program = loader::load_x32(&data).expect("load");

        assert_eq!(program.language_id, "x86:LE:32:default");
        let blocks = program.memory.blocks().collect::<Vec<_>>();
        assert_eq!(blocks.len(), 1, "one flat segment");
        let b = blocks[0];
        assert_eq!(b.start().offset, 0, "mapped at the descriptor base");
        assert_eq!(b.size(), u64::from(bss_end), "memsz from image[0x12c]");
        assert!(b.is_execute() && b.is_read() && b.is_write());

        // file bytes present, BSS tail zero
        let at = |a: u64| program.memory.byte_at(mosura::decompile::space::Address::new(b.start().space, a));
        assert_eq!(at(u64::from(entry)), Some(0xe8), "the planted call");
        assert_eq!(at(payload.len() as u64), Some(0), "zero-filled BSS");

        assert_eq!(program.entry_points.len(), 1);
        assert_eq!(program.entry_points[0].offset, u64::from(entry));
        assert!(
            program.function_manager.function_at(program.entry_points[0]).is_some(),
            "entry is a function"
        );
    }
}

#[test]
fn auto_analysis_discovers_the_planted_call_graph() {
    // A loader is only useful if the pipeline runs over what it maps: the second function is
    // reachable ONLY through the first, so finding it exercises real recursive descent.
    for &(stub, sixteen, entry) in CASES {
        let (payload, _, [f1, f2]) = call_graph_payload(entry);
        let data = build_x32(stub, sixteen, entry, &payload, 0);
        let mut program = loader::load_x32(&data).expect("load");
        mosura::analysis::analyze(&mut program);

        let found: Vec<u64> =
            program.function_manager.functions().map(|f| f.entry_point().offset).collect();
        for want in [u64::from(entry), u64::from(f1), u64::from(f2)] {
            assert!(found.contains(&want), "function {want:#x} not discovered, got {found:x?}");
        }
    }
}

#[test]
fn refuses_malformed_containers() {
    let (payload, _, _) = call_graph_payload(0x10);

    // (1) the paragraph field points past end of file
    let mut past_eof = build_x32(0x200, 0x1000, 0x10, &payload, 0);
    let img = 0x200 + 32;
    past_eof[img..img + 2].copy_from_slice(&0xfff0u16.to_le_bytes());
    assert!(loader::load_x32(&past_eof).is_err(), "paragraph field past EOF");

    // (2) no transfer idiom -> refuse rather than guess an entry
    let mut no_idiom = build_x32(0x200, 0x1000, 0x10, &payload, 0);
    let idiom_at = 0x200 + 32 + 0x1000 - 0x40;
    no_idiom[idiom_at..idiom_at + 14].fill(0x90);
    assert!(loader::load_x32(&no_idiom).is_err(), "missing idiom");

    // (3) a relocation at or above the 32-bit image start breaks the no-fixups invariant
    let mut relocated = build_x32(0x200, 0x1000, 0x10, &payload, 0);
    let inner = 0x200;
    relocated[inner + 0x06..inner + 0x08].copy_from_slice(&1u16.to_le_bytes()); // e_crlc = 1
    let table = inner + 0x1c;
    relocated[table..table + 2].copy_from_slice(&0u16.to_le_bytes()); // offset
    relocated[table + 2..table + 4].copy_from_slice(&0x200u16.to_le_bytes()); // seg 0x200 => 0x2000
    let err = loader::load_x32(&relocated).expect_err("relocation inside the 32-bit image");
    assert!(
        format!("{err:?}").contains("not supposed to be relocated"),
        "the error should name the invariant, got {err:?}"
    );
}

#[test]
fn native_dispatch_routes_x32_and_declines_others() {
    let (payload, _, _) = call_graph_payload(0x20);
    let data = build_x32(0x300, 0x1000, 0x20, &payload, 0);
    assert_eq!(mosura::analysis::native_loader_name(&data), Some("X-32"));

    let mut bare_mz = vec![0u8; 0x400];
    bare_mz[0..2].copy_from_slice(b"MZ");
    bare_mz[0x04..0x06].copy_from_slice(&2u16.to_le_bytes());
    bare_mz[0x08..0x0a].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(
        mosura::analysis::native_loader_name(&bare_mz),
        None,
        "a plain DOS MZ has no native view; the default dispatch owns it"
    );
}

/// The default container dispatch must NOT change for an X-32 file: it stays on the
/// Ghidra-parity MZ-stub path, exactly as it does for a DOS/4GW-bound LE. The native view is
/// opt-in (`analyze_native_file`) precisely because Ghidra has no loader to validate it against.
#[test]
fn default_dispatch_stays_on_the_ghidra_parity_path() {
    let (payload, _, _) = call_graph_payload(0x20);
    let data = build_x32(0x300, 0x1000, 0x20, &payload, 0);
    let program = loader::load(&data).expect("default dispatch loads the stub");
    assert_eq!(
        program.language_id, "x86:LE:16:Real Mode",
        "the default view of an X-32 file is its 16-bit stub, as Ghidra sees it"
    );
}

/// Skip-if-absent extra on a real X-32 binary (`MOSURA_X32_EXE`). No Ghidra golden exists for
/// this path, so the assertions are the clean-subset invariants `le_war2_analysis` uses.
#[test]
fn real_x32_binary_analyses_cleanly() {
    let path = mosura::paths::x32_exe();
    let Ok(data) = std::fs::read(&path) else {
        eprintln!("skip real_x32_binary_analyses_cleanly: {} absent", path.display());
        return;
    };
    if !x32::is_x32_image(&data) {
        eprintln!("skip: {} is not an X-32 container", path.display());
        return;
    }
    let l = x32::detect_x32(&data).expect("layout");
    let program = mosura::analysis::analyze_native_file(&path).expect("native analysis");

    assert_eq!(program.language_id, "x86:LE:32:default");
    assert_eq!(program.memory.blocks().count(), 1);
    assert!(program.function_manager.functions().count() > 100, "the 32-bit program is mapped");
    assert!(
        program.memory.contains(program.entry_points[0]),
        "entry {:#x} inside the mapped image",
        l.entry
    );

    // No reference may leave mapped memory, and no computed jump may be spurious.
    for r in program.reference_manager.references() {
        assert!(
            program.memory.contains(r.to),
            "reference {:#x} -> {:#x} leaves mapped memory",
            r.from.offset,
            r.to.offset
        );
    }
}
