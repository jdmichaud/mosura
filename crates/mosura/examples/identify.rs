//! Everything mosura can say about a binary, in one place: how it was dispatched, what language
//! and compiler spec it resolved to, which compiler produced it and on what evidence, and what
//! FID has to identify it with.
//!
//! ```text
//! cargo run --release --example identify -- <binary> [--native | --le] [--cspec <id>]
//! ```
//!
//! Why this exists: every one of these facts was already computed inside mosura — the loader picks
//! a language and a compiler spec, `loader::compiler_version` reads the embedded version marker,
//! the snapshot header carries `compiler=`/`compilerinfo=`/`compilerversion=` — but no committed
//! tool printed any of it, so answering "what is this file?" meant writing a throwaway. This is
//! that tool, promoted.
//!
//! `--native` uses the beyond-Ghidra loader registry (`analyze_native_file`) instead of the
//! Ghidra-parity default dispatch, which is what a DOS-extender-bound executable needs to show its
//! 32-bit content. `--cspec` *declares* the compiler spec instead of detecting it, which is how
//! you test a compiler hypothesis on a linked image: FID selects databases by language AND spec,
//! so a program analysed as `gcc` can never match a `highc` or `watcom` database.

use mosura::analysis::loader;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut path: Option<std::path::PathBuf> = None;
    let mut native = false;
    let mut le = false;
    let mut cspec: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--native" => native = true,
            "--le" => le = true,
            "--cspec" => cspec = args.next(),
            _ => path = Some(std::path::PathBuf::from(a)),
        }
    }
    let path = path.expect("usage: identify <binary> [--native|--le] [--cspec <id>]");
    let data = std::fs::read(&path).expect("read the binary");

    println!("== {}  ({} bytes)", path.display(), data.len());
    println!("   sha256 {}", sha256_hex(&data));

    // ---- container, and which loader claims it
    println!("\n-- container");
    println!("   magic            {}", magic(&data));
    match mosura::analysis::native_loader_name(&data) {
        Some(n) => println!("   native loader    {n} (beyond-Ghidra; use --native for its view)"),
        None => println!("   native loader    none — the default dispatch owns this file"),
    }
    if let Some(off) = loader::detect_le(&data) {
        let bound = data
            .get(0x3c..0x40)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize != off)
            .unwrap_or(true);
        println!(
            "   LE header        at {off:#x} ({})",
            if bound { "bound — e_lfanew invalid, found by scanning" } else { "standalone — e_lfanew points at it" }
        );
    }
    if let Some(l) = loader::detect_x32(&data) {
        println!(
            "   X-32 container   inner MZ {:#x}, 32-bit image {:#x}, base {:#x}, entry {:#x}",
            l.inner, l.flat, l.base, l.entry
        );
    }

    // ---- the compiler question, before analysis, straight from the bytes
    println!("\n-- compiler evidence in the file");
    match loader::compiler_version::detect(&data) {
        Some(id) => {
            println!("   version marker   {} ({:?})", id.label(), id.precision);
            println!("   evidence         {}", truncate(&id.evidence, 92));
        }
        None => println!("   version marker   none found"),
    }
    if let Some(w) = loader::watcom::detect(&data) {
        println!("   watcom banner    {}  [{}]", w.compiler_label(), truncate(&w.banner, 66));
    }
    if let Some(m) = loader::metaware::detect(&data) {
        println!("   metaware marker  {}  [{}]", m.compiler_label(), truncate(&m.banner, 66));
    }

    // ---- analysis
    let program = if native {
        mosura::analysis::analyze_native_file(&path)
    } else if le {
        mosura::analysis::analyze_le_file(&path)
    } else {
        mosura::analysis::analyze_file_as(&path, cspec.as_deref())
    }
    .expect("analyze the binary");

    println!("\n-- as loaded and analysed{}", if native { " (--native)" } else if le { " (--le)" } else { "" });
    println!("   language         {}", program.language_id);
    println!("   compiler spec    {}", program.compiler_spec_id);
    match mosura::lang::resolve_cspec(&program.language_id, &program.compiler_spec_id) {
        Some(p) => println!("   cspec file       {}", p.display()),
        None => println!("   cspec file       UNRESOLVED — prototype recovery will use defaults"),
    }
    println!("   compiler opinion {}", program.compiler);
    println!(
        "   compiler version {}",
        program.compiler_version.clone().unwrap_or_else(|| "(none)".into())
    );
    println!("   image base       {:#x}   address size {} bits", program.image_base.offset, program.addr_size_bits);
    println!("   blocks           {}", program.memory.blocks().count());
    for b in program.memory.blocks() {
        println!(
            "     {:<12} {:#010x}..{:#010x}  {}{}{}",
            b.name(),
            b.start().offset,
            b.end().offset,
            if b.is_read() { 'r' } else { '-' },
            if b.is_write() { 'w' } else { '-' },
            if b.is_execute() { 'x' } else { '-' },
        );
    }
    println!("   entry points     {:?}", program
        .entry_points
        .iter()
        .map(|a| format!("{:#x}", a.offset))
        .collect::<Vec<_>>());
    println!("   functions        {}", program.function_manager.functions().count());
    println!("   symbols          {}", program.symbol_table.symbols().count());

    // ---- FID: what is available, and what it identified
    // the same databases the analyzer sees: the resource provider's `fid/`
    let service = mosura::analysis::fid::query::FidQueryService::load_matching_resources(
        &program.language_id,
        &program.compiler_spec_id,
    );
    println!("\n-- FID (databases are selected by language AND compiler spec)");
    println!("   records attached {}", service.function_count());
    if service.function_count() == 0 {
        println!("   note             no database matches {} / {} — try --cspec to test a hypothesis",
                 program.language_id, program.compiler_spec_id);
    }
    let results = mosura::analysis::fid::analyzer::search_program(&program, &service);
    let mut named: Vec<(u64, String)> =
        results.into_iter().filter_map(|r| r.name.map(|n| (r.entry.offset, n))).collect();
    named.sort();
    let total = program.function_manager.functions().count();
    println!(
        "   named            {} of {} functions{}",
        named.len(),
        total,
        if total > 0 { format!(" ({:.0}%)", 100.0 * named.len() as f64 / total as f64) } else { String::new() }
    );
    for (a, n) in named.iter().take(15) {
        println!("     {a:#010x} {n}");
    }
    if named.len() > 15 {
        println!("     ... and {} more", named.len() - 15);
    }
}

fn truncate(s: &str, n: usize) -> String {
    let s = s.replace(['\r', '\n'], " ");
    if s.chars().count() <= n { s } else { s.chars().take(n).collect::<String>() + "…" }
}

fn magic(d: &[u8]) -> String {
    match d {
        _ if d.starts_with(b"\x7fELF") => "ELF".into(),
        _ if d.starts_with(b"MZ") => {
            let pe = d
                .get(0x3c..0x40)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
                .filter(|&o| d.get(o..o + 4) == Some(b"PE\0\0"))
                .is_some();
            if pe { "MZ + PE".into() } else { "MZ (DOS)".into() }
        }
        _ if matches!(d.first(), Some(0x80 | 0x82)) => "OMF object".into(),
        _ if d.starts_with(b"\xf0") => "OMF library".into(),
        _ => format!("{:02x?}", &d[..d.len().min(4)]),
    }
}

/// Small local sha256 so the tool has no new dependency.
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        for (i, v) in [a, b, c, d, e, f, g, hh].into_iter().enumerate() {
            h[i] = h[i].wrapping_add(v);
        }
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}
