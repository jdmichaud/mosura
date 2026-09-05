//! **The Borland column's recall gate — and the only end-to-end cover for half of the OMF port.**
//!
//! Borland is 64 of the 85 committed databases, and until this existed nothing about them could
//! fail: `fid_detect_versions` scores each database against its OWN records, and
//! `fid_database_drift` proves a database reproduces from its libraries. Neither asks whether a
//! database matches a real linked program.
//!
//! It also covers a part of the loader nothing else reaches. A 32-bit object uses location 9
//! (32-bit offset) and little else; a **16-bit** one uses location 1/5 (16-bit offset), location 2
//! (a segment selector) and location 3 (the 16:16 far pointer). The far memory models matter most
//! — a far call is segment-relative rather than self-relative.
//!
//! # This gate found a real regression on its first run
//!
//! The OMF relocation port (`b678279`) dropped a range guard, and this is what noticed. Our
//! synthetic layout puts the `EXTERNAL` block above `0x10000`, so a 16-bit field cannot hold a
//! slot address; writing one truncated changed the instruction decode and destroyed the very call
//! the fixup described. It cost `borland-bc4.5-cs` 128 of its 3315 relations, `_brk` in the small
//! model and `__write` in the large one. Hence two models here, not one.
//!
//! # Precision is checked against the LINKER MAP, not against a list we wrote
//!
//! The committed `.map` files are ground truth from Borland's own linker, so every name FID
//! applies is checked against the symbol really at that address rather than against expectations
//! that would need updating by hand. Two things are skipped, both deliberately:
//!
//! - **Demangled C++ entries.** Borland's map writes `operator delete(void near*)` where FID
//!   reports the mangled `@$bdele$qnv`. They are the same symbol in two spellings, so map entries
//!   that are not plain identifiers are counted but not compared. (A naive whitespace split
//!   invents two dozen mismatches — the demangled forms contain spaces.)
//! - **Addresses with no map symbol.** A map lists PUBLICS only, so a file-static helper such as
//!   `@typeIDname$qn4tpid` legitimately has no entry.

use std::collections::{BTreeMap, BTreeSet};

use mosura::analysis::fid::analyzer;
use mosura::analysis::fid::query::FidQueryService;
use mosura::paths;

/// Routines the probe calls by name that MUST come back, per memory model.
///
/// Derived from `oracle/fid/src/bcprobe.c`. The small model resolves the near spellings; the large
/// model inlines or renames more, so its required set is the intersection that survives there.
/// `_brk`/`__write` are listed explicitly because they are what the dropped range guard cost.
const SMALL_REQUIRED: &[&str] = &[
    "_memset", "_strncpy", "_strcpy", "_strlen", "_memcpy", "_strcspn", "_malloc", "_free",
    "_gmtime", "_asctime", "_ltoa", "_ultoa", "_brk", "_sbrk", "__write",
];
const LARGE_REQUIRED: &[&str] =
    &["_malloc", "_farmalloc", "_farfree", "_gmtime", "_asctime", "_ltoa", "_ultoa", "__write"];

/// A Borland `.map` line is `  SSSS:OOOO   name`. The MZ loader places the image at segment
/// `0x1000`, so the address FID reports is `0x10000 + (segment << 4) + offset`.
fn map_symbols(path: &std::path::Path) -> BTreeMap<u64, BTreeSet<String>> {
    let text = std::fs::read(path).expect("read the linker map");
    let text = String::from_utf8_lossy(&text);
    let mut out: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        let trimmed = line.trim_start();
        // Only the public-symbol lines: `SSSS:OOOO` followed by a name.
        let Some((addr, name)) = trimmed.split_once(char::is_whitespace) else { continue };
        let Some((seg, off)) = addr.split_once(':') else { continue };
        if seg.len() != 4 || off.len() != 4 {
            continue;
        }
        let (Ok(seg), Ok(off)) = (u64::from_str_radix(seg, 16), u64::from_str_radix(off, 16)) else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        out.entry(0x10000 + (seg << 4) + off).or_default().insert(name.to_string());
    }
    assert!(!out.is_empty(), "no symbols parsed from {}", path.display());
    out
}

/// Whether a map entry is a plain symbol rather than a demangled C++ signature.
fn is_plain_symbol(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || "_@?$".contains(c))
}

fn check(model: &str, exe: &str, map: &str, required: &[&str]) {
    let dir = paths::workspace_root().join("oracle/fid/binaries");
    let (exe, map) = (dir.join(exe), dir.join(map));
    if !exe.exists() {
        eprintln!("skip: {} absent (rebuild: scripts/build-fid-probes.sh borland)", exe.display());
        return;
    }

    // An ordinary MZ: the default container dispatch is the right entry point here, unlike the
    // Watcom column's DOS/4GW LE.
    let program = mosura::analysis::analyze_file(&exe).expect("analyze the Borland probe");
    let service = FidQueryService::load_matching_all(
        &paths::fid_db_dirs(),
        &program.language_id,
        &program.compiler_spec_id,
    );
    assert!(
        !service.is_empty(),
        "no signature database attaches for {}/{} — the Borland column is committed under \
         data/fid but unreachable from the analyzer",
        program.language_id,
        program.compiler_spec_id
    );

    let results = analyzer::search_program(&program, &service);
    let named: Vec<(u64, String)> =
        results.into_iter().filter_map(|r| r.name.map(|n| (r.entry.offset, n))).collect();
    let names: BTreeSet<&str> = named.iter().map(|(_, n)| n.as_str()).collect();

    let truth = map_symbols(&map);
    let (mut exact, mut mangled, mut unlisted) = (0, 0, 0);
    let mut disagreements = Vec::new();
    for (address, name) in &named {
        match truth.get(address) {
            None => unlisted += 1, // a file-static: maps list publics only
            Some(at) if at.contains(name) => exact += 1,
            // The map spelled it demangled; FID reports the mangled form. Same symbol.
            Some(at) if !at.iter().any(|s| is_plain_symbol(s)) => mangled += 1,
            Some(at) => disagreements.push((*address, name.clone(), at.clone())),
        }
    }

    eprintln!(
        "FID identify (borland-bc4.5 {model}): {} named — {exact} match the linker map, \
         {mangled} C++ mangled-vs-demangled, {unlisted} not public in the map",
        named.len()
    );

    // Precision, against ground truth rather than a list we maintain.
    assert!(
        disagreements.is_empty(),
        "FID named symbols the linker map contradicts: {disagreements:#x?}"
    );

    // Recall: what the source calls must come back.
    let missing: Vec<&str> = required.iter().copied().filter(|n| !names.contains(n)).collect();
    assert!(
        missing.is_empty(),
        "FID failed to identify {missing:?} in a program we compiled ourselves\nnamed: {names:?}"
    );
}

#[test]
fn borland_small_model_crt_functions_are_identified() {
    check("small", "bcprobe.bc4.5-cs-x86-16.exe", "bcprobe.bc4.5-cs-x86-16.map", SMALL_REQUIRED);
}

/// The far model, where a call is segment-relative and the 16:16 far-pointer fixup lives.
#[test]
fn borland_large_model_crt_functions_are_identified() {
    check("large", "bcprobe.bc4.5-cl-x86-16.exe", "bcprobe.bc4.5-cl-x86-16.map", LARGE_REQUIRED);
}
