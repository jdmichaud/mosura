//! Repository policy: every oracle fixture is a SELF-COMPILED unit (in-house Watcom, source in the
//! fixture's header) or a hand-assembled template — never verbatim bytes of a third-party binary.
//! The "fixture-as-specimen" trick (bytes lifted from the survey manifest) is for scratch
//! diagnosis only; eight such fixtures were committed twice in one week and replaced by MVEs.
//!
//! This test rejects any fixture whose code shares a window with the WAR2 text: 32 bytes for a
//! hand-assembled fixture, 64 for a generator product. The compiler reproduces its own templates —
//! x86_32c00's prologue + memcpy pair coincides with WAR2 for 34 bytes by construction — but never
//! a whole lifted function, and the header the generator writes is text anyone can paste above
//! lifted bytes, so it raises the bar rather than waiving it. The test needs the binary to compare
//! against and SKIPS (with a note) when it is absent — `WAR2_EXE` or the default path below — so
//! the suite stays third-party-free on machines without it.
//!
//! The generator is the source of truth for its products: before landing anything that touches a
//! fixture, run `cargo run --release --example watcom_mve_fixtures -- --check <WATCOM-dir>` (the
//! in-house wcc386 under dosemu2; it regenerates into a temp dir and exits 1 on any difference).
use std::collections::HashSet;

/// The longest run a hand-assembled fixture may share with the text.
const WINDOW: usize = 32;
/// The longest run a generator product may share with the text (a template coincidence).
const GENERATED_WINDOW: usize = 64;
/// The header line `examples/watcom_mve_fixtures.rs` writes.
const GENERATED_MARKER: &str = "<!-- SELF-COMPILED fixture: wcc386";
/// Pre-existing specimens (already pushed), allow-listed until their MVEs exist — the fixture-policy
/// follow-up on the ledger (fable-b's R1 review, 2026-08-27).
const ALLOW_LISTED: &[&str] = &[
    // b555c38 (the AncestorRealistic port), 255 B at WAR2 0x66da8 — tests/ancestor_copy_solid.rs
    "x86_watcom_ancestor_copy_solid.xml",
    // c3489dd, a 115-byte shared window (fable-b's scan) — tests/dowhile_or.rs
    "x86_watcom_dowhile_or.xml",
];

fn fixture_chunks(xml: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<bytechunk") {
        let after = &rest[i..];
        let Some(gt) = after.find('>') else { break };
        let body_start = gt + 1;
        let Some(end) = after.find("</bytechunk>") else { break };
        let hex: String = after[body_start..end].chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let bytes: Vec<u8> = (0..hex.len() / 2).map(|k| u8::from_str_radix(&hex[2 * k..2 * k + 2], 16).unwrap()).collect();
        out.push(bytes);
        rest = &after[end..];
    }
    out
}

/// Every `WINDOW`-byte window of the text, hashed once.
fn window_index(text: &[u8]) -> HashSet<&[u8]> {
    text.windows(WINDOW).collect()
}

/// Does `chunk` share a run of `win` (>= `WINDOW`) bytes with `text`? A candidate run is confirmed
/// against the text only when its first `WINDOW` bytes are in the index, so the direct scan runs
/// on hits alone.
fn shares_window(chunk: &[u8], win: usize, text: &[u8], index: &HashSet<&[u8]>) -> bool {
    debug_assert!(win >= WINDOW);
    chunk.windows(win).any(|w| index.contains(&w[..WINDOW]) && text.windows(win).any(|t| t == w))
}

/// The detector on synthetic data (no binary needed): a lifted run is found at its length and not
/// beyond it, and a single changed byte breaks the run.
#[test]
fn window_detection_is_exact() {
    let mut x: u32 = 0x2545_f491;
    let text: Vec<u8> = (0..400)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            (x >> 16) as u8
        })
        .collect();
    let index = window_index(&text);
    let lifted40 = text[50..90].to_vec();
    assert!(shares_window(&lifted40, WINDOW, &text, &index), "a 40-byte lift shares a 32-byte window");
    assert!(!shares_window(&lifted40, GENERATED_WINDOW, &text, &index), "a 40-byte lift has no 64-byte run");
    let mut broken = text[50..130].to_vec();
    broken[40] ^= 0xff;
    assert!(shares_window(&broken, WINDOW, &text, &index), "a changed byte leaves 32-byte runs on both sides");
    assert!(!shares_window(&broken, GENERATED_WINDOW, &text, &index), "a changed byte in the middle leaves no 64-byte run");
    assert!(shares_window(&text[50..130], GENERATED_WINDOW, &text, &index), "an 80-byte lift shares a 64-byte run");
    let mut foreign = text[50..130].to_vec();
    for (i, b) in foreign.iter_mut().enumerate() {
        if i % 16 == 0 {
            *b ^= 0x5a;
        }
    }
    assert!(!shares_window(&foreign, WINDOW, &text, &index), "a byte changed every 16 leaves no 32-byte run");
}

#[test]
fn no_fixture_carries_a_window_of_the_war2_text() {
    let exe = std::env::var("WAR2_EXE").unwrap_or_else(|_| "/home/jd/WAR2.EXE".to_string());
    let Ok(text) = std::fs::read(&exe) else {
        eprintln!("fixture_provenance: {exe} absent — the WAR2 window check is skipped here");
        return;
    };
    let index = window_index(&text);
    let dir = mosura::paths::oracle_fixtures_dir();
    let mut offenders = Vec::new();
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("xml") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if ALLOW_LISTED.contains(&name.as_str()) {
            continue;
        }
        let xml = std::fs::read_to_string(&path).unwrap();
        let win = if xml.starts_with(GENERATED_MARKER) { GENERATED_WINDOW } else { WINDOW };
        checked += 1;
        if fixture_chunks(&xml).iter().any(|chunk| shares_window(chunk, win, &text, &index)) {
            offenders.push(format!("{name} ({win}-byte window)"));
        }
    }
    assert!(checked > 0, "no fixtures found under {}", dir.display());
    assert!(
        offenders.is_empty(),
        "fixtures carrying verbatim WAR2 bytes (replace with self-compiled MVEs via examples/watcom_mve_fixtures.rs): {offenders:?}"
    );
}
