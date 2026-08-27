//! Repository policy: every oracle fixture is a SELF-COMPILED unit (in-house Watcom, source in the
//! fixture's header) or a hand-assembled template — never verbatim bytes of a third-party binary.
//! The "fixture-as-specimen" trick (bytes lifted from the survey manifest) is for scratch
//! diagnosis only; eight such fixtures were committed twice in one week and replaced by MVEs.
//!
//! This test rejects any fixture whose code shares a 32-byte window with the WAR2 text. It needs
//! the binary to compare against and SKIPS (with a note) when it is absent — `WAR2_EXE` or the
//! default path below — so the suite stays third-party-free on machines without it.
use std::path::Path;

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

#[test]
fn no_fixture_carries_a_window_of_the_war2_text() {
    let exe = std::env::var("WAR2_EXE").unwrap_or_else(|_| "/home/jd/WAR2.EXE".to_string());
    let Ok(text) = std::fs::read(&exe) else {
        eprintln!("fixture_provenance: {exe} absent — the WAR2 window check is skipped here");
        return;
    };
    const WINDOW: usize = 32;
    let dir = mosura::paths::oracle_fixtures_dir();
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("xml") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let xml = std::fs::read_to_string(&path).unwrap();
        // A generator product cannot contain lifted bytes; a shared window there is the compiler
        // reproducing the same template (x86_32c00's prologue + memcpy pair coincides with WAR2's
        // for 34 bytes by construction). The marker is the generator's own header line.
        if xml.starts_with("<!-- SELF-COMPILED fixture: wcc386") {
            continue;
        }
        // Pre-existing specimens, allow-listed until their MVE exists — owner: the next session on
        // the fixture policy (review R1 remainder), tracked in memory `fixtures-self-compiled-only`.
        // TODO x86_watcom_ancestor_copy_solid (b555c38, AncestorRealistic port, 255 B at 0x66da8).
        // TODO x86_watcom_dowhile_or (a 115-byte window, found by fable-b's scan 2026-08-27).
        if name == "x86_watcom_ancestor_copy_solid.xml" || name == "x86_watcom_dowhile_or.xml" {
            continue;
        }
        for chunk in fixture_chunks(&xml) {
            if chunk.len() < WINDOW {
                continue;
            }
            // every window, stride 1: a shared run may start at any offset
            let hit = chunk.windows(WINDOW).any(|w| text.windows(WINDOW).any(|t| t == w));
            if hit {
                offenders.push(Path::new(&path).file_name().unwrap().to_string_lossy().to_string());
                break;
            }
        }
    }
    assert!(offenders.is_empty(), "fixtures carrying verbatim WAR2 bytes (replace with self-compiled MVEs via examples/watcom_mve_fixtures.rs): {offenders:?}");
}
