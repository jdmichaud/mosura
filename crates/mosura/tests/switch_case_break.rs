//! Ghidra `PrintC::emitBlockSwitch` ends every case that EXITS the switch (its block has exactly
//! one out-edge, `BlockSwitch::addCase` sets `isexit = sizeOut()==1`) with `break;` — except the
//! last case, which needs none. The WAR2 specimen 0x2c00c (fixture `x86_2c00c_switch.xml`): case
//! 13's body is an if-with-return whose exit edge goes to the switch tail (`JE 0x2c085`); a
//! "RETURN-terminated" heuristic dropped the `break` and the C fell through into case 14 — wrong
//! code (docs/wc2src-reconciliation-4.md W8).
use mosura::decompile::emit::EmitChoices;
use mosura::decompile::printc::print_c_report;
use mosura::decompile::{build, pipeline};
use mosura::{datatest, paths};

fn decompile(fixture: &str) -> String {
    let path = paths::oracle_fixtures_dir().join(fixture);
    let dt = datatest::parse_file(&path).unwrap();
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("x86 SLEIGH tables load");
    let image: Vec<(u64, &[u8])> =
        dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f);
    print_c_report(&f, &EmitChoices::default()).0
}

/// The statements of one case: the text between `case N:` and the next case label / the closing
/// brace of the switch.
fn case_body<'a>(c: &'a str, n: u32) -> &'a str {
    let label = format!("case {n}:");
    let start = c.find(&label).unwrap_or_else(|| panic!("no `{label}` in:\n{c}")) + label.len();
    let rest = &c[start..];
    // the body ends at the next case/default label, at whatever indentation the switch sits
    let mut end = rest.len();
    let mut pos = 0;
    for line in rest.split_inclusive('\n') {
        let t = line.trim_start();
        if pos > 0 && (t.starts_with("case ") || t.starts_with("default:")) {
            end = pos;
            break;
        }
        pos += line.len();
    }
    // or at the switch's closing brace: the first `}` line indented less than the body
    let body_indent = rest.lines().find(|l| !l.trim().is_empty()).map(|l| l.len() - l.trim_start().len()).unwrap_or(0);
    let mut pos = 0;
    for line in rest[..end].split_inclusive('\n') {
        let indent = line.len() - line.trim_start().len();
        if line.trim() == "}" && indent < body_indent {
            end = pos;
            break;
        }
        pos += line.len();
    }
    rest[..end].trim_end()
}

#[test]
fn case_exiting_to_the_switch_tail_ends_with_break() {
    let c = decompile("x86_2c00c_switch.xml");
    assert!(c.contains("switch ("), "expected a switch, got:\n{c}");
    // Case 13 exits to the switch tail after its inner `if` → `break;` is its last statement.
    let body13 = case_body(&c, 13);
    assert!(
        body13.ends_with("break;"),
        "case 13 must end with `break;` (it exits to the switch tail), got:\n{body13}\n\nfull:\n{c}"
    );
    // A case ending in a RETURN has no out-edge → no `break` after the `return;`.
    let body4 = case_body(&c, 4);
    assert!(body4.ends_with("return;"), "case 4 ends with its return, got:\n{body4}");
    // Case 6 exits to the tail → `break;` (unchanged behaviour).
    assert!(case_body(&c, 6).ends_with("break;"), "case 6 must keep its break:\n{c}");
}
