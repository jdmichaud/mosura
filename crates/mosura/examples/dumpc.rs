//! Throwaway grounding tool (Task #2, sibling of `trace.rs`): dump mosura's decompiled output for
//! a datatest fixture — the final C by default, or the raw post-decompile IR with `--raw` (for
//! diffing mosura's op-graph against Ghidra's `oracle/capture --c` / IR).
//! Usage: `cargo run -q --example dumpc -- <fixture-stem> [--raw|--pre] [--debug <spec>]` (`--pre` = the lifted
//! p-code BEFORE any action, i.e. exactly what heritage sees).
use mosura::decompile::{build, pipeline};
use mosura::decompile::printc::print_c;
use mosura::{datatest, paths};

fn main() {
    let args = mosura::debug::from_args(std::env::args().collect()).unwrap_or_else(|e| panic!("--debug: {e}"));
    let args = mosura::resources::from_args(args).unwrap_or_else(|e| panic!("{e}"));
    let stem = args.get(1).expect("fixture stem");
    // A bare stem resolves in the datatests dir; a path (contains '/' or ends .xml) is used
    // as-is, so ad-hoc fixtures (e.g. scratchpad extracts of corpus functions) dump too.
    let path = if stem.contains('/') || stem.ends_with(".xml") {
        std::path::PathBuf::from(stem)
    } else {
        paths::datatests_dir().join(format!("{stem}.xml"))
    };
    let dt = datatest::parse_file(&path).unwrap();
    // The fixture's own language, resolved like the analysis pipeline (`lang::load_cached`:
    // .ldefs → .sla + .pspec context sets, laned registers attached) — the same honor-the-
    // declared-arch rule as `raw_funcdata_flow_image_arch`, extended to the SLEIGH tables so
    // an `x86:LE:32:*` fixture decodes 32-bit instead of through the old hardcoded x86-64 pair.
    // `lang:endian:size:variant[:compiler]` — the compiler component names the cspec, not the
    // SLEIGH language; strip it only when present (a four-part arch is already the language id).
    let lang_id = if dt.arch.matches(':').count() >= 4 {
        dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i])
    } else {
        dt.arch.as_str()
    };
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("fixture language loads");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    if args.iter().any(|a| a == "--pre") {
        // The lifted p-code BEFORE any action runs — the input heritage actually sees.
        print!("{}", f.print_raw());
        return;
    }
    pipeline::decompile(&mut f);
    if args.get(2).map(|s| s.as_str()) == Some("--raw") {
        print!("{}", f.print_raw());
    } else {
        print!("{}", print_c(&f));
    }
}
