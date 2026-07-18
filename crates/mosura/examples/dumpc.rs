//! Throwaway grounding tool (Task #2, sibling of `trace.rs`): dump mosura's decompiled output for
//! a datatest fixture — the final C by default, or the raw post-decompile IR with `--raw` (for
//! diffing mosura's op-graph against Ghidra's `oracle/capture --c` / IR).
//! Usage: `cargo run -q --example dumpc -- <fixture-stem> [--raw]`.
use mosura::decompile::{build, pipeline};
use mosura::decompile::printc::print_c;
use mosura::{datatest, paths};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let stem = args.get(1).expect("fixture stem");
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    // Load through the spec cache so the dump sees exactly what the pipeline/tests see —
    // including the laned (vector) registers the cache loader attaches (a direct
    // `Spec::from_sla` would silently miss them and dump a lane-blind decompile).
    let spec = mosura::speccache::get(&sla).expect("x86-64.sla parses");
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    let path = paths::datatests_dir().join(format!("{stem}.xml"));
    let dt = datatest::parse_file(&path).unwrap();
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image(spec, "func", &image, entry, &ctx);
    pipeline::decompile(&mut f);
    if args.get(2).map(|s| s.as_str()) == Some("--raw") {
        print!("{}", f.print_raw());
    } else {
        print!("{}", print_c(&f));
    }
}
