//! Throwaway grounding tool (Task #2): dump mosura's rule-application trace for a datatest
//! fixture, in the same `DEBUG <n>: <rule>` format Ghidra's `capture_trace --trace` emits, so the
//! two can be diffed. Usage: `cargo run -q --example trace -- <fixture-stem> --debug opaction`
//! (`--debug opaction=<action>` for one action, `;trace-func=<name>` to scope a function).
use mosura::decompile::{build, pipeline};
use mosura::datatest;

fn main() {
    let args = mosura::debug::from_args(std::env::args().collect()).unwrap_or_else(|e| panic!("--debug: {e}"));
    let args = mosura::resources::from_args(args).unwrap_or_else(|e| panic!("{e}"));
    let stem = args.get(1).expect("fixture stem");
    let path = mosura::paths::datatests_dir().join(format!("{stem}.xml"));
    let dt = datatest::parse_file(&path).unwrap();
    // The fixture's OWN language, exactly as dumpc resolves it. This tool hardcoded the
    // x86-64 tables for its whole life — right for the x86-64 datatests it was built on,
    // and silently catastrophic for anything else: a 32-bit fixture decoded as 64-bit
    // garbage, and the pipeline spun on the nonsense without terminating (measured: 57
    // CPU-minutes on an 8-instruction the subject function before it was killed).
    let lang_id = dt.arch.rfind(':').map_or(dt.arch.as_str(), |i| &dt.arch[..i]);
    let (spec, ctx) = mosura::lang::load_cached(lang_id).expect("fixture language loads");
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image_arch(spec, "func", &image, entry, ctx, &dt.arch);
    pipeline::decompile(&mut f); // emits the trace when `--debug opaction` is set
}
