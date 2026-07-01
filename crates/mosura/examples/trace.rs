//! Throwaway grounding tool (Task #2): dump mosura's rule-application trace for a datatest
//! fixture, in the same `DEBUG <n>: <rule>` format Ghidra's `capture_trace --trace` emits, so the
//! two can be diffed. Usage: `MOSURA_TRACE=1 cargo run -q --example trace -- <fixture-stem>`.
use mosura::decompile::{build, pipeline};
use mosura::sleigh::engine::Spec;
use mosura::{datatest, paths};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let stem = args.get(1).expect("fixture stem");
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    let path = paths::datatests_dir().join(format!("{stem}.xml"));
    let dt = datatest::parse_file(&path).unwrap();
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let entry = dt.chunks[0].offset;
    let mut f = build::raw_funcdata_flow_image(&spec, "func", &image, entry, &ctx);
    pipeline::decompile(&mut f); // emits the trace to stdout when MOSURA_TRACE is set
}
