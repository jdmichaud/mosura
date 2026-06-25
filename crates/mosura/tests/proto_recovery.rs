//! A6 gate: the recovered function prototype (`Funcdata::func_proto`) the analysis-track
//! parameter-ID reads back must match Ghidra's recovered parameter/return *storage* exactly.
//!
//! Storage only — parameter *width* (the heritage normalize-read-size over-widening) and *type*
//! are tracked separately; this pins the storage locations and ordering, which is the contract.

use mosura::decompile::build::raw_funcdata_flow_image;
use mosura::decompile::pipeline;
use mosura::sleigh::engine::Spec;
use mosura::{datatest, paths};

/// Decompile a datatest function and return its recovered (param-offsets, return-offset).
fn proto_of(name: &str) -> Option<(Vec<u64>, Option<u64>)> {
    let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    if !sla.exists() {
        return None; // no SLEIGH spec available — skip (matches the corpus gate's behaviour)
    }
    let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).unwrap();
    let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
    let dt = datatest::parse_file(&paths::datatests_dir().join(format!("{name}.xml"))).unwrap();
    let img: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let mut f = raw_funcdata_flow_image(&spec, "func", &img, dt.chunks[0].offset, &ctx);
    pipeline::decompile(&mut f);
    let p = f.func_proto();
    Some((p.params.iter().map(|s| s.addr.offset).collect(), p.output.map(|o| o.addr.offset)))
}

// System V argument registers in formal order, by mosura register offset.
const RDI: u64 = 0x38;
const RSI: u64 = 0x30;
const RDX: u64 = 0x10;
const RCX: u64 = 0x8;
const RAX: u64 = 0x0;

#[test]
fn modulo_recovers_four_pointer_params() {
    let Some((params, output)) = proto_of("modulo") else { return };
    assert_eq!(params, vec![RDI, RSI, RDX, RCX], "four params at RDI,RSI,RDX,RCX");
    assert_eq!(output, Some(RAX), "integer return in RAX");
}

#[test]
fn twodim_recovers_two_params() {
    let Some((params, output)) = proto_of("twodim") else { return };
    assert_eq!(params, vec![RDI, RSI]);
    assert_eq!(output, Some(RAX));
}

#[test]
fn divopt_recovers_one_param() {
    let Some((params, output)) = proto_of("divopt") else { return };
    assert_eq!(params, vec![RDI]);
    assert_eq!(output, Some(RAX));
}
