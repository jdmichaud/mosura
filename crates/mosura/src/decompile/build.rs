//! Build a raw [`Funcdata`] from the SLEIGH lifter — the bridge from the kept engine
//! (`sleigh`) to the faithful decompiler model. This is the pre-heritage "raw p-code"
//! form: one varnode per operand occurrence (heritage links them into SSA in P1), the
//! analogue of Ghidra's `Funcdata::followFlow` result before `ActionHeritage`.

use crate::sleigh::engine::Spec;
use crate::sleigh::pcode::PArg;

use super::funcdata::Funcdata;
use super::op::SeqNum;
use super::opcode::OpCode;
use super::space::{Address, SpaceKind, SpaceManager};
use super::varnode::VarnodeId;

impl Funcdata {
    /// Intern a lifter space name, adding it (with a kind guessed from the name) if new.
    fn intern_space(&mut self, name: &str) -> super::space::SpaceId {
        if let Some(id) = self.spaces.by_name(name) {
            return id;
        }
        let kind = match name {
            "const" => SpaceKind::Constant,
            "unique" => SpaceKind::Internal,
            "stack" => SpaceKind::Spacebase,
            _ => SpaceKind::Processor,
        };
        self.spaces.add(name, kind, 8, 1)
    }

    /// Create the varnode for one lifter operand.
    fn build_operand(&mut self, v: &crate::sleigh::pcode::Varnode) -> VarnodeId {
        if v.space == "const" {
            return self.new_const(v.size, v.offset);
        }
        let space = self.intern_space(&v.space);
        self.new_varnode(v.size, Address::new(space, v.offset))
    }
}

/// Lift `bytes` at `base` and build the raw [`Funcdata`]. Mirrors the prototype's
/// `disassemble_ctx` loop but produces the faithful Varnode graph.
pub fn raw_funcdata(
    spec: &Spec,
    name: impl Into<String>,
    bytes: &[u8],
    base: u64,
    context: &[u32],
) -> Funcdata {
    let spaces = SpaceManager::standard();
    let ram = spaces.by_name("ram").expect("standard ram space");
    let mut f = Funcdata::new(name, Address::new(ram, base), spaces);

    let mut uniq: u32 = 0;
    for insn in spec.disassemble_ctx(bytes, base, context) {
        let pc = Address::new(ram, insn.address);
        for op in insn.ops {
            let Some(opcode) = OpCode::from_u32(op.opcode) else { continue };
            let seqnum = SeqNum { pc, uniq };
            uniq += 1;

            // inputs: PArg::Var → a varnode; PArg::Space → a constant annotation holding
            // the space id (Ghidra encodes the AddrSpace* as a constant on LOAD/STORE in0).
            let inputs: Vec<VarnodeId> = op
                .ins
                .iter()
                .map(|a| match a {
                    PArg::Var(v) => f.build_operand(v),
                    PArg::Space(s) => {
                        let sid = f.intern_space(s);
                        f.new_const(8, sid.0 as u64)
                    }
                })
                .collect();

            let id = f.new_op(opcode, seqnum, inputs);
            if let Some(out) = &op.out {
                let space = f.intern_space(&out.space);
                f.new_output(id, out.size, Address::new(space, out.offset));
            }
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use crate::sleigh::engine::Spec;
    use crate::{datatest, paths};

    fn x86_64() -> Option<(Spec, Vec<u32>)> {
        let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
        if !sla.exists() {
            eprintln!("skip: {} not found", sla.display());
            return None;
        }
        let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).ok()?;
        let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
        Some((spec, ctx))
    }

    /// Build the raw Funcdata for a real function and check the Varnode graph is
    /// internally consistent: every written varnode points back at its defining op, and
    /// every op appears in each of its inputs' descendant lists.
    #[test]
    fn raw_funcdata_graph_is_consistent() {
        let Some((spec, ctx)) = x86_64() else { return };
        let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_sem.xml")).expect("fixture");
        let f = super::raw_funcdata(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

        assert!(f.num_ops() > 0, "no ops lifted");
        for id in f.op_ids() {
            let op = f.op(id).clone();
            if let Some(out) = op.output {
                assert_eq!(f.vn(out).def, Some(id), "output's def must be its op");
                assert!(f.vn(out).is_written());
            }
            for inp in op.inrefs {
                assert!(f.vn(inp).descend.contains(&id), "op must be in each input's descend");
            }
        }
        assert!(f.print_raw().lines().count() > 1);
    }
}
