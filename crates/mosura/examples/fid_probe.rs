use mosura::analysis;
fn main() {
    let bin = mosura::paths::ground_truth_dir().join(std::env::args().nth(1).unwrap());
    let min = u64::from_str_radix(&std::env::args().nth(2).unwrap(), 16).unwrap();
    let max = u64::from_str_radix(&std::env::args().nth(3).unwrap(), 16).unwrap();
    let p = analysis::analyze_file_as(&bin, None).expect("analyze");
    let (spec, ctx) = mosura::lang::load(&p.language_id).expect("lang");
    let addr = mosura::decompile::space::Address::new(p.default_space, min);
    let w = p.memory.read_window(addr, (max - min + 1) as usize);
    let ins = spec.disassemble_ctx(&w, min, &ctx);
    let fps = spec.disassemble_fingerprint(&w, min, &ctx);
    println!("--- references in range ---");
    for r in p.reference_manager.references() {
        if r.from.offset >= min && r.from.offset <= max {
            println!("  from={:#x} to={:#x} op={} type={} in_mem={}", r.from.offset, r.to.offset, r.op_index, r.ref_type.name(), p.memory.contains(r.to));
        }
    }
    println!("--- instructions ---");
    for (i, f) in ins.iter().zip(&fps) {
        println!("{:#x} {:<9} {:<28} call={} mask={:02x?}", i.address, i.mnemonic, i.body, f.is_call, f.instruction_mask);
        for (n, op) in f.operands.iter().enumerate() {
            println!("      op{n} scalar={} addr={} objs={:?}", op.is_scalar, op.is_address, op.objects);
        }
    }
}
