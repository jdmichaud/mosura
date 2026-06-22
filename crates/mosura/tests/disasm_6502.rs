//! End-to-end SLEIGH engine test on 6502 — the first real disassembly.
//!
//! Loads the compiled 6502 `.sla`, builds the spec, disassembles a few bytes, and
//! checks against the captured golden (`goldens/disasm/m6502_tiny.golden`).
//! Operand resolution and LOAD-space rendering aren't implemented yet, so LDA/RTS
//! aren't fully green — but NOP/CLC/SEC (operand-free) must match exactly.

use mosura::golden;
use mosura::sleigh::engine::Spec;
use std::path::PathBuf;

fn read(p: &str) -> Vec<u8> {
    std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(p)).expect(p)
}

#[test]
fn disassembles_6502_simple_instructions() {
    let spec = Spec::from_sla(&read("tests/fixtures/sla/6502.sla")).expect("build 6502 spec");

    // ea=NOP, 18=CLC, 38=SEC, a9 05=LDA #5, 60=RTS  @ 0x8000
    let code = [0xeau8, 0x18, 0x38, 0xa9, 0x05, 0x60];
    let insns = spec.disassemble(&code, 0x8000);

    for i in &insns {
        eprintln!("{:#06x}  {}  {} {}  pcode={:?}", i.address, hex(&i.bytes), i.mnemonic, i.body, i.pcode);
    }

    // Operand-aware length: LDA #imm is 2 bytes, so RET lands at 0x8005.
    let mnem: Vec<&str> = insns.iter().map(|i| i.mnemonic.trim()).collect();
    assert_eq!(mnem, ["NOP", "CLC", "SEC", "LDA", "RTS"]);

    // Every instruction must fully match the Ghidra golden (disasm + p-code),
    // including LDA's operand + RTS's LOAD/RETURN.
    let goldens = golden::parse(&String::from_utf8(read("../../goldens/disasm/m6502_tiny.golden")).unwrap());
    for m in &insns {
        let g = goldens.insns.iter().find(|g| g.address == m.address).expect("golden insn");
        assert_eq!(m.mnemonic.trim(), g.mnemonic, "mnemonic @ {:#x}", m.address);
        assert_eq!(m.bytes, g.bytes, "bytes @ {:#x}", m.address);
        assert_eq!(m.body.trim(), g.body, "operands @ {:#x}", m.address);
        assert_eq!(m.pcode, g.pcode, "p-code @ {:#x} ({})", m.address, g.mnemonic);
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
