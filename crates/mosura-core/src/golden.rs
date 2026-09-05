//! Parser for the disasm + raw-p-code golden format produced by the offline
//! capture tool (`oracle/capture.cc`). The format is line-oriented (design §5):
//!
//! ```text
//! # lang=x86:LE:64:default:gcc capture=v1
//! 00100000  89f0  MOV EAX,ESI
//!           pcode: (register,0x0,4) = COPY (register,0x30,4)
//! 00100002  83e00f  AND EAX,0xf
//!           pcode: ...
//! ```
//!
//! mosura's SLEIGH runtime must eventually reproduce this exactly (after
//! normalization). For now the conformance harness parses goldens and holds a
//! red baseline against the stubbed engine.

/// A captured instruction: address, raw bytes, disassembly, and lifted p-code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoldenInsn {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub body: String,
    pub pcode: Vec<String>,
}

/// A full disasm golden: the language id plus its instruction sequence.
#[derive(Debug, Clone, Default)]
pub struct DisasmGolden {
    pub lang: String,
    pub insns: Vec<GoldenInsn>,
}

/// Parse the golden text. Lenient: unknown header fields are ignored.
pub fn parse(text: &str) -> DisasmGolden {
    let mut g = DisasmGolden::default();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix('#') {
            // header: `# lang=<id> capture=v1`
            for tok in rest.split_whitespace() {
                if let Some(v) = tok.strip_prefix("lang=") {
                    g.lang = v.to_string();
                }
            }
        } else if let Some(pc) = line.trim_start().strip_prefix("pcode:") {
            if let Some(insn) = g.insns.last_mut() {
                insn.pcode.push(pc.trim().to_string());
            }
        } else if line.contains("<decode error") {
            // the oracle hit data (e.g. a constant pool / string) and could not
            // decode it — not an instruction; a linear sweep stops here too.
            continue;
        } else if !line.trim().is_empty() {
            // instruction line: `<hexaddr>  <hexbytes>  <mnem> <body...>`
            let mut it = line.splitn(3, "  ").map(str::trim);
            let addr = it.next().unwrap_or("");
            let bytes = it.next().unwrap_or("");
            let asm = it.next().unwrap_or("");
            let (mnemonic, body) = match asm.split_once(' ') {
                Some((m, b)) => (m.to_string(), b.trim().to_string()),
                None => (asm.to_string(), String::new()),
            };
            g.insns.push(GoldenInsn {
                address: u64::from_str_radix(addr, 16).unwrap_or(0),
                bytes: hex(bytes),
                mnemonic,
                body,
                pcode: Vec::new(),
            });
        }
    }
    g
}

fn hex(s: &str) -> Vec<u8> {
    let d: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    d.chunks_exact(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16).unwrap() as u8;
            let lo = (p[1] as char).to_digit(16).unwrap() as u8;
            (hi << 4) | lo
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_golden() {
        let g = parse(
            "# lang=x86:LE:64:default:gcc capture=v1\n\
             00100000  89f0  MOV EAX,ESI\n\
             \x20         pcode: (register,0x0,4) = COPY (register,0x30,4)\n\
             00100005  c3  RET \n\
             \x20         pcode: RETURN (register,0x288,8)\n",
        );
        assert_eq!(g.lang, "x86:LE:64:default:gcc");
        assert_eq!(g.insns.len(), 2);
        assert_eq!(g.insns[0].address, 0x100000);
        assert_eq!(g.insns[0].bytes, vec![0x89, 0xf0]);
        assert_eq!(g.insns[0].mnemonic, "MOV");
        assert_eq!(g.insns[0].body, "EAX,ESI");
        assert_eq!(g.insns[0].pcode, vec!["(register,0x0,4) = COPY (register,0x30,4)"]);
        assert_eq!(g.insns[1].mnemonic, "RET");
        assert_eq!(g.insns[1].pcode, vec!["RETURN (register,0x288,8)"]);
    }
}
