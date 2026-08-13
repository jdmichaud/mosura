//! Disassemble and lift raw hex bytes — the grounding tool for "what does this instruction
//! actually become in p-code?".
//!
//! Usage: `lift <hex> [--base <va>] [--lang <id>]`
use mosura::sleigh;

fn main() {
    let mut args = std::env::args().skip(1);
    let hex = args.next().expect("usage: lift <hex> [--base va] [--lang id]");
    let mut base = 0u64;
    let mut lang = "x86:LE:32:default".to_string();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--base" => base = u64::from_str_radix(args.next().unwrap().trim_start_matches("0x"), 16).unwrap(),
            "--lang" => lang = args.next().unwrap(),
            o => panic!("unknown arg {o}"),
        }
    }
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect();
    for i in sleigh::disassemble(&lang, &bytes, base).expect("language tables") {
        println!("{:08x}  {:<24} {} {}", i.address, hex_of(&i.bytes), i.mnemonic, i.body);
        for op in &i.ops {
            println!("            {}", op.render());
        }
    }
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
