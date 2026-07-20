//! Recompilation-equivalence PROBE (task #3, phase 1) — the DECOMPILER-level oracle.
//!
//! The user's objective judge: decompile -> recompile with the same compiler -> same binary.
//! This probe MEASURES where mosura lands today: decompile functions from a ground-truth binary
//! (read-only via the decompiler's public API — it does NOT modify the decompiler), then try to
//! compile the emitted C, first raw and then with Ghidra's decompiler-C sized-int prelude, and
//! report what blocks compilation. It is a measurement harness, not a passing gate (recompilation
//! equivalence needs decompiler C-emission maturity — a decompiler-track handoff).
//!
//! Usage: cargo run -q --example gt_recompile_probe -- <binary> <hexaddr> [<hexaddr> ...]

use std::process::Command;

use mosura::analysis::{self, decompiler::decompile_function};
use mosura::decompile::printc::print_c;
use mosura::decompile::space::Address;

// The sized-int / undefined typedefs Ghidra's decompiler output assumes (what a compilable-C
// emitter would prepend). Deliberately generous so the probe isolates the *structural* blockers
// (intrinsics, prototypes) from the trivial missing-typedef ones.
const PRELUDE: &str = "\
typedef unsigned char undefined; typedef unsigned char byte; typedef unsigned char undefined1;
typedef unsigned short undefined2; typedef unsigned int undefined4; typedef unsigned long undefined8;
typedef unsigned char uint1; typedef unsigned short uint2; typedef unsigned int uint4; typedef unsigned long uint8;
typedef signed char int1; typedef short int2; typedef int int4; typedef long int8;
typedef unsigned char uchar; typedef unsigned short ushort; typedef unsigned int uint; typedef unsigned long ulong;
typedef unsigned long code;
";

fn gcc_check(path: &str) -> String {
    match Command::new("gcc").args(["-c", "-w", "-o", "/dev/null", path]).output() {
        Ok(o) if o.status.success() => "COMPILES".into(),
        Ok(o) => {
            let errs: Vec<_> = String::from_utf8_lossy(&o.stderr)
                .lines()
                .filter(|l| l.contains("error:"))
                .take(4)
                .map(|l| l.trim().to_string())
                .collect();
            format!("{} error(s); first:\n      {}", errs.len().max(1), errs.join("\n      "))
        }
        Err(e) => format!("gcc unavailable: {e}"),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let bin = args.next().expect("usage: gt_recompile_probe <binary> <hexaddr>...");
    let addrs: Vec<u64> = args
        .map(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).expect("hex addr"))
        .collect();
    let prog = analysis::analyze_file(std::path::Path::new(&bin)).expect("analyze");
    let ram = prog.default_space;
    let outdir = mosura::paths::workspace_root().join("build/recompile-probe");
    std::fs::create_dir_all(&outdir).ok();

    for a in addrs {
        println!("\n===== function {a:08x} =====");
        let Some(f) = decompile_function(&prog, Address::new(ram, a)) else {
            println!("  decompile failed");
            continue;
        };
        let c = print_c(&f);
        print!("{c}");
        let raw = outdir.join(format!("fn_{a:08x}.raw.c"));
        std::fs::write(&raw, &c).unwrap();
        let pre = outdir.join(format!("fn_{a:08x}.prelude.c"));
        std::fs::write(&pre, format!("{PRELUDE}\n{c}")).unwrap();
        println!("  raw       gcc -c: {}", gcc_check(raw.to_str().unwrap()));
        println!("  +prelude  gcc -c: {}", gcc_check(pre.to_str().unwrap()));
    }
}
