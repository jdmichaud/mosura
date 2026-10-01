//! The 68000 emulator state modifier against an independent 68000: BlastEm.
//!
//! Each fixture is a small Mega Drive ROM that executes one instruction over a grid of inputs and
//! stores every result and the condition codes after it from `$FF0000` on, then writes `$DEAD` to
//! `$FFFF00` and spins. `<name>.ram` is BlastEm's work RAM once that marker is set; the test runs
//! the same ROM in this interpreter and compares the RAM byte for byte. What each ROM covers, the
//! sources and the generator are in `tests/fixtures/m68k-emulation/README.md`.
//!
//! `exhaustive_against_blastem` runs the whole generated set (every destination byte, four
//! condition-code inputs, all six BCD forms) when dev-config `oracle.m68k_emulation` names its
//! directory.

use mosura_core::sleigh::emu::{Image, RunOptions, Stop};
use std::path::{Path, PathBuf};

const RESULTS: u64 = 0xff_0000;
const MARKER: u64 = 0xff_ff00;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/m68k-emulation")
}

/// Run `rom` from its reset vector until it reaches its final `bra.s *` and return the work RAM
/// at `$FF0000`, `len` bytes.
fn run_rom(rom: &[u8], len: usize) -> Vec<u8> {
    let (spec, ctx) = mosura_core::lang::load_cached("68000:BE:32:default").expect("68000 tables");
    let entry = u64::from(u32::from_be_bytes(rom[4..8].try_into().unwrap()));
    // The program ends in `bra.s *` (0x60FE), its only one.
    let spin = (0x200..rom.len() - 1).step_by(2).find(|&i| rom[i] == 0x60 && rom[i + 1] == 0xfe).expect("final bra.s *");
    let mut image = Image::new(spec, rom, 0, ctx).with_address_mask(0xff_ffff).with_image_memory();
    let opts = RunOptions { entry: Some(entry), max_steps: usize::MAX, stubs: [spin as u64].into(), ..RunOptions::default() };
    let run = image.run(&[], &opts);
    assert_eq!(run.stop, Stop::Returned, "the ROM did not reach its end");
    assert_eq!(run.machine.unmodeled_ops.iter().collect::<Vec<_>>(), Vec::<&String>::new(), "unmodelled operations");
    let m = &run.machine;
    assert_eq!(m.read("ram", MARKER, 2), 0xdead, "the ROM did not finish");
    (0..len as u64).map(|i| m.read("ram", RESULTS + i, 1) as u8).collect()
}

/// Compare one ROM's results with BlastEm's RAM; `record` is the size of one case's record and
/// `skip` the offsets in a record left out of the comparison.
fn compare(name: &str, rom: &[u8], ram: &[u8], record: usize, cases: usize, skip: &[usize]) -> Vec<String> {
    let mut got = run_rom(rom, record * cases);
    let mut want = ram[..record * cases].to_vec();
    for i in 0..cases {
        for &k in skip {
            got[i * record + k] = 0;
            want[i * record + k] = 0;
        }
    }
    (0..cases)
        .filter(|i| got[i * record..(i + 1) * record] != want[i * record..(i + 1) * record])
        .map(|i| {
            format!(
                "{name} case {i:#x}: mosura {:02x?}, BlastEm {:02x?}",
                &got[i * record..(i + 1) * record],
                &want[i * record..(i + 1) * record]
            )
        })
        .collect()
}

/// Record size, case count and skipped offsets of a fixture, from its name: `bcd-*` stores a
/// byte and the low byte of SR for 64 x 256 cases, `div-*` a long and the SR word for 4000,
/// `shift-*` a long, the low byte of SR and a pad byte (skipped) per case (`shifts.py`).
///
/// The SR word's high byte (T, S, the interrupt mask) is left out: 68000.sinc's `packflags`
/// (68000.sinc:779) shifts the one-byte `TF`, `SVF` and `IPL` at their own width, so its
/// `move SR,<ea>` stores them as zero — Ghidra's p-code does the same. That is not what these
/// fixtures test, and the condition codes in the low byte are.
fn layout(name: &str) -> (usize, usize, &'static [usize]) {
    if name == "forms" {
        (30, 1, &[])
    } else if name == "nbcd-memory" {
        (0x14, 1, &[])
    } else if name == "shift-memory" {
        (6, 8 * 2 * 20, &[5])
    } else if name.starts_with("shift-") && name.ends_with("-imm") {
        (6, 3 * 8 * 2 * 20, &[5])
    } else if name.starts_with("shift-") {
        (6, 70 * 2 * 20, &[5])
    } else if name.starts_with("div-") {
        (6, 4000, &[4])
    } else {
        (2, 64 * 256, &[])
    }
}

fn check_dir(roms: &Path, rams: &Path) -> (usize, Vec<String>) {
    let mut names: Vec<String> = std::fs::read_dir(roms)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".bin").map(str::to_string))
        .filter(|n| rams.join(format!("{n}.ram")).exists())
        .collect();
    names.sort();
    let mut bad = Vec::new();
    for name in &names {
        let rom = std::fs::read(roms.join(format!("{name}.bin"))).unwrap();
        let ram = std::fs::read(rams.join(format!("{name}.ram"))).unwrap();
        let (record, cases, skip) = layout(name);
        bad.extend(compare(name, &rom, &ram, record, cases, skip));
    }
    (names.len(), bad)
}

#[test]
fn bcd_and_word_division_match_the_68000() {
    let dir = fixtures();
    let (n, bad) = check_dir(&dir, &dir);
    assert!(n >= 10, "fixtures missing: {n}");
    assert!(bad.is_empty(), "{} mismatches, first: {:#?}", bad.len(), &bad[..bad.len().min(10)]);
}

/// `nbcd` through memory operands stores its result: `$02` negated is `$98` (M68000PRM 4-146).
/// The ROM is `nbcd (a0)`, `nbcd (a1)+`, `nbcd $FF0012.l` on `$02` in memory, then `nbcd d3` on
/// `$02` stored to `$FF0013`. Stated from the manual as well as compared with BlastEm, whose
/// memory-destination `nbcd` did not store before its 17c97f4.
#[test]
fn nbcd_stores_through_memory_operands() {
    let rom = std::fs::read(fixtures().join("nbcd-memory.bin")).unwrap();
    assert_eq!(run_rom(&rom, 0x14)[0x10..], [0x98; 4]);
}

/// The whole generated set: dev-config `oracle.m68k_emulation` names a directory holding `roms/`
/// and `ram/` (`generate.py all DIR`).
#[test]
#[ignore = "needs the generated oracle set (dev-config oracle.m68k_emulation); run in release"]
fn exhaustive_against_blastem() {
    let dir = mosura_core::devcfg::m68k_emulation_oracle().expect("set oracle.m68k_emulation in dev-config.toml");
    let (n, bad) = check_dir(&dir.join("roms"), &dir.join("ram"));
    eprintln!("{n} ROMs, {} mismatching cases", bad.len());
    assert!(bad.is_empty(), "{} mismatches, first: {:#?}", bad.len(), &bad[..bad.len().min(20)]);
}
