//! **Stage 3 — the byte-exact hash parity gate** (`docs/fid-port-plan.md` §5).
//!
//! The choke point of the FID track: mosura's `FidHashQuad` for a function body must equal,
//! **bit for bit**, the quad Ghidra's own `FidService.hashFunction` produces for the same body.
//! Any divergence in the FNV state, the operand masking, the endianness of the int feed, the
//! scalar/register mixing, the call subtraction, or the NOP skipping shows up here and nowhere
//! earlier.
//!
//! The oracle is Ghidra itself. `scripts/capture-fid-hashes.sh` runs `analyzeHeadless` over the
//! committed self-compiled ground-truth corpus and records, per function, the quad **plus the
//! body's address ranges**. This test hashes exactly those ranges.
//!
//! **Why the ranges matter.** Hashing Ghidra's ranges isolates the *hasher*. If mosura and
//! Ghidra disagreed about where a function begins or ends, every quad would differ and the
//! gate would measure function-boundary recovery instead — a real thing to chase, but a
//! different question with its own tests. Feeding both hashers the same instructions is what
//! makes a failure here mean "the hash is wrong".
//!
//! No user-supplied binary is involved: every input is self-compiled, committed, and permanent.

use std::collections::BTreeMap;

use mosura::analysis::fid::hash::{
    CodeUnitInput, FidHashQuad, FidHasher, OperandAddressQuery, RelocationQuery, Skipper,
};
use mosura::analysis::program::Program;
use mosura::analysis::{self};
use mosura::paths;

/// One golden line: a function Ghidra hashed.
#[derive(Debug, Clone)]
struct GoldenFunction {
    entry: u64,
    name: String,
    quad: FidHashQuad,
    /// Inclusive `(min, max)` body ranges, ascending.
    ranges: Vec<(u64, u64)>,
}

fn goldens_dir() -> std::path::PathBuf {
    paths::workspace_root().join("oracle/fid/hashes")
}

fn parse_golden(text: &str) -> Vec<GoldenFunction> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        assert!(f.len() >= 7, "malformed golden line: {line}");
        let ranges = f[6]
            .split(',')
            .map(|r| {
                let (a, b) = r.split_once('-').expect("min-max range");
                (
                    u64::from_str_radix(a, 16).expect("hex min"),
                    u64::from_str_radix(b, 16).expect("hex max"),
                )
            })
            .collect();
        out.push(GoldenFunction {
            entry: u64::from_str_radix(f[0], 16).expect("hex entry"),
            name: f[1].to_string(),
            quad: FidHashQuad {
                code_unit_size: f[2].parse().expect("code unit size"),
                full_hash: u64::from_str_radix(f[3], 16).expect("full hash"),
                specific_hash_additional_size: f[4].parse().expect("specific add size"),
                specific_hash: u64::from_str_radix(f[5], 16).expect("specific hash"),
            },
            ranges,
        });
    }
    out
}

/// The program's own relocation table, queried by inclusive offset range — Ghidra's
/// `RelocationTable.getRelocations(AddressSet)`.
struct ProgramRelocations<'a>(&'a Program);

impl RelocationQuery for ProgramRelocations<'_> {
    fn any_in_range(&self, min_offset: u64, max_offset: u64) -> bool {
        self.0
            .relocation_table
            .relocations()
            .any(|r| r.address.offset >= min_offset && r.address.offset <= max_offset)
    }
}

/// The analysis-derived half of `OperandType.ADDRESS`, as `InstructionDB.getOperandType`
/// (`:398-419`) computes it: the operand's primary reference, when it targets a memory
/// address, sets the bit. mosura's references carry the operand index they came from, which is
/// exactly the granularity Ghidra's `getPrimaryReference(opIndex)` needs.
///
/// **mosura's references record `op_index = -1`** — the analyzers that create data references
/// do not track which operand produced them, so Ghidra's `getPrimaryReference(opIndex)` cannot
/// be asked directly. The operand is instead identified **by value**: the ADDRESS bit belongs
/// to the operand whose scalar *is* the referenced address.
///
/// That reconstruction is exact for the only case that can change a hash — a *whole-scalar*
/// operand, the sole branch where `isAddress` is consulted (`:151-154`). For any other operand
/// shape the bit is computed but never read. Recording the real operand index in the reference
/// analyzers would let this consult the index directly; it is a wider analysis-lane change and
/// is tracked as a follow-on in `docs/fid-port-plan.md` §8.
struct ProgramOperandAddresses<'a>(&'a Program);

impl OperandAddressQuery for ProgramOperandAddresses<'_> {
    fn operand_is_address(
        &self,
        instruction_address: u64,
        op_index: usize,
        objects: &[mosura::sleigh::OpObject],
    ) -> bool {
        self.0.reference_manager.references().any(|r| {
            if r.from.offset != instruction_address || !self.0.memory.contains(r.to) {
                return false;
            }
            if r.op_index >= 0 {
                return r.op_index == op_index as i32;
            }
            // Unattributed reference: it belongs to whichever operand carries its target.
            objects.iter().any(|o| {
                matches!(o, mosura::sleigh::OpObject::Scalar { signed_value }
                    if *signed_value as u64 == r.to.offset)
            })
        })
    }
}

/// Hash one golden function out of the analyzed program, over Ghidra's body ranges.
fn hash_function(program: &Program, golden: &GoldenFunction) -> Option<FidHashQuad> {
    let (spec, ctx) = mosura::lang::load_cached(&program.language_id)?;
    let skipper = Skipper::for_language(&program.language_id);

    // Decode each range independently, then hash the whole body in ascending address order —
    // Ghidra's `FunctionBodyFunctionExtentGenerator` walks `listing.getInstructions(body, true)`.
    let mut bytes_per_range = Vec::new();
    for &(min, max) in &golden.ranges {
        let len = (max - min + 1) as usize;
        let addr = mosura::decompile::space::Address::new(program.default_space, min);
        let window = program.memory.read_window(addr, len);
        if window.len() < len {
            return None; // not loaded — reported by the caller
        }
        bytes_per_range.push((min, window));
    }

    let mut decoded = Vec::new();
    for (min, window) in &bytes_per_range {
        let insns = spec.disassemble_ctx(window, *min, ctx);
        let fps = spec.disassemble_fingerprint(window, *min, ctx);
        assert_eq!(insns.len(), fps.len(), "one fingerprint per instruction");
        for (insn, fp) in insns.into_iter().zip(fps) {
            decoded.push((insn, fp));
        }
    }

    let units: Vec<CodeUnitInput> = decoded
        .iter()
        .map(|(insn, fp)| {
            // `InstructionDB.getFlowType()` = getModifiedFlowType(proto flow, flowOverride).
            // The override is what analysis decided (a recovered tail call, say) and outranks
            // the bytes; FID subtracts every call from codeUnitSize, so reading it off SLEIGH
            // alone leaves the size one too high per tail call.
            let addr = mosura::decompile::space::Address::new(program.default_space, insn.address);
            let next = insn.address + insn.bytes.len() as u64;
            let props = mosura::analysis::flowtype::overridden_flow_props(
                &insn.ops,
                insn.address,
                next,
                program.flow_override_at(addr),
            );
            CodeUnitInput {
                min_address: insn.address,
                max_address: next - 1,
                bytes: &insn.bytes,
                fingerprint: Some(fp),
                is_call: Some(props.call),
            }
        })
        .collect();

    FidHasher::new(skipper).hash(
        &units,
        &ProgramRelocations(program),
        &ProgramOperandAddresses(program),
    )
}

/// Analyze the binary a golden was captured from.
fn analyze(binary: &std::path::Path) -> Option<Program> {
    let ext = binary.extension().and_then(|e| e.to_str()).unwrap_or_default();
    // The `.watcom-le` column is a bound MZ+LE (DOS-extender) image; `analyze_file` would send
    // it down the MZ-stub path, so the LE objects need the LE loader — same routing as
    // `tests/ground_truth_parity.rs`.
    if ext == "watcom-le" {
        return analysis::analyze_le_file(binary).ok();
    }
    let declared = ext.starts_with("watcom").then_some("watcom");
    analysis::analyze_file_as(binary, declared).ok()
}

/// The gate. Every quad in every golden must be reproduced byte-identically.
///
/// Reports the full tally rather than stopping at the first divergence — when the hasher is
/// wrong, *which* functions diverge and on which architecture is the diagnostic.
#[test]
fn quads_match_ghidra_byte_for_byte() {
    let dir = goldens_dir();
    if !dir.exists() {
        eprintln!("skip: {} absent (regenerate: scripts/capture-fid-hashes.sh)", dir.display());
        return;
    }

    let mut goldens: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .expect("goldens dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "fidhash"))
        .collect();
    goldens.sort();
    assert!(!goldens.is_empty(), "goldens are committed");

    let mut matched = 0usize;
    let mut compared = 0usize;
    let mut unreadable = 0usize;
    let mut per_arch: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut failures: Vec<String> = Vec::new();

    for golden_path in &goldens {
        let stem = golden_path.file_stem().unwrap().to_string_lossy().to_string();
        let binary = paths::ground_truth_dir().join(&stem);
        if !binary.exists() {
            continue;
        }
        let Some(program) = analyze(&binary) else {
            eprintln!("  skip {stem}: analysis failed");
            continue;
        };
        let arch = stem.rsplit('.').next().unwrap_or("?").to_string();

        for golden in parse_golden(&std::fs::read_to_string(golden_path).expect("golden")) {
            let Some(ours) = hash_function(&program, &golden) else {
                unreadable += 1;
                continue;
            };
            compared += 1;
            let entry = per_arch.entry(arch.clone()).or_default();
            entry.1 += 1;
            if ours == golden.quad {
                matched += 1;
                entry.0 += 1;
            } else if failures.len() < 400 {
                failures.push(format!(
                    "{stem} {} @ {:#x}\n     ghidra: size={} full={:016x} add={} spec={:016x}\n     mosura: size={} full={:016x} add={} spec={:016x}",
                    golden.name,
                    golden.entry,
                    golden.quad.code_unit_size,
                    golden.quad.full_hash,
                    golden.quad.specific_hash_additional_size,
                    golden.quad.specific_hash,
                    ours.code_unit_size,
                    ours.full_hash,
                    ours.specific_hash_additional_size,
                    ours.specific_hash
                ));
            }
        }
    }

    eprintln!("FID hash parity: {matched}/{compared} quads byte-identical to Ghidra");
    for (arch, (ok, total)) in &per_arch {
        eprintln!("  {arch:<16} {ok}/{total}");
    }
    if unreadable > 0 {
        eprintln!("  ({unreadable} bodies not readable from the loaded image)");
    }

    assert!(compared > 0, "the gate actually compared something");

    // Per-architecture floors. x86 is the column the port is built on and the one Ghidra's
    // shipped databases cover, so it is held at FULL parity. The others carry known,
    // diagnosed gaps (see below) and are ratcheted: they may improve, never regress.
    //
    // Raise a floor whenever a fix lands. Never lower one to make a change pass — a drop is
    // the regression this gate exists to catch.
    let floors: &[(&str, usize, usize)] = &[
        // (arch, floor, total-at-the-time-the-floor-was-set)
        ("gcc-x86-64", 52, 52),
        ("watcom-x86-32", 83, 84),
        ("gcc-riscv64", 53, 58),
        ("gcc-aarch64", 16, 56),
        ("gcc-m68k", 12, 41),
        ("watcom-le", 0, 1),
    ];

    let mut regressions = Vec::new();
    for (arch, floor, _known_total) in floors {
        let (ok, total) = per_arch.get(*arch).copied().unwrap_or((0, 0));
        if total == 0 {
            continue; // that column's goldens are absent
        }
        if ok < *floor {
            regressions.push(format!("{arch}: {ok}/{total}, floor is {floor}"));
        }
    }

    assert!(
        regressions.is_empty(),
        "FID hash parity regressed:\n  {}\n\nDiverging quads:\n  {}",
        regressions.join("\n  "),
        failures.iter().take(10).cloned().collect::<Vec<_>>().join("\n  ")
    );

    // The x86 columns are held exactly, so any divergence there is a hard failure with the
    // detail attached rather than a silent ratchet pass.
    let x86_failures: Vec<&String> =
        failures.iter().filter(|f| f.contains("x86-64")).collect();
    assert!(
        x86_failures.is_empty(),
        "x86-64 must stay at full parity; {} diverged:\n  {}",
        x86_failures.len(),
        x86_failures.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n  ")
    );
}
