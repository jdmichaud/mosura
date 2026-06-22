//! Jump-table recovery for `switch` statements — phase **S1** of the switch port
//! (`docs/switches-plan.md`), a port of Ghidra's `JumpBasic` model (`jumptable.cc`).
//! Given a `BRANCHIND`, recognize the index→target computation, read the table out of
//! the binary image, and produce the list of case target addresses. (S2 wires these as
//! CFG edges; S3 structures the `switch`.)

use super::cfg::Funcdata;
use super::ssa::{Def, Ssa};
use crate::sleigh::pcode::{opcode_name, PArg};

/// A read-only view of the binary: `(base_address, bytes)` segments (the datatest
/// chunks). Jump tables and globals live in segments other than the function's code.
pub type Image<'a> = [(u64, &'a [u8])];

/// A recovered jump table: the switch index value and the per-case target addresses.
pub struct JumpTable {
    pub index: Def,
    pub targets: Vec<u64>,
}

fn op_name(fd: &Funcdata, i: usize) -> &'static str {
    opcode_name(fd.ops[i].op.opcode)
}

fn as_named(fd: &Funcdata, d: Def, name: &str) -> Option<usize> {
    match d {
        Def::Op(i) if op_name(fd, i) == name => Some(i),
        _ => None,
    }
}

/// Follow `COPY`/`ZEXT`/`SEXT` to the underlying reaching def.
fn fold(fd: &Funcdata, ssa: &Ssa, mut d: Def) -> Def {
    for _ in 0..64 {
        match d {
            Def::Op(i) if matches!(op_name(fd, i), "COPY" | "INT_ZEXT" | "INT_SEXT") => match ssa.uses.get(&(i, 0)) {
                Some(&nd) => d = nd,
                None => return d,
            },
            _ => return d,
        }
    }
    d
}

/// The reaching def of op `i`'s input `pos`, with transparent ops folded away.
fn operand(fd: &Funcdata, ssa: &Ssa, i: usize, pos: usize) -> Option<Def> {
    ssa.uses.get(&(i, pos)).map(|&d| fold(fd, ssa, d))
}

/// The constant value of op `i`'s input `pos` (direct, or a `COPY` of a constant).
fn const_in(fd: &Funcdata, ssa: &Ssa, i: usize, pos: usize) -> Option<u64> {
    if let Some(PArg::Var(v)) = fd.ops[i].op.ins.get(pos) {
        if v.is_const() {
            return Some(v.offset);
        }
    }
    match operand(fd, ssa, i, pos)? {
        Def::Op(j) if op_name(fd, j) == "COPY" => {
            if let Some(PArg::Var(v)) = fd.ops[j].op.ins.first() {
                if v.is_const() {
                    return Some(v.offset);
                }
            }
            None
        }
        _ => None,
    }
}

/// Read `size` little-endian bytes at address `addr` from the image, sign-extended.
fn read_sext(image: &Image, addr: u64, size: usize) -> Option<i64> {
    for (base, bytes) in image {
        if addr >= *base && addr + size as u64 <= *base + bytes.len() as u64 {
            let off = (addr - *base) as usize;
            let mut val: i64 = 0;
            for k in 0..size {
                val |= (bytes[off + k] as i64) << (8 * k);
            }
            let shift = 64 - 8 * size;
            return Some((val << shift) >> shift); // sign-extend from `size` bytes
        }
    }
    None
}

/// The byte length available at `addr` in whatever image segment contains it.
fn seg_len(image: &Image, addr: u64) -> Option<u64> {
    image.iter().find(|(b, by)| addr >= *b && addr < *b + by.len() as u64).map(|(b, by)| *b + by.len() as u64 - addr)
}

const MAX_CASES: u64 = 1024;

/// Recover the jump table rooted at the `BRANCHIND` op `indop`. Handles the `JumpBasic`
/// forms gcc emits — a table of either absolute targets or table-base-relative offsets,
/// indexed by `index * entry_size`:
///
/// ```text
///   target = (base +) sext(*(base + index * esize))
/// ```
pub fn recover(fd: &Funcdata, ssa: &Ssa, image: &Image, indop: usize) -> Option<JumpTable> {
    if op_name(fd, indop) != "BRANCHIND" {
        return None;
    }
    let target = operand(fd, ssa, indop, 0)?;

    // Relative form: target = table_base + sext(load). Find the constant base addend and
    // the loaded entry; otherwise the load is the target directly (absolute form).
    let (relative_base, load) = match target {
        Def::Op(i) if op_name(fd, i) == "INT_ADD" => {
            let a = operand(fd, ssa, i, 0);
            let b = operand(fd, ssa, i, 1);
            let load_a = a.and_then(|d| as_named(fd, d, "LOAD"));
            let load_b = b.and_then(|d| as_named(fd, d, "LOAD"));
            match (const_in(fd, ssa, i, 0), const_in(fd, ssa, i, 1), load_a, load_b) {
                (Some(base), _, _, Some(l)) => (base, l),
                (_, Some(base), Some(l), _) => (base, l),
                _ => return None,
            }
        }
        Def::Op(i) if op_name(fd, i) == "LOAD" => (0, i), // absolute table
        _ => return None,
    };

    // The load address: base + index * entry_size.
    let addr = operand(fd, ssa, load, 1).and_then(|d| as_named(fd, d, "INT_ADD"))?;
    let mul = operand(fd, ssa, addr, 0)
        .and_then(|d| as_named(fd, d, "INT_MULT"))
        .or_else(|| operand(fd, ssa, addr, 1).and_then(|d| as_named(fd, d, "INT_MULT")))?;
    // the non-multiply operand of the address add is the table base
    let table_base = const_in(fd, ssa, addr, 0).or_else(|| const_in(fd, ssa, addr, 1))?;
    let entry_size = const_in(fd, ssa, mul, 0).or_else(|| const_in(fd, ssa, mul, 1))? as usize;
    if entry_size == 0 || entry_size > 8 {
        return None;
    }
    // the index is the multiply's non-constant operand
    let index = if const_in(fd, ssa, mul, 1).is_some() {
        operand(fd, ssa, mul, 0)?
    } else {
        operand(fd, ssa, mul, 1)?
    };

    // The table spans from table_base to the end of its image segment (the .rodata
    // chunk); read entries until a target leaves the code or the cap is hit.
    let n = (seg_len(image, table_base)? / entry_size as u64).min(MAX_CASES);
    let mut targets = Vec::new();
    for k in 0..n {
        let entry = read_sext(image, table_base + k * entry_size as u64, entry_size)?;
        let t = if relative_base != 0 {
            (relative_base as i64 + entry) as u64
        } else {
            entry as u64
        };
        targets.push(t);
    }
    if targets.is_empty() {
        return None;
    }
    Some(JumpTable { index, targets })
}
