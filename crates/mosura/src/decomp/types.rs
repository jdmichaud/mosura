//! The data-type lattice (Ghidra `type.hh`/`type.cc`), phase **T0** of the type-system
//! port (see `docs/type-system-plan.md`). This is the foundation `ActionInferTypes`
//! propagates over: a `Datatype` plus the lattice order `type_order` (Ghidra
//! `Datatype::compare`/`typeOrder`) that decides which of two types is more *specific*
//! and therefore wins during propagation.
//!
//! In Rust the `TypeFactory`'s interning is unnecessary — `Datatype` is a value type —
//! so the "factory" is just the constructor helpers here.

use std::cmp::Ordering;

/// A data type. Mirrors the subset of Ghidra's `type_metatype` the decompiler needs
/// first; structs/unions/enums (the higher `TYPE_*` metatypes) come in later phases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Datatype {
    /// An unknown low-level type — treated as an unsigned integer (`TYPE_UNKNOWN`).
    Unknown(u32),
    /// Signed integer (`TYPE_INT`). Signed is *less* specific than unsigned in C.
    Int(u32),
    /// Unsigned integer (`TYPE_UINT`).
    Uint(u32),
    /// Boolean (`TYPE_BOOL`).
    Bool,
    /// Floating-point (`TYPE_FLOAT`).
    Float(u32),
    /// Executable code (`TYPE_CODE`).
    Code,
    /// Pointer (`TYPE_PTR`) to `to`, with the given pointer `size` and address `wordsize`.
    Ptr { to: Box<Datatype>, size: u32, wordsize: u32 },
    /// Array (`TYPE_ARRAY`) of `count` `elem`s.
    Array { elem: Box<Datatype>, count: u32 },
    /// The "void" type (`TYPE_VOID`).
    Void,
    /// Placeholder for spacebase (stack/register) look-ups (`TYPE_SPACEBASE`).
    Spacebase(u32),
}

// type_metatype values (type.hh) — lower = more specific, affecting propagation.
const TYPE_VOID: u8 = 17;
const TYPE_SPACEBASE: u8 = 16;
const TYPE_UNKNOWN: u8 = 15;
const TYPE_INT: u8 = 14;
const TYPE_UINT: u8 = 13;
const TYPE_BOOL: u8 = 12;
const TYPE_CODE: u8 = 11;
const TYPE_FLOAT: u8 = 10;
const TYPE_PTR: u8 = 9;
const TYPE_ARRAY: u8 = 7;

// sub_metatype values for the base types (Datatype::base2sub) — the primary compare key.
const SUB_VOID: u8 = 23;
const SUB_SPACEBASE: u8 = 22;
const SUB_UNKNOWN: u8 = 21;
const SUB_INT_PLAIN: u8 = 17;
const SUB_UINT_PLAIN: u8 = 16;
const SUB_BOOL: u8 = 10;
const SUB_CODE: u8 = 9;
const SUB_FLOAT: u8 = 8;
const SUB_PTR: u8 = 6;
const SUB_ARRAY: u8 = 3;

/// The compare recursion depth bound for pointers (`Datatype::typeOrder` passes 10).
const ORDER_LEVEL: i32 = 10;

impl Datatype {
    /// Size in bytes.
    pub fn size(&self) -> u32 {
        match self {
            Datatype::Unknown(s) | Datatype::Int(s) | Datatype::Uint(s) | Datatype::Float(s) | Datatype::Spacebase(s) => *s,
            Datatype::Bool | Datatype::Code => 1,
            Datatype::Ptr { size, .. } => *size,
            Datatype::Array { elem, count } => elem.size() * count,
            Datatype::Void => 0,
        }
    }

    /// The core meta-type (`type_metatype`).
    pub fn metatype(&self) -> u8 {
        match self {
            Datatype::Unknown(_) => TYPE_UNKNOWN,
            Datatype::Int(_) => TYPE_INT,
            Datatype::Uint(_) => TYPE_UINT,
            Datatype::Bool => TYPE_BOOL,
            Datatype::Float(_) => TYPE_FLOAT,
            Datatype::Code => TYPE_CODE,
            Datatype::Ptr { .. } => TYPE_PTR,
            Datatype::Array { .. } => TYPE_ARRAY,
            Datatype::Void => TYPE_VOID,
            Datatype::Spacebase(_) => TYPE_SPACEBASE,
        }
    }

    /// The sub-meta-type — the primary key of the lattice order.
    fn submeta(&self) -> u8 {
        match self {
            Datatype::Unknown(_) => SUB_UNKNOWN,
            Datatype::Int(_) => SUB_INT_PLAIN,
            Datatype::Uint(_) => SUB_UINT_PLAIN,
            Datatype::Bool => SUB_BOOL,
            Datatype::Float(_) => SUB_FLOAT,
            Datatype::Code => SUB_CODE,
            Datatype::Ptr { .. } => SUB_PTR,
            Datatype::Array { .. } => SUB_ARRAY,
            Datatype::Void => SUB_VOID,
            Datatype::Spacebase(_) => SUB_SPACEBASE,
        }
    }

    /// Lattice comparison (Ghidra `Datatype::compare`): order two types by specificity.
    /// `Less` means `self` is *more specific* (sorts earlier) and wins propagation:
    /// first by sub-meta-type (lower is more specific), then by size (larger first),
    /// then — for pointers/arrays — recursively by the pointed-to/element type.
    fn compare(&self, op: &Datatype, level: i32) -> Ordering {
        match self.submeta().cmp(&op.submeta()) {
            Ordering::Equal => {}
            ne => return ne,
        }
        match op.size().cmp(&self.size()) {
            // Ghidra returns (op.size - size): larger size is more specific (sorts first)
            Ordering::Equal => {}
            ne => return ne,
        }
        match (self, op) {
            (Datatype::Ptr { to, wordsize, .. }, Datatype::Ptr { to: to2, wordsize: ws2, .. }) => {
                match wordsize.cmp(ws2) {
                    Ordering::Equal => {}
                    ne => return ne,
                }
                if level <= 0 {
                    Ordering::Equal // depth-bounded: treat as equal rather than recurse forever
                } else {
                    to.compare(to2, level - 1)
                }
            }
            (Datatype::Array { elem, .. }, Datatype::Array { elem: elem2, .. }) => elem.compare(elem2, level),
            _ => Ordering::Equal,
        }
    }

    /// Order `self` against `op` (Ghidra `Datatype::typeOrder`): negative if `self` is
    /// more specific (and should replace `op` during propagation), 0 if equal.
    pub fn type_order(&self, op: &Datatype) -> i32 {
        if self == op {
            return 0;
        }
        match self.compare(op, ORDER_LEVEL) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    /// Is `self` strictly more specific than `op`? (The propagation update test:
    /// Ghidra refines a Varnode's type when `0 > newtype.typeOrder(oldtype)`.)
    pub fn more_specific_than(&self, op: &Datatype) -> bool {
        self.type_order(op) < 0
    }

    /// The exact sub-type occupying `[off, off+size)` within `self`, if one exists
    /// (Ghidra `TypeFactory::getExactPiece`). The identity piece and array-element
    /// access are handled; struct fields come with the struct phase (T5).
    pub fn get_exact_piece(&self, off: u32, size: u32) -> Option<Datatype> {
        if off == 0 && size == self.size() {
            return Some(self.clone());
        }
        match self {
            Datatype::Array { elem, count } => {
                let es = elem.size();
                if es != 0 && off % es == 0 && size == es && off / es < *count {
                    Some((**elem).clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Construct a pointer to `to` (default 8-byte pointer, wordsize 1 — x86-64).
pub fn pointer(to: Datatype) -> Datatype {
    Datatype::Ptr { to: Box::new(to), size: 8, wordsize: 1 }
}

/// Construct an array of `count` `elem`s.
pub fn array(elem: Datatype, count: u32) -> Datatype {
    Datatype::Array { elem: Box::new(elem), count }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specificity_order_matches_ghidra() {
        // unknown is the least specific; a concrete int refines it
        assert!(Datatype::Int(4).more_specific_than(&Datatype::Unknown(4)));
        // unsigned is more specific than signed ("signed is less specific in C")
        assert!(Datatype::Uint(4).more_specific_than(&Datatype::Int(4)));
        // a pointer is more specific than any integer of the same size
        assert!(pointer(Datatype::Int(4)).more_specific_than(&Datatype::Unknown(8)));
        // float vs int: float sub-meta (8) < int (17), so float is more specific
        assert!(Datatype::Float(8).more_specific_than(&Datatype::Int(8)));
        // equal types order as 0
        assert_eq!(Datatype::Int(4).type_order(&Datatype::Int(4)), 0);
    }

    #[test]
    fn larger_size_is_more_specific_within_a_metatype() {
        // same sub-meta-type → the larger size sorts first (Ghidra: op.size - size)
        assert!(Datatype::Int(8).more_specific_than(&Datatype::Int(4)));
        assert!(!Datatype::Int(4).more_specific_than(&Datatype::Int(8)));
    }

    #[test]
    fn pointer_order_recurses_on_pointee() {
        // pointers compare equal sub-meta/size, then by what they point to
        assert!(pointer(Datatype::Uint(4)).more_specific_than(&pointer(Datatype::Int(4))));
    }

    #[test]
    fn sizes() {
        assert_eq!(pointer(Datatype::Int(4)).size(), 8);
        assert_eq!(array(Datatype::Int(4), 10).size(), 40);
        assert_eq!(Datatype::Bool.size(), 1);
        assert_eq!(Datatype::Void.size(), 0);
    }

    #[test]
    fn exact_piece_extracts_array_elements() {
        let a = array(Datatype::Int(4), 10);
        assert_eq!(a.get_exact_piece(0, 40), Some(a.clone())); // whole
        assert_eq!(a.get_exact_piece(8, 4), Some(Datatype::Int(4))); // element 2
        assert_eq!(a.get_exact_piece(6, 4), None); // misaligned
        assert_eq!(a.get_exact_piece(40, 4), None); // out of range
    }
}
