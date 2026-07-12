//! The data-type lattice — a port of Ghidra's `Datatype`/`TypeFactory` (`type.cc`). Types
//! are ordered by *metatype* (how specific they are); type inference (`infertypes`) meets
//! the types implied at each varnode and settles on the most specific consistent one.

use super::space::SpaceId;

/// A C data type. `Pointer` carries the pointee; aggregate types (array/struct) are later.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Datatype {
    Void,
    /// Ghidra `TypeSpacebase` (`TYPE_SPACEBASE`, type.hh:721): a size-0 placeholder standing for a
    /// virtual address space (the `stack`) treated as a structure of symbols. It is the pointee of
    /// the input stack-pointer's locked pointer type (`Funcdata::spacebase`, funcdata.cc:245): a
    /// `PTRSUB` off such a pointer resolves, via the function's `ScopeLocal` symbol table, to a named
    /// local. `getSubType` is never null (Ghidra returns `TYPE_UNKNOWN` when no symbol is mapped), so
    /// pointer-arithmetic always folds a spacebase offset into a `PTRSUB` (`calcSubtype`,
    /// ruleaction.cc:6286); the symbol lookup/naming is deferred to print (`opPtrsub`, printc.cc:1057).
    Spacebase(SpaceId),
    /// `undefined<N>` — a value of known width but unknown interpretation.
    Unknown(u32),
    /// Signed integer of N bytes.
    Int(u32),
    /// Unsigned integer of N bytes.
    Uint(u32),
    /// A 1-byte boolean.
    Bool,
    /// IEEE float of N bytes.
    Float(u32),
    /// Pointer of N bytes to a pointee.
    Pointer(u32, Box<Datatype>),
    /// Array of `count` elements of the given type (Ghidra `TypeArray`).
    Array(Box<Datatype>, u64),
    /// Structure: total size + `(byte offset, field type)` components (Ghidra `TypeStruct`).
    Struct(u32, Vec<(u64, Datatype)>),
}

impl Datatype {
    pub fn size(&self) -> u32 {
        match self {
            Datatype::Void => 0,
            // Ghidra `TypeSpacebase` is size 0 (open-ended, `Datatype(0,1,TYPE_SPACEBASE)`).
            Datatype::Spacebase(_) => 0,
            Datatype::Bool => 1,
            Datatype::Unknown(n) | Datatype::Int(n) | Datatype::Uint(n) | Datatype::Float(n) => *n,
            Datatype::Pointer(n, _) => *n,
            Datatype::Array(elem, count) => elem.size() * *count as u32,
            Datatype::Struct(n, _) => *n,
        }
    }

    /// How specific the type is (higher wins a meet). Mirrors Ghidra's metatype ordering
    /// (`enum type_metatype`, type.hh:79, here inverted so higher = more specific):
    /// void < spacebase < unknown < int/uint < bool < float < pointer < array < struct.
    pub fn metatype(&self) -> u8 {
        match self {
            Datatype::Void => 0,
            // Ghidra `TYPE_SPACEBASE = 16`, between `TYPE_VOID = 17` and `TYPE_UNKNOWN = 15`.
            Datatype::Spacebase(_) => 1,
            Datatype::Unknown(_) => 2,
            Datatype::Int(_) | Datatype::Uint(_) => 3,
            Datatype::Bool => 4,
            Datatype::Float(_) => 5,
            Datatype::Pointer(..) => 6,
            // aggregates are more specific than a pointer (Ghidra TYPE_ARRAY/STRUCT < TYPE_PTR)
            Datatype::Array(..) => 7,
            Datatype::Struct(..) => 8,
        }
    }

    /// Ghidra's `sub_metatype` — the fine-grained ordering key used by [`type_order`] (the
    /// type-propagation comparator). *Lower* values order *earlier* / are more specific. These
    /// are the exact values from `enum sub_metatype` (`type.hh`) for the lattice we model; note
    /// `uint` (16) is deemed slightly more specific than `int` (17), as in Ghidra.
    pub fn submeta(&self) -> u8 {
        match self {
            Datatype::Struct(..) => 2,    // SUB_STRUCT
            Datatype::Array(..) => 3,     // SUB_ARRAY
            Datatype::Pointer(..) => 6,   // SUB_PTR
            Datatype::Float(_) => 8,      // SUB_FLOAT
            Datatype::Bool => 10,         // SUB_BOOL
            Datatype::Uint(_) => 16,      // SUB_UINT_PLAIN
            Datatype::Int(_) => 17,       // SUB_INT_PLAIN
            Datatype::Unknown(_) => 21,   // SUB_UNKNOWN
            Datatype::Spacebase(_) => 22, // SUB_SPACEBASE
            Datatype::Void => 23,         // SUB_VOID
        }
    }

    /// The default type for a bare value of a given width.
    pub fn default_for(size: u32) -> Datatype {
        Datatype::Unknown(size)
    }

    /// Ghidra `TYPE_PTR` test.
    pub fn is_pointer(&self) -> bool {
        matches!(self, Datatype::Pointer(..))
    }

    /// Ghidra `TypePointer::getPtrTo` — the pointed-at type.
    pub fn ptr_to(&self) -> Option<&Datatype> {
        if let Datatype::Pointer(_, p) = self {
            Some(p)
        } else {
            None
        }
    }

    /// Ghidra `Datatype::getAlignSize` — the type's size rounded up to its alignment. mosura
    /// models no padding/alignment beyond the byte size, so this is just [`size`](Self::size).
    pub fn align_size(&self) -> u32 {
        self.size()
    }

    /// Ghidra `Datatype::getSubType(off, newoff)`: descend one level to the sub-component that
    /// contains byte `off`, returning it with the residual offset into it. Arrays drill to the
    /// element; structs to the field; scalars have no sub-component (`None`).
    pub fn get_subtype(&self, off: i64) -> Option<(Datatype, i64)> {
        match self {
            // Ghidra `TypeSpacebase::getSubType` (type.cc:2947) queries the function's `ScopeLocal`
            // symbol at `off` and returns its type, or `TYPE_UNKNOWN` size 1 (newoff 0) when no symbol
            // is mapped — it is **never** null. mosura has no `glb` back-pointer on the `Datatype`, so
            // the symbol resolution is deferred to print time (`printc::render_ptrsub` over
            // `varmap::recover_scope`); here it returns the always-present `undefined1`/0 stand-in, so
            // `hasMatchingSubType` is trivially true and `calcSubtype` always folds into a `PTRSUB`.
            Datatype::Spacebase(_) => Some((Datatype::Unknown(1), 0)),
            Datatype::Array(elem, _) => {
                if off >= self.size() as i64 {
                    return None; // Ghidra TypeArray::getSubType: out of bounds → base (none)
                }
                let es = elem.align_size() as i64;
                Some(((**elem).clone(), if es != 0 { off % es } else { 0 }))
            }
            Datatype::Struct(_, fields) => fields
                .iter()
                .find(|(foff, fty)| {
                    let fo = *foff as i64;
                    fo <= off && off < fo + fty.size() as i64
                })
                .map(|(foff, fty)| (fty.clone(), off - *foff as i64)),
            _ => None,
        }
    }

    /// The C name (used in declarations and casts).
    pub fn name(&self) -> String {
        match self {
            Datatype::Void => "void".into(),
            // Ghidra `TypeSpacebase` is an internal analysis type never declared in C output; it only
            // ever appears as the pointee of the stack-pointer's type. Ghidra's name is "spacebase".
            Datatype::Spacebase(_) => "spacebase".into(),
            // Ghidra's core name for an undefined value of N bytes (`sleigh_arch.cc` core types).
            Datatype::Unknown(n) => format!("xunknown{n}"),
            Datatype::Int(n) => format!("int{n}"),
            Datatype::Uint(n) => format!("uint{n}"),
            Datatype::Bool => "bool".into(),
            Datatype::Float(n) => format!("float{n}"),
            Datatype::Pointer(_, to) => format!("{} *", to.name()),
            Datatype::Array(elem, count) => format!("{}[{}]", elem.name(), count),
            Datatype::Struct(n, _) => format!("struct_{n}"),
        }
    }
}

/// The more-specific of two types of the same width (Ghidra's type meet). Differing widths
/// keep `a` (the established type); differing int signedness prefers signed `int`.
pub fn meet(a: &Datatype, b: &Datatype) -> Datatype {
    if a == b {
        return a.clone();
    }
    if a.size() != b.size() && b.size() != 0 && a.size() != 0 {
        return a.clone();
    }
    let (ma, mb) = (a.metatype(), b.metatype());
    match ma.cmp(&mb) {
        std::cmp::Ordering::Greater => a.clone(),
        std::cmp::Ordering::Less => b.clone(),
        std::cmp::Ordering::Equal => match (a, b) {
            // same metatype: int/uint conflict resolves to signed int
            (Datatype::Uint(n), Datatype::Int(_)) | (Datatype::Int(n), Datatype::Uint(_)) => {
                Datatype::Int(*n)
            }
            _ => a.clone(),
        },
    }
}

/// Ghidra's `Datatype::typeOrder` (`type.cc::compare`): order two data-types the way the type
/// propagation algorithm does. [`Ordering::Less`] means `a` is *more specific* (so propagation
/// keeps `a`). Within one sub-metatype, *bigger* types order earlier; across sub-metatypes, the
/// more specific sub-metatype orders earlier. This is the comparator that decouples a value's
/// type from its varnode storage — propagation overwrites a varnode's type only when the
/// incoming type orders strictly before the one it carries, regardless of either width.
pub fn type_order(a: &Datatype, b: &Datatype) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (sa, sb) = (a.submeta(), b.submeta());
    if sa != sb {
        return sa.cmp(&sb); // lower sub-metatype orders first (more specific)
    }
    if a.size() != b.size() {
        return b.size().cmp(&a.size()); // bigger size orders first
    }
    // same sub-metatype and size: pointers tie-break on the pointee, one level down
    if let (Datatype::Pointer(_, pa), Datatype::Pointer(_, pb)) = (a, b) {
        return type_order(pa, pb);
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_order_matches_ghidra_submeta_ordering() {
        use std::cmp::Ordering::*;
        // more-specific sub-metatypes order earlier (Less), regardless of size
        assert_eq!(type_order(&Datatype::Int(4), &Datatype::Unknown(8)), Less);
        assert_eq!(type_order(&Datatype::Pointer(8, Box::new(Datatype::Unknown(1))), &Datatype::Int(4)), Less);
        assert_eq!(type_order(&Datatype::Float(8), &Datatype::Bool), Less);
        // uint is fractionally more specific than int (SUB_UINT_PLAIN < SUB_INT_PLAIN)
        assert_eq!(type_order(&Datatype::Uint(4), &Datatype::Int(4)), Less);
        // within a sub-metatype, the bigger type orders earlier
        assert_eq!(type_order(&Datatype::Int(8), &Datatype::Int(4)), Less);
        assert_eq!(type_order(&Datatype::Int(4), &Datatype::Int(4)), Equal);
    }

    #[test]
    fn meet_picks_the_more_specific_type() {
        assert_eq!(meet(&Datatype::Unknown(4), &Datatype::Int(4)), Datatype::Int(4));
        assert_eq!(meet(&Datatype::Int(4), &Datatype::Unknown(4)), Datatype::Int(4));
        assert_eq!(
            meet(&Datatype::Int(8), &Datatype::Pointer(8, Box::new(Datatype::Unknown(4)))),
            Datatype::Pointer(8, Box::new(Datatype::Unknown(4)))
        );
        assert_eq!(meet(&Datatype::Int(4), &Datatype::Uint(4)), Datatype::Int(4));
        // differing widths keep the established type
        assert_eq!(meet(&Datatype::Int(8), &Datatype::Int(4)), Datatype::Int(8));
    }

    #[test]
    fn names() {
        assert_eq!(Datatype::Int(4).name(), "int4");
        assert_eq!(Datatype::Unknown(8).name(), "xunknown8");
        assert_eq!(Datatype::Pointer(8, Box::new(Datatype::Int(4))).name(), "int4 *");
    }
}
