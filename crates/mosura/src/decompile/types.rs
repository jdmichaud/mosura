//! The data-type lattice — a port of Ghidra's `Datatype`/`TypeFactory` (`type.cc`). Types
//! are ordered by *metatype* (how specific they are); type inference (`infertypes`) meets
//! the types implied at each varnode and settles on the most specific consistent one.

/// A C data type. `Pointer` carries the pointee; aggregate types (array/struct) are later.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Datatype {
    Void,
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
}

impl Datatype {
    pub fn size(&self) -> u32 {
        match self {
            Datatype::Void => 0,
            Datatype::Bool => 1,
            Datatype::Unknown(n) | Datatype::Int(n) | Datatype::Uint(n) | Datatype::Float(n) => *n,
            Datatype::Pointer(n, _) => *n,
        }
    }

    /// How specific the type is (higher wins a meet). Mirrors Ghidra's metatype ordering:
    /// unknown < int/uint < bool < float < pointer.
    pub fn metatype(&self) -> u8 {
        match self {
            Datatype::Void => 0,
            Datatype::Unknown(_) => 1,
            Datatype::Int(_) | Datatype::Uint(_) => 2,
            Datatype::Bool => 3,
            Datatype::Float(_) => 4,
            Datatype::Pointer(..) => 5,
        }
    }

    /// Ghidra's `sub_metatype` — the fine-grained ordering key used by [`type_order`] (the
    /// type-propagation comparator). *Lower* values order *earlier* / are more specific. These
    /// are the exact values from `enum sub_metatype` (`type.hh`) for the lattice we model; note
    /// `uint` (16) is deemed slightly more specific than `int` (17), as in Ghidra.
    pub fn submeta(&self) -> u8 {
        match self {
            Datatype::Pointer(..) => 6, // SUB_PTR
            Datatype::Float(_) => 8,    // SUB_FLOAT
            Datatype::Bool => 10,       // SUB_BOOL
            Datatype::Uint(_) => 16,    // SUB_UINT_PLAIN
            Datatype::Int(_) => 17,     // SUB_INT_PLAIN
            Datatype::Unknown(_) => 21, // SUB_UNKNOWN
            Datatype::Void => 23,       // SUB_VOID
        }
    }

    /// The default type for a bare value of a given width.
    pub fn default_for(size: u32) -> Datatype {
        Datatype::Unknown(size)
    }

    /// The C name (used in declarations and casts).
    pub fn name(&self) -> String {
        match self {
            Datatype::Void => "void".into(),
            Datatype::Unknown(n) => format!("undefined{n}"),
            Datatype::Int(n) => format!("int{n}"),
            Datatype::Uint(n) => format!("uint{n}"),
            Datatype::Bool => "bool".into(),
            Datatype::Float(n) => format!("float{n}"),
            Datatype::Pointer(_, to) => format!("{} *", to.name()),
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
        assert_eq!(Datatype::Unknown(8).name(), "undefined8");
        assert_eq!(Datatype::Pointer(8, Box::new(Datatype::Int(4))).name(), "int4 *");
    }
}
