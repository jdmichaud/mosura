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
    /// Ghidra `TypeChar` (type.hh:356) — a 1-byte `TYPE_INT` carrying the `chartype` flag, with
    /// `sub_metatype = SUB_INT_CHAR`. It is a DISTINCT core type from `int1`, and it is the DEFAULT
    /// one: `cacheCoreTypes` installs it as `typecache[1][TYPE_INT]` under the comment "Char is
    /// preferred over other int types" (type.cc:3228), so `getBase(1,TYPE_INT)` answers `char` while
    /// `int1` is `type_nochar` (:3220), reachable only through `getBaseNoChar` (type.hh:830).
    /// [`Datatype::Int(1)`](Self::Int) remains that opt-out; Ghidra calls it from three shift-amount
    /// sites (typeop.cc:1514/1539/1604) that mosura has not ported.
    Char,
    /// Signed integer of N bytes.
    Int(u32),
    /// Unsigned integer of N bytes.
    Uint(u32),
    /// A 1-byte boolean.
    Bool,
    /// IEEE float of N bytes.
    Float(u32),
    /// Ghidra `TypeCode` (`TYPE_CODE = 11`, type.hh:86) — "Data is actual executable code".
    /// `TypeFactory::getTypeCode` (type.cc) hands back a size-1 generic, complete code object;
    /// it exists to be POINTED AT, and `TypeOpCallind::getInputLocal` (typeop.cc) makes exactly
    /// that pointer the local type of an indirect call's slot 0: "First parameter is code
    /// pointer". Without it a call target is only ever `undefined4`, so the printer must cast the
    /// value to call it — which is a different program from `call [mem]`.
    Code,
    /// Pointer of N bytes to a pointee.
    Pointer(u32, Box<Datatype>),
    /// Array of `count` elements of the given type (Ghidra `TypeArray`).
    Array(Box<Datatype>, u64),
    /// Structure: total size + `(byte offset, field type)` components (Ghidra `TypeStruct`).
    Struct(u32, Vec<(u64, Datatype)>),
}

impl Datatype {
    /// The tag of an anonymous struct of `size` bytes with `fields` = `(byte offset, type)`,
    /// ascending: `s<size>` for the contiguous all-`int4` layout (gcc's common case), else
    /// `s<size>_<sig>` with every field as `<kind><bytes>` (`i` int, `u` uint, `x` unknown, `c`
    /// char, `b` bool, `f` float, `r` pointer, `k` code, `a` array, `s` struct) and every gap as
    /// `p<bytes>` — `s12_i4p4u2p2`. A function of the layout only: two layouts of one size never
    /// share a tag, and the same layout in two TUs always does.
    pub fn struct_tag(size: u32, fields: &[(u64, Datatype)]) -> String {
        let contiguous_int4 = !fields.is_empty()
            && size as u64 == 4 * fields.len() as u64
            && fields.iter().enumerate().all(|(i, (off, ty))| *off == 4 * i as u64 && matches!(ty, Datatype::Int(4)));
        if contiguous_int4 {
            return format!("s{size}");
        }
        let kind = |ty: &Datatype| match ty {
            Datatype::Int(_) => 'i',
            Datatype::Uint(_) => 'u',
            Datatype::Unknown(_) => 'x',
            Datatype::Char => 'c',
            Datatype::Bool => 'b',
            Datatype::Float(_) => 'f',
            Datatype::Pointer(..) => 'r',
            Datatype::Code => 'k',
            Datatype::Array(..) => 'a',
            Datatype::Struct(..) => 's',
            Datatype::Void | Datatype::Spacebase(_) => 'v',
        };
        let mut sig = String::new();
        let mut at = 0u64;
        for (off, ty) in fields {
            if *off > at {
                sig += &format!("p{}", off - at);
            }
            sig += &format!("{}{}", kind(ty), ty.size());
            at = off + ty.size() as u64;
        }
        if size as u64 > at {
            sig += &format!("p{}", size as u64 - at);
        }
        format!("s{size}_{sig}")
    }

    pub fn size(&self) -> u32 {
        match self {
            Datatype::Void => 0,
            // Ghidra `TypeSpacebase` is size 0 (open-ended, `Datatype(0,1,TYPE_SPACEBASE)`).
            Datatype::Spacebase(_) => 0,
            // `getTypeCode` reads `typecache[1][...]`: the generic code object is size 1.
            Datatype::Bool | Datatype::Char | Datatype::Code => 1,
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
            Datatype::Char | Datatype::Int(_) | Datatype::Uint(_) => 3,
            Datatype::Bool => 4,
            // Ghidra `TYPE_CODE = 11`, between `TYPE_BOOL = 12` and `TYPE_FLOAT = 10`.
            Datatype::Code => 5,
            Datatype::Float(_) => 6,
            Datatype::Pointer(..) => 7,
            // aggregates are more specific than a pointer (Ghidra TYPE_ARRAY/STRUCT < TYPE_PTR)
            Datatype::Array(..) => 8,
            Datatype::Struct(..) => 9,
        }
    }

    /// Ghidra `TypeFactory::getExactPiece` (type.cc:4028): the data-type covering `size` bytes at
    /// `offset` within this type — descending through components until the size matches exactly.
    ///
    /// Ghidra falls back to a `TypePartialStruct`/`TypePartialEnum`/`TypePartialUnion` wrapper when
    /// no component matches exactly; mosura models no partial-type variants, so that fallback
    /// answers `None` and the caller keeps the piece's own type. That is the conservative
    /// direction — a piece is left untyped rather than given an invented type.
    pub fn get_exact_piece(&self, offset: i64, size: u32) -> Option<Datatype> {
        let mut ct = self.clone();
        let mut cur_off = offset;
        loop {
            if (ct.size() as i64) < size as i64 + cur_off {
                break; // range is beyond the end of the current data-type
            }
            if ct.size() == size {
                return Some(ct); // perfect size match
            }
            match ct.get_subtype(cur_off) {
                Some((sub, newoff)) => {
                    ct = sub;
                    cur_off = newoff;
                }
                None => break,
            }
        }
        None
    }

    /// Ghidra `Datatype::isCharPrint` (type.hh:218): `flags & (chartype|utf16|utf32|opaque_string)`
    /// — does this print as a character rather than a number? mosura models only the `chartype`
    /// member of that set ([`Datatype::Char`]); it has no wide-char or opaque-string variants, so a
    /// UTF-16/32 string type cannot arise and cannot be misjudged here.
    pub fn is_char_print(&self) -> bool {
        matches!(self, Datatype::Char)
    }

    /// Ghidra `Datatype::isPieceStructured` (type.hh:929): the type is made of separate pieces —
    /// `metatype <= TYPE_ARRAY`, i.e. the composite metatypes. mosura models `Struct` and `Array`
    /// of that set (union/partial-* have no variant here).
    pub fn is_piece_structured(&self) -> bool {
        matches!(self, Datatype::Struct(..) | Datatype::Array(..))
    }

    /// Ghidra `Datatype::isPrimitiveWhole` (type.cc:501): is this really one primitive value, rather
    /// than an aggregate that merely happens to be this wide? A non-composite is; a composite is
    /// only if its first component spans the whole thing and is itself primitive-whole (an array of
    /// one element, a struct with a single full-width field).
    ///
    /// Read by the double-precision `attemptMarking` routines, which refuse to mark a type-locked
    /// whole as double precision unless it is a single primitive.
    pub fn is_primitive_whole(&self) -> bool {
        if !self.is_piece_structured() {
            return true;
        }
        let component = match self {
            Datatype::Array(elem, _) => Some((**elem).clone()),
            Datatype::Struct(_, fields) => fields.first().map(|(_, t)| t.clone()),
            _ => None,
        };
        if let Some(component) = component {
            if component.size() == self.size() {
                return component.is_primitive_whole();
            }
        }
        false
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
            Datatype::Code => 9,          // SUB_CODE
            Datatype::Bool => 10,         // SUB_BOOL
            Datatype::Uint(_) => 16,      // SUB_UINT_PLAIN
            Datatype::Int(_) => 17,       // SUB_INT_PLAIN
            // SUB_INT_CHAR is 19 — LESS specific than SUB_INT_PLAIN, so propagation prefers a plain
            // `int1` over a `char` when both reach a Varnode (type.hh:108).
            Datatype::Char => 19,         // SUB_INT_CHAR
            Datatype::Unknown(_) => 21,   // SUB_UNKNOWN
            Datatype::Spacebase(_) => 22, // SUB_SPACEBASE
            Datatype::Void => 23,         // SUB_VOID
        }
    }

    /// The default type for a bare value of a given width.
    pub fn default_for(size: u32) -> Datatype {
        Datatype::Unknown(size)
    }

    /// Ghidra `TypeFactory::getBase(s, TYPE_INT)` (type.cc:3631): the signed-integer core type of
    /// `size` bytes. At size 1 that is [`Datatype::Char`], NOT `int1` — `cacheCoreTypes` installs the
    /// chartype as `typecache[1][TYPE_INT]` because "Char is preferred over other int types"
    /// (type.cc:3228). Every site that mirrors a Ghidra `getBase(_, TYPE_INT)` must come through
    /// here; the opt-out is `getBaseNoChar` (type.hh:830), which Ghidra calls only for a shift's
    /// amount operand (typeop.cc:1514/1539/1604) and which mosura spells `Datatype::Int(1)` directly.
    pub fn base_int(size: u32) -> Datatype {
        if size == 1 {
            Datatype::Char
        } else {
            Datatype::Int(size)
        }
    }

    /// Ghidra `TYPE_PTR` test.
    pub fn is_pointer(&self) -> bool {
        matches!(self, Datatype::Pointer(..))
    }

    /// Ghidra `getMetatype() == TYPE_INT`. [`Datatype::Char`] IS `TYPE_INT` (`TypeChar` is a
    /// `TypeBase(1,TYPE_INT,…)`, type.hh:356), so every predicate that Ghidra writes against the
    /// METATYPE must accept it. mosura's predicates match on the enum VARIANT, which is the same
    /// thing only as long as one variant per metatype exists — adding `Char` broke that, and the
    /// first casualty was `isSubpieceCast`, which stopped recognising a 1-byte truncation as a cast
    /// and printed `SUB81(x,0)` where Ghidra prints `(char)x`. Use this at any site whose Ghidra
    /// original tests `TYPE_INT`.
    ///
    /// ⭐ THE WORD "first" ABOVE WAS A TELL THAT A SET EXISTED, AND NOBODY ENUMERATED IT. The second
    /// casualty went unnoticed for four more type-layer commits: `cast_standard` matched the `Int`
    /// variant, so `Char` fell through its `_` catch-all and cast unconditionally — worth 302 casts
    /// across 64 the subject functions and one corpus fixture stuck below 1.000 (fixed in `e517104`).
    ///
    /// THE SWEEP IS NOW COMPLETE AND ENUMERATED, so the next variant addition gets a checklist
    /// instead of an archaeology problem. Every site that must know `Char` is an int, verified:
    ///   · `cast.rs`   `cast_standard` reqbase arm + all three `curbase` acceptability sets, and
    ///                 the `input_cast` unsigned test (`cast.rs:149`)
    ///   · `varmap.rs` the five type-compatibility predicates (`:79`, `:85`, `:144`, `:252`, `:253`)
    ///   · `printc.rs` the unsigned-render test (`:86`), and the two variant lists at `:70`/`:76`
    ///                 which spell `Datatype::Char` out explicitly
    ///   · `infertypes.rs` the propagation guards at `:393` and `:824`
    ///   · `types.rs`  this predicate, plus [`type_order`]'s two int/uint meet arms
    /// And every per-variant site in this file that must answer for `Char` at all: `size` (1),
    /// `metatype` (grouped with Int/Uint), `submeta` (SUB_INT_CHAR = 19, deliberately LESS specific
    /// than SUB_INT_PLAIN), `name` ("char").
    /// Checked and correctly NOT metatype predicates: `printc.rs`'s declaration printer (a `_` arm
    /// that just prints `ty.name()`) and `infertypes.rs`'s `Option` match.
    ///
    /// ⇒ WHEN YOU ADD A DATATYPE VARIANT: walk this list, and extend it. A variant match is not a
    ///   metatype test, and the failure is silent — the wrong answer compiles and renders.
    pub fn is_int_meta(&self) -> bool {
        matches!(self, Datatype::Int(_) | Datatype::Char)
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

    /// Ghidra `Datatype::printNameBase` (type.hh:273): the one-letter stem a default variable name is
    /// built from — the FIRST CHARACTER of the data-type's name, with `TypePointer` prepending `p`
    /// (type.hh:424) and `TypeArray` prepending `a` (type.hh:457), each recursing into what it points
    /// at. This is what makes an `int4` local `iVar1`, a `char *` local `pcVar1`, an `undefined4`
    /// stack slot `xStack_24` and an array of them `axStack_24`.
    ///
    /// Ghidra's base case is guarded — `if (!name.empty()) s << name[0];` — and `TypeSpacebase` is
    /// constructed with NO name (`Datatype(0,1,TYPE_SPACEBASE)`, type.hh:733/736), so it contributes
    /// nothing and a pointer to it is a bare `pVar1`. mosura's [`Self::name`] answers `"spacebase"`
    /// for the C declaration form, which is a rendering mosura emits and Ghidra does not; that string
    /// must not leak into a variable stem as well.
    pub fn print_name_base(&self) -> String {
        match self {
            Datatype::Pointer(_, to) => format!("p{}", to.print_name_base()),
            Datatype::Array(elem, _) => format!("a{}", elem.print_name_base()),
            Datatype::Spacebase(_) => String::new(),
            _ => self.name().chars().next().map(String::from).unwrap_or_default(),
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
            Datatype::Char => "char".into(),
            Datatype::Int(n) => format!("int{n}"),
            Datatype::Uint(n) => format!("uint{n}"),
            Datatype::Bool => "bool".into(),
            Datatype::Float(n) => format!("float{n}"),
            // Ghidra's `code` pseudo-type; the survey prelude declares `typedef int (*code)();`
            // so `code *` renders as a callable function pointer.
            Datatype::Code => "code".to_string(),
            Datatype::Pointer(_, to) => format!("{} *", to.name()),
            Datatype::Array(elem, count) => format!("{}[{}]", elem.name(), count),
            // The tag the `struct-return` arm declares (`analysis::sret::struct_declaration`) —
            // the one producer of this variant, at PRINT time only (the census in cast.rs). Ghidra
            // names a struct by its symbol; this is the port's spelling of an anonymous one, a
            // function of the LAYOUT alone (`struct_tag`), so a definition and its callers'
            // externs in other TUs spell the same struct the same way.
            Datatype::Struct(n, fields) => format!("struct {}", Datatype::struct_tag(*n, fields)),
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
            (Datatype::Uint(n), b) if b.is_int_meta() => Datatype::base_int(*n),
            (a, Datatype::Uint(n)) if a.is_int_meta() => Datatype::base_int(*n),
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

    /// Ghidra `Datatype::printNameBase` (type.hh:273) with the `TypePointer`/`TypeArray` overrides
    /// (:424/:457): each wrapper contributes its own letter AND recurses, so the stem of a `uint4 *`
    /// is `pu`, not `p`. `TypeSpacebase` carries no name and contributes nothing (:733).
    /// Ghidra `TypeFactory::getBase(s,TYPE_INT)` prefers the chartype at size 1 (type.cc:3228), so
    /// the DEFAULT 1-byte signed integer is `char`, not `int1`. `int1` survives as `type_nochar`
    /// (:3220) for `getBaseNoChar`. Confirmed like-for-like against `oracle/capture --c` on the
    /// `partialsplit` datatest, which declares `char cVar1; char *pcVar2;` and casts `(char)`.
    #[test]
    fn base_int_prefers_char_at_size_one() {
        assert_eq!(Datatype::base_int(1), Datatype::Char);
        assert_eq!(Datatype::base_int(2), Datatype::Int(2));
        assert_eq!(Datatype::base_int(4), Datatype::Int(4));
        assert_eq!(Datatype::Char.name(), "char");
        assert_eq!(Datatype::Char.size(), 1);
        assert_eq!(Datatype::Char.print_name_base(), "c");
        // `char` IS TYPE_INT, so every metatype predicate accepts it (type.hh:356)...
        assert!(Datatype::Char.is_int_meta());
        assert_eq!(Datatype::Char.metatype(), Datatype::Int(1).metatype());
        // ...but it is a DISTINCT, less specific sub-metatype: SUB_INT_CHAR 19 > SUB_INT_PLAIN 17,
        // so a plain int1 wins propagation against it (type.hh:108).
        assert_eq!(Datatype::Char.submeta(), 19);
        assert_eq!(type_order(&Datatype::Int(1), &Datatype::Char), std::cmp::Ordering::Less);
    }

    #[test]
    fn print_name_base_recurses_like_ghidra() {
        assert_eq!(Datatype::Int(4).print_name_base(), "i");
        assert_eq!(Datatype::Unknown(4).print_name_base(), "x");
        assert_eq!(
            Datatype::Pointer(4, Box::new(Datatype::Uint(4))).print_name_base(),
            "pu"
        );
        assert_eq!(
            Datatype::Array(Box::new(Datatype::Int(4)), 4).print_name_base(),
            "ai"
        );
        // wrappers nest
        assert_eq!(
            Datatype::Pointer(4, Box::new(Datatype::Pointer(4, Box::new(Datatype::Int(1)))))
                .print_name_base(),
            "ppi"
        );
        // a pointer to the internal spacebase type is a BARE `p` — the pointee has no name
        assert_eq!(
            Datatype::Pointer(4, Box::new(Datatype::Spacebase(crate::decompile::space::SpaceId(4))))
                .print_name_base(),
            "p"
        );
    }

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
