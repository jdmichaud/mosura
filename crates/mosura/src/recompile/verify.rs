//! One function, checked: original bytes in, compiled object in, attributed verdict out.
//!
//! Both the whole-corpus census and the single-function loop need exactly this, and when each
//! carried its own copy they drifted — different padding trims and different symbol-resolution
//! rules, which is how two instruments come to disagree about the same function and nobody can
//! say which is right. There is one implementation and both call it.

use super::align::{FnDiff, compare};
use super::candidate::{Candidate, SymbolResolver, load_object_function};
use super::insn::{NoReloc, NormInsn, normalize};

/// What is being checked: a function's identity in the original image.
#[derive(Debug, Clone)]
pub struct Subject {
    /// Symbol the object publishes for this function. Trailing-underscore variants are tolerated.
    pub name: String,
    /// Address in the original image, and the coordinate system both sides are compared in.
    pub va: u64,
    /// Extent recorded for the function, including any inter-function padding.
    pub len: usize,
}

/// How the candidate's BYTES compare, once it is relinked at the original's addresses.
///
/// The distinction matters because it is the one the campaign's historical "byte-clean" figure
/// blurred. That figure masked every byte at a relocation site on both sides, so a candidate
/// referencing the WRONG address scored as clean — the masking cannot tell "the same call, with
/// an unlinked displacement" from "a call somewhere else".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteVerdict {
    /// Every byte agrees, relocation sites included — they were resolved and they matched.
    Identical,
    /// Every byte outside the relocation sites agrees, and at least one site does not. The
    /// candidate references something different from what the original references. This is the
    /// permissive reading that the old masking comparison counted as clean.
    IdenticalOutsideRelocations,
    /// Lengths differ, or a byte outside any relocation site differs.
    Different,
}

/// A checked function.
#[derive(Debug, Clone)]
pub struct Checked {
    pub diff: FnDiff,
    /// Byte-level verdict after relinking — see [`ByteVerdict`].
    pub bytes: ByteVerdict,
    pub original: Vec<NormInsn>,
    pub candidate: Vec<NormInsn>,
    /// The relinked object, carrying the relocations that were resolved to reach this verdict.
    pub relinked: Candidate,
}

#[derive(Debug)]
pub enum VerifyError {
    /// The object holds no code under that name.
    Object(String),
    /// The language tables are unavailable.
    Language(crate::Unimplemented),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Object(e) => write!(f, "{e}"),
            VerifyError::Language(e) => write!(f, "{e}"),
        }
    }
}

/// Compare one compiled object against the original bytes of the function it was decompiled from.
pub fn verify(
    lang: &str,
    original_bytes: &[u8],
    subject: &Subject,
    object: &[u8],
    resolver: &dyn SymbolResolver,
) -> Result<Checked, VerifyError> {
    let relinked = load_object_function(object, &subject.name, subject.va, resolver)
        .or_else(|_| load_object_function(object, &format!("{}_", subject.name), subject.va, resolver))
        .map_err(VerifyError::Object)?;
    let original = trim_padding(normalize(lang, original_bytes, subject.va, &NoReloc).map_err(VerifyError::Language)?);
    // Decode the RELINKED bytes with no relocator. The relinking has already written each
    // resolvable fixup's real value into the bytes, so running the relocator over them again is a
    // second application of the same correction — and it is not harmless: a fixup site whose
    // placeholder is 0 (the usual one) would rewrite any genuine 0 operand elsewhere in the same
    // instruction into a resolved address. That invented an `immediate` divergence on 250
    // functions whose bytes were already identical to the original's, which is how it was found:
    // the byte-level verdict and the instruction-level verdict disagreed, and the bytes were right.
    let candidate =
        trim_padding(normalize(lang, &relinked.relinked_bytes(), subject.va, &NoReloc).map_err(VerifyError::Language)?);
    let diff = compare(&original, &candidate);
    let bytes = byte_verdict(&original, &candidate, &relinked, subject.va);
    Ok(Checked { diff, bytes, original, candidate, relinked })
}

/// Compare the two byte strings over the trimmed extents, and say whether the only disagreements
/// are at relocation sites.
///
/// Both sides are bounded by their trimmed instruction streams rather than by the recorded extent,
/// so inter-function padding does not decide a verdict.
fn byte_verdict(original: &[NormInsn], candidate: &[NormInsn], relinked: &Candidate, va: u64) -> ByteVerdict {
    let (Some(o_end), Some(c_end)) = (original.last().map(|i| i.end()), candidate.last().map(|i| i.end()))
    else {
        return ByteVerdict::Different;
    };
    if o_end != c_end {
        return ByteVerdict::Different;
    }
    let len = (o_end - va) as usize;
    let obytes: Vec<u8> = original.iter().flat_map(|i| i.bytes.iter().copied()).collect();
    let cbytes = relinked.relinked_bytes();
    if obytes.len() < len || cbytes.len() < len {
        return ByteVerdict::Different;
    }
    let mut at_reloc = vec![false; len];
    for f in &relinked.fixups {
        for k in f.offset..(f.offset + f.width).min(len) {
            at_reloc[k] = true;
        }
    }
    let mut reloc_differs = false;
    for k in 0..len {
        if obytes[k] == cbytes[k] {
            continue;
        }
        if at_reloc[k] {
            reloc_differs = true;
        } else {
            return ByteVerdict::Different;
        }
    }
    if reloc_differs { ByteVerdict::IdenticalOutsideRelocations } else { ByteVerdict::Identical }
}

/// Drop the alignment padding a linker leaves between functions.
///
/// A recorded extent runs to the next function's entry, so it includes whatever the linker put in
/// between. At byte level that has to be pattern-matched against a list of the forms each compiler
/// happens to use; at instruction level it is simply the trailing run of no-ops, decided on
/// semantics ([`NormInsn::is_nop`]) and therefore correct for spellings nobody has enumerated.
pub fn trim_padding(mut insns: Vec<NormInsn>) -> Vec<NormInsn> {
    while insns.len() > 1 && insns.last().is_some_and(|i| i.is_nop()) {
        insns.pop();
    }
    insns
}

/// Resolve the symbols mosura's own emitter produces, which name the address they came from
/// (`FUN_00010c20`, `func_0x00010c20_`, `_xRam00083090`).
///
/// A project with a different convention supplies its own [`SymbolResolver`]; this one is here so
/// the two callers cannot disagree about what `_xRam000a71b1` means.
pub fn emitted_symbol_address(symbol: &str) -> Option<u64> {
    let s = symbol.trim_start_matches('_').trim_end_matches('_');
    let hex = s
        .strip_prefix("func_0x")
        .or_else(|| s.strip_prefix("FUN_"))
        .or_else(|| s.rsplit_once("Ram").map(|(_, h)| h))
        .or_else(|| s.rsplit_once("_0x").map(|(_, h)| h))?;
    let hex: String = hex.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() < 4 {
        return None;
    }
    u64::from_str_radix(&hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_the_emitter_s_naming_conventions() {
        assert_eq!(emitted_symbol_address("FUN_00010c20"), Some(0x10c20));
        assert_eq!(emitted_symbol_address("func_0x00010c20_"), Some(0x10c20));
        assert_eq!(emitted_symbol_address("_xRam000a71b1"), Some(0xa71b1));
        assert_eq!(emitted_symbol_address("iRam00083090"), Some(0x83090));
    }

    /// A name that does NOT encode an address must stay unresolved. Guessing one would silently
    /// relink a call to an invented target and score the result as agreement.
    #[test]
    fn a_name_without_an_address_is_not_guessed() {
        assert_eq!(emitted_symbol_address("_STK_"), None);
        assert_eq!(emitted_symbol_address("memcpy"), None);
        assert_eq!(emitted_symbol_address("FUN_12"), None);
    }
}
