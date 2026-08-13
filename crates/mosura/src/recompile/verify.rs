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

/// A checked function.
#[derive(Debug, Clone)]
pub struct Checked {
    pub diff: FnDiff,
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
    let candidate = trim_padding(
        normalize(lang, &relinked.relinked_bytes(), subject.va, &relinked).map_err(VerifyError::Language)?,
    );
    let diff = compare(&original, &candidate);
    Ok(Checked { diff, original, candidate, relinked })
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
