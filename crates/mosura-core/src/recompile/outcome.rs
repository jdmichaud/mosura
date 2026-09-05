//! ONE verdict vocabulary for the recompile pipeline. The aligner's [`Verdict`] says how a
//! candidate compares with the original; the stages before it can fail to produce a candidate at
//! all, and the drivers used to spell those failures by hand (`COMPILE_FAIL`, `OBJ_ERROR`,
//! `EMIT_FAIL` in `recompile_check`, `DECOMPILE_FAIL` in the ground-truth oracle). This is the
//! type behind the `verdict` column of every verdict table: the strings are the ones the tables
//! have always carried, so old and new files read the same.

use super::align::Verdict;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A candidate object was produced, relinked and aligned: the aligner's verdict.
    Verified(Verdict),
    /// The toolchain produced no object for the translation unit.
    CompileFail,
    /// The object could not be loaded or the function not found in it.
    ObjError,
    /// No translation unit was emitted for the function.
    EmitFail,
    /// The decompiler produced no function at all.
    DecompileFail,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Verified(v) => v.as_str(),
            Outcome::CompileFail => "COMPILE_FAIL",
            Outcome::ObjError => "OBJ_ERROR",
            Outcome::EmitFail => "EMIT_FAIL",
            Outcome::DecompileFail => "DECOMPILE_FAIL",
        }
    }

    /// The inverse of [`Self::as_str`], for the tables written before this type existed.
    pub fn parse(s: &str) -> Option<Outcome> {
        Some(match s {
            "EXACT" => Outcome::Verified(Verdict::Exact),
            "SAME_CODE" => Outcome::Verified(Verdict::SameCode),
            "SAME_SHAPE" => Outcome::Verified(Verdict::SameShape),
            "MISMATCH" => Outcome::Verified(Verdict::Mismatch),
            "COMPILE_FAIL" => Outcome::CompileFail,
            "OBJ_ERROR" => Outcome::ObjError,
            "EMIT_FAIL" => Outcome::EmitFail,
            "DECOMPILE_FAIL" => Outcome::DecompileFail,
            _ => return None,
        })
    }

    /// No candidate reached the aligner (the row scores zero at its full weight).
    pub fn is_failure(self) -> bool {
        !matches!(self, Outcome::Verified(_))
    }

    /// Every outcome, in the order a census lists them.
    pub const ALL: [Outcome; 8] = [
        Outcome::Verified(Verdict::Exact),
        Outcome::Verified(Verdict::SameCode),
        Outcome::Verified(Verdict::SameShape),
        Outcome::Verified(Verdict::Mismatch),
        Outcome::CompileFail,
        Outcome::ObjError,
        Outcome::EmitFail,
        Outcome::DecompileFail,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_outcome_round_trips_through_its_string() {
        for o in Outcome::ALL {
            assert_eq!(Outcome::parse(o.as_str()), Some(o));
        }
        assert_eq!(Outcome::parse("RELOC_EXACT"), None, "the retired verdict is not one");
        assert!(Outcome::CompileFail.is_failure() && !Outcome::Verified(Verdict::Mismatch).is_failure());
    }
}
