//! Emission choices — the θ in `IR × θ → C`.
//!
//! A decompiler emits *one* rendering of a function, chosen to be readable. Recovering source that
//! a compiler maps back to the original bytes needs a different power: the ability to ask for a
//! **different rendering of the same IR**. The set of renderings is what this type names.
//!
//! ## Why this is not a place to hide bugs
//!
//! The danger of a knob on the printer is obvious: any byte mismatch can be "fixed" by adding one,
//! and the result is a decompiler that reproduces one binary and understands none. Three rules keep
//! an axis honest, and every axis added here has to pass all three:
//!
//! 1. **Both values are faithful renderings of the same recovered IR.** If one value is simply a
//!    truer claim about the program than the other, this is a *bug with a switch on it* and belongs
//!    wherever the recovery went wrong. The test is whether a correct decompiler could legitimately
//!    print either.
//! 2. **Acceptance is the byte verdict, never a similarity score.** A θ is kept because the function
//!    reassembles *exactly*; a θ that merely scores better is noise, and optimizing the instrument
//!    instead of the goal is the documented way this work fails.
//! 3. **The axis is justified by measured compiler behaviour**, with the probe that established it.
//!
//! [`ReturnWidth`] is the worked example of rule 1, and of how easily it is misjudged. Declaring the
//! return storage width rather than the value's width looks like papering over a type-recovery
//! defect — until you ask the reference decompiler, which declares `undefined1` for exactly the
//! function whose original writes all four bytes of `EAX`. Both are true statements: the *value* is
//! one byte and the *storage* is four. C forces a choice between them, and which one the original
//! compiler was given is not derivable from the IR. That is an axis.
//!
//! ## Separation of concerns
//!
//! - [`EmitChoices::default`] is exactly the reference decompiler's behaviour, so the port is
//!   unaffected by θ existing and nothing downstream needs to know about it.
//! - No axis knows which compiler it is for. The axes are properties of C; the mapping from an
//!   attributed divergence to the axis worth perturbing is compiler-specific and lives with the
//!   codegen model in [`crate::recompile`]. An `if target == watcom` in this file is the failure
//!   mode the separation exists to prevent.
//! - Axes are reachable **by name** ([`EmitChoices::axes`], [`EmitChoices::set`]). A search that
//!   enumerates them reflectively keeps working when an axis is added; one that names its axes in
//!   code must be edited every time, which is the difference between a search that grows and a
//!   table of hand-written arms.

use std::fmt;

/// Whether a function's return type is declared at the width of the **value** or of the
/// **storage** it travels in.
///
/// A function may compute one byte and return it in a four-byte register. The reference decompiler
/// prints the value's width — measured, it emits `undefined1` for WAR2's `FUN_000570cc`, whose
/// original is `XOR EAX,EAX ; MOV AL,[m] ; RET`. That is a true statement about the value, and it
/// is also the rendering under which the compiler emits only the `MOV AL`, dropping the `XOR` that
/// materializes the other three bytes. Declaring the storage width recovers the `XOR` and breaks
/// the functions that really do return a byte. Neither rule wins everywhere; the original's own
/// choice is not recoverable from the IR, so it is searched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnWidth {
    /// The width the return-value recovery found the function to produce
    /// (`Funcdata::output_storage_size`) — the current reference behaviour, and the default.
    Recovered,
    /// The returned Varnode's own width — what the reference decompiler prints, and the narrowest
    /// of the three. Under it the compiler materializes only the bytes the value occupies.
    Value,
    /// The full width of the calling convention's return storage entry — the widest. Under it the
    /// compiler materializes the whole register, recovering a zero-extension the original performs.
    Storage,
}

/// The choice vector.
///
/// Adding an axis is: a field, an entry in [`EmitChoices::AXES`], and arms in [`EmitChoices::get`]
/// and [`EmitChoices::set`]. The compile fails until all four exist, which is deliberate — an axis
/// the search cannot enumerate is an axis that will never be tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmitChoices {
    pub return_width: ReturnWidth,
}

impl Default for EmitChoices {
    fn default() -> Self {
        Self { return_width: ReturnWidth::Recovered }
    }
}

/// One axis: its name, and the values it accepts. The first value listed is the default.
#[derive(Debug, Clone, Copy)]
pub struct Axis {
    pub name: &'static str,
    pub values: &'static [&'static str],
    /// What this axis changes about the emitted C, for `--help` and for reports.
    pub doc: &'static str,
}

impl EmitChoices {
    /// Every axis this build knows about.
    pub const AXES: &'static [Axis] = &[Axis {
        name: "return-width",
        values: &["recovered", "value", "storage"],
        doc: "declare the return type at the width of the value, or of the convention's storage",
    }];

    /// Every axis, for a search that wants to enumerate rather than hardcode.
    pub fn axes() -> &'static [Axis] {
        Self::AXES
    }

    /// The value currently selected on `axis`, or `None` if there is no such axis.
    pub fn get(&self, axis: &str) -> Option<&'static str> {
        match axis {
            "return-width" => Some(match self.return_width {
                ReturnWidth::Recovered => "recovered",
                ReturnWidth::Value => "value",
                ReturnWidth::Storage => "storage",
            }),
            _ => None,
        }
    }

    /// Select `value` on `axis`. Returns an error naming what was wrong, so a bad choice on a
    /// command line fails loudly: a silently-ignored assignment makes a search report that an axis
    /// does not help when it was never applied.
    pub fn set(&mut self, axis: &str, value: &str) -> Result<(), ChoiceError> {
        match axis {
            "return-width" => {
                self.return_width = match value {
                    "recovered" => ReturnWidth::Recovered,
                    "value" => ReturnWidth::Value,
                    "storage" => ReturnWidth::Storage,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            _ => return Err(ChoiceError::Axis(axis.to_string())),
        }
        Ok(())
    }

    /// Parse an `axis=value` assignment, as a command line spells one.
    pub fn assign(&mut self, spec: &str) -> Result<(), ChoiceError> {
        let (axis, value) = spec.split_once('=').ok_or_else(|| ChoiceError::Syntax(spec.to_string()))?;
        self.set(axis.trim(), value.trim())
    }

    /// Parse a whole vector from a comma-separated `axis=value` list. `"default"` and the empty
    /// string both mean the reference rendering.
    pub fn parse(spec: &str) -> Result<Self, ChoiceError> {
        let mut c = Self::default();
        for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty() && *s != "default") {
            c.assign(part)?;
        }
        Ok(c)
    }

    /// The non-default axes, as `axis=value`. Empty for the default vector, so it reads as "the
    /// reference rendering" in a report rather than as a list of every axis.
    pub fn deviations(&self) -> Vec<String> {
        let d = Self::default();
        Self::AXES
            .iter()
            .filter_map(|a| {
                let (v, dv) = (self.get(a.name)?, d.get(a.name)?);
                (v != dv).then(|| format!("{}={}", a.name, v))
            })
            .collect()
    }

    /// A short name for this vector, usable as a directory or cache-key component.
    /// `"default"` for the reference rendering, else the deviations joined by `+`.
    pub fn tag(&self) -> String {
        let d = self.deviations();
        if d.is_empty() {
            "default".to_string()
        } else {
            d.join("+").replace('=', "-")
        }
    }

    /// Every vector obtained by moving exactly one axis off its current value — the neighbourhood a
    /// directed search steps through. Enumerated from [`Self::AXES`], so a new axis joins the
    /// search without the search being edited.
    pub fn neighbours(&self) -> Vec<Self> {
        let mut out = Vec::new();
        for a in Self::AXES {
            let cur = self.get(a.name);
            for v in a.values {
                if Some(*v) == cur {
                    continue;
                }
                let mut n = *self;
                if n.set(a.name, v).is_ok() {
                    out.push(n);
                }
            }
        }
        out
    }
}

/// A rendering of the whole vector, stable and order-independent: usable as a cache key.
impl fmt::Display for EmitChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for a in Self::AXES {
            if !first {
                f.write_str(",")?;
            }
            first = false;
            write!(f, "{}={}", a.name, self.get(a.name).unwrap_or("?"))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChoiceError {
    /// No axis by that name.
    Axis(String),
    /// The axis exists but does not take that value.
    Value { axis: String, value: String },
    /// Not an `axis=value` assignment.
    Syntax(String),
}

impl fmt::Display for ChoiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChoiceError::Axis(a) => {
                let names: Vec<&str> = EmitChoices::AXES.iter().map(|x| x.name).collect();
                write!(f, "no emission axis `{a}` (known: {})", names.join(", "))
            }
            ChoiceError::Value { axis, value } => {
                let vs = EmitChoices::AXES.iter().find(|x| x.name == axis).map(|x| x.values).unwrap_or(&[]);
                write!(f, "axis `{axis}` does not take `{value}` (accepts: {})", vs.join(", "))
            }
            ChoiceError::Syntax(s) => write!(f, "`{s}` is not an axis=value assignment"),
        }
    }
}

impl std::error::Error for ChoiceError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default vector is the reference rendering: every axis sits on the first value its table
    /// lists, so the table and the `Default` impl cannot drift apart unnoticed.
    #[test]
    fn default_selects_the_first_value_of_every_axis() {
        let d = EmitChoices::default();
        for a in EmitChoices::AXES {
            assert_eq!(d.get(a.name), Some(a.values[0]), "axis {}", a.name);
        }
        assert!(d.deviations().is_empty(), "the default vector deviates from nothing");
        assert_eq!(d.tag(), "default");
    }

    /// Every axis is reachable by name in both directions. A search enumerates `AXES` and calls
    /// `set`; an axis present in the table but missing from `set` would be silently unsearchable.
    #[test]
    fn every_listed_axis_round_trips_through_name_and_value() {
        for a in EmitChoices::AXES {
            for v in a.values {
                let mut c = EmitChoices::default();
                c.set(a.name, v).unwrap_or_else(|e| panic!("set {}={v}: {e}", a.name));
                assert_eq!(c.get(a.name), Some(*v));
            }
        }
    }

    /// The neighbourhood covers every off-current value of every axis, and nothing else — this is
    /// the step set of the search, so a gap here is a rendering that is never tried.
    #[test]
    fn neighbours_cover_every_other_value_of_every_axis() {
        let d = EmitChoices::default();
        let n = d.neighbours();
        let expected: usize = EmitChoices::AXES.iter().map(|a| a.values.len() - 1).sum();
        assert_eq!(n.len(), expected);
        for a in EmitChoices::AXES {
            for v in a.values.iter().filter(|v| **v != a.values[0]) {
                assert!(n.iter().any(|c| c.get(a.name) == Some(*v)), "{}={v} unreachable", a.name);
            }
        }
        assert!(!n.contains(&d), "a neighbour is never the vector itself");
    }

    /// A misspelled axis or value is an error, not a no-op. A silently-dropped choice would make a
    /// search conclude the axis does not help when it was never applied.
    #[test]
    fn unknown_axes_and_values_are_rejected() {
        let mut c = EmitChoices::default();
        assert!(matches!(c.set("no-such-axis", "x"), Err(ChoiceError::Axis(_))));
        assert!(matches!(c.set("return-width", "nonsense"), Err(ChoiceError::Value { .. })));
        assert!(matches!(c.assign("return-width"), Err(ChoiceError::Syntax(_))));
        assert_eq!(c, EmitChoices::default(), "a rejected assignment changes nothing");
    }

    /// The error names the alternatives, because the first thing anyone does with a rejected
    /// choice is ask what the accepted ones are.
    #[test]
    fn errors_name_the_alternatives() {
        let e = EmitChoices::default().set("return-width", "nope").unwrap_err().to_string();
        assert!(e.contains("recovered") && e.contains("value") && e.contains("storage"), "{e}");
        let e = EmitChoices::default().set("bogus", "x").unwrap_err().to_string();
        assert!(e.contains("return-width"), "{e}");
    }

    /// `Display` covers every axis, so it identifies a rendering completely — which is what makes
    /// it safe as a cache key for "the C this θ produces".
    #[test]
    fn display_names_every_axis() {
        let s = EmitChoices::default().to_string();
        for a in EmitChoices::AXES {
            assert!(s.contains(a.name), "{s} omits {}", a.name);
        }
    }

    /// A vector round-trips through the spelling a command line and a directory name use.
    #[test]
    fn a_vector_round_trips_through_its_written_forms() {
        let mut c = EmitChoices::default();
        c.assign("return-width=storage").unwrap();
        assert_eq!(c.return_width, ReturnWidth::Storage);
        assert_eq!(c.deviations(), vec!["return-width=storage"]);
        assert_eq!(c.tag(), "return-width-storage");
        assert_eq!(EmitChoices::parse("return-width=storage").unwrap(), c);
        assert_eq!(EmitChoices::parse("default").unwrap(), EmitChoices::default());
        assert_eq!(EmitChoices::parse("").unwrap(), EmitChoices::default());
    }
}
