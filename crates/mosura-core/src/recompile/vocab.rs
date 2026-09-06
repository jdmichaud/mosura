//! What a toolchain is *able* to emit — its instruction-selection vocabulary.
//!
//! Some functions in a real binary cannot be reproduced from C by the toolchain under test, and
//! no amount of decompiler work will change that: hand-written assembler, objects from a
//! third-party library built with another compiler, code from a compiler build nobody has. Left
//! in the denominator they make the score a measure of how much foreign code the binary
//! contains. Excluding them by hand makes the score a measure of the operator's optimism.
//!
//! This decides it from evidence. A compiler, faced with a given operation, picks one encoding of
//! it — Watcom 10.0a spells register-to-register `MOV` as `89 /r` and never as `8b /r`. So
//! collect, over everything that compiler has actually produced, the set of
//! (operation shape, encoding form) pairs it uses. An original function containing a pair the
//! compiler has never once emitted is evidence that this compiler did not build it.
//!
//! The vocabulary is a **lower bound**: a pair that is present is certainly reachable, a pair
//! that is absent may merely be unexercised. So the finding is reported with its evidence (which
//! instruction, how many) and grows more decisive as the corpus does — never as a silent verdict.
//!
//! This is how the `55 8b ec` regions of the subject binary were found: 84 functions whose frame setup uses
//! an encoding Watcom does not emit, in three contiguous address ranges rather than scattered —
//! the signature of linked-in objects from another toolchain, not of a decompiler defect.

use super::insn::NormInsn;
use std::collections::HashSet;

/// The set of (operation shape, encoding form) pairs a toolchain has been observed to emit.
#[derive(Debug, Default, Clone)]
pub struct Vocabulary {
    pairs: HashSet<(Vec<u8>, Vec<u8>)>,
    /// Forms alone, for the weaker question "does this compiler ever use this encoding at all".
    forms: HashSet<Vec<u8>>,
    pub instructions_seen: usize,
}

fn shape_key(i: &NormInsn) -> Vec<u8> {
    // A stable byte key for the erased-operand semantics. Rendering it is cheap and keeps the
    // vocabulary serializable without a hashing dependency.
    let mut k = Vec::new();
    for op in &i.shape {
        k.extend_from_slice(&op.opcode.to_le_bytes());
        k.push(op.out.is_some() as u8);
        k.push(op.ins.len() as u8);
        for a in op.out.iter().chain(op.ins.iter()) {
            k.extend_from_slice(format!("{a:?}").as_bytes());
            k.push(0x1f);
        }
        k.push(0x1e);
    }
    k
}

impl Vocabulary {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record everything in one compiled function.
    ///
    /// No-ops are skipped, and that is load-bearing rather than tidy. Padding and interior
    /// self-moves are not instruction *selections*: the compiler did not choose that spelling to
    /// express an operation, it needed some bytes. Because [`NormInsn::form`] masks the operand
    /// bits, a single `MOV EAX,EAX` would enter the `8b /r` form into the vocabulary and
    /// thereafter legitimise every register-to-register load-form move in the binary under test —
    /// one meaningless instruction silently switching the whole instrument off. A vocabulary is
    /// only useful while absence still means something.
    pub fn observe(&mut self, insns: &[NormInsn]) {
        for i in insns {
            if i.is_nop() {
                continue;
            }
            self.pairs.insert((shape_key(i), i.form.clone()));
            self.forms.insert(i.form.clone());
            self.instructions_seen += 1;
        }
    }

    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// True when this toolchain has been seen to spell this operation this way.
    pub fn contains(&self, i: &NormInsn) -> bool {
        self.pairs.contains(&(shape_key(i), i.form.clone()))
    }

    /// True when this toolchain has been seen to use this encoding for anything at all. Weaker
    /// than [`Self::contains`] and correspondingly harder to argue with.
    pub fn contains_form(&self, i: &NormInsn) -> bool {
        self.forms.contains(&i.form)
    }

    /// Instructions in `insns` whose (shape, form) pair this toolchain has never emitted.
    ///
    /// No-ops are excluded for the same reason [`Self::observe`] does not learn from them: an
    /// alignment `NOP` or an `XCHG BX,BX` says nothing about who selected the surrounding code,
    /// and flagging a function for its padding is a false accusation.
    pub fn foreign<'a>(&self, insns: &'a [NormInsn]) -> Vec<&'a NormInsn> {
        insns.iter().filter(|i| !i.is_nop() && !self.contains(i)).collect()
    }

    /// The subset of [`Self::foreign`] whose *encoding* is unknown to the toolchain entirely.
    /// This is the strong signal: the compiler does not use this byte form for anything.
    pub fn foreign_forms<'a>(&self, insns: &'a [NormInsn]) -> Vec<&'a NormInsn> {
        insns.iter().filter(|i| !i.is_nop() && !self.contains_form(i)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recompile::insn::{NoReloc, normalize};

    fn lift(hex: &str) -> Vec<NormInsn> {
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        normalize("x86:LE:32:default", &bytes, 0x1000, &NoReloc).expect("language tables")
    }

    /// The case this exists for: a vocabulary built from code that spells `MOV EBP,ESP` as
    /// `89 e5` must reject the `8b ec` spelling of the same operation — while still accepting
    /// `8b` used the way that compiler does use it, as a load from memory. Rejecting the whole
    /// opcode would flag most of the binary and mean nothing.
    #[test]
    fn an_unused_spelling_of_a_used_operation_is_foreign() {
        let mut v = Vocabulary::new();
        v.observe(&lift("5589e58b45085dc3")); // push ebp; mov ebp,esp (89 e5); mov eax,[ebp+8]; pop ebp; ret
        assert!(v.contains(&lift("89e5")[0]), "the observed spelling must be known");
        assert!(v.contains(&lift("8b4508")[0]), "the observed load must be known");
        assert!(!v.contains(&lift("8bec")[0]), "the unobserved spelling must be foreign");
        assert_eq!(v.foreign(&lift("8bec")).len(), 1);
    }

    /// Different registers are the same vocabulary entry: the vocabulary is about selection, not
    /// allocation. Otherwise every function would look foreign for using ESI where the corpus
    /// used EDI.
    #[test]
    fn allocation_is_not_part_of_the_vocabulary() {
        let mut v = Vocabulary::new();
        v.observe(&lift("89e5")); // mov ebp,esp
        assert!(v.contains(&lift("89c3")[0]), "mov ebx,eax is the same selection");
    }

    /// A no-op must not teach the vocabulary an encoding form. `form` masks the operand bits, so
    /// learning `8b c0` (`MOV EAX,EAX`, a self-move some tunings emit as interior padding) would
    /// enter the whole `8b /r` form and thereafter legitimise every load-form register move —
    /// one meaningless instruction blinding the instrument for the rest of the binary.
    #[test]
    fn a_noop_does_not_teach_the_vocabulary_a_form() {
        let nop = lift("8bc0"); // mov eax,eax — a self-move, semantically a no-op
        assert!(nop[0].is_nop(), "the fixture must actually be a no-op");
        let mut v = Vocabulary::new();
        v.observe(&lift("89e5")); // the compiler's real spelling of a register move
        v.observe(&nop);
        assert_eq!(v.instructions_seen, 1, "the no-op is not counted as an observation");
        assert!(!v.contains(&lift("8bec")[0]), "the no-op must not legitimise the 8b spelling");
        assert_eq!(v.foreign(&lift("8bec")).len(), 1, "the foreign spelling is still caught");
    }

    /// The mirror: padding in the binary under test must not make a function look foreign. A
    /// function is accused for the instructions someone selected, not for its alignment bytes.
    #[test]
    fn padding_in_the_scanned_code_is_not_evidence() {
        let mut v = Vocabulary::new();
        v.observe(&lift("89e5"));
        let padded = lift("89e590"); // the known move, then a NOP the vocabulary has never seen
        assert!(padded.iter().any(|i| i.is_nop()), "the fixture must contain a no-op");
        assert!(v.foreign(&padded).is_empty(), "padding is not a foreign selection");
        assert!(v.foreign_forms(&padded).is_empty(), "nor an unknown form worth reporting");
    }
}
