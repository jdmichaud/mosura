//! Content keys of the session store (design §5.4): `blake3(len‖stage_fp ‖ len‖op ‖ (len‖input)* ‖
//! len‖tag ‖ len‖annotations_digest)`, every field length-prefixed so the concatenation is
//! unambiguous; the lowercase hex is the directory name. Invalidation is by key, never by mtime.

use crate::fingerprint::{fp, hex, Stage};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key(pub [u8; 32]);

impl Key {
    pub fn hex(&self) -> String {
        hex(&self.0)
    }
    pub fn from_hex(s: &str) -> Option<Key> {
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(Key(out))
    }
}

fn feed(h: &mut blake3::Hasher, field: &[u8]) {
    h.update(&(field.len() as u32).to_le_bytes());
    h.update(field);
}

/// The key of a table set: the stage it depends on, the operation, its inputs (digests of the
/// input file, or the program key ‖ entry), the Result-options tag, and the annotations digest.
pub fn key(stage: Stage, op: &str, inputs: &[&[u8]], tag: &str, annotations: &[u8; 32]) -> Key {
    let mut h = blake3::Hasher::new();
    feed(&mut h, &fp(stage));
    feed(&mut h, op.as_bytes());
    for i in inputs {
        feed(&mut h, i);
    }
    feed(&mut h, tag.as_bytes());
    feed(&mut h, annotations);
    Key(*h.finalize().as_bytes())
}

/// The digest of an input file's bytes (`inputs/<digest>`).
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// The digest of an empty annotations table — what every P1 key carries (no annotations yet).
pub fn no_annotations() -> [u8; 32] {
    digest(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same inputs → same key; the stage, the op, an input, the tag, the input ORDER and the
    /// annotations each change it; length-prefixing keeps `ab‖c` apart from `a‖bc`; hex round-trips.
    #[test]
    fn keys_depend_on_every_field_and_only_on_them() {
        let a = digest(b"input a");
        let b = digest(b"input b");
        let k = key(Stage::Analysis, "program.analyze", &[&a], "default", &no_annotations());
        assert_eq!(k, key(Stage::Analysis, "program.analyze", &[&a], "default", &no_annotations()));
        assert_eq!(k, key(Stage::Decompile, "program.analyze", &[&a], "default", &no_annotations()), "analysis and decompile share a fingerprint in P1");
        assert_ne!(k, key(Stage::Emit, "program.analyze", &[&a], "default", &no_annotations()));
        assert_ne!(k, key(Stage::Analysis, "program.load", &[&a], "default", &no_annotations()));
        assert_ne!(k, key(Stage::Analysis, "program.analyze", &[&b], "default", &no_annotations()));
        assert_ne!(k, key(Stage::Analysis, "program.analyze", &[&a], "knobs.off=frame-agg", &no_annotations()));
        assert_ne!(k, key(Stage::Analysis, "program.analyze", &[&a], "default", &digest(b"x")));
        assert_ne!(key(Stage::Analysis, "op", &[&a, &b], "t", &no_annotations()), key(Stage::Analysis, "op", &[&b, &a], "t", &no_annotations()));
        assert_ne!(key(Stage::Analysis, "op", &[b"ab", b"c"], "t", &no_annotations()), key(Stage::Analysis, "op", &[b"a", b"bc"], "t", &no_annotations()));
        assert_eq!(k.hex().len(), 64);
        assert_eq!(Key::from_hex(&k.hex()), Some(k));
        assert_eq!(Key::from_hex("zz"), None);
    }
}
