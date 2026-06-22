//! `.sla` loader conformance — the first real slice of the SLEIGH runtime.
//!
//! Decodes a committed compiled `.sla` (6502, pinned to Ghidra 12.0.3 format v4)
//! and cross-checks it against facts read from Ghidra's own `sleigh_opt -y`
//! XML-debug serialization of the same spec:
//! - total element count (5228) — a whole-tree structural check that the
//!   PackedDecode reader traverses every record without desyncing;
//! - the `<sleigh>` header (version / endianness / alignment);
//! - the address-space table.

use mosura::sleigh::sla::{self, id};
use std::path::PathBuf;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sla/6502.sla")
}

/// Element count of `sleigh_opt -y 6502.slaspec` (number of opening XML tags).
const EXPECTED_ELEMENTS: usize = 5228;

#[test]
fn decodes_6502_sla() {
    let bytes = std::fs::read(fixture()).expect("read 6502.sla fixture");
    let root = sla::decode(&bytes).expect("decode .sla");

    // Whole-tree structural check vs the -y XML serialization.
    assert_eq!(root.count(), EXPECTED_ELEMENTS, "element count mismatch — packed reader desynced");

    // <sleigh version="4" bigendian="false" align="1" ...>
    assert_eq!(root.id, id::ELEM_SLEIGH);
    assert_eq!(root.attr_int(id::ATTRIB_VERSION), Some(4));
    assert_eq!(root.attr_bool(id::ATTRIB_BIGENDIAN), Some(false));
    assert_eq!(root.attr_int(id::ATTRIB_ALIGN), Some(1));

    // <spaces defaultspace="RAM"> with OTHER / unique / RAM / register
    let spaces = root.child(id::ELEM_SPACES).expect("<spaces> element");
    assert_eq!(spaces.attr_str(id::ATTRIB_DEFAULTSPACE), Some("RAM"));
    let names: Vec<&str> = spaces
        .children
        .iter()
        .filter_map(|c| c.attr_str(id::ATTRIB_NAME))
        .collect();
    assert_eq!(names, ["OTHER", "unique", "RAM", "register"]);
}
