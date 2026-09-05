//! The table framework end to end: the builder writes every column type, the accessors read it
//! back, the `.tbl` image re-opens owned and mapped with identical cells, a corrupt or foreign or
//! differently-versioned file is refused (D6), a sorted key column binary-searches.

use mosura_api::schema::{ColHint, ColType, Column, Schema};
use mosura_api::table::builder::TableBuilder;
use mosura_api::{tbl, Error, Table};

static EVERY: Schema = Schema {
    name: "test.every",
    version: 3,
    columns: &[
        Column::hex("addr", ColType::U64),
        Column::new("small", ColType::U8),
        Column::new("word", ColType::U16),
        Column::new("dword", ColType::U32),
        Column::new("signed", ColType::I64),
        Column::new("real", ColType::F64),
        Column::new("flag", ColType::Bool),
        Column::new("name", ColType::Str),
        Column::new("raw", ColType::Bytes),
        Column::new("ids", ColType::ListU32),
        Column::new("vas", ColType::ListU64),
    ],
};

fn every() -> Table {
    let mut b = TableBuilder::new(&EVERY);
    b.row().u64(0x1000).u8(7).u16(0xbeef).u32(0xdead_beef).i64(-42).f64(2.5).bool(true).str("alpha").bytes(&[1, 2, 3]).list_u32(&[1, 2]).list_u64(&[u64::MAX, 0]);
    b.row().u64(0x2000).u8(0).u16(0).u32(0).i64(i64::MIN).f64(-0.0).bool(false).str("").bytes(&[]).list_u32(&[]).list_u64(&[7]);
    b.row().u64(0x3000).u8(255).u16(1).u32(2).i64(3).f64(f64::INFINITY).bool(true).str("alpha").bytes(&[1, 2, 3]).list_u32(&[9, 8, 7]).list_u64(&[]);
    b.finish(true)
}

fn assert_same_cells(a: &Table, b: &Table) {
    assert_eq!(a.rows(), b.rows());
    assert_eq!(a.ncols(), b.ncols());
    for r in 0..a.rows() {
        assert_eq!(a.u64(r, 0).unwrap(), b.u64(r, 0).unwrap());
        assert_eq!(a.u64(r, 1).unwrap(), b.u64(r, 1).unwrap());
        assert_eq!(a.u64(r, 2).unwrap(), b.u64(r, 2).unwrap());
        assert_eq!(a.u64(r, 3).unwrap(), b.u64(r, 3).unwrap());
        assert_eq!(a.i64(r, 4).unwrap(), b.i64(r, 4).unwrap());
        assert_eq!(a.f64(r, 5).unwrap().to_bits(), b.f64(r, 5).unwrap().to_bits());
        assert_eq!(a.bool(r, 6).unwrap(), b.bool(r, 6).unwrap());
        assert_eq!(a.str(r, 7).unwrap(), b.str(r, 7).unwrap());
        assert_eq!(a.bytes(r, 8).unwrap(), b.bytes(r, 8).unwrap());
        assert_eq!(a.list_u32(r, 9).unwrap().collect::<Vec<_>>(), b.list_u32(r, 9).unwrap().collect::<Vec<_>>());
        assert_eq!(a.list_u64(r, 10).unwrap().collect::<Vec<_>>(), b.list_u64(r, 10).unwrap().collect::<Vec<_>>());
    }
    assert_eq!(a.digest(), b.digest());
    assert_eq!(a.sorted(), b.sorted());
}

/// Every column type writes and reads back; the type check refuses the wrong accessor; the row
/// layout is the natural one padded to 8; identical strings and byte runs share one blob range.
#[test]
fn builder_accessors_every_type() {
    let t = every();
    assert_eq!(t.rows(), 3);
    assert_eq!(t.u64(0, 0).unwrap(), 0x1000);
    assert_eq!(t.u64(0, 1).unwrap(), 7);
    assert_eq!(t.u64(0, 2).unwrap(), 0xbeef);
    assert_eq!(t.u64(0, 3).unwrap(), 0xdead_beef);
    assert_eq!(t.i64(0, 4).unwrap(), -42);
    assert_eq!(t.f64(0, 5).unwrap(), 2.5);
    assert!(t.bool(0, 6).unwrap() && !t.bool(1, 6).unwrap());
    assert_eq!(t.str(0, 7).unwrap(), "alpha");
    assert_eq!(t.str(1, 7).unwrap(), "");
    assert_eq!(t.bytes(0, 8).unwrap(), &[1, 2, 3]);
    assert_eq!(t.list_u32(2, 9).unwrap().collect::<Vec<_>>(), vec![9, 8, 7]);
    assert_eq!(t.list_u64(0, 10).unwrap().collect::<Vec<_>>(), vec![u64::MAX, 0]);
    assert_eq!(t.list_raw(2, 9).unwrap().1, 3);
    assert_eq!(t.i64(1, 4).unwrap(), i64::MIN);
    assert!(t.f64(2, 5).unwrap().is_infinite());
    assert!(matches!(t.i64(0, 0), Err(Error::InvalidArg(_))), "a u64 column is not an i64");
    assert!(matches!(t.str(0, 0), Err(Error::InvalidArg(_))));
    assert!(matches!(t.u64(3, 0), Err(Error::NotFound(_))), "row past the end");
    assert!(matches!(t.u64(0, 11), Err(Error::NotFound(_))), "column past the end");
    assert_eq!(t.col("name"), Some(7));
    assert_eq!(t.col("nope"), None);
    assert_eq!(t.col_hint(0), ColHint::Hex);
    // layout: u64@0 u8@8 u16@10 u32@12 i64@16 f64@24 bool@32 str@36 bytes@44 list@52 list@60 → 68, padded to 72
    assert_eq!(t.row_size(), 72);
    let (col, stride) = t.column(3).unwrap();
    assert_eq!(stride, 72);
    assert_eq!(u32::from_le_bytes(col[0..4].try_into().unwrap()), 0xdead_beef);
    assert_eq!(u32::from_le_bytes(col[72..76].try_into().unwrap()), 0);
    assert!(matches!(t.column(7), Err(Error::InvalidArg(_))), "no strided view of a variable column");
    // blob dedup: "alpha" and [1,2,3] appear once each; the empty string shares the empty run
    let image = tbl::write(&t);
    let blob_len = u64::from_le_bytes(image[56..64].try_into().unwrap());
    assert_eq!(blob_len, 5 + 3 + 8 + 16 + 8 + 12, "alpha, [1,2,3], list_u32 [1,2], list_u64 [MAX,0], list_u64 [7], list_u32 [9,8,7] — each once");
}

#[test]
fn empty_table() {
    let t = TableBuilder::new(&EVERY).finish(true);
    assert_eq!(t.rows(), 0);
    assert_eq!(t.find(0, 1), None);
    let again = tbl::open_owned(tbl::write(&t), Some(&EVERY), true).unwrap();
    assert_eq!(again.rows(), 0);
    assert_eq!(again.column(0).unwrap().0.len(), 0);
}

/// The image re-opens with identical cells, owned and mapped, digest verified.
#[test]
fn write_then_open_owned_and_mapped_equal_cells() {
    let t = every();
    let image = tbl::write(&t);
    assert_eq!(&image[0..8], tbl::MAGIC);
    let owned = tbl::open_owned(image.clone(), Some(&EVERY), true).unwrap();
    assert_same_cells(&t, &owned);
    let dir = std::env::temp_dir().join(format!("mosura-api-tbl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("every.tbl");
    std::fs::write(&path, &image).unwrap();
    let mapped = tbl::open_mapped(&path, Some(&EVERY), true).unwrap();
    assert_same_cells(&t, &mapped);
    assert_eq!(mapped.find(0, 0x2000), Some(1));
    // an unknown schema name is served render-only with the file's own schema
    let unknown = tbl::open_owned(image.clone(), None, true).unwrap();
    assert_eq!(unknown.schema().name(), "test.every");
    assert_eq!(unknown.str(0, 7).unwrap(), "alpha");
    assert_eq!(tbl::write(&unknown), image, "re-serializing an opened image reproduces it");
    let _ = std::fs::remove_dir_all(&dir);
}

/// D6: a flipped byte, a foreign magic, another schema version or another column set are refused.
#[test]
fn corrupt_foreign_or_other_version_refused() {
    let t = every();
    let image = tbl::write(&t);
    let mut flipped = image.clone();
    let rows_off = u64::from_le_bytes(image[40..48].try_into().unwrap()) as usize;
    flipped[rows_off + 1] ^= 0x01;
    assert!(matches!(tbl::open_owned(flipped.clone(), Some(&EVERY), true), Err(Error::Format(_))), "digest mismatch");
    assert!(tbl::open_owned(flipped, Some(&EVERY), false).is_ok(), "verify = false trusts the bytes");
    let mut foreign = image.clone();
    foreign[7] = b'2';
    assert!(matches!(tbl::open_owned(foreign, Some(&EVERY), true), Err(Error::Version { .. })));
    static OTHER: Schema = Schema { name: "test.every", version: 4, columns: EVERY.columns };
    assert!(matches!(tbl::open_owned(image.clone(), Some(&OTHER), true), Err(Error::Version { .. })), "another version of the same name");
    static NARROW: Schema = Schema { name: "test.every", version: 3, columns: &[Column::hex("addr", ColType::U64)] };
    assert!(matches!(tbl::open_owned(image.clone(), Some(&NARROW), true), Err(Error::Version { .. })), "another column set");
    assert!(matches!(tbl::open_owned(image[..40].to_vec(), Some(&EVERY), true), Err(Error::Format(_))), "truncated");
}

/// `find`: binary search on a sorted key column, linear otherwise, absent keys → None.
#[test]
fn sorted_find() {
    static KEYS: Schema = Schema { name: "test.keys", version: 1, columns: &[Column::hex("va", ColType::U64), Column::new("n", ColType::U32)] };
    let mut b = TableBuilder::new(&KEYS);
    for (i, va) in [0x10u64, 0x20, 0x30, 0x35, 0x100, 0x1000].iter().enumerate() {
        b.row().u64(*va).u32(i as u32);
    }
    let t = b.finish(true);
    for (i, va) in [0x10u64, 0x20, 0x30, 0x35, 0x100, 0x1000].iter().enumerate() {
        assert_eq!(t.find(0, *va), Some(i as u64));
    }
    assert_eq!(t.find(0, 0x36), None);
    assert_eq!(t.find(0, 0), None);
    assert_eq!(t.find(1, 3), Some(3), "a linear scan on another column");
    let mut u = TableBuilder::new(&KEYS);
    u.row().u64(0x30).u32(0);
    u.row().u64(0x10).u32(1);
    let unsorted = u.finish(false);
    assert_eq!(unsorted.find(0, 0x10), Some(1), "linear when unsorted");
}

/// A million rows write and map back (the size class of a whole-program listing).
#[test]
#[ignore = "size smoke: ~100 MB of temp file; run at plan closure"]
fn million_rows_smoke() {
    static KEYS: Schema = Schema { name: "test.keys", version: 1, columns: &[Column::hex("va", ColType::U64), Column::new("n", ColType::U32)] };
    let mut b = TableBuilder::new(&KEYS);
    for i in 0..1_000_000u64 {
        b.row().u64(i * 4).u32(i as u32);
    }
    let t = b.finish(true);
    let dir = std::env::temp_dir().join(format!("mosura-api-tbl-big-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("big.tbl");
    std::fs::write(&path, tbl::write(&t)).unwrap();
    let m = tbl::open_mapped(&path, Some(&KEYS), true).unwrap();
    assert_eq!(m.rows(), 1_000_000);
    assert_eq!(m.find(0, 999_999 * 4), Some(999_999));
    let _ = std::fs::remove_dir_all(&dir);
}
