//! Stage 2a gate (`docs/fid-port-plan.md` §5): unpacking Ghidra's packed `.fidb`.
//!
//! The strong assertion here is an **independent oracle**: Ghidra's own module build unpacks
//! the same `.fidb` into `.fidbf` (`FunctionID/build.gradle:46`), so when a Ghidra checkout is
//! present our unpacked bytes must equal that file **exactly**. No hand-derived expectation is
//! involved — Ghidra's unpacker is the reference.
//!
//! Without a checkout the structural checks still run against the committed databases: header
//! fields, the declared length, and the `LocalBufferFile` magic that must open the payload.

use std::path::PathBuf;

use mosura::analysis::fid::packed::{self, ITEM_MAGIC_NUMBER, ITEM_MAGIC_NUMBER_POS};
use mosura::paths;

/// `LocalBufferFile.MAGIC_NUMBER` (`:36`) — what a correctly unpacked payload must start with.
const BUFFER_FILE_MAGIC: u64 = 0x2f30_312c_3429_2c2a;

/// The database used for the detailed checks: the smallest of the ten, to keep this fast.
const SAMPLE: &str = "vs2017_x64.fidb";

fn read_db(name: &str) -> Option<Vec<u8>> {
    let path = paths::fid_db_dir().join(name);
    std::fs::read(&path).ok()
}

/// The `.fidbf` Ghidra's own build produced from the same `.fidb`, if a checkout is present.
fn ghidra_unpacked(name: &str) -> Option<Vec<u8>> {
    let stem = name.strip_suffix(".fidb")?;
    let path: PathBuf = paths::ghidra_src()
        .join("Ghidra/Features/FunctionID/build/data")
        .join(format!("{stem}.fidbf"));
    std::fs::read(&path).ok()
}

#[test]
fn every_shipped_database_is_a_packed_item() {
    let dir = paths::fid_db_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        panic!("FID database directory missing: {}", dir.display());
    };

    let mut seen = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("fidb") {
            continue;
        }
        let data = std::fs::read(&path).expect("readable");
        let name = path.file_name().unwrap().to_string_lossy().to_string();

        assert!(packed::is_packed_file(&data), "{name} is not a packed item");

        let header = packed::parse_header(&data)
            .unwrap_or_else(|e| panic!("{name}: header parse failed: {e}"));
        assert_eq!(header.item_name, "Function ID Database", "{name} item name");
        assert_eq!(header.content_type, "Function ID Database", "{name} content type");
        assert!(header.length > 0, "{name} declares a zero-length payload");
        // The unpacked form is always larger than the compressed one — a sanity check that
        // the length field was read from the right offset and in the right byte order.
        assert!(
            header.length > data.len() as u64,
            "{name}: declared unpacked length {} should exceed the packed size {}",
            header.length,
            data.len()
        );
        seen += 1;
    }

    assert_eq!(seen, 10, "the ten shipped Visual Studio databases");
}

/// The magic sits at `ItemSerializer.MAGIC_NUMBER_POS`, i.e. straight after the
/// `ObjectOutputStream` stream header and the block-data marker.
#[test]
fn magic_is_at_the_documented_offset() {
    let Some(data) = read_db(SAMPLE) else { return };

    let at = &data[ITEM_MAGIC_NUMBER_POS..ITEM_MAGIC_NUMBER_POS + 8];
    assert_eq!(u64::from_be_bytes(at.try_into().unwrap()), ITEM_MAGIC_NUMBER);

    // ObjectOutputStream framing, byte for byte.
    assert_eq!(&data[0..4], &[0xac, 0xed, 0x00, 0x05], "STREAM_MAGIC + STREAM_VERSION");
    assert_eq!(data[4], 0x77, "TC_BLOCKDATA");
    assert_eq!(
        data[5], 0x44,
        "68 bytes = 8 + 4 + (2+20) + (2+20) + 4 + 8, tied to the two string lengths"
    );

    // ...and a non-packed buffer must be rejected rather than mis-parsed.
    assert!(!packed::is_packed_file(&[0u8; 64]));
    assert!(packed::parse_header(&[0u8; 64]).is_err());
}

/// Unpacking yields exactly the declared number of bytes, and those bytes open with the raw
/// `LocalBufferFile` magic — the payload is the buffer file, not another wrapper.
#[test]
fn unpacked_payload_is_a_local_buffer_file() {
    let Some(data) = read_db(SAMPLE) else { return };
    let header = packed::parse_header(&data).expect("header");
    let out = packed::unpack(&data).expect("unpack");

    assert_eq!(out.len() as u64, header.length, "inflated length matches the header");
    assert_eq!(
        u64::from_be_bytes(out[0..8].try_into().unwrap()),
        BUFFER_FILE_MAGIC,
        "payload begins with LocalBufferFile.MAGIC_NUMBER"
    );
    // LocalBufferFile.readHeader (`:437-465`): magic(8) fileId(8) formatVersion(4)
    // blockSize(4) firstFreeBufferIndex(4) parameterCount(4) — all big-endian.
    assert_eq!(u32::from_be_bytes(out[16..20].try_into().unwrap()), 1, "header format version");
    assert_eq!(
        u32::from_be_bytes(out[20..24].try_into().unwrap()),
        0x4000,
        "16 KiB block size"
    );
    assert_eq!(
        out.len() % 0x4000,
        0,
        "the file is a whole number of blocks (readHeader rejects otherwise)"
    );
}

/// **The independent oracle.** Ghidra's own build unpacked these; our bytes must match its
/// bytes exactly. Skips when no Ghidra checkout is available.
#[test]
fn unpacked_bytes_match_ghidras_own_unpacker() {
    let Some(data) = read_db(SAMPLE) else { return };
    let Some(expected) = ghidra_unpacked(SAMPLE) else {
        eprintln!("skip: no Ghidra checkout with build/data/*.fidbf");
        return;
    };

    let out = packed::unpack(&data).expect("unpack");
    assert_eq!(out.len(), expected.len(), "unpacked length matches Ghidra's .fidbf");
    assert!(out == expected, "unpacked bytes are byte-identical to Ghidra's .fidbf");
}

/// Corruption is reported, not silently accepted. Flipping a byte inside the deflate stream
/// must fail the inflate or the length check rather than yield a plausible-looking buffer.
#[test]
fn corrupt_payload_is_rejected() {
    let Some(mut data) = read_db(SAMPLE) else { return };
    let header = packed::parse_header(&data).expect("header");

    // Well past the ZIP local header, inside the compressed data.
    let at = header.payload_offset + 512;
    data[at] ^= 0xff;

    assert!(packed::unpack(&data).is_err(), "a corrupted deflate stream must be rejected");
}
