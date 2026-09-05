//! Bounds-checked little-endian scalar reads, shared by the container loaders.
//!
//! Lifted out of `le.rs`, which had them private, when `x32.rs` needed the same three. Nothing
//! here is container-specific; every reader returns `None` rather than panicking on a short
//! buffer, because a loader's job on a truncated file is to refuse it.

/// Little-endian `u16` at `off`, or `None` if `data` is too short.
pub fn u16le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// Little-endian `u32` at `off`, or `None` if `data` is too short.
pub fn u32le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// A single byte at `off`, or `None`.
pub fn u8at(data: &[u8], off: usize) -> Option<u8> {
    data.get(off).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_and_refuses_short_input() {
        let d = [0x34, 0x12, 0x78, 0x56, 0x9a];
        assert_eq!(u16le(&d, 0), Some(0x1234));
        assert_eq!(u32le(&d, 0), Some(0x5678_1234));
        assert_eq!(u8at(&d, 4), Some(0x9a));
        // one past the end, in each width
        assert_eq!(u16le(&d, 4), None);
        assert_eq!(u32le(&d, 2), None);
        assert_eq!(u8at(&d, 5), None);
        assert_eq!(u16le(&[], 0), None);
    }
}
