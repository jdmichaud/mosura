//! Port of Ghidra's `StringManager` (`stringmanage.cc`) — the test that decides whether the bytes
//! at an address look like a string, so a pointer to them can be rendered as a string constant
//! rather than a number.
//!
//! Only the `isString` path is ported, which is the whole of what `RulePtrsubCharConstant`
//! (ruleaction.cc:7354) needs: read image bytes until a null terminator, then verify the encoding
//! is legal. Ghidra's caching (`stringMap`), truncation reporting and the printable-string
//! extraction used by the emitter are not needed for that test and are not here.

use super::funcdata::Funcdata;

/// Ghidra `StringManagerUnicode`'s constructed maximum (`architecture.cc`, 2048 by default): how
/// far the search for a terminator runs before giving up.
const MAXIMUM_CHARS: usize = 2048;

/// Ghidra `StringManager::getCodepoint` (stringmanage.cc:346): decode one character, returning the
/// codepoint and how many bytes it consumed, or `None` for an illegal encoding.
///
/// `charsize` is 1 for UTF-8, 2 for UTF-16, 4 for UTF-32. mosura loads only little-endian targets,
/// so Ghidra's big-endian branches for the wide encodings are folded to the little-endian ones.
fn get_codepoint(buf: &[u8], charsize: usize) -> Option<(i64, usize)> {
    let (codepoint, sk): (i64, usize) = match charsize {
        2 => {
            // UTF-16, with the surrogate pair rules that give this encoding its self-check.
            if buf.len() < 2 {
                return None;
            }
            let mut cp = u16::from_le_bytes([buf[0], buf[1]]) as i64;
            let mut sk = 2;
            if (0xD800..=0xDBFF).contains(&cp) {
                if buf.len() < 4 {
                    return None;
                }
                let trail = u16::from_le_bytes([buf[2], buf[3]]) as i64;
                sk += 2;
                if !(0xDC00..=0xDFFF).contains(&trail) {
                    return None; // bad trail
                }
                cp = (cp << 10) + trail + (0x10000 - (0xD800 << 10) - 0xDC00);
            } else if (0xDC00..=0xDFFF).contains(&cp) {
                return None; // trail before high
            }
            (cp, sk)
        }
        1 => {
            // UTF-8. The continuation-byte checks are what make this test worth anything on
            // 1-byte data: they reject most non-text bytes.
            let val = *buf.first()? as i64;
            if val & 0x80 == 0 {
                (val, 1)
            } else if val & 0xe0 == 0xc0 {
                let v2 = *buf.get(1)? as i64;
                if v2 & 0xc0 != 0x80 {
                    return None;
                }
                (((val & 0x1f) << 6) | (v2 & 0x3f), 2)
            } else if val & 0xf0 == 0xe0 {
                let (v2, v3) = (*buf.get(1)? as i64, *buf.get(2)? as i64);
                if v2 & 0xc0 != 0x80 || v3 & 0xc0 != 0x80 {
                    return None;
                }
                (((val & 0xf) << 12) | ((v2 & 0x3f) << 6) | (v3 & 0x3f), 3)
            } else if val & 0xf8 == 0xf0 {
                let (v2, v3, v4) =
                    (*buf.get(1)? as i64, *buf.get(2)? as i64, *buf.get(3)? as i64);
                if v2 & 0xc0 != 0x80 || v3 & 0xc0 != 0x80 || v4 & 0xc0 != 0x80 {
                    return None;
                }
                (((val & 7) << 18) | ((v2 & 0x3f) << 12) | ((v3 & 0x3f) << 6) | (v4 & 0x3f), 4)
            } else {
                return None;
            }
        }
        4 => {
            if buf.len() < 4 {
                return None;
            }
            (u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as i64, 4)
        }
        _ => return None,
    };
    if codepoint >= 0xd800 {
        if codepoint > 0x10ffff {
            return None; // bigger than the maximum codepoint
        }
        if codepoint <= 0xdfff {
            return None; // reserved for surrogates
        }
    }
    Some((codepoint, sk))
}

/// Ghidra `StringManager::checkCharacters` (stringmanage.cc:324): the buffer holds a bounded set of
/// valid unicode. Returns the character count, or `None` for an invalid encoding.
fn check_characters(buf: &[u8], charsize: usize) -> Option<usize> {
    let mut i = 0;
    let mut count = 0;
    while i < buf.len() {
        let (codepoint, skip) = get_codepoint(&buf[i..], charsize)?;
        if codepoint == 0 {
            break;
        }
        count += 1;
        i += skip;
    }
    Some(count)
}

/// Ghidra `StringManager::hasCharTerminator` (stringmanage.cc:391).
fn has_char_terminator(buf: &[u8], charsize: usize) -> bool {
    buf.chunks(charsize).any(|c| c.len() == charsize && c.iter().all(|&b| b == 0))
}

/// Ghidra `StringManager::isString` (stringmanage.cc:168) → `StringManagerUnicode::getStringData`
/// (stringmanage.cc:427): do the bytes at `addr` form a string of `charsize`-byte characters?
///
/// Ghidra reads the image 32 bytes at a time until it finds a terminator or hits `maximumChars`,
/// then validates the whole buffer's encoding; a read failure or a missing terminator answers "not
/// a string". This reproduces that, reading through [`Funcdata::read_image`].
///
/// An empty string (a terminator at offset 0) is NOT a string here, matching Ghidra: `getStringData`
/// returns an empty byte vector, and `isString` tests `!buffer.empty()`.
pub fn is_string(data: &Funcdata, addr: u64, charsize: usize) -> bool {
    if charsize == 0 {
        return false;
    }
    let mut buffer: Vec<u8> = Vec::new();
    let mut found_terminator = false;
    while !found_terminator {
        let amount = 32.min(MAXIMUM_CHARS.saturating_sub(buffer.len()));
        if amount == 0 {
            return false; // could not find a terminator
        }
        let base = addr + buffer.len() as u64;
        for i in 0..amount {
            match data.read_image(base + i as u64, 1) {
                Some(b) => buffer.push(b as u8),
                None => return false, // Ghidra's DataUnavailError
            }
        }
        found_terminator = has_char_terminator(&buffer[buffer.len() - amount..], charsize);
    }
    match check_characters(&buffer, charsize) {
        Some(n) => n > 0,
        None => false, // invalid encoding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::{Address, SpaceManager};

    fn fd_with(bytes: &[u8], at: u64) -> Funcdata {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        f.image.push((at, bytes.to_vec()));
        f
    }

    #[test]
    fn ascii_with_terminator_is_a_string() {
        let mut bytes = b"hello world".to_vec();
        bytes.push(0);
        bytes.resize(64, 0);
        let f = fd_with(&bytes, 0x1000);
        assert!(is_string(&f, 0x1000, 1));
    }

    #[test]
    fn invalid_utf8_is_not_a_string() {
        // 0x80 is a bare continuation byte — not a legal UTF-8 lead, so checkCharacters rejects.
        let mut bytes = vec![0x80, 0x41, 0x42, 0x00];
        bytes.resize(64, 0);
        let f = fd_with(&bytes, 0x1000);
        assert!(!is_string(&f, 0x1000, 1));
    }

    #[test]
    fn empty_string_is_not_a_string() {
        // A terminator at offset 0: Ghidra's getStringData returns an empty buffer and isString
        // tests !buffer.empty(), so this answers false.
        let f = fd_with(&vec![0u8; 64], 0x1000);
        assert!(!is_string(&f, 0x1000, 1));
    }

    #[test]
    fn unreadable_memory_is_not_a_string() {
        // Ghidra catches DataUnavailError and returns the empty buffer.
        let f = fd_with(b"hi\0", 0x1000);
        assert!(!is_string(&f, 0x9000, 1), "nothing mapped there");
    }

    #[test]
    fn unterminated_run_is_not_a_string() {
        // No terminator within maximumChars — Ghidra gives up and returns the empty buffer.
        let f = fd_with(&vec![b'A'; 4096], 0x1000);
        assert!(!is_string(&f, 0x1000, 1));
    }
}
