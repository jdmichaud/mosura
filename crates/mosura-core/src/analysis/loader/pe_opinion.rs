//! PE compiler detection — a faithful port of Ghidra `PeLoader.CompilerOpinion.getOpinion`
//! (`app/util/opinion/PeLoader.java:973`). It inspects the DOS stub, the PE-header offset,
//! the Rich ("DanS") header, section names, the CLI data directory, and Rust/Go signatures
//! to name the compiler. Ghidra uses the result two ways: the [`CompilerEnum::family`] is the
//! Opinion *secondary* that selects the compiler spec (`PeLoader.java:93-96`, the x86.opinion
//! PE block), and the [`CompilerEnum::label`] is stored as the program's `Compiler` info
//! property (`PeLoader.java:163`). No invented heuristics — every branch mirrors the source.

use object::pe;
use object::read::pe::{ImageNtHeaders, PeFile};
use object::LittleEndian as LE;

/// Ghidra `PeLoader.CompilerOpinion.CompilerEnum`. The two ambiguous values (`GccVs`,
/// `GccVsClang`) are internal indicators and are never returned by [`get_opinion`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CompilerEnum {
    VisualStudio,
    Gcc,
    Clang,
    BorlandPascal,
    BorlandCpp,
    BorlandUnk,
    Cli,
    Rustc,
    Golang,
    Swift,
    Unknown,
    /// GCC | VS (ambiguous — internal only).
    GccVs,
    /// GCC | VS | CLANG (ambiguous — internal only).
    GccVsClang,
}

impl CompilerEnum {
    /// The value Ghidra stores as the `ProgramInformation.Compiler` property
    /// (`CompilerEnum.label`). The ambiguous internal values have no label (`null`).
    pub fn label(self) -> &'static str {
        match self {
            CompilerEnum::VisualStudio => "visualstudio:unknown",
            CompilerEnum::Gcc => "gcc:unknown",
            CompilerEnum::Clang => "clang:unknown",
            CompilerEnum::BorlandPascal => "borland:pascal",
            CompilerEnum::BorlandCpp => "borland:c++",
            CompilerEnum::BorlandUnk => "borland:unknown",
            CompilerEnum::Cli => "cli",
            CompilerEnum::Rustc => "rustc", // RustConstants.RUST_COMPILER
            CompilerEnum::Golang => "golang",
            CompilerEnum::Swift => "swift", // SwiftUtils.SWIFT_COMPILER
            CompilerEnum::Unknown | CompilerEnum::GccVs | CompilerEnum::GccVsClang => "unknown",
        }
    }

    /// The Opinion *secondary* query parameter (`CompilerEnum.family`).
    pub fn family(self) -> &'static str {
        match self {
            CompilerEnum::VisualStudio => "visualstudio",
            CompilerEnum::Gcc => "gcc",
            CompilerEnum::Clang => "clang",
            CompilerEnum::BorlandPascal => "borlanddelphi",
            CompilerEnum::BorlandCpp | CompilerEnum::BorlandUnk => "borlandcpp",
            CompilerEnum::Cli => "cli",
            CompilerEnum::Rustc => "rustc",
            CompilerEnum::Golang => "golang",
            CompilerEnum::Swift => "swift",
            CompilerEnum::Unknown | CompilerEnum::GccVs | CompilerEnum::GccVsClang => "unknown",
        }
    }

    /// The x86-64 PE compiler-spec id this opinion selects — the Opinion query resolved
    /// against the x86.opinion PE block (`primary=34404`, i.e. `IMAGE_FILE_MACHINE_AMD64`):
    /// only `clang`/`golang`/`swift` have a size-64 secondary; every other family (including
    /// `visualstudio`/`gcc`, whose size-64 constraint carries no secondary) resolves to the
    /// block's default `windows` compiler spec.
    pub fn cspec_x64(self) -> &'static str {
        match self.family() {
            "clang" => "clangwindows",
            "golang" => "golang",
            "swift" => "swift",
            _ => "windows",
        }
    }

    /// The x86-32 PE compiler-spec id — the Opinion query resolved against the x86.opinion PE
    /// block for `primary=332` (`IMAGE_FILE_MACHINE_I386`). Unlike the AMD64 block, the i386
    /// block carries `borlandcpp`/`borlanddelphi` secondaries (Borland is 32-bit only) and no
    /// `swift`; `clang`/`golang` keep their secondaries, and every other family (including
    /// `visualstudio`/`gcc`) resolves to the block's default `windows` compiler spec.
    pub fn cspec_x86(self) -> &'static str {
        match self.family() {
            "clang" => "clangwindows",
            "borlandcpp" => "borlandcpp",
            "borlanddelphi" => "borlanddelphi",
            "golang" => "golang",
            _ => "windows",
        }
    }
}

// --- static byte/char constants (PeLoader.java:905-916) ---
const ASM16_BORLAND: [u8; 16] = [
    0xBA, 0x10, 0x00, 0x0E, 0x1F, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x90, 0x90,
];
const ASM16_GCC_VS_CLANG: [u8; 14] =
    [0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21];
const ERRSTRING_BORLAND: &[u8] = b"This program must be run under Win32\r\n$";
const ERRSTRING_GCC_VS: &[u8] = b"This program cannot be run in DOS mode.\r\r\n$";
const ERRSTRING_CLANG: &[u8] = b"This program cannot be run in DOS mode.$";
const THIS_BYTES: &[u8] = b"This";
/// `RustConstants.RUST_SIGNATURES`.
const RUST_SIGNATURES: [&[u8]; 3] = [b"RUST_BACKTRACE", b"RUST_MIN_STACK", b"/rustc/"];
/// `SwiftUtils` section-name prefixes.
const SWIFT_PREFIXES: [&str; 3] = ["__swift", "swift", ".sw5"];
/// `GoBuildId.GO_BUILDID_MAGIC` (ISO-8859-1).
const GO_BUILDID_MAGIC: &[u8] = b"\xff Go build ID: \"";
/// `GoBuildInfo.GO_BUILDINF_MAGIC` (ISO-8859-1).
const GO_BUILDINF_MAGIC: &[u8] = b"\xff Go buildinf:";

/// Read a little-endian `i32` at file offset `off` (Ghidra `BinaryReader(provider, true)`),
/// or 0 if out of range.
fn read_i32(data: &[u8], off: usize) -> i32 {
    data.get(off..off + 4).map_or(0, |b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Ghidra `compareBytesToChars`: true iff `chars` matches `bytes` starting at `start`, with
/// the array-bounds guard `start + chars.len() < bytes.len()` (strictly less, as in Ghidra).
fn compare_bytes_to_chars(bytes: &[u8], start: usize, chars: &[u8]) -> bool {
    if start + chars.len() < bytes.len() {
        bytes[start..start + chars.len()] == *chars
    } else {
        false
    }
}

/// A section's short name (the raw 8-byte field, trimmed of NUL padding — as `pe.rs` reads
/// it). Long `/NNN` string-table names are not matched (none of the tell sections use them).
fn sec_name(raw: &[u8; 8]) -> Option<&str> {
    std::str::from_utf8(raw).ok().map(|n| n.trim_end_matches('\0'))
}

/// The raw on-disk bytes of the named section (`pointer_to_raw_data..+size_of_raw_data`).
fn section_raw<'a, Pe: ImageNtHeaders>(data: &'a [u8], pe: &PeFile<'_, Pe>, name: &str) -> Option<&'a [u8]> {
    for s in pe.section_table().iter() {
        if sec_name(&s.name) == Some(name) {
            let off = s.pointer_to_raw_data.get(LE) as usize;
            let len = s.size_of_raw_data.get(LE) as usize;
            return data.get(off..off + len);
        }
    }
    None
}

fn has_section<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>, name: &str) -> bool {
    pe.section_table().iter().any(|s| sec_name(&s.name) == Some(name))
}

/// `RustUtilities.isRust`: any `RUST_SIGNATURES` byte pattern occurs in the `.rdata` block.
fn is_rust<Pe: ImageNtHeaders>(data: &[u8], pe: &PeFile<'_, Pe>) -> bool {
    let Some(rdata) = section_raw(data, pe, ".rdata") else { return false };
    RUST_SIGNATURES.iter().any(|sig| find_sub(rdata, sig).is_some())
}

/// `SwiftUtils.isSwift(sectionNames)`: any section name starts with a Swift prefix.
fn is_swift<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>) -> bool {
    pe.section_table().iter().any(|s| {
        sec_name(&s.name).is_some_and(|name| SWIFT_PREFIXES.iter().any(|p| name.starts_with(p)))
    })
}

/// `PeLoader.isGolang`: a Go build id at the start of `.text` (`GoBuildId.read`) or the Go
/// buildinfo magic present in `.data` (`GoBuildInfo.isPresent`).
fn is_golang<Pe: ImageNtHeaders>(data: &[u8], pe: &PeFile<'_, Pe>) -> bool {
    let build_id = section_raw(data, pe, ".text").is_some_and(|t| t.starts_with(GO_BUILDID_MAGIC));
    let build_info =
        section_raw(data, pe, ".data").is_some_and(|d| find_sub(d, GO_BUILDINF_MAGIC).is_some());
    build_id || build_info
}

/// First index of `needle` in `haystack`.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Faithful port of `PeLoader.CompilerOpinion.getOpinion` (PeLoader.java:982). `data` is the
/// raw PE file image; `pe` its parsed header. `program_rdata` gates the Rust check (Ghidra's
/// `program` may be null — passing `false` skips it, as Ghidra does with a null program).
pub fn get_opinion<Pe: ImageNtHeaders>(data: &[u8], pe: &PeFile<'_, Pe>) -> CompilerEnum {
    use CompilerEnum::*;
    let e_lfanew = pe.dos_header().nt_headers_offset() as usize;

    // Check for Rust (.rdata signatures).
    if is_rust(data, pe) {
        return Rustc;
    }
    // Check for Swift (section names).
    if is_swift(pe) {
        return Swift;
    }
    // Check for managed code (.NET/CLI): the COM-descriptor data directory (entry 14).
    if pe.data_directories().get(pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR).is_some() {
        return Cli;
    }

    // Determine based on PE-header offset (e_lfanew).
    let mut offset_choice = Unknown;
    if e_lfanew == 0x80 {
        offset_choice = GccVs;
    } else if e_lfanew == 0x78 {
        offset_choice = Clang;
    } else if e_lfanew >= 0x80 {
        // Check for "DanS" (Rich image header).
        let val1 = read_i32(data, 0x80);
        let val2 = read_i32(data, 0x84);
        if val1 != 0 && val2 != 0 && (val1 ^ val2) == 0x536e_6144 {
            return VisualStudio;
        }
        if e_lfanew == 0x100 {
            offset_choice = BorlandPascal; // could also be Borland-C
        } else if e_lfanew == 0x200 {
            offset_choice = BorlandCpp;
        } else if e_lfanew > 0x300 {
            return Unknown;
        }
    }

    // The DOS-stub asm (256 bytes at 0x40).
    let asm: &[u8] = data.get(0x40..(0x40 + 256).min(data.len())).unwrap_or(&[]);
    let mut asm_choice = Unknown;
    if asm.starts_with(&ASM16_BORLAND) {
        asm_choice = BorlandUnk;
    } else if asm.starts_with(&ASM16_GCC_VS_CLANG) {
        asm_choice = GccVsClang;
    }

    // The DOS-stub error message.
    let mut err_choice = Unknown;
    match find_sub(asm, THIS_BYTES) {
        None => asm_choice = Unknown,
        Some(off) => {
            if compare_bytes_to_chars(asm, off, ERRSTRING_BORLAND) {
                if offset_choice == BorlandCpp || offset_choice == BorlandPascal {
                    return offset_choice;
                }
                err_choice = BorlandUnk;
            } else if compare_bytes_to_chars(asm, off, ERRSTRING_GCC_VS) {
                err_choice = GccVs;
            } else if compare_bytes_to_chars(asm, off, ERRSTRING_CLANG) {
                err_choice = Clang;
            } else {
                err_choice = Unknown;
            }
        }
    }

    // Disambiguation.
    if err_choice == GccVs && asm_choice == GccVsClang && e_lfanew == 0x80 {
        // gcc vs old VS.
        if is_golang(data, pe) {
            return Golang;
        }
        // PointerToSymbolTable (0 for VS, non-zero for gcc) at e_lfanew + 12.
        if read_i32(data, e_lfanew + 12) != 0 {
            return Gcc;
        }
    } else if (offset_choice == Clang || err_choice == Clang) && asm_choice == GccVsClang {
        return Clang;
    } else if err_choice == Unknown || asm_choice == Unknown {
        return Unknown;
    }

    if err_choice == BorlandUnk || asm_choice == BorlandUnk {
        return BorlandUnk; // pretty sure Borland, but didn't get 0x100 or 0x200
    }

    // Section-header tells (reaching here: no "DanS", no Borland DOS complaint).
    if has_section(pe, "CODE") {
        return BorlandPascal; // could be Borland-C
    }
    if has_section(pe, ".bss") {
        return Gcc;
    }
    if !has_section(pe, ".idata") {
        return VisualStudio; // assume VS if .idata not found
    }
    if has_section(pe, ".tls") {
        return BorlandCpp; // assume Borland, prefer cpp since no CODE segment
    }
    Unknown
}

#[cfg(test)]
mod tests {
    use super::CompilerEnum::*;
    use super::*;

    #[test]
    fn enum_label_family_match_ghidra() {
        // (enum, label, family) — verbatim from PeLoader.CompilerEnum(label, secondary).
        let cases = [
            (VisualStudio, "visualstudio:unknown", "visualstudio"),
            (Gcc, "gcc:unknown", "gcc"),
            (Clang, "clang:unknown", "clang"),
            (BorlandPascal, "borland:pascal", "borlanddelphi"),
            (BorlandCpp, "borland:c++", "borlandcpp"),
            (BorlandUnk, "borland:unknown", "borlandcpp"),
            (Cli, "cli", "cli"),
            (Rustc, "rustc", "rustc"),
            (Golang, "golang", "golang"),
            (Swift, "swift", "swift"),
            (Unknown, "unknown", "unknown"),
        ];
        for (c, label, family) in cases {
            assert_eq!(c.label(), label, "{c:?} label");
            assert_eq!(c.family(), family, "{c:?} family");
        }
    }

    #[test]
    fn cspec_x64_matches_x86_opinion_pe_block() {
        // x86.opinion PE block (primary=34404): only clang/golang/swift carry a size-64
        // secondary; every other family resolves to the block's default `windows` cspec.
        assert_eq!(Clang.cspec_x64(), "clangwindows");
        assert_eq!(Golang.cspec_x64(), "golang");
        assert_eq!(Swift.cspec_x64(), "swift");
        assert_eq!(VisualStudio.cspec_x64(), "windows");
        assert_eq!(Gcc.cspec_x64(), "windows");
        assert_eq!(BorlandCpp.cspec_x64(), "windows");
        assert_eq!(Cli.cspec_x64(), "windows");
        assert_eq!(Rustc.cspec_x64(), "windows");
        assert_eq!(Unknown.cspec_x64(), "windows");
    }

    #[test]
    fn compare_bytes_to_chars_bounds() {
        // Ghidra's guard is `start + chars.len() < bytes.len()` (strictly less).
        let b = b"This program cannot be run in DOS mode.$\x00\x00";
        assert!(compare_bytes_to_chars(b, 0, ERRSTRING_CLANG));
        assert!(!compare_bytes_to_chars(b, 0, ERRSTRING_GCC_VS)); // "\r\r\n$" doesn't match
        // A match that runs to the very end fails the strict `<` bound.
        assert!(!compare_bytes_to_chars(b"AB", 0, b"AB"));
    }

    #[test]
    fn dans_constant_is_little_endian_dans() {
        assert_eq!(0x536e_6144u32, u32::from_le_bytes(*b"DanS"));
    }
}
