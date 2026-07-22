//! Compiler **version** identification — a beyond-Ghidra "second oracle" that reads the
//! version marker a toolchain stamps into its output, refining Ghidra's coarse
//! `CompilerOpinion` *family* (`pe_opinion.rs`) into a specific version/era. Ghidra's opinion
//! answers "which family" from container heuristics (`e_lfanew`, the DOS stub, the DanS flag);
//! this answers "which version" from the marker the compiler itself embeds. The two compose —
//! the faithful family opinion stays, this adds precision — and where Ghidra's family heuristic
//! is wrong (e.g. it calls Borland C++ output `borland:pascal` from `e_lfanew==0x100`), the
//! embedded `Borland C++` banner gives the true family too.
//!
//! **Marker per family** (grounded against real toolchain output — the second oracle):
//! - **MSVC**: the "Rich" header — `link.exe` records, XOR-masked between the DOS stub and the
//!   PE header, one `@comp.id` per contributing tool = `(product_id, build_number)`. The build
//!   number is the **exact** compiler build (VC6.0 = 8168). See `msvc`.
//! - **GCC / Clang**: a literal version string the compiler writes into `.comment`
//!   (`GCC: (GNU) 14...`, `clang version 19.1.7`) — the **exact** version. The `.comment` unions
//!   every object's producer, so the toolchain that built the user code is the max. See `gcc`,
//!   `clang`.
//! - **Borland**: the C run-time startup stamps `Borland C++ - Copyright YYYY Borland Intl.`
//!   (`Turbo C++ - Copyright YYYY` for the 16-bit line) — an **era** (copyright year); the
//!   embedded Turbo Assembler version narrows it where present. See `borland`.
//! - **Watcom**: the run-time copyright-year-range banner (era); handled by [`super::watcom`].

use regex::bytes::Regex;
use std::sync::OnceLock;

/// The compiler family a marker names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Family {
    Msvc,
    Gcc,
    Clang,
    Borland,
    Watcom,
}

impl Family {
    fn tag(self) -> &'static str {
        match self {
            Family::Msvc => "msvc",
            Family::Gcc => "gcc",
            Family::Clang => "clang",
            Family::Borland => "borland",
            Family::Watcom => "watcom",
        }
    }
}

/// How precisely the marker pins the release.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Precision {
    /// The marker carries the exact build/version (MSVC build id, GCC/Clang version string).
    Exact,
    /// The marker is an era fingerprint (a copyright year / year-range), not a precise release.
    Era,
    /// The version is **inferred from a structural field** that `link.exe` fills in — the PE
    /// optional-header linker version — rather than a self-stamped marker. Reliable for genuine
    /// compiler output; it distinguishes pre-Rich MSVC toolchains (VC4 → 3.0, VC5 → 5.0).
    Inferred,
    /// The marker names the family but the version is **not recoverable** — e.g. a stripped or
    /// non-PE MSVC artifact with the runtime string but no linker-version field.
    FamilyOnly,
}

/// A version identification from the embedded second-oracle marker.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CompilerId {
    pub family: Family,
    /// The best version label the marker supports — `6.0`, `14`, `19.1.7`, era `1994`.
    pub version: String,
    pub precision: Precision,
    /// The raw marker text/values this was read from (for reporting / auditing).
    pub evidence: String,
}

impl CompilerId {
    /// The stored label: `<family>:<version>` (`msvc:6.0`, `gcc:14`, `borland:c++:1994`). The
    /// Borland family carries the `c++`/`c` product wording the banner proves, since it is
    /// exactly the distinction Ghidra's `e_lfanew` heuristic gets wrong.
    pub fn label(&self) -> String {
        format!("{}:{}", self.family.tag(), self.version)
    }
}

/// First index of `needle` in `haystack`.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The PE optional-header linker version (`MajorLinkerVersion.MinorLinkerVersion`, at
/// `e_lfanew + 26/27`) — the value `link.exe` writes for its own version. `None` if `data` is
/// not a PE. A reliable toolchain discriminator (VC4 → 3.0, VC5 → 5.0, VC6 → 6.0).
fn pe_linker_version(data: &[u8]) -> Option<(u8, u8)> {
    let e = u32::from_le_bytes(data.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if data.get(e..e + 4)? != b"PE\0\0" {
        return None;
    }
    Some((*data.get(e + 26)?, *data.get(e + 27)?))
}

/// Identify the compiler + version from the binary's embedded marker, trying each family's
/// definitive marker in turn. Returns `None` when no marker is present (stripped runtime, or a
/// family not covered here — Watcom is covered by [`super::watcom`]). MSVC's Rich header, GCC's
/// and Clang's `.comment`, and Borland's startup banner are mutually exclusive in practice.
pub fn detect(data: &[u8]) -> Option<CompilerId> {
    msvc::detect(data)
        .or_else(|| gcc::detect(data))
        .or_else(|| clang::detect(data))
        .or_else(|| borland::detect(data))
        .or_else(|| watcom_id(data))
}

/// Adapt [`super::watcom::detect`] (the existing Watcom banner detector) into a [`CompilerId`].
fn watcom_id(data: &[u8]) -> Option<CompilerId> {
    let w = super::watcom::detect(data)?;
    let (y0, y1) = w.year_range;
    Some(CompilerId {
        family: Family::Watcom,
        version: format!("{y0}-{y1}"),
        precision: Precision::Era,
        evidence: w.banner,
    })
}

/// MSVC — decode the "Rich" header build ids.
pub mod msvc {
    use super::*;

    /// Decode the Rich-header entries: `(product_id, build_number, use_count)` per contributing
    /// tool. The header sits between the DOS stub (0x80) and the "Rich"+key marker, XOR-masked
    /// dword-wise with the 4-byte key; it opens with the masked `DanS` signature followed by
    /// three padding dwords, then the `@comp.id`/count pairs.
    pub fn rich_entries(data: &[u8]) -> Option<Vec<(u16, u16, u32)>> {
        let scan = &data[..data.len().min(0x1000)];
        let r = find_sub(scan, b"Rich")?;
        if r < 0x80 || r + 8 > data.len() {
            return None;
        }
        let key = [data[r + 4], data[r + 5], data[r + 6], data[r + 7]];
        let region = &data[0x80..r];
        let dec: Vec<u8> = region.iter().enumerate().map(|(i, b)| b ^ key[i % 4]).collect();
        let dans = dec.windows(4).position(|w| w == [0x44, 0x61, 0x6e, 0x53])?; // "DanS"
        let body = &dec[dans..];
        let mut ents = Vec::new();
        let mut off = 16; // DanS (4) + three padding dwords (12)
        while off + 8 <= body.len() {
            let compid = u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]]);
            let count = u32::from_le_bytes([body[off + 4], body[off + 5], body[off + 6], body[off + 7]]);
            off += 8;
            if compid == 0 && count == 0 {
                continue;
            }
            ents.push(((compid >> 16) as u16, (compid & 0xffff) as u16, count));
        }
        Some(ents)
    }

    /// Map a linker/compiler **build number** to the Visual Studio product. The build number is
    /// itself the exact identifier; the product name is a convenience lookup, and an unknown
    /// build honestly reports `build-<n>`. `8168` is verified in-house against a real VC6.0
    /// binary (`vc6_hello.exe`); the rest are Microsoft's published build numbers, to be
    /// verified as those toolchains are compiled (Phase 3 lineage sweep).
    pub fn product(build: u16) -> String {
        match build {
            8168 | 8804 => "6.0".to_string(), // VERIFIED (VC6.0 RTM / SP)
            // Published build numbers (not yet verified in-house):
            9782 => "5.0".to_string(),          // Visual C++ 5.0
            9466 => "7.0".to_string(),          // VS .NET 2002
            3077 => "7.1".to_string(),          // VS .NET 2003
            50727 => "8.0".to_string(),         // VS 2005
            21022 | 30729 => "9.0".to_string(), // VS 2008 (RTM / SP1)
            b => format!("build-{b}"),
        }
    }

    /// The C run-time library string every MSVC embeds (`Microsoft Visual C++ Runtime Library`)
    /// — the family fallback for pre-Rich toolchains (VC 2.0 through VC5) that carry no build id.
    const RUNTIME_STRING: &[u8] = b"Microsoft Visual C++ Runtime Library";

    pub fn detect(data: &[u8]) -> Option<CompilerId> {
        // Rich header (VC6-era onward): exact build.
        if let Some(ents) = rich_entries(data) {
            // The largest build among the real tool entries is the toolchain build (the linker
            // and the C/C++ compiler carry the version; product_id 0/1 are import/padding).
            if let Some(build) = ents.iter().filter(|(pid, _, _)| *pid > 1).map(|(_, b, _)| *b).max() {
                return Some(CompilerId {
                    family: Family::Msvc,
                    version: product(build),
                    precision: Precision::Exact,
                    evidence: format!("Rich header build {build}"),
                });
            }
        }
        // Pre-Rich MSVC (VC 2.0 through VC5, 1994-1997; the Rich header arrives with VC6): the
        // runtime-library string names the family. No self-stamped version, but the PE linker
        // version (link.exe's own version) distinguishes the toolchains — VC4→3.0, VC5→5.0.
        if find_sub(data, RUNTIME_STRING).is_some() {
            return Some(match pe_linker_version(data) {
                Some((maj, min)) => CompilerId {
                    family: Family::Msvc,
                    version: format!("link-{maj}.{min}"),
                    precision: Precision::Inferred,
                    evidence: format!(
                        "Microsoft Visual C++ Runtime Library + PE linker version {maj}.{min} ({})",
                        linker_note(maj, min)
                    ),
                },
                None => CompilerId {
                    family: Family::Msvc,
                    version: "unknown".to_string(),
                    precision: Precision::FamilyOnly,
                    evidence: "Microsoft Visual C++ Runtime Library (pre-Rich; no linker-version field)".to_string(),
                },
            });
        }
        None
    }

    /// The likely product for a pre-Rich MSVC linker version — verified in-house against real
    /// builds (VC4.0 → 3.0, VC5.0 → 5.0); other values are reported as-is.
    fn linker_note(maj: u8, min: u8) -> &'static str {
        match (maj, min) {
            (3, 0) => "VC++ 4.0",
            (5, 0) => "VC++ 5.0",
            (6, 0) => "VC++ 6.0",
            _ => "unmapped linker version",
        }
    }
}

/// GCC — the `.comment` producer string (`GCC: (GNU) <ver>`).
pub mod gcc {
    use super::*;

    fn re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"GCC: \([^)]*\) ([0-9]+(?:\.[0-9]+)*[A-Za-z0-9._-]*)").unwrap())
    }

    pub fn detect(data: &[u8]) -> Option<CompilerId> {
        let mut best: Option<(Vec<u32>, String)> = None;
        for c in re().captures_iter(data) {
            let raw = String::from_utf8_lossy(&c[1]).into_owned();
            let key: Vec<u32> = raw.split(['.', '-']).map(|p| p.parse().unwrap_or(0)).collect();
            if best.as_ref().is_none_or(|(bk, _)| key > *bk) {
                best = Some((key, raw));
            }
        }
        let (_, ver) = best?;
        Some(CompilerId {
            family: Family::Gcc,
            version: ver.clone(),
            precision: Precision::Exact,
            evidence: format!("GCC: (GNU) {ver}"),
        })
    }
}

/// Clang — the `clang version <ver>` producer string.
pub mod clang {
    use super::*;

    fn re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"clang version ([0-9]+(?:\.[0-9]+)*)").unwrap())
    }

    pub fn detect(data: &[u8]) -> Option<CompilerId> {
        let c = re().captures(data)?;
        let ver = String::from_utf8_lossy(&c[1]).into_owned();
        Some(CompilerId {
            family: Family::Clang,
            version: ver.clone(),
            precision: Precision::Exact,
            evidence: format!("clang version {ver}"),
        })
    }
}

/// Borland — the C run-time startup copyright banner.
pub mod borland {
    use super::*;

    /// `Borland C++ - Copyright YYYY Borland Intl.` (32-bit line) or `Turbo C++ - Copyright YYYY`
    /// (16-bit line). The product wording (`C++`) is captured — it is the true family that
    /// Ghidra's `e_lfanew` heuristic can miss.
    fn re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?:Borland|Turbo) (C\+\+|C) - Copyright (\d{4})(?: Borland Intl\.)?").unwrap()
        })
    }

    /// The Turbo Assembler version bcc embeds (`Turbo Assembler  Version 4.1`) — a secondary
    /// signal that narrows the era where present.
    fn tasm_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"Turbo Assembler +Version ([0-9.]+)").unwrap())
    }

    pub fn detect(data: &[u8]) -> Option<CompilerId> {
        // A linked binary can carry banners from several runtime objects; the era is the max year.
        let mut best: Option<(u32, String)> = None;
        for c in re().captures_iter(data) {
            let prod = String::from_utf8_lossy(&c[1]).into_owned(); // "C++" | "C"
            let year: u32 = std::str::from_utf8(&c[2]).ok()?.parse().ok()?;
            if best.as_ref().is_none_or(|(y, _)| year > *y) {
                best = Some((year, prod));
            }
        }
        let (year, prod) = best?;
        let prod_tag = if prod == "C++" { "c++" } else { "c" };
        // Narrow with TASM version if present (max, same union reasoning).
        let tasm = tasm_re()
            .captures_iter(data)
            .filter_map(|c| String::from_utf8(c[1].to_vec()).ok())
            .max_by(|a, b| a.split('.').flat_map(|p| p.parse::<u32>()).collect::<Vec<_>>()
                .cmp(&b.split('.').flat_map(|p| p.parse::<u32>()).collect::<Vec<_>>()));
        let evidence = match &tasm {
            Some(t) => format!("Borland {prod} - Copyright {year}; TASM {t}"),
            None => format!("Borland {prod} - Copyright {year}"),
        };
        Some(CompilerId {
            family: Family::Borland,
            version: format!("{prod_tag}:{year}"),
            precision: Precision::Era,
            evidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borland_banner_reads_family_and_era() {
        // The exact banner from a real Borland C++ 4.5 binary (bc45_hello.exe startup, C0X32.OBJ).
        let img = b"....Borland C++ - Copyright 1994 Borland Intl.\x00..Turbo Assembler  Version 4.1\x00";
        let id = detect(img).expect("borland detected");
        assert_eq!(id.family, Family::Borland);
        assert_eq!(id.version, "c++:1994"); // family from the banner, not Ghidra's e_lfanew guess
        assert_eq!(id.label(), "borland:c++:1994");
        assert_eq!(id.precision, Precision::Era);
        assert!(id.evidence.contains("TASM 4.1"));
    }

    #[test]
    fn borland_takes_max_year_across_objects() {
        let img = b"Borland C++ - Copyright 1991 Borland Intl. Borland C++ - Copyright 1994 Borland Intl.";
        assert_eq!(detect(img).unwrap().version, "c++:1994");
    }

    #[test]
    fn gcc_reads_exact_version_max_across_objects() {
        // mingw unions the runtime's producer (13) with the user code's (14) — the max is the
        // compiler that built the code.
        let img = b"..GCC: (GNU) 13-win32\x00..GCC: (GNU) 14-win32\x00..";
        let id = detect(img).expect("gcc detected");
        assert_eq!(id.family, Family::Gcc);
        assert_eq!(id.version, "14-win32");
        assert_eq!(id.precision, Precision::Exact);
    }

    #[test]
    fn clang_reads_exact_version() {
        let id = detect(b"..clang version 19.1.7 (3+b1)..").expect("clang detected");
        assert_eq!(id.family, Family::Clang);
        assert_eq!(id.version, "19.1.7");
        assert_eq!(id.label(), "clang:19.1.7");
    }

    #[test]
    fn msvc_build_maps_to_product() {
        assert_eq!(msvc::product(8168), "6.0"); // VC6.0, grounded against vc6_hello.exe
        assert_eq!(msvc::product(50727), "8.0");
        assert_eq!(msvc::product(1234), "build-1234"); // honest fallback
    }

    #[test]
    fn msvc_pre_rich_is_family_only() {
        // A pre-Rich MSVC (VC 2.0/4.0) binary: no Rich header, but the runtime string names the
        // family. Grounded against a real MSVC 4.0 build (hello_vc4.exe).
        let id = detect(b"...\x00Microsoft Visual C++ Runtime Library\x00...").expect("msvc family");
        assert_eq!(id.family, Family::Msvc);
        assert_eq!(id.version, "unknown");
        assert_eq!(id.precision, Precision::FamilyOnly); // version not recoverable — honest
        assert_eq!(id.label(), "msvc:unknown");
    }

    #[test]
    fn non_compiler_marker_returns_none() {
        assert!(detect(b"just some bytes, no compiler marker here at all").is_none());
    }
}
