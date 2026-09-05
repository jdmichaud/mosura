//! Watcom compiler detection — a **two-oracle extension** (beyond Ghidra: Ghidra's only
//! Watcom awareness is `OmfLoader.mapTranslator` mapping the OMF `"WATCOM"` translator
//! comment to the `"watcom"` opinion secondary, and there is **no watcom compiler spec in any
//! Ghidra processor**). The Watcom C run-time startup embeds a copyright banner right at the
//! `_cstart_` entry (the CRT init thunk jumps over it — WAR2.EXE's entry is `EB 76`, a jump
//! over the inline string). Scanning for that banner identifies the compiler as Watcom and
//! pins its **era**.
//!
//! **Oracle (not memory).** The banner grammar + strings are grounded in Open Watcom source
//! (`open-watcom-v2 bld/clib/startup/h/msgcpyrt.h` composes it: `"<Open >?Watcom C/C++<bits>
//! Run-Time system. "` + the copyright line) and verified against a real Watcom 10.0a
//! toolchain's runtime libraries (`clib3r.lib` etc.) plus the WAR2.EXE ground truth.
//!
//! **Granularity — a grounded finding, not a limitation to hide.** The embedded run-time
//! banner is an *era* fingerprint (vendor wording + product + bitness + copyright year range),
//! **not** a precise release: one toolchain (10.0a) ships several runtime libraries carrying
//! different year ranges (`1988-1993` for the older `C 386`/`C/C++32` runtimes, `1988-1994`
//! for the `C/C++` ones), and WAR2.EXE (built by a compiler *older* than 10.0a per
//! warcraft2-re) carries the same `1988-1994` banner as 10.0a. So the banner reliably names
//! Watcom + the era; the exact `wcc`/`wpp` release is not recoverable from the compiled image
//! (it lives in the tool banner, not the runtime banner). The detected value is therefore the
//! honest era fingerprint, not an invented version number.

use regex::bytes::Regex;
use std::sync::OnceLock;

/// The vendor wording of the copyright line — the primary era discriminator.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WatcomVendor {
    /// `(c) Copyright by WATCOM International Corp.` — classic Watcom (through 11.0, before
    /// the Sybase rewording and the 2002 open-sourcing).
    WatcomIntl,
    /// `Copyright (c) Open Watcom Contributors` — Open Watcom (2003+; the year range's end is
    /// the build year).
    OpenWatcom,
}

/// A detected Watcom run-time banner (`bld/clib/startup/h/msgcpyrt.h`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WatcomInfo {
    pub vendor: WatcomVendor,
    /// `C` or `C/C++` — the product wording (`C` is the pre-C++ 386 runtime).
    pub product: String,
    /// `16`, `32`, `386`, or empty — the runtime bitness/target.
    pub bitness: String,
    /// The copyright year range `(start, end)` from the vendor line — the era fingerprint.
    pub year_range: (u32, u32),
    /// The full matched banner text (for reporting).
    pub banner: String,
}

impl WatcomInfo {
    /// The value to store as the program `Compiler` info property. Format `watcom[:open]:<era>`
    /// where the era is the copyright year range — the honest banner-derived fingerprint (the
    /// runtime banner does not carry a precise release; see the module note). Examples:
    /// `watcom:1988-1994` (classic Watcom C/C++ ~10.x), `watcom:open:2002-2010` (Open Watcom).
    pub fn compiler_label(&self) -> String {
        let (y0, y1) = self.year_range;
        match self.vendor {
            WatcomVendor::WatcomIntl => format!("watcom:{y0}-{y1}"),
            WatcomVendor::OpenWatcom => format!("watcom:open:{y0}-{y1}"),
        }
    }
}

/// Matches the Watcom C run-time copyright banner. Assembled to mirror how `msgcpyrt.h`
/// composes the string: an `"<Open >?Watcom C[/C++][ 16|32|386] Run-Time system."` product
/// clause, then either the classic `"...WATCOM International Corp. YYYY-YYYY"` vendor line or
/// the Open Watcom `"...Open Watcom Contributors YYYY-YYYY"` line — the year range captured
/// from the vendor line (not the trailing "Portions Copyright ... 1988-2002").
fn banner_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?P<open>Open )?WATCOM (?P<prod>C(?:/C\+\+)?)(?: ?(?P<bits>16|32|386))? Run-Time system\. (?:\(c\) Copyright by WATCOM International Corp\. (?P<iy0>\d{4})-(?P<iy1>\d{4})|Copyright \(c\) Open Watcom Contributors (?P<oy0>\d{4})-(?P<oy1>\d{4}))",
        )
        .expect("valid watcom banner regex")
    })
}

/// Scan a binary image for the Watcom run-time banner and identify the compiler + era.
/// Returns `None` if no banner is present (not a Watcom binary, or the runtime was stripped).
/// Scans the raw file bytes so it works from any container path (LE / MZ / PE), matching the
/// fact that the banner is embedded verbatim in the compiled image.
/// The x86-32 compiler-spec id implied by the binary's run-time banner: `"watcom"` when
/// [`detect`] matches, else the generic `"gcc"` placeholder.
///
/// Both 32-bit x86 loaders decide this the same way and must keep doing so. The container
/// cannot answer it — an ELF32 i386 built by `wcc386 -bt=linux` is header-identical to a gcc
/// one, and an LE is a bare DOS/4GW image — so the linked C run-time's copyright banner is the
/// only in-band evidence of the calling convention. Choosing wrong is not cosmetic: `__watcall`
/// passes arguments in EAX/EDX/EBX/ECX and preserves every register but EAX, while `__cdecl`
/// passes on the stack, so prototype recovery and the entire call-effect model differ.
///
/// # The declared compiler spec (`Knobs::x86_32_cspec`) — the hook, and why it has to exist
///
/// The banner is a **run-time** string: it is in the C run-time the linker pulls in, not in
/// anything the compiler emits per translation unit. The ground-truth corpus links
/// `option nodefaultlib` with a hand-written `_cstart_` (it is a freestanding corpus, and this
/// toolchain root ships `binl/` only — there are no libraries to link), so **no ground-truth
/// binary carries the banner and every one of them detects as `gcc`** — verified, not assumed:
/// `wprologue`, `wprologue_sf` and `fnpattern` all report `cspec=gcc`, which
/// `src/fnpattern.c` property 1 already noted.
///
/// The consequence is that the `(x86:LE:32:default, watcom)` half of the pattern-file decision
/// tree — i.e. the whole of `specs/patterns/x86watcom_patterns.xml` — was unreachable from the
/// corpus, so a gate written against a Watcom-compiled fixture silently measured Ghidra's
/// `x86gcc_patterns.xml` instead. This override lets a test route the same binary through both,
/// which is what `ground_truth_parity::watcom_save_first_shape_spec` does.
///
/// Deliberately narrow: only the two ids that this function can otherwise return are accepted,
/// so a typo cannot select a nonexistent spec; anything else falls through to detection. When
/// unset — which is every non-test path — behaviour is bit-for-bit what it was.
///
/// `forced` is the caller's declaration ([`Knobs::x86_32_cspec`](crate::switches::Knobs)),
/// passed down as a value. It was once read from `std::env`, which raced: `cargo test` runs a
/// binary's tests on parallel threads in one process, so one test's routing leaked into another
/// test's analysis and two unrelated tests failed; a per-thread override fixed the race, and a
/// value passed down removes the need for either.
pub fn compiler_spec_id(data: &[u8], forced: Option<&str>) -> &'static str {
    if let Some(forced) = forced {
        match forced {
            "watcom" => return "watcom",
            "gcc" => return "gcc",
            // `highc` = specs/x86-32-highc.cspec (MetaWare High C 386). Declaring it is how a
            // caller TESTS a compiler hypothesis on a linked image: the MetaWare markers live
            // only in objects/libraries, and FID selects databases by (language, spec), so a
            // program analysed as `gcc` can never match a `highc` database.
            "highc" => return "highc",
            _ => {}
        }
    }
    // MetaWare before Watcom: its markers are distinct and its spec differs from both others
    // (see `super::metaware`). Only input that actually carries a MetaWare marker is affected —
    // an OMF object or library, never a linked X-32 image.
    if super::metaware::detect(data).is_some() {
        return "highc";
    }
    if detect(data).is_some() { "watcom" } else { "gcc" }
}

pub fn detect(data: &[u8]) -> Option<WatcomInfo> {
    // A linked binary can embed banners from SEVERAL runtime objects (a real 10.0a toolchain
    // ships `C 386 … 1988-1993` and `C/C++32 … 1988-1994` runtimes side by side), and which
    // one sits first in the file is a link-layout accident. The image's era is its NEWEST
    // banner's — the max-across-markers reading `gcc::detect` and the Borland detector use
    // (compiler_version.rs). Ties keep the first match.
    let mut best: Option<WatcomInfo> = None;
    for caps in banner_regex().captures_iter(data) {
        let get =
            |n: &str| caps.name(n).map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned());
        let num = |n: &str| {
            caps.name(n).and_then(|m| std::str::from_utf8(m.as_bytes()).ok()?.parse::<u32>().ok())
        };

        let (vendor, year_range) = if let (Some(y0), Some(y1)) = (num("iy0"), num("iy1")) {
            (WatcomVendor::WatcomIntl, (y0, y1))
        } else if let (Some(y0), Some(y1)) = (num("oy0"), num("oy1")) {
            (WatcomVendor::OpenWatcom, (y0, y1))
        } else {
            continue;
        };

        if best.as_ref().is_none_or(|b| year_range.1 > b.year_range.1) {
            best = Some(WatcomInfo {
                vendor,
                product: get("prod").unwrap_or_default(),
                bitness: get("bits").unwrap_or_default(),
                year_range,
                banner: String::from_utf8_lossy(caps.get(0).unwrap().as_bytes()).into_owned(),
            });
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact banner strings extracted from a real Watcom 10.0a toolchain's runtime
    /// libraries (`LIB386/DOS/CLIB3R.LIB` etc.) — the second oracle.
    #[test]
    fn detects_watcom_10_runtime_banners() {
        let cases: &[(&str, &str, &str, (u32, u32))] = &[
            (
                "WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. All rights reserved.",
                "C/C++", "32", (1988, 1994),
            ),
            (
                "WATCOM C/C++16 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. All rights reserved.",
                "C/C++", "16", (1988, 1994),
            ),
            (
                "WATCOM C 386 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1993. All rights reserved.",
                "C", "386", (1988, 1993),
            ),
            (
                "WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1993. All rights reserved.",
                "C/C++", "32", (1988, 1993),
            ),
        ];
        for (banner, prod, bits, years) in cases {
            let info = detect(banner.as_bytes()).unwrap_or_else(|| panic!("no match: {banner}"));
            assert_eq!(info.vendor, WatcomVendor::WatcomIntl);
            assert_eq!(info.product, *prod);
            assert_eq!(info.bitness, *bits);
            assert_eq!(info.year_range, *years);
            assert_eq!(info.compiler_label(), format!("watcom:{}-{}", years.0, years.1));
        }
    }

    /// The full Watcom **10.0–11.0 lineage**, validated against the concatenated runtime
    /// banners pulled from every toolchain's real install ISO (the second oracle; see
    /// `docs/watcom-detection.md`). Confirms `detect()` reads the right era from each real
    /// banner across the lineage: the standalone `C 386` runtime is always `1988-1993`, 10.0x
    /// tops out at `1988-1994`, and 10.5 through 11.0B add the `1988-1995` lib. No runtime
    /// banner in the lineage exceeds 1995 — the era stamp, not the release.
    #[test]
    fn detects_watcom_lineage_eras() {
        let cases: &[(&str, &str, &str, (u32, u32))] = &[
            // 10.0 LE preprod + every 10.0x: the standalone C 386 runtime
            ("WATCOM C 386 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1993. All rights reserved.",
             "C", "386", (1988, 1993)),
            // 10.0 / 10.0a: the 1994-era C/C++ runtimes
            ("WATCOM C/C++16 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. All rights reserved.",
             "C/C++", "16", (1988, 1994)),
            ("WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. All rights reserved.",
             "C/C++", "32", (1988, 1994)),
            // 10.5 / 10.6 / 11.0 / 11.0A / 11.0B: the 1995-era lib (lineage cap)
            ("WATCOM C/C++16 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1995. All rights reserved.",
             "C/C++", "16", (1988, 1995)),
            ("WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1995. All rights reserved.",
             "C/C++", "32", (1988, 1995)),
        ];
        for (banner, prod, bits, years) in cases {
            let info = detect(banner.as_bytes()).unwrap_or_else(|| panic!("no match: {banner}"));
            assert_eq!(info.vendor, WatcomVendor::WatcomIntl);
            assert_eq!(info.product, *prod);
            assert_eq!(info.bitness, *bits);
            assert_eq!(info.year_range, *years);
            assert_eq!(info.compiler_label(), format!("watcom:{}-{}", years.0, years.1));
        }
    }

    /// The Open Watcom banner grammar (open-watcom-v2 `msgcpyrt.h`): the run-time system line
    /// + `Copyright (c) Open Watcom Contributors 2002-<CYEAR>. Portions Copyright (C) Sybase,
    /// Inc. 1988-2002.` — the year range comes from the Contributors line, not the Sybase tail.
    #[test]
    fn detects_open_watcom_banner() {
        let banner = "Open Watcom C/C++32 Run-Time system. Copyright (c) Open Watcom Contributors 2002-2010. Portions Copyright (C) Sybase, Inc. 1988-2002.";
        let info = detect(banner.as_bytes()).expect("open watcom match");
        assert_eq!(info.vendor, WatcomVendor::OpenWatcom);
        assert_eq!(info.product, "C/C++");
        assert_eq!(info.bitness, "32");
        assert_eq!(info.year_range, (2002, 2010));
        assert_eq!(info.compiler_label(), "watcom:open:2002-2010");
    }

    /// The banner embedded in a larger image (with surrounding bytes) is still found.
    #[test]
    fn finds_banner_in_image() {
        let mut img = vec![0u8; 64];
        img.extend_from_slice(b"\xeb\x76WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. All rights reserved.\x8d@\x00");
        img.extend_from_slice(&[0u8; 32]);
        let info = detect(&img).expect("banner in image");
        assert_eq!(info.compiler_label(), "watcom:1988-1994");
    }

    #[test]
    fn non_watcom_returns_none() {
        assert!(detect(b"just some bytes, no banner here").is_none());
        assert!(detect(b"This program cannot be run in DOS mode.$").is_none());
    }

    /// Open task #7's live half: a LINKED binary can embed banners from several runtime
    /// objects — a real 10.0a toolchain ships `C 386 … 1988-1993` and `C/C++32 … 1988-1994`
    /// runtimes side by side (the module note's grounded finding). Which banner sits at the
    /// lower file offset is a LINK-LAYOUT accident, so first-match answers an older era for
    /// the same toolchain depending on object order. The era of the image is the NEWEST
    /// banner's — the same max-across-markers reading `gcc::detect` and the Borland detector
    /// already use (compiler_version.rs:284, :326).
    #[test]
    fn multi_banner_image_reports_the_newest_era() {
        let mut img = vec![0u8; 16];
        // The OLDER runtime's banner first in file order…
        img.extend_from_slice(b"WATCOM C 386 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1993. All rights reserved.");
        img.extend_from_slice(&[0u8; 16]);
        // …the newer one after it.
        img.extend_from_slice(b"WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. All rights reserved.");
        img.extend_from_slice(&[0u8; 16]);
        let info = detect(&img).expect("banner in image");
        assert_eq!(
            info.year_range,
            (1988, 1994),
            "the era of a multi-banner image is its NEWEST banner's, not whichever object the \
             linker placed first"
        );
        assert_eq!(info.product, "C/C++");
    }
}
