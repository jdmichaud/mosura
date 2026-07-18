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
pub fn detect(data: &[u8]) -> Option<WatcomInfo> {
    let caps = banner_regex().captures(data)?;
    let get = |n: &str| caps.name(n).map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned());
    let num = |n: &str| caps.name(n).and_then(|m| std::str::from_utf8(m.as_bytes()).ok()?.parse::<u32>().ok());

    let (vendor, year_range) = if let (Some(y0), Some(y1)) = (num("iy0"), num("iy1")) {
        (WatcomVendor::WatcomIntl, (y0, y1))
    } else if let (Some(y0), Some(y1)) = (num("oy0"), num("oy1")) {
        (WatcomVendor::OpenWatcom, (y0, y1))
    } else {
        return None;
    };

    Some(WatcomInfo {
        vendor,
        product: get("prod").unwrap_or_default(),
        bitness: get("bits").unwrap_or_default(),
        year_range,
        banner: String::from_utf8_lossy(caps.get(0).unwrap().as_bytes()).into_owned(),
    })
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
}
