//! MetaWare High C/C++ 386 detection — a **two-oracle extension** (beyond Ghidra: no Ghidra
//! loader or processor knows MetaWare, and no Ghidra x86 processor ships a MetaWare compiler
//! spec). Sibling of [`super::watcom`]; same shape, same standard of evidence.
//!
//! **Oracle (not memory).** Every marker below was read out of the real toolchains, installed by
//! `scripts/setup-metaware-dosemu.sh` and scanned in their own runtime libraries. See
//! `docs/metaware-highc-support.md`.
//!
//! Three markers, in decreasing order of precision:
//!
//! | marker | example | what it pins |
//! | --- | --- | --- |
//! | C++ run-time library banner | `MetaWare Incorporated C++ Runtime Library.  Copyright (C) 1990-1993 MetaWare Incorporated.  Library Version 0.30 Oct  2 1994` | the RTL version **and** its build date |
//! | OMF translator comment | `MetaWare High C [dosomf v2.05b(4pes)]` | the code generator's own version |
//! | C run-time library banner | `High C Run-time Library Copyright (C) 1983-1992 MetaWare Incorporated.` | an era (copyright year range) |
//!
//! Observed across the four DOS-hosted releases — the translator version separates all four,
//! which is what makes it the useful discriminator:
//!
//! | release | translator | C RTL years | C++ RTL |
//! | --- | --- | --- | --- |
//! | High C 386 v2.31 (1992) | `v2.04b` | 1983-1990 | — (C only) |
//! | High C/C++ v3.03 | `v2.05a` | 1983-1992 | 0.10 Apr  9 1992 |
//! | High C/C++ v3.04 (1993) | `v2.05b` | 1983-1992 | 0.10 Aug 21 1992 |
//! | High C/C++ v3.31 | `v2.10b` | 1983-1993 | 0.30 Oct  2 1994 |
//!
//! **Granularity — a grounded finding, not a limitation to hide.** These are the markers the
//! toolchain stamps; none of them *names its release*. The label therefore reports the marker,
//! never an invented release number — the same rule [`super::watcom`] follows for its era
//! banner. The mapping table above is how a reader turns a marker into a release, and it is
//! evidence from four installs, not a guarantee that no other release shares a translator.
//!
//! **WHERE THIS APPLIES — including linked images.** The `dosomf` translator comment is an OMF
//! COMENT record and so lives only in objects and libraries. The **C run-time banner does
//! survive linking**: a program linked against `HC386.LIB` by Phar Lap 386|LINK carries
//! `High C Run-time Library Copyright (C) 1983-1993 MetaWare Incorporated.` in its image, and
//! this detector finds it there (verified on `oracle/probes/libprobe.c` linked with the real
//! toolchain — see `docs/metaware-highc-support.md`).
//!
//! That makes the *absence* of any marker in a linked image informative rather than expected.
//! It is why the two real X-32 samples, which carry none of these strings and which the FID
//! databases name nothing in, are **evidence of a different compiler** rather than a gap in
//! detection.
//!
//! ⚠️ An earlier plan for this work guessed that the runtime strings visible in the X-32 samples
//! (`NULL code pointer called`, `Bad stack size parameter`, …) were High C's. They are **not**:
//! they appear in no MetaWare library, and belong to the FlashTek extender. Do not resurrect
//! them as a compiler tell.

use regex::bytes::Regex;
use std::sync::OnceLock;

/// A detected MetaWare marker.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MetaWareInfo {
    /// `dosomf` translator version, e.g. `2.05b` — the code generator's own version.
    pub translator: Option<String>,
    /// C run-time banner copyright year range, e.g. `(1983, 1992)`.
    pub c_rtl_years: Option<(u32, u32)>,
    /// C++ run-time library version and build date, e.g. `("0.30", "Oct  2 1994")`.
    pub cpp_rtl: Option<(String, String)>,
    /// The strongest matched banner text, for reporting.
    pub banner: String,
}

impl MetaWareInfo {
    /// The value to store as the program `Compiler` info property: `metaware:highc:<marker>`,
    /// reporting the most precise marker found. Examples:
    /// `metaware:highc:cpprtl0.30`, `metaware:highc:dosomf2.05b`, `metaware:highc:1983-1992`.
    pub fn compiler_label(&self) -> String {
        if let Some((ver, _)) = &self.cpp_rtl {
            return format!("metaware:highc:cpprtl{ver}");
        }
        if let Some(t) = &self.translator {
            return format!("metaware:highc:dosomf{t}");
        }
        match self.c_rtl_years {
            Some((y0, y1)) => format!("metaware:highc:{y0}-{y1}"),
            None => "metaware:highc".to_string(),
        }
    }

    /// True when a C++ run-time banner is present, i.e. the C/C++ (3.x) product rather than the
    /// C-only 386 line.
    pub fn is_cpp(&self) -> bool {
        self.cpp_rtl.is_some()
    }
}

fn translator_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Match the whole bracket so the reported evidence is the complete marker rather than a
    // fragment ending mid-parenthesis.
    RE.get_or_init(|| {
        Regex::new(r"MetaWare High C \[dosomf v([0-9]+\.[0-9]+[a-z]?)\([^)\]]*\)\]").unwrap()
    })
}

fn c_rtl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"High C Run-time Library Copyright \(C\) ([0-9]{4})-([0-9]{4}) MetaWare")
            .unwrap()
    })
}

fn cpp_rtl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // One line on purpose: a `\`-newline continuation inside a RAW string is not a line
        // continuation, it is a literal backslash, and the pattern then matches nothing.
        Regex::new(r"MetaWare Incorporated C\+\+ Runtime Library\..{0,120}?Library Version ([0-9]+\.[0-9]+) ([A-Z][a-z]{2} +[0-9]{1,2} [0-9]{4})")
            .unwrap()
    })
}

/// Scan `data` for any MetaWare marker. `None` when none is present — which is the expected
/// answer for a linked X-32 image (see the module note), not a failure.
pub fn detect(data: &[u8]) -> Option<MetaWareInfo> {
    let s = |m: regex::bytes::Match<'_>| String::from_utf8_lossy(m.as_bytes()).into_owned();

    let cpp = cpp_rtl_re().captures(data);
    let translator = translator_re().captures(data);
    let c_rtl = c_rtl_re().captures(data);
    if cpp.is_none() && translator.is_none() && c_rtl.is_none() {
        return None;
    }

    // The banner reported is the most precise marker matched.
    let banner = cpp
        .as_ref()
        .map(|c| s(c.get(0).unwrap()))
        .or_else(|| translator.as_ref().map(|c| s(c.get(0).unwrap())))
        .or_else(|| c_rtl.as_ref().map(|c| s(c.get(0).unwrap())))
        .unwrap_or_default();

    Some(MetaWareInfo {
        translator: translator.map(|c| s(c.get(1).unwrap())),
        c_rtl_years: c_rtl.and_then(|c| {
            let y0 = s(c.get(1)?).parse().ok()?;
            let y1 = s(c.get(2)?).parse().ok()?;
            Some((y0, y1))
        }),
        cpp_rtl: cpp.map(|c| (s(c.get(1).unwrap()), s(c.get(2).unwrap()))),
        banner,
    })
}

/// The compiler spec id to select when MetaWare is detected in 32-bit input: `highc`, the
/// beyond-Ghidra `specs/x86-32-highc.cspec` (ordinary cdecl, except a <=8-byte struct returns
/// in EDX:EAX — derived from the compiler's own output, see that file). `None` leaves the
/// caller's choice alone.
pub fn compiler_spec_id(data: &[u8]) -> Option<&'static str> {
    detect(data).map(|_| "highc")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Marker fragments copied verbatim from the real libraries, so these gates run without the
    // historical toolchains present (the `compiler_version` marker-fragment convention).
    const V231_C: &[u8] =
        b"xx High C Run-time Library Copyright (C) 1983-1990 MetaWare Incorporated. yy";
    const V231_T: &[u8] = b"\x88 MetaWare High C [dosomf v2.04b(4pes)] \x00";
    const V304_T: &[u8] = b"\x88 MetaWare High C [dosomf v2.05b(4pes)] \x00";
    const V331_T: &[u8] = b"\x88 MetaWare High C [dosomf v2.10b(4pes)] \x00";
    const V331_CPP: &[u8] = b"  MetaWare Incorporated C++ Runtime Library.  Copyright (C) \
        1990-1993 MetaWare Incorporated.  Library Version 0.30 Oct  2 1994 13:41:37";
    const V303_CPP: &[u8] = b"  MetaWare Incorporated C++ Runtime Library.  Copyright (C) \
        1990-1991 MetaWare Incorporated.  Library Version 0.10 Apr  9 1992 19:10:43";

    #[test]
    fn c_runtime_banner_gives_the_era() {
        let i = detect(V231_C).expect("C run-time banner");
        assert_eq!(i.c_rtl_years, Some((1983, 1990)));
        assert!(!i.is_cpp());
        assert_eq!(i.compiler_label(), "metaware:highc:1983-1990");
    }

    #[test]
    fn translator_version_discriminates_the_releases() {
        // The four DOS-hosted releases carry four different translator versions; that is what
        // makes this the useful marker.
        for (data, want) in [(V231_T, "2.04b"), (V304_T, "2.05b"), (V331_T, "2.10b")] {
            let i = detect(data).expect("translator comment");
            assert_eq!(i.translator.as_deref(), Some(want));
            assert_eq!(i.compiler_label(), format!("metaware:highc:dosomf{want}"));
        }
    }

    #[test]
    fn cpp_runtime_banner_gives_version_and_date() {
        let i = detect(V331_CPP).expect("C++ RTL banner");
        assert_eq!(i.cpp_rtl, Some(("0.30".into(), "Oct  2 1994".into())));
        assert!(i.is_cpp());
        assert_eq!(i.compiler_label(), "metaware:highc:cpprtl0.30");

        let i = detect(V303_CPP).expect("C++ RTL banner");
        assert_eq!(i.cpp_rtl, Some(("0.10".into(), "Apr  9 1992".into())));
    }

    #[test]
    fn cpp_banner_outranks_the_others() {
        let mut both = V331_CPP.to_vec();
        both.extend_from_slice(V331_T);
        let i = detect(&both).unwrap();
        assert_eq!(i.compiler_label(), "metaware:highc:cpprtl0.30");
        assert_eq!(i.translator.as_deref(), Some("2.10b"), "still recorded");
    }

    #[test]
    fn no_false_positive_on_other_vendors() {
        // Other vendors' banners, and the FlashTek extender strings that an earlier plan wrongly
        // attributed to High C. None of these is a MetaWare marker.
        for s in [
            &b"WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp."[..],
            &b"Borland C++ - Copyright 1994 Borland Intl."[..],
            &b"Turbo C++ - Copyright 1990 Borland Intl."[..],
            &b"GCC: (GNU) 14.2.0"[..],
            &b"\r\nNULL code pointer called\r\n$\r\nNot enough memory\r\n$"[..],
            &b"DOS extender Copyright 1991-1994 by Doug Huffman"[..],
            &b"__X386_VM_DISABLED DGROUP relative address"[..],
            &b""[..],
        ] {
            assert!(detect(s).is_none(), "false positive on {:?}", String::from_utf8_lossy(s));
        }
    }

    #[test]
    fn spec_id_is_highc_when_detected() {
        assert_eq!(compiler_spec_id(V304_T), Some("highc"));
        assert_eq!(compiler_spec_id(b"nothing here"), None);
    }
}
