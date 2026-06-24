//! The **analysis snapshot** — mosura's canonical, normalized view of the
//! converged `Program` state Ghidra's auto-analysis produces (A0; plan
//! `docs/analysis-port-plan.md` §3). It is to the analysis port what the disasm
//! golden ([`crate::golden`]) is to the SLEIGH engine: a line-oriented,
//! diff-friendly text format captured from the Ghidra oracle and committed under
//! `goldens/analysis/`, which mosura's analyzers must eventually reproduce
//! *structurally exact*.
//!
//! Format (v1) — a header plus one fact per line, mirroring [`crate::golden`]:
//!
//! ```text
//! # mosura-analysis-snapshot v1 lang=x86:LE:64:default compiler=gcc base=00400000 endian=little addrsize=64
//! # oracle=ghidra-12.0.3 via=GhidraMCP
//! block 00400000 0040011f segment_0.1
//! block 00401000 00401078 .text
//! func 00401000 add
//! func 00401042 _start
//! ```
//!
//! Addresses are lowercase hex, no `0x`, matching the disasm golden. Lines are
//! emitted **sorted** ([`Snapshot::render`]) so a comparison is order-independent.
//! Parsing is lenient: unknown header fields and unknown line prefixes are
//! ignored, so later phases can add sections (`entrypoint`, `sym`, `data`, `ref`)
//! without breaking older goldens. v1 covers the two facts the loader (A2) and
//! disassembly/function-discovery (A4) must reproduce: the loaded **memory map**
//! and the recovered **functions**.

/// A loaded memory block (Ghidra `MemoryBlock`): an address range with a name.
/// v1 records only blocks with a numeric address range (the loaded, `ram`-space
/// map); file-overlay metadata blocks (`.comment`, `.symtab`, …) are deferred.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Block {
    pub start: u64,
    pub end: u64,
    pub name: String,
}

/// A recovered function (Ghidra `Function`): its entry point and name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Function {
    pub entry: u64,
    pub name: String,
}

/// The converged-program snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub lang: String,
    pub compiler: String,
    pub base: u64,
    /// `"little"` or `"big"`.
    pub endian: String,
    pub addr_size: u32,
    pub blocks: Vec<Block>,
    pub functions: Vec<Function>,
}

impl Snapshot {
    /// Sort all sections into the canonical order used by [`Snapshot::render`]
    /// and golden comparison (blocks by start address, functions by entry).
    pub fn normalize(&mut self) {
        self.blocks.sort();
        self.functions.sort();
    }

    /// Render to the canonical v1 text format (sorted). Round-trips with
    /// [`parse`].
    pub fn render(&self) -> String {
        let mut s = self.clone();
        s.normalize();
        let mut out = String::new();
        out.push_str(&format!(
            "# mosura-analysis-snapshot v1 lang={} compiler={} base={:08x} endian={} addrsize={}\n",
            s.lang, s.compiler, s.base, s.endian, s.addr_size
        ));
        for b in &s.blocks {
            out.push_str(&format!("block {:08x} {:08x} {}\n", b.start, b.end, b.name));
        }
        for f in &s.functions {
            out.push_str(&format!("func {:08x} {}\n", f.entry, f.name));
        }
        out
    }
}

/// Parse the snapshot text. Lenient: unknown header fields and line prefixes are
/// ignored. The returned snapshot is [`normalized`](Snapshot::normalize).
pub fn parse(text: &str) -> Snapshot {
    let mut snap = Snapshot::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#') {
            for tok in rest.split_whitespace() {
                if let Some((k, v)) = tok.split_once('=') {
                    match k {
                        "lang" => snap.lang = v.to_string(),
                        "compiler" => snap.compiler = v.to_string(),
                        "base" => snap.base = u64::from_str_radix(v, 16).unwrap_or(0),
                        "endian" => snap.endian = v.to_string(),
                        "addrsize" => snap.addr_size = v.parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }
            continue;
        }
        let mut it = line.split_whitespace();
        match it.next() {
            Some("block") => {
                let start = it.next().and_then(|s| u64::from_str_radix(s, 16).ok());
                let end = it.next().and_then(|s| u64::from_str_radix(s, 16).ok());
                let name = it.collect::<Vec<_>>().join(" ");
                if let (Some(start), Some(end)) = (start, end) {
                    snap.blocks.push(Block { start, end, name });
                }
            }
            Some("func") => {
                let entry = it.next().and_then(|s| u64::from_str_radix(s, 16).ok());
                let name = it.collect::<Vec<_>>().join(" ");
                if let Some(entry) = entry {
                    snap.functions.push(Function { entry, name });
                }
            }
            _ => {} // unknown prefix (future section) — ignore
        }
    }
    snap.normalize();
    snap
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# mosura-analysis-snapshot v1 lang=x86:LE:64:default compiler=gcc base=00400000 endian=little addrsize=64
# oracle=ghidra-12.0.3 via=GhidraMCP
block 00401000 00401078 .text
block 00400000 0040011f segment_0.1
func 00401042 _start
func 00401000 add
";

    #[test]
    fn parses_header_and_sections() {
        let s = parse(SAMPLE);
        assert_eq!(s.lang, "x86:LE:64:default");
        assert_eq!(s.compiler, "gcc");
        assert_eq!(s.base, 0x0040_0000);
        assert_eq!(s.endian, "little");
        assert_eq!(s.addr_size, 64);
        // normalized: blocks by start, functions by entry
        assert_eq!(s.blocks[0].start, 0x0040_0000);
        assert_eq!(s.blocks[1].name, ".text");
        assert_eq!(s.functions[0].name, "add");
        assert_eq!(s.functions[1].name, "_start");
    }

    #[test]
    fn round_trips_through_render() {
        let s = parse(SAMPLE);
        assert_eq!(parse(&s.render()), s);
    }

    #[test]
    fn ignores_unknown_prefixes() {
        // a future section prefix must not break a v1 parser
        let s = parse("# v1 lang=x\nfunc 00401000 f\nref 00401000 00402000 CALL\n");
        assert_eq!(s.functions.len(), 1);
    }
}
