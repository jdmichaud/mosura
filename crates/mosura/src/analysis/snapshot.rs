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

/// An external entry point (Ghidra `SymbolTable.getExternalEntryPointIterator`):
/// the address plus its primary symbol name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntryPoint {
    pub addr: u64,
    pub name: String,
}

/// A defined symbol (Ghidra `Symbol`): address, name, and `SymbolType` kind
/// (`"Function"` / `"Label"` / …, matching Ghidra's `SymbolType` string).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Symbol {
    pub addr: u64,
    pub name: String,
    pub kind: String,
}

/// A reference (Ghidra `Reference`): `from → to` with a `RefType` kind string
/// (`"READ"`/`"DATA"`/`"UNCONDITIONAL_CALL"`/…), deduped on `(from, to, kind)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ref {
    pub from: u64,
    pub to: u64,
    pub kind: String,
}

/// A function's body (Ghidra `Function.getBody`): its entry plus the inclusive address
/// ranges of code units it owns.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FnBody {
    pub entry: u64,
    pub ranges: Vec<(u64, u64)>,
}

/// A defined data unit (Ghidra `Data` from `Listing.getDefinedData`): its address, the
/// data-type name (`Data.getDataType().getName()`, e.g. `dword`/`eh_frame_hdr`/
/// `fde_table_entry`/`Elf64_Ehdr`), and byte length (`Data.getLength()`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Data {
    pub addr: u64,
    pub type_name: String,
    pub len: u32,
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
    pub entries: Vec<EntryPoint>,
    pub symbols: Vec<Symbol>,
    pub refs: Vec<Ref>,
    /// Disassembled-instruction start addresses (Ghidra `Listing` code units) — the A4
    /// disassembly output.
    pub code_units: Vec<u64>,
    /// Function bodies (Ghidra `Function.getBody`).
    pub bodies: Vec<FnBody>,
    /// Defined data units (Ghidra `Listing.getDefinedData`).
    pub data: Vec<Data>,
}

impl Snapshot {
    /// Sort all sections into the canonical order used by [`Snapshot::render`]
    /// and golden comparison, so a comparison is order-independent.
    pub fn normalize(&mut self) {
        self.blocks.sort();
        self.functions.sort();
        self.entries.sort();
        self.symbols.sort();
        self.refs.sort();
        self.refs.dedup();
        self.code_units.sort_unstable();
        self.code_units.dedup();
        for b in &mut self.bodies {
            b.ranges.sort_unstable();
        }
        self.bodies.sort();
        self.bodies.dedup();
        self.data.sort();
        self.data.dedup();
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
        for e in &s.entries {
            out.push_str(&format!("entry {:08x} {}\n", e.addr, e.name));
        }
        for sym in &s.symbols {
            out.push_str(&format!("sym {:08x} {} {}\n", sym.addr, sym.name, sym.kind));
        }
        for r in &s.refs {
            out.push_str(&format!("ref {:08x} {:08x} {}\n", r.from, r.to, r.kind));
        }
        for a in &s.code_units {
            out.push_str(&format!("insn {a:08x}\n"));
        }
        for b in &s.bodies {
            out.push_str(&format!("fnbody {:08x}", b.entry));
            for (start, end) in &b.ranges {
                out.push_str(&format!(" {start:08x}:{end:08x}"));
            }
            out.push('\n');
        }
        for d in &s.data {
            out.push_str(&format!("data {:08x} {} {}\n", d.addr, d.type_name, d.len));
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
            Some("entry") => {
                let addr = it.next().and_then(|s| u64::from_str_radix(s, 16).ok());
                let name = it.collect::<Vec<_>>().join(" ");
                if let Some(addr) = addr {
                    snap.entries.push(EntryPoint { addr, name });
                }
            }
            Some("sym") => {
                // `sym <addr> <name> <kind>`; kind is the final token.
                let addr = it.next().and_then(|s| u64::from_str_radix(s, 16).ok());
                let mut rest: Vec<&str> = it.collect();
                let kind = rest.pop().unwrap_or("").to_string();
                let name = rest.join(" ");
                if let Some(addr) = addr {
                    snap.symbols.push(Symbol { addr, name, kind });
                }
            }
            Some("ref") => {
                // `ref <from> <to> <kind>`.
                let from = it.next().and_then(|s| u64::from_str_radix(s, 16).ok());
                let to = it.next().and_then(|s| u64::from_str_radix(s, 16).ok());
                let kind = it.collect::<Vec<_>>().join(" ");
                if let (Some(from), Some(to)) = (from, to) {
                    snap.refs.push(Ref { from, to, kind });
                }
            }
            Some("insn") => {
                if let Some(a) = it.next().and_then(|s| u64::from_str_radix(s, 16).ok()) {
                    snap.code_units.push(a);
                }
            }
            Some("data") => {
                // `data <addr> <type-name> <len>`; len is the final token, type-name the
                // middle (Ghidra datatype names carry no spaces, but join defensively).
                let addr = it.next().and_then(|s| u64::from_str_radix(s, 16).ok());
                let mut rest: Vec<&str> = it.collect();
                let len = rest.pop().and_then(|s| s.parse::<u32>().ok());
                let type_name = rest.join(" ");
                if let (Some(addr), Some(len)) = (addr, len) {
                    snap.data.push(Data { addr, type_name, len });
                }
            }
            Some("fnbody") => {
                // `fnbody <entry> s:e s:e ...`.
                if let Some(entry) = it.next().and_then(|s| u64::from_str_radix(s, 16).ok()) {
                    let ranges = it
                        .filter_map(|tok| {
                            let (s, e) = tok.split_once(':')?;
                            Some((u64::from_str_radix(s, 16).ok()?, u64::from_str_radix(e, 16).ok()?))
                        })
                        .collect();
                    snap.bodies.push(FnBody { entry, ranges });
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
entry 00401042 _start
entry 00402000 __bss_start
sym 00401000 add Function
sym 00402000 _end Label
sym 00402000 __bss_start Label
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
        // v2 sections: entries by (addr,name), symbols by (addr,name,kind)
        assert_eq!(s.entries.len(), 2);
        assert_eq!(s.entries[0].name, "_start");
        assert_eq!(s.symbols.len(), 3);
        // same address 0x402000 sorts __bss_start before _end (by name)
        assert_eq!(s.symbols[1].name, "__bss_start");
        assert_eq!(s.symbols[2].name, "_end");
        assert_eq!(s.symbols[0].kind, "Function");
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

    #[test]
    fn parses_and_round_trips_data_units() {
        let s = parse(
            "# v1 lang=x\ndata 00402008 eh_frame_hdr 4\ndata 00402014 fde_table_entry 8\n",
        );
        assert_eq!(s.data.len(), 2);
        assert_eq!(s.data[0].type_name, "eh_frame_hdr");
        assert_eq!(s.data[0].len, 4);
        assert_eq!(s.data[1].addr, 0x0040_2014);
        // round-trips through render
        assert_eq!(parse(&s.render()), s);
    }
}
