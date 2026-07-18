//! Reader for Ghidra's decompiler *datatests*.
//!
//! Each datatest is a self-contained XML fixture (`<decompilertest>`) holding a
//! raw memory image (`<binaryimage>` / `<bytechunk>`), symbols, a `<script>` of
//! console commands, and `<stringmatch>` assertions over the decompiled C. This
//! reader parses that format so mosura's conformance harness can ingest Ghidra's
//! own corpus verbatim — no re-derivation. See `docs/testing-baseline.md` §3.

use std::path::{Path, PathBuf};

/// A parsed datatest fixture.
#[derive(Debug, Clone)]
pub struct Datatest {
    /// File stem (e.g. `bitfields`), set by [`parse_file`].
    pub name: String,
    /// Language id from `<binaryimage arch="...">` (e.g. `x86:LE:64:default:gcc`).
    pub arch: String,
    pub chunks: Vec<ByteChunk>,
    pub symbols: Vec<Symbol>,
    /// Console commands from `<script><com>…</com></script>`.
    pub script: Vec<String>,
    /// Assertions over the decompiled output.
    pub matches: Vec<StringMatch>,
}

/// A run of bytes loaded at a fixed address.
#[derive(Debug, Clone)]
pub struct ByteChunk {
    pub space: String,
    pub offset: u64,
    pub readonly: bool,
    pub bytes: Vec<u8>,
}

/// A named address (function / data symbol).
#[derive(Debug, Clone)]
pub struct Symbol {
    pub space: String,
    pub offset: u64,
    pub name: String,
}

/// A `<stringmatch>`: `pattern` must occur within `[min, max]` times in the output.
#[derive(Debug, Clone)]
pub struct StringMatch {
    pub name: String,
    pub min: u32,
    pub max: u32,
    pub pattern: String,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Xml(roxmltree::Error),
    Parse(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Xml(e) => write!(f, "xml: {e}"),
            Error::Parse(s) => write!(f, "parse: {s}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}
impl From<roxmltree::Error> for Error {
    fn from(e: roxmltree::Error) -> Self {
        Error::Xml(e)
    }
}

/// List the `*.xml` datatests in `dir`, sorted.
pub fn list(dir: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut v = Vec::new();
    for ent in std::fs::read_dir(dir)? {
        let p = ent?.path();
        if p.extension().and_then(|e| e.to_str()) == Some("xml") {
            v.push(p);
        }
    }
    v.sort();
    Ok(v)
}

/// Parse a datatest from a file, setting [`Datatest::name`] from the file stem.
pub fn parse_file(path: &Path) -> Result<Datatest, Error> {
    let text = std::fs::read_to_string(path)?;
    let mut dt = parse_str(&text)?;
    dt.name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_string();
    Ok(dt)
}

/// Parse a datatest from an XML string.
pub fn parse_str(xml: &str) -> Result<Datatest, Error> {
    let doc = roxmltree::Document::parse(xml)?;
    let mut dt = Datatest {
        name: String::new(),
        arch: String::new(),
        chunks: Vec::new(),
        symbols: Vec::new(),
        script: Vec::new(),
        matches: Vec::new(),
    };
    for n in doc.descendants() {
        match n.tag_name().name() {
            "binaryimage" => {
                if let Some(a) = n.attribute("arch") {
                    dt.arch = a.to_string();
                }
            }
            "bytechunk" => dt.chunks.push(ByteChunk {
                space: n.attribute("space").unwrap_or("ram").to_string(),
                offset: parse_u64(n.attribute("offset").unwrap_or("0"))?,
                readonly: n.attribute("readonly") == Some("true"),
                bytes: parse_hex(n.text().unwrap_or(""))?,
            }),
            "symbol" => dt.symbols.push(Symbol {
                space: n.attribute("space").unwrap_or("ram").to_string(),
                offset: parse_u64(n.attribute("offset").unwrap_or("0"))?,
                name: n.attribute("name").unwrap_or("").to_string(),
            }),
            "com" => {
                if let Some(t) = n.text() {
                    dt.script.push(t.trim().to_string());
                }
            }
            "stringmatch" => dt.matches.push(StringMatch {
                name: n.attribute("name").unwrap_or("").to_string(),
                min: n.attribute("min").map(parse_u32).transpose()?.unwrap_or(1),
                max: n.attribute("max").map(parse_u32).transpose()?.unwrap_or(1),
                pattern: n.text().unwrap_or("").to_string(),
            }),
            _ => {}
        }
    }
    if dt.arch.is_empty() {
        return Err(Error::Parse("missing <binaryimage arch=...>".into()));
    }
    Ok(dt)
}

impl Datatest {
    /// Bytes of the first (typically executable) chunk — convenience for stubs.
    pub fn primary_bytes(&self) -> &[u8] {
        self.chunks.first().map(|c| c.bytes.as_slice()).unwrap_or(&[])
    }

    /// Entry address: first symbol offset, else first chunk offset.
    pub fn entry(&self) -> u64 {
        self.symbols
            .first()
            .map(|s| s.offset)
            .or_else(|| self.chunks.first().map(|c| c.offset))
            .unwrap_or(0)
    }
}

fn parse_u64(s: &str) -> Result<u64, Error> {
    let s = s.trim();
    let r = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse::<u64>(),
    };
    r.map_err(|e| Error::Parse(format!("bad integer {s:?}: {e}")))
}

fn parse_u32(s: &str) -> Result<u32, Error> {
    parse_u64(s).and_then(|v| {
        u32::try_from(v).map_err(|_| Error::Parse(format!("value {v} does not fit u32")))
    })
}

/// Parse a whitespace-delimited hex blob (the `<bytechunk>` body) into bytes.
fn parse_hex(s: &str) -> Result<Vec<u8>, Error> {
    let digits: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    if !digits.len().is_multiple_of(2) {
        return Err(Error::Parse(format!(
            "odd number of hex digits ({})",
            digits.len()
        )));
    }
    Ok(digits
        .chunks_exact(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16).unwrap() as u8;
            let lo = (p[1] as char).to_digit(16).unwrap() as u8;
            (hi << 4) | lo
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        <decompilertest>
          <binaryimage arch="x86:LE:64:default:gcc">
            <bytechunk space="ram" offset="0x100000" readonly="true">
              89 f0 83 e0
              0f
            </bytechunk>
            <symbol space="ram" offset="0x100000" name="dosomething"/>
          </binaryimage>
          <script>
            <com>lo fu dosomething</com>
            <com>decompile</com>
          </script>
          <stringmatch name="m1" min="1" max="1">return loadptr-&gt;field2;</stringmatch>
        </decompilertest>
    "#;

    #[test]
    fn parses_structure() {
        let dt = parse_str(SAMPLE).unwrap();
        assert_eq!(dt.arch, "x86:LE:64:default:gcc");
        assert_eq!(dt.chunks.len(), 1);
        assert_eq!(dt.chunks[0].offset, 0x100000);
        assert!(dt.chunks[0].readonly);
        assert_eq!(dt.chunks[0].bytes, vec![0x89, 0xf0, 0x83, 0xe0, 0x0f]);
        assert_eq!(dt.symbols[0].name, "dosomething");
        assert_eq!(dt.script, vec!["lo fu dosomething", "decompile"]);
        assert_eq!(dt.matches.len(), 1);
        // XML entities are decoded by the parser.
        assert_eq!(dt.matches[0].pattern, "return loadptr->field2;");
        assert_eq!(dt.entry(), 0x100000);
    }
}
