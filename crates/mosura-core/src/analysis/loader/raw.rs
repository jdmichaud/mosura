//! Two container-less loaders: a **raw image** (bytes + a SLEIGH language + a load address —
//! Ghidra's "Raw Binary" import) and a Ghidra **`<binaryimage>` datatest** (the decompiler's
//! own fixture format: byte chunks at fixed addresses, optional symbols). Both build the same
//! `Program` shape the container loaders do, so the analysis and the decompiler run over them
//! unchanged; nothing is detected — the caller declares the language.

use super::elf::LoadError;
use crate::analysis::program::{AddressSet, Program, SymbolType};
use crate::datatest::Datatest;
use crate::decompile::space::{Address, SpaceKind, SpaceManager};

/// Endianness and address width from a language id `proc:LE|BE:bits:variant[:cspec]`.
fn lang_facts(language_id: &str) -> Result<(bool, u32), LoadError> {
    let parts: Vec<&str> = language_id.split(':').collect();
    if parts.len() < 4 {
        return Err(LoadError::Unsupported(format!("language id `{language_id}` is not `proc:endian:bits:variant`")));
    }
    let big_endian = match parts[1] {
        "LE" => false,
        "BE" => true,
        e => return Err(LoadError::Unsupported(format!("language id `{language_id}`: endianness `{e}` is not LE or BE"))),
    };
    let bits: u32 = parts[2].parse().map_err(|_| LoadError::Unsupported(format!("language id `{language_id}`: `{}` is not an address width", parts[2])))?;
    if !matches!(bits, 8 | 16 | 24 | 32 | 64) {
        return Err(LoadError::Unsupported(format!("language id `{language_id}`: address width {bits}")));
    }
    Ok((big_endian, bits))
}

/// The four-part SLEIGH language id and the compiler spec id of a datatest `arch`
/// (`x86:LE:64:default:gcc` → `x86:LE:64:default`, `gcc`; a four-part arch keeps `default`).
pub fn split_arch(arch: &str) -> (&str, &str) {
    if arch.matches(':').count() >= 4 {
        match arch.rfind(':') {
            Some(i) => (&arch[..i], &arch[i + 1..]),
            None => (arch, "default"),
        }
    } else {
        (arch, "default")
    }
}

fn empty_program(language_id: &str, compiler_spec_id: &str, base: u64) -> Result<Program, LoadError> {
    let (big_endian, bits) = lang_facts(language_id)?;
    if crate::lang::resolve(language_id).is_none() {
        return Err(LoadError::Unsupported(format!("unknown language `{language_id}`")));
    }
    let mut spaces = SpaceManager::standard();
    let ram = spaces.add("ram", SpaceKind::Processor, bits / 8, 1);
    Ok(Program::new(spaces, ram, language_id, compiler_spec_id, Address::new(ram, base), big_endian, bits))
}

/// A raw image: one readable, writable, executable block `ram` at `base`, the entry point and one
/// function at `base`.
pub fn load_raw(data: &[u8], language_id: &str, base: u64) -> Result<Program, LoadError> {
    if data.is_empty() {
        return Err(LoadError::Unsupported("empty raw image".into()));
    }
    let mut p = empty_program(language_id, "default", base)?;
    let ram = p.default_space;
    p.memory.add_block("ram", Address::new(ram, base), data.len() as u64, true, true, true, Some(data.to_vec()));
    p.entry_points.push(Address::new(ram, base));
    p.function_manager.create_function(Address::new(ram, base), &format!("FUN_{base:08x}"), AddressSet::default());
    p.symbol_table.add_symbol(Address::new(ram, base), "entry", SymbolType::Label);
    Ok(p)
}

/// A parsed datatest: one block per `<bytechunk>` (`readonly="true"` → not writable), every
/// `<symbol>` as a label, the entry (first symbol, else the first chunk) as the entry point and
/// the one function — named by its symbol when it has one, else `func` as the fixture tools do.
pub fn load_datatest(dt: &Datatest) -> Result<Program, LoadError> {
    if dt.chunks.is_empty() {
        return Err(LoadError::Unsupported("datatest has no <bytechunk>".into()));
    }
    let (language_id, cspec) = split_arch(&dt.arch);
    let mut p = empty_program(language_id, cspec, dt.chunks[0].offset)?;
    let ram = p.default_space;
    for (i, c) in dt.chunks.iter().enumerate() {
        if c.bytes.is_empty() {
            continue;
        }
        p.memory.add_block(&format!("chunk{i}"), Address::new(ram, c.offset), c.bytes.len() as u64, true, !c.readonly, true, Some(c.bytes.clone()));
    }
    for s in &dt.symbols {
        p.symbol_table.add_symbol(Address::new(ram, s.offset), &s.name, SymbolType::Label);
    }
    let entry = dt.entry();
    let name = dt.symbols.iter().find(|s| s.offset == entry).map(|s| s.name.clone()).unwrap_or_else(|| "func".to_string());
    p.entry_points.push(Address::new(ram, entry));
    p.function_manager.create_function(Address::new(ram, entry), &name, AddressSet::default());
    Ok(p)
}

/// [`load_datatest`] from the XML bytes.
pub fn load_datatest_bytes(data: &[u8]) -> Result<Program, LoadError> {
    let xml = std::str::from_utf8(data).map_err(|e| LoadError::Unsupported(format!("datatest is not UTF-8: {e}")))?;
    let dt = crate::datatest::parse_str(xml).map_err(|e| LoadError::Unsupported(format!("datatest: {e:?}")))?;
    load_datatest(&dt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_facts_and_arch_split() {
        assert_eq!(lang_facts("x86:LE:32:default").unwrap(), (false, 32));
        assert_eq!(lang_facts("68000:BE:32:default").unwrap(), (true, 32));
        assert!(lang_facts("x86:LE:32").is_err());
        assert!(lang_facts("x86:ME:32:default").is_err());
        assert_eq!(split_arch("x86:LE:64:default:gcc"), ("x86:LE:64:default", "gcc"));
        assert_eq!(split_arch("AARCH64:LE:64:v8A:default"), ("AARCH64:LE:64:v8A", "default"));
        assert_eq!(split_arch("x86:LE:64:default"), ("x86:LE:64:default", "default"));
    }

    #[test]
    fn a_raw_image_is_one_block_with_an_entry() {
        let p = load_raw(&[0x55, 0x89, 0xe5, 0xc3], "x86:LE:32:default", 0x1000).unwrap();
        assert_eq!(p.memory.blocks().count(), 1);
        assert_eq!(p.entry_points, vec![Address::new(p.default_space, 0x1000)]);
        assert_eq!(p.function_manager.function_count(), 1);
        assert_eq!(p.addr_size_bits, 32);
        assert!(load_raw(&[], "x86:LE:32:default", 0).is_err());
        assert!(load_raw(&[0x90], "nope:LE:32:default", 0).is_err());
    }

    #[test]
    fn a_datatest_keeps_its_chunks_readonly_flag_and_names_the_entry() {
        let xml = r#"<binaryimage arch="x86:LE:32:default:watcom">
<bytechunk space="ram" offset="0x1000" readonly="true">c3</bytechunk>
<bytechunk space="ram" offset="0x2000">00000000</bytechunk>
<symbol space="ram" offset="0x1000" name="main"/>
</binaryimage>"#;
        let p = load_datatest_bytes(xml.as_bytes()).unwrap();
        assert_eq!((p.language_id.as_str(), p.compiler_spec_id.as_str()), ("x86:LE:32:default", "watcom"));
        let blocks: Vec<(u64, bool)> = p.memory.blocks().map(|b| (b.start().offset, b.is_write())).collect();
        assert_eq!(blocks, vec![(0x1000, false), (0x2000, true)]);
        let f = p.function_manager.functions().next().unwrap();
        assert_eq!((f.entry_point().offset, f.name()), (0x1000, "main"));
        assert!(load_datatest_bytes(b"<binaryimage arch=\"x86:LE:32:default\"></binaryimage>").is_err());
    }
}
