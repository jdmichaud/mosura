//! The candidate side: a compiled object, symbolically relinked to the original's addresses.
//!
//! Comparing a freshly compiled object against a linked binary has one structural obstacle. In a
//! translation unit holding a single function, every call to another function and every
//! reference to a global is *external*: the compiler emits a placeholder and records a fixup,
//! while the original binary holds a resolved address. Those sites differ by construction, in
//! every function that has any.
//!
//! There are two ways to handle it. Masking the bytes at fixup sites makes the comparison pass —
//! and also makes a candidate that calls the *wrong function* pass, which destroys the
//! instrument. Resolving them does not: we ask what address the fixup's symbol denotes, write
//! that address in, and a wrong target then shows up as a wrong address. This module does the
//! second. It is the same operation a linker performs, restricted to what one function needs.
//!
//! The symbol → address direction is supplied by the caller ([`SymbolResolver`]), because it is
//! a property of the emitter's naming convention rather than of object files.

use crate::analysis::loader::omf::{self, FixupTarget, OmfModule};
use crate::recompile::insn::Relocator;

/// Maps an emitted symbol name to the address it denotes in the original image.
///
/// mosura names what it emits after the address it came from (`FUN_00010c20`,
/// `_xRam00083090`), so the convention itself carries the answer; a resolver that knows a
/// project's other conventions (a real symbol table, a map file) plugs in the same way.
pub trait SymbolResolver {
    fn address_of(&self, symbol: &str) -> Option<u64>;
}

impl<F: Fn(&str) -> Option<u64>> SymbolResolver for F {
    fn address_of(&self, symbol: &str) -> Option<u64> {
        self(symbol)
    }
}

/// One relocation site inside the extracted function.
#[derive(Debug, Clone)]
pub struct CandFixup {
    /// Byte offset from the start of the function.
    pub offset: usize,
    /// Width of the field, in bytes.
    pub width: usize,
    /// The symbol the fixup names, when it names one (external references).
    pub symbol: Option<String>,
    /// True when the field holds a displacement from its own end (`call rel32`).
    pub self_relative: bool,
    /// Address the site resolves to, when the resolver could answer.
    pub resolved: Option<u64>,
    /// The placeholder value the compiler wrote at the site.
    pub placeholder: u64,
    /// For a module-local reference to bytes OUTSIDE the function's own extent (a switch's
    /// jump table, which Watcom emits at the front of `_TEXT`): the referenced segment
    /// offset. Such a site has no meaning at the original's addresses until
    /// [`Candidate::resolve_tables`] proves the referenced table corresponds to one in the
    /// original image; until then `resolved` stays `None` and the site diffs.
    pub local_data: Option<u64>,
}

/// A jump table carried in the compiled object's own code segment, outside the function's
/// extent: Watcom places a switch's table at the front of `_TEXT`, each entry a 4-byte
/// segment-relative fixup targeting a case block inside the function.
#[derive(Debug, Clone)]
pub struct CandTable {
    /// The table's starting offset within the code segment.
    pub seg_off: u64,
    /// Each entry's target, as an offset from the FUNCTION's start (entry fixup target
    /// minus the function's own segment offset) — layout-independent case positions.
    pub entries_fnrel: Vec<u64>,
}

/// A function extracted from a compiled object, ready to be compared against the original.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Code bytes of the function alone.
    pub bytes: Vec<u8>,
    /// Address the function is being compared *at* — the original's, so both sides' absolute
    /// operands and branch targets are in one coordinate system.
    pub base: u64,
    pub fixups: Vec<CandFixup>,
    /// Fixups whose symbol the resolver could not place. These are carried rather than dropped:
    /// an unresolved site is a limit of the comparison and has to be visible in the verdict.
    pub unresolved: Vec<String>,
    /// Jump tables found in the object's code segment outside the function extent.
    pub tables: Vec<CandTable>,
}

impl Candidate {
    /// Bytes with every resolvable fixup site patched to its linked value.
    ///
    /// This is what makes a *byte* comparison meaningful again: after relinking, a byte-identical
    /// result is genuine agreement rather than agreement-modulo-masking.
    pub fn relinked_bytes(&self) -> Vec<u8> {
        let mut out = self.bytes.clone();
        for f in &self.fixups {
            let Some(target) = f.resolved else { continue };
            if f.offset + f.width > out.len() {
                continue;
            }
            let site_end = self.base + (f.offset + f.width) as u64;
            // OMF fixups are ADDITIVE (TIS OMF 1.1: the computed value is added to the field's
            // existing content) — the compiler writes any `symbol ± k` addend INTO the field.
            // Replacing instead of adding silently dropped every such addend: `(long)shortvar`
            // compiles as `MOV EAX,[var-2]; SAR EAX,16` (the original's own idiom at
            // FUN_00045ee0, `MOV EAX,[0x971d2]` for the short at 0x971d4), and the bare-target
            // patch turned the candidate's identical instruction into `[0x971d4]` — a
            // manufactured ±k "wrong neighboring global" family, 58 functions / 92 rows of
            // harness artifact. The self-relative arm keeps replace semantics: the toolchain
            // demonstrably writes call fields the current arithmetic already matches (739 EXACT
            // functions' call sites), and OMF's self-relative addend interacts with the
            // module-local site offset in a way this loader's `base` normalization already
            // absorbs.
            let value = if f.self_relative {
                target.wrapping_sub(site_end)
            } else {
                target.wrapping_add(f.placeholder)
            };
            for (i, b) in value.to_le_bytes()[..f.width.min(8)].iter().enumerate() {
                out[f.offset + i] = *b;
            }
        }
        out
    }
}

impl Candidate {
    /// Resolve module-local jump-table references by TABLE CORRESPONDENCE against the
    /// original image (JD-approved metric rule, 2026-08-22: every linker-filled reference
    /// compares by what it denotes, never by the literal address).
    ///
    /// A table-base operand (`JMP [EAX*4 + base]`) is a linker-filled address exactly like
    /// a call target: the compiler said "this function's table", the number is layout. The
    /// resolution is gated on CONTENT: from the candidate table's function-relative entry
    /// targets we construct the byte string the original's table must hold (each entry =
    /// the function's VA plus the same offset), and `find` searches the original image for
    /// it. Found at `P` ⇒ the tables correspond entry-for-entry and the reference resolves
    /// to `P` (plus the within-table displacement); not found — wrong size, wrong order,
    /// any entry targeting a different case — ⇒ the site stays unresolved and diffs, so a
    /// candidate with a WRONG table still fails. Nothing the compiler decides is masked.
    pub fn resolve_tables(&mut self, find: &dyn Fn(&[u8]) -> Option<u64>) {
        for f in &mut self.fixups {
            if f.resolved.is_some() {
                continue;
            }
            let Some(referenced) = f.local_data else { continue };
            let Some(table) = self
                .tables
                .iter()
                .find(|t| referenced >= t.seg_off && referenced < t.seg_off + 4 * t.entries_fnrel.len() as u64)
            else {
                continue;
            };
            let expected: Vec<u8> = table
                .entries_fnrel
                .iter()
                .flat_map(|k| ((self.base.wrapping_add(*k)) as u32).to_le_bytes())
                .collect();
            if let Some(p) = find(&expected) {
                // Additive-fixup convention (see `relinked_bytes`): the field's own content
                // (the addend, e.g. a folded index bias) is added on top, so the resolved
                // value carries only the displacement — mirroring the external-symbol arm.
                let displacement = referenced.wrapping_sub(f.placeholder);
                f.resolved = Some(p.wrapping_add(displacement).wrapping_sub(table.seg_off));
            }
        }
    }
}

impl Relocator for Candidate {
    fn resolve(&self, insn_addr: u64, insn_len: usize, value: u64, size: u32) -> Option<u64> {
        let lo = insn_addr.checked_sub(self.base)? as usize;
        let hi = lo + insn_len;
        for f in &self.fixups {
            // Only a fixup inside *this* instruction may rewrite its operands, so a placeholder
            // that coincides with a genuine constant elsewhere is left alone.
            if f.offset < lo || f.offset + f.width > hi {
                continue;
            }
            let target = f.resolved?;
            if f.self_relative {
                // The decoded operand is already absolute (`base + disp + end-of-field`), so the
                // value to match is the site's own arithmetic rather than the raw displacement.
                let site_end = self.base + (f.offset + f.width) as u64;
                if value == site_end.wrapping_add(f.placeholder) {
                    return Some(target);
                }
                // An unlinked `call rel32` most often holds -4 or 0; accept the operand that
                // decodes into this instruction's own footprint as the relocated one.
                if value >= insn_addr && value < insn_addr + insn_len as u64 + 8 {
                    return Some(target);
                }
            } else {
                let masked = if size >= 8 { value } else { value & ((1u64 << (size * 8)) - 1) };
                if masked == f.placeholder || value == f.placeholder {
                    // Additive OMF semantics (see `relinked_bytes`): the linked value is the
                    // target PLUS the field's addend, so the differ must display the same sum
                    // or every `symbol ± k` operand prints as `symbol` and diffs as a phantom
                    // neighboring-global access.
                    return Some(target.wrapping_add(f.placeholder));
                }
            }
        }
        None
    }
}

/// Extract `name`'s code from an OMF object, positioned at `base`.
///
/// The function's extent is taken from the object's own symbol table: it starts at the public
/// symbol and runs to the next public in the same segment, or the segment's end. Nothing is
/// inferred from the original's length — an emitted function that is longer or shorter than the
/// original is a result, not a parameter.
pub fn load_object_function(
    data: &[u8],
    name: &str,
    base: u64,
    resolver: &dyn SymbolResolver,
) -> Result<Candidate, String> {
    let module = omf::parse_module(data);
    let (seg_idx, start) = locate(&module, name)?;
    let seg = module.segments.get(seg_idx - 1).ok_or("segment index out of range")?;

    // The function ends where the next public symbol in this segment begins.
    let end = module
        .publics
        .iter()
        .filter(|(_, si, off)| *si == seg_idx && (*off as usize) > start)
        .map(|(_, _, off)| *off as usize)
        .min()
        .unwrap_or(seg.data.len())
        .min(seg.data.len());
    let bytes = seg.data[start..end].to_vec();

    let mut fixups = Vec::new();
    let mut unresolved = Vec::new();
    for f in &module.fixups {
        if f.segment != seg_idx {
            continue;
        }
        let width = fixup_width(f.location, f.wide);
        if width == 0 || f.offset < start || f.offset + width > end {
            continue;
        }
        let offset = f.offset - start;
        let mut placeholder = 0u64;
        for i in 0..width.min(8) {
            placeholder |= (bytes[offset + i] as u64) << (8 * i);
        }
        let symbol = match f.target {
            FixupTarget::External(i) => module.externals.get(i - 1).cloned(),
            _ => None,
        };
        let mut local_data = None;
        let resolved = match &symbol {
            Some(s) => match resolver.address_of(s) {
                Some(a) => Some(a.wrapping_add(f.displacement)),
                None => {
                    unresolved.push(s.clone());
                    None
                }
            },
            // A module-local fixup denotes segment offset `displacement + addend` (OMF
            // additive: the field's content joins the sum). Inside the function's extent it
            // is a self-reference — the address is `base` plus the offset FROM THE
            // FUNCTION's start (`start` need not be 0: a switch's jump table precedes the
            // public). Outside the extent it references module-local DATA (that table),
            // which has no meaning at the original's addresses until `resolve_tables`
            // proves correspondence — record the referenced offset and leave it unresolved.
            None => {
                let referenced = f.displacement.wrapping_add(placeholder);
                let fun = (start as u64)..(end as u64);
                if fun.contains(&referenced) {
                    // relinked_bytes adds the addend back, so carry displacement only.
                    Some(base.wrapping_add(f.displacement).wrapping_sub(start as u64))
                } else {
                    local_data = Some(referenced);
                    None
                }
            }
        };
        fixups.push(CandFixup { offset, width, symbol, self_relative: f.self_relative, resolved, placeholder, local_data });
    }

    // Collect the jump tables the object carries OUTSIDE the function's extent: runs of
    // consecutive 4-byte module-local fixups whose targets all land INSIDE the extent (a
    // switch's table dispatches into its own function). Entry targets are recorded relative
    // to the function start, making them layout-independent for `resolve_tables`.
    let mut entry_sites: Vec<(u64, u64)> = Vec::new(); // (segment offset, target seg offset)
    for f in &module.fixups {
        if f.segment != seg_idx || f.self_relative || fixup_width(f.location, f.wide) != 4 {
            continue;
        }
        if matches!(f.target, FixupTarget::External(_)) {
            continue;
        }
        if f.offset + 4 <= start || f.offset >= end {
            let mut ph = 0u64;
            for i in 0..4 {
                if let Some(b) = seg.data.get(f.offset + i) {
                    ph |= (*b as u64) << (8 * i);
                }
            }
            entry_sites.push((f.offset as u64, f.displacement.wrapping_add(ph)));
        }
    }
    entry_sites.sort_unstable();
    let mut tables: Vec<CandTable> = Vec::new();
    for (off, target) in entry_sites {
        let in_fun = target >= start as u64 && target < end as u64;
        match tables.last_mut() {
            Some(t) if off == t.seg_off + 4 * t.entries_fnrel.len() as u64 && in_fun => {
                t.entries_fnrel.push(target - start as u64);
            }
            _ if in_fun => tables.push(CandTable { seg_off: off, entries_fnrel: vec![target - start as u64] }),
            _ => {}
        }
    }

    Ok(Candidate { bytes, base, fixups, unresolved, tables })
}

/// OMF `LLLL` location code → field width. Mirrors the loader's own reading of the same field.
fn fixup_width(location: u8, wide: bool) -> usize {
    match location {
        0 => 1,
        1 | 5 if wide => 4,
        1 | 2 | 5 => 2,
        3 | 4 | 9 | 13 => 4,
        _ => 0,
    }
}

/// Find `name`'s segment and offset, tolerating the leading-underscore convention and falling
/// back to the first code segment when the object publishes nothing under that name.
fn locate(module: &OmfModule, name: &str) -> Result<(usize, usize), String> {
    // Underscores are decoration, on either end: Watcom's register convention APPENDS one
    // (`FUN_00069980_`), its cdecl PREPENDS one. The old test trimmed only the front, so the
    // appended form never matched here -- and the fallback below then "succeeded" at offset 0,
    // which meant the caller's own trailing-underscore retry (see `verify`) never ran.
    let stripped = name.trim_matches('_');
    for (sym, seg, off) in &module.publics {
        if sym == name || sym.trim_matches('_') == stripped {
            return Ok((*seg, *off as usize));
        }
    }
    for (i, seg) in module.segments.iter().enumerate() {
        if seg.is_code() && !seg.data.is_empty() {
            // The offset-0 guess is for objects that publish no code symbol at all. When the
            // code segment HAS publics and none matched, guessing is how a function with a
            // leading jump table got compared against its own table: Watcom emits a switch's
            // table at the FRONT of `_TEXT`, the function's public sits past it (offset 32 on
            // WAR2's FUN_00069980), and the guessed slice [0..first_public] was 8 relocated
            // table words decoded as code -- similarity 0.009 against a candidate that was
            // never the function. A miss among named symbols is an error, not a guess.
            if module.publics.iter().any(|(_, si, _)| *si == i + 1) {
                return Err(format!("no public matching `{name}` in the code segment"));
            }
            return Ok((i + 1, 0));
        }
    }
    Err(format!("no public `{name}` and no code segment"))
}
