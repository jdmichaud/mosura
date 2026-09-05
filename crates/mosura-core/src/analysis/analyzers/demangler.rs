//! GNU/Itanium C++ demangler analyzer — a port of the *behaviour* of Ghidra's
//! `GnuDemanglerAnalyzer` (`Ghidra/Features/GnuDemangler/.../GnuDemanglerAnalyzer.java`)
//! and `AbstractDemanglerAnalyzer`
//! (`Ghidra/Features/Base/.../app/plugin/core/analysis/AbstractDemanglerAnalyzer.java`).
//!
//! Ghidra's GNU demangler is **not** a Java grammar: `GnuDemangler` shells out
//! (`GnuDemanglerNativeProcess`) to the bundled native `demangler_gnu_v2_41` binary
//! (libiberty cp-demangle, binutils 2.41 — GPL, under `GPL/DemanglerGnu/`), and the Java
//! side (`GnuDemanglerParser`) only *re-parses* the native output string into a
//! `DemangledObject` (namespace + name + signature). Because mosura is Apache-2.0 and
//! libiberty is GPL, we cannot port or link it; instead we wrap the pure-Rust, Apache-2.0
//! `cpp_demangle` crate (gimli-rs — same org as `object`) as the cp-demangle equivalent,
//! and reproduce the parser's "take the symbol's simple name" step ourselves (no
//! hand-rolled mangling grammar — `cpp_demangle` owns the grammar).
//!
//! What the analyzer does (`AbstractDemanglerAnalyzer.demangleSymbols`): iterate the
//! primary symbols, skip the un-demanglable ones (`skipSymbol`: DEFAULT-source, external
//! not in a Library, non-global namespace), demangle the name, and `DemangledObject.applyTo`
//! it. `applyTo` → `applyDemangledName` (`DemangledObject.java`) creates the demangled
//! symbol in its namespace and makes it primary (`SetLabelPrimaryCmd`) — for a function it
//! renames the function; the **original mangled name is retained as a secondary label**.
//! The snapshot dumps `Symbol.getName()` (the simple name), so the namespace is implicit.

use crate::analysis::program::{Program, SymbolType};

/// Apply demangled names to the program's symbols (Ghidra `GnuDemanglerAnalyzer.added`).
///
/// For each primary, non-default symbol whose name is an Itanium-mangled C++ name that
/// `cpp_demangle` can parse: rename the primary symbol (and, if a function, the function)
/// to the demangled simple name, and re-add the original mangled name as a secondary label
/// — exactly the net symbol state Ghidra's `DemangledObject.applyTo` leaves behind.
pub fn analyze(program: &mut Program) {
    let ram = program.default_space;

    // Collect candidates first (we mutate the symbol table below). A candidate is a primary
    // symbol in the default space whose name demangles to a distinct simple name. Ghidra's
    // `skipSymbol` rejects DEFAULT-source names — mosura's synthetic `FUN_/DAT_/LAB_` names
    // (and any non-`_Z` name) simply fail to demangle, so the demangle gate subsumes it.
    let candidates: Vec<(crate::decompile::space::Address, String, bool, String)> = program
        .symbol_table
        .symbols()
        .filter(|s| s.is_primary() && !s.is_external() && s.address().space == ram)
        .filter_map(|s| {
            let mangled = s.name().to_string();
            let simple = demangle_simple(&mangled)?;
            if simple == mangled {
                return None; // not actually mangled / no change
            }
            Some((s.address(), mangled, s.symbol_type() == SymbolType::Function, simple))
        })
        .collect();

    for (addr, mangled, is_function, simple) in candidates {
        // `SetLabelPrimaryCmd`: the demangled name becomes the primary symbol …
        program.symbol_table.rename_primary(addr, &simple);
        // … and the original mangled name is kept as a secondary (non-primary) label.
        program.symbol_table.add_with_primary(addr, &mangled, SymbolType::Label, false);
        // For a function, the demangled name is applied to the function too (the snapshot's
        // `func`/`entry` lines read the function / primary-symbol name).
        if is_function {
            program.function_manager.set_name(addr, &simple);
        }
    }
}

/// Demangle a mangled Itanium C++ name to its **simple** name (the trailing scope
/// component), or `None` if it isn't a C++ mangled name `cpp_demangle` can parse.
///
/// `cpp_demangle` owns the Itanium grammar; we ask it for the qualified name without the
/// parameter list / return type (`DemangleOptions::no_params().no_return_type()`), e.g.
/// `_ZN8geometry4areaEii` → `geometry::area`, then keep the last `::`-separated component
/// (`area`) at template/paren depth 0 — the simple `Symbol.getName()` Ghidra applies.
fn demangle_simple(mangled: &str) -> Option<String> {
    // Itanium C++ names start with `_Z` (or the `_GLOBAL_`/`__` special forms cp-demangle
    // also accepts). `cpp_demangle::Symbol::new` rejects everything else, but gate up front
    // so a plain C name like `_start` is never even offered to the parser.
    if !mangled.starts_with("_Z") && !mangled.starts_with("_GLOBAL_") {
        return None;
    }
    let sym = cpp_demangle::Symbol::new(mangled).ok()?;
    let opts = cpp_demangle::DemangleOptions::new().no_params().no_return_type();
    let qualified = sym.demangle(&opts).ok()?;
    Some(last_scope_component(&qualified))
}

/// The last `::`-separated component of a qualified name, scanning at template/paren
/// nesting depth 0 so `Foo<A::B>::method` → `method` (not `B>::method`) and a bare
/// `compute` → `compute`.
fn last_scope_component(qualified: &str) -> String {
    let bytes = qualified.as_bytes();
    let mut depth = 0i32;
    let mut name_start = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'<' | b'(' | b'[' => depth += 1,
            b'>' | b')' | b']' => depth -= 1,
            b':' if depth == 0 && i + 1 < bytes.len() && bytes[i + 1] == b':' => {
                name_start = i + 2;
                i += 1; // skip the second ':'
            }
            _ => {}
        }
        i += 1;
    }
    qualified[name_start..].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangles_corpus_names_to_simple() {
        // The cppsym.elf fixture's mangled names → Ghidra's applied simple names.
        assert_eq!(demangle_simple("_ZN8geometry4areaEii").as_deref(), Some("area"));
        assert_eq!(demangle_simple("_ZN8geometry4areaEd").as_deref(), Some("area"));
        assert_eq!(demangle_simple("_Z7computeP5Shapei").as_deref(), Some("compute"));
        assert_eq!(demangle_simple("_ZNK5Shape9perimeterEi").as_deref(), Some("perimeter"));
    }

    #[test]
    fn leaves_unmangled_names_alone() {
        assert_eq!(demangle_simple("_start"), None);
        assert_eq!(demangle_simple("main"), None);
        assert_eq!(demangle_simple("FUN_00401020"), None);
        assert_eq!(demangle_simple("__bss_start"), None);
    }

    #[test]
    fn last_scope_component_handles_templates() {
        assert_eq!(last_scope_component("area"), "area");
        assert_eq!(last_scope_component("geometry::area"), "area");
        assert_eq!(last_scope_component("ns::Foo<a::b>::method"), "method");
    }
}
