/* Dump the converged Program state as a mosura analysis snapshot (A0).
 *
 * The offline, version-pinned oracle for the analysis port: run by analyzeHeadless
 * as a -postScript after auto-analysis, it emits the v1 snapshot format parsed by
 * crate::analysis::snapshot (docs/analysis-port-plan.md §3). Equivalent to the
 * GhidraMCP capture, but reproducible without a running server and able to run
 * under a controlled analyzer set (a -preScript) for stage-by-stage gating.
 *
 * Usage:
 *   analyzeHeadless <proj_dir> <proj> -import <binary> \
 *     -scriptPath oracle/ghidra_scripts -postScript DumpAnalysisSnapshot.java <out.snapshot> \
 *     -deleteProject
 *
 * v1 sections: loaded memory map (block) + recovered functions (func). Blocks are
 * filtered to the default (loaded) address space, matching the MCP capture — the
 * file-overlay metadata blocks (.comment/.symtab/...) live in the OTHER space and
 * are excluded.
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

import java.io.PrintWriter;

public class DumpAnalysisSnapshot extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("DumpAnalysisSnapshot: missing output path argument");
            return;
        }
        String outPath = args[0];

        String lang = currentProgram.getLanguageID().getIdAsString();
        String cspec = currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString();
        long base = currentProgram.getImageBase().getOffset();
        String endian = currentProgram.getLanguage().isBigEndian() ? "big" : "little";
        int addrBits = currentProgram.getLanguage().getLanguageDescription().getSize();
        AddressSpace defaultSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();

        try (PrintWriter w = new PrintWriter(outPath)) {
            w.printf("# mosura-analysis-snapshot v1 lang=%s compiler=%s base=%08x endian=%s addrsize=%d%n",
                    lang, cspec, base, endian, addrBits);
            w.printf("# oracle=ghidra-%s via=analyzeHeadless source=%s%n",
                    getGhidraVersion(), currentProgram.getName());

            // Loaded memory map: blocks in the default address space (skip OTHER-space
            // file-overlay metadata blocks, which print as `name::offset`).
            for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
                Address start = b.getStart();
                if (!start.getAddressSpace().equals(defaultSpace)) {
                    continue;
                }
                w.printf("block %08x %08x %s%n", start.getOffset(), b.getEnd().getOffset(), b.getName());
            }

            // Recovered functions (address order; includes thunks + external locations).
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                w.printf("func %08x %s%n", f.getEntryPoint().getOffset(), f.getName());
            }

            // External entry points (Ghidra getExternalEntryPointIterator), address-sorted.
            ghidra.program.model.symbol.SymbolTable st = currentProgram.getSymbolTable();
            java.util.List<Address> entries = new java.util.ArrayList<>();
            ghidra.program.model.address.AddressIterator eit = st.getExternalEntryPointIterator();
            while (eit.hasNext()) entries.add(eit.next());
            java.util.Collections.sort(entries);
            for (Address a : entries) {
                if (!a.getAddressSpace().equals(defaultSpace)) continue;
                ghidra.program.model.symbol.Symbol s = st.getPrimarySymbol(a);
                w.printf("entry %08x %s%n", a.getOffset(), s != null ? s.getName() : "");
            }

            // Defined symbols in the default space (loader labels/functions/data).
            ghidra.program.model.symbol.SymbolIterator sit = st.getDefinedSymbols();
            while (sit.hasNext()) {
                ghidra.program.model.symbol.Symbol s = sit.next();
                Address a = s.getAddress();
                if (!a.getAddressSpace().equals(defaultSpace)) continue;
                w.printf("sym %08x %s %s%n", a.getOffset(), s.getName(), s.getSymbolType());
            }

            // References within the default space (memory→memory): the analysis port's
            // flow + data references. Filtered to default-space endpoints (skip stack,
            // register, external, const-space refs) and deduped on (from, to, type).
            ghidra.program.model.symbol.ReferenceManager rm = currentProgram.getReferenceManager();
            java.util.TreeSet<String> refs = new java.util.TreeSet<>();
            ghidra.program.model.address.AddressIterator rsit =
                    rm.getReferenceSourceIterator(currentProgram.getMemory(), true);
            while (rsit.hasNext()) {
                Address from = rsit.next();
                if (!from.getAddressSpace().equals(defaultSpace)) continue;
                for (ghidra.program.model.symbol.Reference r : rm.getReferencesFrom(from)) {
                    Address to = r.getToAddress();
                    if (!to.getAddressSpace().equals(defaultSpace)) continue;
                    refs.add(String.format("ref %08x %08x %s",
                            from.getOffset(), to.getOffset(), r.getReferenceType().getName()));
                }
            }
            for (String line : refs) w.println(line);
        }
        println("DumpAnalysisSnapshot: wrote " + outPath);
    }
}
