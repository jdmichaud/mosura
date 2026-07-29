import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/// Decompile a list of virtual addresses and print each function's C, delimited so a driver can
/// split the output per function.
///
/// Args: <va-list-file> — one hex VA per line (no 0x prefix). Emits, per address:
///   ===== FUNC <va> =====
///   <Ghidra's C, or an ERROR line>
///
/// Used by `scripts/ghidra-decompile-war2.sh` to get Ghidra's own rendering of WAR2 functions,
/// which the DOS/4GW-LE loader otherwise makes impossible (see that script's header).
public class DecompileFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: usage: DecompileFunctions <va-list-file>");
            return;
        }
        List<String> vas = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new FileReader(args[0]))) {
            String line;
            while ((line = r.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) vas.add(line);
            }
        }
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        for (String va : vas) {
            println("===== FUNC " + va + " =====");
            try {
                Address a = toAddr(Long.parseLong(va, 16));
                Function f = getFunctionAt(a);
                if (f == null) {
                    disassemble(a);
                    f = createFunction(a, "FUN_" + va);
                }
                if (f == null) {
                    println("ERROR: no function at " + va);
                    continue;
                }
                DecompileResults res = d.decompileFunction(f, 120, monitor);
                if (res == null || !res.decompileCompleted()) {
                    println("ERROR: decompile failed: "
                            + (res == null ? "null" : res.getErrorMessage()));
                    continue;
                }
                // One println per line: Ghidra tags only the FIRST line of a multi-line println
                // with its log marker, so a whole-block print loses every subsequent line to the
                // driver's filter.
                for (String line : res.getDecompiledFunction().getC().split("\n", -1)) {
                    println(line);
                }
            } catch (Exception e) {
                println("ERROR: " + e);
            }
        }
        d.dispose();
    }
}
