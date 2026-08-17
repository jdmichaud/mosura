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
        // Optional extra args `data=<hexstart>:<hexlen>`: create a zero-initialized data block,
        // so the program's global scope can resolve symbols for addresses the function references
        // (ActionConstantPtr's queryContainer, coreaction.cc:1152). Without a covering block the
        // action is structurally silent in this per-function recipe — the trace-blindness recorded
        // in docs/coverage.md's ActionConstantPtr row.
        for (int i = 1; i < args.length; i++) {
            if (args[i].startsWith("data=")) {
                String[] kv = args[i].substring(5).split(":");
                long start = Long.parseLong(kv[0], 16);
                long len = Long.parseLong(kv[1], 16);
                currentProgram.getMemory().createInitializedBlock(
                    "data" + kv[0], toAddr(start), len, (byte) 0, monitor, false);
            } else if (args[i].startsWith("bytes=")) {
                // Real content, not zeros: `bytes=<hexaddr>:<hexbytes>` — needed when the
                // question depends on VALUES (a jump table between functions, string data).
                String[] kv = args[i].substring(6).split(":");
                long start = Long.parseLong(kv[0], 16);
                byte[] bs = new byte[kv[1].length() / 2];
                for (int j = 0; j < bs.length; j++)
                    bs[j] = (byte) Integer.parseInt(kv[1].substring(2 * j, 2 * j + 2), 16);
                var blk = currentProgram.getMemory().createInitializedBlock(
                    "bytes" + kv[0], toAddr(start), bs.length, (byte) 0, monitor, false);
                currentProgram.getMemory().setBytes(toAddr(start), bs);
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
