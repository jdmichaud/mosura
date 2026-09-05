import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/// Dump Ghidra's DECOMPILER DEBUG SAVEFILE (XML) for a list of virtual addresses, so that
/// `oracle/capture_trace <sleighdir> <file.xml> --trace` can replay the function under
/// OPACTION_DEBUG and report Ghidra's ACTUAL rule-firing sequence.
///
/// This is the subject counterpart of the datatest-fixture path in `scripts/trace-diff.sh`: that
/// script can only trace fixtures shipped with Ghidra, so any question about a subject function
/// ("which rule narrows this divide?") previously had to be answered by READING ruleaction.cc
/// and inferring. Inference was wrong more than once. This closes that gap — Ghidra names the
/// mechanism itself.
///
/// Args: <va-list-file> <out-dir> — one hex VA per line (no 0x prefix); writes <out-dir>/<va>.xml.
/// Driven by `scripts/ghidra-decompile-subject.sh` via POSTSCRIPT=DumpDecompDebug.java.
public class DumpDecompDebug extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("ERROR: usage: DumpDecompDebug <va-list-file> <out-dir>");
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
        File outDir = new File(args[1]);
        outDir.mkdirs();
        // Optional `data=<hexstart>:<hexlen>` args — see DecompileFunctions.java; required for any
        // question involving ActionConstantPtr, whose symbol query needs the address in a block.
        for (int i = 2; i < args.length; i++) {
            if (!args[i].startsWith("data=")) continue;
            String[] kv = args[i].substring(5).split(":");
            long start = Long.parseLong(kv[0], 16);
            long len = Long.parseLong(kv[1], 16);
            currentProgram.getMemory().createInitializedBlock(
                "data" + kv[0], toAddr(start), len, (byte) 0, monitor, false);
        }
        for (String va : vas) {
            println("===== FUNC " + va + " =====");
            // A fresh interface per function: the debug savefile is armed per decompile, and
            // reusing one interface would append every function to the first file.
            DecompInterface d = new DecompInterface();
            try {
                // The debug savefile encodes the options block, so options MUST be set explicitly:
                // without this the writer NPEs on a null `options` (the non-debug path never
                // encodes them, which is why DecompileFunctions.java gets away without it).
                d.setOptions(new DecompileOptions());
                d.openProgram(currentProgram);
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
                File xml = new File(outDir, va + ".xml");
                d.enableDebug(xml);
                DecompileResults res = d.decompileFunction(f, 240, monitor);
                if (res == null || !res.decompileCompleted()) {
                    println("ERROR: decompile failed: "
                            + (res == null ? "null" : res.getErrorMessage()));
                    continue;
                }
                println("WROTE " + xml.getAbsolutePath() + " (" + xml.length() + " bytes)");
            } catch (Exception e) {
                println("ERROR: " + e);
            } finally {
                d.dispose();
            }
        }
    }
}
