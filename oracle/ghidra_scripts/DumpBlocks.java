import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;

/// Dump GHIDRA'S BASIC-BLOCK PARTITION for a list of virtual addresses — the ground truth for the
/// question "do we cut the CFG where Ghidra cuts it?".
///
/// The C-only oracle (`DecompileFunctions.java`) cannot answer that: by the time you see C, the
/// partition has been consumed by structuring, so a granularity divergence shows up only as its
/// third-order symptom (extra `goto`s, an uncollapsed graph). `HighFunction.getBasicBlocks()` is
/// the same `BlockBasic` list Ghidra's `CollapseStructure` runs on, so this is the exact
/// counterpart of mosura's `MOSURA_CFG=1` instrument.
///
/// Args: <va-list-file> — one hex VA per line (no 0x prefix). Emits, per address:
///   ===== FUNC <va> =====
///   CFG <name> nblocks=<n>
///   CFG blk<i> start=<addr> stop=<addr> ops=<n> ins=[..] outs=[..] last=<opcode>
///
/// Driven by `scripts/ghidra-decompile-war2.sh` with `GHIDRA_POSTSCRIPT=DumpBlocks.java`.
public class DumpBlocks extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: usage: DumpBlocks <va-list-file>");
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
                HighFunction hf = res.getHighFunction();
                if (hf == null) {
                    println("ERROR: no high function");
                    continue;
                }
                ArrayList<PcodeBlockBasic> bbs = hf.getBasicBlocks();
                println("CFG " + f.getName() + " nblocks=" + bbs.size());
                for (PcodeBlockBasic bb : bbs) {
                    int nops = 0;
                    String last = "";
                    for (Iterator<PcodeOp> it = bb.getIterator(); it.hasNext();) {
                        PcodeOp op = it.next();
                        nops++;
                        last = op.getMnemonic();
                    }
                    println("CFG blk" + bb.getIndex()
                            + " start=" + hex(bb.getStart()) + " stop=" + hex(bb.getStop())
                            + " ops=" + nops
                            + " ins=" + edges(bb, true) + " outs=" + edges(bb, false)
                            + " last=" + last);
                }
                // Every p-code op, block by block: the partition alone says where the cuts are,
                // this says what is inside each piece (which is what decides whether a block can
                // serve as a condition — see BlockBasic::isComplex).
                for (PcodeBlockBasic bb : bbs) {
                    for (Iterator<PcodeOp> it = bb.getIterator(); it.hasNext();) {
                        PcodeOp op = it.next();
                        println("OP blk" + bb.getIndex() + " " + op.getSeqnum() + " " + op);
                    }
                }
            } catch (Exception e) {
                println("ERROR: " + e);
            }
        }
        d.dispose();
    }

    private static String hex(Address a) {
        return a == null ? "-" : "0x" + a.toString(false);
    }

    private static String edges(PcodeBlockBasic bb, boolean in) {
        StringBuilder sb = new StringBuilder("[");
        int n = in ? bb.getInSize() : bb.getOutSize();
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(", ");
            sb.append((in ? bb.getIn(i) : bb.getOut(i)).getIndex());
        }
        return sb.append("]").toString();
    }
}
