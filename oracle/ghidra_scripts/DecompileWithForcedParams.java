import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;

/// Decompile functions after FORCING a callee's parameter storage — the way to make Ghidra reason
/// about the same graph mosura reasons about.
///
/// Why this exists: the per-function oracle imports only the requested bytes, so a callee's
/// prototype is whatever the database default is (usually "no parameters"). A caller's dead-code
/// elimination then deletes every register the callee "does not read". When mosura, working on the
/// whole program, recovers a parameter the oracle could not, the two sides are decompiling
/// DIFFERENT functions and any structuring comparison between them is void. Forcing the parameter
/// removes that asymmetry, so a remaining difference is attributable to the decompiler.
///
/// Args: <va-list-file> [<callee-va>=<REG>[+<REG>...]]...
///   e.g. DecompileWithForcedParams vas.txt 63c35=EDX
/// Functions are created for every VA in the list BEFORE any decompilation, so intra-list calls
/// resolve; the forced prototypes are applied after that and before the first decompile.
///
/// Emits, per address: `===== FUNC <va> =====`, Ghidra's C, then its basic-block partition in the
/// same fields as `DumpBlocks.java` / mosura's `MOSURA_CFG=1`.
public class DecompileWithForcedParams extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: usage: DecompileWithForcedParams <va-list-file> [<va>=<REG>[+<REG>]]...");
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
        // Create every function first, so calls between them resolve to real functions rather than
        // to `func_0x...` placeholders with a default prototype.
        for (String va : vas) {
            Address a = toAddr(Long.parseLong(va, 16));
            if (getFunctionAt(a) == null) {
                disassemble(a);
                createFunction(a, "FUN_" + va);
            }
        }
        for (int i = 1; i < args.length; i++) {
            String[] kv = args[i].split("=", 2);
            if (kv.length != 2) {
                println("ERROR: bad forced-param spec: " + args[i]);
                continue;
            }
            Address a = toAddr(Long.parseLong(kv[0].trim(), 16));
            Function f = getFunctionAt(a);
            if (f == null) {
                println("ERROR: no function at " + kv[0] + " to force params on");
                continue;
            }
            List<Variable> params = new ArrayList<>();
            int n = 0;
            for (String rn : kv[1].split("\\+")) {
                Register reg = currentProgram.getRegister(rn.trim());
                if (reg == null) {
                    println("ERROR: unknown register " + rn);
                    continue;
                }
                params.add(new ParameterImpl("forced_" + (++n), new Undefined4DataType(), reg,
                        currentProgram));
            }
            f.setCustomVariableStorage(true);
            f.updateFunction(null, null, params,
                    Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);
            println("FORCED " + f.getName() + " " + f.getPrototypeString(true, false));
        }
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        for (String va : vas) {
            println("===== FUNC " + va + " =====");
            try {
                Function f = getFunctionAt(toAddr(Long.parseLong(va, 16)));
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
                for (String line : res.getDecompiledFunction().getC().split("\n", -1)) {
                    println(line);
                }
                HighFunction hf = res.getHighFunction();
                if (hf == null) continue;
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
                            + " start=0x" + bb.getStart() + " stop=0x" + bb.getStop()
                            + " ops=" + nops
                            + " ins=" + edges(bb, true) + " outs=" + edges(bb, false)
                            + " last=" + last);
                }
            } catch (Exception e) {
                println("ERROR: " + e);
            }
        }
        d.dispose();
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
