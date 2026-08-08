/* Dump Ghidra's VERBOSE SLEIGH resolution for one instruction: the constructors it matched (by
 * .sinc line) and the instruction/context pattern blocks it accumulated.
 *
 * Answers "which pattern contributes this mask bit?" — the question you hit when mosura's
 * instruction mask differs from Ghidra's by a bit or two and the operand value masks agree, so
 * the divergence must be in the accumulated PATTERN rather than in operand handling.
 *
 * Run: analyzeHeadless <proj> p -import <bin> -scriptPath oracle/fid \
 *        -postScript FidPatternDump.java <out-file> <addrHex>
 * @category FunctionID
 */
import java.io.PrintWriter;

import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger.SleighDebugMode;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class FidPatternDump extends GhidraScript {
	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		Address a = currentProgram.getAddressFactory().getDefaultAddressSpace()
				.getAddress(Long.parseLong(args[1], 16));
		try (PrintWriter out = new PrintWriter(args[0])) {
			Instruction insn = getInstructionAt(a);
			out.printf("%s  %s%n", a, insn == null ? "<no instruction>" : insn.toString());

			SleighDebugLogger log =
				new SleighDebugLogger(currentProgram, a, SleighDebugMode.VERBOSE);
			out.println("--- constructors matched (file:line) ---");
			for (String c : log.getConstructorLineNumbers()) {
				out.println("  " + c);
			}
			out.println("--- instruction mask ---");
			out.println("  " + log.getFormattedInstructionMask(-1));
			for (int i = 0; i < log.getNumOperands(); i++) {
				out.printf("  op%d %s%n", i, log.getFormattedInstructionMask(i));
			}
			out.println("--- verbose resolution log ---");
			out.println(log.toString());
		}
		println("FidPatternDump: done");
	}
}
