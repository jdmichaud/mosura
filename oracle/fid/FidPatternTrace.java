/* Log EVERY pattern block Ghidra commits while resolving one instruction, with the group nesting.
 *
 * `FidPatternDump` prints the formatted resolution trace, which turned out not to account for all
 * the bits in the final instruction mask. This goes underneath it: it subclasses
 * SleighDebugLogger and overrides the four mutators the resolver calls, so every
 * addInstructionPattern / addContextPattern is recorded with the group it lands in and whether
 * that group was committed. The final mask is the OR of the committed instruction patterns, so
 * this attributes each mask bit to a specific call.
 *
 * Run: analyzeHeadless <proj> p -import <bin> -scriptPath oracle/fid \
 *        -postScript FidPatternTrace.java <out-file> <addrHex>
 * @category FunctionID
 */
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger.SleighDebugMode;
import ghidra.app.plugin.processors.sleigh.pattern.PatternBlock;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryBufferImpl;

public class FidPatternTrace extends GhidraScript {

	/** Collected outside the instance: the overrides fire during the SUPER constructor. */
	private static final List<String> LOG = new ArrayList<>();
	private static int depth = 0;

	/** Subclass that narrates what the resolver commits. */
	public static class Tracer extends SleighDebugLogger {
		public Tracer(MemBuffer buf, ghidra.program.model.lang.ProcessorContextView ctx,
				Language lang, SleighDebugMode mode) {
			super(buf, ctx, lang, mode);
		}

		@Override
		public void startPatternGroup(String name) {
			LOG.add(pad() + "startPatternGroup(" + name + ")");
			depth++;
			super.startPatternGroup(name);
		}

		@Override
		public void endPatternGroup(boolean commit) {
			depth--;
			LOG.add(pad() + "endPatternGroup(commit=" + commit + ")");
			super.endPatternGroup(commit);
		}

		@Override
		public void addInstructionPattern(int offset, PatternBlock maskvalue) {
			LOG.add(pad() + "addInstructionPattern(offset=" + offset + ") mask="
				+ maskHex(maskvalue));
			super.addInstructionPattern(offset, maskvalue);
		}

		@Override
		public void addContextPattern(PatternBlock maskvalue) {
			LOG.add(pad() + "addContextPattern() mask=" + maskHex(maskvalue));
			super.addContextPattern(maskvalue);
		}

		private static String pad() {
			return "  ".repeat(Math.max(0, depth));
		}

		/** PatternBlock's raw mask words, plus the byte offset it applies at. */
		private static String maskHex(PatternBlock b) {
			if (b == null) {
				return "null";
			}
			StringBuilder s = new StringBuilder();
			int[] mv = b.getMaskVector();
			if (mv == null) {
				s.append("(empty)");
			}
			else {
				for (int w : mv) {
					s.append(String.format("%08x ", w));
				}
			}
			return s.toString().trim() + " @byte" + b.getOffset();
		}
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		Address a = currentProgram.getAddressFactory().getDefaultAddressSpace()
				.getAddress(Long.parseLong(args[1], 16));
		LOG.clear();
		depth = 0;

		Tracer t = new Tracer(new MemoryBufferImpl(currentProgram.getMemory(), a),
			new DebugContext(), currentProgram.getLanguage(), SleighDebugMode.VERBOSE);

		try (PrintWriter out = new PrintWriter(args[0])) {
			Instruction insn = getInstructionAt(a);
			out.printf("%s  %s%n", a, insn == null ? "<none>" : insn.toString());
			out.println("--- committed pattern calls, in order ---");
			for (String l : LOG) {
				out.println(l);
			}
			out.println("--- resulting masks ---");
			out.println("  instruction " + hex(t.getInstructionMask()));
			for (int i = 0; i < t.getNumOperands(); i++) {
				out.printf("  op%d         %s%n", i, hex(t.getOperandValueMask(i)));
			}
		}
		println("FidPatternTrace: done");
	}

	/** Minimal context view over the program's own register values at that address. */
	private class DebugContext implements ghidra.program.model.lang.ProcessorContextView {
		@Override
		public ghidra.program.model.lang.Register getBaseContextRegister() {
			return currentProgram.getLanguage().getContextBaseRegister();
		}

		@Override
		public ghidra.program.model.lang.Register getRegister(String name) {
			return currentProgram.getLanguage().getRegister(name);
		}

		@Override
		public ghidra.program.model.lang.RegisterValue getRegisterValue(
				ghidra.program.model.lang.Register register) {
			return new ghidra.program.model.lang.RegisterValue(register);
		}

		@Override
		public List<ghidra.program.model.lang.Register> getRegisters() {
			return currentProgram.getLanguage().getRegisters();
		}

		@Override
		public java.math.BigInteger getValue(ghidra.program.model.lang.Register register,
				boolean signed) {
			return null;
		}

		@Override
		public boolean hasValue(ghidra.program.model.lang.Register register) {
			return false;
		}
	}

	private static String hex(byte[] b) {
		if (b == null) {
			return "null";
		}
		StringBuilder s = new StringBuilder();
		for (byte x : b) {
			s.append(String.format("%02x", x));
		}
		return s.toString();
	}
}
