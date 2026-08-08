/* Answer ONE question: when Ghidra's buildOperandMask hits an empty mask, does its
 * `mainSubGroups.get(sym.getName())` fallback FIND a group or MISS?
 *
 * mosura's port applies that fallback unconditionally, which is the whole R7 hash-parity gap
 * (AArch64 `mov x29,sp`: Ghidra keeps the Rn bits in the instruction mask, we hand them to the
 * operand). Ghidra's fallback is name-keyed and CAN miss, and `mainSubGroups` is populated only
 * for named groups whose parent is the main group (SleighDebugLogger.startPatternGroup:812-818).
 * Everything here is private, so it is read by reflection.
 *
 * Run: analyzeHeadless <proj> p -import <bin> -scriptPath oracle/fid \
 *        -postScript FidMaskGroupDump.java <out-file> <addrHex>
 * @category FunctionID
 */
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.util.Map;

import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger.SleighDebugMode;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.listing.Instruction;

public class FidMaskGroupDump extends GhidraScript {
	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		Address a = currentProgram.getAddressFactory().getDefaultAddressSpace()
				.getAddress(Long.parseLong(args[1], 16));
		try (PrintWriter out = new PrintWriter(args[0])) {
			Instruction insn = getInstructionAt(a);
			out.printf("%s  %s%n", a, insn == null ? "<no instruction>" : insn.toString());
			if (insn == null) {
				return;
			}
			SleighDebugLogger log =
				new SleighDebugLogger(currentProgram, a, SleighDebugMode.MASKS_ONLY);

			out.printf("instructionMask = %s%n", hex(log.getInstructionMask()));
			for (int i = 0; i < log.getNumOperands(); i++) {
				out.printf("  op%d valueMask = %s%n", i, hex(log.getOperandValueMask(i)));
			}

			// The two private members that decide whether the fallback fires.
			Map<?, ?> groups = (Map<?, ?>) get(log, "mainSubGroups");
			out.printf("mainSubGroups keys = %s%n", groups.keySet());

			InstructionPrototype proto = insn.getPrototype();
			for (int i = 0; i < log.getNumOperands(); i++) {
				String name = operandName(proto, i);
				out.printf("  op%d symbolName = %s   inMainSubGroups = %s%n",
					i, name, name == null ? "?" : groups.containsKey(name));
			}
		}
		println("FidMaskGroupDump: done");
	}

	/** The operand symbol's name — the exact key buildOperandMask looks up. */
	private String operandName(InstructionPrototype proto, int i) {
		try {
			java.lang.reflect.Method m = proto.getClass()
					.getDeclaredMethod("getOperandSymbol", int.class,
						ghidra.program.model.mem.MemBuffer.class,
						ghidra.program.model.lang.ProcessorContext.class);
			m.setAccessible(true);
			Object sym = m.invoke(proto, i, null, null);
			if (sym == null) {
				return null;
			}
			java.lang.reflect.Method n = sym.getClass().getMethod("getName");
			return (String) n.invoke(sym);
		}
		catch (Exception e) {
			return "<" + e.getClass().getSimpleName() + ": " + e.getMessage() + ">";
		}
	}

	private static Object get(Object target, String field) throws Exception {
		Field f = target.getClass().getDeclaredField(field);
		f.setAccessible(true);
		return f.get(target);
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
