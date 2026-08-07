/* Dump, per instruction of a function, exactly what Ghidra's FID hasher consumes:
 * the instruction mask, and per operand the value mask, the operand type flags, and
 * getOpObjects(). The diagnostic instrument for a hash-parity divergence.
 *
 * Run: analyzeHeadless <proj> p -import <bin> -scriptPath oracle/fid \
 *        -postScript FidOperandDump.java <out-file> <minHex> <maxHex>
 * @category FunctionID
 */
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

public class FidOperandDump extends GhidraScript {
	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		long min = Long.parseLong(args[1], 16);
		long max = Long.parseLong(args[2], 16);
		Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(min);
		try (PrintWriter out = new PrintWriter(args[0])) {
			while (a != null && a.getOffset() <= max) {
				Instruction insn = getInstructionAt(a);
				if (insn == null) { out.println(a + " <no instruction>"); break; }
				InstructionPrototype proto = insn.getPrototype();
				Mask im = proto.getInstructionMask();
				out.printf("%x %-10s %-30s call=%b mask=%s%n", a.getOffset(), insn.getMnemonicString(),
					insn.toString(), insn.getFlowType().isCall(), im == null ? "null" : hex(im.getBytes()));
				for (int i = 0; i < insn.getNumOperands(); ++i) {
					Mask om = proto.getOperandValueMask(i);
					int t = insn.getOperandType(i);
					StringBuilder objs = new StringBuilder();
					for (Object o : insn.getOpObjects(i)) {
						if (objs.length() > 0) objs.append(", ");
						if (o instanceof Scalar) objs.append("Scalar(" + ((Scalar) o).getSignedValue() + ")");
						else if (o instanceof Register) objs.append("Register(" + ((Register) o).getOffset() + ")");
						else if (o instanceof Address) objs.append("Address(" + ((Address) o).getOffset() + ")");
						else objs.append(o.getClass().getSimpleName() + "[" + o + "]");
					}
					out.printf("      op%d scalar=%b addr=%b vmask=%s objs=[%s]%n", i,
						OperandType.isScalar(t), OperandType.isAddress(t),
						om == null ? "null" : hex(om.getBytes()), objs);
				}
				a = insn.getMaxAddress().add(1);
			}
		}
		println("FidOperandDump: done");
	}

	private static String hex(byte[] b) {
		StringBuilder s = new StringBuilder();
		for (byte x : b) s.append(String.format("%02x", x));
		return s.toString();
	}
}
