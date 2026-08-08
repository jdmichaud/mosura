/* Mark the CP/M `.COM` entry point so auto-analysis has somewhere to start.
 *
 * A `.COM` is a flat image: no header, no sections, no symbol table, no entry record. Imported
 * with `-loader BinaryLoader -loader-baseAddr 0x100` Ghidra maps the bytes correctly but has no
 * reason to disassemble anything, so analysis finds zero functions and the FID capture emits zero
 * quads — silently, since "no functions" is not an error.
 *
 * The one thing the format guarantees is that execution begins at the load base (the Transient
 * Program Area, 0x100), which is exactly the knowledge `analysis/loader/com.rs` encodes on our
 * side. Marking it is enough; analysis follows the flow from there.
 *
 * Runs as a PRE-script, before auto-analysis:
 *   analyzeHeadless <proj> p -import x.com -processor z80:LE:16:default \
 *     -loader BinaryLoader -loader-baseAddr 0x100 \
 *     -preScript MarkComEntry.java -postScript FidHashDump.java <out>
 * @category FunctionID
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class MarkComEntry extends GhidraScript {
	@Override
	public void run() throws Exception {
		Address entry = currentProgram.getMinAddress();
		if (entry == null) {
			println("MarkComEntry: empty program");
			return;
		}
		addEntryPoint(entry);
		disassemble(entry);
		createFunction(entry, "entry");
		println("MarkComEntry: entry at " + entry);
	}
}
