/* Dump every function's FID hash quad, for use as a byte-exact oracle for mosura's
 * port of MessageDigestFidHasher (docs/fid-port-plan.md Stage 3).
 *
 * Emits, per function, the ENTRY, the NAME, the BODY ADDRESS RANGES, and the quad.
 * The ranges matter: they let mosura hash exactly the instruction set Ghidra hashed,
 * so the comparison measures the HASHER and not any difference in function-boundary
 * recovery. A boundary difference is a real thing to chase, but it is not this gate.
 *
 * Run:  analyzeHeadless <proj-dir> <proj> -import <binary> \
 *         -scriptPath oracle/fid -postScript FidHashDump.java <out-dir>
 *
 * Writes <out-dir>/<programName>.fidhash, so a single headless run may import a whole
 * directory of binaries and emit one golden per program.
 *
 * @category FunctionID
 */
import java.io.File;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class FidHashDump extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			println("FidHashDump: expected an output directory argument");
			return;
		}
		File outDir = new File(args[0]);
		outDir.mkdirs();
		File outFile = new File(outDir, currentProgram.getName() + ".fidhash");

		FidService service = new FidService();
		try (PrintWriter out = new PrintWriter(outFile)) {
			out.println("# FID hash quads emitted by Ghidra's own FidService.hashFunction");
			out.println("# language=" + currentProgram.getLanguageID());
			out.println("# compilerSpec=" + currentProgram.getCompilerSpec().getCompilerSpecID());
			out.println("# shortHashCodeUnitLength=" + service.getShortHashCodeUnitLength());
			out.println("# columns: entry name codeUnitSize fullHash specificHashAddSize "
				+ "specificHash ranges(min-max[,min-max]...)");

			FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
			int emitted = 0;
			int skipped = 0;
			for (Function function : functions) {
				if (function.isExternal() || function.isThunk()) {
					++skipped;
					continue;
				}
				FidHashQuad quad = service.hashFunction(function);
				if (quad == null) {
					// Below the short-hash floor: Ghidra declines to hash it.
					++skipped;
					continue;
				}

				StringBuilder ranges = new StringBuilder();
				for (AddressRange range : function.getBody().getAddressRanges(true)) {
					if (ranges.length() > 0) {
						ranges.append(',');
					}
					ranges.append(Long.toHexString(range.getMinAddress().getOffset()));
					ranges.append('-');
					ranges.append(Long.toHexString(range.getMaxAddress().getOffset()));
				}

				out.printf("%x %s %d %016x %d %016x %s%n",
					function.getEntryPoint().getOffset(),
					function.getName(),
					quad.getCodeUnitSize(),
					quad.getFullHash(),
					quad.getSpecificHashAdditionalSize(),
					quad.getSpecificHash(),
					ranges);
				++emitted;
			}
			out.println("# emitted=" + emitted + " skipped=" + skipped);
			println("FidHashDump: " + currentProgram.getName() + " emitted " + emitted + ", skipped " + skipped);
		}
	}
}
