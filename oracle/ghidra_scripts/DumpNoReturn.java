/* Dump every no-return function and every FindNoReturnFunctionsAnalyzer bookmark (which
 * carries the indicator reasons), after auto-analysis. Output file is the script argument.
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Bookmark;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Iterator;

public class DumpNoReturn extends GhidraScript {
    @Override
    public void run() throws Exception {
        String out = getScriptArgs().length > 0 ? getScriptArgs()[0] : "/tmp/noreturn.log";
        PrintWriter w = new PrintWriter(new FileWriter(out), true);
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.hasNoReturn()) {
                w.println("NORETURN " + Long.toHexString(f.getEntryPoint().getOffset()) + " " +
                    f.getName());
            }
        }
        Iterator<Bookmark> bit = currentProgram.getBookmarkManager().getBookmarksIterator();
        while (bit.hasNext()) {
            Bookmark b = bit.next();
            w.println("BOOKMARK " + Long.toHexString(b.getAddress().getOffset()) + " [" +
                b.getTypeString() + "/" + b.getCategory() + "] " + b.getComment());
        }
        w.println("# done");
    }
}
