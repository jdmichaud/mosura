/* Pre-script for a raw CP/M .COM imported via BinaryLoader (-loader-baseAddr 0x100,
 * -processor z80:LE:16:default): mark the CP/M entry point at 0x100 (the TPA start where
 * CP/M begins execution). Auto-analysis then disassembles + discovers functions from it;
 * with -noanalysis this is the pure loader-stage state (block + pspec RST/NMI defaults +
 * the .COM entry). This is the manual processor/base/entry setup a raw .COM needs — the
 * loader-side knowledge mosura's `load_com` encapsulates. */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class SetComEntry extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address entry = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0x100);
        addEntryPoint(entry);
    }
}
