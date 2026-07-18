// capture.cc — mosura's offline disasm + raw-p-code golden generator.
//
// Loads a Ghidra "binaryimage" fixture (the same <binaryimage arch="..."> format
// the decompiler datatests use) through the *exact* version-correct path the
// reference datatest runner uses (the "xml" ArchitectureCapability), then walks
// every <bytechunk> emitting, per instruction: address, raw bytes, disassembly,
// and the lifted raw p-code — in the normalized text form of testing-baseline.md §5.
//
// Links against Ghidra's decompiler library (libdecomp_dbg.a). No external Ghidra
// install is used: the SLEIGH specs come from the pinned source tree via <sleighdir>.
//
// IMPORTANT — ABI: this file MUST be compiled with the SAME preprocessor switches
// the linked libdecomp_dbg.a was built with, namely `-DCPUI_DEBUG -D__TERMINAL__`
// (Ghidra's Makefile `COMMANDLINE_DEBUG`; CPUI_DEBUG is the master debug switch that
// turns on OPACTION_DEBUG etc.). Those switches add instance members to core classes
// (Funcdata/PcodeOp/Action/Architecture...), so omitting them gives capture a SMALLER
// struct layout than the library's — a silent ABI mismatch that does not crash but
// reads/writes the wrong field offsets and corrupts decompilation (e.g. divopt's
// parameter inference: capture emitted `xunknown8 param_1` where canonical Ghidra
// `decomp_dbg` emits `uint8 *param_1`). The build is in scripts/setup-oracle.sh.
//
//   usage: capture <sleighdir> <fixture.xml>
//
#include "libdecomp.hh"
#include "architecture.hh"
#include "loadimage.hh"
#include "translate.hh"
#include "opcodes.hh"
#include "funcdata.hh"

#include <iostream>
#include <sstream>
#include <iomanip>

using namespace ghidra;
using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::ostringstream;

namespace {

// Capture the disassembled mnemonic/operands of one instruction.
class AsmEmit : public AssemblyEmit {
public:
  string mnem, body;
  void dump(const Address &, const string &m, const string &b) override {
    mnem = m;
    body = b;
  }
};

void print_vardata(std::ostream &s, VarnodeData &d) {
  s << '(' << d.space->getName() << ',';
  d.space->printOffset(s, d.offset);
  s << ',' << std::dec << d.size << ')';
}

// Collect the raw p-code ops of one instruction as normalized text lines.
class PcEmit : public PcodeEmit {
public:
  std::vector<string> ops;
  void dump(const Address &, OpCode opc, VarnodeData *outvar, VarnodeData *vars,
            int4 isize) override {
    ostringstream s;
    if (outvar != nullptr) {
      print_vardata(s, *outvar);
      s << " = ";
    }
    s << get_opname(opc);
    for (int4 i = 0; i < isize; ++i) {
      s << ' ';
      // For LOAD/STORE, input 0 is a space-id encoded as a raw AddrSpace*
      // pointer constant (non-deterministic across runs). Normalize to the
      // space name so goldens are stable.
      if ((opc == CPUI_LOAD || opc == CPUI_STORE) && i == 0) {
        AddrSpace *spc = reinterpret_cast<AddrSpace *>((uintp)vars[i].offset);
        s << "(space," << spc->getName() << ')';
      } else {
        print_vardata(s, vars[i]);
      }
    }
    ops.push_back(s.str());
  }
};

string hex_bytes(const uint1 *p, int4 n) {
  ostringstream s;
  for (int4 i = 0; i < n; ++i)
    s << std::setw(2) << std::setfill('0') << std::hex << (unsigned)p[i];
  return s.str();
}

} // namespace

int main(int argc, char **argv) {
  if (argc < 3 || argc > 5) {
    cerr << "usage: " << argv[0] << " <sleighdir> <fixture.xml> [--c | --ir [action]]" << endl;
    return 2;
  }
  const string sleighdir(argv[1]);
  const string fixture(argv[2]);

  startDecompilerLibrary(sleighdir.c_str());

  DocumentStorage store;
  const Element *root;
  try {
    root = store.openDocument(fixture)->getRoot();
  } catch (DecoderError &e) {
    // XML/marshal decode failures (xml.hh:297) are NOT derived from LowlevelError,
    // so they escape a plain catch(LowlevelError&) → terminate. Ghidra's own tools
    // (testfunction.cc:160, consolemain.cc:89) catch DecoderError alongside it; mirror that.
    cerr << "open " << fixture << ": " << e.explain << endl;
    return 1;
  } catch (LowlevelError &e) {
    cerr << "open " << fixture << ": " << e.explain << endl;
    return 1;
  }

  // Locate the <binaryimage> (bare, or wrapped in <decompilertest>).
  const Element *bin = nullptr;
  if (root->getName() == "binaryimage") {
    bin = root;
  } else {
    for (const Element *c : root->getChildren())
      if (c->getName() == "binaryimage") {
        bin = c;
        break;
      }
  }
  if (bin == nullptr) {
    cerr << "no <binaryimage> in " << fixture << endl;
    return 1;
  }

  Architecture *conf;
  try {
    store.registerTag(bin);
    ArchitectureCapability *capa = ArchitectureCapability::getCapability("xml");
    if (capa == nullptr)
      throw LowlevelError("missing xml architecture capability");
    conf = capa->buildArchitecture("capture", "", &cerr);
    conf->init(store);
  } catch (DecoderError &e) {
    cerr << "init: " << e.explain << endl;
    return 1;
  } catch (LowlevelError &e) {
    cerr << "init: " << e.explain << endl;
    return 1;
  }

  const Translate *trans = conf->translate;
  AddrSpace *code = trans->getDefaultCodeSpace();
  const string arch = bin->getAttributeValue("arch");

  // `--ir [action]` mode: run the decompiler pipeline until the start of the named action
  // (default `heritage`) and dump the intermediate IR (`Funcdata::printRaw`) — the
  // per-phase oracle for mosura's IR-parity gate (port-plan.md §3). With no action name,
  // breaks before `heritage` (i.e. the raw, post-followFlow p-code).
  if (argc >= 4 && string(argv[3]) == "--ir") {
    const string breakat = (argc >= 5) ? string(argv[4]) : string("heritage");
    uintb foff = 0;
    for (const Element *el : bin->getChildren()) {
      if (el->getName() == "bytechunk") {
        std::istringstream s(el->getAttributeValue("offset"));
        s >> std::hex >> foff;
        break;
      }
    }
    try {
      Address entry(code, foff);
      Funcdata *fd = conf->symboltab->getGlobalScope()->addFunction(entry, "func")->getFunction();
      Action *root = conf->allacts.getCurrent();
      root->reset(*fd);
      if (!breakat.empty() && breakat != "-")
        root->setBreakPoint(Action::break_start, breakat);
      root->perform(*fd); // runs until the breakpoint (partial, returns <0) or completion
      fd->printRaw(cout);
      cout << endl;
    } catch (DecoderError &e) {
      cerr << "ir: " << e.explain << endl;
      delete conf;
      return 1;
    } catch (LowlevelError &e) {
      cerr << "ir: " << e.explain << endl;
      delete conf;
      return 1;
    }
    delete conf;
    return 0;
  }

  // `--c` mode: decompile the function at the first bytechunk's offset and print
  // Ghidra's C (the reference for the mosura decompiler's structural comparator).
  if (argc >= 4 && string(argv[3]) == "--c") {
    uintb foff = 0;
    for (const Element *el : bin->getChildren()) {
      if (el->getName() == "bytechunk") {
        std::istringstream s(el->getAttributeValue("offset"));
        s >> std::hex >> foff;
        break;
      }
    }
    try {
      Address entry(code, foff);
      Funcdata *fd = conf->symboltab->getGlobalScope()->addFunction(entry, "func")->getFunction();
      conf->allacts.getCurrent()->reset(*fd);
      conf->allacts.getCurrent()->perform(*fd);
      conf->print->setOutputStream(&cout);
      conf->print->docFunction(fd);
      cout << endl;
    } catch (DecoderError &e) {
      cerr << "decompile: " << e.explain << endl;
      delete conf;
      return 1;
    } catch (LowlevelError &e) {
      cerr << "decompile: " << e.explain << endl;
      delete conf;
      return 1;
    }
    delete conf;
    return 0;
  }

  cout << "# lang=" << arch << " capture=v1" << endl;

  for (const Element *el : bin->getChildren()) {
    if (el->getName() != "bytechunk")
      continue;
    uintb off = 0;
    { std::istringstream s(el->getAttributeValue("offset")); s >> std::hex >> off; }
    int hexdigits = 0;
    for (char c : el->getContent())
      if (isxdigit((unsigned char)c))
        ++hexdigits;
    const uintb len = hexdigits / 2;

    Address addr(code, off);
    const Address end(code, off + len);
    while (addr < end) {
      AsmEmit ae;
      PcEmit pe;
      int4 ilen;
      try {
        trans->printAssembly(ae, addr);
        ilen = trans->oneInstruction(pe, addr);
      } catch (LowlevelError &e) {
        cout << std::setw(8) << std::setfill('0') << std::hex << addr.getOffset()
             << "  ; <decode error: " << e.explain << ">" << endl;
        break;
      }
      if (ilen <= 0)
        break;

      uint1 buf[32];
      const int4 nb = ilen < 32 ? ilen : 32;
      conf->loader->loadFill(buf, nb, addr);

      cout << std::setw(8) << std::setfill('0') << std::hex << addr.getOffset()
           << "  " << std::setw(0) << hex_bytes(buf, nb) << "  " << ae.mnem << ' '
           << ae.body << endl;
      for (const string &op : pe.ops)
        cout << "          pcode: " << op << endl;

      addr = addr + ilen;
    }
  }

  delete conf;
  return 0;
}
