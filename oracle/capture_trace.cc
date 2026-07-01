// capture_trace.cc — Ghidra's rule-application trace, for diffing against mosura (Task #2).
//
// Ghidra's OPACTION_DEBUG facility records every Rule/Action that modifies a PcodeOp, printing the
// op before and after via Funcdata::debugModPrint (action.cc ActionPool::processOp). This is the
// canonical "which rule fired where" oracle for mosura's rule pool.
//
// KEY BUILD FACT: OPACTION_DEBUG is *not* a separate switch you must add — types.h does
// `#ifdef CPUI_DEBUG  #define OPACTION_DEBUG`, so the machinery is already compiled into the
// existing libdecomp_dbg.a (built with COMMANDLINE_DEBUG = -DCPUI_DEBUG -D__TERMINAL__). This tool
// therefore links the SAME libdecomp_dbg.a as oracle/capture, with the SAME switches, and leaves
// the oracle's capture binary completely untouched (no separate library, no ABI divergence — the
// d5ae08d ABI lesson). It is a separate binary only so `capture` stays byte-for-byte as-is.
//
// The trace is enabled at runtime (ifacedecomp.cc IfcTraceEnable/IfcTraceRange):
//   fd->debugEnable();                       // turn on op-action recording
//   fd->debugSetRange(Address(), Address());  // invalid range + default unique = entire function
//   conf->setDebugStream(&cout);              // route glb->printDebug output to stdout
// then run the normal pipeline; each modifying rule emits a "DEBUG <n>: <RuleName>" block.
//
// Links against Ghidra's decompiler library (libdecomp_dbg.a), like oracle/capture. Build is in
// scripts/setup-oracle.sh (build_capture_trace).
//
//   usage: capture_trace <sleighdir> <fixture.xml> --trace
//
#include "libdecomp.hh"
#include "architecture.hh"
#include "funcdata.hh"

#include <iostream>
#include <sstream>

using namespace ghidra;
using std::cerr;
using std::cout;
using std::endl;
using std::string;

int main(int argc, char **argv) {
  if (argc != 4 || string(argv[3]) != "--trace") {
    cerr << "usage: " << argv[0] << " <sleighdir> <fixture.xml> --trace" << endl;
    return 2;
  }
  const string sleighdir(argv[1]);
  const string fixture(argv[2]);

  startDecompilerLibrary(sleighdir.c_str());

  DocumentStorage store;
  const Element *root;
  try {
    root = store.openDocument(fixture)->getRoot();
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
  } catch (LowlevelError &e) {
    cerr << "init: " << e.explain << endl;
    return 1;
  }

  const Translate *trans = conf->translate;
  AddrSpace *code = trans->getDefaultCodeSpace();

  // Function entry = the first bytechunk's offset (matches oracle/capture --c/--ir).
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
    conf->setDebugStream(&cout);
    fd->debugEnable();
    fd->debugSetRange(Address(), Address()); // invalid range + default unique = entire function
    conf->allacts.getCurrent()->perform(*fd);
  } catch (LowlevelError &e) {
    cerr << "trace: " << e.explain << endl;
    delete conf;
    return 1;
  }
  delete conf;
  return 0;
}
