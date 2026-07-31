// capture_typeprop.cc — Ghidra's TYPE-PROPAGATION trace, for diffing against mosura (task #11).
//
// WHY A SECOND TRACE TOOL EXISTS AT ALL. oracle/capture_trace drives Ghidra's OPACTION_DEBUG, which
// is a p-code-OP mutation log: Funcdata::debugModCheck takes a PcodeOp*, and debugModPrint returns
// early on `if (modify_list.empty())` (funcdata.cc:1012/1035). ActionInferTypes assigns Datatype* to
// VARNODES through updateType and mutates no ops, so it NEVER prints there — on either side. It
// fires zero times in both traces on every fixture, which reads as agreement and is really
// invisibility. That blind spot cost a pass of the 1-byte-typing investigation before it was found.
//
// Ghidra already ships the right instrument for this: a SEPARATE debug channel guarded by
// TYPEPROP_DEBUG, whose hook is ActionInferTypes::propagationDebug (coreaction.cc:4980). Its most
// important call site is inside propagateTypeEdge (coreaction.cc:5105), immediately at
//
//     if (0 > newtype->typeOrder(*outvn->getTempType())) {   // <-- the preference ordering itself
//       propagationDebug(...);
//       outvn->setTempType(newtype);
//
// so the log records EVERY accepted type decision: the varnode, the type that won, and the op+slot
// it propagated from. That is exactly the decision a "which type wins a meet" question is about, so
// the diff can implicate or exonerate a type-ordering hypothesis with evidence instead of
// plausibility. mosura's mirror of this hook already exists (infertypes.rs propagation_debug,
// MOSURA_TYPEPROP=1) and emits the same tuple; it had simply never been diffed against anything.
//
// BUILD FACT: NOTHING NEW IS NEEDED. TYPEPROP_DEBUG is auto-defined by CPUI_DEBUG, exactly like
// OPACTION_DEBUG — types.h:88-91 is
//
//     #ifdef CPUI_DEBUG
//     # define OPACTION_DEBUG
//     # define PRETTY_DEBUG
//     # define TYPEPROP_DEBUG
//
// so the hook has been compiled into the existing libdecomp_dbg.a all along, and this tool links
// that same library with the same switches (-DCPUI_DEBUG -D__TERMINAL__) as oracle/capture and
// oracle/capture_trace. No library rebuild, no flag divergence, no ABI risk (the d5ae08d lesson).
// The facility was available for the whole campaign and simply never wired to a diff.
//
// I originally recorded the opposite here — that the library needed rebuilding with an explicit
// -DTYPEPROP_DEBUG — by reasoning from capture_trace.cc's note that OPACTION_DEBUG is auto-defined
// and inferring that a separately-#ifdef'd symbol therefore was not. One grep of types.h refuted
// it. Kept as a marker: a build premise is checkable in seconds and should never be carried on an
// inference.
//
// The runtime half IS still required and is NOT implied: TypeFactory::propagatedbg_on defaults to
// false (type.cc:3101), which is why the trace is silent in normal oracle runs.
//
//   usage: capture_typeprop <sleighdir> <fixture.xml> --typeprop
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
  if (argc != 4 || string(argv[3]) != "--typeprop") {
    cerr << "usage: " << argv[0] << " <sleighdir> <fixture.xml> --typeprop" << endl;
    return 2;
  }
#ifndef TYPEPROP_DEBUG
  // Refuse rather than print an empty trace. An empty type-propagation log is indistinguishable
  // from "the two engines agree", which is the exact failure this tool exists to prevent.
  cerr << "REFUSING: built without -DTYPEPROP_DEBUG, so Ghidra's propagation hook is compiled out"
       << endl
       << "  and this tool can only ever emit an empty trace. Rebuild via scripts/setup-oracle.sh."
       << endl;
  return 3;
#else
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

  // Function entry = the first bytechunk's offset (matches oracle/capture and capture_trace).
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
    // The runtime half of the switch (ifacedecomp.cc IfcTracePropagation). The compile-time half is
    // -DTYPEPROP_DEBUG; both are required, and neither implies the other.
    TypeFactory::propagatedbg_on = true;
    conf->allacts.getCurrent()->perform(*fd);
  } catch (LowlevelError &e) {
    cerr << "typeprop: " << e.explain << endl;
    delete conf;
    return 1;
  }
  delete conf;
  return 0;
#endif
}
