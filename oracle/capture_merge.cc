// capture_merge.cc — Ghidra's HighVariable membership AND covers, captured at the END of the
// merge cluster, for diffing against mosura's merge.
//
// WHY THIS EXISTS. `decomp_dbg`'s console can show membership (`print high <name>`) but NOT the
// cover that decided it: `HighVariable::printCover` is
//     if ((highflags & coverdirty)==0) internalCover.print(s); else s << "Cover dirty";
// (variable.hh:188), and by the time a full `decompile` returns, later phases have set
// `coverdirty`. The cover that drove the merge does not survive the pipeline, so the console can
// say WHAT merged and never WHY. Every merge-side question (why Ghidra merges two values we keep
// apart) needs the why.
//
// HOW IT GETS THE COVER ANYWAY. `HighVariable::updateInternalCover` is private, but the cover is
// by definition the union of its members' covers, and `Varnode::getCover()` is public and
// REFRESHES on access (`{ updateCover(); return cover; }`, varnode.hh:202). So this tool prints
// each member's freshly-recomputed cover rather than asking the high for a stale one. Nothing in
// Ghidra is patched: it is read through public accessors at an earlier stopping point.
//
// THE STOPPING POINT is a breakpoint on an action, exactly as `capture --ir <action>` does. The
// merge cluster is coreaction.cc:5718-5729 — mergerequired, markexplicit, markimplied,
// mergemultientry, mergecopy, dominantcopy, mergeadjacent, mergetype — so breaking at the START
// of `copymarker` (:5729) is "all merging done, nothing after it has run". Note that names are
// assigned later still (ActionNameVars, :5734), so highs here are UNNAMED and are identified by
// their member set — which is a stronger identity than a name anyway.
//
// SCOPE LIMIT, stated because it was asked for and cannot be delivered: this tool cannot log
// Ghidra's `buildDominantCopy` ATTEMPTS. Those are internal control flow, and reaching them would
// mean patching Ghidra, which is the reference and is not ours to modify. What it can show is the
// RESULT — the op set at the breakpoint, in which a trim COPY is visible as an op we do not have.
//
// Build (scripts/setup-oracle.sh, same library and switches as capture/capture_trace — a mismatch
// is silent ABI corruption):
//   g++ -std=c++11 -DCPUI_DEBUG -D__TERMINAL__ -I$CPP -O2 -o oracle/capture_merge \
//       oracle/capture_merge.cc -Wl,--whole-archive $CPP/libdecomp_dbg.a \
//       -Wl,--no-whole-archive -lbfd -lz
//
// CALIBRATION (must be able to FAIL, per the house rule): run it under a root with no watcom
// compiler spec — it must die with `No sleigh specification`, not fall back silently.

#include "libdecomp.hh"
#include "architecture.hh"
#include "funcdata.hh"
#include <iostream>
#include <sstream>
#include <set>

using namespace ghidra;
using std::cerr;
using std::cout;
using std::endl;
using std::string;

int main(int argc, char **argv) {
  if (argc < 3) {
    cerr << "usage: " << argv[0] << " <sleighdir> <fixture.xml> [--at <action>]" << endl;
    return 2;
  }
  const string sleighdir(argv[1]);
  const string fixture(argv[2]);
  string breakat = "copymarker";
  if (argc >= 5 && string(argv[3]) == "--at")
    breakat = argv[4];

  startDecompilerLibrary(sleighdir.c_str());
  DocumentStorage store;
  const Element *root;
  try {
    root = store.openDocument(fixture)->getRoot();
  } catch (LowlevelError &e) {
    cerr << "open " << fixture << ": " << e.explain << endl;
    return 1;
  }
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
    Action *act = conf->allacts.getCurrent();
    act->reset(*fd);
    act->setBreakPoint(Action::break_start, breakat);
    act->perform(*fd); // runs until the breakpoint (partial, returns <0) or completion
    cout << "STOPPED at start of action: " << breakat << endl;

    // Walk every Varnode with a cover, group by HighVariable, print members + their covers.
    // Highs are unnamed at this point (ActionNameVars has not run), so each is identified by its
    // member set, printed in the console's `print high` form so the two can be compared directly.
    std::set<HighVariable *> seen;
    int4 hcount = 0;
    VarnodeLocSet::const_iterator iter = fd->beginLoc();
    VarnodeLocSet::const_iterator enditer = fd->endLoc();
    for (; iter != enditer; ++iter) {
      Varnode *vn = *iter;
      if (!vn->hasCover())
        continue;
      HighVariable *high = vn->getHigh();
      if (high == (HighVariable *)0 || seen.count(high))
        continue;
      seen.insert(high);
      hcount += 1;
      cout << std::dec << "HIGH " << hcount << " instances=" << high->numInstances();
      Datatype *ct = high->getType();
      if (ct != (Datatype *)0) {
        cout << " type=";
        ct->printRaw(cout);
      }
      cout << endl;
      for (int4 i = 0; i < high->numInstances(); ++i) {
        Varnode *m = high->getInstance(i);
        cout << std::dec << "  MEMBER ";
        m->printRaw(cout);
        PcodeOp *def = m->getDef();
        cout << " def=";
        if (def != (PcodeOp *)0)
          cout << "0x" << std::hex << def->getAddr().getOffset() << std::dec;
        else
          cout << "-";
        // Varnode::getCover() recomputes on access, so this is the cover as the merge tests saw
        // it -- the thing the console cannot show.
        cout << " cover=";
        if (m->hasCover())
          m->getCover()->print(cout);
        else
          cout << "(none)";
        cout << endl;
      }
    }
    cout << std::dec << "HIGHS " << hcount << endl;

    // The op set, so a trim COPY Ghidra built and we did not is visible as a difference.
    int4 copies = 0;
    for (PcodeOpTree::const_iterator oi = fd->beginOpAll(); oi != fd->endOpAll(); ++oi) {
      PcodeOp *op = (*oi).second;
      if (op->code() == CPUI_COPY)
        copies += 1;
    }
    cout << std::dec << "COPYOPS " << copies << endl;
  } catch (LowlevelError &e) {
    cerr << "merge: " << e.explain << endl;
    delete conf;
    return 1;
  }
  delete conf;
  return 0;
}
