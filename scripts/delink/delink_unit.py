"""Delink one of ATLAS's compile units out of the server (or client) binary into a COFF object with ghidra-delinker
0.9.2, nothing saved to the Ghidra project. The hybrid link's first tool (ADR-0006 option c, plan P2, 2026-10-29).

What it does, inside one transaction on the read-only project that is rolled back at the end:
1. disassembles the unit's .text ranges (the PDB-only project's functions have one-byte bodies) and fixes the
   function bodies;
2. types every absolute pointer the PE's base relocations mark inside the unit's data ranges;
3. runs the reference analyzers on the unit's ranges;
4. the naming rule: every symbol the unit defines or references that has no PDB public and no `?`-mangled name at
   its address (function-local statics such as `ret`, 370 of them in the server; funclets `dtor$N`; lambdas) is renamed
   `<name>@local@<va>` so that no two externals collide and the owning unit defines the same name in a relink; the
   label at the image base becomes the linker's `__ImageBase`;
5. the delinker's "Relocation table synthesizer" on the unit's ranges;
6. the "COFF relocatable object" exporter (AMD64, MSVC name preference: the `?`-mangled publics).
The extension loads only from the isolated settings folder (-Dapplication.settingsdir=D:\\ATLAS\\build\\delink\\settings).
Judge the object with `func_match.py <obj> ShooterGameServer.exe` (it knows the `@local@` names: a target is
checked at that address, a function judged there). First result, PrimalRaft.cpp.obj (module 406, 1,190 ranges,
694 functions): 655 byte-identical, 1 DIFF (the image base, before step 4's rename), 38 SIZE on funclets.

usage: python -I _tools/delink_unit.py <ranges.txt from unit_contribs.py> <out.obj>
           [--sections .text,.rdata,.data] [--heap 4g] [--project D:\\ATLAS\\_re\\ghidra --name atlas
           --program ShooterGameServer.exe]
"""
import argparse
import os
import pickle
import re
import sys
import time
from collections import Counter
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
os.environ.setdefault("GHIDRA_INSTALL_DIR", str(TOOLS / "ghidra_12.1.4_PUBLIC"))
os.environ.setdefault("JAVA_HOME", str(TOOLS / "jdk-21.0.12.1+1"))
SETTINGS = r"D:\ATLAS\build\delink\settings"
CACHE = TOOLS.parent / "_re" / "cache"
BASE = 0x140000000
REF_ANALYZERS = ["x86 Constant Reference Analyzer", "Data Reference", "Scalar Operand References",
                 "Create Address Tables"]
MANGLED = re.compile(r"^\?")


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ranges")
    ap.add_argument("out")
    ap.add_argument("--sections", default=".text,.rdata,.data")
    ap.add_argument("--heap", default="4g")
    ap.add_argument("--project", default=r"D:\ATLAS\_re\ghidra")
    ap.add_argument("--name", default="atlas")
    ap.add_argument("--program", default="ShooterGameServer.exe")
    args = ap.parse_args()
    keep = set(args.sections.split(","))
    ranges = []
    for line in open(args.ranges):
        span, sec = line.split()
        if sec in keep:
            a, b = span.split("-")
            ranges.append((int(a, 16), int(b, 16), sec))
    log(len(ranges), "ranges", {s: sum(1 for r in ranges if r[2] == s) for s in keep})
    publics_pkl = CACHE / f"{Path(args.program).stem}.pdbsyms2.pkl"
    if not publics_pkl.exists():
        sys.exit(f"{publics_pkl} missing: run func_match.py once against {args.program} to build the publics cache")
    by_name, _sizes, _mods = pickle.loads(publics_pkl.read_bytes())
    public_vas = {BASE + rva for rva in by_name.values()}
    log("publics", len(public_vas))

    import pyghidra
    launcher = pyghidra.HeadlessPyGhidraLauncher()
    launcher.add_vmargs(f"-Xmx{args.heap}", f"-Dapplication.settingsdir={SETTINGS}")
    launcher.start()
    from ghidra.framework import Application
    from ghidra.base.project import GhidraProject
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.app.util.exporter import Exporter
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.data import PointerDataType
    from ghidra.program.model.data import DataUtilities
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.classfinder import ClassSearcher
    from ghidra.util.task import ConsoleTaskMonitor
    from java.io import File
    log("settings dir", Application.getUserSettingsDirectory())
    exporters = [e for e in ClassSearcher.getInstances(Exporter) if e.getName() == "COFF relocatable object"]
    if not exporters:
        sys.exit("the delinker extension did not load (no COFF relocatable object exporter)")
    monitor = ConsoleTaskMonitor()
    project = GhidraProject.openProject(args.project, args.name, True)
    tx = None
    try:
        program = project.openProgram("/", args.program, True)
        space = program.getAddressFactory().getDefaultAddressSpace()
        A = lambda v: space.getAddress(v)  # noqa: E731
        allset, text, data = AddressSet(), AddressSet(), AddressSet()
        for a, b, sec in ranges:
            allset.add(A(a), A(b))
            (text if sec == ".text" else data).add(A(a), A(b))
        tx = program.startTransaction("delink (not saved)")
        # 1. code
        DisassembleCommand(text, text, True).applyTo(program, monitor)
        fm = program.getFunctionManager()
        nf = 0
        for f in list(fm.getFunctions(text, True)):
            CreateFunctionCmd.fixupFunctionBody(program, f, monitor)
            nf += 1
        ninsn = sum(1 for _ in program.getListing().getInstructions(text, True))
        log("functions", nf, "instructions", ninsn)
        # 2. pointers: every base relocation inside the unit's data ranges is an absolute pointer
        rt = program.getRelocationTable()
        listing = program.getListing()
        ptr = PointerDataType()
        nptr = nrel = nhad = nfail = 0
        for r in rt.getRelocations(data):
            nrel += 1
            at = r.getAddress()
            d = listing.getDataContaining(at)
            if d is not None and d.isPointer() and d.getAddress().equals(at):
                nhad += 1
                continue
            try:
                DataUtilities.createData(program, at, ptr, -1, DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA)
                nptr += 1
            except Exception:
                nfail += 1
        log("base relocations in data", nrel, "already pointers", nhad, "pointers typed", nptr, "failed", nfail)
        # 3. references
        aam = AutoAnalysisManager.getAnalysisManager(program)
        for name in REF_ANALYZERS:
            an = aam.getAnalyzer(name)
            if an is None:
                log("no analyzer", name)
                continue
            aam.scheduleOneTimeAnalysis(an, allset)
        aam.startAnalysis(monitor)
        log("reference analysis done")
        # 4. the naming rule
        st = program.getSymbolTable()
        rm = program.getReferenceManager()
        targets = set()
        for ref in rm.getReferenceIterator(allset.getMinAddress()):
            if not allset.contains(ref.getFromAddress()):
                if ref.getFromAddress().compareTo(allset.getMaxAddress()) > 0:
                    break
                continue
            targets.add(ref.getToAddress())
        defined = set()
        for s in st.getSymbolIterator(allset.getMinAddress(), True):
            if s.getAddress().compareTo(allset.getMaxAddress()) > 0:
                break
            if allset.contains(s.getAddress()) and not s.isDynamic():
                defined.add(s.getAddress())
        before = Counter()
        renamed = Counter()
        for addr in defined | targets:
            syms = list(st.getSymbols(addr))
            if not syms or any(MANGLED.match(s.getName()) for s in syms):
                continue
            prim = next((s for s in syms if s.isPrimary()), syms[0])
            if prim.isDynamic():
                continue
            va = addr.getOffset()
            if va in public_vas:
                continue  # a C-style public (e.g. __chkstk): its name is the link name
            before[prim.getName()] += 1
            try:
                prim.setName(f"{prim.getName()}@local@{va:x}", SourceType.USER_DEFINED)
                renamed["defined" if addr in defined else "referenced"] += 1
            except Exception as ex:
                renamed["failed"] += 1
                if renamed["failed"] <= 5:
                    log("  rename failed", addr, prim.getName(), str(ex)[:100])
        log("non-public symbols renamed:", dict(renamed), "; most common names before:", before.most_common(8))
        for s in list(st.getSymbols(A(BASE))):
            if s.isPrimary() and s.getName() != "__ImageBase":
                s.setName("__ImageBase", SourceType.USER_DEFINED)
                log("image base label renamed to __ImageBase")
        # 5. the delinker's synthesizer
        syn = aam.getAnalyzer("Relocation table synthesizer")
        if syn is None:
            sys.exit("no Relocation table synthesizer analyzer")
        aam.scheduleOneTimeAnalysis(syn, allset)
        aam.startAnalysis(monitor)
        nsyn = sum(1 for _ in rt.getRelocations(allset))
        log("synthesizer done; relocations in the unit's ranges now", nsyn)
        # 6. export
        exp = exporters[0]
        exp.setOptions(exp.getOptions(lambda: program))
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        ok = exp.export(File(str(out)), program, allset, monitor)
        log("export", ok, out, out.stat().st_size if out.exists() else 0)
        msgs = str(exp.getMessageLog())
        if msgs.strip():
            log("exporter messages:", msgs)
        if not ok:
            sys.exit(1)
    finally:
        if tx is not None:
            program.endTransaction(tx, False)
        project.close()


if __name__ == "__main__":
    main()
