"""Import a binary into the shared Ghidra project and run a one-time analysis with its PDB.

Runs headless through PyGhidra. Expensive analyzers that matter little when a full PDB is
available are turned off so a binary the size of ShooterGameServer.exe finishes in hours,
not days. pyghidra-mcp later opens the same project and skips re-analysis because the
program is marked analyzed.

Usage:
  python ghidra_analyze.py <binary> [--pdb <file>] [--project D:\\ATLAS\\_re\\ghidra] [--name atlas] [--heap 8g]
  --no-pdb: a binary shipped without its PDB (the DevKit's plugin DLLs): full auto-analysis, no symbols.
"""
import argparse
import os
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
os.environ.setdefault("GHIDRA_INSTALL_DIR", str(TOOLS / "ghidra_12.1.4_PUBLIC"))
os.environ.setdefault("JAVA_HOME", str(TOOLS / "jdk-21.0.12.1+1"))

# Analyzer name -> enabled. Names that don't exist in this Ghidra version are reported and skipped.
ANALYZERS = {
    "PDB Universal": True,
    "Decompiler Parameter ID": False,  # decompiles every function; hours on its own
    "Decompiler Switch Analysis": False,  # also decompiles; run later on functions we care about
    "Function ID": False,  # library signature matching; the PDB already names everything
    "Aggressive Instruction Finder": False,
}


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--pdb", help="PDB to apply (default: next to the binary)")
    ap.add_argument("--project", default=r"D:\ATLAS\_re\ghidra")
    ap.add_argument("--name", default="atlas")
    ap.add_argument("--heap", default="8g")
    ap.add_argument("--pdb-only", action="store_true",
                    help="run only the PDB analyzer (minutes instead of hours); enough to decompile named functions")
    ap.add_argument("--no-pdb", action="store_true", help="the binary has no PDB: full analysis without symbols")
    ap.add_argument("--decompile", nargs="*", default=[],
                    help="fully qualified function names to decompile into --out after analysis")
    ap.add_argument("--out", help=r"default: D:\ATLAS\_re\decompiled\server or \client by binary name")
    args = ap.parse_args()

    binary = Path(args.binary).resolve()
    if not args.out:
        sub = "client" if binary.name.lower().startswith("atlasgame") else "server"
        args.out = rf"D:\ATLAS\_re\decompiled\{sub}"
    pdb = Path(args.pdb).resolve() if args.pdb else binary.with_suffix(".pdb")
    if not pdb.exists() and not args.no_pdb:
        raise SystemExit(f"PDB not found: {pdb} (--no-pdb for a binary shipped without one)")

    import pyghidra

    launcher = pyghidra.HeadlessPyGhidraLauncher()
    launcher.add_vmargs(f"-Xmx{args.heap}")
    launcher.start()
    log(f"Ghidra started (heap {args.heap})")

    from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
    from ghidra.app.script import GhidraScriptUtil
    from ghidra.base.project import GhidraProject
    from ghidra.framework.model import ProjectLocator
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import Program
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.util.task import ConsoleTaskMonitor
    from java.io import File

    Path(args.project).mkdir(parents=True, exist_ok=True)
    if ProjectLocator(args.project, args.name).exists():
        project = GhidraProject.openProject(args.project, args.name, True)
    else:
        project = GhidraProject.createProject(args.project, args.name, False)

    try:
        root = project.getProjectData().getRootFolder()
        if root.getFile(binary.name):
            log(f"opening existing {binary.name}")
            program = project.openProgram("/", binary.name, False)
        else:
            log(f"importing {binary} ({binary.stat().st_size / 2**20:.0f} MB)")
            program = project.importProgram(File(str(binary)))
            project.saveAs(program, "/", binary.name, True)

        if not GhidraProgramUtilities.shouldAskToAnalyze(program):
            log("already analyzed")
            decompile(program, args.decompile, Path(args.out))
            return

        if not args.no_pdb:
            PdbUniversalAnalyzer.setPdbFileOption(program, File(str(pdb)))
            log(f"PDB set to {pdb} ({pdb.stat().st_size / 2**20:.0f} MB)")

        txn = program.startTransaction("analysis options")
        try:
            options = program.getOptions(Program.ANALYSIS_PROPERTIES)
            names = set(options.getOptionNames())
            # without a PDB the default analyzers (function ID, parameter ID, ...) are what finds the functions
            wanted = {"PDB Universal": False} if args.no_pdb else dict(ANALYZERS)
            if args.pdb_only:
                # Option names without a "." are the analyzer on/off switches.
                wanted = {n: (n == "PDB Universal") for n in names if "." not in n}
            for name, enabled in wanted.items():
                if name in names:
                    options.setBoolean(name, enabled)
                    log(f"analyzer '{name}' = {enabled}")
                else:
                    log(f"analyzer '{name}' not in this Ghidra version; skipped")
        finally:
            program.endTransaction(txn, True)

        start = time.time()
        log("analysis started")
        # Some analyzers (e.g. Windows resource references) run Ghidra scripts and need the bundle host.
        GhidraScriptUtil.acquireBundleHostReference()
        try:
            FlatProgramAPI(program, ConsoleTaskMonitor()).analyzeAll(program)
        finally:
            GhidraScriptUtil.releaseBundleHostReference()
        GhidraProgramUtilities.markProgramAnalyzed(program)
        project.save(program)

        functions = list(program.getFunctionManager().getFunctions(True))
        named = sum(1 for f in functions if not f.getName().startswith("FUN_"))
        log(f"analysis finished in {(time.time() - start) / 3600:.2f} h; "
            f"{len(functions):,} functions, {named:,} named from symbols; saved")
        decompile(program, args.decompile, Path(args.out))
    finally:
        project.close()


def decompile(program, names, out_dir):
    if not names:
        return
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    out_dir.mkdir(parents=True, exist_ok=True)
    iface = DecompInterface()
    iface.openProgram(program)
    st = program.getSymbolTable()
    fm = program.getFunctionManager()
    for name in names:
        ns, _, short = name.rpartition("::")
        funcs = []
        for sym in st.getSymbols(short):
            f = fm.getFunctionAt(sym.getAddress())
            if f and (not ns or f.getParentNamespace().getName(True).endswith(ns)):
                funcs.append(f)
        if not funcs:
            log(f"decompile: {name} not found")
            continue
        for f in funcs:
            res = iface.decompileFunction(f, 120, ConsoleTaskMonitor())
            code = res.getDecompiledFunction().getC() if res.decompileCompleted() else f"// failed: {res.getErrorMessage()}"
            path = out_dir / f"{name.replace('::', '__')}@{f.getEntryPoint()}.c"
            path.write_text(code, encoding="utf-8")
            log(f"decompiled {name} @ {f.getEntryPoint()} -> {path} ({len(code.splitlines())} lines)")
    iface.dispose()


if __name__ == "__main__":
    main()
