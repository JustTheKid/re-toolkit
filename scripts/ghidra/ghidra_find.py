"""List functions whose qualified name matches a regex (or that start at given addresses), optionally decompiling them.

Usage: python ghidra_find.py <regex> [--decompile] [--limit 80]
       python ghidra_find.py --address 141a3b030 1425c3260 [--decompile]   (overloads / templates, by entry VA)
       python ghidra_find.py --address 141a58b10 --callees                  (the functions each one calls, in order)
       python ghidra_find.py --address 141a36af0 --stores                   (memory writes as base+offset = value:
                                                                             field offsets the C output hides)
       python ghidra_find.py --address-file vas.txt --decompile --workers 6 --skip-existing --limit 5000 --out <dir>
                                                                            (many functions: decompiler threads, resumable)
       --fix-imports <dll>: a DevKit DLL whose PDB hides its import slots: give the imports back their names and
                            prototypes for this run (ghidra_imports.py; not saved), so calls into Core / CoreUObject
                            keep their stack arguments
Output files are <Class>__<Func>@<va>.c; characters not allowed in Windows file names (<>:"/\\|?*,) become '_'.
"""
import argparse
import os
import re
from pathlib import Path

UNSAFE = re.compile(r'[<>:"/\\|?*,\s`\']')  # the backtick and the quote too (2026-10-31: `scalar_deleting_destructor')

TOOLS = Path(__file__).resolve().parent
os.environ.setdefault("GHIDRA_INSTALL_DIR", str(TOOLS / "ghidra_12.1.4_PUBLIC"))
os.environ.setdefault("JAVA_HOME", str(TOOLS / "jdk-21.0.12.1+1"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pattern", nargs="?", default=None)
    ap.add_argument("--address", nargs="*", default=[], help="also select the functions starting at these hex VAs")
    ap.add_argument("--address-file", help="also select the functions at the hex VAs in this file (first word per line)")
    ap.add_argument("--workers", type=int, default=1, help="decompiler threads for --decompile (one interface each)")
    ap.add_argument("--skip-existing", action="store_true", help="with --decompile: leave functions whose file exists")
    ap.add_argument("--decompile", action="store_true")
    ap.add_argument("--callees", action="store_true", help="list each function's call targets in address order")
    ap.add_argument("--stores", action="store_true", help="list each function's memory writes (p-code STORE) "
                    "as <base>+<offset> = <value>, in address order")
    ap.add_argument("--limit", type=int, default=80)
    ap.add_argument("--timeout", type=int, default=180, help="decompiler seconds per function")
    ap.add_argument("--out", help=r"default: D:\ATLAS\_re\decompiled\server or \client by --program")
    ap.add_argument("--project", default=r"D:\ATLAS\_re\ghidra")
    ap.add_argument("--name", default="atlas")
    ap.add_argument("--program", default="ShooterGameServer.exe")
    ap.add_argument("--fix-imports", help="the program's DLL file: retype its import slots for this run (not saved)")
    ap.add_argument("--no-locals", action="store_true",
                    help="export without the PDB locals block and the param_N renames (_tools/pdb_locals.py)")
    ap.add_argument("--max-payload", type=int, default=0,
                    help="decompiler output limit in MB (Ghidra's default 50 is too small for AActor's reflection)")
    args = ap.parse_args()
    if not args.out:
        sub = "client" if args.program.lower().startswith("atlasgame") else "server"
        args.out = rf"D:\ATLAS\_re\decompiled\{sub}"
    if args.address_file:
        args.address += [line.split()[0] for line in open(args.address_file, encoding="utf-8") if line.strip()]
    if not args.pattern and not args.address:
        ap.error("give a name regex and/or --address")
    rx = re.compile(args.pattern, re.I) if args.pattern else None

    import pyghidra
    launcher = pyghidra.HeadlessPyGhidraLauncher()
    launcher.add_vmargs("-Xmx6g")
    launcher.start()
    from ghidra.app.decompiler import DecompileOptions, DecompInterface
    from ghidra.base.project import GhidraProject
    from ghidra.util.task import ConsoleTaskMonitor

    project = GhidraProject.openProject(args.project, args.name, True)
    tx = None
    try:
        program = project.openProgram("/", args.program, True)
        fm = program.getFunctionManager()
        # The PDB's parameters and locals as a block over each export, Ghidra's param_N renamed to the PDB's names
        # (_tools/pdb_locals.py, 2026-10-29); without an index (`pdb_locals.py build <pdb>`) the exports are as before.
        loc = None
        if args.decompile and not args.no_locals:
            import sys
            sys.path.insert(0, str(TOOLS))
            from pdb_locals import Locals
            loc = Locals.open(args.program)
            print("PDB locals: " + (str(loc.path) if loc else
                                    f"no index for {args.program} (pdb_locals.py build), exporting without"), flush=True)

        def finish(code, f):
            return code if loc is None else loc.decorate(code, int(str(f.getEntryPoint()), 16))[0]
        # This PDB-only project was never auto-analyzed, so __chkstk lacks its call fixup and the decompiler loses the
        # stack in functions with big frames (constants become "*(ulong64 *)(&stack0x... + lVar2)"). Install the
        # fixup in a transaction that is rolled back at the end: nothing is saved to the project.
        tx = program.startTransaction("call fixups for this run (not saved)")
        for sym in program.getSymbolTable().getGlobalSymbols("__chkstk"):
            chk = fm.getFunctionAt(sym.getAddress())
            if chk is not None and chk.getCallFixup() is None:
                chk.setCallFixup("alloca_probe")
        if args.fix_imports:
            import sys
            sys.path.insert(0, str(TOOLS))
            from ghidra_imports import retype_imports
            retype_imports(program, args.fix_imports)
        hits = [f for f in fm.getFunctions(True) if rx.search(f.getName(True))] if rx else []
        space = program.getAddressFactory().getDefaultAddressSpace()
        for va in args.address:
            f = fm.getFunctionAt(space.getAddress(int(va, 16)))
            if f is None:
                print(f"no function starts at {va}")
            elif f not in hits:
                hits.append(f)
        print(f"{len(hits)} matches")
        iface = None
        aux = None  # --stores / --callees: their own interface, so they never turn on file output
        def new_iface():
            d = DecompInterface()
            if args.max_payload:
                opts = DecompileOptions()
                opts.grabFromProgram(program)
                opts.setMaxPayloadMBytes(args.max_payload)
                d.setOptions(opts)
            d.openProgram(program)
            return d

        if args.decompile:
            iface = new_iface()
            Path(args.out).mkdir(parents=True, exist_ok=True)

        def out_path(f):
            return Path(args.out) / f"{UNSAFE.sub('_', f.getName(True).replace('::', '__'))[:120]}@{f.getEntryPoint()}.c"

        if args.decompile and args.workers > 1:
            # Many functions: one decompiler interface per thread (as ghidra_bulk_export.py does); same file format.
            import threading
            from concurrent.futures import ThreadPoolExecutor, as_completed
            local = threading.local()
            todo = [f for f in hits[:args.limit] if not (args.skip_existing and out_path(f).exists())]
            print(f"{len(todo)} to decompile with {args.workers} workers", flush=True)

            def work(f):
                if not hasattr(local, "iface"):
                    local.iface = new_iface()
                res = local.iface.decompileFunction(f, args.timeout, ConsoleTaskMonitor())
                code = res.getDecompiledFunction().getC() if res.decompileCompleted() else f"// failed: {res.getErrorMessage()}"
                out_path(f).write_text(finish(code, f), encoding="utf-8")
                return f
            pool = ThreadPoolExecutor(max_workers=args.workers)
            try:
                for n, fut in enumerate(as_completed([pool.submit(work, f) for f in todo]), 1):
                    f = fut.result()
                    print(f"{f.getEntryPoint()}  {f.getName(True)}  -> {out_path(f).name}", flush=True)
                    if n % 100 == 0:
                        print(f"  {n}/{len(todo)}", flush=True)
            finally:
                pool.shutdown(wait=True)
            hits = []
        for f in hits[:args.limit]:
            name = f.getName(True)
            line = f"{f.getEntryPoint()}  {f.getBody().getNumAddresses():6} bytes  {name}"
            if iface:
                res = iface.decompileFunction(f, args.timeout, ConsoleTaskMonitor())
                code = res.getDecompiledFunction().getC() if res.decompileCompleted() else f"// failed: {res.getErrorMessage()}"
                path = Path(args.out) / f"{UNSAFE.sub('_', name.replace('::', '__'))[:120]}@{f.getEntryPoint()}.c"
                path.write_text(finish(code, f), encoding="utf-8")
                line += f"  -> {path.name}"
            print(line)
            if args.stores:
                from ghidra.program.model.pcode import PcodeOp
                if aux is None:
                    aux = DecompInterface()
                    aux.openProgram(program)
                res = aux.decompileFunction(f, args.timeout, ConsoleTaskMonitor())
                high = res.getHighFunction() if res.decompileCompleted() else None

                def expr(vn, depth=0):
                    """A varnode as text: constants in hex, base+offset for pointer arithmetic, op(...) otherwise."""
                    if vn.isConstant():
                        return hex(vn.getOffset())
                    hv = vn.getHigh()
                    name = hv.getName() if hv is not None and hv.getName() not in (None, "UNNAMED") else None
                    d = vn.getDef()
                    if d is None or depth > 3:
                        return name or str(vn)
                    code = d.getOpcode()
                    ins = [expr(d.getInput(i), depth + 1) for i in range(d.getNumInputs())]
                    if code in (PcodeOp.INT_ADD, PcodeOp.PTRSUB):
                        return f"({ins[0]}+{ins[1]})"
                    if code == PcodeOp.PTRADD:
                        return f"({ins[0]}+{ins[1]}*{ins[2]})"
                    if code in (PcodeOp.COPY, PcodeOp.CAST):
                        return ins[0]
                    if code == PcodeOp.LOAD:
                        return f"*{ins[1]}"
                    return f"{d.getMnemonic()}({', '.join(ins)})"

                stores = [op for op in (high.getPcodeOps() if high else []) if op.getOpcode() == PcodeOp.STORE]
                for op in sorted(stores, key=lambda o: o.getSeqnum().getTarget().getOffset()):
                    size = op.getInput(2).getSize()
                    print(f"    {op.getSeqnum().getTarget()}  [{size}] *{expr(op.getInput(1))} = {expr(op.getInput(2))}")
            if args.callees:
                # direct calls in the decompiled p-code (function bodies in this project are entry stubs), in address order
                from ghidra.program.model.pcode import PcodeOp
                if aux is None:
                    aux = DecompInterface()
                    aux.openProgram(program)
                res = aux.decompileFunction(f, args.timeout, ConsoleTaskMonitor())
                high = res.getHighFunction() if res.decompileCompleted() else None
                calls = []
                for op in (high.getPcodeOps() if high else []):
                    if op.getOpcode() == PcodeOp.CALL:
                        callee = fm.getFunctionAt(op.getInput(0).getAddress())
                        if callee is not None:
                            calls.append((op.getSeqnum().getTarget(), callee))
                for at, callee in sorted(calls, key=lambda c: c[0].getOffset()):
                    print(f"    {at} -> {callee.getEntryPoint()} {callee.getName(True)}")
    finally:
        if tx is not None:
            program.endTransaction(tx, False)
        project.close()


if __name__ == "__main__":
    main()
