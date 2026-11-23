"""Find functions that reference given UTF-16/ASCII strings in the analyzed ATLAS server and decompile them.

Usage: python ghidra_xrefs.py "ServerX" "Missing server coords" ... [--out D:\\ATLAS\\_re\\decompiled]
"""
import argparse
import os
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
os.environ.setdefault("GHIDRA_INSTALL_DIR", str(TOOLS / "ghidra_12.1.4_PUBLIC"))
os.environ.setdefault("JAVA_HOME", str(TOOLS / "jdk-21.0.12.1+1"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("strings", nargs="+")
    ap.add_argument("--out", default=r"D:\ATLAS\_re\decompiled")
    args = ap.parse_args()

    import pyghidra
    launcher = pyghidra.HeadlessPyGhidraLauncher()
    launcher.add_vmargs("-Xmx6g")
    launcher.start()

    from ghidra.app.decompiler import DecompInterface
    from ghidra.base.project import GhidraProject
    from ghidra.util.task import ConsoleTaskMonitor

    project = GhidraProject.openProject(r"D:\ATLAS\_re\ghidra", "atlas", True)
    try:
        program = project.openProgram("/", "ShooterGameServer.exe", True)
        mem = program.getMemory()
        refs = program.getReferenceManager()
        fm = program.getFunctionManager()
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        iface = DecompInterface()
        iface.openProgram(program)
        done = set()
        for text in args.strings:
            for enc in ("utf-16le", "ascii"):
                needle = text.encode(enc)
                addr = mem.getMinAddress()
                while True:
                    addr = mem.findBytes(addr, needle, None, True, ConsoleTaskMonitor())
                    if addr is None:
                        break
                    for ref in refs.getReferencesTo(addr):
                        f = fm.getFunctionContaining(ref.getFromAddress())
                        name = f.getName(True) if f else "?"
                        print(f"'{text}' ({enc}) @ {addr} <- {ref.getFromAddress()} in {name}")
                        if f and f.getEntryPoint() not in done:
                            done.add(f.getEntryPoint())
                            res = iface.decompileFunction(f, 180, ConsoleTaskMonitor())
                            code = res.getDecompiledFunction().getC() if res.decompileCompleted() else "// failed"
                            path = out / f"{name.replace('::', '__')[:120]}@{f.getEntryPoint()}.c"
                            path.write_text(code, encoding="utf-8")
                            print(f"   -> {path.name} ({len(code.splitlines())} lines)")
                    addr = addr.add(1)
        iface.dispose()
    finally:
        project.close()


if __name__ == "__main__":
    main()
