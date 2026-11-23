"""Instruction listing of functions from the Ghidra project (when a decompile hides data movement, e.g. whether a
temporary is copied into a local). One line per instruction: address, bytes, mnemonic and operands, and the called
function's name for calls.

Usage: python -I _tools/ghidra_listing.py <va> [<va> ...] [--out <file>]
       [--project _re/ghidra --name atlas --program ShooterGameServer.exe]
"""
import argparse
import os
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
os.environ.setdefault("GHIDRA_INSTALL_DIR", str(TOOLS / "ghidra_12.1.4_PUBLIC"))
os.environ.setdefault("JAVA_HOME", str(TOOLS / "jdk-21.0.12.1+1"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("va", nargs="+", help="hex VA of a function (its whole body is listed)")
    ap.add_argument("--out")
    ap.add_argument("--project", default=r"D:\ATLAS\_re\ghidra")
    ap.add_argument("--name", default="atlas")
    ap.add_argument("--program", default="ShooterGameServer.exe")
    args = ap.parse_args()

    import pyghidra
    launcher = pyghidra.HeadlessPyGhidraLauncher()
    launcher.add_vmargs("-Xmx6g")
    launcher.start()
    from ghidra.base.project import GhidraProject

    from ghidra.app.cmd.disassemble import DisassembleCommand

    project = GhidraProject.openProject(args.project, args.name, True)
    lines = []
    tx = None
    try:
        program = project.openProgram("/", args.program, True)
        fm = program.getFunctionManager()
        listing = program.getListing()
        space = program.getAddressFactory().getDefaultAddressSpace()
        # The PDB-only project was never auto-analyzed, so its functions hold no instructions yet: disassemble them in a
        # transaction that is rolled back at the end (nothing is saved to the project)
        tx = program.startTransaction("disassembly for this listing (not saved)")
        for va in args.va:
            f = fm.getFunctionContaining(space.getAddress(int(va, 16)))
            if f is None:
                lines.append(f"# no function at {va}")
                continue
            # PDB-only functions have one-byte bodies: follow the flow from the entry, list up to the next function
            entry = f.getEntryPoint()
            DisassembleCommand(entry, None, True).applyTo(program)
            following = fm.getFunctions(entry.add(1), True)
            end = following.next().getEntryPoint() if following.hasNext() else entry.add(0x10000)
            lines.append(f"# {f.getName(True)} @ {entry}")
            for ins in listing.getInstructions(entry, True):
                if ins.getAddress().compareTo(end) >= 0:
                    break
                raw = " ".join(f"{b & 0xff:02x}" for b in ins.getBytes())
                text = f"{ins.getAddress()}  {raw:<30}  {ins}"
                for ref in ins.getReferencesFrom():
                    if ref.getReferenceType().isCall():
                        callee = fm.getFunctionAt(ref.getToAddress())
                        if callee is not None:
                            text += f"    ; {callee.getName(True)}"
                lines.append(text)
    finally:
        if tx is not None:
            program.endTransaction(tx, False)
        project.close()
    out = "\n".join(lines) + "\n"
    if args.out:
        open(args.out, "w", encoding="utf-8").write(out)
        print(f"{len(lines)} lines -> {args.out}")
    else:
        sys.stdout.write(out)


if __name__ == "__main__":
    main()
