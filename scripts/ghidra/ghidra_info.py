"""Print addresses of named symbols and offsets of struct fields from an analyzed Ghidra project.

Usage: python ghidra_info.py --symbols GEngine UGameViewportClient::ConsoleCommand --fields UEngine.GameViewport
       [--project D:\\ATLAS\\_re\\ghidra-client --name client --program AtlasGame.exe]
"""
import argparse
import os
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
os.environ.setdefault("GHIDRA_INSTALL_DIR", str(TOOLS / "ghidra_12.1.4_PUBLIC"))
os.environ.setdefault("JAVA_HOME", str(TOOLS / "jdk-21.0.12.1+1"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--symbols", nargs="*", default=[])
    ap.add_argument("--fields", nargs="*", default=[], help="Struct.Field")
    ap.add_argument("--project", default=r"D:\ATLAS\_re\ghidra-client")
    ap.add_argument("--name", default="client")
    ap.add_argument("--program", default="AtlasGame.exe")
    args = ap.parse_args()

    import pyghidra
    launcher = pyghidra.HeadlessPyGhidraLauncher()
    launcher.add_vmargs("-Xmx6g")
    launcher.start()
    from ghidra.base.project import GhidraProject

    project = GhidraProject.openProject(args.project, args.name, True)
    try:
        program = project.openProgram("/", args.program, True)
        st = program.getSymbolTable()
        for full in args.symbols:
            ns, _, short = full.rpartition("::")
            for sym in st.getSymbols(short):
                if not ns or sym.getParentNamespace().getName(True).endswith(ns):
                    print(f"SYMBOL {sym.getName(True)} @ {sym.getAddress()} ({sym.getSymbolType()})")
        dtm = program.getDataTypeManager()
        for spec in args.fields:
            struct_name, field = spec.split(".", 1)
            found = False
            for dt in dtm.getAllStructures():
                if dt.getName() == struct_name:
                    for comp in dt.getComponents():
                        if comp.getFieldName() == field:
                            print(f"FIELD {dt.getCategoryPath()}/{struct_name}.{field} offset 0x{comp.getOffset():x} type {comp.getDataType().getName()}")
                            found = True
            if not found:
                print(f"FIELD {spec} not found")
    finally:
        project.close()


if __name__ == "__main__":
    main()
