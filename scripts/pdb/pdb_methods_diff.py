"""Which member functions a class has in one binary and not in another, from the two PDBs (pdb_struct.py --methods):
ATLAS's DevKit DLL against the same module of our engine build, to scope a port by the methods ATLAS added or
removed. Overloads count once per name; generated members (operator new / =, StaticClass, StaticRegisterNatives,
destructors, deleting destructors) are left out.

Usage: python -I _tools/pdb_methods_diff.py <atlas binary> <our binary> <Class> [<Class> ...]
  e.g. pdb_methods_diff.py "<DevKit>/UE4Editor-Engine.dll" D:/UE/4.5.1/Engine/Binaries/Win64/UE4Editor-Engine.dll
       UAnimSequence FRawCurveTracks
Step 1.9e, 2026-10-23.
"""
import re
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
SKIP = re.compile(r"::(operator|StaticClass|StaticRegisterNatives|GetPrivateStaticClass|StaticClassCastFlags|~|"
                  r"`|StaticStruct|__vecDelDtor|__local_vftable)|^operator|^__vecDelDtor|^__local_vftable")


def methods(binary, cls):
    out = subprocess.run([sys.executable, "-I", str(TOOLS / "pdb_struct.py"), binary, "--methods", cls],
                         capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    names = []
    for line in out.splitlines():
        m = re.match(r"^\s+\+0x[0-9a-f]+\s+(.+?)\s*$", line)
        if not m:
            continue
        name = m.group(1)
        if SKIP.search(name) or name == cls:
            continue
        name = name.split("::")[-1]
        if name not in names:
            names.append(name)
    return names


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    atlas, ours = sys.argv[1], sys.argv[2]
    for cls in sys.argv[3:]:
        a, o = methods(atlas, cls), methods(ours, cls)
        only_a = [n for n in a if n not in o]
        only_o = [n for n in o if n not in a]
        print(f"== {cls}: ATLAS {len(a)}, ours {len(o)}")
        if only_a:
            print("   ATLAS only: " + ", ".join(only_a))
        if only_o:
            print("   ours only:  " + ", ".join(only_o))


if __name__ == "__main__":
    main()
