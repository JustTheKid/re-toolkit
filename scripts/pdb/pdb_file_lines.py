"""Where one of ATLAS's source files differs from ours, from a PDB's line info: for every function whose line info
points into the file of the same name, ATLAS's first line (the opening brace) next to the opening brace of the same
function in our file, and the offset between them. A changing offset ("<-") marks where ATLAS's file gains or loses
lines; a function with "-" in our column is ATLAS's only (or not found by the simple definition scan). Narrow a
region down with pdb_func_lines.py --overlay.

Usage: python -I _tools/pdb_file_lines.py <dll> <our source file> [<symbol pattern>]
  symbol pattern: dbghelp wildcard of the functions to look up (default "*"; a narrower one is much faster),
                  e.g. "FK2ActionMenuBuilder::*"
Step 1.9d, 2026-10-23: found the console-variable and pure-cast changes in BlueprintGraph, the GraphEditorSettings
defaults and the 157 extra lines of ATLAS's EditorFactories.cpp.
"""
import re
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    dll, ours = sys.argv[1], Path(sys.argv[2])
    pattern = sys.argv[3] if len(sys.argv) > 3 else "*"
    name = ours.name.lower()

    out = subprocess.run([sys.executable, "-I", str(TOOLS / "pdb_lookup.py"), dll, pattern, "--lines"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    atlas = []
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) >= 5 and f[-1].lower().replace("/", "\\").rsplit("\\", 1)[-1].startswith(name + ":"):
            atlas.append((int(f[-1].rsplit(":", 1)[1]), f[2]))
    atlas.sort()

    text = ours.read_text(encoding="utf-8", errors="replace").splitlines()
    # our functions: a line "<...> Class::Func(" (a definition) followed, within a few lines, by "{"
    mine = {}
    for i, l in enumerate(text):
        m = re.match(r"^[\w:<>*&, ]*?\b([A-Z]\w*::~?\w+)\s*\(", l)
        if m and not l.rstrip().endswith(";"):
            for j in range(i, min(i + 6, len(text))):
                if text[j].strip() == "{":
                    mine.setdefault(m.group(1), []).append(j + 1)
                    break

    seen = {}
    prev = None
    for lno, fn in atlas:
        k = seen.get(fn, 0)
        seen[fn] = k + 1
        ourl = mine.get(fn, [])
        o = ourl[k] if k < len(ourl) else None
        off = (lno - o) if o else None
        mark = "" if off == prev else "  <-"
        print(f"{lno:6} {o if o else '-':>6} {off if off is not None else '':>5}  {fn}{mark}")
        if off is not None:
            prev = off


if __name__ == "__main__":
    main()
