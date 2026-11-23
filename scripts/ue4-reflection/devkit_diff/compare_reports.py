"""Compare two folders of diff reports: diffs.py's <work>/diff before and after a port, or a re-run against an
earlier run (the "byte-identical to step 1.9c" checks of steps 1.9a-1.9d). Each *.md / *.json of the first folder
against the file of the same name in the second, ignoring the line that names the input folders ("ATLAS `<dir>` vs
ours `<dir>`..."; diffs.py's *_row.json and summary.md name nothing but results). Prints "identical" or "DIFFERS"
with the first differing lines per file, then the files only one folder has; exit 1 if anything differs.

Usage: python -I _tools/devkit_diff/compare_reports.py <old dir> <new dir> [--glob 'animgraph_*'] [--lines 20]
Step 1.9d's recheck (2026-10-23) did the same with `diff <(sed 3d old) <(sed 3d new)`.
"""
import argparse
import difflib
import re
import sys
from pathlib import Path

INPUTS = re.compile(r"^ATLAS `.*` vs ours `")


def body(path):
    return [l for l in path.read_text(encoding="utf-8", errors="replace").splitlines() if not INPUTS.match(l)]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("old")
    ap.add_argument("new")
    ap.add_argument("--glob", default="*", help="file name pattern, e.g. 'animgraph_*' (default: all)")
    ap.add_argument("--lines", type=int, default=20, help="differing lines shown per file")
    a = ap.parse_args()
    old, new = Path(a.old), Path(a.new)
    names = lambda d: {p.name for p in d.glob(a.glob) if p.is_file() and p.suffix in (".md", ".json")}
    mine, theirs = names(old), names(new)
    differ = 0
    for name in sorted(mine & theirs):
        x, y = body(old / name), body(new / name)
        if x == y:
            print(f"{name}: identical")
            continue
        differ += 1
        print(f"{name}: DIFFERS")
        for line in list(difflib.unified_diff(x, y, "old", "new", n=0, lineterm=""))[2:2 + a.lines]:
            print("   ", line)
    for label, only in (("only in old", mine - theirs), ("only in new", theirs - mine)):
        if only:
            print(f"{label}: {', '.join(sorted(only))}")
    print(f"{len(mine & theirs)} compared, {differ} differ, {len(mine - theirs)} only in old, "
          f"{len(theirs - mine)} only in new")
    sys.exit(1 if differ or mine ^ theirs else 0)


if __name__ == "__main__":
    main()
