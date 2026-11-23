"""DevKit module diff, after step 2 (export.ps1): per module of <work>/modules.tsv, the DevKit exports' Z_Construct
files by kind (the untyped metadata export, and the typed one for DLLs with a PDB) against the census's count of our
types, and the last error-looking line of each step's log in <work>/logs. A module whose export has fewer classes and
structs than ours is marked: an export that stopped early, or types ATLAS lacks (diffs.py tells which). Static.

Usage: python -I _tools/devkit_diff/check_exports.py --work <dir> [--modules AnimGraph,Paper*] [--corpus <dir>]
"""
import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devkit_modules import CORPUS, read_census, selector  # noqa: E402

KIND = re.compile(r"^Z_Construct_U(Class|ScriptStruct|Function|Enum)_")
BAD = re.compile(r"error|exception|traceback|failed|timeout|timed out", re.I)
CLEAN = re.compile(r"\b0 (errors?|failed)", re.I)


def kinds(d):
    c = {}
    for f in d.glob("*.c") if d.is_dir() else ():
        m = KIND.match(f.name)
        k = m.group(1) if m else "other"
        c[k] = c.get(k, 0) + 1
    return c


def read_log(path):
    # PowerShell 5.1's *> writes UTF-16
    data = path.read_bytes()
    return data.decode("utf-16" if data[:2] == b"\xff\xfe" else "utf-8", errors="replace")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work", required=True)
    ap.add_argument("--modules")
    ap.add_argument("--corpus", default=str(CORPUS))
    a = ap.parse_args()
    wanted, _ = selector(a.modules)
    corpus, logs = Path(a.corpus), Path(a.work) / "logs"
    for row in read_census(a.work):
        module, low = row["module"], row["module"].lower()
        if not wanted(module):
            continue
        if not row["dll"]:
            print(f"{module:30} no DevKit DLL")
            continue
        meta = kinds(corpus / low)
        typed = kinds(corpus / f"{low}-typed") if row["pdb"] == "pdb" else None
        n = int(row["types"])
        short = meta.get("Class", 0) + meta.get("ScriptStruct", 0) < n or (
            typed is not None and typed.get("Class", 0) + typed.get("ScriptStruct", 0) < n)
        line = (f"{module:30} {row['pdb']:5} ours {n:>3} t {row['enums']:>2} e   meta "
                f"{meta.get('Class', 0) + meta.get('ScriptStruct', 0):>3} t {meta.get('Enum', 0):>2} e "
                f"{meta.get('Function', 0):>3} f")
        if typed is not None:
            n_typed = typed.get("Class", 0) + typed.get("ScriptStruct", 0)
            line += f"   typed {n_typed:>3} t {typed.get('Function', 0):>3} f"
        print(line + ("  <-- fewer types than ours" if short else ""))
        for step in ("analyze", "meta", "typed"):
            log = logs / f"{low}.{step}.txt"
            if log.exists():
                hits = [l.strip() for l in read_log(log).splitlines() if BAD.search(l) and not CLEAN.search(l)]
                if hits:
                    print(f"      {step}: {hits[-1][:110]}")


if __name__ == "__main__":
    main()
