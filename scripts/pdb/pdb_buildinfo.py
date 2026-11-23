"""The exact compiler command line of a compile unit, from the PDB: each module's S_BUILDINFO symbol points to an
LF_BUILDINFO record in the ID stream (working directory, compiler, source file, PDB, arguments; the arguments are an
LF_STRING_ID whose prefix is an LF_SUBSTR_LIST of further strings). Read with llvm-pdbutil (VS 2022's LLVM tools).

Usage: python -I _tools/pdb_buildinfo.py <pe or pdb> <compile unit regex> [--args-only] [--split] [--limit N]
  e.g. pdb_buildinfo.py ShooterGameServer.exe "\\\\ShooterGame\\\\ARKDinoDataObject\\.cpp\\.obj$" --split
Prints per matching unit: cwd, tool, source, pdb and the argument string (--split: one argument per line).
2026-10-24: ATLAS's server game files are compiled with
  -nologo -Oi -Zp8 -Gy -fp:fast -c -Zm800 -bigobj -wd4819 -wd4651 -wd4005 -Ox -Zo -Ot -Ob2 -errorreport:prompt
  -EHs -EHc -Z7 -MD ... -TP -GR- -W4 -X -Yu<pch> -Fp<pch> -FI<pch> (VS2013 Update 5 amd64 cl.exe, Windows Kits 8.1).
"""
import argparse
import re
import shlex
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pdb_source_md5 import pdbutil  # noqa: E402


def run(*args):
    return subprocess.run([pdbutil(), *args], capture_output=True, text=True, encoding="utf-8", errors="replace").stdout


def modules(pdb):
    """(index, object path) of every compile unit."""
    return [(int(m.group(1)), m.group(2)) for m in re.finditer(r"^\s*Mod (\d+) \| `([^`]*)`", run("dump", "-modules",
                                                                                                 str(pdb)), re.M)]


def build_id(pdb, modi):
    m = re.search(r"S_BUILDINFO \[size = \d+\] BuildId = `(0x[0-9A-Fa-f]+)`", run("dump", "-symbols", f"-modi={modi}",
                                                                                 str(pdb)))
    return m.group(1) if m else None


def build_info(pdb, bid):
    text = run("dump", "-ids", f"-id-index={bid}", "-dependents", str(pdb))
    strings, refs, lists = {}, {}, {}
    for m in re.finditer(r"^\s*(0x[0-9A-F]+) \| LF_STRING_ID \[size = \d+\] ID: (<no type>|0x[0-9A-F]+), String: (.*)$",
                         text, re.M):
        strings[m.group(1)] = m.group(3)
        if m.group(2).startswith("0x"):
            refs[m.group(1)] = m.group(2)
    for m in re.finditer(r"^\s*(0x[0-9A-F]+) \| LF_SUBSTR_LIST \[size = \d+\]\n((?:\s+0x[0-9A-F]+: `.*`\n?)+)", text,
                         re.M):
        lists[m.group(1)] = re.findall(r"(0x[0-9A-F]+): `", m.group(2))
    m = re.search(rf"^\s*{bid.upper().replace('0X', '0x')} \| LF_BUILDINFO \[size = \d+\]\n((?:\s+0x[0-9A-F]+: `.*`\n?)+)",
                  text, re.M)
    if not m:
        return None
    ids = re.findall(r"(0x[0-9A-F]+): `", m.group(1))

    def full(sid):
        pre = "".join(strings.get(s, "") for s in lists.get(refs.get(sid, ""), []))
        return pre + strings.get(sid, "")
    keys = ["cwd", "tool", "source", "pdb", "args"]
    return {k: full(s) for k, s in zip(keys, ids)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("unit")
    ap.add_argument("--args-only", action="store_true")
    ap.add_argument("--split", action="store_true")
    ap.add_argument("--limit", type=int, default=5)
    a = ap.parse_args()
    pdb = Path(a.binary)
    if pdb.suffix.lower() != ".pdb":
        pdb = pdb.with_suffix(".pdb")
    pat = re.compile(a.unit, re.I)
    hits = [(i, o) for i, o in modules(pdb) if pat.search(o)][:a.limit]
    if not hits:
        sys.exit("no compile unit matches")
    for modi, obj in hits:
        bid = build_id(pdb, modi)
        info = build_info(pdb, bid) if bid else None
        if not info:
            print(f"== {obj}: no build info")
            continue
        if a.args_only:
            print(info["args"])
            continue
        print(f"== {obj}\n   cwd:    {info['cwd']}\n   tool:   {info['tool']}\n   source: {info['source']}\n"
              f"   pdb:    {info['pdb']}")
        if a.split:
            for arg in shlex.split(info["args"], posix=False):
                print("   ", arg)
        else:
            print("   args:  ", info["args"])


if __name__ == "__main__":
    main()
