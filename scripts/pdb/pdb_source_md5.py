"""Which of ATLAS's source files are stock: a PDB records the MD5 of every source file its binary was compiled from
(the file checksum table). This compares those MD5s with the files of a stock commit of our engine repo (as stored,
LF and CRLF variants), so every engine file ATLAS changed or added is listed without reading any code.

Usage: python -I _tools/pdb_source_md5.py <pe or pdb> [--engine D:/UE/4.5.1] [--stock 14d2ac8] [--prefix d:\\atlassvn\\]
           [--tsv <out.tsv>] [--list differs|new|same]
  The PDB is read with llvm-pdbutil (Visual Studio's LLVM tools, found automatically). Paths are matched below the
  prefix (ATLAS's server PDB: d:\\atlassvn\\, the DevKit's: e:\\atlasdevkitsvn\\) against the stock tree.
  Output: counts per state (same / differs / not in stock) and per engine area; --tsv writes path, md5, state.
2026-10-24: server PDB 5,390 engine files, 2,886 same as stock 4.5.1, 1,435 differ, 1,069 not in stock.
"""
import argparse
import collections
import glob
import hashlib
import re
import subprocess
import sys
from pathlib import Path

PDBUTIL_GLOBS = [r"C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\Llvm\x64\bin\llvm-pdbutil.exe",
                 r"C:\Program Files (x86)\Microsoft Visual Studio\*\*\VC\Tools\Llvm\x64\bin\llvm-pdbutil.exe"]


def pdbutil():
    for pattern in PDBUTIL_GLOBS:
        hits = sorted(glob.glob(pattern))
        if hits:
            return hits[-1]
    sys.exit("llvm-pdbutil.exe not found (Visual Studio's C++ Clang tools)")


def file_md5s(pdb, prefix):
    out = subprocess.run([pdbutil(), "dump", "-files", str(pdb)], capture_output=True, text=True, encoding="utf-8",
                         errors="replace").stdout
    files = {}
    for m in re.finditer(r"\(MD5:\s*([0-9A-Fa-f]{32})\)\s*(\S[^\r\n]*)", out):
        path = m.group(2).strip().lower().replace("/", "\\")
        if path.startswith(prefix):
            files[path] = m.group(1).lower()
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("--engine", default=r"D:\UE\4.5.1")
    ap.add_argument("--stock", default="14d2ac8")
    ap.add_argument("--prefix", default="d:\\atlassvn\\")
    ap.add_argument("--tsv")
    ap.add_argument("--list", choices=("differs", "new", "same"))
    a = ap.parse_args()
    pdb = Path(a.binary)
    if pdb.suffix.lower() != ".pdb":
        pdb = pdb.with_suffix(".pdb")
    prefix = a.prefix.lower()
    files = {p: m for p, m in file_md5s(pdb, prefix).items() if p.startswith(prefix + "engine\\")}
    tree = subprocess.run(["git", "-C", a.engine, "ls-tree", "-r", "--name-only", a.stock], capture_output=True,
                          text=True, check=True).stdout.splitlines()
    stock = {(prefix + f.replace("/", "\\")).lower(): f for f in tree}
    rows, counts, areas = [], collections.Counter(), collections.Counter()
    for path, md5 in sorted(files.items()):
        f = stock.get(path)
        if f is None:
            state = "new"
        else:
            data = subprocess.run(["git", "-C", a.engine, "show", f"{a.stock}:{f}"], capture_output=True,
                                  check=True).stdout
            lf = data.replace(b"\r\n", b"\n")
            known = {hashlib.md5(v).hexdigest() for v in (data, lf, lf.replace(b"\n", b"\r\n"))}
            state = "same" if md5 in known else "differs"
        rows.append((path, md5, state))
        counts[state] += 1
        parts = path[len(prefix):].split("\\")
        areas[("\\".join(parts[1:4]) if parts[1] == "source" else "\\".join(parts[1:3]), state)] += 1
    print(f"{pdb.name}: {len(rows)} engine source files; same as stock {counts['same']}, differ {counts['differs']}, "
          f"not in stock {counts['new']}")
    names = sorted({k for k, _ in areas}, key=lambda k: -sum(areas[(k, s)] for s in ("same", "differs", "new")))
    print(f"{'area':45s} {'same':>6s} {'differs':>8s} {'new':>6s}")
    for k in names[:25]:
        print(f"{k:45s} {areas[(k, 'same')]:6d} {areas[(k, 'differs')]:8d} {areas[(k, 'new')]:6d}")
    if a.tsv:
        with open(a.tsv, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("path\tmd5\tstate\n")
            fh.writelines(f"{p}\t{m}\t{s}\n" for p, m, s in rows)
    if a.list:
        for p, _, s in rows:
            if s == a.list:
                print(p)


if __name__ == "__main__":
    main()
