"""The judge's verdicts per source file: every function func_match.py found in the original (MATCH / MATCH~ / DIFF /
SIZE), grouped by the file ATLAS compiled its code from (the PDB's line record at the function's first byte, dbghelp
SymGetLineFromAddrW64) and that file's state in pdb_source_md5.py's table (the same as stock 4.5.1, changed by ATLAS,
or new). In a unity unit this separates differences that come from headers and layouts (a stock .cpp whose functions
differ) from ATLAS's own code changes (a changed .cpp): the order to port them in.

Usage: python -I _tools/judge_files.py <original pe> <match.json> [...] [--tsv <pdb_source_md5 tsv>] [--top N]
  --tsv  default tracking/evidence/engine-files-server.tsv (pdb_source_md5.py --tsv on the server PDB)
Output: per file (most DIFFs first): state, functions found, byte-identical, DIFF, percent; then totals per state.
2026-10-25 (phase 4d: the judge on ATLAS's unity units, unity_unit.py).
"""
import argparse
import csv
import ctypes
import json
import struct
from collections import defaultdict
from ctypes import wintypes
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


class IMAGEHLP_LINEW64(ctypes.Structure):
    _fields_ = [("SizeOfStruct", wintypes.DWORD), ("Key", ctypes.c_void_p), ("LineNumber", wintypes.DWORD),
                ("FileName", ctypes.c_wchar_p), ("Address", ctypes.c_uint64)]


def line_reader(pe):
    """A function (rva -> lower-case source path or None) over the PE's PDB."""
    with open(pe, "rb") as f:
        head = f.read(4096)
    e = struct.unpack_from("<I", head, 0x3C)[0]
    base = struct.unpack_from("<Q", head, e + 24 + 24)[0]
    image_size = struct.unpack_from("<I", head, e + 24 + 56)[0]
    d = ctypes.WinDLL(r"C:\Windows\System32\dbghelp.dll")
    proc = wintypes.HANDLE(0x2B7C1)
    d.SymSetOptions.argtypes = [wintypes.DWORD]
    d.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
    d.SymLoadModuleExW.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                   ctypes.c_uint64, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    d.SymLoadModuleExW.restype = ctypes.c_uint64
    d.SymGetLineFromAddrW64.argtypes = [wintypes.HANDLE, ctypes.c_uint64, ctypes.POINTER(wintypes.DWORD),
                                        ctypes.POINTER(IMAGEHLP_LINEW64)]
    d.SymSetOptions(0x4 | 0x10 | 0x200 | 0x80000)  # deferred loads, load lines, fail critical errors, no prompts
    d.SymInitializeW(proc, str(Path(pe).resolve().parent), False)
    d.SymLoadModuleExW(proc, None, str(Path(pe).resolve()), None, base, image_size, None, 0)
    line = IMAGEHLP_LINEW64(SizeOfStruct=ctypes.sizeof(IMAGEHLP_LINEW64))
    disp = wintypes.DWORD()

    def at(rva):
        if d.SymGetLineFromAddrW64(proc, base + rva, ctypes.byref(disp), ctypes.byref(line)):
            return line.FileName.lower()
        return None
    return at


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("original")
    ap.add_argument("match", nargs="+")
    ap.add_argument("--tsv", default=str(REPO / "tracking" / "evidence" / "engine-files-server.tsv"))
    ap.add_argument("--top", type=int, default=40)
    a = ap.parse_args()
    with open(a.tsv, encoding="utf-8") as f:
        states = {r["path"].lower(): r["state"] for r in csv.DictReader(f, delimiter="\t")}
    at = line_reader(a.original)
    per = defaultdict(lambda: [0, 0, 0])  # found, identical, diff
    for m in a.match:
        for r in json.loads(Path(m).read_text(encoding="utf-8")):
            if r["state"] == "MISSING" or "rva" not in r:
                continue
            src = at(r["rva"]) or "(no line record)"
            c = per[src]
            c[0] += 1
            c[1] += r["state"] in ("MATCH", "MATCH~", "MATCH-L")  # MATCH-L: Q-0017
            c[2] += r["state"] in ("DIFF", "SIZE")
    totals = defaultdict(lambda: [0, 0, 0, 0])
    rows = []
    for src, (found, ident, diff) in per.items():
        state = states.get(src, "not in the table")
        rows.append((diff, src, state, found, ident))
        t = totals[state]
        t[0] += 1
        t[1] += found
        t[2] += ident
        t[3] += diff
    rows.sort(key=lambda r: (-r[0], r[1]))
    print(f"{'DIFF':>5} {'found':>6} {'ident':>6} {'%':>6}  state      file")
    for diff, src, state, found, ident in rows[:a.top]:
        name = src.split("\\engine\\source\\", 1)[-1]
        print(f"{diff:>5} {found:>6} {ident:>6} {100 * ident / found:>5.1f}%  {state:<10} {name}")
    print("\nper file state: files, functions found, byte-identical, DIFF")
    for state, (files, found, ident, diff) in sorted(totals.items(), key=lambda kv: -kv[1][3]):
        print(f"  {state:<16} {files:>5} files {found:>7} {ident:>7} ({100 * ident / max(found, 1):.1f}%) {diff:>6} DIFF")


if __name__ == "__main__":
    main()
