"""The source lines a function's code comes from, from its PDB's line table (dbghelp SymGetLineFromAddrW64 at every
byte of the function, so inlined code from other files does not stop the walk). With --overlay, our version of the
file is printed with the lines that have code in ATLAS's build marked "A": where the marks stop matching our code
lines, ATLAS's file gains or loses lines (an added list entry, a removed block) - the way step 1.9d found ARK's
double temporary variables in FK2ActionMenuBuilder::GetContextAllowedNodeTypes.

Usage: python -I _tools/pdb_func_lines.py <dll> <function> [--file <source file name>] [--overlay <our file> [from to]]
  function: a dbghelp pattern as for pdb_lookup.py (the first match is used), or "<hex VA> <hex size>" in
            pdb_lookup.py's numbering (image base 0x140000000)
  --file:   keep the line records of this source file only (default: the function's own file)
Output: "<VA>\t<line>\t<file>" per line record, or the overlay. Step 1.9d, 2026-10-23.
"""
import ctypes
import re
import struct
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

BASE = 0x140000000
TOOLS = Path(__file__).resolve().parent


class IMAGEHLP_LINEW64(ctypes.Structure):
    _fields_ = [("SizeOfStruct", wintypes.DWORD), ("Key", ctypes.c_void_p), ("LineNumber", wintypes.DWORD),
                ("FileName", ctypes.c_wchar_p), ("Address", ctypes.c_uint64)]


def file_name(path):
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        sys.exit(__doc__)
    dll = Path(args.pop(0)).resolve()
    only, overlay, span = None, None, None
    if "--file" in args:
        i = args.index("--file")
        only = args[i + 1].lower()
        del args[i:i + 2]
    if "--overlay" in args:
        i = args.index("--overlay")
        overlay = Path(args[i + 1])
        rest = args[i + 2:i + 4]
        if len(rest) == 2 and all(r.isdigit() for r in rest):
            span = (int(rest[0]), int(rest[1]))
            del args[i:i + 4]
        else:
            del args[i:i + 2]
    if len(args) == 2 and re.fullmatch(r"[0-9a-fA-F]{6,}", args[0]) and re.fullmatch(r"(0x)?[0-9a-fA-F]+", args[1]):
        start, size = int(args[0], 16), int(args[1], 16)
    else:
        out = subprocess.run([sys.executable, "-I", str(TOOLS / "pdb_lookup.py"), str(dll), args[0]],
                             capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
        rows = [l.split("\t") for l in out.splitlines() if re.match(r"[0-9a-f]+\t0x", l)]
        if not rows:
            sys.exit(f"no function matches {args[0]}")
        start, size = int(rows[0][0], 16), int(rows[0][1], 16)

    with open(dll, "rb") as f:
        head = f.read(4096)
    pe = struct.unpack_from("<I", head, 0x3C)[0]
    image_size = struct.unpack_from("<I", head, pe + 24 + 56)[0]
    d = ctypes.WinDLL(r"C:\Windows\System32\dbghelp.dll")
    proc = wintypes.HANDLE(0x1A7A6)
    d.SymSetOptions.argtypes = [wintypes.DWORD]
    d.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
    d.SymLoadModuleExW.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                   ctypes.c_uint64, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    d.SymLoadModuleExW.restype = ctypes.c_uint64
    d.SymGetLineFromAddrW64.argtypes = [wintypes.HANDLE, ctypes.c_uint64, ctypes.POINTER(wintypes.DWORD),
                                        ctypes.POINTER(IMAGEHLP_LINEW64)]
    d.SymSetOptions(0x4 | 0x10 | 0x200 | 0x80000)  # deferred loads, load lines, fail critical errors, no prompts
    d.SymInitializeW(proc, str(dll.parent), False)
    d.SymLoadModuleExW(proc, None, str(dll), None, BASE, image_size, None, 0)
    line = IMAGEHLP_LINEW64(SizeOfStruct=ctypes.sizeof(IMAGEHLP_LINEW64))
    disp = wintypes.DWORD()
    if only is None and d.SymGetLineFromAddrW64(proc, start, ctypes.byref(disp), ctypes.byref(line)):
        only = file_name(line.FileName)
    records = []
    for addr in range(start, start + size):
        if d.SymGetLineFromAddrW64(proc, addr, ctypes.byref(disp), ctypes.byref(line)) and disp.value == 0:
            name = file_name(line.FileName)
            if only is None or name == only:
                records.append((addr, line.LineNumber, name))

    if overlay is None:
        for addr, n, name in records:
            print(f"{addr:x}\t{n}\t{name}")
        return
    code = {n for _a, n, _f in records}
    text = overlay.read_text(encoding="utf-8", errors="replace").splitlines()
    first, last = span or (min(code), max(code))
    for n in range(first, min(last, len(text)) + 1):
        print(f"{n:6} {'A' if n in code else ' '} {text[n - 1][:120]}")


if __name__ == "__main__":
    main()
