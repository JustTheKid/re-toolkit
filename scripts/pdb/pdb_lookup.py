"""Look up functions in an exe's PDB with Windows' dbghelp: VA, size and full C++ prototype.

Much lighter than opening the Ghidra project (a few hundred MB instead of several GB), so it works while the
game is running. The prototype comes from the PDB's public (decorated) symbol, undecorated, so argument types
are exact — what a timing wrapper needs to forward arguments correctly.

Usage: python -I _tools/pdb_lookup.py <exe> <pattern> [pattern ...] [--lines] [--data]
  pattern  dbghelp wildcard on the undecorated name, e.g. "UGameEngine::Tick" or "*CollectGarbage*"
  --lines  add each function's source file and line from the PDB's line info, i.e. ATLAS's own source tree
           layout (d:/atlassvn/engine/source/...); functions UHT generates inline (GENERATED_* bodies) give
           the class's header
The PDB must sit next to the exe (it does for the client and server installs).
  --data   also global variables (a static table's address and size, to read from the exe)
"""
import ctypes
import struct
import sys
from ctypes import wintypes
from pathlib import Path

IMAGE_BASE = 0x140000000
SYMOPT_UNDNAME = 0x2
SYMOPT_DEFERRED_LOADS = 0x4
SYMOPT_LOAD_LINES = 0x10
SYMOPT_PUBLICS_ONLY = 0x4000
SYMOPT_FAIL_CRITICAL_ERRORS = 0x200
SYMOPT_NO_PROMPTS = 0x80000
UNDNAME_COMPLETE = 0x0
SYMTAG_FUNCTION = 5
SYMTAG_DATA = 7
SYMTAG_PUBLIC = 10
MAX_NAME = 2000


class IMAGEHLP_LINEW64(ctypes.Structure):
    _fields_ = [("SizeOfStruct", wintypes.DWORD), ("Key", ctypes.c_void_p), ("LineNumber", wintypes.DWORD),
                ("FileName", ctypes.c_wchar_p), ("Address", ctypes.c_uint64)]


class SYMBOL_INFOW(ctypes.Structure):
    _fields_ = [("SizeOfStruct", wintypes.ULONG), ("TypeIndex", wintypes.ULONG),
                ("Reserved", ctypes.c_uint64 * 2), ("Index", wintypes.ULONG), ("Size", wintypes.ULONG),
                ("ModBase", ctypes.c_uint64), ("Flags", wintypes.ULONG), ("Value", ctypes.c_uint64),
                ("Address", ctypes.c_uint64), ("Register", wintypes.ULONG), ("Scope", wintypes.ULONG),
                ("Tag", wintypes.ULONG), ("NameLen", wintypes.ULONG), ("MaxNameLen", wintypes.ULONG),
                ("Name", wintypes.WCHAR * 1)]


def make_symbol():
    buf = ctypes.create_string_buffer(ctypes.sizeof(SYMBOL_INFOW) + MAX_NAME * 2)
    sym = ctypes.cast(buf, ctypes.POINTER(SYMBOL_INFOW)).contents
    sym.SizeOfStruct = ctypes.sizeof(SYMBOL_INFOW)
    sym.MaxNameLen = MAX_NAME
    return buf, sym


def sym_name(sym):
    return ctypes.wstring_at(ctypes.addressof(sym) + SYMBOL_INFOW.Name.offset, sym.NameLen).rstrip("\x00")


def image_size(exe: Path) -> int:
    with open(exe, "rb") as f:
        head = f.read(4096)
    pe = struct.unpack_from("<I", head, 0x3C)[0]
    return struct.unpack_from("<I", head, pe + 24 + 56)[0]


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    lines = "--lines" in sys.argv
    data = "--data" in sys.argv  # global variables too (address and size), e.g. a static table to read
    args = [a for a in sys.argv[1:] if a not in ("--lines", "--data")]
    exe = Path(args[0]).resolve()
    patterns = args[1:]

    dbghelp = ctypes.WinDLL(r"C:\Windows\System32\dbghelp.dll")
    process = wintypes.HANDLE(0x1A7A5)  # any unique value; we never invade a real process
    dbghelp.SymSetOptions.argtypes = [wintypes.DWORD]
    dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
    dbghelp.SymLoadModuleExW.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                         ctypes.c_uint64, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    dbghelp.SymLoadModuleExW.restype = ctypes.c_uint64
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.POINTER(SYMBOL_INFOW), wintypes.ULONG, ctypes.c_void_p)
    dbghelp.SymEnumSymbolsW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, wintypes.LPCWSTR, callback_type,
                                        ctypes.c_void_p]
    dbghelp.SymFromAddrW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64),
                                     ctypes.c_void_p]
    dbghelp.UnDecorateSymbolNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    dbghelp.SymGetLineFromAddrW64.argtypes = [wintypes.HANDLE, ctypes.c_uint64, ctypes.POINTER(wintypes.DWORD),
                                              ctypes.POINTER(IMAGEHLP_LINEW64)]

    base_opts = SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS
    if lines:
        base_opts |= SYMOPT_LOAD_LINES
    dbghelp.SymSetOptions(base_opts | SYMOPT_UNDNAME)
    if not dbghelp.SymInitializeW(process, str(exe.parent), False):
        sys.exit(f"SymInitialize failed: {ctypes.GetLastError()}")
    try:
        if not dbghelp.SymLoadModuleExW(process, None, str(exe), None, IMAGE_BASE, image_size(exe), None, 0):
            sys.exit(f"SymLoadModuleEx failed: {ctypes.GetLastError()}")

        found = {}
        hits = [0]

        @callback_type
        def on_symbol(p, _size, _ctx):
            s = p.contents
            if s.Tag == SYMTAG_FUNCTION or (data and s.Tag == SYMTAG_DATA):
                found.setdefault(s.Address, (sym_name(s), s.Size))
                hits[0] += 1
            return True

        for pattern in patterns:
            hits[0] = 0
            dbghelp.SymEnumSymbolsW(process, IMAGE_BASE, pattern, on_symbol, None)
            if not hits[0]:
                print(f"# no {'symbol' if data else 'function'} matches {pattern}")

        # Prototypes: the public symbol at the same address carries the decorated (mangled) name.
        dbghelp.SymSetOptions(base_opts | SYMOPT_PUBLICS_ONLY)
        buf, sym = make_symbol()
        out = ctypes.create_unicode_buffer(4096)
        for addr in sorted(found):
            name, size = found[addr]
            proto = ""
            disp = ctypes.c_uint64()
            sym.MaxNameLen = MAX_NAME
            if dbghelp.SymFromAddrW(process, addr, ctypes.byref(disp), ctypes.addressof(sym)) and disp.value == 0:
                decorated = sym_name(sym)
                if dbghelp.UnDecorateSymbolNameW(decorated, out, len(out), UNDNAME_COMPLETE):
                    proto = out.value
            where = ""
            if lines:
                line = IMAGEHLP_LINEW64(SizeOfStruct=ctypes.sizeof(IMAGEHLP_LINEW64))
                line_disp = wintypes.DWORD()
                if dbghelp.SymGetLineFromAddrW64(process, addr, ctypes.byref(line_disp), ctypes.byref(line)):
                    where = f"\t{line.FileName}:{line.LineNumber}"
            print(f"{addr:x}\t{size:#x}\t{name}\t{proto}{where}")
    finally:
        dbghelp.SymCleanup(process)


if __name__ == "__main__":
    main()
