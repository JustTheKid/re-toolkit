"""Enums from an exe's PDB via dbghelp: list an enum's members with values, or find type names by pattern.
Light on memory (no Ghidra).
Usage: python -I _tools/pdb_enum.py <exe> <EnumName> [EnumName ...]      members and values
       python -I _tools/pdb_enum.py <exe> --find "<mask>" [--find ...]     type names matching a dbghelp mask (*, ?)
"""
import ctypes
import os
import struct
import sys
from ctypes import wintypes

IMAGE_BASE = 0x140000000
SYMOPT = 0x4 | 0x200 | 0x80000  # DEFERRED_LOADS | FAIL_CRITICAL_ERRORS | NO_PROMPTS
TI_GET_SYMTAG, TI_GET_SYMNAME, TI_FINDCHILDREN, TI_GET_VALUE, TI_GET_CHILDRENCOUNT = 0, 1, 7, 11, 13
SYMTAG_ENUM = 12
VT_INTS = {2: "<h", 3: "<i", 16: "<b", 17: "<B", 18: "<H", 19: "<I", 20: "<q", 21: "<Q", 22: "<i", 23: "<I"}


class SYMBOL_INFOW(ctypes.Structure):
    _fields_ = [("SizeOfStruct", wintypes.ULONG), ("TypeIndex", wintypes.ULONG), ("Reserved", ctypes.c_uint64 * 2),
                ("Index", wintypes.ULONG), ("Size", wintypes.ULONG), ("ModBase", ctypes.c_uint64),
                ("Flags", wintypes.ULONG), ("Value", ctypes.c_uint64), ("Address", ctypes.c_uint64),
                ("Register", wintypes.ULONG), ("Scope", wintypes.ULONG), ("Tag", wintypes.ULONG),
                ("NameLen", wintypes.ULONG), ("MaxNameLen", wintypes.ULONG), ("Name", wintypes.WCHAR * 1)]


def image_size(path):
    d = open(path, "rb").read(4096)
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    return struct.unpack_from("<I", d, pe + 24 + 56)[0]


def main():
    exe, args = sys.argv[1], sys.argv[2:]
    dh = ctypes.WinDLL(r"C:\Windows\System32\dbghelp.dll")
    proc = wintypes.HANDLE(0x5E9A)
    dh.SymSetOptions(SYMOPT)
    dh.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
    dh.SymLoadModuleExW.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                    ctypes.c_uint64, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    dh.SymLoadModuleExW.restype = ctypes.c_uint64
    dh.SymGetTypeFromNameW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, wintypes.LPCWSTR,
                                       ctypes.POINTER(SYMBOL_INFOW)]
    dh.SymGetTypeInfo.argtypes = [wintypes.HANDLE, ctypes.c_uint64, wintypes.ULONG, ctypes.c_int, ctypes.c_void_p]
    callback = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.POINTER(SYMBOL_INFOW), wintypes.ULONG, ctypes.c_void_p)
    dh.SymEnumTypesByNameW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, wintypes.LPCWSTR, callback, ctypes.c_void_p]

    dh.SymInitializeW(proc, os.path.dirname(exe), False)
    if not dh.SymLoadModuleExW(proc, None, exe, None, IMAGE_BASE, image_size(exe), None, 0):
        sys.exit("SymLoadModuleEx failed")

    def name_of(tid):
        p = ctypes.c_void_p()
        if dh.SymGetTypeInfo(proc, IMAGE_BASE, tid, TI_GET_SYMNAME, ctypes.byref(p)) and p.value:
            s = ctypes.wstring_at(p.value)
            ctypes.windll.kernel32.LocalFree(p)
            return s
        return ""

    def value_of(tid):
        var = (ctypes.c_ubyte * 24)()
        if not dh.SymGetTypeInfo(proc, IMAGE_BASE, tid, TI_GET_VALUE, ctypes.byref(var)):
            return None
        vt = struct.unpack_from("<H", bytes(var), 0)[0]
        fmt = VT_INTS.get(vt)
        return struct.unpack_from(fmt, bytes(var), 8)[0] if fmt else f"vt{vt}"

    i = 0
    while i < len(args):
        if args[i] == "--find":
            mask = args[i + 1]
            i += 2
            hits = []

            @callback
            def on_type(p, _size, _ctx):
                info = p.contents
                name = ctypes.wstring_at(ctypes.addressof(info) + SYMBOL_INFOW.Name.offset, info.NameLen)
                hits.append((name, info.Tag))
                return True

            dh.SymEnumTypesByNameW(proc, IMAGE_BASE, mask, on_type, None)
            print(f"== types matching {mask}: {len(hits)}")
            for name, tag in sorted(set(hits)):
                print(f"   {'enum ' if tag == SYMTAG_ENUM else ''}{name}")
            continue
        tname = args[i]
        i += 1
        buf = ctypes.create_string_buffer(ctypes.sizeof(SYMBOL_INFOW) + 2048)
        sym = ctypes.cast(buf, ctypes.POINTER(SYMBOL_INFOW)).contents
        sym.SizeOfStruct = ctypes.sizeof(SYMBOL_INFOW)
        sym.MaxNameLen = 1024
        if not dh.SymGetTypeFromNameW(proc, IMAGE_BASE, tname, ctypes.byref(sym)):
            print(f"# type not found: {tname}")
            continue
        tid = sym.TypeIndex
        count = wintypes.ULONG()
        dh.SymGetTypeInfo(proc, IMAGE_BASE, tid, TI_GET_CHILDRENCOUNT, ctypes.byref(count))

        class FC(ctypes.Structure):
            _fields_ = [("Count", wintypes.ULONG), ("Start", wintypes.ULONG), ("ChildId", wintypes.ULONG * count.value)]

        fc = FC(Count=count.value, Start=0)
        dh.SymGetTypeInfo(proc, IMAGE_BASE, tid, TI_FINDCHILDREN, ctypes.byref(fc))
        members = [(value_of(fc.ChildId[k]), name_of(fc.ChildId[k])) for k in range(count.value)]
        print(f"== {tname}: {len(members)} members")
        for value, name in members:
            print(f"   {value!s:>8}  {name}")


if __name__ == "__main__":
    main()
