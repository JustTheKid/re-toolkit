"""Find code that compares against given constants (e.g. package versions 402..410) in an exe's .text section, and name
the function each hit is in (from the PDB). A static first pass for "which code reads this version": cmp with a 32-bit
immediate in its common encodings. False positives are possible (the same number used for something else) — check the
function names, then read the decompile.
Usage: python -I _tools/find_version_checks.py <exe> <first> <last> [--also <n> ...]
       python -I _tools/find_version_checks.py <exe> <first> <last> --field <disp>
         small values (imm8) compared against a struct field at +disp — e.g. --field 0x14 for FArchive's
         ArLicenseeUE4Ver: `cmp dword [reg+disp], imm8`, or `mov r32, [reg+disp]` followed within 16 bytes by
         `cmp r32, imm8`.
"""
import collections
import ctypes
import os
import struct
import sys
from ctypes import wintypes

IMAGE_BASE = 0x140000000
SYMOPT = 0x4 | 0x200 | 0x80000 | 0x2  # DEFERRED_LOADS | FAIL_CRITICAL_ERRORS | NO_PROMPTS | UNDNAME


class SYMBOL_INFOW(ctypes.Structure):
    _fields_ = [("SizeOfStruct", wintypes.ULONG), ("TypeIndex", wintypes.ULONG), ("Reserved", ctypes.c_uint64 * 2),
                ("Index", wintypes.ULONG), ("Size", wintypes.ULONG), ("ModBase", ctypes.c_uint64),
                ("Flags", wintypes.ULONG), ("Value", ctypes.c_uint64), ("Address", ctypes.c_uint64),
                ("Register", wintypes.ULONG), ("Scope", wintypes.ULONG), ("Tag", wintypes.ULONG),
                ("NameLen", wintypes.ULONG), ("MaxNameLen", wintypes.ULONG), ("Name", wintypes.WCHAR * 1)]


def sections(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    n = struct.unpack_from("<H", data, pe + 6)[0]
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    for i in range(n):
        off = pe + 24 + opt + 40 * i
        yield (data[off:off + 8].rstrip(b"\0").decode(), struct.unpack_from("<I", data, off + 12)[0],
               struct.unpack_from("<I", data, off + 16)[0], struct.unpack_from("<I", data, off + 20)[0])


def cmp_sites(text, base_va, value):
    """VAs of `cmp r/m32, imm32` (81 /7) and `cmp eax, imm32` (3D) whose immediate is `value`."""
    imm = struct.pack("<I", value)
    hits = []
    start = 0
    while True:
        i = text.find(imm, start)
        if i < 0:
            return hits
        start = i + 1
        if i >= 1 and text[i - 1] == 0x3D:  # cmp eax, imm32
            hits.append(base_va + i - 1)
            continue
        # 81 /7 forms: modrm before the immediate, with 0/1/4 displacement bytes (+ optional SIB)
        for back in (2, 3, 4, 6, 7):
            j = i - back
            if j < 0 or text[j] != 0x81:
                continue
            modrm = text[j + 1]
            if (modrm >> 3) & 7 != 7:
                continue
            mod, rm = modrm >> 6, modrm & 7
            disp = {0: 0, 1: 1, 2: 4, 3: 0}[mod] + (4 if mod == 0 and rm == 5 else 0)
            sib = 1 if mod != 3 and rm == 4 else 0
            if 2 + sib + disp == back:
                hits.append(base_va + j - (1 if j > 0 and 0x40 <= text[j - 1] <= 0x4F else 0))
                break


def field_sites(text, base_va, disp, value):
    """VAs comparing the int at [reg+disp] (disp8) with imm8 `value`, directly or via a register."""
    hits = []
    direct = bytes([disp, value])
    start = 0
    while True:
        i = text.find(direct, start)
        if i < 0:
            break
        start = i + 1
        if i >= 2 and text[i - 2] == 0x83 and text[i - 1] >> 6 == 1 and (text[i - 1] >> 3) & 7 == 7 \
                and text[i - 1] & 7 != 4:
            hits.append(base_va + i - 2)
        elif i >= 3 and text[i - 3] == 0x83 and text[i - 2] == 0x7C and text[i - 1] == 0x24:
            hits.append(base_va + i - 3)
    start = 0
    while True:  # mov r32, [reg+disp]  ...  cmp r32, imm8
        i = text.find(bytes([0x8B]), start)
        if i < 0 or i + 3 > len(text):
            break
        start = i + 1
        modrm = text[i + 1]
        if modrm >> 6 != 1 or modrm & 7 == 4 or text[i + 2] != disp:
            continue
        dst = (modrm >> 3) & 7
        window = text[i + 3:i + 19]
        k = window.find(bytes([0x83, 0xF8 | dst, value]))
        if k >= 0:
            hits.append(base_va + i)
    return sorted(set(hits))


def main():
    exe = sys.argv[1]
    lo, hi = int(sys.argv[2]), int(sys.argv[3])
    values = list(range(lo, hi + 1))
    if "--also" in sys.argv:
        values += [int(v) for v in sys.argv[sys.argv.index("--also") + 1:]]
    field = int(sys.argv[sys.argv.index("--field") + 1], 0) if "--field" in sys.argv else None
    data = open(exe, "rb").read()
    text = next(s for s in sections(data) if s[0] == ".text")
    _, va, size, raw = text
    code = data[raw:raw + size]

    dh = ctypes.WinDLL(r"C:\Windows\System32\dbghelp.dll")
    proc = wintypes.HANDLE(0x7A11)
    dh.SymSetOptions(SYMOPT)
    dh.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
    dh.SymLoadModuleExW.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                    ctypes.c_uint64, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    dh.SymLoadModuleExW.restype = ctypes.c_uint64
    dh.SymFromAddrW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64), ctypes.c_void_p]
    dh.SymInitializeW(proc, os.path.dirname(exe), False)
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    dh.SymLoadModuleExW(proc, None, exe, None, IMAGE_BASE, struct.unpack_from("<I", data, pe + 24 + 56)[0], None, 0)
    buf = ctypes.create_string_buffer(ctypes.sizeof(SYMBOL_INFOW) + 2048)

    def func_at(addr):
        sym = ctypes.cast(buf, ctypes.POINTER(SYMBOL_INFOW)).contents
        sym.SizeOfStruct = ctypes.sizeof(SYMBOL_INFOW)
        sym.MaxNameLen = 1024
        disp = ctypes.c_uint64()
        if dh.SymFromAddrW(proc, addr, ctypes.byref(disp), buf):
            name = ctypes.wstring_at(ctypes.addressof(sym) + SYMBOL_INFOW.Name.offset, sym.NameLen)
            return f"{sym.Address:x}", name
        return "?", "?"

    for value in values:
        sites = field_sites(code, IMAGE_BASE + va, field, value) if field is not None \
            else cmp_sites(code, IMAGE_BASE + va, value)
        funcs = collections.OrderedDict()
        for s in sites:
            fva, name = func_at(s)
            funcs.setdefault((fva, name), []).append(s)
        print(f"== {value} (0x{value:x}): {len(sites)} compare sites in {len(funcs)} functions")
        for (fva, name), ss in funcs.items():
            print(f"   {fva}  {name}  @ {', '.join(f'{x:x}' for x in ss[:4])}")


if __name__ == "__main__":
    main()
