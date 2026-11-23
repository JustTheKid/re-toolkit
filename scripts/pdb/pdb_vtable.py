"""Name the functions in a class's vftable slots: the vftable's address from the PDB's public symbol (??_7<Class>@@6B@),
the slot's target from the exe's bytes, the target's name from the PDB. For resolving virtual calls in decompiles
(`(**(code **)(this->_padding_ + 0x4f8))(...)` is slot 0x4f8 of the object's vftable). With interfaces a class has
one vftable per vfptr; the primary one (slot 0 = the class's destructor, not an adjustor thunk) is used.

Identical-code folding means a slot's target can carry another function's name (an empty virtual shows up as
whatever empty function the linker kept); then name the slot from its neighbours and the class's declaration order
(`pdb_struct`'s type records list member functions in source order; dbghelp gives no vtable offsets for them).

Usage: python -I _tools/pdb_vtable.py <exe> <Class> <slot offset (hex)> [<slot offset> ...]
       a slot range "9c0-a20" lists every slot in it
       python -I _tools/pdb_vtable.py <exe> --match <regex> <slot offset> [...]
       every vftable whose undecorated class name matches the regex (templates too, e.g.
       "^TBasePassPS<"; names read "TBasePassPS<class FNoLightMapPolicy,0>"), one line per class and slot:
       <class>\t<slot>\t<target VA>\t<target name>
"""
import ctypes
import struct
import sys
from ctypes import wintypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pdb_struct import IMAGE_BASE, SYMBOL_INFOW, Pdb  # noqa: E402

MAX_NAME = 2000


def symbol():
    buf = ctypes.create_string_buffer(ctypes.sizeof(SYMBOL_INFOW) + MAX_NAME * 2)
    sym = ctypes.cast(buf, ctypes.POINTER(SYMBOL_INFOW)).contents
    sym.SizeOfStruct = ctypes.sizeof(SYMBOL_INFOW)
    sym.MaxNameLen = MAX_NAME
    return buf, sym


def name(sym):
    return ctypes.wstring_at(ctypes.addressof(sym) + SYMBOL_INFOW.Name.offset, sym.NameLen)


def read_va(data, va, size):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    rva = va - IMAGE_BASE
    for i in range(count):
        s = pe + 24 + opt + 40 * i
        vsize, vaddr, rsize, raw = struct.unpack_from("<IIII", data, s + 8)
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return data[raw + rva - vaddr:raw + rva - vaddr + size]
    raise ValueError(f"VA 0x{va:x} not in a section")


def parse_slots(args):
    slots = []
    for arg in args:
        if "-" in arg:
            lo, hi = (int(x, 16) for x in arg.split("-"))
            slots += range(lo, hi + 1, 8)
        else:
            slots.append(int(arg, 16))
    return slots


def match_main(exe, rx, slots):
    """--match: every primary vftable whose undecorated class name matches rx."""
    import re
    pattern = re.compile(rx)
    pdb = Pdb(exe)
    dh = pdb.dh
    dh.SymFromAddrW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64), ctypes.c_void_p]
    dh.UnDecorateSymbolNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    tables = {}
    cb = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p)

    def on_symbol(p, _size, _ctx):
        info = ctypes.cast(p, ctypes.POINTER(SYMBOL_INFOW)).contents
        decorated = name(info).rstrip(chr(0))
        out = ctypes.create_unicode_buffer(4096)
        dh.UnDecorateSymbolNameW(decorated, out, 4096, 0)
        text = out.value
        if text.startswith("const ") and text.endswith("::`vftable'"):
            cls = text[len("const "):-len("::`vftable'")].replace("class ", "").replace("struct ", "")
            cls = cls.replace("enum ", "")
            if pattern.search(cls):
                tables.setdefault(cls, []).append(info.Address)
        elif "::`vftable'{for `" in text:
            cls = text[len("const "):text.index("::`vftable'")].replace("class ", "").replace("struct ", "")
            if pattern.search(cls):
                tables.setdefault(cls, []).append(info.Address)
        return True
    dh.SymEnumSymbolsW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, wintypes.LPCWSTR, cb, ctypes.c_void_p]
    keep = cb(on_symbol)
    dh.SymEnumSymbolsW(pdb.proc, IMAGE_BASE, "??_7*", keep, None)
    data = Path(exe).read_bytes()
    for cls in sorted(tables):
        vft = None
        for addr in sorted(set(tables[cls])):
            first = struct.unpack("<Q", read_va(data, addr, 8))[0]
            disp = ctypes.c_uint64()
            b0, s0 = symbol()
            if dh.SymFromAddrW(pdb.proc, first, ctypes.byref(disp), b0) and not name(s0).startswith("[thunk]"):
                vft = addr
                break
        if vft is None:
            print(f"{cls}\t-\t-\tno primary vftable")
            continue
        for slot in slots:
            target = struct.unpack("<Q", read_va(data, vft + slot, 8))[0]
            disp = ctypes.c_uint64()
            buf2, sym2 = symbol()
            found = dh.SymFromAddrW(pdb.proc, target, ctypes.byref(disp), buf2)
            print(f"{cls}\t0x{slot:x}\t{target:x}\t{name(sym2) if found else '?'}"
                  f"{f'+0x{disp.value:x}' if found and disp.value else ''}")


def main():
    if len(sys.argv) > 3 and sys.argv[2] == "--match":
        return match_main(sys.argv[1], sys.argv[3], parse_slots(sys.argv[4:]))
    exe, cls = sys.argv[1], sys.argv[2]
    slots = []
    for arg in sys.argv[3:]:
        if "-" in arg:
            lo, hi = (int(x, 16) for x in arg.split("-"))
            slots += range(lo, hi + 1, 8)
        else:
            slots.append(int(arg, 16))
    pdb = Pdb(exe)
    dh = pdb.dh
    dh.SymFromNameW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_void_p]
    dh.SymFromAddrW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64), ctypes.c_void_p]
    # a class with interfaces has one vftable per vfptr; enumerate them and keep the primary one (slot 0 is the
    # class's own destructor, not an adjustor thunk)
    found = []
    cb = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p)

    def on_symbol(p, _size, _ctx):
        # decorated: ??_7<Class>@@6B@ (one vftable) or ??_7<Class>@@6B<Base>@@@ (one per vfptr)
        info = ctypes.cast(p, ctypes.POINTER(SYMBOL_INFOW)).contents
        if name(info).rstrip(chr(0)).startswith(f"??_7{cls}@@6B"):
            found.append(info.Address)
        return True
    dh.SymEnumSymbolsW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, wintypes.LPCWSTR, cb, ctypes.c_void_p]
    keep = cb(on_symbol)
    dh.SymEnumSymbolsW(pdb.proc, IMAGE_BASE, f"??_7{cls}@@6B*", keep, None)
    data = Path(exe).read_bytes()
    vft = None
    for addr in sorted(set(found)):
        first = struct.unpack("<Q", read_va(data, addr, 8))[0]
        disp = ctypes.c_uint64()
        b0, s0 = symbol()
        if dh.SymFromAddrW(pdb.proc, first, ctypes.byref(disp), b0) and not name(s0).startswith("[thunk]"):
            vft = addr
            break
    if vft is None:
        sys.exit(f"no primary vftable for {cls} (vftables found: {', '.join(hex(a) for a in found) or 'none'})")
    print(f"{cls} vftable at 0x{vft:x}")
    for slot in slots:
        target = struct.unpack("<Q", read_va(data, vft + slot, 8))[0]
        disp = ctypes.c_uint64()
        buf2, sym2 = symbol()
        found = dh.SymFromAddrW(pdb.proc, target, ctypes.byref(disp), buf2)
        print(f"  +0x{slot:x}  0x{target:x}  {name(sym2) if found else '?'}{f'+0x{disp.value:x}' if found and disp.value else ''}")


if __name__ == "__main__":
    main()
