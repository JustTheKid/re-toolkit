r"""Print a struct/class's fields, types and byte offsets from an exe's PDB, via dbghelp's type info. Light on memory
(no Ghidra); for an enum, its values. Usage: python -I _tools/pdb_struct.py <exe> <TypeName> [TypeName ...]
  --methods <TypeName> ...: member functions in declaration order with virtual functions' vtable offsets
  e.g. python -I _tools/pdb_struct.py ...\ShooterGameServer.exe "AShooterGameSession::FPlayerJoinAllowedCheck"
"""
import ctypes
import struct
import sys
from ctypes import wintypes

IMAGE_BASE = 0x140000000
SYMOPT = 0x4 | 0x200 | 0x80000  # DEFERRED_LOADS | FAIL_CRITICAL_ERRORS | NO_PROMPTS
# IMAGEHLP_SYMBOL_TYPE_INFO
TI_GET_SYMTAG = 0
TI_GET_SYMNAME = 1
TI_GET_LENGTH = 2
TI_GET_TYPE = 3
TI_GET_BASETYPE = 5
TI_FINDCHILDREN = 7
TI_GET_VALUE = 11
TI_GET_OFFSET = 10
TI_GET_COUNT = 12
TI_GET_CHILDRENCOUNT = 13
TI_GET_BITPOSITION = 14
TI_GET_VIRTUALBASEOFFSET = 29
# SymTag / BasicType values (cvconst.h)
TAG_UDT, TAG_ENUM, TAG_POINTER, TAG_ARRAY, TAG_BASE, TAG_TYPEDEF = 11, 12, 14, 15, 16, 17
BASIC = {1: 'void', 2: 'char', 3: 'wchar_t', 6: 'int', 7: 'uint', 8: 'float', 10: 'bool', 13: 'long', 14: 'ulong'}


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


def array_name(element, count):
    """The C++ name of an array of count elements: its dimension before the element's own (T[5] x 4 -> T[4][5])."""
    i = element.find("[", element.rfind(">") + 1)
    return f"{element[:i]}[{count}]{element[i:]}" if i >= 0 else f"{element}[{count}]"


TAG_BASECLASS = 18
TAG_FUNCTION = 5
TAG_FUNCTIONTYPE = 13


class Pdb:
    """Type information of one exe's PDB. members(type) -> [{offset, bit, width, name, type, size, base}]"""

    def __init__(self, exe, proc=0x5712C):
        """proc: the dbghelp session's handle; a second Pdb in the same process needs another one."""
        import os
        self.dh = dh = ctypes.WinDLL(r"C:\Windows\System32\dbghelp.dll")
        self.proc = wintypes.HANDLE(proc)
        dh.SymSetOptions(SYMOPT)
        dh.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
        dh.SymLoadModuleExW.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                        ctypes.c_uint64, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
        dh.SymLoadModuleExW.restype = ctypes.c_uint64
        dh.SymGetTypeFromNameW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, wintypes.LPCWSTR,
                                           ctypes.POINTER(SYMBOL_INFOW)]
        dh.SymGetTypeInfo.argtypes = [wintypes.HANDLE, ctypes.c_uint64, wintypes.ULONG, ctypes.c_int, ctypes.c_void_p]
        dh.SymInitializeW(self.proc, os.path.dirname(exe), False)
        if not dh.SymLoadModuleExW(self.proc, None, exe, None, IMAGE_BASE, image_size(exe), None, 0):
            sys.exit("SymLoadModuleEx failed")

    def info(self, tid, kind, ctype):
        v = ctype()
        if self.dh.SymGetTypeInfo(self.proc, IMAGE_BASE, tid, kind, ctypes.byref(v)):
            return v.value
        return None

    def name_of(self, tid):
        p = ctypes.c_void_p()
        if self.dh.SymGetTypeInfo(self.proc, IMAGE_BASE, tid, TI_GET_SYMNAME, ctypes.byref(p)) and p.value:
            s = ctypes.wstring_at(p.value)
            ctypes.windll.kernel32.LocalFree(p)
            return s
        return ""

    def type_name(self, tid):
        info = self.info
        tag = info(tid, TI_GET_SYMTAG, wintypes.ULONG)
        if tag == TAG_POINTER:
            pointee = info(tid, TI_GET_TYPE, wintypes.ULONG)
            if info(pointee, TI_GET_SYMTAG, wintypes.ULONG) == TAG_FUNCTIONTYPE:
                # a function pointer (e.g. a third-party DLL's export kept in a member): ret (*)(args)
                return self.type_name(pointee).replace("(", "(*)(", 1)
            return self.type_name(pointee) + "*"
        if tag == TAG_FUNCTIONTYPE:
            count = info(tid, TI_GET_CHILDRENCOUNT, wintypes.ULONG) or 0

            class FC(ctypes.Structure):
                _fields_ = [("Count", wintypes.ULONG), ("Start", wintypes.ULONG), ("ChildId", wintypes.ULONG * count)]
            args = []
            if count:
                fc = FC(Count=count, Start=0)
                self.dh.SymGetTypeInfo(self.proc, IMAGE_BASE, tid, TI_FINDCHILDREN, ctypes.byref(fc))
                args = [self.type_name(info(fc.ChildId[i], TI_GET_TYPE, wintypes.ULONG)) for i in range(count)]
            return f"{self.type_name(info(tid, TI_GET_TYPE, wintypes.ULONG))} ({', '.join(args) or 'void'})"
        if tag == TAG_ARRAY:
            # C order, the outermost dimension first: T x[4][5] is an array of 4 arrays of 5 (2026-10-29, L30b: this
            # printed the element's dimensions first, [5][4], and a port declared them so)
            return array_name(self.type_name(info(tid, TI_GET_TYPE, wintypes.ULONG)), info(tid, TI_GET_COUNT, wintypes.ULONG))
        if tag == TAG_BASE:
            size = info(tid, TI_GET_LENGTH, ctypes.c_uint64)
            return f"{BASIC.get(info(tid, TI_GET_BASETYPE, wintypes.ULONG), 'basic')}{size * 8 if size else ''}"
        return self.name_of(tid) or f"<tag {tag}>"

    def type_id(self, tname):
        buf = ctypes.create_string_buffer(ctypes.sizeof(SYMBOL_INFOW) + 2048)
        sym = ctypes.cast(buf, ctypes.POINTER(SYMBOL_INFOW)).contents
        sym.SizeOfStruct = ctypes.sizeof(SYMBOL_INFOW)
        sym.MaxNameLen = 1024
        if not self.dh.SymGetTypeFromNameW(self.proc, IMAGE_BASE, tname, ctypes.byref(sym)):
            return None
        if self.info(sym.TypeIndex, TI_GET_LENGTH, ctypes.c_uint64):
            return sym.TypeIndex
        # the first type of that name can be a forward declaration (no size, no members, e.g. UFunction in the
        # server PDB): take the largest complete one of the same name instead
        found = []
        cb_type = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p)

        def on_type(p, _size, _ctx):
            info = ctypes.cast(p, ctypes.POINTER(SYMBOL_INFOW)).contents
            name = ctypes.wstring_at(ctypes.addressof(info) + SYMBOL_INFOW.Name.offset, info.NameLen).rstrip("\0")
            if name == tname:
                found.append(info.TypeIndex)
            return True

        self.dh.SymEnumTypesByNameW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, wintypes.LPCWSTR, cb_type,
                                                ctypes.c_void_p]
        self.dh.SymEnumTypesByNameW(self.proc, IMAGE_BASE, tname, cb_type(on_type), None)
        sized = [(self.info(t, TI_GET_LENGTH, ctypes.c_uint64) or 0, t) for t in found]
        best = max(sized, default=(0, sym.TypeIndex))
        return best[1] if best[0] else sym.TypeIndex

    def enumerators(self, tname):
        """[(name, value)] of an enum, or None when the type is not an enum."""
        tid = self.type_id(tname)
        if tid is None or self.info(tid, TI_GET_SYMTAG, wintypes.ULONG) != TAG_ENUM:
            return None
        count = self.info(tid, TI_GET_CHILDRENCOUNT, wintypes.ULONG) or 0

        class FC(ctypes.Structure):
            _fields_ = [("Count", wintypes.ULONG), ("Start", wintypes.ULONG), ("ChildId", wintypes.ULONG * count)]

        fc = FC(Count=count, Start=0)
        self.dh.SymGetTypeInfo(self.proc, IMAGE_BASE, tid, TI_FINDCHILDREN, ctypes.byref(fc))
        out = []
        for i in range(count):
            var = (ctypes.c_ubyte * 24)()  # VARIANT: vt at 0, the value at 8
            self.dh.SymGetTypeInfo(self.proc, IMAGE_BASE, fc.ChildId[i], TI_GET_VALUE, ctypes.byref(var))
            vt = struct.unpack_from("<H", bytes(var), 0)[0]
            fmt = {2: "<h", 3: "<i", 16: "<b", 17: "<B", 18: "<H", 19: "<I", 20: "<q", 21: "<Q"}.get(vt, "<i")
            out.append((self.name_of(fc.ChildId[i]), struct.unpack_from(fmt, bytes(var), 8)[0]))
        return out

    def size(self, tname):
        tid = self.type_id(tname)
        return None if tid is None else self.info(tid, TI_GET_LENGTH, ctypes.c_uint64)

    def members(self, tname, flatten=False, _base_offset=0):
        """Data members (and base classes) with offsets; flatten=True inlines base classes' members."""
        info = self.info
        tid = self.type_id(tname)
        if tid is None:
            return None
        count = info(tid, TI_GET_CHILDRENCOUNT, wintypes.ULONG) or 0

        class FC(ctypes.Structure):
            _fields_ = [("Count", wintypes.ULONG), ("Start", wintypes.ULONG), ("ChildId", wintypes.ULONG * count)]

        fc = FC(Count=count, Start=0)
        self.dh.SymGetTypeInfo(self.proc, IMAGE_BASE, tid, TI_FINDCHILDREN, ctypes.byref(fc))
        out = []
        for i in range(count):
            cid = fc.ChildId[i]
            off = info(cid, TI_GET_OFFSET, wintypes.ULONG)
            if off is None:
                continue
            ftype = info(cid, TI_GET_TYPE, wintypes.ULONG)
            tname_f = self.type_name(ftype) if ftype is not None else "?"
            base = info(cid, TI_GET_SYMTAG, wintypes.ULONG) == TAG_BASECLASS
            bit = info(cid, TI_GET_BITPOSITION, wintypes.ULONG)
            m = {"offset": _base_offset + off, "bit": bit,
                 "width": info(cid, TI_GET_LENGTH, ctypes.c_uint64) if bit is not None else None,
                 "name": self.name_of(cid) or tname_f, "type": tname_f,
                 "size": info(ftype, TI_GET_LENGTH, ctypes.c_uint64) if ftype is not None else None, "base": base}
            if base and flatten:
                out += self.members(tname_f, True, _base_offset + off) or []
            else:
                out.append(m)
        return out


    def methods(self, tname):
        """Member functions in declaration order: [(name, vtable offset or None)]; the offset is the slot of a virtual
        function this class introduces or overrides (DIA's virtualBaseOffset)."""
        info = self.info
        tid = self.type_id(tname)
        if tid is None:
            return None
        count = info(tid, TI_GET_CHILDRENCOUNT, wintypes.ULONG) or 0

        class FC(ctypes.Structure):
            _fields_ = [("Count", wintypes.ULONG), ("Start", wintypes.ULONG), ("ChildId", wintypes.ULONG * count)]

        fc = FC(Count=count, Start=0)
        self.dh.SymGetTypeInfo(self.proc, IMAGE_BASE, tid, TI_FINDCHILDREN, ctypes.byref(fc))
        out = []
        for i in range(count):
            cid = fc.ChildId[i]
            if info(cid, TI_GET_SYMTAG, wintypes.ULONG) != TAG_FUNCTION:
                continue
            out.append((self.name_of(cid), info(cid, TI_GET_VIRTUALBASEOFFSET, wintypes.ULONG)))
        return out


def main():
    exe = sys.argv[1]
    pdb = Pdb(exe)
    if sys.argv[2] == "--methods":
        for tname in sys.argv[3:]:
            print(f"== {tname} member functions (declaration order; vtable offset of virtuals)")
            for name, voff in pdb.methods(tname) or []:
                print(f"  {'+0x%x' % voff if voff is not None else '':<8} {name}")
        return
    for tname in sys.argv[2:]:
        enum = pdb.enumerators(tname)
        if enum is not None:
            print(f"== enum {tname}  ({len(enum)} values)")
            for name, value in enum:
                print(f"  {name} = {value}")
            continue
        members = pdb.members(tname)
        if members is None:
            print(f"# type not found: {tname}")
            continue
        print(f"== {tname}  (size 0x{pdb.size(tname):x}, {len(members)} members)")
        for m in members:
            length = f"{m['width']} bit" if m["bit"] is not None else m["size"]
            where = f"+0x{m['offset']:<4x}" + (f".{m['bit']}" if m["bit"] is not None else "")
            print(f"  {where:<9} {m['name']}  {m['type']}  (size {length})")


if __name__ == "__main__":
    main()
