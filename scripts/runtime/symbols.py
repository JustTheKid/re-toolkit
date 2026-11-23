"""Names for the stack sampler's addresses (atlasre-samples-*.csv, src/hook/perf_sampler.cpp): module + RVA ->
"Class::Function" from the module's PDB (dbghelp; the server's PDB sits next to its exe), or the nearest export for
system and third-party DLLs; and for a place in the sampled function, the instruction there (capstone), so a call
site shows what it calls.

Library of report.py; alone: python -I symbols.py <server root> <module> <rva hex> [...]
"""
import ctypes
import struct
import sys
from ctypes import wintypes
from pathlib import Path

IMAGE_BASE = 0x140000000


class _SymbolInfo(ctypes.Structure):
    _fields_ = [("SizeOfStruct", wintypes.ULONG), ("TypeIndex", wintypes.ULONG), ("Reserved", ctypes.c_uint64 * 2),
                ("Index", wintypes.ULONG), ("Size", wintypes.ULONG), ("ModBase", ctypes.c_uint64),
                ("Flags", wintypes.ULONG), ("Value", ctypes.c_uint64), ("Address", ctypes.c_uint64),
                ("Register", wintypes.ULONG), ("Scope", wintypes.ULONG), ("Tag", wintypes.ULONG),
                ("NameLen", wintypes.ULONG), ("MaxNameLen", wintypes.ULONG), ("Name", wintypes.WCHAR * 1)]


def _sections(data):
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    n = struct.unpack_from("<H", data, pe + 6)[0]
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    out = []
    for i in range(n):
        o = pe + 24 + opt + i * 40
        vsize, va, rsize, raw = struct.unpack_from("<IIII", data, o + 8)
        out.append((va, vsize, raw, rsize))
    return out


class Symbols:
    """dbghelp over the server's exe (its PDB beside it) and whatever DLLs the samples name."""

    def __init__(self, server_root):
        self.root = Path(server_root)
        self.dbg = ctypes.WinDLL("dbghelp.dll")
        self.proc = ctypes.c_void_p(0x5A4D)
        self.dbg.SymSetOptions(0x2 | 0x4 | 0x200 | 0x80000)  # UNDNAME | DEFERRED_LOADS | FAIL_CRITICAL | NO_PROMPTS
        self.dbg.SymInitializeW(self.proc, None, False)
        self.dbg.SymLoadModuleExW.restype = ctypes.c_uint64
        self.bases = {}   # module name (lower case) -> load base, or None when not found
        self.files = {}
        self.next_base = 0x300000000
        self.buf = ctypes.create_string_buffer(ctypes.sizeof(_SymbolInfo) + 2048)
        self._dll_index = None

    def _find(self, module):
        name = module.lower()
        if name.endswith(".exe"):
            exe = self.root / "ShooterGame" / "Binaries" / "Win64" / module
            return exe if exe.exists() else None
        for d in (self.root / "ShooterGame" / "Binaries" / "Win64", Path(r"C:\Windows\System32")):
            if (d / module).exists():
                return d / module
        if self._dll_index is None:  # third-party DLLs (PhysX, ...) live under Engine\Binaries\ThirdParty
            self._dll_index = {p.name.lower(): p for p in (self.root / "Engine" / "Binaries").rglob("*.dll")}
        return self._dll_index.get(name)

    def base(self, module):
        key = module.lower()
        if key not in self.bases:
            path = self._find(module)
            base = None
            if path:
                want = IMAGE_BASE if key.endswith(".exe") else self.next_base
                size = path.stat().st_size
                got = self.dbg.SymLoadModuleExW(self.proc, None, str(path), None, ctypes.c_uint64(want), size, None, 0)
                if got:
                    base = want
                    self.files[key] = path
                    if not key.endswith(".exe"):
                        self.next_base += 0x10000000
            self.bases[key] = base
        return self.bases[key]

    def name(self, module, rva):
        """'Function' (with +offset when not at its start) for an RVA in a module, or 'module+0xRVA'."""
        base = self.base(module)
        if base is None:
            return f"{module}+0x{rva:x}"
        info = ctypes.cast(self.buf, ctypes.POINTER(_SymbolInfo)).contents
        info.SizeOfStruct = ctypes.sizeof(_SymbolInfo)
        info.MaxNameLen = 1000
        disp = ctypes.c_uint64(0)
        if self.dbg.SymFromAddrW(self.proc, ctypes.c_uint64(base + rva), ctypes.byref(disp), ctypes.byref(info)):
            nm = ctypes.wstring_at(ctypes.addressof(info) + _SymbolInfo.Name.offset, info.NameLen)
            prefix = "" if module.lower().endswith(".exe") else module.split(".")[0] + "!"
            approx = " [nearest export]" if info.Flags & 0x200 else ""  # SYMFLAG_EXPORT: no PDB, only a guess
            return prefix + nm + (f"+0x{disp.value:x}" if disp.value else "") + approx
        return f"{module}+0x{rva:x}"

    def instruction_before(self, module, rva):
        """The instruction that ends at RVA (the call a return address belongs to), as text with its target named."""
        return self._instruction(module, rva, ends_at=True)

    def instruction_at(self, module, rva):
        return self._instruction(module, rva, ends_at=False)

    def _instruction(self, module, rva, ends_at):
        import capstone
        key = module.lower()
        if self.base(module) is None or key not in self.files:
            return ""
        if not hasattr(self, "_images"):
            self._images = {}
        if key not in self._images:
            data = self.files[key].read_bytes()
            self._images[key] = (data, _sections(data))
        data, secs = self._images[key]

        def read(r, n):
            for va, vsize, raw, rsize in secs:
                if va <= r < va + max(vsize, rsize):
                    return data[raw + r - va: raw + r - va + n]
            return b""

        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        candidates = range(rva - 15, rva) if ends_at else [rva]
        for start in candidates:
            code = read(start, 16)
            ins = next(md.disasm(code, IMAGE_BASE + start), None) if code else None
            if not ins:
                continue
            if ends_at and start + ins.size != rva:
                continue
            text = f"{ins.mnemonic} {ins.op_str}"
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_IMM and ins.group(capstone.CS_GRP_CALL):
                    text += "  ; " + self.name(module, op.imm - IMAGE_BASE)
            return text
        return ""


if __name__ == "__main__":
    s = Symbols(sys.argv[1])
    args = sys.argv[2:]
    for mod, rva in zip(args[::2], args[1::2]):
        r = int(rva, 16)
        print(mod, rva, s.name(mod, r), "|", s.instruction_before(mod, r))
