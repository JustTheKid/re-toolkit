"""Every thread's call stack from a server or client minidump (the engine's `Dump-*.dmp`), symbolized offline.

The engine's crash handler writes a small minidump next to each `crashcallstack-*.txt` in `ShooterGame/Saved/Logs`.
The text file only has the crashing thread; the dump also has every other thread's registers and stack memory, so
the game thread's stack at the moment of the crash can be read back here. Stacks are walked with Windows' dbghelp
(StackWalk64) against the matching binaries and PDBs of a local install: each module in the dump is matched to a
local file by name, PE timestamp and image size (D:\\ATLASServer and D:\\ATLAS by default, plus System32 for the
system DLLs). A dump from another machine has other system DLLs (and maybe server plugins) we cannot unwind through:
there the walk resumes at the next stack slot holding a return address into a matched module whose preceding bytes
are a call instruction; such frames are marked "~" (the first ones can be stale leftovers in dead stack space).
Heap memory is not in these dumps.

Usage: python -I _tools/minidump_stacks.py <dump.dmp> [--root DIR ...] [--crash-only] [--frames N] [--scan]
  --root DIR    another install to take binaries / PDBs from (searched before the defaults)
  --crash-only  only the thread that raised the exception
  --frames N    at most N frames per thread (default 64)
  --scan        for the crashing thread, also list every stack slot that points into a known module's code
                (return-address candidates; useful when the walk stops early)
"""
import bisect
import ctypes
import struct
import sys
from ctypes import wintypes
from pathlib import Path

DEFAULT_ROOTS = [Path(r"D:\ATLASServer"), Path(r"D:\ATLAS")]
SYSTEM_DIR = Path(r"C:\Windows\System32")
MACHINE_AMD64 = 0x8664
ADDR_MODE_FLAT = 3
CTX_RSP, CTX_RBP, CTX_RIP, CTX_SIZE = 0x98, 0xA0, 0xF8, 0x4D0
SYMOPT_UNDNAME, SYMOPT_DEFERRED_LOADS, SYMOPT_LOAD_LINES = 0x2, 0x4, 0x10
SYMOPT_FAIL_CRITICAL_ERRORS, SYMOPT_NO_PROMPTS = 0x200, 0x80000
CBA_READ_MEMORY = 0x6
MAX_NAME = 2000
EXCEPTION_NAMES = {0xC0000005: "ACCESS_VIOLATION", 0xC00000FD: "STACK_OVERFLOW", 0xC0000094: "INT_DIVIDE_BY_ZERO",
                   0x80000003: "BREAKPOINT", 0xC0000409: "STACK_BUFFER_OVERRUN", 0xE06D7363: "C++ exception",
                   0xC0000374: "HEAP_CORRUPTION", 0xC000001D: "ILLEGAL_INSTRUCTION"}


# ---- minidump parsing -------------------------------------------------------------------------------------------

class Dump:
    def __init__(self, path: Path):
        self.data = data = path.read_bytes()
        if data[:4] != b"MDMP":
            sys.exit(f"{path}: not a minidump")
        nstreams, dir_rva = struct.unpack_from("<II", data, 8)
        self.streams = {}
        for i in range(nstreams):
            stype, size, rva = struct.unpack_from("<III", data, dir_rva + 12 * i)
            self.streams.setdefault(stype, (rva, size))
        self.ranges = []  # (start, size, file offset)
        self.threads = []  # (tid, context bytes, stack start, stack size)
        self.modules = []  # (base, size, timestamp, name)
        self.exception = None
        self.thread_names = {}
        self._memory()
        self._threads()
        self._modules()
        self._exception()
        self._thread_names()
        self.ranges.sort()
        self.starts = [r[0] for r in self.ranges]

    def string(self, rva):
        n = struct.unpack_from("<I", self.data, rva)[0]
        return self.data[rva + 4:rva + 4 + n].decode("utf-16-le", "replace")

    def _memory(self):
        if 5 in self.streams:  # MemoryListStream
            rva, _ = self.streams[5]
            for i in range(struct.unpack_from("<I", self.data, rva)[0]):
                start, size, mrva = struct.unpack_from("<QII", self.data, rva + 4 + 16 * i)
                self.ranges.append((start, size, mrva))
        if 9 in self.streams:  # Memory64ListStream (full dumps)
            rva, _ = self.streams[9]
            count, base = struct.unpack_from("<QQ", self.data, rva)
            for i in range(count):
                start, size = struct.unpack_from("<QQ", self.data, rva + 16 + 16 * i)
                self.ranges.append((start, size, base))
                base += size

    def _threads(self):
        rva, _ = self.streams.get(3, (None, 0))
        if rva is None:
            return
        for i in range(struct.unpack_from("<I", self.data, rva)[0]):
            o = rva + 4 + 48 * i
            tid = struct.unpack_from("<I", self.data, o)[0]
            st_start, st_size, st_rva = struct.unpack_from("<QII", self.data, o + 24)
            ctx_size, ctx_rva = struct.unpack_from("<II", self.data, o + 40)
            self.threads.append((tid, self.data[ctx_rva:ctx_rva + ctx_size], st_start, st_size))
            if not any(r[0] == st_start for r in self.ranges):
                self.ranges.append((st_start, st_size, st_rva))

    def _modules(self):
        rva, _ = self.streams.get(4, (None, 0))
        if rva is None:
            return
        for i in range(struct.unpack_from("<I", self.data, rva)[0]):
            o = rva + 4 + 108 * i
            base, size, _cs, stamp, name_rva = struct.unpack_from("<QIIII", self.data, o)
            self.modules.append((base, size, stamp, self.string(name_rva)))

    def _exception(self):
        if 6 not in self.streams:
            return
        rva, _ = self.streams[6]
        tid = struct.unpack_from("<I", self.data, rva)[0]
        code, flags, _rec, addr, nparams = struct.unpack_from("<IIQQI", self.data, rva + 8)
        params = struct.unpack_from("<15Q", self.data, rva + 8 + 32)[:nparams]
        ctx_size, ctx_rva = struct.unpack_from("<II", self.data, rva + 8 + 152)
        self.exception = (tid, code, addr, params, self.data[ctx_rva:ctx_rva + ctx_size])

    def _thread_names(self):
        if 24 not in self.streams:  # ThreadNamesStream (written by newer dbghelp only)
            return
        rva, _ = self.streams[24]
        for i in range(struct.unpack_from("<I", self.data, rva)[0]):
            tid, name_rva = struct.unpack_from("<IQ", self.data, rva + 4 + 12 * i)
            self.thread_names[tid] = self.string(name_rva)

    def read(self, addr, size):
        i = bisect.bisect_right(self.starts, addr) - 1
        if i >= 0:
            start, rsize, off = self.ranges[i]
            if addr + size <= start + rsize:
                return self.data[off + addr - start:off + addr - start + size]
        return None


# ---- local images -----------------------------------------------------------------------------------------------

def pe_header(path: Path):
    with open(path, "rb") as f:
        head = f.read(4096)
    pe = struct.unpack_from("<I", head, 0x3C)[0]
    stamp = struct.unpack_from("<I", head, pe + 8)[0]
    nsec = struct.unpack_from("<H", head, pe + 6)[0]
    optsz = struct.unpack_from("<H", head, pe + 20)[0]
    size_image, size_headers = struct.unpack_from("<II", head, pe + 24 + 56)
    sections = []
    for i in range(nsec):
        o = pe + 24 + optsz + 40 * i
        vsize, va, rsize, raw = struct.unpack_from("<IIII", head, o + 8)
        chars = struct.unpack_from("<I", head, o + 36)[0]
        sections.append((va, max(vsize, rsize), raw, rsize, bool(chars & 0x20000000)))
    return stamp, size_image, size_headers, sections


class Image:
    def __init__(self, path: Path, base: int):
        self.path, self.base = path, base
        _, self.size, self.size_headers, self.sections = pe_header(path)
        self._bytes = None

    def read(self, addr, size):
        rva = addr - self.base
        if self._bytes is None:
            self._bytes = self.path.read_bytes()
        if rva + size <= self.size_headers:
            return self._bytes[rva:rva + size]
        for va, vsize, raw, rsize, _x in self.sections:
            if va <= rva and rva + size <= va + vsize:
                off = rva - va
                chunk = self._bytes[raw + off:raw + min(off + size, rsize)] if off < rsize else b""
                return chunk + b"\0" * (size - len(chunk))
        return None

    def is_code(self, addr):
        rva = addr - self.base
        return any(x and va <= rva < va + vsize for va, vsize, _r, _s, x in self.sections)


def index_files(roots):
    found = {}
    for root in roots:
        if not root.exists():
            continue
        for pattern in ("*.exe", "*.dll"):
            for p in root.rglob(pattern):
                if "Binaries" in p.parts:
                    found.setdefault(p.name.lower(), []).append(p)
    return found


def match_modules(dump, roots):
    files = index_files(roots)
    images, missing = [], []
    for base, size, stamp, name in dump.modules:
        leaf = name.replace("/", "\\").rsplit("\\", 1)[-1]
        candidates = files.get(leaf.lower(), []) + [SYSTEM_DIR / leaf]
        hit = None
        for c in candidates:
            try:
                s, sz, _h, _sec = pe_header(c)
            except OSError:
                continue
            if s == stamp and sz == size:
                hit = c
                break
        if hit:
            images.append(Image(hit, base))
        else:
            missing.append(leaf)
    return images, missing


# ---- dbghelp ----------------------------------------------------------------------------------------------------

class SYMBOL_INFOW(ctypes.Structure):
    _fields_ = [("SizeOfStruct", wintypes.ULONG), ("TypeIndex", wintypes.ULONG),
                ("Reserved", ctypes.c_uint64 * 2), ("Index", wintypes.ULONG), ("Size", wintypes.ULONG),
                ("ModBase", ctypes.c_uint64), ("Flags", wintypes.ULONG), ("Value", ctypes.c_uint64),
                ("Address", ctypes.c_uint64), ("Register", wintypes.ULONG), ("Scope", wintypes.ULONG),
                ("Tag", wintypes.ULONG), ("NameLen", wintypes.ULONG), ("MaxNameLen", wintypes.ULONG),
                ("Name", wintypes.WCHAR * 1)]


class IMAGEHLP_LINEW64(ctypes.Structure):
    _fields_ = [("SizeOfStruct", wintypes.DWORD), ("Key", ctypes.c_void_p), ("LineNumber", wintypes.DWORD),
                ("FileName", ctypes.c_wchar_p), ("Address", ctypes.c_uint64)]


class IMAGEHLP_CBA_READ_MEMORY(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint64), ("buf", ctypes.c_void_p), ("bytes", wintypes.DWORD),
                ("bytesread", ctypes.POINTER(wintypes.DWORD))]


READ_MEMORY = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE, ctypes.c_uint64, ctypes.c_void_p, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD))
FUNC_TABLE = ctypes.WINFUNCTYPE(ctypes.c_void_p, wintypes.HANDLE, ctypes.c_uint64)
MODULE_BASE = ctypes.WINFUNCTYPE(ctypes.c_uint64, wintypes.HANDLE, ctypes.c_uint64)
SYM_CALLBACK = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE, wintypes.ULONG, ctypes.c_uint64, ctypes.c_uint64)


class Symbolizer:
    def __init__(self, dump, images):
        self.dump, self.images = dump, sorted(images, key=lambda m: m.base)
        self.bases = [m.base for m in self.images]
        self.dbghelp = d = ctypes.WinDLL(str(SYSTEM_DIR / "dbghelp.dll"))
        self.process = wintypes.HANDLE(0x1A7A6)
        d.SymSetOptions.argtypes = [wintypes.DWORD]
        d.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
        d.SymLoadModuleExW.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                       ctypes.c_uint64, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
        d.SymLoadModuleExW.restype = ctypes.c_uint64
        d.SymFromAddrW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64), ctypes.c_void_p]
        d.SymGetLineFromAddrW64.argtypes = [wintypes.HANDLE, ctypes.c_uint64, ctypes.POINTER(wintypes.DWORD),
                                            ctypes.POINTER(IMAGEHLP_LINEW64)]
        d.SymRegisterCallbackW64.argtypes = [wintypes.HANDLE, SYM_CALLBACK, ctypes.c_uint64]
        d.StackWalk64.argtypes = [wintypes.DWORD, wintypes.HANDLE, wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  READ_MEMORY, FUNC_TABLE, MODULE_BASE, ctypes.c_void_p]
        d.SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_FAIL_CRITICAL_ERRORS
                        | SYMOPT_NO_PROMPTS)
        search = ";".join(sorted({str(m.path.parent) for m in self.images}))
        if not d.SymInitializeW(self.process, search, False):
            sys.exit(f"SymInitialize failed: {ctypes.GetLastError()}")
        self._read_cb = READ_MEMORY(self._read_memory)
        self._sym_cb = SYM_CALLBACK(self._on_sym_callback)
        d.SymRegisterCallbackW64(self.process, self._sym_cb, 0)
        for m in self.images:
            d.SymLoadModuleExW(self.process, None, str(m.path), None, m.base, m.size, None, 0)
        self._func_table = FUNC_TABLE(("SymFunctionTableAccess64", d))
        self._module_base = MODULE_BASE(("SymGetModuleBase64", d))
        self._sym_buf = ctypes.create_string_buffer(ctypes.sizeof(SYMBOL_INFOW) + MAX_NAME * 2)

    def image_at(self, addr):
        i = bisect.bisect_right(self.bases, addr) - 1
        if i >= 0 and addr < self.images[i].base + self.images[i].size:
            return self.images[i]
        return None

    def read(self, addr, size):
        got = self.dump.read(addr, size)
        if got is None:
            img = self.image_at(addr)
            got = img.read(addr, size) if img else None
        return got

    def _copy_out(self, addr, buf, size, nread):
        got = self.read(addr, size)
        if got is None:
            return False
        ctypes.memmove(buf, got, len(got))
        if nread:
            nread[0] = len(got)
        return True

    def _read_memory(self, _process, addr, buf, size, nread):
        return self._copy_out(addr, buf, size, nread)

    def _on_sym_callback(self, _process, action, data, _ctx):
        if action != CBA_READ_MEMORY:
            return False
        req = ctypes.cast(ctypes.c_void_p(data), ctypes.POINTER(IMAGEHLP_CBA_READ_MEMORY)).contents
        return self._copy_out(req.addr, req.buf, req.bytes, req.bytesread)

    def describe(self, addr):
        img = self.image_at(addr)
        mod = img.path.name if img else "?"
        sym = ctypes.cast(self._sym_buf, ctypes.POINTER(SYMBOL_INFOW)).contents
        sym.SizeOfStruct, sym.MaxNameLen = ctypes.sizeof(SYMBOL_INFOW), MAX_NAME
        disp = ctypes.c_uint64()
        name = ""
        if img and self.dbghelp.SymFromAddrW(self.process, addr, ctypes.byref(disp), ctypes.addressof(sym)):
            name = ctypes.wstring_at(ctypes.addressof(sym) + SYMBOL_INFOW.Name.offset, sym.NameLen)
            name = f"{name}+{disp.value:#x}"
        where = ""
        line = IMAGEHLP_LINEW64(SizeOfStruct=ctypes.sizeof(IMAGEHLP_LINEW64))
        ldisp = wintypes.DWORD()
        if img and self.dbghelp.SymGetLineFromAddrW64(self.process, addr, ctypes.byref(ldisp), ctypes.byref(line)):
            where = f"  [{line.FileName}:{line.LineNumber}]"
        rva = f"+{addr - img.base:#x}" if img else ""
        return f"{mod}{rva}  {name}{where}"

    def is_call_site(self, ret):
        """True when the bytes before `ret` end in a call instruction (so `ret` is a real return address)."""
        img = self.image_at(ret)
        if not img or not img.is_code(ret):
            return False
        b = img.read(ret - 7, 7)
        if b is None:
            return False
        rex = (0x40, 0x41, 0x48, 0x49)
        return (b[2] == 0xE8                                            # call rel32
                or (b[1] == 0xFF and (b[2] == 0x15 or 0x90 <= b[2] <= 0x97))  # call [rip+d32] / [reg+d32]
                or (b[0] == 0xFF and b[1] == 0x94)                      # call [rsp+sib+d32]
                or (b[5] == 0xFF and 0xD0 <= b[6] <= 0xD7)              # call reg
                or (b[4] in rex and b[5] == 0xFF and 0xD0 <= b[6] <= 0xD7)
                or (b[5] == 0xFF and 0x10 <= b[6] <= 0x17 and b[6] not in (0x14, 0x15))  # call [reg]
                or (b[4] == 0xFF and 0x50 <= b[5] <= 0x57 and b[5] != 0x54)  # call [reg+d8]
                or (b[3] == 0xFF and b[4] == 0x54)                      # call [rsp+sib+d8]
                or (b[3] in rex and b[4] == 0xFF and 0x50 <= b[5] <= 0x57))

    def resume_point(self, stack_from, stack_end):
        """The first stack slot at or above `stack_from` holding a verified return address into a matched module."""
        for addr in range(stack_from & ~7, stack_end - 7, 8):
            raw = self.dump.read(addr, 8)
            if raw is None:
                return None
            value = struct.unpack("<Q", raw)[0]
            if self.is_call_site(value):
                return addr, value
        return None

    def _walk_from(self, context, rip, rsp, rbp, max_frames, frames, seen, kind):
        ctx_buf = ctypes.create_string_buffer(CTX_SIZE + 16)
        ctx_addr = (ctypes.addressof(ctx_buf) + 15) & ~15
        ctypes.memmove(ctx_addr, context[:CTX_SIZE], min(len(context), CTX_SIZE))
        for off, value in ((CTX_RIP, rip), (CTX_RSP, rsp), (CTX_RBP, rbp)):
            ctypes.memmove(ctx_addr + off, struct.pack("<Q", value), 8)
        frame = ctypes.create_string_buffer(2048)  # STACKFRAME64 with room for any KDHELP64 version
        for off, value in ((0, rip), (32, rbp), (48, rsp)):
            struct.pack_into("<Q", frame, off, value)
            struct.pack_into("<I", frame, off + 12, ADDR_MODE_FLAT)
        last_sp = rsp
        while len(frames) < max_frames:
            if not self.dbghelp.StackWalk64(MACHINE_AMD64, self.process, wintypes.HANDLE(1), frame, ctx_addr,
                                            self._read_cb, self._func_table, self._module_base, None):
                break
            pc, sp = struct.unpack_from("<Q", frame, 0)[0], struct.unpack_from("<Q", frame, 48)[0]
            if pc == 0 or (pc, sp) in seen:
                break
            seen.add((pc, sp))
            frames.append((pc, sp, kind))
            kind = "ret"
            last_sp = sp
            if not self.image_at(pc):
                return last_sp, False  # an unmatched module: no unwind data, the caller may resume by scan
        return last_sp, True

    def walk(self, context, max_frames, stack_end):
        """Frames as (pc, sp, kind): kind "top" (the context's own pc), "ret" (unwound) or "scan" (resumed)."""
        rip, rsp, rbp = (struct.unpack_from("<Q", context, o)[0] for o in (CTX_RIP, CTX_RSP, CTX_RBP))
        frames, seen = [], set()
        sp, done = self._walk_from(context, rip, rsp, rbp, max_frames, frames, seen, "top")
        added = len(frames)
        for _ in range(48):
            # a walk that ended normally after real frames is complete; resume when it stopped in a module we have
            # no image of (the other machine's ntdll / kernelbase, a plugin) or when a resumed start was a stale
            # leftover on the stack (it unwinds to nothing)
            if (done and added > 1) or len(frames) >= max_frames:
                break
            point = self.resume_point(max(sp, rsp), stack_end)
            if not point:
                break
            slot, ret = point
            if frames and not self.image_at(frames[-1][0]):
                frames.pop()
            before = len(frames)
            sp, done = self._walk_from(context, ret, slot + 8, rbp, max_frames, frames, seen, "scan")
            added = len(frames) - before
            sp = max(sp, slot + 8)
        return frames

    def scan(self, stack_start, stack_size, rsp):
        out = []
        start = max(stack_start, rsp)
        for addr in range(start & ~7, stack_start + stack_size - 7, 8):
            raw = self.dump.read(addr, 8)
            if raw is None:
                break
            value = struct.unpack("<Q", raw)[0]
            img = self.image_at(value)
            if img and img.is_code(value):
                out.append((addr, value))
        return out


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        sys.exit(__doc__)
    roots, crash_only, max_frames, scan = [], False, 64, False
    path = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--root":
            roots.append(Path(args[i + 1]))
            i += 1
        elif a == "--crash-only":
            crash_only = True
        elif a == "--frames":
            max_frames = int(args[i + 1])
            i += 1
        elif a == "--scan":
            scan = True
        else:
            path = Path(a)
        i += 1
    dump = Dump(path)
    images, missing = match_modules(dump, roots + DEFAULT_ROOTS)
    sym = Symbolizer(dump, images)
    try:
        print(f"# {path.name}: {len(dump.threads)} threads, {len(dump.modules)} modules "
              f"({len(images)} matched locally), {len(dump.ranges)} memory ranges")
        if missing:
            print(f"# no local match (no symbols, walk may stop): {', '.join(sorted(set(missing)))}")
        crash_tid = None
        if dump.exception:
            crash_tid, code, addr, params, _ctx = dump.exception
            info = ""
            if code == 0xC0000005 and len(params) >= 2:
                info = f" ({['read', 'write', '?', '?', '?', '?', '?', '?', 'execute'][params[0] if params[0] < 9 else 2]} of {params[1]:#x})"
            print(f"# exception {code:#010x} {EXCEPTION_NAMES.get(code, '')}{info} at {addr:#x} "
                  f"on thread {crash_tid}")
            print(f"#   {sym.describe(addr)}")
        order = sorted(dump.threads, key=lambda t: t[0] != crash_tid)
        for tid, ctx, st_start, st_size in order:
            if crash_only and tid != crash_tid:
                continue
            is_crash = tid == crash_tid
            context = dump.exception[4] if is_crash and dump.exception[4] else ctx
            name = dump.thread_names.get(tid, "")
            print(f"\n== thread {tid}{' ' + name if name else ''}{'  <== exception' if is_crash else ''}")
            for pc, sp, kind in sym.walk(context, max_frames, st_start + st_size):
                # a return address points after the call; look up the call itself
                mark = "~" if kind == "scan" else " "
                print(f" {mark}{sp:016x}  {sym.describe(pc if kind == 'top' else pc - 1)}")
            if scan and is_crash:
                rsp = struct.unpack_from("<Q", context, CTX_RSP)[0]
                print("  -- stack scan (return-address candidates) --")
                for addr, value in sym.scan(st_start, st_size, rsp):
                    print(f"  {addr:016x}  {sym.describe(value - 1)}")
    finally:
        sym.dbghelp.SymCleanup(sym.process)


if __name__ == "__main__":
    main()
