"""An x64 stack walk over a minidump without a Windows debugger (P2c, 2026-10-30): the thread's registers and stack
memory from the dump, each frame unwound through its module's .pdata / UNWIND_INFO (the PE files on disk: our
link's exe, the system and runtime DLLs the dump lists), the frames named through our PDB where they lie in the exe.

usage: python -I _tools/pe_unwind.py <dump.dmp> [--exe build/delink/link/ShooterGameServer.exe] [--cache ...]
                                     [--frames 40] [--regs] [--all]
Mini dumps (MemoryListStream) and full dumps (procdump -ma, Memory64ListStream) are both read.
"""
import argparse
import bisect
import struct
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

UWOP_PUSH_NONVOL, UWOP_ALLOC_LARGE, UWOP_ALLOC_SMALL, UWOP_SET_FPREG = 0, 1, 2, 3
UWOP_SAVE_NONVOL, UWOP_SAVE_NONVOL_FAR, UWOP_EPILOG, UWOP_SPARE, UWOP_SAVE_XMM128, UWOP_SAVE_XMM128_FAR, UWOP_PUSH_MACHFRAME = 4, 5, 6, 7, 8, 9, 10
REG = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
CTX = {"rax": 0x78, "rcx": 0x80, "rdx": 0x88, "rbx": 0x90, "rsp": 0x98, "rbp": 0xA0, "rsi": 0xA8, "rdi": 0xB0,
       "r8": 0xB8, "r9": 0xC0, "r10": 0xC8, "r11": 0xD0, "r12": 0xD8, "r13": 0xE0, "r14": 0xE8, "r15": 0xF0, "rip": 0xF8}


class Module:
    """A PE on disk with its exception directory, mapped at the base the dump gives."""

    def __init__(self, path, base):
        self.path, self.base = path, base
        d = self.d = Path(path).read_bytes()
        e = struct.unpack_from("<I", d, 0x3C)[0]
        nsec, optsz = struct.unpack_from("<H", d, e + 6)[0], struct.unpack_from("<H", d, e + 20)[0]
        o = e + 24
        self.size = struct.unpack_from("<I", d, o + 56)[0]
        ndirs = struct.unpack_from("<I", d, o + 108)[0]
        dirs = [struct.unpack_from("<II", d, o + 112 + 8 * i) for i in range(ndirs)]
        self.secs = []
        for i in range(nsec):
            so = e + 24 + optsz + 40 * i
            vs, va, rs, rp = struct.unpack_from("<IIII", d, so + 8)
            self.secs.append((va, max(vs, rs), rp))
        rva, size = dirs[3]
        self.entries = []
        if rva:
            p = self.off(rva)
            for i in range(size // 12):
                self.entries.append(struct.unpack_from("<III", d, p + 12 * i))
        self.begins = [b for b, _e, _u in self.entries]

    def off(self, rva):
        for va, sz, rp in self.secs:
            if va <= rva < va + sz:
                return rp + rva - va
        return None

    def entry(self, rva):
        i = bisect.bisect_right(self.begins, rva) - 1
        if i >= 0 and self.entries[i][0] <= rva < self.entries[i][1]:
            return self.entries[i]
        return None

    def unwind(self, rva, regs, read):
        """One frame: the UNWIND_INFO of the function holding rva applied to regs (rsp, the frame register,
        the saved nonvolatiles); returns the return address, or None."""
        ent = self.entry(rva)
        if ent is None:
            return None  # a leaf: the return address is at rsp
        b, e, u = ent
        chain = 0
        while True:
            p = self.off(u)
            ver_flags, prolog, ncodes, frame = struct.unpack_from("<BBBB", self.d, p)
            flags, frame_reg, frame_off = ver_flags >> 3, frame & 0xF, (frame >> 4) * 16
            codes = [struct.unpack_from("<BB", self.d, p + 4 + 2 * i) for i in range(ncodes)]
            # inside the prolog: only the codes already executed apply (the ones with offset <= rva - b)
            in_prolog = (rva - b) < prolog
            k = 0
            if frame_reg and not in_prolog:
                regs["rsp"] = regs[REG[frame_reg]] - frame_off
            while k < ncodes:
                off, op_info = codes[k]
                op, info = op_info & 0xF, op_info >> 4
                applies = (not in_prolog) or off <= (rva - b)
                if op == UWOP_PUSH_NONVOL:
                    if applies:
                        regs[REG[info]] = read(regs["rsp"])
                        regs["rsp"] += 8
                    k += 1
                elif op == UWOP_ALLOC_LARGE:
                    if info == 0:
                        size = codes[k + 1][0] | (codes[k + 1][1] << 8)
                        size *= 8
                        k += 2
                    else:
                        size = (codes[k + 1][0] | (codes[k + 1][1] << 8) | (codes[k + 2][0] << 16) | (codes[k + 2][1] << 24))
                        k += 3
                    if applies:
                        regs["rsp"] += size
                elif op == UWOP_ALLOC_SMALL:
                    if applies:
                        regs["rsp"] += info * 8 + 8
                    k += 1
                elif op == UWOP_SET_FPREG:
                    k += 1
                elif op == UWOP_SAVE_NONVOL:
                    o2 = (codes[k + 1][0] | (codes[k + 1][1] << 8)) * 8
                    if applies:
                        regs[REG[info]] = read(regs["rsp"] + o2)
                    k += 2
                elif op == UWOP_SAVE_NONVOL_FAR:
                    o2 = codes[k + 1][0] | (codes[k + 1][1] << 8) | (codes[k + 2][0] << 16) | (codes[k + 2][1] << 24)
                    if applies:
                        regs[REG[info]] = read(regs["rsp"] + o2)
                    k += 3
                elif op in (UWOP_SAVE_XMM128, UWOP_EPILOG, UWOP_SPARE):
                    k += 2
                elif op == UWOP_SAVE_XMM128_FAR:
                    k += 3
                elif op == UWOP_PUSH_MACHFRAME:
                    if applies:
                        regs["rsp"] += 40 if info == 0 else 48
                    k += 1
                else:
                    return None
            if flags & 4:  # chained: the parent's codes follow
                q = p + 4 + 2 * ((ncodes + 1) & ~1)
                b, e, u = struct.unpack_from("<III", self.d, q)
                chain += 1
                if chain > 8:
                    return None
                in_prolog = False
                continue
            break
        ret = read(regs["rsp"])
        regs["rsp"] += 8
        return ret


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--exe", default=str(ROOT / "build" / "delink" / "link" / "ShooterGameServer.exe"))
    ap.add_argument("--cache", default=str(ROOT / "build" / "delink" / "link" / "cache"))
    ap.add_argument("--frames", type=int, default=40)
    ap.add_argument("--regs", action="store_true", help="the nonvolatile registers as unwound at each frame")
    ap.add_argument("--all", action="store_true", help="every thread of the dump (a hang), not the exception's")
    a = ap.parse_args()
    d = Path(a.dump).read_bytes()
    _sig, _ver, nstreams, dir_rva = struct.unpack_from("<4sIII", d, 0)
    streams = {}
    for i in range(nstreams):
        typ, size, rva = struct.unpack_from("<III", d, dir_rva + 12 * i)
        streams[typ] = (rva, size)
    rva, _ = streams[4]
    n = struct.unpack_from("<I", d, rva)[0]
    modules = []
    for i in range(n):
        o = rva + 4 + 108 * i
        base, size, _cs, _ts, name_rva = struct.unpack_from("<QIIII", d, o)
        ln = struct.unpack_from("<I", d, name_rva)[0]
        modules.append((base, size, d[name_rva + 4:name_rva + 4 + ln].decode("utf-16-le", "replace")))
    ranges = []
    if 5 in streams:  # MemoryListStream: a mini dump's ranges, each with its own file offset
        r, _ = streams[5]
        cnt = struct.unpack_from("<I", d, r)[0]
        for i in range(cnt):
            start, size, mrva = struct.unpack_from("<QII", d, r + 4 + 16 * i)
            ranges.append((start, size, mrva))
    if 9 in streams:  # Memory64ListStream: a full dump's ranges, laid out back to back from BaseRva
        r, _ = streams[9]
        cnt, base_rva = struct.unpack_from("<QQ", d, r)
        off = base_rva
        for i in range(cnt):
            start, size = struct.unpack_from("<QQ", d, r + 16 + 16 * i)
            ranges.append((start, size, off))
            off += size

    ranges.sort()
    starts = [s for s, _sz, _off in ranges]

    def read(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0:
            s, sz, off = ranges[i]
            if s <= va < s + sz - 7:
                return struct.unpack_from("<Q", d, off + va - s)[0]
        raise KeyError(f"{va:#x} not in the dump")

    threads = []  # (tid, context rva) from the ThreadListStream
    if 3 in streams:
        trva, _ = streams[3]
        tn = struct.unpack_from("<I", d, trva)[0]
        for i in range(tn):
            o = trva + 4 + 48 * i
            tid_i = struct.unpack_from("<I", d, o)[0]
            _csz, crva = struct.unpack_from("<II", d, o + 40)
            threads.append((tid_i, crva))
    if 6 in streams and not a.all:
        rva, _ = streams[6]
        tid, _al, code, _fl, _rec, addr, _np = struct.unpack_from("<IIIIQQI", d, rva)
        ctx_size, ctx_rva = struct.unpack_from("<II", d, rva + 32 + 8 + 15 * 8)
        todo = [(tid, ctx_rva, f"exception {code:#010x} at {addr:#x}")]
    else:
        todo = [(t, c, "") for t, c in threads]  # a hang: every thread's own context (--all, or no exception stream)
    loaded = {}

    def module_of(va):
        for base, size, name in modules:
            if base <= va < base + size:
                if base not in loaded:
                    p = Path(name)
                    if not p.exists():
                        p = Path(a.exe) if Path(name).name.lower() == Path(a.exe).name.lower() else Path("C:/Windows/System32") / Path(name).name
                    loaded[base] = Module(p, base) if p.exists() else None
                return loaded[base], base, name
        return None, None, None

    from func_match import Original
    orig = Original(a.exe, a.cache)
    exe_name = Path(a.exe).name.lower()
    for tid, ctx_rva, what in todo:
        regs = {r: struct.unpack_from("<Q", d, ctx_rva + off)[0] for r, off in CTX.items()}
        print(f"thread {tid}: {what or 'rip ' + hex(regs['rip'])}")
        walk(regs, a, module_of, exe_name, orig, read)


def walk(regs, a, module_of, exe_name, orig, read):
    rip = regs["rip"]
    for frame in range(a.frames):
        mod, base, name = module_of(rip)
        if mod is None:
            print(f"  #{frame:2d} {rip:#x} (in no module{' on disk' if base else ''})")
            break
        r = rip - base
        if Path(name).name.lower() == exe_name:
            names, delta = orig.names_at(r)
            where = f"{names[0][:90] if names else '?'} + {delta:#x}"
        else:
            where = f"{Path(name).name}+{r:#x}"
        print(f"  #{frame:2d} {rip:#x} {where}")
        if a.regs:
            print("       " + " ".join(f"{k}={regs[k]:#x}" for k in ("rsp", "rbx", "rbp", "rsi", "rdi", "r12", "r13", "r14", "r15")))
        try:
            ret = mod.unwind(r, regs, read)
            if ret is None:  # a leaf function: the return address is at rsp
                ret = read(regs["rsp"])
                regs["rsp"] += 8
        except KeyError as ex:
            print(f"      (stack memory missing: {ex})")
            break
        if not ret:
            break
        rip = ret


if __name__ == "__main__":
    main()
