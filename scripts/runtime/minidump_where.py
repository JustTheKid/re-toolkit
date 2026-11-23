"""Where a minidump's exception happened: the exception code and address, the module it lies in, and the symbol
through that module's PDB (our link's, beside the exe) - no Windows debugger needed (P2c, 2026-10-30).

usage: python -I _tools/minidump_where.py <dump.dmp> [--exe build/delink/link/ShooterGameServer.exe]
                                           [--cache build/delink/link/cache]
"""
import argparse
import struct
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

# CONTEXT (x64): Rip at 0xF8, Rsp at 0x98, Rax.. at 0x78
REGS = {"rax": 0x78, "rcx": 0x80, "rdx": 0x88, "rbx": 0x90, "rsp": 0x98, "rbp": 0xA0, "rsi": 0xA8, "rdi": 0xB0,
        "r8": 0xB8, "r9": 0xC0, "r10": 0xC8, "r11": 0xD0, "r12": 0xD8, "r13": 0xE0, "r14": 0xE8, "r15": 0xF0, "rip": 0xF8}


def returns_from_call(orig, rva):
    """True when the bytes before rva end a call instruction (E8 rel32, FF /2 with its ModRM forms, or a
    REX-prefixed one): a return address, as against a stale code pointer left on the stack."""
    b = orig.read(rva - 7, 7)
    if not b or len(b) < 7:
        return False
    if b[2] == 0xE8:  # call rel32
        return True
    for n in (2, 3, 4, 5, 6, 7):  # FF /2: FF D0..D7, FF 10..17, FF 50..57 ib, FF 90..97 id, FF 14 sib, ...
        s = b[7 - n:]
        i = 1 if s[0] in range(0x40, 0x50) else 0  # a REX prefix
        if len(s) > i and s[i] == 0xFF and len(s) > i + 1 and (s[i + 1] >> 3) & 7 == 2:
            return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--exe", default=str(ROOT / "build" / "delink" / "link" / "ShooterGameServer.exe"))
    ap.add_argument("--cache", default=str(ROOT / "build" / "delink" / "link" / "cache"))
    a = ap.parse_args()
    d = Path(a.dump).read_bytes()
    sig, _ver, nstreams, dir_rva = struct.unpack_from("<4sIII", d, 0)
    assert sig == b"MDMP", "not a minidump"
    streams = {}
    for i in range(nstreams):
        typ, size, rva = struct.unpack_from("<III", d, dir_rva + 12 * i)
        streams[typ] = (rva, size)
    modules = []
    if 4 in streams:
        rva, _ = streams[4]
        n = struct.unpack_from("<I", d, rva)[0]
        for i in range(n):
            o = rva + 4 + 108 * i
            base, size, _cs, _ts, name_rva = struct.unpack_from("<QIIII", d, o)
            ln = struct.unpack_from("<I", d, name_rva)[0]
            name = d[name_rva + 4:name_rva + 4 + ln].decode("utf-16-le", "replace")
            modules.append((base, size, name))

    def module_of(addr):
        for base, size, name in modules:
            if base <= addr < base + size:
                return base, name
        return None, None

    if 6 not in streams:
        sys.exit("no exception stream")
    rva, _ = streams[6]
    tid, _al, code, flags, _rec, addr, nparams = struct.unpack_from("<IIIIQQI", d, rva)
    params = struct.unpack_from("<15Q", d, rva + 32 + 8)
    ctx_size, ctx_rva = struct.unpack_from("<II", d, rva + 32 + 8 + 15 * 8)
    base, name = module_of(addr)
    print(f"thread {tid}: exception {code:#010x} at {addr:#x}" + (f" = {Path(name).name}+{addr - base:#x}" if base else " (in no module)"))
    if code == 0xC0000005:
        print(f"  access violation: {'write' if params[0] == 1 else 'read' if params[0] == 0 else 'execute'} of {params[1]:#x}")
    regs = {r: struct.unpack_from("<Q", d, ctx_rva + off)[0] for r, off in REGS.items()} if ctx_size >= 0x100 else {}
    if regs:
        print("  " + "  ".join(f"{r}={v:#x}" for r, v in regs.items()))
    exe = next(((b, s, n) for b, s, n in modules if Path(n).name.lower() == Path(a.exe).name.lower()), None)
    if exe:
        from func_match import Original
        orig = Original(a.exe, a.cache)
        ebase, esize, _ = exe

        def where(va):
            if ebase <= va < ebase + esize:
                names, delta = orig.names_at(va - ebase)
                return f"exe+{va - ebase:#x} = {names[:2]} + {delta:#x}"
            b, n = module_of(va)
            return f"{Path(n).name}+{va - b:#x}" if b else None

        for r, v in regs.items():
            w = where(v)
            if w:
                print(f"  {r} -> {w}")
        # the return addresses on the stack: a poor man's stack walk (every stack slot that points into a module)
        if regs and 3 in streams:  # ThreadListStream: find the thread's stack memory
            trva, _ = streams[3]
            n = struct.unpack_from("<I", d, trva)[0]
            for i in range(n):
                o = trva + 4 + 48 * i
                t_id = struct.unpack_from("<I", d, o)[0]
                if t_id != tid:
                    continue
                # MINIDUMP_THREAD: ThreadId, SuspendCount, PriorityClass, Priority, Teb (8), Stack {StartOfMemoryRange
                # (8), Memory {DataSize, Rva}}, ThreadContext {DataSize, Rva}
                s_start, s_size, s_rva = struct.unpack_from("<QII", d, o + 24)
                stack = d[s_rva:s_rva + s_size]
                print(f"  stack {s_start:#x}+{s_size:#x}: slots above rsp that hold a return address (the bytes before it a call)")
                shown = 0
                for k in range(max(0, regs['rsp'] - s_start), min(s_size - 7, regs['rsp'] - s_start + 0x2000), 8):
                    v = struct.unpack_from("<Q", stack, k)[0]
                    w = where(v)
                    if not w or (ebase <= v < ebase + 0x1000):
                        continue
                    if ebase <= v < ebase + esize and not returns_from_call(orig, v - ebase):
                        continue  # a stale pointer, not a return address
                    print(f"    [rsp+{k - (regs['rsp'] - s_start):#x}] {v:#x} = {w}")
                    shown += 1
                    if shown >= 30:
                        break
    print("modules:", len(modules), [Path(n).name for _b, _s, n in modules[:6]], "...")


if __name__ == "__main__":
    main()
