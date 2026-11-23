"""Image-base-relative data operands of two PEs (P2c, 2026-10-31): every instruction of .text with a register base
(not RIP) and a 32-bit displacement that lies in a data section's RVA range is a table read through the image base
in a register (MSVC: `test byte ptr [rax + rdi + imagerel sqlite3CtypeMap], 0x46` with rdi = __ImageBase). A
displacement value that occurs in both PEs is one our link never relocated (the twelfth start's hang: SQLite's
tokenizer reading its character classes at the original's address).

usage: python -I _tools/pe_imagerel.py [ours.exe] [--theirs D:\\ATLASServer\\...\\ShooterGameServer.exe] [--map ...]
"""
import argparse
import bisect
import re
import struct
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86

ROOT = Path(__file__).resolve().parent.parent
THEIRS = Path(r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe")


def scan(path):
    d = Path(path).read_bytes()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    nsec, optsz = struct.unpack_from("<H", d, e + 6)[0], struct.unpack_from("<H", d, e + 20)[0]
    base = struct.unpack_from("<Q", d, e + 24 + 24)[0]
    size_of_image = struct.unpack_from("<I", d, e + 24 + 56)[0]
    secs = []
    for i in range(nsec):
        so = e + 24 + optsz + 40 * i
        name = d[so:so + 8].rstrip(b"\0").decode()
        vs, va, rs, rp, _a, _b, _c, _d, ch = struct.unpack_from("<IIIIIIHHI", d, so + 8)
        secs.append((name, va, max(vs, rs), rp, ch))
    text = next(s for s in secs if s[0] == ".text")
    data_lo = min(s[1] for s in secs if not (s[4] & 0x20000000))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True
    hits = []
    t0 = time.time()
    for ins in md.disasm(d[text[3]:text[3] + text[2]], base + text[1]):
        if ins.id == 0 or ins.disp_size not in (2, 4):
            continue
        for op in ins.operands:
            if op.type == x86.X86_OP_MEM and op.mem.base not in (x86.X86_REG_RIP, 0) and data_lo <= op.mem.disp < size_of_image:
                hits.append((ins.address, op.mem.disp, f"{ins.mnemonic} {ins.op_str}"))
    print(f"{Path(path).name}: {len(hits):,} image-base-relative data operands, {len(set(h[1] for h in hits)):,} tables, {time.time() - t0:.0f} s")
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("ours", nargs="?", default=str(ROOT / "build" / "delink" / "link" / "ShooterGameServer.exe"))
    ap.add_argument("--theirs", default=str(THEIRS))
    ap.add_argument("--map", default=str(ROOT / "build" / "delink" / "link" / "ShooterGameServer.map"))
    a = ap.parse_args()
    ours, theirs = scan(a.ours), scan(a.theirs)
    common = set(h[1] for h in ours) & set(h[1] for h in theirs)
    bad = [h for h in ours if h[1] in common]
    print(f"displacements common to both: {len(common)} tables, {len(bad)} sites in ours (unrelocated)")
    syms = []
    if Path(a.map).exists():
        mp = Path(a.map).read_text(encoding="utf-8", errors="replace")
        syms = sorted((int(m.group(4), 16), m.group(3)) for m in re.finditer(r"^\s*(\d{4}):([0-9a-f]{8})\s+(\S+)\s+([0-9a-f]{16})", mp, re.M))
    svas = [v for v, _ in syms]

    def name_of(va):
        i = bisect.bisect_right(svas, va) - 1
        return f"{syms[i][1][:50]}+{va - syms[i][0]:#x}" if i >= 0 else f"{va:#x}"

    byfn = defaultdict(list)
    for va, disp, txt in bad:
        byfn[name_of(va).split("+")[0]].append((va, disp, txt))
    for fn, sites in sorted(byfn.items(), key=lambda kv: -len(kv[1]))[:50]:
        va, disp, txt = sites[0]
        print(f"  {len(sites):3d} {fn:50s} e.g. {va:#x} {txt[:56]}  rva {disp:#x}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
