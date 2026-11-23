"""One compile unit's section contributions in the server, from the judge's PDB cache (func_match.py's pdbsyms2.pkl):
the module that holds a VA, every range it contributes (with the PE section's name), and the publics inside them.
The ranges file is delink_unit.py's input. Written for the delink trial (plan P2, 2026-10-29, the handover session).

usage: python -I _tools/unit_contribs.py <hex VA inside the unit> [--ranges <out.txt>] [--symbols <out.txt>]
  e.g. unit_contribs.py 140591c50 --ranges build/delink/raft-ranges.txt   (PrimalRaft.cpp.obj, module 406)
"""
import bisect
import pickle
import struct
import sys
from collections import Counter
from pathlib import Path

PE = Path(r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe")
CACHE = Path(r"D:\ATLAS\_re\cache\ShooterGameServer.pdbsyms2.pkl")
BASE = 0x140000000

data = PE.read_bytes()[:4096]
e = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, e + 6)[0]
opt = struct.unpack_from("<H", data, e + 20)[0]
secs = []
for i in range(nsec):
    o = e + 24 + opt + 40 * i
    name = data[o:o + 8].rstrip(b"\0").decode()
    vsize, va = struct.unpack_from("<II", data, o + 8)
    secs.append((va, vsize, name))


def sec_name(rva):
    for va, vs, n in secs:
        if va <= rva < va + vs:
            return n
    return "?"


by_name, sizes, mods = pickle.loads(CACHE.read_bytes())
starts = sorted(mods)
va = int(sys.argv[1], 16) - BASE
i = bisect.bisect_right(starts, va) - 1
mod = mods[starts[i]][0]
mine = [(r, mods[r][1]) for r in starts if mods[r][0] == mod]
print("module", mod, "contributions", len(mine), "bytes", sum(s for _, s in mine))
print(" by section", dict(Counter(sec_name(r) for r, _ in mine)))
print(" bytes by section", {n: sum(s for r, s in mine if sec_name(r) == n) for n in set(sec_name(r) for r, _ in mine)})
pubs = []
rvas = sorted((r, n) for n, r in by_name.items())
keys = [r for r, _ in rvas]
for r, s in mine:
    a = bisect.bisect_left(keys, r)
    while a < len(rvas) and rvas[a][0] < r + s:
        pubs.append((rvas[a][0], rvas[a][1], sec_name(rvas[a][0])))
        a += 1
print(" publics inside", len(pubs), dict(Counter(p[2] for p in pubs)))
if "--ranges" in sys.argv:
    out = Path(sys.argv[sys.argv.index("--ranges") + 1])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join("%x-%x %s\n" % (BASE + r, BASE + r + s - 1, sec_name(r)) for r, s in mine))
if "--symbols" in sys.argv:
    out = Path(sys.argv[sys.argv.index("--symbols") + 1])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("".join("%x %s %s\n" % (BASE + r, n, sn) for r, n, sn in pubs), encoding="utf-8")
