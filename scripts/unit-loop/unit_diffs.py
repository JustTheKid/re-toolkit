"""unit_diffs.py <Unit.cpp>: the unit's DIFF / MATCH~ functions after a judge, for the fix rounds - each with the original's
address, its size, the first differing byte offset, the cause bucket (causes.json), the ledger-style ID and the bodies file
(build/loop/<unit>/bodies/*.cpp) whose `//@ SRV@<va>` chunk holds it; the hand-written rows first (the skeleton's), then
what the compiler emits for the headers. 2026-11-08 (P6, the eighteenth unit PrimalRaft.cpp: 90 DIFFs over ten batch
files, instead of a scratch script per unit).
Usage: python _tools/rebuild/unit_diffs.py PrimalRaft.cpp [--all] (--all: the compiler's ones too, not only the count)"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        sys.exit(__doc__)
    w = ROOT / "build" / "loop" / args[0]
    funcs = json.loads((w / "match.json").read_text(encoding="utf-8"))
    causes = {c["name"]: c for c in json.loads((w / "causes.json").read_text(encoding="utf-8"))} if (w / "causes.json").exists() else {}
    hand = set()
    if (w / "skeleton.cpp").exists():
        hand = set(re.findall(r"// ATLAS-ID: SRV@([0-9a-f]+)", (w / "skeleton.cpp").read_text(encoding="utf-8")))
    where = {}
    for f in sorted((w / "bodies").glob("*.cpp")) if (w / "bodies").exists() else []:
        for va in re.findall(r"^//@ SRV@([0-9a-f]+)\s*$", f.read_text(encoding="utf-8"), re.M):
            where[va] = f.name
    rows = []
    for f in funcs:
        if f.get("state") not in ("DIFF", "MATCH~") or "rva" not in f:
            continue
        va = format(0x140000000 + int(f["rva"]), "x")
        c = causes.get(f["name"], {})
        rows.append((va in hand, va, f["state"], f.get("size", 0), f.get("first", ""), c.get("bucket", ""), c.get("first", ""),
                     where.get(va, "-"), f["name"]))
    own = [r for r in rows if r[0]]
    other = [r for r in rows if not r[0]]
    print(f"{args[0]}: {len(own)} hand-written DIFF / MATCH~, {len(other)} of the compiler's")
    for r in sorted(own, key=lambda r: (r[7], r[1])):
        print(f"  {r[7]:8} SRV@{r[1]} {r[2]:6} {r[3]:6} +{r[4]!s:5} {r[5][:44]:44} {r[8][:70]}")
    if "--all" in sys.argv:
        for r in sorted(other, key=lambda r: r[1]):
            print(f"  compiler SRV@{r[1]} {r[2]:6} {r[3]:6} +{r[4]!s:5} {r[5][:44]:44} {r[8][:70]}")


if __name__ == "__main__":
    main()
