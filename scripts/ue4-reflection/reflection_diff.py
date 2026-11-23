"""Compare ATLAS's reflected property table of a class (from its Z_Construct decompile) with our engine's.

Our side comes from `UE4Editor-Cmd -run=AtlasFormatTest -reflection=<Class,...> -out=<dir>` (one .jsonl per class,
names without the U/A/F prefix). Flags are compared without the computed bits (IsPlainOldData, NoDestructor,
ZeroConstructor), which depend on how a type is compiled. Offsets are not compared.

Usage: python -I _tools/reflection_diff.py <Z_Construct_...@va.c> <ours.jsonl>
Exit status 1 when anything differs.
"""
import json
import subprocess
import sys
from pathlib import Path

COMPUTED = 0x40000000 | 0x1000000000 | 0x200


def ours(path):
    return [json.loads(line) for line in open(path, encoding="utf-8-sig") if line.strip()]


def atlas(decompile):
    out = subprocess.run([sys.executable, "-I", str(Path(__file__).with_name("reflection_table.py")), decompile],
                         capture_output=True, text=True, check=True).stdout
    return [json.loads(line) for line in out.splitlines() if line.startswith("{")]


def key(row):
    return (row["name"], row.get("inner_of", ""))


def flags(row):
    try:
        return int(row["flags"], 16) & ~COMPUTED
    except (KeyError, ValueError):
        return None


def main():
    theirs, mine = atlas(sys.argv[1]), ours(sys.argv[2])
    a, b = {key(r): r for r in theirs}, {key(r): r for r in mine}
    problems = []
    for k, r in a.items():
        if k not in b:
            problems.append(f"missing in ours: {k[0]}{' (inner)' if k[1] else ''} {r['kind']} {r.get('ref', '')} flags {r.get('flags')}")
            continue
        o = b[k]
        if r["kind"] != o["kind"]:
            problems.append(f"{k[0]}: kind {r['kind']} vs ours {o['kind']}")
        fa, fo = flags(r), flags(o)
        if fa is not None and fa != fo:
            problems.append(f"{k[0]}{' (inner)' if k[1] else ''}: flags 0x{fa:x} vs ours 0x{fo:x} (differ 0x{fa ^ fo:x})")
        # ATLAS names nested types after their outer (UObject_FVector); ours by prefix + name (FVector)
        if r.get("ref") and o.get("ref") and not (r["ref"] == o["ref"] or r["ref"].endswith("_" + o["ref"].lstrip("UAFE"))
                                                  or r["ref"].endswith("_" + o["ref"])):
            problems.append(f"{k[0]}: type {r['ref']} vs ours {o['ref']}")
        if "native_bool" in r and r.get("native_bool") != o.get("native_bool"):
            problems.append(f"{k[0]}: native bool {r['native_bool']} vs ours {o.get('native_bool')}")
        if r.get("dim", 1) != o.get("dim", 1):
            problems.append(f"{k[0]}: array dim {r.get('dim', 1)} vs ours {o.get('dim', 1)}")
    for k, o in b.items():
        if k not in a:
            problems.append(f"extra in ours: {k[0]}{' (inner)' if k[1] else ''} {o['kind']}")
    order_a = [k for k in a if k[1] == "" and k in b]
    order_b = [k for k in b if k[1] == "" and k in a]
    # UHT emits properties in reverse declaration order; our dump is in declaration order
    if order_a != list(reversed(order_b)):
        problems.append("declaration order differs")
    print(f"{Path(sys.argv[2]).stem}: {len(a)} ATLAS / {len(b)} ours, {len(problems)} difference(s)")
    for p in problems:
        print("  " + p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
