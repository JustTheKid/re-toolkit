"""ATLAS constructor defaults as `Member = value` lines: the constructor's memory writes (ghidra_find.py --stores)
mapped onto the class's PDB layout (pdb_struct.Pdb, base classes flattened).

Handles plain constants (floats / doubles decoded by the member's type), bitfield writes (OR = set, AND = clear,
INSERT = value) and writes into a member's own fields (`Member+0x8`). Writes through other pointers (subobjects,
allocated helpers) are listed as unresolved. Base-class constructors are separate functions and not included.

Usage: python -I _tools/ctor_defaults.py <Class> [--va <hex>] [--exe <ShooterGameServer.exe>]
       [--stores-file <ghidra_find --stores output>] [--struct]
       e.g. python -I _tools/ctor_defaults.py UPrimitiveComponent
"""
import argparse
import re
import struct
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from pdb_struct import Pdb  # noqa: E402

SERVER = r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe"
STORE = re.compile(r"^\s+([0-9a-f]+)\s+\[(\d+)\]\s+\*(.+?) = (.+)$")


def this_offset(expr):
    """'(this+0x210)+0x4' / '((this+0x8a4)+0xc)+0x0' / 'this' -> offset, else None"""
    e = expr.replace(" ", "")
    if not e.startswith("(") and e != "this":
        e = "(" + e + ")"
    terms = re.findall(r"\+0x([0-9a-f]+)", e)
    base = re.sub(r"[()]|\+0x[0-9a-f]+", "", e)
    if base != "this":
        return None
    return sum(int(t, 16) for t in terms)


def decode(value, size, mtype):
    m = re.fullmatch(r"(-?)0x([0-9a-f]+)", value)
    if not m:
        return value
    v = int(m.group(2), 16) * (-1 if m.group(1) else 1) % (1 << (size * 8))
    if mtype in ("float32",) and size == 4:
        return repr(struct.unpack("<f", struct.pack("<I", v & 0xFFFFFFFF))[0]) + "f"
    if mtype in ("float64",) and size == 8:
        return repr(struct.unpack("<d", struct.pack("<Q", v))[0])
    if mtype.startswith("bool") or mtype.startswith("uint8"):
        return "true" if v else "false"
    if v >= 1 << (size * 8 - 1) and not mtype.startswith("uint"):
        v -= 1 << (size * 8)
    return str(v)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cls")
    ap.add_argument("--va")
    ap.add_argument("--exe", default=SERVER)
    ap.add_argument("--stores-file", help="saved `ghidra_find.py --address ... --stores` output of many functions (one "
                                          "Ghidra run for a batch); the block of --va is used")
    ap.add_argument("--struct", action="store_true", help="a struct constructor (no FPostConstructInitializeProperties)")
    args = ap.parse_args()
    py = sys.executable
    va = args.va
    if not va:
        out = subprocess.run([py, "-I", str(TOOLS / "pdb_lookup.py"), args.exe, f"{args.cls}::{args.cls}"],
                             capture_output=True, text=True).stdout
        cands = [l.split("\t")[0] for l in out.splitlines() if "\t" in l and
                 (args.struct or "FPostConstructInitializeProperties" in l)]
        if not cands:
            sys.exit(f"no constructor found for {args.cls}:\n{out}")
        va = cands[0]
    if args.stores_file:
        lines, inside = [], False
        for line in open(args.stores_file, encoding="utf-8-sig"):
            if line[:1].strip():  # a function header line: "<va>  <n> bytes  <name>"
                inside = line.split()[0] == va
            elif inside:
                lines.append(line.rstrip("\n"))
        stores = "\n".join(lines)
    else:
        stores = subprocess.run([py, "-I", str(TOOLS / "ghidra_find.py"), "--address", va, "--stores"],
                                capture_output=True, text=True).stdout
    members = Pdb(args.exe).members(args.cls, flatten=True) or []
    by_off = {}
    for m in members:
        by_off.setdefault(m["offset"], []).append(m)

    def member_at(off):
        exact = by_off.get(off)
        if exact:
            return exact, 0
        inside = [m for m in members if m["bit"] is None and m["size"] and m["offset"] < off < m["offset"] + m["size"]]
        return (inside, off - inside[0]["offset"]) if inside else ([], 0)

    print(f"// {args.cls} constructor @{va}: ATLAS defaults (base-class constructors not included)")
    for line in stores.splitlines():
        m = STORE.match(line)
        if not m:
            continue
        addr, size, target, value = m.group(1), int(m.group(2)), m.group(3), m.group(4)
        off = this_offset(target)
        if off is None:
            print(f"// unresolved @{addr}: *{target} = {value}")
            continue
        cands, inner = member_at(off)
        bitfields = [c for c in cands if c["bit"] is not None]
        if bitfields:
            ins = re.match(r"INSERT\(.*?, (0x[0-9a-f]+), (0x[0-9a-f]+), (0x[0-9a-f]+)\)$", value)
            orm = re.search(r"INT_OR\(.*, (0x[0-9a-f]+)\)$", value)
            andm = re.search(r"INT_AND\(.*, (0x[0-9a-f]+)\)$", value)
            if ins:
                val, bit = int(ins.group(1), 16), int(ins.group(2), 16)
                for c in bitfields:
                    if c["bit"] == bit:
                        print(f"{c['name']} = {'true' if val else 'false'};  // +0x{off:x}.{bit}")
                continue
            mask, setting = None, None
            if orm:
                mask, setting = int(orm.group(1), 16), True
            elif andm:
                mask, setting = ~int(andm.group(1), 16) & ((1 << (size * 8)) - 1), False
            if mask is not None:
                for c in bitfields:
                    if mask >> c["bit"] & 1:
                        print(f"{c['name']} = {'true' if setting else 'false'};  // +0x{off:x}.{c['bit']}")
                continue
            print(f"// bitfield word +0x{off:x} ({', '.join(c['name'] for c in bitfields)}) = {value}")
            continue
        if not cands:
            print(f"// +0x{off:x} (no member) = {value}")
            continue
        c = cands[0]
        if inner or (c["size"] and size < c["size"] and c["type"] not in ("float32", "float64")):
            print(f"{c['name']} (+0x{inner:x}, {size} bytes) = {value};  // {c['type']} +0x{off:x}")
        else:
            print(f"{c['name']} = {decode(value, size, c['type'])};  // {c['type']} +0x{off:x}")


if __name__ == "__main__":
    main()
