"""Two PEs per function through their PDBs (plan P2c, 2026-10-30): the linked ShooterGameServer.exe against ATLAS's.

For every public function of the original (its size from the PDB's section contribution, capped at the next public)
the same name in ours (our link's PDB beside our exe; publics only, so the delinked objects' external names), and
the bytes compared: identical as they are, else instruction by instruction with capstone, where the fields that
encode an address (a RIP-relative displacement, a call / jump / jcc target, a 64-bit immediate inside the image)
are compared by what they reach - the same public name and offset in both PDBs, or the same offset within the
function for a target inside it - instead of by value, since the two layouts differ.

Verdicts: IDENTICAL (bytes equal), MATCH (every address field reaches the same symbol), MATCH~ (some field's
target has no public name on one side: unchecked), DIFF (an opcode, an operand or a reached symbol differs),
ALIAS (an original name whose folded body ours holds under another of its names: identical-code folding),
MISSING (not in ours), SIZE (ours shorter than the original's function).

usage: python -I _tools/pe_compare.py [ours.exe] [--theirs D:\\ATLASServer\\...\\ShooterGameServer.exe]
                                      [--cache build/delink/link/cache] [--names REGEX] [--json out.json] [--limit N]
"""
import argparse
import json
import re
import struct
import sys
import time
from collections import Counter
from pathlib import Path

import capstone
from capstone import x86

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
from func_match import Original  # noqa: E402

THEIRS = Path(r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe")
OURS = ROOT / "build" / "delink" / "link" / "ShooterGameServer.exe"
BRANCH = {"call", "jmp", "je", "jne", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle", "js", "jns", "jo", "jno",
          "jp", "jnp", "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne"}


class Pe:
    def __init__(self, path, cache):
        self.orig = Original(path, cache)
        self.base = self.orig.image_base
        self.size_of_image = max(va + vs for va, vs, _r, _rs in self.orig.secs)

    def read(self, rva, n):
        return self.orig.read(rva, n)

    def inside(self, va):
        return self.base <= va < self.base + self.size_of_image

    def names(self, rva):
        return self.orig.names_at(rva)


def function_size(theirs, rva):
    size = theirs.orig.sizes.get(rva)
    i = theirs.orig.rvas.index(rva) if rva in theirs.orig.by_rva else None
    nxt = theirs.orig.rvas[i + 1] - rva if i is not None and i + 1 < len(theirs.orig.rvas) else None
    if size is None:
        return nxt
    return min(size, nxt) if nxt else size


def address_fields(insn, base):
    """[(offset, width, target va)] of the operand fields that encode an address. A 32-bit displacement with a
    register base other than RIP may be an RVA (the image base in the register: a switch table's load
    `[r11 + rax*4 + imagerel table]`, a global `[rbp + rsi*8 + imagerel G]`): it is taken as one when it lies inside
    the image, as the va base + disp - compare() only looks at a field whose raw value differs between the sides."""
    out = []
    if insn.mnemonic in BRANCH and insn.imm_size and insn.operands and insn.operands[0].type == x86.X86_OP_IMM:
        out.append((insn.imm_offset, insn.imm_size, insn.operands[0].imm))
    # capstone reports disp_size 2 under a 0x66 operand-size prefix (comisd, movdqa, `cmp word ptr`), but 64-bit
    # mode has no 16-bit displacement: such a field is the 4-byte one (674 false "bytes" DIFFs, 2026-10-30)
    disp_size = 4 if insn.disp_size == 2 else insn.disp_size
    for op in insn.operands:
        if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP and disp_size:
            out.append((insn.disp_offset, disp_size, insn.address + insn.size + op.mem.disp))
        elif op.type == x86.X86_OP_MEM and disp_size == 4 and 0x1000 <= op.mem.disp < IMAGE_SPAN:
            out.append((insn.disp_offset, disp_size, base + op.mem.disp, "maybe"))
        elif op.type == x86.X86_OP_IMM and insn.imm_size == 8 and insn.mnemonic not in BRANCH:
            out.append((insn.imm_offset, insn.imm_size, op.imm))
    return out


IMAGE_SPAN = 0x5000000  # both images are smaller than 80 MB


def compare(ours, theirs, name, orva, trva, size, md):
    a, b = ours.read(orva, size), theirs.read(trva, size)
    if a is None or len(a) < size:
        return "SIZE", {}
    if a == b:
        return "IDENTICAL", {}
    ia = list(md.disasm(a, ours.base + orva))
    ib = list(md.disasm(b, theirs.base + trva))
    unchecked = 0
    pos = 0
    for x, y in zip(ia, ib):
        if x.size != y.size or x.mnemonic != y.mnemonic:
            return "DIFF", {"at": pos, "ours": f"{x.mnemonic} {x.op_str}", "theirs": f"{y.mnemonic} {y.op_str}"}
        fx, fy = address_fields(x, ours.base), address_fields(y, theirs.base)
        if len(fx) != len(fy) or [(f[0], f[1]) for f in fx] != [(f[0], f[1]) for f in fy]:
            return "DIFF", {"at": pos, "ours": f"{x.mnemonic} {x.op_str}", "theirs": f"{y.mnemonic} {y.op_str}"}
        xb, yb = bytearray(x.bytes), bytearray(y.bytes)
        for fxi, fyi in zip(fx, fy):
            o, w, tx = fxi[:3]
            ty = fyi[2]
            if len(fxi) > 3 and tx - ours.base == ty - theirs.base:
                continue  # a displacement that may be an RVA, equal on both sides: an offset, compared as bytes
            xb[o:o + w] = b"\0" * w
            yb[o:o + w] = b"\0" * w
            if not ours.inside(tx) and not theirs.inside(ty):
                if tx != ty:
                    return "DIFF", {"at": pos, "ours": f"{x.mnemonic} {x.op_str}", "theirs": f"{y.mnemonic} {y.op_str}"}
                continue
            if ours.inside(tx) != theirs.inside(ty):
                return "DIFF", {"at": pos, "ours": f"{x.mnemonic} {x.op_str}", "theirs": f"{y.mnemonic} {y.op_str}",
                                "why": "one target outside the image"}
            rx, ry = tx - ours.base, ty - theirs.base
            if orva <= rx < orva + size or trva <= ry < trva + size:
                if rx - orva != ry - trva:
                    return "DIFF", {"at": pos, "ours": f"{x.mnemonic} {x.op_str}", "theirs": f"{y.mnemonic} {y.op_str}",
                                    "why": "a different offset within the function"}
                continue
            nx, dx = ours.names(rx)
            ny, dy = theirs.names(ry)
            if not nx or not ny:
                unchecked += 1
                continue
            common = set(nx) & set(ny)
            if common and dx == dy:
                continue
            if dx != dy or not common:
                # the delinked objects name a public-less target by the address it carried (LAB_<va>, @local@<va>)
                carried = [n for n in nx if re.search(r"(1[0-9a-f]{8})$", n)]
                if carried and any(int(re.search(r"(1[0-9a-f]{8})$", n).group(1), 16) - theirs.base + dx == ry for n in carried):
                    continue  # the carried name plus our offset is the original's target: the same place, named differently
                return "DIFF", {"at": pos, "ours": f"{x.mnemonic} {x.op_str}", "theirs": f"{y.mnemonic} {y.op_str}",
                                "reach": [sorted(nx)[:2], dx, sorted(ny)[:2], dy]}
        if bytes(xb) != bytes(yb):
            return "DIFF", {"at": pos, "ours": f"{x.mnemonic} {x.op_str}", "theirs": f"{y.mnemonic} {y.op_str}", "why": "bytes"}
        pos += x.size
    if len(ia) != len(ib) or pos < size:
        # the decoders stopped at different places: compare the rest as bytes
        if a[pos:] != b[pos:]:
            return "DIFF", {"at": pos, "why": "undecoded tail differs"}
    return ("MATCH~" if unchecked else "MATCH"), {"unchecked": unchecked}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ours", nargs="?", default=str(OURS))
    ap.add_argument("--theirs", default=str(THEIRS))
    ap.add_argument("--cache", default=str(ROOT / "build" / "delink" / "link" / "cache"))
    ap.add_argument("--names")
    ap.add_argument("--json")
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    t0 = time.time()
    theirs = Pe(a.theirs, ROOT / "_re" / "cache")
    ours = Pe(a.ours, a.cache)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    pat = re.compile(a.names) if a.names else None
    text = next((va, vs) for va, vs, _r, _rs in theirs.orig.secs)  # the first section is .text
    counts = Counter()
    results = []
    n = 0
    for name, trva in sorted(theirs.orig.by_name.items(), key=lambda kv: kv[1]):
        if not text[0] <= trva < text[0] + text[1] or (pat and not pat.search(name)):
            continue
        size = function_size(theirs, trva)
        if not size:
            continue
        orva = ours.orig.by_name.get(name)
        if orva is None:
            # identical-code folding gave the original several public names per folded body; our link holds the
            # one the exporter picked, so the others are aliases, not missing code
            others = [n for n in theirs.orig.by_rva.get(trva, []) if n in ours.orig.by_name]
            state, info = ("ALIAS", {"of": others[0]}) if others else ("MISSING", {})
        else:
            state, info = compare(ours, theirs, name, orva, trva, size, md)
        counts[state] += 1
        n += 1
        if state in ("DIFF", "SIZE", "MISSING") and len(results) < 2000 or a.json:
            results.append({"name": name, "rva": trva, "size": size, "state": state, **info})
        if n % 20000 == 0:
            print(f"  {n:,} functions, {time.time() - t0:.0f} s: {dict(counts)}", flush=True)
        if a.limit and n >= a.limit:
            break
    total = sum(counts.values())
    found = total - counts["MISSING"] - counts["ALIAS"]
    same = counts["IDENTICAL"] + counts["MATCH"] + counts["MATCH~"]
    print(f"{Path(a.ours).name} against {Path(a.theirs).name}: {total:,} public names in .text, {counts['ALIAS']:,} "
          f"of them ICF aliases of a name ours has; {found:,} compared: the same code {same:,} "
          f"({100 * same / max(found, 1):.2f}%) - IDENTICAL {counts['IDENTICAL']:,}, MATCH {counts['MATCH']:,}, "
          f"MATCH~ {counts['MATCH~']:,}; DIFF {counts['DIFF']:,}, SIZE {counts['SIZE']:,}, MISSING {counts['MISSING']:,}; "
          f"{time.time() - t0:.0f} s")
    for r in [r for r in results if r["state"] == "DIFF"][:12]:
        print("  DIFF", r["name"][:70], json.dumps({k: v for k, v in r.items() if k not in ("name", "state")})[:220])
    if a.json:
        Path(a.json).write_text(json.dumps(results, indent=0), encoding="utf-8")


if __name__ == "__main__":
    main()
