"""Why the judge's DIFFs differ: sorts func_match.py's results by root cause. For a byte DIFF both functions are
disassembled (capstone), call and RIP-relative targets are named (ours from our object's relocations, the
original's from its PDB publics) and the first differing instruction is classified: a virtual call through another
vtable slot, a constant (often a sizeof), a member offset, another callee, register allocation. A relocation DIFF is
classified from the judge's record (e.g. a function-local static the PDB's publics do not name).

Usage: python -I _tools/judge_causes.py <our .obj> <original pe> <func_match --json output> [--details N]
           [--json <out.json>] [--cache <dir>]
  Prints the root-cause buckets with counts; --details N also lists the N most frequent first differences with an
  example each; --json writes one record per DIFF (name, kind, first difference, bucket).
Needs capstone in the venv (docs/knowledge/tooling.md). 2026-10-24: ADR-0006 calibration (matching-decompilation.md).
"""
import argparse
import collections
import json
import re
import sys
from pathlib import Path

import capstone
from capstone import x86

sys.path.insert(0, str(Path(__file__).resolve().parent))
from func_match import REPO, Coff, Original  # noqa: E402

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = True
RIPMEM = re.compile(r"\[rip(?: [+-] (?:0x)?[0-9a-f]+)?\]")
HEX = re.compile(r"0x[0-9a-f]+")
REG = re.compile(r"\b(r[a-z0-9]+|e[a-z]{2}|[a-d][lhx]|[sd]il|[sb]pl|xmm\d+)\b")
NUM = re.compile(r"0x[0-9a-f]+|\b\d+\b")
LOCAL_STATIC = re.compile(r"\?\d+\?\?|\$initializer\$|\?\?_B")


def kind(n):
    """Kind of function by its decorated name (generated reflection code first)."""
    for k, p in (("Z_Construct_UClass", "Z_Construct_UClass_"), ("Z_Construct_UScriptStruct", "Z_Construct_UScriptStruct_"),
                 ("Z_Construct_UFunction", "Z_Construct_UFunction_"), ("Z_Construct_UEnum", "Z_Construct_UEnum_"),
                 ("Z_Construct other", "Z_Construct_"), ("exec thunk", r"^\?exec"),
                 ("StaticRegisterNatives", "StaticRegisterNatives"), ("GetPrivateStaticClass", "GetPrivateStaticClass"),
                 ("StaticStruct", "StaticStruct"), ("TCppStructOps", "TCppStructOps"),
                 ("constructor / destructor", r"^\?\?[01]"), ("operator", r"^\?\?[2-9A-Z_]"), ("template", r"^\?\?\$")):
        if re.search(p, n):
            return k
    return "other"


def short(n):
    """Class::Function (or Template<>) from a decorated name, for reports."""
    m = re.match(r"\?\?\$(\w+)@", n or "")
    if m:
        return m.group(1) + "<>"
    m = re.match(r"\?(\w+)@(\w+)@@", n or "")
    if m:
        return f"{m.group(2)}::{m.group(1)}"
    m = re.match(r"\?(\w+)@@", n or "")
    return m.group(1) if m else (n or "?")[:40]


def direct_branch(i):
    return (i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_CALL)) and any(
        o.type == x86.X86_OP_IMM for o in i.operands)


def disasm(code, base, targets):
    """[(mnemonic, operands with the named target replaced by @T, target names or None)]"""
    out = []
    for i in MD.disasm(code, base):
        names = targets(i)
        op = i.op_str
        if names is not None:
            op = RIPMEM.sub("[@T]", op, count=1) if "rip" in op else HEX.sub("@T", op, count=1)
        out.append((i.mnemonic, op, names))
    return out


def our_targets(obj, sec, off, size):
    rel = {}
    for va, symi, _ in obj.relocs(sec):
        if off <= va < off + size:
            sym = obj.symbols[symi]
            rel[va - off] = sym["name"] if sym else "?"

    def f(i):
        for b in range(i.address, i.address + i.size):
            if b in rel:
                return {rel[b]}
        return {"local"} if direct_branch(i) else None
    return f


def their_targets(orig, rva, size):
    def f(i):
        tgt = None
        if direct_branch(i):
            tgt = next(o.imm for o in i.operands if o.type == x86.X86_OP_IMM)
            if rva <= tgt < rva + size:
                return {"local"}
        for o in i.operands:
            if o.type == x86.X86_OP_MEM and o.mem.base == x86.X86_REG_RIP:
                tgt = i.address + i.size + o.mem.disp
        if tgt is None:
            return None
        names, delta = orig.names_at(tgt)
        if not names:
            return {"?"}
        return set(names) if not delta else {f"{n}+{delta:#x}" for n in names}
    return f


def same(a, b):
    """Equal instructions: same mnemonic and operands, and a shared target name. An original target without a
    public name (no name, or only a nearest name plus an offset) is accepted, as the judge does."""
    if a[0] != b[0] or a[1] != b[1]:
        return False
    if a[2] is None or b[2] is None:
        return a[2] is b[2]
    unnamed = "?" in b[2] or any("+0x" in n for n in b[2])
    return bool(a[2] & b[2]) or unnamed and "local" not in a[2]


def first_difference(a, b):
    if a is None or b is None:
        return "length: one side ends earlier"
    (ma, oa, ta), (mb, ob, tb) = a, b
    if ma == mb and oa == ob and ta is not None and tb is not None:
        return f"target: {short(sorted(ta)[0])} vs {short(sorted(tb)[0])}"
    if ma == mb and REG.sub("R", oa) == REG.sub("R", ob):
        return "registers differ (allocation)"
    if ma == mb and NUM.sub("N", oa) == NUM.sub("N", ob):
        return f"{'displacement' if '[' in oa else 'immediate'}: {ma} {oa} vs {ob}"
    if ma == mb:
        return f"operands: {ma} {oa} vs {ob}"
    return f"instruction: {ma} {oa} vs {mb} {ob}"


def bucket(diff, fkind):
    """Root-cause bucket of a first difference."""
    m = re.match(r"displacement: (call|jmp) qword ptr \[\w+ \+ (0x[0-9a-f]+)\] vs qword ptr \[\w+ \+ (0x[0-9a-f]+)\]", diff)
    if m:
        d = (int(m.group(3), 16) - int(m.group(2), 16)) // 8
        return "virtual call, slot +14 (UObject's 14 extra virtuals)" if d == 14 else f"virtual call, slot {d:+d} (another class's vtable)"
    m = re.match(r"displacement: mov r\w+, qword ptr \[r\w+ \+ (0x[0-9a-f]+)\] vs r\w+, qword ptr \[r\w+ \+ (0x[0-9a-f]+)\]", diff)
    if m and int(m.group(2), 16) - int(m.group(1), 16) == 0x70:
        return "vtable slot load, +14 (UObject's 14 extra virtuals)"
    if diff == "immediate: mov edx, 0x180 vs edx, 0x198":
        return "sizeof(UClass) 0x180 -> 0x198"
    if fkind == "Z_Construct_UClass" and re.match(r"displacement: \w+ dword ptr \[\w+ \+ 0xa0\], .* vs dword ptr \[\w+ \+ 0xb0\]", diff):
        return "UClass::ClassFlags at +0xb0 (ours +0xa0)"
    if re.match(r"(immediate: mov r9d|displacement: mov dword ptr \[rax \+ 8\]), 0x[0-9a-f]+ vs", diff):
        return "struct size differs (StaticStruct / TCppStructOps)"
    if diff.startswith("target:") and "CopyToEmpty" in diff:
        return "TArray::CopyToEmpty template (later UE TArray)"
    if diff.startswith("registers differ"):
        return "register allocation (follows another difference)"
    if diff.startswith("displacement:"):
        return "member offset or stack frame differs (other)"
    if diff.startswith("immediate:"):
        return "constant differs (other)"
    return "other first difference"


def reloc_bucket(rec):
    _, ours, theirs, delta, _ = rec["reloc"][0]
    if LOCAL_STATIC.search(ours) and (not theirs or delta):
        return "judge gap: function-local static (no public symbol in the PDB)"
    if "CopyToEmpty" in ours:
        return "TArray::CopyToEmpty template (later UE TArray)"
    if not theirs or delta:
        return "judge gap: target without a public name (static function or data)"
    return "relocation reaches another symbol (other)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("obj")
    ap.add_argument("original")
    ap.add_argument("match")
    ap.add_argument("--details", type=int, default=0)
    ap.add_argument("--json")
    ap.add_argument("--cache", default=str(REPO / "_re" / "cache"))
    a = ap.parse_args()
    obj = Coff(a.obj)
    orig = Original(a.original, a.cache)
    funcs = {n: (sec, off, size) for n, sec, off, size in obj.functions()}
    rows = json.load(open(a.match, encoding="utf-8"))
    buckets, firsts, examples, records = collections.Counter(), collections.Counter(), {}, []
    for r in rows:
        if r["state"] != "DIFF":
            continue
        fk = kind(r["name"])
        if "reloc" in r:
            b, diff = reloc_bucket(r), f"relocation: {short(r['reloc'][0][1])}"
        else:
            sec, off, size = funcs[r["name"]]
            osize = orig.sizes.get(r["rva"], size)
            ours = obj.data[obj.sections[sec]["raw"] + off: obj.sections[sec]["raw"] + off + size]
            x = disasm(ours, 0, our_targets(obj, sec, off, size))
            y = disasm(orig.read(r["rva"], osize), r["rva"], their_targets(orig, r["rva"], osize))
            k = 0
            while k < min(len(x), len(y)) and same(x[k], y[k]):
                k += 1
            diff = ("no instruction difference after naming targets" if k == len(x) == len(y) else
                    first_difference(x[k] if k < len(x) else None, y[k] if k < len(y) else None))
            b = bucket(diff, fk)
        buckets[b] += 1
        firsts[diff] += 1
        examples.setdefault(diff, r["name"])
        records.append({"name": r["name"], "kind": fk, "first": diff, "bucket": b})
    total = sum(buckets.values())
    print(f"{total} DIFFs by root cause:")
    for b, n in buckets.most_common():
        print(f"{n:6d}  {100 * n / max(total, 1):5.1f}%  {b}")
    if a.details:
        print(f"\nmost frequent first differences ({len(firsts)} distinct):")
        for d, n in firsts.most_common(a.details):
            print(f"{n:6d}  {d[:140]}\n          e.g. {examples[d][:110]}")
    if a.json:
        Path(a.json).write_text(json.dumps(records, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
