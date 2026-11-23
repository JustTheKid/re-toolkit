"""unit_skeleton.py <unit dir name> [--class <Class>] [--out <file>]: the port's skeleton for a compile unit - one block
per function of the unit's plan (build/loop/<unit>/plan.tsv) in address order: the ATLAS-ID header lines (ID, original
name, raw file) and the definition's signature rebuilt from the decorated name (dbghelp's UnDecorateSymbolName, the
Windows undecorator) with the parameters' names from the PDB's locals cache (_tools/pdb_locals.py), and an empty body
to fill from the decompile. Functions the unit only instantiates (templates, other classes' inline copies) are listed
at the end as a comment, not as blocks. Default output: build/loop/<unit>/skeleton.cpp (never the port's file).
2026-11-08 (P6, the fourteenth unit PrimalCharacter.cpp: 554 functions, the signatures alone ~550 lines).
Usage: python _tools/rebuild/unit_skeleton.py PrimalCharacter.cpp --class APrimalCharacter [--also SRV@<va>,...]"""
import argparse
import csv
import ctypes
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "_re" / "decompiled" / "server"
LOCALS = ROOT / "_re" / "cache" / "ShooterGameServer.locals.sqlite"

_dbghelp = ctypes.windll.dbghelp
_dbghelp.UnDecorateSymbolName.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32]


def undecorate(name, flags=0):
    buf = ctypes.create_string_buffer(4096)
    n = _dbghelp.UnDecorateSymbolName(name.encode("ascii"), buf, 4096, flags)
    return buf.value.decode("ascii", errors="replace") if n else name


def split_params(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "<(":
            depth += 1
        elif ch in ">)":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return [] if out == ["void"] else out


def cpp_type(t):
    """an undecorated type as source: no __ptr64 / class / struct / enum keywords, `X const &` -> `const X&`"""
    t = t.replace(" __ptr64", "").replace("__ptr64", "")
    t = re.sub(r"\b(class|struct|enum|union) ", "", t)
    t = re.sub(r"\bunsigned int\b", "uint32", t)
    t = re.sub(r"\bunsigned char\b", "uint8", t)
    t = re.sub(r"\bunsigned short\b", "uint16", t)
    t = re.sub(r"\bunsigned __int64\b", "uint64", t)
    t = re.sub(r"\b__int64\b", "int64", t)
    t = re.sub(r"\bint\b", "int32", t)
    t = re.sub(r"\bwchar_t\b", "TCHAR", t)
    t = re.sub(r",FDefaultAllocator>", ">", t)
    # the shared pointers' thread-safety mode as the PDB spells it (ESPMode::NotThreadSafe = 0): the default argument in
    # source, `TSharedPtr<X,0>` does not compile (2026-11-09, the twenty-sixth unit: TSharedPtr<FStepExecutor,0>)
    # (one nesting level inside too: TSharedPtr<TArray<uint8>,0>, 2026-11-10, the thirty-fifth unit)
    t = re.sub(r"\b(TSharedPtr|TSharedRef|TWeakPtr)<((?:[^<>]|<[^<>]*>)+?),0>", r"\1<\2>", t)
    # ESPMode::ThreadSafe = 1 written by name (2026-11-09, the twenty-eighth unit: TSharedPtr<IHttpResponse,1>)
    t = re.sub(r"\b(TSharedPtr|TSharedRef|TWeakPtr)<((?:[^<>]|<[^<>]*>)+?),1>", r"\1<\2, ESPMode::ThreadSafe>", t)
    t = re.sub(r"TEnumAsByte<(\w+)::Type>", r"TEnumAsByte<\1::Type>", t)
    m = re.match(r"^(.*?)\s+const\s*([&*]+)$", t)
    if m:
        t = "const " + m.group(1).strip() + m.group(2)
    t = re.sub(r"\s+([&*])", r"\1", t)
    t = re.sub(r"\s*>\s*>", "> >", t)
    return t.strip()


def signature(decorated, params):
    full = undecorate(decorated)
    if "`" in full:  # compiler-generated: vcall thunks, vector deleting destructors
        return None, full
    full = full.replace("__cdecl ", "")
    full = re.sub(r"^(?:(?:public|protected|private): )?(?:(?:virtual|static) )*", "", full)
    # the parameter list: the parenthesis that closes at the end (after an optional const / __ptr64)
    tail = re.search(r"\)\s*(const)?\s*(?:__ptr64)?\s*$", full)
    if not tail:
        return None, full
    const = tail.group(1)
    end = tail.start()
    depth, k = 0, end
    while k >= 0:
        if full[k] == ")":
            depth += 1
        elif full[k] == "(":
            depth -= 1
            if depth == 0:
                break
        k -= 1
    head_, args = full[:k], full[k + 1:end]
    # the name: the last space-separated part of the head outside template brackets
    depth, cut = 0, -1
    for q, ch in enumerate(head_):
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        elif ch == " " and depth == 0:
            cut = q
    ret, name = (head_[:cut], head_[cut + 1:]) if cut >= 0 else ("", head_)
    ret = cpp_type(ret.strip()) if ret.strip() else ""
    types = [cpp_type(a) for a in split_params(args)]
    out = []
    for i, ty in enumerate(types):
        nm = params[i] if i < len(params) else f"Param{i + 1}"
        out.append(f"{ty} {nm}")
    return f"{(ret + ' ') if ret else ''}{name.replace(' ', '')}({', '.join(out)}){' const' if const else ''}", full


REGPOS = {"rcx": 0, "ecx": 0, "cl": 0, "xmm0": 0, "rdx": 1, "edx": 1, "dl": 1, "xmm1": 1, "r8": 2, "r8d": 2, "r8b": 2,
          "xmm2": 2, "r9": 3, "r9d": 3, "r9b": 3, "xmm3": 3}


def param_names(db, va):
    """the parameters' names in call order: the PDB's records (by-value aggregates flagged 'param | aggregate' too),
    ordered by the register a parameter arrives in (its storage at +0x0), the stack ones after them in record order"""
    rows = list(db.execute("select ord, name, storage from locals where va=? and flags like 'param%' and name!='this' order by ord", (va,)))
    def key(r):
        m = re.search(r"([A-Z0-9]+)(?:\(part\+0x0\))? @\+0x0\.\.", r[2] or "")
        pos = REGPOS.get(m.group(1).lower()) if m else None
        return (pos if pos is not None else 4, r[0])
    return [r[1] for r in sorted(rows, key=key)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("unit")
    ap.add_argument("--class", dest="cls", action="append", default=[])
    ap.add_argument("--out")
    # plan rows that are the unit's own source though the class filter or the name test leaves them out (free functions,
    # an operator<< whose name has a "<"; 2026-11-09, the twenty-sixth unit: the grid structs' archive operators)
    ap.add_argument("--also", default="", help="comma-separated SRV@ IDs to write as blocks too")
    a = ap.parse_args()
    w = ROOT / "build" / "loop" / a.unit
    plan = list(csv.DictReader(open(w / "plan.tsv", encoding="utf-8"), delimiter="\t"))
    db = sqlite3.connect(str(LOCALS))
    also = {x.strip() for x in a.also.split(",") if x.strip()}
    own, other = [], []
    for r in plan:
        name = r["function"]
        cls = name.split("::")[0] if "::" in name else ""
        mine = (cls in a.cls) if a.cls else True
        generated = ("`" in name or "<" in name.split("(")[0]  # vcall and adjustor thunks, deleting destructors, template instances
                     or "`" in undecorate(r["decorated"]))
        (own if (mine and not generated) or r["id"] in also else other).append(r)
    lines = [f"// skeleton of {a.unit} (unit_skeleton.py): {len(own)} functions of {', '.join(a.cls) or 'the unit'}, address order"]
    for r in sorted(own, key=lambda r: int(r["id"][4:], 16)):
        va = int(r["id"][4:], 16)
        params = param_names(db, va)
        sig, full = signature(r["decorated"], params)
        raws = sorted(RAW.glob(f"*@{va:x}.c"))
        lines += ["", f"// ATLAS-ID: {r['id']}   orig: {r['function']}   status: REIMPL",
                  f"// raw: {raws[0].relative_to(ROOT).as_posix() if raws else '(no raw file)'}  ({r['bytes']} bytes)",
                  "// deviations: none"]
        lines += [sig if sig else f"// ?? {full}", "{", "}"]
    lines += ["", "// the unit's other functions (instances and inline copies; not this file's):"]
    lines += [f"//   {r['id']} {r['bytes']:>6} {r['function']}" for r in other]
    out = Path(a.out) if a.out else w / "skeleton.cpp"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"{out}: {len(own)} blocks, {len(other)} listed")


if __name__ == "__main__":
    main()
