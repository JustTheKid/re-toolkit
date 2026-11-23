"""The C++ ABI (layouts and vtables) of two binaries' types, compared: ATLAS's original against ours. Ours comes
from a probe DLL linked from one of our objects compiled with ATLAS's command line (recompile_unit.py), so its
types are in the server configuration (WITH_EDITOR=0 ...). Each side is dumped in its own dbghelp session
(pdb_struct.Pdb), then the dumps are compared. A differing class is a root when its base classes are identical:
the change is its own, the port list; otherwise it inherits a difference.

Usage:
  python -I _tools/abi_diff.py probe <our .obj> --out <dir>      link <dir>/probe.dll + probe.pdb with VS2013's
                                                                   linker (unresolved externals allowed)
  python -I _tools/abi_diff.py dump <pe> --out <json> [--names <json dump or text file>] [--regex R]
  python -I _tools/abi_diff.py compare <original.json> <ours.json> [--regex R] [--report <md>] [--limit N]
  Type names are dbghelp's (e.g. "UObject", "TArray<int,FDefaultAllocator>"). A dump holds per type: size,
  members (name, offset, size, type, bit, base) and member functions (name, vtable offset of virtuals).
2026-10-24: phase 4b step 1.11 (C++ ABI parity, ADR-0006 point 4).
"""
import argparse
import ctypes
import json
import re
import subprocess
import sys
from collections import Counter
from ctypes import wintypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pdb_struct import IMAGE_BASE, SYMBOL_INFOW, Pdb  # noqa: E402

TAG_UDT = 11
VCVARS = r"C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat"


def udt_names(pdb):
    """Every user-defined type (class, struct, union) the PDB knows, by dbghelp name."""
    names = set()
    cb_type = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p)

    def on_type(p, _size, _ctx):
        info = ctypes.cast(p, ctypes.POINTER(SYMBOL_INFOW)).contents
        if info.Tag == TAG_UDT:  # NameLen counts the terminating NUL here
            names.add(ctypes.wstring_at(ctypes.addressof(info) + SYMBOL_INFOW.Name.offset, info.NameLen).rstrip("\0"))
        return True

    callback = cb_type(on_type)
    pdb.type_id("UObject")  # dbghelp loads symbols lazily (deferred loads); a lookup loads them
    pdb.dh.SymEnumTypesW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, cb_type, ctypes.c_void_p]
    if not pdb.dh.SymEnumTypesW(pdb.proc, IMAGE_BASE, callback, None):
        sys.exit(f"SymEnumTypesW failed: {ctypes.GetLastError()}")
    return sorted(n for n in names if n)


def dump_type(pdb, name):
    members = pdb.members(name)
    if members is None:
        return None
    methods = pdb.methods(name) or []
    return {"size": pdb.size(name), "members": members, "methods": methods}


def cmd_probe(a):
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    obj = Path(a.obj).resolve()
    cmd = (f'"{VCVARS}" amd64 >nul && link /nologo /DLL /NOENTRY /MACHINE:X64 /DEBUG /FORCE:UNRESOLVED '
           f'/OPT:NOREF /OPT:NOICF /OUT:"{out / "probe.dll"}" /PDB:"{out / "probe.pdb"}" "{obj}"')
    with open(out / "link.log", "w", encoding="utf-8", errors="replace") as log:
        r = subprocess.run(f'cmd /s /c "{cmd}"', stdout=log, stderr=subprocess.STDOUT, shell=False)
    ok = (out / "probe.pdb").exists()
    print(f"link exit {r.returncode}; probe.pdb {'written' if ok else 'missing'} (log: {out / 'link.log'})")
    sys.exit(0 if ok else 1)


def cmd_dump(a):
    pdb = Pdb(a.pe)
    if a.names:
        text = Path(a.names).read_text(encoding="utf-8")
        names = sorted(json.loads(text)) if text.lstrip().startswith("{") else text.split("\n")
    else:
        names = udt_names(pdb)
    rx = re.compile(a.regex) if a.regex else None
    out = {}
    for n in names:
        n = n.strip()
        if not n or rx and not rx.search(n):
            continue
        d = dump_type(pdb, n)
        if d is not None:
            out[n] = d
    Path(a.out).write_text(json.dumps(out), encoding="utf-8")
    print(f"{a.pe}: {len(out)} types dumped to {a.out}")


def key_methods(methods):
    """{(name, k): vtable offset} of the virtuals (k counts overloads in declaration order). dbghelp gives
    non-virtual functions offset 0 too, so slot 0 (the destructor in both) is left out; names lose their
    "Class::" (a PDB names a function it saw defined with it, one it saw only declared without)."""
    seen, out = Counter(), {}
    for name, voff in methods:
        if not voff:
            continue
        name = name.rsplit("::", 1)[-1]
        out[(name, seen[name])] = voff
        seen[name] += 1
    return out


def hx(v):
    return "?" if v is None else f"0x{v:x}"


def primary_base(t):
    bases = [m for m in t["members"] if m["base"] and m["offset"] == 0]
    return bases[0]["name"] if bases else None


def vtable_end(dump, name, memo):
    """End of a class's vtable (bytes): its highest virtual slot + 8, or its primary base's."""
    if name not in memo:
        memo[name] = 0
        t = dump.get(name)
        if t:
            own = list(key_methods(t["methods"]).values())
            base = primary_base(t)
            memo[name] = max([v + 8 for v in own] + [vtable_end(dump, base, memo) if base else 0])
    return memo[name]


def diff_type(t, o, shift_size=0, shift_vtable=0):
    """Differences of one type, theirs t against ours o, as edits: [(own, line)]. Members and virtuals only one
    side has, members whose size or bit position differs, and change points: the first matched member (or virtual)
    whose offset shift differs from the one before it (the first one is compared with the shift the primary base
    explains: shift_size, shift_vtable). own is False only for a size difference the base explains. Empty if the
    ABI agrees."""
    lines = []
    if t["size"] != o["size"]:
        own = t["size"] is None or o["size"] is None or t["size"] - o["size"] != shift_size
        lines.append((own, f"size {hx(t['size'])} (ours {hx(o['size'])})"))
    tb = [(m["name"], m["offset"]) for m in t["members"] if m["base"]]
    ob = [(m["name"], m["offset"]) for m in o["members"] if m["base"]]
    if tb != ob:
        lines.append((True, f"bases {tb} (ours {ob})"))
    tm = [m for m in t["members"] if not m["base"]]
    om = {m["name"]: m for m in o["members"] if not m["base"]}
    names_t = {m["name"] for m in tm}
    prev = shift_size
    for m in sorted(tm, key=lambda m: (m["offset"], m["bit"] or 0)):
        mine = om.get(m["name"])
        if mine is None:
            lines.append((True, f"+{hx(m['offset'])} {m['name']} ({m['type']}, {hx(m['size'])}): not in ours"))
            continue
        if mine["size"] != m["size"] or mine["bit"] != m["bit"] and mine["offset"] == m["offset"]:
            lines.append((True, f"{m['name']} size {hx(m['size'])} bit {m['bit']} (ours size {hx(mine['size'])} "
                                f"bit {mine['bit']})"))
        d = m["offset"] - mine["offset"]
        if d != prev:
            lines.append((True, f"from {m['name']} on: theirs +{hx(m['offset'])}, ours +{hx(mine['offset'])} "
                                f"(shift {d:+#x}, before {prev:+#x})"))
            prev = d
    for m in o["members"]:
        if not m["base"] and m["name"] not in names_t:
            lines.append((True, f"ours only: +{hx(m['offset'])} {m['name']} ({m['type']})"))
    tv, ov = key_methods(t["methods"]), key_methods(o["methods"])
    prev = shift_vtable
    for k, voff in sorted(tv.items(), key=lambda kv: kv[1]):
        if k not in ov:
            lines.append((True, f"virtual {k[0]} at +0x{voff:x}: not in ours"))
            continue
        d = voff - ov[k]
        if d != prev:
            lines.append((True, f"from virtual {k[0]} on: theirs +0x{voff:x}, ours +0x{ov[k]:x} "
                                f"(shift {d // 8:+d} slots, before {prev // 8:+d})"))
            prev = d
    for k, voff in ov.items():
        if k not in tv:
            lines.append((True, f"ours only: virtual {k[0]} at +0x{voff:x}"))
    return lines


def cmd_compare(a):
    theirs = json.loads(Path(a.original).read_text(encoding="utf-8"))
    ours = json.loads(Path(a.ours).read_text(encoding="utf-8"))
    rx = re.compile(a.regex) if a.regex else None
    both = sorted(n for n in theirs if n in ours and (not rx or rx.search(n)))
    tmemo, omemo = {}, {}
    diffs = {}
    for n in both:
        base = primary_base(theirs[n])
        ss = sv = 0
        if base and base in theirs and base in ours and theirs[base]["size"] is not None and ours[base]["size"]:
            ss = theirs[base]["size"] - ours[base]["size"]
            sv = vtable_end(theirs, base, tmemo) - vtable_end(ours, base, omemo)
        diffs[n] = diff_type(theirs[n], ours[n], ss, sv)
    differing = {n for n, d in diffs.items() if d}
    roots = sorted(n for n in differing if any(own for own, _ in diffs[n]))
    inherit = sorted(n for n in differing if n not in roots)
    lines = [f"# ABI comparison: {Path(a.original).name} vs {Path(a.ours).name}", "",
             f"{len(both)} types in both; {len(both) - len(differing)} identical, {len(differing)} differ: "
             f"{len(roots)} with differences of their own (the port list), {len(inherit)} only shifted by a "
             f"base.", "", "## Own differences (the port list)"]
    for n in roots:
        own = [d for o, d in diffs[n] if o]
        lines.append(f"- **{n}** ({len(own)} own, {len(diffs[n]) - len(own)} inherited)")
        for d in own[:a.limit]:
            lines.append(f"  - {d}")
        if len(own) > a.limit:
            lines.append(f"  - ... {len(own) - a.limit} more")
    lines += ["", "## Only shifted by a base", ""]
    for n in inherit:
        lines.append(f"- {n} (base {primary_base(theirs[n])}): {len(diffs[n])} shifted entries")
    text = "\n".join(lines) + "\n"
    if a.report:
        Path(a.report).write_text(text, encoding="utf-8")
    print(text[:6000] if not a.report else "\n".join(lines[:4 + min(60, len(lines))]))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("probe")
    p.add_argument("obj")
    p.add_argument("--out", required=True)
    p = sub.add_parser("dump")
    p.add_argument("pe")
    p.add_argument("--out", required=True)
    p.add_argument("--names")
    p.add_argument("--regex")
    p = sub.add_parser("compare")
    p.add_argument("original")
    p.add_argument("ours")
    p.add_argument("--regex")
    p.add_argument("--report")
    p.add_argument("--limit", type=int, default=40)
    a = ap.parse_args()
    {"probe": cmd_probe, "dump": cmd_dump, "compare": cmd_compare}[a.cmd](a)


if __name__ == "__main__":
    main()
