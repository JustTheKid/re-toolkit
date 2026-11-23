"""A compile unit's bodies without a public name - lambda bodies, dynamic initializers, atexit destructors - through
the 4d loop (2026-11-08, from the scratch scripts of units 11-14). The work dir is build/loop/<Unit.cpp>/ (plan.tsv
from `unit_loop.py plan`, match.json from `unit_loop.py judge`).

  list     <Unit.cpp>            extra-vas.txt from the PDB locals cache: the unit module's S_*PROC32 records that are
                                 lambda bodies, dynamic initializers or atexit destructors (not the plan's publics, not
                                 funclets, not lambda constructors / destructors, not the STL's)
  export   <Unit.cpp>            the RAW decompiles by address (ghidra_find.py --address-file, --skip-existing; the
                                 Ghidra server project must be free)
  callers  <Unit.cpp>            each extra's callers in the original (E8 rel32 calls into its address) mapped to the
                                 plan's functions: a lambda's parent, where its ID header goes in the port
  verdicts <Unit.cpp> [--quiet]  extra-verdicts.json: lambda bodies by the judge's pairing in match.json (an
                                 ATLAS_STATIC_FNAME lambda pairs only through a matching parent: else "unpaired");
                                 initializers, destructors and file-static functions matched to our symbols by name
                                 and compared at the original's address (func_match.compare, then settle: a
                                 relocation to an unnamed target - a function-local static - is unchecked, MATCH~)
  ledger   <Unit.cpp> --system SYS-x add|reimpl
                                 add: RAW rows for the extras without a row (the raw file's sha256); reimpl: REIMPL +
                                 parity from extra-verdicts.json (MATCH / MATCH-L -> match, MATCH~ -> match~, else
                                 functional) with the port's path. Line-based: every other ledger line byte for byte.

Run with the venv Python, without -I (atlasre_common is not needed, func_match is imported from _tools/)."""
import argparse
import csv
import hashlib
import json
import re
import sqlite3
import struct
import subprocess
import sys
from collections import Counter
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "_tools"
LOOP = ROOT / "build" / "loop"
LEDGER = ROOT / "tracking" / "functions.csv"
RAW = ROOT / "_re" / "decompiled" / "server"
LOCALS = ROOT / "_re" / "cache" / "ShooterGameServer.locals.sqlite"
EXE = Path(r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe")
B = 0x140000000
PARITY = {"MATCH": "match", "MATCH~": "match~", "MATCH-L": "match"}
# a header's static (BadData, GlobalVectorConstants, the online subsystem's GameSessionName, WorldComposition.h's
# NAME_*) has a copy in every unit that includes the header: 11 to 184 of the PDB's modules for the ones seen in units
# 1-14, against 1-4 for a unit's own file statics (NAME_FirstPerson). From this many modules on, an initializer or
# destructor is a header copy, left out of extra-vas.txt (kept in extra-vas.all.txt); lambda bodies are always the unit's
HEADER_COPY_MODULES = 8


def plan_rows(w):
    return list(csv.DictReader(open(w / "plan.tsv", encoding="utf-8"), delimiter="\t"))


def extras(w):
    out = {}
    for line in (w / "extra-vas.txt").read_text(encoding="utf-8").splitlines():
        if line.strip():
            va, name = line.split("  ", 1)
            out[va] = name
    return out


def cmd_list(w):
    ids = {int(r["id"][4:], 16) for r in plan_rows(w)}
    c = sqlite3.connect(str(LOCALS))
    # the unit's module: the most common among the plan's functions (a template or inline copy can be recorded under
    # the module that emitted it first)
    mods = Counter(m[0] for m in (c.execute("select modi from funcs where va=?", (va,)).fetchone() for va in ids) if m)
    (modi, n), = mods.most_common(1)
    assert n * 2 > sum(mods.values()), mods
    out = []
    for va, name, _size in c.execute("select va,name,size from funcs where modi=? order by va", (modi,)):
        if va in ids or "`1'::dtor" in name or "catch$" in name or name.startswith("`std::"):
            continue
        if name.endswith("::operator()") or "dynamic initializer" in name or "dynamic atexit" in name:
            out.append(f"{va:x}  {name}")
        elif re.fullmatch(r"[A-Za-z_]\w*", name):
            # a file-static function: a plain name the publics lack (CustomCanvasWidget.cpp's DoGetCanvasByName,
            # FindWidgetByFNameRecursive; the sixteenth unit, 2026-11-08)
            out.append(f"{va:x}  {name}")
    (w / "extra-vas.all.txt").write_text("".join(o + "\n" for o in out), encoding="utf-8")
    def copies(name):
        return c.execute("select count(distinct modi) from funcs where name=?", (name,)).fetchone()[0]
    own = [o for o in out if o.endswith("::operator()") or copies(o.split("  ", 1)[1]) < HEADER_COPY_MODULES]
    (w / "extra-vas.txt").write_text("".join(o + "\n" for o in own), encoding="utf-8")
    print(f"module {modi}: {len(out)} bodies without a public name, {len(own)} the unit's own -> {w / 'extra-vas.txt'} "
          f"(all: extra-vas.all.txt)")
    for o in own:
        print(" ", o[:150])


def cmd_export(w):
    r = subprocess.run([sys.executable, "-I", str(TOOLS / "ghidra_find.py"), "--address-file", str(w / "extra-vas.txt"),
                        "--decompile", "--workers", "4", "--skip-existing", "--limit", "5000"], cwd=ROOT)
    sys.exit(r.returncode)


def text_section():
    data = EXE.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt = struct.unpack_from("<H", data, pe + 20)[0]
    sec = pe + 24 + opt
    for i in range(nsec):
        o = sec + 40 * i
        if data[o:o + 8].rstrip(b"\0") == b".text":
            _vsize, va, rsize, raw = struct.unpack_from("<IIII", data, o + 8)
            return va, data[raw:raw + rsize]
    raise SystemExit("no .text")


def cmd_callers(w):
    tva, code = text_section()
    plan = [(int(r["id"][4:], 16), int(r["bytes"]), r["function"]) for r in plan_rows(w)]
    ex = {int(v, 16): n for v, n in extras(w).items()}
    found = {v: [] for v in ex}
    for i in range(len(code) - 5):
        if code[i] != 0xE8:
            continue
        src = B + tva + i
        dst = src + 5 + struct.unpack_from("<i", code, i + 1)[0]
        if dst in found:
            found[dst].append(src)
    for v in sorted(ex):
        names = []
        for s in found[v]:
            f = next((n for (a, sz, n) in plan if a <= s < a + sz), None)
            names.append(f"{s:x} in {f}" if f else f"{s:x} (outside the plan)")
        print(f"{v:x} {ex[v][:48]:48} <- " + ("; ".join(names) if names else "no direct call"))


def cmd_verdicts(w, quiet):
    sys.path.insert(0, str(TOOLS))
    from func_match import Coff, Original, compare, settle  # noqa: E402
    mj = json.load(open(w / "match.json", encoding="utf-8"))
    by_rva = {}
    for r in mj:
        if r.get("rva") is not None:
            by_rva.setdefault(r["rva"] + B, []).append(r)
    unit = w.name
    obj = Coff(str(w / f"{unit}.obj"))
    orig = Original(str(EXE), str(ROOT / "_re" / "cache"))
    funcs = {f[0]: f[1:] for f in obj.functions()}
    # our lambda bodies the judge paired with nothing (their hashes are ours): candidates for the original's unpaired ones,
    # judged at the original's address - the one that matches is the lambda (2026-11-08, the eighteenth unit: eight
    # std::function and cached-name lambdas no hash paired)
    paired = {r["name"] for r in mj if r.get("rva") is not None}
    loose = [n for n in funcs if n.startswith("??R<lambda_") and n not in paired]
    out = {}
    for va_s, name in extras(w).items():
        va = int(va_s, 16)
        if name.endswith("::operator()"):
            rs = [r for r in by_rva.get(va, []) if r["name"].startswith("??R<lambda_")]
            state = rs[0]["state"] if rs else "unpaired"
            if not rs:
                hits = []
                for cand in loose:
                    st, _info = settle(*compare(obj, orig, cand, *funcs[cand], rva_override=va - B), {})
                    if st in PARITY:
                        hits.append((st, cand))
                if hits:
                    state = sorted(hits)[0][0]  # MATCH before MATCH-L / MATCH~
                    loose.remove(sorted(hits)[0][1])
        elif re.fullmatch(r"[A-Za-z_]\w*", name):  # a file-static function: ours by its decorated name's head
            ours = [n for n in funcs if n.startswith("?" + name + "@@")]
            if len(ours) != 1:
                state = f"ours? {ours[:2]}"
            else:
                state, _info = settle(*compare(obj, orig, ours[0], *funcs[ours[0]], rva_override=va - B), {})
        elif re.match(r"`<lambda_[0-9a-f]+>::operator\(\)'::`\d+'::`dynamic atexit destructor for '\w+''$", name):
            # a lambda's function-local static (2026-11-08, the nineteenth unit): our decorated name carries our lambda's
            # hash, so the static's destructors of every lambda of ours are candidates, judged at the original's address
            static = re.search(r"for '(\w+)''$", name).group(1)
            cands = [n for n in funcs if n.startswith("??__F" + static + "@") and "<lambda_" in n]
            state = "ours? none"
            for cand in cands:
                st, _info = settle(*compare(obj, orig, cand, *funcs[cand], rva_override=va - B), {})
                state = st
                if st in PARITY:
                    break
        else:
            m = re.match(r"`(?:(\w+)::)?(\w+)'::`(\d+)'::`dynamic atexit destructor for '(\w+)''", name)
            if m:  # a function-local static's destructor: a member function's (Class::Func) or a free function's
                cls, fn, _scope, static = m.groups()
                # the scope number as MSVC mangles it: one digit, or from 10 on hex letters A-P closed by '@'
                # (`?L@??`, `?CF@??` - 2026-11-10, the thirty-fifth unit's TickPendingSharedLog / SavePlayerData)
                pat = re.compile(r"^\?\?__F" + re.escape(static) + r"@\?(?:\d|[A-P]+@)\?\?" + re.escape(fn) + "@" +
                                 (re.escape(cls) + "@@" if cls else "@?Y"))
            else:  # a namespace-scope name's initializer / destructor (??__EMainMenu@ShooterGameInstanceState@@YAXXZ)
                m = re.match(r"(?:(\w+)::)?`dynamic (initializer|atexit destructor) for '(\w+)''", name)
                ns, what, static = m.groups()
                kind = "E" if what == "initializer" else "F"
                pat = re.compile(r"^\?\?__" + kind + re.escape(static) + "@" + (re.escape(ns) + "@" if ns else "") +
                                 "@YAXXZ$")
            ours = [n for n in funcs if pat.match(n)]
            if len(ours) != 1:
                state = f"ours? {ours[:2]}"
            else:
                state, _info = settle(*compare(obj, orig, ours[0], *funcs[ours[0]], rva_override=va - B), {})
        out[va_s] = state
        if not quiet or state not in PARITY:
            print("  ", va_s, state, name[:100])
    print("extras:", dict(Counter(out.values())))
    json.dump(out, open(w / "extra-verdicts.json", "w", encoding="utf-8"), indent=1)


def nl_of(s):
    return "\r\n" if "\r\n" in s else "\n"


def cmd_ledger(w, system, step):
    today = date.today().isoformat()
    unit = w.name
    src = "src/reimpl/ShooterGame/Source/ShooterGame/Private/" + unit
    text = LEDGER.read_bytes().decode("utf-8")
    nl = nl_of(text)
    if step == "add":
        lines = [l for l in text.split(nl) if l]
        have = {l.split(",", 1)[0] for l in lines[1:]}
        added = 0
        for va, name in extras(w).items():
            rid = f"SRV@{va}"
            if rid in have:
                continue
            files = list(RAW.glob(f"*@{va}.c"))
            assert len(files) == 1, (va, files)
            sha = hashlib.sha256(files[0].read_bytes()).hexdigest()
            kind = ("a lambda body without a public name" if name.endswith("::operator()") else
                    "the compiler's: no plan row")
            note = (f"\"ghidra 12.1.4 pdb-only; bin sha256 aac2f353dce7c0d4; exported {today} by _tools/ghidra_find.py "
                    f"--address ({kind}, by the PDB's private symbol; unit {unit})\"")
            assert "," not in name and '"' not in name, name
            lines.append(",".join([rid, "server", va, name, system, "RAW", "functional", sha, "", "", "", "", "",
                                   note, today]))
            added += 1
        head, body = lines[0], sorted(lines[1:], key=lambda l: l.split(",", 1)[0])
        LEDGER.write_bytes((nl.join([head] + body) + nl).encode("utf-8"))
        print("rows added:", added)
    else:
        verdicts = json.load(open(w / "extra-verdicts.json", encoding="utf-8"))
        # a REIMPL row needs its `// ATLAS-ID:` line in the port (ledger_check's rule): a lambda written inline in its
        # host gets that line in the host's chunk, before the `{` (2026-11-08, the seventeenth unit's RemoveAll
        # predicate had none); rows without it stay as they are and are listed
        port = (ROOT / src).read_text(encoding="utf-8") if (ROOT / src).exists() else ""
        missing = sorted(va for va in verdicts if f"// ATLAS-ID: SRV@{va}" not in port)
        for va in missing:
            print(f"  no '// ATLAS-ID: SRV@{va}' line in {src}: the row stays (write the line in its host's chunk)")
        lines = text.split(nl)
        changed = 0
        for i, l in enumerate(lines):
            rid = l.split(",", 1)[0]
            if rid.startswith("SRV@") and rid[4:] in verdicts and rid[4:] not in missing:
                f = l.split(",")  # no commas before the notes column
                f[5], f[6], f[8] = "REIMPL", PARITY.get(verdicts[rid[4:]], "functional"), src
                f[-1] = today
                lines[i] = ",".join(f)
                changed += 1
        LEDGER.write_bytes(nl.join(lines).encode("utf-8"))
        print("rows to REIMPL:", changed)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("cmd", choices=["list", "export", "callers", "verdicts", "ledger"])
    ap.add_argument("unit", help="the work dir's name, e.g. ShooterCheatManager.cpp")
    ap.add_argument("step", nargs="?", choices=["add", "reimpl"], help="ledger: add or reimpl")
    ap.add_argument("--system", help="ledger add: the rows' SYS- id")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()
    w = LOOP / a.unit
    if a.cmd == "list":
        cmd_list(w)
    elif a.cmd == "export":
        cmd_export(w)
    elif a.cmd == "callers":
        cmd_callers(w)
    elif a.cmd == "verdicts":
        cmd_verdicts(w, a.quiet)
    else:
        if not a.step or (a.step == "add" and not (a.system or "").startswith("SYS-")):
            ap.error("ledger needs add --system SYS-... or reimpl")
        cmd_ledger(w, a.system, a.step)


if __name__ == "__main__":
    main()
