"""The phase 4d loop as one command (P4, 2026-10-31): one original compile unit of the server through its steps.

ADR-0006's work unit is one original .cpp of the game (503 units); per unit: the plan (its functions from the PDB,
their reach rank, their ledger state), the exports (decompiles with PDB locals, RAW rows), the headers its classes
need (gen_headers.py), the port (ours, by hand: the draft is the one step this tool does not do), the mini unit
(recompile_unit.py: our source with ATLAS's own command line), the judge (func_match.py, judge_causes.py), the
ledger (REIMPL rows, parity from the verdicts) and a stub in the system doc.

usage: python _tools/rebuild/unit_loop.py <unit> <step> [--system SYS-...] [--source <our .cpp>] [--obj <.obj>]
                                          [--map A=B ...] [--known <types>] [--workers 4] [--theirs <exe>]
  unit   the original unit: a regex on the PDB's object paths (PrimalRaft.cpp, Module.Engine.16_of_26.cpp, ...);
         exactly one object must match
  step   plan | export | headers | build | judge | ledger | doc | all
    plan     build/loop/<unit>/plan.tsv: every function of the unit (the PDB's publics flagged as functions whose
             section contribution lies in it), its size, its rank in tracking/reach.csv, its ledger status, whether
             its raw decompile exists, our verdict if judged; a summary line
    export   decompiles with locals for the functions without a raw file (ghidra_find.py --address-file ...
             --decompile --workers N --skip-existing) into _re/decompiled/server/, then RAW rows in the ledger
             (--system required for new rows)
    headers  build/loop/<unit>/layouts.h from gen_headers.py for the classes of the unit's functions (--known as
             gen_headers takes it)
    build    recompile_unit.py <pe> <unit> --out build/loop/<unit> --source <our .cpp> [--map ...]: the object
    judge    func_match.py on the object (--obj, else the one build left) -> match.json, judge_causes.py ->
             causes.json; the verdict counts
    ledger   the unit's rows: REIMPL where our object defines the function, parity match for MATCH / MATCH-L,
             reimpl_path = --source, updated today; only changed rows are rewritten
    doc      a stub section in docs/systems/<system>.md (the summary and the reached functions with their
             verdicts); replaced when it exists
    all      plan, export, headers; then build, judge, ledger, doc when --source is given
Runs without -I (it imports its siblings and _tools/).
"""
import argparse
import csv
import datetime
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(HERE))
PY = sys.executable
THEIRS = Path(r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe")
BASE = 0x140000000
LEDGER = ROOT / "tracking" / "functions.csv"
REACH = ROOT / "tracking" / "reach.csv"
RAW_DIR = ROOT / "_re" / "decompiled" / "server"
KNOWN_TYPES = ROOT / "build" / "loop" / "common" / "engine-types.txt"  # engine_types.py: the names our engine declares
COLUMNS = "id,binary,va,symbol,system,status,parity,raw_sha256,reimpl_path,toggle,rep,evidence,bug,notes,updated".split(",")
TODAY = datetime.date.today().isoformat()


def log(*a):
    print(datetime.datetime.now().strftime("%H:%M:%S"), *a, flush=True)


# ---------------------------------------------------------------- the unit and its functions
def resolve_unit(theirs, unit):
    from reach_record import pdb_modules
    rx = re.compile(unit)
    hits = sorted({p for p in pdb_modules(theirs).values() if rx.search(p)})
    if len(hits) != 1:
        sys.exit(f"{len(hits)} objects match {unit!r}: {hits[:6]}")
    return hits[0]


def unit_functions(theirs, module):
    from reach_record import list_functions
    return list_functions(theirs, re.escape(module) + "$")


def undecorator(theirs):
    from func_match import Original
    o = Original(str(theirs), str(ROOT / "_re" / "cache"))
    return o.undecorate


def reach_ranks():
    if not REACH.exists():
        return {}
    with open(REACH, newline="", encoding="utf-8") as f:
        return {int(r["rva"], 16): int(r["seq"]) for r in csv.DictReader(f)}


def raw_file(va, symbol):
    """The raw decompile's path for a function (ghidra_find.py's naming: Class__Func@va.c, unsafe characters '_')."""
    for p in RAW_DIR.glob(f"*@{va:x}.c"):
        return p
    return None


# ---------------------------------------------------------------- the ledger (line-based: untouched rows stay byte-identical)
def read_ledger():
    text = LEDGER.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(nl)
    rows = {}
    for i, line in enumerate(lines[1:], 1):
        if not line:
            continue
        fields = next(csv.reader([line]))
        if len(fields) == len(COLUMNS):
            rows[fields[0]] = (i, fields)
    return lines, nl, rows


def format_row(fields):
    out = []
    for k, f in enumerate(fields):
        if k == 13 or "," in f or '"' in f:
            out.append('"' + f.replace('"', '""') + '"')
        else:
            out.append(f)
    return ",".join(out)


def write_ledger(lines, nl, changed, added):
    """changed: {line index: fields}; added: [fields] inserted in ID order."""
    for i, fields in changed.items():
        lines[i] = format_row(fields)
    body = [l for l in lines[1:] if l]
    body += [format_row(f) for f in added]
    body.sort(key=lambda l: l.split(",", 1)[0])
    LEDGER.write_bytes((nl.join([lines[0]] + body) + nl).encode("utf-8"))


def load_verdicts(mj):
    """{decorated name: state} and {original rva: state} in one dict (the names are strings, the rvas ints): a
    function the original folded under another first name is still found by where the judge found it."""
    verdicts = {}
    if mj.exists():
        m = json.load(open(mj, encoding="utf-8"))
        for r in (m.get("functions", m) if isinstance(m, dict) else m):
            verdicts[r["name"]] = r["state"]
            if r.get("rva"):
                verdicts[int(r["rva"])] = r["state"]
    return verdicts


# ---------------------------------------------------------------- steps
def step_plan(a, ctx):
    funcs, und, ranks, (lines, nl, rows) = ctx["funcs"], ctx["und"], reach_ranks(), ctx["ledger"]
    verdicts = load_verdicts(ctx["work"] / "match.json")
    out = ctx["work"] / "plan.tsv"
    table = []
    for rva in sorted(funcs):
        name, _mod, size = funcs[rva]
        va = BASE + rva
        rid = f"SRV@{va:x}"
        status = rows[rid][1][5] if rid in rows else "UNTOUCHED"
        table.append((rid, und(name), size, ranks.get(rva, ""), status, "yes" if raw_file(va, name) else "", verdicts.get(name) or verdicts.get(rva, ""), name))
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["id", "function", "bytes", "reach", "status", "raw", "verdict", "decorated"])
        w.writerows(table)
    n = len(table)
    reached = [t for t in table if t[3] != ""]
    st = Counter(t[4] for t in table)
    summary = (f"{ctx['short']}: {n} functions, {sum(t[2] for t in table):,} bytes; reached {len(reached)} "
               f"({sum(t[2] for t in reached):,} bytes); ledger {dict(st)}; raw {sum(1 for t in table if t[5])}; "
               f"judged {sum(1 for t in table if t[6])} -> {out.relative_to(ROOT)}")
    log(summary)
    ctx["summary"] = summary
    ctx["table"] = table
    return table


def step_export(a, ctx):
    funcs, (lines, nl, rows) = ctx["funcs"], ctx["ledger"]
    todo = [rva for rva in sorted(funcs) if raw_file(BASE + rva, funcs[rva][0]) is None]
    if todo:
        vas = ctx["work"] / "export-vas.txt"
        vas.write_text("".join(f"{BASE + rva:x}\n" for rva in todo), encoding="utf-8")
        cmd = [PY, "-I", str(TOOLS / "ghidra_find.py"), "--address-file", str(vas), "--decompile", "--workers", str(a.workers),
               "--skip-existing", "--limit", str(len(todo) + 10), "--out", str(RAW_DIR)]
        log(f"export: {len(todo)} functions to decompile ({a.workers} workers)")
        r = subprocess.run(cmd, cwd=ROOT)
        if r.returncode != 0:
            sys.exit("the export failed")
    changed, added = {}, []
    for rva in sorted(funcs):
        name, _mod, size = funcs[rva]
        va = BASE + rva
        p = raw_file(va, name)
        if p is None:
            continue
        rid = f"SRV@{va:x}"
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        if rid in rows:
            i, f = rows[rid]
            if f[5] == "UNTOUCHED":
                f = list(f)
                f[5], f[7], f[14] = "RAW", sha, TODAY
                changed[i] = f
            continue
        if not a.system:
            sys.exit(f"--system needed for the new row {rid}")
        und = ctx["und"](name)
        note = (f"ghidra 12.1.4 pdb-only; bin sha256 aac2f353dce7c0d4; exported {TODAY} by _tools/ghidra_find.py "
                f"(unit_loop.py export, unit {ctx['short']})")
        added.append([rid, "server", f"{va:x}", und, a.system, "RAW", "functional", sha, "", "", "", "", "", note, TODAY])
    if changed or added:
        write_ledger(lines, nl, changed, added)
        ctx["ledger"] = read_ledger()
    log(f"ledger: {len(added)} RAW rows added, {len(changed)} rows to RAW")


def step_headers(a, ctx):
    classes = sorted({ctx["und"](n).rsplit("::", 1)[0] for n, _m, _s in ctx["funcs"].values() if "::" in ctx["und"](n)})
    classes = [c for c in classes if re.match(r"^[AUFIS][A-Z]\w*$", c)]
    if not classes:
        log("headers: no classes among the unit's functions")
        return
    out = ctx["work"] / "layouts.h"
    cmd = [PY, "-I", str(TOOLS / "gen_headers.py"), str(a.theirs), *classes, "--out", str(out), "--declare"]
    known = a.known or (str(KNOWN_TYPES) if KNOWN_TYPES.exists() else None)
    if known:
        cmd += ["--known", known]
    log(f"headers: {len(classes)} classes -> {out.relative_to(ROOT)}: {classes[:8]}{' ...' if len(classes) > 8 else ''}")
    r = subprocess.run(cmd, cwd=ROOT)
    if r.returncode != 0:
        log("gen_headers.py failed (see above); the layout header is the port's first task")


def unit_objects(work):
    """the unit's objects, oldest first - not the probes' (unit_probe.py writes probe*.obj beside them, 2026-11-08: the
    newest .obj would otherwise be judged as the unit)"""
    return sorted((p for p in work.glob("*.obj") if not p.name.startswith("probe")), key=lambda p: p.stat().st_mtime)


def step_build(a, ctx):
    if not a.source:
        sys.exit("build needs --source <our .cpp>")
    cmd = [PY, "-I", str(TOOLS / "recompile_unit.py"), str(a.theirs), re.escape(ctx["module"]) + "$", "--out", str(ctx["work"]),
           "--source", a.source]
    for m in a.map:
        cmd += ["--map", m]
    if not a.no_pch:
        cmd += ["--pch"]  # through the unit's precompiled header, as ATLAS compiled it (2026-10-31)
    log("build:", Path(a.source).name, "with", ctx["short"] + "'s command line" + (" (no PCH)" if a.no_pch else ", through its PCH"))
    r = subprocess.run(cmd, cwd=ROOT)
    objs = unit_objects(ctx["work"])
    if r.returncode != 0 or not objs:
        sys.exit("the build failed")
    ctx["obj"] = objs[-1]
    log("object:", objs[-1].relative_to(ROOT))


def step_judge(a, ctx):
    obj = Path(a.obj) if a.obj else ctx.get("obj")
    if obj is None:
        objs = unit_objects(ctx["work"])
        obj = objs[-1] if objs else None
    if obj is None:
        sys.exit("judge needs an object: --obj, or build first")
    mj = ctx["work"] / "match.json"
    r = subprocess.run([PY, "-I", str(TOOLS / "func_match.py"), str(obj), str(a.theirs), "--json", str(mj)], cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    (ctx["work"] / "match.out").write_text(r.stdout + r.stderr, encoding="utf-8")
    if not mj.exists():
        sys.exit("func_match.py wrote no match.json:\n" + r.stdout[-2000:] + r.stderr[-2000:])
    m = json.load(open(mj, encoding="utf-8"))
    rows = m.get("functions", m) if isinstance(m, dict) else m
    unit_names = {n for n, _m, _s in ctx["funcs"].values()}
    c_all = Counter(r["state"] for r in rows)
    # ours is the unit's by its name, or by the original address the judge found it at (a function the original
    # folded under another first name, or one named after a lambda whose hash is ours)
    c_unit = Counter(r["state"] for r in rows if r["name"] in unit_names or r.get("rva") in ctx["funcs"])
    log(f"judge: {len(rows)} functions of ours: {dict(c_all)}; of them in {ctx['short']}: {sum(c_unit.values())} {dict(c_unit)}")
    cj = ctx["work"] / "causes.json"
    r = subprocess.run([PY, "-I", str(TOOLS / "judge_causes.py"), str(obj), str(a.theirs), str(mj), "--json", str(cj)], cwd=ROOT,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    (ctx["work"] / "causes.out").write_text(r.stdout + r.stderr, encoding="utf-8")
    log("causes:", (r.stdout.strip().splitlines() or ["(none)"])[-1][:160])
    ctx["verdicts"] = load_verdicts(mj)


def step_ledger(a, ctx):
    verdicts = ctx.get("verdicts")
    if verdicts is None:
        if not (ctx["work"] / "match.json").exists():
            sys.exit("ledger needs a judge run (match.json)")
        verdicts = load_verdicts(ctx["work"] / "match.json")
    lines, nl, rows = ctx["ledger"]
    changed = {}
    src = Path(a.source).relative_to(ROOT).as_posix() if a.source and Path(a.source).is_absolute() else (a.source or "")
    # where each ID's "// ATLAS-ID:" line lives: a hand-written function in the unit's source or in a game header (an
    # inline body); the compiler's functions get a generated block at the end of the source (ledger_check.py wants the
    # line in the row's reimpl_path)
    id_rx = re.compile(r"// ATLAS-ID: (SRV@[0-9a-f]+)")
    id_home = {}
    for h in sorted((ROOT / "src" / "reimpl" / "ShooterGame" / "Source").rglob("*.h")):
        for m in id_rx.finditer(h.read_text(encoding="utf-8", errors="replace")):
            id_home.setdefault(m.group(1), h.relative_to(ROOT).as_posix())
    src_text = Path(a.source).read_text(encoding="utf-8") if a.source else ""
    head = "// ---- the compiler's functions of this unit (unit_loop.py ledger): emitted for the headers, judged with the rest ----"
    tail = "// ---- end of the compiler's functions ----"
    # the hand-written text only: a block from an earlier run is regenerated whole, not appended to (2026-11-04: a
    # re-run after a re-judge listed only the new functions and dropped the others' ID lines)
    hand_text = src_text[:src_text.index(head)] + src_text[src_text.index(tail) + len(tail):] if head in src_text else src_text
    in_src = set(id_rx.findall(hand_text))
    generated = []
    for rva in sorted(ctx["funcs"]):
        name = ctx["funcs"][rva][0]
        verdict = verdicts.get(name) or verdicts.get(rva)
        if verdict is None:
            continue
        rid = f"SRV@{BASE + rva:x}"
        if rid not in rows:
            log(f"  {rid} {ctx['und'](name)}: no ledger row (export first)")
            continue
        i, f = rows[rid]
        f = list(f)
        if f[8] and not f[8].startswith("src/reimpl/ShooterGame/"):
            # a function another port owns (an engine one the linker folded with one of ours): its row stays
            log(f"  {rid} {ctx['und'](name)}: kept, reimplemented in {f[8]} ({f[4]})")
            continue
        parity = "match" if verdict in ("MATCH", "MATCH-L") else ("match~" if verdict == "MATCH~" else "")
        new = list(f)
        if new[5] in ("UNTOUCHED", "RAW", "ANNOTATED", "UNDERSTOOD"):
            new[5] = "REIMPL"
        new[6] = parity or new[6]
        if src:
            new[8] = id_home.get(rid, src)
            if rid not in in_src and rid not in id_home:
                generated.append(f"// ATLAS-ID: {rid}   orig: {ctx['und'](name)}   status: REIMPL   judge: {verdict}")
        if new != f:
            new[14] = TODAY
            changed[i] = new
    if changed:
        write_ledger(lines, nl, changed, [])
        ctx["ledger"] = read_ledger()
    if a.source and generated:
        block = "\n".join([head, "// (constructors, destructors and template instantiations the layouts imply; the names are the PDB's)"]
                          + generated + [tail]) + "\n"
        if head in src_text:
            src_text = src_text[:src_text.index(head)] + block + src_text[src_text.index(tail) + len(tail) + 1:]
        else:
            src_text = src_text.rstrip("\n") + "\n\n" + block
        Path(a.source).write_text(src_text, encoding="utf-8")
        log(f"source: {len(generated)} compiler-emitted functions listed at the end of {Path(a.source).name}")
    log(f"ledger: {len(changed)} rows updated (REIMPL / parity)")


def step_doc(a, ctx):
    if not a.system:
        sys.exit("doc needs --system")
    doc = ROOT / "docs" / "systems" / f"{a.system}.md"
    if not doc.exists():
        sys.exit(f"no {doc}")
    text = doc.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in text else "\n"
    heading = f"## Unit `{ctx['short']}` (phase 4d loop)"
    table = ctx.get("table") or step_plan(a, ctx)
    reached = [t for t in table if t[3] != ""]
    reached.sort(key=lambda t: t[3])
    lines = [heading + f" — {TODAY}", "",
             f"The server's `{ctx['short']}` unit: {len(table)} functions, {sum(t[2] for t in table):,} bytes; "
             f"{len(reached)} reached in the recorded sessions ({sum(t[2] for t in reached):,} bytes), the port's order. "
             f"The whole list: `python _tools/rebuild/unit_loop.py {ctx['short']} plan` (build/loop/{ctx['short']}/plan.tsv).", "",
             "| reach | ID | function | bytes | status | verdict |", "|---|---|---|---|---|---|"]
    for t in reached[:80]:
        lines.append(f"| {t[3]} | {t[0]} | `{t[1]}` | {t[2]} | {t[4]} | {t[6]} |")
    if len(reached) > 80:
        lines.append(f"| … | | {len(reached) - 80} more reached functions in plan.tsv | | | |")
    block = nl.join(lines) + nl
    if heading in text:  # replace the section (up to the next heading or the end)
        a0 = text.index(heading)
        b0 = text.find(nl + "## ", a0 + len(heading))
        text = text[:a0] + block + (text[b0 + len(nl):] if b0 >= 0 else "")
        doc.write_bytes(text.encode("utf-8"))
        log(f"doc: section replaced in {doc.relative_to(ROOT)}")
        return
    doc.write_bytes((text.rstrip(nl) + nl + nl + block).encode("utf-8"))
    log(f"doc: section added to {doc.relative_to(ROOT)}")


STEPS = {"plan": step_plan, "export": step_export, "headers": step_headers, "build": step_build, "judge": step_judge,
         "ledger": step_ledger, "doc": step_doc}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("unit")
    ap.add_argument("step", choices=list(STEPS) + ["all"])
    ap.add_argument("--system")
    ap.add_argument("--source")
    ap.add_argument("--obj")
    ap.add_argument("--map", action="append", default=[])
    ap.add_argument("--known")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--theirs", default=str(THEIRS))
    ap.add_argument("--no-pch", action="store_true", help="build without the unit's precompiled header (the pre-2026-10-31 way)")
    a = ap.parse_args()
    module = resolve_unit(a.theirs, a.unit)
    short = Path(module).name.replace(".obj", "")
    work = ROOT / "build" / "loop" / short
    work.mkdir(parents=True, exist_ok=True)
    log(f"unit {short}: {module}")
    ctx = {"module": module, "short": short, "work": work, "funcs": unit_functions(a.theirs, module),
           "und": undecorator(a.theirs), "ledger": read_ledger()}
    steps = [a.step] if a.step != "all" else (["plan", "export", "headers"] + (["build", "judge", "ledger", "doc"] if a.source else []))
    for s in steps:
        STEPS[s](a, ctx)


if __name__ == "__main__":
    main()
