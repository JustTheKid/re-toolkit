"""The reach set (P3, 2026-10-31): which functions of the game module a server session executes, in first-hit order.

A Frida agent writes an int3 over the entry of every listed function in the running original server, catches the
breakpoint exception on the first hit, records the function and the time, restores the byte and resumes at the entry:
one exception per function per run, nothing after. The list comes from the server's PDB (publics flagged as functions
whose section contribution belongs to a module matching --modules; ICF-folded names share an entry).

usage: python -I _tools/reach_record.py functions [--modules REGEX] [--out build/reach/functions.csv]
       python -I _tools/reach_record.py record [--name ShooterGameServer.exe | --pid N] [--functions build/reach/functions.csv]
                                               --out build/reach/<run>.csv
           attaches as soon as the process exists (poll), records until it exits (the stop) or Ctrl-C; the hits are
           appended every 5 s, so a death loses nothing
       python -I _tools/reach_record.py merge build/reach/<run>.csv ... [--out tracking/reach.csv]
           the union in first-hit order (the runs in the order given), with the run that hit each function first
"""
import argparse
import csv
import json
import re
import subprocess
import sys
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
THEIRS = Path(r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe")
DEFAULT_MODULES = r"\\ShooterGame\\[^\\]+\.obj$"

AGENT = r"""
'use strict';
var base = null, hits = null, orig = null, index = {}, rvas = null, order = [], times = [], t0 = 0, sent = 0, patched = 0;
function patchAll(mod) {
    var ranges = mod.enumerateRanges('r-x');
    ranges.forEach(function (r) { Memory.protect(r.base, r.size, 'rwx'); });
    for (var i = 0; i < rvas.length; i++) {
        var p = base.add(rvas[i]);
        orig[i] = p.readU8();
        p.writeU8(0xCC);
        index[rvas[i]] = i;
        patched++;
    }
}
function flush(final) {
    if (order.length > sent) {
        send({ type: 'hits', seq0: sent, rvas: order.slice(sent), t: times.slice(sent) });
        sent = order.length;
    }
    if (final) send({ type: 'done', n: order.length });
}
recv('start', function (msg) {
    var mod = Process.getModuleByName(msg.module);
    base = mod.base;
    rvas = msg.rvas;
    hits = new Uint8Array(rvas.length);
    orig = new Uint8Array(rvas.length);
    t0 = Date.now();
    Process.setExceptionHandler(function (d) {
        if (d.type !== 'breakpoint') return false;
        var rva = d.address.sub(base).toInt32();
        var i = index[rva];
        if (i === undefined) return false;
        if (!hits[i]) {
            hits[i] = 1;
            d.address.writeU8(orig[i]);
            order.push(rva);
            times.push(Date.now() - t0);
        }
        d.context.pc = d.address;
        return true;
    });
    patchAll(mod);
    send({ type: 'ready', patched: patched, base: base.toString() });
    setInterval(function () { flush(false); }, 5000);
});
recv('stop', function () { flush(true); });
"""


def pdbutil():
    from func_match import pdbutil as pu
    return pu()


def pdb_modules(theirs):
    """Module index -> object path, from the PDB's module list (cached as JSON beside the symbol cache)."""
    pdb = Path(theirs).with_suffix(".pdb")
    cache = ROOT / "_re" / "cache" / f"{Path(theirs).stem}.{pdb.stat().st_size:x}-{int(pdb.stat().st_mtime):x}.modules.json"
    if cache.exists():
        return {int(k): v for k, v in json.load(open(cache, encoding="utf-8")).items()}
    out = subprocess.run([pdbutil(), "dump", "-modules", str(pdb)], capture_output=True, text=True,
                         encoding="utf-8", errors="replace").stdout
    mods = {int(m.group(1)): m.group(2) for m in re.finditer(r"Mod (\d+) \| `([^`]*)`", out)}
    cache.parent.mkdir(parents=True, exist_ok=True)
    json.dump(mods, open(cache, "w", encoding="utf-8"))
    return mods


def list_functions(theirs, modules_regex):
    """rva -> (decorated name, object path, size) of every public flagged as a function whose section contribution
    lies in a module matching the regex; ICF-folded names share one entry (the first name)."""
    from func_match import Original
    o = Original(str(theirs), str(ROOT / "_re" / "cache"))
    mods = pdb_modules(theirs)
    want = re.compile(modules_regex)
    pub = subprocess.run([pdbutil(), "dump", "-publics", str(Path(theirs).with_suffix(".pdb"))], capture_output=True,
                         text=True, encoding="utf-8", errors="replace").stdout
    funcs = {}
    for m in re.finditer(r"S_PUB32 \[size = \d+\] `(.*)`\n\s+flags = ([^,]*), addr = (\d+):(\d+)", pub):
        if "function" not in m.group(2):
            continue
        rva = o.seg_rva(int(m.group(3)), int(m.group(4)))
        if rva in funcs:
            continue
        mi = o.module_of(rva)
        name = mods.get(mi, "") if mi is not None else ""
        if not want.search(name):
            continue
        funcs[rva] = (m.group(1), name, o.sizes.get(rva, 0))
    return funcs


def cmd_functions(a):
    funcs = list_functions(a.theirs, a.modules)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["rva", "size", "module", "name"])
        for rva in sorted(funcs):
            name, mod, size = funcs[rva]
            w.writerow([f"{rva:x}", size, mod, name])
    by_mod = {}
    for name, mod, size in funcs.values():
        by_mod[mod] = by_mod.get(mod, 0) + 1
    print(f"{len(funcs)} functions in {len(by_mod)} modules matching {a.modules!r} -> {a.out}")


def load_functions(path):
    funcs = {}
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            funcs[int(r["rva"], 16)] = (r["name"], r["module"], int(r["size"]))
    return funcs


def cmd_record(a):
    import frida
    funcs = load_functions(a.functions)
    rvas = sorted(funcs)
    t_wait = time.time()
    session = None
    while session is None:
        try:
            session = frida.attach(a.pid if a.pid else a.name)
        except frida.ProcessNotFoundError:
            if time.time() - t_wait > a.wait:
                sys.exit(f"no {a.name or a.pid} within {a.wait} s")
            time.sleep(0.05)
    pid = session._impl.pid if hasattr(session, "_impl") else a.pid
    a.out.parent.mkdir(parents=True, exist_ok=True)
    out = open(a.out, "w", newline="", encoding="utf-8")
    w = csv.writer(out)
    w.writerow(["seq", "t_ms", "rva", "size", "module", "name"])
    state = {"n": 0, "done": False, "ready": False}

    def on_message(msg, data):
        if msg["type"] != "send":
            print("agent:", msg, file=sys.stderr)
            return
        p = msg["payload"]
        if p["type"] == "ready":
            state["ready"] = True
            print(f"attached (pid {pid}), {p['patched']} entries patched, base {p['base']}, {time.time() - t_wait:.1f} s after the first poll")
        elif p["type"] == "hits":
            for k, (rva, t) in enumerate(zip(p["rvas"], p["t"])):
                name, mod, size = funcs[rva]
                w.writerow([p["seq0"] + k, t, f"{rva:x}", size, Path(mod).name, name])
            out.flush()
            state["n"] = p["seq0"] + len(p["rvas"])
            print(f"  {time.strftime('%H:%M:%S')} hits {state['n']} (+{len(p['rvas'])})")
        elif p["type"] == "done":
            state["done"] = True

    def on_detached(reason, *rest):
        print(f"detached: {reason}")
        state["done"] = True

    session.on("detached", on_detached)
    script = session.create_script(AGENT)
    script.on("message", on_message)
    script.load()
    script.post({"type": "start", "module": a.module, "rvas": rvas})
    try:
        while not state["done"]:
            time.sleep(0.5)
    except KeyboardInterrupt:
        try:
            script.post({"type": "stop"})
            time.sleep(1)
        except Exception:
            pass
    out.close()
    print(f"{state['n']} functions hit -> {a.out}")


def cmd_merge(a):
    seen, rows = set(), []
    for run in a.runs:
        with open(run, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if r["rva"] in seen:
                    continue
                seen.add(r["rva"])
                rows.append([len(rows), r["rva"], r["name"], r["module"], r["size"], Path(run).stem])
    a.out.parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["seq", "rva", "name", "module", "size", "run"])
        w.writerows(rows)
    total = sum(int(r[4]) for r in rows)
    print(f"{len(rows)} functions, {total:,} bytes, from {len(a.runs)} run(s) -> {a.out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("functions")
    f.add_argument("--theirs", default=str(THEIRS))
    f.add_argument("--modules", default=DEFAULT_MODULES)
    f.add_argument("--out", type=Path, default=ROOT / "build" / "reach" / "functions.csv")
    r = sub.add_parser("record")
    r.add_argument("--name", default="ShooterGameServer.exe")
    r.add_argument("--pid", type=int)
    r.add_argument("--module", default="ShooterGameServer.exe")
    r.add_argument("--functions", type=Path, default=ROOT / "build" / "reach" / "functions.csv")
    r.add_argument("--out", type=Path, required=True)
    r.add_argument("--wait", type=float, default=600, help="seconds to wait for the process")
    m = sub.add_parser("merge")
    m.add_argument("runs", nargs="+")
    m.add_argument("--out", type=Path, default=ROOT / "tracking" / "reach.csv")
    a = ap.parse_args()
    {"functions": cmd_functions, "record": cmd_record, "merge": cmd_merge}[a.cmd](a)


if __name__ == "__main__":
    main()
