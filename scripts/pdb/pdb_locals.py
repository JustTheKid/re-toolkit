"""Every function's parameters and local variables from a PDB, as an overlay on the decompiles.

Why: ATLAS's PDBs carry `S_LOCAL` records (name, type) with `S_DEFRANGE_*` live ranges (a register or a frame slot
per address range) for the optimised code, and `S_REGREL32` records for variables homed to the stack. Ghidra 12.1.4
applies none of the optimised ones (its `LocalOptimizedSymbolApplier` is a stub, `DefinedSingleAddressRangeSymbolApplier`
"eventually apply"; audit 2026-10-29), so our exports show `param_1` / `local_28`. This tool reads them once from
`llvm-pdbutil dump -symbols` (one streaming pass, nothing kept but the index) into
`_re/cache/<pdb stem>.locals.sqlite`; the exporters (`ghidra_find.py --decompile`, `ghidra_bulk_export.py`) prepend
each function's block and rename Ghidra's `param_N` to the PDB's names when the parameter counts agree (the block
records the mapping). Inlined callees' locals are listed under the inlinee's name. Types are llvm-pdbutil's
abbreviated spellings (31 characters) with the type index.

Usage:
  python -I _tools/pdb_locals.py build <pdb> [--image-base 0x140000000] [--cache D:\\ATLAS\\_re\\cache]
  python -I _tools/pdb_locals.py show <pdb or program name> <VA> [<VA> ...]    e.g. show ShooterGameServer.exe 140591c50
  python -I _tools/pdb_locals.py stats <pdb or program name>
In code: Locals.open("ShooterGameServer.exe") -> .block(va) / .decorate(code, va) -> (text, mapping)

Ranges are offsets from the function's entry: `RCX @+0x0..+0x23` (the value is in RCX for those bytes),
`[RSP+0x28] @+0x0..+0x1` (a stack slot for that range), `[RSP+0x90]` (a frame slot for the whole function; the frame
register is `S_FRAMEPROC`'s local fp reg). `S_REGREL32` storage is whole-function too.
"""
import argparse
import re
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pdb_source_md5 import pdbutil  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "_re" / "cache"
PDBS = {  # program name -> its PDB (the originals, read-only)
    "shootergameserver": Path(r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.pdb"),
    "atlasgame": Path(r"D:\ATLAS\ShooterGame\Binaries\Win64\AtlasGame.pdb"),
}

REC = re.compile(r"^\s*(\d+) \| (S_[A-Z0-9_]+) \[size = \d+\](.*)$")
MOD = re.compile(r"^\s*Mod (\d+) \| `(.*)`:\s*$")
NAME = re.compile(r"`(.*)`")
ADDR = re.compile(r"addr = (\d+):(\d+), code size = (\d+)")
END = re.compile(r"end = (\d+)")
TYPE_LOCAL = re.compile(r"type=0x([0-9A-Fa-f]+) \((.*)\), flags = (.*)$")
TYPE_REGREL = re.compile(r"type = 0x([0-9A-Fa-f]+) \((.*)\), register = (\w+), offset = (-?\d+)")
RANGE_START = re.compile(r"register = (\w+), .*range start = (\d+):(\d+), length = (\d+)")
RANGE_BR = re.compile(r"range = \[(\d+):(\d+),\+(\d+)\)")
REG_REL = re.compile(r"register = (\w+), offset = (-?\d+)")
SUBFIELD = re.compile(r"register = (\w+), .*offset in parent = (-?\d+)")
FP_REL = re.compile(r"offset = (-?\d+)")
INLINEE = re.compile(r"inlinee = 0x[0-9A-Fa-f]+ \((.*?)\), parent")
FRAMEPROC = re.compile(r"local fp reg = (\w+), param fp reg = (\w+)")
IDENT = re.compile(r"^[A-Za-z_]\w*$")
PARAM_N = re.compile(r"\bparam_(\d+)\b")


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def pe_image_base(pe: Path):
    with open(pe, "rb") as f:
        d = f.read(0x400)
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    opt = e_lfanew + 4 + 20
    magic = struct.unpack_from("<H", d, opt)[0]
    return struct.unpack_from("<Q", d, opt + 24)[0] if magic == 0x20B else struct.unpack_from("<I", d, opt + 28)[0]


def section_bases(pdb: Path):
    out = subprocess.run([pdbutil(), "dump", "-section-headers", str(pdb)], capture_output=True, text=True,
                         encoding="utf-8", errors="replace").stdout
    bases, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"\s*SECTION HEADER #(\d+)", line)
        if m:
            cur = int(m.group(1))
            continue
        m = re.match(r"\s*([0-9A-Fa-f]+) virtual address", line)
        if m and cur is not None and cur not in bases:
            bases[cur] = int(m.group(1), 16)
    if not bases:
        sys.exit(f"no section headers in {pdb}")
    return bases


def cache_path(pdb: Path, cache_dir: Path):
    return cache_dir / f"{pdb.stem}.locals.sqlite"


def build(pdb: Path, cache_dir: Path, image_base: int):
    bases = section_bases(pdb)
    cache_dir.mkdir(parents=True, exist_ok=True)
    db_path = cache_path(pdb, cache_dir)
    tmp = db_path.with_suffix(".tmp")
    if tmp.exists():
        tmp.unlink()
    con = sqlite3.connect(tmp)
    con.executescript("""
        PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;
        CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE funcs(va INTEGER PRIMARY KEY, name TEXT, size INTEGER, modi INTEGER, fp TEXT);
        CREATE TABLE locals(va INTEGER, ord INTEGER, name TEXT, type TEXT, flags TEXT, scope TEXT, storage TEXT,
                            PRIMARY KEY(va, ord));
    """)
    con.execute("INSERT INTO meta VALUES ('pdb', ?)", (str(pdb),))
    con.execute("INSERT INTO meta VALUES ('image_base', ?)", (hex(image_base),))
    con.execute("INSERT INTO meta VALUES ('built', ?)", (time.strftime("%Y-%m-%d %H:%M"),))

    def va_of(seg, off):
        base = bases.get(int(seg))
        return None if base is None else image_base + base + int(off)

    proc = subprocess.Popen([pdbutil(), "dump", "-symbols", str(pdb)], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace", bufsize=1 << 20)
    modi = -1
    func = None  # the open procedure
    cur = None  # the local the next DEFRANGE records belong to
    kind = None  # the record whose continuation lines are being read
    pend = {}
    inl = []  # inlinee names, innermost last
    nfunc = nloc = 0
    start = time.time()
    frows, lrows = [], []

    def flush():
        nonlocal frows, lrows
        con.executemany("INSERT OR REPLACE INTO funcs VALUES (?,?,?,?,?)", frows)
        con.executemany("INSERT OR REPLACE INTO locals VALUES (?,?,?,?,?,?,?)", lrows)
        frows, lrows = [], []

    def close_func():
        nonlocal func, nfunc, nloc
        if func is None or func["va"] is None:
            func = None
            return
        frows.append((func["va"], func["name"], func["size"], func["modi"], func["fp"]))
        for i, loc in enumerate(func["locals"]):
            lrows.append((func["va"], i, loc["name"], loc["type"], loc["flags"], loc["scope"],
                          fmt_storage(loc["storage"], func)))
        nfunc += 1
        nloc += len(func["locals"])
        func = None
        if nfunc % 20000 == 0:
            flush()
            log(f"{nfunc:,} functions, {nloc:,} locals, {time.time() - start:.0f} s")

    def rel(seg, off):
        va = va_of(seg, off)
        return None if va is None or func is None or func["va"] is None else va - func["va"]

    for line in proc.stdout:
        m = REC.match(line)
        if m:
            offset, kind, rest = int(m.group(1)), m.group(2), m.group(3)
            pend = {}
            if kind in ("S_GPROC32", "S_LPROC32"):
                close_func()
                nm = NAME.search(rest)
                func = {"name": nm.group(1) if nm else "?", "va": None, "size": None, "end": None, "fp": "",
                        "locals": [], "modi": modi}
                cur, inl = None, []
            elif kind == "S_LOCAL":
                nm = NAME.search(rest)
                cur = {"name": nm.group(1) if nm else "?", "type": "", "flags": "", "scope": inl[-1] if inl else "",
                       "storage": []}
                if func is not None:
                    func["locals"].append(cur)
            elif kind == "S_REGREL32":
                nm = NAME.search(rest)
                pend = {"name": nm.group(1) if nm else "?"}
                cur = None
            elif kind == "S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE":
                fm = FP_REL.search(rest)
                if cur is not None and fm:
                    cur["storage"].append(("FP", int(fm.group(1)), None, None))
            elif kind == "S_INLINESITE_END":
                if inl:
                    inl.pop()
            elif kind == "S_END":
                if func is not None and func["end"] == offset:
                    close_func()
                    cur, inl = None, []
            continue
        mm = MOD.match(line)
        if mm:
            close_func()
            modi = int(mm.group(1))
            continue
        if kind is None:
            continue
        # continuation lines of the current record
        if kind in ("S_GPROC32", "S_LPROC32") and func is not None:
            am = ADDR.search(line)
            if am:
                func["va"] = va_of(am.group(1), am.group(2))
                func["size"] = int(am.group(3))
                em = END.search(line)
                if em:
                    func["end"] = int(em.group(1))
        elif kind == "S_FRAMEPROC" and func is not None:
            fm = FRAMEPROC.search(line)
            if fm:
                func["fp"] = fm.group(1)
        elif kind == "S_LOCAL" and cur is not None:
            tm = TYPE_LOCAL.search(line)
            if tm:
                cur["type"], cur["flags"] = f"{tm.group(2)} <0x{tm.group(1)}>", tm.group(3).strip()
        elif kind == "S_DEFRANGE_REGISTER" and cur is not None:
            rm = RANGE_START.search(line)
            if rm:
                cur["storage"].append(("REG", rm.group(1), rel(rm.group(2), rm.group(3)), int(rm.group(4))))
        elif kind == "S_DEFRANGE_REGISTER_REL" and cur is not None:
            rm = REG_REL.search(line)
            if rm and "reg" not in pend:
                pend["reg"], pend["off"] = rm.group(1), int(rm.group(2))
            bm = RANGE_BR.search(line)
            if bm and "reg" in pend:
                cur["storage"].append(("MEM", f"{pend['reg']}{pend['off']:+#x}", rel(bm.group(1), bm.group(2)),
                                       int(bm.group(3))))
        elif kind == "S_DEFRANGE_FRAMEPOINTER_REL" and cur is not None:
            fm = FP_REL.search(line)
            bm = RANGE_BR.search(line)
            if fm and bm:
                cur["storage"].append(("FP", int(fm.group(1)), rel(bm.group(1), bm.group(2)), int(bm.group(3))))
        elif kind == "S_DEFRANGE_SUBFIELD_REGISTER" and cur is not None:
            sm = SUBFIELD.search(line)
            if sm and "reg" not in pend:
                pend["reg"], pend["off"] = sm.group(1), int(sm.group(2))
            bm = RANGE_BR.search(line)
            if bm and "reg" in pend:
                cur["storage"].append(("REG", f"{pend['reg']}(part+{pend['off']:#x})", rel(bm.group(1), bm.group(2)),
                                       int(bm.group(3))))
        elif kind == "S_REGREL32" and func is not None and pend:
            tm = TYPE_REGREL.search(line)
            if tm:
                stor = ("MEM", f"{tm.group(3)}{int(tm.group(4)):+#x}", None, None)
                scope = inl[-1] if inl else ""
                same = [l for l in func["locals"] if l["name"] == pend["name"] and l["scope"] == scope]
                if same:
                    same[-1]["storage"].append(stor)
                else:
                    func["locals"].append({"name": pend["name"], "type": f"{tm.group(2)} <0x{tm.group(1)}>",
                                           "flags": "regrel", "scope": scope, "storage": [stor]})
                pend = {}
        elif kind == "S_INLINESITE":
            im = INLINEE.search(line)
            if im:
                inl.append(im.group(1))
                kind = None  # the site's binary annotation lines follow; nothing to read
    close_func()
    flush()
    rc = proc.wait()
    if rc != 0:
        con.close()
        tmp.unlink(missing_ok=True)
        sys.exit(f"llvm-pdbutil exited with {rc}")
    con.execute("INSERT INTO meta VALUES ('functions', ?)", (str(nfunc),))
    con.execute("INSERT INTO meta VALUES ('locals', ?)", (str(nloc),))
    con.commit()
    con.close()
    if db_path.exists():
        db_path.unlink()
    tmp.rename(db_path)
    log(f"done: {nfunc:,} functions, {nloc:,} locals in {time.time() - start:.0f} s -> {db_path}")


def fmt_storage(items, func, limit=8):
    parts = []
    if len(items) > limit:  # a big function moves a value through dozens of places; the first ones say enough
        items, more = items[:limit], len(items) - limit
    else:
        more = 0
    for kind, where, start, length in items:
        if kind == "FP":
            where = f"[{func['fp'] or 'fp'}{where:+#x}]"
        elif kind == "MEM":
            where = f"[{where}]"
        if start is None:
            parts.append(where)
        else:
            parts.append(f"{where} @{start:+#x}..{start + length:+#x}")
    if more:
        parts.append(f"... +{more} more")
    return "; ".join(parts)


class Locals:
    """The index of one PDB, read by the exporters."""

    def __init__(self, db_path: Path):
        self.path = db_path
        self.con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, check_same_thread=False)
        self.lock = threading.Lock()  # one connection shared by the exporters' worker threads
        self.stem = db_path.name.split(".")[0]

    @classmethod
    def open(cls, program_or_pdb, cache_dir: Path = CACHE):
        """By program name (ShooterGameServer.exe, AtlasGame.exe), PDB path or cache path; None when not built."""
        p = Path(str(program_or_pdb))
        stem = p.name.split(".")[0]
        db = p if p.suffix == ".sqlite" else cache_path(Path(stem + ".pdb"), cache_dir)
        return cls(db) if db.exists() else None

    def function(self, va: int):
        with self.lock:
            return self.con.execute("SELECT name, size, modi, fp FROM funcs WHERE va = ?", (va,)).fetchone()

    def rows(self, va: int):
        with self.lock:
            return self.con.execute("SELECT name, type, flags, scope, storage FROM locals WHERE va = ? ORDER BY ord",
                                    (va,)).fetchall()

    def params(self, va: int):
        """The function's own parameters in order, `this` left out."""
        return [r for r in self.rows(va) if r[3] == "" and r[2] == "param" and r[0] != "this"]

    def block(self, va: int, mapping=None, newline="\n", renamed=None):
        """The comment block. `renamed` is None outside an export, else whether decorate() renamed param_N."""
        f = self.function(va)
        if f is None:
            return ""
        name, size, modi, fp = f
        rows = self.rows(va)
        this = [r for r in rows if r[3] == "" and r[0] == "this"]
        params = self.params(va)
        own = [r for r in rows if r[3] == "" and r not in params and r[0] != "this"]
        inlined = [r for r in rows if r[3] != ""]
        mapping = mapping or {}
        head = (f"// PDB locals of {name} ({self.stem}.pdb, _tools/pdb_locals.py): {len(params)} params, "
                f"{len(own)} locals, {len(inlined)} inlined; frame reg {fp or '?'}")
        if params and renamed is False:
            head += "; Ghidra's param_N not renamed (parameter counts differ)"
        out = [head]
        for r in this:
            out.append(f"//   this: {r[1]} [{r[4]}]")
        for i, r in enumerate(params, 1):
            tag = f"param_{i} -> {r[0]}" if mapping.get(i) == r[0] else f"p{i} {r[0]}"
            out.append(f"//   {tag}: {r[1]} [{r[4]}]")
        for r in own:
            out.append(f"//   {r[0]}: {r[1]} [{r[4]}]" + (f" ({r[2]})" if r[2] not in ("none", "") else ""))
        last = None
        for r in inlined:
            if r[3] != last:
                last = r[3]
            out.append(f"//   ({r[3]}) {r[0]}: {r[1]} [{r[4]}]")
        return newline.join(out) + newline

    def decorate(self, code: str, va: int):
        """The block and the code with `param_N` renamed to the PDB's names when the counts agree.
        Returns (text, mapping); text is the code unchanged when the function is not in the index."""
        if self.function(va) is None:
            return code, {}
        nl = "\r\n" if "\r\n" in code else "\n"
        params = self.params(va)
        nums = sorted({int(n) for n in PARAM_N.findall(code)})
        names = [r[0] for r in params]
        mapping = {}
        if params and nums == list(range(1, len(params) + 1)) and all(IDENT.match(n) for n in names) \
                and len(set(names)) == len(names) \
                and not any(re.search(rf"\b{re.escape(n)}\b", code) for n in names):
            mapping = {i + 1: n for i, n in enumerate(names)}
            code = PARAM_N.sub(lambda m: mapping.get(int(m.group(1)), m.group(0)), code)
        return self.block(va, mapping, nl, renamed=bool(mapping)) + code, mapping


def resolve_pdb(arg: str) -> Path:
    p = Path(arg)
    if p.suffix.lower() == ".pdb" and p.exists():
        return p
    key = p.name.split(".")[0].lower()
    if key in PDBS:
        return PDBS[key]
    sys.exit(f"unknown PDB or program: {arg}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("Usage:")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("pdb")
    b.add_argument("--image-base", help="default: the PE next to the PDB, else 0x140000000")
    b.add_argument("--cache", default=str(CACHE))
    s = sub.add_parser("show")
    s.add_argument("pdb")
    s.add_argument("va", nargs="+", help="hex VAs, e.g. 140591c50")
    s.add_argument("--cache", default=str(CACHE))
    t = sub.add_parser("stats")
    t.add_argument("pdb")
    t.add_argument("--cache", default=str(CACHE))
    a = ap.parse_args()

    if a.cmd == "build":
        pdb = resolve_pdb(a.pdb)
        if a.image_base:
            base = int(a.image_base, 16)
        else:
            pe = next((pdb.with_suffix(ext) for ext in (".exe", ".dll") if pdb.with_suffix(ext).exists()), None)
            base = pe_image_base(pe) if pe else 0x140000000
        log(f"building locals index of {pdb} (image base {base:#x})")
        build(pdb, Path(a.cache), base)
        return
    pdb = resolve_pdb(a.pdb)
    loc = Locals.open(pdb, Path(a.cache))
    if loc is None:
        sys.exit(f"no index for {pdb.name}: run `pdb_locals.py build {pdb}` first")
    if a.cmd == "stats":
        for k, v in loc.con.execute("SELECT key, value FROM meta ORDER BY key"):
            print(f"{k}: {v}")
        n, = loc.con.execute("SELECT COUNT(*) FROM funcs WHERE va IN (SELECT va FROM locals)").fetchone()
        print(f"functions with locals: {n:,}")
        return
    for va in a.va:
        text = loc.block(int(va, 16))
        print(text if text else f"// {va}: not in the index", end="" if text else "\n")


if __name__ == "__main__":
    main()
