"""The hybrid link's swap as one command (plan P2d, 2026-10-31): one judged object of ours in place of the delinked
set's definitions of the functions it matched byte for byte, wherever the original's linker had put them.

What it does, in a work folder `build/delink/hybrid/<name>/`:
 1. the set's symbol index (every defined external of every delinked object, cached as `set-defined.json`);
 2. the keep list: the judge's MATCH functions of our object that some delinked object defines (the ICF aliases at
    the same original address become extra names of our function, `defines`);
 3. the labels: the set's `LAB_<va>` names inside each kept function's original range (the leftovers' EH tables point
    at them), more `defines`; the aliases: every undefined external the set defines under another name (the
    original folded identical functions: `operator new` is `??2FRHICommandList@@SAPEAX_K@Z` there); the retargets:
    every relocation of a kept function through a section symbol of a removed section of ours (a function-local
    static, a literal), pointed at the set's symbol for the datum the byte-identical original reads;
 4. the leftovers: every module that defines a kept function re-exported without them (`delink_all.py export
    --modules <regex> --redo --exclude --synth module`);
 5. our object stripped (`coff_strip.py`) and the link (`delink_link.py --extra`).
`--dry-run` stops before the export and prints the counts. The boot and the checks are the delink-boot skill's.

Swaps accumulate: a function an earlier swap (another work dir under build/delink/hybrid/) keeps stays with it, the
leftovers are re-exported without every swap's functions (exclude-all.txt), the link takes every swap's stripped
object. A dry run writes the work dir's lists too, so a dry run under a name never linked misleads the next swap:
delete its dir.

usage: python -I _tools/delink_swap.py <name> <ours.obj> <match.json> [--set build/delink/server-p2c]
                                      [--out build/delink/link-hybrid] [--pure-map build/delink/link/ShooterGameServer.map]
                                      [--dry-run] [--no-export] [--no-link]
"""
import argparse
import bisect
import json
import re
import struct
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))
PY = Path(sys.executable)
BASE = 0x140000000
THEIRS = Path(r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe")
TAB = chr(9)
NL = chr(10)


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def coff(path):
    """(defined externals {name: (section, value)}, undefined externals set, sections, symbols [(i, name, value, sect, cls,
    naux)], the raw bytes, header size, symbol size) of a COFF object, /bigobj or plain."""
    d = Path(path).read_bytes()
    if d[:4] == bytes.fromhex("0000ffff"):
        nsec, symoff, nsym = struct.unpack_from("<III", d, 44)
        hdr, symsize, fmt = 56, 20, "<8sIiHBB"
    else:
        nsec, symoff, nsym = struct.unpack_from("<H", d, 2)[0], struct.unpack_from("<I", d, 8)[0], struct.unpack_from("<I", d, 12)[0]
        hdr, symsize, fmt = 20, 18, "<8sIhHBB"
    secs = [struct.unpack_from("<8sIIIIIIHHI", d, hdr + 40 * i) for i in range(nsec)]
    strtab = symoff + symsize * nsym
    defined, undefined, syms = {}, set(), []
    i = 0
    while i < nsym:
        name, value, sect, typ, cls, naux = struct.unpack_from(fmt, d, symoff + symsize * i)
        if name[:4] == bytes(4):
            so = struct.unpack_from("<I", name, 4)[0]
            nm = d[strtab + so:d.index(bytes(1), strtab + so)].decode(errors="replace")
        else:
            nm = name.rstrip(bytes(1)).decode(errors="replace")
        syms.append((i, nm, value, sect, cls, naux))
        if cls == 2:
            if sect > 0:
                defined[nm] = (sect, value)
            elif sect == 0:
                undefined.add(nm)
        i += 1 + naux
    return defined, undefined, secs, syms, d


def symoff_of(d):
    return struct.unpack_from("<I", d, 48)[0] if d[:4] == bytes.fromhex("0000ffff") else struct.unpack_from("<I", d, 8)[0]


def symsize_of(d):
    return 20 if d[:4] == bytes.fromhex("0000ffff") else 18


def set_index(set_dir, cache, pure):
    """Every defined external of the set, from the pure copy of a module that was re-exported without functions
    already (`<pure>/<rel>`, kept by this tool before each re-export) and the set's object otherwise."""
    newest = max(p.stat().st_mtime for p in list(set_dir.glob("**/*.obj")) + list(pure.glob("**/*.obj")))
    if cache.exists() and cache.stat().st_mtime > newest:
        return json.load(open(cache))
    log("indexing the set's defined externals")
    index, mods = {}, {}
    for f in sorted(set_dir.glob("**/*.obj")):
        rel = f.relative_to(set_dir).as_posix()
        src = pure / rel if (pure / rel).exists() else f
        defined, _u, _s, _y, _d = coff(src)
        for nm in defined:
            index.setdefault(nm, rel)
    json.dump(index, open(cache, "w"))
    return index


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("name")
    ap.add_argument("ours")
    ap.add_argument("match")
    ap.add_argument("--set", default=str(ROOT / "build" / "delink" / "server-p2c"))
    ap.add_argument("--out", default=str(ROOT / "build" / "delink" / "link-hybrid"))
    ap.add_argument("--pure-map", default=str(ROOT / "build" / "delink" / "link" / "ShooterGameServer.map"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-export", action="store_true", help="the leftovers are exported already")
    ap.add_argument("--no-link", action="store_true")
    a = ap.parse_args()
    set_dir, work = Path(a.set), ROOT / "build" / "delink" / "hybrid" / a.name
    work.mkdir(parents=True, exist_ok=True)
    manifest = {l.split(TAB)[3]: l.split(TAB)[2] for l in (set_dir / "manifest.tsv").read_text(encoding="utf-8").splitlines()[1:]}
    pure = ROOT / "build" / "delink" / "hybrid" / "pure"
    pure.mkdir(parents=True, exist_ok=True)
    index = set_index(set_dir, ROOT / "build" / "delink" / "hybrid" / "set-defined.json", pure)
    from pe_compare import Pe, function_size
    theirs = Pe(THEIRS, ROOT / "_re" / "cache")
    o_def, o_und, o_secs, o_syms, o_bytes = coff(a.ours)
    rows = json.load(open(a.match))
    rows = rows.get("functions", rows) if isinstance(rows, dict) else rows
    match = sorted({r["name"] for r in rows if r["state"] == "MATCH"})
    # 2. the keep list, by the module that defines each function in the set
    keep, by_module, nowhere = [], defaultdict(list), []
    for n in match:
        if n not in o_def:
            continue
        obj = index.get(n)
        if obj is None:
            nowhere.append(n)
            continue
        keep.append(n)
        by_module[manifest.get(obj, obj)].append(n)
    log(f"{len(match)} MATCH functions; {len(keep)} defined by the set in {len(by_module)} modules; {len(nowhere)} by no object (inlines the original never emitted on their own)")
    # earlier swaps (the other work dirs' keep lists): a function one of them keeps stays with it, so that its labels
    # are defined once and the leftovers exclude it once
    hybrid = ROOT / "build" / "delink" / "hybrid"
    previous = {}
    for kf in sorted(hybrid.glob("*/keep.txt")):
        if kf.parent != work:
            for n in kf.read_text(encoding="utf-8").split():
                previous[n] = kf.parent.name
    taken = [n for n in keep if n in previous]
    if taken:
        log(f"{len(taken)} kept by earlier swaps already ({sorted({previous[n] for n in taken})}): left to them")
        keep = [n for n in keep if n not in previous]
        for m in list(by_module):
            by_module[m] = [n for n in by_module[m] if n not in previous]
            if not by_module[m]:
                del by_module[m]
    # the ICF aliases: the other names of the original at a kept function's address, defined by the set -> our function
    defines, group_names = [], 0
    for n in keep:
        rva = theirs.orig.by_name.get(n)
        if rva is None:
            continue
        for other in sorted(theirs.names(rva)[0]):
            if other != n and other in index and other not in o_def:
                defines.append((other, n, 0))
                group_names += 1
    # 3. the labels inside the kept functions' original ranges (the pure link's map carries the original addresses)
    carried = {}
    for m in re.finditer(r"^\s*(\d{4}):([0-9a-f]{8})\s+(\S+)\s+([0-9a-f]{16})", Path(a.pure_map).read_text(encoding="utf-8", errors="replace"), re.M):
        nm = m.group(3)
        mm = re.search(r"(1[0-9a-f]{8})$", nm)
        if mm:
            carried.setdefault(int(mm.group(1), 16), nm)
    label_vas = sorted(v for v, nm in carried.items() if nm.startswith("LAB_"))
    labels = 0
    spans = []
    for n in keep:
        rva = theirs.orig.by_name.get(n)
        if rva is None:
            continue
        size = function_size(theirs, rva)
        spans.append((rva, size, n))
        lo, hi = BASE + rva, BASE + rva + size
        for va in label_vas[bisect.bisect_left(label_vas, lo):bisect.bisect_left(label_vas, hi)]:
            defines.append((carried[va], n, va - lo))
            labels += 1
    spans.sort()
    # the aliases: an undefined external of ours the set defines under another name at the same address
    aliases, libs = {}, []
    keep_set = set(keep)
    kept_sections = {o_def[n][0] for n in keep}
    # plus the sections associated with them (the functions' .pdata, .xdata and funclets: a dtor funclet names the
    # destructors it calls), as coff_strip keeps them
    symoff, symsize = symoff_of(o_bytes), symsize_of(o_bytes)
    assoc = {}
    for i, nm, v, sect, cls, naux in o_syms:
        if cls == 3 and naux >= 1 and sect > 0 and o_secs[sect - 1][9] & 0x1000:
            aux = symoff + symsize * (i + 1)
            number = struct.unpack_from("<H", o_bytes, aux + 12)[0]
            if symsize == 20:
                number |= struct.unpack_from("<H", o_bytes, aux + 16)[0] << 16
            if o_bytes[aux + 14] == 5:
                assoc[sect] = number
    changed = True
    while changed:
        changed = False
        for sct, parent in assoc.items():
            if parent in kept_sections and sct not in kept_sections:
                kept_sections.add(sct)
                changed = True
    # the externals our kept sections refer to (through their relocations' symbol indices)
    sym_by_index = {i: (nm, v, sect, cls) for i, nm, v, sect, cls, _n in o_syms}
    referenced = set()
    for k in kept_sections:
        s = o_secs[k - 1]
        for r in range(s[7]):
            referenced.add(struct.unpack_from("<I", o_bytes, s[5] + 10 * r + 4)[0])
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    fn_of_sec = {o_def[n][0]: n for n in keep}
    insn_cache = {}

    def original_target(fn, va):
        """What the byte-identical original's instruction at offset va of function fn reaches (a RIP-relative
        operand or a direct call / jump), or None."""
        rva = theirs.orig.by_name.get(fn)
        if rva is None:
            return None
        if fn not in insn_cache:
            insn_cache[fn] = list(md.disasm(theirs.read(rva, function_size(theirs, rva)), BASE + rva))
        for ins in insn_cache[fn]:
            off = ins.address - BASE - rva
            if off <= va < off + ins.size:
                for op in ins.operands:
                    if op.type == x86.X86_OP_MEM and op.mem.base == x86.X86_REG_RIP:
                        return ins.address + ins.size + op.mem.disp
                    if op.type == x86.X86_OP_IMM and ins.mnemonic.startswith(("call", "j")):
                        return op.imm
                return None
            if off > va:
                return None
        return None

    def set_name_at(target):
        if target is None:
            return None
        if target in carried and carried[target] in index:
            return carried[target]
        nms, dx = theirs.names(target - BASE)
        if nms and dx == 0:
            return next((m for m in sorted(nms) if m in index), None)
        return None

    sites = defaultdict(list)  # symbol index -> [(function, va)] over the kept functions' own sections
    for k, fn in fn_of_sec.items():
        s = o_secs[k - 1]
        for r in range(s[7]):
            va, si, ty = struct.unpack_from("<IIH", o_bytes, s[5] + 10 * r)
            sites[si].append((fn, va))
    # a referenced weak external (a vector deleting destructor) makes the linker look its default up by name
    for i, nm, v, sect, cls, naux in o_syms:
        if cls == 105 and i in referenced and naux >= 1:
            referenced.add(struct.unpack_from("<I", o_bytes, symoff + symsize * (i + 1))[0])
    for i in referenced:
        nm, v, sect, cls = sym_by_index[i]
        if cls != 2 or nm in keep_set or nm in index or nm in aliases:
            continue
        # the name the set uses for what the original reaches here: by the PDB's names at the public's address, else
        # by the original instruction's own target (an inline the original folded under a name the PDB does not
        # give this one)
        rva = theirs.orig.by_name.get(nm)
        alias = None
        if rva is not None:
            alias = next((m for m in sorted(theirs.names(rva)[0]) if m in index), None)
        if alias is None:
            for fn, va in sites.get(i, []):
                alias = set_name_at(original_target(fn, va))
                if alias:
                    break
        if alias:
            aliases[nm] = alias
        else:
            libs.append(nm)
    # the retargets: relocations of kept sections through static (section) symbols of other sections
    retargets, untargeted = [], []
    for k, fn in fn_of_sec.items():
        s = o_secs[k - 1]
        for r in range(s[7]):
            va, si, ty = struct.unpack_from("<IIH", o_bytes, s[5] + 10 * r)
            nm, v, sect, cls = sym_by_index[si]
            if cls != 3 or sect <= 0 or sect in kept_sections:
                continue
            name_at = set_name_at(original_target(fn, va))
            if name_at:
                retargets.append((fn, va, name_at))
            else:
                untargeted.append((fn, va))
    # the files
    (work / "keep.txt").write_text(NL.join(keep) + NL, encoding="utf-8")
    (work / "aliases.txt").write_text(NL.join(k + TAB + v for k, v in sorted(aliases.items())) + NL, encoding="utf-8")
    (work / "defines.txt").write_text(NL.join(f"{nm}{TAB}{fn}{TAB}{off:#x}" for nm, fn, off in defines) + NL, encoding="utf-8")
    (work / "retarget.txt").write_text(NL.join(f"{fn}{TAB}{va:#x}{TAB}{nm}" for fn, va, nm in retargets) + NL, encoding="utf-8")
    mods = sorted(by_module)
    regex = "^(" + "|".join(re.escape(m) for m in mods) + ")$"
    (work / "modules.txt").write_text(NL.join(mods) + NL, encoding="utf-8")
    log(f"keep {len(keep)} in {len(mods)} modules; defines {len(defines)} ({group_names} ICF names, {labels} labels); aliases {len(aliases)}; "
        f"retargets {len(retargets)} ({len(untargeted)} without a target); left to the libraries: {len(libs)} {libs[:6]}")
    for m in mods[:12]:
        log(f"   {len(by_module[m]):4d} {m}")
    if a.dry_run:
        return
    # 4. the leftovers: the pure copy of each module kept first (the index reads it next time)
    if not a.no_export:
        for obj, mod in manifest.items():
            if mod in by_module and not (pure / obj).exists():
                (pure / obj).parent.mkdir(parents=True, exist_ok=True)
                (pure / obj).write_bytes((set_dir / obj).read_bytes())
        # the exclusion is every swap's keep list: a module re-exported for this swap must stay without the
        # functions an earlier swap took from it
        names = set(keep)
        for kf in hybrid.glob("*/keep.txt"):
            names.update(kf.read_text(encoding="utf-8").split())
        (work / "exclude-all.txt").write_text(NL.join(sorted(names)) + NL, encoding="utf-8")
        cmd = [str(PY), "-I", str(TOOLS / "delink_all.py"), "export", "--out", str(set_dir), "--modules", regex, "--redo",
               "--exclude", str(work / "exclude-all.txt"), "--synth", "module", "--heap", "4g"]
        log("export:", " ".join(cmd[2:7]), "...")
        r = subprocess.run(cmd, cwd=ROOT)
        if r.returncode != 0:
            sys.exit("the export failed")
    # 5. the strip and the link
    stripped = work / (Path(a.ours).stem + ".ours.obj")
    r = subprocess.run([str(PY), "-I", str(TOOLS / "coff_strip.py"), a.ours, str(stripped), "--keep", str(work / "keep.txt"),
                        "--alias", str(work / "aliases.txt"), "--define", str(work / "defines.txt"), "--retarget", str(work / "retarget.txt")], cwd=ROOT)
    if r.returncode != 0:
        sys.exit("the strip failed")
    if a.no_link:
        return
    # every swap's stripped object, the earlier ones first
    extras = sorted(str(o) for o in hybrid.glob("*/*.ours.obj") if o.resolve() != stripped.resolve()) + [str(stripped)]
    log(f"link with {len(extras)} object(s) of ours: " + ", ".join(Path(e).name for e in extras))
    r = subprocess.run([str(PY), "-I", str(TOOLS / "delink_link.py"), "--objs", str(set_dir), "--out", a.out, "--extra", *extras], cwd=ROOT)
    sys.exit(r.returncode)


if __name__ == "__main__":
    main()
