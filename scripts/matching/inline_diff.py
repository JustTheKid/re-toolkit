"""Inlining decisions on both sides: a function's inline tree in our object and in ATLAS's PDB, and where they differ.
Our objects (recompile_unit.py: ATLAS's command line has /Z7 /Zo) and ATLAS's PDB both record, per function, every
inlined call (S_INLINESITE, with the inlinee's file and line) and every call left out of line (S_CALLEES). Where one
compiler inlined a call the other did not, the code differs although the functions' own source may be the same: the
callee's definition (a forced inline, a header layout, a heavier body) or what the caller inlined before it decides.
--match turns this into a cause count over a judge run: which callees ATLAS calls and we inline, and the other way.

Usage: python -I _tools/inline_diff.py <our .obj> <original pe> <decorated name> [...] [--tree]
       python -I _tools/inline_diff.py <our .obj> <original pe> --match <match.json> [--states DIFF,SIZE] [--top N]
  --tree    print both inline trees (inlinee, its file after \\Source\\ and line; "call" for an out-of-line call);
            for a function our object lacks (not ported yet) ATLAS's tree alone
  --match   every function of a judge run's match.json in these states (default DIFF and SIZE)
Output: per function, each place where one side inlines and the other calls, and what only one side inlines or
calls; with --match the callees counted over all functions. The original's modules are parsed from llvm-pdbutil
(dump -symbols / -il per module) and cached as pickles in _re/cache/pdbsym; our object's llvm-readobj --codeview dump
is streamed, not stored.
2026-10-25 (phase 4b step 1.11, Core batch C4: UObjectBaseInit calls PreAllocate in ATLAS's build; --tree shows
ATLAS's tree for functions not ported yet).
"""
import argparse
import json
import pickle
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from func_match import Original  # noqa: E402
from pdb_source_md5 import pdbutil  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
CACHE = REPO / "_re" / "cache"


def readobj():
    return str(Path(pdbutil()).with_name("llvm-readobj.exe"))


def short_path(path):
    p = path.replace("/", "\\").lower()
    i = p.find("\\source\\")
    return p[i + 8:] if i >= 0 else p.rsplit("\\", 1)[-1]


def short_name(name):
    """llvm-pdbutil cuts names after 32 characters ("_InterlockedCompareExchangePoint..."): compare that much."""
    return (name[:-3] if name.endswith("...") else name)[:32]


class Node:
    __slots__ = ("name", "fid", "file", "line", "inlines", "calls")

    def __init__(self, name, fid=None):
        self.name, self.fid, self.file, self.line = name, fid, None, None
        self.inlines, self.calls = [], []

    def key(self):
        return (self.name, self.file)


def resolve(node, lines):
    """Fill in each inline node's file and line from its side's inlinee table."""
    for n in node.inlines:
        n.file, n.line = lines.get(n.fid, (None, None))
        resolve(n, lines)


# --- ATLAS's side: llvm-pdbutil dumps of one module ---------------------------------------------------------------

def module_dump(pdb, modi, what):
    flag = {"sym": "-symbols", "il": "-il"}[what]
    return subprocess.run([pdbutil(), "dump", flag, "-modi", str(modi), str(pdb)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace").stdout


def module_trees(pdb, modi):
    """({(segment, offset): root Node}, {inlinee id: (file, line)}) of one module, cached as a pickle."""
    out = CACHE / "pdbsym" / f"{pdb.stem}.mod{modi}.pkl"
    if out.exists() and out.stat().st_mtime > pdb.stat().st_mtime:
        return pickle.loads(out.read_bytes())
    res = (pdb_procs(module_dump(pdb, modi, "sym")), pdb_inlinee_lines(module_dump(pdb, modi, "il")))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(pickle.dumps(res))
    return res


REC = re.compile(r"^\s*(\d+) \| (S_[A-Z0-9_]+) \[size = \d+\](?: `(.*)`)?\s*$")


def pdb_procs(text):
    """{(segment, offset): root Node} for every procedure of a module's symbol dump."""
    procs, stack, cur = {}, [], None
    for line in text.splitlines():
        m = REC.match(line)
        if m:
            kind = m.group(2)
            cur = kind
            if kind in ("S_GPROC32", "S_LPROC32", "S_GPROC32_ID", "S_LPROC32_ID"):
                stack = [Node(m.group(3) or "?")]
                stack[0].fid = "proc"
            elif kind == "S_BLOCK32" and stack:
                stack.append(None)
            elif kind == "S_INLINESITE" and stack:
                stack.append("pending")
            elif kind == "S_INLINESITE_END" and stack:
                stack.pop()
            elif kind in ("S_END", "S_PROC_ID_END") and stack:
                stack.pop()
            continue
        if not stack:
            continue
        if cur in ("S_GPROC32", "S_LPROC32", "S_GPROC32_ID", "S_LPROC32_ID") and len(stack) == 1:
            a = re.search(r"addr = (\d+):(\d+)", line)
            if a:
                procs[(int(a.group(1)), int(a.group(2)))] = stack[0]
        elif cur == "S_INLINESITE" and stack[-1] == "pending":
            a = re.search(r"inlinee = (0x[0-9A-Fa-f]+) \((.*)\), parent", line)
            if a:
                n = Node(short_name(a.group(2)), int(a.group(1), 16))
                parent = next(x for x in reversed(stack[:-1]) if isinstance(x, Node))
                parent.inlines.append(n)
                stack[-1] = n
        elif cur == "S_CALLEES":
            a = re.search(r"callee: (0x[0-9A-Fa-f]+) \((.*)\)", line)
            if a:
                owner = next(x for x in reversed(stack) if isinstance(x, Node))
                owner.calls.append(short_name(a.group(2)))
    return procs


def pdb_inlinee_lines(text):
    lines = {}
    for m in re.finditer(r"^\s*(0x[0-9A-Fa-f]+) \|\s*(\d+) \| (.+?) \(MD5:", text, re.M):
        lines[int(m.group(1), 16)] = (short_path(m.group(3)), int(m.group(2)))
    return lines


# --- our side: llvm-readobj --codeview of one object --------------------------------------------------------------

def obj_dump(obj):
    """llvm-readobj --codeview of the object, streamed (a unity unit's dump is some 200 MB)."""
    proc = subprocess.Popen([readobj(), "--codeview", str(obj)], stdout=subprocess.PIPE, text=True,
                            encoding="utf-8", errors="replace")
    yield from proc.stdout
    proc.wait()


def obj_procs(lines_in):
    """({linkage name: root Node}, {inlinee id: (file, line)}) from an object's CodeView dump."""
    procs, lines, stack, kind, in_callees, il = {}, {}, [], None, False, None
    for line in lines_in:
        s = line.strip()
        m = re.match(r"Kind: (S_[A-Z0-9_]+)", s)
        if m:
            kind = m.group(1)
            in_callees = False
            if kind in ("S_GPROC32_ID", "S_LPROC32_ID", "S_GPROC32", "S_LPROC32"):
                stack = [Node("?", "proc")]
            elif kind == "S_BLOCK32" and stack:
                stack.append(None)
            elif kind == "S_INLINESITE" and stack:
                stack.append("pending")
            elif kind == "S_INLINESITE_END" and stack:
                stack.pop()
            elif kind in ("S_PROC_ID_END", "S_END") and stack:
                stack.pop()
            continue
        if s.startswith("InlineeSourceLine {"):
            il = {}
            continue
        if il is not None:
            a = re.match(r"(Inlinee|FileID): (.*) \((0x[0-9A-Fa-f]+)\)$", s)
            if a:
                il[a.group(1)] = (a.group(2), int(a.group(3), 16))
            elif s.startswith("SourceLineNum:"):
                if "Inlinee" in il and "FileID" in il:
                    lines[il["Inlinee"][1]] = (short_path(il["FileID"][0]), int(s.split(":")[1]))
                il = None
            continue
        if not stack:
            continue
        if kind in ("S_GPROC32_ID", "S_LPROC32_ID", "S_GPROC32", "S_LPROC32") and len(stack) == 1:
            if s.startswith("DisplayName:"):
                stack[0].name = s.split(":", 1)[1].strip()
            elif s.startswith("LinkageName:"):
                procs[s.split(":", 1)[1].strip()] = stack[0]
        elif kind == "S_INLINESITE" and stack[-1] == "pending":
            a = re.match(r"Inlinee: (.*) \((0x[0-9A-Fa-f]+)\)$", s)
            if a:
                n = Node(short_name(a.group(1)), int(a.group(2), 16))
                parent = next(x for x in reversed(stack[:-1]) if isinstance(x, Node))
                parent.inlines.append(n)
                stack[-1] = n
        elif kind == "S_CALLEES":
            if s.startswith("Callees ["):
                in_callees = True
            elif in_callees:
                a = re.match(r"FuncID: (.*) \((0x[0-9A-Fa-f]+)\)$", s)
                if a:
                    owner = next(x for x in reversed(stack) if isinstance(x, Node))
                    owner.calls.append(short_name(a.group(1)))
                elif s == "]":
                    in_callees = False
    return procs, lines


# --- the comparison -----------------------------------------------------------------------------------------------

def compare(ours, theirs, path, out):
    """Append (path, what, name) for every difference below a pair of matched nodes."""
    oi = Counter(n.name for n in ours.inlines)
    ti = Counter(n.name for n in theirs.inlines)
    oc, tc = Counter(ours.calls), Counter(theirs.calls)
    for name in sorted(set(oi) | set(ti) | set(oc) | set(tc)):
        if oi[name] and not ti[name]:
            out.append((path, "ATLAS calls, ours inlines" if tc[name] else "only ours inlines", name))
        elif ti[name] and not oi[name]:
            out.append((path, "ours calls, ATLAS inlines" if oc[name] else "only ATLAS inlines", name))
        elif oc[name] and not tc[name] and not ti[name]:
            out.append((path, "only ours calls", name))
        elif tc[name] and not oc[name] and not oi[name]:
            out.append((path, "only ATLAS calls", name))
    # recurse into inlinees both sides have, paired by name and file in order
    pool = {}
    for n in theirs.inlines:
        pool.setdefault(n.name, []).append(n)
    for n in ours.inlines:
        cands = pool.get(n.name) or []
        if not cands:
            continue
        pick = next((c for c in cands if c.file == n.file), None)
        if pick is None:
            pick = next((c for c in cands if c.file and n.file and c.file.rsplit("\\", 1)[-1] ==
                         n.file.rsplit("\\", 1)[-1]), cands[0])
        cands.remove(pick)
        compare(n, pick, path + (n.name,), out)


def tree(node, depth=0):
    for n in node.inlines:
        where = f"  [{n.file}:{n.line}]" if n.file else ""
        print(f"{'   ' * (depth + 1)}{n.name}{where}")
        tree(n, depth + 1)
    for c in node.calls:
        print(f"{'   ' * (depth + 1)}call {c}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("obj")
    ap.add_argument("pe")
    ap.add_argument("names", nargs="*")
    ap.add_argument("--tree", action="store_true")
    ap.add_argument("--match")
    ap.add_argument("--states", default="DIFF,SIZE")
    ap.add_argument("--top", type=int, default=30)
    a = ap.parse_args()
    names = list(a.names)
    if a.match:
        states = set(a.states.split(","))
        names += [r["name"] for r in json.loads(Path(a.match).read_text(encoding="utf-8")) if r["state"] in states]
    if not names:
        sys.exit(__doc__)
    o = Original(a.pe, CACHE)
    pdb = Path(a.pe).with_suffix(".pdb")
    ours, our_lines = obj_procs(obj_dump(a.obj))
    by_mod = {}
    totals = Counter()
    shown = differing = 0
    for name in names:
        mine, rva = ours.get(name), o.by_name.get(name)
        if rva is None or (mine is None and (a.match or not a.tree)):
            if not a.match:
                print(f"== {name}: {'not in the original' if rva is None else 'not in our object'}")
            continue
        modi = o.module_of(rva)
        if modi not in by_mod:
            procs, il = module_trees(pdb, modi)
            by_mod[modi] = ({o.seg_rva(seg, off): p for (seg, off), p in procs.items()}, il)
        theirs_by_rva, their_lines = by_mod[modi]
        theirs = theirs_by_rva.get(rva)
        if theirs is None:
            if not a.match:
                print(f"== {name}: no procedure record at {rva + o.image_base:x}")
            continue
        resolve(theirs, their_lines)
        if mine is None:
            # --tree for a function our object lacks (not ported yet): ATLAS's tree alone
            print(f"== {name}  (SRV@{rva + o.image_base:x}, not in our object)\n   -- ATLAS's:")
            tree(theirs, 1)
            continue
        resolve(mine, our_lines)
        diffs = []
        compare(mine, theirs, (), diffs)
        shown += 1
        if diffs:
            differing += 1
        for path, what, callee in diffs:
            totals[(what, callee)] += 1
        if a.match and not diffs:
            continue
        print(f"== {name}  (SRV@{rva + o.image_base:x})")
        for path, what, callee in diffs:
            where = " > ".join(path) if path else "the function itself"
            print(f"   {what}: {callee}   (in {where})")
        if a.tree:
            print("   -- ours:")
            tree(mine, 1)
            print("   -- ATLAS's:")
            tree(theirs, 1)
    if a.match:
        print(f"\n{shown} functions compared, {differing} with an inlining difference.")
        decided = Counter({k: v for k, v in totals.items() if "calls, " in k[0]})
        print(f"Inlining decisions (one side calls what the other inlines), {sum(decided.values())}:")
        for (what, callee), k in decided.most_common(a.top):
            print(f"  {k:5}  {what}: {callee}")
        print(f"Code only one side has, {sum(totals.values()) - sum(decided.values())}:")
        for (what, callee), k in Counter({k: v for k, v in totals.items() if "calls, " not in k[0]}).most_common(a.top):
            print(f"  {k:5}  {what}: {callee}")


if __name__ == "__main__":
    main()
