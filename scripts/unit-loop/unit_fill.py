"""unit_fill.py <skeleton.cpp> <prelude.cpp> <bodies dir> <out .cpp>: the port's file from unit_skeleton.py's skeleton
and bodies written in batches. A bodies file (any *.cpp in the dir, read in name order) holds chunks, each opened by
`//@ SRV@<va>`; in a chunk, a line `=sig <signature>` replaces the skeleton's signature, other lines before the first
`{` are comments placed after the block's header lines, and the rest (from the first line that is `{`) is the body.
A chunk `//@ TOP` is free text placed after the prelude (file statics, helpers); `//@ END` free text at the end.
The skeleton's blocks without a body are written as before (an empty body) and counted; --strict fails on them.
2026-11-08 (P6, the fourteenth unit PrimalCharacter.cpp: 474 bodies in batches instead of one edit each).
Usage: python _tools/rebuild/unit_fill.py build/loop/PrimalCharacter.cpp/skeleton.cpp <prelude> <dir> <out> [--strict | --omit-empty]"""
import re
import sys
from pathlib import Path


def parse_bodies(d):
    chunks, top, end = {}, [], []
    for f in sorted(Path(d).glob("*.cpp")):
        cur, buf = None, []
        for line in f.read_text(encoding="utf-8").replace("\r\n", "\n").split("\n") + ["//@ __EOF__"]:
            m = re.match(r"^//@ (SRV@[0-9a-f]+|TOP|END|__EOF__)\s*$", line)
            if m:
                if cur:
                    while buf and not buf[-1].strip():
                        buf.pop()
                    if cur == "TOP":
                        top += buf + [""]
                    elif cur == "END":
                        end += [""] + buf
                    else:
                        if cur in chunks:
                            sys.exit(f"{f.name}: {cur} twice")
                        chunks[cur] = buf
                cur, buf = m.group(1), []
                continue
            if cur:
                buf.append(line)
    return chunks, top, end


def main():
    a = [x for x in sys.argv[1:] if not x.startswith("--")]
    strict = "--strict" in sys.argv
    omit = "--omit-empty" in sys.argv  # a partial port that compiles: the blocks without a body left out
    skel, prelude, bodies, out = a
    chunks, top, end = parse_bodies(bodies)
    lines = Path(skel).read_text(encoding="utf-8").split("\n")
    res = Path(prelude).read_text(encoding="utf-8").rstrip("\n").split("\n") + [""] + top
    i, used, empty = 1, set(), []  # line 0 is the skeleton's own comment
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^// ATLAS-ID: (SRV@[0-9a-f]+)", line)
        if not m:
            if line.startswith("// the unit's other functions"):
                res += lines[i:]
                break
            res.append(line)
            i += 1
            continue
        rid = m.group(1)
        hdr = [lines[i], lines[i + 1], lines[i + 2]]  # ID, raw, deviations
        sig = lines[i + 3]
        assert lines[i + 4] == "{" and lines[i + 5] == "}", (rid, lines[i + 4:i + 6])
        i += 6
        if rid not in chunks:
            empty.append(rid)
            if not omit:
                res += hdr + [sig, "{", "}"]
            elif res and res[-1] == "":
                res.pop()
            continue
        used.add(rid)
        ch = chunks[rid]
        k = next((n for n, l in enumerate(ch) if l == "{"), None)
        if k is None:
            sys.exit(f"{rid}: no body (a line that is just '{{')")
        comments = [l for l in ch[:k] if not l.startswith("=sig ")]
        sigs = [l[5:] for l in ch[:k] if l.startswith("=sig ")]
        res += hdr[:2] + comments + [hdr[2]] + [sigs[0] if sigs else sig] + ch[k:]
    unknown = sorted(set(chunks) - used)
    if unknown:
        sys.exit(f"bodies for IDs not in the skeleton: {unknown[:10]}")
    res += end
    Path(out).write_text("\n".join(res).rstrip("\n") + "\n", encoding="utf-8", newline="\n")
    print(f"{out}: {len(used)} bodies, {len(empty)} empty")
    if strict and empty:
        sys.exit(f"empty: {empty[:20]}")


if __name__ == "__main__":
    main()
