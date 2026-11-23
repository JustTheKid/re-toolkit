"""unit_lines.py <unit regex>: which source file the original PDB's line table attributes each function of a compile
unit to — the home of the inline functions a unit emits (a struct's constructor in Classes\\PrimalGameData.h, the
delegates' bodies in ShooterGameMode.h ...), the evidence for where the port's headers define them. Reads
`llvm-pdbutil dump -l -modi N` for the unit's module, maps every address range to the PDB's public at that address
(or the nearest one below it, with the offset) and prints, per file, the functions it holds, then per public its
file(s). Ranges with no public of the unit (code the linker folded into another module's copy, static functions)
are listed by address. 2026-10-31 (P6, the second unit; the lesson: CustomGameMode.cpp.obj's line table named the
nine game headers the unit saw and put FTribeData's constructor in PrimalGameData.h, not ShooterTypes.h).
Usage: python _tools/rebuild/unit_lines.py "CustomGameMode\\.cpp\\.obj" [--theirs <exe>] [--all]"""
import argparse
import collections
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from func_match import REPO, Original  # noqa: E402
from pdb_source_md5 import pdbutil  # noqa: E402
from reach_record import pdb_modules  # noqa: E402
from unit_loop import BASE, THEIRS  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("unit")
    ap.add_argument("--theirs", default=str(THEIRS))
    ap.add_argument("--all", action="store_true", help="list every file's functions, not only the game's and the unit's")
    a = ap.parse_args()
    rx = re.compile(a.unit)
    mods = pdb_modules(a.theirs)
    items = list(mods.items()) if isinstance(mods, dict) else list(enumerate(mods))
    hits = [(int(i), str(m)) for i, m in items if rx.search(str(m))]
    if len(hits) != 1:
        sys.exit(f"{len(hits)} modules match {a.unit!r}: {[h[1][-60:] for h in hits[:5]]}")
    modi, module = hits[0]
    pdb = str(Path(a.theirs).with_suffix(".pdb"))
    dump = subprocess.run([pdbutil(), "dump", "-l", "-modi", str(modi), pdb], capture_output=True, text=True,
                          errors="replace").stdout
    orig = Original(a.theirs, str(REPO / "_re" / "cache"))
    # the unit's own functions: the PDB's publics whose contribution lies in this module
    text_base = 0x1000  # section 1's RVA (the server's .text)
    per_file, per_func, cur = collections.OrderedDict(), collections.defaultdict(collections.Counter), None
    for l in dump.splitlines():
        m = re.match(r"^([A-Za-z]:\\.*?) \(MD5", l)
        if m:
            cur = m.group(1).lower()
            per_file.setdefault(cur, [])
            continue
        m = re.match(r"\s+0001:([0-9A-F]{8})-([0-9A-F]{8}), line/addr entries = (\d+)", l)
        if m and cur:
            rva = int(m.group(1), 16) + text_base
            names, delta = orig.names_at(rva)
            name = (names[0] if names else f"<{BASE + rva:x}>") + (f"+0x{delta:x}" if delta else "")
            per_file[cur].append(name)
            per_func[name][cur] += 1
    print(f"module {modi}: {module}")
    game = [f for f in per_file if "\\projects\\" in f]
    for f, names in per_file.items():
        short = f.rsplit("\\", 1)[-1]
        c = collections.Counter(names)
        print(f"== {short}: {len(names)} ranges, {len(c)} functions" + ("" if f in game or a.all else " (engine: names not listed)"))
        if f in game or a.all:
            for n, k in c.most_common():
                print(f"   {k:3} {n[:120]}")


if __name__ == "__main__":
    main()
