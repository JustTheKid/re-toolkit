"""Rebuild one of ATLAS's unity compile units (Module.<Module>.N_of_M.cpp) from the PDB, so the byte-matching judge can
compare hand-written engine code too, not only the generated units. The PDB's file list of the unit (llvm-pdbutil dump
-files -modi N) names every .cpp it included; UnrealBuildTool 4.5 sorted a module's files by their lower-case absolute
path and packed them into unity files in that order, so the includes are written in that order, each mapped onto our
engine tree (the default maps of recompile_unit.py, real case from the directory listing). Files we do not have (ATLAS's
own) are left out and listed. recompile_unit.py --source then compiles it with ATLAS's command line for func_match.py.

Usage: python -I _tools/unity_unit.py <original pe> (<compile unit regex> | --at <hex VA>) --out <dir>
  --at  the unit whose code holds this address (the PDB's section contributions), e.g. --at 141945960 for
        AActor::RegisterActorTickFunctions -> Module.Engine.1_of_26.cpp
Writes <out>/<unit>.cpp (e.g. Module.Engine.1_of_26.cpp) and prints the unit's regex and the recompile_unit.py line.
2026-10-25 (phase 4d, step 1.11's signature batch: Actor.cpp and the components are in ATLAS's Module.Engine units).
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pdb_buildinfo  # noqa: E402
from pdb_source_md5 import pdbutil  # noqa: E402
from recompile_unit import MAPS, map_path  # noqa: E402

_listings = {}


def real_case(path):
    """The path as our file system spells it (the PDB's paths are lower case), or None if it does not exist."""
    p = Path(path)
    parts = p.parts
    cur = Path(parts[0].upper())
    for part in parts[1:]:
        key = str(cur)
        if key not in _listings:
            try:
                _listings[key] = {n.lower(): n for n in os.listdir(cur)}
            except OSError:
                return None
        name = _listings[key].get(part.lower())
        if name is None:
            return None
        cur = cur / name
    return cur


def unit_files(pdb, modi):
    out = subprocess.run([pdbutil(), "dump", "-files", "-modi", str(modi), str(pdb)], capture_output=True, text=True,
                         encoding="utf-8", errors="replace").stdout
    return [m.group(1).strip() for m in re.finditer(r"\(MD5: [0-9A-F]+\) (.+)$", out, re.M)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("unit", nargs="?")
    ap.add_argument("--at")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    pdb = Path(a.binary).with_suffix(".pdb")
    mods = pdb_buildinfo.modules(pdb)
    if a.at:
        from func_match import Original
        o = Original(a.binary, Path(__file__).resolve().parent.parent / "_re" / "cache")
        modi = o.module_of(int(a.at, 16) - o.image_base)
        if modi is None:
            sys.exit(f"no section contribution holds {a.at}")
        obj = dict(mods)[modi]
    else:
        hits = [(i, o) for i, o in mods if re.search(a.unit, o, re.I)]
        if len(hits) != 1:
            sys.exit(f"{len(hits)} compile units match; make the pattern unique")
        modi, obj = hits[0]
    unit = re.split(r"[\\/]", obj)[-1].removesuffix(".obj")
    own = obj.lower().removesuffix(".obj")
    cpps = sorted({f.lower() for f in unit_files(pdb, modi) if f.lower().endswith(".cpp") and f.lower() != own})
    maps = [(x.lower(), y) for x, y in MAPS]
    found, missing = [], []
    for f in cpps:
        ours = real_case(map_path(f, maps))
        (found if ours else missing).append(ours or f)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    lines = [f"// ATLAS's {unit} rebuilt by _tools/unity_unit.py from the server PDB's file list (module {modi}),",
             "// in UnrealBuildTool's order (lower-case path), mapped onto our engine tree."]
    if missing:
        lines.append(f"// Not in our tree ({len(missing)}): " + ", ".join(Path(m).name for m in missing))
    lines += [f'#include "{p}"' for p in found]
    path = out / unit
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{obj}\n{len(found)} of {len(cpps)} files included, {len(missing)} not in our tree; wrote {path}")
    for m in missing:
        print("   missing", m)
    rx = re.escape(unit + ".obj").replace("\\_", "_") + "$"
    print(f"recompile: python -I _tools/recompile_unit.py {a.binary} '{rx}' --source \"{path}\" --out <dir>")


if __name__ == "__main__":
    main()
