"""DevKit module diff, step 1: the census. Every module of our engine whose UHT output has reflected classes, structs
or enums and that the server does not ship, with its DevKit editor DLL, whether the DLL has a PDB, and whether it is
in the devkit Ghidra project yet. Writes <work>/modules.tsv (module, types, enums, dll, pdb|nopdb, in|new; the last
three empty without a DevKit DLL), which the other steps read. Static: no Ghidra, no build.

Usage: python -I _tools/devkit_diff/census.py --work <dir> [--modules AnimGraph,Paper*] [--all-modules]
       [--dll-root <AtlasModKit>/Engine] [--engine D:/UE/4.5.1] [--server-corpus _re/corpus/server]
       [--project _re/ghidra-devkit --name devkit]
  --modules      names or wildcards, comma separated, case-insensitive (default: all)
  --all-modules  also the modules the server ships (Engine, UMG, AIModule, ...: their editor-only members, step 1.9a)
The counts are ours at census time; diffs.py recounts after a port. Step 1.9d, 2026-10-23: 67 modules, 65 with a
DevKit DLL, 18 of them without a PDB.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devkit_modules import (DLL_ROOT, ENGINE, PROJECT, PROJECT_NAME, SERVER_CORPUS, inc_root, our_counts,  # noqa: E402
                            selector, write_census)


def find_dll(root, module):
    dll = root / "Binaries" / "Win64" / f"UE4Editor-{module}.dll"
    if dll.exists():
        return dll
    hits = sorted(root.glob(f"Plugins/**/Binaries/Win64/UE4Editor-{module}.dll"))
    return hits[0] if hits else None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work", required=True)
    ap.add_argument("--modules")
    ap.add_argument("--all-modules", action="store_true")
    ap.add_argument("--dll-root", default=str(DLL_ROOT))
    ap.add_argument("--engine", default=str(ENGINE))
    ap.add_argument("--server-corpus", default=str(SERVER_CORPUS))
    ap.add_argument("--project", default=str(PROJECT))
    ap.add_argument("--name", default=PROJECT_NAME)
    args = ap.parse_args()
    wanted, pats = selector(args.modules)
    root = Path(args.dll_root)
    if not (root / "Binaries" / "Win64").is_dir():
        raise SystemExit(f"--dll-root {root}: no Binaries/Win64 (give the DevKit's Engine folder)")
    inc = inc_root(args.engine)
    server = {p.name[len("_reflection_"):].lower() for p in Path(args.server_corpus).glob("_reflection_*")}
    index = Path(args.project) / f"{args.name}.rep" / "idata" / "~index.dat"
    index = index.read_bytes() if index.exists() else b""

    rows, seen = [], set()
    dirs = [d for d in list(inc.iterdir()) + list((inc / "Plugins").iterdir()) if d.is_dir()]
    for d in sorted(dirs, key=lambda p: p.name.lower()):
        m = d.name
        if m in seen or not wanted(m) or (m.lower() in server and not args.all_modules):
            continue
        types, enums = our_counts(d)
        if not types and not enums:
            continue
        seen.add(m)
        dll = find_dll(root, m)
        rows.append({"module": m, "types": len(types), "enums": enums, "dll": str(dll) if dll else "",
                     "pdb": ("pdb" if dll.with_suffix(".pdb").exists() else "nopdb") if dll else "",
                     "ghidra": ("in" if dll.name.encode() in index else "new") if dll else ""})

    write_census(args.work, rows)
    with_dll = [r for r in rows if r["dll"]]
    print(f"{len(rows)} modules, {sum(r['types'] for r in rows)} types, {sum(r['enums'] for r in rows)} enums; "
          f"{len(rows) - len(with_dll)} without DevKit DLL; {sum(r['pdb'] == 'nopdb' for r in with_dll)} DLLs without "
          f"PDB; {sum(r['ghidra'] == 'new' for r in with_dll)} to import -> {Path(args.work) / 'modules.tsv'}")
    for r in rows:
        if r["pdb"] != "pdb":
            print("  ", r["module"], f"no PDB: {r['dll']}" if r["dll"] else "no DevKit DLL")
    for p in pats:
        if not any(selector(p)[0](r["module"]) for r in rows):
            print(f"  no module with reflected types matches {p!r}")


if __name__ == "__main__":
    main()
