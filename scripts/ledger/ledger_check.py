"""Consistency checks for the tracking ledgers; runs as the git pre-commit hook.

Fails (exit 1) when:
  - a ledger row has a bad ID, binary, VA or status
  - a row at RAW or above has no raw file, or the raw file's SHA-256 differs from the ledger
  - a reimpl header (// ATLAS-ID: ...) in src/reimpl names an ID that isn't in the ledger, or a ledger
    row's reimpl_path is missing or lacks that header ("engine:<path>" = a file in our engine tree, which must cite
    the ID in a comment at the ported code; only a warning when the engine tree is not on this machine)
  - a row at HOOKED or above has no ATLAS_REPLACE registration in src/hook or src/reimpl
  - a row at VERIFIED or above has no evidence file
  - a replacement covers an unknown function or surface ID
  - a ledger row has more or fewer fields than the header, or its system is not a SYS- id (a comma left unquoted,
    a row split on bare commas: 2026-11-08)
Warns when a raw decompile exists that the ledger doesn't list yet.

--staged reads the tables from git's index (`git show :tracking/<name>.csv`, honouring GIT_INDEX_FILE) instead of the
working tree: the pre-commit hook checks what is being committed, also when a commit is composed in a private index
(2026-11-08: two such commits carried mis-split rows past the working-tree check). The raw files and sources are
still read from the working tree.

Usage: python _tools/rebuild/ledger_check.py [--quiet] [--staged]
"""
import argparse
import csv
import io
import re
import subprocess
import sys
from collections import Counter

from atlasre_common import (ALL_STATES, BINARIES, DECOMP, ENGINE, ENGINE_PREFIX, LADDER, REPO, SRC, find_raw,
                            parse_func_id, read_table, resolve_reimpl, sha256_file)

HEADER = re.compile(r"//\s*ATLAS-ID:\s*((?:SRV|CLI|EDT)@[0-9a-f]+)")
# Only code lines count: the usage example in src/hook/registry.h is a comment.
REGISTRATION = re.compile(r"^\s*ATLAS_REPLACE\(\s*(SRV|CLI|EDT)\s*,\s*0x([0-9a-fA-F]+)", re.M)


def rung(status: str) -> int:
    return LADDER.index(status) if status in LADDER else -1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--staged", action="store_true", help="check the tables in git's index, not the working tree")
    args = ap.parse_args()
    errors, warnings = [], []

    def table(name):
        if not args.staged:
            return read_table(name)
        r = subprocess.run(["git", "show", f":tracking/{name}.csv"], cwd=REPO, capture_output=True)
        if r.returncode != 0:
            return read_table(name)
        return list(csv.DictReader(io.StringIO(r.stdout.decode("utf-8"), newline="")))

    functions = table("functions")
    replacements = table("replacements")
    surfaces = table("surfaces")
    for row in functions:
        if None in row or any(v is None for v in row.values()):
            errors.append(f"{row.get('id')}: {'more' if None in row else 'fewer'} fields than the header (a comma "
                          f"unquoted or a row split on bare commas)")
        elif not row["system"].startswith("SYS-"):
            errors.append(f"{row['id']}: system '{row['system'][:40]}' is not a SYS- id")
    func_ids = {r["id"] for r in functions}
    surface_ids = {r["id"] for r in surfaces}
    # one row per ID (two rows of one function once held RAW and REIMPL at the same time, 2026-10-21 to 10-24)
    seen = Counter(r["id"] for r in functions)
    errors += [f"{fid}: {n} rows (one row per ID)" for fid, n in sorted(seen.items()) if n > 1]

    # Reimpl headers and hook registrations in src/
    headers = {}
    for path in (SRC / "reimpl").rglob("*") if (SRC / "reimpl").exists() else []:
        if path.suffix in {".cpp", ".h", ".hpp", ".cc"}:
            for m in HEADER.finditer(path.read_text(encoding="utf-8", errors="replace")):
                headers.setdefault(m.group(1), []).append(path.relative_to(REPO).as_posix())
    registered = set()
    for folder in (SRC / "hook", SRC / "reimpl"):
        for path in folder.rglob("*") if folder.exists() else []:
            if path.suffix in {".cpp", ".h", ".hpp", ".cc"}:
                for m in REGISTRATION.finditer(path.read_text(encoding="utf-8", errors="replace")):
                    registered.add(f"{m.group(1)}@{m.group(2).lower().lstrip('0') or '0'}")

    for row in functions:
        fid = row["id"]
        try:
            prefix, va = parse_func_id(fid)
        except ValueError as e:
            errors.append(str(e))
            continue
        if row["binary"] != BINARIES[prefix][0]:
            errors.append(f"{fid}: binary '{row['binary']}' should be '{BINARIES[prefix][0]}'")
        if row["va"] != va:
            errors.append(f"{fid}: va column '{row['va']}' doesn't match the ID")
        if row["status"] not in ALL_STATES:
            errors.append(f"{fid}: unknown status '{row['status']}'")
            continue
        level = rung(row["status"])
        if level >= rung("RAW") or row["status"] in ("STUBBED", "DEAD"):
            raw = find_raw(fid)
            if raw is None:
                errors.append(f"{fid}: status {row['status']} but no raw file in {DECOMP.relative_to(REPO)}")
            elif row["raw_sha256"] != sha256_file(raw):
                errors.append(f"{fid}: raw file {raw.name} changed (SHA-256 differs from ledger) — raw files are never hand-edited")
        if row["reimpl_path"]:
            path = row["reimpl_path"]
            p = resolve_reimpl(path)
            in_engine = path.startswith(ENGINE_PREFIX)
            if in_engine and not ENGINE.exists():
                warnings.append(f"{fid}: engine tree {ENGINE} not found, {path} not checked")
            elif not p.exists():
                errors.append(f"{fid}: reimpl_path {path} does not exist")
            elif in_engine:
                # Engine files cite the ID in a comment at the ported code, e.g. "// ATLAS (SRV@141a895a0): ..."
                if fid not in p.read_text(encoding="utf-8", errors="replace"):
                    errors.append(f"{fid}: {path} does not cite {fid}")
            elif fid not in headers or path not in headers[fid]:
                errors.append(f"{fid}: {path} lacks the '// ATLAS-ID: {fid}' header")
        if level >= rung("REIMPL") and not row["reimpl_path"]:
            errors.append(f"{fid}: status {row['status']} needs reimpl_path")
        if level >= rung("HOOKED") and fid not in registered:
            errors.append(f"{fid}: status {row['status']} but no ATLAS_REPLACE registration in src/hook")
        if level >= rung("VERIFIED"):
            ev = row["evidence"]
            if not ev or not (REPO / ev).exists():
                errors.append(f"{fid}: status {row['status']} needs an evidence file (tracking/evidence/{fid}.md)")

    for fid, paths in headers.items():
        if fid not in func_ids:
            errors.append(f"{fid}: reimpl header in {', '.join(paths)} but no ledger row")

    for rep in replacements:
        for cid in filter(None, (c.strip() for c in rep["covers"].split(";"))):
            if cid not in func_ids and cid not in surface_ids:
                errors.append(f"{rep['rep']}: covers unknown ID {cid}")

    listed = {(r["id"].split("@")[0], r["va"]) for r in functions}
    for prefix, (_, folder, _) in BINARIES.items():
        for raw in sorted((DECOMP / folder).glob("*@*.c")):
            va = raw.stem.rsplit("@", 1)[1]
            if (prefix, va) not in listed:
                warnings.append(f"{prefix}@{va}: raw file {raw.name} not in ledger")

    if warnings and not args.quiet:
        print(f"{len(warnings)} warning(s):")
        for w in warnings[:20]:
            print("  warn:", w)
        if len(warnings) > 20:
            print(f"  ... and {len(warnings) - 20} more")
    for e in errors:
        print("  ERROR:", e)
    print(f"ledger_check: {len(functions)} functions, {len(replacements)} replacements, {len(surfaces)} surfaces — "
          f"{len(errors)} error(s), {len(warnings)} warning(s)")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
