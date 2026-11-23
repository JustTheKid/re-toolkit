"""Print the full traceability chain for one ID.

  trace.py SRV@1426140a0     function: ledger row, raw file + hash check, annotations, docs, reimpl,
                             hook registration, toggle, tests, evidence, commits
  trace.py REP-0001          replacement row, covered IDs, docs, commits
  trace.py SVC-auth-arkdedicated / BUG-0001 / Q-0001 / SYS-... / FMT-...   registry row (if any), docs, commits
"""
import re
import sys

from atlasre_common import (ANNOTATIONS, BINARIES, DOCS, REPO, SRC, find_raw, git, parse_func_id, read_table,
                            sha256_file)


def section(title):
    print(f"\n== {title}")


def grep(root, needle, exts=(".md", ".cpp", ".h", ".hpp", ".py", ".ini", ".csv", ".jsonl")):
    hits = []
    if not root.exists():
        return hits
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in exts:
            for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if needle in line:
                    hits.append(f"{path.relative_to(REPO).as_posix()}:{n}: {line.strip()[:140]}")
    return hits


def show(lines, empty="(none)"):
    for line in lines or [empty]:
        print("  " + line)


def commits(tid):
    out = git("log", "--format=%h %ad %s", "--date=short", f"--grep=Atlas-Id: {tid}", f"--grep=Atlas-Rep: {tid}")
    mentions = git("log", "--format=%h %ad %s", "--date=short", f"--grep={tid}", "--fixed-strings")
    lines = list(dict.fromkeys((out + "\n" + mentions).splitlines()))
    return [line for line in lines if line.strip()]


def trace_function(fid):
    prefix, va = parse_func_id(fid)
    row = next((r for r in read_table("functions") if r["id"] == fid), None)
    section(f"{fid} ledger")
    if row:
        for k, v in row.items():
            if v:
                print(f"  {k:12} {v}")
    else:
        print("  not in ledger (UNTOUCHED)")
    section("raw decompile")
    raw = find_raw(fid)
    if raw:
        actual = sha256_file(raw)
        state = "matches ledger" if row and row["raw_sha256"] == actual else "DIFFERS from ledger" if row else "no ledger hash"
        print(f"  {raw.relative_to(REPO).as_posix()}  sha256 {actual[:16]}…  ({state})")
    else:
        print("  (none)")
    section("annotations")
    show(grep(ANNOTATIONS, fid))
    section("docs")
    needles = [fid] + ([row["symbol"]] if row and row["symbol"] else [])
    show(sorted({h for n in needles for h in grep(DOCS, n)}))
    section("reimplementation")
    show(grep(SRC / "reimpl", f"ATLAS-ID: {fid}"))
    section("hook registration / toggle")
    show(grep(SRC / "hook", f"0x{va}") + grep(REPO, f"{fid}=", exts=(".ini",)))
    section("tests / evidence")
    show(grep(REPO / "tests", fid) + [p.relative_to(REPO).as_posix() for p in (REPO / "tracking" / "evidence").glob(f"{fid}*")])
    section("commits")
    show(commits(fid))


def trace_other(tid):
    tables = {"REP": ("replacements", "rep"), "SVC": ("surfaces", "id")}
    kind = tid.split("-")[0]
    if kind in tables:
        name, key = tables[kind]
        row = next((r for r in read_table(name) if r[key] == tid), None)
        section(f"{tid} {name}.csv")
        if row:
            for k, v in row.items():
                if v:
                    print(f"  {k:12} {v}")
            if kind == "REP":
                section("covers")
                show([c.strip() for c in row["covers"].split(";") if c.strip()])
        else:
            print("  (no row)")
    section("docs")
    show(grep(DOCS, tid))
    section("code / tests")
    show(grep(SRC, tid) + grep(REPO / "tests", tid))
    section("commits")
    show(commits(tid))


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    tid = sys.argv[1]
    if re.match(r"^(SRV|CLI|EDT)@", tid):
        trace_function(tid)
    else:
        trace_other(tid)


if __name__ == "__main__":
    main()
