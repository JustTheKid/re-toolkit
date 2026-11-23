"""regress.py: rebuild and re-judge every ported game unit, and report each ledger row that was `match` and is not any
more (2026-11-04, the tool pass: the bulk headers change every unit's precompiled header, so a header change is
checked against all the units at once, not only the one in hand).

For each game source in the ledger's reimpl_path column (src/reimpl/ShooterGame/Source/ShooterGame/Private/<File>.cpp):
unit_loop.py build + judge (the unit's own command line, through its PCH), then each row of that file with parity
`match` must be MATCH, MATCH~ or MATCH-L again (by the original's address, else by name). Writes
build/loop/regress.tsv (unit, id, ledger parity, verdict now) and prints a line per unit.

Usage: python _tools/rebuild/regress.py [--only <regex on the file name>] [--no-build]
"""
import argparse
import csv
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "_tools"))
from unit_loop import load_verdicts  # noqa: E402

PY = sys.executable
SRC = "src/reimpl/ShooterGame/Source/ShooterGame/Private/"
MAP = r"d:\atlassvn\projects\shootergame\source=" + str(ROOT / "src" / "reimpl" / "ShooterGame" / "Source")
OK = {"MATCH", "MATCH~", "MATCH-L"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="a regex on the source file names")
    ap.add_argument("--no-build", action="store_true", help="judge the objects already built")
    a = ap.parse_args()
    rows = list(csv.DictReader(open(ROOT / "tracking" / "functions.csv", encoding="utf-8", newline="")))
    units = sorted({r["reimpl_path"] for r in rows if r["reimpl_path"].startswith(SRC) and r["reimpl_path"].endswith(".cpp")})
    if a.only:
        units = [u for u in units if re.search(a.only, u)]
    out, total_bad = [], 0
    for u in units:
        name = Path(u).name
        # anchored: CustomCanvasWidget.cpp.obj is also the tail of SCustomCanvasWidget.cpp.obj (2026-11-08, the
        # seventeenth unit's regression: unit_loop.py refuses a regex that matches two objects)
        unit_rx = r"(^|[^A-Za-z_])" + re.escape(name) + r"\.obj"
        work = ROOT / "build" / "loop" / name
        if not a.no_build:
            r = subprocess.run([PY, str(HERE / "unit_loop.py"), unit_rx, "build", "--source", str(ROOT / u), "--map", MAP],
                               cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
            if r.returncode != 0:
                print(f"{name}: BUILD FAILED (see {work.relative_to(ROOT)}\\*.log)")
                out.append((name, "-", "-", "build failed"))
                total_bad += 1
                continue
        r = subprocess.run([PY, str(HERE / "unit_loop.py"), unit_rx, "judge"], cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        verdicts = load_verdicts(work / "match.json")
        # bodies without a public name that the unit's port judged by address (a scratchpad verdict script wrote
        # extra-verdicts.json {va: verdict}): the judge's name lookup cannot find them (2026-11-08, the twelfth unit)
        by_address = {}
        if (work / "extra-verdicts.json").exists():
            import json
            # re-judged now by unit_extras.py (2026-11-08, the fifteenth unit), which rewrites extra-verdicts.json from
            # this build's object; a unit without its extra-vas.txt keeps the verdicts its port wrote
            if (work / "extra-vas.txt").exists():
                subprocess.run([PY, str(HERE / "unit_extras.py"), "verdicts", name, "--quiet"], cwd=ROOT, capture_output=True,
                               text=True, encoding="utf-8", errors="replace")
            by_address = {k.lower(): v for k, v in json.loads((work / "extra-verdicts.json").read_text(encoding="utf-8")).items()}
        mine = [x for x in rows if x["reimpl_path"] == u and x["parity"] == "match"]
        bad, lam, addr = [], [], []
        for x in mine:
            rva = int(x["va"], 16) - 0x140000000 if x["va"] else None
            v = verdicts.get(rva) or verdicts.get(x["symbol"]) or "MISSING"
            if v == "MISSING" and x["va"].lower() in by_address and by_address[x["va"].lower()] != "unpaired":
                # unit_extras.py's verdict at the original's address comes first: since the eighteenth unit it pairs a
                # lambda no hash pairs by judging our loose lambda bodies there (2026-11-08)
                addr.append(x["id"])
                v = by_address[x["va"].lower()]
                if v not in OK:
                    bad.append((x["id"], v, x["symbol"]))
            elif v == "MISSING" and "lambda" in x["symbol"]:
                # a lambda's hashed name is ours, not ATLAS's: the judge pairs it by name only when the hashes agree,
                # the port paired it by address (disasm_obj.py --at); listed apart, to check that way
                lam.append(x["id"])
                v = "UNPAIRED-LAMBDA"
            elif v not in OK:
                bad.append((x["id"], v, x["symbol"]))
            out.append((name, x["id"], "match", v))
        total_bad += len(bad)
        print(f"{name}: {len(mine) - len(bad) - len(lam)} of {len(mine)} match rows still match"
              + (f" ({len(addr)} of them bodies without a public name, judged at their address by unit_extras.py)" if addr else "")
              + (f"; {len(lam)} lambda pieces paired by address before (check with disasm_obj.py --at): {', '.join(lam[:6])}" if lam else "")
              + (f"; LOST {len(bad)}: " + ", ".join(f"{i} {v}" for i, v, s in bad[:6]) if bad else ""))
    (ROOT / "build" / "loop" / "regress.tsv").write_text("unit\tid\tledger\tnow\n" + "".join("\t".join(r) + "\n" for r in out),
                                                         encoding="utf-8")
    sys.exit(1 if total_bad else 0)


if __name__ == "__main__":
    main()
