"""Two judge runs compared function by function: for every unit both runs judged (judge_module.ps1 folders, or two
match.json files), the functions that became byte-identical, the ones that stopped being so (a regression to look
at before committing), and the per-unit counts.

Usage: python -I _tools/judge_compare.py <before> <after> [--names REGEX] [--list N]
  before / after  a judge_module.ps1 output folder (one sub-folder per unit with match.json) or one match.json
  --names         only functions whose decorated name matches
  --list          how many gained / lost names to print per unit (default 25)
2026-10-25 (phase 4b step 1.11: the check after each batch).
"""
import argparse
import json
import re
from pathlib import Path

IDENT = ("MATCH", "MATCH~", "MATCH-L")  # MATCH-L: Q-0017, accepted as matching


def runs(path):
    p = Path(path)
    if p.is_file():
        return {p.parent.name: p}
    return {d.name: d / "match.json" for d in sorted(p.iterdir()) if (d / "match.json").exists()}


def states(path, rx):
    return {r["name"]: r["state"] for r in json.loads(Path(path).read_text(encoding="utf-8"))
            if not rx or rx.search(r["name"])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument("--names")
    ap.add_argument("--list", type=int, default=25)
    a = ap.parse_args()
    rx = re.compile(a.names) if a.names else None
    b, c = runs(a.before), runs(a.after)
    if len(b) == 1 and len(c) == 1:
        b, c = {"run": next(iter(b.values()))}, {"run": next(iter(c.values()))}
    tg = tl = 0
    for unit in sorted(set(b) & set(c)):
        sb, sc = states(b[unit], rx), states(c[unit], rx)
        ib = sum(s in IDENT for s in sb.values())
        ic = sum(s in IDENT for s in sc.values())
        gained = sorted(n for n, s in sc.items() if s in IDENT and sb.get(n) not in IDENT and n in sb)
        lost = sorted(n for n, s in sb.items() if s in IDENT and sc.get(n) not in IDENT and n in sc)
        new = sorted(n for n in sc if n not in sb)
        tg += len(gained)
        tl += len(lost)
        print(f"== {unit}: byte-identical {ib} -> {ic} ({ic - ib:+d}); gained {len(gained)}, lost {len(lost)}, "
              f"only in the second run {len(new)}")
        for n in gained[:a.list]:
            print(f"   + {n[:150]}")
        for n in lost[:a.list]:
            print(f"   - {n[:150]}  ({sb[n]} -> {sc[n]})")
    for unit in sorted(set(b) ^ set(c)):
        print(f"== {unit}: only in {'the first' if unit in b else 'the second'} run")
    print(f"total: gained {tg}, lost {tl}")


if __name__ == "__main__":
    main()
