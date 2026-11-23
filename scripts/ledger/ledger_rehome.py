"""ledger_rehome.py: point each ledger row whose reimpl_path is a game header without its `// ATLAS-ID:` line at the
header that has it now (2026-11-07: the generated headers move types between headers - an inline body's ID line moves
with its type). Only reimpl_path changes; every other byte of the ledger stays.

Usage: python _tools/rebuild/ledger_rehome.py [--dry-run]      (or import rehome(text) -> (text, changes))
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "tracking" / "functions.csv"
GAME = ROOT / "src" / "reimpl" / "ShooterGame" / "Source" / "ShooterGame"


def id_homes():
    homes = {}
    for p in sorted(list((GAME / "Classes").glob("*.h")) + list((GAME / "Public").glob("*.h")) + list((GAME / "Private").glob("*.cpp"))):
        for m in re.finditer(r"// ATLAS-ID: (SRV@[0-9a-f]+)", p.read_text(encoding="utf-8", errors="replace")):
            homes.setdefault(m.group(1), p.relative_to(ROOT).as_posix())
    return homes


def rehome(text):
    nl = "\r\n" if "\r\n" in text else "\n"
    homes = id_homes()
    prefix = (GAME / "Classes").relative_to(ROOT).as_posix() + "/"
    out, changes = [], []
    for l in text.split(nl):
        i = l.split(",", 1)[0]
        m = re.search(r",(" + re.escape(prefix) + r"[^,]+\.h),", l)
        if m and i in homes and homes[i] != m.group(1):
            text_now = (ROOT / m.group(1)).read_text(encoding="utf-8", errors="replace") if (ROOT / m.group(1)).exists() else ""
            if f"// ATLAS-ID: {i}" not in text_now:
                l = l.replace("," + m.group(1) + ",", "," + homes[i] + ",", 1)
                changes.append((i, m.group(1), homes[i]))
        out.append(l)
    return nl.join(out), changes


def main():
    t = LEDGER.read_bytes().decode("utf-8")
    n, ch = rehome(t)
    for c in ch:
        print("  ", *c)
    print(f"{len(ch)} rows repointed")
    if ch and "--dry-run" not in sys.argv:
        LEDGER.write_bytes(n.encode("utf-8"))


if __name__ == "__main__":
    main()
