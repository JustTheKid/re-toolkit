"""The type names our engine declares (classes, structs, unions, enums and the namespaces of namespaced enums), from
the headers of D:\\UE\\4.5.1\\Engine\\Source and the generated ones under Intermediate\\Build\\Win64\\Inc: the --known list
of gen_headers.py, so that a game unit's layout header references the engine's types instead of re-emitting them.
Usage: python _tools/rebuild/engine_types.py [--engine D:\\UE\\4.5.1\\Engine] [--out build/loop/common/engine-types.txt]
One name per line, sorted; ~16,500 names in 75 s (2026-10-31, P6's second unit)."""
import argparse
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unit_loop import KNOWN_TYPES  # noqa: E402

RX_TYPE = re.compile(r'^\s*(?:class|struct|union)\s+(?:[A-Z_0-9]+_API\s+)?([A-Za-z_]\w*)\s*(?:final\s*)?(?::|\{|;|$)', re.M)
RX_NS = re.compile(r'\bnamespace\s+([A-Za-z_]\w*)')
RX_ENUM = re.compile(r'\benum\s+(?:class\s+)?([A-Za-z_]\w*)')
SKIP = {"_API", "Type", "std"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default=r"D:\UE\4.5.1\Engine")
    ap.add_argument("--out", default=str(KNOWN_TYPES))
    a = ap.parse_args()
    t = time.time()
    names, files = set(), 0
    for root in (Path(a.engine) / "Source", Path(a.engine) / "Intermediate" / "Build" / "Win64" / "Inc"):
        for d, _, fs in os.walk(root):
            for f in fs:
                if f.endswith((".h", ".inl", ".hpp")):
                    files += 1
                    try:
                        s = open(os.path.join(d, f), encoding="utf-8", errors="replace").read()
                    except OSError:
                        continue
                    names.update(RX_TYPE.findall(s))
                    names.update(RX_NS.findall(s))
                    names.update(RX_ENUM.findall(s))
    names -= SKIP
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(sorted(names)) + "\n", encoding="utf-8")
    print(f"{out}: {len(names)} names from {files} headers, {time.time() - t:.0f} s")


if __name__ == "__main__":
    main()
