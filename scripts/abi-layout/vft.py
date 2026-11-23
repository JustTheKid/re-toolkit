"""vft.py: a class's primary vftable in the original, slot by slot, and against MSVC's layout of ours (2026-11-07).

  vft.py dump <Class> [--pe <exe|dll>] [--from N] [--to N]   every slot: index, offset, target, the names there
  vft.py align <Class> <layout.txt>                          our slots (cl /d1reportSingleClassLayout<Class> output)
                                                             found by function name in the server's table; prints
                                                             where the shift changes and the original slots between

The primary table is the one whose first entry is the class's own deleting destructor (`??_G<Class>@@U` /
`??_E<Class>@@U`, not an adjustor thunk): the plain `??_7<Class>@@6B@` name is checked too, it is not always the
primary (APrimalStructure's holds APrimalStructureItemContainer's functions). `--pe` reads another PE with its PDB,
e.g. the DevKit's UE4Editor-UMG.dll, whose editor build names slots the server folds into shared bodies (UWidget's
UseCustomToolTip / AllowDragging / GetCustomToolTipBlueprintOverride, 2026-11-07)."""
import argparse
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from func_match import Original  # noqa: E402

SERVER = r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe"
CACHE = str(Path(__file__).resolve().parents[2] / "_re" / "cache")


def primary(o, cls):
    plain = o.by_name.get(f"??_7{cls}@@6B@")
    vs = sorted(r for k, r in o.by_name.items() if k.startswith(f"??_7{cls}@@6B"))
    for r in ([plain] if plain is not None else []) + vs:
        first = struct.unpack("<Q", o.read(r, 8))[0] - o.image_base
        if any(k.startswith((f"??_G{cls}@@U", f"??_E{cls}@@U")) for k in o.names_at(first)[0]):
            return r
    return plain


def slots(o, cls, a=0, b=4000):
    v = primary(o, cls)
    if v is None:
        sys.exit(f"no vftable for {cls}")
    out = []
    for i in range(a, b):
        t = struct.unpack("<Q", o.read(v + 8 * i, 8))[0] - o.image_base
        if not (0 < t < 0x10000000):
            break
        out.append((i, t, o.names_at(t)[0]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["dump", "align"])
    ap.add_argument("cls")
    ap.add_argument("layout", nargs="?")
    ap.add_argument("--pe", default=SERVER)
    ap.add_argument("--from", dest="a", type=int, default=0)
    ap.add_argument("--to", dest="b", type=int, default=4000)
    x = ap.parse_args()
    o = Original(x.pe, CACHE)
    if x.mode == "dump":
        for i, t, names in slots(o, x.cls, x.a, x.b):
            print(f"{i:4d} {8 * i:#06x} {t + o.image_base:#x} {[n[:110] for n in names[:3]]}")
        return
    orig = [({m.group(1) for m in (re.match(r"\?(\w+)@", k) for k in names) if m}, names[:2])
            for _, _, names in slots(o, x.cls)]
    blk = Path(x.layout).read_text(encoding="utf-8").split(f"{x.cls}::$vftable@:")[1]
    ours = []
    for l in blk.split("\n")[1:]:
        m = re.match(r"^\s*(\d+)\s*\|\s*&(.*?)\s*$", l)
        if not m:
            if ours and l.strip() == "":
                break
            continue
        ours.append(m.group(2))
    print(f"orig {len(orig)} slots, ours {len(ours)}")
    last, j = None, 0
    for i, f in enumerate(ours):
        fn = f.split("::")[-1]
        if fn.startswith("{dtor}"):
            continue
        k = next((y for y in range(j, min(j + 40, len(orig))) if fn in orig[y][0]), None)
        if k is None:
            continue
        if k - i != last:
            print(f"ours {i:4d} {f[:60]:60s} -> orig {k:4d} shift {k - i:+d}")
            if last is not None:
                for y in range(j, k):
                    print(f"      orig {y:4d} {[n[:90] for n in orig[y][1]]}")
            last = k - i
        j = k + 1
    for y in range(j, len(orig)):
        print(f"      orig {y:4d} (after our last) {[n[:90] for n in orig[y][1]]}")


if __name__ == "__main__":
    main()
