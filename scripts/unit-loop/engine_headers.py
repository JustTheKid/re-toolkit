"""engine_headers.py: where our engine defines each class and struct - name -> the include path a game header writes
(relative to the module's Classes\\ or Public\\ folder, which every game unit's command line has on its include path).

Read from the engine's source (D:\\UE\\4.5.1\\Engine\\Source\\Runtime\\<Module>\\{Classes,Public}\\**\\*.h): a line that
opens a definition (`class ENGINE_API AWaveWorksOcean : public AInfo`, `struct FSlateBrush`, not a forward
declaration). game_headers.py includes, ahead of a game header's types, the headers of the engine types they derive
from or hold by value - in place of the hand-kept ENGINE_INCLUDES lists (2026-11-04, the bulk headers: the AI module's
behaviour-tree nodes and the WaveWorks ocean were the first that Engine.h did not bring). A name defined in two places
keeps the first by module order (Core, CoreUObject, Engine, then the rest alphabetically).

Usage: python _tools/rebuild/engine_headers.py [--engine D:\\UE\\4.5.1\\Engine] [--out build/loop/common/engine-headers.json]
"""
import argparse
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "build" / "loop" / "common" / "engine-headers.json"
KEYWORDS = REPO / "build" / "loop" / "common" / "engine-keywords.json"
FIRST = ["Core", "CoreUObject", "Engine", "InputCore", "SlateCore", "Slate", "UMG", "AIModule"]
DELEGATE = re.compile(r"^\s*(?:DECLARE_(?:DYNAMIC_)?(?:MULTICAST_)?DELEGATE\w*\(\s*(\w+)|DECLARE_EVENT\w*\(\s*\w+\s*,\s*(\w+))")
TYPEDEF = re.compile(r"^typedef\s+[^;()]*?\b([A-Za-z_]\w*)\s*;")
DEF = re.compile(r"^\s*(class|struct)\s+(?:\w+_API\s+)?(?:DEPRECATED\([^)]*\)\s+)?([A-Za-z_]\w*)\s*(?::(?!:)[^;{]*)?(?:\{.*)?(?://.*)?$")  # a trailing comment after the name too


def build(engine):
    runtime = Path(engine) / "Source" / "Runtime"
    # the modules one or two levels down (Runtime/Online/OnlineSubsystemUtils: UOnlineSessionClient)
    mods = [p for p in runtime.iterdir() if p.is_dir()]
    mods += [q for p in mods if not (p / "Classes").exists() and not (p / "Public").exists() for q in p.iterdir() if q.is_dir()]
    mods = sorted(mods, key=lambda p: (FIRST.index(p.name) if p.name in FIRST else len(FIRST), p.name))
    # the plugins' runtime modules too (OnlineSubsystemUtils: UOnlineSessionClient, the bulk headers' fourth build)
    plugins = Path(engine) / "Plugins"
    if plugins.exists():
        mods += sorted((p for p in plugins.rglob("Source/*") if p.is_dir() and ((p / "Classes").exists() or (p / "Public").exists())),
                       key=lambda p: p.name)
    found, keyword = {}, {}
    for mod in mods:
        for top in ("Classes", "Public"):
            root = mod / top
            if not root.exists():
                continue
            for h in sorted(root.rglob("*.h")):
                rel = h.relative_to(root).as_posix()
                try:
                    lines = h.read_text(encoding="utf-8", errors="replace").split("\n")
                except OSError:
                    continue
                for i, l in enumerate(lines):
                    d = DELEGATE.match(l)
                    if d:  # a delegate type a macro declares (FActorCustomEventSignature in the engine's actor header)
                        found.setdefault(d.group(1) or d.group(2), f"{mod.name}:{rel}")
                        continue
                    t = TYPEDEF.match(l)
                    if t:  # a top-level typedef (FDefaultAllocator): a name a member may hold by value
                        found.setdefault(t.group(1), f"typedef:{mod.name}:{rel}")
                        continue
                    if l[:1].isspace():
                        continue  # a nested type (FHittestGrid's FCell is not the game's FCell)
                    m = DEF.match(l)
                    if not m or l.rstrip().endswith(";"):
                        continue
                    nxt = "".join(lines[i + 1:i + 3])
                    if "{" not in l and not nxt.lstrip().startswith(("{", ":", "public", ",")) and "{" not in nxt[:2]:
                        continue
                    found.setdefault(m.group(2), f"{mod.name}:{rel}")
                    keyword.setdefault(m.group(2), m.group(1))
    KEYWORDS.write_text(json.dumps(keyword, indent=0, sort_keys=True), encoding="utf-8")
    return found


def keywords():
    """name -> class / struct, as the engine defines it (a forward declaration must say the same: C4099)"""
    return json.loads(KEYWORDS.read_text(encoding="utf-8")) if KEYWORDS.exists() else {}


def load(typedefs=False):
    """name -> "Module:path" of the engine's class and struct definitions (and its typedefs, "typedef:Module:path", when
    asked: names a member may hold by value but that have no header of their own to include)"""
    d = json.loads(OUT.read_text(encoding="utf-8")) if OUT.exists() else {}
    return d if typedefs else {n: p for n, p in d.items() if not p.startswith("typedef:")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default=r"D:\UE\4.5.1\Engine")
    ap.add_argument("--out", default=str(OUT))
    a = ap.parse_args()
    found = build(a.engine)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(found, indent=0, sort_keys=True), encoding="utf-8")
    print(f"{len(found)} engine types -> {a.out}")
    for n in ("AWaveWorksOcean", "UBTTaskNode", "UBTService_BlackboardBase", "UUserWidget", "FSlateBrush", "SCompoundWidget"):
        print(" ", n, found.get(n))


if __name__ == "__main__":
    main()
