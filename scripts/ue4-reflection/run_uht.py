"""run_uht.py: our engine's UnrealHeaderTool over the game module's headers (2026-11-04, the generated 45%).

The manifest is UBT's editor manifest (Engine/Intermediate/Build/Win64/UE4Editor/Development/UnrealHeaderTool.manifest)
with every engine module's output redirected to build/uht/engine/<Module> and a ShooterGame module appended: the Classes\\ headers that carry UHT macros (game_headers.py --reflect), the
stand-in PCH, and the output where every game unit's command line looks for it
(Engine/Intermediate/Build/Win64/Inc/ShooterGame, the rsp's -I). UHT writes ShooterGame.generated*.cpp, the
.generated.h files and ShooterGameClasses.h there. The log is build/uht/uht.log; the first error lines are printed.

After a clean run, an engine module's output that differs from the engine's own (the module's OutputDirectory in UBT's
manifest, Engine/Intermediate/Build/Win64/Inc/<Module>) is copied there, as UBT's UHT step would: GENERATED_*_BODY()
is keyed by its line, so an engine delta that moves lines in a reflected header needs its module's generated headers
again (2026-11-07: EngineTypes.h's FDamageEvent constructors moved 19 USTRUCT_BODY_LINE macros). Printed per file.

Usage: python _tools/rebuild/run_uht.py
"""
import shutil
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENGINE = Path(r"D:\UE\4.5.1\Engine")
UHT = ENGINE / "Binaries" / "Win64" / "UnrealHeaderTool.exe"
BASE_MANIFEST = ENGINE / "Intermediate" / "Build" / "Win64" / "UE4Editor" / "Development" / "UnrealHeaderTool.manifest"
GAME = ROOT / "src" / "reimpl" / "ShooterGame" / "Source" / "ShooterGame"
OUT = ENGINE / "Intermediate" / "Build" / "Win64" / "Inc" / "ShooterGame"
WORK = ROOT / "build" / "uht"
MACROS = re.compile(r"^\s*(UCLASS|USTRUCT|UENUM|UINTERFACE|DECLARE_DYNAMIC_\w*DELEGATE\w*)\s*\(", re.M)


def main():
    ap = argparse.ArgumentParser()
    ap.parse_args()
    WORK.mkdir(parents=True, exist_ok=True)
    m = json.loads(BASE_MANIFEST.read_text(encoding="utf-8-sig"))
    engine_out = {mod["Name"]: Path(mod["OutputDirectory"]) for mod in m["Modules"]}
    for mod in m["Modules"]:
        o = WORK / "engine" / mod["Name"]
        mod["OutputDirectory"] = str(o)
        mod["GeneratedCPPFilenameBase"] = str(o / (mod["Name"] + ".generated"))
    # in UBT's order, the folder's listing (alphabetical, case-insensitive): UHT processes the classes in it, deferring
    # one until the headers it #includes are parsed, and splits its output after 30,000 lines - ATLAS's units follow
    # that order (2026-11-07; the PCH's order put 3,189 tables in another unit than ATLAS's)
    files = sorted((GAME / "Classes").glob("*.h"), key=lambda p: p.name.lower())
    headers = [str(p) for p in files if MACROS.search(p.read_text(encoding="utf-8", errors="replace"))]
    OUT.mkdir(parents=True, exist_ok=True)
    m["Modules"].append({"Name": "ShooterGame", "ModuleType": "Game", "BaseDirectory": str(GAME), "IncludeBase": str(GAME),
                         "OutputDirectory": str(OUT), "ClassesHeaders": headers, "PublicHeaders": [], "PrivateHeaders": [],
                         "PCH": str(GAME / "Public" / "ShooterGame.h"), "GeneratedCPPFilenameBase": str(OUT / "ShooterGame.generated"),
                         "SaveExportedHeaders": True})
    man = WORK / "ShooterGame.uhtmanifest"
    man.write_text(json.dumps(m, indent=1), encoding="utf-8")
    log = WORK / "uht.log"
    print(f"UHT over {len(headers)} game headers (and the engine's {len(m['Modules']) - 1} modules) ...", flush=True)
    r = subprocess.run([str(UHT), "UE4Editor", str(man), "-LogCmds=loginit warning, logexit warning, logdatabase error",
                        "-Unattended", f"-abslog={log}"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    text = (r.stdout or "") + (r.stderr or "")
    (WORK / "uht.out").write_text(text, encoding="utf-8")
    errs = [l for l in text.split("\n") if re.search(r"error|Error", l)]
    print(f"exit {r.returncode}; {len(errs)} error lines")
    for l in errs[:15]:
        print("  ", l.strip()[:240])
    gen = sorted(OUT.glob("ShooterGame.generated*.cpp"))
    print(f"generated: {[p.name for p in gen]}")
    if r.returncode == 0:
        synced = []
        for name, real in engine_out.items():
            ours = WORK / "engine" / name
            if not ours.is_dir():
                continue
            for f in ours.iterdir():
                dst = real / f.name
                if f.is_file() and (not dst.exists() or dst.read_bytes() != f.read_bytes()):
                    real.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(f, dst)
                    synced.append(f"{name}/{f.name}")
        print(f"engine generated files brought up to date: {len(synced)} {synced[:20]}")
    sys.exit(r.returncode)


if __name__ == "__main__":
    main()
