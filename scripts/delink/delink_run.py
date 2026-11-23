"""A server root for the linked ShooterGameServer.exe (plan P2c, 2026-10-30), so that `_tools/start-server.ps1 -Root`
boots it without touching the original install: junctions to the original's Engine, Content, SeekFreeContent,
ServerGrid, Config, AtlasTools and steamapps; a copy of ShooterGame\\Binaries\\Win64 without the two exes and the
PDBs (the DLLs the server loads from its own folder), our exe and its PDB in it; copies of the root's files
(the Steam client DLLs, PackageInfo.bin) and ShooterGame's (ServerGrid.json, the uproject, AssetRegistry.bin,
TradeEvents.csv); ShooterGame\\Saved as a fresh folder with the original's Saved\\<cell>\\Config (the deployed grid
configs) copied in, so the logs and saves of a run stay in the run root.

usage: python -I _tools/delink_run.py [--root build/delink/run] [--exe build/delink/link/ShooterGameServer.exe]
                                      [--original D:\\ATLASServer] [--cell 00] [--dry-run]
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
JUNCTIONS = ["Engine", "AtlasTools", "steamapps", "ShooterGame/Content", "ShooterGame/SeekFreeContent",
             "ShooterGame/ServerGrid", "ShooterGame/Config"]
ROOT_FILES = ["steamclient.dll", "steamclient64.dll", "steamwebrtc.dll", "steamwebrtc64.dll", "tier0_s.dll",
              "tier0_s64.dll", "vstdlib_s.dll", "vstdlib_s64.dll", "PackageInfo.bin"]
GAME_FILES = ["ShooterGame/ServerGrid.json", "ShooterGame/ServerGrid.ServerOnly.json", "ShooterGame/ShooterGame.uproject",
              "ShooterGame/AssetRegistry.bin", "ShooterGame/TradeEvents.csv"]
SKIP_BINARIES = {"ShooterGameServer.exe", "AtlasGame.exe", "AtlasGame_BE.exe"}


def junction(link, target, dry):
    if link.exists() or link.is_symlink():
        return "kept"
    if dry:
        return "would make"
    link.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"mklink failed for {link}: {r.stdout}{r.stderr}")
    return "made"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(ROOT / "build" / "delink" / "run"))
    ap.add_argument("--exe", default=str(ROOT / "build" / "delink" / "link" / "ShooterGameServer.exe"))
    ap.add_argument("--original", default=r"D:\ATLASServer")
    ap.add_argument("--cell", default="00")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    root, orig, exe = Path(a.root), Path(a.original), Path(a.exe)
    if not exe.exists():
        sys.exit(f"no linked exe at {exe}")
    root.mkdir(parents=True, exist_ok=True)
    for rel in JUNCTIONS:
        print(f"  junction {rel}: {junction(root / rel, orig / rel, a.dry_run)}")
    for rel in ROOT_FILES + GAME_FILES:
        src, dst = orig / rel, root / rel
        if not src.exists():
            print(f"  (no {rel} in the original)")
            continue
        if dst.exists():
            continue
        if not a.dry_run:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        print(f"  copied {rel}")
    binaries = root / "ShooterGame" / "Binaries" / "Win64"
    n = 0
    for p in (orig / "ShooterGame" / "Binaries" / "Win64").iterdir():
        if p.is_dir() or p.name in SKIP_BINARIES or p.suffix.lower() == ".pdb":
            continue
        dst = binaries / p.name
        if dst.exists():
            continue
        if not a.dry_run:
            binaries.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dst)
        n += 1
    print(f"  binaries: {n} files copied (not the exes, not the PDBs)")
    for p in (exe, exe.with_suffix(".pdb")):
        if p.exists() and not a.dry_run:
            shutil.copy2(p, binaries / p.name)
            print(f"  our {p.name} -> {binaries / p.name}")
    saved_cfg = orig / "ShooterGame" / "Saved" / a.cell / "Config"
    dst = root / "ShooterGame" / "Saved" / a.cell / "Config"
    if saved_cfg.exists() and not dst.exists():
        if not a.dry_run:
            shutil.copytree(saved_cfg, dst)
        print(f"  Saved/{a.cell}/Config copied from the original (the deployed grid configs)")
    # the cell's save files too (ocean.atlas, its backups), the world the control run loads: without them the
    # eleventh start (2026-10-31) made an empty ocean.atlas and waited forever for its load; not our ships snapshot
    n = 0
    for p in sorted(saved_cfg.parent.glob("*")):
        dst = root / "ShooterGame" / "Saved" / a.cell / p.name
        if p.is_file() and ".ships-" not in p.name and not dst.exists():
            if not a.dry_run:
                shutil.copy2(p, dst)
            n += 1
    if n:
        print(f"  Saved/{a.cell}: {n} save files copied from the original (the same world as the control run)")
    print(f"run root: {root}\n  boot: powershell -ExecutionPolicy Bypass -File _tools\\start-server.ps1 -Root {root}")


if __name__ == "__main__":
    main()
