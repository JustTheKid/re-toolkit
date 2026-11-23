"""Write SHA-256 manifests of the original installs to tracking/baseline/.

Covers every exe/dll/pdb/lib/exp/ini file plus ServerGrid* files and version.txt, so any later change
to an original file can be detected (ground rule: originals are read-only).

Usage: python _tools/rebuild/baseline.py [--check]
  --check  compare the installs against the existing manifests instead of writing them
"""
import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INSTALLS = {
    "client": Path(r"D:\ATLAS"),
    "server": Path(r"D:\ATLASServer"),
}
EXTS = {".exe", ".dll", ".pdb", ".lib", ".exp", ".ini"}
# Our own work inside the client root is not part of the original install.
SKIP_DIRS = {"_tools", "_re", "_prompts", "docs", "tracking", "src", "tests", ".git", ".claude", "AtlasTools", "build",
             "side-projects"}
# Hook files _tools/hook-deploy.ps1 puts next to the exe (ADR-0002); reported, not counted as drift.
DEPLOYED = {f"ShooterGame/Binaries/Win64/{n}" for n in ("VERSION.dll", "atlasre.dll", "atlasre.pdb", "atlasre.ini")}
# Files the game rewrites itself whenever it runs (its saved settings, e.g. the server's GameUserSettings.ini): a
# change is reported, not counted as drift (2026-10-23; the originals are the binaries and the Config folders).
RUNTIME_WRITTEN = ("ShooterGame/Saved/",)


def wanted(path: Path) -> bool:
    name = path.name
    return path.suffix.lower() in EXTS or name.startswith("ServerGrid") or name == "version.txt"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def scan(root: Path) -> dict:
    files = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if rel.parts and rel.parts[0] in SKIP_DIRS:
            continue
        if path.is_file() and wanted(path):
            if rel.as_posix() in DEPLOYED:
                print(f"{root}: deployed hook file (ours) {rel.as_posix()}")
                continue
            files[rel.as_posix()] = {"sha256": sha256(path), "size": path.stat().st_size}
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    out_dir = REPO / "tracking" / "baseline"
    out_dir.mkdir(parents=True, exist_ok=True)
    changed = False
    for name, root in INSTALLS.items():
        files = scan(root)
        manifest = out_dir / f"{name}.json"
        if args.check:
            old = json.loads(manifest.read_text(encoding="utf-8"))["files"]
            every = sorted(set(old) ^ set(files)) + sorted(k for k in old.keys() & files.keys()
                                                            if old[k]["sha256"] != files[k]["sha256"])
            diffs = [d for d in every if not d.startswith(RUNTIME_WRITTEN)]
            for d in every:
                if d in diffs:
                    print(f"{name}: CHANGED {d}")
                else:
                    print(f"{name}: runtime-written (expected) {d}")
            changed |= bool(diffs)
            print(f"{name}: {len(files)} files, {len(diffs)} differences")
        else:
            manifest.write_text(json.dumps({
                "install": str(root),
                "created": datetime.date.today().isoformat(),
                "note": "SHA-256 of exe/dll/pdb/lib/exp/ini, ServerGrid* and version.txt",
                "files": files,
            }, indent=1), encoding="utf-8")
            print(f"{name}: wrote {manifest.relative_to(REPO)} ({len(files)} files)")
    sys.exit(1 if changed else 0)


if __name__ == "__main__":
    main()
