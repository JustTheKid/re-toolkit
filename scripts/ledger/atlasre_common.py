"""Shared helpers for the rebuild tools: paths, ID parsing, CSV ledgers, hashing."""
import csv
import datetime
import hashlib
import os
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TRACKING = REPO / "tracking"
DECOMP = REPO / "_re" / "decompiled"
ANNOTATIONS = REPO / "_re" / "annotations"
DOCS = REPO / "docs"
SRC = REPO / "src"
# Our engine tree: UE 4.5.1 + ATLAS's engine changes (ADR-0001), its own local-only git repo, never part of this one
# (Epic's license). A ledger reimpl_path "engine:<path>" is relative to it.
ENGINE = Path(os.environ.get("ATLAS_ENGINE_ROOT", r"D:\UE\4.5.1"))
ENGINE_PREFIX = "engine:"


def resolve_reimpl(path: str) -> Path:
    if path.startswith(ENGINE_PREFIX):
        return ENGINE / path[len(ENGINE_PREFIX):]
    return REPO / path

# Function-ID prefix -> (binary key, decompile folder, executable path)
BINARIES = {
    "SRV": ("server", "server", Path(r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe")),
    "CLI": ("client", "client", Path(r"C:\Program Files (x86)\Steam\steamapps\common\ATLAS\ShooterGame\Binaries\Win64\AtlasGame.exe")),
    "EDT": ("editor", "editor", Path(r"D:\ATLAS\ShooterGame\Binaries\Win64\UE4Editor-ShooterGame.dll")),
}
BASELINE_KEYS = {
    "server": ("server", "ShooterGame/Binaries/Win64/ShooterGameServer.exe"),
    "client": ("client", "ShooterGame/Binaries/Win64/AtlasGame.exe"),
    "editor": ("client", "ShooterGame/Binaries/Win64/UE4Editor-ShooterGame.dll"),
}

LADDER = ["UNTOUCHED", "RAW", "ANNOTATED", "UNDERSTOOD", "REIMPL", "HOOKED", "VERIFIED", "NATIVE"]
SIDE_STATES = ["STUBBED", "DEAD", "BLOCKED"]
ALL_STATES = LADDER + SIDE_STATES

FUNC_ID = re.compile(r"^(SRV|CLI|EDT)@([0-9a-f]{6,16})$")
SCHEMAS = {
    "functions": ["id", "binary", "va", "symbol", "system", "status", "parity", "raw_sha256", "reimpl_path",
                  "toggle", "rep", "evidence", "bug", "notes", "updated"],
    "replacements": ["rep", "title", "kind", "covers", "status", "toggle", "default", "adr", "notes", "updated"],
    "surfaces": ["id", "service", "protocol", "endpoint_or_api", "direction", "state", "used_by", "rep", "doc",
                 "notes", "updated"],
}


def today() -> str:
    return datetime.date.today().isoformat()


def parse_func_id(fid: str):
    m = FUNC_ID.match(fid)
    if not m:
        raise ValueError(f"not a function ID (SRV@/CLI@/EDT@<lowercase hex va>): {fid}")
    return m.group(1), m.group(2)


def raw_dir(prefix: str) -> Path:
    return DECOMP / BINARIES[prefix][1]


def find_raw(fid: str):
    """Return the raw decompile file for a function ID (matched by '@<va>.c'), or None."""
    prefix, va = parse_func_id(fid)
    hits = sorted(raw_dir(prefix).glob(f"*@{va}.c"))
    return hits[0] if hits else None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_table(name: str) -> list[dict]:
    path = TRACKING / f"{name}.csv"
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return rows


def write_table(name: str, rows: list[dict]) -> None:
    key = SCHEMAS[name][0]
    rows = sorted(rows, key=lambda r: r[key])
    with open(TRACKING / f"{name}.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SCHEMAS[name], lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in SCHEMAS[name]})


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True).stdout.strip()


def git_head() -> str:
    head = git("rev-parse", "--short", "HEAD") or "uncommitted"
    dirty = git("status", "--porcelain")
    return head + ("-dirty" if dirty else "")
