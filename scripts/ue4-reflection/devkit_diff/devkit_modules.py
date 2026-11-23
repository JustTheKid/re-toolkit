"""Shared by the DevKit module-diff tools in _tools/devkit_diff/ (step 1.9d's workflow): default paths, the census
file <work>/modules.tsv and the module filter. The PowerShell steps read the same file with Import-Csv."""
import csv
import fnmatch
import os
import re
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
REPO = TOOLS.parent
# our engine tree (ADR-0001), as _tools/rebuild/atlasre_common.py
ENGINE = Path(os.environ.get("ATLAS_ENGINE_ROOT", r"D:\UE\4.5.1"))
# the DevKit's engine folder: editor DLLs in Binaries/Win64, plugin DLLs in Plugins/**/Binaries/Win64 (read-only)
DLL_ROOT = Path(r"C:\Program Files\Epic Games\AtlasModKit\Engine")
CORPUS = REPO / "_re" / "corpus" / "devkit"
SERVER_CORPUS = REPO / "_re" / "corpus" / "server"
PROJECT, PROJECT_NAME = REPO / "_re" / "ghidra-devkit", "devkit"
# reflection_diff_all.py --mask: hides ATLAS's save-archive bits 51/52/54/55 (step 6), as in reflection-editor.md
MASK = "0xD8000000000000"
COLUMNS = ["module", "types", "enums", "dll", "pdb", "ghidra"]
# definitions (not declarations) of UHT's Z_Construct functions in <Module>.generated*.cpp
TYPE_DEF = re.compile(rb"^[ \t]*\w[\w\* ]*\bZ_Construct_U(Class|ScriptStruct)_(\w+)\(\)[ \t\r]*$", re.M)
ENUM_DEF = re.compile(rb"^[ \t]*\w[\w\* ]*\bZ_Construct_UEnum_\w+\(\)[ \t\r]*$", re.M)


def inc_root(engine):
    return Path(engine) / "Engine" / "Intermediate" / "Build" / "Win64" / "Inc"


def inc_dir(engine, module):
    """UHT's generated code of a module: Inc/<Module>, or Inc/Plugins/<Module> for a plugin."""
    inc = inc_root(engine)
    return inc / module if (inc / module).is_dir() else inc / "Plugins" / module


def our_counts(inc):
    """Our reflected classes and structs (names) and the number of enums in a module's generated code."""
    text = b"".join(f.read_bytes() for f in Path(inc).glob("*.generated*.cpp"))
    return {n for _, n in TYPE_DEF.findall(text) if not n.endswith(b"_NoRegister")}, len(ENUM_DEF.findall(text))


def selector(spec):
    """--modules: names or wildcards, comma separated, case-insensitive; empty selects every module."""
    pats = [p.strip().lower() for p in (spec or "").split(",") if p.strip()]
    return (lambda name: not pats or any(fnmatch.fnmatchcase(name.lower(), p) for p in pats)), pats


def read_census(work):
    path = Path(work) / "modules.tsv"
    if not path.exists():
        raise SystemExit(f"{path} not found: run census.py --work {work} first")
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def write_census(work, rows):
    Path(work).mkdir(parents=True, exist_ok=True)
    with open(Path(work) / "modules.tsv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, COLUMNS, delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
