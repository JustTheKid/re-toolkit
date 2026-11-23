"""DevKit module diff, step 4: per module of <work>/modules.tsv, ATLAS's DevKit editor DLL against our engine.
- reflection: reflection_diff_all.py <typed export> <ours> --dll <dll> --editor --mask 0xD8000000000000 (a DLL without
              a PDB: its untyped export, since --fix-imports loses its calls' parameters)
- metadata:   devkit_metadata.py parse (into <corpus>/<module>.metadata.jsonl), then metadata_diff.py against our
              UHT output
- enums:      enum_diff.py when our generated code or the DevKit export has enums (step 1.9d's script asked the census,
              which counts ours only, and so skipped SpeedTreeImporter's two)
- classes:    reflection_classes.py --dll (superclass, class flags, config name, interfaces), with --classes
Reports: <work>/diff/<module>_{refl,meta,enum,classes}.{md,json}, plus <module>_row.json (a module's old ones are
removed first). <work>/summary.md has a row per census module from the row files on disk and the count of identical
modules. Static: no Ghidra, no build.

Usage: python -I _tools/devkit_diff/diffs.py --work <dir> [--modules AnimGraph,Paper*] [--classes]
       [--ours <dir>] [--corpus _re/corpus/devkit] [--engine D:/UE/4.5.1] [--mask 0xD8000000000000]
  --ours  folder with one dump folder per module (default <work>/ours, written by dump.ps1)
Verdict "identical": all types and functions identical, none ATLAS-only or ours-only (our AtlasFormatTestCommandlet
aside); metadata without differences or ATLAS-only members (our entries for members ATLAS has no metadata for count
only if they carry a key metadata_diff compares, i.e. not just ModuleRelativePath); enums identical; classes, if run,
identical (a class whose ATLAS flags read as 0x0 counts as "not read": reflection_classes.py misses the flags of
PDB-less plugins other than SpeedTreeImporter). Functions count as "not exported" when the typed export has no
UFunction file but the untyped one has (step 1.9a's Engine / UMG / AIModule typed exports hold classes and structs).
Results on step 1.9d's dumps (2026-10-23): 61 of 65 identical; after step 1.9e and the metadata corrections
(2026-10-24): 65 of 65 (with --classes EditorStyle differs, a reading gap: its config name is stored by a byte-copy
loop reflection_classes.py does not read); with the server's modules (census --all-modules) 70 of 87, Engine
identical, HoudiniEngineRuntime 30 / 31, 16 pending without a typed DevKit export.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devkit_modules import CORPUS, ENGINE, MASK, TOOLS, inc_dir, our_counts, read_census, selector  # noqa: E402

sys.path.insert(1, str(TOOLS))
import metadata_diff  # noqa: E402

# ours only and never ATLAS's: the engine repo's test commandlet (UnrealEd)
OURS_EXPECTED = {"AtlasFormatTestCommandlet"}
ENUM_LINE = re.compile(r"(\d+) compared, (\d+) identical, (\d+) differing, (\d+) only ATLAS, (\d+) only ours")


def run(*args):
    r = subprocess.run([sys.executable, "-I", *map(str, args)], capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    return r.returncode, (r.stdout + r.stderr).strip()


def load(path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def reflection_cell(rep, atlas, meta):
    t = rep["totals"]
    ours_only = [n for n in rep["ours_only"] if n not in OURS_EXPECTED]
    ok = t["identical"] == t["types_compared"] and not t["atlas_only_types"] and not ours_only
    text = f"{t['identical']}/{t['types_compared']} types"
    if "functions_compared" in t:
        if (not t["functions_compared"] and not t["atlas_only_functions"]
                and not any(atlas.glob("Z_Construct_UFunction_*.c")) and any(meta.glob("Z_Construct_UFunction_*.c"))):
            text += ", fns not exported"
        else:
            text += f", {t['functions_identical']}/{t['functions_compared']} fns"
            ok &= (t["functions_identical"] == t["functions_compared"] and not t["atlas_only_functions"]
                   and not t["ours_only_functions"])
            if t["atlas_only_functions"] or t["ours_only_functions"]:
                text += f" (ATLAS-only {t['atlas_only_functions']}, ours-only {t['ours_only_functions']})"
    if t["atlas_only_types"]:
        text += f", ATLAS-only types {t['atlas_only_types']}"
    if ours_only:
        text += f", ours-only types {len(ours_only)}"
    expected = sorted(set(rep["ours_only"]) & OURS_EXPECTED)
    if expected:
        text += f" (+ ours: {', '.join(expected)})"
    return ok, text


def metadata_cell(rep, jsonl, inc):
    stats = rep["stats"]
    other = {k: v for k, v in stats.items() if k not in ("same", "ours_only_member_entries")}
    ok = not other and not rep["atlas_only_members"]
    text = f"same {stats.get('same', 0)}" + "".join(f", {k} {v}" for k, v in sorted(other.items()))
    if rep["atlas_only_members"]:
        text += f", ATLAS-only members {len(rep['atlas_only_members'])}"
    n = stats.get("ours_only_member_entries", 0)
    if n:
        theirs, mine = metadata_diff.atlas(str(jsonl)), metadata_diff.ours(str(inc))
        types = {t for t, _ in theirs}
        real = sum(1 for (t, m), kv in mine.items() if (t, m) not in theirs and t in types
                   and any(k not in metadata_diff.SKIP for k in kv))
        text += f", ours-only entries {n}" + (f" ({n - real} with skipped keys only)" if real < n else "")
        ok &= real == 0
    return ok, text


def diff_module(row, a, out):
    """Runs the diffs of one module; returns its summary row (also written to diff/<module>_row.json)."""
    module, dll, low = row["module"], row["dll"], row["module"].lower()
    ours = Path(a.ours) / module
    meta = Path(a.corpus) / low
    atlas = Path(a.corpus) / (f"{low}-typed" if row["pdb"] == "pdb" else low)
    inc = inc_dir(a.engine, module)
    res = {"module": module, "pdb": row["pdb"], "verdict": "pending", "reflection": "", "metadata": "", "enums": "",
           "classes": ""}
    for old in out.glob(f"{low}_*"):
        old.unlink()
    absent = [str(p) for p in dict.fromkeys((ours, atlas, meta, inc)) if not p.is_dir()]
    if absent:
        res["reflection"] = "no " + ", ".join(absent)
        (out / f"{low}_row.json").write_text(json.dumps(res, indent=1), encoding="utf-8", newline="\n")
        return res
    oks, errors = [], []

    code, text = run(TOOLS / "reflection_diff_all.py", atlas, ours, "--dll", dll, "--editor", "--mask", a.mask,
                     "--report", out / f"{low}_refl.md", "--json", out / f"{low}_refl.json")
    if code:
        errors.append("reflection")
        res["reflection"] = "ERR " + text[-200:]
    else:
        ok, res["reflection"] = reflection_cell(load(out / f"{low}_refl.json"), atlas, meta)
        oks.append(ok)

    jsonl = Path(a.corpus) / f"{low}.metadata.jsonl"
    code, text = run(TOOLS / "devkit_metadata.py", "parse", meta, "--dll", dll, "--json", jsonl)
    if code == 0:
        code, text = run(TOOLS / "metadata_diff.py", jsonl, inc, "--report", out / f"{low}_meta.md",
                         "--json", out / f"{low}_meta.json")
    if code:
        errors.append("metadata")
        res["metadata"] = "ERR " + text[-200:]
    else:
        ok, res["metadata"] = metadata_cell(load(out / f"{low}_meta.json"), jsonl, inc)
        oks.append(ok)

    if our_counts(inc)[1] or any(meta.glob("Z_Construct_UEnum_*.c")):
        code, text = run(TOOLS / "enum_diff.py", meta, "--dll", dll, inc, "--report", out / f"{low}_enum.md",
                         "--json", out / f"{low}_enum.json")
        m = ENUM_LINE.search(text)
        if code or not m:
            errors.append("enums")
            res["enums"] = "ERR " + text[-200:]
        else:
            compared, same, differing, only_atlas, only_ours = map(int, m.groups())
            res["enums"] = f"{same}/{compared}" + (f", differing {differing}" if differing else "") + \
                (f", ATLAS-only {only_atlas}" if only_atlas else "") + (f", ours-only {only_ours}" if only_ours else "")
            oks.append(not differing and not only_atlas and not only_ours)

    if a.classes:
        code, text = run(TOOLS / "reflection_classes.py", atlas, inc, "--dll", dll,
                         "--report", out / f"{low}_classes.md", "--json", out / f"{low}_classes.json")
        if code:
            errors.append("classes")
            res["classes"] = "ERR " + text[-200:]
        else:
            rep = load(out / f"{low}_classes.json")
            t = rep["totals"]
            # every UHT class ORs in CLASS_Native (0x80): ATLAS flags 0x0 mean the flags were not read (PDB-less
            # plugins other than SpeedTreeImporter), not a difference
            blind = sum(any(d.startswith("flags 0x0 vs") for d in r["diffs"]) for r in rep["differing"])
            res["classes"] = f"{t['identical']}/{t['classes_compared'] - blind}" + \
                (f", unread {t['unread']}" if t["unread"] else "") + \
                (f", ATLAS flags not read {blind}" if blind else "")
            oks.append(t["differing"] == blind)

    res["verdict"] = "ERR " + "/".join(errors) if errors else "identical" if all(oks) else "differs"
    (out / f"{low}_row.json").write_text(json.dumps(res, indent=1), encoding="utf-8", newline="\n")
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--work", required=True)
    ap.add_argument("--modules")
    ap.add_argument("--classes", action="store_true")
    ap.add_argument("--ours")
    ap.add_argument("--corpus", default=str(CORPUS))
    ap.add_argument("--engine", default=str(ENGINE))
    ap.add_argument("--mask", default=MASK)
    a = ap.parse_args()
    work = Path(a.work)
    a.ours = a.ours or str(work / "ours")
    out = work / "diff"
    out.mkdir(parents=True, exist_ok=True)
    rows = read_census(work)
    wanted, pats = selector(a.modules)
    selected = [r for r in rows if wanted(r["module"])]
    if pats and not selected:
        raise SystemExit(f"no module of {work / 'modules.tsv'} matches {a.modules}")

    failed = False
    for row in selected:
        if not row["dll"]:
            print(row["module"], "| no DevKit DLL")
            continue
        r = diff_module(row, a, out)
        failed |= r["verdict"].startswith("ERR")
        print(" | ".join([r["module"], r["verdict"], r["reflection"], r["metadata"], r["enums"] or "-",
                          r["classes"] or "-"]), flush=True)

    # the summary covers every census module, from the row files of this and earlier runs
    table, verdicts = [], []
    for row in rows:
        if not row["dll"]:
            table.append([row["module"], "no DevKit DLL", "", "", "", "", ""])
            continue
        r = load(out / f"{row['module'].lower()}_row.json") or {
            "verdict": "pending", "reflection": "", "metadata": "", "enums": "", "classes": "", "pdb": row["pdb"]}
        verdicts.append((row["module"], r["verdict"]))
        table.append([row["module"], r["verdict"], r["reflection"], r["metadata"], r["enums"], r["classes"], r["pdb"]])
    same = sum(v == "identical" for _, v in verdicts)
    groups = {k: [m for m, v in verdicts if v.split(" ")[0] == k] for k in ("differs", "ERR", "pending")}
    head = f"{same} of {len(verdicts)} modules with a DevKit DLL identical" + "".join(
        f"; {k} {len(ms)}" + (f": {', '.join(ms)}" if k != "pending" else "") for k, ms in groups.items() if ms)
    lines = ["# DevKit module diff: ATLAS's editor DLLs vs our engine", "", head + ".", "",
             f"Census `{work / 'modules.tsv'}`, ours `{a.ours}`, DevKit exports `{a.corpus}`, reports `{out}`.", "",
             "| module | verdict | reflection (editor-only members included) | metadata | enums | classes | pdb |",
             "|---|---|---|---|---|---|---|"]
    lines += ["| " + " | ".join(c.replace("|", "\\|") for c in t) + " |" for t in table]
    (work / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(head, "->", work / "summary.md")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
