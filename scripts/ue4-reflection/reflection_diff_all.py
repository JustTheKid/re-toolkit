"""Whole-module reflection diff: every class and struct ATLAS reflects in a module vs our engine's.

ATLAS side: a folder of Z_Construct_UClass_* / Z_Construct_UScriptStruct_* decompiles (e.g. the corpus export
_re/corpus/server/_reflection_engine). Our side: the folder written by
`UE4Editor-Cmd -run=AtlasFormatTest -reflectionall=Engine -out=<dir>` (<Name>.jsonl for classes,
struct_<Name>.jsonl for structs, _index.tsv).

Per type it compares names, kinds, flags (without the computed bits), referenced types, array dims, native bools and
declaration order, like reflection_diff.py. Functions (Z_Construct_UFunction_*, ours func_<Owner>_<Name>.jsonl and the
"function" rows of _index.tsv) get the same parameter comparison plus their function flags; their totals are separate. Writes a markdown report and a JSON summary; prints totals.

Usage: python -I _tools/reflection_diff_all.py <atlas_dir> <ours_dir> --report <out.md> [--json <out.json>]
       [--mask 0x40000000000000]   ignore extra flag bits (e.g. ATLAS's save-archive bit 54 while it is not ported)
       [--dll <DevKit DLL>]        ATLAS's side is the DevKit's editor DLL (decompiles exported with ghidra_find.py
                                   --fix-imports, e.g. _re/corpus/devkit/engine-typed): read through
                                   reflection_table.devkit_text(); the editor build has the editor-only members
       [--editor]                  compare editor-only members too (with --dll): ours that ATLAS lacks are extra
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reflection_table  # noqa: E402

COMPUTED = 0x40000000 | 0x1000000000 | 0x200
EDITOR_ONLY = 0x800000000  # CPF_EditorOnly: WITH_EDITORONLY_DATA members, absent from ATLAS's game binaries
FILE_RX = re.compile(r"^Z_Construct_(UClass|UScriptStruct|UFunction)_(\w+?)@([0-9a-f]+)\.c$")
# UFunction::UFunction(this, initializer, super, FunctionFlags, RepOffset, ParmsSize)
FUNC_RX = re.compile(r"UFunction::UFunction\(\s*[^,]+,\s*[^,]+,\s*(?:\([^()]*\)\s*)?[^,]+,\s*(0x[0-9a-fA-F]+|\d+)\s*,")


def flags(row, mask):
    try:
        return int(row["flags"], 16) & ~COMPUTED & ~mask
    except (KeyError, ValueError):
        return None


def key(row):
    return (row["name"], row.get("inner_of", ""))


def compare(theirs, mine, mask, editor_too=False):
    a, b = {key(r): r for r in theirs}, {key(r): r for r in mine}
    missing, extra, changed = [], [], []
    # a name read twice means the extractor missed the literal of a property in between: never let the dict hide it
    if len(a) != len(theirs):
        names = [key(r) for r in theirs]
        changed += [f"{k[0]}: listed {names.count(k)} times in ATLAS's table (extractor missed a name)"
                    for k in dict.fromkeys(names) if names.count(k) > 1]
    for k, r in a.items():
        if k not in b:
            missing.append(f"{k[0]}{' (inner)' if k[1] else ''}: {r['kind']} {r.get('ref', '')} flags {r.get('flags')}".rstrip())
            continue
        o = b[k]
        if r["kind"] != o["kind"]:
            changed.append(f"{k[0]}: kind {r['kind']} vs ours {o['kind']}")
        fa, fo = flags(r, mask), flags(o, mask)
        if fa is not None and fa != fo:
            changed.append(f"{k[0]}{' (inner)' if k[1] else ''}: flags 0x{fa:x} vs ours 0x{fo:x} (differ 0x{fa ^ (fo or 0):x})")
        typed = r["kind"] in ("UObjectProperty", "UClassProperty", "UStructProperty", "UByteProperty",
                              "UInterfaceProperty", "UWeakObjectProperty", "ULazyObjectProperty", "UAssetObjectProperty",
                              "UAssetClassProperty")
        if typed and r.get("ref") and o.get("ref") and not (
                r["ref"] == o["ref"] or r["ref"].endswith("_" + o["ref"].lstrip("UAFE")) or r["ref"].endswith("_" + o["ref"])):
            changed.append(f"{k[0]}: type {r['ref']} vs ours {o['ref']}")
        if "native_bool" in r and r.get("native_bool") != o.get("native_bool"):
            changed.append(f"{k[0]}: native bool {r['native_bool']} vs ours {o.get('native_bool')}")
        if r.get("dim", 1) != o.get("dim", 1):
            changed.append(f"{k[0]}: array dim {r.get('dim', 1)} vs ours {o.get('dim', 1)}")
    editor = []
    for k, o in b.items():
        if k not in a:
            parent = b.get((k[1], "")) if k[1] else o
            if int(parent.get("flags", "0"), 16) & EDITOR_ONLY and not editor_too:
                editor.append(f"{k[0]}{' (inner)' if k[1] else ''}")
            else:
                extra.append(f"{k[0]}{' (inner)' if k[1] else ''}: {o['kind']}")
    order_a = [k for k in a if k[1] == "" and k in b]
    order_b = [k for k in b if k[1] == "" and k in a]
    order = order_a != list(reversed(order_b))
    return missing, extra, changed, order, editor


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("atlas_dir")
    ap.add_argument("ours_dir")
    ap.add_argument("--report", required=True)
    ap.add_argument("--json")
    ap.add_argument("--mask", default="0")
    ap.add_argument("--dll")
    ap.add_argument("--editor", action="store_true")
    args = ap.parse_args()
    mask = int(args.mask, 0)
    if args.dll:
        from devkit_metadata import PE
        reflection_table.DEVKIT = PE(args.dll)
    ours = Path(args.ours_dir)
    our_classes = {p.stem for p in ours.glob("*.jsonl") if not p.stem.startswith(("struct_", "func_"))}
    our_structs = {p.stem[len("struct_"):] for p in ours.glob("struct_*.jsonl")}
    our_funcs = {}
    index = ours / "_index.tsv"
    for line in (index.read_text(encoding="utf-8-sig").splitlines() if index.exists() else []):
        cols = line.split("	")
        if cols[0] == "function" and len(cols) >= 5:
            our_funcs[cols[1]] = int(cols[4], 16)

    results, absent = [], []
    seen_classes, seen_structs, seen_funcs = set(), set(), set()
    for f in sorted(Path(args.atlas_dir).glob("Z_Construct_*.c")):
        m = FILE_RX.match(f.name)
        if not m or m.group(2).endswith("_NoRegister"):
            continue
        kind, full, va = m.groups()
        if kind == "UFunction":
            # <prefixed owner>_<name>; ours is keyed by the owner without its prefix
            name = full[1:] if full[1:] in our_funcs else full
            ours_file = ours / f"func_{name}.jsonl" if name in our_funcs else None
            seen = seen_funcs
        elif kind == "UClass":
            name, ours_file, seen = full[1:], None, seen_classes
            # a deprecated class is UDEPRECATED_Foo in C++ but registers as "Foo" (IMPLEMENT_CLASS skips the prefix)
            if name.startswith("DEPRECATED_") and name[len("DEPRECATED_"):] in our_classes:
                name = name[len("DEPRECATED_"):]
            if name in our_classes:
                ours_file = ours / f"{name}.jsonl"
        else:
            # <OuterHeaderClass>_F<Struct>: take the longest struct name of ours that the function name ends with
            cands = [s for s in our_structs if full == "F" + s or full.endswith("_F" + s)]
            name = max(cands, key=len) if cands else (full[1:] if full.startswith("F") else full.split("_F", 1)[-1])
            ours_file = ours / f"struct_{name}.jsonl" if cands else None
            seen = seen_structs
        reflection_table.OUTER_SELF.clear()
        # a function's file first references its owner class (Z_Construct_UClass_<Owner>), before any parameter
        reflection_table.OUTER_SELF[str(f)] = full.split("_", 1)[0] if kind == "UFunction" else full
        _, theirs = reflection_table.table(str(f))
        if ours_file is None:
            absent.append({"kind": kind, "name": name, "va": va, "properties": sum("inner_of" not in r for r in theirs)})
            continue
        seen.add(name)
        mine = [json.loads(l) for l in open(ours_file, encoding="utf-8-sig") if l.strip()]
        missing, extra, changed, order, editor = compare(theirs, mine, mask, args.editor)
        if kind == "UFunction":
            fm = FUNC_RX.search(f.read_text(encoding="utf-8", errors="replace"))
            theirs_flags = int(fm.group(1), 0) if fm else None
            if theirs_flags is not None and theirs_flags != our_funcs[name]:
                x = theirs_flags ^ our_funcs[name]
                changed.append(f"function flags 0x{theirs_flags:x} vs ours 0x{our_funcs[name]:x} (differ 0x{x:x})")
        results.append({"kind": kind, "name": name, "va": va, "atlas": len(theirs), "ours": len(mine),
                        "missing": missing, "extra": extra, "changed": changed, "order": order, "editor_only": editor})

    only_ours = sorted(our_classes - seen_classes) + [f"F{s}" for s in sorted(our_structs - seen_structs)]
    only_ours_funcs = sorted(set(our_funcs) - seen_funcs)
    differing = [r for r in results if r["missing"] or r["extra"] or r["changed"] or r["order"]]
    types = [r for r in results if r["kind"] != "UFunction"]
    funcs = [r for r in results if r["kind"] == "UFunction"]
    totals = {
        "types_compared": len(types),
        "identical": sum(r not in differing for r in types),
        "differing": sum(r in differing for r in types),
        "missing_properties": sum(len(r["missing"]) for r in types),
        "extra_properties": sum(len(r["extra"]) for r in types),
        "changed_properties": sum(len(r["changed"]) for r in types),
        "order_differs": sum(1 for r in types if r["order"]),
        "editor_only_properties_ignored": sum(len(r["editor_only"]) for r in types),
        "atlas_only_types": sum(a["kind"] != "UFunction" for a in absent),
        "ours_only_types": len(only_ours),
    }
    if funcs or our_funcs:
        totals.update({
            "functions_compared": len(funcs),
            "functions_identical": sum(r not in differing for r in funcs),
            "functions_differing": sum(r in differing for r in funcs),
            "atlas_only_functions": sum(a["kind"] == "UFunction" for a in absent),
            "ours_only_functions": len(only_ours_funcs),
        })

    lines = ["# Reflection diff: ATLAS vs our engine", "",
             f"ATLAS `{args.atlas_dir}` vs ours `{args.ours_dir}`; flags compared without computed bits"
             + (f" and mask 0x{mask:x}" if mask else "") + ".", "",
             "| | count |", "|---|---|"] + [f"| {k} | {v} |" for k, v in totals.items()] + [""]
    lines += ["## Types ATLAS has and our engine lacks", ""]
    lines += [f"- {a['kind'][1:]} `{a['name']}` ({a['properties']} properties) — @{a['va']}" for a in absent] or ["(none)"]
    lines += ["", "## Types that differ (most missing properties first)", ""]
    for r in sorted(differing, key=lambda r: (-len(r["missing"]), r["name"])):
        lines.append(f"### {r['kind'][1:]} `{r['name']}` — ATLAS {r['atlas']} / ours {r['ours']} rows (@{r['va']})")
        lines += [f"- missing: {x}" for x in r["missing"]]
        lines += [f"- extra in ours: {x}" for x in r["extra"]]
        lines += [f"- changed: {x}" for x in r["changed"]]
        if r["order"]:
            lines.append("- declaration order differs")
        lines.append("")
    lines += ["## Types only in our engine", ""] + [f"- `{n}`" for n in only_ours]
    if only_ours_funcs:
        lines += ["", "## Functions only in our engine", ""] + [f"- `{n}`" for n in only_ours_funcs]
    Path(args.report).write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    if args.json:
        Path(args.json).write_bytes(json.dumps({"totals": totals, "absent": absent, "differing": differing,
                                                "ours_only": only_ours, "ours_only_functions": only_ours_funcs},
                                               indent=1).encode("utf-8"))
    for k, v in totals.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
