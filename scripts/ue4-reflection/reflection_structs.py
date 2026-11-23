"""Compare the script structs' parent struct and declared flags (EStructFlags) of ATLAS's engine with ours.

The property tables (reflection_diff_all.py) cover members; this covers the struct itself: the super struct and the
flags UHT passes to the UScriptStruct constructor (Native, RequiredAPI = ENGINE_API, Atomic, Immutable, ...).

ATLAS: the server's Z_Construct_UScriptStruct_* decompiles, where Ghidra prints
`UScriptStruct::UScriptStruct(Outer, PCIP, <super>, <ops>, STRUCT_RequiredAPI|STRUCT_Native, ...)` with the super as a
variable assigned from `Z_Construct_UScriptStruct_<Parent>()` just before (or 0 for none).
Ours: UHT's generated code, `UScriptStruct(FPostConstructInitializeProperties(), Z_Construct_UScriptStruct_<Parent>()
| NULL, new UScriptStruct::TCppStructOps<F>, EStructFlags(0x...))`.

Usage: python -I _tools/reflection_structs.py <atlas Z_Construct dir> <Inc/<Module> dir> --report <out.md> [--json <out.json>]
"""
import argparse
import json
import re
from pathlib import Path

FLAGS = {"STRUCT_NoFlags": 0x0, "STRUCT_Native": 0x1, "STRUCT_IdenticalNative": 0x2, "STRUCT_HasInstancedReference": 0x4,
         "STRUCT_Atomic": 0x10, "STRUCT_Immutable": 0x20, "STRUCT_AddStructReferencedObjects": 0x40,
         "STRUCT_RequiredAPI": 0x200, "STRUCT_NetSerializeNative": 0x400, "STRUCT_SerializeNative": 0x800,
         "STRUCT_CopyNative": 0x1000, "STRUCT_IsPlainOldData": 0x2000, "STRUCT_NoDestructor": 0x4000,
         "STRUCT_ZeroConstructor": 0x8000, "STRUCT_ExportTextItemNative": 0x10000,
         "STRUCT_ImportTextItemNative": 0x20000, "STRUCT_PostSerializeNative": 0x40000}
CALL = re.compile(r"UScriptStruct::UScriptStruct\s*\(\s*\w+\s*,\s*\w+\s*,\s*(\(UScriptStruct \*\)0x0|\w+)\s*,\s*[^,]+,\s*"
                  r"([A-Za-z_|0-9x ]+?)\s*,")
OURS_DEF = re.compile(r"^\tUScriptStruct\* (Z_Construct_UScriptStruct_\w+)\(\)\s*$", re.M)
OURS_CALL = re.compile(r"UScriptStruct\(FPostConstructInitializeProperties\(\), (?:(Z_Construct_UScriptStruct_\w+)\(\)|NULL), "
                       r"new UScriptStruct::TCppStructOps<\w+>, EStructFlags\((0x[0-9a-fA-F]+)\)\)")
NAMES = {v: k for k, v in FLAGS.items() if v}


def flag_value(expr):
    total = 0
    for part in expr.split("|"):
        part = part.strip()
        if part in FLAGS:
            total |= FLAGS[part]
        else:
            total |= int(part, 0)
    return total


def names(v):
    return "|".join(n for bit, n in sorted(NAMES.items()) if v & bit) or "0"


def atlas(dirpath):
    out = {}
    for f in sorted(Path(dirpath).glob("Z_Construct_UScriptStruct_*.c")):
        text = f.read_text(encoding="utf-8", errors="replace")
        m = CALL.search(text)
        if not m:
            continue
        var, flags = m.group(1), m.group(2)
        parent = None
        if not var.startswith("("):
            assigns = list(re.finditer(re.escape(var) + r"\s*=\s*Z_Construct_UScriptStruct_(\w+)\(\);", text[:m.start()]))
            if assigns:
                parent = "Z_Construct_UScriptStruct_" + assigns[-1].group(1)
        out[f.stem.split("@")[0]] = {"parent": parent, "flags": flag_value(flags), "va": f.stem.split("@")[1]}
    return out


def ours(inc):
    out = {}
    for f in sorted(Path(inc).glob("*.generated*.cpp")):
        text = f.read_text(encoding="utf-8", errors="replace")
        defs = list(OURS_DEF.finditer(text))
        for i, d in enumerate(defs):
            body = text[d.end():defs[i + 1].start() if i + 1 < len(defs) else len(text)]
            m = OURS_CALL.search(body)
            if m:
                out[d.group(1)] = {"parent": m.group(1), "flags": int(m.group(2), 16)}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("atlas_dir")
    ap.add_argument("inc")
    ap.add_argument("--report", required=True)
    ap.add_argument("--json")
    a = ap.parse_args()
    theirs, mine = atlas(a.atlas_dir), ours(a.inc)
    rows, same = [], 0
    for name, t in sorted(theirs.items()):
        o = mine.get(name)
        if o is None:
            continue
        if t["parent"] == o["parent"] and t["flags"] == o["flags"]:
            same += 1
            continue
        rows.append({"struct": name, "va": t["va"], "parent": (t["parent"], o["parent"]),
                     "flags": (names(t["flags"]), names(o["flags"]))})
    lines = ["# Script struct parents and flags: ATLAS vs our engine", "",
             f"ATLAS `{a.atlas_dir}` vs ours `{a.inc}`; structs both sides construct.", "", "| | count |", "|---|---|",
             f"| compared | {same + len(rows)} |", f"| identical | {same} |", f"| differing | {len(rows)} |", "", "## Differing", ""]
    for r in rows:
        lines.append(f"### `{r['struct']}` (@{r['va']})")
        if r["parent"][0] != r["parent"][1]:
            lines.append(f"- parent: ATLAS {r['parent'][0]} / ours {r['parent'][1]}")
        if r["flags"][0] != r["flags"][1]:
            lines.append(f"- flags: ATLAS {r['flags'][0]} / ours {r['flags'][1]}")
        lines.append("")
    Path(a.report).write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    if a.json:
        Path(a.json).write_text(json.dumps(rows, indent=1), encoding="utf-8", newline="\n")
    print(f"{same + len(rows)} compared, {same} identical, {len(rows)} differing")


if __name__ == "__main__":
    main()
