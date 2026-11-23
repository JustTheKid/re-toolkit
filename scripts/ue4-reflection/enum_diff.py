"""Compare the reflected enums (UEnum: value names in order, C++ form) of ATLAS's engine with ours.

UE 4.5 enums are an ordered list of names (`UEnum::SetEnums`; a value is its index), and saved enum properties
store the name, so a missing, extra or moved name changes what content loads to.

ATLAS side: the DevKit's decompiled `Z_Construct_UEnum_*` functions (`devkit_metadata.py export`), whose name
literals come in order: the enum's own name, then every value; the import-block calls and literals are resolved as
in devkit_metadata.py. Ours: UHT's generated code, `EnumNames.Add(FName(TEXT("...")))` and
`SetEnums(EnumNames, UEnum::ECppForm::...)`.

Usage: python -I _tools/enum_diff.py <devkit decompile dir> --dll <DevKit dll> <Inc/<Module> dir> --report <out.md>
       [--json <out.json>]
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devkit_metadata import PE, resolve, unquote  # noqa: E402

LIT = re.compile(r'\[\?\?0FName@@QEAA@PEB_W[^\]]*\]\s*\([^,;]*,\s*L"((?:[^"\\]|\\.)*)"')
# the Engine DLL calls SetEnums through its import block; a plugin DLL without a PDB shows UEnum::SetEnums(..., <n>)
FORM = re.compile(r"(?:\[\?SetEnums@UEnum@@[^\]]*\]|UEnum::SetEnums)\s*\([^;]*?,\s*(\d|\w+)\s*\)")
OURS_DEF = re.compile(r"^\tUEnum\* (Z_Construct_UEnum_\w+)\(\)\s*$", re.M)
OURS_NAME = re.compile(r'EnumNames\.Add\(FName\(TEXT\("([^"]*)"\)\)\);')
OURS_FORM = re.compile(r"SetEnums\(EnumNames, UEnum::ECppForm::(\w+)\)")
FORMS = {"0": "Regular", "1": "Namespaced", "2": "EnumClass"}


def atlas(dirpath, dll):
    pe = PE(dll)
    imps = pe.imports()
    block = next((va for va, s in imps.items() if s == "?GErrorHist@@3PA_WA"), None)  # Engine DLL only; others: resolve()
    out = {}
    for f in sorted(Path(dirpath).glob("Z_Construct_UEnum_*.c")):
        text = resolve(f.read_text(encoding="utf-8", errors="replace"), pe, imps, block)
        names = [unquote(m.group(1)) for m in LIT.finditer(text)]
        fm = FORM.search(text)
        out[f.stem.split("@")[0]] = {"names": names[1:], "form": FORMS.get(fm.group(1), fm.group(1)) if fm else None,
                                     "va": f.stem.split("@")[1]}
    return out


def ours(inc):
    out = {}
    for f in sorted(Path(inc).glob("*.generated*.cpp")):
        text = f.read_text(encoding="utf-8", errors="replace")
        defs = list(OURS_DEF.finditer(text))
        for i, d in enumerate(defs):
            body = text[d.end():defs[i + 1].start() if i + 1 < len(defs) else len(text)]
            body = body[:body.find("\n\t}\n") + 1] if "\n\t}\n" in body else body
            fm = OURS_FORM.search(body)
            out[d.group(1)] = {"names": OURS_NAME.findall(body), "form": fm.group(1) if fm else None}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("devkit_dir")
    ap.add_argument("--dll", required=True)
    ap.add_argument("inc")
    ap.add_argument("--report", required=True)
    ap.add_argument("--json")
    a = ap.parse_args()
    theirs, mine = atlas(a.devkit_dir, a.dll), ours(a.inc)
    rows, same, only_atlas = [], 0, []
    for name, t in sorted(theirs.items()):
        o = mine.get(name)
        if o is None:
            only_atlas.append(name)
            continue
        if t["names"] == o["names"] and t["form"] == o["form"]:
            same += 1
            continue
        missing = [n for n in t["names"] if n not in o["names"]]
        extra = [n for n in o["names"] if n not in t["names"]]
        reordered = not missing and not extra and t["names"] != o["names"]
        rows.append({"enum": name, "va": t["va"], "missing": missing, "extra": extra, "reordered": reordered,
                     "form": (t["form"], o["form"]) if t["form"] != o["form"] else None,
                     "atlas": t["names"], "ours": o["names"]})
    only_ours = sorted(set(mine) - set(theirs))
    lines = ["# Enum diff: ATLAS (DevKit) vs our engine", "",
             f"ATLAS `{a.devkit_dir}` vs ours `{a.inc}`.", "", "| | count |", "|---|---|",
             f"| enums compared | {same + len(rows)} |", f"| identical | {same} |", f"| differing | {len(rows)} |",
             f"| only in ATLAS | {len(only_atlas)} |", f"| only in ours | {len(only_ours)} |", "", "## Differing", ""]
    for r in rows:
        lines.append(f"### `{r['enum']}` (@{r['va']})")
        if r["missing"]:
            lines.append("- missing: " + ", ".join(f"`{n}`" for n in r["missing"]))
        if r["extra"]:
            lines.append("- extra: " + ", ".join(f"`{n}`" for n in r["extra"]))
        if r["reordered"]:
            lines.append("- same names, other order")
        if r["form"]:
            lines.append(f"- C++ form: ATLAS {r['form'][0]} / ours {r['form'][1]}")
        lines.append("")
    lines += ["## Only in ATLAS", ""] + [f"- `{n}`" for n in only_atlas] + ["", "## Only in ours", ""]
    lines += [f"- `{n}`" for n in only_ours]
    Path(a.report).write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    if a.json:
        Path(a.json).write_text(json.dumps({"differing": rows, "only_atlas": only_atlas, "only_ours": only_ours},
                                           indent=1), encoding="utf-8", newline="\n")
    print(f"{same + len(rows)} compared, {same} identical, {len(rows)} differing, {len(only_atlas)} only ATLAS, "
          f"{len(only_ours)} only ours")


if __name__ == "__main__":
    main()
