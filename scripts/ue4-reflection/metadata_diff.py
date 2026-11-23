"""Compare our engine's UHT metadata with ATLAS's (from the DevKit) — categories, tooltips (header comments), meta
specifiers, default arguments — per type, member and key.

ATLAS side: the JSON lines of `devkit_metadata.py parse` (type, member, kind, key, value). Ours: UHT's generated code
for the module (`<Module>.generated.*.cpp` under Engine/Intermediate/Build/Win64/Inc/<Module>), where each
Z_Construct_U{Class,Function,ScriptStruct,Enum}_* function creates its properties as
`UProperty* NewProp_X = new(Outer, TEXT("X"), ...)` and sets `MetaData->SetValue(Object, TEXT(Key), TEXT(Value))`.
Both sides use the same names (type = the Z_Construct suffix, functions as `<Class>.<Function>`).

Usage: python -I _tools/metadata_diff.py <devkit.metadata.jsonl> <Inc/<Module> dir> --report <out.md> [--json <out.json>]
       [--keys Category,ToolTip,...]   compare only these keys (default: all but ModuleRelativePath / IncludePath)
"""
import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

DEF = re.compile(r"^\t(?:\w+_API )?(?:class )?U(?:Class|Function|ScriptStruct|Enum)\* (Z_Construct_U(Class|Function|ScriptStruct|Enum)_(\w+))\(\)\s*$",
                 re.M)
TEXTLIT = r'TEXT\("((?:[^"\\]|\\.)*)"\)'
NEWPROP = re.compile(r"\b(NewProp_\w+) = new\(\w+, " + TEXTLIT)
SETVALUE = re.compile(r"MetaData->SetValue\((\w+), " + TEXTLIT + r", " + TEXTLIT + r"\);")
SELF = {"OuterClass", "ReturnClass", "ReturnFunction", "ReturnStruct", "ReturnEnum"}
SKIP = {"ModuleRelativePath", "IncludePath", "(FunctionFlags)"}


def unescape(s):
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "r": "\r", "t": "\t"}.get(m.group(1), m.group(1)), s)


def ours(inc_dir):
    """{(type, member): {key: value}} from UHT's generated code."""
    out = defaultdict(dict)
    for f in sorted(Path(inc_dir).glob("*.generated*.cpp")):
        text = f.read_text(encoding="utf-8", errors="replace")
        defs = list(DEF.finditer(text))
        for i, d in enumerate(defs):
            body = text[d.end():defs[i + 1].start() if i + 1 < len(defs) else len(text)]
            kind, rest = d.group(2), d.group(3)
            if rest.endswith("_NoRegister"):
                continue
            tname = rest
            if kind == "Function":
                cls, _, fn = rest.partition("_")
                tname = f"{cls}.{fn}"
            props = {m.group(1): unescape(m.group(2)) for m in NEWPROP.finditer(body)}
            for m in SETVALUE.finditer(body):
                obj = m.group(1)
                member = "" if obj in SELF else props.get(obj, "?" + obj)
                out[(tname, member)][unescape(m.group(2))] = unescape(m.group(3))
    return out


def atlas(jsonl):
    out = defaultdict(dict)
    for l in open(jsonl, encoding="utf-8"):
        r = json.loads(l)
        out[(r["type"], r["member"])][r["key"]] = r["value"]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("devkit")
    ap.add_argument("inc")
    ap.add_argument("--report", required=True)
    ap.add_argument("--json")
    ap.add_argument("--keys")
    a = ap.parse_args()
    keys = set(a.keys.split(",")) if a.keys else None
    theirs, mine = atlas(a.devkit), ours(a.inc)
    our_types = {t for t, _ in mine}
    stats = Counter()
    diffs = []
    only_atlas_members = []
    for (t, m), kv in sorted(theirs.items()):
        if t not in our_types:
            stats["atlas_only_type_entries"] += 1
            continue
        if (t, m) not in mine:
            # an ATLAS member we lack (or one without any metadata in ours)
            if any(k not in SKIP for k in kv):
                only_atlas_members.append((t, m))
            continue
        ok = mine[(t, m)]
        for k in sorted(set(kv) | set(ok)):
            if k in SKIP or (keys and k not in keys):
                continue
            va, vo = kv.get(k), ok.get(k)
            if va == vo:
                stats["same"] += 1
                continue
            kind = "missing" if vo is None else "extra" if va is None else "differs"
            stats[f"{kind}:{'ToolTip' if k == 'ToolTip' else 'Category' if k == 'Category' else 'other'}"] += 1
            diffs.append({"type": t, "member": m, "key": k, "atlas": va, "ours": vo, "kind": kind})
    for (t, m), kv in sorted(mine.items()):
        if (t, m) not in theirs and t in {x for x, _ in theirs}:
            stats["ours_only_member_entries"] += 1
    by_type = Counter(d["type"].split(".")[0] for d in diffs)
    lines = ["# Metadata diff: ATLAS (DevKit) vs our engine", "",
             f"ATLAS `{a.devkit}` vs ours `{a.inc}`" + (f"; keys {sorted(keys)}" if keys else "; all keys but "
             + ", ".join(sorted(SKIP))) + ".", "", "| | count |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in sorted(stats.items())]
    lines += [f"| members ATLAS has (with metadata) that ours lacks | {len(only_atlas_members)} |", "",
              "## Most differences by type", ""] + [f"- `{t}`: {n}" for t, n in by_type.most_common(40)]
    lines += ["", "## Differences", ""]
    for d in diffs:
        loc = d["type"] + ("::" + d["member"] if d["member"] else "")
        short = lambda v: "—" if v is None else v.replace("\n", " / ")[:120]
        lines.append(f"- `{loc}` {d['key']} ({d['kind']}): ATLAS `{short(d['atlas'])}` / ours `{short(d['ours'])}`")
    Path(a.report).write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    if a.json:
        Path(a.json).write_text(json.dumps({"stats": stats, "diffs": diffs, "atlas_only_members": only_atlas_members},
                                           indent=1, ensure_ascii=False), encoding="utf-8", newline="\n")
    print(dict(stats), "atlas-only members:", len(only_atlas_members))


if __name__ == "__main__":
    main()
