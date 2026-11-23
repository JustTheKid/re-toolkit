"""Class-level reflection diff: superclass, class flags, config name and interfaces of every class ATLAS reflects in a
module vs our engine's (reflection_diff_all.py compares the properties only).

ATLAS side: the folder of Z_Construct_UClass_* decompiles (e.g. _re/corpus/server/_reflection_engine) plus the server
PDB for the superclass (Ghidra often inlines the superclass's Z_Construct into the class's, so the decompile alone does
not say which class is the parent). Our side: UHT's output for the module (Engine.generated.*.cpp under
Engine/Intermediate/Build/Win64/Inc/<Module>).

Read from ATLAS's decompile, after the class's own StaticClass call: the first `ClassFlags | 0x...`, the FName assigned
to ClassConfigName and, for each growth of the Interfaces array, the class referenced just before it.

Usage: python -I _tools/reflection_classes.py <atlas_dir> <generated_dir> --exe <ShooterGameServer.exe>
       --report <out.md> [--json <out.json>]
       python -I _tools/reflection_classes.py _re/corpus/devkit/<module>[-typed] <Inc/<Module>> --dll <DevKit DLL>
       --report <out.md>          (a DevKit editor DLL, step 1.9d; its own PDB if it has one)
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pdb_struct import Pdb  # noqa: E402

FILE_RX = re.compile(r"^Z_Construct_UClass_(\w+?)@([0-9a-f]+)\.c$")
# DevKit DLLs without a PDB name no fields: UClass::ClassFlags is the store at +0x118
FLAGS_RX = re.compile(r"ClassFlags\s*(?:=\s*\w+->ClassFlags\s*\||\|=)\s*(0x[0-9a-fA-F]+)"
                      r"|\*\(uint \*\)\(\w+ \+ 0x118\) = \*\(uint \*\)\(\w+ \+ 0x118\) \| (0x[0-9a-fA-F]+)")
PARENT_RX = re.compile(r"\bZ_Construct_UClass_(\w+?)\(\)")
# typed DevKit decompiles store the FName field by field: (pUVar2->ClassConfigName).ComparisonIndex = ...
CONFIG_RX = re.compile(r"ClassConfigName(?:\)\.ComparisonIndex)?\s*=")
FNAME_RX = re.compile(r'FName::FName\([^;]*?L"(\w+)"')
# FImplementedInterface is 16 bytes: its TArray::Emplace is folded with FRenderingCompositeOutputRef's in ATLAS's binary
IFACE_RX = re.compile(r"=\s*\(\w+->Interfaces\)\.ArrayNum;|\bEmplace<FRenderingCompositeOutputRef"
                      r"|Emplace<FImplementedInterface>\s*\(&\w+->Interfaces")  # typed DevKit decompiles
CLASSREF_RX = re.compile(r"GetPrivateStaticClassBody<(\w+)>|TClassCompiledInDefer<(\w+)>::Register"
                         r"|\b(\w+)::(?:GetPrivateStaticClass|StaticClass)\s*\("
                         r"|Z_Construct_UClass_(\w+?)(?:_NoRegister)?\(\)")  # not the casts Ghidra types locals with
OUR_SUPER_RX = re.compile(r"^\t\t\t(?:Z_Construct_UClass_(\w+)|(\w+)::StaticClass)\(\);", re.M)
GEN_FUNC_RX = re.compile(r"^\tUClass\* Z_Construct_UClass_(\w+)\(\)\n\t\{\n(.*?)^\t\}", re.M | re.S)

CLASS_FLAGS = {0x1: "Abstract", 0x2: "DefaultConfig", 0x4: "Config", 0x8: "Transient", 0x10: "Parsed",
               0x20: "Localized", 0x40: "AdvancedDisplay", 0x80: "Native", 0x100: "NoExport", 0x200: "NotPlaceable",
               0x400: "PerObjectConfig", 0x800: "PointersDefaultToWeak", 0x1000: "EditInlineNew",
               0x2000: "CollapseCategories", 0x4000: "Interface", 0x8000: "CustomConstructor", 0x10000: "Const",
               0x20000: "PointersDefaultToAutoWeak", 0x40000: "CompiledFromBlueprint", 0x80000: "MinimalAPI",
               0x100000: "RequiredAPI", 0x200000: "DefaultToInstanced", 0x400000: "TokenStreamAssembled",
               0x800000: "HasInstancedReference", 0x1000000: "Hidden", 0x2000000: "Deprecated",
               0x4000000: "HideDropDown", 0x10000000: "Intrinsic", 0x20000000: "Temporary",
               0x40000000: "ConfigDoNotCheckDefaults", 0x80000000: "NewerVersionExists"}


def flag_names(v):
    return "|".join(n for b, n in CLASS_FLAGS.items() if v & b) or "0"


def last_ref(text, own):
    name = None
    for m in CLASSREF_RX.finditer(text):
        n = next(g for g in m.groups() if g)
        if n != own:
            name = n
    return name


def atlas_class(path, cls, pdb, devkit=None):
    text = path.read_text(encoding="utf-8", errors="replace")
    if devkit is not None:
        # a DevKit DLL's decompile in the server corpus's form (literals inlined, imported calls named)
        import reflection_table
        text = reflection_table.devkit_text(text.replace("\r", ""), devkit,
                                            reflection_table.local_classes(str(path.parent)))
    own = re.search(rf"\b{cls}::(?:GetPrivateStaticClass|StaticClass)\s*\(|GetPrivateStaticClassBody<{cls}>", text)
    if not own:
        return None
    body = text[own.end():]
    m = FLAGS_RX.search(body)
    out = {"flags": int(m.group(1) or m.group(2), 16) if m else 0, "config": None, "interfaces": [], "super": None}
    m = CONFIG_RX.search(body)
    if m:
        names = FNAME_RX.findall(body[:m.start()])
        out["config"] = names[-1] if names else "?"
    elif devkit is not None and not (pdb and pdb.members(cls)):
        # without a PDB the store into ClassConfigName has no name: the config is the FName literal that no property
        # of the class is named after (the first FNames of the body, before the properties' blocks)
        import reflection_table
        props = {r["name"] for r in reflection_table.table(str(path))[1]}
        names = [n for n in FNAME_RX.findall(body) if n not in props]
        out["config"] = names[0] if names else None
    for m in IFACE_RX.finditer(body):
        out["interfaces"].append(last_ref(body[:m.start()], cls) or "?")
    bases = [b for b in ((pdb.members(cls) if pdb else None) or []) if b.get("base") and b["name"][:1] in "UA"]
    if bases:
        out["super"] = bases[0]["name"]
    elif devkit is not None:
        # the parent's Z_Construct is called first, before the class registers itself
        m = PARENT_RX.search(text[:own.start()])
        out["super"] = m.group(1) if m else None
    return out


def our_classes(gen_dir):
    out = {}
    for p in sorted(Path(gen_dir).glob("*.generated*.cpp")):
        for m in GEN_FUNC_RX.finditer(p.read_text(encoding="utf-8", errors="replace")):
            cls, body = m.group(1), m.group(2)
            if cls.endswith("_NoRegister"):
                continue
            sup = OUR_SUPER_RX.search(body)
            fl = re.search(r"ClassFlags \|= (0x[0-9A-Fa-f]+)", body)
            cfg = re.search(r'ClassConfigName = FName\(TEXT\("(\w+)"\)\)', body)
            out[cls] = {"super": (sup.group(1) or sup.group(2)) if sup else None, "flags": int(fl.group(1), 16) if fl else 0,
                        "config": cfg.group(1) if cfg else None,
                        "interfaces": re.findall(r"FImplementedInterface\(Z_Construct_UClass_(\w+)_NoRegister\(\)", body)}
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("atlas_dir")
    ap.add_argument("generated_dir")
    ap.add_argument("--exe", help="the binary whose PDB gives the superclasses (the server exe, or the DevKit DLL)")
    ap.add_argument("--dll", help="a DevKit editor DLL the decompiles come from (typed or untyped export): their "
                    "literals are inlined first; without a PDB the parent comes from the decompile (step 1.9d)")
    ap.add_argument("--report", required=True)
    ap.add_argument("--json")
    args = ap.parse_args()

    devkit = None
    if args.dll:
        from devkit_metadata import PE
        import reflection_table
        devkit = reflection_table.DEVKIT = PE(args.dll)
    exe = args.exe or args.dll
    pdb = Pdb(exe) if exe and Path(exe).with_suffix(".pdb").exists() else None
    if pdb is None and not args.dll:
        sys.exit("--exe needs a binary with its PDB next to it")
    ours = our_classes(args.generated_dir)
    rows, unread, compared = [], [], 0
    for p in sorted(Path(args.atlas_dir).iterdir()):
        m = FILE_RX.match(p.name)
        if not m or m.group(1).endswith("_NoRegister") or m.group(1) not in ours:
            continue
        cls, va = m.group(1), m.group(2)
        a = atlas_class(p, cls, pdb, devkit)
        if a is None:
            unread.append(cls)
            continue
        o = ours[cls]
        compared += 1
        diffs = []
        if a["super"] != o["super"]:
            diffs.append(f"super {a['super']} vs ours {o['super']}")
        if a["flags"] != o["flags"]:
            x = a["flags"] ^ o["flags"]
            diffs.append(f"flags 0x{a['flags']:x} vs ours 0x{o['flags']:x} (ATLAS only: {flag_names(x & a['flags'])}; "
                         f"ours only: {flag_names(x & o['flags'])})")
        if a["config"] != o["config"]:
            diffs.append(f"config {a['config']} vs ours {o['config']}")
        if sorted(a["interfaces"]) != sorted(o["interfaces"]):
            diffs.append(f"interfaces {a['interfaces']} vs ours {o['interfaces']}")
        if diffs:
            rows.append({"name": cls, "va": va, "diffs": diffs})

    totals = {"classes_compared": compared, "identical": compared - len(rows), "differing": len(rows),
              "unread": len(unread),
              "super": sum(any(d.startswith("super") for d in r["diffs"]) for r in rows),
              "flags": sum(any(d.startswith("flags") for d in r["diffs"]) for r in rows),
              "config": sum(any(d.startswith("config") for d in r["diffs"]) for r in rows),
              "interfaces": sum(any(d.startswith("interfaces") for d in r["diffs"]) for r in rows)}
    lines = ["# Class-level reflection diff", "", *(f"- {k}: {v}" for k, v in totals.items()), ""]
    if unread:
        lines += ["Own StaticClass call not found (not compared): " + ", ".join(unread), ""]
    for r in rows:
        lines += [f"### `{r['name']}` (@{r['va']})", *(f"- {d}" for d in r["diffs"]), ""]
    Path(args.report).write_text("\n".join(lines), encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps({"totals": totals, "differing": rows, "unread": unread}, indent=1),
                                   encoding="utf-8")
    for k, v in totals.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
