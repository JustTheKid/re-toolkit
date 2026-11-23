"""reflect.py: what ATLAS's UnrealHeaderTool saw in the game's headers, read back from its output - the reflection
tables of the four ShooterGame.generated units (the Z_Construct_* decompiles in _re/corpus/server/_reflection_ShooterGame)
and the DevKit metadata - as one JSON for game_headers.py --reflect (2026-11-04, the tool pass: the generated 45%).

Per class: the UCLASS specifiers, the parent and interfaces, each reflected property's UPROPERTY specifiers (in the
table's order), each UFunction's UFUNCTION specifiers, access and parameter names. Per struct: the USTRUCT specifiers and
its properties. Per enum: its C++ form (Regular / Namespaced / EnumClass) and names. The specifier logic is
reflection_newtype.py's (step 1.6 of phase 4b, the engine's headers); this is the same reading for every type at once.

Usage: python _tools/rebuild/reflect.py [--out build/loop/all/reflect.json] [--only <regex on type names>]
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "_tools"))
import reflection_codegen as codegen  # noqa: E402
import reflection_classes  # noqa: E402
import reflection_newtype as nt  # noqa: E402
import reflection_structs  # noqa: E402
import reflection_table  # noqa: E402
from pdb_struct import Pdb  # noqa: E402

EXE = r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe"
CORPUS = ROOT / "_re" / "corpus" / "server" / "_reflection_ShooterGame"
META = ROOT / "_re" / "corpus" / "devkit" / "game.metadata.jsonl"
OUT = ROOT / "build" / "loop" / "all" / "reflect.json"
OWNER = {}  # a UFunction table's file name -> its class
CUSTOM_THUNKS = set()  # (class, function) whose exec thunk a hand-written unit defines


SIMPLE = {"UBoolProperty": "bool", "UFloatProperty": "float", "UDoubleProperty": "double", "UIntProperty": "int32",
          "UInt64Property": "int64", "UUInt32Property": "uint32", "UUInt64Property": "uint64", "UInt16Property": "int16",
          "UUInt16Property": "uint16", "UInt8Property": "int8", "UStrProperty": "FString", "UNameProperty": "FName",
          "UTextProperty": "FText", "UClassProperty": "TSubclassOf<UObject>"}  # UHT 4.5 spells a class property so
OWNERS = set()
ENUM_FORMS = {}


def base_type(r, rows):
    """a parameter row's C++ type by its property kind and the class, struct or enum it refers to [INFERRED]"""
    k, ref = r["kind"], r.get("ref")
    if k in SIMPLE:
        return SIMPLE[k]
    if k == "UObjectProperty":
        return f"{ref or 'UObject'}*"
    if k == "UWeakObjectProperty":
        return f"TWeakObjectPtr<{ref or 'UObject'}>"
    if k == "UStructProperty":
        return own_name(ref, OWNERS) if ref else "FTODOStruct"
    if k == "UByteProperty":
        e = own_name(ref, OWNERS) if ref else None
        if not e or not (e in ENUM_FORMS or re.match(r"^E[A-Z]", e)):
            return "uint8"  # no enum, or the reader's reference is another object (a UFunction)
        form = ENUM_FORMS.get(e, "Namespaced")
        return e if form == "EnumClass" else f"TEnumAsByte<{e}::Type>" if form == "Namespaced" else f"TEnumAsByte<{e}>"
    if k == "UArrayProperty":
        inner = next((x for x in rows if x.get("inner_of") == r["name"]), None)
        return f"TArray<{base_type(inner, rows) if inner else 'uint8'}>"
    if k == "UInterfaceProperty":
        return f"TScriptInterface<I{(ref or 'UInterface')[1:]}>"
    return f"/*{k}*/ int32"


def param_type(r, rows, ret=False):
    """with the parameter's passing: const T& (CPF_ConstParm | CPF_ReferenceParm), T& (CPF_OutParm), else by value"""
    f = int(r.get("flags") or "0", 16) if isinstance(r.get("flags"), str) else (r.get("flags") or 0)
    t = base_type(r, rows)
    if ret:
        return t
    if f & 0x8000000 or (f & 0x2 and r["kind"] in ("UStructProperty", "UStrProperty", "UTextProperty", "UArrayProperty")):
        return f"const {t}&"
    if f & 0x100:
        return f"{t}&"
    return t


def own_name(cpp, owners):
    """UPrimalItem_FCropItemPhaseData -> FCropItemPhaseData, UDatabase_SharedLog_TradeTripWorldChangeType ->
    TradeTripWorldChangeType, ShooterGame_EShipType -> EShipType: the longest prefix that is a class or the package"""
    for o in sorted(owners, key=len, reverse=True):
        if cpp.startswith(o + "_") and len(cpp) > len(o) + 1:
            return cpp[len(o) + 1:]
    m = re.match(r"^[AUI][A-Z][A-Za-z0-9]*_([FE][A-Z]\w*)$", cpp)  # an engine class's struct or enum (UObject_FVector)
    if m:
        return m.group(1)
    m = re.match(r"^[A-Z][A-Za-z0-9]*_(E[A-Z]\w*)$", cpp)  # an engine module's enum (SlateCore_ETextCommit)
    return m.group(1) if m else cpp


def load_meta():
    by_type = defaultdict(lambda: defaultdict(list))
    for line in open(META, encoding="utf-8"):
        r = json.loads(line)
        by_type[r["type"]][r["member"]].append(r)
    return by_type


def prop_specs(path, owner, meta_rows, members):
    """[(member, 'UPROPERTY(...)', kind, bits)] in the table's order, for the table at path"""
    reflection_table.OUTER_SELF[str(path)] = owner
    sflags, rows = reflection_table.table(str(path))
    rows = list(reversed(rows))
    top = {r["name"]: r for r in rows if "inner_of" not in r}
    inner = {r["inner_of"]: r for r in rows if "inner_of" in r}
    text = path.read_text(encoding="utf-8", errors="replace")
    repnotify, last = {}, None
    for lm in re.finditer(r'L"(\w+)"', text):
        if lm.group(1) in top:
            last = lm.group(1)
        elif last:
            repnotify.setdefault(last, lm.group(1))
            last = None
    out = []
    for n, r in top.items():
        f = codegen.flag_value(r)
        fi = codegen.flag_value(inner[n]) if n in inner and codegen.flag_value(inner[n]) is not None else 0
        mm = meta_rows.get(n, [])
        cat = next((x["value"] for x in mm if x["key"] == "Category"), None)
        if cat and not re.match(r"^\w+$", cat):
            cat = f'"{cat}"'
        spec = codegen.specifiers((f or 0) & ~codegen.COMPUTED, cat, fi, r["kind"])
        spec = [s for s in spec if not s.startswith("meta=")]
        mt = nt.meta_text(mm) + (["ExposeOnSpawn=true"] if (f or 0) & codegen.CPF["ExposeOnSpawn"] else [])
        if mt:
            spec.append(f"meta=({', '.join(mt)})")
        if f and f & codegen.CPF["RepNotify"]:
            spec = [f"ReplicatedUsing={repnotify.get(n, 'OnRep_TODO_' + n)}" if s.startswith("ReplicatedUsing") else s for s in spec]
        bits = r["kind"] == "UBoolProperty" and r.get("native_bool") is False
        out.append({"name": n, "spec": f"UPROPERTY({', '.join(spec)})", "kind": r["kind"], "bitfield": bits,
                    "tooltip": next((x["value"] for x in mm if x["key"] == "ToolTip"), None),
                    "notes": codegen.notes(f or 0)})
    return out


def read_class(path, name, meta, pdb):
    info = reflection_classes.atlas_class(path, name, pdb) or {"flags": 0, "config": None, "interfaces": []}
    members = pdb.members(name) or []
    base = next((m for m in members if m["base"]), None)
    parent = info.get("super") or (base["name"] if base else "UObject")
    spec = nt.class_specifiers(info["flags"], meta[name][""], meta[parent][""], info["config"])
    funcs = []
    for fp in sorted(path.parent.glob(f"Z_Construct_UFunction_{name}_*.c")):
        if OWNER.get(fp.name) != name:
            continue  # a function of a class whose name extends this one's (UFoo_Bar's under UFoo_)
        fn = fp.name.split("@")[0][len(f"Z_Construct_UFunction_{name}_"):]
        text = fp.read_text(encoding="utf-8", errors="replace")
        fm = nt.FUNC_RX.search(text)
        flags = int(fm.group(1), 0) if fm else 0
        fmm = [x for x in meta.get(f"{name}.{fn}", {}).get("", [])]
        fspec, access, fnames = nt.function_specs(flags, fmm)
        fspec = [f'Category="{s[9:]}"' if s.startswith("Category=") and not s.startswith('Category="')
                 and not re.match(r"^\w+$", s[9:]) else s for s in fspec]  # Auto-Pilot: no plain word
        if (name, fn) in CUSTOM_THUNKS:  # its exec thunk is in a hand-written unit (UJsonObject's struct fields)
            fspec = ["CustomThunk"] + fspec
        reflection_table.OUTER_SELF[str(fp)] = name
        prow = [r for r in reversed(reflection_table.table(str(fp))[1]) if "inner_of" not in r]
        allrows = list(reversed(reflection_table.table(str(fp))[1]))
        funcs.append({"name": fn, "spec": f"UFUNCTION({', '.join(fspec)})", "access": access, "flags": flags,
                      "tooltip": next((x["value"] for x in fmm if x["key"] == "ToolTip"), None),
                      "defaults": {x["key"][len("CPP_Default_"):]: x["value"] for x in fmm if x["key"].startswith("CPP_Default_")},
                      "ptypes": [param_type(r, allrows) for r in prow if r["name"] != "ReturnValue"],
                      "ret": next((param_type(r, allrows, ret=True) for r in prow if r["name"] == "ReturnValue"), None),
                      "params": [r["name"] for r in prow if r["name"] != "ReturnValue"],
                      "returns": any(r["name"] == "ReturnValue" for r in prow), "names": sorted(fnames)})
    return {"kind": "class", "parent": parent, "flags": info["flags"], "interfaces": info.get("interfaces", []),
            "tooltip": next((x["value"] for x in meta[name][""] if x["key"] == "ToolTip"), None),
            "is_interface": bool(info["flags"] & 0x4000), "spec": spec,
            "props": prop_specs(path, name, meta[name], members), "funcs": funcs}


def read_struct(path, cpp, name, meta, pdb):
    m = reflection_structs.CALL.search(path.read_text(encoding="utf-8", errors="replace"))
    f = reflection_structs.flag_value(m.group(2)) if m else 0
    spec = [s for b, s in ((0x10, "atomic"), (0x20, "immutable")) if f & b]
    if any(r["key"] == "BlueprintType" and r["value"] == "true" for r in meta[cpp][""]):
        spec.append("BlueprintType")
    return {"kind": "struct", "flags": f, "spec": spec, "props": prop_specs(path, cpp, meta[cpp], pdb.members(name) or []),
            "tooltip": next((x["value"] for x in meta[cpp][""] if x["key"] == "ToolTip"), None)}


def read_enum(path):
    t = path.read_text(encoding="utf-8", errors="replace")
    form = re.search(r"SetEnums\([^,]*,[^,]*,(\w+)\)", t)
    names = re.findall(r'FName::FName\([^,]*,L"([^"]+)",FNAME_Add', t)
    return {"kind": "enum", "form": form.group(1) if form else "Regular", "names": names[1:] if names else []}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--only")
    a = ap.parse_args()
    meta = load_meta()
    pdb = Pdb(EXE)
    out, errors = {}, []
    # [CONFIRMED by the PDB] a UFunction whose exec thunk lies in a hand-written game object, not the generated ones:
    # UFUNCTION(CustomThunk) (UHT writes no thunk for it; the unit's DECLARE_FUNCTION / DEFINE_FUNCTION does)
    from reach_record import list_functions
    from func_match import Original
    sep = chr(92)
    o = Original(EXE, str(ROOT / "_re" / "cache"))
    for rva, (dec, mod, size) in list_functions(EXE, "(?i)" + re.escape(sep + "Shipping" + sep + "ShooterGame" + sep)).items():
        if ".generated" not in mod:
            m = re.search(r"\b(\w+)::exec(\w+)(?:\(|$)", o.undecorate(dec))  # the name only, no parameter list
            if m:
                CUSTOM_THUNKS.add((m.group(1), m.group(2)))
    classes = sorted({re.match(r"^Z_Construct_UClass_(\w+?)(?:_NoRegister)?$", p.name.split("@")[0]).group(1)
                      for p in CORPUS.glob("Z_Construct_UClass_*.c")}, key=len, reverse=True)
    owners = set(classes) | {"ShooterGame"}
    OWNERS.update(owners)
    for p in CORPUS.glob("Z_Construct_UEnum_*.c"):  # the enums' forms first: a byte parameter names its enum
        ENUM_FORMS[own_name(p.name.split("@")[0][len("Z_Construct_UEnum_"):], owners)] = read_enum(p)["form"]
    for p in CORPUS.glob("Z_Construct_UFunction_*.c"):  # each UFunction table to the longest class name it starts with
        rest = p.name.split("@")[0][len("Z_Construct_UFunction_"):]
        OWNER[p.name] = next((c for c in classes if rest.startswith(c + "_")), None)
    for p in sorted(CORPUS.glob("Z_Construct_U*.c")):
        stem = p.name.split("@")[0]
        m = re.match(r"^Z_Construct_(UClass|UScriptStruct|UEnum)_(\w+)$", stem)
        if not m or stem.endswith("_NoRegister"):
            continue
        cpp = m.group(2)
        try:
            if m.group(1) == "UClass":
                if a.only and not re.search(a.only, cpp):
                    continue
                out[cpp] = read_class(p, cpp, meta, pdb)
            elif m.group(1) == "UScriptStruct":
                name = own_name(cpp, owners)
                if a.only and not re.search(a.only, name):
                    continue
                out[name] = read_struct(p, cpp, name, meta, pdb)
                out[name]["scoped"] = cpp
                # [CONFIRMED by UHT's naming] the first class of the header ATLAS declared it in ("ShooterGame": a header
                # with no class, UHT's temporary one)
                out[name]["outer"] = cpp[:-len(name) - 1] if cpp != name else None
            else:
                name = own_name(cpp, owners)
                if a.only and not re.search(a.only, name):
                    continue
                out[name] = read_enum(p)
                out[name]["outer"] = cpp[:-len(name) - 1] if cpp != name else None
        except Exception as e:  # one table the readers cannot parse: listed, the rest go on
            errors.append(f"{p.name}: {type(e).__name__}: {e}")
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=0, sort_keys=True), encoding="utf-8")
    kinds = defaultdict(int)
    for v in out.values():
        kinds[v["kind"]] += 1
    print(f"{dict(kinds)} -> {a.out}; {sum(len(v.get('funcs', [])) for v in out.values())} functions, "
          f"{sum(len(v.get('props', [])) for v in out.values())} properties; {len(errors)} tables unread")
    for e in errors[:10]:
        print("  ", e)


if __name__ == "__main__":
    main()
