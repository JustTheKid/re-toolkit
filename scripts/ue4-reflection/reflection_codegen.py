"""Suggest UPROPERTY declarations that bring one of our classes / structs to ATLAS's reflection.

Reads ATLAS's table (Z_Construct decompile, via reflection_table.py) and ours (AtlasFormatTest -reflection*), and
prints, in ATLAS's declaration order: each missing property as a ready UPROPERTY declaration with the property of
ours it goes after, and each property whose specifiers differ with the specifiers ATLAS's flags imply. Types come
from the property kind and referenced type; categories are not in the shipped binaries, so the class name stands in
[GUESS]. Native-only members, defaults and behaviour are not covered.

Usage: python -I _tools/reflection_codegen.py <Z_Construct_...@va.c> <ours.jsonl> [--category X]
       [--apply <header> --type <UClassOrFStruct>]   insert the missing declarations into the header, each after the
                                                    member it follows in ATLAS's order (searched inside that type's
                                                    body); flag / type changes are only printed
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reflection_table  # noqa: E402

CPF = {
    "Edit": 0x1, "ConstParm": 0x2, "BlueprintVisible": 0x4, "ExportObject": 0x8, "BlueprintReadOnly": 0x10,
    "Net": 0x20, "EditFixedSize": 0x40, "ZeroConstructor": 0x200, "DisableEditOnTemplate": 0x800,
    "Transient": 0x2000, "Config": 0x4000, "Localized": 0x8000, "DisableEditOnInstance": 0x10000,
    "EditConst": 0x20000, "GlobalConfig": 0x40000, "InstancedReference": 0x80000, "DuplicateTransient": 0x200000,
    "SubobjectReference": 0x400000, "SaveGame": 0x1000000, "NoClear": 0x2000000, "EditInline": 0x4000000,
    "BlueprintAssignable": 0x10000000, "Deprecated": 0x20000000, "IsPlainOldData": 0x40000000,
    "RepSkip": 0x80000000, "RepNotify": 0x100000000, "Interp": 0x200000000, "NonTransactional": 0x400000000,
    "EditorOnly": 0x800000000, "NoDestructor": 0x1000000000, "RepRetry": 0x2000000000, "AutoWeak": 0x4000000000,
    "ContainsInstancedReference": 0x8000000000, "AssetRegistrySearchable": 0x10000000000,
    "SimpleDisplay": 0x20000000000, "AdvancedDisplay": 0x40000000000, "Protected": 0x80000000000,
    "BlueprintCallable": 0x100000000000, "BlueprintAuthorityOnly": 0x200000000000,
    "TextExportTransient": 0x400000000000, "NonPIEDuplicateTransient": 0x800000000000,
    "ExposeOnSpawn": 0x1000000000000,
}
COMPUTED = CPF["IsPlainOldData"] | CPF["NoDestructor"] | CPF["ZeroConstructor"] | CPF["ContainsInstancedReference"]
KNOWN = sum(CPF.values())
SIMPLE = {"UIntProperty": "int32", "UUInt32Property": "uint32", "UInt64Property": "int64", "UUInt64Property": "uint64",
          "UInt16Property": "int16", "UUInt16Property": "uint16", "UInt8Property": "int8", "UFloatProperty": "float",
          "UDoubleProperty": "double", "UNameProperty": "FName", "UStrProperty": "FString", "UTextProperty": "FText"}


def type_name(ref):
    """'UObject_FVector' -> FVector, 'UEngineTypes_ENetDormancy' -> ENetDormancy, 'USoundBase' -> USoundBase"""
    if not ref:
        return None
    m = re.search(r"_([FE][A-Z]\w*)$", ref)
    return m.group(1) if m and "_" in ref else ref


_NAMESPACED = {}


def namespaced_enum(name):
    """True when the engine declares the enum as `namespace EFoo { enum Type ... }` (then EFoo::Type is the type)."""
    if name not in _NAMESPACED:
        import os
        root = Path(os.environ.get("ATLAS_ENGINE_ROOT", r"D:\UE\4.5.1")) / "Engine" / "Source"
        rx = re.compile(r"^\s*namespace\s+" + re.escape(name) + r"\b", re.M)
        found = False
        for f in root.rglob("*.h"):
            data = f.read_bytes()
            if name.encode() in data and rx.search(data.decode("utf-8", errors="replace")):
                found = True
                break
        _NAMESPACED[name] = found
    return _NAMESPACED[name]


def cpp_type(row, inner=None):
    kind, ref = row["kind"], type_name(row.get("ref"))
    if kind in SIMPLE:
        return SIMPLE[kind]
    if kind == "UBoolProperty":
        return "bool" if row.get("native_bool") else "uint32"
    if kind == "UByteProperty":
        if ref and ref.startswith("E"):
            return f"TEnumAsByte<{ref}::Type>" if namespaced_enum(ref) else f"TEnumAsByte<enum {ref}>"
        return "uint8"
    if kind == "UObjectProperty":
        return f"class {ref or 'UObject'}*"
    if kind == "UClassProperty":
        return f"TSubclassOf<class {ref or 'UObject'}>"
    if kind == "UStructProperty":
        return ref or "FTODO"  # no `struct` keyword: some engine structs are forward-declared as class
    if kind == "UWeakObjectProperty":
        return f"TWeakObjectPtr<class {ref or 'UObject'}>"
    if kind == "ULazyObjectProperty":
        return f"TLazyObjectPtr<class {ref or 'UObject'}>"
    if kind == "UAssetObjectProperty":
        return f"TAssetPtr<class {ref or 'UObject'}>"
    if kind == "UAssetClassProperty":
        return f"TAssetSubclassOf<class {ref or 'UObject'}>"
    if kind == "UInterfaceProperty":
        return f"TScriptInterface<class {ref or 'IInterface'}>"
    if kind == "UArrayProperty":
        t = cpp_type(inner) if inner else "TODO"
        return f"TArray<{t}{' ' if t.endswith('>') else ''}>"
    if kind in ("UMulticastDelegateProperty", "UDelegateProperty"):
        return "FTODO_DelegateSignature"
    return f"/* {kind} */ TODO"


def flag_value(row):
    try:
        return int(row["flags"], 16)
    except (KeyError, ValueError):
        return None


def specifiers(f, category, inner_flags=0, kind=""):
    s = []
    if f & CPF["Edit"]:
        if f & CPF["EditConst"]:
            s.append("VisibleDefaultsOnly" if f & CPF["DisableEditOnInstance"] else
                     "VisibleInstanceOnly" if f & CPF["DisableEditOnTemplate"] else "VisibleAnywhere")
        else:
            s.append("EditDefaultsOnly" if f & CPF["DisableEditOnInstance"] else
                     "EditInstanceOnly" if f & CPF["DisableEditOnTemplate"] else "EditAnywhere")
    if f & CPF["BlueprintVisible"]:
        s.append("BlueprintReadOnly" if f & CPF["BlueprintReadOnly"] else "BlueprintReadWrite")
    if f & CPF["Net"]:
        s.append("ReplicatedUsing=OnRep_TODO" if f & CPF["RepNotify"] else "Replicated")
    for name, spec in (("Transient", "Transient"), ("DuplicateTransient", "DuplicateTransient"),
                       ("NonPIEDuplicateTransient", "NonPIEDuplicateTransient"),
                       ("TextExportTransient", "TextExportTransient"), ("Config", "Config"),
                       ("GlobalConfig", "GlobalConfig"), ("Localized", "Localized"), ("SaveGame", "SaveGame"),
                       ("NoClear", "NoClear"), ("EditFixedSize", "EditFixedSize"), ("Interp", "Interp"),
                       ("NonTransactional", "NonTransactional"), ("AssetRegistrySearchable", "AssetRegistrySearchable"),
                       ("SimpleDisplay", "SimpleDisplay"), ("AdvancedDisplay", "AdvancedDisplay"),
                       ("BlueprintAssignable", "BlueprintAssignable"), ("BlueprintCallable", "BlueprintCallable"),
                       ("BlueprintAuthorityOnly", "BlueprintAuthorityOnly"), ("RepSkip", "NotReplicated"),
                       ("RepRetry", "RepRetry")):
        if f & CPF[name]:
            s.append(spec)
    if ((f | inner_flags) & CPF["InstancedReference"] and not (f | inner_flags) & CPF["SubobjectReference"]
            and kind not in ("UMulticastDelegateProperty", "UDelegateProperty")):
        s.append("Instanced")
    if f & (CPF["Edit"] | CPF["BlueprintVisible"]) and category:
        s.append(f"Category={category}")
    meta = ["ExposeOnSpawn=true"] if f & CPF["ExposeOnSpawn"] else []
    if meta:
        s.append(f"meta=({', '.join(meta)})")
    return s


def notes(f):
    out = []
    if f & CPF["Protected"]:
        out.append("protected section")
    if f & CPF["EditorOnly"]:
        out.append("WITH_EDITORONLY_DATA")
    unknown = f & ~KNOWN
    if unknown:
        bits = [b for b in range(64) if unknown >> b & 1]
        out.append("ATLAS flag bit(s) " + ", ".join(map(str, bits)) + " not ported (save-archive specifiers)")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("atlas")
    ap.add_argument("ours")
    ap.add_argument("--category")
    ap.add_argument("--apply", help="header to insert the missing declarations into")
    ap.add_argument("--type", help="with --apply: the class / struct whose body is searched, e.g. USkeletalMeshComponent")
    ap.add_argument("--comment", default="ATLAS", help="comment line put above each inserted group")
    args = ap.parse_args()
    inserts = []  # (anchor or None, [declaration lines])
    owner = re.search(r"Z_Construct_U(?:Class|ScriptStruct)_(\w+?)@", Path(args.atlas).name)
    reflection_table.OUTER_SELF[args.atlas] = owner.group(1) if owner else ""
    _, theirs = reflection_table.table(args.atlas)
    mine = [json.loads(l) for l in open(args.ours, encoding="utf-8-sig") if l.strip()]
    category = args.category or (re.sub(r"^[UAF]", "", owner.group(1).split("_F")[-1]) if owner else None)
    ours_by = {(r["name"], r.get("inner_of", "")): r for r in mine}

    rows = [r for r in reversed(theirs)]  # declaration order
    top = [r for r in rows if "inner_of" not in r]
    inner = {r["inner_of"]: r for r in rows if "inner_of" in r}
    previous = None
    for r in top:
        name = r["name"]
        f = flag_value(r)
        if f is None:
            print(f"?? {name}: flags not constant ({r.get('flags')})")
            continue
        fi = flag_value(inner[name]) if name in inner and flag_value(inner[name]) is not None else 0
        o = ours_by.get((name, ""))
        spec = specifiers(f & ~COMPUTED, category, fi, r["kind"])
        decl_type = cpp_type(r, inner.get(name))
        bit = r["kind"] == "UBoolProperty" and not r.get("native_bool")
        decl = f"{decl_type} {name}{':1' if bit else ''}{'[%d]' % r['dim'] if r.get('dim', 1) > 1 else ''};"
        extra = notes(f)
        if o is None:
            print(f"+ after {previous or '(start)'}:")
            print(f"    UPROPERTY({', '.join(spec)})")
            print(f"    {decl}" + (f"   // {'; '.join(extra)}" if extra else ""))
            lines = [f"\tUPROPERTY({', '.join(spec)})" + (f"\t// {'; '.join(extra)}" if extra else ""), f"\t{decl}"]
            if inserts and inserts[-1][0] == previous:
                inserts[-1][1].append("")
                inserts[-1][1].extend(lines)
            else:
                inserts.append((previous, lines))
        else:
            fo = flag_value(o)
            mask = ~(COMPUTED | CPF["EditorOnly"])
            if fo is not None and (f & mask) != (fo & mask):
                print(f"~ {name}: ATLAS flags 0x{f:x} vs ours 0x{fo:x} -> UPROPERTY({', '.join(spec)})"
                      + (f"   // {'; '.join(extra)}" if extra else ""))
            if o["kind"] != r["kind"]:
                print(f"~ {name}: type {o['kind']} -> {r['kind']}: {decl}")
            previous = name
    print(f"# {len(top)} ATLAS properties; ours {sum('inner_of' not in r for r in mine)}")
    if args.apply:
        apply(Path(args.apply), args.type, inserts, args.comment)


def apply(header, type_name, inserts, comment):
    """Insert each group after its anchor's declaration inside the type's body (LF / CRLF kept)."""
    raw = header.read_bytes().decode("utf-8")
    crlf = "\r\n" in raw
    text = raw.replace("\r\n", "\n")
    # the declaration line only: a multi-line match would run past GENERATED_*_BODY() and miss "(start)" groups
    start = re.search(r"^(class|struct)\s+(\w+_API\s+)?" + re.escape(type_name) + r"\b[^;{\n]*$", text, re.M)
    if not start:
        sys.exit(f"{type_name}: declaration not found in {header}")
    body_from = start.end()
    for anchor, lines in inserts:
        if anchor is None:
            m = re.search(r"GENERATED_U(CLASS|STRUCT)_BODY\(\)[^\n]*\n", text[body_from:])
        else:
            m = re.search(r"^[^\n/]*\b" + re.escape(anchor) + r"(_DEPRECATED)?\b\s*(:\s*1\s*)?(\[[^\]]*\]\s*)?;[^\n]*\n",
                          text[body_from:], re.M)
        if not m:
            sys.exit(f"anchor {anchor!r} not found in {type_name}")
        at = body_from + m.end()
        block = "\n\t// " + comment + "\n" + "\n".join(lines) + "\n"
        text = text[:at] + block + text[at:]
    header.write_bytes((text.replace("\n", "\r\n") if crlf else text).encode("utf-8"))
    print(f"# applied {sum(1 for _ in inserts)} group(s) to {header}")


if __name__ == "__main__":
    main()
