"""Draft the C++ declaration of a type ATLAS reflects and our engine lacks (a class, interface or script struct).

Sources, all read-only:
- ATLAS's UHT reflection code (the server's Z_Construct_UClass_* / Z_Construct_UScriptStruct_* decompile): which members
  are reflected, their property flags, the class flags / struct flags, and the class's UFunctions (the
  Z_Construct_UFunction_<Class>_* files next to it: function flags and parameters);
- the server PDB (pdb_struct.Pdb): every data member in declaration order with its C++ type and bitfield width, the
  base class, and (pdb_lookup output, optional) each function's exact prototype;
- the DevKit's UHT metadata (devkit_metadata.py parse): categories, header comments (ToolTip), meta=(...) values,
  the class's HideCategories / ShowCategories / ClassGroup and the header file (ModuleRelativePath).

Output: a header draft with the members in ATLAS's order, reflected ones as UPROPERTY(...) with the specifiers their
flags imply, native ones with their PDB type, and UFUNCTION declarations with ATLAS's parameter names. It is a draft:
delegates, nested types, access sections, constructors and bodies need a hand pass, and every line it is unsure of
carries a `TODO`. Learned in step 1.6 (UHT 4.5): a UFUNCTION declaration must end in ';' (an inline body goes after the
class, `inline` in the same header); GENERATED_UCLASS_BODY already declares GetLifetimeReplicatedProps for a class with
replicated members; a citation made of `//` lines needs a `/* ~ */` after it or it becomes the tooltip; a UObject
header under Public/ is not included by the generated code, so something in the module's PCH must include it.

Usage: python -I _tools/reflection_newtype.py <Z_Construct_...@va.c> --exe <ShooterGameServer.exe>
         --meta <devkit metadata.jsonl> [--protos <pdb_lookup output>] [--api ENGINE_API]
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import reflection_codegen as codegen  # noqa: E402
import reflection_table  # noqa: E402
import reflection_classes  # noqa: E402
import reflection_structs  # noqa: E402
from pdb_struct import Pdb  # noqa: E402

FUNC_FLAGS = {"Final": 0x1, "RequiredAPI": 0x2, "BlueprintAuthorityOnly": 0x4, "BlueprintCosmetic": 0x8, "Net": 0x40,
              "NetReliable": 0x80, "NetRequest": 0x100, "Exec": 0x200, "Native": 0x400, "Event": 0x800,
              "NetResponse": 0x1000, "Static": 0x2000, "NetMulticast": 0x4000, "MulticastDelegate": 0x10000,
              "Public": 0x20000, "Private": 0x40000, "Protected": 0x80000, "Delegate": 0x100000,
              "NetServer": 0x200000, "HasOutParms": 0x400000, "HasDefaults": 0x800000, "NetClient": 0x1000000,
              "DLLImport": 0x2000000, "BlueprintCallable": 0x4000000, "BlueprintEvent": 0x8000000,
              "BlueprintPure": 0x10000000, "Const": 0x40000000, "NetValidate": 0x80000000}
FUNC_RX = re.compile(r"UFunction::UFunction\(\s*[^,]+,\s*[^,]+,\s*(?:\([^()]*\)\s*)?[^,]+,\s*(0x[0-9a-fA-F]+|\d+)\s*,")
# metadata keys that are not meta=(...) on a property / function
NOT_META = {"Category", "ToolTip", "ModuleRelativePath", "IncludePath", "(FunctionFlags)"}
DEFAULT_ARGS = {"FDefaultAllocator", "FDefaultSetAllocator", "0", "ESPMode::NotThreadSafe"}


def split_args(s):
    """'A<B,C>,D' -> ['A<B,C>', 'D'] (top-level commas only)."""
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def cpp_from_pdb(t, owner="", in_template=False):
    """A PDB type name as source would write it: float32 -> float, TArray<X,FDefaultAllocator> -> TArray<X>, ..."""
    t = t.strip()
    t = {"float32": "float", "float64": "double", "bool8": "bool", "unsigned char": "uint8", "wchar_t": "TCHAR",
         "char": "ANSICHAR", "int64": "int64", "uint64": "uint64"}.get(t, t)
    if owner and t.startswith(owner + "::"):
        t = t[len(owner) + 2:]
    ptr = ""
    while t.endswith("*"):
        ptr += "*"
        t = t[:-1].strip()
    m = re.match(r"^(\w+(?:::\w+)*)<(.*)>$", t)
    if m:
        name, args = m.group(1), split_args(m.group(2))
        if name in ("TMap", "TMultiMap"):
            args = args[:2]
        elif name == "TSet":
            args = args[:1]
        elif name == "TEnumAsByte":
            args = [re.sub(r"^enum\s+", "", args[0])]
        else:
            while len(args) > 1 and (args[-1] in DEFAULT_ARGS or args[-1].startswith("TDefaultMapKeyFuncs")
                                     or args[-1].startswith("FWeakObjectPtr") or args[-1] == "false"):
                args.pop()
        inner = ", ".join(cpp_from_pdb(a, owner, name != "TEnumAsByte") for a in args)
        t = f"{name}<{inner}{' ' if inner.endswith('>') else ''}>"
    elif re.match(r"^[UA][A-Z]\w*$", t) and (ptr or in_template):
        t = "class " + t
    t = re.sub(r"^(?:enum|struct|class)\s+(?=[EF])", "", t)
    return t + ptr


def class_specifiers(flags, meta_self, parent_meta, cfg):
    s = []
    names = {n for b, n in reflection_classes.CLASS_FLAGS.items() if flags & b}
    for flag, spec in (("Abstract", "abstract"), ("Transient", "transient"), ("NotPlaceable", "notplaceable"),
                       ("EditInlineNew", "editinlinenew"), ("CollapseCategories", "collapsecategories"),
                       ("DefaultToInstanced", "DefaultToInstanced"), ("Deprecated", "deprecated"),
                       ("PerObjectConfig", "perobjectconfig"), ("Const", "const"), ("Hidden", "hidden"),
                       ("HideDropDown", "hidedropdown"), ("DefaultConfig", "defaultconfig"),
                       ("ConfigDoNotCheckDefaults", "configdonotcheckdefaults"), ("MinimalAPI", "MinimalAPI")):
        if flag in names:
            s.append(spec)
    if "Config" in names and cfg:
        s.append(f"config={cfg}")
    m = {r["key"]: r["value"] for r in meta_self}
    pm = {r["key"]: r["value"] for r in parent_meta}
    for key, spec in (("HideCategories", "hidecategories"), ("ShowCategories", "showcategories"),
                      ("AutoExpandCategories", "AutoExpandCategories"), ("AutoCollapseCategories", "AutoCollapseCategories")):
        own = [c for c in m.get(key, "").split() if c not in pm.get(key, "").split()]
        if own:
            cats = [f'"{c}"' if "|" in c else c for c in own]
            s.append(f"{spec}=({', '.join(cats)})" if len(cats) > 1 else f"{spec}={cats[0]}")
    if m.get("ClassGroupNames") and m.get("ClassGroupNames") != pm.get("ClassGroupNames"):
        s.append(f"ClassGroup={m['ClassGroupNames']}")
    if m.get("IsConversionRoot") == "true" and pm.get("IsConversionRoot") != "true":
        s.append("ConversionRoot")
    if m.get("IsBlueprintBase") == "true" and pm.get("IsBlueprintBase") != "true":
        s.append("Blueprintable")
    elif m.get("IsBlueprintBase") == "false" and pm.get("IsBlueprintBase") != "false":
        s.append("NotBlueprintable")
    if m.get("BlueprintType") == "true" and pm.get("BlueprintType") != "true":
        s.append("BlueprintType")
    meta = []
    for key in ("ChildCanTick", "BlueprintSpawnableComponent"):
        if key in m and key not in pm:
            meta.append(key)
    if "DisplayName" in m:
        meta.append(f'DisplayName="{m["DisplayName"]}"')
    if meta:
        s.append(f"meta=({', '.join(meta)})")
    return s


def meta_text(rows):
    out = []
    for r in rows:
        if r["key"] in NOT_META or r["key"].startswith("CPP_Default_"):
            continue
        v = r["value"]
        out.append(f'{r["key"]}="{v}"' if v not in ("true", "") else (r["key"] if v == "" else f"{r['key']}=true"))
    return out


def comment(text, indent="\t"):
    if not text:
        return []
    lines = text.split("\n")
    if len(lines) == 1:
        return [f"{indent}/** {lines[0]} */"]
    return [f"{indent}/**"] + [f"{indent} * {l}".rstrip() for l in lines] + [f"{indent} */"]


def function_specs(flags, meta, owner_is_interface=False):
    names = {n for n, b in FUNC_FLAGS.items() if flags & b}
    s = []
    if "BlueprintEvent" in names:
        s.append("BlueprintNativeEvent" if "Native" in names else "BlueprintImplementableEvent")
    if "BlueprintPure" in names:
        s.append("BlueprintPure")
    elif "BlueprintCallable" in names and "BlueprintEvent" not in names:
        s.append("BlueprintCallable")
    if "Exec" in names:
        s.append("exec")
    if "NetServer" in names:
        s.append("Server")
    if "NetClient" in names:
        s.append("Client")
    if "NetMulticast" in names:
        s.append("NetMulticast")
    if "Net" in names:
        s.append("Reliable" if "NetReliable" in names else "Unreliable")
    if "NetValidate" in names:
        s.append("WithValidation")
    if "BlueprintAuthorityOnly" in names:
        s.append("BlueprintAuthorityOnly")
    if "BlueprintCosmetic" in names:
        s.append("BlueprintCosmetic")
    m = {r["key"]: r["value"] for r in meta}
    # UHT's own category for a callable function without one (step 1.8d): leave it out
    if "Category" in m and m["Category"] != "Default Blue Print Callable":
        s.append(f'Category="{m["Category"]}"' if " " in m["Category"] or "|" in m["Category"] else f"Category={m['Category']}")
    mt = meta_text(meta)
    if mt:
        s.append(f"meta=({', '.join(mt)})")
    access = "protected" if "Protected" in names else "private" if "Private" in names else "public"
    return s, access, names


def source_type(t):
    """'class FTransform const &' -> 'const FTransform&', 'class APhysicsVolume *' -> 'APhysicsVolume*'"""
    t = re.sub(r"\b(?:class|struct|enum)\s+", "", t.strip())
    ref = "&" if t.endswith("&") else ""
    t = t.rstrip("& ").strip()
    const = t.endswith(" const")
    t = t[:-len(" const")].strip() if const else t
    t = re.sub(r"\s*\*", "*", t)
    t = {"int": "int32", "unsigned int": "uint32", "unsigned char": "uint8", "__int64": "int64",
         "unsigned __int64": "uint64", "short": "int16", "unsigned short": "uint16", "wchar_t": "TCHAR"}.get(t, t)
    return ("const " if const else "") + t + ref


def source_decl(proto, owner, params):
    """A PDB prototype as a declaration with ATLAS's parameter names (from the UFunction's reflection table)."""
    if not proto:
        return ""
    d = re.sub(r"\s*__ptr64", "", proto)
    d = re.sub(r"__cdecl\s+", "", d).replace(f"{owner}::", "")
    d = re.sub(r"^(?:public|protected|private):\s*", "", d)
    m = re.match(r"^(.*?)(\w+)\((.*)\)(\s*const)?\s*$", d)
    if not m:
        return d
    head, fname, args, const = m.group(1), m.group(2), m.group(3), m.group(4) or ""
    virt = "virtual " if head.startswith("virtual ") else ("static " if head.startswith("static ") else "")
    ret = source_type(head[len(virt):]) if head[len(virt):].strip() else ""
    types = [] if args.strip() in ("", "void") else [source_type(x) for x in split_args(args)]
    if len(types) == len(params):
        types = [f"{t} {p}" for t, p in zip(types, params)]
    return f"{virt}{ret} {fname}({', '.join(types)}){' const' if const else ''}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("decompile")
    ap.add_argument("--exe", required=True)
    ap.add_argument("--meta", required=True)
    ap.add_argument("--protos", help="pdb_lookup output with the class's functions (prototypes)")
    ap.add_argument("--api", default="ENGINE_API")
    ap.add_argument("--pdb", default=None, help=argparse.SUPPRESS)
    a = ap.parse_args()
    path = Path(a.decompile)
    stem = path.name.split("@")[0]
    kind = "Class" if stem.startswith("Z_Construct_UClass_") else "ScriptStruct"
    cpp = re.sub(r"^Z_Construct_U(?:Class|ScriptStruct)_", "", stem)
    outer, _, short = cpp.rpartition("_F") if kind == "ScriptStruct" and "_F" in cpp else ("", "", cpp)
    name = ("F" + short) if outer else cpp
    meta_type = cpp  # the DevKit names a struct "<Outer>_<FStruct>", like the decompile
    meta = defaultdict(list)
    fmeta = defaultdict(list)
    for line in open(a.meta, encoding="utf-8"):
        r = json.loads(line)
        if r["type"] == meta_type:
            meta[r["member"]].append(r)
        elif kind == "Class" and r["type"].startswith(name + "."):
            fmeta[r["type"].split(".", 1)[1]].append(r)
    pdb = a.pdb or Pdb(a.exe)
    members = pdb.members(name) or []
    reflection_table.OUTER_SELF[str(path)] = cpp
    sflags, rows = reflection_table.table(str(path))
    rows = list(reversed(rows))
    top = {r["name"]: r for r in rows if "inner_of" not in r}
    inner = {r["inner_of"]: r for r in rows if "inner_of" in r}
    base = next((m for m in members if m["base"]), None)
    out = [f"// draft: {path.name}; PDB {name} size 0x{(pdb.size(name) or 0):x}"]
    header = next((r["value"] for r in meta[""] if r["key"] == "ModuleRelativePath"), None)
    if header:
        out.append(f"// ATLAS header: {header}")
    tip = next((r["value"] for r in meta[""] if r["key"] == "ToolTip"), None)
    out += comment(tip, "")
    if kind == "Class":
        info = reflection_classes.atlas_class(path, cpp, pdb) or {"flags": 0, "config": None, "interfaces": []}
        parent = info.get("super") or (base["name"] if base else "UObject")
        pmeta = []
        for line in open(a.meta, encoding="utf-8"):
            r = json.loads(line)
            if r["type"] == parent and r["member"] == "":
                pmeta.append(r)
        is_iface = bool(info["flags"] & 0x4000)
        spec = class_specifiers(info["flags"], meta[""], pmeta, info["config"])
        api = f"{a.api} " if info["flags"] & 0x100000 else ""
        if is_iface:
            out.append(f"UINTERFACE({', '.join(s for s in spec if s not in ('abstract',))})")
            out.append(f"class {api}{name} : public {parent}")
            out += ["{", "\tGENERATED_UINTERFACE_BODY()", "};", "", f"class {api}I{name[1:]}", "{",
                    "\tGENERATED_IINTERFACE_BODY()", "};"]
            print("\n".join(out))
            return
        out.append(f"UCLASS({', '.join(spec)})")
        ifaces = "".join(f", public I{i[1:]}" for i in info["interfaces"] if i and i != "?")
        # native C++ bases besides the UObject parent and the UInterfaces (e.g. a plain interface with a vtable)
        native = [m["name"] for m in members if m["base"] and m["name"] != parent
                  and m["name"] not in ("I" + i[1:] for i in info["interfaces"] if i)]
        ifaces += "".join(f", public {n} /* TODO native base */" for n in native)
        out.append(f"class {api}{name} : public {parent}{ifaces}")
        out += ["{", "\tGENERATED_UCLASS_BODY()"]
    else:
        m = reflection_structs.CALL.search(path.read_text(encoding="utf-8", errors="replace"))
        f = reflection_structs.flag_value(m.group(2)) if m else 0
        spec = [s for b, s in ((0x10, "atomic"), (0x20, "immutable")) if f & b]
        bm = meta[""]
        if any(r["key"] == "BlueprintType" and r["value"] == "true" for r in bm):
            spec.append("BlueprintType")
        api = f"{a.api} " if f & 0x200 else ""
        parent = f" : public {base['name']}" if base else ""
        out.append(f"USTRUCT({', '.join(spec)})")
        out.append(f"struct {api}{name}{parent}")
        out += ["{", "\tGENERATED_USTRUCT_BODY()"]
    # RepNotify function names: the FName literal "OnRep_..." after the property's own name literal
    repnotify, last = {}, None
    for lm in re.finditer(r'L"(\w+)"', path.read_text(encoding="utf-8", errors="replace")):
        if lm.group(1) in top:
            last = lm.group(1)
        elif lm.group(1).startswith("OnRep_") and last:
            repnotify.setdefault(last, lm.group(1))
    seen = set()
    for mbr in members:
        if mbr["base"]:
            continue
        n = mbr["name"]
        seen.add(n)
        ctype = cpp_from_pdb(mbr["type"], name)
        bits = f":{mbr['width']}" if mbr["bit"] is not None else ""
        dim = ""
        dm = re.match(r"^(.*)\[(\d+)\]$", ctype)
        if dm:
            ctype, dim = dm.group(1), f"[{dm.group(2)}]"
        out.append("")
        r = top.get(n)
        mm = meta.get(n, [])
        out += comment(next((x["value"] for x in mm if x["key"] == "ToolTip"), None))
        if r is not None:
            f = codegen.flag_value(r)
            fi = codegen.flag_value(inner[n]) if n in inner and codegen.flag_value(inner[n]) is not None else 0
            cat = next((x["value"] for x in mm if x["key"] == "Category"), None)
            if cat and (" " in cat or "|" in cat):
                cat = f'"{cat}"'
            spec = codegen.specifiers((f or 0) & ~codegen.COMPUTED, cat, fi, r["kind"])
            spec = [s for s in spec if not s.startswith("meta=")]
            mt = meta_text(mm) + (["ExposeOnSpawn=true"] if (f or 0) & codegen.CPF["ExposeOnSpawn"] else [])
            if mt:
                spec.append(f"meta=({', '.join(mt)})")
            if f and f & codegen.CPF["RepNotify"]:
                onrep = repnotify.get(n, f"OnRep_TODO_{n}")
                spec = [f"ReplicatedUsing={onrep}" if s.startswith("ReplicatedUsing") else s for s in spec]
            notes = codegen.notes(f or 0)
            out.append(f"\tUPROPERTY({', '.join(spec)})" + (f"\t// TODO {'; '.join(notes)}" if notes else ""))
            if r["kind"] == "UBoolProperty" and r.get("native_bool") is False and not bits:
                bits = ":1"
        out.append(f"\t{ctype} {n}{bits}{dim};")
    for n in top:
        if n not in seen:
            out.append(f"\t// TODO reflected {n} ({top[n]['kind']}) has no PDB member")
    if kind == "Class":
        protos = {}
        if a.protos:
            for line in open(a.protos, encoding="utf-8", errors="replace"):
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 4 and parts[2].strip(" \x00").startswith(name + "::"):
                    fn = parts[2].strip(" \x00").split("::", 1)[1]
                    # identical-code folding: a folded function's public symbol is another function's
                    folded = f"{name}::{fn}(" not in parts[3]
                    protos.setdefault(fn, ("" if folded else parts[3], parts[4] if len(parts) > 4 else ""))
        for fp in sorted(path.parent.glob(f"Z_Construct_UFunction_{name}_*.c")):
            fn = fp.name.split("@")[0][len(f"Z_Construct_UFunction_{name}_"):]
            text = fp.read_text(encoding="utf-8", errors="replace")
            fm = FUNC_RX.search(text)
            flags = int(fm.group(1), 0) if fm else 0
            fmm = [x for x in fmeta.get(fn, []) if x["member"] == ""]
            spec, access, fnames = function_specs(flags, fmm)
            out.append("")
            out += comment(next((x["value"] for x in fmm if x["key"] == "ToolTip"), None))
            proto = protos.pop(fn, ("", ""))[0]
            out.append(f"\tUFUNCTION({', '.join(spec)})\t// {access}; flags 0x{flags:x}")
            reflection_table.OUTER_SELF[str(fp)] = name
            params = [r["name"] for r in reversed(reflection_table.table(str(fp))[1])
                      if "inner_of" not in r and r["name"] != "ReturnValue"]
            decl = source_decl(proto, name, params)
            out.append(f"\t{decl};" if decl else f"\t// TODO prototype of {fn} (pdb_lookup \"{name}::{fn}\"), parameters {params}")
        native = {fn: v for fn, v in protos.items()
                  if not fn.startswith(("exec", "StaticRegisterNatives", "GetPrivateStaticClass", "__", "`"))}
        if native:
            out += ["", "\t// ATLAS native functions (PDB; a folded one shows no prototype):"]
            for fn, (proto, where) in sorted(native.items()):
                src = re.sub(r"^.*[\\/]source[\\/]", "", where)
                out.append(f"\t//   {fn}: {re.sub(r'__ptr64|__cdecl ', '', proto) or '(folded)'}  [{src}]")
    out.append("};")
    print("\n".join(out))


if __name__ == "__main__":
    main()
