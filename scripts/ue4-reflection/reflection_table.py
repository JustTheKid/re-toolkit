"""Property table of a class or struct from its UHT reflection code in a raw decompile (Z_Construct_UClass_* /
Z_Construct_UScriptStruct_*), as JSON lines: name, property kind, offset, flags, array dim, referenced type, and
whether it is the inner property of the array before it. Compared with our engine's own table by
`AtlasFormatTest -reflection` (see _tools/reflection_diff.py).

The code is read as a sequence of events: property-name literals, type references (Z_Construct_* /
GetPrivateStaticClass of a non-property class / an inlined StaticClass, TClassCompiledInDefer<T>::Register), property constructor calls and vtable assignments. Each constructor
call is one property; its kind is the constructor's class, or for the generic UProperty::UProperty the vtable assigned
right after it. An array's inner property follows the array and usually reuses its name literal.

Usage: python -I _tools/reflection_table.py <Z_Construct_...@va.c> [--json out.jsonl]
"""
import json
import os
import re
import sys

# Arguments may wrap onto the next line (also before a comma: a long name literal ends its line), and the constructed
# object and the initializer may carry a cast:
# "(UProperty *)pUVar13", "(FPostConstructInitializeProperties *)FStack_750".
EVENTS = re.compile(
    r'FName::FName\([^,;]*,\s*L"(?P<name>\w+)"\s*,\s*FNAME_Add'
    r'|(?P<ctor>U\w*Property)::(?P=ctor)\s*\(\s*(?:\([^()]*\)\s*)?\w+\s*,\s*(?:\([^()]*\)\s*)?\w+\s*,\s*EC_CppProperty\s*,\s*(?P<offset>[^,]+?)\s*,\s*(?P<flags>[^,\)]+)(?P<rest>[^;]*)\)\s*;'
    r'|___7(?P<vtable>U\w*Property)__6B_'
    r'|Z_Construct_U(?:ScriptStruct|Class|Enum)_(?P<zref>\w+?)(?:_NoRegister)?\s*\(\)'
    r'|\b(?P<gref>\w+)::GetPrivateStaticClass\(L"/Script/(?!CoreUObject)|GetPrivateStaticClassBody<(?P<bref>\w+)>'
    r'|TClassCompiledInDefer<(?P<tref>\w+)>::Register'
    r'|\b(?P<cref>\w+Property)::GetPrivateStaticClass\(L"/Script/CoreUObject"'
    r'|\b(?P<oref>U\w+)::GetPrivateStaticClass\(L"/Script/CoreUObject"'
    r'|(?:->ArrayDim|\*\(int \*\)\(\(longlong\)\w+ \+ 0x30\)|\*\((?:int|undefined4) \*\)&\w+->_padding_)\s*=\s*(?P<dim>0x[0-9a-f]+|\d+);')
CLASSFLAGS = re.compile(r'OuterClass->ClassFlags\s*=\s*OuterClass->ClassFlags\s*\|\s*(0x[0-9a-f]+)')


def number(text):
    try:
        return int(text.strip(), 0)
    except ValueError:
        return None  # a variable: bitfield offsets come from DetermineBitfieldOffsetAndMask


DEVKIT = None  # a devkit_metadata.PE of the DevKit DLL the decompiles come from: read them through devkit_text()


def devkit_text(text, pe, classes=None):
    """A DevKit editor DLL's decompile (exported with ghidra_find.py --fix-imports) in the server corpus's form:
    imported calls named as the server shows them, UTF-16 literals inlined, the editor build's ArrayDim (+0x90).
    classes: {"PaperSpriteComponent": "UPaperSpriteComponent"} for the DLL's own classes (see below)."""
    from devkit_metadata import quote

    def lit(m):
        s = pe.wstr(int(m.group(1), 16))
        return quote(s) if s is not None else m.group(0)
    text = re.sub(r"&UNK_([0-9a-f]{9,})", lit, text)
    # without a PDB, a class of the same DLL is fetched through an unnamed GetPrivateStaticClassBody<T> copy:
    # FUN_18004a9b0(L"/Script/Paper2D",L"PaperSpriteComponent",...) (APaperSpriteActor::RenderComponent)
    if classes:
        text = re.sub(r'\bFUN_[0-9a-f]+\(\s*L"/Script/(\w+)"\s*,\s*L"(\w+)"',
                      lambda m: (f'{classes[m.group(2)]}::GetPrivateStaticClass(L"/Script/{m.group(1)}"'
                                 if m.group(2) in classes else m.group(0)), text)

    # with the program's decompiler options (ghidra_find.py --max-payload) a call through an import slot shows the
    # slot's file value instead, the RVA of the import's hint / name entry: (*(code *)&DAT_02d28528)(...)
    def by_name(m):
        o = pe.off(int(m.group(1), 16) + 2)
        if o is None:
            return m.group(0)
        name = pe.b[o:pe.b.find(b"\0", o)].decode("latin-1")
        return "(*__imp_" + re.sub(r"[^A-Za-z0-9_]", "_", name) + ")" if re.match(r"[?\w]", name) else m.group(0)
    text = re.sub(r"\(\*\(code \*\)&DAT_([0-9a-f]+)\)", by_name, text)

    # a package-name literal the PDB names (MSVC's ??_C@_1...@...$AA/$AAS$AAc...): "/Script/<Package>"
    def script_lit(m):
        rest = m.group(1).split("_1__AAS__AAc__AAr__AAi__AAp__AAt__AA_1", 1)
        if len(rest) != 2:
            return m.group(0)
        pkg, s = "", rest[1]
        while (c := re.match(r"__AA([A-Za-z0-9])", s)) is not None:
            pkg, s = pkg + c.group(1), s[c.end():]
        return f'L"/Script/{pkg}"' if pkg else m.group(0)
    text = re.sub(r"&\s*___C__(\w+)", script_lit, text)
    imp = r"\(\*\s*__imp_{}\s*\)\s*\("
    # FName(Name, FNAME_Add, true)
    text = re.sub(imp.format(r"__0FName__QEAA_PEB_WW4EFindName___N_Z"), "FName::FName(", text)
    text = re.sub(r'FName::FName\(([^,;]*),\s*(L"(?:[^"\\]|\\.)*")\s*,\s*1\s*,', r"FName::FName(\1,\2,FNAME_Add,", text)
    # U<Kind>Property::operator new: the server's inlined StaticAllocateObject names the property's class first
    text = re.sub(imp.format(r"__2(U\w*?Property)__SAPEAX\w*"),
                  lambda m: f'{m.group(1)}::GetPrivateStaticClass(L"/Script/CoreUObject"); operator_new(', text)
    # U<Kind>Property::U<Kind>Property(this, PCIP, EC_CppProperty, Offset, Flags, ...)
    text = re.sub(imp.format(r"__0(U\w*?Property)__QEAA_AEBVFPostConstructInitializeProperties__W4ECppProperty__\w*"),
                  lambda m: f"{m.group(1)}::{m.group(1)}(", text)
    # (the decompiler may wrap the call before its "(": "UBoolProperty::UBoolProperty\n   ((UBoolProperty *)this,")
    text = re.sub(r"(U\w*Property)::\1\s*\(([^,;]+),([^,;]+),\s*0\s*,", r"\1::\1(\2,\3,EC_CppProperty,", text)
    # CoreUObject classes and structs referenced by a property
    text = re.sub(imp.format(r"_GetPrivateStaticClass_(U\w+?)__\w*"), r"\1::GetPrivateStaticClass(", text)
    text = re.sub(imp.format(r"_StaticClass_(U\w+?)__SAPEAVUClass__XZ") + r"\s*\)",
                  r'\1::GetPrivateStaticClass(L"/Script/CoreUObject")', text)
    text = re.sub(imp.format(r"_(Z_Construct_U(?:ScriptStruct|Class|Enum)_\w+?)__YAPEAV\w*"), r"\1(", text)
    text = re.sub(r"___SU(\w*Property)__6B_", r"___7U\1__6B_", text)
    return re.sub(r"\*\((?:int|undefined4) \*\)\((\w+) \+ 0x12\)\s*=\s*(0x[0-9a-f]+|\d+);", r"\1->ArrayDim = \2;", text)


_LOCAL = {}


def local_classes(folder):
    """{"PaperSpriteComponent": "UPaperSpriteComponent"} for the classes whose Z_Construct is exported in folder."""
    if folder not in _LOCAL:
        found = (re.match(r"Z_Construct_UClass_([AU])(\w+?)@", f) for f in os.listdir(folder))
        _LOCAL[folder] = {m.group(2): m.group(1) + m.group(2) for m in found if m}
    return _LOCAL[folder]


def table(path):
    text = open(path, encoding="utf-8", errors="replace").read().replace("\r", "")
    if DEVKIT is not None:
        text = devkit_text(text, DEVKIT, local_classes(os.path.dirname(os.path.abspath(path))))
    flags = CLASSFLAGS.search(text)
    rows, name, refs, pending = [], None, [], None
    core = 0  # CoreUObject property classes named since the last property name
    for m in EVENTS.finditer(text):
        if m.group("name"):
            name = m.group("name")
            core = 0
        elif m.group("cref"):
            # the first is the property's own class (StaticAllocateObject); a second, before the constructor, is the
            # class an object property points to, e.g. FTimeline::DirectionProperty (UByteProperty*)
            core += 1
            if core == 2:
                refs.append(m.group("cref"))
        elif m.group("zref") or m.group("gref") or m.group("bref") or m.group("tref") or m.group("oref"):
            # oref: a CoreUObject class inlined as UEnum::GetPrivateStaticClass (ATLAS's blackboard enum keys), or an
            # imported StaticClass (UPackage, UField: UDiffPackagesCommandlet::Packages); property classes are crefs
            ref = m.group("zref") or m.group("gref") or m.group("bref") or m.group("tref") or m.group("oref")
            # the class's own registration names it before any property; inside a property block it is a real
            # self reference (e.g. USkinnedMeshComponent::OverrideTickingVisiblityMesh)
            if not ref.endswith("Property") and (ref != OUTER_SELF.get(path) or name is not None):
                # the latest reference wins: a type named again moves to the end (it may still be pending from an
                # earlier, unrelated block)
                if ref in refs:
                    refs.remove(ref)
                refs.append(ref)
        elif m.group("ctor"):
            row = {"name": name, "kind": m.group("ctor"), "offset": number(m.group("offset"))}
            flag = number(m.group("flags"))
            row["flags"] = f"0x{flag:x}" if flag is not None else m.group("flags").strip()
            if row["kind"] == "UBoolProperty":
                row["native_bool"] = m.group("rest").strip().endswith("true")
            if refs:
                row["ref"] = refs[-1]
            refs = []
            # inner property of the array just constructed (offset 0, same name)
            if rows and rows[-1]["kind"] == "UArrayProperty" and "inner" not in rows[-1] and row["offset"] == 0:
                row["inner_of"] = rows[-1]["name"]
                rows[-1]["inner"] = True
            rows.append(row)
            pending = row if row["kind"] == "UProperty" else None
        elif m.group("vtable") and pending is not None:
            pending["kind"] = m.group("vtable")
            pending = None
        elif m.group("dim") and rows:
            # the mistyped-field form also writes into freshly allocated helpers (struct ops: operator_new just
            # before); only a write that follows a property is its ArrayDim
            if "_padding_" in m.group(0) and "operator_new" in text[max(0, m.start() - 240):m.start()]:
                continue
            rows[-1]["dim"] = int(m.group("dim"), 0)
    return (f"0x{int(flags.group(1), 16):x}" if flags else None), rows


OUTER_SELF = {}

if __name__ == "__main__":
    path = sys.argv[1]
    # the class being constructed shows up as a GetPrivateStaticClass reference; don't report it as a type
    owner = re.search(r"Z_Construct_U(?:Class|ScriptStruct)_([A-Z]\w+?)@|Z_Construct_UFunction_([A-Z][A-Za-z0-9]*)_",
                      path.replace("\\", "/"))
    if owner:
        OUTER_SELF[path] = owner.group(1) or owner.group(2)
    class_flags, rows = table(path)
    out = open(sys.argv[sys.argv.index("--json") + 1], "w", encoding="utf-8") if "--json" in sys.argv else None
    print(f"# class flags |= {class_flags}; {sum('inner_of' not in r for r in rows)} properties")
    for r in rows:
        line = json.dumps(r)
        print(line)
        if out:
            out.write(line + "\n")
