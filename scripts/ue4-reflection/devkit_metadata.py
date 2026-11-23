"""UHT metadata (Category, ToolTip, ModuleRelativePath, UIMin, CPP_Default_*, ...) of ATLAS's reflected types, read
from the ATLAS DevKit's editor DLLs. Only editor builds compile metadata (WITH_METADATA); the shipped client and
server have none, so this is the one place ATLAS's categories, header comments and header paths survive.

The DevKit DLLs are imported into their own Ghidra project (PDB only):
  python -I _tools/ghidra_analyze.py "<kit>/Engine/Binaries/Win64/UE4Editor-Engine.dll"
         --project D:/ATLAS/_re/ghidra-devkit --name devkit --pdb-only

In those decompiles the calls into other DLLs show as offsets into one import block
("(*(code *)__imp__GErrorHist__3PA_WA._13192_8_)") and the UTF-16 literals as bare addresses ("&UNK_1821390b8").
Both are resolved from the DLL file itself: the import table names each slot, the literal is read at its address.
The code is then read as a sequence of events: a name literal (FName constructor), an object allocation
(U<Kind>::operator new, which follows its name), copies of the object pointer into other variables, and
UMetaData::SetValue(MetaData, Object, Key, Value).

Usage:
  python -I _tools/devkit_metadata.py export --dll <dll> --out <dir> [--workers 4]
      decompile every Z_Construct_U{Class,Function,ScriptStruct,Enum}_* of the DLL (skips existing files)
  python -I _tools/devkit_metadata.py parse --dll <dll> <dir> --json <out.jsonl>
      one JSON line per metadata value: type, member ("" = the type / function itself), kind, key, value; each
      function also gets a "(FunctionFlags)" row (its EFunctionFlags, not metadata)
  python -I _tools/devkit_metadata.py show <out.jsonl> <type> [<member>]
      print a type's (or member's) metadata grouped per member
  python -I _tools/devkit_metadata.py notes <out.jsonl> --label <module> --out <notes.md> --summary <summary.json>
      the developers' tagged notes (PRIMAL / YARK / ATLAS / CC), other markers (TODO, HACK, ...), console (Exec)
      functions and dev / test / debug named members; the wording goes to <notes.md> (local, never into git: it is
      the developers' text), names and counts to <summary.json> for docs/dev-notes.md
"""
import argparse
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
PROJECT = r"D:\ATLAS\_re\ghidra-devkit"


class PE:
    """Just enough of a PE32+ reader: sections, the import table, and UTF-16 literals by VA."""

    def __init__(self, path):
        self.b = b = Path(path).read_bytes()
        e = struct.unpack_from("<I", b, 0x3C)[0]
        nsec, = struct.unpack_from("<H", b, e + 6)
        optsz, = struct.unpack_from("<H", b, e + 20)
        opt = e + 24
        self.base, = struct.unpack_from("<Q", b, opt + 24)
        self.imp_rva, _ = struct.unpack_from("<II", b, opt + 112 + 8)
        self.secs = []
        s = opt + optsz
        for _ in range(nsec):
            vsz, va, rsz, roff = struct.unpack_from("<IIII", b, s + 8)
            self.secs.append((va, max(vsz, rsz), roff, rsz))
            s += 40

    def off(self, rva):
        for va, sz, roff, rsz in self.secs:
            if va <= rva < va + sz:
                return roff + rva - va if rva - va < rsz else None
        return None

    def cstr(self, rva):
        o = self.off(rva)
        return self.b[o:self.b.index(b"\0", o)].decode("latin-1")

    def imports(self):
        """IAT slot VA -> imported symbol (decorated name, or #ordinal)."""
        out = {}
        d = self.off(self.imp_rva)
        while True:
            oft, _, _, name, ft = struct.unpack_from("<IIIII", self.b, d)
            if not ft:
                return out
            t = self.off(oft or ft)
            i = 0
            while True:
                v, = struct.unpack_from("<Q", self.b, t + 8 * i)
                if not v:
                    break
                out[self.base + ft + 8 * i] = f"#{v & 0xffff}" if v >> 63 else self.cstr((v & 0x7fffffff) + 2)
                i += 1
            d += 20

    def wstr(self, va):
        """The UTF-16 literal at va, or None when the bytes there do not look like one."""
        o = self.off(va - self.base)
        if o is None:
            return None
        end = o
        while end + 1 < len(self.b) and self.b[end:end + 2] != b"\0\0":
            end += 2
            if end - o > 8000:
                return None
        try:
            s = self.b[o:end].decode("utf-16-le")
        except UnicodeDecodeError:
            return None
        ok = all((c.isprintable() or c in "\r\n\t") and ord(c) < 0x2100 for c in s)
        return s if ok else None


def quote(s):
    return 'L"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t") + '"'


def unquote(s):
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "r": "\r", "t": "\t"}.get(m.group(1), m.group(1)), s)


def array_element_size(mangled):
    """Byte size of one element of an imported array, from its MSVC name: '?CRCTablesSB8@FCrc@@2PAY0BAA@IA'
    (uint32[][256]) -> 0x400. 0 when the name is not such an array."""
    m = re.search(r"Y0([A-P]+)@(_?[A-Z])", mangled)
    if not m:
        return 0
    count = int("".join("0123456789ABCDEF"["ABCDEFGHIJKLMNOP".index(c)] for c in m.group(1)), 16)
    size = {"C": 1, "D": 1, "E": 1, "F": 2, "G": 2, "H": 4, "I": 4, "J": 4, "K": 4, "M": 4, "N": 8, "_J": 8, "_K": 8,
            "_W": 2}.get(m.group(2), 0)
    return count * size


FIELDS = {"PermanentObjectPoolSize": 0, "PermanentObjectPool": 8, "PermanentObjectPoolTail": 16,
          "PermanentObjectPoolExceededTail": 24}


def resolve(text, pe, imps, block):
    """Name the import-block calls and replace string addresses by their literals."""
    # DLLs without a PDB (the plugins' editor DLLs, step 1.7c) get a full Ghidra analysis, which names the imported
    # calls in demangled form and reads the literals itself: FName::FName(..., L"X", ...), UFloatProperty::operator_new(
    # ...), UFunction::UFunction(this, ..., (UFunction *)0x0, 0x14c22401, ...), UMetaData::SetValue(...). Map them onto
    # the bracketed names the events below match.
    text = re.sub(r"(?<![\w:])FName::FName\s*\(", "[??0FName@@QEAA@PEB_W](", text)
    text = re.sub(r"(?<![\w:])(U\w+)::operator_new\s*\(", r"[??2\1@@SAPEAX](", text)
    text = re.sub(r"(?<![\w:])(U(?:Delegate)?Function)::\1\s*\(", r"[??0\1@@QEAA@](", text)
    text = re.sub(r"(?<![\w:])UMetaData::SetValue\s*\(", "[?SetValue@UMetaData@@](", text)
    text = re.sub(r"\(U\w+ \*\)0x0\b", "0x0", text)
    if block is not None:
        text = re.sub(r"\(\*\(code \*\)__imp__GErrorHist__3PA_WA\._(\d+)_8_\)",
                      lambda m: "[" + imps.get(block + int(m.group(1)), "?") + "]", text)
        # a call through the first slot of the block itself
        text = re.sub(r"\(\*\(code \*\)__imp__GErrorHist__3PA_WA\)", lambda m: "[" + imps.get(block, "?") + "]", text)
    # DLLs whose import slots Ghidra names one by one (the game DLL): (*___imp_<mangled name, non-alphanumerics as _>)
    sanitized = getattr(resolve, "_cache", {}).get(id(imps))
    if sanitized is None:
        sanitized = {re.sub(r"[^A-Za-z0-9_]", "_", v): v for v in imps.values()}
        resolve._cache = {id(imps): sanitized}
        resolve._rev = {id(imps): {re.sub(r"[^A-Za-z0-9_]", "_", v): va for va, v in imps.items()}}
    rev = resolve._rev[id(imps)]

    # other DLLs (SlateCore) name the block after a different first import, typed as an array:
    # (*(code *)__imp__CRCTablesSB8_FCrc__2PAY0BAA_IA[1]._72_8_) = slot at that symbol + 1 * element size + 72
    def block_call(m):
        va = rev.get(m.group(1))
        if va is None:
            return m.group(0)
        if m.group(2):
            va += int(m.group(2)) * array_element_size(imps[va])
        return "[" + imps.get(va + int(m.group(3)), "?") + "]"
    text = re.sub(r"\(\*\(code \*\)__imp_(\w+?)(?:\[(\d+)\])?\._(\d+)_8_\)", block_call, text)

    # an import slot typed as the object it points to names the next slots after its fields (BlueprintGraph's bool
    # properties' operator new): (*(code *)__imp__GUObjectAllocator__3VFUObjectAllocator__A.
    # PermanentObjectPoolExceededTail) = that slot + the field's offset (FUObjectAllocator, UObjectAllocator.h)
    def field_call(m):
        va, off = rev.get(m.group(1)), FIELDS.get(m.group(2))
        if va is None or off is None:
            return m.group(0)
        return "[" + imps.get(va + off, "?") + "]"
    text = re.sub(r"\(\*\(code \*\)__imp_(\w+?)\.\s*(\w+)\)", field_call, text)
    text = re.sub(r"\(\*(?:\(code \*\))?_?__imp_(\w+)\)",
                  lambda m: "[" + sanitized[m.group(1)] + "]" if m.group(1) in sanitized else m.group(0), text)
    # local copies of the property allocators and function constructors in such DLLs, sanitised the same way:
    # __2UFloatProperty__SAPEAX_... = ??2UFloatProperty@@SAPEAX..., __0UFunction__QEAA_... = ??0UFunction@@QEAA@...
    text = re.sub(r"(?<![\w*\[])__2(U\w+?)__SAPEAX(\w*)", r"[??2\1@@SAPEAX\2]", text)
    text = re.sub(r"(?<![\w*\[])__0(U(?:Delegate)?Function)__QEAA_(\w*?)(?=\s*\()", r"[??0\1@@QEAA@\2]", text)
    # CoreUObject itself (2026-10-24): its own FName constructor, named like the mangled name
    text = re.sub(r"(?<![\w*\[])__0FName__QEAA_PEB_W\w*(?=\s*\()", "[??0FName@@QEAA@PEB_W]", text)
    # ... and calls through Ghidra's import thunks, named like the slot: _SetValue_UMetaData__QEAA...(
    text = re.sub(r"(?<![\w*])(_\w+)(?=\s*\()",
                  lambda m: "[" + sanitized[m.group(1)] + "]" if m.group(1) in sanitized else m.group(0), text)

    def lit(m):
        s = pe.wstr(int(m.group(1), 16))
        return quote(s) if s is not None else m.group(0)
    return re.sub(r"&UNK_([0-9a-f]{9,})", lit, text)


def lit(group):
    return r'L"(?P<' + group + r'>(?:[^"\\]|\\.)*)"'


# a variable, or an element of a local array (`local_d18[0]`, Paper2D's two bool members, step 1.9e)
VAR = r"\w+(?:\[\d+\])?"
EVENTS = re.compile(
    r"\[\?\?0FName@@QEAA@PEB_W[^\]]*\]\s*\([^,;]*,\s*" + lit("name") +
    r"|(?P<new>" + VAR + r")\s*=\s*(?:\([^()]*\)\s*)?\[\?\?2(?P<kind>U\w+)@@SAPEAX[^\]]*\]"
    r"|\[\?SetValue@UMetaData@@[^\]]*\]\s*\(\s*\w+\s*,\s*(?:\([^()]*\)\s*)?(?P<obj>" + VAR + r")\s*,\s*" + lit("key") +
    r"\s*,\s*" + lit("value") +
    r"|\[\?\?0U(?:Delegate)?Function@@QEAA@[^\]]*\]\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*,\s*(?P<fflags>0x[0-9a-f]+)"
    # CoreUObject inlines its properties' operator new: U<Kind>::GetPrivateStaticClass(...), then
    # <var> = (UProperty *)StaticAllocateObject(that class, outer, name, ...)
    r"|(?<![\w:])(?P<cls>U\w+)::GetPrivateStaticClass\s*\("
    r"|(?P<alloc>" + VAR + r")\s*=\s*(?:\([^()]*\)\s*)?StaticAllocateObject\s*\("
    # ... and keeps what a property constructor returns (its this): <var> = UStructProperty::UStructProperty(<obj>, ...)
    r"|(?P<ctor>" + VAR + r")\s*=\s*(?:\([^()]*\)\s*)?(?P<ccls>U\w+)::(?P=ccls)\s*\(\s*(?:\([^()]*\)\s*)?(?P<this>"
    + VAR + r")\s*,"
    r"|(?P<lhs>" + VAR + r")\s*=\s*(?:\([^()]*\)\s*)?(?P<rhs>" + VAR + r")\s*;")
SELF = {"OuterClass", "ReturnClass", "ReturnFunction", "ReturnStruct", "ReturnEnum"}
NULL_BRANCH = re.compile(r"if \(" + VAR + r" == (?:\([^()]*\))?0x0\) \{([^{}]*)\}")
ASSIGN = re.compile(r"^" + VAR + r"\s*=\s*(?:\([^()]*\)\s*)?(?:" + VAR + r"|0x0)$")


def parse_one(text, type_name):
    """Metadata rows of one Z_Construct function."""
    objs = {v: ("", "self") for v in SELF}
    # without a PDB the type object is a bare global, tested first (`if (DAT_1800213c8 == 0x0)`, enums return it early
    # with `!=`): the type itself
    first = re.search(r"if \((DAT_\w+) [=!]= (?:\([^()]*\))?0x0\)", text)
    if first:
        objs[first.group(1)] = ("", "self")
    # the null branch of an allocation check never runs, but the events are read in code order: in
    # `if (p == 0x0) { q = 0x0; p = r; } else { q = p; }` q would get r's member (USkeletalMeshComponent's cached
    # pose arrays got RootBoneTranslation's tooltips, 2026-10-24). Only branches of plain assignments go: a type's own
    # guard (`if (ReturnFunction == 0x0) { ... }`) holds calls
    text = NULL_BRANCH.sub(lambda m: "" if all(ASSIGN.match(s.strip()) for s in m.group(1).split(";") if s.strip())
                           else m.group(0), text)
    name = None
    pending = None
    rows = []
    for m in EVENTS.finditer(text):
        if m.group("name") is not None:
            name = unquote(m.group("name"))
        elif m.group("new") or m.group("alloc"):
            kind = m.group("kind")[1:] if m.group("new") else (pending or "U?")[1:]
            objs[m.group("new") or m.group("alloc")] = (
                "" if kind in ("Function", "Class", "ScriptStruct", "Enum") else name, kind)
        elif m.group("cls"):
            pending = m.group("cls")
        elif m.group("obj"):
            member, kind = objs.get(m.group("obj"), ("?" + m.group("obj"), "?"))
            rows.append({"type": type_name, "member": member, "kind": kind,
                         "key": unquote(m.group("key")), "value": unquote(m.group("value"))})
        elif m.group("fflags"):
            # not metadata: the UFunction's EFunctionFlags (FUNC_Exec 0x200 marks a console command)
            rows.append({"type": type_name, "member": "", "kind": "Function", "key": "(FunctionFlags)",
                         "value": m.group("fflags")})
        elif m.group("ctor"):
            # the type's own object stays "self" (ReturnStruct = UScriptStruct::UScriptStruct(<global>, ...))
            if m.group("this") in objs and objs.get(m.group("ctor"), ("", ""))[1] != "self":
                objs[m.group("ctor")] = objs[m.group("this")]
        elif m.group("rhs") in objs:
            objs[m.group("lhs")] = objs[m.group("rhs")]
    return rows


def type_of(stem):
    """Z_Construct_UFunction_ULightComponentBase_SetCastVolumetricShadow -> ULightComponentBase.SetCastVolumetricShadow
    (the class name is the longest prefix that is not followed by a known split; functions keep the full rest)."""
    m = re.match(r"Z_Construct_U(Class|Function|ScriptStruct|Enum)_(.+)$", stem)
    kind, rest = m.groups()
    if kind == "Function":
        cls, _, fn = rest.partition("_")
        # class names have no underscore; delegate signatures keep theirs in the function part
        return f"{cls}.{fn}"
    return rest


def cmd_export(a):
    rx = r"^Z_Construct_U(Class|Function|ScriptStruct|Enum)_(?!.*_NoRegister$)"
    cmd = [sys.executable, "-I", str(TOOLS / "ghidra_find.py"), rx, "--decompile", "--skip-existing", "--limit", "1000000",
           "--workers", str(a.workers), "--project", a.project, "--name", a.name, "--program", Path(a.dll).name,
           "--out", str(Path(a.out).resolve())]
    sys.exit(subprocess.call(cmd))


def cmd_parse(a):
    pe = PE(a.dll)
    imps = pe.imports()
    block = next((va for va, s in imps.items() if s == "?GErrorHist@@3PA_WA"), None)
    n = 0
    with open(a.json, "w", encoding="utf-8", newline="\n") as out:
        for f in sorted(Path(a.dir).glob("Z_Construct_*.c")):
            text = resolve(f.read_text(encoding="utf-8", errors="replace"), pe, imps, block)
            for r in parse_one(text, type_of(f.stem.split("@")[0])):
                r["va"] = f.stem.split("@")[1]
                out.write(json.dumps(r, ensure_ascii=False) + "\n")
                n += 1
    unresolved = sum(1 for l in open(a.json, encoding="utf-8") if '"member": "?' in l)
    print(f"{n} metadata values, {unresolved} on objects not traced to a name")


def cmd_show(a):
    sys.stdout.reconfigure(encoding="utf-8")
    rows = [json.loads(l) for l in open(a.json, encoding="utf-8")]
    rows = [r for r in rows if r["type"] == a.type or r["type"].startswith(a.type + ".")]
    if a.member is not None:
        rows = [r for r in rows if r["member"] == a.member or r["type"].endswith("." + a.member)]
    last = None
    for r in rows:
        k = (r["type"], r["member"])
        if k != last:
            print(f"\n{r['type']}{'::' + r['member'] if r['member'] else ''}  ({r['kind']}, @{r['va']})")
            last = k
        v = r["value"].replace("\n", "\n" + " " * (6 + len(r["key"])))
        print(f"    {r['key']}: {v}")


# Developer notes: the team / author tags the developers put in their header comments (which become ToolTips).
# PRIMAL = ARK's engine work, YARK and ATLAS = ATLAS's; "PRIMAL - DK", "ATLAS - ScottM:", "YARK - INSTINCT", "END PRIMAL".
# Initials used alone as a prefix ("CC: ...", "LB: ...", "CR - ..."); "NB:" (nota bene) is not an author.
INITIALS = ("AS", "CC", "CD", "CR", "LB", "RJ")
TEAM = re.compile(r"(?<![A-Za-z])(?:(?:END|End|end)\s+(?P<eteam>PRIMAL|YARK|ATLAS)\b"
                  r"|(?P<team>PRIMAL|YARK|ATLAS)\b(?:\s*[-_]?\s*(?P<who>[A-Za-z][\w.]*))?)"
                  r"|(?:^|(?<=\n)|(?<=//)|(?<=// )|(?<=\. ))(?P<cc>" + "|".join(INITIALS) + r")(?::| -)\s")
MARKER = re.compile(r"\bTODO\b|@todo|\bHACK\b|\bhack\b|FIXME|no longer used|\bTEMP\b|[Tt]emporary|@warning|\bDO NOT\b"
                    r"|[Ll]atest ?bit")
# a commented-out declaration right above a member becomes that member's tooltip
DECL = re.compile(r"^\s*(?:UPROPERTY|UFUNCTION)\s*\(")
DEVNAME = re.compile(r"Debug|Test|Cheat|Stress|Profil(?:ing|er)|Hack|Temp(?!late|erature|o|le)|Dummy|Benchmark")
TEXTKEYS = ("ToolTip", "DisplayName", "FriendlyName", "Category", "DeprecationMessage", "Keywords")


def tags(text):
    """[(team, author)] of a note; author '(end)' for block-end markers."""
    out = []
    for m in TEAM.finditer(text):
        if m.group("eteam"):
            out.append((m.group("eteam"), "(end)"))
        elif m.group("cc"):
            out.append((m.group("cc"), ""))
        else:
            who = m.group("who") or ""
            if who.lower() == "end":
                who = "(end)"
            elif who.lower() == "instinct":
                who = "Instinct"
            out.append((m.group("team"), who))
    return out


def cmd_notes(a):
    """Developer notes, markers and dev-tool functions of one module's metadata: the full wording goes to a local
    file (not for git), the counts and names to a summary JSON."""
    rows = [json.loads(l) for l in open(a.json, encoding="utf-8")]
    loc = lambda r: r["type"] + ("::" + r["member"] if r["member"] else "")
    notes, markers, decls = [], [], []
    for r in rows:
        if r["key"] not in TEXTKEYS:
            continue
        t = tags(r["value"])
        if t:
            notes.append((t, r))
        elif MARKER.search(r["value"]):
            markers.append(r)
        elif r["key"] == "ToolTip" and DECL.search(r["value"]):
            decls.append(r)
    flags = {r["type"]: int(r["value"], 16) for r in rows if r["key"] == "(FunctionFlags)"}
    execs = sorted(t for t, f in flags.items() if f & 0x200)
    # types, functions and class / struct properties (not the parameters of a function)
    devnamed = sorted({loc(r) for r in rows if not ("." in r["type"] and r["member"])
                       and DEVNAME.search(r["type"].split(".")[-1] + " " + r["member"])})
    by_author = {}
    for t, r in notes:
        for team, who in dict.fromkeys(t):
            by_author.setdefault((team, who), []).append(r)
    lines = [f"# Developer notes in the DevKit's {a.label} metadata (generated, local only — not for git)", "",
             f"From `{a.json}` by `_tools/devkit_metadata.py notes`. {len(notes)} tagged notes, {len(markers)} other "
             f"markers (TODO / HACK / ...), {len(decls)} commented-out declarations, {len(execs)} console (Exec) functions, {len(devnamed)} dev / test / debug "
             "named members. Wording as the developers wrote it (header comments, via UHT ToolTips).", ""]
    for (team, who), rs in sorted(by_author.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        lines += [f"## {team}{' - ' + who if who else ''} ({len(rs)})", ""]
        for r in sorted(rs, key=loc):
            lines.append(f"- `{loc(r)}` ({r['kind']}, {r['key']}, @{r['va']}): " + r["value"].replace("\n", " / "))
        lines.append("")
    lines += [f"## Other markers ({len(markers)})", ""]
    lines += [f"- `{loc(r)}` ({r['key']}): " + r["value"].replace("\n", " / ") for r in sorted(markers, key=loc)]
    lines += ["", f"## Commented-out declarations ({len(decls)})", ""]
    lines += [f"- `{loc(r)}`: " + r["value"].replace("\n", " / ") for r in sorted(decls, key=loc)]
    lines += ["", f"## Console (Exec) functions ({len(execs)})", ""] + [f"- `{e}`" for e in execs]
    lines += ["", f"## Dev / test / debug named ({len(devnamed)})", ""] + [f"- `{d}`" for d in devnamed]
    Path(a.out).write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    summary = {"label": a.label, "tagged_notes": len(notes), "markers": len(markers), "declarations": len(decls),
               "authors": {f"{team}{' - ' + who if who else ''}": len(rs) for (team, who), rs in
                           sorted(by_author.items(), key=lambda kv: (-len(kv[1]), kv[0]))},
               "notes_by_type": {}, "exec": execs, "dev_named": devnamed}
    for t, r in notes:
        summary["notes_by_type"].setdefault(r["type"].split(".")[0], []).append(
            {"member": r["member"] or r["type"].partition(".")[2], "tags": [f"{x}{' - ' + y if y else ''}" for x, y in dict.fromkeys(t)]})
    Path(a.summary).write_text(json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8", newline="\n")
    print(f"{len(notes)} tagged notes, {len(markers)} markers, {len(decls)} declarations, {len(execs)} exec, {len(devnamed)} dev-named -> {a.out}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export")
    e.add_argument("--dll", required=True)
    e.add_argument("--out", required=True)
    e.add_argument("--workers", type=int, default=4)
    e.add_argument("--project", default=PROJECT)
    e.add_argument("--name", default="devkit")
    p = sub.add_parser("parse")
    p.add_argument("dir")
    p.add_argument("--dll", required=True)
    p.add_argument("--json", required=True)
    s = sub.add_parser("show")
    s.add_argument("json")
    s.add_argument("type")
    s.add_argument("member", nargs="?")
    n = sub.add_parser("notes")
    n.add_argument("json")
    n.add_argument("--label", required=True)
    n.add_argument("--out", required=True)
    n.add_argument("--summary", required=True)
    a = ap.parse_args()
    {"export": cmd_export, "parse": cmd_parse, "show": cmd_show, "notes": cmd_notes}[a.cmd](a)


if __name__ == "__main__":
    main()
