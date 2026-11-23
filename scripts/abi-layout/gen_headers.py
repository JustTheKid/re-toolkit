"""Layout headers from a PDB: a C++ declaration of each class or struct with ATLAS's exact layout - base classes, data
members in offset order with their types, bitfields and arrays, virtual functions in vtable order - followed by
static_asserts of its size and of every member's offset. Compiled against our engine (recompile_unit.py with a game
unit's command line, --source <probe.cpp>), the asserts prove the layout; phase 4d's headers start from these
(ADR-0006 point 3), with UPROPERTY / UFUNCTION specifiers from the reflection tables added later.

Usage: python -I _tools/gen_headers.py <exe> <Type> [<Type> ...] --out <file.h> [--known <json or list>] [--have RX]
  --known  types our engine has (an abi_diff.py dump of our probe, or a text file, one name per line): referenced,
           never emitted. Every other type a member needs is emitted first: its base classes, the structs it holds
           by value and the enums it uses as definitions, the classes it only points to as forward declarations.
  --have   a regex of further types to treat as known
  --declare member functions as declarations instead of comments (virtuals in vtable order, then the non-virtual
           ones with a unique public name; overloads and slots without a public name stay comments), with the forward
           declarations and enum definitions their signatures need: the start of a real header (2026-10-31, P6).
Members are public in the output (layout is what is checked; MSVC does not reorder by access). Virtuals' signatures
come from the decorated public names (dbghelp UnDecorateSymbolName); a virtual without a public name is left as a
comment with its slot. 2026-10-24, phase 4d (matching-decompilation.md).
"""
import argparse
import ctypes
import json
import re
import sys
from ctypes import wintypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from func_match import REPO, Original  # noqa: E402
from pdb_struct import Pdb  # noqa: E402

BASIC = {"bool8": "bool", "float32": "float", "float64": "double", "char8": "char", "wchar_t16": "wchar_t",
         "long32": "long", "ulong32": "unsigned long", "int8": "int8", "uint8": "uint8", "int16": "int16",
         "uint16": "uint16", "int32": "int32", "uint32": "uint32", "int64": "int64", "uint64": "uint64"}


def cpp_type(t):
    """dbghelp's type spelling -> C++ (basic types renamed inside templates too)."""
    t = re.sub(r"\b(TSharedPtr|TSharedRef|TWeakPtr|TSharedFromThis)<(.+?),([01])>",
               lambda m: f"{m.group(1)}<{m.group(2)},ESPMode::{'NotThreadSafe' if m.group(3) == '0' else 'ThreadSafe'}>", t)
    t = re.sub(r"\bTQueue<(.+?),([01])>", lambda m: f"TQueue<{m.group(1)},EQueueMode::{'Mpsc' if m.group(2) == '0' else 'Spsc'}>", t)
    # the map key funcs' bAllowDuplicateKeys is a bool the PDB spells 0 / 1 (the bulk headers, 2026-11-04)
    t = re.sub(r"\bTDefaultMapKeyFuncs<(.+?),([01])>", lambda m: f"TDefaultMapKeyFuncs<{m.group(1)},{'false' if m.group(2) == '0' else 'true'}>", t)
    return re.sub(r"\b(bool8|float32|float64|char8|wchar_t16|long32|ulong32)\b", lambda m: BASIC[m.group(1)], t)


def member_decl(m):
    t, name = cpp_type(m["type"]), m["name"]
    if m["bit"] is not None:
        return f"{t} {name} : {m['width']};"
    arr = re.match(r"^(.*?)((?:\[\d+\])+)$", t)
    if arr:
        return f"{arr.group(1)} {name}{arr.group(2)};"
    if "(*)" in t:
        return t.replace("(*)", f"(*{name})", 1) + ";"
    return f"{t} {name};"


class Decls:
    """Undecorated declarations of a class's member functions from the PE's publics."""

    def __init__(self, exe):
        self.orig = Original(exe, str(REPO / "_re" / "cache"))
        self.orig.symbol_at(0)
        self.dh = self.orig.dbghelp[0].dh
        self.dh.UnDecorateSymbolNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        self.by_class = {}
        for dec in self.orig.by_name:
            m = re.match(r"^\?(\w+)@(\w+)@@", dec)
            if m:
                self.by_class.setdefault(m.group(2), {}).setdefault(m.group(1), []).append(dec)

    def undecorate(self, dec):
        buf = ctypes.create_unicode_buffer(4096)
        return buf.value if self.dh.UnDecorateSymbolNameW(dec, buf, 4096, 0) else dec

    def declaration(self, cls, method):
        """'virtual bool IsActor() const;' for one name, or None when absent or overloaded."""
        decs = self.by_class.get(cls, {}).get(method, [])
        if len(decs) != 1:
            return None
        text = self.undecorate(decs[0])
        self.last_access = (re.match(r"^(public|protected|private): ", text) or [None, "public"])[1]
        text = re.sub(r"^(public|protected|private): ", "", text)
        text = text.replace("__cdecl ", "").replace(" __ptr64", "").replace("__ptr64", "")
        text = text.replace(f"{cls}::", "").replace("(void)", "()")
        return cpp_type(re.sub(r"\s+", " ", text).strip()) + ";"

    def overloads(self, cls, method):
        """Every overload's declaration of a name, as (access, text) in decorated-name order - for the names
        declaration() leaves out (2026-11-07: the static UPrimalUI::GetParentPrimalUI(const UWidget*) beside the
        virtual GetParentPrimalUI() const, which the tenth 4d unit calls)."""
        out = []
        for dec in sorted(self.by_class.get(cls, {}).get(method, [])):
            text = self.undecorate(dec)
            access = (re.match(r"^(public|protected|private): ", text) or [None, "public"])[1]
            text = re.sub(r"^(public|protected|private): ", "", text)
            text = text.replace("__cdecl ", "").replace(" __ptr64", "").replace("__ptr64", "")
            text = text.replace(f"{cls}::", "").replace("(void)", "()")
            if "(" not in text or "`" in text:
                continue
            out.append((access, cpp_type(re.sub(r"\s+", " ", text).strip()) + ";"))
        return out

    def all_methods(self, cls):
        """Every method name of a class that has public symbols."""
        return sorted(self.by_class.get(cls, {}))


# any capitalised name (2026-11-04, the bulk headers: ATLAS's PGSettings, HighlightStartingPoint, OverlayAnimationData,
# DepthOfFieldLimits and ServerSortingTypeType have no UE prefix and were never emitted); a word the PDB does not know
# as a type is dropped by need()
TYPE_NAME = re.compile(r"(?:enum\s+)?(?<![A-Za-z0-9_])([A-Z][A-Za-z0-9_]*(?:::[A-Za-z0-9_]+)?)")
POINTED = re.compile(r"^(?:TSubclassOf|TWeakObjectPtr|TLazyObjectPtr|TAssetPtr|TAssetSubclassOf)<|\*$")
WRAPPERS = ("TSubclassOf", "TWeakObjectPtr", "TLazyObjectPtr", "TAssetPtr", "TAssetSubclassOf", "TSharedPtr", "TSharedRef",
            "TWeakPtr", "TUniquePtr", "TAutoPtr", "TScopedPointer", "TFunction")


def type_refs(t):
    """The type names in a member's type with whether each is held by value: a name directly followed by '*' or '&'
    is pointed to; so is every name inside a pointer-like wrapper template (TSubclassOf<...>, TSharedPtr<...>);
    anything else, a container's element type included, must be complete for the layout."""
    out, depth, wrapped = [], 0, []
    for m in re.finditer(r"([A-Za-z_][\w:]*)|([<>])", t):
        if m.group(2) == "<":
            depth += 1
            continue
        if m.group(2) == ">":
            depth -= 1
            wrapped = [d for d in wrapped if d <= depth]
            continue
        name = m.group(1)
        if name in ("enum", "class", "struct", "const", "unsigned", "signed", "int", "char", "short", "long", "float", "double",
                    "bool", "void", "__cdecl", "__int64", "__ptr64"):
            continue
        rest = t[m.end():m.end() + 2].strip()
        pointed = rest.startswith(("*", "&")) or bool(wrapped)
        if name in WRAPPERS:
            wrapped.append(depth + 1)
        if re.match(r"^[A-Z][A-Za-z0-9_]*(?:::[A-Za-z0-9_]+)?$", name):  # any capitalised name (PGSettings, the bulk headers)
            out.append((name, not pointed))
    return out


class Gen:
    def __init__(self, pdb, decls, known, declare=False):
        self.pdb, self.decls, self.known, self.declare = pdb, decls, known, declare
        self.out, self.done, self.forward, self.base_checked = [], set(), set(), set()
        self.sig_enums, self.sig_forward = [], set()

    def signature_types(self, decl):
        """The types a declaration names: enums become definitions, classes forward declarations (both ahead of the
        header's first class), unless known or already emitted."""
        for m in re.finditer(r"\b(class|struct|enum)\s+([A-Za-z_][\w:]*)(<?)", decl):
            kind, name = m.group(1), m.group(2)
            if m.group(3) == "<" or name in self.done or self.is_known(name) or name.split("::")[0] in self.done \
                    or self.is_known(name.split("::")[0]):
                continue  # a template instance: its template is declared by the engine (or by hand)
            if kind == "enum":
                if name not in self.sig_forward:
                    self.sig_forward.add(name)
                    enum = self.pdb.enumerators(name)
                    if enum is not None:
                        values = ", ".join(f"{n} = {v}" for n, v in enum)
                        if "::" in name:
                            ns, en = name.split("::", 1)
                            self.sig_enums.append(f"namespace {ns} {{ enum {en} {{ {values} }}; }}")
                        else:
                            self.sig_enums.append(f"enum {name} {{ {values} }};")
            elif "<" not in name and name not in self.forward and name not in self.sig_forward:
                self.sig_forward.add(name)
                self.sig_enums.append(f"{kind} {name};")

    def is_known(self, name):
        return name in self.known

    def access_prefix(self):
        """'protected: ' / 'private: ' ahead of a declaration whose public symbol says so, with 'public:' restored on
        the same line's tail by the caller's layout: the labels are one-line so the members stay in symbol order."""
        a = getattr(self.decls, "last_access", "public")
        return "" if a == "public" else f"{a}: "

    def need(self, name, by_value):
        """Make a referenced type available before it is used."""
        if name in self.done or self.is_known(name) or name.split("::")[0] in self.done or self.is_known(name.split("::")[0]):
            return
        enum = self.pdb.enumerators(name)
        if enum is not None:
            self.done.add(name)
            values = ", ".join(f"{n} = {v}" for n, v in enum)
            if "::" in name:
                ns, en = name.split("::", 1)
                self.out.append(f"namespace {ns} {{ enum {en} {{ {values} }}; }}")
            else:
                self.out.append(f"enum {name} {{ {values} }};")
            return
        if self.pdb.members(name) is None:
            return  # not a type the PDB knows (a template parameter word, a typedef)
        if by_value:
            self.emit(name)
        elif name not in self.forward:
            self.forward.add(name)
            self.out.append(f"{'class' if name[0] in 'UA' else 'struct'} {name};")

    def known_base(self, base):
        """A base that is a template instance our engine does not have (e.g. the delegate signature class
        TBaseDynamicMulticastDelegate_TwoParams<void,bool,FString,FWeakObjectPtr>) is replaced by its own primary base,
        repeatedly, until a known or non-template one: same layout, no specialisation to declare."""
        while "<" in base["name"] and not self.is_known(base["name"]):
            inner = [m for m in self.pdb.members(base["name"]) or [] if m["base"] and m["offset"] == 0]
            if not inner:
                break
            base = dict(inner[0], offset=base["offset"])
        return base

    def emit(self, name):
        if name in self.done:
            return
        self.done.add(name)
        pdb = self.pdb
        members = pdb.members(name)
        if members is None:
            self.out.append(f"// {name}: not in the PDB")
            return
        base_list = [self.known_base(m) for m in members if m["base"]]
        for b in base_list:
            self.need(b["name"], True)
            if self.is_known(b["name"]) and b["name"] not in self.base_checked:
                self.base_checked.add(b["name"])
                bsize = self.pdb.size(b["name"])
                self.out.append(f"static_assert(sizeof({b['name']}) == 0x{bsize:x}, \"engine base {b['name']}: size (ours differs from ATLAS's)\");")
        for m in members:
            if m["base"]:
                continue
            for ref, by_value in type_refs(m["type"]):
                if ref != name:
                    self.need(ref, by_value=by_value)
        size = pdb.size(name)
        head = f"struct {name}" + (" : " + ", ".join(f"public {b['name']}" for b in base_list) if base_list else "")
        out = self.out
        out += ["", f"// {name}: size 0x{size:x}, from the PDB (gen_headers.py)", head, "{"]
        for m in sorted((m for m in members if not m["base"]), key=lambda m: (m["offset"], m["bit"] or 0)):
            where = f"+0x{m['offset']:x}" + (f".{m['bit']}" if m["bit"] is not None else "")
            if self.declare and "<tag " in m["type"]:
                out.append(f"	// (the vtable pointer, from the virtual functions below)                  // {where}")
                continue
            out.append(f"	{member_decl(m):<64} // {where}")
        virtuals = sorted({(v, n) for n, v in (pdb.methods(name) or []) if v}, key=lambda x: x[0])
        seen = set()
        for voff, method in virtuals:
            short = method.rsplit("::", 1)[-1]
            seen.add(short)
            d = self.decls.declaration(name, short)
            if self.declare and d:
                self.signature_types(d)
                out.append(f"	{self.access_prefix()}{d:<64} // vtable +0x{voff:x}")
            else:
                out.append(f"	// {d:<61} // vtable +0x{voff:x}" if d else
                           f"	// virtual {short}: vtable +0x{voff:x} (no unique public name)")
        if self.declare:
            rest = [m for m in self.decls.all_methods(name) if m not in seen and not m.startswith("?")]
            if rest:
                out.append("	// non-virtual member functions with a public symbol (gen_headers.py --declare)")
            for short in rest:
                d = self.decls.declaration(name, short)
                if d:
                    self.signature_types(d)
                    out.append(f"	{self.access_prefix()}{d}")
                    continue
                # an overloaded name stays a comment: one of its overloads may be a reflected function, which the
                # reflection pass declares (2026-11-07: AShooterGameMode::PostAlarmNotification, both overloads
                # declared, gave UHT the wrong one)
                out.append(f"	// {short}: overloaded (declare by hand)")
            # a virtual's name with non-virtual overloads beside it (a static, a non-virtual sibling): declared too
            for short in sorted(seen):
                ovs = self.decls.overloads(name, short)
                if len(ovs) < 2:
                    continue
                for acc, od in ovs:
                    if not od.startswith("virtual "):
                        self.signature_types(od)
                        out.append(f"	{'' if acc == 'public' else acc + ': '}{od} // overload beside the virtual")
        # a one-line 'protected: ' / 'private: ' label changes the access of what follows: restore it
        fixed = []
        for l in out[len(out) - (len(out) - out.index(head) if head in out else 0):]:
            fixed.append(l)
        start = out.index(head) if head in out else 0
        body = out[start:]
        del out[start:]
        for l in body:
            out.append(l)
            if re.match(r"^\t(protected|private): ", l):
                out.append("	public:")
        out += ["};", f"static_assert(sizeof({name}) == 0x{size:x}, \"{name}: size\");"]
        for m in members:
            if not m["base"] and m["bit"] is None and not (self.declare and "<tag " in m["type"]):
                out.append(f"static_assert(STRUCT_OFFSET({name}, {m['name']}) == 0x{m['offset']:x}, "
                           f"\"{name}::{m['name']}: offset\");")


def main():
    ap = argparse.ArgumentParser(fromfile_prefix_chars="@")
    ap.add_argument("exe")
    ap.add_argument("types", nargs="+")
    ap.add_argument("--out", required=True)
    ap.add_argument("--known")
    ap.add_argument("--have")
    ap.add_argument("--declare", action="store_true")
    a = ap.parse_args()
    known = set()
    if a.known:
        text = Path(a.known).read_text(encoding="utf-8")
        known = set(json.loads(text)) if text.lstrip().startswith("{") else {l.strip() for l in text.split("\n") if l.strip()}
    if a.have:
        rx = re.compile(a.have)
        known |= {"__have__"}
    gen = Gen(Pdb(a.exe), Decls(a.exe), known, a.declare)
    if a.have:
        gen.is_known = lambda n: n in known or bool(rx.search(n))
    for t in a.types:
        gen.emit(t)
    head = [f"// Layout header generated by _tools/gen_headers.py from {Path(a.exe).name}'s PDB - do not edit.",
            "// Virtual functions are listed as comments: a layout check does not need them.", "#pragma once",
            "#pragma warning(disable: 4510 4610)  // layout-only structs: no constructors", ""]
    if gen.sig_enums:
        head += ["// types named by member function signatures (gen_headers.py --declare)"] + gen.sig_enums + [""]
    Path(a.out).write_text("\n".join(head + gen.out) + "\n", encoding="utf-8")
    print(f"{a.out}: {len(gen.done)} types emitted, {len(gen.forward)} forward declarations")


if __name__ == "__main__":
    main()
