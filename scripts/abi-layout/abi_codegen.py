"""The edits that bring one of our classes to ATLAS's C++ ABI, from abi_diff.py's two dumps: each member ATLAS has and
we lack as a declaration, placed after the nearest member both have (bitfields in ATLAS's bit order); each virtual
ATLAS has and we lack, with its signature from the server's decorated public names, placed after the virtual it
follows in ATLAS's vtable; members and virtuals only we have, to remove or move under WITH_EDITOR; size and bit
changes. A new virtual whose body the linker folded into one of the tiny shared stubs gets that body inline
(`{ return false; }`, `{ return true; }`, `{ return 0; }`, `{}`, `{ return nullptr; }`); any other body is a TODO
naming its address. It suggests, it does not edit: the order of edits follows our header's declaration order.

Usage: python -I _tools/abi_codegen.py <original exe> <theirs.json> <ours.json> <Class> [--bodies]
           [--names-from <DevKit DLL>]
  theirs.json / ours.json: abi_diff.py dumps (ATLAS's PDB, our probe). --bodies reads each new virtual's code
  (first bytes at its address) to classify the trivial ones. --names-from takes the parameters' names from a PE's PDB
  (the function's scope): the DevKit's editor DLLs, whose linker did not fold the trivial virtuals as the server's did.
2026-10-24, phase 4b step 1.11 (matching-decompilation.md "ABI parity").
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from abi_diff import key_methods, primary_base  # noqa: E402
from gen_headers import Decls, member_decl  # noqa: E402

# the shared stubs MSVC folds trivial virtuals into, by their code bytes
STUBS = {
    bytes.fromhex("32c0c3"): "{ return false; }",          # xor al, al; ret
    bytes.fromhex("b001c3"): "{ return true; }",           # mov al, 1; ret
    bytes.fromhex("33c0c3"): "{ return 0; }",              # xor eax, eax; ret
    bytes.fromhex("c20000"): "{}",                         # ret 0
    bytes.fromhex("c3"): "{}",                             # ret
}

# the undecorated basic types in UE's spelling
UE_TYPES = [("unsigned __int64", "uint64"), ("__int64", "int64"), ("unsigned int", "uint32"),
            ("unsigned short", "uint16"), ("unsigned char", "uint8"), ("short", "int16"), ("int", "int32"),
            ("wchar_t", "TCHAR")]


# types every engine header sees; any other class keeps its `class` / `struct` keyword, which declares it on the spot
# (a header's new parameter types need no forward declarations, as UE's own headers write them)
CORE_TYPES = {"FVector", "FVector2D", "FVector4", "FRotator", "FQuat", "FTransform", "FMatrix", "FPlane", "FName",
              "FString", "FText", "FBox", "FBoxSphereBounds", "FColor", "FLinearColor", "FGuid", "FIntPoint",
              "FIntVector", "TArray", "TMap", "TSet", "TSubclassOf", "TWeakObjectPtr", "TSharedPtr", "TSharedRef",
              "TEnumAsByte", "TLinkedList", "TMulticastDelegate_NoParams", "UObject", "UClass", "FDefaultAllocator"}


def tidy(decl):
    """An undecorated declaration in UE's spelling: basic types, no default allocator, const in front."""
    decl = re.sub(r"\b(?:class|struct) (\w+)", lambda m: m.group(1) if m.group(1) in CORE_TYPES else m.group(0), decl)
    decl = decl.replace(" *", "*").replace(" &", "&")
    for c, ue in UE_TYPES:
        decl = re.sub(r"(?<![A-Za-z0-9_])" + c + r"(?![A-Za-z0-9_])", ue, decl)
    decl = decl.replace(",FDefaultAllocator>", ">")
    # the other containers' and pointers' default arguments, as UE's headers leave them out
    decl = decl.replace(",FWeakObjectPtr,FIndexToObject>", ">")
    decl = re.sub(r",FDefaultSetAllocator,TDefaultMapKeyFuncs<[^<>]*,0> >", ">", decl)
    decl = re.sub(r",DefaultKeyFuncs<[^<>]*,0>,FDefaultSetAllocator>", ">", decl)
    # the shared pointers' default mode (ESPMode::NotThreadSafe) is a bare 0 in the decorated name, not valid C++
    decl = re.sub(r"\b(TSharedPtr|TSharedRef|TWeakPtr)<([^<>]*),0>", r"\1<\2>", decl)
    # a type with up to one nested template argument list, never across a parameter's comma
    decl = re.sub(r"((?:(?:class|struct|enum) )?[A-Za-z_][\w:]*(?:<(?:[^()<>]|<[^()<>]*>)*>)?) const([*&])",
                  r"const \1\2", decl)
    return re.sub(r"\)const\b", ") const", decl)


def split_params(text):
    """A parameter list split at its top-level commas."""
    out, depth, cur = [], 0, ""
    for ch in text:
        depth += (ch in "<(") - (ch in ">)")
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    return out + [cur.strip()] if cur.strip() else out


class ParamNames:
    """Parameter names of Class::Method from a PE's PDB (dbghelp: the function's scope, SYMFLAG_PARAMETER), in a
    dbghelp session of its own beside Decls's."""

    def __init__(self, pe):
        import ctypes
        from ctypes import wintypes
        from pdb_struct import SYMBOL_INFOW, Pdb
        from pdb_vtable import symbol
        self.ctypes, self.info, self.symbol = ctypes, SYMBOL_INFOW, symbol
        self.pdb = Pdb(pe, proc=0x5712E)
        self.pdb.type_id("UObject")  # loads the module's symbols
        dh = self.pdb.dh
        dh.SymFromNameW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, ctypes.c_void_p]
        dh.SymSetScopeFromAddr.argtypes = [wintypes.HANDLE, ctypes.c_uint64]
        self.cb = ctypes.WINFUNCTYPE(wintypes.BOOL, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p)
        dh.SymEnumSymbolsW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, wintypes.LPCWSTR, self.cb, ctypes.c_void_p]

    def names(self, qualified):
        """['InWorld', ...] without 'this', or None when the PDB has no such function."""
        ctypes, dh = self.ctypes, self.pdb.dh
        _, sym = self.symbol()
        if not dh.SymFromNameW(self.pdb.proc, qualified, ctypes.addressof(sym)):
            return None
        found = []

        def on(p, _s, _c):
            i = ctypes.cast(p, ctypes.POINTER(self.info)).contents
            if i.Flags & 0x40:  # SYMFLAG_PARAMETER
                n = ctypes.wstring_at(ctypes.addressof(i) + self.info.Name.offset, i.NameLen).rstrip("\0")
                if n != "this" and n not in found:
                    found.append(n)
            return True

        dh.SymSetScopeFromAddr(self.pdb.proc, sym.Address)
        dh.SymEnumSymbolsW(self.pdb.proc, 0, None, self.cb(on), None)
        return found

    def line(self, qualified):
        """'Actor.h:1234', the source line of the function's code (an inline virtual's own header line), or None."""
        ctypes = self.ctypes
        from ctypes import wintypes
        from pdb_func_lines import IMAGEHLP_LINEW64
        dh = self.pdb.dh
        _, sym = self.symbol()
        if not dh.SymFromNameW(self.pdb.proc, qualified, ctypes.addressof(sym)):
            return None
        dh.SymGetLineFromAddrW64.argtypes = [wintypes.HANDLE, ctypes.c_uint64, ctypes.POINTER(wintypes.DWORD),
                                             ctypes.POINTER(IMAGEHLP_LINEW64)]
        ln = IMAGEHLP_LINEW64(SizeOfStruct=ctypes.sizeof(IMAGEHLP_LINEW64))
        disp = wintypes.DWORD(0)
        if not dh.SymGetLineFromAddrW64(self.pdb.proc, sym.Address, ctypes.byref(disp), ctypes.byref(ln)):
            return None
        return f"{ln.FileName.replace('/', chr(92)).rsplit(chr(92), 1)[-1]}:{ln.LineNumber}"


def with_names(decl, names):
    """'virtual bool F(UWorld*);' + ['InWorld'] -> 'virtual bool F(UWorld* InWorld);', when the counts agree."""
    m = re.match(r"^(.*?\()(.*)(\)(?: const)?;?)$", decl)
    if not m or not names:
        return decl
    params = [p for p in split_params(m.group(2)) if p != "void"]
    if len(params) != len(names):
        return decl
    return m.group(1) + ", ".join(f"{p} {n}" for p, n in zip(params, names)) + m.group(3)


def own_virtuals(dump, name):
    """{(name, k): slot} of the virtuals a class introduces (slots past its primary base's vtable)."""
    t = dump[name]
    base = primary_base(t)
    base_slots = set(key_methods(dump[base]["methods"]).values()) if base in dump else set()
    return {k: v for k, v in key_methods(t["methods"]).items() if v not in base_slots}


def in_order(items, slots):
    """The longest subsequence of items (in ATLAS's order) whose slots in ours ascend: the virtuals that stay."""
    tails, prev_of, best = [], {}, []
    for k in items:
        s = slots[k]
        lo, hi = 0, len(tails)
        while lo < hi:
            mid = (lo + hi) // 2
            if slots[tails[mid]] < s:
                lo = mid + 1
            else:
                hi = mid
        prev_of[k] = tails[lo - 1] if lo else None
        if lo == len(tails):
            tails.append(k)
        else:
            tails[lo] = k
    k = tails[-1] if tails else None
    while k is not None:
        best.append(k)
        k = prev_of[k]
    return set(best)


def overrides(dump, name):
    """{method: slot} of the inherited virtuals a class overrides. dbghelp gives an override no vtable offset (only
    a virtual's introduction has one), so: a function of the class without one, named as a virtual of a base."""
    inherited, base = {}, primary_base(dump[name])
    while base in dump:
        for (m, _k), slot in key_methods(dump[base]["methods"]).items():
            inherited.setdefault(m, slot)
        base = primary_base(dump[base])
    own = {n.rsplit("::", 1)[-1] for n, voff in dump[name]["methods"] if not voff}
    return {m: inherited[m] for m in own if m in inherited}


def body_of(decls, cls, method, orig, shapes=None, params=None):
    """A trivial stub's inline body, a tiny function's from its shape (tiny_bodies.py), else a TODO naming the
    address; None without a single public name."""
    decs = decls.by_class.get(cls, {}).get(method, [])
    if len(decs) != 1:
        return None
    rva = orig.by_name.get(decs[0])
    if rva is None:
        return None
    code = orig.read(rva, 3) or b""
    for stub, body in STUBS.items():
        if code.startswith(stub) and (len(stub) == 3 or code[:1] == b"\xc3"):
            return body
    body = shapes.body(rva + orig.image_base, params) if shapes else None
    return body or f"// TODO body: SRV@{rva + orig.image_base:x}"


def arity(decls, cls):
    """name -> the parameter count of the class's function from its public name (None: absent or overloaded)."""
    def count(name):
        d = decls.declaration(cls, name)
        m = re.match(r"^.*?\((.*)\)", d or "")
        return len([p for p in split_params(m.group(1)) if p != "void"]) if m else None
    return count


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("exe")
    ap.add_argument("theirs")
    ap.add_argument("ours")
    ap.add_argument("cls")
    ap.add_argument("--bodies", action="store_true")
    ap.add_argument("--names-from")
    a = ap.parse_args()
    theirs = json.loads(Path(a.theirs).read_text(encoding="utf-8"))
    ours = json.loads(Path(a.ours).read_text(encoding="utf-8"))
    t, o = theirs[a.cls], ours[a.cls]
    decls = Decls(a.exe)
    orig = decls.orig
    pnames = ParamNames(a.names_from) if a.names_from else None
    shapes = None
    if a.bodies:
        from tiny_bodies import Body
        shapes = Body(orig, theirs, a.cls, arity(decls, a.cls))
    print(f"// {a.cls}: ATLAS size 0x{t['size']:x}, ours 0x{o['size']:x}")

    def declare(m, override=False):
        """The declaration of the class's function m with names, spelling and body."""
        d = tidy(decls.declaration(a.cls, m) or f"virtual /* signature: overloaded or no public name */ {m}(...);")
        names = pnames.names(f"{a.cls}::{m}") if pnames else None
        d = with_names(d, names)
        if override and d.endswith(";"):
            d = d[:-1] + " override;"
        body = body_of(decls, a.cls, m, orig, shapes, names) if a.bodies else None
        if body and not body.startswith("//") and d.endswith(";"):
            return d[:-1] + " " + body
        return f"{d} {body}" if body else d

    def where(m, slot):
        """The trailing comment of a function's edit: its slot, its access (from the decorated name: it is part of the
        name every caller links to) and, with --names-from, the DevKit's source line."""
        decs = decls.by_class.get(a.cls, {}).get(m, [])
        acc = re.match(r"^(public|protected|private): ", decls.undecorate(decs[0])) if len(decs) == 1 else None
        line = pnames.line(f"{a.cls}::{m}") if pnames else None
        return f"// slot +0x{slot:x}; {acc.group(1) if acc else 'access ?'}" + (f"; DevKit {line}" if line else "")

    # data members, in ATLAS's order. As for the virtuals: the longest run of the members both have that ours already
    # declares in ATLAS's order stays, the others move, and every edit's anchor is the member before it in ATLAS's order.
    om = {m["name"]: m for m in o["members"] if not m["base"]}
    tm = sorted((m for m in t["members"] if not m["base"]), key=lambda m: (m["offset"], m["bit"] or 0))
    stay = in_order([m["name"] for m in tm if m["name"] in om],
                    {n: (m["offset"], -1 if m["bit"] is None else m["bit"]) for n, m in om.items()})
    print("\n// == members")
    prev = None
    for m in tm:
        mine = om.get(m["name"])
        at = f"+0x{m['offset']:x}" + (f".{m['bit']}" if m["bit"] is not None else "")
        anchor = f"after {prev}" if prev else "first member"
        if mine is None:
            print(f"ADD    {anchor:<40} {tidy(member_decl(m)):<60} // {at}")
        else:
            if m["name"] not in stay:
                print(f"MOVE   {m['name']:<40} ours declares it elsewhere: move it {anchor}  // {at}")
            # a bit that only moved (another bit was added before it) is no edit of its own
            if mine["size"] != m["size"] or (mine["bit"] is None) != (m["bit"] is None) or mine.get("width") != m.get("width"):
                print(f"CHANGE {m['name']:<40} ATLAS {member_decl(m)} ({at}, size 0x{m['size'] or 0:x}); "
                      f"ours size 0x{mine['size'] or 0:x}")
        prev = m["name"]
    names_t = {m["name"] for m in tm}
    for m in o["members"]:
        if not m["base"] and m["name"] not in names_t:
            print(f"REMOVE {m['name']:<40} (only ours: {member_decl(m)}; WITH_EDITOR in ATLAS?)")

    # virtuals this class introduces, in ATLAS's vtable order; one ours declares without virtual keeps its body. The
    # longest run of the virtuals both have that ours already declares in ATLAS's order stays; the others move. Every
    # edit's anchor is the virtual before it in ATLAS's order, so an edit can follow one this list adds or moves.
    tv, ov = own_virtuals(theirs, a.cls), own_virtuals(ours, a.cls) if a.cls in ours else {}
    plain = {n.rsplit("::", 1)[-1] for n, voff in o["methods"] if not voff}
    atlas_order = [k for k, _ in sorted(tv.items(), key=lambda kv: kv[1])]
    keep = in_order([k for k in atlas_order if k in ov], ov)
    print("\n// == virtuals this class introduces")
    prev = None
    for k in atlas_order:
        slot = tv[k]
        anchor = f"after virtual {prev}" if prev else "first new virtual"
        if k in ov:
            if k not in keep:
                print(f"MOVE   {k[0]:<40} ours declares it elsewhere: move it {anchor}  {where(k[0], slot)}")
        elif k[0] in plain:
            print(f"VIRTUAL {k[0]:<39} ours declares it without virtual: move it {anchor}, add virtual  "
                  f"{where(k[0], slot)}")
        else:
            print(f"ADD    {anchor:<40} {declare(k[0])}  {where(k[0], slot)}")
        prev = k[0]
    for k, slot in sorted(ov.items(), key=lambda kv: kv[1]):
        if k not in tv:
            print(f"REMOVE virtual {k[0]} (only ours, slot +0x{slot:x}; WITH_EDITOR in ATLAS?)")

    # overrides: no slot of their own, but the slot's function (the vtable's contents) is the class's
    to, oo = overrides(theirs, a.cls), overrides(ours, a.cls) if a.cls in ours else {}
    print("\n// == overrides of inherited virtuals")
    for m, slot in sorted(to.items(), key=lambda kv: kv[1]):
        if m not in oo:
            print(f"ADD    {'override':<40} {declare(m, override=True)}  {where(m, slot)}")
    for m, slot in sorted(oo.items(), key=lambda kv: kv[1]):
        if m not in to:
            print(f"REMOVE override {m} (only ours, slot +0x{slot:x}; WITH_EDITOR in ATLAS?)")


if __name__ == "__main__":
    main()
