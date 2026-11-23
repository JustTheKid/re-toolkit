"""Give a PDB-only Ghidra program its imported functions back: named, typed external functions behind every IAT slot.

Why: in the DevKit's editor DLLs (UE4Editor-Engine.dll, -UnrealEd.dll, ...) the PDB types one import slot as a big
array (`__imp_?GErrorHist@@3PA_WA` = wchar_t[16384], 32 KB), which swallows the slots after it and their external
references. The decompiler then shows every call into Core / CoreUObject as `(*(code *)__imp__GErrorHist__3PA_WA._N_8_)`
with at most four register arguments: stack arguments such as a property constructor's flags are lost. The PDB-only
analysis never demangled the external names either, so even intact slots have no prototypes.

`retype_imports(program, dll)` (call it inside a transaction; ghidra_find.py --fix-imports rolls it back after
decompiling, so the project is never changed): clears any data spanning several slots, re-creates each slot as a
pointer with its external reference (library and decorated name from the DLL's own import table), turns imported
functions into external functions and applies their demangled name, namespace and prototype (MSVC names encode the
parameter types; members get __thiscall's `this`). Calls then decompile as `UObjectProperty::UObjectProperty(this,
PCIP, 0, 0x298, 0x8040a0009, cls)`.

Usage (check one function): python -I _tools/ghidra_imports.py <dll> <function regex> [--project D:/ATLAS/_re/ghidra-devkit
       --name devkit]
"""
import argparse
import os
import struct
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
os.environ.setdefault("GHIDRA_INSTALL_DIR", str(TOOLS / "ghidra_12.1.4_PUBLIC"))
os.environ.setdefault("JAVA_HOME", str(TOOLS / "jdk-21.0.12.1+1"))


def import_slots(dll):
    """[(slot VA, DLL name, decorated name or '#ordinal')] from the PE import table."""
    b = Path(dll).read_bytes()
    e = struct.unpack_from("<I", b, 0x3C)[0]
    nsec, = struct.unpack_from("<H", b, e + 6)
    optsz, = struct.unpack_from("<H", b, e + 20)
    opt = e + 24
    base, = struct.unpack_from("<Q", b, opt + 24)
    imp_rva, _ = struct.unpack_from("<II", b, opt + 112 + 8)
    secs = []
    s = opt + optsz
    for _ in range(nsec):
        vsz, va, rsz, roff = struct.unpack_from("<IIII", b, s + 8)
        secs.append((va, max(vsz, rsz), roff))
        s += 40

    def off(rva):
        return next(roff + rva - va for va, sz, roff in secs if va <= rva < va + sz)

    def cstr(rva):
        o = off(rva)
        return b[o:b.index(b"\0", o)].decode("latin-1")
    out = []
    d = off(imp_rva)
    while True:
        oft, _, _, name, ft = struct.unpack_from("<IIIII", b, d)
        if not ft:
            return out
        lib = cstr(name)
        t = off(oft or ft)
        i = 0
        while True:
            v, = struct.unpack_from("<Q", b, t + 8 * i)
            if not v:
                break
            out.append((base + ft + 8 * i, lib, f"#{v & 0xffff}" if v >> 63 else cstr((v & 0x7fffffff) + 2)))
            i += 1
        d += 20


def retype_imports(program, dll, log=print):
    from ghidra.app.util.demangler import DemangledFunction
    from ghidra.app.util.demangler.microsoft import MicrosoftDemangler
    from ghidra.program.model.data import (BooleanDataType, FunctionDefinitionDataType, ByteDataType, CharDataType, DoubleDataType,
                                           FloatDataType, IntegerDataType, LongLongDataType, PointerDataType,
                                           ShortDataType, UnsignedIntegerDataType, UnsignedLongLongDataType,
                                           UnsignedShortDataType, VoidDataType, WideChar16DataType)
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl
    from ghidra.program.model.symbol import RefType, SourceType
    from ghidra.app.util import NamespaceUtils
    from java.util import ArrayList

    slots = import_slots(dll)
    space = program.getAddressFactory().getDefaultAddressSpace()
    listing = program.getListing()
    refs = program.getReferenceManager()
    ext = program.getExternalManager()
    st = program.getSymbolTable()
    libs = {n.upper(): n for n in ext.getExternalLibraryNames()}
    # 1. data spanning several slots (the PDB's typed import symbol) goes
    cleared = 0
    for va, _, _ in slots:
        a = space.getAddress(va)
        dat = listing.getDataContaining(a)
        if dat is not None and dat.getLength() > 8:
            listing.clearCodeUnits(dat.getAddress(), dat.getMaxAddress(), False)
            cleared += 1
    # 2. slot pointers and external references
    dem = MicrosoftDemangler()
    prim = {"bool": BooleanDataType(), "char": CharDataType(), "wchar_t": WideChar16DataType(),
            "short": ShortDataType(), "int": IntegerDataType(), "long": IntegerDataType(),
            "__int64": LongLongDataType(), "float": FloatDataType(), "double": DoubleDataType(),
            "void": VoidDataType()}
    uns = {"char": ByteDataType(), "short": UnsignedShortDataType(), "int": UnsignedIntegerDataType(),
           "long": UnsignedIntegerDataType(), "__int64": UnsignedLongLongDataType()}
    ptr = PointerDataType()

    def dtype(t):
        if t is None:
            return VoidDataType()
        if t.isPointer() or t.isReference():
            return ptr
        name = t.getName()
        if t.isUnsigned() and name in uns:
            return uns[name]
        if name in prim:
            return prim[name]
        if t.isEnum():
            return IntegerDataType()
        return UnsignedLongLongDataType()  # a class by value: one 8-byte slot (larger ones go by reference)

    made = typed = failed = 0
    for va, lib, name in slots:
        a = space.getAddress(va)
        if listing.getDataAt(a) is None:
            listing.createData(a, ptr)
        glib = libs.get(lib.upper(), lib)
        if not any(r.isExternalReference() for r in refs.getReferencesFrom(a)):
            refs.addExternalReference(a, glib, name, None, SourceType.IMPORTED, 0, RefType.DATA)
            made += 1
        if not name.startswith("?"):
            continue
        r = next(r for r in refs.getReferencesFrom(a) if r.isExternalReference())
        loc = r.getExternalLocation()
        try:
            obj = dem.demangle(dem.createMangledContext(name, None, program, a))
        except Exception:
            obj = None
        if not isinstance(obj, DemangledFunction):
            continue
        try:
            f = loc.getFunction() or loc.createFunction()
            ns = loc.getParentNameSpace()
            if obj.getNamespace() is not None:
                ns = NamespaceUtils.createNamespaceHierarchy(obj.getNamespace().getNamespaceString().replace(" ", "_"),
                                                            ns, program, SourceType.IMPORTED)
            f.setParentNamespace(ns)
            f.setName(obj.getName(), SourceType.IMPORTED)
            params = []
            for p in obj.getParameters():
                t = p.getType()
                if t.getName() == "void" and not (t.isPointer() or t.isReference()):
                    continue
                if t.getName() == "...":
                    f.setVarArgs(True)
                    continue
                params.append(ParameterImpl(f"p{len(params) + 1}", dtype(t), program))
            cc = "__thiscall" if obj.getCallingConvention() == "__thiscall" else "__fastcall"
            jparams = ArrayList()
            for p in params:
                jparams.add(p)
            f.updateFunction(cc, ReturnParameterImpl(dtype(obj.getReturnType()), program), jparams,
                             Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True, SourceType.IMPORTED)
            # the decompiler types a call through the slot by the slot's own data type
            listing.clearCodeUnits(a, a.add(7), False)
            listing.createData(a, PointerDataType(FunctionDefinitionDataType(f, False)))
            typed += 1
        except Exception as e:  # keep going: one odd name must not stop the run
            failed += 1
            if failed <= 5:
                log(f"  import {name}: {e}")
    log(f"imports: {len(slots)} slots, {cleared} spanning data cleared, {made} references added, {typed} functions "
        f"typed, {failed} failed")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dll")
    ap.add_argument("pattern")
    ap.add_argument("--project", default=r"D:\ATLAS\_re\ghidra-devkit")
    ap.add_argument("--name", default="devkit")
    a = ap.parse_args()
    import re
    import pyghidra
    launcher = pyghidra.HeadlessPyGhidraLauncher()
    launcher.add_vmargs("-Xmx6g")
    launcher.start()
    from ghidra.app.decompiler import DecompInterface
    from ghidra.base.project import GhidraProject
    from ghidra.util.task import ConsoleTaskMonitor
    project = GhidraProject.openProject(a.project, a.name, True)
    try:
        program = project.openProgram("/", Path(a.dll).name, True)
        tx = program.startTransaction("typed imports for this run (not saved)")
        try:
            fm = program.getFunctionManager()
            for sym in program.getSymbolTable().getGlobalSymbols("__chkstk"):
                chk = fm.getFunctionAt(sym.getAddress())
                if chk is not None and chk.getCallFixup() is None:
                    chk.setCallFixup("alloca_probe")
            retype_imports(program, a.dll)
            rx = re.compile(a.pattern)
            iface = DecompInterface()
            iface.openProgram(program)
            for f in fm.getFunctions(True):
                if rx.search(f.getName(True)):
                    res = iface.decompileFunction(f, 180, ConsoleTaskMonitor())
                    print(res.getDecompiledFunction().getC() if res.decompileCompleted() else res.getErrorMessage())
                    break
        finally:
            program.endTransaction(tx, False)
    finally:
        project.close()


if __name__ == "__main__":
    main()
