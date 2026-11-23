"""pdb_decl.py <Class::method | ::global | Class::*> ...: the undecorated declarations of the named functions from the original
server PDB's publics (every overload), for the port's headers. Also 'va:<hex>' prints the public(s) at an address."""
import ctypes
import re
import sys
from ctypes import wintypes

sys.path.insert(0, r"D:\ATLAS\_tools")
from func_match import REPO, Original  # noqa: E402

EXE = r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe"
o = Original(EXE, str(REPO / "_re" / "cache"))
o.symbol_at(0)
dh = o.dbghelp[0].dh
dh.UnDecorateSymbolNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]


def und(dec):
    buf = ctypes.create_unicode_buffer(4096)
    return buf.value if dh.UnDecorateSymbolNameW(dec, buf, 4096, 0) else dec


by_class = {}
globs = {}
for dec in o.by_name:
    m = re.match(r"^\?(\??\w+)@((?:\w+@)+)@", dec)
    if m:
        # the scope as C++ spells it: ?connect@client@cpp_redis@@ -> cpp_redis::client
        scope = "::".join(reversed(m.group(2).rstrip("@").split("@")))
        by_class.setdefault(scope, {}).setdefault(m.group(1), []).append(dec)
        continue
    m = re.match(r"^\?(\w+)@@", dec)
    if m:
        globs.setdefault(m.group(1), []).append(dec)

for arg in sys.argv[1:]:
    if arg.startswith("va:"):
        va = int(arg[3:], 16)
        print(arg, o.symbol_at(va - o.image_base) if hasattr(o, "image_base") else "")
        continue
    cls, _, meth = arg.rpartition("::")
    if cls == "":
        decs = globs.get(meth, [])
    elif meth == "*":
        decs = [d for ds in by_class.get(cls, {}).values() for d in ds]
    else:
        decs = by_class.get(cls, {}).get(meth, [])
    print(f"== {arg}: {len(decs)}")
    for d in sorted(decs):
        rva = o.by_name[d] if isinstance(o.by_name[d], int) else o.by_name[d][0] if isinstance(o.by_name[d], tuple) else o.by_name[d]
        print(f"   {und(d)}")
        print(f"      {d}  @{rva if not isinstance(rva, int) else hex(0x140000000 + rva)}")
