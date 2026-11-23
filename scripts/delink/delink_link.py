"""The relink (plan P2c, 2026-10-30): VS2013's link.exe over the delinked objects of ShooterGameServer.exe.

The PDB holds no link command line, so the line is UnrealBuildTool 4.5's for a monolithic Shipping target
(VCToolChain.cs: /MANIFEST:NO /NOLOGO /DEBUG /MACHINE:x64 /FIXED:No /LARGEADDRESSAWARE /NXCOMPAT /STACK:5000000
/RELEASE /OPT:REF /OPT:ICF /INCREMENTAL:NO /ignore:4199 /ignore:4099, the delay-loads) with what the PE header says:
/SUBSYSTEM:WINDOWS (2; the entry public is WinMainCRTStartup), the 16 delay-loaded DLLs from the delay-import
directory, the 44 exports (a .def from the export directory: NvOptimusEnablement is DATA), the import libraries from
the 32 import DLLs (Windows Kits 8.1, the VS2013 CRT's msvcrt / msvcprt, the DirectX pair from UE 4.5.1's ThirdParty,
the game DLLs' from `delink_implibs.py`, PxPvdSDK_x64's from its one `__imp_` public in the PDB). The objects go in
PDB module order (the linker records modules in input order); no /LTCG (the 17 LTCG objects are delinked as native
code); /NODEFAULTLIB, since the delinked objects carry no .drectve. The original's resources are a module of the
PDB (ShooterGame.rc.res.obj), delinked with the rest; a .res made from the PE's resource tree is kept for a set
without it (the linker takes one resource file only). Never the same: the Authenticode signature, the PDB path and
GUID, the timestamps.
After the link, the sections side by side with the original's (--compare does that alone).

usage: python -I _tools/delink_link.py [--objs build/delink/server-p2c] [--out build/delink/link] [--dry-run] [--no-res] [--compare]
"""
import argparse
import pickle
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
VCVARS = r"C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat"
VC = Path(r"C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\amd64")
PE = Path(r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe")
PUBLICS = ROOT / "_re" / "cache" / "ShooterGameServer.pdbsyms2.pkl"
IMPLIBS = ROOT / "build" / "delink" / "implibs"
DIRECTX = Path(r"D:\UE\4.5.1\Engine\Source\ThirdParty\Windows\DirectX\Lib\x64")

# import DLL -> import library (Windows Kits 8.1 um\x64 and VC\lib\amd64 are on vcvarsall's LIB; the rest by path)
SYSTEM_LIBS = {
    "WININET.dll": "wininet.lib", "WS2_32.dll": "ws2_32.lib", "dbghelp.dll": "dbghelp.lib", "WINMM.dll": "winmm.lib",
    "KERNEL32.dll": "kernel32.lib", "USER32.dll": "user32.lib", "GDI32.dll": "gdi32.lib", "ADVAPI32.dll": "advapi32.lib",
    "SHELL32.dll": "shell32.lib", "ole32.dll": "ole32.lib", "OLEAUT32.dll": "oleaut32.lib", "IPHLPAPI.DLL": "iphlpapi.lib",
    "SETUPAPI.dll": "setupapi.lib", "dwmapi.dll": "dwmapi.lib", "bcrypt.dll": "bcrypt.lib", "WLDAP32.dll": "wldap32.lib",
    "Normaliz.dll": "normaliz.lib", "dxgi.dll": "dxgi.lib", "d3d9.dll": "d3d9.lib", "d3d11.dll": "d3d11.lib",
    "X3DAudio1_7.dll": "X3DAudio.lib", "XAPOFX1_5.dll": "XAPOFX.lib", "OPENGL32.dll": "opengl32.lib",
    "DSOUND.dll": "dsound.lib", "MSVCP120.dll": "msvcprt.lib", "MSVCR120.dll": "msvcrt.lib", "wer.dll": "wer.lib",
    "VERSION.dll": "version.lib", "PSAPI.DLL": "psapi.lib", "POWRPROF.dll": "powrprof.lib", "CRYPT32.dll": "crypt32.lib",
    "mscoree.dll": "mscoree.lib", "SHLWAPI.dll": "shlwapi.lib", "MF.dll": "mf.lib", "MFPlat.DLL": "mfplat.lib",
}


class Pe:
    def __init__(self, path):
        self.d = d = path.read_bytes()
        e = struct.unpack_from("<I", d, 0x3C)[0]
        nsec, optsz = struct.unpack_from("<H", d, e + 6)[0], struct.unpack_from("<H", d, e + 20)[0]
        o = e + 24
        self.entry = struct.unpack_from("<I", d, o + 16)[0]
        self.subsystem = struct.unpack_from("<H", d, o + 68)[0]
        self.stack_reserve = struct.unpack_from("<Q", d, o + 72)[0]
        ndirs = struct.unpack_from("<I", d, o + 108)[0]
        self.dirs = [struct.unpack_from("<II", d, o + 112 + 8 * i) for i in range(ndirs)]
        self.secs = []
        for i in range(nsec):
            so = e + 24 + optsz + 40 * i
            name = d[so:so + 8].rstrip(b"\0").decode()
            vs, va, rs, rp = struct.unpack_from("<IIII", d, so + 8)
            self.secs.append((name, va, max(vs, rs), rp))

    def off(self, rva):
        for _n, va, sz, rp in self.secs:
            if va <= rva < va + sz:
                return rp + rva - va
        raise ValueError(f"rva {rva:#x} in no section")

    def sec(self, rva):
        return next(n for n, va, sz, _rp in self.secs if va <= rva < va + sz)

    def cstr(self, rva):
        q = self.off(rva)
        return self.d[q:self.d.index(b"\0", q)].decode()

    def imports(self):
        p = self.off(self.dirs[1][0])
        out = []
        while True:
            ilt, _ts, _fwd, name_rva, iat = struct.unpack_from("<IIIII", self.d, p)
            if not name_rva:
                return out
            out.append(self.cstr(name_rva))
            p += 20

    def delay_imports(self):
        p = self.off(self.dirs[13][0])
        out = []
        while True:
            _attrs, name_rva = struct.unpack_from("<II", self.d, p)
            if not name_rva:
                return out
            out.append(self.cstr(name_rva))
            p += 32

    def exports(self):
        """[(name, ordinal, rva)] from the export directory."""
        p = self.off(self.dirs[0][0])
        _f, _ts, _mj, _mn, _name, base, nfunc, nnames, aof, aon, aoo = struct.unpack_from("<IIHHIIIIIII", self.d, p)
        funcs = [struct.unpack_from("<I", self.d, self.off(aof) + 4 * i)[0] for i in range(nfunc)]
        out = []
        for i in range(nnames):
            name = self.cstr(struct.unpack_from("<I", self.d, self.off(aon) + 4 * i)[0])
            oi = struct.unpack_from("<H", self.d, self.off(aoo) + 2 * i)[0]
            out.append((name, oi + base, funcs[oi]))
        return out


def rsrc_to_res(pe, path):
    """The PE's resource tree as a .res file (RESOURCEHEADER per leaf: type, name, language; the data), for the
    linker to rebuild the .rsrc section; the resource directory's attributes are the linker's own."""
    rva, _size = pe.dirs[2]
    if not rva:
        return 0
    d, base = pe.d, pe.off(rva)
    out = bytearray(struct.pack("<IIHHHHIHHII", 0, 32, 0xFFFF, 0, 0xFFFF, 0, 0, 0, 0, 0, 0))

    def field(v):
        if v & 0x80000000:  # a name: IMAGE_RESOURCE_DIR_STRING_U, as a null-terminated UTF-16 string
            o = base + (v & 0x7FFFFFFF)
            n = struct.unpack_from("<H", d, o)[0]
            return d[o + 2:o + 2 + 2 * n] + b"\0\0"
        return struct.pack("<HH", 0xFFFF, v & 0xFFFF)

    def leaves(off, trail):
        _c, _ts, _mj, _mn, nnamed, nid = struct.unpack_from("<IIHHHH", d, base + off)
        for i in range(nnamed + nid):
            key, data = struct.unpack_from("<II", d, base + off + 16 + 8 * i)
            if data & 0x80000000:
                yield from leaves(data & 0x7FFFFFFF, trail + [key])
            else:
                yield trail + [key], data

    count = 0
    for (typ, name, lang), entry in leaves(0, []):
        drva, dsize, _cp, _r = struct.unpack_from("<IIII", d, base + entry)
        data = d[pe.off(drva):pe.off(drva) + dsize]
        hdr = bytearray(field(typ) + field(name))
        if len(hdr) % 4:
            hdr += b"\0\0"
        hdr += struct.pack("<IHHII", 0, 0x1030, lang & 0xFFFF, 0, 0)  # DataVersion, MemoryFlags, LanguageId, Version, Characteristics
        out += struct.pack("<II", dsize, 8 + len(hdr)) + hdr + data
        while len(out) % 4:
            out += b"\0"
        count += 1
    path.write_bytes(out)
    return count


def compare(ours, theirs):
    """The sections of the two PEs side by side, and how much of each section's bytes agree."""
    a, b = Pe(ours), Pe(theirs)
    print(f"{'section':8s} {'ours vsize':>12s} {'theirs':>12s} {'ours raw':>12s} {'theirs':>12s}  same bytes (of the shorter)")
    for name, va, sz, rp in a.secs:
        other = next(((n, v, s, r) for n, v, s, r in b.secs if n == name), None)
        if other is None:
            print(f"{name:8s} {sz:12,} {'-':>12s}")
            continue
        n = min(sz, other[2])
        x, y = a.d[rp:rp + n], b.d[other[3]:other[3] + n]
        same = sum(1 for i in range(0, n, 4096) if x[i:i + 4096] == y[i:i + 4096]) * 4096 if n > 1 << 20 else sum(1 for i in range(n) if x[i] == y[i])
        print(f"{name:8s} {sz:12,} {other[2]:12,} {a.secs[[s[0] for s in a.secs].index(name)][2]:12,} {other[2]:12,}  "
              f"{100 * min(same, n) / max(n, 1):5.1f}%{' (4 KB pages)' if n > 1 << 20 else ''}")
    for n, _va, _sz, _rp in b.secs:
        if n not in [s[0] for s in a.secs]:
            print(f"{n:8s} {'-':>12s} {_sz:12,}  (theirs only)")


def sort_pdata(path):
    """The exception directory of a linked PE sorted by BeginAddress, in place, and the PE checksum recomputed:
    Windows binary-searches .pdata on every exception dispatch and every unwind, and the linker sorted the
    original's entries because they came as per-function COMDATs, while the delinked objects' .pdata are plain
    sections that it merely concatenates (2026-10-30, the eighth boot: unsorted, 155,525 entries). Returns the
    number of entries that were out of order."""
    d = bytearray(Path(path).read_bytes())
    pe = Pe(Path(path))
    rva, size = pe.dirs[3]
    if not rva:
        return 0
    p, n = pe.off(rva), size // 12
    entries = [struct.unpack_from("<III", d, p + 12 * i) for i in range(n)]
    out_of_order = sum(1 for i in range(n - 1) if entries[i][0] > entries[i + 1][0])
    if out_of_order:
        entries.sort()
        for i, e in enumerate(entries):
            struct.pack_into("<III", d, p + 12 * i, *e)
    # the checksum (IMAGE_NT_HEADERS.OptionalHeader.CheckSum): the word sum over the file with the field zeroed
    e = struct.unpack_from("<I", d, 0x3C)[0]
    cs_off = e + 24 + 64
    struct.pack_into("<I", d, cs_off, 0)
    total = 0
    for i in range(0, len(d) - 1, 2):
        total += struct.unpack_from("<H", d, i)[0]
        total = (total & 0xFFFF) + (total >> 16)
    if len(d) % 2:
        total += d[-1]
        total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    struct.pack_into("<I", d, cs_off, (total & 0xFFFF) + len(d))
    Path(path).write_bytes(d)
    return out_of_order


def pvd_implib(out_dir):
    """PxPvdSDK_x64.lib from the PDB's __imp_ publics (the DLL did not ship with the server; one export is used)."""
    lib = out_dir / "PxPvdSDK_x64.lib"
    if lib.exists():
        return lib
    by_name, _sizes, _mods = pickle.loads(PUBLICS.read_bytes())
    # (`__imp_load_<name>` is the delay-load thunk's own name, not an import)
    names = sorted(n[len("__imp_"):] for n in by_name
                   if n.startswith("__imp_") and not n.startswith("__imp_load_") and "Pvd" in n)
    deff = out_dir / "PxPvdSDK_x64.def"
    deff.write_text("LIBRARY PxPvdSDK_x64.dll\nEXPORTS\n" + "".join(f"    {n}\n" for n in names), encoding="utf-8")
    r = subprocess.run([str(VC / "lib.exe"), "/nologo", f"/def:{deff}", "/machine:x64", f"/out:{lib}"],
                       capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        sys.exit("lib /def failed: " + r.stdout + r.stderr)
    print(f"built {lib.name} with {len(names)} exports")
    return lib


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--objs", default=str(ROOT / "build" / "delink" / "server-p2c"))
    ap.add_argument("--out", default=str(ROOT / "build" / "delink" / "link"))
    ap.add_argument("--dry-run", action="store_true", help="write the response file and stop")
    ap.add_argument("--no-res", action="store_true", help="link without the original's resources")
    ap.add_argument("--compare", action="store_true", help="only compare the linked PE's sections with the original's")
    ap.add_argument("--sort-pdata", action="store_true", help="only sort the linked PE's exception directory in place")
    ap.add_argument("--no-aslr", action="store_true", help="/DYNAMICBASE:NO: the image at its preferred base (a test "
                    "for pointers without a base relocation)")
    ap.add_argument("--extra", nargs="*", default=[], help="P2d: our own objects, linked before the set (stripped by "
                    "coff_strip.py to the functions they provide; the set exported without those)")
    a = ap.parse_args()
    objs, out = Path(a.objs), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    pe = Pe(PE)
    if a.compare:
        compare(out / "ShooterGameServer.exe", PE)
        return
    if a.sort_pdata:
        print(f".pdata entries out of order before the sort: {sort_pdata(out / 'ShooterGameServer.exe'):,}")
        return
    res = out / "ShooterGameServer.res"
    rows = [l.split("\t") for l in (objs / "manifest.tsv").read_text(encoding="utf-8").splitlines()[1:]]
    if any(r[3].endswith(".res.obj") for r in rows):
        # the original's compiled resources are a module of the PDB (ShooterGame.rc.res.obj), delinked with the
        # rest; the linker refuses a second resource file (LNK1241)
        a.no_res = True
    if not a.no_res:
        print(f"{rsrc_to_res(pe, res)} resources -> {res.name}")
    # the objects in module order (the manifest's modi)
    rows = [r for r in rows if r[8].startswith("ok")]
    rows.sort(key=lambda r: int(r[0]))
    objects = [objs / r[3] for r in rows]
    # the exports
    deff = out / "exports.def"
    lines = ["LIBRARY ShooterGameServer.exe", "EXPORTS"]
    for name, ordinal, rva in pe.exports():
        lines.append(f"    {name} @{ordinal}" + ("" if pe.sec(rva).startswith(".text") else " DATA"))
    deff.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # the libraries
    imports, delays = pe.imports(), pe.delay_imports()
    libs = []
    for dll in imports + delays:
        if dll in SYSTEM_LIBS:
            libs.append(SYSTEM_LIBS[dll])
        elif (IMPLIBS / (Path(dll).stem + ".lib")).exists():
            libs.append(Path(dll).stem + ".lib")
        elif dll == "PxPvdSDK_x64.dll":
            libs.append(pvd_implib(IMPLIBS).name)
        else:
            sys.exit(f"no import library for {dll}")
    libs += ["delayimp.lib", "oldnames.lib"]
    exe, pdb, mapf = out / "ShooterGameServer.exe", out / "ShooterGameServer.pdb", out / "ShooterGameServer.map"
    subsystem = {2: "WINDOWS", 3: "CONSOLE"}[pe.subsystem]
    # no /ENTRY: the linker takes WinMainCRTStartup for the WINDOWS subsystem when WinMain is defined, and an explicit
    # entry makes it warn per object with a .CRT section (LNK4210, 587 times) that initializers may not run
    # /MERGE: the CRT's objects carry `/merge:.CRT=.rdata` and `/merge:.rtc=.rdata` directives (sect_attribs.h);
    # the delinked ones carry no directives, and the first successful link (2026-10-30) had a .CRT and a .rtc section
    switches = ["/NOLOGO", "/MANIFEST:NO", "/DEBUG", "/MACHINE:x64", f"/SUBSYSTEM:{subsystem}",
                "/MERGE:.CRT=.rdata", "/MERGE:.rtc=.rdata", "/FIXED:No", "/LARGEADDRESSAWARE", "/NXCOMPAT", f"/STACK:{pe.stack_reserve}", "/RELEASE", "/OPT:REF",
                "/OPT:ICF", "/INCREMENTAL:NO", "/ignore:4199", "/ignore:4099", "/NODEFAULTLIB",
                f'/DEF:"{deff}"', f'/OUT:"{exe}"', f'/PDB:"{pdb}"', f'/MAP:"{mapf}"',
                f'/LIBPATH:"{IMPLIBS}"', f'/LIBPATH:"{DIRECTX}"']
    switches += [f'/DELAYLOAD:"{dll}"' for dll in delays]
    if a.no_aslr:
        switches.append("/DYNAMICBASE:NO")
    rsp = out / "link.rsp"
    inputs = [f'"{Path(o).resolve()}"' for o in a.extra] + [f'"{o}"' for o in objects] + ([f'"{res}"'] if not a.no_res else [])
    rsp.write_text("\n".join(switches + inputs + libs) + "\n", encoding="utf-8")
    print(f"{len(objects)} objects{' + ' + str(len(a.extra)) + ' of ours' if a.extra else ''}, {len(libs)} libraries, {len(delays)} delay-loads, {len(lines) - 2} exports -> {rsp}")
    if a.dry_run:
        return
    t0 = time.time()
    cmd = f'"{VCVARS}" amd64 >nul && link @"{rsp}"'
    r = subprocess.run(f'cmd /s /c "{cmd}"', cwd=out, capture_output=True, text=True, errors="replace")
    log = out / "link.log"
    log.write_text(r.stdout + r.stderr, encoding="utf-8")
    text = r.stdout + r.stderr
    kinds = {}
    for l in text.splitlines():
        m = re.search(r"(LNK\d{4})", l)
        if m:
            kinds.setdefault(m.group(1), []).append(l)
    print(f"link exit {r.returncode} in {time.time() - t0:.0f} s; log {log}")
    for k, ls in sorted(kinds.items(), key=lambda kv: -len(kv[1])):
        print(f"  {k}: {len(ls)}  e.g. {ls[0][:200]}")
    if exe.exists():
        print(f"  {exe.name}: {exe.stat().st_size:,} bytes (the original {PE.stat().st_size:,}); .pdata entries out of "
              f"order before the sort: {sort_pdata(exe):,}")
        compare(exe, PE)


if __name__ == "__main__":
    main()
