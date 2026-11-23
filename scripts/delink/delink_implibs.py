"""Import libraries for the relink (plan P2c, 2026-10-29): the server imports 13 of ATLAS's own DLLs whose import
libraries did not ship; `lib /def` makes them from the DLLs' export tables. A .def is written per DLL
(`dumpbin /exports`: ordinal, name; an export whose RVA lies in a non-code section is marked DATA, else a thunk
would be made for a variable), then VS2013's amd64 `lib.exe` builds <out>/<name>.lib. The Windows Kit, CRT and
DirectX import libraries are installed already (matching-decompilation.md "For P2c").

usage: python -I _tools/delink_implibs.py [--out D:\\ATLAS\\build\\delink\\implibs] [--only NAME ...]
"""
import argparse
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VC = Path(r"C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\bin\amd64")
SERVER = Path(r"D:\ATLASServer")
DLLS = {  # DLL name -> where the server install keeps it
    "PhysX3_x64": SERVER / "Engine/Binaries/ThirdParty/PhysX/PhysX-3.4/Win64/VS2013/PhysX3_x64.dll",
    "PhysX3Common_x64": SERVER / "Engine/Binaries/ThirdParty/PhysX/PhysX-3.4/Win64/VS2013/PhysX3Common_x64.dll",
    "PhysX3Cooking_x64": SERVER / "Engine/Binaries/ThirdParty/PhysX/PhysX-3.4/Win64/VS2013/PhysX3Cooking_x64.dll",
    "PxFoundation_x64": SERVER / "Engine/Binaries/ThirdParty/PhysX/PhysX-3.4/Win64/VS2013/PxFoundation_x64.dll",
    "PxPvdSDK_x64": SERVER / "Engine/Binaries/ThirdParty/PhysX/PhysX-3.4/Win64/VS2013/PxPvdSDK_x64.dll",
    "steam_api64": SERVER / "Engine/Binaries/ThirdParty/Steamworks/Steamv132/Win64/steam_api64.dll",
    "GameNetworkingSockets": SERVER / "ShooterGame/Binaries/Win64/GameNetworkingSockets.dll",
    "AnselSDK64": SERVER / "Engine/Binaries/ThirdParty/Ansel/Win64/AnselSDK64.dll",
    "LIBEAY32": SERVER / "ShooterGame/Binaries/Win64/libeay32.dll",
    "SSLEAY32": SERVER / "ShooterGame/Binaries/Win64/ssleay32.dll",
    "aws-cpp-sdk-core": SERVER / "ShooterGame/Binaries/Win64/aws-cpp-sdk-core.dll",
    "aws-cpp-sdk-s3": SERVER / "ShooterGame/Binaries/Win64/aws-cpp-sdk-s3.dll",
    "libvorbisfile_64": SERVER / "Engine/Binaries/ThirdParty/Vorbis/Win64/VS2013/libvorbisfile_64.dll",
}
EXPORT = re.compile(r"^\s+(\d+)\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]{8})\s+(\S+)")  # ordinal hint RVA name


def code_ranges(dll: Path):
    data = dll.read_bytes()[:4096]
    e = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    opt = struct.unpack_from("<H", data, e + 20)[0]
    out = []
    for i in range(nsec):
        o = e + 24 + opt + 40 * i
        vsize, va = struct.unpack_from("<II", data, o + 8)
        flags = struct.unpack_from("<I", data, o + 36)[0]
        if flags & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            out.append((va, va + vsize))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "build" / "delink" / "implibs"))
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, dll in DLLS.items():
        if a.only and name not in a.only:
            continue
        if not dll.exists():
            print(f"{name}: MISSING {dll}")
            continue
        text = subprocess.run([str(VC / "dumpbin.exe"), "/nologo", "/exports", str(dll)], capture_output=True,
                              text=True, encoding="utf-8", errors="replace").stdout
        code = code_ranges(dll)
        lines, ndata = [], 0
        for line in text.splitlines():
            m = EXPORT.match(line)
            if not m:
                continue
            ordinal, rva, sym = int(m.group(1)), int(m.group(3), 16), m.group(4)
            if sym == "[NONAME]":
                continue
            is_code = any(lo <= rva < hi for lo, hi in code)
            if not is_code:
                ndata += 1
            lines.append(f"    {sym} @{ordinal}" + ("" if is_code else " DATA"))
        if not lines:
            print(f"{name}: no named exports found")
            continue
        deff = out / f"{name}.def"
        deff.write_text(f"LIBRARY {dll.name}\nEXPORTS\n" + "\n".join(lines) + "\n", encoding="utf-8")
        lib = out / f"{name}.lib"
        r = subprocess.run([str(VC / "lib.exe"), "/nologo", f"/def:{deff}", "/machine:x64", f"/out:{lib}"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        ok = r.returncode == 0 and lib.exists()
        print(f"{name}: {len(lines)} exports ({ndata} data) -> {lib.name} {lib.stat().st_size if ok else 0} bytes"
              + ("" if ok else f" FAILED {(r.stdout + r.stderr).strip()[:200]}"))


if __name__ == "__main__":
    main()
