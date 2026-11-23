"""Print the DLLs a PE imports (import and delay-load directories), the linker version and, with --strings, the
printable strings that match a regex (e.g. the build paths in a third-party DLL).

Shows which third-party SDK a binary was built against without a debugger: ATLAS's server, client and DevKit
delay-load PhysX 3.4's `PxFoundation_x64.dll` / `PxPvdSDK_x64.dll`, which PhysX 3.3 (UE 4.5) does not have.

Usage: python -I _tools/pe_imports.py <pe> [<pe> ...] [--filter REGEX] [--strings REGEX]
  --filter   only the DLL names matching REGEX (case-insensitive), e.g. "physx|apex|pxfoundation|pxpvd"
  --strings  also print the file's printable strings (8+ chars) matching REGEX, first 20
Step 1.9e, 2026-10-23.
"""
import argparse
import re
import struct


def sections(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    table = pe + 24 + opt_size
    for i in range(count):
        vsize, va, rsize, raw = struct.unpack_from("<IIII", data, table + 40 * i + 8)
        yield va, max(vsize, rsize), raw


def offset(secs, rva):
    for va, size, raw in secs:
        if va <= rva < va + size:
            return rva - va + raw
    return None


def cstr(data, off):
    return data[off:data.index(b"\0", off)].decode("ascii", "replace")


def imports(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe + 24
    dirs = opt + (112 if struct.unpack_from("<H", data, opt)[0] == 0x20B else 96)
    secs = list(sections(data))
    names = []
    # (directory index, descriptor size, offset of the name RVA in a descriptor, label)
    for index, size, name_at, label in ((1, 20, 12, ""), (13, 32, 4, " (delay)")):
        rva = struct.unpack_from("<I", data, dirs + 8 * index)[0]
        off = offset(secs, rva) if rva else None
        while off is not None:
            name_rva = struct.unpack_from("<I", data, off + name_at)[0]
            if not name_rva:
                break
            names.append(cstr(data, offset(secs, name_rva)) + label)
            off += size
    return f"{data[opt + 2]}.{data[opt + 3]:02d}", names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pe", nargs="+")
    ap.add_argument("--filter")
    ap.add_argument("--strings")
    args = ap.parse_args()
    for path in args.pe:
        data = open(path, "rb").read()
        linker, names = imports(data)
        if args.filter:
            names = [n for n in names if re.search(args.filter, n, re.I)]
        print(f"{path}: linker {linker}")
        print("  imports: " + (", ".join(names) or "-"))
        if args.strings:
            found = sorted({m.group().decode() for m in re.finditer(rb"[ -~]{8,}", data)
                            if re.search(args.strings, m.group().decode(), re.I)})
            for s in found[:20]:
                print("  string: " + s)
            if len(found) > 20:
                print(f"  ... {len(found) - 20} more strings")


if __name__ == "__main__":
    main()
