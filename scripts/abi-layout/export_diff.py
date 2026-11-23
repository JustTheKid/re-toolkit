"""The exported functions two builds of a module differ in, per class: the DevKit's editor DLL (ATLAS) against ours.
A class exported with *_API exports every member function, so a name only one side has is a function the other
lacks, or one whose signature differs (parameter types, const, access, virtual, static): the decorated name holds
them all. abi_diff.py compares layouts and vtable slots, which a changed signature in the same slot does not alter.

Usage: python -I _tools/export_diff.py <ATLAS dll> <our dll> [--class REGEX] [--both]
  Prints per class the undecorated names only ATLAS has (-) and only ours has (+), pairing overloads by name.
  --both also lists classes whose exports are identical. Reads the PE export tables, no PDB.
2026-10-24, phase 4b step 1.11 (signatures behind the ABI).
"""
import argparse
import ctypes
import re
import struct
import sys
from collections import defaultdict
from ctypes import wintypes
from pathlib import Path


def exports(path):
    """The export names of a PE (the export directory's name table)."""
    data = Path(path).read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    ddir = opt + (112 if magic == 0x20B else 96)
    exp_rva = struct.unpack_from("<I", data, ddir)[0]
    secs = []
    sect = opt + struct.unpack_from("<H", data, pe + 20)[0]
    for i in range(nsec):
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, sect + i * 40 + 8)
        secs.append((va, max(vsize, raw_size), raw_ptr))

    def off(rva):
        for va, size, raw in secs:
            if va <= rva < va + size:
                return rva - va + raw
        raise ValueError(hex(rva))

    e = off(exp_rva)
    n_names, names_rva = struct.unpack_from("<I", data, e + 24)[0], struct.unpack_from("<I", data, e + 32)[0]
    table = off(names_rva)
    out = []
    for i in range(n_names):
        p = off(struct.unpack_from("<I", data, table + 4 * i)[0])
        out.append(data[p:data.index(b"\0", p)].decode("ascii", "replace"))
    return out


DBGHELP = ctypes.WinDLL(r"C:\Windows\System32\dbghelp.dll")
DBGHELP.UnDecorateSymbolName.argtypes = [ctypes.c_char_p, ctypes.c_char_p, wintypes.DWORD, wintypes.DWORD]


def undecorate(name):
    buf = ctypes.create_string_buffer(4096)
    if DBGHELP.UnDecorateSymbolName(name.encode(), buf, 4096, 0):
        text = buf.value.decode("ascii", "replace")
        return re.sub(r"\s+", " ", text.replace("__cdecl ", "").replace(" __ptr64", "").replace("__ptr64", ""))
    return name


def by_class(names):
    """{class: {decorated name}} of member functions (?Method@Class@@...), operators and special members included."""
    out = defaultdict(set)
    for n in names:
        m = re.match(r"^\?(?:\?[0-9A-Z_]|\w+)@(\w+)@@", n)
        if m:
            out[m.group(1)].add(n)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("atlas")
    ap.add_argument("ours")
    ap.add_argument("--class", dest="cls", default=None)
    ap.add_argument("--both", action="store_true")
    a = ap.parse_args()
    theirs, ours = by_class(exports(a.atlas)), by_class(exports(a.ours))
    rx = re.compile(a.cls) if a.cls else None
    same = differ = 0
    for cls in sorted(set(theirs) | set(ours)):
        if rx and not rx.search(cls):
            continue
        t, o = theirs.get(cls, set()), ours.get(cls, set())
        only_t, only_o = sorted(t - o), sorted(o - t)
        if not only_t and not only_o:
            same += 1
            if a.both:
                print(f"== {cls}: identical ({len(t)})")
            continue
        differ += 1
        print(f"== {cls}: {len(only_t)} only ATLAS, {len(only_o)} only ours (of {len(t)} / {len(o)})")
        for n in only_t:
            print(f"  - {undecorate(n)}")
        for n in only_o:
            print(f"  + {undecorate(n)}")
    print(f"{same} classes identical, {differ} differ", file=sys.stderr)


if __name__ == "__main__":
    main()
