"""List the callers of functions in a PE with its PDB, from the code bytes: every direct `call rel32` (E8) or
`jmp rel32` (E9, tail call) whose target is one of the given functions, mapped to the function that contains it.

For DLLs imported into Ghidra with the PDB only (the DevKit's editor DLLs, ghidra_analyze.py --pdb-only) Ghidra has
no references, so "who creates this menu action" cannot be asked there. Byte scanning finds direct calls only (not
calls through vtables or function pointers) and may report a few false hits inside data; check each in a decompile.

Usage: python -I _tools/pe_callers.py <dll> <pattern | hex VA> [...] [--data]
  pattern  dbghelp wildcard as for pdb_lookup.py, e.g. "FEdGraphSchemaAction_K2AddConsoleVariableEvent::FEdGraph*"
  VA       hex, in pdb_lookup.py's numbering (image base 0x140000000)
  --data   also RIP-relative `lea` / `mov` of the targets, and patterns match global data too: references to a
           class's vtable, PrivateStaticClass or GetPrivateStaticClass find where an inlined constructor or
           StaticClass() uses it (step 1.9d: FK2ActionMenuBuilder::GetEventsForBlueprint for the console events)
Output: target, then per call site the caller's VA in pdb_lookup's numbering, the same in Ghidra's (the PE's own
image base, e.g. 0x180000000 for DLLs), and the caller's name. Step 1.9d, 2026-10-23.
"""
import bisect
import re
import struct
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
LOOKUP_BASE = 0x140000000


def functions(dll, pattern, data=False):
    out = subprocess.run([sys.executable, "-I", str(TOOLS / "pdb_lookup.py"), str(dll), pattern]
                         + (["--data"] if data else []),
                         capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    rows = []
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) >= 3 and re.fullmatch(r"[0-9a-f]+", f[0]):
            rows.append((int(f[0], 16), int(f[1], 16), f[2]))
    return rows


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    dll = Path(sys.argv[1])
    data = dll.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    image_base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]
    count = struct.unpack_from("<H", data, pe + 6)[0]
    table = pe + 24 + struct.unpack_from("<H", data, pe + 20)[0]
    code = []
    for i in range(count):
        name, vsize, va, rsize, raw, = struct.unpack_from("<8sIIII", data, table + 40 * i)
        flags = struct.unpack_from("<I", data, table + 40 * i + 36)[0]
        if flags & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            code.append((va, raw, min(vsize, rsize)))

    data_mode = "--data" in sys.argv
    targets = {}
    for arg in (a for a in sys.argv[2:] if a != "--data"):
        if re.fullmatch(r"(0x)?[0-9a-fA-F]{6,}", arg):
            targets[int(arg, 16) - LOOKUP_BASE] = arg
        else:
            for va, _size, name in functions(dll, arg, data_mode):
                targets[va - LOOKUP_BASE] = name
    if not targets:
        sys.exit("no target function found")

    every = sorted(functions(dll, "*"))
    starts = [va - LOOKUP_BASE for va, _s, _n in every]

    def owner(rva):
        i = bisect.bisect_right(starts, rva) - 1
        if i >= 0 and rva < starts[i] + max(every[i][1], 1):
            return every[i][2], starts[i]
        return "?", None

    hits = {t: [] for t in targets}
    for va, raw, size in code:
        block = data[raw:raw + size]
        for m in re.finditer(rb"[\xe8\xe9]", block):
            at = m.start()
            if at + 5 > len(block):
                break
            dest = va + at + 5 + struct.unpack_from("<i", block, at + 1)[0]
            if dest in hits:
                hits[dest].append(va + at)
        if data_mode:
            # lea / mov r64, [rip+disp32]: REX.W (48 / 4c) 8d / 8b, ModRM mod=00 rm=101
            for m in re.finditer(rb"[\x48\x4c][\x8d\x8b][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", block, re.S):
                at = m.start()
                if at + 7 > len(block):
                    break
                dest = va + at + 7 + struct.unpack_from("<i", block, at + 3)[0]
                if dest in hits:
                    hits[dest].append(va + at)
    for t, sites in sorted(hits.items()):
        print(f"== {targets[t]}  ({LOOKUP_BASE + t:x} / ghidra {image_base + t:x}): {len(sites)} reference(s)")
        for site in sites:
            name, start = owner(site)
            where = f"{LOOKUP_BASE + start:x} / ghidra {image_base + start:x}" if start is not None else "?"
            print(f"   {where}  {name}  (+{site - start:#x})" if start is not None else f"   {site:x}  ?")


if __name__ == "__main__":
    main()
