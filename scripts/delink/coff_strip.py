"""Strip a COFF object of ours down to a list of symbols, for the hybrid link (plan P2d, 2026-10-31): every section
that defines none of the kept symbols (and is not associated with one that does) is marked IMAGE_SCN_LNK_REMOVE, loses
its COMDAT flag (the linker wants a symbol for every COMDAT section, LNK1143) and its relocations (the linker resolves
a removed section's references all the same); every external symbol such a section defined becomes an undefined
external when a kept section references it, else an absolute static (the linker reports every undefined external,
referenced or not); an undefined external named in `--alias` is renamed to the name the delinked set defines at the
same address (the original folded identical functions under one name, and our link holds one name per address).
So the linker takes only the kept functions from ours and everything else from the delinked objects. Our judged
units are /bigobj objects (ANON_OBJECT_HEADER_BIGOBJ, 20-byte symbols); the plain COFF form is handled too. The .CRT
initializer sections go with the rest, so a global's dynamic initializer runs once, the original's.

usage: python -I _tools/coff_strip.py <in.obj> <out.obj> --keep <names, one per line> [--alias <name TAB alias>]
                                     [--report]
"""
import argparse
import struct
from pathlib import Path

LNK_REMOVE, LNK_COMDAT, NRELOC_OVFL = 0x00000800, 0x00001000, 0x01000000
SELECT_ASSOCIATIVE = 5
TAB = chr(9)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--keep", required=True)
    ap.add_argument("--alias", help="a file of `name<TAB>alias` lines")
    ap.add_argument("--define", help="a file of `name<TAB>kept function<TAB>offset` lines: a symbol added at that offset "
                    "of the kept function (the delinked set's labels inside a function we provide: the EH tables left "
                    "in the leftover object point into the function's body)")
    ap.add_argument("--retarget", help="a file of `kept function<TAB>relocation offset<TAB>set name` lines: a relocation "
                    "of the kept function that went through a removed section's symbol (a function-local static or a "
                    "literal of ours) repointed at the set's symbol for the original's datum, its addend zeroed")
    ap.add_argument("--report", action="store_true")
    a = ap.parse_args()
    keep = {ln.strip() for ln in Path(a.keep).read_text(encoding="utf-8").splitlines() if ln.strip()}
    aliases = {}
    if a.alias:
        for ln in Path(a.alias).read_text(encoding="utf-8").splitlines():
            if TAB in ln:
                k_, v_ = ln.split(TAB, 1)
                aliases[k_.strip()] = v_.strip()
    d = bytearray(Path(a.src).read_bytes())
    if bytes(d[:4]) == bytes.fromhex("0000ffff"):
        nsec, symoff, nsym = struct.unpack_from("<III", d, 44)
        hdr, symsize, fmt = 56, 20, "<8sIiHBB"
    else:
        nsec, symoff, nsym = struct.unpack_from("<H", d, 2)[0], struct.unpack_from("<I", d, 8)[0], struct.unpack_from("<I", d, 12)[0]
        hdr, symsize, fmt = 20, 18, "<8sIhHBB"
    strtab = symoff + symsize * nsym
    secs = [struct.unpack_from("<8sIIIIIIHHI", d, hdr + 40 * i) for i in range(nsec)]
    syms = []  # (index, name, value, section, class, aux)
    i = 0
    while i < nsym:
        name, value, sect, typ, cls, naux = struct.unpack_from(fmt, d, symoff + symsize * i)
        if name[:4] == bytes(4):
            so = struct.unpack_from("<I", name, 4)[0]
            nm = bytes(d[strtab + so:d.index(bytes(1), strtab + so)]).decode(errors="replace")
        else:
            nm = name.rstrip(bytes(1)).decode(errors="replace")
        syms.append((i, nm, value, sect, cls, naux))
        i += 1 + naux
    # the sections that keep: those defining a kept external symbol, then those associated with a keeping section
    keeping = {sect for _i, nm, _v, sect, cls, _n in syms if cls == 2 and sect > 0 and nm in keep}
    assoc = {}
    for i_, nm, _v, sect, cls, naux in syms:
        if cls == 3 and naux >= 1 and sect > 0 and secs[sect - 1][9] & LNK_COMDAT:
            # the section definition aux record: Number at +12 (2 bytes; the high half at +16 in a bigobj), Selection at +14
            aux = symoff + symsize * (i_ + 1)
            number = struct.unpack_from("<H", d, aux + 12)[0]
            if symsize == 20:
                number |= struct.unpack_from("<H", d, aux + 16)[0] << 16
            if d[aux + 14] == SELECT_ASSOCIATIVE:
                assoc[sect] = number
    changed = True
    while changed:
        changed = False
        for s, parent in assoc.items():
            if parent in keeping and s not in keeping:
                keeping.add(s)
                changed = True
    removed_secs = 0
    for k, s in enumerate(secs, 1):
        name = s[0].rstrip(bytes(1)).decode(errors="replace")
        if (k in keeping and not name.startswith(".debug$")) or name == ".debug$T" or name == ".drectve":
            continue  # every .debug$S goes: a kept function's records name the functions inlined into it (LNK2001 for inlines the original never emitted)
        so = hdr + 40 * (k - 1)
        struct.pack_into("<I", d, so + 36, (s[9] | LNK_REMOVE) & ~LNK_COMDAT & ~NRELOC_OVFL)
        struct.pack_into("<IIHH", d, so + 24, 0, 0, 0, 0)  # no relocations, no line numbers
        # and out of its named group: a removed `.CRT$XCU` of ours still registered the `.CRT` group's attributes
        # ahead of the set's (LNK4078), and the hybrid got a `.CRT` segment the pure link merges into `.rdata`
        d[so:so + 8] = b".removed"
        removed_secs += 1
    referenced = set()  # the symbol indices the kept sections' relocations use (PointerToRelocations, NumberOfRelocations)
    for k in keeping:
        s = secs[k - 1]
        for r in range(s[7]):
            referenced.add(struct.unpack_from("<I", d, s[5] + 10 * r + 4)[0])
    # a referenced weak external (a vector deleting destructor our kept code calls) makes the linker look its default
    # up by name: that default (`??_G`, the aux record's TagIndex) counts as referenced, so it stays an external and
    # takes its alias
    for i_, nm, _v, sect, cls, naux in syms:
        if cls == 105 and i_ in referenced and naux >= 1:
            referenced.add(struct.unpack_from("<I", d, symoff + symsize * (i_ + 1))[0])
    strtab_size = struct.unpack_from("<I", d, strtab)[0]
    if strtab + strtab_size != len(d):
        raise SystemExit("the string table is not at the end of the file: no renaming possible")
    undefined = absolute = renamed = weak = 0
    for i_, nm, _v, sect, cls, naux in syms:
        off = symoff + symsize * i_
        if cls == 105 and i_ not in referenced:
            # a weak external (a vector deleting destructor `??_E` aliasing its `??_G`) that nothing kept refers to:
            # the linker would still resolve its default by name - an absolute static instead, its aux record turned
            # into a static absolute of its own (the indices must not move: relocations hold them)
            struct.pack_into("<h" if symsize == 18 else "<i", d, off + 12, -1)
            d[off + (16 if symsize == 18 else 18)] = 3
            d[off + (17 if symsize == 18 else 19)] = 0
            for k_ in range(naux):
                aux = off + symsize * (k_ + 1)
                d[aux:aux + symsize] = bytes(symsize)
                d[aux:aux + 8] = b"$weakaux"
                struct.pack_into("<h" if symsize == 18 else "<i", d, aux + 12, -1)
                d[aux + (16 if symsize == 18 else 18)] = 3
            weak += 1
            continue
        if cls != 2:
            continue
        if sect == 0 and i_ not in referenced:
            # an undefined external nothing kept refers to: the default of a weak external (a vector deleting destructor's
            # `??_E` aliases `??_G`) that the linker would otherwise resolve - an absolute static instead
            struct.pack_into("<h" if symsize == 18 else "<i", d, off + 12, -1)
            d[off + (16 if symsize == 18 else 18)] = 3
            absolute += 1
            continue
        if sect > 0 and sect not in keeping:
            struct.pack_into("<I", d, off + 8, 0)
            if i_ in referenced:
                struct.pack_into("<h" if symsize == 18 else "<i", d, off + 12, 0)
                undefined += 1
            else:
                struct.pack_into("<h" if symsize == 18 else "<i", d, off + 12, -1)  # IMAGE_SYM_ABSOLUTE
                d[off + (16 if symsize == 18 else 18)] = 3  # StorageClass: IMAGE_SYM_CLASS_STATIC (after the 4-byte section number in a bigobj)
                absolute += 1
        if (sect == 0 or (sect > 0 and sect not in keeping)) and i_ in referenced and nm in aliases:
            new = aliases[nm].encode() + bytes(1)
            struct.pack_into("<II", d, off, 0, len(d) - strtab)
            d += new
            strtab_size += len(new)
            renamed += 1
    struct.pack_into("<I", d, strtab, strtab_size)
    defined_at = {nm: (sect, _v) for _i, nm, _v, sect, cls, _n in syms if cls == 2 and sect > 0 and sect in keeping}
    added = 0
    if a.define:
        # new symbols at the end of the symbol table (the indices in the relocations stay), the string table after them
        strings = bytearray(d[strtab:strtab + strtab_size])
        d = d[:strtab]
        new_syms = bytearray()
        for ln in Path(a.define).read_text(encoding="utf-8").splitlines():
            parts = ln.rstrip().split(TAB)
            if len(parts) != 3 or parts[1] not in defined_at:
                continue
            name, fn, off_ = parts[0], parts[1], int(parts[2], 0)
            sect, base_v = defined_at[fn]
            entry = bytearray(symsize)
            struct.pack_into("<II", entry, 0, 0, len(strings))
            strings += name.encode() + bytes(1)
            struct.pack_into("<I", entry, 8, base_v + off_)
            struct.pack_into("<h" if symsize == 18 else "<i", entry, 12, sect)
            entry[16 if symsize == 18 else 18] = 2  # EXTERNAL
            new_syms += entry
            added += 1
        d += new_syms
        struct.pack_into("<I", strings, 0, len(strings))
        d += strings
        struct.pack_into("<I", d, 52 if symsize == 20 else 12, nsym + added)
    retargeted = 0
    if a.retarget:
        # the symbol table may have grown above: re-read its size, then append one undefined external per new name
        nsym_now = struct.unpack_from("<I", d, 52 if symsize == 20 else 12)[0]
        strtab = symoff + symsize * nsym_now
        strings = bytearray(d[strtab:])
        d = d[:strtab]
        new_syms = bytearray()
        index_of = {}
        for ln in Path(a.retarget).read_text(encoding="utf-8").splitlines():
            parts = ln.rstrip().split(TAB)
            if len(parts) < 3 or parts[0] not in defined_at:
                continue
            fn, rva, name = parts[0], int(parts[1], 0), parts[2]
            sect = defined_at[fn][0]
            s = secs[sect - 1]
            for r in range(s[7]):
                ro = s[5] + 10 * r
                va, si, ty = struct.unpack_from("<IIH", d, ro)
                if va != rva:
                    continue
                if name not in index_of:
                    index_of[name] = nsym_now + len(new_syms) // symsize
                    entry = bytearray(symsize)
                    struct.pack_into("<II", entry, 0, 0, len(strings))
                    strings += name.encode() + bytes(1)
                    entry[16 if symsize == 18 else 18] = 2
                    new_syms += entry
                struct.pack_into("<I", d, ro + 4, index_of[name])
                struct.pack_into("<I", d, s[4] + va, 0)  # the addend: the offset inside our section, now the datum itself
                retargeted += 1
        d += new_syms
        struct.pack_into("<I", strings, 0, len(strings))
        d += strings
        struct.pack_into("<I", d, 52 if symsize == 20 else 12, nsym_now + len(new_syms) // symsize)
    Path(a.dst).write_bytes(bytes(d))
    kept = sum(1 for _i, nm, _v, sect, cls, _n in syms if cls == 2 and sect > 0 and sect in keeping)
    print(f"{Path(a.src).name}: {nsec:,} sections, {len(keeping):,} kept ({removed_secs:,} marked LNK_REMOVE); "
          f"{kept:,} defined externals kept, {undefined:,} now undefined (referenced by kept sections), "
          f"{absolute:,} absolute statics, {weak:,} weak externals neutralized, {renamed:,} renamed, {added:,} labels added, {retargeted:,} static references retargeted; {len(keep):,} names asked -> {a.dst}")
    if a.report:
        missing = keep - {nm for _i, nm, _v, sect, cls, _n in syms if cls == 2 and sect > 0}
        if missing:
            print(f"  {len(missing)} kept names the object does not define: {sorted(missing)[:5]}")


if __name__ == "__main__":
    main()
