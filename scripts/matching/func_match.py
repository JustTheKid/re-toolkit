"""The byte-matching judge: compare every function of one of our object files with the same function (by decorated
name) in ATLAS's binary. Both were built by the same compiler (VS2013 Update 5) with the same flags
(recompile_unit.py), so a correctly reconstructed function has the same bytes. Relocation sites are not compared as
bytes: there each relocation of our object must reach the same symbol and offset as the original's resolved address
(the original's targets are named through its PDB publics; several names at one address all count, the linker folds
identical functions).

Usage: python -I _tools/func_match.py <our .obj> <original pe> [--names REGEX] [--verbose] [--json <out.json>]
           [--cache <dir>]
  Result per function: MATCH (bytes and relocations agree), MATCH~ (bytes agree, some relocations reach symbols
  without a public name, e.g. this object's static data, and are not checked), MATCH-L (identical but for the source
  location passed to fatal-error, assert or log calls: ATLAS's files have other line numbers wherever ATLAS changed
  them, and its paths another root; each differing immediate must be the Line argument, each differing path string
  the File argument, of the next call, to FError::LowLevelFatal / FMsg::Logf / FDebug::AssertFailed / EnsureFailed,
  shown on the original's code decoded with capstone; counted apart from byte-identical, accepted as matching by
  Q-0017), DIFF (first differing offset shown with
  --verbose), SIZE (lengths differ), MISSING (no public symbol of that name in the original: inlined, static or
  folded away).
The original's publics and section contributions are read with llvm-pdbutil once and cached (--cache, default
_re/cache, git-ignored). A relocation target without a public name (a function-local static such as
`PrivateStaticClass`, a static function) is named through dbghelp (`SymFromAddr`, module symbols) instead: it must
carry our symbol's own name, and a local static must lie in the same module (object) as the original's enclosing
function.
A call or reference whose target names differ but whose code is the same also counts (2026-10-25): when our
target is a function of our object and its name carries a compiler-made lambda name (`<lambda_<hash>>`, never the
same as ATLAS's) or the original's target is folded under several names, the target itself is judged at the
original's address (two levels deep); identical code is interchangeable, as the linker's folding shows.
A relocation to the linker's `__ImageBase` (MSVC addresses a table or global from it, `lea r, [rip + __ImageBase]`
then `[r + rva]`) must reach the original's image base itself, RVA 0, which no PDB public names (2026-10-29, L30).
A delinked object's symbol `<name>@local@<va>` (a target without a public, named from its original address by the
delink trial's naming rule so that no two externals collide) must reach exactly that address, and a function so named
is judged at that address instead of MISSING (2026-10-29, P2).
Lambda instances are paired one to one (2026-11-04, the seventh 4d unit): the relocations of every function judged
at an exactly known address teach which of our lambda hashes is which of the original's (a vtable, functor or
caller named after a lambda at the same offset; a jump to a lambda's body, which dbghelp names), and each of our
functions named after lambdas whose hashes all pair uniquely is judged again at its exact counterpart (a body at
the address its thunk reaches), repeated while new pairs appear; before, the first original of the same shape.
2026-10-24: phase 4d pipeline (docs/decisions/ADR-0006); unnamed targets resolved through dbghelp the same day.
"""
import argparse
import bisect
import json
import pickle
import re
import struct
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pdb_source_md5 import pdbutil  # noqa: E402

REPO = Path(__file__).resolve().parent.parent

# x64 COFF relocation types: (width in bytes, kind)
RELOCS = {1: (8, "addr64"), 2: (4, "addr32"), 3: (4, "addr32nb"), 4: (4, "rel32"), 5: (4, "rel32_1"),
          6: (4, "rel32_2"), 7: (4, "rel32_3"), 8: (4, "rel32_4"), 9: (4, "rel32_5"), 10: (2, "section"),
          11: (4, "secrel")}


class Coff:
    """A COFF object file, plain or /bigobj (ANON_OBJECT_HEADER_BIGOBJ, 32-bit section numbers)."""

    def __init__(self, path):
        self.data = d = Path(path).read_bytes()
        sig1, sig2 = struct.unpack_from("<HH", d, 0)
        if sig1 == 0 and sig2 == 0xFFFF and struct.unpack_from("<H", d, 4)[0] >= 2:
            self.machine = struct.unpack_from("<H", d, 6)[0]
            nsec, self.symptr, self.nsym = struct.unpack_from("<III", d, 44)
            sec_off, self.symsize, self.bigobj = 56, 20, True
        else:
            self.machine, nsec = struct.unpack_from("<HH", d, 0)
            self.symptr, self.nsym = struct.unpack_from("<II", d, 8)
            opt = struct.unpack_from("<H", d, 16)[0]
            sec_off, self.symsize, self.bigobj = 20 + opt, 18, False
        self.strtab = self.symptr + self.nsym * self.symsize
        self.sections = []
        for i in range(nsec):
            o = sec_off + 40 * i
            name = d[o:o + 8].rstrip(b"\0").decode("latin-1")
            size, raw, relptr, _, nrel, _, chars = struct.unpack_from("<IIIIHHI", d, o + 16)
            if chars & 0x01000000 and nrel == 0xFFFF:
                # IMAGE_SCN_LNK_NRELOC_OVFL: more than 65,535 relocations; the real count (that entry included) sits
                # in the first entry's address field (a delinked unity unit, 2026-10-29)
                nrel = struct.unpack_from("<I", d, relptr)[0] - 1
                relptr += 10
            if name.startswith("/"):
                name = self.cstr(self.strtab + int(name[1:]))
            self.sections.append({"name": name, "size": size, "raw": raw, "relptr": relptr, "nrel": nrel,
                                  "chars": chars})
        self.symbols = []
        i = 0
        while i < self.nsym:
            o = self.symptr + i * self.symsize
            raw_name = d[o:o + 8]
            if raw_name[:4] == b"\0\0\0\0":
                name = self.cstr(self.strtab + struct.unpack_from("<I", raw_name, 4)[0])
            else:
                name = raw_name.rstrip(b"\0").decode("latin-1")
            value = struct.unpack_from("<I", d, o + 8)[0]
            if self.bigobj:
                secnum, typ, cls, naux = struct.unpack_from("<iHBB", d, o + 12)
            else:
                secnum, typ, cls, naux = struct.unpack_from("<hHBB", d, o + 12)
            self.symbols.append({"name": name, "value": value, "sec": secnum, "type": typ, "cls": cls})
            for _ in range(naux):
                self.symbols.append(None)
            i += 1 + naux

    def cstr(self, off):
        end = self.data.index(b"\0", off)
        return self.data[off:end].decode("latin-1")

    def relocs(self, sec):
        s = self.sections[sec]
        out = []
        for i in range(s["nrel"]):
            va, sym, typ = struct.unpack_from("<IIH", self.data, s["relptr"] + 10 * i)
            out.append((va, sym, typ))
        return out

    def data_of(self, symi, limit=4096):
        """The bytes of a static data symbol (e.g. a `$SG` string literal): from its offset to the next symbol of
        its section or the section's end, at most limit; None for uninitialised or unknown data."""
        if not hasattr(self, "_sec_offsets"):
            self._sec_offsets = defaultdict(set)
            for s in self.symbols:
                if s and s["sec"] > 0:
                    self._sec_offsets[s["sec"] - 1].add(s["value"])
            self._sec_offsets = {k: sorted(v) for k, v in self._sec_offsets.items()}
        s = self.symbols[symi]
        if not s or s["sec"] <= 0:
            return None
        sec = self.sections[s["sec"] - 1]
        if not sec["raw"] or sec["chars"] & 0x80:  # IMAGE_SCN_CNT_UNINITIALIZED_DATA
            return None
        offs = self._sec_offsets[s["sec"] - 1]
        i = bisect.bisect_right(offs, s["value"])
        end = offs[i] if i < len(offs) else sec["size"]
        end = min(end, s["value"] + limit)
        return self.data[sec["raw"] + s["value"]: sec["raw"] + end]

    def functions(self):
        """(name, section index, offset, size) of every function defined here; with /Gy each function has its
        own COMDAT section, so its size is the section's (or up to the next symbol of the same section)."""
        by_sec = defaultdict(list)
        for s in self.symbols:
            if s and s["sec"] > 0 and (s["type"] >> 4) == 2 and s["cls"] in (2, 3) and not GHIDRA_FUN.match(s["name"]):
                # (a delinked object's FUN_<va>@local@<va> are functions Ghidra's disassembly made at addresses the
                # PDB has no symbol for - orphan code after padding, jump-table targets - not boundaries, 2026-10-29)
                by_sec[s["sec"] - 1].append(s)
        out = []
        for sec, syms in by_sec.items():
            syms.sort(key=lambda s: s["value"])
            size = self.sections[sec]["size"]
            for k, s in enumerate(syms):
                end = syms[k + 1]["value"] if k + 1 < len(syms) else size
                out.append((s["name"], sec, s["value"], end - s["value"]))
        return out


class Original:
    """ATLAS's binary: section table and image base from the PE, publics and section contributions from its PDB."""

    def __init__(self, pe, cache_dir):
        self.pe = Path(pe)
        self.data = self.pe.read_bytes()
        e = struct.unpack_from("<I", self.data, 0x3C)[0]
        nsec = struct.unpack_from("<H", self.data, e + 6)[0]
        opt = struct.unpack_from("<H", self.data, e + 20)[0]
        self.image_base = struct.unpack_from("<Q", self.data, e + 24 + 24)[0]
        self.secs = []
        for i in range(nsec):
            o = e + 24 + opt + 40 * i
            vsize, va, rsize, raw = struct.unpack_from("<IIII", self.data, o + 8)
            self.secs.append((va, vsize, raw, rsize))
        pdb = self.pe.with_suffix(".pdb")
        # the cache named by the PDB's size and time, so that a cache dir shared between exes (minidump_where's
        # default) never answers for another link's PDB (2026-10-31: the pure link's dumps named through the
        # hybrid's symbols)
        st = pdb.stat()
        cache = Path(cache_dir) / f"{self.pe.stem}.{st.st_size:x}-{int(st.st_mtime):x}.pdbsyms2.pkl"
        if cache.exists() and cache.stat().st_mtime > st.st_mtime:
            self.by_name, self.sizes, self.mods = pickle.loads(cache.read_bytes())
        else:
            self.by_name, self.sizes, self.mods = self.load(pdb)
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_bytes(pickle.dumps((self.by_name, self.sizes, self.mods)))
        self.by_rva = defaultdict(list)
        for n, r in self.by_name.items():
            self.by_rva[r].append(n)
        self.rvas = sorted(self.by_rva)
        self.contribs = sorted(self.mods)
        self.dbghelp = None
        self.resolved = {}

    def seg_rva(self, seg, off):
        return self.secs[seg - 1][0] + off

    def load(self, pdb):
        tool = pdbutil()
        pub = subprocess.run([tool, "dump", "-publics", str(pdb)], capture_output=True, text=True,
                             encoding="utf-8", errors="replace").stdout
        by_name = {}
        for m in re.finditer(r"S_PUB32 \[size = \d+\] `(.*)`\n\s+flags = [^,]*, addr = (\d+):(\d+)", pub):
            by_name[m.group(1)] = self.seg_rva(int(m.group(2)), int(m.group(3)))
        sc = subprocess.run([tool, "dump", "-section-contribs", str(pdb)], capture_output=True, text=True,
                            encoding="utf-8", errors="replace").stdout
        sizes, mods = {}, {}
        for m in re.finditer(r"SC\[[^\]]*\]\s+\| mod = (\d+), (\d+):(\d+), size = (\d+)", sc):
            rva = self.seg_rva(int(m.group(2)), int(m.group(3)))
            sizes[rva] = int(m.group(4))
            mods[rva] = (int(m.group(1)), int(m.group(4)))
        return by_name, sizes, mods

    def module_of(self, rva):
        """Index of the module (object file) whose section contribution holds rva, else None."""
        i = bisect.bisect_right(self.contribs, rva) - 1
        if i < 0:
            return None
        start = self.contribs[i]
        mod, size = self.mods[start]
        return mod if rva < start + size else None

    def symbol_at(self, rva):
        """(name, displacement) of the PDB symbol at rva through dbghelp (module symbols too: function-local
        statics, static functions), cached; (None, 0) if there is none."""
        if rva not in self.resolved:
            if self.dbghelp is None:
                import ctypes
                from ctypes import wintypes
                from pdb_struct import Pdb
                from pdb_vtable import name, symbol
                pdb = Pdb(str(self.pe))
                pdb.dh.SymFromAddrW.argtypes = [wintypes.HANDLE, ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint64),
                                                ctypes.c_void_p]
                pdb.dh.UnDecorateSymbolNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
                                                         wintypes.DWORD]
                self.dbghelp = (pdb, ctypes, name, symbol)
            pdb, ctypes, name, symbol = self.dbghelp
            _, sym = symbol()
            disp = ctypes.c_uint64(0)
            ok = pdb.dh.SymFromAddrW(pdb.proc, self.image_base + rva, ctypes.byref(disp), ctypes.addressof(sym))
            self.resolved[rva] = (name(sym), disp.value) if ok else (None, 0)
        return self.resolved[rva]

    def undecorate(self, decorated):
        """Class::Function of a decorated name (dbghelp UnDecorateSymbolName, name only)."""
        self.symbol_at(0)
        pdb, ctypes = self.dbghelp[:2]
        buf = ctypes.create_unicode_buffer(4096)
        n = pdb.dh.UnDecorateSymbolNameW(decorated, buf, 4096, 0x1000)  # UNDNAME_NAME_ONLY
        return buf.value if n else decorated

    def read(self, rva, n):
        for va, vsize, raw, rsize in self.secs:
            if va <= rva < va + max(vsize, rsize):
                o = raw + rva - va
                return self.data[o:o + n]
        return None

    def names_at(self, rva):
        """Exact names at rva, else (nearest public below, offset)."""
        if rva in self.by_rva:
            return self.by_rva[rva], 0
        i = bisect.bisect_right(self.rvas, rva) - 1
        if i < 0:
            return [], 0
        base = self.rvas[i]
        return self.by_rva[base], rva - base


def target_of(orig, site_rva, kind, raw):
    if kind.startswith("rel32"):
        k = 0 if kind == "rel32" else int(kind[-1])
        return site_rva + 4 + k + struct.unpack("<i", raw)[0]
    if kind == "addr64":
        return struct.unpack("<Q", raw)[0] - orig.image_base
    if kind in ("addr32nb", "addr32"):
        v = struct.unpack("<I", raw)[0]
        return v - (orig.image_base & 0xFFFFFFFF) if kind == "addr32" else v
    return None


# A function-local static: ?<name>@?<scope>??<function>@<n>... where MSVC writes the scope number as one digit (1-10)
# or, from 11 on, as A-P letters closed by '@' (?L@ = 11; 2026-10-28, L27c: UGameViewportClient::Draw's ICVar)
LOCAL_STATIC = re.compile(r"^\?([^@?]+)@\?(?:\d+|[A-P]+@)\?(\?.+Z)@\d")
# The guard of a function-local static ($S<n>): MSVC numbers guards through the whole compile unit, so the same
# static's guard has another number in a unity unit with other files around it (2026-10-25, C4: $S24 for
# SupportsMultithreading's static in ours, $S29 in ATLAS's Core unit 1)
GUARD = re.compile(r"^\$S\d+$")


def literal(data):
    """A string literal's bytes up to and including its terminator (UTF-16 when it looks like it), so that the
    alignment padding after it is not compared."""
    if not data:
        return data
    if len(data) >= 4 and data[1] == 0 and data[3] == 0:
        for i in range(0, len(data) - 1, 2):
            if data[i] == 0 and data[i + 1] == 0:
                return data[:i + 2]
        return data
    i = data.find(b"\0")
    return data[:i + 1] if i >= 0 else data


def unnamed_target(orig, ours, base):
    """A relocation target the publics do not name at base: "ok" if dbghelp names a symbol starting exactly there
    that is ours (a local static of the same name, or a static's guard $S<n> of any number, in the module of the
    original's enclosing function; another symbol by its undecorated name), "unchecked" if only the local name could
    be checked, "unknown" if no symbol
    starts there (e.g. the static of a function the original inlined everywhere), else "bad"."""
    if base in orig.by_rva:
        return "bad"  # a public starts there and it is not ours
    found, disp = orig.symbol_at(base)
    if not found or disp:
        return "unknown"
    m = LOCAL_STATIC.match(ours)
    if m:
        if found != m.group(1) and not (GUARD.match(found) and GUARD.match(m.group(1))):
            return "bad"
        func_rva = orig.by_name.get(m.group(2))
        if func_rva is None:
            return "unchecked"
        return "ok" if orig.module_of(func_rva) == orig.module_of(base) is not None else "bad"
    want = orig.undecorate(ours) if ours.startswith("?") else ours
    # (a lambda's operator() carries our hash; the original's, another - compared with the hashes blanked)
    if found == want or ("<lambda_" in want and lambda_key(found) == lambda_key(want)):
        return "ok"
    # a local static's atexit destructor (or initializer) whose name differs only in its scope number ("`4'" against
    # "`5'"): the compiler's block numbering, not the code - "unchecked", so the function is MATCH~ (MapInfo.cpp's
    # BlankInfo was judged so by hand; 2026-11-08, the eleventh unit's CurrentServerKey)
    # (a static inside a lambda's body: its function name carries our lambda hash too, the tenth unit's colorReqMetString)
    if ours.startswith(("??__F", "??__E")) and (SCOPE_NUMBER.sub("`#'", lambda_key(found)) ==
                                                 SCOPE_NUMBER.sub("`#'", lambda_key(want))):
        return "unchecked"
    return "bad"


# a local static's scope in an undecorated name: `UDatabase_TravelData_Redis::DeleteTravelData'::`2'::...
SCOPE_NUMBER = re.compile(r"`\d+'")


# A delinked object's name for a symbol without a public: <name>@local@<original va> (the delink trial, 2026-10-29).
DELINKED_LOCAL = re.compile(r"^(.*)@local@([0-9a-f]+)$")
GHIDRA_FUN = re.compile(r"^FUN_[0-9a-f]+@local@")
# Ghidra's default label on referenced data or code without a name, <prefix>_<va> (LAB_, DAT_, UNWIND_INFO_,
# FuncInfo_, UnwindMapEntry_ARRAY_, ...): exported as externals since P2c (2026-10-30), so that the folded unwind
# data one module defines resolves from the others; the name carries the address like @local@ does.
GHIDRA_DEFAULT = re.compile(r"^[A-Za-z][\w$]*?_(1[0-9a-f]{8})$")
# A dynamic symbol inside a datum (Ghidra's offcut name: the datum's label plus the field path, `G._padding_`,
# `Set.Elements.AllocationFlags._padding_+4`) repeats across offsets, so the patched exporter appends the address
# (`<name>@<va>`, 2026-10-30) to every dynamic name that does not end with it already.
DYNAMIC_SUFFIX = re.compile(r"@(1[0-9a-f]{8})$")


def carried_va(name):
    """The original address a delinked symbol's name carries (@local@, a Ghidra default label, or the exporter's
    @<va> suffix on an offcut dynamic name), else None."""
    m = DELINKED_LOCAL.match(name)
    if m:
        return int(m.group(2), 16)
    m = GHIDRA_DEFAULT.match(name) or DYNAMIC_SUFFIX.search(name)
    return int(m.group(1), 16) if m else None


def image_base(ours, tgt, addend):
    """True when our relocation to the linker's __ImageBase reaches the original's image base, RVA 0, which no public
    names: MSVC's `lea r, [rip + __ImageBase]` before `[r + rva]` (2026-10-29, L30: FSceneTextureShaderParameters::Set's
    GSceneRenderTargets fields)."""
    return ours == "__ImageBase" and tgt - addend == 0


def past_symbol(orig, ours, tgt, addend):
    """True when our relocation ours + addend reaches tgt because a public of our name starts at tgt - addend: a
    pointer past the symbol's start that may lie past its end, where the original's next public starts (a loop's bound
    one past an array, e.g. OCTREE_BUCKET_TYPES' 17 entries and ATLAS's GCurrentWorldSaveVersion after them)."""
    return bool(addend) and ours in orig.by_rva.get(tgt - addend, ())


def settle(state, info, seen):
    """Second pass for relocations no symbol names ("unknown"): one of our symbols must reach the same address as
    wherever else it was verified; if it was never verified it stays unchecked."""
    if state != "PENDING":
        return state, info
    bad = []
    unchecked = info["unchecked"]
    for rel, sym_name, base in info.pop("pending"):
        if sym_name not in seen:
            unchecked += 1
        elif base not in seen[sym_name]:
            bad.append((rel, sym_name, ["(not where it is elsewhere)"], 0, 0))
    if bad:
        return "DIFF", {"rva": info["rva"], "reloc": bad[:3]}
    if info.get("lines"):
        return "MATCH-L", {"rva": info["rva"], "unchecked": unchecked, "lines": info["lines"]}
    return ("MATCH~" if unchecked else "MATCH"), {"rva": info["rva"], "unchecked": unchecked}


# Functions whose File and Line arguments are the caller's __FILE__ / __LINE__ (Q-0017), with the registers that
# carry them: FError::LowLevelFatal(File, Line, ...) and FMsg::Logf(File, Line, ...) in rcx / edx,
# FDebug::AssertFailed / EnsureFailed(Expr, File, Line, ...) in rdx / r8d.
LINE_SINKS = {"?LowLevelFatal@FError@@": ("rcx", "rdx"), "?Logf@FMsg@@": ("rcx", "rdx"),
              "?LogfImpl@FMsg@@": ("rcx", "rdx"), "?AssertFailed@FDebug@@": ("rdx", "r8"),
              "?EnsureFailed@FDebug@@": ("rdx", "r8")}
FAMILY = {"rcx": ("rcx", "ecx", "cx", "cl", "ch"), "rdx": ("rdx", "edx", "dx", "dl", "dh"),
          "r8": ("r8", "r8d", "r8w", "r8b")}
_MD = []


def decode(code):
    """A function's instructions, decoded from its first byte (capstone, with details)."""
    if not _MD:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        _MD.append(md)
    return list(_MD[0].disasm(bytes(code), 0))


def sink_argument(insns, k, family, which, sinks):
    """True when instruction k writes a register of `family` that reaches the next call unchanged and without a
    branch, and that call (a call or tail jump rel32 at a relocation in sinks: offset -> (file family, line family))
    takes its File (which 0) or Line (which 1) argument in that register."""
    import capstone
    for n in insns[k + 1:]:
        if n.bytes[0] in (0xE8, 0xE9) and n.address + 1 in sinks:
            return sinks[n.address + 1][which] == family
        if any(n.group(g) for g in (capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL, capstone.CS_GRP_RET,
                                    capstone.CS_GRP_INT)):
            return False
        if any(n.reg_name(r) in FAMILY[family] for r in n.regs_access()[1]):
            return False
    return False


def instruction_at(insns, i):
    """Index of the instruction that holds byte offset i, else None."""
    k = bisect.bisect_right([n.address for n in insns], i) - 1
    return k if k >= 0 and i < insns[k].address + insns[k].size else None


def source_tail(data):
    """The part of a source path string after its last `\\Source\\` (lower case), or None if it is no source path."""
    s = data.split(b"\0", 1)[0].decode("latin-1").lower().replace("/", "\\")
    i = s.rfind("\\source\\")
    return s[i + 8:] if i >= 0 and s.endswith((".cpp", ".h", ".inl", ".c")) else None


def line_immediates(ours, theirs, diffs, sinks, insns):
    """How many source line numbers explain every differing byte: each must lie in the immediate of a
    `mov edx, imm32` / `mov r8d, imm32` of the original's decoded code (insns) that both sides have, holding a
    plausible line number on both, and be the Line argument of the next call, to one of LINE_SINKS. None if any
    byte is left."""
    starts = set()
    for i in diffs:
        k = instruction_at(insns, i)
        if k is None:
            return None
        n = insns[k]
        op = bytes(n.bytes[:2])
        if op[:1] == b"\xba" and n.size == 5:
            family, imm = "rdx", n.address + 1
        elif op == b"\x41\xb8" and n.size == 6:
            family, imm = "r8", n.address + 2
        else:
            return None
        if not imm <= i < imm + 4 or ours[n.address:imm] != theirs[n.address:imm]:
            return None
        a = struct.unpack_from("<I", ours, imm)[0]
        b = struct.unpack_from("<I", theirs, imm)[0]
        if not (0 < a < 1000000 and 0 < b < 1000000 and sink_argument(insns, k, family, 1, sinks)):
            return None
        starts.add(n.address)
    return len(starts)


def file_argument(insns, rel, sinks):
    """True when the relocation at rel is the displacement of a `lea <reg>, [rip + ...]` whose register is the File
    argument of the next call, to one of LINE_SINKS."""
    k = instruction_at(insns, rel)
    if k is None or insns[k].mnemonic != "lea" or not insns[k].operands:
        return False
    reg = insns[k].reg_name(insns[k].operands[0].reg)
    family = next((f for f, names in FAMILY.items() if reg in names), None)
    return family is not None and sink_argument(insns, k, family, 0, sinks)


_FUNCS = {}


def same_code(obj, orig, ours_name, tgt, depth):
    """True when our function ours_name (defined in obj) judges MATCH / MATCH~ / MATCH-L against the original's code
    at tgt."""
    if depth <= 0:
        return False
    if id(obj) not in _FUNCS:
        _FUNCS[id(obj)] = {f[0]: f[1:] for f in obj.functions()}
    f = _FUNCS[id(obj)].get(ours_name)
    if f is None:
        return False
    state, _ = compare(obj, orig, ours_name, *f, rva_override=tgt, depth=depth - 1)
    return state in ("MATCH", "MATCH~", "MATCH-L")


def compare(obj, orig, name, sec, off, size, seen=None, rva_override=None, depth=2, notes=None):
    """State of one function; seen (our symbol -> original addresses verified for it) is filled for settle().
    rva_override judges it against the original's code there (a target reached under another name). notes, when
    given, collects what the relocations teach about lambdas: "pairs" (our name, the original's name with the
    same shape) and "bodies" (our lambda body, the original's undecorated name, its address)."""
    seen = {} if seen is None else seen
    rva = rva_override if rva_override is not None else orig.by_name.get(name)
    if rva is None and "<lambda_" in name:
        # a function named after a lambda (its vtable's functor, its TFunction caller): the original's copy carries
        # another hash, so it is judged against the original's functions of the same name with the hashes blanked,
        # the first that matches (two lambdas of one signature give two candidates) - 2026-10-31, the Redis unit
        # (only candidates of our size: the original's publics of a folded one-line template - forward<>, _Get -
        # name an address whose code is another function's, and ours would be judged DIFF against it)
        best = None
        for cand in lambda_candidates(orig, name):
            if orig.sizes.get(cand) != size:
                continue
            state, info = compare(obj, orig, name, sec, off, size, seen, rva_override=cand, depth=depth)
            if state in ("MATCH", "MATCH~", "MATCH-L"):
                return state, info
            best = best or (state, info)
        if best is not None:
            return best
    if rva is None:
        va = carried_va(name)
        if va is not None:  # a delinked function without a public (funclet, lambda, static): judged at the address its name carries
            rva = va - orig.image_base
    if rva is None:
        return "MISSING", {}
    osize = orig.sizes.get(rva)
    ours = obj.data[obj.sections[sec]["raw"] + off: obj.sections[sec]["raw"] + off + size]
    if osize is not None and 0 < osize < size and all(b in (0xCC, 0) for b in ours[osize:size]):
        # the delinked objects' ranges are padded to 16 bytes (delink_patch.py part 5, 2026-10-30): a tail of
        # int3 / zero bytes past the original's size is the padding, not the function
        size = osize
        ours = ours[:size]
    theirs = orig.read(rva, size)
    if theirs is None or len(theirs) < size:
        return "SIZE", {"rva": rva}
    mask = bytearray(size)
    unchecked = paths = 0
    bad, pending = [], []
    relocs = [(va, symi, typ) for va, symi, typ in obj.relocs(sec) if off <= va < off + size]
    sinks = {}
    for va, symi, _ in relocs:
        sym_name = obj.symbols[symi]["name"] if obj.symbols[symi] else ""
        regs = next((r for prefix, r in LINE_SINKS.items() if sym_name.startswith(prefix)), None)
        if regs:
            sinks[va - off] = regs
    insns = []  # the original's code, decoded when a difference may be a source location
    for va, symi, typ in relocs:
        width, kind = RELOCS.get(typ, (4, f"type{typ}"))
        rel = va - off
        for b in range(width):
            if rel + b < size:
                mask[rel + b] = 1
        sym = obj.symbols[symi]
        tgt = target_of(orig, rva + rel, kind, theirs[rel:rel + width])
        addend = struct.unpack("<i", ours[rel:rel + 4])[0] if width == 4 else struct.unpack("<q", ours[rel:rel + 8])[0]
        is_section_sym = sym is None or sym["cls"] == 3 and sym["value"] == 0 and sym["name"].startswith(".")
        if tgt is not None and not is_section_sym and sym["cls"] == 3 and sym["name"].startswith("$SG"):
            # a string literal has no name to compare: checked by its content up to its terminator
            ours_data = literal(obj.data_of(symi))
            if ours_data:
                if orig.read(tgt - addend, len(ours_data)) == ours_data:
                    continue
                # Q-0017: the __FILE__ of a fatal-error / assert / log call names the same source file under another
                # root (ours D:\UE\4.5.1\Engine\..., ATLAS's D:\AtlasSVN\Engine\...)
                tail = source_tail(ours_data)
                if tail and sinks and tail == source_tail(orig.read(tgt - addend, 512) or b""):
                    insns = insns or decode(theirs)
                    if file_argument(insns, rel, sinks):
                        paths += 1
                        continue
                bad.append((rel, sym["name"], ["(other data)"], 0, addend))
                continue
        if tgt is not None and not is_section_sym and sym["name"].startswith("??_C@") and sinks:
            # Q-0017 again: a header inline's __FILE__ is a COMDAT literal whose name encodes the path, so it differs
            # under another root; same file after \Source\ and the File argument of a sink, as for $SG literals
            ours_data = literal(obj.data_of(symi))
            if ours_data and orig.read(tgt - addend, len(ours_data)) != ours_data:
                tail = source_tail(ours_data)
                if tail and tail == source_tail(orig.read(tgt - addend, 512) or b""):
                    insns = insns or decode(theirs)
                    if file_argument(insns, rel, sinks):
                        paths += 1
                        continue
        if tgt is None or is_section_sym:
            unchecked += 1
            continue
        va = carried_va(sym["name"])
        if va is not None:
            # the name carries the original address: exact, whatever dbghelp calls it — static labels too (since
            # 2026-10-30 the objects keep every PC-relative site as a relocation, so a jump within the function
            # reaches a static LAB_<va> label; before, such a symbol went unchecked)
            if va - orig.image_base == tgt - addend:
                seen.setdefault(sym["name"], set()).add(tgt - addend)
                continue
            bad.append((rel, sym["name"], orig.names_at(tgt)[0][:3], orig.names_at(tgt)[1], addend))
            continue
        if sym["cls"] == 3 and not sym["name"].startswith("?"):
            unchecked += 1
            continue
        if image_base(sym["name"], tgt, addend):
            continue
        names, delta = orig.names_at(tgt)
        if sym["name"] in names and delta == addend:
            seen.setdefault(sym["name"], set()).add(tgt - addend)
            continue
        if "<lambda_" in sym["name"] and delta == addend and lambda_key(sym["name"]) in {lambda_key(n) for n in names}:
            # the compiler names a lambda by a hash of its source position; the vtables, functors and callers of
            # ours carry another hash than the original's for the same lambda, so names are compared with the
            # hash blanked (the lambda's body is judged on its own, by address) - 2026-10-31, the Redis unit
            if notes is not None:
                same = {n for n in names if lambda_key(n) == lambda_key(sym["name"])}
                if len(same) == 1:
                    notes.setdefault("pairs", []).append((sym["name"], same.pop()))
            seen.setdefault(sym["name"], set()).add(tgt - addend)
            continue
        if past_symbol(orig, sym["name"], tgt, addend):
            seen.setdefault(sym["name"], set()).add(tgt - addend)
            continue
        verdict = unnamed_target(orig, sym["name"], tgt - addend)
        if verdict == "ok":
            if notes is not None and "<lambda_" in sym["name"]:
                found, _disp = orig.symbol_at(tgt - addend)
                notes.setdefault("bodies", []).append((sym["name"], found, tgt - addend))
            seen.setdefault(sym["name"], set()).add(tgt - addend)
            continue
        if verdict == "unchecked":
            unchecked += 1
            continue
        if verdict == "unknown":
            pending.append((rel, sym["name"], tgt - addend))
            continue
        if (delta == addend == 0 and ("<lambda_" in sym["name"] or len(names) > 1)
                and same_code(obj, orig, sym["name"], tgt, depth)):
            continue
        if delta == addend == 0 and sym["name"].startswith("??__F") and same_code(obj, orig, sym["name"], tgt, depth):
            # a local static's atexit destructor that the original's linker folded into an identical one under another
            # name (??__FCurrentServerKey@... reaching ??__FGenericStreamingSystem@...): the same code, so MATCH~ -
            # 2026-11-08, the eleventh unit (the tenth's upgrade lambda had the same gap)
            unchecked += 1
            continue
        bad.append((rel, sym["name"], names[:3], delta, addend))
    diffs = [i for i in range(size) if not mask[i] and ours[i] != theirs[i]]
    lines = 0
    if diffs:
        lines = line_immediates(ours, theirs, diffs, sinks, insns or decode(theirs)) if sinks else None
    if lines is None:
        i = diffs[0]
        return "DIFF", {"rva": rva, "first": i, "ours": ours[i:i + 16].hex(), "theirs": theirs[i:i + 16].hex()}
    if bad:
        return "DIFF", {"rva": rva, "reloc": bad[:3]}
    if osize is not None and osize != size and not DELINKED_LOCAL.match(name):
        # (a delinked funclet's length is the distance to the next funclet; the original's contribution holds
        # several funclets, so its size cannot be compared; the bytes were)
        return "SIZE", {"rva": rva, "ours": size, "theirs": osize}
    if pending:
        return "PENDING", {"rva": rva, "unchecked": unchecked, "pending": pending, "lines": lines + paths}
    if lines or paths:
        return "MATCH-L", {"rva": rva, "unchecked": unchecked, "lines": lines + paths}
    return ("MATCH~" if unchecked else "MATCH"), {"rva": rva, "unchecked": unchecked}


LAMBDA_HASH = re.compile(r"<lambda_[0-9a-f]{32}>")


def lambda_key(name):
    """The decorated name with every compiler lambda hash blanked, for comparing ours with the original's."""
    return LAMBDA_HASH.sub("<lambda_*>", name)


def lambda_candidates(orig, name):
    """The original's rvas of the functions whose decorated name equals ours with the lambda hashes blanked."""
    if not hasattr(orig, "by_lambda_key"):
        d = {}
        for n, r in orig.by_name.items():
            if "<lambda_" in n:
                d.setdefault(lambda_key(n), []).append(r)
        orig.by_lambda_key = d
    return orig.by_lambda_key.get(lambda_key(name), [])


MATCHES = ("MATCH", "MATCH~", "MATCH-L")


def hash_pairs(ours, theirs):
    """The lambda hashes of two names of the same shape, position by position."""
    a, b = LAMBDA_HASH.findall(ours), LAMBDA_HASH.findall(theirs)
    return list(zip(a, b)) if len(a) == len(b) and lambda_key(ours) == lambda_key(theirs) else []


def learn(orig, notes, pairs, bodies):
    """Add what one exactly judged function's relocations taught to pairs (our hash -> the original's hashes) and
    bodies (our lambda body -> the original's addresses)."""
    for ours, theirs in notes.get("pairs", []):
        for a, b in hash_pairs(ours, theirs):
            pairs.setdefault(a, set()).add(b)
    for ours, found, rva in notes.get("bodies", []):
        bodies.setdefault(ours, set()).add(rva)
        want = orig.undecorate(ours) if ours.startswith("?") else ours
        for a, b in hash_pairs(want, found or ""):
            pairs.setdefault(a, set()).add(b)


def unique_pairs(pairs):
    """Our hash -> the original's, where both sides pair with nothing else."""
    one = {a: next(iter(bs)) for a, bs in pairs.items() if len(bs) == 1}
    back = {}
    for a, b in one.items():
        back.setdefault(b, []).append(a)
    return {a: b for a, b in one.items() if len(back[b]) == 1}


def pair_lambdas(obj, orig, funcs, results, notes_of, seen):
    """Judge our lambda instances again at their exact counterparts (see the module docstring); results is the
    list of result dicts, replaced in place. Returns (pairs learned, functions judged by pairing)."""
    pairs, bodies, exact = {}, {}, set()
    for r in results:
        if "<lambda_" not in r["name"] and r["state"] in MATCHES:
            learn(orig, notes_of.get(r["name"], {}), pairs, bodies)
    index = {r["name"]: i for i, r in enumerate(results)}
    for _round in range(6):
        one = unique_pairs(pairs)
        new = 0
        for name, (sec, off, size) in funcs.items():
            if "<lambda_" not in name or name in exact:
                continue
            hs = LAMBDA_HASH.findall(name)
            if not all(h in one for h in hs):
                continue
            rva = orig.by_name.get(LAMBDA_HASH.sub(lambda m: one[m.group(0)], name))
            if rva is None and len(bodies.get(name, ())) == 1:
                rva = next(iter(bodies[name]))
            if rva is None:
                continue
            notes = {}
            state, info = settle(*compare(obj, orig, name, sec, off, size, seen, rva_override=rva, notes=notes), seen)
            info = {**info, "rva": rva, "paired": 1}
            results[index[name]] = {"name": name, "size": size, "state": state, **info}
            exact.add(name)
            new += 1
            if state in MATCHES:
                learn(orig, notes, pairs, bodies)
        if not new:
            break
    return len(unique_pairs(pairs)), len(exact)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("obj")
    ap.add_argument("original")
    ap.add_argument("--names")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--json")
    ap.add_argument("--cache", default=str(REPO / "_re" / "cache"))
    a = ap.parse_args()
    obj = Coff(a.obj)
    orig = Original(a.original, a.cache)
    pat = re.compile(a.names) if a.names else None
    first, seen, notes_of, funcs = [], {}, {}, {}
    for name, sec, off, size in sorted(obj.functions()):
        if pat and not pat.search(name):
            continue
        funcs[name] = (sec, off, size)
        notes_of[name] = {}
        first.append((name, size) + compare(obj, orig, name, sec, off, size, seen, notes=notes_of[name]))
    results = []
    for name, size, state, info in first:
        state, info = settle(state, info, seen)
        results.append({"name": name, "size": size, "state": state, **info})
    n_pairs, n_paired = pair_lambdas(obj, orig, funcs, results, notes_of, seen)
    counts = Counter(r["state"] for r in results)
    if a.verbose:
        for r in results:
            if r["state"] not in ("MATCH", "MATCH~"):
                info = {k: v for k, v in r.items() if k not in ("name", "size", "state")}
                print(f"{r['state']:7s} {r['name']} {json.dumps(info)[:300]}")
    total = sum(counts.values())
    found = total - counts["MISSING"]
    exact = counts["MATCH"] + counts["MATCH~"]
    print(f"{Path(a.obj).name}: {total} functions; in the original {found}; byte-identical {exact} "
          f"({100 * exact / max(found, 1):.1f}% of those found); line numbers only {counts['MATCH-L']}; "
          f"lambda hashes paired {n_pairs}, functions judged by pairing {n_paired}")
    for k in ("MATCH", "MATCH~", "MATCH-L", "DIFF", "SIZE", "MISSING"):
        print(f"  {k:8s} {counts[k]}")
    if a.json:
        Path(a.json).write_text(json.dumps(results, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
