"""The whole-binary delink (plan P2b, 2026-10-29): every compile unit of ATLAS's server back to a COFF object with
ghidra-delinker 0.9.2, on a copy of the Ghidra project that keeps the preparation, each object judged by func_match.py.

Stages, each resumable (the state file beside the project copy records what is done):

  prepare   One-time, on a copy of the server project (made if missing, 2.2 GB):
            1. the memory blocks split at the COFF groups' bounds (the PDB's linker module, S_SECTION / S_COFFGROUP)
               and named after the groups (.text$mn, .text$x, .rdata, .CRT$XCU, .idata$5, .pdata, ...): the exporter
               names an object's sections after the blocks, so the linker sorts and merges them as the original;
            2. the whole .text disassembled and the function bodies fixed (PDB-only functions have one-byte bodies);
            3. every base-relocation site in the data sections typed as a pointer (a data reference each);
            4. the reference analyzers over the program;
            5. the naming rule: a symbol with no PDB public and no `?`-name at its address becomes <name>@local@<va>
               (unique across units; the owning unit defines it in a relink), the image-base label __ImageBase;
            6. (recorded, no longer needed: the delinker's relocation table is an in-memory singleton, never saved,
               so `export` runs the synthesizer per module instead);
            7. (rvadata, P2c 2026-10-30) the image-base-relative holders typed, so that the synthesizer makes
               IMAGE_REL_AMD64_ADDR32NB relocations of them: .pdata's EndAddress (the loader left it a dword), the
               MSVC exception tables behind the UNWIND_INFO handlers (FuncInfo and its maps, SEH scope tables), RTTI
               and throw-info objects by their publics, and the x64 switch jump tables inside .text (cleared of the
               disasm stage's code, typed ibo32[n] / byte[n], the load instructions referencing them); needs the
               ADDR32NB part of `_tools/delink_patch.py`;
            8. (mangled, P2c 2026-10-30) the `?`-name made primary wherever an address has one: Ghidra names an
               offcut dynamic symbol after the primary's plain name plus the field path, and demangled plain names
               repeat across namespaces (two `MoviePlayer` globals), which failed 24 units on the exporter's
               duplicate-symbol check once dynamic symbols were external;
            9. (outside, 2026-10-30, the first link) references to addresses in no memory block dropped (constants
               the analyzers took for addresses; the delinker made relocations of them);
            10. (bss, the same) the `.bss` block made uninitialized, so the objects carry a proper .bss;
            11. (imports, the second link) `__imp_` symbols primary (a delay-load slot's primary was the loader's
                `ImgDelayDescr_IAT@<va>`, which no library defines);
            12. (entries, the same) a function at each .text contribution start without one (1,408: code in no
                function gets no relocations; 28 COMDATs merged into the previous function's body);
            13. (thunks, the same) a thunk with no public of its own (a `jmp` forwarder the entries stage made a
                function of; Ghidra names a thunk after its target) un-thunked and named thunk_<target>@local@<va>;
            14. (pdfuncs) a function at each .pdata entry that begins in no function; (pointers2, the first boot) the
                base-relocation sites the pointers stage refused, typed after clearing what covered them; (callees,
                the fifth boot) a function at every referenced .text address in no function (code the synthesizer's
                function-walking sinks never saw keeps its original displacements); (handlers, the sixth boot) each
                UNWIND_INFO's exception-handler field its own ImageBaseOffset32 datum; (crtorder, the seventh) one
                `.CRT$XCU<rank>` block per initializer contribution, so the linker sorts the initializers into the
                original's order; (orphans, the tenth boot) every instruction inside a .pdata range that lies in no
                function joins the body of the function at the range's begin (switch cases and split tails that
                `callees` could not make functions of: 11,236 instructions in 3,456 functions); (imagerel, the
                twelfth) a DATA reference for every `[reg + disp32]` operand whose displacement is a data section's
                RVA (a table read through the image base in a register: SQLite's character classes, opus, zlib, the
                CRT - 585 sites), so the synthesizer's image-base-relative sink relocates it; (imageref, the
                fourteenth) that reference made the operand's primary one (the sink follows the primary, and
                Ghidra's own element references came first at 58 sites), a reference to no data removed;
                (orphans2, the same) every instruction of .text in no function at all - leaf functions without a
                .pdata entry, PhysX's inertia helpers among them - joins the function before it;
            saved after every stage.
            The exporter needs `_tools/delink_patch.py` applied once: unpatched, every export streams every symbol
            of the program (4.7 min per module on this DB).
  export    Every delinkable module (not the import descriptors / thunks `Import:X.dll` / `X.dll`, not `* Linker *`
            and `* CIL *`) exported as <out>/<kind>/[<lib>/]<name>.obj from its section contributions (every section,
            .pdata included); manifest.tsv with the module, kind, object, bytes, sections and relocation counts.
            Objects already present are kept (resumable); --modules limits by regex on the module path.
  judge     func_match.py on every object of the manifest, --jobs processes at once; summary.tsv and the totals.

usage: python -I _tools/delink_all.py prepare [--copy D:\\ATLAS\\_re\\ghidra-delink] [--heap 6g] [--dry-run]
       python -I _tools/delink_all.py export  [--copy ...] [--out D:\\ATLAS\\build\\delink\\server] [--modules REGEX] [--heap 4g] [--limit N]
       python -I _tools/delink_all.py judge   [--out ...] [--jobs 4] [--modules REGEX]
"""
import argparse
import bisect
import json
import os
import pickle
import re
import shutil
import struct
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
os.environ.setdefault("GHIDRA_INSTALL_DIR", str(TOOLS / "ghidra_12.1.4_PUBLIC"))
os.environ.setdefault("JAVA_HOME", str(TOOLS / "jdk-21.0.12.1+1"))
sys.path.insert(0, str(TOOLS))
from pdb_source_md5 import pdbutil  # noqa: E402

SETTINGS = ROOT / "build" / "delink" / "settings"
SRC_PROJECT, PROJECT_NAME, PROGRAM = ROOT / "_re" / "ghidra", "atlas", "ShooterGameServer.exe"
PE = Path(r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe")
PDB = PE.with_suffix(".pdb")
PUBLICS = ROOT / "_re" / "cache" / "ShooterGameServer.pdbsyms2.pkl"
PY = sys.executable
BASE = 0x140000000
REF_ANALYZERS = ["x86 Constant Reference Analyzer", "Data Reference", "Scalar Operand References",
                 "Create Address Tables"]
MANGLED = re.compile(r"^\?")
STAGES = ["groups", "disasm", "pointers", "refs", "names", "synth", "unthunk", "unpad", "rvadata", "mangled",
          "outside", "bss", "imports", "entries", "thunks", "pdfuncs", "pointers2", "callees", "thunks2", "unthunk2",
          "handlers", "crtorder", "orphans", "imagerel", "imageref", "orphans2"]
THROW_INFO = re.compile(r"^_TI\d\?")  # _TI<flags>?AV<class>@@: a throw info; _CTA<n>?..: its catchable-type array
CATCHABLE_ARRAY = re.compile(r"^_CTA\d\?")
# the x64 switch: mov r32 / movsxd r64, [rBase + rIndex*4 + disp32] (ModRM mod=10 r/m=100, SIB scale=4, optional REX),
# a jmp r64 within 24 bytes; the two-level form loads the index first: movzx r32, byte ptr [rBase + rIndex + disp32]
DWORD_LOAD = re.compile(rb"(?:[\x40-\x4F])?[\x8B\x63][\x84\x8C\x94\x9C\xA4\xAC\xB4\xBC][\x80-\xBF]", re.DOTALL)
BYTE_LOAD = re.compile(rb"(?:[\x40-\x4F])?\x0F\xB6[\x84\x8C\x94\x9C\xA4\xAC\xB4\xBC][\x00-\x3F]", re.DOTALL)
JMP_REG = re.compile(rb"(?:\x41)?\xFF[\xE0-\xE7]", re.DOTALL)


LOG_FILE = None  # --log: the same lines appended to a file, for a watcher


def log(*a):
    line = " ".join([time.strftime("%H:%M:%S"), *map(str, a)])
    print(line, flush=True)
    if LOG_FILE:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def run(*args):
    return subprocess.run(list(args), capture_output=True, text=True, encoding="utf-8", errors="replace").stdout


# ----------------------------------------------------------------------------------------------- PDB-side facts
def pe_sections():
    """[(va, virtual size, name)] from the PE header."""
    data = PE.read_bytes()[:4096]
    e = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    opt = struct.unpack_from("<H", data, e + 20)[0]
    secs = []
    for i in range(nsec):
        o = e + 24 + opt + 40 * i
        name = data[o:o + 8].rstrip(b"\0").decode()
        vsize, va = struct.unpack_from("<II", data, o + 8)
        secs.append((va, vsize, name))
    return secs


def modules():
    """{modi: (module name, obj path)} from llvm-pdbutil dump -modules."""
    out = run(pdbutil(), "dump", "-modules", str(PDB))
    mods, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"\s*Mod (\d+) \| `(.*)`:", line)
        if m:
            cur = int(m.group(1))
            mods[cur] = [m.group(2), ""]
            continue
        m = re.match(r"\s*Obj: `(.*)`:", line)
        if m and cur is not None:
            mods[cur][1] = m.group(1)
    return {k: tuple(v) for k, v in mods.items()}


def kind_of(name, obj):
    low = name.lower()
    if low.startswith("import:") or low.endswith(".dll"):
        return "import"
    if name == "* CIL *":
        # the LTCG module: the 17 /GL objects' data (8.4 MB of .data, 21 KB of .rdata; their code is attributed
        # to the objects themselves) - delinked as one object (2026-10-30: the first link wanted 252 of its labels)
        return "obj"
    if name == "* Linker *":
        # the linker's own: 40 bytes of .data with the CRT's common variables (__onexitbegin, __onexitend,
        # __native_startup_lock / _state, __dyn_tls_init_callback) and the PCH symbol, which the first link pulled
        # from msvcrt.lib's atonexit.obj against ours; its .rdata (the debug records) is left to the linker
        return "obj"
    if name.startswith("* "):
        return "linker"
    if obj and obj.lower() != low and obj.lower().endswith(".lib"):
        return "lib"
    if low.endswith(".cpp.obj"):
        return "unit"
    return "obj"


def coff_groups(linker_modi, secs):
    """[(name, va, length)] of the linker module's S_COFFGROUP records, addresses through S_SECTION's rva per segment."""
    out = run(pdbutil(), "dump", "-symbols", "-modi", str(linker_modi), str(PDB))
    section_rva = {}
    groups = []
    lines = out.splitlines()
    for i, line in enumerate(lines):
        m = re.search(r"S_SECTION \[size = \d+\] `(.*)`", line)
        if m and i + 1 < len(lines):
            mm = re.search(r"length = (\d+), alignment = \d+, rva = (\d+), section # = (\d+)", lines[i + 1])
            if mm:
                section_rva[int(mm.group(3))] = int(mm.group(2))
        m = re.search(r"S_COFFGROUP \[size = \d+\] `(.*)`", line)
        if m and i + 1 < len(lines):
            mm = re.search(r"length = (\d+), addr = (\d+):(\d+)", lines[i + 1])
            if mm:
                seg, off, length = int(mm.group(2)), int(mm.group(3)), int(mm.group(1))
                if seg in section_rva and length:
                    groups.append((m.group(1), BASE + section_rva[seg] + off, length))
    return sorted(groups, key=lambda g: g[1])


def contributions():
    """{modi: [(va, size)]} from the judge's PDB cache."""
    by_name, _sizes, mods = pickle.loads(PUBLICS.read_bytes())
    per = defaultdict(list)
    for rva, (modi, size) in mods.items():
        per[modi].append((BASE + rva, size))
    for v in per.values():
        v.sort()
    return per, {BASE + rva for rva in by_name.values()}


def linker_modi(mods):
    return next(k for k, (n, _) in mods.items() if n == "* Linker *")


# ----------------------------------------------------------------------------------------------- the PE's RVA holders
class Image:
    """The server PE's bytes, sections and exception directory: the RVA holders are walked in the file and typed in
    Ghidra (a JPype memory read per field would be the slow part)."""

    def __init__(self):
        self.data = d = PE.read_bytes()
        e = struct.unpack_from("<I", d, 0x3C)[0]
        nsec = struct.unpack_from("<H", d, e + 6)[0]
        opt = struct.unpack_from("<H", d, e + 20)[0]
        self.secs = {}
        for i in range(nsec):
            o = e + 24 + opt + 40 * i
            name = d[o:o + 8].rstrip(b"\0").decode()
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", d, o + 8)
            self.secs[name] = (va, vsize, rawptr, rawsize)
        self.pdata = struct.unpack_from("<II", d, e + 24 + 112 + 3 * 8)  # the exception directory (PE32+)
        self.begins = sorted(self.u32(self.pdata[0] + 12 * k) for k in range(self.pdata[1] // 12))

    def off(self, rva):
        for va, vsize, rawptr, rawsize in self.secs.values():
            if va <= rva < va + max(vsize, rawsize):
                return rawptr + (rva - va)
        raise ValueError(f"rva {rva:#x} lies in no section")

    def u32(self, rva):
        return struct.unpack_from("<I", self.data, self.off(rva))[0]

    def i32(self, rva):
        return struct.unpack_from("<i", self.data, self.off(rva))[0]

    def unpack(self, fmt, rva):
        return struct.unpack_from(fmt, self.data, self.off(rva))

    def next_function(self, rva):
        """The first .pdata begin after rva (a bound for a table inside .text), or None."""
        i = bisect.bisect_right(self.begins, rva)
        return self.begins[i] if i < len(self.begins) else None


def switch_tables(img, mods_by_rva):
    """MSVC x64 switch jump tables inside .text (validated on inflate, opus_encoder_ctl and others, 2026-10-30): the
    load (DWORD_LOAD) with a jmp through the register within 24 bytes and the table inside the same PDB section
    contribution as the site (a function's COMDAT holds its tables after the code); the two-level form's byte table
    (BYTE_LOAD just before the dword load, in .text or .rdata). Extents: consecutive entries that are RVAs into the
    contribution (bytes below the paired table's entry count), bounded by the contribution, the next table and the
    next .pdata function. Returns ([(table rva, entries, [site rvas])], [(byte table rva, bytes, [site rvas], in .text)])."""
    tva, tsize, tptr, traw = img.secs[".text"]
    rva0, rsize, _, _ = img.secs[".rdata"]
    text = img.data[tptr:tptr + traw]
    starts = sorted(mods_by_rva)

    def contribution(rva):
        i = bisect.bisect_right(starts, rva) - 1
        if i >= 0 and rva < starts[i] + mods_by_rva[starts[i]][1]:
            return starts[i], starts[i] + mods_by_rva[starts[i]][1]
        return None

    dword = {}  # table rva -> (contribution lo, hi, [sites])
    for m in DWORD_LOAD.finditer(text):
        o = m.end()
        disp = struct.unpack_from("<I", text, o)[0]
        site = tva + m.start()
        c = contribution(site)
        if c is None or not (c[0] <= disp < c[1]) or not JMP_REG.search(text[o + 4:o + 28]):
            continue
        dword.setdefault(disp, (c[0], c[1], []))[2].append(site)
    bytes_ = {}  # byte table rva -> (paired dword table rva, [sites], in .text)
    for m in BYTE_LOAD.finditer(text):
        o = m.end()
        disp = struct.unpack_from("<I", text, o)[0]
        site = tva + m.start()
        in_text = tva <= disp < tva + tsize
        if not in_text and not (rva0 <= disp < rva0 + rsize):
            continue
        mm = DWORD_LOAD.search(text, o + 4, o + 20)  # the paired dword load follows within 16 bytes
        if not mm:
            continue
        t = struct.unpack_from("<I", text, mm.end())[0]
        c = contribution(site)
        if t not in dword or (in_text and (c is None or not (c[0] <= disp < c[1]))):
            continue
        bytes_.setdefault(disp, (t, [], in_text))[1].append(site)
    bounds = sorted(set(dword) | {b for b, (_t, _s, in_text) in bytes_.items() if in_text})

    def limit(rva, hi):
        i = bisect.bisect_right(bounds, rva)
        lim = min(hi, bounds[i]) if i < len(bounds) else hi
        nf = img.next_function(rva)
        return min(lim, nf) if nf is not None else lim

    tables = []
    for t, (lo, hi, sites) in sorted(dword.items()):
        lim = limit(t, hi)
        n = 0
        while t + 4 * n + 4 <= lim and lo <= img.u32(t + 4 * n) < hi:
            n += 1
        if n >= 2:
            tables.append((t, n, sites))
    sizes = {t: n for t, n, _ in tables}
    btables = []
    for b, (t, sites, in_text) in sorted(bytes_.items()):
        if t not in sizes:
            continue
        lim = limit(b, contribution(b)[1]) if in_text else b + 4096
        n = 0
        while b + n < lim and img.data[img.off(b + n)] < sizes[t]:
            n += 1
        if n >= 2:
            btables.append((b, n, sites, in_text))
    return tables, btables


def imagerel_sites(img):
    """[(instruction VA, displacement)] of every .text instruction with a register base (not RIP) and a 32-bit
    displacement that lies in a data section's RVA range: a table read through the image base in a register
    (capstone over the PE file, a few minutes)."""
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone import x86 as _x86
    tva, tsize, trawptr, _trs = img.secs[".text"]
    data_lo = min(va for name, (va, vs, rp, rs) in img.secs.items() if name != ".text")
    size_of_image = max(va + vs for va, vs, rp, rs in img.secs.values())
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.skipdata = True
    sites = []
    for ins in md.disasm(img.data[trawptr:trawptr + tsize], BASE + tva):
        if ins.id == 0 or ins.disp_size not in (2, 4):
            continue
        for op in ins.operands:
            if (op.type == _x86.X86_OP_MEM and op.mem.base not in (_x86.X86_REG_RIP, 0)
                    and data_lo <= op.mem.disp < size_of_image):
                sites.append((ins.address, op.mem.disp))
    return sites


# ----------------------------------------------------------------------------------------------- Ghidra side
def launch(heap):
    import pyghidra
    launcher = pyghidra.HeadlessPyGhidraLauncher()
    launcher.add_vmargs(f"-Xmx{heap}", f"-Dapplication.settingsdir={SETTINGS}")
    launcher.start()


def ensure_copy(copy_dir):
    if (copy_dir / f"{PROJECT_NAME}.gpr").exists():
        return
    log(f"copying the Ghidra project {SRC_PROJECT} -> {copy_dir} (one time)")
    copy_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SRC_PROJECT / f"{PROJECT_NAME}.gpr", copy_dir / f"{PROJECT_NAME}.gpr")
    shutil.copytree(SRC_PROJECT / f"{PROJECT_NAME}.rep", copy_dir / f"{PROJECT_NAME}.rep")


def state_path(copy_dir):
    return copy_dir / "delink-state.json"


def load_state(copy_dir):
    p = state_path(copy_dir)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"done": [], "log": {}}


def save_state(copy_dir, state):
    state_path(copy_dir).write_text(json.dumps(state, indent=1), encoding="utf-8")


def prepare(a):
    copy_dir = Path(a.copy)
    secs = pe_sections()
    mods = modules()
    lm = linker_modi(mods)
    groups = coff_groups(lm, secs)
    kinds = Counter(kind_of(n, o) for n, o in mods.values())
    log(f"{len(mods)} modules {dict(kinds)}; linker module {lm}; {len(groups)} COFF groups")
    if a.dry_run:
        for name, va, length in groups:
            print(f"  {name:12s} {va:x} +{length:#x}")
        return
    ensure_copy(copy_dir)
    state = load_state(copy_dir)
    todo = [s for s in STAGES if s not in state["done"]]
    log("stages done", state["done"], "to do", todo)
    if not todo or a.copy_only:
        return
    launch(a.heap)
    from ghidra.base.project import GhidraProject
    from ghidra.app.cmd.disassemble import DisassembleCommand
    from ghidra.app.cmd.function import CreateFunctionCmd
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.data import DataUtilities, PointerDataType
    from ghidra.program.model.symbol import SourceType, SymbolType
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    project = GhidraProject.openProject(str(copy_dir), PROJECT_NAME, True)
    try:
        program = project.openProgram("/", PROGRAM, False)
        space = program.getAddressFactory().getDefaultAddressSpace()
        A = lambda v: space.getAddress(v)  # noqa: E731
        memory = program.getMemory()

        def stage(name):
            return name in todo

        def done(name, info=""):
            state["done"].append(name)
            state["log"][name] = f"{time.strftime('%Y-%m-%d %H:%M')} {info}"
            project.save(program)
            save_state(copy_dir, state)
            log(f"stage {name} done, saved: {info}")

        if stage("groups"):
            tx = program.startTransaction("COFF groups as blocks")
            try:
                n = 0
                for name, va, length in groups:
                    start, end = A(va), A(va + length - 1)
                    blk = memory.getBlock(start)
                    if blk is None:
                        continue
                    if not blk.getStart().equals(start):
                        memory.split(blk, start)
                        blk = memory.getBlock(start)
                    if blk.getEnd().compareTo(end) > 0:
                        memory.split(blk, A(va + length))
                        blk = memory.getBlock(start)
                    if blk.getName() != name:
                        blk.setName(name)
                    n += 1
                blocks = [(b.getName(), str(b.getStart()), b.getSize()) for b in memory.getBlocks()]
            finally:
                program.endTransaction(tx, True)
            done("groups", f"{n} groups applied; {len(blocks)} blocks")

        text = AddressSet()
        for b in memory.getBlocks():
            if b.isExecute():
                text.add(b.getStart(), b.getEnd())
        data = AddressSet()
        for b in memory.getBlocks():
            if not b.isExecute():
                data.add(b.getStart(), b.getEnd())

        if stage("disasm"):
            tx = program.startTransaction("disassemble")
            try:
                DisassembleCommand(text, text, True).applyTo(program, monitor)
                fm = program.getFunctionManager()
                nf = 0
                for f in fm.getFunctions(text, True):
                    CreateFunctionCmd.fixupFunctionBody(program, f, monitor)
                    nf += 1
                    if nf % 20000 == 0:
                        log(f"  {nf:,} function bodies fixed")
                ninsn = program.getListing().getNumInstructions()
            finally:
                program.endTransaction(tx, True)
            done("disasm", f"{nf:,} functions, {ninsn:,} instructions")

        if stage("pointers"):
            tx = program.startTransaction("base-relocation pointers")
            try:
                rt = program.getRelocationTable()
                listing = program.getListing()
                ptr = PointerDataType()
                nrel = nhad = nptr = nfail = 0
                for r in rt.getRelocations():
                    at = r.getAddress()
                    if not data.contains(at) or r.getType() != 10:  # IMAGE_REL_BASED_DIR64 only (0 = block padding)
                        continue
                    nrel += 1
                    d = listing.getDataContaining(at)
                    if d is not None and d.isPointer() and d.getAddress().equals(at):
                        nhad += 1
                        continue
                    try:
                        DataUtilities.createData(program, at, ptr, -1,
                                                 DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA)
                        nptr += 1
                    except Exception:
                        nfail += 1
                    if nrel % 50000 == 0:
                        log(f"  {nrel:,} base relocations seen")
            finally:
                program.endTransaction(tx, True)
            done("pointers", f"{nrel:,} in data: {nhad:,} were pointers, {nptr:,} typed, {nfail:,} failed")

        aam = AutoAnalysisManager.getAnalysisManager(program)
        if stage("refs"):
            tx = program.startTransaction("reference analyzers")
            try:
                for name in REF_ANALYZERS:
                    an = aam.getAnalyzer(name)
                    if an is None:
                        log("no analyzer", name)
                        continue
                    t0 = time.time()
                    aam.scheduleOneTimeAnalysis(an, memory)
                    aam.startAnalysis(monitor)
                    log(f"  {name}: {time.time() - t0:.0f} s")
            finally:
                program.endTransaction(tx, True)
            done("refs", "the four reference analyzers")

        if stage("names"):
            _per, public_vas = contributions()
            tx = program.startTransaction("naming rule")
            try:
                st = program.getSymbolTable()
                before, renamed = Counter(), Counter()
                seen = set()
                for s in st.getSymbolIterator(True):
                    addr = s.getAddress()
                    if addr in seen or s.isDynamic() or not addr.isMemoryAddress():
                        continue
                    seen.add(addr)
                    syms = list(st.getSymbols(addr))
                    if any(MANGLED.match(x.getName()) for x in syms):
                        continue
                    prim = next((x for x in syms if x.isPrimary()), syms[0])
                    if prim.isDynamic():
                        continue
                    va = addr.getOffset()
                    if va in public_vas or va == BASE:
                        continue
                    before[prim.getName()] += 1
                    try:
                        prim.setName(f"{prim.getName()}@local@{va:x}", SourceType.USER_DEFINED)
                        renamed["ok"] += 1
                    except Exception as ex:
                        renamed["failed"] += 1
                        if renamed["failed"] <= 5:
                            log("  rename failed", addr, prim.getName(), str(ex)[:100])
                for s in list(st.getSymbols(A(BASE))):
                    if s.isPrimary() and s.getName() != "__ImageBase":
                        s.setName("__ImageBase", SourceType.USER_DEFINED)
            finally:
                program.endTransaction(tx, True)
            done("names", f"{dict(renamed)}; most common before: {before.most_common(6)}")

        if stage("synth"):
            syn = aam.getAnalyzer("Relocation table synthesizer")
            if syn is None:
                sys.exit("no Relocation table synthesizer analyzer: the delinker extension did not load")
            tx = program.startTransaction("relocation synthesizer")
            try:
                t0 = time.time()
                aam.scheduleOneTimeAnalysis(syn, memory)
                aam.startAnalysis(monitor)
            finally:
                program.endTransaction(tx, True)
            done("synth", f"{time.time() - t0:.0f} s")

        def unthunk_imports(name):
            # The import thunks (`jmp [__imp_sinf]`, publics named `sinf` in the thunk modules) were marked as thunks
            # to the external functions by the analysis, and the exporter then names a call's target after the
            # external (`MSVCR120.DLL::sinf`); the original object's call wants the thunk's own name, which the import
            # library defines. Un-thunk them: the delinked objects' externals are then `sinf`. Run again after the
            # callees stage (unthunk2, 2026-10-30): a delay-load stub `__imp_load_X` made a function became such a
            # thunk, and one call to it went out as `PXFOUNDATION_X64.DLL::X`, which nothing defines (the linker
            # itself defines `__imp_load_X` when it makes the delay-load thunks).
            fm = program.getFunctionManager()
            tx = program.startTransaction("un-thunk the import thunks")
            try:
                n = 0
                for f in fm.getFunctions(True):
                    if f.isThunk():
                        t = f.getThunkedFunction(False)
                        if t is not None and t.isExternal():
                            f.setThunkedFunction(None)
                            n += 1
            finally:
                program.endTransaction(tx, True)
            done(name, f"{n:,} import thunks un-thunked")

        if stage("unthunk"):
            unthunk_imports("unthunk")

        if stage("unpad"):
            # The first pointers stage typed every base-relocation site, the type-0 ABSOLUTE padding entries of the
            # relocation blocks too (offset 0 of a page: a bogus 8-byte pointer inside whatever lies at the page
            # start, e.g. a string literal; the synthesizer then made a relocation of it and the export of that
            # module failed with "buffer does not contain relocation"). Clear those pointers again.
            rt = program.getRelocationTable()
            listing = program.getListing()
            tx = program.startTransaction("clear the padding entries' pointers")
            try:
                n = seen = 0
                for r in rt.getRelocations():
                    if r.getType() == 10:
                        continue
                    seen += 1
                    at = r.getAddress()
                    d = listing.getDataAt(at)
                    if d is not None and d.isPointer() and d.getLength() == 8:
                        listing.clearCodeUnits(at, at.add(7), False)
                        n += 1
            finally:
                program.endTransaction(tx, True)
            done("unpad", f"{seen:,} non-DIR64 relocation entries, {n:,} bogus pointers cleared")

        if stage("rvadata"):
            # P2c: every 32-bit image-base-relative field typed ImageBaseOffset32 (ibo32), inside structures where
            # the field has siblings; the patched delinker's ImageBaseRelativeDataRelocationSynthesizer then makes
            # an ADDR32NB relocation of each (an End field anchored to its Begin sibling). The holders are walked
            # in the PE file (Image), the PDB publics name the handlers and the RTTI / throw-info objects.
            from ghidra.program.model.data import (ArrayDataType, ByteDataType, CategoryPath, DataTypeConflictHandler,
                                                   DWordDataType, IBO32DataType, IntegerDataType, StructureDataType)
            from ghidra.program.model.symbol import RefType
            img = Image()
            by_name, _sizes, mods_by_rva = pickle.loads(PUBLICS.read_bytes())
            name_at = {}
            for nm, rva in by_name.items():
                name_at.setdefault(rva, nm)
            dtm = program.getDataTypeManager()
            listing = program.getListing()
            refman = program.getReferenceManager()
            fm = program.getFunctionManager()
            ibo, dword, int32, byte = IBO32DataType(), DWordDataType(), IntegerDataType(), ByteDataType()
            cat = CategoryPath("/ATLAS")
            stats = Counter()

            def struct_type(name, fields):
                s = StructureDataType(cat, name, 0)
                for dt, nm in fields:
                    s.add(dt, nm, None)
                return dtm.resolve(s, DataTypeConflictHandler.REPLACE_HANDLER)

            def array(dt, n):
                return ArrayDataType(dt, n, dt.getLength())

            def put(rva, dt, what):
                try:
                    DataUtilities.createData(program, A(BASE + rva), dt, -1,
                                             DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA)
                    stats[what] += 1
                except Exception as ex:
                    stats[what + " failed"] += 1
                    if stats[what + " failed"] <= 3:
                        log(f"  {what} at {BASE + rva:x} failed: {str(ex)[:140]}")

            tx = program.startTransaction("RVA holders typed")
            try:
                # 1. .pdata: the loader's structure has EndAddress as a dword (one edit retypes every entry)
                rf = dtm.getDataType("/PE/_IMAGE_RUNTIME_FUNCTION_ENTRY")
                if rf is None:
                    rf = next((t for t in dtm.getAllDataTypes() if t.getName() == "_IMAGE_RUNTIME_FUNCTION_ENTRY"), None)
                if rf is None:
                    sys.exit("no _IMAGE_RUNTIME_FUNCTION_ENTRY structure: .pdata is not typed")
                if rf.getComponentAt(4).getDataType().getName() != ibo.getName():
                    rf.replaceAtOffset(4, ibo, 4, "EndAddress", "ATLAS: image-base-relative, anchored to BeginAddress")
                    stats[".pdata EndAddress retyped"] = 1
                # 2. the exception handlers' data behind the UNWIND_INFO (the loader typed the UNWIND_INFO itself, the
                #    handler field and chained entries included): FuncInfo and its maps for __CxxFrameHandler3 and
                #    __GSHandlerCheck_EH, the scope table for __C_specific_handler and __GSHandlerCheck_SEH
                FuncInfo = struct_type("FuncInfo", [
                    (dword, "magicNumber"), (int32, "maxState"), (ibo, "dispUnwindMap"), (int32, "nTryBlocks"),
                    (ibo, "dispTryBlockMap"), (int32, "nIPMapEntries"), (ibo, "dispIPtoStateMap"),
                    (int32, "dispUnwindHelp"), (ibo, "dispESTypeList"), (int32, "EHFlags")])
                UnwindMapEntry = struct_type("UnwindMapEntry", [(int32, "toState"), (ibo, "action")])
                TryBlockMapEntry = struct_type("TryBlockMapEntry", [
                    (int32, "tryLow"), (int32, "tryHigh"), (int32, "catchHigh"), (int32, "nCatches"),
                    (ibo, "dispHandlerArray")])
                HandlerType = struct_type("HandlerType", [
                    (dword, "adjectives"), (ibo, "dispType"), (int32, "dispCatchObj"), (ibo, "dispOfHandler"),
                    (int32, "dispFrame")])
                IPtoStateMapEntry = struct_type("IPtoStateMapEntry", [(ibo, "Ip"), (int32, "state")])
                ESTypeList = struct_type("ESTypeList", [(int32, "nCount"), (ibo, "dispTypeArray")])
                ScopeRecord = struct_type("SCOPE_RECORD", [
                    (ibo, "BeginAddress"), (ibo, "EndAddress"), (ibo, "HandlerAddress"), (ibo, "JumpTarget")])
                ScopeRecordConst = struct_type("SCOPE_RECORD_CONST", [  # HandlerAddress 1 = EXCEPTION_EXECUTE_HANDLER
                    (ibo, "BeginAddress"), (ibo, "EndAddress"), (dword, "HandlerAddress"), (ibo, "JumpTarget")])
                pd_rva, pd_size = img.pdata
                seen_unwind, seen_funcinfo = set(), set()
                for k in range(pd_size // 12):
                    _begin, _end, uw = img.unpack("<III", pd_rva + 12 * k)
                    if uw & 1 or uw in seen_unwind:
                        continue
                    seen_unwind.add(uw)
                    b0, _prolog, ncodes, _frame = img.unpack("<BBBB", uw)
                    flags = b0 >> 3
                    if flags & 4 or not flags & 3:
                        continue
                    p = uw + 4 + 2 * ((ncodes + 1) & ~1)
                    hn = name_at.get(img.u32(p), "?")
                    d = p + 4
                    stats["handler " + hn] += 1
                    if hn in ("__CxxFrameHandler3", "__GSHandlerCheck_EH"):
                        put(d, ibo, "FuncInfo rva")
                        fi = img.u32(d)
                        if fi in seen_funcinfo:
                            continue
                        seen_funcinfo.add(fi)
                        maxstate, uwmap, ntry, trymap, nip, ipmap, _help, estypes, _flags = img.unpack("<iIiIiIiIi", fi + 4)
                        put(fi, FuncInfo, "FuncInfo")
                        if maxstate > 0:
                            put(uwmap, array(UnwindMapEntry, maxstate), "UnwindMap")
                        if ntry > 0:
                            put(trymap, array(TryBlockMapEntry, ntry), "TryBlockMap")
                            for t in range(ntry):
                                _lo, _hi, _ch, ncatch, harr = img.unpack("<iiiiI", trymap + 20 * t)
                                if ncatch > 0:
                                    put(harr, array(HandlerType, ncatch), "HandlerArray")
                        if nip > 0:
                            put(ipmap, array(IPtoStateMapEntry, nip), "IPtoStateMap")
                        if estypes:
                            put(estypes, ESTypeList, "ESTypeList")
                            cnt, arr = img.unpack("<iI", estypes)
                            if cnt > 0:
                                put(arr, array(HandlerType, cnt), "ESTypeList handlers")
                    elif hn in ("__C_specific_handler", "__GSHandlerCheck_SEH"):
                        cnt = img.u32(d)
                        put(d, dword, "ScopeTable count")
                        for t in range(cnt):
                            r = d + 4 + 16 * t
                            put(r, ScopeRecordConst if img.u32(r + 8) <= 1 else ScopeRecord, "ScopeRecord")
                # 3. RTTI and throw info, by their publics (ICF folds several names onto one address)
                COL = struct_type("RTTICompleteObjectLocator", [
                    (dword, "signature"), (dword, "offset"), (dword, "cdOffset"), (ibo, "pTypeDescriptor"),
                    (ibo, "pClassDescriptor"), (ibo, "pSelf")])
                CHD = struct_type("RTTIClassHierarchyDescriptor", [
                    (dword, "signature"), (dword, "attributes"), (dword, "numBaseClasses"), (ibo, "pBaseClassArray")])
                BCD = struct_type("RTTIBaseClassDescriptor", [
                    (ibo, "pTypeDescriptor"), (dword, "numContainedBases"), (int32, "mdisp"), (int32, "pdisp"),
                    (int32, "vdisp"), (dword, "attributes"), (ibo, "pClassDescriptor")])
                ThrowInfo = struct_type("ThrowInfo", [
                    (dword, "attributes"), (ibo, "pmfnUnwind"), (ibo, "pForwardCompat"), (ibo, "pCatchableTypeArray")])
                CatchableType = struct_type("CatchableType", [
                    (dword, "properties"), (ibo, "pType"), (int32, "mdisp"), (int32, "pdisp"), (int32, "vdisp"),
                    (int32, "sizeOrOffset"), (ibo, "copyFunction")])
                cta_types = {}
                typed = set()
                for nm, rva in by_name.items():
                    if rva in typed:
                        continue
                    if nm.startswith("??_R4"):
                        dt, what = COL, "COL"
                    elif nm.startswith("??_R3"):
                        dt, what = CHD, "CHD"
                        nb, bca = img.unpack("<iI", rva + 8)
                        if nb > 0 and bca not in typed:
                            typed.add(bca)
                            put(bca, array(ibo, nb), "BCA")
                    elif nm.startswith("??_R1"):
                        dt, what = BCD, "BCD"
                    elif THROW_INFO.match(nm):
                        dt, what = ThrowInfo, "ThrowInfo"
                    elif CATCHABLE_ARRAY.match(nm):
                        n = img.i32(rva)
                        if n not in cta_types:
                            cta_types[n] = struct_type(f"CatchableTypeArray{n}", [
                                (int32, "nCatchableTypes"), (array(ibo, n), "arrayOfCatchableTypes")])
                        dt, what = cta_types[n], "CatchableTypeArray"
                    elif nm.startswith("_CT??_R0"):
                        dt, what = CatchableType, "CatchableType"
                    else:
                        continue
                    typed.add(rva)
                    put(rva, dt, what)
                # 4. the switch jump tables inside .text (code since the disasm stage; a table of the .text group's
                #    libraries can even carry a .pdata entry and so a function of its own) and the loads' references
                tables, btables = switch_tables(img, mods_by_rva)
                jobs = [(t, 4 * n, array(ibo, n), "jump table") for t, n, _s in tables]
                jobs += [(b, n, array(byte, n), "index table") for b, n, _s, in_text in btables if in_text]
                for t, length, dt, what in jobs:
                    start, end = A(BASE + t), A(BASE + t + length - 1)
                    if fm.getFunctionAt(start) is not None:
                        fm.removeFunction(start)
                        stats["function at a table removed"] += 1
                    listing.clearCodeUnits(start, end, False)
                    put(t, dt, what)
                loads = [(s, t) for t, _n, sites in tables for s in sites]
                loads += [(s, b) for b, _n, sites, _in_text in btables for s in sites]
                for s, t in loads:
                    ins = listing.getInstructionAt(A(BASE + s))
                    if ins is None:
                        stats["load without an instruction"] += 1
                        continue
                    ref = refman.addMemoryReference(ins.getAddress(), A(BASE + t), RefType.DATA, SourceType.USER_DEFINED, 1)
                    refman.setPrimary(ref, True)
                    stats["load referenced"] += 1
                stats["jump tables"], stats["jump-table entries"] = len(tables), sum(n for _t, n, _s in tables)
                stats["index tables"] = len(btables)
            finally:
                program.endTransaction(tx, True)
            done("rvadata", "; ".join(f"{k} {v:,}" for k, v in sorted(stats.items())))

        if stage("mangled"):
            # Ghidra names an offcut dynamic symbol after the containing datum's primary symbol's plain name and the
            # field path (MoviePlayer.SharedReferenceCount.ReferenceController); with a demangled primary the plain
            # name repeats across namespaces (FDefaultGameMoviePlayer::MoviePlayer, FNullGameMoviePlayer::MoviePlayer:
            # fully qualified names are unique, 0 duplicates program-wide), so two addresses got one external name and
            # 24 engine units failed the exporter's duplicate-symbol check (P2c, 2026-10-30: dynamic symbols are
            # external since the ICF-shared unwind data). The mangled symbol made primary wherever one exists: the
            # dotted names then start with the ?-name, unique by address, and the exporter's MSVC preference already
            # named the symbols themselves so.
            tx = program.startTransaction("mangled symbols primary")
            try:
                st = program.getSymbolTable()
                stats = Counter()
                seen = set()
                for s in st.getSymbolIterator(True):
                    addr = s.getAddress()
                    if addr in seen or s.isDynamic() or not addr.isMemoryAddress():
                        continue
                    seen.add(addr)
                    syms = list(st.getSymbols(addr))
                    prim = next((x for x in syms if x.isPrimary()), None)
                    if prim is None or MANGLED.match(prim.getName()):
                        continue
                    mangled = [x for x in syms if MANGLED.match(x.getName())]
                    if not mangled:
                        continue
                    try:
                        mangled[0].setPrimary()
                        stats["function" if prim.getSymbolType() == SymbolType.FUNCTION else "data"] += 1
                    except Exception as ex:
                        stats["failed"] += 1
                        if stats["failed"] <= 5:
                            log("  setPrimary failed", addr, prim.getName(), str(ex)[:100])
            finally:
                program.endTransaction(tx, True)
            done("mangled", "; ".join(f"{k} {v:,}" for k, v in sorted(stats.items())))

        if stage("outside"):
            # The reference analyzers took constants for addresses outside the image (`MOV EDX, 0x10000`: 93
            # references to 0x10000, which no block holds) and the delinker's absolute code sink made relocations of
            # them, so the first link (2026-10-30) wanted a `DAT_00010000` from 25 objects. A reference to an address
            # in no memory block is dropped (externals, stack and registers are not memory addresses).
            tx = program.startTransaction("references outside memory")
            try:
                refman = program.getReferenceManager()
                stats = Counter()
                drop = []
                it = refman.getReferenceIterator(program.getMinAddress())
                while it.hasNext():
                    r = it.next()
                    to = r.getToAddress()
                    stats["references"] += 1
                    if to.isMemoryAddress() and not memory.contains(to):
                        drop.append(r)
                        stats[f"to {to.getOffset():#x}"] += 1
                for r in drop:
                    refman.delete(r)
                stats["dropped"] = len(drop)
            finally:
                program.endTransaction(tx, True)
            top = ", ".join(f"{k[3:]} x{v}" for k, v in stats.most_common(6) if k.startswith("to "))
            done("outside", f"references {stats['references']:,}; dropped {stats['dropped']:,} (to {top})")

        if stage("bss"):
            # The PE loader filled the image's uninitialized tail with zero bytes, so the `.bss` group's block was
            # initialized and the exporter wrote it as initialized data (the linker: "multiple '.bss' sections found
            # with different attributes"). The block uninitialized, the objects get a proper .bss.
            tx = program.startTransaction(".bss uninitialized")
            try:
                n = 0
                for b in memory.getBlocks():
                    if b.getName() == ".bss" and b.isInitialized():
                        memory.convertToUninitialized(b)
                        n += 1
            finally:
                program.endTransaction(tx, True)
            done("bss", f"{n} block(s) uninitialized")

        if stage("imports"):
            # A delay-load IAT slot carries two imported labels, `ImgDelayDescr_IAT@<va>` (primary) and the PDB's
            # `__imp_X`; the exporter named the slot after the primary and the second link (2026-10-30) wanted
            # `ImgDelayDescr_IAT@143cf5590` from 7 objects. `__imp_` names primary wherever they are: the import
            # libraries define them.
            tx = program.startTransaction("__imp_ primary")
            try:
                st = program.getSymbolTable()
                n = 0
                for s in st.getSymbolIterator("__imp_*", True):
                    if not s.isPrimary() and s.setPrimary():
                        n += 1
            finally:
                program.endTransaction(tx, True)
            done("imports", f"{n} __imp_ symbols made primary")

        if stage("entries"):
            # 1,408 of the 143,188 .text contribution starts had no function entry (2026-10-30, the second link):
            # 1,380 chunks Ghidra disassembled but put in no function (the synthesizer's code sinks walk functions,
            # so such code got no relocations) and 28 COMDATs merged into the preceding function's body (a vtable of
            # ImfTiledInputFile.obj points into ImfScanLineInputFile.obj's; zlib's compressBound). A function at
            # each, the containing function's body cut before it; named by the naming rule unless a label names it.
            from ghidra.program.model.address import AddressSet as _AddressSet
            per_, public_vas = contributions()
            tva_, tsize_ = Image().secs[".text"][:2]
            starts_ = sorted(va for cs in per_.values() for va, _s in cs if tva_ <= va - BASE < tva_ + tsize_)
            tx = program.startTransaction("function entries at contribution starts")
            try:
                fm = program.getFunctionManager()
                stats = Counter()
                for va in starts_:
                    a = A(va)
                    if fm.getFunctionAt(a) is not None or program.getListing().getInstructionAt(a) is None:
                        continue
                    f = fm.getFunctionContaining(a)
                    if f is not None:
                        # a body may hold addresses below its entry (a backward chunk): the cut stops at the entry
                        body, entry = f.getBody(), f.getEntryPoint()
                        cut = _AddressSet(a, entry.subtract(1) if entry.compareTo(a) > 0 else body.getMaxAddress())
                        f.setBody(body.subtract(cut))
                        stats["bodies cut"] += 1
                    if not CreateFunctionCmd(a).applyTo(program, monitor):
                        stats["failed"] += 1
                        if stats["failed"] <= 5:
                            log(f"  no function at {va:x}")
                        continue
                    g = fm.getFunctionAt(a)
                    CreateFunctionCmd.fixupFunctionBody(program, g, monitor)
                    if g.getName().startswith("FUN_") and va not in public_vas:
                        g.setName(f"FUN_{va:x}@local@{va:x}", SourceType.USER_DEFINED)
                        stats["named @local@"] += 1
                    stats["created"] += 1
            finally:
                program.endTransaction(tx, True)
            done("entries", "; ".join(f"{k} {v:,}" for k, v in sorted(stats.items())))

        def unthunk_locals(name):
            # A function the entries / callees stage made of a 5-byte `jmp` forwarder is a thunk to Ghidra, named
            # after its target (`thunk_FUN_<va>`, or the target's own name): conncache.obj then held
            # `Curl_bundle_destroy` twice and failed the duplicate check (2026-10-30, the fifth export); after the
            # callees stage ten objects held `thunk_FUN_<va>` several times. A thunk with no public of its own is
            # un-thunked and named thunk_<target>@local@<va>; the bytes are the same.
            _perx, public_vas = contributions()
            tx = program.startTransaction("thunks without a public")
            try:
                fm = program.getFunctionManager()
                n = 0
                for f in fm.getFunctions(True):
                    va = f.getEntryPoint().getOffset()
                    if not f.isThunk() or va in public_vas:
                        continue
                    target = f.getThunkedFunction(False)
                    tname = target.getName() if target is not None else "unknown"
                    f.setThunkedFunction(None)
                    f.setName(f"thunk_{tname}@local@{va:x}", SourceType.USER_DEFINED)
                    n += 1
            finally:
                program.endTransaction(tx, True)
            done(name, f"{n} thunks without a public un-thunked and named")

        if stage("thunks"):
            unthunk_locals("thunks")

        if stage("pdfuncs"):
            # 72 of the 155,525 .pdata entries begin in no function (none at a contribution start) and one of them
            # inside a garbage instruction that the disassembly of the previous function ran into (0x141dc3872:
            # `ADD byte ptr [RAX-0x77], CL` starts one byte before it); the synthesizer found no target for such
            # an entry's BeginAddress, the object's .pdata entry had no relocation, and the linker refused the
            # object ("invalid .pdata contributions", 2026-10-30). Each such entry: its range cleared and
            # disassembled from the entry, a function made there, named by the rule.
            from ghidra.program.model.address import AddressSet as _AddressSet
            _per3, public_vas = contributions()
            img_ = Image()
            pd_rva, pd_size = img_.pdata
            tx = program.startTransaction("functions at .pdata entries")
            try:
                fm, listing = program.getFunctionManager(), program.getListing()
                stats = Counter()
                for e in range(pd_rva, pd_rva + pd_size, 12):
                    b, end = img_.u32(e), img_.u32(e + 4)
                    if not b or end <= b:
                        continue
                    a = A(BASE + b)
                    cu = listing.getCodeUnitContaining(a)
                    mid = cu is not None and cu.getMinAddress().getOffset() != a.getOffset()
                    if fm.getFunctionContaining(a) is not None and not mid:
                        continue
                    f = fm.getFunctionContaining(a)
                    if f is not None:
                        body, entry = f.getBody(), f.getEntryPoint()
                        cut = _AddressSet(a, entry.subtract(1) if entry.compareTo(a) > 0 else body.getMaxAddress())
                        f.setBody(body.subtract(cut))
                        stats["bodies cut"] += 1
                    if mid:
                        listing.clearCodeUnits(cu.getMinAddress(), A(BASE + end - 1), False)
                        stats["cleared"] += 1
                    DisassembleCommand(a, _AddressSet(a, A(BASE + end - 1)), True).applyTo(program, monitor)
                    if not CreateFunctionCmd(a).applyTo(program, monitor):
                        stats["failed"] += 1
                        if stats["failed"] <= 5:
                            log(f"  no function at {BASE + b:x}")
                        continue
                    g = fm.getFunctionAt(a)
                    if g.getName().startswith("FUN_") and b + BASE not in public_vas:
                        g.setName(f"FUN_{BASE + b:x}@local@{BASE + b:x}", SourceType.USER_DEFINED)
                        stats["named @local@"] += 1
                    stats["created"] += 1
            finally:
                program.endTransaction(tx, True)
            done("pdfuncs", "; ".join(f"{k} {v:,}" for k, v in sorted(stats.items())))

        if stage("pointers2"):
            # The pointers stage refused 2,115 base-relocation sites that lay inside data the loader had typed (the
            # TLS directory, the load config, ...): no pointer, no relocation, and the linked PE carried 2,008 image
            # pointers without a base relocation - under ASLR they point into nothing, and the loader, which reads
            # the TLS directory before the entry point, failed with 0xc0000005 (2026-10-30, the first boot). Each
            # such site: the datum covering it cleared (its bytes still export; only the relocations need types),
            # a pointer made there.
            tx = program.startTransaction("base-relocation pointers, second pass")
            try:
                rt = program.getRelocationTable()
                listing = program.getListing()
                ptr = PointerDataType()
                stats = Counter()
                for r in rt.getRelocations():
                    at = r.getAddress()
                    if not data.contains(at) or r.getType() != 10:
                        continue
                    d = listing.getDataContaining(at)
                    if d is not None and d.isPointer() and d.getAddress().equals(at):
                        continue
                    stats["sites"] += 1
                    if d is not None and d.isDefined():
                        listing.clearCodeUnits(d.getAddress(), d.getMaxAddress(), False)
                        stats["cleared " + d.getDataType().getName()[:30]] += 1
                    try:
                        DataUtilities.createData(program, at, ptr, -1,
                                                 DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA)
                        stats["typed"] += 1
                    except Exception as ex:
                        stats["failed"] += 1
                        if stats["failed"] <= 5:
                            log(f"  pointer at {at} failed: {str(ex)[:120]}")
            finally:
                program.endTransaction(tx, True)
            done("pointers2", "; ".join(f"{k} {v:,}" for k, v in sorted(stats.items(), key=lambda kv: -kv[1])[:8]))

        if stage("callees"):
            # Code in no function gets no relocations (the synthesizer's sinks walk functions), and the entries
            # stage covered the contribution starts only: the fifth boot (2026-10-30) died on a call inside such a
            # chunk (LAB_141b7ec09, a callee of FStaticMeshVertexBuffer::Init in an LTCG object's code), whose
            # displacement still pointed where the original's callee had been. A function at every referenced
            # .text address that lies in no function: call and jump targets, function pointers in data.
            _per4, public_vas = contributions()
            tva_, tsize_ = Image().secs[".text"][:2]
            tx = program.startTransaction("functions at referenced code")
            try:
                fm, listing, refman = program.getFunctionManager(), program.getListing(), program.getReferenceManager()
                from ghidra.program.model.address import AddressSet as _AddressSet
                tset = _AddressSet(A(BASE + tva_), A(BASE + tva_ + tsize_ - 1))
                stats = Counter()
                it = refman.getReferenceDestinationIterator(tset, True)
                todo = []
                while it.hasNext():
                    a = it.next()
                    if fm.getFunctionContaining(a) is None and listing.getInstructionAt(a) is not None:
                        todo.append(a)
                stats["referenced, in no function"] = len(todo)
                for a in todo:
                    if fm.getFunctionContaining(a) is not None:  # made by an earlier one of this pass
                        stats["covered meanwhile"] += 1
                        continue
                    if not CreateFunctionCmd(a).applyTo(program, monitor):
                        stats["failed"] += 1
                        continue
                    g = fm.getFunctionAt(a)
                    if g is None:
                        stats["no entry"] += 1
                        continue
                    va = a.getOffset()
                    if g.getName().startswith("FUN_") and va not in public_vas:
                        g.setName(f"FUN_{va:x}@local@{va:x}", SourceType.USER_DEFINED)
                        stats["named @local@"] += 1
                    stats["created"] += 1
                    if stats["created"] % 2000 == 0:
                        log(f"  {stats['created']:,} functions made")
            finally:
                program.endTransaction(tx, True)
            done("callees", "; ".join(f"{k} {v:,}" for k, v in sorted(stats.items())))

        if stage("thunks2"):
            unthunk_locals("thunks2")

        if stage("unthunk2"):
            unthunk_imports("unthunk2")

        if stage("handlers"):
            # The loader types each UNWIND_INFO as PEx64_UnwindInfo, whose first components are bitfields (version,
            # flags); the delinker's walk of that structure never reaches the ExceptionHandler component (nor the
            # chained entry's three), so every handler RVA stayed the original's - __C_specific_handler at the
            # original's thunk address, inside another function in the link - and the sixth boot died in the first
            # exception dispatch (2026-10-30; the field has its reference, the scope tables behind it relocate).
            # The structure cleared, the handler field its own ImageBaseOffset32 datum; a chained entry a struct
            # of our own (its end field anchored to its start sibling), the UNWIND_INFO_<va> labels untouched.
            from ghidra.program.model.data import CategoryPath, IBO32DataType, StructureDataType
            from ghidra.program.model.data import DataTypeConflictHandler
            img_ = Image()
            pd_rva, pd_size = img_.pdata
            dtm = program.getDataTypeManager()
            ibo = IBO32DataType()
            chain = StructureDataType(CategoryPath("/ATLAS"), "UNWIND_CHAIN", 0)
            chain.add(ibo, 4, "FunctionStartAddress", None)
            chain.add(ibo, 4, "FunctionEndAddress", None)
            chain.add(ibo, 4, "UnwindInfoAddress", None)
            tx = program.startTransaction("unwind handler fields")
            try:
                chain = dtm.resolve(chain, DataTypeConflictHandler.REPLACE_HANDLER)
                listing = program.getListing()
                stats = Counter()
                seen = set()
                for e in range(pd_rva, pd_rva + pd_size, 12):
                    u = img_.u32(e + 8)
                    if u & 1 or u in seen:
                        continue
                    seen.add(u)
                    p = img_.off(u)
                    flags, ncodes = img_.data[p] >> 3, img_.data[p + 2]
                    if not (flags & 7):
                        continue
                    q = u + 4 + 2 * ((ncodes + 1) & ~1)
                    d = listing.getDataAt(A(BASE + u))
                    if d is not None and d.isDefined():
                        listing.clearCodeUnits(A(BASE + u), A(BASE + u + d.getLength() - 1), False)
                        stats["cleared"] += 1
                    try:
                        if flags & 4:
                            DataUtilities.createData(program, A(BASE + q), chain, -1,
                                                     DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA)
                            stats["chained"] += 1
                        else:
                            DataUtilities.createData(program, A(BASE + q), ibo, -1,
                                                     DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA)
                            stats["handler"] += 1
                    except Exception as ex:
                        stats["failed"] += 1
                        if stats["failed"] <= 5:
                            log(f"  at {BASE + q:x}: {str(ex)[:120]}")
            finally:
                program.endTransaction(tx, True)
            done("handlers", "; ".join(f"{k} {v:,}" for k, v in sorted(stats.items())))

        if stage("crtorder"):
            # The C++ static initializers run in the order of the .CRT$XCU entries, and the original's 1,396
            # contributions interleave the modules (the linker's own order, not the input order); one .CRT$XCU
            # section per object, merged in input order, put 454 of 12,533 consecutive pairs the other way round
            # (2026-10-30, the seventh boot: ICU's lazy locale set-up freeing an unset Locale). The block split into
            # one block per contribution, named .CRT$XCU<rank>, which the linker sorts by name back into the
            # original's sequence.
            per_, _pv = contributions()
            blocks = [b for b in memory.getBlocks() if b.getName() == ".CRT$XCU"]
            assert len(blocks) == 1, [b.getName() for b in blocks]
            block = blocks[0]
            cs = sorted((va, size, m) for m, lst in per_.items() for va, size in lst
                        if block.getStart().getOffset() <= va <= block.getEnd().getOffset())
            tx = program.startTransaction(".CRT$XCU by contribution")
            try:
                n = 0
                for i, (va, size, _m) in enumerate(cs):
                    a = A(va)
                    b = memory.getBlock(a)
                    if b.getStart().getOffset() != va:
                        memory.split(b, a)
                        b = memory.getBlock(a)
                    b.setName(f".CRT$XCU{i + 1:05d}")
                    n += 1
            finally:
                program.endTransaction(tx, True)
            done("crtorder", f"{n:,} .CRT$XCU blocks, one per contribution, named by the original's order")

        if stage("orphans"):
            # Instructions in no function get no relocations (the synthesizer's sinks walk function bodies), and
            # `callees` made functions at the referenced starts only: a block whose flow falls into the middle of
            # another function's body - a switch case ending in the shared tail an earlier case had taken into its
            # FUN_ - gets no function of its own (CreateFunctionCmd refuses the overlap), and a split tail between
            # two small functions (uprv_malloc's `lea zeroMem` between a dead jmp made a thunk and the epilogue made
            # FUN_) neither. The tenth boot (2026-10-30, 23:16, the full dump) died on such a block: the second case
            # of UnicodeSet::_appendToPat, whose call to PatternProps::isWhiteSpace still carried the original's
            # displacement, in our link the middle of Locale::getLocaleCache (pe_compare: 60 call and load targets
            # inside other functions, 8 outside the image, all in such blocks; the census over the .pdata ranges:
            # 47,678 instructions in no function in 3,498 ranges, 67 undefined bytes). Every instruction inside a
            # RUNTIME_FUNCTION's range that lies in no function joins the body of the function at the range's
            # begin (a function made there first when none is: 23 ranges).
            img_ = Image()
            pd_rva, pd_size = img_.pdata
            _per5, public_vas = contributions()
            from ghidra.program.model.address import AddressSet as _AddressSet
            fm, listing = program.getFunctionManager(), program.getListing()
            stats = Counter()
            tx = program.startTransaction("orphan instructions into their functions")
            try:
                n = pd_size // 12
                for k in range(n):
                    b, e, _u = img_.unpack("<III", pd_rva + 12 * k)
                    if e <= b:
                        continue
                    lo, hi = A(BASE + b), A(BASE + e - 1)
                    f = fm.getFunctionContaining(lo)
                    if f is None:
                        if listing.getInstructionAt(lo) is None or not CreateFunctionCmd(lo).applyTo(program, monitor):
                            stats["no function at begin, none made"] += 1
                            continue
                        f = fm.getFunctionAt(lo)
                        if f is None:
                            stats["no function at begin, none made"] += 1
                            continue
                        if f.getName().startswith("FUN_") and (BASE + b) not in public_vas:
                            f.setName(f"FUN_{BASE + b:x}@local@{BASE + b:x}", SourceType.USER_DEFINED)
                        stats["made at begin"] += 1
                    body = f.getBody()
                    if body.contains(lo, hi):
                        continue
                    rest = _AddressSet(lo, hi).subtract(body)
                    add = _AddressSet()
                    for ins in listing.getInstructions(rest, True):
                        if fm.getFunctionContaining(ins.getMinAddress()) is None:
                            add.add(ins.getMinAddress(), ins.getMaxAddress())
                            stats["instructions adopted"] += 1
                    if add.isEmpty():
                        continue
                    try:
                        f.setBody(body.union(add))
                        stats["functions extended"] += 1
                    except Exception as ex:  # an OverlappingFunctionException would be a bug above
                        stats["setBody refused"] += 1
                        log(f"  setBody refused at {lo}: {ex}")
                    if k and k % 50000 == 0:
                        log(f"  {k:,}/{n:,} ranges: {dict(stats)}")
            finally:
                program.endTransaction(tx, True)
            done("orphans", "; ".join(f"{k_} {v:,}" for k_, v in sorted(stats.items())))

        if stage("imagerel"):
            # The twelfth start (2026-10-31) hung in the world-save load: SQLite's tokenizer read its character-class
            # table through `test byte ptr [rax + rdi + 0x36e1e30], 0x46` - rdi the image base, the displacement the
            # table's RVA in the original - and our link had left that displacement as it was (the table lies
            # elsewhere in ours), so every SQL statement failed ("near \"PR\": syntax error") and the load never
            # completed. Ghidra makes no reference for such an operand (it cannot know rdi holds __ImageBase), and the
            # synthesizer's image-base-relative sink emits ADDR32NB only for an operand that is a referenced target's
            # RVA. A capstone scan of the original's .text: every instruction with a register base (not RIP) and a
            # 32-bit displacement that lies in a data section's RVA range is such a lookup (585 sites, 194 tables;
            # a structure offset of 44 MB and more is no offset); 141 of them had no relocation in our link (SQLite's
            # CtypeMap, aiClass and UpperToLower, opus and zlib tables, the CRT's). Each gets a DATA reference from
            # its instruction to image base + displacement on the memory operand, which the sink turns into the
            # relocation.
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            from capstone import x86 as _x86
            from ghidra.program.model.scalar import Scalar
            from ghidra.program.model.symbol import RefType
            img_ = Image()
            tva_, tsize_, trawptr_, _trs = img_.secs[".text"]
            data_lo = min(va for name, (va, vs, rp, rs) in img_.secs.items() if name != ".text")
            size_of_image = max(va + vs for va, vs, rp, rs in img_.secs.values())
            md_ = Cs(CS_ARCH_X86, CS_MODE_64)
            md_.detail = True
            md_.skipdata = True
            log("  scanning the original's .text for image-base-relative data operands (capstone, a few minutes)")
            sites = []
            for ins in md_.disasm(img_.data[trawptr_:trawptr_ + tsize_], BASE + tva_):
                if ins.id == 0 or ins.disp_size not in (2, 4):
                    continue
                for oi, op in enumerate(ins.operands):
                    if (op.type == _x86.X86_OP_MEM and op.mem.base not in (_x86.X86_REG_RIP, 0)
                            and data_lo <= op.mem.disp < size_of_image):
                        sites.append((ins.address, op.mem.disp))
            log(f"  {len(sites):,} sites, {len(set(d for _, d in sites)):,} tables")
            refman, listing = program.getReferenceManager(), program.getListing()
            stats = Counter()
            tx = program.startTransaction("image-base-relative operand references")
            try:
                for va, disp in sites:
                    ins = listing.getInstructionAt(A(va))
                    if ins is None:
                        stats["no instruction"] += 1
                        continue
                    target = A(BASE + disp)
                    opi = None
                    for i in range(ins.getNumOperands()):
                        if any(isinstance(o, Scalar) and o.getUnsignedValue() == disp for o in ins.getOpObjects(i)):
                            opi = i
                            break
                    if opi is None:
                        stats["no operand with the displacement"] += 1
                        continue
                    if any(r.getToAddress().equals(target) for r in ins.getOperandReferences(opi)):
                        stats["reference present"] += 1
                        continue
                    refman.addMemoryReference(ins.getAddress(), target, RefType.DATA, SourceType.USER_DEFINED, opi)
                    stats["references added"] += 1
            finally:
                program.endTransaction(tx, True)
            done("imagerel", f"{len(sites):,} sites; " + "; ".join(f"{k_} {v:,}" for k_, v in sorted(stats.items())))

        if stage("imageref"):
            # The fourteenth start (2026-10-31, 02:07) reached the ready line, and pe_imagerel.py still found 58
            # sites: such an instruction carries references from Ghidra's own analysis to the table's elements
            # (table + 2, + 4: what a constant index reaches) besides the one imagerel added, and the synthesizer
            # follows the operand's primary reference, the first one made. The reference to the table itself is
            # made primary; a site whose target holds no defined data and no symbol is no table (`lea edx,
            # [r9 + 0x4881d05]`, a hash constant) and loses the reference imagerel gave it.
            from ghidra.program.model.scalar import Scalar
            img_ = Image()
            log("  scanning the original's .text for image-base-relative data operands (capstone, a few minutes)")
            sites = imagerel_sites(img_)
            refman, listing, st_ = program.getReferenceManager(), program.getListing(), program.getSymbolTable()
            stats = Counter()
            tx = program.startTransaction("image-base-relative references primary")
            try:
                for va, disp in sites:
                    ins = listing.getInstructionAt(A(va))
                    if ins is None:
                        stats["no instruction"] += 1
                        continue
                    target = A(BASE + disp)
                    opi = None
                    for i in range(ins.getNumOperands()):
                        if any(isinstance(o, Scalar) and o.getUnsignedValue() == disp for o in ins.getOpObjects(i)):
                            opi = i
                            break
                    if opi is None:
                        stats["no operand with the displacement"] += 1
                        continue
                    exact = [r for r in ins.getOperandReferences(opi) if r.getToAddress().equals(target)]
                    if not exact:
                        stats["no reference to the table"] += 1
                        continue
                    if listing.getDataContaining(target) is None and st_.getPrimarySymbol(target) is None:
                        for r in exact:
                            refman.delete(r)
                        stats["no data at the target, reference removed"] += 1
                        continue
                    if exact[0].isPrimary():
                        stats["primary already"] += 1
                    else:
                        refman.setPrimary(exact[0], True)
                        stats["made primary"] += 1
            finally:
                program.endTransaction(tx, True)
            done("imageref", f"{len(sites):,} sites; " + "; ".join(f"{k_} {v:,}" for k_, v in sorted(stats.items())))

        if stage("orphans2"):
            # After the fourteenth start pe_compare still reached wrong places from eleven publics, PhysX's
            # `InertiaTensorComputer::setBox` among them: its `movss xmm2, [rip + 0xe8dd14]` at +4 kept the
            # original's displacement. Such leaf functions have no .pdata entry, so `orphans` never saw them, and
            # their instructions lie in no Ghidra function. Every instruction of .text in no function (the text
            # block minus every function body, padding runs of int3 / nop left alone) joins the body of the
            # function that contains the instruction before it, else the nearest function before it.
            from ghidra.program.model.address import AddressSet as _AddressSet
            fm, listing = program.getFunctionManager(), program.getListing()
            stats = Counter()
            covered = _AddressSet()
            nf = 0
            for f in fm.getFunctions(True):
                covered.add(f.getBody())
                nf += 1
            rest = text.subtract(covered)
            log(f"  {nf:,} function bodies; {rest.getNumAddresses():,} bytes of .text in no function in {rest.getNumAddressRanges():,} ranges")
            tx = program.startTransaction("orphan instructions outside the .pdata ranges")
            try:
                for rng in rest.getAddressRanges():
                    insns = list(listing.getInstructions(_AddressSet(rng), True))
                    if not insns:
                        stats["ranges without instructions"] += 1
                        continue
                    if all(i.getMnemonicString().upper() in ("INT3", "NOP") for i in insns):
                        stats["padding runs"] += 1
                        continue
                    before = listing.getInstructionBefore(rng.getMinAddress())
                    f = fm.getFunctionContaining(before.getAddress()) if before is not None else None
                    if f is None:
                        it = fm.getFunctions(rng.getMinAddress(), False)
                        f = it.next() if it.hasNext() else None
                    if f is None:
                        stats["no function before"] += 1
                        continue
                    add = _AddressSet()
                    for i in insns:
                        add.add(i.getMinAddress(), i.getMaxAddress())
                    try:
                        f.setBody(f.getBody().union(add))
                        stats["ranges adopted"] += 1
                        stats["instructions adopted"] += len(insns)
                    except Exception as ex:
                        stats["setBody refused"] += 1
                        log(f"  setBody refused at {rng.getMinAddress()}: {ex}")
            finally:
                program.endTransaction(tx, True)
            done("orphans2", "; ".join(f"{k_} {v:,}" for k_, v in sorted(stats.items())))
    finally:
        project.close()


ALIGN16, ALIGN4, ALIGN_MASK = 0x00500000, 0x00300000, 0x00F00000  # IMAGE_SCN_ALIGN_16BYTES / _4BYTES


def align_sections(path):
    """The alignment bits in an exported object's section headers: the delinker sets none, and the linker then
    placed the 16-byte-padded blobs at any offset - the first C++ initializer's movaps on GlobalVectorConstants
    faulted (2026-10-30, the fourth boot). 16 for every section but .pdata (12-byte entries: 4) and .comment."""
    d = bytearray(Path(path).read_bytes())
    nsec = struct.unpack_from("<H", d, 2)[0]
    opt = struct.unpack_from("<H", d, 16)[0]
    n = 0
    for i in range(nsec):
        o = 20 + opt + 40 * i
        name = d[o:o + 8].rstrip(b"\0")
        if name.startswith(b"/"):  # a long name in the string table: resolved through the symbol table's end
            symtab, nsyms = struct.unpack_from("<II", d, 8)
            strtab = symtab + 18 * nsyms
            k = strtab + int(name[1:])
            name = d[k:d.index(b"\0", k)]
        chars = struct.unpack_from("<I", d, o + 36)[0]
        if name == b".comment":
            continue
        want = ALIGN4 if name == b".pdata" else ALIGN16
        if chars & ALIGN_MASK != want:
            struct.pack_into("<I", d, o + 36, (chars & ~ALIGN_MASK) | want)
            n += 1
    if n:
        Path(path).write_bytes(d)
    return n


def export(a):
    copy_dir, out = Path(a.copy), Path(a.out)
    state = load_state(copy_dir)
    missing = [s for s in STAGES if s not in state["done"]]
    if missing:
        sys.exit(f"prepare first: stages {missing} not done")
    mods = modules()
    per, _publics = contributions()
    # The PDB's .pdata contributions do not describe a module's own functions (7.3% do, server-wide; PrimalRaft's 642
    # are other modules' entries): the linker sorts .pdata by BeginAddress and records the contributions in module
    # order. A module's .pdata is therefore the entries whose BeginAddress lies in its code ranges (2026-10-30, P2c).
    img = Image()
    pd_rva, pd_size = img.pdata
    entries = sorted((img.u32(e), e) for e in range(pd_rva, pd_rva + pd_size, 12))  # (BeginAddress, entry rva)
    begins = [b for b, _e in entries]
    pva, pvs, _, _ = img.secs[".pdata"]
    tva, tsize, _, _ = img.secs[".text"]

    dva, dvs, _, _ = img.secs[".data"]
    extra = defaultdict(list)  # modi -> [(va, size)]: the referenced gaps between contributions (below)

    def own_ranges(contribs, name="", modi=None):
        """The module's contributions with its .pdata replaced by the entries of its own functions: [(va, size)]."""
        if name == "* Linker *":
            contribs = [(va, size) for va, size in contribs if dva <= va - BASE < dva + dvs]
        contribs = list(contribs) + extra.get(modi, [])
        out = [(va, size) for va, size in contribs if not pva <= va - BASE < pva + pvs]
        for va, size in contribs:
            rva = va - BASE
            if tva <= rva < tva + tsize:
                i = bisect.bisect_left(begins, rva)
                while i < len(entries) and begins[i] < rva + size:
                    out.append((BASE + entries[i][1], 12))
                    i += 1
        return sorted(set(out))

    pat = re.compile(a.modules) if a.modules else None
    out.mkdir(parents=True, exist_ok=True)
    manifest = out / "manifest.tsv"
    have = {}
    if manifest.exists():
        lines = manifest.read_text(encoding="utf-8").splitlines()
        if a.redo and pat:
            # the matching rows dropped from the manifest, so that their modules are exported again
            keep = [lines[0]] + [l for l in lines[1:] if not pat.search(l.split("\t")[2])]
            manifest.write_text("\n".join(keep) + "\n", encoding="utf-8")
            lines = keep
        for line in lines[1:]:
            f = line.split("\t")
            if f[8].startswith("ok"):  # a failed row is tried again
                have[int(f[0])] = f
    else:
        manifest.write_text("modi\tkind\tmodule\tobj\tbytes\tranges\tsections\trelocs\tresult\n", encoding="utf-8")
    jobs = []
    used = set(f[3] for f in have.values())
    for modi in sorted(mods):
        name, objp = mods[modi]
        kind = kind_of(name, objp)
        if kind in ("import", "linker") or modi in have or modi not in per:
            continue
        if pat and not pat.search(name):
            continue
        base = name.strip("* ") if name.startswith("* ") else Path(name).name
        rel = Path(kind) / (Path(objp).stem if kind == "lib" else "") / base
        if not str(rel).endswith(".obj"):
            rel = rel.with_name(rel.name + ".obj")
        if str(rel) in used:
            rel = rel.with_name(f"{rel.stem}~{modi}{rel.suffix}")
        used.add(str(rel))
        jobs.append((modi, kind, name, rel))
    if a.limit:
        jobs = jobs[:a.limit]
    log(f"{len(jobs)} modules to export ({len(have)} in the manifest already) -> {out}")
    if not jobs:
        return
    launch(a.heap)
    from ghidra.base.project import GhidraProject
    from ghidra.app.util.exporter import Exporter
    from ghidra.program.model.address import AddressSet
    from ghidra.util.classfinder import ClassSearcher
    from ghidra.util.task import ConsoleTaskMonitor
    from java.io import File
    from func_match import Coff

    exporters = [e for e in ClassSearcher.getInstances(Exporter) if e.getName() == "COFF relocatable object"]
    if not exporters:
        sys.exit("the delinker extension did not load (no COFF relocatable object exporter)")
    exp = exporters[0]
    monitor = ConsoleTaskMonitor()
    project = GhidraProject.openProject(str(copy_dir), PROJECT_NAME, True)
    tx = None
    try:
        program = project.openProgram("/", PROGRAM, True)
        space = program.getAddressFactory().getDefaultAddressSpace()
        opts = exp.getOptions(lambda: program)
        for o in opts:
            if o.getName() == "Give dynamic symbols static visibility":
                # off (2026-10-30, P2c): identical-code folding shares UNWIND_INFOs, unwind maps and such between
                # modules (76,469 shared UNWIND_INFO uses), and Ghidra's default labels on them (UNWIND_INFO_<va>,
                # UnwindMapEntry_ARRAY_<va>) must resolve across objects in a relink; the names are unique by address
                o.setValue(False)
                log(f"  option {o.getName()} = {o.getValue()}")
            if o.getName() == "Trim superfluous PC-relative relocations":
                # off: a reference whose target lies in the same exported section would otherwise lose its
                # relocation and get its displacement rewritten to the packed layout's distance (a module's
                # contributions are packed without their gaps) - the bytes then differ from the original's and
                # the judge cannot name the target; with every PC-relative site a relocation, the linker resolves
                # them and the bytes stay the original's
                o.setValue(bool(a.trim_pc_relative))
                log(f"  option {o.getName()} = {o.getValue()}")
        exp.setOptions(opts)
        # The gaps between the data contributions (35,572, mostly alignment) hold 17 referenced addresses that no
        # module's record covers (an 8-byte static of CoreUObject unit 1 in the gap after its 16-byte contribution,
        # a constant 31 modules share): each such gap goes to the module referring to it, the lowest-numbered when
        # several do, and the others reach it as an external by Ghidra's default name (2026-10-30, the second link).
        owner_starts = sorted((va, size, m) for m, cs in per.items() for va, size in cs)
        owner_keys = [va for va, _s, _m in owner_starts]

        def modi_of(va):
            i = bisect.bisect_right(owner_keys, va) - 1
            if i >= 0 and va < owner_starts[i][0] + owner_starts[i][1]:
                return owner_starts[i][2]
            return None

        gaps = AddressSet()
        gap_of = {}
        for (va, size, _m), (nxt, _s2, _m2) in zip(owner_starts, owner_starts[1:]):
            end = va + size
            if end < nxt and not (tva <= va - BASE < tva + tsize):
                gaps.add(space.getAddress(end), space.getAddress(nxt - 1))
                gap_of[end] = (end, nxt - end)
        gap_keys = sorted(gap_of)
        refman = program.getReferenceManager()
        it = refman.getReferenceDestinationIterator(gaps, True)
        taken = {}
        while it.hasNext():
            to = it.next().getOffset()
            g = gap_of[gap_keys[bisect.bisect_right(gap_keys, to) - 1]]
            owners = sorted(m for m in (modi_of(r.getFromAddress().getOffset()) for r in refman.getReferencesTo(space.getAddress(to))) if m is not None)
            if owners and g not in taken:
                taken[g] = owners[0]
                extra[owners[0]].append(g)
        log(f"  {len(taken)} referenced gaps between contributions given to their referring modules")
        # The delinker's relocation table lives in memory (a singleton per program, never saved), so the synthesizer
        # runs here per module, in a transaction that is rolled back at the end (nothing of it is saved).
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
        aam = AutoAnalysisManager.getAnalysisManager(program)
        syn = aam.getAnalyzer("Relocation table synthesizer")
        if syn is None:
            sys.exit("no Relocation table synthesizer analyzer: the delinker extension did not load")
        tx = program.startTransaction("synthesis (not saved)")
        if a.synth == "whole":
            # once over the program (~29 min on the server), then every export costs about a second; per module the
            # synthesizer takes ~30 s each (PrimalRaft: synth 31.6 s, export 0.9 s)
            ts = time.time()
            aam.scheduleOneTimeAnalysis(syn, program.getMemory())
            aam.startAnalysis(monitor)
            log(f"relocation synthesizer over the whole program: {time.time() - ts:.0f} s")
        # P2d (2026-10-31): the functions our object provides in the hybrid link leave the module's export - their
        # bodies, and the .pdata entries that begin at them (the leftover object then references them as externals)
        excluded_bodies, excluded_entries = AddressSet(), set()
        if a.exclude:
            fm_, st_ = program.getFunctionManager(), program.getSymbolTable()
            names = [ln.strip() for ln in Path(a.exclude).read_text(encoding="utf-8").splitlines() if ln.strip()]
            nf = 0
            for nm in names:
                for sym in st_.getGlobalSymbols(nm):
                    f = fm_.getFunctionAt(sym.getAddress())
                    if f is not None:
                        excluded_bodies.add(f.getBody())
                        excluded_entries.add(f.getEntryPoint().getOffset() - BASE)
                        nf += 1
            log(f"  --exclude: {nf} of {len(names)} names are functions; {excluded_bodies.getNumAddresses():,} bytes left out")
        t0 = time.time()
        with open(manifest, "a", encoding="utf-8") as mf:
            for i, (modi, kind, name, rel) in enumerate(jobs, 1):
                aset = AddressSet()
                nbytes = 0
                ranges = own_ranges(per[modi], name, modi)
                if excluded_entries:
                    # every .pdata entry that begins inside an excluded body - the function's own and its funclets'
                    # and chained entries' (an entry left behind made the linker refuse the object: LNK1223)
                    ranges = [(va, size) for va, size in ranges
                              if not (size == 12 and pva <= va - BASE < pva + pvs
                                      and excluded_bodies.contains(space.getAddress(BASE + img.u32(va - BASE))))]
                for va, size in ranges:
                    aset.add(space.getAddress(va), space.getAddress(va + size - 1))
                    nbytes += size
                if not excluded_bodies.isEmpty():
                    aset = aset.subtract(excluded_bodies)
                path = out / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    ts = time.time()
                    if a.synth == "module":
                        aam.scheduleOneTimeAnalysis(syn, aset)
                        aam.startAnalysis(monitor)
                    tsynth = time.time() - ts
                    # The exporter keeps one message log for its lifetime: cleared per module (2026-10-30), else a
                    # module's row shows the first module's messages and a failed module's own are "truncated".
                    mlog = exp.getMessageLog()
                    mlog.clear()
                    ok = exp.export(File(str(path)), program, aset, monitor)
                    texport = time.time() - ts - tsynth
                    full = str(mlog).strip()
                    lines = [ln for ln in full.splitlines() if ln.strip()]
                    # The x86-64 builder cannot encode an 8-bit PC-relative site (a short jump: its target lies in
                    # the same function, the bytes stay as they are) and says so per site; those lines last, counted.
                    short = sum(1 for ln in lines if "RelocationRelativePC width 1 " in ln)
                    rest = [ln for ln in lines if "RelocationRelativePC width 1 " not in ln]
                    if short:
                        rest.append(f"{short} short-jump sites not encodable")
                    msgs = " | ".join(rest)[:300]
                    if not ok:
                        path.with_name(path.name + ".log").write_text(full, encoding="utf-8")
                except Exception as ex:
                    ok, msgs = False, f"exception: {str(ex)[:200]}"
                    tsynth = texport = 0
                    trace = getattr(ex, "stacktrace", None)
                    log("  export failed:", (trace() if callable(trace) else str(ex))[:1500])
                secs = relocs = ""
                if ok and path.exists():
                    align_sections(path)
                    try:
                        c = Coff(str(path))
                        secs = ",".join(f"{s['name']}:{s['size']}" for s in c.sections)
                        relocs = ",".join(f"{s['name']}:{sum(1 for _ in c.relocs(k))}" for k, s in enumerate(c.sections))
                    except Exception as ex:
                        secs = f"unreadable: {str(ex)[:80]}"
                result = "ok" if ok else f"failed {msgs}"
                mf.write(f"{modi}\t{kind}\t{name}\t{rel.as_posix()}\t{nbytes}\t{len(ranges)}\t{secs}\t{relocs}\t{result}\n")
                mf.flush()
                if i % 20 == 0 or i == len(jobs) or i <= 3:
                    log(f"  {i}/{len(jobs)} exported, {(time.time() - t0) / i:.1f} s each (last: synth {tsynth:.1f} s, "
                        f"export {texport:.1f} s), last {rel.name}: {result[:60]}")
    finally:
        if tx is not None:
            program.endTransaction(tx, False)
        project.close()


SUMMARY = re.compile(r"(\d+) functions; in the original (\d+); byte-identical (\d+) .*; line numbers only (\d+)")


def judge(a):
    out = Path(a.out)
    manifest = out / "manifest.tsv"
    rows = [l.split("\t") for l in manifest.read_text(encoding="utf-8").splitlines()[1:]]
    pat = re.compile(a.modules) if a.modules else None
    todo = [r for r in rows if r[8].startswith("ok") and (not pat or pat.search(r[2]))]
    summary = out / "summary.tsv"
    have = set()
    if summary.exists():
        have = {l.split("\t")[0] for l in summary.read_text(encoding="utf-8").splitlines()[1:]}
    else:
        summary.write_text("modi\tkind\tmodule\tfunctions\tfound\tidentical\tlines_only\tMATCH\tMATCH~\tMATCH-L\tDIFF\tSIZE\tMISSING\n",
                           encoding="utf-8")
    if a.redo:
        have = set()
        summary.write_text("modi\tkind\tmodule\tfunctions\tfound\tidentical\tlines_only\tMATCH\tMATCH~\tMATCH-L\tDIFF\tSIZE\tMISSING\n",
                           encoding="utf-8")
    todo = [r for r in todo if r[0] not in have]
    log(f"{len(todo)} objects to judge with {a.jobs} processes")

    def one(r):
        obj = out / r[3]
        res = subprocess.run([PY, "-I", str(TOOLS / "func_match.py"), str(obj), str(PE), "--json", str(obj) + ".match.json"],
                             capture_output=True, text=True, encoding="utf-8", errors="replace")
        m = SUMMARY.search(res.stdout)
        counts = dict(re.findall(r"^\s+(MATCH~?|MATCH-L|DIFF|SIZE|MISSING)\s+(\d+)", res.stdout, re.M))
        return r, m, counts, res.stderr[-300:]

    t0 = time.time()
    tot = Counter()
    with ThreadPoolExecutor(max_workers=a.jobs) as pool, open(summary, "a", encoding="utf-8") as sf:
        futs = [pool.submit(one, r) for r in todo]
        for i, fut in enumerate(as_completed(futs), 1):
            r, m, counts, err = fut.result()
            if not m:
                sf.write(f"{r[0]}\t{r[1]}\t{r[2]}\terror\t\t\t\t\t\t\t\t\t{err.strip()[:120]}\n")
                sf.flush()
                continue
            f, found, ident, lines = (int(x) for x in m.groups())
            sf.write(f"{r[0]}\t{r[1]}\t{r[2]}\t{f}\t{found}\t{ident}\t{lines}\t" +
                     "\t".join(counts.get(k, "0") for k in ("MATCH", "MATCH~", "MATCH-L", "DIFF", "SIZE", "MISSING")) + "\n")
            sf.flush()
            tot["functions"] += f
            tot["found"] += found
            tot["identical"] += ident
            for k, v in counts.items():
                tot[k] += int(v)
            if i % 25 == 0 or i == len(todo):
                log(f"  {i}/{len(todo)} judged, {(time.time() - t0) / i:.1f} s each; so far {tot['identical']:,} of "
                    f"{tot['found']:,} found byte-identical, DIFF {tot['DIFF']:,}, SIZE {tot['SIZE']:,}")
    log("totals", dict(tot))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("usage:")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--copy", default=str(ROOT / "_re" / "ghidra-delink"))
    p.add_argument("--heap", default="6g")
    p.add_argument("--dry-run", action="store_true", help="print the module kinds and the COFF groups; no Ghidra")
    p.add_argument("--copy-only", action="store_true", help="make the project copy and stop (no Ghidra)")
    e = sub.add_parser("export")
    e.add_argument("--copy", default=str(ROOT / "_re" / "ghidra-delink"))
    e.add_argument("--out", default=str(ROOT / "build" / "delink" / "server"))
    e.add_argument("--modules", help="regex on the module path")
    e.add_argument("--heap", default="4g")
    e.add_argument("--limit", type=int, default=0)
    e.add_argument("--exclude", help="P2d: a file of function names (one per line) left out of the export - their "
                   "bodies and .pdata entries - because our own object provides them in the hybrid link")
    e.add_argument("--redo", action="store_true", help="with --modules: export the matching modules again (their "
                   "rows dropped from the manifest first)")
    e.add_argument("--synth", choices=["whole", "module"], default="whole",
                   help="run the relocation synthesizer once over the program (default) or per module (~30 s each)")
    e.add_argument("--trim-pc-relative", action="store_true",
                   help="the exporter's default: drop relocations whose target lies in the same section and rewrite "
                        "the displacement (off here: every PC-relative site keeps its relocation)")
    j = sub.add_parser("judge")
    j.add_argument("--out", default=str(ROOT / "build" / "delink" / "server"))
    j.add_argument("--jobs", type=int, default=4)
    j.add_argument("--modules", help="regex on the module path")
    j.add_argument("--redo", action="store_true", help="judge every object again (the summary is kept otherwise)")
    al = sub.add_parser("align", help="set the section alignment bits in every object of a set already exported")
    al.add_argument("--out", default=str(ROOT / "build" / "delink" / "server"))
    for sp in (p, e, j, al):
        sp.add_argument("--log", help="append the log lines to this file (default build/delink/<command>.log)")
    a = ap.parse_args()
    global LOG_FILE
    LOG_FILE = Path(a.log) if a.log else ROOT / "build" / "delink" / f"{a.cmd}.log"
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    log(f"== {a.cmd} {' '.join(sys.argv[2:])}")
    if a.cmd == "align":
        rows = [l.split("\t") for l in (Path(a.out) / "manifest.tsv").read_text(encoding="utf-8").splitlines()[1:]]
        n = sum(align_sections(Path(a.out) / r[3]) for r in rows if r[8].startswith("ok"))
        log(f"align: {n} section headers set in {len(rows)} objects of {a.out}")
        return
    {"prepare": prepare, "export": export, "judge": judge}[a.cmd](a)


if __name__ == "__main__":
    main()
