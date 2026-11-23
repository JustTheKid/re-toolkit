"""disasm_obj.py <obj> <name substring> [<name substring> ...]: disassemble our COFF object's function (its COMDAT
section) with the relocation targets named, next to the original's function of the same decorated name with its call,
jump and RIP-relative targets named through the PDB, the first differing byte marked (*). The judge's DIFF read in
one screen; `--ours-only` / `--theirs-only` for one column. Uses func_match.Coff and Original. 2026-10-31."""
import struct
import sys

sys.path.insert(0, r"D:\ATLAS\_tools")
from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402
from func_match import REPO, Coff, Original  # noqa: E402

EXE = r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe"
args = [a for a in sys.argv[1:] if not a.startswith("--")]
flags = {a for a in sys.argv[1:] if a.startswith("--")}
# --at=0x<va>: the original's function is at this address (one without a public name: a lambda's operator(), a
# static), instead of the one the decorated name finds
AT = next((int(f.split("=", 1)[1], 16) for f in flags if f.startswith("--at=")), None)
obj = Coff(args[0])
orig = Original(EXE, str(REPO / "_re" / "cache"))
IMAGE_BASE = 0x140000000
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False


def relocs_of(sec):
    s = obj.sections[sec]
    out = []
    for i in range(s["nrel"]):
        o = s["relptr"] + 10 * i
        va, symi, typ = struct.unpack_from("<IIH", obj.data, o)
        out.append((va, symi, typ))
    return out


def short(name):
    return name[:46] if name else "?"


def name_at(va):
    names, delta = orig.names_at(va - IMAGE_BASE)
    if not names:
        return None
    return short(names[0]) + (f"+0x{delta:x}" if delta else "")


def func_size(va):
    """The original function's size from the PDB cache (funcs.size); None when unknown."""
    import sqlite3
    try:
        c = sqlite3.connect(str(REPO / "_re" / "cache" / "ShooterGameServer.locals.sqlite"))
        row = c.execute("select size from funcs where va=?", (va,)).fetchone()
        return row[0] if row else None
    except sqlite3.Error:
        return None


def show_ours(code, relmap):
    lines = []
    for ins in md.disasm(code, 0):
        tag = ""
        for off in range(ins.address, ins.address + ins.size):
            if off in relmap:
                tag = "  ; " + relmap[off]
                break
        lines.append((ins.address, f"{ins.address:4x}  {ins.mnemonic} {ins.op_str}".ljust(46) + tag))
    return lines


def show_theirs(code, va):
    lines = []
    for ins in md.disasm(code, va):
        tag = ""
        op = ins.op_str
        if ins.mnemonic in ("call", "jmp") and op.startswith("0x"):
            n = name_at(int(op, 16))
            if n:
                tag = "  ; " + n
        elif "rip + 0x" in op or "rip - 0x" in op:
            i = op.index("rip")
            j = op.index("]", i)
            expr = op[i + 3:j].replace(" ", "")
            disp = int(expr[1:], 16) * (1 if expr[0] == "+" else -1)
            n = name_at(ins.address + ins.size + disp)
            if n:
                tag = "  ; " + n
        off = ins.address - va
        lines.append((off, f"{off:4x}  {ins.mnemonic} {ins.op_str}".ljust(46) + tag))
    return lines


for want in args[1:]:
    # externals, and the statics a lambda's operator() and other local functions are (class 3)
    cands = [(i, s) for i, s in enumerate(obj.symbols) if s and s["sec"] > 0 and s["cls"] in (2, 3) and want in s["name"]]
    if not cands:
        print("no external symbol matching", want)
        continue
    symi, sym = cands[0]
    sec = obj.sections[sym["sec"] - 1]
    code = obj.data[sec["raw"]:sec["raw"] + sec["size"]][sym["value"]:]
    relmap = {}
    for va, ri, typ in relocs_of(sym["sec"] - 1):
        rs = obj.symbols[ri]
        relmap[va - sym["value"]] = short(rs["name"] if rs else "?")
    rva = (AT - IMAGE_BASE) if AT is not None else orig.by_name.get(sym["name"])
    size = func_size(IMAGE_BASE + rva) if rva is not None else None
    theirs_code = orig.read(rva, max(size or 0, len(code) + 64)) if rva is not None else b""
    ours = show_ours(code, relmap)
    theirs = show_theirs(theirs_code[:size] if size else theirs_code, IMAGE_BASE + rva) if theirs_code else []
    first = next((i for i in range(min(len(code), len(theirs_code))) if code[i] != theirs_code[i]), None)
    print(f"=== {sym['name']}\n    ours {len(code)} bytes; theirs {size or '?'} bytes @{hex(IMAGE_BASE + rva) if rva is not None else '?'}; first differing byte: {first}")
    if "--ours-only" in flags:
        for _, l in ours:
            print("   ", l)
        continue
    if "--theirs-only" in flags:
        for _, l in theirs:
            print("   ", l)
        continue
    n = max(len(ours), len(theirs))
    for k in range(n):
        a = ours[k][1] if k < len(ours) else ""
        b = theirs[k][1] if k < len(theirs) else ""
        mark = "*" if (k < len(ours) and first is not None and ours[k][0] <= first < (ours[k + 1][0] if k + 1 < len(ours) else 1 << 30)) else " "
        print(f"{mark} {a[:92]:92} | {b[:88]}")
