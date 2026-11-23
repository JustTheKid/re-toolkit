"""C++ bodies for the server's tiny member functions, read from their machine code: the shapes MSVC gives one-line
functions - return a member, a bit (or its negation), a constant, a global, the first argument; set or clear a bit;
call another function or virtual when a bit is set; forward to another virtual. Members are named from the class's
layout in an abi_diff.py dump (bases flattened), virtual slots from its vtable, call targets from the PDB. A body is
a suggestion for the judge (func_match.py) to prove; None when the code has any other shape.

Usage (library): body(orig, va, cls, dump, params) with orig a func_match.Original; or
  python -I _tools/tiny_bodies.py <original exe> <abi_diff dump.json> <Class> <SRV@va> ...
2026-10-24, phase 4b step 1.11 / phase 4d (batch conversion of decompiled functions).
"""
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from abi_diff import key_methods  # noqa: E402

HEX = r"(0x[0-9a-f]+|\d+)"
MEM = r"\[rcx \+ " + HEX + r"\]"


def num(text):
    return int(text, 0)


def members(dump, cls, base=0):
    """[(offset, bit, name, type)] of a class with its bases' members, offsets from the class's start."""
    out = []
    for m in dump[cls]["members"]:
        if m["base"]:
            if m["name"] in dump:
                out += members(dump, m["name"], base + m["offset"])
        else:
            out.append((base + m["offset"], m["bit"], m["name"], m["type"]))
    return out


def slots(dump, cls):
    """{vtable offset: virtual's name} of a class and its primary bases (the class's own name wins)."""
    out, name = {}, cls
    while name in dump:
        for (m, _k), off in key_methods(dump[name]["methods"]).items():
            out.setdefault(off, m)
        bases = [b for b in dump[name]["members"] if b["base"] and b["offset"] == 0]
        name = bases[0]["name"] if bases else None
    return out


def float_literal(raw):
    """The shortest C++ float literal for 4 bytes: 1500.f, 0.1f."""
    value = struct.unpack("<f", raw)[0]
    for p in range(1, 10):
        text = f"{value:.{p}g}"
        if struct.pack("<f", float(text)) == raw:
            break
    if "e" not in text and "." not in text:
        text += "."
    return text + "f"


class Body:
    """arity(name): the parameter count of one of the class's functions, or None (a forwarded call then passes all
    of the caller's parameters)."""

    def __init__(self, orig, dump, cls, arity=None):
        import capstone
        self.orig, self.cls, self.arity = orig, cls, arity or (lambda _name: None)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.layout = members(dump, cls)
        self.vslots = slots(dump, cls)

    def code(self, va):
        """The function's instructions: up to its PDB size, else up to the int3 padding (64 bytes at most)."""
        orig = self.orig
        orig.symbol_at(0)
        pdb, ct, _name, symbol = orig.dbghelp
        _, sym = symbol()
        disp = ct.c_uint64(0)
        size = sym.Size if pdb.dh.SymFromAddrW(pdb.proc, va, ct.byref(disp), ct.addressof(sym)) and not disp.value \
            else 0
        raw = orig.read(va - orig.image_base, size or 64) or b""
        out = []
        for i in self.md.disasm(raw, va):
            if not size and i.mnemonic == "int3":
                break
            out.append(i)
        return out

    def member(self, off, bit=None):
        """A member's name by its offset (and bit: the bit's absolute position from the storage unit's start)."""
        for moff, mbit, name, _t in self.layout:
            if bit is None and mbit is None and moff == off:
                return name
            if bit is not None and mbit is not None and moff * 8 + mbit == off * 8 + bit:
                return name
        return None

    def bit_of(self, off, mask, width):
        """The member a single-bit mask (or, for and, its complement) names."""
        full = (1 << width) - 1
        for m in (mask, full ^ mask):
            if m and m & (m - 1) == 0:
                return self.member(off, m.bit_length() - 1), m == mask
        return None, None

    def target(self, va):
        """The called function's name, if it is one of this class's (else None: folded into another's code)."""
        name, disp = self.orig.symbol_at(va - self.orig.image_base)
        if name and not disp and name.startswith(self.cls + "::"):
            return name[len(self.cls) + 2:]
        return None

    def body(self, va, params=None, ret="void"):
        ins = self.code(va)
        if not ins:
            return None
        text = "; ".join(f"{i.mnemonic} {i.op_str}".strip() for i in ins)
        rip = {i.address: i.address + i.size for i in ins}

        def call(callee):
            n = self.arity(callee)
            return f"{callee}({', '.join((params or [])[:n] if n is not None else params or [])})"

        def ripref(i, d):
            return rip[i.address] + num(d)

        # return a member
        m = re.fullmatch(r"(?:movss xmm0, dword|movsd xmm0, qword|mov eax, dword|mov rax, qword|movzx eax, byte|"
                         r"mov al, byte) ptr " + MEM + r"; ret", text)
        if m and self.member(num(m.group(1))):
            return f"{{ return {self.member(num(m.group(1)))}; }}"
        # return a bit, or its negation
        m = re.fullmatch(r"(?:mov eax, dword|movzx eax, byte) ptr " + MEM + r"; (?:shr (?:eax|al), " + HEX +
                         r"; )?(not eax; )?and (?:eax|al), 1; ret", text)
        if m:
            name = self.member(num(m.group(1)), num(m.group(2) or "0"))
            if name:
                return f"{{ return {'!' if m.group(3) else ''}{name}; }}"
        # set or clear a bit
        m = re.fullmatch(r"(or|and) (dword|byte) ptr " + MEM + r", " + HEX + r"; ret", text)
        if m:
            name, direct = self.bit_of(num(m.group(3)), num(m.group(4)), 32 if m.group(2) == "dword" else 8)
            if name and direct == (m.group(1) == "or"):
                return f"{{ {name} = {'true' if m.group(1) == 'or' else 'false'}; }}"
        # call a function of the class when a bit is set
        m = re.fullmatch(r"test (dword|byte) ptr " + MEM + r", " + HEX + r"; jne " + HEX + r"; ret", text)
        if m:
            name, direct = self.bit_of(num(m.group(2)), num(m.group(3)), 32 if m.group(1) == "dword" else 8)
            callee = self.target(num(m.group(4)))
            if name and direct and callee:
                return f"{{ if ({name}) {{ {call(callee)}; }} }}"
        # call a virtual when a bit is set (and return false otherwise)
        m = re.fullmatch(r"test (dword|byte) ptr " + MEM + r", " + HEX + r"; je " + HEX +
                         r"; mov rax, qword ptr \[rcx\]; jmp qword ptr \[rax \+ " + HEX + r"\]; (xor al, al; )?ret",
                         text)
        if m:
            name, direct = self.bit_of(num(m.group(2)), num(m.group(3)), 32 if m.group(1) == "dword" else 8)
            callee = self.vslots.get(num(m.group(5)))
            if name and direct and callee:
                if m.group(6):
                    return f"{{ if ({name}) {{ return {call(callee)}; }} return false; }}"
                return f"{{ if ({name}) {{ {call(callee)}; }} }}"
        # forward to another virtual
        m = re.fullmatch(r"mov rax, qword ptr \[rcx\]; jmp qword ptr \[rax \+ " + HEX + r"\]", text)
        if m and self.vslots.get(num(m.group(1))):
            return f"{{ return {call(self.vslots[num(m.group(1))])}; }}"
        # constants, the first argument
        m = re.fullmatch(r"mov eax, " + HEX + r"; ret", text)
        if m:
            return f"{{ return {num(m.group(1))}; }}"
        if text == "or eax, 0xffffffff; ret":
            return "{ return -1; }"
        if text == "xorps xmm0, xmm0; ret":
            return "{ return 0.f; }"
        if text == "mov rax, rdx; ret" and params:
            return f"{{ return {params[0]}; }}"
        m = re.fullmatch(r"movss xmm0, dword ptr \[rip \+ " + HEX + r"\]; ret", text)
        if m:
            raw = self.orig.read(ripref(ins[0], m.group(1)) - self.orig.image_base, 4)
            return f"{{ return {float_literal(raw)}; }}" if raw and len(raw) == 4 else None
        # return a global FVector (12 bytes through the hidden return pointer)
        m = re.fullmatch(r"mov eax, dword ptr \[rip \+ " + HEX + r"\]; movsd xmm0, qword ptr \[rip \+ " + HEX +
                         r"\]; movsd qword ptr \[rdx\], xmm0; mov dword ptr \[rdx \+ 8\], eax; mov rax, rdx; ret", text)
        if m:
            name, disp = self.orig.symbol_at(ripref(ins[1], m.group(2)) - self.orig.image_base)
            if name and not disp and ripref(ins[0], m.group(1)) == ripref(ins[1], m.group(2)) + 8:
                return f"{{ return {name}; }}"
        return None


def main():
    import json
    from func_match import Original
    exe, dump, cls = sys.argv[1:4]
    b = Body(Original(exe, str(Path(__file__).resolve().parent.parent / "_re" / "cache")),
             json.loads(Path(dump).read_text(encoding="utf-8")), cls)
    for a in sys.argv[4:]:
        va = int(a.split("@")[-1], 16)
        print(f"SRV@{va:x}\t{b.body(va, ['Arg0', 'Arg1', 'Arg2'])}")


if __name__ == "__main__":
    main()
