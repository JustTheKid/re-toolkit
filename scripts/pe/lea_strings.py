"""List the string operands of each function's RIP-relative LEAs, in code order, from a PE with its PDB.

Ghidra's decompiles of the DevKit's editor DLLs drop LOCTEXT's key: `FInternationalization::
ForUseOnlyByLocMacroAndGraphNodeTextLiterals_CreateText(text, namespace, key)` prints with two arguments, the key in R9
is lost. The code still loads all three with `lea rdx / r8 / r9, [rip+...]`, so this reads them from the bytes: for
each LOCTEXT the lines come as `r9 <key>`, `r8 <namespace>`, `rdx <text>`. With the PDB's line info (`pdb_lookup.py
--lines`) each function also shows its source file and line, i.e. the order of the functions in ATLAS's source file.

Usage: python -I _tools/lea_strings.py <dll> <pattern> [pattern ...]   (patterns as pdb_lookup.py: dbghelp wildcards)
  --ascii  also ASCII strings (style names, FName literals); default UTF-16 only
Step 1.9b, 2026-10-23.
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devkit_metadata import PE  # noqa: E402

# REX prefix and ModRM byte of `lea <reg>, [rip+disp32]`
REG = {(0x48, 0x15): "rdx", (0x4C, 0x05): "r8", (0x4C, 0x0D): "r9", (0x48, 0x0D): "rcx"}


def main():
    args = [a for a in sys.argv[1:] if a != "--ascii"]
    ascii_too = "--ascii" in sys.argv
    dll, patterns = args[0], args[1:]
    pe = PE(dll)
    out = subprocess.run([sys.executable, "-I", str(Path(__file__).with_name("pdb_lookup.py")), dll, *patterns,
                          "--lines"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) < 3 or line.startswith("#"):
            continue
        rva, size = int(f[0], 16) - 0x140000000, int(f[1], 16)  # pdb_lookup prints VAs at image base 0x140000000
        print(f"== {f[2]} {f[-1] if len(f) > 4 else ''}")
        o = pe.off(rva)
        code = pe.b[o:o + size]
        for i in range(len(code) - 7):
            reg = REG.get((code[i], code[i + 2])) if code[i + 1] == 0x8D else None
            if not reg:
                continue
            target = pe.base + rva + i + 7 + int.from_bytes(code[i + 3:i + 7], "little", signed=True)
            s = pe.wstr(target)
            if not s and ascii_too and pe.off(target - pe.base) is not None:
                s = pe.cstr(target - pe.base)
                s = s if s and len(s) > 1 else None
            if s:
                print(f"   {reg:3} {s.encode('ascii', 'replace').decode()}")


if __name__ == "__main__":
    main()
