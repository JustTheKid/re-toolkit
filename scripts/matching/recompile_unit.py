"""Compile one of our source files the way ATLAS compiled the matching compile unit: ATLAS's own command line is read
from the original PDB (pdb_buildinfo.py: flags, defines, include paths in order), its paths are mapped onto our trees,
the precompiled-header switches are dropped (-Yu / -Fp; the header stays force-included with -FI, so the code is the
same), and the VS2013 Update 5 compiler ATLAS used builds the object. The object is what the byte-matching judge
(func_match.py) compares with ATLAS's binary.

Usage: python -I _tools/recompile_unit.py <original pe> <compile unit regex> --out <dir> [--source <our file>]
           [--map ATLAS_PREFIX=OUR_PREFIX ...] [--define NAME=VALUE ...] [--dry-run]
  Default maps: d:\\atlassvn\\engine\\ -> D:\\UE\\4.5.1\\Engine\\, ATLAS's server Inc folder -> our
  Engine\\Intermediate\\Build\\Win64\\Inc\\, and PhysX 3.4's include folders -> our PhysX 3.3 ones (until step 11).
  --define adds or overrides a define (e.g. to test what a mismatch depends on).
Writes <out>/<unit>.obj, <out>/<unit>.rsp and <out>/<unit>.log; exit code is cl.exe's.
2026-10-24 (phase 4d pipeline, calibration on Engine.generated.1.cpp).
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pdb_buildinfo  # noqa: E402

VCVARS = r"C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat"
ENGINE = r"D:\UE\4.5.1\Engine" + "\\"
MAPS = [
    ("d:\\atlassvn\\projects\\shootergame\\intermediate\\build\\win64\\shootergameserver\\inc\\",
     ENGINE + "Intermediate\\Build\\Win64\\Inc\\"),
    ("d:\\atlassvn\\engine\\source\\thirdparty\\physx\\physx_3.4\\include", ENGINE + "Source\\ThirdParty\\PhysX\\PhysX-3.3\\include"),
    ("d:\\atlassvn\\engine\\source\\thirdparty\\physx\\pxshared\\include", ENGINE + "Source\\ThirdParty\\PhysX\\PhysX-3.3\\include"),
    ("d:\\atlassvn\\engine\\", ENGINE),
]


def split_args(text):
    """Split a cl.exe argument string: spaces separate arguments except inside double quotes; \\" is a literal quote
    (ATLAS's -DORIGINAL_FILE_NAME=\\"ShooterGameServer.exe\\") and does not open or close one."""
    args, cur, quoted, i = [], [], False, 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text) and text[i + 1] == '"':
            cur.append('\\"')
            i += 2
            continue
        if c == '"':
            quoted = not quoted
            cur.append(c)
        elif c.isspace() and not quoted:
            if cur:
                args.append("".join(cur))
                cur = []
        else:
            cur.append(c)
        i += 1
    if cur:
        args.append("".join(cur))
    return args


def map_path(text, maps):
    low = text.lower()
    for a, b in maps:
        i = low.find(a)
        if i >= 0:
            return text[:i] + b + text[i + len(a):]
    return text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("unit")
    ap.add_argument("--out", required=True)
    ap.add_argument("--source")
    ap.add_argument("--map", action="append", default=[])
    ap.add_argument("--define", action="append", default=[])
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--pch", action="store_true",
                    help="build the unit's precompiled header first (-Yc on the force-included header, as UBT did) and "
                         "compile the unit through it (-Yu / -Fp), instead of dropping those switches")
    a = ap.parse_args()
    maps = [tuple(m.split("=", 1)) for m in a.map] + MAPS
    maps = [(x.lower(), y) for x, y in maps]
    pdb = Path(a.binary).with_suffix(".pdb")
    pat = re.compile(a.unit, re.I)
    hits = [(i, o) for i, o in pdb_buildinfo.modules(pdb) if pat.search(o)]
    if len(hits) != 1:
        sys.exit(f"{len(hits)} compile units match; make the pattern unique")
    modi, obj = hits[0]
    info = pdb_buildinfo.build_info(pdb, pdb_buildinfo.build_id(pdb, modi))
    unit = re.split(r"[\\/]", obj)[-1].removesuffix(".obj")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    args = []
    overrides = {d.split("=", 1)[0]: d for d in a.define}
    for arg in split_args(info["args"]):
        if arg[:3] in ("-Yu", "-Fp") or arg[:3] in ("/Yu", "/Fp"):
            continue
        if arg[:2] in ("-D", "/D"):
            name = arg[2:].split("=", 1)[0]
            if name in overrides:
                arg = "-D" + overrides.pop(name)
        if arg[:2] in ("-I", "/I", "-F") and len(arg) > 3:
            q = arg[2:].strip('"') if arg[:3] != "-FI" else arg[3:].strip('"')
            head = arg[:3] if arg[:3] == "-FI" else arg[:2]
            arg = f'{head}"{map_path(q, maps)}"'
        args.append(arg)
    args += ["-D" + d for d in overrides.values()]
    source = a.source or map_path(info["source"], maps)
    cwd = map_path(info["cwd"], maps)
    pch_args = None
    if a.pch:
        # the header ATLAS precompiled is the force-included one; -Yu must name it exactly as -FI does. The PCH's own
        # source is an empty file: -Yc stops the PCH at the end of the forced include, as UBT's wrapper did
        # (2026-10-31, the Redis unit: dllimport inline functions and frame shapes differed without the PCH)
        fi = next((x for x in args if x.startswith("-FI")), None)
        if fi is None:
            sys.exit("--pch needs a force-included header (-FI) on the unit's command line")
        pch = out / (unit + ".pch")
        pch_src = out / "pch.cpp"
        pch_src.write_text("// the precompiled header's source: empty, the header is force-included (recompile_unit.py --pch)\n",
                           encoding="utf-8")
        pch_args = args + [f'-Yc{fi[3:]}', f'-Fp"{pch}"', f'-Fo"{out / "pch.obj"}"', f'"{pch_src}"']
        args += [f'-Yu{fi[3:]}', f'-Fp"{pch}"']
    args += [f'-Fo"{out / (unit + ".obj")}"', f'"{source}"']
    rsp = out / (unit + ".rsp")
    rsp.write_text("\n".join(args) + "\n", encoding="utf-8")
    print(f"unit {obj}\nsource {source}\ncwd {cwd}\nresponse file {rsp} ({len(args)} arguments)")
    if a.dry_run:
        return
    log = out / (unit + ".log")
    if pch_args is not None:
        prsp = out / (unit + ".pch.rsp")
        prsp.write_text("\n".join(pch_args) + "\n", encoding="utf-8")
        cmd = f'"{VCVARS}" amd64 >nul && cl @"{prsp}"'
        r = subprocess.run(f'cmd /s /c "{cmd}"', cwd=cwd, capture_output=True, text=True, errors="replace")
        plog = out / (unit + ".pch.log")
        plog.write_text(r.stdout + r.stderr, encoding="utf-8")
        if r.returncode != 0:
            print(f"pch: cl exit {r.returncode}; log {plog}")
            for e in [l for l in (r.stdout + r.stderr).splitlines() if " error " in l or "fatal error" in l][:15]:
                print("  ", e[:220])
            sys.exit(r.returncode)
        print(f"pch: {pch.name} built")
    cmd = f'"{VCVARS}" amd64 >nul && cl @"{rsp}"'
    # one string, so the quotes reach cmd.exe as written (a list would escape them as \"); /s strips the outer pair
    r = subprocess.run(f'cmd /s /c "{cmd}"', cwd=cwd, capture_output=True, text=True, errors="replace")
    log.write_text(r.stdout + r.stderr, encoding="utf-8")
    errors = [l for l in (r.stdout + r.stderr).splitlines() if " error " in l or "fatal error" in l]
    print(f"cl exit {r.returncode}; {len(errors)} error lines; log {log}")
    for e in errors[:15]:
        print("  ", e[:220])
    sys.exit(r.returncode)


if __name__ == "__main__":
    main()
