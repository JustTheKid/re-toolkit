"""unit_probe.py <Unit.cpp> <probe.cpp> [--variants N] [--show]: try source variants of a unit's functions with the unit's
own command line, through its precompiled header (a probe compiles in seconds, the whole unit in minutes). The probe file
defines the real functions (a member of the unit's class again, in its own translation unit) and picks its variant with
`#if PROBE == 1 ... #elif PROBE == 2 ...`; each variant is compiled with -DPROBE=<k> into build/loop/<unit>/probe<k>.obj
and every function of the probe that the original has by its decorated name is judged (func_match.compare, as the judge
does): one line per function and variant - the verdict and the first differing byte. --show disassembles the variants'
DIFFs (disasm_obj.py). The unit must have been built once (its .rsp and .pch), and not be building: a probe reads the
unit's .pch, which the unit's build rewrites. --tag names the probe's files, so probes run side by side. 2026-11-08 (P6, the eighteenth unit
PrimalRaft.cpp: 84 DIFFs, many of one shape).
Usage: python _tools/rebuild/unit_probe.py PrimalRaft.cpp build/loop/PrimalRaft.cpp/probe.cpp --variants 3 [--only APrimalRaft]"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "_tools"
sys.path.insert(0, str(TOOLS))
from func_match import Coff, Original, compare, settle  # noqa: E402

VCVARS = r"C:\Program Files (x86)\Microsoft Visual Studio 12.0\VC\vcvarsall.bat"
EXE = r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe"
CWD = r"D:\UE\4.5.1\Engine\Source"


def build(w, unit, probe, k, tag=""):
    rsp = (w / f"{unit}.rsp").read_text(encoding="utf-8").splitlines()
    out = w / f"probe{tag}{k}.obj"
    args = []
    for l in rsp:
        if l.startswith("-Fo"):
            l = f'-Fo"{out}"'
        elif l.startswith('"') and l.rstrip('"').lower().endswith(".cpp"):
            l = f'"{probe}"'
        args.append(l)
    args.insert(len(args) - 1, f"-DPROBE={k}")
    prsp = w / f"probe{tag}{k}.rsp"
    prsp.write_text("\n".join(args) + "\n", encoding="utf-8")
    cmd = f'"{VCVARS}" amd64 >nul && cl @"{prsp}"'
    r = subprocess.run(f'cmd /s /c "{cmd}"', cwd=CWD, capture_output=True, text=True, errors="replace")
    errs = [l for l in (r.stdout + r.stderr).splitlines() if " error " in l or "fatal error" in l]
    if r.returncode != 0:
        print(f"variant {k}: cl exit {r.returncode}")
        for e in errs[:8]:
            print("   ", e.strip()[:200])
        return None
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("unit")
    ap.add_argument("probe")
    ap.add_argument("--variants", type=int, default=1)
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--tag", default="", help="a name in the probe's files (probe<tag><k>.obj, probe_funcs<tag>.cpp): probes run side by side")
    ap.add_argument("--only", help="a regex on the decorated names to judge (default: all the original has by name)")
    ap.add_argument("--funcs", help="SRV@<va>,...: instead of a probe file, these functions' blocks from the port (the unit's "
                    "Private/<Unit.cpp>, merged by unit_fill.py) after the unit's prelude - a re-judge of edited bodies "
                    "without the whole unit's build (give '-' as the probe)")
    a = ap.parse_args()
    w = ROOT / "build" / "loop" / a.unit
    if a.funcs:
        port = (ROOT / "src" / "reimpl" / "ShooterGame" / "Source" / "ShooterGame" / "Private" / a.unit).read_text(encoding="utf-8")
        # a block starts at an ID line after a blank line (a lambda's ID line sits inside its host's header block)
        heads = [m.start() + 2 for m in re.finditer(r"\n\n// ATLAS-ID: SRV@[0-9a-f]+ ", port)]
        blocks = []
        for va in a.funcs.split(","):
            va = va.strip().lower().replace("srv@", "")
            i = port.find(f"// ATLAS-ID: SRV@{va} ")
            if i < 0:
                sys.exit(f"no block SRV@{va} in the port")
            nxt = [h for h in heads if h > i]
            blocks.append(port[i:nxt[0] if nxt else len(port)])
        probe = w / f"probe_funcs{a.tag}.cpp"
        prelude = (w / "prelude.cpp").resolve()
        probe.write_text(f'#include "{prelude}"\n\n' + "\n".join(blocks), encoding="utf-8")
    else:
        probe = Path(a.probe).resolve()
    orig = Original(EXE, str(ROOT / "_re" / "cache"))
    for k in range(1, a.variants + 1):
        out = build(w, a.unit, probe, k, a.tag)
        if out is None:
            continue
        obj = Coff(str(out))
        funcs = {f[0]: f[1:] for f in obj.functions()}
        for name in sorted(funcs):
            if orig.by_name.get(name) is None:  # the original has no function of that name: an inline the probe emits
                continue
            if a.only and not re.search(a.only, name):
                continue
            state, info = settle(*compare(obj, orig, name, *funcs[name]), {})
            first = info.get("first", "") if isinstance(info, dict) else ""
            print(f"variant {k}: {state:8} {('+' + str(first)) if first != '' else '':6} {name[:110]}")
            if a.show and state == "DIFF":
                subprocess.run([sys.executable, str(TOOLS / "disasm_obj.py"), str(out), name], cwd=ROOT)


if __name__ == "__main__":
    main()
