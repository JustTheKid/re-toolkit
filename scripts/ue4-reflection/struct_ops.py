"""Engine structs' C++ parity in one probe: every UScriptStruct::TCppStructOps<T> the server instantiates for a top-level
engine struct (Construct, Destruct, Copy, Identical, Serialize ... - each inlines T's constructor, destructor or
operators), compiled the way UHT's generated code creates them (`new UScriptStruct::TCppStructOps<T>()`) with the
generated unit 4's command line, then judged by name against the server (func_match.py). Structs our tree does not
declare at the game's include set are dropped (up to 14 compile rounds: cl stops after 100 errors).
usage: struct_ops.py [--game] -> build/loop/probe/structops/{structops.cpp,.obj,judge.json,report.txt}

2026-11-07, first run: 621 engine structs with ops in the server, 428 compiled at the game's include set, 11,915 of the
11,984 functions found identical; 37 structs with a differing op. Not real differences: the Core structs whose
TStructOpsTypeTraits specialisations live in CoreUObject's own sources (FBox, FBoxSphereBounds, FIntPoint, FIntRect,
FLinearColor, FVector2D, FDateTime: their Has* answers and the ops they select); the probe does not see them."""
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, r"D:\ATLAS\_tools")
from func_match import Original  # noqa: E402

PY = r"D:\ATLAS\_tools\ghidra-mcp-venv\Scripts\python.exe"
EXE = r"D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe"
W = Path(r"D:\ATLAS\build\loop\probe\structops")
W.mkdir(parents=True, exist_ok=True)
GAME = "--game" in sys.argv

orig = Original(EXE, r"D:\ATLAS\_re\cache")
OPS = re.compile(r"^\?\w+@\?\$TCppStructOps@U(\w+)@@@UScriptStruct@@")
structs = sorted({m.group(1) for n in orig.by_name for m in [OPS.match(n)] if m})
game = set()
for l in open(r"D:\ATLAS\build\loop\all\types.txt", encoding="utf-8"):
    game.add(l.strip())
names = [s for s in structs if (s in game) == GAME]
print(f"{len(structs)} top-level structs with ops in the server; {len(names)} {'game' if GAME else 'engine'} ones")

rsp = Path(r"D:\ATLAS\build\loop\ShooterGame.generated.4.cpp\ShooterGame.generated.4.cpp.rsp").read_text(encoding="utf-8").split("\n")
src = W / "structops.cpp"
obj = W / "structops.obj"


def compile_once(ns):
    src.write_text("// struct ops probe: the PCH stand-in is force-included\n" +
                   "".join(f"void* StructOpsProbe_{n}() {{ return new UScriptStruct::TCppStructOps<{n}>(); }}\n" for n in ns),
                   encoding="utf-8")
    out = []
    for l in rsp:
        s = l.strip()
        if not s:
            continue
        if s.endswith('.cpp"') or s.endswith(".cpp"):
            out.append(f'"{src}"')
        elif s.startswith(("-Fo", "/Fo")):
            out.append(f'-Fo"{obj}"')
        elif s.startswith(("-Yu", "/Yu", "-Fp", "/Fp", "-Yc", "/Yc")):
            continue
        else:
            out.append(s)
    out.append("/bigobj")
    (W / "structops.rsp").write_text("\n".join(out) + "\n", encoding="utf-8")
    bat = W / "structops.bat"
    bat.write_text('@echo off\r\ncall "C:\\Program Files (x86)\\Microsoft Visual Studio 12.0\\VC\\vcvarsall.bat" amd64 >nul\r\n'
                   f'cd /d D:\\UE\\4.5.1\\Engine\\Source\r\ncl @{W / "structops.rsp"}\r\n', encoding="utf-8")
    r = subprocess.run(["cmd", "/c", str(bat)], capture_output=True, text=True, encoding="mbcs", errors="replace")
    txt = r.stdout + r.stderr
    (W / "cl.txt").write_text(txt, encoding="utf-8")
    bad = set()
    lines = src.read_text(encoding="utf-8").split("\n")
    for m in re.finditer(r"structops\.cpp\((\d+)\) : (?:fatal )?error", txt):
        k = int(m.group(1)) - 1
        mm = re.search(r"StructOpsProbe_(\w+)\(", lines[k]) if k < len(lines) else None
        if mm:
            bad.add(mm.group(1))
    # an error inside a template instantiation names the probe line in its "see reference" note
    for m in re.finditer(r"structops\.cpp\((\d+)\) : see reference", txt):
        k = int(m.group(1)) - 1
        mm = re.search(r"StructOpsProbe_(\w+)\(", lines[k]) if k < len(lines) else None
        if mm and " error " in txt:
            bad.add(mm.group(1))
    return txt, bad


dropped = set()
for rnd in range(14):
    txt, bad = compile_once([n for n in names if n not in dropped])
    errs = len(re.findall(r" error C\d+", txt))
    print(f"compile round {rnd + 1}: {errs} errors, {len(bad)} structs to drop")
    if not errs:
        break
    if not bad:
        print(txt[-3000:])
        sys.exit(1)
    dropped |= bad
kept = [n for n in names if n not in dropped]
print(f"compiled {len(kept)}; dropped {len(dropped)}")
r = subprocess.run([PY, "-I", r"D:\ATLAS\_tools\func_match.py", str(obj), EXE, "--names", r"TCppStructOps@",
                    "--json", str(W / "judge.json")], capture_output=True, text=True, encoding="utf-8", errors="replace")
print(r.stdout.strip().split("\n")[-8:] if r.stdout else r.stderr[-2000:])
res = json.load(open(W / "judge.json", encoding="utf-8"))
rows = res if isinstance(res, list) else res.get("results", res)
by_struct = defaultdict(dict)
for x in rows:
    m = re.match(r"^\?(\w+)@\?\$TCppStructOps@U(\w+)@@@", x["name"])
    if m:
        by_struct[m.group(2)][m.group(1)] = x["state"]
bad_structs = {s: {f: st for f, st in fs.items() if not st.startswith("MATCH") and st != "MISSING"}
               for s, fs in by_struct.items()}
bad_structs = {s: v for s, v in bad_structs.items() if v}
per_fn = Counter((f, st) for fs in by_struct.values() for f, st in fs.items())
with open(W / "report.txt", "w", encoding="utf-8") as f:
    f.write(f"structs compiled {len(kept)}, dropped {len(dropped)}: {sorted(dropped)}\n\n")
    for (fn, st), c in sorted(per_fn.items()):
        f.write(f"{fn:24s} {st:8s} {c}\n")
    f.write("\nstructs with a differing op:\n")
    for s in sorted(bad_structs):
        f.write(f"{s}: {bad_structs[s]}\n")
print(f"structs with a differing op: {len(bad_structs)} of {len(by_struct)}; report {W / 'report.txt'}")
