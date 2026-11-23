"""Bulk-decompile game-code functions into the searchable corpus _re/corpus/<bin>/ (git-ignored).

The corpus is a read-only reference for searching ("where is X used?"); it is NOT the ledger.
A function enters tracking/functions.csv only when it is worked on (atlas-decompile skill).

- Works on a COPY of the Ghidra project (_re/ghidra-bulk or _re/ghidra-client-bulk), made on first run,
  so the main project stays free for MCP and other scripts.
- Resumable: existing output files are skipped; files are written via a temp name, so Ctrl+C never
  leaves a half-written file. Rerun the same command to continue.
- Output: _re/corpus/<bin>/<Class>/<Function>@<va>.c with a one-line provenance header, plus
  _index.tsv (va, symbol, path, lines) and _failed.tsv.

Usage:
  python -I _tools/ghidra_bulk_export.py server [--workers 4] [--limit N] [--timeout 60] [--all]
  python -I _tools/ghidra_bulk_export.py client ...
  --all exports every function, not just game-code classes.
"""
import argparse
import datetime
import os
import re
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "_tools"
os.environ.setdefault("GHIDRA_INSTALL_DIR", str(TOOLS / "ghidra_12.1.4_PUBLIC"))
os.environ.setdefault("JAVA_HOME", str(TOOLS / "jdk-21.0.12.1+1"))

BINS = {
    #          source project dir      name      program                 copy dir                    baseline sha256 prefix
    "server": (ROOT / "_re/ghidra", "atlas", "ShooterGameServer.exe", ROOT / "_re/ghidra-bulk", "d861a989e96dee69"),
    "client": (ROOT / "_re/ghidra-client", "client", "AtlasGame.exe", ROOT / "_re/ghidra-client-bulk", "aac2f353dce7c0d4"),
}
# Same selection that sized the game code at ~49k server functions (2026-10-21).
GAME_CLASS = re.compile(r"^(A|U|F|E)?(Shooter|Primal|Atlas|Seamless|Database|UI_|Tribe|Ship|Dino|Structure|Claim|Trade|"
                        r"Discovery|Treasure|Harvest|Biome|DayCycle|Island|Grid|Raft|Sail|Cannon|Buff|Map)", re.I)
SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def safe(name: str, limit: int = 90) -> str:
    return SAFE.sub("_", name).strip("_")[:limit] or "_"


def ensure_copy(src: Path, name: str, dst: Path):
    if (dst / f"{name}.gpr").exists():
        return
    print(f"copying Ghidra project {src} -> {dst} (one time) ...", flush=True)
    dst.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src / f"{name}.gpr", dst / f"{name}.gpr")
    shutil.copytree(src / f"{name}.rep", dst / f"{name}.rep")


def reindex(out: Path):
    """Rebuild _index.tsv from the corpus files (their first line is '// <symbol> @ <va> | ...')."""
    rows = []
    for path in sorted(out.rglob("*.c")):
        with open(path, encoding="utf-8", errors="replace", newline="") as f:
            first = f.readline()
            lines = 1 + sum(1 for _ in f)
        m = re.match(r"// (.*) @ ([0-9a-f]+) \|", first)
        symbol, va = (m.group(1), m.group(2)) if m else ("?", path.stem.rsplit("@", 1)[-1])
        rows.append((va, symbol, path.relative_to(out).as_posix(), lines - 1))
    with open(out / "_index.tsv", "w", encoding="utf-8") as f:
        for va, symbol, rel, n in sorted(rows):
            f.write(f"{va}\t{symbol}\t{rel}\t{n}\n")
    print(f"reindexed {len(rows)} files -> {out / '_index.tsv'}")


def has_locals(path):
    """Whether a corpus file was exported with the PDB locals block (its header says `pdb-only+locals`)."""
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        return "+locals" in f.readline()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", choices=BINS)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0, help="stop after this many new exports (0 = all)")
    ap.add_argument("--timeout", type=int, default=60, help="decompiler seconds per function")
    ap.add_argument("--all", action="store_true", help="export every function, not only game-code classes")
    ap.add_argument("--reindex", action="store_true",
                    help="rebuild _index.tsv from the corpus files on disk (no Ghidra needed), then exit")
    ap.add_argument("--refresh", action="store_true",
                    help="also re-export files whose header lacks the PDB locals (exported before 2026-10-29); "
                         "run --reindex afterwards")
    args = ap.parse_args()

    src, name, prog, copy_dir, bin_sha = BINS[args.binary]
    out = ROOT / "_re/corpus" / args.binary
    out.mkdir(parents=True, exist_ok=True)
    if args.reindex:
        reindex(out)
        return
    ensure_copy(src, name, copy_dir)

    import pyghidra
    launcher = pyghidra.HeadlessPyGhidraLauncher()
    launcher.add_vmargs("-Xmx6g")
    launcher.start()
    from ghidra.app.decompiler import DecompInterface
    from ghidra.base.project import GhidraProject
    from ghidra.util.task import ConsoleTaskMonitor

    project = GhidraProject.openProject(str(copy_dir), name, True)
    program = project.openProgram("/", prog, True)
    today = datetime.date.today().isoformat()
    # The PDB's parameters and locals over each export (_tools/pdb_locals.py, 2026-10-29); the header says so.
    import sys
    sys.path.insert(0, str(ROOT / "_tools"))
    from pdb_locals import Locals
    loc = Locals.open(prog)
    print("PDB locals: " + (str(loc.path) if loc else f"no index for {prog} (pdb_locals.py build), exporting without"),
          flush=True)

    jobs = []
    for f in program.getFunctionManager().getFunctions(True):
        if f.isThunk() or f.isExternal():
            continue
        full = f.getName(True)
        ns = f.getParentNamespace()
        top = "_global" if ns.isGlobal() else ns.getName(True).lstrip("`").split("::")[0]
        if not args.all and not GAME_CLASS.match(top):
            continue
        va = str(f.getEntryPoint()).lower()
        path = out / safe(top) / f"{safe(f.getName())}@{va}.c"
        if not path.exists() or (args.refresh and loc is not None and not has_locals(path)):
            jobs.append((f, full, va, path))
    if args.limit:
        jobs = jobs[:args.limit]
    print(f"{args.binary}: {len(jobs)} functions to export ({'all' if args.all else 'game code'}), "
          f"{args.workers} workers, timeout {args.timeout}s -> {out}", flush=True)

    local = threading.local()
    lock = threading.Lock()
    index = open(out / "_index.tsv", "a", encoding="utf-8")
    failed = open(out / "_failed.tsv", "a", encoding="utf-8")
    done = fails = 0
    start = time.time()

    def work(job):
        f, full, va, path = job
        if not hasattr(local, "iface"):
            local.iface = DecompInterface()
            local.iface.openProgram(program)
        res = local.iface.decompileFunction(f, args.timeout, ConsoleTaskMonitor())
        if not res.decompileCompleted():
            return job, None, res.getErrorMessage() or "unknown error"
        code = res.getDecompiledFunction().getC()
        tag = "pdb-only"
        if loc is not None:
            code, _ = loc.decorate(code, int(va, 16))
            tag = "pdb-only+locals"
        header = f"// {full} @ {va} | corpus export {today} | ghidra 12.1.4 {tag} | bin sha256 {bin_sha}\n"
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        # newline="": Ghidra already returns CRLF; text-mode translation would double every line break.
        tmp.write_text(header.replace("\n", "\r\n") + code, encoding="utf-8", newline="")
        os.replace(tmp, path)
        return job, code.count("\n"), None

    pool = ThreadPoolExecutor(max_workers=args.workers)
    futures = {pool.submit(work, j): j for j in jobs}
    try:
        for fut in as_completed(futures):
            try:
                job, lines, err = fut.result()
            except Exception as e:  # a Java/decompiler exception counts as one failed function
                job, lines, err = futures[fut], None, f"exception: {e}"
            _, full, va, path = job
            with lock:
                if err:
                    fails += 1
                    failed.write(f"{va}\t{full}\t{err.strip()[:200]}\n")
                else:
                    done += 1
                    index.write(f"{va}\t{full}\t{path.relative_to(out).as_posix()}\t{lines}\n")
                n = done + fails
                if n % 200 == 0 or n == len(jobs):
                    rate = n / max(time.time() - start, 1e-6)
                    eta = (len(jobs) - n) / rate if rate else 0
                    print(f"  {n}/{len(jobs)}  ok {done}  failed {fails}  {rate:.1f}/s  "
                          f"ETA {eta / 3600:.1f} h", flush=True)
                    index.flush()
                    failed.flush()
    except KeyboardInterrupt:
        print("stopping: cancelling queued work, waiting for running decompiles; rerun to resume "
              "(then --reindex if the index looks short)", flush=True)
    finally:
        # Let in-flight decompiles finish before the project closes, or their threads hit "File is closed".
        pool.shutdown(wait=True, cancel_futures=True)
        index.close()
        failed.close()
        project.close()
    print(f"finished: {done} exported, {fails} failed in {(time.time() - start) / 60:.1f} min", flush=True)


if __name__ == "__main__":
    main()
