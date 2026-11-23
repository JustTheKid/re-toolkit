"""Trace calls inside the linked server (P2c, 2026-10-31): Frida attached to the running ShooterGameServer.exe of a
run root, hooks at functions named in our link's map file (the RVA is the map's VA minus the preferred base), the
arguments and return value of each call printed with the thread id - for a hang the original never has, where a
dump shows only the waiting side (the twelfth start: `FAtlasSaveManager::LoadSync` waiting for a load that
`LoadOperationSql` never completes).

usage: python -I _tools/delink_trace.py <pid> [--map build/delink/link/ShooterGameServer.map] [--log FILE]
                                       SYMBOL[:FMT] ...
  SYMBOL  a name from the map (a prefix is enough when unique); FMT one letter per argument (rcx, rdx, r8, r9):
          p pointer (the default), i int32, s char*, w wchar_t*, W FString& (the array's data pointer, wide),
          and after a colon the return value: :p (default) :i :s (char*) :w; e.g. sqlite3_exec:ps:i
Ctrl-C stops the trace; the process goes on.
"""
import argparse
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = 0x140000000

AGENT = r"""
const base = Process.getModuleByName('ShooterGameServer.exe').base;
const hooks = %HOOKS%;
function rd(kind, p) {
  try {
    if (p.isNull()) return 'null';
    if (kind === 'i') return p.toInt32().toString();
    if (kind === 's') return JSON.stringify(p.readUtf8String());
    if (kind === 'w') return JSON.stringify(p.readUtf16String());
    if (kind === 'W') { const d = p.readPointer(); return d.isNull() ? '""' : JSON.stringify(d.readUtf16String()); }
  } catch (e) { return p.toString() + '?'; }
  return p.toString();
}
for (const h of hooks) {
  Interceptor.attach(base.add(h.rva), {
    onEnter(args) {
      const a = [];
      for (let i = 0; i < h.args.length; i++) a.push(rd(h.args[i], args[i]));
      this.line = h.name + '(' + a.join(', ') + ')';
      send({t: 'enter', tid: this.threadId, line: this.line});
    },
    onLeave(retval) {
      send({t: 'leave', tid: this.threadId, line: this.line + ' = ' + rd(h.ret, retval)});
    }
  });
}
send({t: 'ready', n: hooks.length});
"""


def map_symbols(path):
    syms = {}
    for m in re.finditer(r"^\s*(\d{4}):([0-9a-f]{8})\s+(\S+)\s+([0-9a-f]{16})", Path(path).read_text(encoding="utf-8", errors="replace"), re.M):
        syms.setdefault(m.group(3), int(m.group(4), 16))
    return syms


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pid", type=int)
    ap.add_argument("symbols", nargs="+")
    ap.add_argument("--map", default=str(ROOT / "build" / "delink" / "link" / "ShooterGameServer.map"))
    ap.add_argument("--log")
    a = ap.parse_args()
    syms = map_symbols(a.map)
    hooks = []
    for spec in a.symbols:
        parts = spec.split(":")
        name, fmt, ret = parts[0], (parts[1] if len(parts) > 1 else ""), (parts[2] if len(parts) > 2 else "p")
        va = syms.get(name)
        if va is None:
            cands = [n for n in syms if n.startswith(name)]
            if len(cands) != 1:
                sys.exit(f"{name}: {len(cands)} map names start with it" + (f": {cands[:5]}" if cands else ""))
            name, va = cands[0], syms[cands[0]]
        hooks.append({"name": name[:70], "rva": va - BASE, "args": list(fmt), "ret": ret})
        print(f"hook {va:#x} {name[:90]} args {fmt or '-'} ret {ret}")
    import frida
    import json
    log = open(a.log, "a", encoding="utf-8") if a.log else None

    def out(line):
        line = time.strftime("%H:%M:%S ") + line
        print(line, flush=True)
        if log:
            log.write(line + "\n")
            log.flush()

    session = frida.attach(a.pid)
    script = session.create_script(AGENT.replace("%HOOKS%", json.dumps(hooks)))

    def on_message(msg, _data):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p["t"] == "ready":
                out(f"attached to pid {a.pid}, {p['n']} hooks")
            else:
                out(f"[{p['tid']}] {'>' if p['t'] == 'enter' else '<'} {p['line']}")
        else:
            out(str(msg))

    script.on("message", on_message)
    script.load()
    done = False

    def on_detached(reason, *_):
        nonlocal done
        out(f"detached: {reason}")
        done = True

    session.on("detached", on_detached)
    try:
        while not done:
            time.sleep(0.5)
    except KeyboardInterrupt:
        out("stopped")
        try:
            session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
