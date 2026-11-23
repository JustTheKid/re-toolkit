"""Functions ATLAS's server build compiles to a stub while the client build has real code: the same decorated name in
both PDBs, a few bytes in the server (a bare `ret`, `return false / true / 0 / 1`, or a jump to a shared body) and a
real body in the client. Each is a server-build difference in ATLAS's source (`#if UE_SERVER` / `#if !UE_SERVER`
around a body, a dedicated-server constant such as AActor::GetNetMode's NM_DedicatedServer, ...), so the judge
reports our full body as a DIFF until the same guard is in our engine.

Usage: python -I _tools/server_stubs.py <server pe> <client pe> [--max-server 8] [--min-client 32] [--templates]
           [--tsv <out.tsv>] [--top N]
  --templates  keep template instantiations (TCppStructOps<...> alone has ~6,400, mostly editor struct ops)
Output: counts per class, then the stubs with their server bytes decoded (ret / return 0 / return 1 / jmp <name>),
largest client body first; --tsv writes all of them.
2026-10-25 (phase 4b step 1.11: AActor::GetNetMode found this way, the server's `mov eax, 1; ret`).
"""
import argparse
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from func_match import Original  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def decode(o, rva, size):
    b = o.read(rva, size)
    if b[:1] == b"\xc3" or b[:3] == b"\xc2\x00\x00":
        return "ret"
    if b in (b"\x32\xc0\xc3", b"\x33\xc0\xc3"):
        return "return 0 / false"
    if b == b"\xb0\x01\xc3":
        return "return true"
    if len(b) >= 6 and b[0] == 0xB8 and b[5] == 0xC3:
        return f"return {struct.unpack_from('<i', b, 1)[0]}"
    if b[:1] == b"\xe9" and len(b) >= 5:
        t = rva + 5 + struct.unpack_from("<i", b, 1)[0]
        names, off = o.names_at(t)
        return f"jmp {names[0] if names else hex(t)}" + (f"+{off:#x}" if off else "")
    return b.hex()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("server")
    ap.add_argument("client")
    ap.add_argument("--max-server", type=int, default=8)
    ap.add_argument("--min-client", type=int, default=32)
    ap.add_argument("--templates", action="store_true")
    ap.add_argument("--tsv")
    ap.add_argument("--top", type=int, default=60)
    a = ap.parse_args()
    cache = REPO / "_re" / "cache"
    s, c = Original(a.server, cache), Original(a.client, cache)
    hits = []
    for d, rs in s.by_name.items():
        if not d.startswith("?") or d.startswith("??_") or (not a.templates and "?$" in d):
            continue
        rc = c.by_name.get(d)
        ss, cs = s.sizes.get(rs), c.sizes.get(rc) if rc is not None else None
        if ss is None or cs is None or ss > a.max_server or cs < a.min_client:
            continue
        hits.append((d, ss, cs, decode(s, rs, ss), rs + s.image_base))
    hits.sort(key=lambda h: (-h[2], h[0]))
    by_class = Counter(d.split("@")[1] if d.count("@") >= 2 else "(free function)" for d, *_ in hits)
    print(f"{len(hits)} functions are stubs in the server and real code in the client")
    print("by class:", ", ".join(f"{k} {v}" for k, v in by_class.most_common(30)))
    for d, ss, cs, what, va in hits[:a.top]:
        print(f"  {va:#x} {ss:>2} / {cs:<5} {what[:40]:<40} {s.undecorate(d)}")
    if a.tsv:
        with open(a.tsv, "w", encoding="utf-8") as f:
            f.write("server_va\tserver_bytes\tclient_bytes\tserver_body\tfunction\tdecorated\n")
            for d, ss, cs, what, va in hits:
                f.write(f"{va:#x}\t{ss}\t{cs}\t{what}\t{s.undecorate(d)}\t{d}\n")
        print("wrote", a.tsv)


if __name__ == "__main__":
    main()
