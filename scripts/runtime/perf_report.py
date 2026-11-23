"""Summarise an atlasre perf recording (atlasre-perf-<time>.csv + atlasre-proc-<time>.csv, see docs/knowledge/perf-recorder.md).

Prints: frame-time percentiles and histogram, where frame time goes (per zone), the worst hitches with their
biggest zones, and memory/CPU. Hitch rule = the DLL's: frame >= --hitch-ms AND >= --factor x running average.

Usage: python -I _tools/perf_report.py <atlasre-perf-*.csv> [--hitch-ms 50] [--factor 2.0] [--top 15] [--skip-s 0]
  --skip-s  ignore the first N seconds (e.g. the loading screen)
"""
import argparse
import csv
from pathlib import Path


def pct(sorted_values, p):
    if not sorted_values:
        return 0.0
    return sorted_values[min(len(sorted_values) - 1, int(p * (len(sorted_values) - 1)))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("perf_csv")
    ap.add_argument("--hitch-ms", type=float, default=50.0)
    ap.add_argument("--factor", type=float, default=2.0)
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--skip-s", type=float, default=0.0)
    args = ap.parse_args()

    path = Path(args.perf_csv)
    with open(path, newline="") as f:
        rows = [r for r in csv.DictReader(f) if float(r["t_s"]) >= args.skip_s]
    if not rows:
        raise SystemExit("no frames")
    zones = [c[:-3] for c in rows[0].keys() if c.endswith("_ms") and c not in ("frame_ms", "work_ms", "other_ms")]
    has_other = "other_ms" in rows[0]
    frame_ms = [float(r["frame_ms"]) for r in rows]
    duration = float(rows[-1]["t_s"]) - float(rows[0]["t_s"]) + frame_ms[-1] / 1000

    print(f"== {path.name}")
    print(f"frames {len(rows)}  duration {duration:.1f} s  avg {len(rows) / duration:.1f} fps  "
          f"(t = {float(rows[0]['t_s']):.1f} .. {float(rows[-1]['t_s']):.1f} s since atlasre start)")
    s = sorted(frame_ms)
    print("frame ms  " + "  ".join(f"p{int(p * 1000) / 10:g} {pct(s, p):.1f}" for p in (0.5, 0.9, 0.95, 0.99, 0.999))
          + f"  max {s[-1]:.1f}")

    buckets = [(8.33, "<8.3 (120+ fps)"), (16.7, "<16.7 (60+)"), (33.3, "<33.3 (30+)"), (50, "<50"),
               (100, "<100"), (250, "<250"), (float("inf"), ">=250")]
    counts = [0] * len(buckets)
    for ms in frame_ms:
        counts[next(i for i, (limit, _) in enumerate(buckets) if ms < limit)] += 1
    print("histogram " + "  ".join(f"{label} {c}" for (_, label), c in zip(buckets, counts) if c))

    total = sum(frame_ms)
    print("\nwhere frame time goes (inclusive, nested zones overlap):")
    if has_other:
        ot = sum(float(r["other_ms"]) for r in rows)
        print(f"  {'(other: no zone)':<18} {ot / 1000:8.2f} s  {ot / total * 100:5.1f} %  max/frame {max(float(r['other_ms']) for r in rows):8.1f} ms")
    for z in sorted(zones, key=lambda z: -sum(float(r[f"{z}_ms"]) for r in rows)):
        zt = sum(float(r[f"{z}_ms"]) for r in rows)
        if zt < 0.5:
            continue
        calls = f"  calls {sum(int(r[f'{z}_n']) for r in rows)}" if f"{z}_n" in rows[0] else ""
        print(f"  {z:<18} {zt / 1000:8.2f} s  {zt / total * 100:5.1f} %  max/frame {max(float(r[f'{z}_ms']) for r in rows):8.1f} ms{calls}")

    hitches, ema = [], 0.0
    for r, ms in zip(rows, frame_ms):
        if ema > 0 and ms >= args.hitch_ms and ms >= args.factor * ema:
            hitches.append((ms, ema, r))
        ema = ms if ema == 0 else ema * 0.95 + ms * 0.05
    print(f"\nhitches: {len(hitches)} ({len(hitches) / duration * 60:.1f}/min)")
    cause = {}
    for ms, _, r in hitches:
        top = max(zones, key=lambda z: float(r[f"{z}_ms"]) if z not in ("engine_tick", "world_tick") else -1)
        cause[top] = cause.get(top, 0) + 1
    if cause:
        print("  biggest non-tick zone per hitch: " + ", ".join(f"{z} {n}" for z, n in sorted(cause.items(), key=lambda x: -x[1])))
    proc_path = path.with_name(path.name.replace("atlasre-perf-", "atlasre-proc-"))
    proc = []
    if proc_path.exists():
        with open(proc_path, newline="") as f:
            proc = [r for r in csv.DictReader(f) if float(r["t_s"]) >= args.skip_s]

    def sample_at(t):
        """The once-a-second process sample covering time t (the first sample taken after it)."""
        return next((p for p in proc if float(p["t_s"]) >= t), None)

    for ms, avg, r in sorted(hitches, key=lambda h: -h[0])[:args.top]:
        parts = sorted(((float(r[f"{z}_ms"]), z) for z in zones), reverse=True)
        detail = ", ".join(f"{z} {v:.1f}" + (f" x{r[z + '_n']}" if f"{z}_n" in r and int(r[f"{z}_n"]) > 1 else "")
                           for v, z in parts[:6] if v >= 1.0)
        if has_other:
            detail = f"other {float(r['other_ms']):.1f}, " + detail
        p = sample_at(float(r["t_s"]))
        mem = (f"  [faults {p['page_faults']}/s" + (f", free {float(p['sys_avail_mb']):.0f} MB" if "sys_avail_mb" in p else "")
               + "]") if p else ""
        print(f"  frame {r['frame']:>7} t {float(r['t_s']):7.1f}s  {ms:7.1f} ms (avg {avg:5.1f})  {detail}{mem}")

    if proc:
        ws = [float(r["working_set_mb"]) for r in proc]
        priv = [float(r["private_mb"]) for r in proc]
        cpu = [float(r["cpu_pct"]) for r in proc[1:]] or [0.0]
        faults = [int(r["page_faults"]) for r in proc]
        print(f"\nprocess: working set {min(ws):.0f}..{max(ws):.0f} MB (last {ws[-1]:.0f}), private max {max(priv):.0f} MB, "
              f"cpu avg {sum(cpu) / len(cpu):.0f}% max {max(cpu):.0f}% (of all cores), "
              f"page faults max {max(faults)}/s, handles last {proc[-1]['handles']}")
        if "sys_avail_mb" in proc[0]:
            avail = [float(r["sys_avail_mb"]) for r in proc]
            commit = [float(r["sys_commit_mb"]) for r in proc]
            print(f"system:  free RAM min {min(avail):.0f} MB (avg {sum(avail) / len(avail):.0f}), "
                  f"commit max {max(commit):.0f} / {proc[0]['sys_commit_limit_mb']} MB")


if __name__ == "__main__":
    main()
