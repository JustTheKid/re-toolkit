"""HTML pages for the test-server reports (report.py): self-contained (inline SVG and a few lines of script for the
hover readout, nothing downloaded), light and dark, a table view under every chart.

Charting rules (the dataviz method): one measure per chart, never two y-scales; series in the validated default
palette's first two categorical slots (blue, orange; checked with validate_palette.js in both modes, 2026-10-24); all
text in text tokens; 2px lines, hairline solid grid; a legend for two series, none for one; tooltips enhance, the
table carries every value; labelled stretches are shaded bands, point marks are hairlines.
"""
import html
import json
import math

CSS = """
:root { color-scheme: light; --page:#f9f9f7; --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e; --muted:#898781;
  --grid:#e1e0d9; --axis:#c3c2b7; --ring:rgba(11,11,11,.10); --s1:#2a78d6; --s2:#eb6834; --band:rgba(11,11,11,.06);
  --warn:#fab219; --crit:#d03b3b; --good:#0ca30c; }
@media (prefers-color-scheme: dark) { :root:where(:not([data-theme="light"])) { color-scheme: dark; --page:#0d0d0d;
  --surface:#1a1a19; --ink:#f0efec; --ink2:#c3c2b7; --muted:#898781; --grid:#2c2c2a; --axis:#383835;
  --ring:rgba(255,255,255,.10); --s1:#3987e5; --s2:#d95926; --band:rgba(255,255,255,.07); } }
:root[data-theme="dark"] { color-scheme: dark; --page:#0d0d0d; --surface:#1a1a19; --ink:#f0efec; --ink2:#c3c2b7;
  --muted:#898781; --grid:#2c2c2a; --axis:#383835; --ring:rgba(255,255,255,.10); --s1:#3987e5; --s2:#d95926;
  --band:rgba(255,255,255,.07); }
* { box-sizing: border-box; }
body { margin:0; background:var(--page); color:var(--ink); font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width:1080px; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:16px; margin:32px 0 8px; }
p.sub, .note { color:var(--ink2); margin:4px 0; }
.status { display:inline-flex; gap:6px; align-items:center; padding:2px 8px; border-radius:6px; border:1px solid var(--ring); }
.status .dot { width:10px; height:10px; border-radius:50%; display:inline-block; }
.tiles { display:grid; grid-template-columns:repeat(auto-fill,minmax(170px,1fr)); gap:12px; margin:16px 0; }
.tile { background:var(--surface); border:1px solid var(--ring); border-radius:10px; padding:12px 14px; }
.tile .label { color:var(--ink2); font-size:12px; } .tile .value { font-size:24px; font-weight:600; margin-top:2px; }
.tile .hint { color:var(--muted); font-size:12px; }
figure.chart { position:relative; background:var(--surface); border:1px solid var(--ring); border-radius:10px;
  margin:12px 0; padding:12px 14px 8px; }
figure.chart figcaption .t { font-weight:600; } figure.chart figcaption .s { color:var(--ink2); font-size:12px; }
.legend { display:flex; gap:16px; margin:6px 0 0; color:var(--ink2); font-size:12px; }
.legend .key { display:inline-block; width:16px; height:2px; vertical-align:middle; margin-right:6px; border-radius:1px; }
svg { display:block; width:100%; height:auto; outline:none; }
svg text { fill:var(--muted); font-size:11px; font-variant-numeric:tabular-nums; }
svg .bandlabel { fill:var(--ink2); }
.tip { position:absolute; display:none; pointer-events:none; background:var(--surface); border:1px solid var(--ring);
  border-radius:8px; padding:6px 10px; font-size:12px; box-shadow:0 2px 10px rgba(0,0,0,.12); min-width:120px; z-index:2; }
.tip .x { color:var(--ink2); margin-bottom:2px; } .tip .row { display:flex; align-items:center; gap:6px; }
.tip .row b { font-weight:600; } .tip .row span.n { color:var(--ink2); }
details { margin-top:6px; } summary { cursor:pointer; color:var(--ink2); font-size:12px; }
table { border-collapse:collapse; width:100%; font-size:13px; }
th, td { text-align:left; padding:5px 8px; border-bottom:1px solid var(--grid); vertical-align:top; }
th { color:var(--ink2); font-weight:600; } td.n, th.n { text-align:right; font-variant-numeric:tabular-nums; }
.wrap { overflow-x:auto; background:var(--surface); border:1px solid var(--ring); border-radius:10px; padding:4px 8px; }
a { color:var(--s1); }
"""

JS = """
document.querySelectorAll('figure.chart').forEach(function (fig) {
  var data = JSON.parse(fig.querySelector('script[type="application/json"]').textContent);
  var svg = fig.querySelector('svg'), cross = svg.querySelector('.cross'), tip = fig.querySelector('.tip');
  var cur = -1;
  function place(i, clientX, clientY) {
    if (i < 0 || i >= data.px.length) return;
    cur = i;
    cross.setAttribute('x1', data.px[i]); cross.setAttribute('x2', data.px[i]); cross.style.display = '';
    tip.replaceChildren();
    var head = document.createElement('div'); head.className = 'x'; head.textContent = data.xs[i]; tip.appendChild(head);
    data.series.forEach(function (s) {
      var row = document.createElement('div'); row.className = 'row';
      var key = document.createElement('span'); key.className = 'key';
      key.style.cssText = 'display:inline-block;width:12px;height:2px;background:var(' + s.color + ')';
      var v = document.createElement('b'); v.textContent = s.vs[i];
      var n = document.createElement('span'); n.className = 'n'; n.textContent = s.name;
      row.appendChild(key); row.appendChild(v); row.appendChild(n); tip.appendChild(row);
    });
    tip.style.display = 'block';
    var box = fig.getBoundingClientRect(), sb = svg.getBoundingClientRect();
    var x = (clientX === undefined) ? sb.left + data.px[i] / data.w * sb.width : clientX;
    var left = x - box.left + 14; if (left + tip.offsetWidth > box.width - 8) left = x - box.left - tip.offsetWidth - 14;
    tip.style.left = Math.max(8, left) + 'px'; tip.style.top = (clientY === undefined ? 40 : clientY - box.top - 10) + 'px';
  }
  function nearest(evt) {
    var p = svg.createSVGPoint(); p.x = evt.clientX; p.y = evt.clientY;
    var q = p.matrixTransform(svg.getScreenCTM().inverse()), best = -1, bd = Infinity;
    for (var i = 0; i < data.px.length; i++) { var d = Math.abs(data.px[i] - q.x); if (d < bd) { bd = d; best = i; } }
    return best;
  }
  svg.addEventListener('pointermove', function (e) { place(nearest(e), e.clientX, e.clientY); });
  svg.addEventListener('pointerleave', function () { cross.style.display = 'none'; tip.style.display = 'none'; });
  svg.addEventListener('keydown', function (e) {
    if (e.key === 'ArrowRight') { place(Math.min(data.px.length - 1, cur + 1)); e.preventDefault(); }
    if (e.key === 'ArrowLeft') { place(Math.max(0, cur - 1)); e.preventDefault(); }
  });
  svg.addEventListener('focus', function () { place(cur < 0 ? data.px.length - 1 : cur); });
  svg.addEventListener('blur', function () { cross.style.display = 'none'; tip.style.display = 'none'; });
});
"""

COLORS = ["--s1", "--s2"]
W, H, L, R, T, B = 760, 210, 54, 20, 22, 28


def esc(text):
    return html.escape(str(text), quote=True)


def fmt(v, digits=1):
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "-"
    if isinstance(v, float):
        return f"{v:,.{digits}f}"
    return f"{v:,}"


def nice_ticks(lo, hi, count=4, integer=False):
    """Round tick values from lo up to the first tick >= hi (1 / 2 / 2.5 / 5 x 10^k steps; whole steps for counts)."""
    if hi <= lo:
        hi = lo + 1
    raw = (hi - lo) / count
    mag = 10 ** math.floor(math.log10(raw))
    step = next(m * mag for m in (1, 2, 2.5, 5, 10) if m * mag >= raw)
    if integer:
        step = max(1, math.ceil(step))
    start = math.floor(lo / step) * step
    ticks = [round(start, 10)]
    while ticks[-1] < hi - 1e-9:
        ticks.append(round(ticks[-1] + step, 10))
    return ticks


def tick_label(v):
    if abs(v) >= 1000:
        return f"{v / 1000:g}K"
    return f"{v:g}"


def page(title, body):
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{esc(title)}</title>"
            f"<style>{CSS}</style></head><body><main>{body}</main><script>{JS}</script></body></html>")


def tiles(items):
    """items: (label, value text, hint text)."""
    out = ['<div class="tiles">']
    for label, value, hint in items:
        out.append(f'<div class="tile"><div class="label">{esc(label)}</div><div class="value">{esc(value)}</div>'
                   f'<div class="hint">{esc(hint)}</div></div>')
    out.append("</div>")
    return "".join(out)


def status(level, text):
    """A status badge: icon + label + status colour (never colour alone)."""
    color, icon = {"warn": ("--warn", "⚠"), "crit": ("--crit", "✖"), "good": ("--good", "✔")}[level]
    return (f'<span class="status"><span class="dot" style="background:var({color})"></span>'
            f'<span>{icon} {esc(text)}</span></span>')


def table(head, rows, numeric=()):
    out = ['<div class="wrap"><table><thead><tr>']
    out += [f'<th class="{"n" if i in numeric else ""}">{esc(h)}</th>' for i, h in enumerate(head)]
    out.append("</tr></thead><tbody>")
    for r in rows:
        out.append("<tr>" + "".join(f'<td class="{"n" if i in numeric else ""}">{esc(c)}</td>'
                                    for i, c in enumerate(r)) + "</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def line_chart(cid, title, subtitle, xs, series, unit, digits=1, bands=(), marks=(), ref=None, step=False,
               x_label="minutes after start-up", x_fmt=None, dots=False):
    """xs: x values (numbers); series: [(name, [value or None])] (1 or 2); bands: [(x0, x1, label)];
    marks: [(x, label)]; ref: (value, label), a horizontal reference line; step: step-after lines (counts)."""
    if not xs:
        return ""
    pw, ph = W - L - R, H - T - B
    x0, x1 = min(xs), max(xs)
    if x1 == x0:
        x1 = x0 + 1
    vals = [v for _, vs in series for v in vs if v is not None]
    if ref:
        vals.append(ref[0])
    y_hi = max(vals) if vals else 1
    yt = nice_ticks(0, y_hi * 1.05 if y_hi > 0 else 1, integer=(digits == 0 and step))
    y_top = yt[-1]

    def X(x):
        return L + (x - x0) / (x1 - x0) * pw

    def Y(v):
        return T + ph - (v / y_top) * ph if y_top else T + ph

    out = [f'<figure class="chart" id="{esc(cid)}"><figcaption><div class="t">{esc(title)}</div>'
           f'<div class="s">{esc(subtitle)} · across: {esc(x_label)}</div></figcaption>']
    if len(series) > 1:
        out.append('<div class="legend">' + "".join(
            f'<span><span class="key" style="background:var({COLORS[i]})"></span>{esc(n)}</span>'
            for i, (n, _) in enumerate(series)) + "</div>")
    out.append(f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="{esc(title)}" tabindex="0">')
    for x_a, x_b, label in bands:  # labelled stretches
        a, b = X(max(x0, x_a)), X(min(x1, x_b))
        if b - a < 1:
            b = a + 1
        out.append(f'<rect x="{a:.1f}" y="{T}" width="{b - a:.1f}" height="{ph}" fill="var(--band)"/>')
        if b - a > 7 * len(label):  # only when it fits; the legend table carries it otherwise
            out.append(f'<text class="bandlabel" x="{a + 4:.1f}" y="{T + 11}">{esc(label)}</text>')
    for v in yt:
        y = Y(v)
        out.append(f'<line x1="{L}" x2="{W - R}" y1="{y:.1f}" y2="{y:.1f}" stroke="var(--grid)" stroke-width="1"/>'
                   f'<text x="{L - 6}" y="{y + 4:.1f}" text-anchor="end">{tick_label(v)}</text>')
    out.append(f'<line x1="{L}" x2="{W - R}" y1="{T + ph}" y2="{T + ph}" stroke="var(--axis)" stroke-width="1"/>')
    for v in nice_ticks(x0, x1, 6):
        if x0 <= v <= x1:
            out.append(f'<text x="{X(v):.1f}" y="{H - 8}" text-anchor="middle">{tick_label(v)}</text>')
    if ref:
        y = Y(ref[0])
        out.append(f'<line x1="{L}" x2="{W - R}" y1="{y:.1f}" y2="{y:.1f}" stroke="var(--ink2)" stroke-width="1"/>'
                   f'<text x="{W - R}" y="{y - 4:.1f}" text-anchor="end" class="bandlabel">{esc(ref[1])}</text>')
    for x, label in marks:
        if x0 <= x <= x1:
            out.append(f'<line x1="{X(x):.1f}" x2="{X(x):.1f}" y1="{T}" y2="{T + ph}" stroke="var(--muted)" '
                       f'stroke-width="1"/><text x="{X(x) + 3:.1f}" y="{T - 6}">{esc(label[:28])}</text>')
    for i, (name, vs) in enumerate(series):
        d, pen = [], False
        prev_y = None
        for x, v in zip(xs, vs):
            if v is None:
                pen = False
                continue
            px, py = X(x), Y(v)
            if not pen:
                d.append(f"M{px:.1f},{py:.1f}")
            elif step and prev_y is not None:
                d.append(f"H{px:.1f}V{py:.1f}")
            else:
                d.append(f"L{px:.1f},{py:.1f}")
            pen, prev_y = True, py
        out.append(f'<path d="{" ".join(d)}" fill="none" stroke="var({COLORS[i]})" stroke-width="2" '
                   f'stroke-linejoin="round" stroke-linecap="round"/>')
        if dots:
            for x, v in zip(xs, vs):
                if v is not None:
                    out.append(f'<circle cx="{X(x):.1f}" cy="{Y(v):.1f}" r="4" fill="var({COLORS[i]})" '
                               f'stroke="var(--surface)" stroke-width="2"/>')
    out.append(f'<line class="cross" x1="0" x2="0" y1="{T}" y2="{T + ph}" stroke="var(--ink2)" stroke-width="1" '
               f'style="display:none"/></svg><div class="tip"></div>')
    xfmt = x_fmt or (lambda x: f"{x:.1f} min")
    data = {"w": W, "px": [round(X(x), 1) for x in xs], "xs": [xfmt(x) for x in xs],
            "series": [{"name": n, "color": COLORS[i], "vs": [f"{fmt(v, digits)} {unit}".strip() for v in vs]}
                       for i, (n, vs) in enumerate(series)]}
    blob = json.dumps(data).replace("</", "<\\/")  # labels are data: never let one close the script element
    out.append(f'<script type="application/json">{blob}</script>')
    rows = [[xfmt(x)] + [fmt(vs[j], digits) for _, vs in series] for j, x in enumerate(xs)]
    out.append("<details><summary>Table</summary>" +
               table([x_label] + [f"{n} ({unit})" for n, _ in series], rows, numeric=set(range(1, len(series) + 1)))
               + "</details></figure>")
    return "".join(out)
