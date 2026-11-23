"""Bring our engine headers' UHT metadata to ATLAS's (DevKit): Category and meta=(...) in the UPROPERTY / UFUNCTION
macros, and the comment UHT turns into the ToolTip.

Input: the JSON of `metadata_diff.py` (what differs) and the DevKit metadata (`devkit_metadata.py parse`; its
ModuleRelativePath names the header of each member). For each type / member with a difference:
- Category: set, change or remove `Category=` in the macro.
- other meta keys: set, change or remove them inside `meta=(...)`. Keys that come from specifiers rather than meta
  (HideCategories, BlueprintType, IsBlueprintBase, ...) and default arguments (CPP_Default_*) are reported, not edited.
- ToolTip: the comment block above the macro is rewritten. Our own `//` lines (ATLAS citations and notes) stay first,
  then comes a `/** ... */` comment that UHT formats to exactly ATLAS's tooltip, or `/* ~ */` when ATLAS has none.
  A `/*` comment replaces everything UHT collected before it (BaseParser.cpp), and a comment without letters or digits
  gives no tooltip (FHeaderParser::FormatCommentForToolTip), so the citations never reach the metadata.

Usage: python -I _tools/metadata_apply.py <diff.json> <devkit.metadata.jsonl> <module source dir> [--dry-run]
       [--keys Category,ToolTip,meta] [--types T1,T2]
"""
import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

SPECIFIER_KEYS = {"HideCategories", "ShowCategories", "BlueprintType", "NotBlueprintType", "IsBlueprintBase",
                  "ClassGroupNames", "HideFunctions", "AutoExpandCategories", "AutoCollapseCategories",
                  "IncludePath", "ModuleRelativePath", "ToolTip", "Category", "(FunctionFlags)",
                  "BlueprintCompilerGeneratedDefaults", "NativeConst", "Abstract", "Blueprintable"}


def match_paren(s, i):
    """Index after the parenthesis group starting at s[i] == '(' (quotes respected)."""
    depth, q = 0, None
    while i < len(s):
        c = s[i]
        if q:
            if c == "\\":
                i += 1
            elif c == q:
                q = None
        elif c in "\"'":
            q = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise ValueError("unbalanced")


def split_top(s):
    """Split a specifier list at top-level commas."""
    out, depth, q, cur = [], 0, None, ""
    for c in s:
        if q:
            cur += c
            if c == q:
                q = None
            continue
        if c in "\"'":
            q = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        cur += c
    if cur.strip():
        out.append(cur.strip())
    return out


def kv(spec):
    k, _, v = spec.partition("=")
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] == '"':
        v = v[1:-1]
    return k.strip(), v if _ else None


def fmt(k, v, quote_always=True):
    """A specifier / meta entry. Meta values stay quoted: UHT stores an unquoted true / false as "TRUE" / "FALSE"."""
    if v is None or v == "":
        return k
    if not quote_always and re.fullmatch(r"[A-Za-z_]\w*", v):
        return f"{k}={v}"
    return f'{k}="{v}"'


def edit_macro(args, want_cat, cat_set, meta_edits):
    """args: text inside UPROPERTY(...) / UFUNCTION(...). want_cat: (True, value or None) to set / remove."""
    specs = split_top(args)
    out = []
    meta = None
    for sp in specs:
        k, v = kv(sp)
        if k.lower() == "category" and cat_set:
            continue
        if k.lower() == "meta":
            inner = sp[sp.index("(") + 1:sp.rindex(")")]
            meta = [kv(x) for x in split_top(inner)]
            continue
        out.append(sp)
    if cat_set and want_cat is not None:
        out.append(fmt("Category", want_cat, quote_always=False))
    if meta_edits:
        meta = meta or []
        d = {k.lower(): (k, v) for k, v in meta}
        for k, v in meta_edits.items():
            if v is None:
                d.pop(k.lower(), None)
            else:
                d[k.lower()] = (k, v)
        meta = list(d.values())
    if meta:
        out.append("meta=(" + ", ".join(fmt(k, v) for k, v in meta) + ")")
    return ", ".join(out)


def tooltip_comment(text, indent):
    if "*/" in text or "/*" in text:
        return None
    lines = text.split("\n")
    if any(" *" in l or l.startswith("*") for l in lines):
        # javadoc star-stripping would eat these: a C-style comment keeps the lines as they are
        return [indent + "/*"] + lines + ["*/"]
    if len(lines) == 1:
        return [f"{indent}/** {text} */"]
    return [indent + "/**"] + [(f"{indent} * {l}" if l else f"{indent} *") for l in lines] + [indent + " */"]


def find_body(src, tname):
    """(start, end) of the class / struct body named by a metadata type name."""
    name = tname.split(".")[0]
    if "_F" in name and not name.startswith("F"):
        name = "F" + name.split("_F", 1)[1]
    kw = "struct" if name.startswith("F") else "class"
    m = re.search(rf"\b{kw}\s+(?:\w+_API\s+)?{re.escape(name)}\b[^;{{]*\{{", src)
    if not m:
        return None
    i, depth = m.end() - 1, 0
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return m.start(), i
        i += 1
    return None


def find_header(root, tname, cache):
    """The header under root/Classes or root/Public that declares the type (for types ATLAS keeps in another file)."""
    if not cache:
        for p in list(root.glob("Classes/**/*.h")) + list(root.glob("Public/**/*.h")):
            cache[p] = p.read_bytes().decode("utf-8", errors="replace").replace("\r\n", "\n")
    for p, src in cache.items():
        if find_body(src, tname):
            return p
    return None


MACRO = re.compile(r"\b(UPROPERTY|UFUNCTION)\s*\(")


def find_member(src, body, member, is_func):
    """(macro start, args start, args end) of the member's UPROPERTY / UFUNCTION inside the body."""
    for m in MACRO.finditer(src, body[0], body[1]):
        if (m.group(1) == "UFUNCTION") != is_func:
            continue
        end = match_paren(src, m.end() - 1)
        # comments first: a trailing comment may hold ';' or '{'
        decl = re.sub(r"//[^\n]*|/\*.*?\*/", " ", src[end:end + 2000], flags=re.S)
        cut = [x for x in (decl.find(";"), decl.find("{") if is_func else -1) if x != -1]
        decl = decl[:min(cut)] if cut else decl
        if is_func:
            fm = re.search(r"\b(\w+)\s*\(", decl)
            ok = fm and fm.group(1) == member
        else:
            vm = re.search(r"\b(\w+)\s*(?:\[[^\]]*\])?\s*(?::\s*\d+)?\s*(?:=[^;]*)?\s*$", decl)
            # UHT reflects a "_DEPRECATED" member without the suffix
            ok = vm and vm.group(1) in (member, member + "_DEPRECATED")
        if ok:
            return m.start(), m.end(), end - 1
    return None


def hoist(src, args_end):
    """Remove `//` comments between the macro's closing parenthesis and the declaration (UHT reads them into the
    tooltip): a trailing comment on the macro line and whole comment lines below it. Returns the new text and the
    removed comments."""
    i = args_end + 1
    taken = []
    m = re.match(r"[ \t]*(//[^\n]*)", src[i:])
    if m:
        taken.append(m.group(1))
        src = src[:i] + src[i + m.end():]
    j = src.find("\n", i)
    while j != -1:
        m = re.match(r"\n[ \t]*(//[^\n]*)(?=\n)", src[j:])
        if not m:
            break
        taken.append(m.group(1))
        src = src[:j] + src[j + m.end():]
    return src, taken


def rewrite_comment(src, macro_start, tip, extra=()):
    """Replace the comment block directly above the macro line."""
    line_start = src.rfind("\n", 0, macro_start) + 1
    indent = re.match(r"[ \t]*", src[line_start:]).group(0)
    lines_before = src[:line_start].split("\n")
    # lines_before ends with '' (the text after the last newline before the macro line)
    tail = lines_before[:-1]
    j = len(tail)
    in_block = False
    while j > 0:
        l = tail[j - 1].strip()
        if in_block:
            j -= 1
            if l.startswith("/*"):
                in_block = False
            continue
        if l.startswith("//"):
            j -= 1
        elif l.endswith("*/"):
            j -= 1
            if not l.startswith("/*"):
                in_block = True
        else:
            break
    block = tail[j:]
    keep, inblock = [], False
    for l in block:
        s = l.strip()
        if inblock:
            if s.endswith("*/"):
                inblock = False
            continue
        if s.startswith("/*"):
            if not s.endswith("*/") or s == "/*":
                inblock = True
            continue
        keep.append(l)
    keep += [indent + e.strip() for e in extra]
    new = tooltip_comment(tip, indent) if tip is not None else [indent + "/* ~ */"]
    if new is None:
        return None
    head = "\n".join(tail[:j] + keep + new)
    return head + "\n" + src[line_start:]


def find_enum(src, tname):
    """(UENUM macro start, body start, body end) of the enum a metadata type names (Outer_EName or EName)."""
    name = tname.rsplit("_", 1)[-1] if "_E" in tname or tname.startswith("Engine_") else tname
    for m in re.finditer(r"\bUENUM\s*\(", src):
        end = match_paren(src, m.end() - 1)
        h = re.match(r"\s*(?:namespace\s+(\w+)\s*\{\s*enum\s+\w+|enum\s+(?:class\s+)?(\w+))[^{;]*\{", src[end:])
        if h and (h.group(1) or h.group(2)) == name:
            bs = end + h.end()
            return m.start(), bs, src.index("}", bs)
    return None


def apply_enum(src, t, ds, stats, skipped):
    loc = find_enum(src, t)
    if not loc:
        return None
    ustart, bs, be = loc
    by_value = defaultdict(list)
    enum_level = []
    for d in ds:
        if "." in d["key"]:
            v, _, sub = d["key"].partition(".")
            by_value[v].append((sub, d["atlas"]))
        else:
            enum_level.append(d)
    # values from the end of the enum backwards so earlier offsets stay valid
    places = []
    for v, subs in by_value.items():
        vm = re.compile(r"^[ \t]*" + re.escape(v) + r"\b[^\n]*", re.M).search(src, bs, be)
        if not vm:
            skipped.append((t, v, "enum value not found"))
            continue
        places.append((vm.start(), vm.end(), v, subs))
    for start, end, v, subs in sorted(places, reverse=True):
        line = src[start:end]
        um = re.search(r"UMETA\s*\(", line)
        meta = []
        if um:
            uend = match_paren(line, um.end() - 1)
            meta = [kv(x) for x in split_top(line[um.end():uend - 1])]
            line = (line[:um.start()].rstrip() + line[uend:])
        md = {k.lower(): (k, val) for k, val in meta}
        tip, tip_set = None, False
        for sub, val in subs:
            if sub == "ToolTip":
                tip, tip_set = val, True
            elif val is None:
                md.pop(sub.lower(), None)
            else:
                md[sub.lower()] = (sub, val)
        if md:
            core = re.match(r"([ \t]*\w+(?:\s*=\s*[^,/]+?)?)\s*(,?)(.*)$", line)
            line = (core.group(1) + " UMETA(" + ", ".join(fmt(k, val) for k, val in md.values()) + ")" + core.group(2)
                    + core.group(3))
        src = src[:start] + line + src[end:]
        stats["enum value edited"] += 1
        if tip_set:
            r = rewrite_comment(src, start + len(re.match(r"[ \t]*", line).group(0)), tip)
            if r is not None:
                src = r
    for d in enum_level:
        if d["key"] == "ToolTip":
            r = rewrite_comment(src, ustart, d["atlas"])
            if r is not None:
                src = r
                stats["enum tooltip rewritten"] += 1
        elif d["key"] == "BlueprintType":
            end = match_paren(src, src.index("(", ustart)) - 1
            args = [s for s in split_top(src[src.index("(", ustart) + 1:end]) if s.lower() != "blueprinttype"]
            if d["atlas"]:
                args.append("BlueprintType")
            src = src[:src.index("(", ustart) + 1] + ", ".join(args) + src[end:]
            stats["enum macro edited"] += 1
        else:
            skipped.append((t, "", f"enum {d['key']}"))
    return src


def path_of_types(path_of):
    return {t for (t, m) in path_of if not m and "." not in t}


TYPE_FLAG_SPECS = {"BlueprintType": ("BlueprintType", None), "IsConversionRoot": ("ConversionRoot", None)}


def apply_type(src, t, ds, stats, skipped):
    """Class / struct-level metadata: UCLASS / USTRUCT specifiers, meta and the tooltip comment."""
    body = find_body(src, t)
    if not body:
        return None
    kw_start = body[0]
    mm = None
    for m in re.compile(r"\b(UCLASS|USTRUCT)\s*\(").finditer(src, 0, kw_start):
        mm = m
    if not mm or src[match_paren(src, mm.end() - 1):kw_start].strip():
        return None
    astart, aend = mm.end(), match_paren(src, mm.end() - 1) - 1
    specs = split_top(src[astart:aend])
    names = {kv(s)[0].lower(): s for s in specs}
    meta = []
    for s in list(specs):
        if kv(s)[0].lower() == "meta":
            meta = [kv(x) for x in split_top(s[s.index("(") + 1:s.rindex(")")])]
            specs.remove(s)
    md = {k.lower(): (k, v) for k, v in meta}
    tip, tip_set, changed = None, False, False
    for d in ds:
        k, va = d["key"], d["atlas"]
        if k == "ToolTip":
            tip, tip_set = va, True
        elif k in TYPE_FLAG_SPECS:
            spec = TYPE_FLAG_SPECS[k][0]
            specs = [s for s in specs if kv(s)[0].lower() != spec.lower()]
            if va is not None and va.lower() == "true":
                specs.append(spec)
            changed = True
        elif k == "IsBlueprintBase":
            specs = [s for s in specs if kv(s)[0].lower() not in ("blueprintable", "notblueprintable")]
            if va is not None:
                specs.append("Blueprintable" if va.lower() == "true" else "NotBlueprintable")
            changed = True
        elif k == "ClassGroupNames":
            specs = [s for s in specs if kv(s)[0].lower() != "classgroup"]
            if va:
                specs.append(f"ClassGroup={va}" if re.fullmatch(r"\w+", va) else f'ClassGroup="{va}"')
            changed = True
        elif k in ("HideCategories", "ShowCategories", "HideFunctions", "AutoExpandCategories", "AutoCollapseCategories",
                   "IncludePath", "ModuleRelativePath", "(FunctionFlags)") or "." in k:
            stats["skip:type specifier"] += 1
            skipped.append((t, "", f"{k}: ATLAS {va!r} / ours {d['ours']!r}"))
        else:
            if va is None:
                md.pop(k.lower(), None)
            else:
                md[k.lower()] = (k, va)
            changed = True
    if changed:
        if md:
            specs.append("meta=(" + ", ".join(fmt(k, v) for k, v in md.values()) + ")")
        src = src[:astart] + ", ".join(specs) + src[aend:]
        stats["type macro edited"] += 1
    if tip_set:
        r = rewrite_comment(src, mm.start(), tip)
        if r is not None:
            src = r
            stats["type tooltip rewritten"] += 1
    return src


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("diff")
    ap.add_argument("devkit")
    ap.add_argument("srcdir")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--keys", default="Category,ToolTip,meta")
    ap.add_argument("--types")
    a = ap.parse_args()
    keys = set(a.keys.split(","))
    only = set(a.types.split(",")) if a.types else None
    diffs = json.load(open(a.diff, encoding="utf-8"))["diffs"]
    path_of, atl = {}, defaultdict(dict)
    for l in open(a.devkit, encoding="utf-8"):
        r = json.loads(l)
        atl[(r["type"], r["member"])][r["key"]] = r["value"]
        if r["key"] == "ModuleRelativePath":
            path_of[(r["type"], r["member"])] = r["value"]
    work = defaultdict(list)
    for d in diffs:
        if only and d["type"].split(".")[0] not in only:
            continue
        work[(d["type"], d["member"])].append(d)
    stats, skipped = Counter(), []
    files = {}
    header_cache = {}
    for (t, m), ds in sorted(work.items()):
        is_func = "." in t
        member = t.split(".", 1)[1] if is_func and not m else m
        if is_func and m:
            stats["skip:parameter"] += 1
            skipped.append((t, m, "parameter metadata"))
            continue
        if not member and (is_func or t not in path_of_types(path_of)):
            stats["skip:type-level"] += 1
            skipped.append((t, m, "type-level: " + ",".join(d["key"] for d in ds)))
            continue
        if not member:
            p = Path(a.srcdir) / path_of[(t, "")]
            if not p.exists():
                p = find_header(Path(a.srcdir), t, header_cache)
            src = files.get(p) if p else None
            if p and src is None:
                src = files[p] = p.read_bytes().decode("utf-8").replace("\r\n", "\n")
            r = None
            if src is not None:
                r = apply_enum(src, t, ds, stats, skipped) if find_enum(src, t) else apply_type(src, t, ds, stats, skipped)
            if r is None:
                stats["skip:type-level"] += 1
                skipped.append((t, m, "type-level (not applied): " + ",".join(d["key"] for d in ds)))
            else:
                files[p] = r
            continue
        rel = path_of.get((t, m)) or path_of.get((t, "")) or path_of.get((t.split(".")[0], ""))
        if not rel:
            stats["skip:no-path"] += 1
            skipped.append((t, m, "no ModuleRelativePath"))
            continue
        p = Path(a.srcdir) / rel
        if not p.exists():
            # ATLAS has the type in a header of its own; ours keeps it elsewhere: find the header that declares it
            p = find_header(Path(a.srcdir), t, header_cache)
            if p is None:
                stats["skip:no-file"] += 1
                skipped.append((t, m, f"missing {rel}"))
                continue
            stats["found in another header"] += 1
        src = files.get(p)
        if src is None:
            raw = p.read_bytes().decode("utf-8")
            src = files[p] = raw.replace("\r\n", "\n")
        body = find_body(src, t)
        loc = find_member(src, body, member, is_func) if body else None
        if not loc:
            stats["skip:not-found"] += 1
            skipped.append((t, m, f"declaration not found in {rel}"))
            continue
        cat_set, want_cat, meta_edits, tip, tip_set = False, None, {}, None, False
        for d in ds:
            k = d["key"]
            if k == "Category" and "Category" in keys:
                cat_set, want_cat = True, d["atlas"]
                if is_func and want_cat == "Default Blue Print Callable":
                    # our UnrealHeaderTool gives an uncategorised Blueprint function this default, as ATLAS's does
                    want_cat = None
            elif k == "ToolTip" and "ToolTip" in keys:
                tip_set, tip = True, d["atlas"]
            elif "meta" in keys and k not in SPECIFIER_KEYS and not k.startswith("CPP_Default_"):
                meta_edits[k] = d["atlas"]
            elif k != "ToolTip" and k != "Category":
                stats["skip:specifier-or-default"] += 1
                skipped.append((t, m, f"{k}: ATLAS {d['atlas']!r} / ours {d['ours']!r}"))
        mstart, astart, aend = loc
        if tip_set and re.search(r"meta\s*=\s*\(.*\bToolTip\s*=", src[astart:aend], re.S | re.I):
            # a meta ToolTip wins over the comment (AddFormattedPrevCommentAsTooltipMetaData): edit it there
            meta_edits["ToolTip"] = tip
            if tip is not None:
                tip_set = False
        if cat_set or meta_edits:
            new_args = edit_macro(src[astart:aend], want_cat, cat_set, meta_edits)
            src = src[:astart] + new_args + src[aend:]
            stats["macro edited"] += 1
        if tip_set:
            aend2 = match_paren(src, src.index("(", mstart)) - 1
            src, taken = hoist(src, aend2)
            r = rewrite_comment(src, mstart, tip, taken)
            if r is None:
                stats["skip:tooltip-unencodable"] += 1
                skipped.append((t, m, "tooltip contains comment markers"))
            else:
                src = r
                stats["tooltip rewritten"] += 1
        files[p] = src
    if not a.dry_run:
        for p, src in files.items():
            raw = p.read_bytes().decode("utf-8")
            nl = "\r\n" if "\r\n" in raw else "\n"
            out = src.replace("\n", nl)
            if out != raw:
                p.write_bytes(out.encode("utf-8"))
                stats["files written"] += 1
    print(dict(stats))
    for s in skipped[:400]:
        print("  skip", s)


if __name__ == "__main__":
    main()
