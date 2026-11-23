"""Apply abi_codegen.py's edit list for one class to our header: each ADD after its anchor (a member after the member,
a virtual after the virtual, in the list's order = ATLAS's), each VIRTUAL edit as the keyword on our declaration when
it already stands in the right place, the overrides in one block after GENERATED_*_BODY(). Every group of inserted
lines gets one leading `// ATLAS (...)` comment with the server's offsets / slots, the DevKit's source lines and the
bodies still to port; UnrealHeaderTool forgets a comment after the next statement, so it never becomes a tooltip
(a trailing comment would: it stays remembered for the next UPROPERTY without a doc comment, even across blank
lines). A function's access is part of its decorated name: a group whose access differs from the place it lands in
gets an access label, and the old one after it. Not applied, only reported: CHANGE and REMOVE edits, anchors that
are not found, VIRTUAL edits whose declaration stands elsewhere (moving a UFUNCTION changes the reflection's order).

Usage: python -I _tools/abi_apply.py <header> <Class> <edits.txt> [--write]
  Without --write it prints what it would insert where. Files are read and written as bytes (engine files are LF).
2026-10-24, phase 4b step 1.11 (matching-decompilation.md "ABI parity").
"""
import argparse
import re
import sys
from pathlib import Path

# the macros that open a class body and leave it public: UHT's GENERATED_*_BODY() and the intrinsic classes'
# DECLARE_CLASS / DECLARE_CLASS_INTRINSIC / DECLARE_CASTED_CLASS_INTRINSIC(...) (UPackageMap, 2026-10-27)
GENERATED = re.compile(r"^\s*(?:GENERATED_(?:UCLASS|USTRUCT|UINTERFACE|IINTERFACE)?_?BODY(?:_LEGACY)?\s*\(\s*\)"
                       r"|DECLARE_(?:CASTED_)?CLASS(?:_INTRINSIC)?(?:_WITH_CONSTRUCT)?\s*\(.*\))\s*;?\s*$")
ACCESS = re.compile(r"^\s*(public|protected|private)\s*:\s*$")
LEAD_MACRO = re.compile(r"^\s*(?:UPROPERTY|UFUNCTION|DEPRECATED|UE_DEPRECATED)\s*\(")
EDIT_ADD = re.compile(r"^ADD    (?P<anchor>after virtual \S+|after \S+|first new virtual|first member|override)\s+"
                      r"(?P<decl>.*?)\s+(?P<info>// (?:slot \+0x[0-9a-f]+.*|\+0x[0-9a-f]+(?:\.\d+)?))\s*$")
EDIT_VIRTUAL = re.compile(r"^VIRTUAL (?P<name>\S+)\s+ours declares it without virtual: move it "
                          r"(?P<anchor>after virtual \S+|first new virtual), add virtual\s+(?P<info>//.*)$")
EDIT_MOVE = re.compile(r"^MOVE   (?P<name>\S+)\s+ours declares it elsewhere: move it "
                       r"(?P<anchor>after virtual \S+|after \S+|first new virtual|first member)\s+(?P<info>//.*)$")


def blank_code(text):
    """The text with comments and string / char literals replaced by spaces (newlines kept), for brace counting."""
    out, i, n = list(text), 0, len(text)
    while i < n:
        c, d = text[i], text[i + 1] if i + 1 < n else ""
        if c == "/" and d == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
        elif c == "/" and d == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if text[k] != "\n":
                    out[k] = " "
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


class Stmt:
    def __init__(self, s, e, lead, code):
        self.s, self.e, self.lead = s, e, lead  # first code line, last line, first line of its comments / macros
        self.code = code
        decl = code
        while True:  # the declaration without its UPROPERTY / UFUNCTION / DEPRECATED macros
            m = re.match(r"^\s*(?:UPROPERTY|UFUNCTION|DEPRECATED|UE_DEPRECATED)\s*\(", decl)
            if not m:
                break
            depth, i = 0, m.end() - 1
            for i in range(m.end() - 1, len(decl)):
                depth += (decl[i] == "(") - (decl[i] == ")")
                if depth == 0:
                    break
            decl = decl[i + 1:]
        self.decl = decl.strip()
        self.kind, self.name = "other", None
        self.virtual = re.search(r"\bvirtual\b", self.decl) is not None
        self.override = re.search(r"\b(?:override|OVERRIDE)\b", self.decl) is not None
        if ACCESS.match(code):
            self.kind = "access"
        elif GENERATED.match(code):
            self.kind = "generated"
        elif re.match(r"^(?:typedef|friend|using|enum|static_assert|template)\b", self.decl):
            pass
        else:
            m = re.match(r"^[^(=]*?(operator\s*(?:\(\)|[^\s(]+)|~?[A-Za-z_]\w*)\s*\(", self.decl)
            if m and not re.match(r"^(?:struct|class|union)\b", self.decl):
                self.kind, self.name = "function", m.group(1)
            else:
                m = re.search(r"(\w+)\s*(?:\[[^\]]*\]\s*)*(?::\s*\d+\s*)?(?:=[^;]*)?;\s*$", self.decl)
                if m and not re.match(r"^(?:struct|class|union)\b.*\{", self.decl) and \
                        not re.match(r"^static\b", self.decl):
                    self.kind, self.name = "member", m.group(1)


def statements(lines, code, first, last):
    """The class body's statements between lines first..last (inclusive), with the access in effect before each."""
    out, i, lead, pp = [], first, None, 0
    while i <= last:
        stripped = code[i].strip()
        if not stripped:
            if not lines[i].strip():
                lead = None  # a blank line ends a statement's leading block
            elif lead is None:
                lead = i     # a comment line
            i += 1
            continue
        if stripped.startswith("#"):
            out.append(Stmt(i, i, i, lines[i]))
            out[-1].kind, out[-1].pp = "preproc", pp
            pp += stripped.startswith("#if") - stripped.startswith("#endif")
            lead, i = None, i + 1
            continue
        s, depth, text = i, 0, ""
        while i <= last:
            text += code[i] + "\n"
            depth += code[i].count("{") + code[i].count("(") - code[i].count("}") - code[i].count(")")
            t = code[i].strip()
            if GENERATED.match(code[i]) or ACCESS.match(code[i]):
                break
            if depth <= 0 and t and t[-1] in ";}" and not LEAD_MACRO.match(code[i]):
                break
            i += 1
        out.append(Stmt(s, i, lead if lead is not None else s, text))
        out[-1].pp = pp  # its #if nesting: a declaration inside a conditional is not moved
        lead, i = None, i + 1
    return out


def class_range(code_lines, cls):
    """(first body line, last body line, struct?) of the class's definition."""
    for i, line in enumerate(code_lines):
        m = re.match(r"^\s*(class|struct)\s+(?:\w+_API\s+)?" + re.escape(cls) + r"\b(?!\s*;)", line)
        if not m:
            continue
        depth, start = 0, None
        for j in range(i, len(code_lines)):
            for ch in code_lines[j]:
                if ch == "{":
                    depth += 1
                    if start is None:
                        start = j
                elif ch == "}":
                    depth -= 1
                    if start is not None and depth == 0:
                        return start + 1, j - 1, m.group(1) == "struct"
            if start is None and ";" in code_lines[j]:
                break  # a forward declaration
    sys.exit(f"class {cls} not found")


def parse_edits(path):
    edits, other = [], []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        m = EDIT_ADD.match(line)
        if m:
            decl, todo = m.group("decl"), None
            t = re.search(r"\s*// TODO body: (SRV@[0-9a-f]+)\s*$", decl)
            if t:
                decl, todo = decl[:t.start()].rstrip(), t.group(1)
            info = m.group("info")
            acc = re.search(r"; (public|protected|private)\b", info)
            edits.append({"kind": "add", "anchor": m.group("anchor"), "decl": re.sub(r"\s*:\s*(\d+);$", r":\1;", decl),
                          "todo": todo, "info": info, "access": acc.group(1) if acc else None})
            continue
        m = EDIT_VIRTUAL.match(line) or EDIT_MOVE.match(line)
        if m:
            acc = re.search(r"; (public|protected|private)\b", m.group("info"))
            edits.append({"kind": "virtual" if line.startswith("VIRTUAL") else "move", "anchor": m.group("anchor"),
                          "name": m.group("name"), "info": m.group("info"), "access": acc.group(1) if acc else None})
            continue
        if line.startswith(("CHANGE", "REMOVE")):
            other.append(line)
    return edits, other


def citation(group):
    """The group's leading comment: offsets or slots, DevKit lines, bodies to port."""
    spots, devkit, todo = [], [], []
    for e in group:
        m = re.search(r"(?:slot )?(\+0x[0-9a-f]+(?:\.\d+)?)", e["info"])
        spots.append(m.group(1) if m else "?")
        d = re.search(r"DevKit (\S+)", e["info"])
        if d:
            devkit.append(d.group(1))
        if e.get("todo"):
            todo.append(e["todo"])
    kind = "server vtable" if "slot" in group[0]["info"] else "server PDB"
    where = spots[0] if len(spots) == 1 else f"{spots[0]}-{spots[-1]}"
    if group[0]["anchor"] == "override":
        kind, where = "overrides, server vtable", ", ".join(spots)
    text = f"// ATLAS ({kind} {where}"
    if devkit:
        # per file its lines: a range when they ascend one file's lines in order, else each line
        files = {}
        for d in devkit:
            f, n = d.rsplit(":", 1)
            files.setdefault(f, []).append(int(n))
        parts = []
        for f, ns in files.items():
            if len(ns) == 1:
                parts.append(f"{f}:{ns[0]}")
            elif ns == sorted(ns) and len(files) == 1 and f.endswith(".h") and ns[-1] - ns[0] < 4 * len(ns):
                parts.append(f"{f}:{ns[0]}-{ns[-1]}")  # declarations next to each other in a header
            else:
                parts.append(f"{f}:" + ", ".join(str(n) for n in ns))
        text += "; DevKit " + "; ".join(parts)
    if all(e["kind"] == "move" for e in group):
        text += ", ATLAS's place"  # moved declarations keep their own UPROPERTY / UFUNCTION and comments
    elif kind == "server PDB":
        text += ", not reflected"
    if todo:
        text += ("; body " if len(todo) == 1 else "; bodies ") + ", ".join(todo)
    return text + ")"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("header")
    ap.add_argument("cls")
    ap.add_argument("edits")
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args()
    raw = Path(a.header).read_bytes()
    assert b"\r\n" not in raw, "CRLF header"
    text = raw.decode("utf-8")
    lines = text.split("\n")
    code = blank_code(text).split("\n")
    first, last, is_struct = class_range(code, a.cls)
    stmts = statements(lines, code, first, last)

    # the access in effect after each statement
    access, after = ("public" if is_struct else "private"), {}
    for st in stmts:
        if st.kind == "access":
            access = ACCESS.match(st.code).group(1)
        elif st.kind == "generated":
            access = "public"
        after[st.s] = access
    def access_at(line):
        acc = "public" if is_struct else "private"
        for st in stmts:
            if st.e > line:
                break
            acc = after[st.s]
        return acc

    members = {st.name: st for st in stmts if st.kind == "member"}
    funcs = {}
    for st in stmts:
        if st.kind == "function":
            funcs.setdefault(st.name, st)
    virtuals = {}
    for st in stmts:
        if st.kind == "function" and st.virtual:
            virtuals.setdefault(st.name, st)
    intro = [st for st in stmts if st.kind == "function" and st.virtual and not st.override
             and not st.name.startswith("~")]
    gen = next((st for st in stmts if st.kind == "generated"), None)

    edits, other = parse_edits(a.edits)
    groups, problems, keyword, moved, joined = {}, [], [], [], {}

    def place(anchor, decl):
        """(line after which to insert, block kind) for an anchor, or None."""
        name = anchor.split()[-1]
        if anchor == "override":
            return (gen.e, 1) if gen else None
        if anchor == "first member":
            st = next((s for s in stmts if s.kind == "member"), None)
            if not st:
                return None
            # not inside a preprocessor block that opens just before the first member (an editor-only member first:
            # ATLAS's server member goes before the #if)
            j = st.lead - 1  # the line before the member's block (0-based)
            while j >= 0 and (not lines[j].strip() or lines[j].strip().startswith("//")):
                j -= 1
            if j >= 0 and lines[j].strip().startswith("#if"):
                return (j - 1, 0)
            return (st.lead - 1, 0)
        if anchor == "first new virtual":
            return (intro[0].lead - 1, 0) if intro else None
        if anchor.startswith("after ") and name in joined:
            return joined[name]  # after a declaration this run adds or moves: in its block, after it
        if anchor.startswith("after virtual "):
            # a function a VIRTUAL edit makes virtual in place anchors the additions after it
            st = virtuals.get(name) or funcs.get(name)
            if st:
                return (st.e, 0)
            if gen and re.search(r"_(?:Implementation|Validate)$", name):
                return (gen.e, 0)  # UHT declares these inside GENERATED_*_BODY() (the RPC wrappers)
            return None
        st = members.get(name)
        return (st.e, 0) if st else None

    moving = {e["name"] for e in edits if e["kind"] == "move"}
    staying = [st for st in intro if st.name not in moving]  # the virtual declarations that keep their place
    for e in edits:
        anchor = e["anchor"]
        aname = anchor.split()[-1] if anchor.startswith("after virtual ") else None
        if e["kind"] in ("virtual", "move"):
            is_member = e["kind"] == "move" and "slot" not in e["info"]
            st = (funcs if e["kind"] == "virtual" else members if is_member else virtuals).get(e["name"])
            if st is None:
                problems.append(f"{e['kind'].upper()} {e['name']}: no declaration found")
                continue
            if is_member:
                # a bitfield moves its bits; a reflected member may not pass another (the properties' order)
                key0 = place(anchor, None)
                lo, hi = sorted((st.s, key0[0] if key0 else st.s))
                crossed = [s.name for s in stmts if s.kind == "member" and s is not st and lo <= s.s <= hi
                           and "UPROPERTY(" in s.code]
                if re.search(r":\s*\d+\s*;\s*$", st.decl) or ("UPROPERTY(" in st.code and crossed):
                    problems.append(f"MOVE {e['name']} (line {st.s + 1}): a bitfield or a reflected member passing "
                                    f"{', '.join(crossed[:3]) or 'bits'}; move it by hand {anchor}")
                    continue
            if e["kind"] == "virtual" and aname not in joined:
                # in place when no staying virtual stands between its predecessor and it
                prev = (virtuals.get(aname) or funcs.get(aname)) if aname else None
                nxt = [v for v in staying if v.s > (prev.s if prev else first)]
                if (prev is None or st.s > prev.s) and (not nxt or st.s < nxt[0].s):
                    keyword.append((st, e))
                    continue
            # it stands elsewhere: move its whole block (comments, UFUNCTION) after the anchor; the reflection does not
            # mind (UHT links a class's functions in name order)
            key = place(anchor, None)
            if key is None:
                problems.append(f"{e['kind'].upper()} {e['name']}: anchor {anchor} not found")
                continue
            target = next((s for s in stmts if s.e == key[0]), None)
            if st.pp or (target is not None and target.pp and aname not in joined):
                problems.append(f"{e['kind'].upper()} {e['name']} (line {st.s + 1}): inside or into an #if block; "
                                f"move it by hand {anchor}")
                continue
            block = lines[st.lead:st.e + 1]
            if e["kind"] == "virtual":
                i = next(k for k in range(st.s - st.lead, len(block)) if not LEAD_MACRO.match(block[k])
                         and re.search(r"\b" + re.escape(e["name"]) + r"\s*\(", block[k])
                         and not block[k].strip().startswith(("//", "/*", "*")))
                block[i] = re.sub(r"^(\s*)", r"\1virtual ", block[i], count=1)
            e["block"], e["from"] = block, (st.lead, st.e)
            e["orig_access"] = access_at(st.s)  # a moved declaration keeps its access in the new place
            moved.append(e)
            groups.setdefault(key, []).append(e)
            joined[e["name"]] = key
            continue
        key = place(anchor, e["decl"])
        if key is None:
            problems.append(f"{anchor}: not found ({e['decl']})")
            continue
        groups.setdefault(key, []).append(e)
        m = re.match(r"^[^(]*?(\w+)\s*\(", e["decl"]) if "slot" in e["info"] else \
            re.search(r"(\w+)\s*(?:\[[^\]]*\]\s*)*(?::\s*\d+\s*)?;\s*$", e["decl"])
        if m and anchor != "override":
            joined[m.group(1)] = key  # an addition anchors the edits after it, in its block

    # the keyword edits (same line count: before the insertions, whose positions do not move)
    for st, e in keyword:
        i = st.s
        while LEAD_MACRO.match(lines[i]) or not code[i].strip():
            i += 1  # past the UFUNCTION(...) lines to the declaration
        lines[i] = re.sub(r"^(\s*)", r"\1virtual ", lines[i], count=1)
        print(f"virtual  {e['name']} (line {i + 1})")

    # insertions and the moved blocks' removals, from the bottom up (positions in the original numbering)
    ops = [((pos, 2 + kind), "insert", (pos, kind)) for pos, kind in groups]
    ops += [((e["from"][0], 0), "remove", e) for e in moved]
    for _key, op, arg in sorted(ops, reverse=True):
        if op == "remove":
            a0, b0 = arg["from"]
            del lines[a0:b0 + 1]
            if not lines[a0 - 1].strip() and a0 < len(lines) and not lines[a0].strip():
                del lines[a0]  # no double blank line where it stood
            print(f"move     {arg['name']} (lines {a0 + 1}-{b0 + 1})")
            continue
        pos, kind = arg
        group, here = groups[arg], access_at(pos)
        block = ["", "\t" + citation(group)]
        cur = here
        for n, e in enumerate(group):
            want = e["access"] if "slot" in e["info"] and e["access"] else (e.get("orig_access") or cur)
            if want != cur:
                block.append(f"{want}:")
                cur = want
            if "block" in e:
                if n == 0:
                    block += ["\t/* ~ */", ""]  # our // comment must not reach its UFUNCTION as a tooltip
                block += e["block"]
            else:
                block.append("\t" + e["decl"])
        if cur != here:
            block.append(f"{here}:")
        lines[pos + 1:pos + 1] = block
        print(f"insert   after line {pos + 1} ({here}): {len(group)} edit(s)  {block[1].strip()}")
    for p in problems:
        print("PROBLEM  " + p)
    for o in other:
        print("MANUAL   " + o)
    todo = [e for e in edits if e.get("todo")]
    for e in todo:
        print(f"BODY     {e['todo']}  {e['decl']}")
    if a.write:
        Path(a.header).write_bytes("\n".join(lines).encode("utf-8"))
        print(f"written: {a.header}")


if __name__ == "__main__":
    main()
