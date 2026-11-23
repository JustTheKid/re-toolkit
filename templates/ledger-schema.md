# Ledger schema

The three tables under `tracking/` are plain CSV (UTF-8, LF, one header row, rows sorted by the first column). The
header rows below are copied from the project's files; no data rows are reproduced here. Column meanings are given
where the project's docs or tools state them; "not described" means the docs give the column no more than its name.

Sources: the master prompt (`atlas-rebuild-prompt.md` in this folder, sections 5 and 6), the working rules
(`CLAUDE.md.example` in this folder), `scripts/ledger/atlasre_common.py` (the `SCHEMAS`, `LADDER`, `FUNC_ID`
constants) and `scripts/ledger/ledger_check.py` (what the pre-commit hook enforces).

## `tracking/functions.csv`: the function ledger

```
id,binary,va,symbol,system,status,parity,raw_sha256,reimpl_path,toggle,rep,evidence,bug,notes,updated
```

Only functions beyond `UNTOUCHED` have a row; one row per ID.

| Column | Meaning |
|---|---|
| `id` | `SRV@<va>`, `CLI@<va>` or `EDT@<va>`: a function in the server exe, the client exe or the editor DLL, keyed by its virtual address in lowercase hex without `0x`. The checker's pattern is `^(SRV\|CLI\|EDT)@([0-9a-f]{6,16})$`. The binaries are frozen, so an ID never changes. |
| `binary` | `server`, `client` or `editor`; must agree with the ID's prefix (checked). |
| `va` | The same lowercase hex address as in the ID (checked). |
| `symbol` | The original function's name. The docs do not describe the column further; their examples use the PDB name (`AGameMode::PreLogin`). |
| `system` | The owning game system, a `SYS-<slug>` id (the checker rejects anything that does not start with `SYS-`). |
| `status` | The rung on the status ladder: `UNTOUCHED`, `RAW`, `ANNOTATED`, `UNDERSTOOD`, `REIMPL`, `HOOKED`, `VERIFIED`, `NATIVE`, or a side state `STUBBED`, `DEAD`, `BLOCKED`. |
| `parity` | The prompt defines `functional` or `matching`. The unit loop (`unit_loop.py ledger`) writes `match` for a function the byte judge found MATCH or MATCH-L, and `regress.py` re-checks every row whose parity is `match`. |
| `raw_sha256` | SHA-256 of the raw decompile file `_re/decompiled/<bin>/<Class>__<Func>@<va>.c`. From `RAW` upward (and for `STUBBED` / `DEAD`) the file must exist and hash to this value: raw files are never hand-edited. |
| `reimpl_path` | The source file that holds the reimplementation, with the `// ATLAS-ID: <id>` header line. Required from `REIMPL` upward. `engine:<path>` names a file in the separate engine tree, which must cite the ID in a comment at the ported code. |
| `toggle` | Not described as a column. The prompt puts the runtime toggles in the hook DLL's ini, one per ID (`<id>=on\|off\|shadow`). |
| `rep` | The replacement (`REP-####`) that covers the function, if any. |
| `evidence` | Path of the evidence file (`tracking/evidence/<id>.md`). Required from `VERIFIED` upward. |
| `bug` | Not described as a column; the ID scheme has `BUG-####` for an original bug the owner wants fixed. |
| `notes` | Free text (quote it when it contains a comma: the checker fails a row whose field count differs from the header). |
| `updated` | ISO date of the last change (`atlasre_common.today()`; the unit loop sets it when it rewrites a row). |

## `tracking/replacements.csv`: the REP registry

```
rep,title,kind,covers,status,toggle,default,adr,notes,updated
```

| Column | Meaning |
|---|---|
| `rep` | `REP-####`: one unit of our code or service that stands in for original behaviour. |
| `title` | Not described beyond its name. |
| `kind` | `reimpl`, `service`, `stub`, `config` or `deviation` (the prompt's list). |
| `covers` | The function and surface IDs the replacement covers, separated by `;`. Each must exist in `functions.csv` or `surfaces.csv` (checked). |
| `status` | Not described beyond its name. |
| `toggle` | Not described beyond its name (see `toggle` above). |
| `default` | Not described beyond its name. The working rules require deviations to sit behind a runtime toggle that is off by default. |
| `adr` | The decision record (`ADR-####`) behind the replacement, where one is required (stubs and deviations). |
| `notes`, `updated` | As above. |

## `tracking/surfaces.csv`: the external-surface registry

```
id,service,protocol,endpoint_or_api,direction,state,used_by,rep,doc,notes,updated
```

| Column | Meaning |
|---|---|
| `id` | `SVC-<service>-<slug>`: one way the client or server reaches outside itself (a backend endpoint, a platform API, a database key family, voice, anti-cheat). |
| `service`, `protocol`, `endpoint_or_api`, `direction`, `used_by` | Not described beyond their names. The `SVC-` doc template asks for the same facts: what it is, who calls it (IDs), protocol and payloads. |
| `state` | `ALIVE` (still works: keep using and document it), `DEAD` (replace with a local service that serves the same format), `UNWANTED` (bypass, by launch options or a stubbed replacement with an ADR) or `UNKNOWN` (investigate). |
| `rep` | The replacement covering the surface, if any. |
| `doc` | Not described beyond its name; the layout puts one `docs/backend/SVC-*.md` per surface. |
| `notes`, `updated` | As above. |

## Extra: `tracking/reach.csv`

Not a ledger, but the unit loop reads it to rank a unit's functions. `scripts/runtime/reach_record.py merge` writes
it: the functions a recorded session executed, in first-hit order.

```
seq,rva,name,module,size,run
```

## What the checker enforces

`python _tools/rebuild/ledger_check.py [--quiet] [--staged]` exits 1 when:

- a row has a bad ID, binary, VA or status, more or fewer fields than the header, or a `system` that is not a `SYS-` id;
- an ID has more than one row;
- a row at `RAW` or above has no raw file, or the file's SHA-256 differs from the ledger;
- a `// ATLAS-ID:` header in `src/reimpl` names an ID without a ledger row, or a row's `reimpl_path` is missing or
  lacks that header;
- a row at `REIMPL` or above has no `reimpl_path`;
- a row at `HOOKED` or above has no `ATLAS_REPLACE(...)` registration in `src/hook` or `src/reimpl`;
- a row at `VERIFIED` or above has no evidence file;
- a replacement covers an unknown function or surface ID.

It warns when a raw decompile exists that the ledger does not list. `--staged` (the hook's mode) reads the three
tables from git's index, also from a private `GIT_INDEX_FILE`, so the check sees what is being committed.
