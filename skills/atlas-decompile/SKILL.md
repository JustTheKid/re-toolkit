---
name: atlas-decompile
description: Export functions from the ATLAS server or client Ghidra project to RAW decompiles and add them to the ledger. Use when a function needs to be read, documented or reimplemented and has no raw file yet.
---

# atlas-decompile

## Inputs
Binary (server|client) and a function-name regex (PDB names, e.g. `^FOnlineSessionSteam::CheckAuthToken$`).

## Steps
1. Find candidates (no decompile yet):
   ```
   D:\ATLAS\_tools\ghidra-mcp-venv\Scripts\python.exe -I _tools\ghidra_find.py "<regex>"                                       # server
   D:\ATLAS\_tools\ghidra-mcp-venv\Scripts\python.exe -I _tools\ghidra_find.py "<regex>" --project _re\ghidra-client --name client --program AtlasGame.exe
   ```
2. Export: add `--decompile [--timeout 300]`. Files land in `_re/decompiled/server|client/<Class>__<Func>@<va>.c`.
   Remove any `` `…'::__l1::dtor$… `` helper exports it picked up (they are not functions we track) — match them
   with `-Filter '*dtor$*'`; a plain `*dtor*` also matches names like `ServerFailedToRespond`.
3. Add one ledger row per new file to `tracking/functions.csv` (keep sorted by id):
   `id=SRV@<va>,binary=server,va=<va>,symbol=<Class::Func>,system=<SYS-…>,status=RAW,parity=functional,raw_sha256=<Get-FileHash … SHA256, lowercase>,notes="ghidra 12.1.4 pdb-only+locals; bin sha256 <first 16 of baseline>; exported <date> by _tools/ghidra_find.py",updated=<date>`.
   If the decompiler times out, keep the file, set `status=BLOCKED` and open a `Q-`.
4. `ledger_check.py` → 0 errors, 0 warnings.
5. Commit: `raw(<system>): <symbol>` with `Atlas-Stage: RAW` and one `Atlas-Id:` line per function.

## Rules
- Never hand-edit a raw file. Changes come only from annotations + re-export (atlas-annotate).
- Since 2026-10-29 an export starts with the PDB's locals block (parameters, locals, inlined callees' locals with
  their register / frame-slot ranges) and has Ghidra's `param_N` renamed to the PDB's names when the counts agree
  (`_tools/pdb_locals.py`; index `_re/cache/<pdb>.locals.sqlite`, rebuilt in a minute with
  `pdb_locals.py build <pdb>` when missing; `--no-locals` exports as before). Raw files from before lack the block
  until re-exported — a re-export changes the row's `raw_sha256`.
- Ghidra DBs must not be open in another process (MCP server, other script) while exporting.

## Common failures
- PDB-only DBs have no string xrefs → search by function name, not by text.
- Huge functions time out (e.g. `FSeamlessGridInfo::ParseJsonFromString`, Q-0007).
