---
name: atlas-annotate
description: Move an ATLAS function from RAW to ANNOTATED by recording renames and comments in _re/annotations/<bin>.jsonl, applying them to Ghidra by script, re-exporting, and updating the ledger. Use after a RAW function has been read and its variables or purpose are understood.
---

# atlas-annotate

## Inputs
A function ID at status RAW, plus what you learned (variable meanings, a summary with evidence and a confidence tag).

## Steps
1. Append lines to `_re/annotations/server.jsonl` (or `client.jsonl`):
   ```
   {"id": "SRV@140327870", "op": "plate_comment", "text": "<what it does, evidence, [CONFIRMED]/[INFERRED]>"}
   {"id": "SRV@140327870", "op": "rename_local", "from": "pFVar1", "to": "currentServer"}
   ```
   Supported ops: `plate_comment`, `rename_local`. (Types/structs go in `src/sdk/*.h` once it exists.)
2. Apply (Ghidra DB must not be open elsewhere):
   `D:\ATLAS\_tools\ghidra-mcp-venv\Scripts\python.exe -I _re\annotations\apply_annotations.py server --only <ID>`
3. Re-export: `... _tools\ghidra_find.py "^<Class>::<Func>$" --decompile` (overwrites the raw file).
4. Review `git diff -- _re/decompiled/...` — only comments and names should change.
5. Ledger row: `status=ANNOTATED`, `raw_sha256=<new hash>`, notes mention the annotations, `updated=<date>`.
6. `ledger_check.py` → 0 errors.
7. Commit: `annotated(<system>): <symbol>` with `Atlas-Id: <ID>` and `Atlas-Stage: ANNOTATED`
   (include the jsonl, the re-exported file and the ledger).

## Checks
- `git log --grep "Atlas-Id: <ID>"` shows the RAW commit and this one; `git diff <raw>..<annotated> -- <file>` is the whole change.

## Example
SRV@140327870 `FSeamlessGridInfo::IsCurrentServerInvalid`, commit `03bde37` (2026-10-21).
