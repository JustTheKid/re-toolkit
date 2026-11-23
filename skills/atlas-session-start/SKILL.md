---
name: atlas-session-start
description: Start an ATLAS rebuild session — verify the environment, read the index, latest journal, questions and ledger state, then state one session goal. Use at the beginning of every session in D:\ATLAS.
---

# atlas-session-start

## Steps
1. Read `CLAUDE.md` and `docs/INDEX.md`.
2. Read the newest file in `docs/journal/` (by name) — its "Next" section is the default goal.
3. Read `docs/questions.md` (open Q-) and `docs/bugs.md`.
4. Verify the environment (fix `docs/knowledge/environment.md` if anything drifted):
   ```
   cd D:\ATLAS
   git status --short
   D:\ATLAS\_tools\ghidra-mcp-venv\Scripts\python.exe _tools\rebuild\baseline.py --check
   D:\ATLAS\_tools\ghidra-mcp-venv\Scripts\python.exe _tools\rebuild\ledger_check.py
   ```
   - `baseline.py --check` must report 0 differences for originals (ServerGrid files may differ only if
     deployed from `_tools/grids/` — note it).
   - Ports 6379/5432/5433/1025/8025 belong to another project; ATLAS Redis is 6380.
5. Ledger snapshot: count rows by status in `tracking/functions.csv`
   (`Import-Csv tracking\functions.csv | Group-Object status`).
6. State **one** goal: a system, a surface, a bug, or a named set of IDs. Write it as the first line of
   today's journal entry `docs/journal/YYYY-MM-DD-<slug>.md`.

## Must update
- `docs/journal/YYYY-MM-DD-<slug>.md` (create with the goal).

## Common failures
- `ModuleNotFoundError: atlasre_common` → run `_tools/rebuild/*.py` without `-I`.
- Baseline differences in exe/dll/pdb → an original changed: stop and ask the user.
