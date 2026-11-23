---
name: atlas-session-end
description: Close an ATLAS rebuild session — run the ledger check, update coverage counts, write the journal, refresh INDEX and questions, and report IDs advanced. Use before finishing any session in D:\ATLAS.
---

# atlas-session-end

## Steps
1. `D:\ATLAS\_tools\ghidra-mcp-venv\Scripts\python.exe _tools\rebuild\ledger_check.py` → 0 errors.
2. Update `tracking/coverage.md` (no generator yet — write the counts by hand):
   - functions by binary × status and by system × status (`Import-Csv tracking\functions.csv | Group-Object binary,status`)
   - surfaces by state (`Import-Csv tracking\surfaces.csv | Group-Object state`)
   - open REP / BUG / Q counts; the commit it was taken at (`git rev-parse --short HEAD`).
3. Finish today's journal entry (template in `_prompts/atlas-rebuild-prompt.md` §7): goal · done ·
   IDs advanced (`from → to`) · REP/ADR/BUG/Q touched · new knowledge (links) · failed/surprised · next.
4. Update `docs/INDEX.md` (latest journal link, new docs) and `docs/questions.md` (move answered Qs to Resolved with evidence).
5. Commit: `doc(session): end of <date> session` with `Atlas-Stage: DOC`.
6. Report to the user: IDs advanced, REP/ADR/BUG/Q changes, new knowledge, failures, proposed next goal.
7. If a workflow repeated this session and has no skill, write it; fix any skill that was wrong (`SKILL` commit).

## Checks
- `git status --short` is empty after the commit.
- Journal entry exists for today and names the next goal.
