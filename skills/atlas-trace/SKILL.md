---
name: atlas-trace
description: Show the full traceability chain for an ATLAS ID (SRV@/CLI@/EDT@ function, REP-, SVC-, BUG-, Q-, SYS-, FMT-) — ledger row, raw file and hash, annotations, docs, reimpl, hook, tests, evidence, commits. Use when asked about the history or status of any function, replacement or surface.
---

# atlas-trace

No trace script exists yet; assemble the chain with these commands (PowerShell, in `D:\ATLAS`).

## Function ID (e.g. SRV@140327870)
```
$id = 'SRV@140327870'; $va = $id.Split('@')[1]
Import-Csv tracking\functions.csv | Where-Object id -eq $id | Format-List           # ledger row
Get-ChildItem _re\decompiled -Recurse -Filter "*@$va.c" | Get-FileHash              # raw file + hash (compare raw_sha256)
Select-String -Path _re\annotations\*.jsonl -Pattern $id                            # annotations
Select-String -Path docs\* -Pattern $id -Recurse                                    # docs (also grep the symbol name)
Select-String -Path src\* -Pattern "ATLAS-ID: $id|0x$va" -Recurse                   # reimpl header + hook registration
Get-ChildItem tracking\evidence -Filter "$id*"; Select-String -Path tests\* -Pattern $id -Recurse
git log --format="%h %ad %s" --date=short --grep "Atlas-Id: $id"                    # history, oldest last
```
Explain the chain: current status, what each commit changed (`git show <hash> -- <raw file>` shows RAW→ANNOTATED diffs), and what the next stage needs.

## Other IDs
- `REP-`: row in `tracking/replacements.csv` (`covers` lists IDs; trace each), `git log --grep "Atlas-Rep: REP-…"`.
- `SVC-`: row in `tracking/surfaces.csv`, `docs/backend/<id>.md`.
- `BUG-` / `Q-`: `docs/bugs.md` / `docs/questions.md`, then grep docs and `git log --grep`.
- `SYS-` / `FMT-`: `docs/systems/` / `docs/formats/`, plus ledger rows with that system.

## Checks
- The raw file's hash equals the ledger's `raw_sha256` (otherwise `ledger_check` fails — raw files are never hand-edited).
