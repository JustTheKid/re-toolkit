---
name: atlas-delink-boot
description: Re-export the delinked server from the Ghidra copy, relink it, check the link against the original, boot it on the local stack from the run root and diagnose a fault or hang (dump, unwinder, Frida trace). Use for every P2c/P2d round of the delink-relink loop, and whenever a linked server must be rebuilt or a start of it read.
---

# atlas-delink-boot

The loop that took the delinked server from its first link to the ready line (2026-10-30/31, sixteen starts; the
write-up in `docs/knowledge/matching-decompilation.md` "The first boot" onward and
`tracking/evidence/delink-server.md`). Every step runs in a visible Terminal tab; the user is told before any
server start. Use the venv Python `D:\ATLAS\_tools\ghidra-mcp-venv\Scripts\python.exe`.

## Steps
1. **Stages** (only after a change to `delink_all.py`'s stage list): `python -I _tools\delink_all.py prepare --heap 6g`
   runs the stages not yet in `_re\ghidra-delink\delink-state.json`; each saves the project. The Ghidra copy must be
   free (no export running, no MCP server holding it).
2. **Export** the whole set: move the old set aside (`build\delink\server-p2c` → `server-p2c-stale-<hhmm>`, the user
   deletes stale sets), then `python -I _tools\delink_all.py export --out D:\ATLAS\build\delink\server-p2c --heap 4g
   --log D:\ATLAS\build\delink\export-<tag>.log` (about 35 min: the synthesizer pass, then 1,315 objects; much slower
   while anything else pages). Wait on `manifest.tsv` reaching 1,316 lines, never on the tab.
3. **Judge** in its own tab: `python -I _tools\delink_all.py judge --out ...\server-p2c --jobs 4` (15 min; the
   totals line at the end: byte-identical, DIFF, SIZE, MISSING).
4. **Link**: `python -I _tools\delink_link.py` (20 s; absolute `--objs` / `--out` for another set; sorts `.pdata`,
   recomputes the checksum, prints the sections against the original's).
5. **Checks** on the link, in tabs: `python -I _tools\pe_compare.py --json build\delink\link\compare.json` (12 min;
   DIFFs with `reach` whose targets are not aliases are the real ones) and `python -I _tools\pe_imagerel.py` (7 min;
   exit 1 while an image-base-relative operand keeps the original's displacement). A byte diff of two links
   (the previous set relinked with `--out ...\link14`) shows exactly what a stage changed.
6. **Run root**: `python -I _tools\delink_run.py` (our exe and PDB into `build\delink\run`, the cell's config and
   saves from the original the first time). The exe cannot be replaced while a server runs from it.
7. **Boot** — announce it first, every time: `powershell -ExecutionPolicy Bypass -File _tools\delink_boot.ps1
   -FirstChance -Filter C0000005` (procdump, a mini dump at the first access violation; `-Full` for the heap). The
   original takes about 235 s to its ready line; wait on the engine log's `has successfully started!`, a new
   `.dmp` beside the exe, or the process's exit (a background until-loop). A2S: `python -I _tools\a2s_info.py
   127.0.0.1 57561`. Stop: `_tools\stop-server.ps1 -Root D:\ATLAS\build\delink\run` (RCON SaveWorld, DoExit).
   The stop itself leaves a dump (exit code 0xC0000005): every DoExit dies in `TickOverSubscription` on a null grid
   info, the original's too (ODD-0366) - not a fault of the link. Pass `--exe` to `minidump_where.py` for the exe
   that ran (its PDB names the dump; the symbol cache is keyed by the PDB).
8. **A fault**: `python -I _tools\minidump_where.py <dmp>` (the exception, registers, return addresses on the
   stack) and `python -I _tools\pe_unwind.py <dmp> --regs` (the frames through the PE files' unwind tables); then
   `pe_compare` for the function's reaches, `dumpbin -relocations` on the object for the site (`MSYS_NO_PATHCONV=1`
   in Git Bash), the Ghidra copy for what lies there (a read-only PyGhidra query; the MCP servers may be down).
9. **A hang**: `procdump -ma <pid> <file>` on the running process, `pe_unwind.py <dmp> --all` for every thread's
   wait; what the waiting side cannot show, a Frida trace on a fresh start: `python -I _tools\delink_trace.py <pid>
   --log <file> "<map name>:<arg formats>:<ret>" ...` (start without procdump; attach within the first minutes).
   Before blaming the link, check the environment: the run root's saves, Redis answering a PING on 6380, free memory.
10. **Record** every start in `tracking/evidence/delink-server.md` (the table: time, build, outcome, cause),
    `docs/knowledge/matching-decompilation.md` (a paragraph per start), the journal, `tooling.md`'s rows and the
    CHANGELOG line; stage from a private index when other sessions have uncommitted lines in the shared files;
    commit on the user's "Commit it".

## Checks
- The set's manifest: 1,315 `ok`; the link exit 0 with LNK4052 only; `pe_imagerel.py` exit 0.
- No server start without the announcement; no stale set deleted by us.
