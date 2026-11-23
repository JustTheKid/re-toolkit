---
name: atlas-unit-loop
description: Port one original compile unit of the ATLAS server (phase 4d) with the loop as one command - plan, export, headers, the draft by hand, build with ATLAS's command line, judge, ledger, doc. Use for every game unit in reach order, and for a re-judge of a unit after an edit.
---

# atlas-unit-loop

`_tools/rebuild/unit_loop.py <unit> <step>` (P4, 2026-10-31; the first unit through it was `ShooterGameModule.cpp`,
nine of nine byte-identical; the second, `CustomGameMode.cpp`, 225 of 226 with the game's first twelve headers).
Run it with the venv Python, without `-I`. The unit is a regex on the PDB's object paths (`PrimalRaft\.cpp\.obj`);
exactly one must match. Every step logs one line; the work dir is `build/loop/<unit>/`.

## Steps
1. **Pick the unit**: the next by the reach set — `tracking/reach.csv` (first-hit order; `reach_record.py` records a
   session) — or the one the user names. `plan` first: `python _tools/rebuild/unit_loop.py "<File>\.cpp\.obj" plan`
   prints the functions, bytes, reached count and ledger state; `plan.tsv` has every function.
2. **Export**: `... export --system SYS-<system> [--workers 6]` — decompiles with PDB locals into
   `_re/decompiled/server/` for the functions without a raw file, RAW rows in the ledger (the Ghidra server project
   must be free: the MCP servers off or idle). Minutes for hundreds of functions; a visible Terminal tab.
3. **What the PDB says about the unit's headers** (before writing any):
   `python _tools/rebuild/unit_lines.py "<File>\.cpp\.obj"` — the unit's line table: which game header holds each
   inline function the unit emitted (a struct's constructor, an inline virtual) and which engine headers it saw.
   The DevKit metadata homes the classes (`_re/corpus/devkit/game.metadata.jsonl`, key `ModuleRelativePath`).
   `python _tools/pdb_decl.py Class::method Class::* ::global va:<hex>` — declarations with their access specifier
   (a protected method decorates `MEBA`, a public one `UEBA`: the header must say the same).
4. **Headers**: `... headers` writes `layouts.h` with `gen_headers.py --declare --known build/loop/common/engine-types.txt`
   (the known list from `python _tools/rebuild/engine_types.py`, once per engine change): layouts, declarations in
   vtable order, container element types in full. Split it into ATLAS's `Classes\*.h` with
   `python _tools/rebuild/game_headers.py build/loop/<unit>/layouts-decl.h` — its tables (HOME with the evidence tag
   per type, HAND for inline bodies, REPLACE for inline virtuals, PRE, ENGINE_INCLUDES, SKIP) are where the hand
   edits go while the headers are still generated; add the unit's types to the generator's type list and the PCH
   stand-in `Public/ShooterGame.h`'s include list. Compile until the static_asserts pass (five rounds the first
   time: vtable-pointer placeholder, template names, engine enums, an engine include, the PCH list).
5. **Draft** the unit by hand from the decompiles into
   `src/reimpl/ShooterGame/Source/ShooterGame/Private/<File>.cpp`, one `// ATLAS-ID: SRV@<va>   orig: <Class::Func>
   status: REIMPL` line and the `raw:` line above each hand-written function (inline bodies in headers carry theirs
   there), `deviations: none` in the file head; the ShooterGame sample's shape where ATLAS grew from it. No inline
   assembly, no embedded bytes (ADR-0006 point 5).
6. **Build**: `... build --source "D:\ATLAS\src\reimpl\ShooterGame\Source\ShooterGame\Private\<File>.cpp"
   --map "d:\atlassvn\projects\shootergame\source=D:\ATLAS\src\reimpl\ShooterGame\Source"` — our file with the
   unit's own switches (VS2013 Update 5) through the unit's precompiled header (`recompile_unit.py --pch`, built
   first from the force-included header; `--no-pch` is the pre-2026-10-31 way — a dllimport inline such as
   `_Container_base0::_Orphan_all` is inlined without the PCH and called through the import with it, and the STL's
   frames move); the cl and pch logs are beside the object. C4263/C4264 warnings mean a base-class
   signature our engine lacks (a hidden virtual = a new vtable slot): list it in SYS-engine-deltas.
7. **Judge**: `... judge` — `match.json`, `causes.json`; the line names the unit's own functions apart. A DIFF:
   `python _tools/disasm_obj.py build/loop/<unit>/<File>.cpp.obj "<decorated name>"` shows ours against theirs with the
   first difference marked (`--at=0x<va>` for an original function without a public, a lambda's `operator()`;
   the judge blanks lambda hashes); a source variant is a one-minute rebuild; a construct the headers decide (an
   engine type's constructor) is phase 4b's — a probe TU compiled with `recompile_unit.py --out build/loop/probe`
   settles it, and so are source-shape questions (`build/loop/probe/probe_redis.cpp`: `!IsEmpty()` against
   `Len() > 0`; `probe_emplace.cpp`: the order a key and a value are built in). A function ATLAS never inlines
   (`Cast<T>`, `FJsonObject::HasField`) gets `FORCENOINLINE` in the engine header and a SYS-engine-deltas row.
   **Fix rounds** (2026-11-08, the eighteenth unit): `python _tools/rebuild/unit_diffs.py <File>.cpp` lists the
   unit's DIFFs with their bodies file; `python _tools/rebuild/unit_probe.py <File>.cpp <probe.cpp> --variants N`
   compiles `#if PROBE == k` variants through the unit's PCH in seconds and judges each (`--funcs SRV@a,SRV@b` re-judges
   the port's current blocks; `--tag` lets fix-round subagents probe side by side; never while the unit builds). Dozens
   of DIFFs go to subagents in byte-balanced batches, each returning matching bodies in `@@ <va>` sections.
8. **Ledger and doc**: `... ledger --source <the .cpp>` (REIMPL, parity `match` for MATCH / MATCH-L; the compiler's
   functions get an ATLAS-ID block at the end of the source, the inline bodies' rows point at their header, a row
   another port owns is left alone) and `... doc --system SYS-<system>` (the section in `docs/systems/SYS-<system>.md`,
   replaced when it exists; narrative goes in a section of its own after it). Then `python _tools/rebuild/ledger_check.py`.
9. **Record**: the journal (the unit, the counts, what differed and why), the CHANGELOG line, the engine repository's
   own commit when an engine header was added; a commit with `Atlas-Stage: REIMPL` (the IDs in the source's block
   stand for the trailers when there are hundreds).

## Known
- **Notes live in `build/loop/<unit>/`**: briefs, the drafters' notes and the engine / header needs of a unit are written
  there (`notes.md`, `brief.md`), never only in a session scratchpad. The Windows reinstall of 2026-11-17 took the
  scratchpad with the forty-second unit's notes and the needs lists of units 43-46; what lay under `build/loop/`
  (bodies, probes, objects) survived on D: and was enough to go on.
- **The decompiler's tail jumps**: a function ending in `jmp` to another function shows the target's body as if
  inlined (`Super::X(); OnX();` looks like the event thunk's FindFunctionChecked + ProcessEvent; a five-byte override
  looks like a whole function). Read `disasm_at.py` first; the UHT 4.5 event thunks are in the generated .cpp.
- The `return true` defaults of a class fold with the engine's `TCppStructOps<...>::HasCopy` (`0x140c57930`); the
  judge finds them by name at that address. `return Damage;` folds with `UDamageType::HandleDamage`.
- A copy of a fixed array that alternates xmm0/xmm1 is `FMemory::Memcpy(..., sizeof)`, not a loop; a zeroed small
  field stored from a fresh zero register is `FMemory::Memzero`.
- `MATCH~`: a relocation reaches a symbol without a public name (a local static) — parity `match~`, read the site.
- `MATCH-L`: identical but for a `__LINE__` immediate — accepted as matching by ADR-0006's amendment (Q-0017).
- Two names at one address: the judge finds a folded function by the original's address when its first PDB name
  is another instantiation's (or `??_E` for our `??_G` destructor); `plan` and `ledger` read verdicts by address too.
- Functions the original's unit emits that no layout implies (a static in a header) stay absent until their source
  is found (Q-0022).
