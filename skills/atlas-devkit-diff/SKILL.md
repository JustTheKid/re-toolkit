---
name: atlas-devkit-diff
description: Diff our engine's modules against the ATLAS DevKit's editor DLLs — census, Ghidra import and exports per DLL, our reflection dump, reflection / metadata / enum / class-level diffs with a per-module verdict — then locate ATLAS's code changes from the DevKit PDBs. Use for phase 4b's editor steps (1.9e-1.9i, editor function parity) or whenever a module must be checked against the DevKit again, e.g. after a port.
---

# atlas-devkit-diff

Step 1.9d's workflow (2026-10-23) as tools in `_tools/devkit_diff/`. Results so far:
`tracking/evidence/reflection-editor.md`; background: `docs/knowledge/devkit.md`, `docs/systems/SYS-engine-deltas.md`
(step 1.9, "How deltas are found").

## Inputs
The modules to check (names or wildcards, e.g. `AnimGraph,UnrealEd`; default all) and a work folder without spaces,
e.g. `D:\ATLAS\build\devkit-diff\<step>` (git-ignored, survives sessions). In PowerShell, in `D:\ATLAS`:
```
$py = 'D:\ATLAS\_tools\ghidra-mcp-venv\Scripts\python.exe'
$W = 'D:\ATLAS\build\devkit-diff\1.9e'
```

## Rules
- 16 GB: one Ghidra JVM, build or commandlet at a time — step 2 never next to step 3.
- Steps 2 and 3 run long: a visible Terminal tab; `run_in_terminal` takes one literal command line, so call the `.ps1`
  with literal paths. `-DryRun` prints what they would run.
- The DevKit (`C:\Program Files\Epic Games\AtlasModKit`) is read-only. Its exports go to git-ignored
  `_re/corpus/devkit/`, never `_re/decompiled/`; DevKit functions get no ledger rows (Q-0011).

## Steps
1. **Census** (seconds): `& $py -I _tools\devkit_diff\census.py --work $W [--modules AnimGraph,UnrealEd]`
   → `$W\modules.tsv`: our modules with reflected types or enums that the server does not ship, our type / enum
   counts, the DevKit DLL (`Binaries\Win64`, then `Plugins\**`), `pdb|nopdb`, `in|new` (in the devkit Ghidra project).
   `--all-modules` adds the modules the server ships (Engine, UMG, AIModule: their editor-only members, step 1.9a).
2. **Import and export** (Terminal tab; step 1.9d: 65 DLLs in 2.5 h, ~3 min per PDB-only import):
   `powershell -ExecutionPolicy Bypass -File D:\ATLAS\_tools\devkit_diff\export.ps1 -Work <W> [-Modules ...]`
   - per DLL: `ghidra_analyze.py --pdb-only` (`--no-pdb` without a PDB: full analysis) if new; `devkit_metadata.py
     export` (untyped, `<corpus>\<module>`); with a PDB `ghidra_find.py ... --fix-imports <dll>` (typed,
     `<module>-typed`). Resumable. The Engine's `AActor` / `FPostProcessSettings` need `-MaxPayload 1024`.
   - check: `& $py -I _tools\devkit_diff\check_exports.py --work $W` (Z_Construct counts per kind against ours, the
     last error line of each log in `$W\logs`).
3. **Our dump** (Terminal tab; after any engine change `-Build` first, ~75 min if an Engine header changed):
   `powershell -ExecutionPolicy Bypass -File D:\ATLAS\_tools\devkit_diff\dump.ps1 -Work <W> [-Modules ...] [-Build]`
   → `$W\ours\<Module>`: one `AtlasFormatTest -reflectionall=Settings,LevelEditor,SoundMod,<modules>` run, missing
   modules retried alone. It ends with `dumped N of N`; the commandlet's own exit code is not the result.
4. **Diffs** (static; 65 modules 40 s, 70 s with `--classes`; Engine + UMG 100 s):
   `& $py -I _tools\devkit_diff\diffs.py --work $W [--modules ...] [--classes] [--ours <dir>]`
   - `reflection_diff_all.py <typed (untyped without PDB)> <ours> --dll <dll> --editor --mask 0xD8000000000000`;
     `devkit_metadata.py parse` (→ `<corpus>\<module>.metadata.jsonl`) + `metadata_diff.py`; `enum_diff.py` when
     either side has enums; with `--classes` `reflection_classes.py --dll` (validated on AnimGraph, BlueprintGraph,
     GraphEditor, UnrealEd, SpeedTreeImporter).
   - Reports `$W\diff\<module>_{refl,meta,enum,classes}.md` (+ `.json`); `$W\summary.md`: a verdict per module and
     "N of M modules with a DevKit DLL identical". Read the `.md` of every module that differs.
5. **Find ATLAS's code for what differs** (DevKit DLLs have PDBs; the PDB-only Ghidra project has no references):
   - functions, prototypes, source lines: `& $py -I _tools\pdb_lookup.py <dll> "<Class>::*" --lines`
   - where ATLAS's source file gains or loses lines: `_tools\pdb_file_lines.py <dll> <our .cpp> ["<Class>::*"]`
   - which lines inside one function: `_tools\pdb_func_lines.py <dll> <function> --overlay <our .cpp> [from to]`
   - callers and users (inlined constructors via `--data`: vtable / `PrivateStaticClass` loads):
     `_tools\pe_callers.py <dll> <pattern | VA> [--data]`
   - LOCTEXT keys and string order (decompiles drop the key): `_tools\lea_strings.py <dll> <pattern> [--ascii]`
   - layout, or methods with vtable slots: `_tools\pdb_struct.py <dll> [--methods] <Class>`; metadata of a type:
     `_tools\devkit_metadata.py show <jsonl> <type> [member]`
   - a decompile: `_tools\ghidra_find.py "^<Class>::<Func>$" --decompile --project D:/ATLAS/_re/ghidra-devkit --name
     devkit --program UE4Editor-<M>.dll --fix-imports <dll> --out _re/corpus/devkit/<topic>`; the instructions when a
     value decides behaviour: `_tools\ghidra_listing.py <va> --project ... --name devkit --program ...`
6. **Port** (as steps 1.9a-1.9d): declarations `& $py -I _tools\devkit_diff\codegen.py <dll> <Z_Construct_...@va.c>
   $W\ours\<M>\<Class>.jsonl [--apply <header> --type <UClass>]`; metadata `_tools\metadata_apply.py
   $W\diff\<module>_meta.json <jsonl> <module source dir> [--dry-run]`; defaults from the DevKit constructor's code
   (`ghidra_find.py --address <va> --stores`). Then step 3 with `-Build` and step 4 again, and compare: copy
   `$W\diff` to `$W\diff-before` before re-running, then
   `& $py -I _tools\devkit_diff\compare_reports.py $W\diff-before $W\diff`. The server tables and content sweeps
   after any engine change: SYS-engine-deltas step 1 and `tracking/evidence/content-audit-*.md`; sweep with
   `_tools\sweep.ps1 -Log <file> [-Assets] [-Content <folder>]` (never the commandlet straight in a Terminal tab:
   its console output makes it 5x slower).

## Reading the verdict
- "identical" = all types / functions identical, no ATLAS-only or ours-only types (`AtlasFormatTestCommandlet` is
  ours), no metadata difference, no ATLAS-only member, enums identical, classes identical if run.
- Not counted, shown in the cell: our metadata entries with only skipped keys (ModuleRelativePath: a member the
  DevKit parse has no entry for, GameProjectGeneration's one); "fns not exported" (a typed export of classes and
  structs only: Engine / UMG / AIModule from step 1.9a); "ATLAS flags not read" (PDB-less plugins: the flags were not
  read, every UHT class has CLASS_Native).
- Known after step 1.9e and the metadata corrections (2026-10-24): all 65 identical; Engine, UMG,
  AIModule, TrueSkyPlugin, OculusLibrary identical; HoudiniEngineRuntime 30 / 31 (its settings' runtime EditConst
  bits, reflection-modules.md). With `--classes` EditorStyle
  differs: its config name is stored by a byte-copy loop `reflection_classes.py` does not read (not a difference).
  With `--all-modules`: CoreUObject "differs" by UInterface's two class values (set in `Interface.cpp`'s
  `IMPLEMENT_CORE_INTRINSIC_CLASS`, the same in ours; `metadata_diff.py` reads UHT output only) and SlateCore by
  `UFontProviderInterface` (UE 4.6's font provider, plan step 3). The 12 modules marked `new` in the census (server
  modules never imported into the devkit Ghidra project) stay pending.

## Must update
`tracking/evidence/reflection-editor.md` (module table, the summary headline), the step's row in
SYS-engine-deltas, journal, `docs/CHANGELOG.md`; ODD- / DN- entries for findings (`devkit_metadata.py notes` for a
module's developer notes, wording local only); `docs/knowledge/tooling.md` for tool fixes, with a
`compare_reports.py` run showing earlier reports unchanged.

## Gotchas
- UE 4.5's `GENERATED_*_BODY()` macros are keyed by line: never edit a reflected header while a build runs.
- An editor class in a new header may compile in ATLAS through an include ours lacks: check each new type's
  includes before the 75-minute build.
- Engine files are LF; Python `write_text` on Windows writes CRLF: write bytes or use the Edit tool.
- The Ghidra server project is `--name atlas`; the DevKit one `--project D:/ATLAS/_re/ghidra-devkit --name devkit`
  (absolute path for `ghidra_find.py`). No other process may have the project open.
- DevKit decompiles drop LOCTEXT's key (`lea_strings.py`); an import printed as `DAT_<rva>` is named by the
  hint/name entry at `rva + 2`; a decompile can misprint a bound value (check the listing).
- UHT keeps `//` comments as tooltips unless a block comment follows: a `// ATLAS` citation above a `UPROPERTY`
  without ATLAS tooltip needs a `/* ~ */` line.
- A DLL without a PDB is read from its untyped export: `--fix-imports` turns its calls into `PTR_DAT_`.
- The metadata, enum and class diffs read our UHT output (`Inc/<Module>`), not the dump: a run on old dumps still
  compares today's generated code. UHT alone (`UnrealHeaderTool.exe UE4Editor <Engine>\Intermediate\Build\Win64\
  UE4Editor\Development\UnrealHeaderTool.manifest`, a minute) regenerates it, so metadata fixes can be checked before
  the 20-75 minute build.
- A gap in `devkit_metadata.py` shows as silence or as a value on the neighbouring member, not as an error (step
  1.8d wrote such values into our headers, fixed 2026-10-24). After changing the parser, re-parse every
  `<corpus>\*.metadata.jsonl` into a separate folder and compare with the old files before trusting a verdict;
  members named `?<variable>` in a JSONL are objects the parser did not trace.
- `-reflectionall` with one package dumps into `-out` itself and skips the list mode's setup (Settings, Slate's
  generic commands); `dump.ps1` always lists more than one.

## Common failures
| Symptom | Cause |
|---|---|
| `modules.tsv not found` | step 1 first (each work folder has its own census) |
| a module "pending: no ..." | its export (step 2) or dump (step 3) is missing; rerun that step with `-Modules` |
| a module missing after `dump.ps1`'s retry | it crashed loading: `$W\logs\refl_<m>.log`; add what it needs first to `-Preload` (1.9d: LevelEditor for Levels, SoundMod for SoundModImporter) |
| `dump.ps1` refuses the work folder | it contains spaces (UE's command line cuts `-out=`) |
| "ReturnValue: UBoolProperty extra in ours", an object property typed as its owner's parent, nameless bool members in metadata | extractor gaps fixed in step 1.9d (`reflection_table.py`, `devkit_metadata.py`); if one returns, a new decompiler form: fix the extractor, re-run, `compare_reports.py` |
| typed decompiles call imports without stack arguments | exported without `--fix-imports` |
| `ghidra_find.py` finds no functions | relative `--project` path, or the project is open elsewhere |
