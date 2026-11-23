# RE toolkit

## What this is

A portable copy of the tools and the working method of this repository's main project: a 1:1 rebuild, by matching
decompilation, of a Windows game that ships its PDBs (an Unreal Engine 4.5 fork; server and client executables with
full PDBs; built with Visual Studio 2013 Update 5). The folder is meant to be carried to another project of the same
kind: reverse engineering, matching decompilation or a rebuild of a Windows program that comes with PDBs.

| Path | Content |
|---|---|
| `README.md` | This summary and index. |
| `scripts/<category>/` | Byte-for-byte copies of 106 of the 145 files of its own that the project keeps under `_tools/` (Python and PowerShell scripts, one C++ source, one git hook, two JSON data files; third-party installs, caches, the grid configs and the local secrets file are not counted). Sorted into 12 categories. Nothing in them was edited. |
| `skills/` | The nine Claude skills of the project (`<name>/SKILL.md`). |
| `templates/` | The master prompt, the working rules, the pre-commit hook, the git ignore / attributes files, the decision-record index, the MCP configuration and `ledger-schema.md`. |
| `MANIFEST.tsv` | One row per copied file: source path (relative to the repository root), toolkit path, bytes, SHA-256, portability tag. |

Not included: any third-party tool, game binaries, PDB content, decompiled code, DevKit-derived data, the project's
hook-DLL and reimplementation sources, and anything with credentials. The 39 files that only make sense for this
game are listed, one line each, in [Left in the project](#left-in-the-project-game-specific).

The copies were taken from the working tree on 2026-11-23 (HEAD `926ff431`), while other sessions were working in
the repository. At that time `_tools/rebuild/baseline.py` and `.claude/skills/atlas-unit-loop/SKILL.md` carried
uncommitted changes, and `_tools/minidump_stacks.py` and `_tools/rebuild/trace.py` were untracked files; the copies
are the working-tree versions. `MANIFEST.tsv` records the SHA-256 of each file as copied, so a later change in the
project shows as a hash difference.

### Portability tags

| Tag | Meaning |
|---|---|
| `generic` | Runs on another target unchanged. Everything target-specific is a positional argument or an option. Where an option's default points at this project, the table says so. |
| `adapt` | Needs an edit first: a path, name, constant or table of this project is fixed in the code, or the script assumes Unreal Engine 4 conventions. The table says what. |
| `specific` | Only meaningful for this game. Not copied. |

Of the 106 copied files, 39 are `generic` and 67 are `adapt`; 39 are `specific` and stayed in the project.

### The category folders are for reading; run the scripts from the original layout

The scripts import each other by module name (`from func_match import Original`), start each other by path
(`_tools/recompile_unit.py`), and find the repository through their own location: a top-level script takes its
parent folder's parent as the repository root, a script from `rebuild/` or `devkit_diff/` goes one level further up.
Beside `_tools` they expect `_re/cache`, `_re/decompiled`, `build/`, `tracking/` and `src/reimpl`. Sorted into
category folders they would not find each other, and they were not edited to make them do so.

To use them, put them back the way they were. `MANIFEST.tsv` holds every file's original path:

```python
import csv, pathlib, shutil, sys

kit = pathlib.Path(sys.argv[1])    # this folder
dest = pathlib.Path(sys.argv[2])   # the new project's root
with open(kit / "MANIFEST.tsv", encoding="utf-8", newline="") as f:
    for row in csv.DictReader(f, delimiter="\t"):
        if row["toolkit_path"].startswith("scripts/"):
            out = dest / row["source"]
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(kit / row["toolkit_path"], out)
```

That gives `_tools/*.py`, `_tools/rebuild/`, `_tools/devkit_diff/` and `_tools/testserver/` (three files) under the
new root. Then work through [Adapting to a new project](#adapting-to-a-new-project).

Conventions from the working rules: run the top-level scripts as `python -I _tools/<name>.py`, and the ones in
`_tools/rebuild/` without `-I` (they import their siblings).

## Pipeline

The order in which the tools are used on a target, as the project's docs describe it
(`docs/knowledge/matching-decompilation.md`, `docs/knowledge/tooling.md`, the `atlas-unit-loop` skill).

1. **Freeze the originals.** The installs are read-only. `ledger/baseline.py` writes SHA-256 manifests of every
   exe, dll, pdb, lib, exp and ini, and `--check` detects drift later.
2. **Read the PDB, before any disassembler.** `pdb/pdb_lookup.py` (functions, sizes, prototypes),
   `pdb/pdb_struct.py` (layouts, enums, methods with vtable offsets), `pdb/pdb_vtable.py` (what a vtable slot
   holds), `pdb/pdb_buildinfo.py` (each compile unit's exact compiler command line, which also names the compiler),
   `pdb/pdb_source_md5.py` (which source files are stock, changed or new, if a stock source tree exists),
   `pe/pe_bytes.py` and `pe/pe_imports.py` (fingerprint, imported SDKs). These need dbghelp or llvm-pdbutil only,
   no Ghidra; the docs note that `pdb_lookup.py` takes about 17 seconds and works while the game runs.
3. **Ghidra import and export.** `ghidra/ghidra_analyze.py --pdb-only` imports a binary with its PDB (the docs
   measured 15 to 17 minutes per binary, about 98% of functions named). `pdb/pdb_locals.py build` indexes the PDB's
   parameter and local names, which Ghidra 12.1.4 does not apply for optimised code. `ghidra/ghidra_find.py
   --decompile` writes raw decompiles (`_re/decompiled/<bin>/<Class>__<Func>@<va>.c`, never hand-edited, hashed
   into the ledger); `ghidra/ghidra_bulk_export.py` writes a searchable corpus; `ghidra/ghidra_mcp_server.py`
   serves the project to an agent through pyghidra-mcp.
4. **Headers from the PDB.** `abi-layout/gen_headers.py` writes layout headers with a `static_assert` for every
   size and offset. Compiled in a probe with a unit's own command line they prove the layout or name the base
   that differs. For an existing source tree that must reach the original's ABI: `abi-layout/abi_diff.py`,
   `abi_codegen.py`, `abi_apply.py`, `export_diff.py`.
5. **Recompile a unit with the original command line.** `matching/recompile_unit.py` takes the unit's command line
   from the PDB, maps its paths onto our trees and compiles our source with the original compiler (VS2013 Update 5
   here), through the unit's precompiled header with `--pch`. `matching/unity_unit.py` rebuilds a unity unit first.
6. **Judge byte for byte.** `matching/func_match.py` compares every function of our object with the same decorated
   name in the original; relocation sites are compared by target symbol and offset, not by bytes. Verdicts:
   MATCH, MATCH~ (bytes agree, some targets unchecked), MATCH-L (identical but for source line / file arguments
   of log and assert calls), DIFF, SIZE, MISSING. For the DIFFs: `matching/judge_causes.py` (root-cause buckets),
   `matching/inline_diff.py` (inlining decisions on both sides), `matching/disasm_obj.py` (both sides in one
   screen), `unit-loop/unit_probe.py` (source variants in seconds).
7. **Ledger.** Each function has one row in `tracking/functions.csv` with its status and parity;
   `ledger/ledger_check.py` runs as the pre-commit hook. See `templates/ledger-schema.md`.
8. **Regression.** `unit-loop/regress.py` rebuilds and re-judges every ported unit after a change to shared
   headers and reports each row that was `match` and is not any more. `matching/judge_compare.py` compares two
   judge runs.

Around that core:

- **The per-unit loop** (`unit-loop/unit_loop.py <unit> <step>`): `plan`, `export`, `headers`, then the draft by
  hand (`unit_skeleton.py` writes the skeleton, `unit_fill.py` assembles bodies written in batches), `build`,
  `judge`, `ledger`, `doc`. One original `.cpp` is one work unit.
- **Work order**: `runtime/reach_record.py` records which functions a real session executes, in first-hit order.
- **Hybrid link** (`delink/`): the original binary delinked into COFF objects with ghidra-delinker, relinked with
  the original linker, and judged objects of ours swapped in function by function, so that a partly rebuilt
  program runs.
- **Runtime checks** (`runtime/`): offline minidump stacks, an unwinder without a debugger, Frida call traces.

## External tools

Third-party tools the project uses. None of them is copied here. Versions, sources and licences are the ones the
project's docs record (`docs/knowledge/tooling.md`, `docs/knowledge/references.md`,
`docs/knowledge/environment.md`); "not stated" means the docs do not give a licence.

| Tool | Version used | Comes from | Licence | Used for |
|---|---|---|---|---|
| Ghidra | 12.1.4 (2026-09-21) | NSA GitHub release `ghidra_12.1.4_PUBLIC_20260921.zip`, SHA-256 checked | Apache-2.0 | Import and analysis with the PDB, decompiles, host of the delinker. |
| Temurin JDK | 21.0.12.1+1 | Adoptium GitHub `OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip`, SHA-256 checked | not stated | Runs Ghidra; `javac` and `jar` for `delink_patch.py`. |
| uv | 0.13.4 | PyPI | not stated | Creates and manages the Python environment. |
| Python | 3.12, uv-managed | uv | not stated | The venv `_tools/ghidra-mcp-venv` every script runs in. |
| pyghidra-mcp | 0.2.7 (with pyghidra 3.1.0, jpype1 1.5.2, chromadb 1.5.9, mcp 1.30.0) | PyPI | Apache-2.0 | Ghidra MCP server for the agent; pyghidra is what all `ghidra_*.py` and `delink_*.py` scripts drive Ghidra with. |
| Frida | 17.22.2 | PyPI wheel `frida-17.22.2-cp37-abi3-win_amd64.whl` | wxWindows Library Licence | Runtime tracing: `reach_record.py`, `delink_trace.py`, the game-specific `frida_*.py`. |
| capstone | 5.0.9 (the module reports 5.0.7) | PyPI wheel, installed offline into the venv | BSD | Disassembly in `judge_causes.py`, `func_match.py` (MATCH-L), `disasm_obj.py`, `pe_compare.py`, `pe_imagerel.py`, `tiny_bodies.py`, `symbols.py`, `delink_all.py`. |
| llvm-pdbutil (and llvm-readobj) | LLVM 19.1.5 | Visual Studio 2022's component "C++ Clang tools" (`Microsoft.VisualStudio.Component.VC.Llvm.Clang`), in `VC\Tools\Llvm\x64\bin` | not stated | PDB dumps: publics, section contributions, build info, file lists and MD5s, line tables, symbols and inline sites. Every PDB tool that is not dbghelp-based needs it. `llvm-readobj --codeview` reads our objects in `inline_diff.py`. |
| Visual Studio 2013 Update 5 (Community) | 12.0.40629; `cl.exe` 18.00.40629.0, MSBuild 12.0, Windows Kits 8.1 | Microsoft, `vs2013.5_ce_enu.iso` | not stated | The original's compiler: every matching build. Its `link`, `lib` and `dumpbin` for the probe DLL and the relink. |
| Visual Studio Build Tools 2022 | 17.14, toolset 14.44.35207, Windows 11 SDK 26100 (until 2026-11-17: VS 2022 Community, toolsets 14.38.33130 and 14.44.35207, Windows SDK 10.0.22621.0) | Microsoft | not stated | Builds the hook DLL, the launcher and the helper tools (`vswhere` + `vcvars64.bat`); provides the LLVM tools above. |
| dbghelp | Windows' own `C:\Windows\System32\dbghelp.dll` (version not recorded) | Windows | not stated | PDB lookups without Ghidra: symbols, types, line info, name undecoration, `StackWalk64`. |
| MinHook | 1.3.4 | GitHub `TsudaKageyu/minhook` source zip, vendored in the project's `src/third_party/minhook` | BSD-2-Clause (+ HDE BSD) | x64 function hooking in the project's hook DLL. |
| ghidra-delinker-extension | 0.9.2 | GitHub release `boricj/ghidra-delinker-extension` v0.9.2 | Apache-2.0 | Delinks a Ghidra program into relocatable COFF objects. Installed only into an isolated Ghidra settings folder; patched by `delink_patch.py`. |
| Redis for Windows | 3.2.100 | The game's server package | not stated | The game's database for the local test stack. |
| SteamCMD | self-updating | Bundled with the game | not stated | Downloads the dedicated server. |
| git | 2.56.0.windows.4 | Git for Windows | not stated | Version control; the ledger's history through commit trailers; the pre-commit hook. |
| Sysinternals procdump | shipped in the server's binaries folder (version not recorded) | Microsoft Sysinternals | not stated | Crash dumps of the relinked exe (the game-specific `delink_boot.ps1`). |
| autoit-ripper | 1.2.0 with pefile 2024.8.26 | PyPI, in a throwaway venv | MIT (both) | One audit of a third-party AutoIt tool; not part of the pipeline. |
| Docker with `postgres:18-alpine`, Node (`npx tsx`) | not recorded in `tooling.md` | n/a | not stated | Only the game-specific `start-accounts.ps1` (the project's accounts service). |

Source dependencies of the rebuilt target, not tools: the UE 4.5.1 engine source tree (kept in its own local
repository, with UnrealBuildTool and UnrealHeaderTool), and `cpp_redis` 4.3.1 with `tacopie` 3.2.0 (MIT), the
library versions the original links.

## Our own tools

Paths in the first column are relative to `scripts/<category>/`. "(from `rebuild/`)" and "(from `testserver/`)"
mark files whose original home is that sub-folder of `_tools/`. In the "Reads -> writes" column, `<repo>` is the
repository root the script derives from its own location.

### `pdb/`: reading PDBs (12)

| File | What it does | Reads -> writes | Needs | Tag |
|---|---|---|---|---|
| `pdb_lookup.py` | Looks up functions by a dbghelp wildcard: VA, size and the full C++ prototype from the undecorated public symbol. `--lines` adds the source file and line, `--data` global variables. | exe or dll with its PDB beside it -> stdout | dbghelp | `generic`. Prints addresses as RVA + 0x140000000 (`IMAGE_BASE`), whatever the image's own base. |
| `pdb_struct.py` | A struct's or class's members with offsets, types and bitfields; an enum's values; `--methods` lists member functions in declaration order with the vtable offset of each virtual. Also the `Pdb` class other tools import. | PE + PDB -> stdout | dbghelp | `generic` |
| `pdb_enum.py` | Lists an enum's members with values, or finds type names by a dbghelp mask (`--find`). | PE + PDB -> stdout | dbghelp | `generic` |
| `pdb_vtable.py` | Names the function a class's vftable slot holds: the table's address from the PDB public, the slot's target from the file's bytes, the target's name from the PDB. A slot range or `--match <regex>` over every vftable. | PE + PDB -> stdout | dbghelp, `pdb_struct.py` | `generic` for images whose preferred base is 0x140000000; the project's docs note that DLLs at 0x180000000 fail with "no primary vftable". |
| `pdb_func_lines.py` | The source lines a function's code comes from (line info asked at every byte, so inlined header code does not stop it). `--overlay <our file>` prints our file with the original's code lines marked. | PE + PDB (+ our source file) -> stdout | dbghelp | `generic` |
| `pdb_file_lines.py` | Where one source file of the original differs from ours: each function's first line in the original next to ours, with the offset; a changing offset marks added or removed lines. | PE + PDB + our source file -> stdout | dbghelp, `pdb_lookup.py` | `generic` |
| `pdb_buildinfo.py` | A compile unit's exact compiler command line from the PDB (`S_BUILDINFO` -> `LF_BUILDINFO`: working directory, compiler, source, PDB, arguments). `--split`, `--args-only`, `--limit`. | PE or PDB + unit regex -> stdout | llvm-pdbutil | `generic` |
| `pdb_locals.py` | Every function's parameters and locals with their live ranges, read in one streaming `llvm-pdbutil dump -symbols` pass into an SQLite index (`build`, `show`, `stats`). The Ghidra exporters prepend each function's block and rename `param_N` to the PDB's names. | PDB -> `<repo>/_re/cache/<pdb stem>.locals.sqlite` | llvm-pdbutil | `generic`: pass a PDB path and, if wanted, `--cache`. The `PDBS` shortcut table names this project's two PDBs. |
| `pdb_decl.py` | The undecorated declarations of named functions from the original PDB's publics, every overload with its address (`Class::method`, `Class::*`, `::global`, `va:<hex>`). | the original exe + PDB -> stdout | `func_match.py` (llvm-pdbutil cache), dbghelp | `adapt`: a `sys.path` entry `D:\ATLAS\_tools`, the `EXE` path and the image base are fixed. |
| `pdb_source_md5.py` | Which of the original's source files are stock: the MD5 of every source file the PDB records against the files of a stock commit in a git repository of the source. Counts per area, `--tsv`, `--list`. Also holds `pdbutil()`, the function all other tools use to find llvm-pdbutil. | PE or PDB + a git repo with the stock source -> stdout, TSV | llvm-pdbutil, git | `generic`: the defaults of `--engine`, `--stock` and `--prefix` are this project's (`D:/UE/4.5.1`, `14d2ac8`, `d:\atlassvn\`). |
| `pdb_methods_diff.py` | Which member functions a class has in one binary and not in another, from the two PDBs; overloads once per name, generated members left out. | two PEs with PDBs + class names -> stdout | dbghelp through `pdb_struct.py --methods` | `generic` |
| `unit_contribs.py` | One compile unit's section contributions: the module that holds a VA, its ranges with the PE section names (`--ranges`, the input of `delink_unit.py`), the publics inside (`--symbols`). | the judge's cache `<repo>/_re/cache/<exe>.pdbsyms2.pkl` + the PE -> text files | a `func_match.py` run that wrote the cache | `adapt`: `PE`, `CACHE` and `BASE` are fixed. |

### `pe/`: reading PE files (5)

| File | What it does | Reads -> writes | Needs | Tag |
|---|---|---|---|---|
| `pe_bytes.py` | PE fingerprint (TimeDateStamp, SizeOfImage, ImageBase, ASLR) and the raw bytes at a VA. Known limit: a VA past a section's raw size prints the file's next bytes instead of zeros. | exe -> stdout | Python only | `generic` |
| `pe_callers.py` | Callers of functions from the code bytes: every direct `call` / `jmp rel32` to a target, mapped to the PDB function that contains it; `--data` adds RIP-relative `lea` / `mov` of the targets. For PDB-only Ghidra databases, which have no references. Direct references only. | PE + PDB -> stdout | dbghelp through `pdb_lookup.py` | `generic` |
| `pe_imports.py` | The DLLs a PE imports (import and delay-load directories), its linker version and, with `--strings REGEX`, matching printable strings: which third-party SDK a binary was built against. | PE(s) -> stdout | Python only | `generic` |
| `lea_strings.py` | The string operands of each function's RIP-relative `lea rdx / r8 / r9` in code order, with the function's source file and line; `--ascii` adds ASCII strings. Recovers string arguments a decompile drops. | PE + PDB -> stdout | `pdb_lookup.py --lines`; the `PE` class of `devkit_metadata.py` (in `ue4-reflection/`) | `generic` |
| `find_version_checks.py` | Finds code that compares against given constants (`cmp` with a 32-bit immediate, or small values against a struct field with `--field`) and names the function each hit is in. A static first pass; false positives are possible. | exe + PDB -> stdout | dbghelp | `generic` |

### `ghidra/`: analysis, find and decompile (8)

All eight drive Ghidra headless through pyghidra. They set `GHIDRA_INSTALL_DIR` and `JAVA_HOME` to the folders
`ghidra_12.1.4_PUBLIC` and `jdk-21.0.12.1+1` beside the script unless the variables are already set.

| File | What it does | Reads -> writes | Needs | Tag |
|---|---|---|---|---|
| `ghidra_analyze.py` | Imports a binary into the shared project and runs a one-time analysis with its PDB. `--pdb-only` (minutes), `--no-pdb` for a binary without a PDB (full auto-analysis), `--decompile`. Expensive analyzers that matter little with a full PDB are off. | binary (+ PDB) -> Ghidra project | Ghidra, JDK, pyghidra | `adapt`: Ghidra / JDK folder names, defaults `--project D:\ATLAS\_re\ghidra --name atlas`, the output folder picked by exe name. |
| `ghidra_find.py` | Lists functions by a regex on the qualified name or by address; `--decompile` writes `<Class>__<Func>@<va>.c`. Also `--callees`, `--stores` (memory writes as base+offset = value), `--address-file` with `--workers` and `--skip-existing`, `--fix-imports <dll>`, `--max-payload`, `--no-locals`. | Ghidra project -> `_re/decompiled/{server,client}` or `--out` | Ghidra, JDK, pyghidra, `ghidra_imports.py`, `pdb_locals.py` | `adapt`: as above, plus the default `--program`. |
| `ghidra_imports.py` | Gives a PDB-only program its imports back for one run: re-creates each import slot's pointer and external reference and types it with the demangled prototype. For DLLs whose PDB types one import slot as a large array that hides the slots after it. Used by `ghidra_find.py --fix-imports`; rolled back, the project is not changed. | Ghidra program + the DLL file -> (in memory) | Ghidra, JDK, pyghidra | `adapt`: defaults `--project D:\ATLAS\_re\ghidra-devkit --name devkit`. |
| `ghidra_info.py` | Prints addresses of named symbols and offsets of struct fields. | Ghidra project -> stdout | Ghidra, JDK, pyghidra | `adapt`: defaults name the client project and `AtlasGame.exe`. |
| `ghidra_listing.py` | Instruction listing of functions (address, bytes, mnemonic, operands, the callee's name for calls), for when a decompile hides data movement. | Ghidra project -> stdout or `--out` | Ghidra, JDK, pyghidra | `adapt`: project, name and program defaults. |
| `ghidra_xrefs.py` | Finds functions that reference given UTF-16 / ASCII strings and decompiles them. Needs a full analysis: a PDB-only database has no string references. | Ghidra project -> `--out` | Ghidra, JDK, pyghidra | `adapt`: project path, name and program are fixed in the code. |
| `ghidra_mcp_server.py` | Starts pyghidra-mcp on the project with the full-binary code index disabled (it would decompile every function at start-up). Launched over stdio from `.mcp.json`. | Ghidra project | pyghidra-mcp, Ghidra, JDK | `adapt`: default project path and name. |
| `ghidra_bulk_export.py` | Bulk-decompiles the game-code classes into a searchable corpus `_re/corpus/<bin>/<Class>/<Function>@<va>.c` with `_index.tsv` and `_failed.tsv`, on a copy of the project. Resumable; `--reindex`, `--refresh`, `--all`. | copy of the Ghidra project -> `<repo>/_re/corpus/<bin>/` | Ghidra, JDK, pyghidra, `pdb_locals.py` | `adapt`: the `BINS` table (projects, programs, hash prefixes of the two binaries) and the `GAME_CLASS` name filter. |

### `matching/`: recompile, judge, causes (10)

| File | What it does | Reads -> writes | Needs | Tag |
|---|---|---|---|---|
| `recompile_unit.py` | Compiles one of our files the way the original compiled the matching unit: the command line from the PDB, its paths mapped onto our trees, the precompiled-header switches dropped (header force-included) or, with `--pch`, the unit's precompiled header built first. `--source`, `--map`, `--define`, `--dry-run`. | original PE + PDB, our source -> `<out>/<unit>.obj`, `.rsp`, `.log` | llvm-pdbutil (`pdb_buildinfo.py`), VS2013 through `vcvarsall.bat` | `adapt`: `VCVARS`, `ENGINE`, and the default path maps from `d:\atlassvn\...` onto this project's trees. |
| `unity_unit.py` | Rebuilds one of the original's unity compile units (`Module.<Module>.N_of_M.cpp`) from the PDB's file list, its `.cpp` files in UnrealBuildTool's order and mapped onto our tree; files we lack are listed and left out. `--at <VA>` picks the unit that holds a function. | PE + PDB -> `<out>/<unit>.cpp` | llvm-pdbutil, `recompile_unit.py`, `func_match.py` | `adapt`: the path maps are `recompile_unit.py`'s; the ordering rule is UnrealBuildTool 4.5's. |
| `func_match.py` | The byte-matching judge: each function of our object against the same decorated name in the original; relocation sites compared by target symbol and offset. MATCH / MATCH~ / MATCH-L / DIFF / SIZE / MISSING. `--names`, `--verbose`, `--json`. Also the `Coff` and `Original` classes most other tools import. | our `.obj`, original PE + PDB -> stdout, `--json`; cache `<pdb>.pdbsyms2.pkl` in `--cache` (default `<repo>/_re/cache`) | llvm-pdbutil, dbghelp, capstone | `generic`. The MATCH-L rule lists UE's fatal-log and assert functions (`LINE_SINKS`); a code base with other log functions would add its own there. |
| `judge_causes.py` | Why the judge's DIFFs differ: both functions disassembled, targets named, the first differing instruction sorted into root-cause buckets (vtable slot shift, `sizeof`, member offset, callee, register allocation, judge gap). `--details N`, `--json`. | our `.obj`, original PE, `match.json` -> stdout, JSON | capstone, `func_match.py` | `adapt`: some bucket rules name this project's findings (for example UObject's 14 extra virtuals, `sizeof(UClass)`). |
| `judge_compare.py` | Two judge runs compared function by function: per unit the byte-identical count before and after, the functions gained and the ones lost. | two run folders or `match.json` files -> stdout | Python only | `generic` |
| `judge_files.py` | The judge's verdicts grouped by the source file the original compiled each function from, with that file's state (stock / changed / new) from `pdb_source_md5.py`'s table. | PE + PDB, `match.json`, the TSV -> stdout | dbghelp | `generic`: the default of `--tsv` is this project's table. |
| `judge_module.ps1` | The judge over a whole engine module: every unity unit rebuilt, compiled and judged; optionally the generated units (`-Generated N`) and the causes (`-Causes`). | -> `<Out>\<unit>\` and `summary.tsv` | everything above | `adapt`: `$py`, `$sv`, `Set-Location D:\ATLAS`, UE's unit names. |
| `inline_diff.py` | Inlining decisions on both sides: a function's inline tree in our object and in the original's PDB, and where one side calls what the other inlines. `--tree`; `--match <match.json>` counts the causes over a judge run. Our object must carry CodeView (`/Z7 /Zo`). | our `.obj`, PE + PDB -> stdout; cache `<repo>/_re/cache/pdbsym` | llvm-pdbutil, llvm-readobj, `func_match.py` | `generic` |
| `disasm_obj.py` | Our object's function disassembled with the relocation targets named, side by side with the original's bytes, the first differing byte marked. `--ours-only`, `--theirs-only`, `--at=0x<va>`. | our `.obj`, the original exe -> stdout | capstone, `func_match.py` | `adapt`: a `sys.path` entry `D:\ATLAS\_tools`, `EXE`, `IMAGE_BASE`, the locals cache's file name. |
| `server_stubs.py` | Functions one build compiles to a stub (`ret`, `return 0 / 1`, a jump) while another build has a real body, from both PDBs: build-configuration guards still to port. | two PEs with PDBs -> stdout, `--tsv` | `func_match.py` (llvm-pdbutil) | `generic` |

### `abi-layout/`: layouts, vtables, headers from the PDB (8)

| File | What it does | Reads -> writes | Needs | Tag |
|---|---|---|---|---|
| `abi_diff.py` | The C++ ABI (layouts, vtables) of two binaries' classes. `probe` links one of our objects into a probe DLL + PDB (unresolved externals allowed), `dump` writes each class's size, members and virtuals from a PE's PDB, `compare` lists per class its own changes apart from classes only shifted by a base. | `.obj`, PE + PDB -> `probe.dll`, JSON dumps, a report | dbghelp (`pdb_struct.py`), VS2013's linker | `adapt`: `VCVARS`; the default type list is the non-template `U` / `A` / `F` names (`--regex` takes any). |
| `abi_codegen.py` | One class's ABI difference as edits to our header, from two `abi_diff.py` dumps: missing members as declarations after the nearest shared member, new virtuals by vtable slot with signatures from the decorated names, `MOVE` and `VIRTUAL` edits. `--bodies`, `--names-from <PE>`. | original exe, two dumps -> edit list on stdout | dbghelp, capstone, `abi_diff.py`, `gen_headers.py`, `pdb_struct.py`, `pdb_vtable.py`, `pdb_func_lines.py`, `tiny_bodies.py` | `adapt`: types are written in UE's spelling (`UE_TYPES`). |
| `abi_apply.py` | Applies an `abi_codegen.py` edit list to a header, each group after its anchor with one leading citation comment. Prints the plan; `--write` applies. CHANGE / REMOVE and unplaceable edits are only reported. | header, class, edits -> header | Python only | `adapt`: anchors on UHT's `GENERATED_*_BODY()`, `UPROPERTY` and `UFUNCTION` macros; the comment prefix `// ATLAS (`. |
| `export_diff.py` | The exported functions two builds of a module differ in, per class, from the PE export tables: a decorated name only one side has is a missing function or a changed signature, which a layout diff cannot see. | two DLLs -> stdout | dbghelp (undecoration) | `generic` |
| `gen_headers.py` | Layout headers from the PDB: bases, members in offset order (types, bitfields, arrays, function pointers), virtuals with their slots, `static_assert`s of the size and every offset; dependencies first; `--known` types are referenced, not emitted; `--declare` writes member functions as declarations with their access specifiers. | exe + PDB, type names (or `@file`) -> `--out <file.h>` | dbghelp (`pdb_struct.py`), `func_match.py` | `adapt`: UE type spellings (`int32`, `ESPMode`) and its list of pointer-like wrapper templates. |
| `tiny_bodies.py` | C++ bodies for tiny member functions from their machine code: return a member, a bit, a constant, a global or the first argument; set or clear a bit; forward to another virtual. Each body is a suggestion for the judge. Library of `abi_codegen.py --bodies`. | exe, an `abi_diff.py` dump, class, VAs -> stdout | capstone, `abi_diff.py`, `func_match.py` | `generic`: prints IDs with the `SRV@` prefix. |
| `ctor_defaults.py` | A constructor's defaults as `Member = value` lines: its memory writes (`ghidra_find.py --stores`) mapped onto the class's PDB layout; plain constants, bitfield writes, writes into a member's own fields. | class, stores output, exe + PDB -> stdout | dbghelp (`pdb_struct.py`), Ghidra for the stores | `adapt`: the default `--exe`; it assumes UE constructors (`--struct` for one without the engine's initializer argument). |
| `vft.py` (from `rebuild/`) | A class's primary vftable slot by slot (`dump`), and against MSVC's layout of ours (`align <Class> <cl /d1reportSingleClassLayout output>`): where the slot shift changes. | PE + PDB (+ layout text) -> stdout | `func_match.py` | `generic`: the default `--pe` is this project's server. |

### `unit-loop/`: the per-unit pipeline and the regression (10)

All ten come from `_tools/rebuild/`. They work in `<repo>/build/loop/<unit>/`.

| File | What it does | Reads -> writes | Needs | Tag |
|---|---|---|---|---|
| `unit_loop.py` | One original compile unit through its steps: `plan` (its functions, sizes, reach rank, ledger status, verdict), `export` (decompiles and RAW ledger rows), `headers`, `build`, `judge`, `ledger` (REIMPL and parity from the verdicts), `doc` (a stub section in the system doc), `all`. The draft itself is the one step it leaves to the writer. | original PE + PDB, `tracking/reach.csv`, the ledger -> `plan.tsv`, `layouts.h`, the object, `match.json`, `causes.json`, ledger rows, `docs/systems/<system>.md` | `ghidra_find.py`, `gen_headers.py`, `recompile_unit.py`, `func_match.py`, `judge_causes.py`, `reach_record.py` | `adapt`: `THEIRS`, `BASE`, the port's folder `src/reimpl/ShooterGame/...`. |
| `unit_skeleton.py` | The port's skeleton: one block per plan function in address order with its ID header lines and the signature rebuilt from the decorated name with the PDB's parameter names, an empty body. `--class`, `--also`. | `plan.tsv`, the locals index -> `skeleton.cpp` | dbghelp, `pdb_locals.py`'s index | `adapt`: the locals index's file name; the header-line format. |
| `unit_fill.py` | The port's file from the skeleton, a prelude and body chunk files (chunks opened by `//@ SRV@<va>`, `=sig`, `//@ TOP`, `//@ END`). `--omit-empty`, `--strict`. | skeleton, prelude, bodies folder -> the `.cpp` | Python only | `generic`: the chunk marker uses the `SRV@` ID. |
| `unit_extras.py` | A unit's bodies without a public name (lambda bodies, dynamic initializers, atexit destructors, file-static functions): `list`, `export`, `callers`, `verdicts`, `ledger add` / `reimpl`. | the locals index, `plan.tsv`, `match.json` -> `extra-vas.txt`, `extra-verdicts.json`, ledger rows | `func_match.py`, `ghidra_find.py`, `unit_loop.py` | `adapt`: `LOCALS`, `EXE`, the base, the port's folder. |
| `unit_diffs.py` | A unit's DIFF / MATCH~ functions after a judge: address, size, first differing byte, cause bucket and the bodies file that holds each. `--all`. | `match.json`, `causes.json`, the bodies folder -> stdout | Python only | `adapt`: the image base and the `build/loop` layout. |
| `unit_probe.py` | Source variants of a unit's functions compiled with the unit's own command line through its precompiled header, in seconds: `#if PROBE == k` variants, each judged. `--funcs`, `--only`, `--show`, `--tag`. Never while the unit builds. | probe `.cpp`, the unit's `.rsp` and `.pch` -> `probe<k>.obj`, verdict lines | VS2013, `func_match.py`, `disasm_obj.py` | `adapt`: `VCVARS`, `EXE`, `CWD`, the port's folder. |
| `unit_lines.py` | A unit's line table mapped to the PDB's publics: which source file each function of the unit is attributed to, that is the header an inline function the unit emits lives in. | PE + PDB -> stdout | llvm-pdbutil, `func_match.py`, `reach_record.py`, `unit_loop.py` | `adapt`: `text_base = 0x1000` and `unit_loop.py`'s defaults. |
| `regress.py` | Rebuilds and re-judges every ported unit in the ledger and reports each row that was `match` and is not any more. `--only`, `--no-build`. | the ledger, the ports -> `build/loop/regress.tsv` | `unit_loop.py`, `unit_extras.py` | `adapt`: `SRC` and `MAP` (the port's folder, the original's source root). |
| `engine_types.py` | The type names our source tree declares (classes, structs, unions, enums, namespaces of namespaced enums): the `--known` list of `gen_headers.py`. | the engine source tree -> `build/loop/common/engine-types.txt` | `unit_loop.py` | `adapt`: UE's tree layout and the default `--engine`. |
| `engine_headers.py` | Where our engine defines each class, struct, delegate and typedef: name -> include path. In the project its reader is `game_headers.py`, which is not in the toolkit. | the engine source tree -> `build/loop/common/engine-headers.json`, `engine-keywords.json` | Python only | `adapt`: UE's tree layout and the default `--engine`. |

### `ledger/`: ledger check, baseline, trace, hook (6)

All six come from `_tools/rebuild/`.

| File | What it does | Reads -> writes | Needs | Tag |
|---|---|---|---|---|
| `atlasre_common.py` | Shared helpers: repository paths, ID parsing, the CSV schemas with sorted writes, hashing, git. | - | git | `adapt`: `BINARIES` (three executable paths), `BASELINE_KEYS`, `ENGINE` (or the environment variable `ATLAS_ENGINE_ROOT`), the ID prefixes. |
| `ledger_check.py` | The consistency check of the three tables and the pre-commit hook's command (`--staged` reads the tables from git's index). What it enforces: `templates/ledger-schema.md`. | `tracking/*.csv`, raw files, `src/` -> exit code, messages | git, `atlasre_common.py` | `adapt`: the marker patterns `// ATLAS-ID:` and `ATLAS_REPLACE(`; the paths come from `atlasre_common.py`. |
| `ledger_rehome.py` | Points each ledger row whose `reimpl_path` is a header without its ID line at the header that has it now. Only that column changes. `--dry-run`. | the ledger, the headers -> the ledger | Python only | `adapt`: the `GAME` source folder. |
| `baseline.py` | SHA-256 manifests of the original installs (every exe, dll, pdb, lib, exp and ini, plus named extras) into `tracking/baseline/`; `--check` compares the installs with them. | the installs -> `tracking/baseline/*.json` | Python only | `adapt`: the install roots, the skip list, the deployed and runtime-written file lists, the extra file names. |
| `trace.py` | Prints the traceability chain of one ID: ledger row, raw file and hash check, annotations, docs, reimplementation, hook registration, toggle, tests, evidence, commits. Untracked in the source repository. | the repository -> stdout | git, `atlasre_common.py` | `generic` within the scheme: it has no paths of its own. |
| `pre-commit` | The git hook: runs `ledger_check.py --quiet --staged`. Copy it to `.git/hooks/`. The same file is in `templates/`. | - | sh (Git for Windows) | `adapt`: two absolute paths. |

### `delink/`: delink and relink (10)

| File | What it does | Reads -> writes | Needs | Tag |
|---|---|---|---|---|
| `delink_unit.py` | Delinks one compile unit out of the binary into a COFF object, nothing saved to the Ghidra project: the unit's `.text` disassembled, base-relocation pointers typed, reference analyzers, the naming rule (a symbol without a public becomes `<name>@local@<va>`), the relocation synthesizer, the COFF exporter. | a ranges file from `unit_contribs.py`, the Ghidra project -> `<out.obj>` | Ghidra, JDK, pyghidra, ghidra-delinker-extension | `adapt`: `SETTINGS`, `BASE`, the Ghidra / JDK folder names, project defaults. |
| `delink_all.py` | The whole-binary delink: `prepare` on a copy of the Ghidra project (staged and resumable), `export` of every delinkable module with a `manifest.tsv`, `judge` (`func_match.py` over the manifest into `summary.tsv`), `align`. | the Ghidra project, PE + PDB -> `_re/ghidra-delink`, `build/delink/server/...` | Ghidra, JDK, pyghidra, the patched delinker, capstone, `func_match.py` | `adapt`: project, program, `PE`, the cache name, `BASE`; many stages record what this one binary needed. |
| `delink_patch.py` | Patches ghidra-delinker 0.9.2 in the isolated install (the original kept as `.jar.orig`; `--restore`): exports that cost only the exported set, the image-base-relative relocation kind `IMAGE_REL_AMD64_ADDR32NB`, unique names for dynamic symbols, alignment padding. | the extension's jar | the JDK's `javac` and `jar`, Ghidra's jars | `adapt`: `JDK`, `GHIDRA` and `EXT`, whose path holds a settings folder named `PC-ghidra` and the Ghidra version. |
| `delink_implibs.py` | Import libraries for the relink from DLL export tables: `dumpbin /exports` -> a `.def` per DLL (an export outside the code sections is `DATA`) -> `lib /def /machine:x64`. | DLLs -> `build/delink/implibs/*.lib` | VS2013's `dumpbin` and `lib` | `adapt`: `VC`, `SERVER`, the DLL table. |
| `delink_link.py` | The relink: VS2013's `link.exe` over the delinked objects with the reconstructed link line and what the PE header says (subsystem, stack, delay-loads, the exports as a `.def`), the objects in PDB module order. `--compare`, `--no-aslr`, `--dry-run`, `--sort-pdata`, `--extra <obj>`. | objects, import libraries -> the exe, `.pdb`, `.map`, `link.log` | VS2013's linker | `adapt`: `VCVARS`, `VC`, `PE`, `PUBLICS`, `DIRECTX`, the import-library table, the output names. |
| `delink_run.py` | A run root for the linked exe, so that it boots without touching the original install: junctions to the original's large folders, copies of the small files and of the binaries folder, our exe and PDB in it. `--dry-run`. | the original install -> `build/delink/run` | Python only | `adapt`: the junction and file lists are this game's folders; the exe names; the default `--original`. |
| `delink_swap.py` | The hybrid link's swap as one command: one judged object of ours in place of the delinked set's definitions of the functions it matched (keep list, defines, aliases, retargets), the leftovers re-exported, our object stripped, the link. `--dry-run`, `--no-export`, `--no-link`. Swaps accumulate. | our `.obj`, `match.json`, the set -> `build/delink/hybrid/<name>/`, the linked exe | `delink_all.py`, `coff_strip.py`, `delink_link.py`, `pe_compare.py`, capstone | `adapt`: `BASE`, `THEIRS`, the map path. |
| `coff_strip.py` | Strips a COFF object of ours down to a list of kept symbols: every other section marked for removal, with `--alias`, `--define` and `--retarget` for the names the delinked set uses. /bigobj and plain COFF. | `<in.obj>`, a keep list -> `<out.obj>` | Python only | `generic` |
| `pe_compare.py` | Two PEs compared per function through their PDBs: bytes equal, else instruction by instruction with the fields that encode an address compared by what they reach. IDENTICAL / MATCH / MATCH~ / DIFF / ALIAS / MISSING / SIZE. `--json`, `--names`, `--limit`. | two PEs with PDBs -> stdout, JSON | capstone, `func_match.py` | `generic`: the positional and `--theirs` defaults are this project's. |
| `pe_imagerel.py` | Image-base-relative data operands of two PEs: instructions with a register base and a 32-bit displacement inside a data section's RVA range. A displacement present in both PEs is one the relink never relocated; exit 1 while any remain. | two PEs (+ map) -> stdout | capstone | `generic`: defaults as above. |

### `runtime/`: dumps, traces, reach, reports (9)

| File | What it does | Reads -> writes | Needs | Tag |
|---|---|---|---|---|
| `minidump_stacks.py` | Every thread's call stack from a minidump, symbolized offline (`StackWalk64`) against the matching binaries and PDBs of a local install, matched by name, PE timestamp and image size. `--root`, `--crash-only`, `--frames`, `--scan`. Untracked in the source repository. | a `.dmp`, local installs -> stdout | dbghelp | `generic`: `--root DIR` adds an install; `DEFAULT_ROOTS` are this project's. |
| `minidump_where.py` | A dump's exception, registers, module map and the return addresses on the stack, named through a PDB. Mini and full dumps. | a `.dmp`, an exe + PDB -> stdout | `func_match.py` (llvm-pdbutil cache) | `generic`: the defaults of `--exe` and `--cache` are this project's. |
| `pe_unwind.py` | An x64 stack walk over a minidump without a debugger: each frame unwound through its module's `.pdata` / UNWIND_INFO read from the PE files on disk, named through the PDB. `--regs`, `--all`, `--frames`. | a `.dmp`, an exe + PDB, system DLLs -> stdout | `func_match.py` (llvm-pdbutil cache) | `generic`: defaults as above. |
| `delink_trace.py` | Frida attached to a running process: hooks at functions named in a linker map file, each call's arguments (one format letter per argument) and return value printed with the thread id. `--log`. | a pid, a `.map` -> stdout, log | Frida | `adapt`: the module name inside the agent, `BASE`, the default `--map`; the `W` format reads UE's `FString`. |
| `reach_record.py` | The reach set: which functions of a module a session executes, in first-hit order. `functions` lists them from the PDB; `record` attaches Frida, writes an int3 over every listed entry, records the first hit, restores the byte and resumes; `merge` writes the union of runs. | PE + PDB, the running process -> `build/reach/*.csv`, `tracking/reach.csv` | Frida, `func_match.py` (llvm-pdbutil) | `generic`: the defaults of `--theirs`, `--modules`, `--name` and `--module` are this project's. |
| `perf_report.py` | Summary of a perf recording: frame-time percentiles, a histogram, time per zone, the worst hitches with memory context. | the recording's CSVs -> stdout | Python only | `adapt`: it reads the CSV format of the project's hook-DLL perf recorder, which is not in the toolkit (format: `docs/knowledge/perf-recorder.md`). |
| `symbols.py` (from `testserver/`) | Names for sampled addresses: module + RVA -> function from the module's PDB, or the nearest export for other DLLs, and the instruction at a place. Library of the project's run report; also runs alone. | a server root, module, RVAs -> stdout | dbghelp, capstone | `adapt`: the sub-path `ShooterGame/Binaries/Win64` under the root; `IMAGE_BASE`. |
| `ctrl_c.py` (from `testserver/`) | Sends one Ctrl+C to a process's console: a graceful exit for a console server that no longer answers its remote console. | `<pid>` | kernel32 through ctypes | `generic` |
| `htmlreport.py` (from `testserver/`) | Helpers for self-contained HTML reports: inline SVG line charts with a hover readout, tiles, tables, light and dark. A library; its caller `report.py` is not in the toolkit. | - | Python only | `generic` |

### `build/`: PowerShell build wrappers (3)

| File | What it does | Reads -> writes | Needs | Tag |
|---|---|---|---|---|
| `build-hook.ps1` | Builds the hook DLLs with MSVC: the proxy DLLs, the hook runtime with MinHook, and `manifest.json` (commit, dirty flag, toolset, compiled-in IDs, SHA-256 of the outputs); then runs the proxy test (`-NoTest` skips it). | `src\hook`, `src\reimpl`, `src\sdk`, `src\third_party\minhook` -> `build\hook\` | VS 2022 (`vswhere`, `vcvars64.bat`), git | `adapt`: the source folders and DLL names (`VERSION.dll`, `XINPUT1_3.dll`, `atlasre.dll`), the `ATLAS_REPLACE` pattern. The sources it builds are not in the toolkit. |
| `build-ue45.ps1` | Builds a UE 4.5.1 engine tree with Visual Studio 2013 through the engine's own batch files, with three environment fixes those 2014 scripts need. `-Root`, `-Target`, `-Platform`, `-Config`, `-GenerateProjectFiles`. | the engine tree | VS2013 (`VS120COMNTOOLS` set machine-wide) | `adapt`: UE4-era engine with VS2013 only; the default `-Root`. |
| `build-tools.ps1` | Builds `video_frames.cpp`, expected beside it, into `<repo>\build\tools\`. | `video_frames.cpp` -> `video_frames.exe` | VS 2022 (`vswhere`, `vcvars64.bat`) | `generic` |

### `misc/` (3)

| File | What it does | Reads -> writes | Needs | Tag |
|---|---|---|---|---|
| `a2s_info.py` | Steam server query `A2S_INFO` (answers the challenge): name, map, folder, game, app id, players, server type, version. Arguments: host, port. | UDP -> stdout | Python only | `generic` |
| `a2s_rules.py` | Steam server queries `A2S_RULES` and `A2S_PLAYER`, what a game client asks before joining. Arguments: host, port. | UDP -> stdout | Python only | `generic` |
| `video_frames.cpp` | Media Foundation probe: prints a video's format and writes PNG frames at given times. Built by `build/build-tools.ps1`. | a video -> PNG files | Windows SDK | `generic` |

### `ue4-reflection/`: Unreal Engine 4 reflection parity (22)

Only useful when the target is an Unreal Engine 4 program whose UnrealHeaderTool output can be read back
(`Z_Construct_*` functions) and, for the metadata tools, when editor-build DLLs of the same code exist. "Ours" in
several of these comes from a reflection-dump commandlet the project added to its own engine tree
(`AtlasFormatTest -reflection...`); that commandlet is not part of this toolkit.

| File | What it does | Reads -> writes | Needs | Tag |
|---|---|---|---|---|
| `devkit_metadata.py` | UHT metadata (categories, tooltips, header paths, defaults) and function flags read from editor-build DLLs, the only builds that compile metadata: `export` (decompile every `Z_Construct_*`), `parse` (JSON lines), `show`, `notes`. Also the `PE` class `lea_strings.py` imports. | editor DLLs, their decompiles -> JSON lines, notes | Ghidra for `export` | `adapt`: `PROJECT`, the project name, the developer-note tags it searches for. |
| `metadata_diff.py` | Our UHT metadata (generated code) against the editor DLLs', per type, member and key. | `parse` output, our generated code -> report, JSON | Python only | `adapt`: UE4 only. |
| `metadata_apply.py` | Writes the original's categories, `meta`, class specifiers, enum `UMETA` and tooltip comments into our headers from a `metadata_diff` JSON. `--dry-run`, `--keys`, `--types`. | diff JSON, metadata, our headers -> our headers | Python only | `adapt`: UE4 only. |
| `enum_diff.py` | Reflected enums (value names in order, C++ form): the original's decompiled `Z_Construct_UEnum_*` against our generated code. | decompiles, a DLL, our generated code -> report, JSON | `devkit_metadata.py` | `adapt`: UE4 only. |
| `reflection_table.py` | The property table of a class or struct from its reflection code in a raw decompile, as JSON lines: name, property kind, offset, flags, array dimension, referenced type. | a `Z_Construct_...` decompile -> JSON lines | `devkit_metadata.py` | `adapt`: UE4 only. |
| `reflection_diff.py` | One class's reflected property table against ours; exit 1 when anything differs. | a decompile, our dump -> stdout | `reflection_table.py`, the project's dump commandlet | `adapt`: UE4 only. |
| `reflection_diff_all.py` | The same for a whole module: every class, struct and function, a markdown report and a JSON summary. `--mask`, `--dll`, `--editor`. | a folder of decompiles, our dump folder -> report, JSON | `reflection_table.py`, `devkit_metadata.py`, the dump commandlet | `adapt`: UE4 only. |
| `reflection_classes.py` | Class-level diff: superclass, class flags, config name and interfaces. | decompiles, our generated code, a PE + PDB -> report | dbghelp (`pdb_struct.py`), `reflection_table.py` | `adapt`: UE4 only. |
| `reflection_structs.py` | Script structs' parent struct and declared flags, the original's against ours. | decompiles, our generated code -> report | Python only | `adapt`: UE4 only. |
| `reflection_codegen.py` | Suggests the `UPROPERTY` declarations that bring one of our types to the original's reflection, in the original's order; `--apply <header> --type` inserts them. | a decompile, our dump -> stdout or the header | `reflection_table.py` | `adapt`: UE4 only; the engine root default (or `ATLAS_ENGINE_ROOT`). |
| `reflection_newtype.py` | Drafts the header of a type the original reflects and we lack: members in the original's order from the PDB, `UPROPERTY` specifiers from the property flags, categories and tooltips from the editor metadata, `UFUNCTION`s with parameter names. A draft: unsure lines carry `TODO`. | decompiles, PE + PDB, metadata -> a header draft | dbghelp (`pdb_struct.py`), the other `reflection_*.py` | `adapt`: UE4 only. |
| `reflect.py` (from `rebuild/`) | What the original's UnrealHeaderTool saw, read back from the generated units' `Z_Construct_*` decompiles and the editor metadata into one JSON: class and struct specifiers, each property's and function's specifiers, enum forms, custom thunks. In the project it feeds `game_headers.py --reflect`, which is not in the toolkit. | the corpus, metadata, PE + PDB -> `build/loop/all/reflect.json` | `reach_record.py`, `func_match.py`, `pdb_struct.py`, the `reflection_*.py` modules | `adapt`: `EXE`, `CORPUS`, `META`, the module name. |
| `run_uht.py` (from `rebuild/`) | Runs our engine's UnrealHeaderTool over the game module's headers: UBT's editor manifest with a game module appended, the output where every game unit's command line looks for it. | the engine tree, the game headers -> generated `.cpp` and `.generated.h` files, `build/uht/` | UnrealHeaderTool | `adapt`: `ENGINE`, the module name, the source folders. |
| `struct_ops.py` (from `rebuild/`) | Engine structs' C++ parity in one probe: every `TCppStructOps<T>` the original instantiates, compiled with a generated unit's command line and judged by name. `--game`. | type list, a unit's `.rsp` -> `build/loop/probe/structops/` | VS2013, `func_match.py` | `adapt`: `D:\ATLAS` seven times (among them the venv and a `sys.path` entry), the VS2013 path, the engine path, the unit's name. |
| `devkit_diff/devkit_modules.py` | Shared by the module-diff tools: default paths, the census file `<work>/modules.tsv`, the module filter. | - | Python only | `adapt`: `ENGINE`, `DLL_ROOT` (the mod kit's install), `CORPUS`, the Ghidra project. |
| `devkit_diff/census.py` | Step 1: every module of our engine with reflected types that the shipped server lacks, with its editor DLL, PDB or not, in the Ghidra project or not. | our engine tree, the kit -> `<work>/modules.tsv` | Python only | `adapt`: UE4 only; defaults from `devkit_modules.py`. |
| `devkit_diff/export.ps1` | Step 2: per editor DLL the Ghidra import, the untyped metadata export and, with a PDB, the typed export. Resumable; `-DryRun`. | `modules.tsv` -> the corpus, logs | Ghidra, `ghidra_analyze.py`, `ghidra_find.py`, `devkit_metadata.py` | `adapt`: the venv path, corpus and project defaults. |
| `devkit_diff/check_exports.py` | After step 2: each module's exported `Z_Construct` files counted against the census, and the last error-looking line of each step's log. | `<work>`, the corpus -> stdout | Python only | `adapt`: UE4 only. |
| `devkit_diff/dump.ps1` | Step 3: our reflection dumps for the census's modules in one commandlet run. `-Build` builds the editor first; `-DryRun`. | `modules.tsv` -> `<Work>\ours\<Module>` | the engine build, the project's dump commandlet, `build-ue45.ps1` | `adapt`: the engine root default, the commandlet, the preload list. |
| `devkit_diff/diffs.py` | Step 4: per module the reflection, metadata and enum diffs and, with `--classes`, the class level; a verdict per module and `summary.md`. | `<work>`, the corpus -> `<work>/diff/`, `summary.md` | the `reflection_*.py`, `metadata_diff.py`, `enum_diff.py`, `devkit_metadata.py` | `adapt`: UE4 only. |
| `devkit_diff/compare_reports.py` | Two folders of diff reports compared file by file, the line that names the input folders ignored; exit 1 if anything differs. | two folders -> stdout | Python only | `generic` |
| `devkit_diff/codegen.py` | `reflection_codegen.py` on an editor DLL's typed decompile. | a DLL, a decompile, our dump -> stdout or the header | `reflection_codegen.py`, `reflection_table.py` | `adapt`: UE4 only. |

### Left in the project (game-specific)

Not copied. Paths are relative to `_tools/` unless they start with `_re/`.

| File | What it is | Why it stays |
|---|---|---|
| `build-launcher.ps1` | Builds the project's own community launcher and its unit tests. | The launcher is this project's product. |
| `delink_boot.ps1` | Runs the relinked server under Sysinternals procdump with the game's launch URL and switches. | The launch line is the game's; it reads the local server config. |
| `frida_trace_loadmap.py` | Spawns the server under Frida and traces map and package loading. | Hooks at this build's addresses. |
| `frida_open.py` | Makes the running client execute a console command. | This build's addresses and engine objects. |
| `frida_client_trace.py` | Client: sends a command and traces travel, failures and exit. | This build's addresses. |
| `frida_server_auth.py` | Server: traces the join authentication check. | This build's addresses. |
| `frida_lookup_trace.py` | Client under Frida: traces the Steam server lookup. | This build's addresses; its usage text holds a public IPv4 address. |
| `hook-deploy.ps1` | Deploys or removes the hook files next to the server or client exe and sets per-ID modes in the ini. | The game's paths and file names; its usage text holds a public IPv4 address. |
| `join-local.ps1` | Launches the Steam client into the local test server. | The game's paths; its usage text holds a public IPv4 address. |
| `launch_experiments.ps1` | Starts the server once per URL variant and records the map and game mode it ends on. | The game's launch parameters. |
| `loadtest/ue45net.py` | Decodes and builds this game's network packets from the perf recorder's packet capture. | The limits and message layouts are this game's. |
| `make_1x1_grid.py` | Cuts one cell out of the game's world-grid file into a standalone 1x1 grid. | The game's file format. |
| `redis_peek.py` | Read-only dump of the local game database's keys. | Reads the local server config for its password. |
| `setup_local_server.py` | One-time set-up of the local test server: database config, the server-only grid file, the local config with generated passwords. | The game's server set-up. |
| `shadermap_census.py` | Census of the cooked shader maps inside the game's material packages. | The game's package format. |
| `show-trace.ps1` | Shows the important lines of one Frida trace. | One trace file; holds a path into an old user profile. |
| `start-accounts.ps1` | Starts the project's accounts service (a Postgres container and the API). | The project's own service. |
| `start-server.ps1` | Starts the database and the dedicated server with the game's launch URL. | The game's launch line; reads the local server config. |
| `status.ps1` | One-screen status of the local test set-up. | The game's process and log names. |
| `steam-listing.ps1` | Asks Valve's `ISteamApps/GetServersAtAddress` which servers Steam lists at an address. | Its default address is a public IPv4 literal. The call itself is one line and easy to rewrite. |
| `stop-server.ps1` | Clean stop of the server over its remote console (save, then exit). | The game's commands; reads the local server config. |
| `sweep.ps1` | Content sweep with the project's own engine commandlet over the game's Content folder. | The game's content and the project's commandlet. |
| `uasset_reader.py` | Minimal reader for this fork's cooked packages. | The game's package versions and layouts. |
| `wait-ready.ps1` | Waits until the server log shows that start-up finished. | The game's log text and paths. |
| `rebuild/game_headers.py` | Splits `gen_headers.py --declare` output into the game's header files. 4,678 lines, most of them tables of this game's types, their header homes and hand-written inline bodies. | It is reconstructed game source held in a script. |
| `rebuild/all_headers.py` | The whole game module's headers in one run. | Its last step is `game_headers.py`. |
| `testserver/start.ps1` | Starts the monitored test server (pre-flight checks, hook with the perf recorder, database, server, recorder). | The game's test bench. |
| `testserver/stop.ps1` | Stops it cleanly, waits for the report and opens it. | As above. |
| `testserver/join.ps1` | Joins the test server from this PC's Steam client. | As above. |
| `testserver/status.ps1` | Shows the active run and the stack's status. | As above. |
| `testserver/mark.ps1` | Labels the active run from outside the game. | As above. |
| `testserver/world.ps1` | Saves and restores snapshots of the test world's save file. | The game's save file. |
| `testserver/console.ps1` | Opens or closes the test console page. | As below. |
| `testserver/console.py` | A local web page with the game's admin and test commands, the live state and the recording buttons. | The game's commands; reads the local server config. |
| `testserver/build_commands.py` | Builds `commands.json` from the game's command list and the mod kit's metadata. | The game's commands. |
| `testserver/commands.json` | The command catalogue. | Data derived from the game and the mod kit. |
| `testserver/testplan.json` | The solo test sessions for the console's test-plan panel. | The game's test plan. |
| `testserver/recorder.py` | Samples the running server (CPU, memory, handles, I/O, players), then collects its logs and the perf recorder's files and starts the report. | Tied to the game's logs and the hook DLL's recorder. Its process sampler, server-query and remote-console code would be the place to start for another dedicated server. |
| `testserver/report.py` | The report for one run and the index over all runs. | Its analysis follows this game's tick rules, logs and the hook DLL's CSV columns. |
| `grids/*/ServerGrid.json` (2 files) | The game's world-grid configs. | Game config, not a tool. |
| `server.local.json` | The local server's ports and passwords. | Secrets. Never opened, printed or copied. |
| `_re/annotations/apply_annotations.py` | Applies the renames and comments recorded in `_re/annotations/<bin>.jsonl` to the Ghidra project (the `atlas-annotate` skill runs it). | It lives under `_re/`, which was out of bounds for this toolkit; the file was not opened. A candidate to add by hand. |
| `_re/inventory/class_inventory.py` | Generator of the PDB class inventory (purpose not verified: the file was not opened). | As above. |

## Adapting to a new project

Counted with a scan over the 106 copied scripts (occurrences in code, comments and usage text together).

### Before anything else

- **Restore the layout** with the snippet at the top. The scripts expect `_tools/` under the repository root with
  `_re/`, `build/`, `tracking/`, `docs/` and `src/reimpl/` beside it.
- **Create a new Python environment.** The project's venv (`_tools/ghidra-mcp-venv`, Python 3.12 managed by uv) is
  bound to its path and cannot be moved. It holds pyghidra-mcp (which brings pyghidra and jpype1), frida and
  capstone. The dbghelp-based tools need nothing beyond the standard library.
- **Install the external tools**: the original's compiler (here VS2013 Update 5), Visual Studio 2022's "C++ Clang
  tools" component for llvm-pdbutil and llvm-readobj, Ghidra and a JDK unpacked beside the scripts.
- The project's own experience after a drive-letter change: its files name the drive in many places, so it changed
  the letter back instead of the files (`docs/knowledge/environment.md`).

### What is hardcoded, and where

| What | Occurrences | Files |
|---|---|---|
| Project root `D:\ATLAS` | 52 in 26 files | `build/`: build-hook.ps1, build-tools.ps1, build-ue45.ps1 (usage comments). `delink/`: delink_all.py, delink_implibs.py, delink_unit.py. `ghidra/`: all but ghidra_bulk_export.py (which derives the root). `ledger/`: atlasre_common.py, baseline.py, pre-commit. `matching/`: disasm_obj.py, judge_module.ps1. `pdb/`: pdb_decl.py, pdb_locals.py, unit_contribs.py. `runtime/`: minidump_stacks.py. `ue4-reflection/`: devkit_metadata.py, struct_ops.py, devkit_diff/dump.ps1, devkit_diff/export.ps1. |
| A hard `sys.path.insert(0, r"D:\ATLAS\_tools")` | 3 in 3 files | matching/disasm_obj.py, pdb/pdb_decl.py, ue4-reflection/struct_ops.py |
| Original install `D:\ATLASServer` (the server exe and PDB) | 27 in 23 files | abi-layout/ctor_defaults.py, abi-layout/vft.py, delink/delink_all.py, delink_implibs.py, delink_link.py, delink_run.py, delink_swap.py, pe_compare.py, pe_imagerel.py, ledger/atlasre_common.py, ledger/baseline.py, matching/disasm_obj.py, matching/judge_module.ps1, pdb/pdb_decl.py, pdb/pdb_locals.py, pdb/unit_contribs.py, runtime/minidump_stacks.py, runtime/reach_record.py, ue4-reflection/reflect.py, ue4-reflection/struct_ops.py, unit-loop/unit_extras.py, unit_loop.py, unit_probe.py |
| Our source tree `D:\UE\4.5.1` | 25 in 17 files | build/build-ue45.ps1, delink/delink_link.py, ledger/atlasre_common.py, matching/func_match.py (a comment), matching/recompile_unit.py, pdb/pdb_methods_diff.py (usage example), pdb/pdb_source_md5.py, ue4-reflection/reflection_codegen.py, run_uht.py, struct_ops.py, devkit_diff/census.py, devkit_modules.py, diffs.py, dump.ps1, unit-loop/engine_headers.py, engine_types.py, unit_probe.py. Four of them read the environment variable `ATLAS_ENGINE_ROOT` first: atlasre_common.py, devkit_modules.py, dump.ps1, reflection_codegen.py. |
| Image base `0x140000000` | 26 in 21 files | delink/delink_all.py, delink_swap.py, delink_unit.py, matching/disasm_obj.py, pdb/pdb_decl.py, pdb_enum.py, pdb_func_lines.py, pdb_locals.py, pdb_lookup.py, pdb_struct.py, unit_contribs.py, pe/find_version_checks.py, lea_strings.py, pe_bytes.py (usage text), pe_callers.py, runtime/delink_trace.py, runtime/symbols.py, unit-loop/regress.py, unit_diffs.py, unit_extras.py, unit_loop.py. In the dbghelp tools it is the base the module is loaded at for the lookup, so addresses print in that numbering for any image; elsewhere it is the original's real preferred base. |
| Executable and PDB names: `ShooterGameServer` (also in `.map`, cache and locals-index file names) | 77 in 36 files | abi-layout/ctor_defaults.py, vft.py; delink/ (all but coff_strip.py, delink_implibs.py, delink_patch.py); ghidra/ (all but ghidra_imports.py, ghidra_info.py); ledger/atlasre_common.py; matching/disasm_obj.py, judge_module.ps1, recompile_unit.py; pdb/pdb_buildinfo.py and pdb_struct.py (usage examples), pdb_decl.py, pdb_locals.py, unit_contribs.py; runtime/delink_trace.py, minidump_where.py, pe_unwind.py, reach_record.py; ue4-reflection/reflect.py, reflection_classes.py, reflection_newtype.py, struct_ops.py; unit-loop/unit_extras.py, unit_loop.py, unit_probe.py, unit_skeleton.py |
| Client executable `AtlasGame` | 9 in 5 files | delink/delink_run.py, ghidra/ghidra_bulk_export.py, ghidra/ghidra_info.py, ledger/atlasre_common.py, pdb/pdb_locals.py |
| Game module and folder name `ShooterGame` (paths such as `ShooterGame\Binaries\Win64`, `src/reimpl/ShooterGame/...`) | 97 in 31 files | Heaviest: delink/delink_run.py (18), ue4-reflection/run_uht.py (12), ledger/atlasre_common.py (8), ue4-reflection/reflect.py (8), delink/delink_implibs.py (5), unit-loop/regress.py (5), unit-loop/unit_extras.py (4). The others hold it one to three times, mostly inside the server path above. |
| VS2013 path `C:\Program Files (x86)\Microsoft Visual Studio 12.0` (`vcvarsall.bat`, `VC\bin\amd64`) | 7 in 6 files | abi-layout/abi_diff.py, delink/delink_implibs.py, delink/delink_link.py (2), matching/recompile_unit.py, ue4-reflection/struct_ops.py, unit-loop/unit_probe.py. build/build-ue45.ps1 reads `VS120COMNTOOLS` from the machine environment instead. |
| The venv path `ghidra-mcp-venv` | 4 in 4 files | ledger/pre-commit, matching/judge_module.ps1, ue4-reflection/struct_ops.py, ue4-reflection/devkit_diff/export.ps1. The other Python scripts start their siblings with `sys.executable`. |
| The original's source roots in the PDB: `d:\atlassvn\` (and `e:\atlasdevkitsvn\` in a usage text) | 11 in 4 files | matching/recompile_unit.py (the path maps, 5), pdb/pdb_source_md5.py (the `--prefix` default), unit-loop/regress.py (the `MAP`), pdb/pdb_lookup.py (docstring) |
| Stock source commit `14d2ac8` | 2 in 1 file | pdb/pdb_source_md5.py (the `--stock` default) |
| Ghidra project folders `_re/ghidra`, `_re/ghidra-client`, `_re/ghidra-bulk`, `_re/ghidra-client-bulk`, `_re/ghidra-devkit`, `_re/ghidra-delink` | 28 in 14 files | the eight scripts in ghidra/, delink/delink_all.py, delink/delink_unit.py, ue4-reflection/devkit_metadata.py, devkit_diff/census.py, devkit_modules.py, export.ps1 |
| Ghidra project names `atlas` (server), `client`, `devkit` | - | `atlas`: delink_all.py, delink_unit.py, ghidra_analyze.py, ghidra_bulk_export.py, ghidra_find.py, ghidra_listing.py, ghidra_mcp_server.py, ghidra_xrefs.py. `client`: ghidra_bulk_export.py, ghidra_info.py. `devkit`: ghidra_imports.py, devkit_metadata.py, devkit_diff/devkit_modules.py, devkit_diff/export.ps1. |
| Ghidra and JDK folder names `ghidra_12.1.4_PUBLIC`, `jdk-21.0.12.1+1` (beside the scripts; `GHIDRA_INSTALL_DIR` and `JAVA_HOME` override them where they are set with `setdefault`) | 12 and 11, in 11 files | the eight scripts in ghidra/, delink/delink_all.py, delink_patch.py, delink_unit.py |
| The delinker's isolated settings folder: `build\delink\settings`, and inside it a folder `PC-ghidra` (it appears to carry the Windows user name of the machine it was set up on; check the real name on yours) | - | delink/delink_unit.py (`SETTINGS`, absolute), delink/delink_all.py (`SETTINGS`), delink/delink_patch.py (`EXT`, the only place with `PC-ghidra`) |
| llvm-pdbutil's location | one function | `pdbutil()` in pdb/pdb_source_md5.py searches `C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\Llvm\x64\bin` and the same under `Program Files (x86)`. Every other tool imports it (the name appears in 8 files); matching/inline_diff.py takes `llvm-readobj.exe` from the same folder. |
| dbghelp's location `C:\Windows\System32\dbghelp.dll` | 7 in 7 files | abi-layout/export_diff.py, matching/judge_files.py, pdb/pdb_enum.py, pdb_func_lines.py, pdb_lookup.py, pdb_struct.py, pe/find_version_checks.py |
| Mod-kit install path (`AtlasModKit`) | 2 in 2 files | ue4-reflection/devkit_diff/devkit_modules.py (`DLL_ROOT`), devkit_diff/census.py (usage text) |
| Steam install path (the client exe) | 1 in 1 file | ledger/atlasre_common.py |
| Windows Kits 8.1 and the DirectX library folder | - | delink/delink_link.py |
| The ID prefix `SRV@` | 32 in 14 files | abi-layout/abi_apply.py, abi_codegen.py, tiny_bodies.py; ledger/atlasre_common.py, ledger_check.py, ledger_rehome.py, trace.py; matching/inline_diff.py; unit-loop/unit_diffs.py, unit_extras.py, unit_fill.py, unit_loop.py, unit_probe.py, unit_skeleton.py |
| The source markers `// ATLAS-ID:` and `ATLAS_REPLACE(` | 19 in 9 files, 5 in 2 files | `ATLAS-ID`: ledger/ledger_check.py, ledger_rehome.py, trace.py, unit-loop/unit_diffs.py, unit_extras.py, unit_fill.py, unit_loop.py, unit_probe.py, unit_skeleton.py. `ATLAS_REPLACE`: build/build-hook.ps1, ledger/ledger_check.py. |
| The project's dump commandlet `AtlasFormatTest` | 8 in 6 files | ue4-reflection/reflection_codegen.py, reflection_diff.py, reflection_diff_all.py, reflection_table.py, devkit_diff/diffs.py, devkit_diff/dump.ps1 |
| The hook DLL's name `atlasre` | 21 in 4 files | build/build-hook.ps1, ledger/baseline.py, runtime/perf_report.py, runtime/symbols.py |

### Repository layout the scripts assume

These are relative to the root each script derives from its own location, so they move with the repository; keep
the names or change them in every file listed.

| Path | Files that use it |
|---|---|
| `_re/cache` (the judge's PDB caches, the locals index) | 25 files across abi-layout/, delink/, matching/, pdb/, runtime/, ue4-reflection/ and unit-loop/ |
| `_re/decompiled/<bin>/` (raw decompiles) | ghidra/ghidra_analyze.py, ghidra_find.py, ghidra_xrefs.py, ledger/atlasre_common.py, unit-loop/unit_extras.py, unit_loop.py, unit_skeleton.py |
| `_re/corpus/` (the bulk corpus and the editor-DLL exports) | ghidra/ghidra_bulk_export.py and eight files in ue4-reflection/ |
| `build/loop/` (the unit loop's work folders) | the ten files in unit-loop/ except unit_lines.py, plus ue4-reflection/reflect.py and struct_ops.py |
| `build/delink/` | the files in delink/ except coff_strip.py, plus pdb/unit_contribs.py, runtime/delink_trace.py, minidump_where.py, pe_unwind.py |
| `build/reach/` | runtime/reach_record.py |
| `tracking/` (ledgers, baseline, reach set, evidence) | ghidra/ghidra_bulk_export.py, ledger/ (all but pre-commit), matching/judge_files.py, runtime/reach_record.py, unit-loop/regress.py, unit_extras.py, unit_loop.py |
| `src/reimpl/` (the ports, with the ID header lines) | build/build-hook.ps1, ledger/ledger_check.py, ledger_rehome.py, ue4-reflection/run_uht.py, unit-loop/regress.py, unit_extras.py, unit_loop.py, unit_probe.py |

### Skills and templates

The copied skills and templates are this project's text and name its paths: `D:\ATLAS` appears 28 times across all
nine skills and 20 times in four templates (`CLAUDE.md.example`, `atlas-rebuild-prompt.md`, `mcp.json.example`,
`pre-commit`); the venv path 8 times in six skills and 5 times in four templates. Rewrite them for the new target
instead of searching and replacing: the rules and the structure carry over, the facts do not.

## Workflow pieces

The method is as reusable as the scripts. The copies in `skills/` and `templates/` are the project's own files,
unedited.

| Piece | Where | What it is |
|---|---|---|
| Master prompt | `templates/atlas-rebuild-prompt.md` | The full brief for the agent: role and mission, ground rules, environment to verify each session, what "1:1" means, the traceability chain, repository layout, tracking schemas, documentation templates, the knowledge base, skills, the external-surface inventory, phases, the bootstrap session and the routine of every later session. |
| Working rules | `templates/CLAUDE.md.example` | The short version the agent loads every session: ground rules, layout, IDs, everyday commands. Renamed from `CLAUDE.md` so that it is not loaded as a live instruction file from inside this folder; rename it back at the root of the new project. |
| Ledger | `templates/ledger-schema.md`, `scripts/ledger/` | Three CSV tables under `tracking/` (functions, replacements, external surfaces), edited directly, rows sorted by ID, one stage change per commit. `ledger_check.py` is the consistency check. |
| Pre-commit hook | `templates/pre-commit` | Runs `ledger_check.py --quiet --staged`; copy it to `.git/hooks/pre-commit`. |
| Git files | `templates/gitignore.example`, `templates/gitattributes.example` | A whitelist `.gitignore` (ignore everything at the root, re-include only our folders) for a repository that sits inside the game's install, and the line-ending rules (`.py`, `.md`, `.csv`, `.json` LF; `.ps1` CRLF; raw decompiles byte-exact). Renamed so that they are not active inside this folder; under their real names the whitelist would hide the other templates from git. |
| Decision records | `templates/decisions-README.md` | The index of `docs/decisions/`: the file-name rule `ADR-####-<slug>.md`, the sections of a record, and the rule that the owner approves decisions. |
| MCP configuration | `templates/mcp.json.example` | The project's `.mcp.json`: two pyghidra-mcp servers (server and client Ghidra projects) started through `ghidra_mcp_server.py`. It holds commands, arguments and paths only. |
| Skills | `skills/<name>/SKILL.md` | Nine repeatable workflows, each written after the workflow had been done by hand once. Listed below. |

### The ID scheme

Every artefact has a filename-safe ID, and docs, ledger rows, source headers and commits refer to each other by it.

| ID | Meaning |
|---|---|
| `SRV@<va>`, `CLI@<va>`, `EDT@<va>` | A function in the server exe, the client exe or the editor DLL, keyed by its virtual address (lowercase hex, no `0x`). The binaries are frozen, so the IDs never change. |
| `SYS-<slug>` | A game system: a group of functions plus data, one doc each. |
| `SVC-<service>-<slug>` | An external surface: a backend endpoint, a platform API, a database key family. |
| `FMT-<slug>` | A file or wire format. |
| `REP-####` | A replacement: one unit of our code or service standing in for original behaviour. |
| `BUG-####` | An original bug the owner wants fixed; fixing it is always a deviation. |
| `ADR-####` | An architecture or strategy decision. |
| `Q-####` | An open question. |
| `ODD-####`, `DN-####` | Oddities, and developer notes found in the original (added by the working rules). |

### The status ladder

```
UNTOUCHED -> RAW -> ANNOTATED -> UNDERSTOOD -> REIMPL -> HOOKED -> VERIFIED -> NATIVE
```

Each step needs the one before it and is its own commit. RAW: the decompile is exported and its SHA-256 is in the
ledger; raw files are never hand-edited. ANNOTATED: names and types fixed through an annotations file applied by
script, so the Ghidra database can be rebuilt. UNDERSTOOD: described in its system doc. REIMPL: our source exists
with its ID header and compiles. HOOKED: ours runs in place of the original behind a per-ID toggle. VERIFIED: tests
pass and the evidence file is written. NATIVE: part of the standalone build. Side states: `STUBBED` (needs a
decision record), `DEAD` (needs evidence), `BLOCKED` (waits on a question).

A reimplementation starts with a header the checker reads:

```cpp
// ATLAS-ID: SRV@141a21100   orig: AGameMode::PreLogin   status: HOOKED
// REP: REP-0004   raw: _re/decompiled/server/AGameMode__PreLogin@141a21100.c
// deviations: none
```

### Evidence tags

Every claim in a doc cites its evidence and carries one of `[CONFIRMED]`, `[INFERRED]` or `[GUESS]`. When two facts
contradict, a question (`Q-####`) is opened instead of one being picked silently.

### Commits

One step per commit, with trailers, so that `git log --grep "Atlas-Id: <ID>"` returns an ID's whole history:

```
<stage>(<scope>): <summary>

Atlas-Id: SRV@141a21100
Atlas-Stage: RAW|ANNOTATED|UNDERSTOOD|REIMPL|HOOKED|VERIFIED|NATIVE|STUBBED|DEAD|DOC|INFRA|SKILL|KNOWLEDGE
Atlas-Rep: REP-0004          (if any)
Evidence: tracking/evidence/SRV@141a21100.md   (VERIFIED only)
```

When several sessions share one checkout they also share one git index. The project's handover notes record a
commit that carried another session's staged files, and the fix: commit through a private index
(`GIT_INDEX_FILE`), which is why `ledger_check.py --staged` honours that variable.

### The skills

| Skill | What it does | Notes for reuse |
|---|---|---|
| `atlas-session-start` | Verifies the environment, reads the index, the latest journal, the questions and the ledger state, then states one session goal. | Process only; names this project's paths. |
| `atlas-session-end` | Runs the ledger check, updates the coverage counts, writes the journal, refreshes the index and the questions, reports the IDs advanced. | Process only. |
| `atlas-decompile` | Exports functions from the Ghidra project to raw decompiles and adds them to the ledger. | Uses `ghidra_find.py`, `pdb_locals.py`, `ledger_check.py`. |
| `atlas-annotate` | Moves a function from RAW to ANNOTATED: renames and comments recorded in an annotations file, applied to Ghidra by script, re-exported, ledger updated. | Uses `_re/annotations/apply_annotations.py`, which is not in the toolkit. |
| `atlas-trace` | Shows the traceability chain of an ID. | Written before `trace.py` existed; it assembles the chain from commands. |
| `atlas-unit-loop` | Ports one original compile unit with the loop as one command. | Uses the scripts in `unit-loop/`, `matching/`, `pdb/`; also names `game_headers.py`, which is not in the toolkit, and a `disasm_at.py` that is not among the project's tracked tools. |
| `atlas-delink-boot` | Re-exports the delinked server, relinks it, checks the link against the original, boots it and diagnoses a fault or hang. | Uses the scripts in `delink/` and `runtime/`; the boot and stop steps use game-specific scripts that are not in the toolkit. |
| `atlas-devkit-diff` | Diffs our engine's modules against the mod kit's editor DLLs: census, exports, our dump, the diffs with a verdict per module. | Uses `ue4-reflection/`; UE4 only. |
| `atlas-run-stack` | Starts the local stack as the monitored test server, joins it, records the run and shuts down with a report. | Game-specific: every script it names stayed in the project. Kept as an example of a run-book skill. |

## Related side projects in this repo

Not part of the toolkit and not copied; each has its own README under `side-projects/`.

| Folder | What it is |
|---|---|
| `crash-catcher/` | For people hosting a normal dedicated server of the game: keeps every server crash together with what is needed to explain it. |
| `discord-relay/` | A relay for the game's company notifications to Discord, for people who host normal servers. Findings and design only, nothing built. |
| `loadtest-bots/` | Bots that join the original dedicated server without Steam, for network and load testing. A side test. |
| `ship-anchor-fix/` | A side test that speeds up one measured hot spot of the dedicated server, the per-tick ship anchoring check. |
| `ship-anchor-fix-v2/` | Version 2 of the same, which asks "anyone aboard?" first. Only one of the two can be installed at a time. |
| `ue5-ship-game/` | A plan, nothing built, for a UE5 ship game that uses the measurements and lessons of the rebuild. |

## Further reading in the project

These stay where they are; they explain how the tools fit together.

| Path | Content |
|---|---|
| `docs/knowledge/tooling.md` | The external tools with sources and hashes, and the project's own description of every script, with dated notes on what each was built for and fixed for. |
| `docs/knowledge/matching-decompilation.md` | The method, the calibration of the judge, mismatches by cause, ABI parity, headers from the PDB, the delink and relink rounds. |
| `docs/knowledge/lessons-from-other-projects.md` | What other game rebuilds learned beyond the method. |
| `docs/knowledge/hooking.md` | The hook DLL: proxy loading, replacement registration, the off / on / shadow modes. |
| `docs/knowledge/test-server.md`, `docs/knowledge/perf-recorder.md` | The monitored test server, its reports, and the perf recorder's file formats. |
| `docs/knowledge/environment.md`, `docs/knowledge/references.md` | The machine and installs; external sources with version and licence. |
| `docs/HANDOVER.md` | "Tools to know" and "Gotchas". |
| `tests/judge/test_func_match.py`, `tests/judge/test_inline_diff.py`, `tests/tools/test_pdb_struct.py` | The project's tests for three of the copied tools. Not copied. |
