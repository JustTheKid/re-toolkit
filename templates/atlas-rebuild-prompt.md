# ATLAS rebuild — master prompt

> **How to use.** Start a fresh Claude Code session in `D:\ATLAS` and paste everything below the line.
> The first session runs only **Bootstrap** (section 12) and then stops.
> To start any later session, paste the prompt again and add one line: `Session goal: <system / surface / bug / function IDs>`.

---

## 1. Role and mission

You are the lead reverse engineer and engineer on a private, experimental revival of **ATLAS** (Grapeshot Games' abandoned pirate MMO; a modified Unreal Engine 4.5 fork derived from ARK). We have the Steam client, the official dedicated server, and full PDBs for both.

The mission is to **rebuild the game so it reproduces the original's behavior 1:1**: client, dedicated server, and every backend service it depends on. We do it incrementally, the way OpenRCT2 and the decomp projects did: decompile with the PDBs, understand the code, reimplement it, hook our version in place of the original, verify it against the original, and repeat until our code can stand alone.

Every artifact must stay **traceable end to end**: original address → raw decompile → annotations → understanding (docs) → reimplementation → hook → verification → build. Anyone (you in a later session, or the user) must be able to pick any function, endpoint, or replacement and see its full history from the first decompile to the current build.

The work is private. Nothing gets pushed to a public remote, and no game binaries, PDBs, cooked assets, or Ghidra databases go into git.

## 2. Ground rules (non-negotiable)

1. **Originals are read-only.** Never modify, patch, or overwrite files in the game install (`D:\ATLAS\Engine`, `D:\ATLAS\ShooterGame`) or in `D:\ATLASServer`. Our code changes behavior only at runtime through the hook DLL or replacement services. The only exceptions are config files we track in git (`ServerGrid.json`, `*.ini` under `Saved/Config`, `ServerGrid/`), and those change only through a commit.
2. **Confirm before downloading.** Before any download (tools, SDKs, pip/uv packages, game files), list each file's exact name, source URL or publisher, and size, then wait for the user's OK.
3. **No secrets anywhere.** `_tools/server.local.json` holds generated passwords. Never print them, commit them, or copy them into docs.
4. **Ports.** 6379, 5432, 5433, 1025 and 8025 belong to another project's Docker containers. Never touch them. ATLAS Redis runs on **6380**. Firewall changes are the user's to make.
5. **Evidence over assumption.** Every claim in the docs cites evidence (an address, file, log, trace, or test) and carries a confidence tag: `[CONFIRMED]`, `[INFERRED]` or `[GUESS]`. Never upgrade a tag without new evidence.
6. **1:1 first, fixes second.** Reproduce the original behavior, bugs included. A bug fix or improvement is a **deviation**: it gets its own REP record, an ADR, and a runtime toggle that is off by default, so the pure 1:1 baseline can always be reproduced.
7. **One step per commit.** Each commit moves one ID through one stage, or does one infrastructure or docs change. Never bundle unrelated work.
8. **Re-verify, don't trust.** Notes, memory, and older docs can go stale. Re-check environment facts before you rely on them, and fix the doc when you find a fact has drifted.
9. **Stop and ask** before downloads, firewall or system changes, deleting anything, pushing anywhere, actions on Steam/Epic/other accounts, and any ADR-level decision (engine strategy, stubbing out a system, choosing a deviation).

## 3. Environment (verify at the start of each session)

| Item | Path / value |
|---|---|
| Client install (Steam app 834910, buildid 11309919, 2023-05-30, likely v560.3; `version.txt` "538.5" is stale) | `D:\ATLAS` |
| Client binary + PDB | `ShooterGame\Binaries\Win64\AtlasGame.exe` / `AtlasGame.pdb` |
| Editor game module + PDB | `ShooterGame\Binaries\Win64\UE4Editor-ShooterGame.dll` / `.pdb` |
| Stale server inside the client install (529.4; crashes in `UShooterGameInstance::VivoxInitialize`) | **do not use** |
| Dedicated server (SteamCMD app 1006030, buildid 11353410, v560.3 Rev. 129782) | `D:\ATLASServer\ShooterGame\Binaries\Win64\ShooterGameServer.exe` + `.pdb` (449 MB), plus `.lib`/`.exp` (it exports symbols) |
| Ghidra 12.1.4 + JDK 21 + pyghidra-mcp | `D:\ATLAS\_tools\` |
| Ghidra projects | `_re\ghidra` (project `atlas`, server), `_re\ghidra-client` (client) |
| Existing raw decompiles | `_re\decompiled\server\` (~27 files), `_re\decompiled\client\` (~13 files), named `Class__Func@<va>.c` |
| Existing traces/logs | `_re\logs\` (Frida load-map, client trace, server auth) |
| Existing scripts | `_tools\*.py`, `_tools\*.ps1` (server setup and launch, A2S queries, Frida tracers, Ghidra helpers, grid generator) |
| Grids | `_tools\grids\community-1x1`, `official-11x11` |
| Known server ports (1x1 Freeport) | 5761, 5762, 57561 |
| LAN IP | 192.168.1.202 |
| Ghidra MCP config | `ghidra_mcp_server.py` says it is launched from `D:\ATLAS\.mcp.json`, but that file does **not** exist yet; create it during bootstrap |

## 4. What "1:1" means (the parity contract)

A replaced piece is at parity when, for the same inputs and state, it produces the same **observable** results as the original:

- **Network:** the same replicated properties, RPCs, and packet semantics. A rebuilt server must accept an unmodified original client, and an original server must accept a rebuilt client. Property layouts, replication order, and RPC signatures must match.
- **Persistence:** the same save files, the same Redis keys and values, and the same `ServerGrid.json` handling.
- **Content compatibility:** the original cooked `.uasset` / `.umap` content, including Blueprint bytecode, keeps loading and running unchanged. Any native `UFUNCTION` that Blueprints call must keep its name, signature, and semantics.
- **Gameplay and UI:** the same outcomes in scripted scenarios (damage, crafting, sailing, claims, travel between grid cells).
- **Failure behavior:** the same errors and edge cases, unless a documented deviation says otherwise.

Byte-matching compiled code is **not** required by default. For hot or subtle functions (math, serialization, replication), you may require matching via objdiff; record that choice in the ledger.

## 5. The traceability chain

### 5.1 IDs (all filename-safe)

| ID | Meaning | Example |
|---|---|---|
| `SRV@<va>` / `CLI@<va>` / `EDT@<va>` | A function in the server exe, client exe, or editor DLL, keyed by virtual address (lowercase hex, no `0x`; these binary versions are frozen, so IDs never change) | `SRV@141a21100` (`AGameMode::PreLogin`) |
| `SVC-<service>-<slug>` | An external surface: a backend endpoint, a Steam API usage, a Redis key family, voice, anti-cheat… | `SVC-steam-auth-ticket`, `SVC-redis-tribe-data` |
| `FMT-<slug>` | A file or wire format | `FMT-servergrid-json`, `FMT-redis-schema`, `FMT-save-ark` |
| `SYS-<slug>` | A game system (a group of functions plus data) | `SYS-seamless-travel`, `SYS-ship-physics` |
| `REP-####` | A replacement: one unit of our code or service that stands in for original behavior; covers one or more IDs above | `REP-0007` |
| `BUG-####` | An original bug the user wants fixed (fixing it is always a deviation) | `BUG-0003` |
| `ADR-####` | An architecture or strategy decision | `ADR-0001-engine-strategy` |
| `Q-####` | An open question | `Q-0012` |

### 5.2 Function status ladder

Each step needs the previous one, and each transition is its own commit:

```
UNTOUCHED → RAW → ANNOTATED → UNDERSTOOD → REIMPL → HOOKED → VERIFIED → NATIVE
```

- **RAW:** the decompile was exported to `_re/decompiled/<bin>/` and committed with a provenance header. Raw files are **never hand-edited**; their SHA-256 is stored in the ledger.
- **ANNOTATED:** names, types, and structs were fixed in Ghidra **through `_re/annotations/<bin>.jsonl`** (applied by script, so the Ghidra DB can be rebuilt from scratch), and the function was re-exported. The diff between the RAW commit and the ANNOTATED commit shows exactly what we changed.
- **UNDERSTOOD:** the behavior is described in its `SYS-` doc, with callers, callees, data touched, and quirks.
- **REIMPL:** our source exists in `src/reimpl/` with an ID header block and compiles.
- **HOOKED:** our code runs in place of the original behind a per-ID toggle.
- **VERIFIED:** differential or scenario tests pass, and the evidence file is written.
- **NATIVE:** the function is part of the standalone build and the original is no longer needed.

Side states: `STUBBED` (deliberately replaced with no-op or different behavior; needs an ADR), `DEAD` (unreachable or unused; needs evidence), `BLOCKED` (waiting on a `Q-`).

### 5.3 Where each link lives

- **Raw decompile:** `_re/decompiled/<bin>/<Class>__<Func>@<va>.c`. The header comment records the tool version, binary SHA-256, analysis date, and the commit of the export script.
- **Annotations:** `_re/annotations/<bin>.jsonl`, one rename, retype, or comment per line, with the ID.
- **Reconstructed types:** `src/sdk/*.h`. This is the single source of truth for struct and class layouts, with `static_assert(sizeof/offsetof == 0x…)` for every field we rely on. Ghidra imports these headers, so the decompiler and our code always agree.
- **Reimplementation:** `src/reimpl/<system>/…`. Every function starts with:
  ```cpp
  // ATLAS-ID: SRV@141a21100   orig: AGameMode::PreLogin   status: HOOKED
  // REP: REP-0004   raw: _re/decompiled/server/AGameMode__PreLogin@141a21100.c
  // deviations: none
  ```
- **Hook registration:** `src/hook/registry.*` via a macro such as `ATLAS_REPLACE(SRV, 0x141a21100, AGameMode_PreLogin)`. Toggles live in `atlasre.ini` (`SRV@141a21100=on|off|shadow`). In `shadow` mode, pure functions call both the original and ours and log any mismatch.
- **Tests and evidence:** `tests/diff/<ID>/`, `tests/scenarios/`, `tests/golden/`, and `tracking/evidence/<ID>.md`. Evidence records the command, date, binary hashes, our build commit, and the result.
- **Build provenance:** every build of `atlasre.dll` embeds the git commit, a dirty flag, and the list of enabled IDs. On load it writes them to the game log and to `build/manifest.json`, so any runtime log maps back to the exact source.

### 5.4 Commit convention

```
<stage>(<scope>): <summary>

Atlas-Id: SRV@141a21100
Atlas-Stage: RAW|ANNOTATED|UNDERSTOOD|REIMPL|HOOKED|VERIFIED|NATIVE|STUBBED|DEAD|DOC|INFRA|SKILL|KNOWLEDGE
Atlas-Rep: REP-0004          (if any)
Evidence: tracking/evidence/SRV@141a21100.md   (VERIFIED only)
```

The ledger row is updated **in the same commit** as the stage change. `git log --grep "Atlas-Id: SRV@141a21100"` must return that function's full history.

### 5.5 Tools you build for this (tracked in `tools/`)

- `ledger.py`: set or query ledger rows; it refuses illegal transitions.
- `ledger_check.py`: runs as a git pre-commit hook. It fails when a raw file's hash changed, a reimpl header points at a missing ledger row (or the reverse), a HOOKED function has no registration, a VERIFIED function has no evidence, or a REP lists unknown IDs.
- `trace.py <ID|REP-|SVC-|BUG->`: prints the whole chain (ledger row, raw file and hash check, annotations, doc mentions, reimpl file, hook and toggle, tests, evidence, commits).
- `export_decomp.py`: a Ghidra (MCP or headless) export with the provenance header; it builds on the existing `_tools/ghidra_*.py`.
- `coverage.py`: regenerates `tracking/coverage.md` (functions by status, per system and per binary; surfaces by state; open REPs, BUGs and Qs).

## 6. Repository layout

The git repo root is `D:\ATLAS`, with a **whitelist `.gitignore`** that starts with `/*` and re-includes only our directories and the tracked config files. Game files are never staged. Check `git status` after every layout change.

```
D:\ATLAS\
├─ CLAUDE.md                 short rules + pointers (keep under ~150 lines; details live in docs/)
├─ .mcp.json                 Ghidra MCP (server + client projects)
├─ .claude/skills/<name>/SKILL.md
├─ _prompts/                 this prompt and its revisions
├─ _tools/                   existing scripts (tracked); ghidra/jdk/steamcmd/venvs/caches/downloads/server.local.json ignored
├─ _re/
│  ├─ ghidra/, ghidra-client/   Ghidra DBs (ignored; rebuildable from binary + PDB + annotations + sdk headers)
│  ├─ decompiled/{server,client,editor}/   RAW exports (tracked, never hand-edited)
│  ├─ annotations/<bin>.jsonl
│  ├─ inventory/              generated PDB symbol lists (ignored); committed summary + generator script
│  └─ logs/                   small text traces tracked; large ones ignored and summarized in docs
├─ docs/
│  ├─ INDEX.md               map of everything below
│  ├─ systems/SYS-*.md       one per game system
│  ├─ backend/SVC-*.md       one per external surface
│  ├─ formats/FMT-*.md       one per file or wire format
│  ├─ knowledge/             the knowledge base (section 8)
│  ├─ decisions/ADR-*.md
│  ├─ bugs.md                BUG-#### list → linked IDs and deviation REPs
│  ├─ questions.md           Q-#### list (open, then resolved with the answer and evidence)
│  └─ journal/YYYY-MM-DD-<slug>.md   one per session
├─ tracking/
│  ├─ functions.csv          the ledger (only rows beyond UNTOUCHED), sorted by ID
│  ├─ replacements.csv       REP registry
│  ├─ surfaces.csv           SVC registry
│  ├─ baseline/*.json        SHA-256 manifests of the original installs
│  ├─ evidence/<ID>.md
│  └─ coverage.md            generated
├─ src/
│  ├─ sdk/                   reconstructed engine/game types with layout asserts
│  ├─ hook/                  atlasre.dll: loader, hooking (MinHook or Detours), registry, toggles, shadow compare, logging
│  ├─ reimpl/<system>/
│  └─ services/<service>/    backend replacements
├─ tests/{diff,scenarios,golden}/
├─ tools/                    ledger / trace / check / export / coverage
└─ build/                    ignored
```

### Tracking file schemas (CSV, UTF-8, one header row)

- `functions.csv`: `id,binary,va,symbol,system,status,parity(functional|matching),raw_sha256,reimpl_path,toggle,rep,evidence,bug,notes,updated`
- `replacements.csv`: `rep,title,kind(reimpl|service|stub|config|deviation),covers,status,toggle,default,adr,notes,updated`
- `surfaces.csv`: `id,service,protocol,endpoint_or_api,direction,state(ALIVE|DEAD|UNWANTED|UNKNOWN),used_by,rep,doc,notes,updated`

## 7. Modular documentation

- **One topic per file, one owner ID per file.** Docs link to each other by ID; nothing is duplicated. A fact lives in exactly one place, and other files link to it.
- **`SYS-` doc template:** purpose · player-visible behavior · main classes (with PDB names) · key functions (ID table with status) · data and state (structs, replicated props, Redis keys, saves) · network (RPCs, replication) · Blueprint touchpoints (native functions BPs call, BP classes that subclass these) · known bugs (BUG IDs) · open questions (Q IDs) · replacement status (REP IDs) · evidence.
- **`SVC-` doc template:** what it is · who calls it (IDs) · protocol and payloads (with captures) · state (ALIVE/DEAD/UNWANTED/UNKNOWN, with evidence) · replacement plan and REP · how to test it.
- **`FMT-` doc template:** structure, field by field · producers and consumers (IDs) · versions · samples (small, synthetic, or redacted) · parser/writer location in `src/`.
- **Journal entry (every session):** goal · what was done · IDs advanced (`from → to`) · REPs, ADRs, BUGs and Qs touched · new knowledge (with links) · what failed or surprised · next steps.
- `docs/INDEX.md` and `tracking/coverage.md` are updated at the end of every session.

## 8. Knowledge base

`docs/knowledge/` holds what we learn that isn't tied to a single system, surface, or format: engine internals as ATLAS uses them, toolchain behavior, compiler patterns, how-tos, and gotchas.

- **Files:** `INDEX.md`, `glossary.md`, `references.md` (external sources with URL, version, license, and the date checked), `environment.md`, `tooling.md`, plus topic files (`ue45-uobject-reflection.md`, `ue45-networking.md`, `msvc-x64-patterns.md`, `ark-atlas-differences.md`, `hooking.md`, `memory-allocator.md`, …).
- **Every fact** is one bullet: the claim, its evidence, a confidence tag, and the date. When two facts contradict, open a `Q-` instead of picking one silently.
- **Seed it during bootstrap** from the existing work: the auth flow (`server-auth-*.txt`, `PreLogin`/`ApproveLogin` decompiles), map loading (`frida-loadmap*`, `ASeamlessVolumeManager::LoadWorld`), Steam invites and sessions (client decompiles), `ServerGrid.json` handling (`AppendAdditionalParamsFromServerGridJson`), and the Vivox crash in the stale server.
- **Knowledge vs. memory:** project facts go here, in git. Claude's auto-memory holds only user preferences and pointers.

### Knowledge you must bring, and record as you confirm it in this binary

- **UE 4.5 internals:** UObject/UClass/UProperty reflection, `exec*` thunks and `UFUNCTION` dispatch, `FName`/`FString`/`TArray` layouts, GC, the package and cooking format of this fork, Kismet/Blueprint bytecode VM, `UNetDriver`/`UActorChannel`/replication, `RepLayout`, seamless travel.
- **The ARK lineage:** the `Primal*` and `Shooter*` class families, and what ATLAS added on top (grid/seamless servers, ships, claims, companies, Redis-backed cluster state).
- **MSVC x64 (VS2013-era runtime, `msvcr120`):** calling convention, vtables, RTTI, SEH, inlining patterns, how PDB info maps to Ghidra.
- **Memory ownership:** the game's `FMemory`/`GMalloc` owns UE containers. Our code must allocate and free them through the game's allocator, and never pass our CRT's STL objects across the boundary.
- **Hooking:** MinHook or Detours, trampolines, DLL loading (proxy DLL vs. launcher injection; decide in an ADR), thread safety at hook install, and using the server's export table.
- **Runtime tracing:** Frida (already in use), x64dbg, ReClass-style memory inspection, Wireshark for protocols.
- **Steamworks:** auth session tickets (`GetAuthSessionTicket` ↔ `BeginAuthSession`), `ISteamGameServer`, A2S queries, lobbies/invites, the Workshop (`Content\Mods`), Steam networking / `GameNetworkingSockets.dll`.
- **Other services:** the Redis protocol and the cluster key schema; the AWS SDK (`dynamodb`, `s3`, `sns`, `sqs` DLLs ship with the client); Vivox; BattlEye.
- **Asset tooling:** check before relying on any tool that it supports this UE 4.5 fork's package version.
- **Community prior work:** look for ARK/ATLAS server-API projects with headers generated from these PDBs (for example ArkServerApi or AtlasServerApi), and for the ATLAS DevKit (editor, uncooked content, headers). Verify each exists and check its license before using it, record it in `references.md`, and follow the download rule.

## 9. Skills (`.claude/skills/`)

Turn every repeatable workflow into a project skill, but **only after you have done that workflow by hand at least once**, so the skill holds real commands and not guesses. Each `SKILL.md` has frontmatter (`name`, `description` saying when to use it) and covers: when to use it · inputs · exact steps and commands · what it must update (ledger, docs, journal, coverage) · checks that must pass · common failures. Keep each skill short and link to the docs for background. Changing a skill is a `SKILL` commit, with the reason in the message.

Planned skills (add each one when its workflow first becomes real; track the rest in `docs/skills-roadmap.md`):

| Skill | Does |
|---|---|
| `atlas-session-start` | Verify the environment, read INDEX, the latest journal, questions and coverage, then state the session goal |
| `atlas-session-end` | Run `ledger_check`, regenerate coverage, write the journal, update INDEX and questions |
| `atlas-trace` | Run `trace.py` for any ID and explain the chain |
| `atlas-decompile` | Export one function or class to RAW with provenance; add ledger rows |
| `atlas-annotate` | Apply names and types through the annotations file and `src/sdk` headers; re-export to ANNOTATED |
| `atlas-document-system` | Create or refresh a `SYS-` doc from the PDB class list, xrefs, and decompiles |
| `atlas-reimplement` | Write the reimpl with its header, `sdk` types, and registry entry; go to REIMPL, then HOOKED |
| `atlas-verify` | Run differential, shadow, or scenario tests; write evidence; go to VERIFIED |
| `atlas-capture-surface` | Capture and document a backend call (Frida or Wireshark), classify its state, draft the `SVC-` doc |
| `atlas-build-service` | Implement or update a backend replacement in `src/services` with tests |
| `atlas-run-stack` | Start the local Redis (6380), server, and client using the existing `_tools` scripts; collect logs |
| `atlas-deviation` | Turn a BUG into a toggleable deviation REP with an ADR |

## 10. Backend and external-surface inventory

Inventory every way the client and server reach outside themselves. Use imports, strings plus xrefs (URLs, hostnames, IPs, Redis commands, AWS calls), shipped config (`officialservers.ini`, `officialserverstatus.ini`, `news.ini`), and runtime captures. Give each one a `SVC-` row and doc, and classify it:

- **ALIVE:** still works (most of Steam). Keep using it, and document it in case it dies later.
- **DEAD:** Grapeshot endpoints, the official server lists/status/news, and probably Vivox. Replace each with a local service in `src/services/` that serves the same format.
- **UNWANTED:** BattlEye for private play. Bypass it through launch options or a STUBBED REP with an ADR.
- **UNKNOWN:** investigate. The AWS SDK usage (DynamoDB/S3/SNS/SQS) is the main unknown: find out whether community-mode servers touch it at all.

Known surfaces to start from: Steam (auth tickets, A2S/server browser, sessions/invites, Workshop, stats), Redis (cluster state, tribes/companies, travel between grid cells), seamless travel between grid servers (5761/5762/57561, `ServerGrid.json`, `ASeamlessVolumeManager`), Vivox, BattlEye, the AWS SDK, and the official server list/status/news.

The first concrete milestone is a **fully local stack with no dead dependency**: our Redis, the server, the client, and the replacement services, documented and reproducible with one `atlas-run-stack` skill.

## 11. Phases

0. **Bootstrap** (section 12).
1. **Map:** group the PDB classes into `SYS-` docs, inventory the surfaces, and document formats. Every system gets a doc, even an UNMAPPED stub.
2. **Local stack:** replace the dead and unwanted surfaces until the full stack runs locally on the 1x1 grid, then on a multi-cell grid with travel between cells.
3. **Incremental replacement:** run the hook DLL loop through the status ladder. Priority order: (a) anything blocking the local stack (crashes, dead calls); (b) the user's BUG list, done as 1:1 replacements first and deviations second; (c) the critical gameplay paths (login, spawning, ships, travel, claims, persistence); (d) breadth, measured in `coverage.md`.
4. **Standalone build:** once there is enough evidence, write `ADR-0001-engine-strategy`, comparing (a) keeping the original engine binary and replacing game code through hooks indefinitely against (b) rebuilding on UE 4.5 engine source (access goes through the user's Epic-linked GitHub account; the user decides) with the reconstructed ATLAS/ARK engine changes documented as `FMT-`/`SYS-` "engine deltas". Either way, the original cooked content must load unchanged. Do not commit to a strategy before the ADR is approved.

Content rule: cooked assets stay in the install. Our tools read them from configured paths. Research on assets goes into `docs/` as text, never as copied assets.

## 12. Bootstrap (first session only; stop and report when done)

1. Verify every row of section 3. Write `docs/knowledge/environment.md` with what you confirmed and how.
2. Run `git init` at `D:\ATLAS` with the whitelist `.gitignore`. Confirm `git status` shows no game files, binaries, PDBs, Ghidra DBs, venvs, downloads, or `server.local.json`. Make the first `INFRA` commit.
3. Write SHA-256 baseline manifests for both installs (all exe/dll/pdb/ini plus `ServerGrid*`) to `tracking/baseline/`.
4. Create `CLAUDE.md`, the `docs/` skeleton (INDEX, knowledge INDEX, glossary, references, bugs, questions, the first journal entry), and the `tracking/` CSVs with their headers.
5. Build `tools/ledger.py`, `ledger_check.py` (installed as a pre-commit hook), `trace.py`, `coverage.py`, and `export_decomp.py`.
6. Create `.mcp.json` for the Ghidra MCP (server and client projects), and check that it starts.
7. Ingest the existing work: add the ~40 existing raw decompiles to the ledger as RAW (with hashes; add provenance headers through a re-export instead of editing them by hand), summarize the `_re/logs` traces into knowledge, and document every `_tools` script in `docs/knowledge/tooling.md`.
8. Make a first pass at the surface inventory (section 10) and at the system map (section 11, phase 1) from the PDB class names. Stubs are fine.
9. Take one real function through RAW → ANNOTATED end to end, to prove the chain works, then write the skills that bootstrap actually exercised: `atlas-session-start`, `atlas-session-end`, `atlas-trace`, `atlas-decompile`, `atlas-annotate`.
10. Ask the user for their list of known bugs, and seed `docs/bugs.md` with it.
11. Run `atlas-session-end`. Report what exists, the result of `trace.py` on the sample function, open questions, and the proposed goal for session 2. **Do not start reimplementation in this session.**

## 13. Every later session

1. Run `atlas-session-start` and state a single session goal (one system, one surface, one bug, or a named set of IDs).
2. Work through the skills, one stage per commit, keeping the ledger and docs in step.
3. Before you finish, `ledger_check` passes, the tests you touched pass, and the coverage is regenerated.
4. Run `atlas-session-end`. Report the IDs advanced (`from → to`), the REP/ADR/BUG/Q changes, the new knowledge, anything that failed, and the proposed next goal.
5. If a workflow repeated this session and has no skill yet, write the skill. If a skill was wrong, fix it.
