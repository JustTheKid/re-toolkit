---
name: atlas-run-stack
description: Start the local ATLAS stack (Redis on 6380, the v560.3 dedicated server on the 1x1 Freeport grid) as the monitored test server, join it from the Steam client through the normal invite path with the CGNAT redirect, record the run and shut down cleanly with a report. Use whenever the game needs to be run, tested, measured or played locally.
---

# atlas-run-stack

Background: `docs/knowledge/test-server.md` (the tools and the report), `docs/knowledge/local-stack.md`,
`docs/knowledge/joining-and-auth.md`. Run every step in a visible Terminal tab and tell the user which tab to watch.
Runs are tests and measurements of the original: every game hook stays off (ADR-0001 addendum).

## 0. Memory
16 GB machine shared with builds and Ghidra. `start.ps1` refuses to start while MSBuild / cl / link / UBT / UHT /
UE4Editor / AtlasFormatTest or a Ghidra job (`java.exe`, or `python.exe` running `_tools\ghidra_*.py`) runs, or with
under 2.5 GB free; don't override that with `-Force` unless the user says so. The server peaks at 4.8 GB private
while loading, then holds ~1.7 GB; the client wants 4-7 GB more.

## 1. Start (tab "test server")
```
powershell -ExecutionPolicy Bypass -File D:\ATLAS\_tools\testserver\start.ps1 [-Join] [-Note "what this run is"]
```
- **Uncapped by default** (the user's choice, 2026-10-24): the server runs with `-OfficialIgnoreFramerateLimit` (30 Hz);
  `-OfficialCap` gives ATLAS's official 8 Hz / 3 Hz cap, the 1:1 configuration (docs/knowledge/server-tick-rate.md).
  The server process is also opted out of Windows 11's minimized-window timer rule (`-NoTimerOptOut` to skip).
- `-ProfileServer` adds ATLAS's own profiler (`-PROFILESERVER`: tick reports per actor class every 150 s, copied into
  the run); `-ClientClassStats` (with `-Join`) gives the client per-class tick stats too (the server has them always).
- Waits for `has successfully started` (2.5-4 min) and the server's **Steam logon**. If the logon fails (a Valve
  outage during start-up), nobody can join: stop and start again.
- `-Join` joins at once (Steam must be running); otherwise later with
  `powershell -ExecutionPolicy Bypass -File D:\ATLAS\_tools\testserver\join.ps1`.
- Never click inside the server console (freezes it; Esc). Never quote the launch URL.

## 2. While it runs
- `status.ps1` (recorder state, last sample, server, game, log tail, A2S) and `mark.ps1 "text"` (a note in the
  report's timeline), both in `D:\ATLAS\_tools\testserver\`.
- Joined: A2S `players=1/...`, RCON `ListPlayers` in the run's `rcon.log`, `net: send redirected` in the client's
  `ShooterGame\Saved\Logs\atlasre.log`.
- Scripted sessions: the test console's **Test plan** panel (`testplan.json`: Solo 1 at 30 Hz, Solo 2 with
  `-OfficialCap` and a loaded galleon, Soak) labels each stretch and shows its commands
  (docs/knowledge/test-server.md#solo-sessions). Its **Live tick** panel shows every second the server's worst frame,
  the game's own server-fps number and what the client received.
- After a session that spawned ships, once stopped: `world.ps1 -Restore clean` (keeps the replaced save), so the
  next run does not carry them.

## 3. Stop
Ask the user to quit the game first, then:
```
powershell -ExecutionPolicy Bypass -File D:\ATLAS\_tools\testserver\stop.ps1
```
RCON `SaveWorld` + `DoExit`, never `taskkill /F` (a kill during a save can corrupt the world, Q-0008). Every stop ends
in the known exit-time crash after the save (ODD-0043): expected. The recorder collects and writes
`_re\perf\testserver\<run>\report.md`; `runs.md` compares all runs. The client's hook files are removed again.

## Manual steps (debugging only)
`_tools\start-server.ps1` + `wait-ready.ps1`; `hook-deploy.ps1 -Target client -Redirect <public ip>=192.168.1.202`
+ `join-local.ps1 -Address <public ip>`; `stop-server.ps1`. Frida fallback: `local-stack.md`.

## Must update
Journal entry (run IDs, what was tested, outcome); findings into the docs they belong to (perf-recorder.md,
SYS-ships-sailing baseline, questions, oddities).

## Common failures
| Symptom | Cause |
|---|---|
| "did not log on to Steam" / join.ps1 refuses | Valve's CM list failed during start-up: restart (test-server.md, Steam logon) |
| "Unable to query server info for invite." | redirect not active / wrong public IP (Q-0002): join with join.ps1 |
| "Invalid authentication token." | joined without a Steam session (e.g. Frida `open` shortcut) (Q-0001) |
| "App ID specified by server is invalid" | Steam browser / steam://connect: don't use |
| server window title starts with "Select" | console text selection: press Esc |
