"""Sends one Ctrl+C to a process's console: a graceful exit for the dedicated server when RCON no longer answers
(seen 2026-10-24 under 2000 stress-test ships). UE 4.5's console handler then sets GIsRequestingExit, the same path as
DoExit's RequestExit(0), so the world is not written again: the last save on disk stays (stock
WindowsPlatformMisc.cpp ConsoleCtrlHandler; a second Ctrl+C would terminate the process, so this sends one only).
Never a substitute for the normal stop (stop.ps1 saves first); it beats a hard kill, which can cut a save in half.

Usage: python -I ctrl_c.py <pid>     (run with python.exe: it attaches to that process's console)
"""
import ctypes
import sys
import time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
CTRL_C_EVENT = 0


def main():
    pid = int(sys.argv[1])
    k32.FreeConsole()
    if not k32.AttachConsole(pid):
        raise SystemExit(f"AttachConsole({pid}) failed: error {ctypes.get_last_error()}")
    k32.SetConsoleCtrlHandler(None, True)  # this process ignores the Ctrl+C it is about to send
    ok = k32.GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0)  # to every process on that console: the server alone
    err = ctypes.get_last_error()
    time.sleep(1)
    k32.FreeConsole()
    if not ok:
        raise SystemExit(f"GenerateConsoleCtrlEvent failed: error {err}")


if __name__ == "__main__":
    main()
