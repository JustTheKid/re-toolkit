"""Start pyghidra-mcp on the ATLAS Ghidra project, sized for very large binaries.

pyghidra-mcp normally decompiles every function at startup to build a semantic code index.
For ShooterGameServer.exe that is hundreds of thousands of functions held in memory, and an
interrupted run starts over, so the code index is disabled here. Decompile, symbol search,
xrefs, call graphs and string search are unaffected; only `search_code` loses its index.

Claude Code launches this over stdio (see D:\\ATLAS\\.mcp.json). Extra CLI arguments are passed
through to pyghidra-mcp, e.g. `--list-project-binaries`.
"""
import os
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
os.environ.setdefault("GHIDRA_INSTALL_DIR", str(TOOLS / "ghidra_12.1.4_PUBLIC"))
os.environ.setdefault("JAVA_HOME", str(TOOLS / "jdk-21.0.12.1+1"))
os.environ.setdefault("JAVA_TOOL_OPTIONS", "-Xmx6g")

from pyghidra_mcp import indexing_mixin  # noqa: E402

_schedule_indexing = indexing_mixin.IndexingMixin.schedule_indexing


def _schedule_indexing_without_code(self, binary_name, *, code=True, strings=True):
    return _schedule_indexing(self, binary_name, code=False, strings=strings)


indexing_mixin.IndexingMixin.schedule_indexing = _schedule_indexing_without_code

from pyghidra_mcp.server import main  # noqa: E402

if __name__ == "__main__":
    defaults = ["--project-path", r"D:\ATLAS\_re\ghidra", "--project-name", "atlas"]
    sys.argv[1:1] = defaults
    main()
