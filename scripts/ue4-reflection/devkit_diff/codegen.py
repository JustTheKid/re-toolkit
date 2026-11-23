"""Porting what the DevKit module diff found: reflection_codegen.py on a DevKit typed decompile. Sets
reflection_table.DEVKIT (as reflection_diff_all.py --dll does: the decompile is read through devkit_text()), then runs
reflection_codegen.py with the remaining arguments: the missing UPROPERTY declarations in ATLAS's order, or with
--apply inserted into our header.

Usage: python -I _tools/devkit_diff/codegen.py <DevKit DLL> <Z_Construct_...@va.c> <ours .jsonl>
       [reflection_codegen options: --apply <header> --type <UClass>, --category, --comment]
  e.g. ... UE4Editor-AnimGraph.dll _re/corpus/devkit/animgraph-typed/Z_Construct_UClass_UAnimPreviewInstance@18005fcd0.c
       <work>/ours/AnimGraph/AnimPreviewInstance.jsonl
Step 1.9d (2026-10-23), from that session's scratch helper.
"""
import runpy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from devkit_modules import TOOLS  # noqa: E402

sys.path.insert(1, str(TOOLS))
import reflection_table  # noqa: E402
from devkit_metadata import PE  # noqa: E402

if len(sys.argv) < 4:
    sys.exit(__doc__)
reflection_table.DEVKIT = PE(sys.argv[1])
sys.argv = ["reflection_codegen.py"] + sys.argv[2:]
runpy.run_path(str(TOOLS / "reflection_codegen.py"), run_name="__main__")
