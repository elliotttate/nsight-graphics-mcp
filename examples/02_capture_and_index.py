"""Headless capture + indexing example.

This demonstrates the recommended workflow:

1. Launch a D3D12 or Vulkan app with ``ngfx-capture.exe`` to take a
   single-frame capture (no UI).
2. Open the resulting ``.ngfx-gfxcap`` and dump its summary metadata.
3. Index its function stream into a SQLite DB and run a histogram.

Edit ``EXE_TO_CAPTURE`` below before running.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from nsight_graphics_mcp import capture_info, events
from nsight_graphics_mcp.cli import build_argv, run_async
from nsight_graphics_mcp.config import get_settings


EXE_TO_CAPTURE = r"C:/path/to/your/app.exe"
OUTPUT_DIR = Path("C:/captures/ngfx-mcp-demo")


async def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    s = get_settings()
    capture_exe = s.require_tool("ngfx_capture")

    argv = [
        str(capture_exe),
        "-e", EXE_TO_CAPTURE,
        "--output-dir", str(OUTPUT_DIR),
        "-o", "demo.ngfx-gfxcap",
        "--capture-frame", "120",
        "--bundle-replayer",
        "--terminate-after-capture",
    ]
    print("running:", " ".join(argv))
    res = await run_async(argv, tool="ngfx-capture", timeout=600)
    print("capture rc:", res.returncode)
    print("stderr tail:", res.stderr[-400:])

    capture_path = OUTPUT_DIR / "demo.ngfx-gfxcap"
    if not capture_path.is_file():
        print("capture not produced; aborting")
        return

    print()
    print("=== summary ===")
    summary = await capture_info.capture_metadata(capture_path)
    print(json.dumps(summary, indent=2, default=str)[:1200])

    print()
    print("=== index ===")
    idx = await events.index_capture_functions(capture_path)
    print(json.dumps(idx.to_dict(), indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
