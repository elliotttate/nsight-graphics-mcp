"""Headless GPU Trace run + report inspection example.

1. Launch a D3D12/Vulkan app with ``ngfx --activity 'GPU Trace Profiler' …``.
2. After it exits (or after you press F11), find the newest .nsight-gputrace
   and inspect its manifest JSON members.

Edit ``EXE_TO_TRACE`` before running.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from nsight_graphics_mcp import captures, gputrace
from nsight_graphics_mcp.cli import ngfx_activity_argv, run_async
from nsight_graphics_mcp.config import get_settings


EXE_TO_TRACE = r"C:/path/to/your/app.exe"
ARCH = "Blackwell GB20x"          # see ngfx_gputrace_archs
METRIC_SET_NAME = "Top-Level Triage"


async def main() -> None:
    s = get_settings()
    argv = ngfx_activity_argv(
        s,
        activity="GPU Trace Profiler",
        exe=EXE_TO_TRACE,
        activity_flags={
            "start_after_frames": 60,
            "limit_to_frames": 1,
            "architecture": ARCH,
            "metric_set_name": METRIC_SET_NAME,
            "set_gpu_clocks": "base",
            "auto_export": True,
        },
    )
    print("running:", " ".join(argv))
    res = await run_async(argv, tool="ngfx", timeout=600)
    print("ngfx rc:", res.returncode)

    print()
    recent = captures.find_recent_captures(kinds=("gpu_trace",), limit=3)
    print("recent .nsight-gputrace files:")
    print(json.dumps(recent, indent=2, default=str))

    if not recent["captures"]:
        return
    newest = Path(recent["captures"][0]["path"])
    print()
    print("=== archive members ===")
    info = gputrace.inspect_archive(newest)
    print(f"container: {info.get('container')}")
    print(f"members: {info.get('member_count')}")
    for m in info.get("members", [])[:25]:
        print(f"  {m['name']:<50} {m['size']:>10}")


if __name__ == "__main__":
    asyncio.run(main())
