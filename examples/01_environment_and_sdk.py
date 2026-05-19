"""Verify the MCP can locate the Nsight Graphics install and parse the
in-app SDK headers. Run from the project root after ``pip install -e .``::

    python examples/01_environment_and_sdk.py
"""

from __future__ import annotations

import asyncio
import json

from nsight_graphics_mcp.config import get_settings
from nsight_graphics_mcp.sdk import generate_snippet, grep_sdk, list_headers


def main() -> None:
    info = get_settings().installation_info()
    print("=== environment ===")
    print(json.dumps(info, indent=2, default=str))
    print()

    print("=== SDK headers ===")
    ref = list_headers()
    print(f"sdk_root: {ref.get('sdk_root')}")
    for h in ref.get("headers", []):
        print(f"  {h['header']:<45} {h['function_count']:>3} fns")
    print()

    print("=== Grep for NGFX_FrameBoundary ===")
    g = grep_sdk("NGFX_FrameBoundary")
    for hit in g["hits"][:8]:
        print(f"  {hit['path']}:{hit['line']}: {hit['text'][:80]}")
    print()

    print("=== Codegen: GraphicsCapture / D3D12 ===")
    snip = generate_snippet("GraphicsCapture", "D3D12")
    print(snip["snippet"][:400] + "\n  ...")


if __name__ == "__main__":
    main()
