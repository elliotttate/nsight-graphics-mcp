"""Console entrypoint: ``nsight-graphics-mcp`` / ``ngfx-mcp``.

By default runs the MCP server on stdio. Pass ``--transport=sse`` /
``streamable-http`` for alternate transports.
"""

from __future__ import annotations

import argparse
import sys

from .server import serve


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="nsight-graphics-mcp",
        description="MCP server for NVIDIA Nsight Graphics (ngfx.exe and friends).",
    )
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "sse", "streamable-http"],
        help="MCP transport (default: stdio, for use with Claude Desktop / Claude Code).",
    )
    args = parser.parse_args(argv)
    try:
        serve(transport=args.transport)
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
