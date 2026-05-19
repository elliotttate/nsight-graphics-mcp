"""Query the indexed function stream for fine-grained answers like:
  * 'every draw inside event index range [start, end]'
  * 'every call that mentions resource handle 0x...'
  * 'top 20 most-frequently-called API functions'

Edit ``CAPTURE_PATH`` before running.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from nsight_graphics_mcp import events


CAPTURE_PATH = Path(r"C:/captures/your-capture.ngfx-gfxcap")


async def main() -> None:
    if not CAPTURE_PATH.is_file():
        print(f"set CAPTURE_PATH to a real capture; got {CAPTURE_PATH}")
        return

    idx = await events.index_capture_functions(CAPTURE_PATH)
    print("== index summary ==")
    print(json.dumps(idx.to_dict(), indent=2, default=str))

    db = events._cache_root_for(CAPTURE_PATH) / "functions.db"

    print()
    print("== first 10 draws ==")
    for row in events.query_calls(db, kind="draw", limit=10):
        print(f"  [{row['idx']}] {row['name']}({row['args'][:80]})")

    print()
    print("== histogram by kind ==")
    for row in events.call_histogram(db, by="kind"):
        print(f"  {row['kind']:<12} {row['count']}")


if __name__ == "__main__":
    asyncio.run(main())
