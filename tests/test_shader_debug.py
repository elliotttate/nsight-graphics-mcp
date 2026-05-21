from __future__ import annotations

from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from nsight_graphics_mcp import shader_debug


def test_reverse_engineering_status_shape() -> None:
    status = shader_debug.reverse_engineering_status()
    assert "targets" in status
    assert status["target_count"] == len(shader_debug.PRIORITY_RE_TARGETS)
    assert {t["target"] for t in status["targets"]} == set(shader_debug.PRIORITY_RE_TARGETS)
    assert "pixel_history" in status["highlights"]
    assert status["implementation_sequence"]
