"""Smoke tests that don't require a live capture.

These verify that:
  * the package imports cleanly,
  * the install discovery finds *something* on this machine if Nsight is installed
    (otherwise the test is skipped),
  * the SDK reflection parses the bundled headers,
  * the codegen produces a non-empty C++ snippet,
  * every MCP tool is registered with a unique name.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def test_import_server() -> None:
    from nsight_graphics_mcp import server

    assert server.mcp.name == "nsight-graphics-mcp"


def test_tool_registration() -> None:
    from nsight_graphics_mcp import server

    names = sorted(t.name for t in server.mcp._tool_manager._tools.values())
    # spot-check a few critical names
    for must_have in [
        "ngfx_environment",
        "ngfx_capture_launched",
        "ngfx_graphics_capture_launched",
        "ngfx_gputrace_launched",
        "ngfx_cpp_capture_launched",
        "ngfx_framedebugger_launched",
        "ngfx_replay_run",
        "ngfx_index_events",
        "ngfx_find_events",
        "ngfx_sdk_reference",
        "ngfx_sdk_snippet",
        "ngfx_layer_install",
        "ngfx_raw",
    ]:
        assert must_have in names, f"missing tool: {must_have}"
    # all unique
    assert len(names) == len(set(names))


def test_render_flag_shapes() -> None:
    from nsight_graphics_mcp.cli import render_flag

    assert render_flag("frame_count", 3) == ["--frame-count", "3"]
    assert render_flag("verbose", True) == ["--verbose"]
    assert render_flag("verbose", False) == []
    assert render_flag("verbose", None) == []
    assert render_flag("metric_set_name", "Top Level Triage") == [
        "--metric-set-name",
        "Top Level Triage",
    ]


@pytest.mark.skipif(
    os.name != "nt", reason="Nsight Graphics CLIs are Windows-only"
)
def test_install_discovery_or_skip() -> None:
    from nsight_graphics_mcp.config import discover_install_roots

    roots = discover_install_roots()
    if not roots:
        pytest.skip("Nsight Graphics not installed on this machine")
    assert all(r.is_dir() for r in roots)


@pytest.mark.skipif(
    os.name != "nt", reason="Nsight Graphics CLIs are Windows-only"
)
def test_sdk_reference_or_skip() -> None:
    from nsight_graphics_mcp.config import discover_install_roots
    from nsight_graphics_mcp.sdk import generate_snippet, list_headers

    if not discover_install_roots():
        pytest.skip("Nsight Graphics not installed")
    ref = list_headers()
    assert ref["ok"]
    assert ref["headers"], "no NGFX headers found"
    found_one_function = any(h["function_count"] > 0 for h in ref["headers"])
    assert found_one_function, "no NGFX_* functions parsed from headers"

    snip = generate_snippet("GraphicsCapture", "D3D12")
    assert snip["ok"]
    assert "NGFX_GraphicsCapture_Inject_D3D12" in snip["snippet"]


def test_classify_events() -> None:
    from nsight_graphics_mcp.events import classify

    assert classify("DrawIndexedInstanced") == "draw"
    assert classify("vkCmdDispatch") == "dispatch"
    assert classify("ResourceBarrier") == "barrier"
    assert classify("Present") == "present"
    assert classify("DispatchRays") == "ray_tracing"
    assert classify("Made-up") == "other"
    assert classify("vkCmdSetViewport") == "set_state"


def test_project_roundtrip(tmp_path: Path) -> None:
    from nsight_graphics_mcp.project import create_project, read_project, update_project

    p = tmp_path / "demo.nsight-gfxproj"
    r = create_project(
        p,
        activity="GPU Trace Profiler",
        exe="C:/games/MyGame.exe",
        args="-windowed",
        working_dir="C:/games",
        env_pairs="FOO=1;BAR=2",
    )
    assert r["ok"]
    assert p.is_file()
    read = read_project(p)
    assert read["ok"]
    assert read["Activity"]["attrib"]["name"] == "GPU Trace Profiler"
    upd = update_project(p, activity="Graphics Capture", set_settings={"frame_count": "3"})
    assert upd["ok"]
    re_read = read_project(p)
    assert re_read["Activity"]["attrib"]["name"] == "Graphics Capture"
