from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from nsight_graphics_mcp import ida_re


def test_known_ida_targets_include_priority_binaries() -> None:
    targets = ida_re.known_targets()
    assert targets["ngfx_rpc"] == "ngfx-rpc.exe"
    assert targets["ngfx_replay"] == "ngfx-replay.exe"
    assert targets["frame_debugger_native"] == "Nvda.Graphics.FrameDebugger.Native.dll"
    assert targets["frame_debugger_d3d12"] == "Nvda.Graphics.FrameDebuggerUi.D3D12.Native.dll"
    assert targets["frame_debugger_vulkan"] == "Nvda.Graphics.FrameDebuggerUi.Vulkan.Native.dll"
    assert targets["frame_debugger_common"] == "Nvda.Graphics.FrameDebuggerUi.Common.Native.dll"
    assert targets["battle_plugin"] == "Plugins/BattlePlugin/BattlePlugin.dll"
    assert targets["pylon_plugin"] == "Plugins/PylonPlugin/PylonPlugin.dll"


def test_ida_discovery_shape() -> None:
    installs = ida_re.discover_ida_installs()
    for inst in installs:
        d = inst.to_dict()
        assert Path(d["exe"]).is_file()
        assert d["edition"] in {"professional", "home", "free", "unknown"}


def test_search_facts_synthetic(tmp_path: Path) -> None:
    p = tmp_path / "facts.json"
    p.write_text(
        """
        {
          "ok": true,
          "schema": "nsight-graphics-mcp.ida-facts.v1",
          "strings": [{"value": "MethodRootParametersRequest", "ea": "0x1000"}],
          "functions_by_name": [{"name": "sub_ApiInspectorState", "ea": "0x2000"}],
          "selected_functions": [],
          "decompiled": [{"name": "sub_1", "pseudocode": "DescriptorState();"}]
        }
        """,
        encoding="utf-8",
    )
    hits = ida_re.search_facts(p, "RootParameters|DescriptorState")
    assert hits["ok"]
    assert hits["count"] == 2


@pytest.mark.skipif(not ida_re.discover_ida_installs(), reason="IDA not installed")
def test_ida_command_preview_for_known_target() -> None:
    try:
        preview = ida_re.command_preview("ngfx_rpc")
    except FileNotFoundError:
        pytest.skip("Nsight Graphics not installed")
    assert preview["ok"]
    assert "idat" in Path(preview["ida"]["exe"]).name.lower() or "ida" in Path(preview["ida"]["exe"]).name.lower()
