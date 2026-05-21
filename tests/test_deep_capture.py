from __future__ import annotations

from pathlib import Path

from nsight_graphics_mcp import deep_capture
from nsight_graphics_mcp.captures import list_captures_in_dir

HOST_SUBDIR = Path("host") / "windows-desktop-nomad-x64"


def _fake_install(root: Path) -> Path:
    install = root / "Nsight Graphics 2026.1.0"
    host = install / HOST_SUBDIR
    plugins = host / "Plugins"
    (plugins / "BattlePlugin").mkdir(parents=True)
    (plugins / "PylonPlugin").mkdir(parents=True)
    (plugins / "PylonFrameDebuggerPlugin").mkdir(parents=True)
    sdk_include = install / "SDKs" / "NsightGraphicsSDK" / "0.8.0" / "include"
    sdk_include.mkdir(parents=True)

    for name in (
        "ngfx.exe",
        "ngfx-capture.exe",
        "ngfx-replay.exe",
        "ngfx-rpc.exe",
        "ngfx-ui.exe",
    ):
        (host / name).write_text("Graphics Capture Generate C++ Capture", encoding="utf-8")

    (plugins / "BattlePlugin" / "BattlePlugin.dll").write_text(
        "Frame Debugger Pixel History Resource Viewer Serialization Save Directory "
        "Export C++ Capture ngfx-cppcap",
        encoding="utf-8",
    )
    (plugins / "PylonPlugin" / "PylonPlugin.dll").write_text(
        "Generate C++ Capture Graphics Capture",
        encoding="utf-8",
    )
    (plugins / "PylonFrameDebuggerPlugin" / "PylonFrameDebuggerPlugin.dll").write_text(
        "BinaryReplay Root Parameters",
        encoding="utf-8",
    )
    (host / "ShaderProfilerPlugin.dll").write_text("Shader Profiler Shader Pipelines", encoding="utf-8")
    (sdk_include / "NGFX.h").write_text(
        "NGFX_GraphicsCapture_InitializeActivity_D3D12_Params_V1\n"
        "NGFX_GPUTrace_InitializeActivity_D3D12_Params_V1\n",
        encoding="utf-8",
    )
    return install


def test_deep_capture_capability_report_detects_current_replacement_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    install = _fake_install(tmp_path)
    capture = tmp_path / "frame.ngfx-capture"
    capture.write_bytes(b"fake")
    monkeypatch.setattr(deep_capture, "discover_install_roots", lambda: [install])

    report = deep_capture.deep_capture_capability_report(
        capture=str(capture),
        install_root=str(install),
        probe_cli_help=False,
    )

    assert report["ok"]
    assert report["capture"]["kind"] == "graphics_capture"
    assert report["replacement_assessment"]["canonical_artifact_extensions"][0] == ".ngfx-capture"
    signals = report["selected_install"]["aggregate_signals"]
    assert signals["graphics_capture"]
    assert signals["generate_cpp_capture"]
    assert signals["frame_debugger"]
    cpp = next(item for item in report["capability_matrix"] if item["name"] == "Generate C++ Capture")
    assert cpp["status"] == "present_saved_export_private_ui_path"
    assert report["ranked_next_steps"][1]["tools"][0] == "ngfx_rpc_open_capture_session"


def test_list_captures_in_dir_includes_current_ngfx_capture_suffix(tmp_path: Path) -> None:
    capture = tmp_path / "sample.ngfx-capture"
    capture.write_bytes(b"x")

    captures = list_captures_in_dir(tmp_path)

    assert [c.path for c in captures] == [capture]
    assert captures[0].kind == "graphics_capture"
