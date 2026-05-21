"""Capability report for deep Nsight-only capture analysis.

This module answers a different question than the normal environment probe:
not just "is Nsight installed?", but "which path can give an LLM enough
render-state detail to debug a visual shader issue from a capture?".
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from .config import (
    TOOL_DEFINITIONS,
    discover_install_roots,
    discover_sdk_versions,
    find_tool,
    host_bin_dir,
)
from .cpp_capture import _D3D_CPP_CAPTURE_SERIALIZER_REMOVED

DOC_REFERENCES: list[dict[str, str]] = [
    {
        "topic": "Graphics Capture overview",
        "url": "https://docs.nvidia.com/nsight-graphics/UserGuide/graphics-capture-overview.html",
        "note": (
            "Current persistent D3D12/Vulkan capture workflow. Nsight describes it as the "
            "evolution of Frame Debugging and the path for render-accuracy issues."
        ),
    },
    {
        "topic": "Graphics Capture CLI",
        "url": "https://docs.nvidia.com/nsight-graphics/UserGuide/graphics-capture-cli.html",
        "note": (
            "Documents ngfx-capture/ngfx-replay, .ngfx-capture files, metadata modes, "
            "and standalone replay."
        ),
    },
    {
        "topic": "Generate C++ Capture",
        "url": "https://docs.nvidia.com/nsight-graphics/UserGuide/generate-cpp-activity.html",
        "note": (
            "Still documents the CLI activity and generated ngfx-cppcap/CMake project, "
            "but the saved-capture route is UI/private-plugin driven."
        ),
    },
    {
        "topic": "Nsight Graphics release notes",
        "url": "https://docs.nvidia.com/nsight-graphics/ReleaseNotes/index.html",
        "note": (
            "Tracks current deprecations; Graphics Capture is NVIDIA's stated persistence "
            "replacement where C++ Capture support is deprecated."
        ),
    },
]


_SCAN_TARGETS = (
    "ngfx.exe",
    "ngfx-capture.exe",
    "ngfx-replay.exe",
    "ngfx-rpc.exe",
    "ngfx-ui.exe",
    r"Plugins\BattlePlugin\BattlePlugin.dll",
    r"Plugins\PylonPlugin\PylonPlugin.dll",
    r"Plugins\PylonFrameDebuggerPlugin\PylonFrameDebuggerPlugin.dll",
    "PylonReplay_PluginInterface.dll",
    "Nvda.Graphics.FrameDebugger.Native.dll",
    "Nvda.Graphics.FrameDebuggerUi.Common.Native.dll",
    "ShaderDebuggerPlugin.dll",
    "ShaderProfilerPlugin.dll",
)


_NEEDLES: dict[str, tuple[str, ...]] = {
    "generate_cpp_capture": (
        "Generate C++ Capture",
        "C++ Capture",
        "NOMAD_IS_CPP_CAPTURE",
        "ngfx-cppcap",
    ),
    "cpp_capture_saved_export_ui": (
        "Serialization Save Directory",
        "Export C++ Capture",
        "Export of C++ Capture",
        "PbSerializeRequestMessage",
    ),
    "d3d_cpp_serializer_removed": (
        _D3D_CPP_CAPTURE_SERIALIZER_REMOVED,
        "please migrate to the Graphics Capture Activity",
    ),
    "graphics_capture": (
        "Graphics Capture",
        "ngfx-capture",
        ".ngfx-capture",
        "Binary Capture",
        "BinaryReplay",
    ),
    "frame_debugger": (
        "Frame Debugger",
        "Pixel History",
        "Resource Viewer",
        "API Inspector",
        "Root Parameters",
    ),
    "shader_deep_tools": (
        "Shader Debugger",
        "Shader Profiler",
        "Shader Pipelines",
        "Shader Source",
    ),
}


def _utf16le(text: str) -> bytes:
    return text.encode("utf-16le", errors="ignore")


def _needle_bytes(text: str) -> tuple[bytes, bytes]:
    return text.encode("utf-8", errors="ignore"), _utf16le(text)


def _file_contains_any(data: bytes, needles: tuple[str, ...]) -> list[str]:
    matches: list[str] = []
    for needle in needles:
        ascii_needle, utf16_needle = _needle_bytes(needle)
        if ascii_needle in data or utf16_needle in data:
            matches.append(needle)
    return matches


def _scan_binary(path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file(),
        "size_bytes": None,
        "signals": {},
    }
    if not path.is_file():
        return info
    try:
        data = path.read_bytes()
    except OSError as exc:
        info["read_error"] = str(exc)
        return info
    info["size_bytes"] = len(data)
    signals: dict[str, Any] = {}
    for name, needles in _NEEDLES.items():
        matches = _file_contains_any(data, needles)
        signals[name] = {
            "present": bool(matches),
            "matched_terms": matches[:8],
        }
    info["signals"] = signals
    return info


def _scan_sdk(sdk_roots: list[Path]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "versions": [str(p) for p in sdk_roots],
        "graphics_capture_sdk": False,
        "gpu_trace_sdk": False,
        "generate_cpp_capture_sdk": False,
        "matched_headers": [],
    }
    for root in sdk_roots:
        include = root / "include"
        if not include.is_dir():
            continue
        for header in include.rglob("*.h"):
            try:
                text = header.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            matched: list[str] = []
            if "NGFX_GraphicsCapture_" in text:
                out["graphics_capture_sdk"] = True
                matched.append("NGFX_GraphicsCapture_*")
            if "NGFX_GPUTrace_" in text:
                out["gpu_trace_sdk"] = True
                matched.append("NGFX_GPUTrace_*")
            if "Generate C++ Capture" in text or "CppCapture" in text or "C++ Capture" in text:
                out["generate_cpp_capture_sdk"] = True
                matched.append("Generate C++ Capture")
            if matched:
                out["matched_headers"].append(
                    {"path": str(header), "signals": matched}
                )
    return out


def _run_help(exe: Path, args: list[str], *, timeout_sec: float) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            [str(exe), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": str(exc), "stdout": "", "stderr": ""}
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def _parse_ngfx_activities(help_text: str) -> list[str]:
    activities: list[str] = []
    in_activity = False
    for line in help_text.splitlines():
        if "--activity" in line:
            in_activity = True
            continue
        if in_activity:
            if "--platform" in line or "activity options:" in line:
                break
            stripped = line.strip()
            if stripped and not stripped.startswith("--") and not stripped.endswith(":"):
                activities.append(stripped)
    return activities


def _help_summary(root: Path, *, timeout_sec: float = 20.0) -> dict[str, Any]:
    ngfx = find_tool("ngfx", install_root=root)
    capture = find_tool("ngfx_capture", install_root=root)
    replay = find_tool("ngfx_replay", install_root=root)
    out: dict[str, Any] = {
        "ngfx_help_all": None,
        "ngfx_capture_help": None,
        "ngfx_replay_help": None,
        "activities": [],
        "ngfx_capture_options": [],
        "ngfx_replay_metadata_options": [],
    }
    if ngfx and ngfx.is_file():
        help_all = _run_help(ngfx, ["--help-all"], timeout_sec=timeout_sec)
        out["ngfx_help_all"] = _summarize_help(help_all, max_chars=6000)
        out["activities"] = _parse_ngfx_activities(help_all.get("stdout", ""))
    if capture and capture.is_file():
        cap_help = _run_help(capture, ["--help"], timeout_sec=timeout_sec)
        out["ngfx_capture_help"] = _summarize_help(cap_help, max_chars=4000)
        out["ngfx_capture_options"] = _extract_options(
            cap_help.get("stdout", ""),
            prefixes=("--recapture", "--recompress", "--output-dir", "--output-file",
                      "--capture-frame", "--capture-full-gpu-allocs", "--no-lazy-data-collection"),
        )
    if replay and replay.is_file():
        replay_help = _run_help(replay, ["--help"], timeout_sec=timeout_sec)
        out["ngfx_replay_help"] = _summarize_help(replay_help, max_chars=5000)
        out["ngfx_replay_metadata_options"] = _extract_options(
            replay_help.get("stdout", ""),
            prefixes=("--metadata", "--metadata-functions", "--metadata-objects",
                      "--metadata-screenshot", "--metadata-logs", "--perf-report-dir"),
        )
    return out


def _summarize_help(result: dict[str, Any], *, max_chars: int) -> dict[str, Any]:
    stdout = result.get("stdout") or ""
    stderr = result.get("stderr") or ""
    return {
        "ok": result.get("ok"),
        "returncode": result.get("returncode"),
        "stdout_head": stdout[:max_chars],
        "stdout_truncated": len(stdout) > max_chars,
        "stderr_tail": stderr[-1000:],
    }


def _extract_options(help_text: str, *, prefixes: tuple[str, ...]) -> list[str]:
    hits: list[str] = []
    for line in help_text.splitlines():
        stripped = line.strip()
        if any(stripped.startswith(prefix) for prefix in prefixes):
            hits.append(stripped)
    return hits


def _scan_install(root: Path, *, probe_cli_help: bool) -> dict[str, Any]:
    host = host_bin_dir(root)
    tools = {
        key: str(path) if path else None
        for key in TOOL_DEFINITIONS
        for path in [find_tool(key, install_root=root)]
    }
    sdk_roots = discover_sdk_versions(root)
    files: dict[str, Any] = {}
    aggregate: dict[str, bool] = {name: False for name in _NEEDLES}
    if host:
        for rel in _SCAN_TARGETS:
            scan = _scan_binary(host / rel)
            files[rel] = scan
            for name, signal in scan.get("signals", {}).items():
                aggregate[name] = aggregate[name] or bool(signal.get("present"))

    sdk = _scan_sdk(sdk_roots)
    if sdk["graphics_capture_sdk"]:
        aggregate["graphics_capture"] = True
    if sdk["generate_cpp_capture_sdk"]:
        aggregate["generate_cpp_capture"] = True

    help_info = _help_summary(root) if probe_cli_help else None
    if help_info:
        activities = set(help_info.get("activities") or [])
        if "Generate C++ Capture" in activities:
            aggregate["generate_cpp_capture"] = True
        if "Graphics Capture" in activities:
            aggregate["graphics_capture"] = True

    return {
        "install_root": str(root),
        "version_dir_name": root.name,
        "host_bin_dir": str(host) if host else None,
        "tools": tools,
        "sdk": sdk,
        "binary_scan": files,
        "aggregate_signals": aggregate,
        "cli_help": help_info,
    }


def _capture_status(capture: str | None) -> dict[str, Any] | None:
    if not capture:
        return None
    path = Path(capture).expanduser()
    suffixes = "".join(path.suffixes[-2:]).lower()
    suffix = path.suffix.lower()
    if suffix in (".ngfx-capture", ".ngfx-gfxcap", ".gfxcap", ".nsightgfx"):
        kind = "graphics_capture"
    elif suffix in (".nsight-gputrace", ".gputrace"):
        kind = "gpu_trace"
    elif suffix == ".ngfx-cppcap" or suffixes.endswith(".ngfx-cppcap"):
        kind = "cpp_capture_document"
    else:
        kind = "unknown"
    sidecar = Path(str(path) + ".ngfxmcp")
    cpp_db_candidates = []
    if path.exists():
        parent = path.parent
        cpp_db_candidates.extend(parent.rglob(".ngfxmcp_cpp_calls.db"))
    return {
        "path": str(path),
        "exists": path.is_file(),
        "size_bytes": path.stat().st_size if path.is_file() else None,
        "kind": kind,
        "suffix": suffix,
        "sidecar_dir": str(sidecar),
        "sidecar_exists": sidecar.is_dir(),
        "objects_db": str(sidecar / "objects.db") if (sidecar / "objects.db").is_file() else None,
        "functions_db": str(sidecar / "functions.db") if (sidecar / "functions.db").is_file() else None,
        "cpp_call_indexes_found": [str(p) for p in cpp_db_candidates[:20]],
        "analysis_warning": (
            "ngfx-replay metadata gives event names/object summaries only; descriptor arguments, "
            "pixel history, and resource revisions require C++ capture indexes, live replay RPC, "
            "or raw capture decoding."
        ),
    }


def _old_version_guidance(installs: list[dict[str, Any]], selected: dict[str, Any]) -> dict[str, Any]:
    older = [i for i in installs if i["install_root"] != selected["install_root"]]
    viable = []
    for install in older:
        signals = install.get("aggregate_signals", {})
        viable.append(
            {
                "install_root": install["install_root"],
                "version_dir_name": install["version_dir_name"],
                "generate_cpp_capture_signal": bool(signals.get("generate_cpp_capture")),
                "graphics_capture_signal": bool(signals.get("graphics_capture")),
                "d3d_cpp_serializer_removed_signal": bool(signals.get("d3d_cpp_serializer_removed")),
            }
        )
    return {
        "detected_older_installs": viable,
        "fallback_rule": (
            "Use an older Nsight only if it can either open this saved capture or recapture the "
            "same repro. NVIDIA documents forward replay compatibility more strongly than reverse "
            "compatibility, so an old replayer may not understand a newer .ngfx-capture."
        ),
        "best_use": (
            "If an old version still emits D3D12 C++ projects, treat that as an optional "
            "argument-index source. Keep Graphics Capture as the canonical artifact."
        ),
    }


def _capability_matrix(selected: dict[str, Any]) -> list[dict[str, Any]]:
    signals = selected.get("aggregate_signals", {})
    tools = selected.get("tools", {})
    help_info = selected.get("cli_help") or {}
    activities = set(help_info.get("activities") or [])
    return [
        {
            "name": "Graphics Capture",
            "status": "available" if tools.get("ngfx_capture") and tools.get("ngfx_replay") else "missing_cli",
            "depth": "canonical saved capture; replayable; current D3D12/Vulkan persistence path",
            "evidence": {
                "ngfx_capture": tools.get("ngfx_capture"),
                "ngfx_replay": tools.get("ngfx_replay"),
                "ngfx_activity_advertised": "Graphics Capture" in activities,
                "binary_or_sdk_signal": bool(signals.get("graphics_capture")),
            },
            "mcp_tools": [
                "ngfx_capture_launched",
                "ngfx_capture_summary",
                "ngfx_index_events",
                "ngfx_index_objects",
                "ngfx_capture_decode_events",
                "ngfx_replay_screenshot",
            ],
        },
        {
            "name": "Graphics Debugger live replay RPC",
            "status": "available_when_session_bound" if signals.get("frame_debugger") else "needs_re",
            "depth": "deep state: pixel history, resource revisions, live object/resource inspection",
            "evidence": {
                "frame_debugger_signal": bool(signals.get("frame_debugger")),
                "ngfx_rpc": tools.get("ngfx_rpc"),
            },
            "mcp_tools": [
                "ngfx_rpc_open_capture_session",
                "ngfx_pixel_history",
                "ngfx_resource_revision_at_event",
                "ngfx_resource_access_history",
                "ngfx_rpc_call_binary_replay",
            ],
        },
        {
            "name": "GPU Trace on Graphics Capture replay",
            "status": "available" if tools.get("ngfx") and tools.get("ngfx_replay") else "missing_cli",
            "depth": "shader performance/source correlation; not a substitute for per-event descriptors",
            "evidence": {
                "shader_deep_tools_signal": bool(signals.get("shader_deep_tools")),
                "ngfx_activity_advertised": "GPU Trace Profiler" in activities,
            },
            "mcp_tools": [
                "ngfx_gputrace_launched",
                "ngfx_gputrace_archive",
                "ngfx_gputrace_read_member",
                "ngfx_replay_run_advanced",
            ],
        },
        {
            "name": "Generate C++ Capture",
            "status": _cpp_capture_status(selected),
            "depth": "best historical source for call arguments and editable replay source",
            "evidence": {
                "ngfx_activity_advertised": "Generate C++ Capture" in activities,
                "binary_or_sdk_signal": bool(signals.get("generate_cpp_capture")),
                "saved_export_ui_signal": bool(signals.get("cpp_capture_saved_export_ui")),
                "serializer_removed_signal": bool(signals.get("d3d_cpp_serializer_removed")),
            },
            "mcp_tools": [
                "ngfx_cpp_capture_launched",
                "ngfx_cpp_capture_saved_headless_attempt",
                "ngfx_cpp_capture_index_calls",
                "ngfx_cpp_capture_descriptor_bindings",
                "ngfx_pso_index",
            ],
        },
        {
            "name": "Raw .ngfx-capture decoder",
            "status": "partial",
            "depth": "headless fallback for format chunks/protobufs/events when private RPC is unavailable",
            "evidence": {
                "capture_decoder_present": True,
                "protobuf_schema_recovery_present": True,
            },
            "mcp_tools": [
                "ngfx_capture_decode_header",
                "ngfx_capture_decode_chunks",
                "ngfx_capture_decode_toc",
                "ngfx_capture_decode_events",
                "ngfx_proto_schemas",
            ],
        },
    ]


def _cpp_capture_status(selected: dict[str, Any]) -> str:
    signals = selected.get("aggregate_signals", {})
    help_info = selected.get("cli_help") or {}
    activities = set(help_info.get("activities") or [])
    if signals.get("d3d_cpp_serializer_removed"):
        return "present_but_d3d_serializer_removed"
    if "Generate C++ Capture" in activities or signals.get("generate_cpp_capture"):
        if signals.get("cpp_capture_saved_export_ui"):
            return "present_saved_export_private_ui_path"
        return "present_live_cli_only"
    return "not_detected"


def _ranked_next_steps(capture_info: dict[str, Any] | None, selected: dict[str, Any]) -> list[dict[str, Any]]:
    signals = selected.get("aggregate_signals", {})
    steps: list[dict[str, Any]] = [
        {
            "rank": 1,
            "goal": "Make the current dump non-shallow.",
            "tools": [
                "ngfx_capture_summary",
                "ngfx_index_events",
                "ngfx_index_objects",
                "ngfx_capture_decode_events",
            ],
            "why": "Build the stable function/object baseline available from Graphics Capture metadata.",
        },
        {
            "rank": 2,
            "goal": "Bind live replay FrameDebugger RPC for exact bug provenance.",
            "tools": [
                "ngfx_rpc_open_capture_session",
                "ngfx_pixel_history",
                "ngfx_resource_revision_at_event",
                "ngfx_resource_access_history",
            ],
            "why": "This is the replacement for C++ source when the question is which event/resource first goes wrong.",
        },
        {
            "rank": 3,
            "goal": "Run GPU Trace on the capture replay when shader cost/source correlation matters.",
            "tools": [
                "ngfx_replay_run_advanced",
                "ngfx_gputrace_launched",
                "ngfx_gputrace_archive",
            ],
            "why": "Nsight 2026.1 exposes replay-aware GPU Trace options, including shader pipeline collection.",
        },
        {
            "rank": 4,
            "goal": "Use C++ Capture only as an optional argument-index source.",
            "tools": [
                "ngfx_cpp_capture_saved_headless_attempt",
                "ngfx_cpp_capture_saved_ui_automation_attempt",
                "ngfx_cpp_capture_index_calls",
            ],
            "why": (
                "The current supported replacement is Graphics Capture. C++ Capture remains useful "
                "when it actually emits a project, but saved-capture export is private UI/plugin code."
            ),
        },
        {
            "rank": 5,
            "goal": "If private RPC remains blocked, continue raw capture decoder work.",
            "tools": [
                "ngfx_capture_decode_toc",
                "ngfx_proto_schemas",
                "ngfx_capture_event_args",
            ],
            "why": "This is the only fully headless path to recover deeper state from the dump itself.",
        },
    ]
    if capture_info and capture_info.get("kind") == "cpp_capture_document":
        steps.insert(
            0,
            {
                "rank": 0,
                "goal": "Index the existing C++ capture document/project first.",
                "tools": ["ngfx_cpp_capture_index_calls", "ngfx_cpp_capture_descriptor_bindings"],
                "why": "A generated project already exists, so per-call arguments may be immediately available.",
            },
        )
    if signals.get("d3d_cpp_serializer_removed"):
        for step in steps:
            if step["goal"].startswith("Use C++ Capture"):
                step["why"] += " This install contains the D3D serializer removal signal, so prefer RPC/raw decoder."
    return steps


def _parse_version_tuple(name: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", name)) or (0,)


def deep_capture_capability_report(
    *,
    capture: str | None = None,
    install_root: str | None = None,
    probe_cli_help: bool = True,
) -> dict[str, Any]:
    """Return a machine-readable plan for deep Nsight-only capture analysis."""
    roots = discover_install_roots()
    if install_root:
        root = Path(install_root).expanduser()
        if root not in roots:
            roots = [root, *roots]
    if not roots:
        return {
            "ok": False,
            "status": "no_nsight_install_found",
            "docs": DOC_REFERENCES,
            "next_steps": [
                "Install Nsight Graphics or set NSIGHT_GRAPHICS_MCP_INSTALL_ROOT.",
            ],
        }
    roots = sorted(roots, key=lambda p: _parse_version_tuple(p.name), reverse=True)
    selected_root = Path(install_root).expanduser() if install_root else roots[0]
    install_reports = [
        _scan_install(root, probe_cli_help=probe_cli_help and root == selected_root)
        for root in roots
    ]
    selected = next(
        (report for report in install_reports if Path(report["install_root"]) == selected_root),
        install_reports[0],
    )
    cap_info = _capture_status(capture)
    matrix = _capability_matrix(selected)
    return {
        "ok": True,
        "status": "reported",
        "selected_install": selected,
        "all_installs": install_reports,
        "capture": cap_info,
        "docs": DOC_REFERENCES,
        "replacement_assessment": {
            "short_answer": (
                "For D3D12/Vulkan persistence, Graphics Capture is the current replacement path "
                "to build around. Generate C++ Capture may still be advertised, but should be "
                "treated as optional/legacy for this MCP workflow."
            ),
            "why": [
                "Graphics Capture creates replayable saved captures and is documented for render-accuracy issues.",
                "ngfx-replay exposes only shallow metadata headlessly; deep state comes from live replay RPC or raw decoding.",
                "C++ Capture's saved-capture exporter is private UI/plugin code and may be API-limited by Nsight version.",
            ],
            "canonical_artifact_extensions": [".ngfx-capture", ".ngfx-gfxcap"],
            "optional_legacy_artifact_extensions": [".ngfx-cppcap"],
        },
        "capability_matrix": matrix,
        "old_version_fallback": _old_version_guidance(install_reports, selected),
        "ranked_next_steps": _ranked_next_steps(cap_info, selected),
    }
