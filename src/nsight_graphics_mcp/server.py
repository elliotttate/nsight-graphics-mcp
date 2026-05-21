"""nsight-graphics-mcp — FastMCP server exposing every documented Nsight
Graphics CLI workflow as an MCP tool, plus an NGFX-SDK reference + codegen
layer for in-app integration.

Surface area:

* ``ngfx_environment`` — install / SDK / tool discovery.
* ``ngfx_*_launched`` / ``ngfx_*_attached`` — one-shot launchers for each of
  the four documented activities (Graphics Capture, GPU Trace Profiler,
  Generate C++ Capture, OpenGL Frame Debugger).
* ``ngfx_capture_*`` — direct headless capture via ``ngfx-capture.exe`` (no
  Nsight UI required; produces a ``.ngfx-capture`` / ``.ngfx-gfxcap`` file you can replay later).
* ``ngfx_replay_*`` — drive ``ngfx-replay.exe``: replay a capture, dump
  metadata, embed-screenshot, bundle replayer, etc.
* ``ngfx_open_capture`` / ``ngfx_open_gputrace`` — register a session handle
  so subsequent queries can chain off it.
* ``ngfx_aftermath_*`` — Aftermath crash-dump configuration + monitoring.
* ``ngfx_remote_monitor_*`` — start/stop the remote-monitor headless daemon.
* ``ngfx_rpc_start`` — start the headless RPC server.
* ``ngfx_rpc_protocol_info`` — reverse-engineered wire-format spec.
* ``ngfx_rpc_transport_connect`` / ``ngfx_rpc_send_raw_frame`` — low-level
  RPC transport (8-byte ``[magic][channel][flag][size_BE]`` framing).
* ``ngfx_layer_*`` — Vulkan / VulkanSC / OpenXR layer install helpers.
* ``ngfx_sdk_*`` — header inventory, regex search, and codegen for the
  in-app NGFX SDK.
* ``ngfx_raw`` — escape hatch: invoke any Nsight tool with an arbitrary argv.

All long-running tools (``ngfx_*_background``, ``remote_monitor_start``,
``ngfx_rpc_start``) return a launch-session handle. Use ``ngfx_launch_status``
to poll its stdio buffers and ``ngfx_launch_stop`` to terminate.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import (
    autonomous_shader_fix as autonomous_fix,
)
from . import (
    capture_decoder as capture_decoder_mod,
)
from . import (
    capture_diff as capture_diff_mod,
)
from . import (
    capture_format as capture_format_mod,
)
from . import (
    capture_info,
    cpp_bridge_re,
    cpp_capture,
    cpp_capture_parser,
    frame_costs,
    handle_resolver,
    ida_re,
    layers,
    proto_descriptors,
    proto_schemas,
    pso_resolver,
    rpc_client,
    rpc_trace,
    sdk,
)
from . import (
    captures as captures_mod,
)
from . import (
    deep_capture as deep_capture_mod,
)
from . import (
    doctor as doctor_mod,
)
from . import (
    events as events_mod,
)
from . import (
    etw_capture as etw_capture_mod,
)
from . import (
    pe_patch_planner as pe_patch_planner_mod,
)
from . import (
    eye_issue as eye_issue_mod,
)
from . import (
    frame_debugger_rpc as frame_debugger_rpc_mod,
)
from . import (
    gputrace as gputrace_mod,
)
from . import (
    objects as objects_mod,
)
from . import (
    project as project_mod,
)
from . import (
    redist as redist_mod,
)
from . import (
    shader_debug as shader_debug_mod,
)
from . import (
    shader_triage as shader_triage_mod,
)
from . import (
    shaders as shaders_mod,
)
from . import (
    ui as ui_mod,
)
from . import (
    watch as watch_mod,
)
from .cli import (
    ngfx_activity_argv,
    result_to_dict,
    run_async,
    start_background,
)
from .config import (
    NGFX_INSTALL_ROOT_ENV,
    TOOL_DEFINITIONS,
    discover_install_roots,
    discover_sdk_versions,
    get_settings,
    reload_settings,
)
from .session import (
    CaptureSession,
    GpuTraceSession,
    get_sessions,
)

mcp = FastMCP(
    "nsight-graphics-mcp",
    instructions=(
        "MCP server for NVIDIA Nsight Graphics. Run ngfx_environment first to confirm the install. "
        "For headless capture, use ngfx_capture_launched (drives ngfx-capture.exe and produces a "
        ".ngfx-capture/.ngfx-gfxcap with a bundled replayer). For driving the full Nsight UI activities — "
        "Graphics Capture, GPU Trace Profiler, Generate C++ Capture, OpenGL Frame Debugger — use "
        "the ngfx_*_launched / ngfx_*_attached tools (they wrap ngfx.exe --activity). To analyse "
        "an existing capture: ngfx_open_capture, then ngfx_capture_summary, "
        "ngfx_capture_screenshot, ngfx_capture_objects. To replay or convert: ngfx_replay_run, "
        "ngfx_replay_bundle_extract. For in-app integration, use ngfx_sdk_reference to discover "
        "NGFX_* functions and ngfx_sdk_snippet to codegen a C++ integration stub."
    ),
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _resolve_capture(handle_or_path: str) -> tuple[CaptureSession | None, Path]:
    """Accept either an open capture handle or a path to a .ngfx-capture/.ngfx-gfxcap file."""
    sessions = get_sessions()
    try:
        sess = sessions.get_capture(handle_or_path)
        return sess, sess.path
    except KeyError:
        pass
    p = Path(handle_or_path).expanduser()
    if p.is_file():
        return None, p.resolve()
    raise FileNotFoundError(
        f"'{handle_or_path}' is neither an open capture handle nor a file path."
    )


def _resolve_gputrace(handle_or_path: str) -> tuple[GpuTraceSession | None, Path]:
    sessions = get_sessions()
    try:
        sess = sessions.get_gputrace(handle_or_path)
        return sess, sess.path
    except KeyError:
        pass
    p = Path(handle_or_path).expanduser()
    if p.is_file():
        return None, p.resolve()
    raise FileNotFoundError(
        f"'{handle_or_path}' is neither an open gputrace handle nor a file path."
    )


def _activity_flags(**kw: Any) -> dict[str, Any]:
    """Drop None / False / "" so render_flag omits them."""
    return {k: v for k, v in kw.items() if v not in (None, False, "")}


# ---------------------------------------------------------------------------
# environment + discovery
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_environment(reload: bool = False) -> dict[str, Any]:
    """Report the resolved Nsight Graphics install + per-tool paths + cache dirs.

    Call this first to confirm the MCP can find your installation. If the
    discovered version is wrong, set the ``NSIGHT_GRAPHICS_MCP_INSTALL_ROOT``
    env var on the MCP host (or one of the per-tool overrides), then
    ``ngfx_environment(reload=True)``.
    """
    if reload:
        reload_settings()
    s = get_settings()
    info = s.installation_info()
    info["env_var_for_override"] = NGFX_INSTALL_ROOT_ENV
    info["per_tool_env_vars"] = {k: v[0] for k, v in TOOL_DEFINITIONS.items()}
    info["version_dir_name"] = s.install_root.name if s.install_root else None
    return info


@mcp.tool()
async def ngfx_list_installs() -> dict[str, Any]:
    """List every Nsight Graphics install detected on this machine."""
    roots = discover_install_roots()
    out: list[dict[str, Any]] = []
    for r in roots:
        sdks = discover_sdk_versions(r)
        out.append(
            {
                "path": str(r),
                "version": r.name,
                "sdk_versions": [s.name for s in sdks],
            }
        )
    return {"installs": out, "current": str(get_settings().install_root) if get_settings().install_root else None}


@mcp.tool()
async def ngfx_deep_capture_capability_report(
    capture: str | None = None,
    install_root: str | None = None,
    probe_cli_help: bool = True,
) -> dict[str, Any]:
    """Report the deepest Nsight-only path available for shader/render debugging.

    This distinguishes the current Graphics Capture pipeline from legacy/
    optional Generate C++ Capture. It scans the selected Nsight install,
    detects available CLIs/plugins/SDK hooks, recognizes `.ngfx-capture`
    dumps, and returns a ranked tool chain for making a saved capture less
    shallow without relying on PIX or game-side instrumentation.
    """
    return deep_capture_mod.deep_capture_capability_report(
        capture=capture,
        install_root=install_root,
        probe_cli_help=probe_cli_help,
    )


@mcp.tool()
async def ngfx_version() -> dict[str, Any]:
    """Return the version reported by ``ngfx.exe --version``.

    Note: ngfx.exe's CLI parser returns a non-zero exit code for --version
    because it considers the command 'incomplete', but the version string is
    written to stdout. We surface stdout regardless of returncode.
    """
    s = get_settings()
    ngfx = s.require_tool("ngfx")
    res = await run_async([str(ngfx), "--version"], tool="ngfx", timeout=30)
    out = result_to_dict(res)
    # Extract the most useful single line from the stdout
    for line in res.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Version "):
            out["version"] = stripped
            break
    return out


@mcp.tool()
async def ngfx_list_activities() -> dict[str, Any]:
    """List the activity names that ``ngfx.exe`` accepts (parsed from --help)."""
    s = get_settings()
    ngfx = s.require_tool("ngfx")
    res = await run_async([str(ngfx), "--help"], tool="ngfx", timeout=30)
    activities: list[str] = []
    in_section = False
    for line in res.stdout.splitlines():
        if "--activity" in line:
            in_section = True
            continue
        if in_section:
            stripped = line.strip()
            if not stripped:
                # leading blank line is fine; second one ends the section
                if activities:
                    break
                continue
            if stripped.startswith("--") or "should be one of" in stripped:
                continue
            if line.startswith("  ") and not line.startswith("    "):
                # back out to top-level option list
                break
            activities.append(stripped)
    return {
        "activities": activities,
        "raw_help_tail": res.stdout[-1500:],
    }


# ---------------------------------------------------------------------------
# Graphics Capture activity (via ngfx.exe)
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_graphics_capture_launched(
    exe: str,
    args: str | None = None,
    working_dir: str | None = None,
    env_pairs: str | None = None,
    output_dir: str | None = None,
    frame_count: int | None = None,
    frame_index: int | None = None,
    elapsed_time_ms: int | None = None,
    hotkey_capture: bool = False,
    hud_position: str | None = None,
    non_portable: bool = False,
    hostname: str | None = None,
    project: str | None = None,
    no_timeout: bool = False,
    no_block_on_first_incompatibility: bool = True,
    verbose: bool = False,
    background: bool = False,
) -> dict[str, Any]:
    """Run ``ngfx --activity 'Graphics Capture' --exe <exe> ...``.

    Captures a frame (or N frames) into the configured Nsight project's output
    directory. Pass ``background=True`` to keep ngfx running so you can press
    the capture hotkey (F11 by default) in the running app — the call returns
    a launch handle you can poll with ``ngfx_launch_status``.

    Trigger semantics (one of):
      * ``frame_count`` — capture N frames starting at the next present.
      * ``frame_index`` — capture a specific 1-based frame index (must be > 1).
      * ``elapsed_time_ms`` — capture once after a countdown.
      * ``hotkey_capture`` — wait for the user to press the capture hotkey.

    ``no_block_on_first_incompatibility`` defaults to true so the capture
    proceeds through known benign warnings such as D3D11 device creation in
    D3D12 UE titles.
    """
    s = get_settings()
    flags = _activity_flags(
        frame_count=frame_count,
        frame_index=frame_index,
        elapsed_time=elapsed_time_ms,
        hotkey_capture=hotkey_capture,
        hud_position=hud_position,
        non_portable=non_portable,
        no_block_on_first_incompatibility=no_block_on_first_incompatibility,
    )
    argv = ngfx_activity_argv(
        s,
        activity="Graphics Capture",
        exe=exe,
        args=args,
        working_dir=working_dir,
        env_pairs=env_pairs,
        output_dir=output_dir,
        project=project,
        hostname=hostname,
        no_timeout=no_timeout,
        verbose=verbose,
        activity_flags=flags,
    )
    if background:
        bg = start_background("__tmp__", argv, tool="ngfx")
        sess = get_sessions().register_launch(
            bg, tool="ngfx", activity="Graphics Capture", exe=exe,
            notes="background Graphics Capture — press F11 in-app",
        )
        return {"mode": "background", **sess.summary()}
    res = await run_async(argv, tool="ngfx")
    return {"mode": "foreground", **result_to_dict(res)}


@mcp.tool()
async def ngfx_graphics_capture_attached(
    attach_pid: int,
    output_dir: str | None = None,
    frame_count: int | None = None,
    frame_index: int | None = None,
    elapsed_time_ms: int | None = None,
    hotkey_capture: bool = False,
    hud_position: str | None = None,
    non_portable: bool = False,
    hostname: str | None = None,
    project: str | None = None,
    no_timeout: bool = False,
    no_block_on_first_incompatibility: bool = True,
    verbose: bool = False,
    background: bool = False,
) -> dict[str, Any]:
    """Same as ``ngfx_graphics_capture_launched`` but attaches to a running PID."""
    s = get_settings()
    flags = _activity_flags(
        frame_count=frame_count,
        frame_index=frame_index,
        elapsed_time=elapsed_time_ms,
        hotkey_capture=hotkey_capture,
        hud_position=hud_position,
        non_portable=non_portable,
        no_block_on_first_incompatibility=no_block_on_first_incompatibility,
    )
    argv = ngfx_activity_argv(
        s,
        activity="Graphics Capture",
        attach_pid=attach_pid,
        output_dir=output_dir,
        project=project,
        hostname=hostname,
        no_timeout=no_timeout,
        verbose=verbose,
        activity_flags=flags,
    )
    if background:
        bg = start_background("__tmp__", argv, tool="ngfx")
        sess = get_sessions().register_launch(
            bg, tool="ngfx", activity="Graphics Capture",
            notes=f"attached to PID {attach_pid}",
        )
        return {"mode": "background", **sess.summary()}
    res = await run_async(argv, tool="ngfx")
    return {"mode": "foreground", **result_to_dict(res)}


# ---------------------------------------------------------------------------
# Headless Graphics Capture via ngfx-capture.exe
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_capture_launched(
    exe: str,
    output_file: str | None = None,
    output_dir: str | None = None,
    args: list[str] | None = None,
    env_pairs: list[str] | None = None,
    working_dir: str | None = None,
    frame_count: int | None = None,
    capture_frame: int | None = None,
    capture_countdown_ms: int | None = None,
    capture_hotkey: bool = False,
    delimiter: str | None = None,
    no_hud: bool = False,
    hud_position: str | None = None,
    new_console: bool = False,
    terminate_after_capture: bool = False,
    bundle_replayer: bool = True,
    non_portable: bool = False,
    compression: str | None = None,
    hvvm_mode: str | None = None,
    passthrough: bool = False,
    ignore_incompatible: bool = False,
    diagnostic_mode: bool = False,
    background: bool = False,
    timeout_sec: int | None = None,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Run ``ngfx-capture.exe`` directly (no Nsight UI required).

    This produces a self-contained ``.ngfx-gfxcap`` file. Setting
    ``bundle_replayer=True`` (default) packs the matching ngfx-replay into
    the capture so the file is replayable on any compatible machine.

    Capture trigger (mutually exclusive — exactly one of):
      * ``capture_hotkey`` — wait for F11 (default if none set).
      * ``capture_frame`` — capture a 1-based frame index (>1).
      * ``capture_countdown_ms`` — capture N ms after launch.

    ``compression`` ∈ {"high", "zstd", "lz4"} (lz4 is the default).
    ``delimiter``   ∈ {"present", "graphics-capture-api", "vk-frame-boundary-ext"}.
    ``hvvm_mode``   ∈ {"demote", "disable", "manual-tracking", "cpu-hash"}.
    """
    s = get_settings()
    exe_path = s.require_tool("ngfx_capture")
    argv: list[str] = [str(exe_path), "-e", exe]
    if working_dir:
        argv += ["--working-dir", working_dir]
    if args:
        argv += ["--args", *args]
    if env_pairs:
        argv += ["--env", *env_pairs]
    if no_hud:
        argv += ["--no-hud"]
    if hud_position:
        argv += ["--hud-position", hud_position]
    if new_console:
        argv += ["--new-console"]
    if terminate_after_capture:
        argv += ["--terminate-after-capture"]
    if output_file:
        argv += ["-o", output_file]
    if output_dir:
        argv += ["--output-dir", output_dir]
    if frame_count is not None:
        argv += ["-n", str(frame_count)]
    if bundle_replayer:
        argv += ["--bundle-replayer"]
    else:
        argv += ["--no-bundle-replayer"]
    if non_portable:
        argv += ["--non-portable"]
    if compression == "high":
        argv += ["--compression-level-high"]
    if compression == "zstd":
        argv += ["--compression-library-zstd"]
    if compression == "lz4":
        argv += ["--compression-library-lz4"]

    triggers = sum(1 for t in (capture_hotkey, capture_frame, capture_countdown_ms) if t)
    if triggers > 1:
        return {
            "ok": False,
            "error": "exactly one capture trigger may be specified: capture_hotkey | capture_frame | capture_countdown_ms",
        }
    if capture_hotkey:
        argv += ["--capture-hotkey"]
    elif capture_frame is not None:
        argv += ["--capture-frame", str(capture_frame)]
    elif capture_countdown_ms is not None:
        argv += ["--capture-countdown-timer", str(capture_countdown_ms)]

    if delimiter == "present":
        argv += ["--delimiter-present"]
    elif delimiter == "graphics-capture-api":
        argv += ["--delimiter-graphics-capture-api"]
    elif delimiter == "vk-frame-boundary-ext":
        argv += ["--delimiter-vk-frame-boundary-ext"]

    hvvm_flag = {
        "demote": "--hvvm-demote",
        "disable": "--hvvm-disable",
        "manual-tracking": "--hvvm-manual-tracking",
        "cpu-hash": "--hvvm-cpu-hash",
    }.get(hvvm_mode or "")
    if hvvm_flag:
        argv.append(hvvm_flag)

    if passthrough:
        argv += ["--passthrough"]
    if ignore_incompatible:
        argv += ["--ignore-incompatible"]
    if diagnostic_mode:
        argv += ["--diagnostic-mode"]
    if extra_args:
        argv += list(extra_args)

    if background:
        bg = start_background("__tmp__", argv, tool="ngfx-capture")
        sess = get_sessions().register_launch(
            bg, tool="ngfx-capture", exe=exe,
            notes="headless capture — press F11 in-app to trigger",
        )
        return {"mode": "background", **sess.summary()}
    res = await run_async(argv, tool="ngfx-capture", timeout=timeout_sec)
    out = result_to_dict(res)
    # Heuristically resolve produced capture file
    if output_file:
        p = Path(output_file)
        if not p.is_absolute() and output_dir:
            p = Path(output_dir) / output_file
        if p.is_file():
            out["capture_path"] = str(p.resolve())
    return out


@mcp.tool()
async def ngfx_capture_recapture(
    input_capture: str,
    output_file: str,
    compression: str | None = "high",
    recompress_threshold: int | None = None,
    timeout_sec: int | None = None,
) -> dict[str, Any]:
    """Recapture / recompress an existing ``.ngfx-gfxcap`` with the current format.

    Useful for shrinking older captures or migrating them to a newer format.
    """
    s = get_settings()
    argv: list[str] = [str(s.require_tool("ngfx_capture")), "--recapture", "-o", output_file]
    if compression == "high":
        argv += ["--compression-level-high"]
    elif compression == "zstd":
        argv += ["--compression-library-zstd"]
    elif compression == "lz4":
        argv += ["--compression-library-lz4"]
    if recompress_threshold:
        argv += ["--recompress-small-data-threshold", str(recompress_threshold)]
    argv.append(input_capture)
    res = await run_async(argv, tool="ngfx-capture", timeout=timeout_sec)
    return result_to_dict(res)


@mcp.tool()
async def ngfx_capture_recompress(
    input_capture: str,
    output_file: str,
    compression: str = "high",
    recompress_threshold: int | None = None,
    timeout_sec: int | None = None,
) -> dict[str, Any]:
    """Recompress an existing capture without re-running the application."""
    s = get_settings()
    argv: list[str] = [str(s.require_tool("ngfx_capture")), "--recompress", "-o", output_file]
    if compression == "high":
        argv += ["--compression-level-high"]
    elif compression == "zstd":
        argv += ["--compression-library-zstd"]
    elif compression == "lz4":
        argv += ["--compression-library-lz4"]
    if recompress_threshold:
        argv += ["--recompress-small-data-threshold", str(recompress_threshold)]
    argv.append(input_capture)
    res = await run_async(argv, tool="ngfx-capture", timeout=timeout_sec)
    return result_to_dict(res)


# ---------------------------------------------------------------------------
# Capture session management + metadata
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_open_capture(path: str) -> dict[str, Any]:
    """Register a capture file path as a session handle.

    Returns a handle (``cap_<stem>_<rand>``) that subsequent tools accept in
    place of the path — keeps later prompts shorter and lets the MCP cache
    per-capture metadata in memory.
    """
    sessions = get_sessions()
    sess = sessions.open_capture(Path(path))
    return sess.summary()


@mcp.tool()
async def ngfx_list_captures() -> dict[str, Any]:
    """List all opened capture sessions."""
    return {"captures": [c.summary() for c in get_sessions().list_captures()]}


@mcp.tool()
async def ngfx_close_capture(handle: str) -> dict[str, Any]:
    closed = get_sessions().close_capture(handle)
    return {"closed": closed, "handle": handle}


@mcp.tool()
async def ngfx_capture_summary(capture: str, refresh: bool = False) -> dict[str, Any]:
    """High-level summary of a capture (runs ``ngfx-replay --metadata``).

    Caches the parsed result in the capture session, keyed by mtime — pass
    ``refresh=True`` to force re-parse.
    """
    sess, path = _resolve_capture(capture)
    mtime = path.stat().st_mtime
    if sess and not refresh and sess.metadata is not None and sess.metadata_mtime == mtime:
        return {"cached": True, "path": str(path), **sess.metadata}
    parsed = await capture_info.capture_metadata(path)
    if sess is not None:
        sess.metadata = parsed
        sess.metadata_mtime = mtime
    return {"cached": False, "path": str(path), **parsed}


@mcp.tool()
async def ngfx_capture_objects(capture: str) -> dict[str, Any]:
    """Run ``ngfx-replay --metadata-objects``: full JSON list of every API
    object recorded in the capture (devices, queues, pipelines, resources...).

    The output can be very large; prefer ``ngfx_capture_summary`` first.
    """
    _, path = _resolve_capture(capture)
    return await capture_info.capture_metadata_objects(path)


@mcp.tool()
async def ngfx_capture_functions(capture: str, max_lines: int = 5000) -> dict[str, Any]:
    """Dump the recorded function stream (``ngfx-replay --metadata-functions``).

    Truncated to ``max_lines`` since the full stream can be huge.
    """
    _, path = _resolve_capture(capture)
    return await capture_info.capture_metadata_functions(path, max_lines=max_lines)


@mcp.tool()
async def ngfx_capture_logs(capture: str, errors_only: bool = False) -> dict[str, Any]:
    """Dump captured application/driver log messages embedded in the capture."""
    _, path = _resolve_capture(capture)
    return await capture_info.capture_metadata_logs(path, errors_only=errors_only)


@mcp.tool()
async def ngfx_capture_screenshot(capture: str, output_image: str) -> dict[str, Any]:
    """Write the embedded final-present screenshot to a file.

    Output format is chosen from the extension: .png / .tga / .bmp / .jpg.
    """
    _, path = _resolve_capture(capture)
    return await capture_info.capture_metadata_screenshot(path, Path(output_image))


# ---------------------------------------------------------------------------
# Replay (ngfx-replay.exe)
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_replay_run(
    capture: str,
    loop_count: int | None = None,
    perf_report_dir: str | None = None,
    fixed_timestamps: bool = False,
    present_mode: str | None = None,
    vsync_mode: str | None = None,
    device_name: str | None = None,
    device_vendor: str | None = None,
    device_index: int | None = None,
    no_present_blit: bool = False,
    no_reset: bool = False,
    reset_only: list[str] | None = None,
    quiet: bool = True,
    timeout_sec: int | None = None,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Replay a capture with ``ngfx-replay.exe`` and return its output.

    Useful for headless verification and for collecting GPU-time perf data
    (via ``perf_report_dir``) without opening the Nsight UI.

    ``present_mode`` ∈ {"wb", "app", "hidden"}.
    ``vsync_mode``   ∈ {"app", "off", "on"}.
    ``reset_only``   subset of {"compute","mappable","nonmappable","raster"}.
    """
    _sess, path = _resolve_capture(capture)
    s = get_settings()
    argv: list[str] = [str(s.require_tool("ngfx_replay"))]
    if quiet:
        argv.append("--quiet")
    argv.append("--no-block-on-incompatibility")
    if loop_count is not None:
        argv += ["-n", str(loop_count)]
    if perf_report_dir:
        argv += ["--perf-report-dir", perf_report_dir]
    if fixed_timestamps:
        argv.append("--fixed-timestamps")
    if present_mode == "wb":
        argv.append("--present-wb")
    elif present_mode == "app":
        argv.append("--present-app")
    elif present_mode == "hidden":
        argv.append("--present-hidden")
    if vsync_mode == "off":
        argv.append("--vsync-off")
    elif vsync_mode == "on":
        argv.append("--vsync-on")
    elif vsync_mode == "app":
        argv.append("--vsync-app")
    if device_name:
        argv += ["--device-name", device_name]
    if device_vendor:
        argv += ["--device-vendor", device_vendor]
    if device_index is not None:
        argv += ["--device-index", str(device_index)]
    if no_present_blit:
        argv.append("--no-present-blit")
    if no_reset:
        argv.append("--no-reset")
    if reset_only:
        argv += ["--reset-only", *reset_only]
    if extra_args:
        argv += list(extra_args)
    argv.append(str(path))
    res = await run_async(argv, tool="ngfx-replay", timeout=timeout_sec)
    return result_to_dict(res)


@mcp.tool()
async def ngfx_replay_bundle_extract(
    capture: str, extract_dir: str, no_rename: bool = False,
) -> dict[str, Any]:
    """Extract a bundled-replayer capture's contents to a directory without
    running the replay.

    Internally runs ``ngfx-replay --bundle-replayer --bundle-replayer-extract-only
    --bundle-replayer-dir <dir>``. Useful for inspection or for sharing the
    replayer separately.
    """
    _, path = _resolve_capture(capture)
    s = get_settings()
    argv: list[str] = [
        str(s.require_tool("ngfx_replay")),
        "--bundle-replayer",
        "--bundle-replayer-dir",
        extract_dir,
        "--bundle-replayer-extract-only",
        "--quiet",
    ]
    if no_rename:
        argv.append("--bundle-replayer-no-rename")
    argv.append(str(path))
    res = await run_async(argv, tool="ngfx-replay")
    return {**result_to_dict(res), "extract_dir": extract_dir}


@mcp.tool()
async def ngfx_replay_metadata(capture: str) -> dict[str, Any]:
    """Direct passthrough to ``ngfx-replay --metadata`` (parsed key/value).

    For caching, prefer ``ngfx_capture_summary``.
    """
    _, path = _resolve_capture(capture)
    return await capture_info.capture_metadata(path)


# ---------------------------------------------------------------------------
# GPU Trace Profiler
# ---------------------------------------------------------------------------


GPU_TRACE_ARCHS = (
    "Turing",
    "Ampere GA10x",
    "Orin GA10B",
    "Ada",
    "Thor GB10B",
    "Blackwell GB20x",
    "T25x GB20x",
)


@mcp.tool()
async def ngfx_gputrace_archs() -> dict[str, Any]:
    """Return the list of GPU architectures accepted by ``--architecture``."""
    return {"architectures": list(GPU_TRACE_ARCHS)}


@mcp.tool()
async def ngfx_gputrace_launched(
    exe: str,
    args: str | None = None,
    working_dir: str | None = None,
    env_pairs: str | None = None,
    output_dir: str | None = None,
    project: str | None = None,
    hostname: str | None = None,
    no_timeout: bool = False,
    verbose: bool = False,
    # Trace start
    start_after_frames: int | None = None,
    start_after_submits: int | None = None,
    start_after_ms: int | None = None,
    start_after_hotkey: bool = False,
    start_with_ngfx_sdk: bool = False,
    start_on_replay_begin: bool = False,
    # Trace stop
    max_duration_ms: int | None = None,
    limit_to_frames: int | None = None,
    limit_to_submits: int | None = None,
    stop_with_ngfx_sdk: bool = False,
    stop_on_replay_end: bool = False,
    # Metric set selection
    architecture: str | None = None,
    metric_set_name: str | None = None,
    metric_set_id: int | None = None,
    multi_pass_metrics: bool = False,
    per_arch_config_path: str | None = None,
    # Sampling / collection
    real_time_shader_profiler: bool = False,
    pc_samples_per_pm_interval_per_sm: int | None = None,
    pm_bandwidth_limit: int | None = None,
    per_line_active_threads_per_warp: bool = False,
    time_every_action: bool = False,
    collect_screenshot: bool = True,
    disable_collect_shader_pipelines: bool = False,
    disable_collect_external_shader_debug_info: bool = False,
    disable_trace_shader_bindings: bool = False,
    auto_export: bool = False,
    # GPU clocks
    set_gpu_clocks: str | None = None,
    # Misc
    allow_tracing_replay_reset: int | None = None,
    keep_going: bool = False,
    trace_timeout_sec: int | None = None,
    hes_enabled: int | None = None,
    background: bool = False,
) -> dict[str, Any]:
    """Run ``ngfx --activity 'GPU Trace Profiler' --exe <exe> ...``.

    Mutually-exclusive start triggers: ``start_after_frames``,
    ``start_after_submits``, ``start_after_ms``, ``start_after_hotkey``,
    ``start_with_ngfx_sdk``, ``start_on_replay_begin``.

    Mutually-exclusive stop triggers: ``limit_to_frames``,
    ``limit_to_submits``, ``stop_with_ngfx_sdk``, ``stop_on_replay_end``
    (otherwise stops at ``max_duration_ms``).

    ``set_gpu_clocks`` ∈ {"unaltered", "base", "boost"} (default: base).

    Setting ``background=True`` returns a launch handle so you can press the
    hotkey to start tracing in the running game.
    """
    starts = sum(
        1
        for f in (
            start_after_frames is not None,
            start_after_submits is not None,
            start_after_ms is not None,
            start_after_hotkey,
            start_with_ngfx_sdk,
            start_on_replay_begin,
        )
        if f
    )
    if starts > 1:
        return {
            "ok": False,
            "error": "at most one of start_after_frames/submits/ms/hotkey/ngfx_sdk/replay_begin may be set",
        }
    stops = sum(
        1
        for f in (
            limit_to_frames is not None,
            limit_to_submits is not None,
            stop_with_ngfx_sdk,
            stop_on_replay_end,
        )
        if f
    )
    if stops > 1:
        return {
            "ok": False,
            "error": "at most one of limit_to_frames/submits/ngfx_sdk/replay_end may be set",
        }

    flags = _activity_flags(
        start_after_frames=start_after_frames,
        start_after_submits=start_after_submits,
        start_after_ms=start_after_ms,
        start_after_hotkey=start_after_hotkey,
        start_with_ngfx_sdk=start_with_ngfx_sdk,
        start_on_replay_begin=start_on_replay_begin,
        max_duration_ms=max_duration_ms,
        limit_to_frames=limit_to_frames,
        limit_to_submits=limit_to_submits,
        stop_with_ngfx_sdk=stop_with_ngfx_sdk,
        stop_on_replay_end=stop_on_replay_end,
        architecture=architecture,
        metric_set_name=metric_set_name,
        metric_set_id=metric_set_id,
        multi_pass_metrics=multi_pass_metrics,
        per_arch_config_path=per_arch_config_path,
        real_time_shader_profiler=real_time_shader_profiler,
        pc_samples_per_pm_interval_per_sm=pc_samples_per_pm_interval_per_sm,
        pm_bandwidth_limit=pm_bandwidth_limit,
        per_line_active_threads_per_warp=per_line_active_threads_per_warp,
        time_every_action=time_every_action,
        collect_screenshot=1 if collect_screenshot else 0,
        disable_collect_shader_pipelines=disable_collect_shader_pipelines,
        disable_collect_external_shader_debug_info=disable_collect_external_shader_debug_info,
        disable_trace_shader_bindings=disable_trace_shader_bindings,
        auto_export=auto_export,
        set_gpu_clocks=set_gpu_clocks,
        allow_tracing_replay_reset=allow_tracing_replay_reset,
        keep_going=keep_going,
        trace_timeout=trace_timeout_sec,
        hes_enabled=hes_enabled,
    )

    s = get_settings()
    argv = ngfx_activity_argv(
        s,
        activity="GPU Trace Profiler",
        exe=exe,
        args=args,
        working_dir=working_dir,
        env_pairs=env_pairs,
        output_dir=output_dir,
        project=project,
        hostname=hostname,
        no_timeout=no_timeout,
        verbose=verbose,
        activity_flags=flags,
    )
    if background:
        bg = start_background("__tmp__", argv, tool="ngfx")
        sess = get_sessions().register_launch(
            bg, tool="ngfx", activity="GPU Trace Profiler", exe=exe,
            notes="background GPU Trace — drive via hotkey or NGFX SDK",
        )
        return {"mode": "background", **sess.summary()}
    res = await run_async(argv, tool="ngfx")
    return {"mode": "foreground", **result_to_dict(res)}


@mcp.tool()
async def ngfx_gputrace_attached(
    attach_pid: int,
    output_dir: str | None = None,
    project: str | None = None,
    hostname: str | None = None,
    max_duration_ms: int | None = None,
    limit_to_frames: int | None = None,
    limit_to_submits: int | None = None,
    architecture: str | None = None,
    metric_set_name: str | None = None,
    metric_set_id: int | None = None,
    multi_pass_metrics: bool = False,
    real_time_shader_profiler: bool = False,
    start_after_hotkey: bool = True,
    auto_export: bool = False,
    set_gpu_clocks: str | None = None,
    background: bool = True,
) -> dict[str, Any]:
    """Attach GPU Trace to a running process by PID. Defaults to hotkey-driven."""
    s = get_settings()
    flags = _activity_flags(
        start_after_hotkey=start_after_hotkey,
        max_duration_ms=max_duration_ms,
        limit_to_frames=limit_to_frames,
        limit_to_submits=limit_to_submits,
        architecture=architecture,
        metric_set_name=metric_set_name,
        metric_set_id=metric_set_id,
        multi_pass_metrics=multi_pass_metrics,
        real_time_shader_profiler=real_time_shader_profiler,
        auto_export=auto_export,
        set_gpu_clocks=set_gpu_clocks,
    )
    argv = ngfx_activity_argv(
        s,
        activity="GPU Trace Profiler",
        attach_pid=attach_pid,
        output_dir=output_dir,
        project=project,
        hostname=hostname,
        activity_flags=flags,
    )
    if background:
        bg = start_background("__tmp__", argv, tool="ngfx")
        sess = get_sessions().register_launch(
            bg, tool="ngfx", activity="GPU Trace Profiler",
            notes=f"attached to PID {attach_pid} — drive via hotkey",
        )
        return {"mode": "background", **sess.summary()}
    res = await run_async(argv, tool="ngfx")
    return {"mode": "foreground", **result_to_dict(res)}


@mcp.tool()
async def ngfx_gputrace_capture_replay(
    capture: str,
    output_dir: str | None = None,
    architecture: str | None = None,
    metric_set_name: str | None = None,
    metric_set_id: int | None = None,
    real_time_shader_profiler: bool = True,
    per_line_active_threads_per_warp: bool = False,
    multi_pass_metrics: bool = False,
    auto_export: bool = True,
    collect_screenshot: bool = True,
    loop_count: int = 1,
    present_hidden: bool = True,
    stop_on_replay_end: bool = True,
    max_duration_ms: int | None = None,
    no_block_on_incompatibility: bool = True,
    enable_dx12_application_specific_driver_state: bool = True,
    replay_extra_args: list[str] | None = None,
    allow_tracing_replay_reset: int = 0,
    no_timeout: bool = True,
    background: bool = False,
) -> dict[str, Any]:
    """Run GPU Trace Profiler against a saved Graphics Capture replay.

    This is the current Nsight replacement path for getting shader pipeline /
    source / binding evidence from a saved D3D12/Vulkan dump when C++ Capture
    is unavailable or too private. Internally this launches
    ``ngfx --activity 'GPU Trace Profiler'`` with ``ngfx-replay.exe`` as the
    target and uses ``--start-on-replay-begin`` / ``--stop-on-replay-end``.
    """
    _, path = _resolve_capture(capture)
    s = get_settings()
    replay = s.require_tool("ngfx_replay")
    out = output_dir or str(events_mod._cache_root_for(path) / "gputrace_replay")
    Path(out).mkdir(parents=True, exist_ok=True)
    replay_args: list[str] = []
    if no_block_on_incompatibility:
        replay_args.append("--no-block-on-incompatibility")
    if enable_dx12_application_specific_driver_state:
        replay_args.append("--enable-dx12-application-specific-driver-state")
    if present_hidden:
        replay_args.append("--present-hidden")
    if loop_count > 0:
        replay_args.extend(["-n", str(loop_count)])
    if replay_extra_args:
        replay_args.extend(replay_extra_args)
    replay_args.append(str(path))
    return await ngfx_gputrace_launched(
        exe=str(replay),
        args=subprocess.list2cmdline(replay_args),
        working_dir=str(path.parent),
        output_dir=out,
        no_timeout=no_timeout,
        start_on_replay_begin=True,
        stop_on_replay_end=stop_on_replay_end,
        max_duration_ms=max_duration_ms,
        architecture=architecture,
        metric_set_name=metric_set_name,
        metric_set_id=metric_set_id,
        real_time_shader_profiler=real_time_shader_profiler,
        per_line_active_threads_per_warp=per_line_active_threads_per_warp,
        multi_pass_metrics=multi_pass_metrics,
        auto_export=auto_export,
        collect_screenshot=collect_screenshot,
        disable_collect_shader_pipelines=False,
        disable_trace_shader_bindings=False,
        allow_tracing_replay_reset=allow_tracing_replay_reset,
        background=background,
    )


# ---------------------------------------------------------------------------
# GPU Trace report session management
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_open_gputrace(path: str) -> dict[str, Any]:
    """Register a .nsight-gputrace path as a session handle."""
    sess = get_sessions().open_gputrace(Path(path))
    return sess.summary()


@mcp.tool()
async def ngfx_list_gputraces() -> dict[str, Any]:
    return {"gputraces": [t.summary() for t in get_sessions().list_gputraces()]}


@mcp.tool()
async def ngfx_close_gputrace(handle: str) -> dict[str, Any]:
    closed = get_sessions().close_gputrace(handle)
    return {"closed": closed, "handle": handle}


@mcp.tool()
async def ngfx_gputrace_inspect(gputrace: str) -> dict[str, Any]:
    """Best-effort inspection of a ``.nsight-gputrace`` file.

    Modern GPU Trace reports are zip-like archives. We peek at the container
    structure (file listing + sizes) without unpacking — useful for confirming
    a trace finished collecting and rough sizing.
    """
    _, path = _resolve_gputrace(gputrace)
    out: dict[str, Any] = {"path": str(path), "size_bytes": path.stat().st_size}
    import zipfile

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            members = [
                {"name": zi.filename, "size": zi.file_size, "compressed": zi.compress_size}
                for zi in zf.infolist()
            ]
        out["container"] = "zip"
        out["member_count"] = len(members)
        out["members"] = members[:200]
        out["members_truncated"] = len(members) > 200
    else:
        # Read leading bytes to identify
        with path.open("rb") as fh:
            head = fh.read(64)
        out["container"] = "unknown"
        out["head_hex"] = head.hex()
    return out


# ---------------------------------------------------------------------------
# Generate C++ Capture activity
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_cpp_capture_launched(
    exe: str,
    args: str | None = None,
    working_dir: str | None = None,
    env_pairs: str | None = None,
    output_dir: str | None = None,
    wait_frames: int | None = None,
    wait_seconds: int | None = None,
    wait_hotkey: bool = False,
    enable_vksc: bool = False,
    project: str | None = None,
    hostname: str | None = None,
    no_timeout: bool = False,
    verbose: bool = False,
    background: bool = False,
) -> dict[str, Any]:
    """Run ``ngfx --activity 'Generate C++ Capture' ...``.

    Generates a self-contained C++ project (.sln + sources) that reproduces
    the captured frame — useful for sharing a repro case or for compiling /
    iterating against the API stream.

    Wait triggers (one of): ``wait_frames`` / ``wait_seconds`` / ``wait_hotkey``.
    """
    waits = sum(1 for f in (wait_frames is not None, wait_seconds is not None, wait_hotkey) if f)
    if waits > 1:
        return {"ok": False, "error": "at most one of wait_frames / wait_seconds / wait_hotkey may be set"}
    s = get_settings()
    flags = _activity_flags(
        wait_frames=wait_frames,
        wait_seconds=wait_seconds,
        wait_hotkey=wait_hotkey,
        enable_vksc=enable_vksc,
    )
    argv = ngfx_activity_argv(
        s,
        activity="Generate C++ Capture",
        exe=exe,
        args=args,
        working_dir=working_dir,
        env_pairs=env_pairs,
        output_dir=output_dir,
        project=project,
        hostname=hostname,
        no_timeout=no_timeout,
        verbose=verbose,
        activity_flags=flags,
    )
    if background:
        bg = start_background("__tmp__", argv, tool="ngfx")
        sess = get_sessions().register_launch(
            bg, tool="ngfx", activity="Generate C++ Capture", exe=exe,
            notes="background C++ Capture — drive via hotkey",
        )
        return {"mode": "background", **sess.summary()}
    res = await run_async(argv, tool="ngfx")
    out = {"mode": "foreground", **result_to_dict(res)}
    classification = cpp_capture.classify_generate_cpp_capture_output(
        stdout=res.stdout,
        stderr=res.stderr,
        returncode=res.returncode,
    )
    if classification is not None:
        out["cpp_capture_classification"] = classification
    return out


# ---------------------------------------------------------------------------
# OpenGL Frame Debugger
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_framedebugger_launched(
    exe: str,
    args: str | None = None,
    working_dir: str | None = None,
    env_pairs: str | None = None,
    output_dir: str | None = None,
    wait_frames: int | None = None,
    wait_seconds: int | None = None,
    wait_hotkey: bool = False,
    enable_vksc: bool = False,
    project: str | None = None,
    hostname: str | None = None,
    no_timeout: bool = False,
    verbose: bool = False,
    background: bool = False,
) -> dict[str, Any]:
    """Run ``ngfx --activity 'OpenGL Frame Debugger' ...``.

    For OpenGL applications. Capture is triggered by CTRL+Z and spacebar by
    default (``wait_hotkey=True``).
    """
    waits = sum(1 for f in (wait_frames is not None, wait_seconds is not None, wait_hotkey) if f)
    if waits > 1:
        return {"ok": False, "error": "at most one of wait_frames / wait_seconds / wait_hotkey"}
    s = get_settings()
    flags = _activity_flags(
        wait_frames=wait_frames,
        wait_seconds=wait_seconds,
        wait_hotkey=wait_hotkey,
        enable_vksc=enable_vksc,
    )
    argv = ngfx_activity_argv(
        s,
        activity="OpenGL Frame Debugger",
        exe=exe,
        args=args,
        working_dir=working_dir,
        env_pairs=env_pairs,
        output_dir=output_dir,
        project=project,
        hostname=hostname,
        no_timeout=no_timeout,
        verbose=verbose,
        activity_flags=flags,
    )
    if background:
        bg = start_background("__tmp__", argv, tool="ngfx")
        sess = get_sessions().register_launch(
            bg, tool="ngfx", activity="OpenGL Frame Debugger", exe=exe,
        )
        return {"mode": "background", **sess.summary()}
    res = await run_async(argv, tool="ngfx")
    return {"mode": "foreground", **result_to_dict(res)}


# ---------------------------------------------------------------------------
# Launch / background process management
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_launch_status(handle: str, tail_lines: int = 100) -> dict[str, Any]:
    """Status + recent stdout/stderr of a background launch."""
    sess = get_sessions().get_launch(handle)
    stdout_tail = sess.bg.recent_stdout(tail_lines)
    stderr_tail = sess.bg.recent_stderr(tail_lines)
    out = {
        **sess.summary(),
        "stdout_tail": stdout_tail,
        "stderr_tail": stderr_tail,
    }
    if sess.activity == "Generate C++ Capture":
        classification = cpp_capture.classify_generate_cpp_capture_output(
            stdout=stdout_tail,
            stderr=stderr_tail,
            returncode=sess.bg.returncode(),
        )
        if classification is not None:
            out["cpp_capture_classification"] = classification
    return out


@mcp.tool()
async def ngfx_list_launches() -> dict[str, Any]:
    sessions = get_sessions()
    reaped = sessions.reap()
    return {
        "launches": [s.summary() for s in sessions.list_launches()],
        "reaped": reaped,
    }


@mcp.tool()
async def ngfx_launch_stop(handle: str, timeout_sec: float = 5.0) -> dict[str, Any]:
    sessions = get_sessions()
    rc = sessions.stop_launch(handle, timeout=timeout_sec)
    return {"handle": handle, "returncode": rc}


# ---------------------------------------------------------------------------
# Remote monitor / RPC
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_remote_monitor_start(
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Start ``nv-nsight-remote-monitor.exe`` headless on this machine so a
    remote Nsight UI can connect. Returns a launch handle — call
    ``ngfx_launch_stop`` to terminate it.
    """
    s = get_settings()
    exe = s.require_tool("remote_monitor")
    argv = [str(exe), *(list(extra_args) if extra_args else [])]
    bg = start_background("__tmp__", argv, tool="nv-nsight-remote-monitor")
    sess = get_sessions().register_launch(
        bg, tool="nv-nsight-remote-monitor", notes="headless remote monitor"
    )
    return sess.summary()


@mcp.tool()
async def ngfx_rpc_start(
    transport: str = "named-pipe",
    pipename: str | None = None,
    base_port: int | None = None,
    port_range_begin: int | None = None,
    port_range_end: int | None = None,
    no_crash_reporting: bool = False,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Start ``ngfx-rpc.exe`` (the replayer UI server) headless.

    ``transport`` ∈ {"named-pipe", "domain-socket", "TCP"}.
    """
    s = get_settings()
    exe = s.require_tool("ngfx_rpc")
    argv: list[str] = [str(exe), "--transport", transport]
    if pipename:
        argv += ["--pipename", pipename]
    if base_port is not None:
        argv += ["--base-port", str(base_port)]
    if port_range_begin is not None:
        argv += ["--port-range-begin", str(port_range_begin)]
    if port_range_end is not None:
        argv += ["--port-range-end", str(port_range_end)]
    if no_crash_reporting:
        argv += ["--no-crash-reporting"]
    if extra_args:
        argv += list(extra_args)
    bg = start_background("__tmp__", argv, tool="ngfx-rpc")
    sess = get_sessions().register_launch(
        bg, tool="ngfx-rpc", notes=f"RPC server, transport={transport}"
    )
    return sess.summary()


@mcp.tool()
async def ngfx_rpc_protocol_info() -> dict[str, Any]:
    """Return everything we know about the ``ngfx-rpc.exe`` custom wire
    protocol — handy as a self-describing reference for callers writing
    their own clients. The full derivation lives in
    ``docs/RPC_PROTOCOL.md`` (in this repo).

    The transport-layer 8-byte framing and the 24-byte per-message
    ``MessageHeader`` wire layout are decoded. The remaining live gap is
    BinaryReplay's private namespace/session/slot binding.
    """
    from . import rpc_client as rc

    try:
        reg = proto_descriptors.get_registry()
        # build a list of category enums + their methods straight from
        # the embedded protos
        method_enums: dict[str, list[dict[str, int]]] = {}
        for fname, fd in reg.files.items():
            for et in fd.enum_type:
                if "Method" in et.name:
                    method_enums[f"{fname}::{et.name}"] = [
                        {"name": v.name, "number": v.number} for v in et.value
                    ]
    except Exception as e:
        method_enums = {"error": str(e)}

    return {
        "transport_frame_header": {
            "size_bytes": rc.FRAME_HEADER_SIZE,
            "layout": "[u8 magic0][u8 magic1][u8 channelId][u8 flag][u32 size_BE]",
            "magic_bytes": [rc.FRAME_MAGIC_0, rc.FRAME_MAGIC_1],
            "endianness": "size is big-endian (network byte order); other "
                          "fields are byte-stream order",
            "verified": True,
        },
        "dispatch": {
            "key": "(category u32, method u32)",
            "system_category_id_pins": {
                "source": "ngfx-rpc.exe::SystemCategories.proto",
                "Diagnostics": rc.CATEGORY_DIAGNOSTICS,
                "SystemInfo": rc.CATEGORY_SYSTEM_INFO,
                "Discovery": rc.CATEGORY_DISCOVERY,
                "Handshake": rc.CATEGORY_HANDSHAKE,
                "DeviceInfo": rc.CATEGORY_DEVICE_INFO,
                "Connection": rc.CATEGORY_CONNECTION,
                "LocalDiscovery": rc.CATEGORY_LOCAL_DISCOVERY,
            },
            "pylon_replay_category_id_pins": {
                "source": "ngfx-rpc.exe::PylonUi.proto",
                "BinaryReplay": rc.CATEGORY_BINARY_REPLAY,
                "remaining_gap": (
                    "BinaryReplay's numeric category is pinned in the Pylon namespace. "
                    "The live UI still performs a private namespace/session/slot binding "
                    "before these requests are accepted."
                ),
            },
            "method_enums_in_proto": method_enums,
        },
        "message_header_in_mem": {
            "size_bytes": rc.MESSAGE_HEADER_IN_MEM_SIZE,
            "fields": [
                {"offset": 2, "type": "u8", "name": "is_valid"},
                {"offset": 32, "type": "u32", "name": "category"},
                {"offset": 36, "type": "u32", "name": "method"},
                {"offset": 48, "type": "u64", "name": "ticket_id"},
                {"offset": 56, "type": "u32", "name": "sertype"},
            ],
            "wire_layout_implemented": (
                "24 bytes: u64 ticket_id BE, u64 request_id BE, u32 seq BE, "
                "u8 category, u8 method, u8 slot, u8 flags"
            ),
            "wire_layout_verified": True,
            "note": "see docs/RPC_PROTOCOL.md for the IDA derivation of "
                    "the 24-byte MessageHeader wire encoding.",
        },
        "session_model": {
            "tcp": "single-shot: server exits when the client TCP "
                   "session closes",
            "named_pipe": "auto-rearms: server stays alive across "
                          "consecutive clients (string evidence: "
                          "'AsioFeatureServer received session closed. "
                          "Setup named pipe again.')",
        },
        "auth_env_vars": [
            "NV_TPS_LAUNCH_TOKEN",
            "NV_TPS_LAUNCH_UUID",
            "NV_TPS_LAUNCH_ENV_HASH",
        ],
    }


@mcp.tool()
async def ngfx_rpc_transport_connect(
    host: str = "127.0.0.1",
    port: int = 0,
    pid: int | None = None,
    timeout_sec: float = 5.0,
) -> dict[str, Any]:
    """Open one TCP transport connection to a running ``ngfx-rpc.exe`` and
    immediately close it. Useful as a smoke test: it verifies the server
    is reachable and that the 8-byte frame magic checks out.

    Provide either ``port`` directly, or ``pid`` (the tool will enumerate
    the listening TCP port for that pid).
    """
    from . import rpc_client as rc

    if pid is not None and port == 0:
        try:
            port = rc.find_listening_port(int(pid), timeout=timeout_sec)
        except TimeoutError as e:
            return {"ok": False, "error": str(e), "pid": pid}

    if port <= 0:
        return {"ok": False, "error": "neither port nor pid provided"}

    try:
        with rc.RpcTransport.connect(host, port, timeout=timeout_sec) as _t:
            pass
        return {"ok": True, "host": host, "port": port,
                "note": "connection established; transport-layer ready"}
    except Exception as e:
        return {"ok": False, "host": host, "port": port,
                "error": f"{type(e).__name__}: {e}"}


@mcp.tool()
async def ngfx_rpc_send_raw_frame(
    host: str,
    port: int,
    channel: int = 0,
    body_hex: str = "",
    expect_reply: bool = True,
    timeout_sec: float = 3.0,
) -> dict[str, Any]:
    """Low-level escape hatch: send one transport frame and (optionally)
    await one reply frame. Useful for protocol RE work.

    ``body_hex`` is the frame body as a hex string (no ``0x`` prefix,
    spaces allowed).
    """
    from . import rpc_client as rc

    body = bytes.fromhex(body_hex.replace(" ", ""))
    try:
        with rc.RpcTransport.connect(host, port, timeout=timeout_sec) as t:
            t.send_frame(rc.TransportFrame(channel=channel, body=body))
            sent = {"bytes_sent": rc.FRAME_HEADER_SIZE + len(body)}
            if not expect_reply:
                return {"ok": True, **sent, "reply": None}
            reply = t.recv_frame()
            return {
                "ok": True,
                **sent,
                "reply": {
                    "channel": reply.channel,
                    "flag": reply.flag,
                    "body_size": len(reply.body),
                    "body_hex": reply.body.hex(),
                    "body_preview_ascii": "".join(
                        chr(b) if 32 <= b < 127 else "." for b in reply.body[:128]
                    ),
                },
            }
    except Exception as e:
        return {"ok": False, "host": host, "port": port,
                "error": f"{type(e).__name__}: {e}"}


def _resolve_rpc_port(host: str, port: int, pid: int | None, timeout_sec: float) -> tuple[bool, dict[str, Any]]:
    from . import rpc_client as rc

    if pid is not None and port == 0:
        try:
            port = rc.find_listening_port(int(pid), timeout=timeout_sec)
        except TimeoutError as exc:
            return False, {"ok": False, "error": str(exc), "pid": pid}
    if port <= 0:
        return False, {"ok": False, "error": "neither port nor pid provided"}
    return True, {"host": host, "port": port}


def _resolve_rpc_endpoint(
    host: str,
    port: int,
    pid: int | None,
    pipename: str | None,
    timeout_sec: float,
) -> tuple[bool, dict[str, Any]]:
    from . import rpc_client as rc

    if pipename:
        return True, {"transport": "named_pipe", "host": host, "port": 0, "pipename": pipename}
    if pid is not None and port == 0:
        endpoint = rc.resolve_process_endpoint(int(pid), timeout=timeout_sec)
        if endpoint.get("transport") == "tcp":
            return True, endpoint
        if endpoint.get("transport") == "named_pipe":
            return True, endpoint
        return False, {"ok": False, **endpoint}
    if port <= 0:
        return False, {"ok": False, "error": "provide port, pid, or pipename"}
    return True, {"transport": "tcp", "host": host, "port": port}


def _rpc_endpoint_open_error_classification(exc: Exception) -> str:
    text = f"{type(exc).__name__}: {exc}".lower()
    if "actively refused" in text or "connectionrefused" in text:
        return "endpoint_refused_connection"
    if "semaphore timeout" in text or "timeout" in text:
        return "endpoint_transport_timeout"
    if "bad frame magic" in text or "connection closed" in text:
        return "endpoint_not_ngfx_rpc"
    return "endpoint_open_failed"


def _rpc_endpoint_probe_classification(probes: list[dict[str, Any]]) -> str:
    if any(item.get("non_empty") for item in probes):
        return "binary_replay_ready"
    errors = [str(item.get("error", "")).lower() for item in probes if item.get("error")]
    if probes and len(errors) == len(probes):
        if any("timeout" in error for error in errors):
            return "connected_but_no_rpc_reply"
        if any("bad frame magic" in error or "connection closed" in error for error in errors):
            return "endpoint_not_ngfx_rpc"
        return "binary_replay_calls_failed"
    if probes and all(not item.get("non_empty") and not item.get("error") for item in probes):
        return "binary_replay_connected_but_unbound_or_empty"
    return "binary_replay_unknown"


def _rpc_endpoint_probe_next_step(classification: str) -> str:
    if classification == "binary_replay_ready":
        return "Open a persistent session and call ngfx_sn2_copyrect_live_pair_probe with mapped CopyRect event indices."
    if classification == "binary_replay_connected_but_unbound_or_empty":
        return "The transport is reachable but BinaryReplay is not bound to a capture/session; use the UI's active capture session or the runtime instrumentation fallback."
    if classification == "endpoint_transport_timeout":
        return "Do not keep retrying this pipe blindly; resolve the current ngfx-rpc endpoint or use a fresh capture/session."
    if classification == "endpoint_not_ngfx_rpc":
        return "This endpoint is not the Nsight RPC protocol; ignore it for BinaryReplay."
    return "Use ngfx_rpc_endpoint_resolve against the ngfx-rpc/ngfx-ui process and verify an active capture is loaded."


def _truncate_probe_reply(reply: dict[str, Any]) -> dict[str, Any]:
    return {str(k): v for k, v in list(reply.items())[:8]}


@mcp.tool()
async def ngfx_frame_debugger_rpc_schema() -> dict[str, Any]:
    """Describe the private BinaryReplay RPC methods used for pixel/resource history."""
    try:
        reg = proto_descriptors.get_registry()
        return {
            "ok": True,
            "category": {
                "name": "BinaryReplay",
                "id": rpc_client.CATEGORY_BINARY_REPLAY,
                "confidence": "pinned by ngfx-rpc.exe PylonUi.proto; live namespace/session binding still private",
            },
            "methods": {
                "pixel_history": {
                    "method": rpc_client.RpcClient.METHOD_PIXEL_HISTORY,
                    "request": "NV.Pylon.Replay.PbPixelHistoryRequest",
                    "reply": "NV.Pylon.Replay.PbPixelHistoryReply",
                    "request_schema": reg.describe("NV.Pylon.Replay.PbPixelHistoryRequest"),
                    "reply_schema": reg.describe("NV.Pylon.Replay.PbPixelHistoryReply"),
                },
                "resource_access_history": {
                    "method": rpc_client.RpcClient.METHOD_RESOURCE_ACCESS_HISTORY,
                    "request": "NV.Pylon.Replay.PbResourceAccessHistoryRequest",
                    "reply": "NV.Pylon.Replay.PbResourceAccessHistoryReply",
                    "request_schema": reg.describe("NV.Pylon.Replay.PbResourceAccessHistoryRequest"),
                    "reply_schema": reg.describe("NV.Pylon.Replay.PbResourceAccessHistoryReply"),
                },
                "resource_info": {
                    "method": rpc_client.RpcClient.METHOD_RESOURCE_INFO,
                    "request": "NV.Pylon.Replay.PbResourceInfoRequest",
                    "reply": "NV.Pylon.Replay.PbResourceInfoReply",
                    "request_schema": reg.describe("NV.Pylon.Replay.PbResourceInfoRequest"),
                    "reply_schema": reg.describe("NV.Pylon.Replay.PbResourceInfoReply"),
                },
                "image_subresource_data": {
                    "method": rpc_client.RpcClient.METHOD_IMAGE_SUBRESOURCE_DATA,
                    "request": "NV.Pylon.Replay.PbImageSubresourceDataRequest",
                    "reply": "NV.Pylon.Replay.PbImageSubresourceDataReply",
                    "request_schema": reg.describe("NV.Pylon.Replay.PbImageSubresourceDataRequest"),
                    "reply_schema": reg.describe("NV.Pylon.Replay.PbImageSubresourceDataReply"),
                },
            },
            "handle_shape": reg.describe("NV.PbApiDataHandle"),
            "notes": [
                "Pixel history needs an image/image-view handle plus x/y pixel coordinates.",
                "Resource revision at event is derived from ResourceAccessHistory by selecting the last access at or before event_index.",
            ],
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_pixel_history(
    image_accessor: int,
    x: int,
    y: int,
    host: str = "127.0.0.1",
    port: int = 0,
    pid: int | None = None,
    image_misc: int = 0,
    image_view_accessor: int | None = None,
    image_view_misc: int = 0,
    aspect: int = 1,
    mip_level: int = 0,
    array_layer: int = 0,
    slice_index: int = 0,
    image_type: int = 3,
    preview_only: bool = False,
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """Call Nsight's private BinaryReplay pixel-history method.

    ``image_accessor``/``image_misc`` are the ``NV.PbApiDataHandle`` values
    for the target image. Use ``preview_only=True`` to build and inspect the
    exact protobuf request without opening a TCP connection.
    """
    from . import rpc_client as rc

    try:
        reg = proto_descriptors.get_registry()
        req = rc.build_pixel_history_request(
            reg,
            image_accessor=image_accessor,
            image_misc=image_misc,
            image_view_accessor=image_view_accessor,
            image_view_misc=image_view_misc,
            x=x,
            y=y,
            aspect=aspect,
            mip_level=mip_level,
            array_layer=array_layer,
            slice_index=slice_index,
            image_type=image_type,
        )
        request_info = {
            "category": rc.CATEGORY_BINARY_REPLAY,
            "method": rc.RpcClient.METHOD_PIXEL_HISTORY,
            "request_fqn": "NV.Pylon.Replay.PbPixelHistoryRequest",
            "reply_fqn": "NV.Pylon.Replay.PbPixelHistoryReply",
            "request": rc.protobuf_to_dict(req),
            "request_body_hex": req.SerializeToString().hex(),
        }
        if preview_only:
            return {"ok": True, "preview_only": True, **request_info}

        ok, conn_info = _resolve_rpc_port(host, port, pid, timeout_sec)
        if not ok:
            return conn_info
        with rc.RpcTransport.connect(conn_info["host"], conn_info["port"], timeout=timeout_sec) as transport:
            client = rc.RpcClient(transport, reg)
            reply = client.pixel_history(
                image_accessor=image_accessor,
                image_misc=image_misc,
                image_view_accessor=image_view_accessor,
                image_view_misc=image_view_misc,
                x=x,
                y=y,
                aspect=aspect,
                mip_level=mip_level,
                array_layer=array_layer,
                slice_index=slice_index,
                image_type=image_type,
                timeout=timeout_sec,
            )
        return {"ok": True, **conn_info, **request_info, "reply": rc.protobuf_to_dict(reply)}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_resource_access_history(
    accessor: int,
    host: str = "127.0.0.1",
    port: int = 0,
    pid: int | None = None,
    misc: int = 0,
    preview_only: bool = False,
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """Call Nsight's private resource-access-history method for one API handle."""
    from . import rpc_client as rc

    try:
        reg = proto_descriptors.get_registry()
        req = rc.build_resource_access_history_request(reg, accessor=accessor, misc=misc)
        request_info = {
            "category": rc.CATEGORY_BINARY_REPLAY,
            "method": rc.RpcClient.METHOD_RESOURCE_ACCESS_HISTORY,
            "request_fqn": "NV.Pylon.Replay.PbResourceAccessHistoryRequest",
            "reply_fqn": "NV.Pylon.Replay.PbResourceAccessHistoryReply",
            "request": rc.protobuf_to_dict(req),
            "request_body_hex": req.SerializeToString().hex(),
        }
        if preview_only:
            return {"ok": True, "preview_only": True, **request_info}

        ok, conn_info = _resolve_rpc_port(host, port, pid, timeout_sec)
        if not ok:
            return conn_info
        with rc.RpcTransport.connect(conn_info["host"], conn_info["port"], timeout=timeout_sec) as transport:
            client = rc.RpcClient(transport, reg)
            reply = client.resource_access_history(accessor=accessor, misc=misc, timeout=timeout_sec)
        return {"ok": True, **conn_info, **request_info, "reply": rc.protobuf_to_dict(reply)}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_resource_revision_at_event(
    accessor: int,
    event_index: int,
    host: str = "127.0.0.1",
    port: int = 0,
    pid: int | None = None,
    session_handle: str | None = None,
    misc: int = 0,
    include_resource_info: bool = False,
    include_image_subresource_data: bool = False,
    aspect: int = 1,
    mip_level: int = 0,
    array_layer: int = 0,
    slice_index: int = 0,
    region: dict[str, int] | None = None,
    preview_only: bool = False,
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """Derive a resource revision at an event from private resource history.

    The exposed RPC method is ``ResourceAccessHistory``. This tool selects the
    last access at or before ``event_index`` and optionally fetches resource
    info and image subresource bytes for that event.
    """
    from . import rpc_client as rc

    try:
        reg = proto_descriptors.get_registry()
        history_req = rc.build_resource_access_history_request(reg, accessor=accessor, misc=misc)
        request_info = {
            "history_request": rc.protobuf_to_dict(history_req),
            "history_request_body_hex": history_req.SerializeToString().hex(),
            "history_method": rc.RpcClient.METHOD_RESOURCE_ACCESS_HISTORY,
            "revision_derivation": "last ResourceAccessHistory.Accesses entry with EventIndex <= event_index",
        }
        if include_resource_info:
            info_req = rc.build_resource_info_request(reg, accessor=accessor, misc=misc)
            request_info["resource_info_request"] = rc.protobuf_to_dict(info_req)
            request_info["resource_info_body_hex"] = info_req.SerializeToString().hex()
        if include_image_subresource_data:
            data_req = rc.build_image_subresource_data_request(
                reg,
                accessor=accessor,
                misc=misc,
                event_index=event_index,
                aspect=aspect,
                mip_level=mip_level,
                array_layer=array_layer,
                slice_index=slice_index,
                region=region,
            )
            request_info["image_subresource_data_request"] = rc.protobuf_to_dict(data_req)
            request_info["image_subresource_data_body_hex"] = data_req.SerializeToString().hex()
        if preview_only:
            return {"ok": True, "preview_only": True, "event_index": event_index, **request_info}

        if session_handle:
            sess = frame_debugger_rpc_mod.get_session(session_handle)
            client = sess.client
            history_reply = client.resource_access_history(accessor=accessor, misc=misc, timeout=timeout_sec)
            revision = rc.resource_revision_from_history(history_reply, event_index)
            out: dict[str, Any] = {
                "ok": True,
                "session": sess.summary(),
                "event_index": event_index,
                **request_info,
                "history_reply": rc.protobuf_to_dict(history_reply),
                "revision": revision,
            }
            if include_resource_info:
                info_reply = client.resource_info(accessor=accessor, misc=misc, timeout=timeout_sec)
                out["resource_info_reply"] = rc.protobuf_to_dict(info_reply)
            if include_image_subresource_data:
                data_reply = client.image_subresource_data(
                    accessor=accessor,
                    misc=misc,
                    event_index=event_index,
                    aspect=aspect,
                    mip_level=mip_level,
                    array_layer=array_layer,
                    slice_index=slice_index,
                    region=region,
                    timeout=max(timeout_sec, 60.0),
                )
                data_dict = rc.protobuf_to_dict(data_reply)
                data = data_dict.get("data")
                if isinstance(data, str):
                    data_dict["data_base64_length"] = len(data)
                    data_dict["data"] = data[:256]
                    data_dict["data_truncated"] = True
                out["image_subresource_data_reply"] = data_dict
            return out

        ok, conn_info = _resolve_rpc_port(host, port, pid, timeout_sec)
        if not ok:
            return conn_info
        with rc.RpcTransport.connect(conn_info["host"], conn_info["port"], timeout=timeout_sec) as transport:
            client = rc.RpcClient(transport, reg)
            history_reply = client.resource_access_history(accessor=accessor, misc=misc, timeout=timeout_sec)
            revision = rc.resource_revision_from_history(history_reply, event_index)
            out: dict[str, Any] = {
                "ok": True,
                **conn_info,
                "event_index": event_index,
                **request_info,
                "history_reply": rc.protobuf_to_dict(history_reply),
                "revision": revision,
            }
            if include_resource_info:
                info_reply = client.resource_info(accessor=accessor, misc=misc, timeout=timeout_sec)
                out["resource_info_reply"] = rc.protobuf_to_dict(info_reply)
            if include_image_subresource_data:
                data_reply = client.image_subresource_data(
                    accessor=accessor,
                    misc=misc,
                    event_index=event_index,
                    aspect=aspect,
                    mip_level=mip_level,
                    array_layer=array_layer,
                    slice_index=slice_index,
                    region=region,
                    timeout=max(timeout_sec, 60.0),
                )
                data_dict = rc.protobuf_to_dict(data_reply)
                data = data_dict.get("data")
                if isinstance(data, str):
                    data_dict["data_base64_length"] = len(data)
                    data_dict["data"] = data[:256]
                    data_dict["data_truncated"] = True
                out["image_subresource_data_reply"] = data_dict
        return out
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_rpc_open_capture_session(
    host: str = "127.0.0.1",
    port: int = 0,
    pid: int | None = None,
    pipename: str | None = None,
    capture: str | None = None,
    launch_capture: bool = False,
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """Open a persistent frame-debugger RPC session and optionally launch a capture."""
    ok, conn_info = _resolve_rpc_endpoint(host, port, pid, pipename, timeout_sec)
    if not ok:
        return conn_info
    try:
        return frame_debugger_rpc_mod.open_session(
            host=conn_info["host"],
            port=conn_info["port"],
            transport_kind=conn_info.get("transport", "tcp"),
            pipename=conn_info.get("pipename"),
            capture_path=capture,
            launch_capture=launch_capture,
            timeout_sec=timeout_sec,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", **conn_info}


@mcp.tool()
async def ngfx_rpc_endpoint_resolve(
    pid: int | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
    pipename: str | None = None,
    timeout_sec: float = 5.0,
) -> dict[str, Any]:
    """Resolve an ngfx-rpc process or explicit args to TCP/named-pipe endpoint info."""
    ok, endpoint = _resolve_rpc_endpoint(host, port, pid, pipename, timeout_sec)
    return {"ok": ok, **endpoint}


@mcp.tool()
async def ngfx_rpc_endpoint_probe(
    pid: int | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
    pipename: str | None = None,
    sample_event_indices: list[int] | None = None,
    timeout_sec: float = 5.0,
) -> dict[str, Any]:
    """Resolve and probe an RPC endpoint, classifying BinaryReplay readiness."""
    ok, endpoint = _resolve_rpc_endpoint(host, port, pid, pipename, timeout_sec)
    if not ok:
        return {"ok": False, "classification": "endpoint_not_resolved", **endpoint}
    session_result: dict[str, Any] | None = None
    handle: str | None = None
    probes: list[dict[str, Any]] = []
    try:
        session_result = frame_debugger_rpc_mod.open_session(
            host=endpoint["host"],
            port=endpoint["port"],
            transport_kind=endpoint.get("transport", "tcp"),
            pipename=endpoint.get("pipename"),
            timeout_sec=timeout_sec,
        )
        handle = session_result.get("session", {}).get("handle")
        sess = frame_debugger_rpc_mod.get_session(handle)
        for event_index in sample_event_indices or [0, 1, 1096, 1166]:
            item: dict[str, Any] = {"event_index": event_index}
            try:
                reply = sess.client.event_details(event_index, timeout=timeout_sec)
                reply_dict = rpc_client.protobuf_to_dict(reply)
                item["reply_key_count"] = len(reply_dict)
                item["reply_text_length"] = len(str(reply_dict))
                item["non_empty"] = bool(reply_dict)
                item["reply_preview"] = _truncate_probe_reply(reply_dict)
            except Exception as exc:
                item["error"] = f"{type(exc).__name__}: {exc}"
            probes.append(item)
    except Exception as exc:
        classification = _rpc_endpoint_open_error_classification(exc)
        return {
            "ok": False,
            "classification": classification,
            "endpoint": endpoint,
            "error": f"{type(exc).__name__}: {exc}",
            "next_step": _rpc_endpoint_probe_next_step(classification),
        }
    finally:
        if handle:
            frame_debugger_rpc_mod.close_session(handle)

    classification = _rpc_endpoint_probe_classification(probes)
    return {
        "ok": classification == "binary_replay_ready",
        "classification": classification,
        "endpoint": endpoint,
        "session_open": session_result,
        "probes": probes,
        "next_step": _rpc_endpoint_probe_next_step(classification),
    }


@mcp.tool()
async def ngfx_rpc_capture_session_status(handle: str | None = None) -> dict[str, Any]:
    """List persistent frame-debugger RPC sessions, or summarize one handle."""
    try:
        if handle:
            return {"ok": True, "session": frame_debugger_rpc_mod.get_session(handle).summary()}
        return {"ok": True, "sessions": frame_debugger_rpc_mod.list_sessions()}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_rpc_close_capture_session(handle: str) -> dict[str, Any]:
    """Close a persistent frame-debugger RPC session."""
    return frame_debugger_rpc_mod.close_session(handle)


@mcp.tool()
async def ngfx_rpc_call_binary_replay(
    handle: str,
    method: int,
    request_fqn: str,
    reply_fqn: str,
    request_body_hex: str = "",
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """Call an arbitrary BinaryReplay method on an open frame-debugger RPC session."""
    try:
        return frame_debugger_rpc_mod.call_binary_replay(
            handle,
            method=method,
            request_fqn=request_fqn,
            reply_fqn=reply_fqn,
            request_body_hex=request_body_hex,
            timeout_sec=timeout_sec,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_rpc_find_live_events(
    handle: str,
    start_event: int = 0,
    end_event: int = 2000,
    text_filter: str | list[str] | None = None,
    draw_ordinals: list[int] | None = None,
    draw_ordinal_base: int = 0,
    max_results: int = 64,
    include_reply: bool = False,
    timeout_sec: float = 10.0,
) -> dict[str, Any]:
    """Scan live BinaryReplay EventDetails to map hook draw ordinals to event_index values.

    This is intentionally brute-force and version-tolerant: Nsight's private
    event-list RPCs vary by build, but EventDetails over an index range is the
    stable primitive already used by the FrameDebugger tools.
    """
    if end_event < start_event:
        return {"ok": False, "error": "end_event must be >= start_event"}
    filters = _normalise_text_filters(text_filter)
    ordinal_targets = {int(item) for item in (draw_ordinals or [])}
    results = []
    errors = []
    draw_count = 0
    try:
        sess = frame_debugger_rpc_mod.get_session(handle)
        for event_index in range(int(start_event), int(end_event) + 1):
            try:
                reply = sess.client.event_details(event_index, timeout=timeout_sec)
                reply_dict = rpc_client.protobuf_to_dict(reply)
            except Exception as exc:
                errors.append({"event_index": event_index, "error": f"{type(exc).__name__}: {exc}"})
                if len(errors) >= 8:
                    break
                continue

            summary = _live_event_reply_summary(reply_dict)
            text = json.dumps(reply_dict, sort_keys=True, default=str).lower()
            is_draw = _live_event_looks_like_draw(summary, text)
            draw_ordinal = None
            if is_draw:
                draw_ordinal = draw_ordinal_base + draw_count
                draw_count += 1

            if ordinal_targets and draw_ordinal not in ordinal_targets:
                continue
            if filters and not all(item in text for item in filters):
                continue

            result: dict[str, Any] = {
                "event_index": event_index,
                "draw_ordinal": draw_ordinal,
                "looks_like_draw": is_draw,
                "summary": summary,
            }
            if include_reply:
                result["reply"] = reply_dict
            results.append(result)
            if len(results) >= max_results:
                break
        return {
            "ok": not errors or bool(results),
            "session": sess.summary(),
            "range": {"start_event": start_event, "end_event": end_event},
            "filters": {"text_filter": filters, "draw_ordinals": sorted(ordinal_targets), "draw_ordinal_base": draw_ordinal_base},
            "draw_events_seen": draw_count,
            "results": results,
            "result_count": len(results),
            "errors": errors,
            "next_step": "Use each result.event_index with ngfx_sn2_copyrect_live_state_probe.",
        }
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_rpc_decode_frame(
    frame_hex: str,
    has_transport_header: bool | None = None,
    include_body_hex: bool = False,
    body_preview_bytes: int = 96,
) -> dict[str, Any]:
    """Decode one ngfx-rpc transport frame or raw RPC message body from hex."""
    try:
        return rpc_trace.decode_rpc_frame_hex(
            frame_hex,
            has_transport_header=has_transport_header,
            include_body_hex=include_body_hex,
            body_preview_bytes=body_preview_bytes,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_rpc_transcript_import(
    transcript_path: str | None = None,
    frames: list[str] | None = None,
    has_transport_header: bool | None = None,
    include_body_hex: bool = False,
) -> dict[str, Any]:
    """Import and decode a JSON, NDJSON, or plain-hex ngfx-rpc transcript."""
    try:
        return rpc_trace.import_rpc_transcript(
            transcript_path=transcript_path,
            frames=frames,
            has_transport_header=has_transport_header,
            include_body_hex=include_body_hex,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_rpc_session_binding_report(
    decoded_frames: list[dict[str, Any]] | None = None,
    transcript_path: str | None = None,
    frames: list[str] | None = None,
    has_transport_header: bool | None = None,
) -> dict[str, Any]:
    """Summarize BinaryReplay session/slot binding evidence from RPC frames."""
    try:
        if decoded_frames is None:
            imported = rpc_trace.import_rpc_transcript(
                transcript_path=transcript_path,
                frames=frames,
                has_transport_header=has_transport_header,
            )
            return imported["session_binding_report"]
        return rpc_trace.session_binding_report(decoded_frames)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_rpc_pe_patch_plan(
    target_exe: str,
    sites: list[str] | None = None,
) -> dict[str, Any]:
    """Plan (do NOT apply) a logger-trampoline patch on ``ngfx-rpc.exe``.

    Emits the structured plan: chosen patch sites (from the known set),
    trampoline template bytes with marker DWORDs, and the next-steps
    checklist. **Nothing is written to disk.** Use
    ``ngfx_rpc_pe_patch_ida_script`` to materialise the IDA Pro script.

    This is one of the three documented sniffer-wall bypasses.
    """
    try:
        return pe_patch_planner_mod.build_patch_plan(
            Path(target_exe), sites=sites,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_rpc_pe_patch_ida_script(
    target_exe: str,
    output_path: str,
    sites: list[str] | None = None,
) -> dict[str, Any]:
    """Emit an IDA Pro 9.0 headless Python script that implements the plan.

    The script intentionally leaves the code-cave allocation and the
    marker-byte patches as TODOs — they are project-specific and should
    be reviewed by a human RE before running. Run the emitted script
    via ``ida.exe -A -S<script>.py <target_exe>`` after backing the
    binary up.
    """
    try:
        return pe_patch_planner_mod.generate_ida_script(
            Path(target_exe), Path(output_path), sites=sites,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_rpc_etw_environment() -> dict[str, Any]:
    """Probe for Windows ETW capture tools (``logman`` / ``tracerpt``)."""
    return etw_capture_mod.etw_environment()


@mcp.tool()
async def ngfx_rpc_etw_capture_start(
    session_name: str = "ngfx_rpc_kernel_file",
    output_etl: str = "ngfx_rpc_kernel_file.etl",
    extra_providers: list[str] | None = None,
    buffer_size_kb: int = 1024,
    max_file_mb: int = 256,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Start a kernel-file ETW session targeted at ngfx-ui ↔ ngfx-rpc I/O.

    Wraps ``logman create trace ... -p <Kernel-File-GUID>``. Defaults to
    ``dry_run=True`` — pass ``dry_run=False`` to actually start the
    capture (requires admin / Performance Log Users group).

    This is one of the three documented bypasses for the shared-memory
    wall: kernel-file ETW sees every pipe/file handle operation
    regardless of how user-mode shims are implemented.
    """
    try:
        return etw_capture_mod.etw_capture_start(
            session_name,
            Path(output_etl),
            extra_providers=extra_providers,
            buffer_size_kb=buffer_size_kb,
            max_file_mb=max_file_mb,
            dry_run=dry_run,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_rpc_etw_capture_stop(
    session_name: str = "ngfx_rpc_kernel_file",
    dry_run: bool = True,
) -> dict[str, Any]:
    """Stop a previously-started kernel-file ETW session."""
    try:
        return etw_capture_mod.etw_capture_stop(session_name, dry_run=dry_run)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_rpc_etw_capture_summary(
    etl_path: str,
    output_xml: str | None = None,
    output_csv: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Convert an ETL trace to XML/CSV via ``tracerpt`` and summarize counts.

    Even without buffer payloads, the per-event counts in the CSV are
    enough to narrow which named pipe / file handle the ngfx-rpc traffic
    flows through, which is the input for the PE-patch or pktmon paths.
    """
    try:
        return etw_capture_mod.etw_capture_summary(
            Path(etl_path),
            output_xml=Path(output_xml) if output_xml else None,
            output_csv=Path(output_csv) if output_csv else None,
            dry_run=dry_run,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_rpc_capture_open_sequence_report(
    transcript_path: str | None = None,
    decoded_frames: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Structured digest of the known + observed capture-open sequence.

    Returns two halves:

    * ``known`` — the static reverse-engineered summary of the
      AttachMessage / session-bind sequence: transport invariants,
      candidate sequence steps (with evidence labels), blocked paths
      that depend on the handshake, and the still-open RE questions.
    * ``observed`` — when ``transcript_path`` (or ``decoded_frames``)
      is provided, analysis of what's present in that capture: the
      first ``CategoryConnection`` frame, the first non-``slot=11``
      reply, and the list of expected ``(category, method, slot)``
      keys that are still missing.

    This is the planner's view for the "pick a sniffer-wall bypass"
    decision documented in NSIGHT_SHADER_DEBUG_AUTONOMY.md.
    """
    try:
        return rpc_trace.capture_open_sequence_report(
            transcript_path=transcript_path,
            decoded_frames=decoded_frames,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _normalise_text_filters(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values = [value]
    else:
        values = value
    return [str(item).strip().lower() for item in values if str(item).strip()]


def _live_event_reply_summary(reply: dict[str, Any]) -> dict[str, Any]:
    flat = _flatten_reply_scalars(reply)
    likely_names = []
    for key, value in flat:
        key_lower = key.lower()
        if isinstance(value, str) and any(marker in key_lower for marker in ("name", "function", "event", "api")):
            likely_names.append({"path": key, "value": value})
    return {
        "likely_names": likely_names[:12],
        "interesting_scalars": [
            {"path": key, "value": value}
            for key, value in flat
            if _live_event_scalar_is_interesting(key, value)
        ][:40],
    }


def _live_event_looks_like_draw(summary: dict[str, Any], text: str) -> bool:
    for item in summary.get("likely_names", []):
        value = str(item.get("value", "")).lower()
        if "draw" in value or "dispatch" in value:
            return "draw" in value
    return "draw" in text and "draw_" not in text


def _live_event_scalar_is_interesting(key: str, value: Any) -> bool:
    key_lower = key.lower()
    if any(marker in key_lower for marker in ("name", "function", "event", "draw", "pso", "pipeline", "root", "descriptor")):
        return True
    return isinstance(value, str) and any(marker in value.lower() for marker in ("draw", "dispatch", "setpipeline", "copy"))


def _flatten_reply_scalars(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            out.extend(_flatten_reply_scalars(child, next_prefix))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            out.extend(_flatten_reply_scalars(child, f"{prefix}[{index}]"))
    else:
        out.append((prefix, value))
    return out


# ---------------------------------------------------------------------------
# Aftermath (crash-dump tools)
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_aftermath_control(
    extra_args: list[str] | None = None,
    timeout_sec: int | None = 60,
) -> dict[str, Any]:
    """Run ``nv-aftermath-control.exe`` with the provided args.

    Use ``extra_args=["--help"]`` first to see what your installed version
    supports. Typical workflows: ``--enable``, ``--disable``, ``--status``,
    ``--dump-dir <path>``.
    """
    s = get_settings()
    exe = s.require_tool("aftermath_control")
    argv = [str(exe), *(list(extra_args) if extra_args else [])]
    res = await run_async(argv, tool="nv-aftermath-control", timeout=timeout_sec)
    return result_to_dict(res)


@mcp.tool()
async def ngfx_aftermath_monitor_start(
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Start ``nv-aftermath-monitor.exe`` in the background to watch for GPU
    crashes / hangs and write dump files.
    """
    s = get_settings()
    exe = s.require_tool("aftermath_monitor")
    argv = [str(exe), *(list(extra_args) if extra_args else [])]
    bg = start_background("__tmp__", argv, tool="nv-aftermath-monitor")
    sess = get_sessions().register_launch(
        bg, tool="nv-aftermath-monitor", notes="background Aftermath crash-dump monitor"
    )
    return sess.summary()


@mcp.tool()
async def ngfx_aftermath_format(
    dump_file: str,
    extra_args: list[str] | None = None,
    timeout_sec: int | None = 120,
) -> dict[str, Any]:
    """Run ``nv-aftermath-format.exe`` against an existing crash dump."""
    s = get_settings()
    exe = s.require_tool("aftermath_format")
    argv = [str(exe), *(list(extra_args) if extra_args else []), dump_file]
    res = await run_async(argv, tool="nv-aftermath-format", timeout=timeout_sec)
    return result_to_dict(res)


# ---------------------------------------------------------------------------
# Layer install helpers
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_layer_list() -> dict[str, Any]:
    """List the Vulkan / VulkanSC / OpenXR layer install scripts shipped with
    the Nsight Graphics install, and whether each one is present.
    """
    return layers.list_layer_scripts()


@mcp.tool()
async def ngfx_layer_install(
    layer: str, global_install: bool = False, uninstall: bool = False
) -> dict[str, Any]:
    """Run a Nsight Graphics layer install script.

    ``layer`` ∈ {"ngfx_install", "vk_ngfx_capture", "vk_gpu_trace", "vk_nomad",
    "vk_shader_debugger", "vksc_ngfx_capture", "vksc_gpu_trace", "vksc_nomad",
    "xr_ngfx_capture", "xr_nomad"}.

    Pass ``global_install=True`` for system-wide install (requires Admin).
    Pass ``uninstall=True`` to undo a prior install.
    """
    return await layers.run_layer_script(layer, uninstall=uninstall, global_install=global_install)


# ---------------------------------------------------------------------------
# NGFX SDK helpers (in-app integration)
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_sdk_reference() -> dict[str, Any]:
    """Enumerate every header in the NGFX in-app SDK, with parsed function
    declarations (name, params, brief) for each.

    Use this to discover the right NGFX_* entry point for your activity/API
    pair (e.g. ``NGFX_GraphicsCapture_RequestCapture_D3D12``).
    """
    return sdk.list_headers()


@mcp.tool()
async def ngfx_sdk_grep(pattern: str, max_hits: int = 200) -> dict[str, Any]:
    """Regex-search across the NGFX header tree (returns matched filename,
    line number, and matched line text).
    """
    return sdk.grep_sdk(pattern, max_hits=max_hits)


@mcp.tool()
async def ngfx_sdk_snippet(activity: str, api: str) -> dict[str, Any]:
    """Generate a C++ integration snippet for an (activity, API) pair.

    ``activity`` ∈ {"GraphicsCapture", "GPUTrace"}
    ``api``      ∈ {"D3D12", "Vulkan", "OpenGL", "CUDA", "CUDART"}
    (GraphicsCapture currently meaningful only for D3D12 / Vulkan.)
    """
    return sdk.generate_snippet(activity, api)


@mcp.tool()
async def ngfx_sdk_header_text(header: str, max_chars: int = 60_000) -> dict[str, Any]:
    """Return the raw text of an NGFX SDK header.

    ``header`` is the filename (e.g. ``NGFX_GraphicsCapture_D3D12.h`` or
    ``Impl/NGFX_Core.h``).
    """
    s = get_settings()
    if s.sdk_root is None:
        return {"ok": False, "error": "no NGFX SDK found"}
    p = s.sdk_root / "include" / header
    if not p.is_file():
        return {"ok": False, "error": f"header not found: {p}"}
    text = p.read_text(encoding="utf-8", errors="replace")
    truncated = len(text) > max_chars
    return {
        "ok": True,
        "path": str(p),
        "bytes": len(text),
        "text": text[:max_chars],
        "truncated": truncated,
    }


# ---------------------------------------------------------------------------
# IDA Pro headless reverse-engineering helpers
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_ida_environment() -> dict[str, Any]:
    """Discover local IDA installs usable for headless decompilation.

    Set ``NSIGHT_GRAPHICS_MCP_IDA`` to an ``idat.exe`` path or an IDA install
    directory if auto-discovery picks the wrong install. Professional/Home
    installs are preferred over Free because Hex-Rays pseudocode export needs
    a decompiler license.
    """
    installs = ida_re.discover_ida_installs()
    version_probe = ida_re.run_ida_version() if installs else None
    return {
        "ok": bool(installs),
        "env_var_for_override": ida_re.IDA_ENV,
        "installs": [i.to_dict() for i in installs],
        "selected": installs[0].to_dict() if installs else None,
        "known_targets": ida_re.known_targets(),
        "version_probe": version_probe,
    }


@mcp.tool()
async def ngfx_ida_analyze_binary(
    target: str,
    ida_path: str | None = None,
    force: bool = False,
    string_patterns: list[str] | None = None,
    function_patterns: list[str] | None = None,
    selected_functions: list[str] | None = None,
    max_strings: int = 500,
    max_functions: int = 200,
    max_decompile: int = 40,
    timeout_sec: int | None = 1800,
) -> dict[str, Any]:
    """Run IDA Pro headless over a Nsight binary and cache JSON RE facts.

    ``target`` can be a path or one of ``ngfx_ida_environment().known_targets``
    such as ``ngfx_rpc``, ``ngfx_replay``, ``frame_debugger_native``,
    ``frame_debugger_d3d12``, or ``frame_debugger_vulkan``.

    The exporter records matching strings, xrefs, selected functions, and
    bounded Hex-Rays pseudocode for the functions most likely to expose
    descriptor state, event details, resource dumps, pixel history, shader
    state, or replay hidden paths.
    """
    try:
        return await ida_re.analyze_binary(
            target,
            ida_path=ida_path,
            force=force,
            string_patterns=string_patterns,
            function_patterns=function_patterns,
            selected_functions=selected_functions,
            max_strings=max_strings,
            max_functions=max_functions,
            max_decompile=max_decompile,
            timeout_sec=timeout_sec,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_ida_search_facts(
    facts_path: str,
    pattern: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Regex-search an IDA facts JSON emitted by ``ngfx_ida_analyze_binary``."""
    try:
        return ida_re.search_facts(facts_path, pattern, limit=limit)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_ida_fact_summary(facts_path: str) -> dict[str, Any]:
    """Summarize an IDA facts JSON without returning all strings/pseudocode."""
    try:
        facts = ida_re.load_facts(facts_path)
        return {"ok": True, "facts_path": facts_path, "summary": ida_re.summarize_facts(facts)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_ida_command_preview(target: str, ida_path: str | None = None) -> dict[str, Any]:
    """Show the headless IDA command shape for a target without running it."""
    try:
        return ida_re.command_preview(target, ida_path=ida_path)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_cpp_capture_saved_bridge_re_analyze(
    ida_path: str | None = None,
    force: bool = False,
    include_pylon: bool = True,
    timeout_sec: int | None = 1800,
) -> dict[str, Any]:
    """Run the targeted IDA passes for the private saved-capture -> C++ bridge.

    This is reverse-engineering support only. It analyzes the Nsight plugins
    that implement the UI-only saved-capture path, then caches facts for
    ``ngfx_cpp_capture_saved_bridge_re_report``.
    """
    try:
        return await cpp_bridge_re.analyze_saved_cpp_bridge(
            ida_path=ida_path,
            force=force,
            include_pylon=include_pylon,
            timeout_sec=timeout_sec,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_cpp_capture_saved_bridge_re_report(
    battle_facts_path: str | None = None,
    pylon_facts_path: str | None = None,
) -> dict[str, Any]:
    """Summarize current RE evidence for fully headless saved C++ export.

    Reports the recovered FrameDebugger serialize protocol, the Pylon saved
    capture activity bridge, and the remaining unverified gap. It does not
    claim to export a saved capture headlessly yet.
    """
    try:
        return cpp_bridge_re.saved_capture_cpp_bridge_report(
            battle_facts_path=battle_facts_path,
            pylon_facts_path=pylon_facts_path,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_cpp_capture_saved_pylon_handoff_preview(
    capture: str,
    additional_args: list[str] | None = None,
    environment: dict[str, str] | None = None,
    output_dir: str | None = None,
    platform: str = "win32",
    install_host_dir: str | None = None,
) -> dict[str, Any]:
    """Preview the pinned Pylon saved-capture -> Generate C++ Capture handoff.

    This emits the exact platform launcher settings Pylon constructs for a
    saved capture. It is a bridge-building primitive; it does not invoke the
    private Pylon activity manager by itself.
    """
    try:
        return cpp_bridge_re.pylon_saved_capture_handoff_preview(
            capture,
            additional_args=additional_args,
            environment=environment,
            output_dir=output_dir,
            platform=platform,
            install_host_dir=install_host_dir,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_pylon_private_bridge_re_report(
    battle_facts_path: str | None = None,
    pylon_facts_path: str | None = None,
) -> dict[str, Any]:
    """Report what remains to build the private Pylon/BinaryReplay executor."""
    try:
        return cpp_bridge_re.pylon_private_executor_re_report(
            battle_facts_path=battle_facts_path,
            pylon_facts_path=pylon_facts_path,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_pylon_bridge_probe_plan(
    capture: str | None = None,
    output_dir: str | None = None,
    additional_args: list[str] | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Return a concrete probe plan for Pylon's private activity-manager bridge."""
    try:
        return cpp_bridge_re.pylon_bridge_probe_plan(
            capture,
            output_dir=output_dir,
            additional_args=additional_args,
            environment=environment,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_pylon_activity_manager_static_binding_report(
    pylon_facts_path: str | None = None,
) -> dict[str, Any]:
    """Extract the static Pylon activity-manager/direct-call binding from IDA facts."""
    try:
        return cpp_bridge_re.pylon_activity_manager_static_binding_report(
            pylon_facts_path=pylon_facts_path,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_pylon_bridge_helper_scaffold(
    out_dir: str,
    capture: str | None = None,
    output_dir: str | None = None,
    additional_args: list[str] | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Write a Frida/native helper scaffold for pinning Pylon's private executor."""
    try:
        return cpp_bridge_re.pylon_bridge_helper_scaffold(
            Path(out_dir),
            capture=capture,
            output_dir=output_dir,
            additional_args=additional_args,
            environment=environment,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_pylon_bridge_probe_log_analyze(
    log_path: str | None = None,
    messages: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Analyze Frida Pylon bridge probe output into binding hypotheses."""
    try:
        return cpp_bridge_re.pylon_bridge_probe_log_analyze(
            log_path=log_path,
            messages=messages,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_pylon_private_binding_from_probe(
    probe_log_path: str | None = None,
    analysis: dict[str, Any] | None = None,
    out_path: str | None = None,
) -> dict[str, Any]:
    """Convert Pylon probe output into a private bridge binding JSON."""
    try:
        return cpp_bridge_re.pylon_private_binding_from_probe(
            probe_log_path=probe_log_path,
            analysis=analysis,
            out_path=out_path,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_pylon_direct_call_binding_from_probe(
    probe_log_path: str | None = None,
    analysis: dict[str, Any] | None = None,
    out_path: str | None = None,
) -> dict[str, Any]:
    """Build the experimental direct-call binding for PylonPlugin!sub_180116CD0."""
    try:
        return cpp_bridge_re.pylon_direct_call_binding_from_probe(
            probe_log_path=probe_log_path,
            analysis=analysis,
            out_path=out_path,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_pylon_bridge_probe_run(
    out_dir: str,
    capture: str | None = None,
    output_dir: str | None = None,
    additional_args: list[str] | None = None,
    environment: dict[str, str] | None = None,
    pid: int | None = None,
    process_name: str = "ngfx-ui.exe",
    spawn_exe: str | None = None,
    frida_path: str | None = None,
    script_path: str | None = None,
    timeout_sec: float = 120.0,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run the Pylon Frida probe and analyze collected private binding events."""
    try:
        return cpp_bridge_re.pylon_bridge_probe_run(
            Path(out_dir),
            capture=capture,
            output_dir=output_dir,
            additional_args=additional_args,
            environment=environment,
            pid=pid,
            process_name=process_name,
            spawn_exe=spawn_exe,
            frida_path=frida_path,
            script_path=script_path,
            timeout_sec=timeout_sec,
            dry_run=dry_run,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_pylon_frida_direct_call_run(
    out_dir: str,
    binding_path: str | None = None,
    binding: dict[str, Any] | None = None,
    pid: int | None = None,
    process_name: str = "ngfx-ui.exe",
    frida_path: str | None = None,
    timeout_sec: float = 120.0,
    dry_run: bool = True,
    allow_experimental_call: bool = False,
) -> dict[str, Any]:
    """Run the experimental Frida direct re-entry call into sub_180116CD0."""
    try:
        return cpp_bridge_re.pylon_frida_direct_call_run(
            Path(out_dir),
            binding_path=binding_path,
            binding=binding,
            pid=pid,
            process_name=process_name,
            frida_path=frida_path,
            timeout_sec=timeout_sec,
            dry_run=dry_run,
            allow_experimental_call=allow_experimental_call,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_private_executor_readiness_report(
    probe_log_path: str | None = None,
    rpc_transcript_path: str | None = None,
    pylon_binding_path: str | None = None,
    pylon_binding: dict[str, Any] | None = None,
    bridge_exe: str | None = None,
) -> dict[str, Any]:
    """Report whether Pylon or direct-RPC private export is ready to invoke."""
    try:
        return cpp_bridge_re.private_executor_readiness_report(
            probe_log_path=probe_log_path,
            rpc_transcript_path=rpc_transcript_path,
            pylon_binding_path=pylon_binding_path,
            pylon_binding=pylon_binding,
            bridge_exe=bridge_exe,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_private_executor_evidence_bundle(
    out_zip: str,
    capture: str | None = None,
    output_dir: str | None = None,
    probe_log_path: str | None = None,
    rpc_transcript_path: str | None = None,
    extra_files: list[str] | None = None,
) -> dict[str, Any]:
    """Bundle Pylon/RPC private-executor evidence into one artifact."""
    try:
        return cpp_bridge_re.private_executor_evidence_bundle(
            Path(out_zip),
            capture=capture,
            output_dir=output_dir,
            probe_log_path=probe_log_path,
            rpc_transcript_path=rpc_transcript_path,
            extra_files=extra_files,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_pylon_private_bridge_invoke(
    capture: str,
    output_dir: str,
    bridge_exe: str | None = None,
    binding_path: str | None = None,
    binding: dict[str, Any] | None = None,
    request_path: str | None = None,
    timeout_sec: float = 900.0,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Guarded entrypoint for invoking the future native Pylon bridge."""
    try:
        return cpp_bridge_re.pylon_private_bridge_invoke(
            capture,
            output_dir=output_dir,
            bridge_exe=bridge_exe,
            binding_path=binding_path,
            binding=binding,
            request_path=request_path,
            timeout_sec=timeout_sec,
            dry_run=dry_run,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_pylon_saved_cpp_export(
    capture: str,
    output_dir: str | None = None,
    additional_args: list[str] | None = None,
    environment: dict[str, str] | None = None,
    scaffold_dir: str | None = None,
    bridge_exe: str | None = None,
    binding_path: str | None = None,
    binding: dict[str, Any] | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Package the private Pylon saved-capture C++ export inputs.

    This is the future private-executor entrypoint. It returns a structured
    blocker until the in-process activity-manager binding is proven.
    """
    try:
        return cpp_bridge_re.pylon_saved_cpp_export(
            capture,
            output_dir=output_dir,
            additional_args=additional_args,
            environment=environment,
            scaffold_dir=scaffold_dir,
            bridge_exe=bridge_exe,
            binding_path=binding_path,
            binding=binding,
            dry_run=dry_run,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_cpp_capture_saved_direct_rpc_plan(
    output_dir: str,
    rpc_session_handle: str | None = None,
    host_save_directory: str | None = None,
    copy_redist_requirements: bool = True,
    target_is_remote: bool = False,
    keep_on_remote_machine: bool = False,
) -> dict[str, Any]:
    """Preview the direct FrameDebugger serialize-RPC request/callback plan."""
    try:
        return cpp_bridge_re.frame_debugger_serialize_rpc_plan(
            output_dir=output_dir,
            rpc_session_handle=rpc_session_handle,
            host_save_directory=host_save_directory,
            copy_redist_requirements=copy_redist_requirements,
            target_is_remote=target_is_remote,
            keep_on_remote_machine=keep_on_remote_machine,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_rpc_direct_export_binding_candidate(
    transcript_path: str | None = None,
    frames: list[str] | None = None,
    has_transport_header: bool | None = None,
) -> dict[str, Any]:
    """Derive a direct saved-C++ RPC binding candidate from a transcript."""
    try:
        return rpc_trace.direct_export_binding_candidate_from_transcript(
            transcript_path=transcript_path,
            frames=frames,
            has_transport_header=has_transport_header,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_cpp_capture_saved_direct_rpc_export(
    output_dir: str,
    rpc_session_handle: str | None = None,
    host_save_directory: str | None = None,
    copy_redist_requirements: bool = True,
    target_is_remote: bool = False,
    keep_on_remote_machine: bool = False,
    binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Future direct FrameDebugger serialize-RPC export entrypoint.

    The request/callback protocol is pinned, but this does not send until the
    live BinaryReplay session/slot binding is supplied and verified.
    """
    try:
        plan = cpp_bridge_re.frame_debugger_serialize_rpc_plan(
            output_dir=output_dir,
            rpc_session_handle=rpc_session_handle,
            host_save_directory=host_save_directory,
            copy_redist_requirements=copy_redist_requirements,
            target_is_remote=target_is_remote,
            keep_on_remote_machine=keep_on_remote_machine,
        )
        session = None
        if rpc_session_handle:
            try:
                session = frame_debugger_rpc_mod.get_session(rpc_session_handle).summary()
            except Exception as exc:
                session = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        return {
            "ok": False,
            "status": "blocked_requires_binaryreplay_session_binding",
            "headless_export_invoked": False,
            "send_enabled": False,
            "session": session,
            "binding": binding,
            "direct_rpc_plan": plan,
            "required_before_send": [
                "A transcript-derived BinaryReplay slot/request_id/seq binding.",
                "A confirmed request body encoding for PbSerializeRequestMessage in the live namespace.",
                "A live callback loop for methods 44, 45, and 46 using ngfx_cpp_capture_saved_file_transfer_apply.",
            ],
            "next_tools": [
                "ngfx_rpc_transcript_import",
                "ngfx_rpc_session_binding_report",
                "ngfx_cpp_capture_saved_direct_rpc_plan",
            ],
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_cpp_capture_saved_file_transfer_apply(
    output_dir: str,
    notification: dict[str, Any],
    state_path: str | None = None,
) -> dict[str, Any]:
    """Apply one FrameDebugger serialize file-transfer notification to disk."""
    try:
        return cpp_bridge_re.frame_debugger_file_transfer_apply(
            output_dir,
            notification,
            state_path=state_path,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_cpp_capture_saved_output_dir_setting(
    output_dir: str,
    organization: str = "NVIDIA Corporation",
    application: str = "Nsight Graphics",
    registry_key: str | None = None,
    write: bool = False,
) -> dict[str, Any]:
    """Preview or write the candidate QSettings output-dir value for C++ export.

    ``write=False`` is a safe preview. Set ``write=True`` only after the
    organization/application or registry key has been confirmed for the local
    Nsight install.
    """
    try:
        return cpp_capture.set_saved_cpp_output_dir_setting(
            Path(output_dir),
            organization=organization,
            application=application,
            registry_key=registry_key,
            write=write,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_cpp_capture_saved_export_validate(
    project_dir: str,
    capture: str | None = None,
    db_path: str | None = None,
    index_calls: bool = True,
    index_psos: bool = True,
    force_index: bool = False,
    compare_event_sequence: bool = True,
    max_compare_events: int = 20000,
) -> dict[str, Any]:
    """Validate and index a saved-capture Generate-C++-Capture export."""
    try:
        return await cpp_capture.validate_cpp_capture_export(
            Path(project_dir),
            capture=Path(capture) if capture else None,
            db_path=Path(db_path) if db_path else None,
            index_calls=index_calls,
            index_psos=index_psos,
            force_index=force_index,
            compare_event_sequence=compare_event_sequence,
            max_compare_events=max_compare_events,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_capture_recapture_with_install(
    capture: str,
    install_root: str | None = None,
    frame: int | None = None,
    countdown_ms: int | None = None,
    output_path: str | None = None,
    terminate_after_capture: bool = True,
    no_hud: bool = True,
    api: str = "d3d12",
    additional_args: list[str] | None = None,
    additional_env: dict[str, str] | None = None,
    timeout_sec: float = 900.0,
) -> dict[str, Any]:
    """Re-run the captured application via the picked install's
    ``ngfx-capture.exe`` with a deterministic frame/countdown trigger.

    Designed for the autonomy gap on Nsight 2026.1.0: the running
    install's D3D12 ``Generate C++ Capture`` was removed by NVIDIA, but
    an older sidecar install (e.g. 2025.5.0) still supports it. The
    source 2026.1.0 capture is too new to be replayed by the sidecar's
    ngfx-replay, so this tool re-runs the captured application via the
    sidecar's ngfx-capture to produce a sidecar-compatible artifact.

    The launched exe path, args, and (if ``frame`` is omitted) the
    original ``MetaData.CaptureBeginFrame`` are read straight from the
    source capture's TOC. ``--terminate-after-capture`` is on by
    default so the game exits cleanly once the capture lands.

    When ``install_root`` is omitted, the picker chooses the newest
    installed Nsight version whose Generate C++ Capture still supports
    ``api`` (defaults to ``d3d12``).
    """
    try:
        _, path = _resolve_capture(capture)
        if install_root is None:
            roots = [Path(r) for r in discover_install_roots()]
            picked = cpp_capture.pick_cpp_capture_capable_install(
                roots, api_hint=api,
            )
            if not picked.get("recommended"):
                return {"ok": False, "error": picked.get("rationale"), "picker": picked}
            install_root_p = Path(picked["recommended"]["install_root"]).resolve()
        else:
            install_root_p = Path(install_root).resolve()
        return await cpp_capture.recapture_with_picked_install_run(
            path,
            install_root_p,
            frame=frame,
            countdown_ms=countdown_ms,
            output_path=Path(output_path) if output_path else None,
            terminate_after_capture=terminate_after_capture,
            no_hud=no_hud,
            additional_args=additional_args,
            additional_env=additional_env,
            timeout_sec=timeout_sec,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_cpp_capture_full_autonomy(
    capture: str,
    install_root: str | None = None,
    api: str = "d3d12",
    frame: int | None = None,
    countdown_ms: int | None = None,
    output_capture_path: str | None = None,
    output_cpp_dir: str | None = None,
    terminate_after_capture: bool = True,
    timeout_sec: float = 900.0,
    index_psos: bool = True,
    force_index: bool = False,
    run_cpp_capture: bool = True,
) -> dict[str, Any]:
    """One-shot autonomous chain for the saved-capture → C++ project →
    indexed workflow on Nsight 2026.1.0.

    Steps:

    1. Pick the newest installed Nsight version whose Generate C++
       Capture activity still supports ``api`` (default ``d3d12``).
    2. Compatibility-check the source capture against the picked
       install (reads ``MetaData.NsightVersion`` from the TOC; no
       replayer invocation).
    3. If a recapture is required, launch the picked install's
       ``ngfx-capture.exe`` with a deterministic trigger (defaults to
       the source capture's ``CaptureBeginFrame`` so the same scene is
       recaptured). The application exits via
       ``--terminate-after-capture``.
    4. Run ``ngfx_cpp_capture_against_replay`` on the resulting
       (now-compatible) capture, which emits a C++ project and indexes
       it via ``cpp_capture_parser`` + ``pso_resolver``.

    Pass ``run_cpp_capture=False`` to stop after step 3 — useful when
    you want to inspect the recaptured artifact before committing to
    the C++ project generation.
    """
    try:
        _, path = _resolve_capture(capture)
        plan = await cpp_capture.cpp_capture_full_autonomy(
            path,
            install_root=Path(install_root) if install_root else None,
            api_hint=api,
            frame=frame,
            countdown_ms=countdown_ms,
            output_capture_path=Path(output_capture_path) if output_capture_path else None,
            output_cpp_dir=Path(output_cpp_dir) if output_cpp_dir else None,
            terminate_after_capture=terminate_after_capture,
            timeout_sec=timeout_sec,
            index_psos=index_psos,
            force_index=force_index,
        )
        if not plan.get("ok"):
            return plan
        if not run_cpp_capture:
            return plan
        next_step = plan["chain"].get("next_step", {})
        next_args = next_step.get("args", {})
        cpp_input = next_args.get("capture")
        if not cpp_input:
            return {"ok": False, "stage": "chain", "error": "no cpp_input_capture", "plan": plan}
        cpp_result = await ngfx_cpp_capture_against_replay(
            capture=cpp_input,
            output_dir=next_args.get("output_dir"),
            auto_index=True,
            index_psos=next_args.get("index_psos", True),
            force_index=next_args.get("force_index", False),
        )
        plan["chain"]["cpp_capture"] = cpp_result
        plan["ok"] = bool(cpp_result.get("ok"))
        return plan
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_cpp_capture_recapture_plan(
    capture: str,
    install_root: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Emit the ``ngfx-capture.exe`` command that re-captures the original
    application using the picked install's capture toolchain.

    The plan is derived from the saved capture's recorded
    ``MetaData.ProcessFileName`` and ``MetaData.ProcessCommandLine`` — no
    guesswork required. Returns the planned argv plus a shell-ready
    command string. Does **not** invoke ``ngfx-capture.exe`` itself: the
    user must launch the recapture interactively because the application
    needs to be driven to the same scene where the bug reproduces.

    Use this after ``ngfx_cpp_capture_compatibility_check`` returns
    ``recapture_required: True`` (i.e., when the saved capture was made
    with a newer Nsight than the installed C++-Capture-capable version).
    """
    try:
        _, path = _resolve_capture(capture)
        return cpp_capture.recapture_with_picked_install_plan(
            path,
            Path(install_root),
            Path(output_path) if output_path else None,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_cpp_capture_compatibility_check(
    capture: str,
    replayer_install_root: str,
) -> dict[str, Any]:
    """Check whether a saved capture is replayable by a given install's
    ``ngfx-replay.exe``.

    Compares the capture's recorded ``Nsight Version`` (from
    ``ngfx-replay --metadata``) against the replayer's version. Forward
    compatibility (older capture → newer replayer) is officially
    supported; the reverse is not — at runtime the older replayer fails
    with ``Unexpected D3D12_FEATURE value: NN``.

    When this returns ``recapture_required: true``, the workflow needs
    to re-run the application with the picked install's ``ngfx-capture.exe``
    to produce a compatible artifact before the C++ Capture flow can run.
    """
    try:
        _, path = _resolve_capture(capture)
        return cpp_capture.capture_replayer_compatibility(
            path, Path(replayer_install_root),
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_cpp_capture_pick_install(
    api: str = "d3d12",
    install_roots: list[str] | None = None,
) -> dict[str, Any]:
    """Pick the newest installed Nsight Graphics version whose Generate C++
    Capture activity still supports ``api`` (``"d3d12"`` or ``"vulkan"``).

    Background: NVIDIA removed D3D11/D3D12 C++ Capture export in Nsight
    Graphics 2026.1.0 (the activity now errors with "Serializing apps to
    C++ capture using D3D11 or D3D12 is no longer supported"). The
    release-notes mapping is in
    :data:`cpp_capture.D3D_CPP_CAPTURE_STATUS_BY_VERSION`.

    If ``install_roots`` is omitted, every Nsight Graphics install detected
    on this machine is considered. When no installed version supports the
    requested API, the ``rationale`` field names the smallest concrete
    follow-up (typically installing Nsight Graphics 2025.5 alongside).
    """
    try:
        if install_roots:
            roots = [Path(r) for r in install_roots]
        else:
            roots = [Path(r) for r in discover_install_roots()]
        return cpp_capture.pick_cpp_capture_capable_install(roots, api_hint=api)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_cpp_capture_route_probe(
    install_root: str | None = None,
) -> dict[str, Any]:
    """Probe the installed Nsight to decide which saved-capture → C++ project
    route is alive in this version.

    Read-only diagnostic: runs ``ngfx.exe --help`` / ``--help-all``,
    scans ``ngfx*.exe`` and every plugin DLL for the relevant marker
    strings, and classifies each documented route as alive or blocked
    with the evidence inline. Returns a ``recommended_route`` field
    naming the most direct path that's actually available.

    Routes considered:

    - ``cli_live_app`` — the original CLI activity (requires re-running
      the app).
    - ``replay_attach`` — launch ``Generate C++ Capture`` against
      ``ngfx-replay.exe`` replaying the saved capture (mirrors the
      ``ngfx_gputrace_capture_replay`` pattern; works without a live app
      and without the UI menu).
    - ``ui_menu_saved_capture`` — the saved-capture menu item that
      was present in older Nsight versions. **Confirmed absent in 2026.1.0**
      (only Launch / Attach labels exist).
    - ``pylon_in_process_activity_manager`` — call
      ``IPlatformActivityManager``/``IPylonReplayFusionActivity`` directly
      via Frida injection into ``ngfx-ui.exe`` (symbols present, entry
      point not exposed externally).
    - ``direct_binaryreplay_rpc`` — invoke ``RequestGenerateCapture``
      over the TPS named pipe; blocked on Gap 1 (BinaryReplay session
      handshake).
    - ``direct_capture_functioninfo_decode`` — version-proof; depends
      on the (pending) FunctionInfo per-event arg decoder.
    """
    try:
        s = get_settings()
        root = Path(install_root) if install_root else s.install_root
        if root is None:
            return {"ok": False, "error": "no Nsight install resolved; set NSIGHT_GRAPHICS_MCP_INSTALL_ROOT or pass install_root"}
        return cpp_capture.saved_capture_route_probe(root)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_cpp_capture_against_replay(
    capture: str,
    output_dir: str | None = None,
    wait_frames: int | None = 1,
    wait_seconds: int | None = None,
    wait_hotkey: bool = False,
    enable_vksc: bool = False,
    no_block_on_incompatibility: bool = True,
    enable_dx12_application_specific_driver_state: bool = True,
    present_hidden: bool = True,
    loop_count: int = 1,
    replay_extra_args: list[str] | None = None,
    no_timeout: bool = True,
    verbose: bool = False,
    background: bool = False,
    auto_index: bool = True,
    index_psos: bool = True,
    force_index: bool = False,
) -> dict[str, Any]:
    """Run ``Generate C++ Capture`` against ``ngfx-replay.exe`` replaying a
    saved capture — the saved-capture → C++ project autonomy path that
    works in Nsight 2026.1.0.

    Background: the original "open saved capture → File menu →
    Generate C++ Capture" path is gone in 2026.1.0 (the UI menu strings
    confirm only ``Launch for Generate C++ Capture`` and
    ``Attach for Generate C++ Capture``). The ``Generate C++ Capture``
    activity backend itself is still alive, so we re-use the
    ``ngfx_gputrace_capture_replay`` trick: replay the saved capture via
    ``ngfx-replay.exe`` and attach the activity to that process.

    By default it waits 1 frame, then captures, then exits — adjust
    ``wait_frames`` / ``wait_seconds`` / ``wait_hotkey`` as needed.

    When ``auto_index`` is true (default) the emitted C++ project is fed
    straight into ``cpp_capture_parser.index_cpp_project`` and
    ``pso_resolver.index_project_psos`` so the downstream resolution
    tools (e.g. ``ngfx_copyrect_t0_resolution_report``) work without an
    extra step.
    """
    _, path = _resolve_capture(capture)
    s = get_settings()
    replay = s.require_tool("ngfx_replay")
    out = output_dir or str(events_mod._cache_root_for(path) / "cpp_capture_replay")
    Path(out).mkdir(parents=True, exist_ok=True)

    replay_args: list[str] = []
    if no_block_on_incompatibility:
        replay_args.append("--no-block-on-incompatibility")
    if enable_dx12_application_specific_driver_state:
        replay_args.append("--enable-dx12-application-specific-driver-state")
    if present_hidden:
        replay_args.append("--present-hidden")
    if loop_count > 0:
        replay_args.extend(["-n", str(loop_count)])
    if replay_extra_args:
        replay_args.extend(replay_extra_args)
    replay_args.append(str(path))

    launched = await ngfx_cpp_capture_launched(
        exe=str(replay),
        args=subprocess.list2cmdline(replay_args),
        working_dir=str(path.parent),
        output_dir=out,
        wait_frames=wait_frames,
        wait_seconds=wait_seconds,
        wait_hotkey=wait_hotkey,
        enable_vksc=enable_vksc,
        no_timeout=no_timeout,
        verbose=verbose,
        background=background,
    )
    if background or not auto_index:
        return launched

    # Foreground path: wait for the project and validate it.
    project_dir = Path(out)
    project = cpp_capture.find_solution(project_dir)
    if project is None:
        return {
            "ok": False,
            "error": (
                "C++ Capture activity ran but no .sln was produced under "
                f"{project_dir}; inspect launched.stdout / launched.stderr."
            ),
            "launched": launched,
        }

    validation = await cpp_capture.validate_cpp_capture_export(
        project.parent,
        capture=path,
        index_calls=True,
        index_psos=index_psos,
        force_index=force_index,
    )
    return {
        "ok": validation.get("ok", False),
        "mode": "replay_attach",
        "capture": str(path),
        "output_dir": str(project_dir),
        "project_path": str(project),
        "launched": launched,
        "validation": validation,
    }


@mcp.tool()
async def ngfx_cpp_capture_saved_ui_automation_attempt(
    capture: str,
    output_dir: str,
    timeout_sec: float = 120.0,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Best-effort pywinauto UI fallback for saved-capture C++ export."""
    try:
        return await cpp_capture.saved_capture_ui_automation_attempt(
            Path(capture),
            Path(output_dir),
            timeout_sec=timeout_sec,
            dry_run=dry_run,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_cpp_capture_saved_headless_attempt(
    capture: str,
    output_dir: str | None = None,
    additional_args: list[str] | None = None,
    environment: dict[str, str] | None = None,
    rpc_session_handle: str | None = None,
    backends: list[str] | None = None,
    wait_for_project: bool = False,
    launch_ui_fallback: bool = True,
    timeout_sec: float = 900.0,
    index_calls: bool = True,
    index_psos: bool = True,
    force_index: bool = False,
) -> dict[str, Any]:
    """Try all known saved-capture -> C++ export routes, then validate output.

    Backends are ``pylon_private_activity_manager``,
    ``direct_frame_debugger_rpc``, and ``ui_automation``. Private backends
    return structured blockers until their remaining NVIDIA-internal binding
    is solved; any existing or newly detected project is validated and indexed.
    """
    try:
        return await cpp_capture.saved_capture_headless_attempt(
            Path(capture),
            output_dir=Path(output_dir) if output_dir else None,
            additional_args=additional_args,
            environment=environment,
            rpc_session_handle=rpc_session_handle,
            backends=backends,
            wait_for_project=wait_for_project,
            launch_ui_fallback=launch_ui_fallback,
            timeout_sec=timeout_sec,
            index_calls=index_calls,
            index_psos=index_psos,
            force_index=force_index,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_cpp_capture_saved_artifact_bundle(
    out_zip: str,
    capture: str | None = None,
    project_dir: str | None = None,
    validation: dict[str, Any] | None = None,
    extra_files: list[str] | None = None,
    include_project_sources: bool = False,
) -> dict[str, Any]:
    """Bundle capture/export validation artifacts into one zip."""
    try:
        return cpp_capture.bundle_saved_capture_artifacts(
            Path(out_zip),
            capture=Path(capture) if capture else None,
            project_dir=Path(project_dir) if project_dir else None,
            validation=validation,
            extra_files=[Path(p) for p in (extra_files or [])],
            include_project_sources=include_project_sources,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_shader_fix_regression_score(
    before_score: float,
    after_score: float,
    repeated_runs: int = 1,
    left_eye_delta: float | None = None,
    event_sequence_match_ratio: float | None = None,
    pso_coverage_ratio: float | None = None,
    min_improvement: float = 0.25,
    max_left_eye_delta: float = 0.03,
    min_event_sequence_match: float = 0.98,
    min_pso_coverage: float = 0.95,
) -> dict[str, Any]:
    """Score whether a shader-fix run is acceptable or regressed."""
    return cpp_capture.shader_fix_regression_score(
        before_score=before_score,
        after_score=after_score,
        repeated_runs=repeated_runs,
        left_eye_delta=left_eye_delta,
        event_sequence_match_ratio=event_sequence_match_ratio,
        pso_coverage_ratio=pso_coverage_ratio,
        min_improvement=min_improvement,
        max_left_eye_delta=max_left_eye_delta,
        min_event_sequence_match=min_event_sequence_match,
        min_pso_coverage=min_pso_coverage,
    )


@mcp.tool()
async def ngfx_shader_debug_re_status() -> dict[str, Any]:
    """Report whether the IDA facts needed for MCP-driven shader debugging are cached.

    This ties together the RE targets that matter for automating shader fixes:
    ``ngfx-rpc`` session setup, frame-debugger pixel/resource/shader services,
    D3D12/Vulkan state panes, and replay metadata/screenshot/resource paths.
    """
    try:
        return shader_debug_mod.reverse_engineering_status()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Shader visual-bug triage orchestration
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_shader_triage_plan(
    issue: str | None = None,
    handoff_path: str | None = None,
    suspect_pso: str | None = None,
    suspect_shader_crc32: str | None = None,
) -> dict[str, Any]:
    """Return the concrete MCP workflow for localising and fixing a shader visual bug.

    The plan is evidence-oriented: capture/index first, classify left/right work,
    locate the first bad event, trace bound resources, then generate targeted
    shader probes or a SetPipelineState swap harness.
    """
    return shader_triage_mod.shader_triage_plan(
        issue=issue,
        handoff_path=handoff_path,
        suspect_pso=suspect_pso,
        suspect_shader_crc32=suspect_shader_crc32,
    )


@mcp.tool()
async def ngfx_eye_event_index(
    db_path: str,
    start: int | None = None,
    end: int | None = None,
    left_patterns: list[str] | None = None,
    right_patterns: list[str] | None = None,
    render_width: float | None = None,
    right_half_min_x: float | None = None,
    include_state_events: bool = False,
    limit: int = 2000,
) -> dict[str, Any]:
    """Classify C++-capture events as left/right/both/unknown.

    Requires ``ngfx_cpp_capture_index_calls`` output. Classification uses
    caller-provided regexes, known stereo words, viewport/scissor numeric hints,
    and inherited state from the latest classified state call.
    """
    try:
        return shader_triage_mod.eye_event_index(
            Path(db_path),
            start=start,
            end=end,
            left_patterns=left_patterns,
            right_patterns=right_patterns,
            render_width=render_width,
            right_half_min_x=right_half_min_x,
            include_state_events=include_state_events,
            limit=limit,
        )
    except (FileNotFoundError, ValueError, sqlite3.Error) as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_compare_eye_passes(
    db_path: str,
    start: int | None = None,
    end: int | None = None,
    left_patterns: list[str] | None = None,
    right_patterns: list[str] | None = None,
    render_width: float | None = None,
    right_half_min_x: float | None = None,
    limit: int = 4000,
) -> dict[str, Any]:
    """Compare left/right draw/dispatch/copy counts from a C++-capture index."""
    try:
        return shader_triage_mod.compare_eye_passes(
            Path(db_path),
            start=start,
            end=end,
            left_patterns=left_patterns,
            right_patterns=right_patterns,
            render_width=render_width,
            right_half_min_x=right_half_min_x,
            limit=limit,
        )
    except (FileNotFoundError, ValueError, sqlite3.Error) as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_find_missing_eye_dispatches(
    db_path: str,
    start: int | None = None,
    end: int | None = None,
    left_patterns: list[str] | None = None,
    right_patterns: list[str] | None = None,
    render_width: float | None = None,
    right_half_min_x: float | None = None,
    limit: int = 4000,
) -> dict[str, Any]:
    """Find dispatch/ray-tracing asymmetries between classified eyes."""
    try:
        return shader_triage_mod.find_missing_eye_dispatches(
            Path(db_path),
            start=start,
            end=end,
            left_patterns=left_patterns,
            right_patterns=right_patterns,
            render_width=render_width,
            right_half_min_x=right_half_min_x,
            limit=limit,
        )
    except (FileNotFoundError, ValueError, sqlite3.Error) as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_event_state(
    db_path: str,
    event_index: int,
    lookback: int = 500,
    context: int = 8,
) -> dict[str, Any]:
    """Return a draw/dispatch event, nearby calls, bound descriptors, and PSO info."""
    try:
        return shader_triage_mod.event_state(
            Path(db_path),
            event_index,
            lookback=lookback,
            context=context,
        )
    except (FileNotFoundError, ValueError, sqlite3.Error) as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_trace_resource_lineage(
    db_path: str,
    resource: str,
    event_index: int | None = None,
    window: int | None = None,
    max_mentions: int = 300,
) -> dict[str, Any]:
    """Find C++-capture calls that mention a resource/symbol and bucket by role."""
    try:
        return shader_triage_mod.trace_resource_lineage(
            Path(db_path),
            resource,
            event_index=event_index,
            window=window,
            max_mentions=max_mentions,
        )
    except (FileNotFoundError, ValueError, sqlite3.Error) as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_pso_bind_trace(
    db_path: str,
    pso_symbol: str | None = None,
    shader_hash: str | None = None,
    shader_toggler_crc32: str | None = None,
    pso_contains: str | None = None,
    lookahead: int = 40,
    limit: int = 200,
) -> dict[str, Any]:
    """Trace SetPipelineState/vkCmdBindPipeline and following draw/dispatch work."""
    try:
        return shader_triage_mod.pso_bind_trace(
            Path(db_path),
            pso_symbol=pso_symbol,
            shader_hash=shader_hash,
            shader_toggler_crc32=shader_toggler_crc32,
            pso_contains=pso_contains,
            lookahead=lookahead,
            limit=limit,
        )
    except (FileNotFoundError, ValueError, sqlite3.Error) as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_pso_swap_harness_plan(
    suspect_pso_label: str | None = None,
    suspect_shader_crc32: str | None = None,
    patched_pso_label: str = "g_sn2PatchedPso",
    right_eye_predicate: str | None = None,
    output_dir: str | None = None,
) -> dict[str, Any]:
    """Generate a D3D12 draw-time PSO swap harness plan and optional C++ files.

    Use this when creation hooks miss a suspect graphics PSO but the runtime
    hook can still see SetPipelineState and draw/dispatch calls.
    """
    try:
        return shader_triage_mod.pso_swap_harness_plan(
            suspect_pso_label=suspect_pso_label,
            suspect_shader_crc32=suspect_shader_crc32,
            patched_pso_label=patched_pso_label,
            right_eye_predicate=right_eye_predicate,
            output_dir=output_dir,
        )
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_shader_probe_plan(
    shader_name: str | None = None,
    pseudocode_path: str | None = None,
    suspect_terms: list[str] | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Generate a targeted shader-probe plan for suspect terms such as t5/t8/t9."""
    try:
        return shader_triage_mod.shader_probe_plan(
            shader_name=shader_name,
            pseudocode_path=pseudocode_path,
            suspect_terms=suspect_terms,
            output_path=output_path,
        )
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_shader_bug_triage(
    capture: str | None = None,
    cpp_db: str | None = None,
    handoff_path: str | None = None,
    suspect_pso: str | None = None,
    suspect_shader_hash: str | None = None,
    suspect_shader_crc32: str | None = None,
    pso_contains: str | None = None,
    roi: dict[str, Any] | None = None,
    render_width: float | None = None,
    right_half_min_x: float | None = None,
    limit: int = 4000,
) -> dict[str, Any]:
    """Produce one LLM-ready shader-bug report from capture/index/handoff evidence."""
    return shader_triage_mod.shader_bug_triage(
        capture=capture,
        cpp_db=cpp_db,
        handoff_path=handoff_path,
        suspect_pso=suspect_pso,
        suspect_shader_hash=suspect_shader_hash,
        suspect_shader_crc32=suspect_shader_crc32,
        pso_contains=pso_contains,
        roi=roi,
        render_width=render_width,
        right_half_min_x=right_half_min_x,
        limit=limit,
    )


@mcp.tool()
async def ngfx_sn2_fog_artifacts(runs_dir: str | None = None) -> dict[str, Any]:
    """Locate the latest clean r.Fog on/off and VoxelizePS/VoxelizeGS artifacts for SN2."""
    try:
        return autonomous_fix.sn2_fog_artifacts(runs_dir=runs_dir)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_fog_signal_report(
    fog_on_path: str | None = None,
    fog_off_path: str | None = None,
    ps_shader_path: str | None = None,
    gs_shader_path: str | None = None,
    lead_pso: str | None = None,
    ps_hash: str | None = None,
    gs_hash: str | None = None,
    expected_draw_count: int | None = None,
    expected_left_eye_bucket: int | str | None = None,
) -> dict[str, Any]:
    """Evaluate the clean r.Fog differential for the SN2 VoxelizePS/VoxelizeGS bug."""
    try:
        return autonomous_fix.sn2_fog_signal_report(
            fog_on_path=fog_on_path,
            fog_off_path=fog_off_path,
            ps_shader_path=ps_shader_path,
            gs_shader_path=gs_shader_path,
            lead_pso=lead_pso,
            ps_hash=ps_hash,
            gs_hash=gs_hash,
            expected_draw_count=expected_draw_count,
            expected_left_eye_bucket=expected_left_eye_bucket,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_fog_fix_plan(signal_report: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the autonomous shader/runtime plan for fixing the SN2 clean fog signal."""
    return autonomous_fix.sn2_fog_fix_plan(signal_report=signal_report)


@mcp.tool()
async def ngfx_sn2_fog_descriptor_probe_plan(
    signal_report: dict[str, Any] | None = None,
    event_index: int | None = None,
    resource_handles: list[dict[str, Any] | str | int] | None = None,
    roi: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Build live BinaryReplay requests for resolving SN2 fog descriptor/resource state."""
    try:
        return autonomous_fix.sn2_fog_descriptor_probe_plan(
            signal_report=signal_report,
            event_index=event_index,
            resource_handles=resource_handles,
            roi=roi,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_fog_slot_candidates(
    descriptor_state_reply: dict[str, Any],
    max_candidates_per_slot: int = 10,
) -> dict[str, Any]:
    """Resolve VoxelizeGS/VoxelizePS slots from a live descriptor-state reply."""
    try:
        return autonomous_fix.sn2_fog_slot_candidates(
            descriptor_state_reply,
            max_candidates_per_slot=max_candidates_per_slot,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_fog_probe_manifest(
    signal_report: dict[str, Any] | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Write or return the GS-first SN2 fog probe manifest for the fix loop."""
    try:
        return autonomous_fix.sn2_fog_probe_manifest(
            signal_report=signal_report,
            output_path=output_path,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_fog_live_state_probe(
    session_handle: str | None = None,
    event_index: int | None = None,
    include_resource_history: bool = False,
    include_resource_info: bool = True,
    max_resource_handles: int = 24,
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """Collect live Nsight state for one SN2 fog lead-draw BinaryReplay event."""
    plan = autonomous_fix.sn2_fog_descriptor_probe_plan(event_index=event_index)
    if not session_handle or event_index is None:
        return {
            "ok": False,
            "preview_only": True,
            "error": "session_handle and event_index are required for live probing",
            "plan": plan,
        }
    try:
        sess = frame_debugger_rpc_mod.get_session(session_handle)
        replies: dict[str, Any] = {}
        errors: list[dict[str, Any]] = []

        calls = [
            ("event_details", sess.client.event_details),
            ("api_inspector_state", sess.client.api_inspector_state),
            ("root_parameters", sess.client.root_parameters),
            ("descriptor_state", sess.client.descriptor_state),
        ]
        for name, fn in calls:
            try:
                reply = fn(event_index, timeout=timeout_sec)
                replies[name] = rpc_client.protobuf_to_dict(reply)
            except Exception as exc:
                errors.append({"call": name, "error": f"{type(exc).__name__}: {exc}"})

        descriptor_reply = replies.get("descriptor_state", {})
        slot_candidates = (
            autonomous_fix.sn2_fog_slot_candidates({"reply": descriptor_reply})
            if descriptor_reply
            else {"ok": False, "error": "descriptor_state call did not return a reply"}
        )
        handles = autonomous_fix.resource_handles_from_state({"reply": replies}, max_handles=max_resource_handles)
        resource_results = []
        if handles and (include_resource_history or include_resource_info):
            for handle in handles[:max_resource_handles]:
                item: dict[str, Any] = {"handle": handle}
                try:
                    if include_resource_info:
                        info = sess.client.resource_info(
                            accessor=int(handle["accessor"]),
                            misc=int(handle.get("misc", 0)),
                            timeout=timeout_sec,
                        )
                        item["resource_info"] = rpc_client.protobuf_to_dict(info)
                    if include_resource_history:
                        history = sess.client.resource_access_history(
                            accessor=int(handle["accessor"]),
                            misc=int(handle.get("misc", 0)),
                            timeout=timeout_sec,
                        )
                        item["resource_history"] = rpc_client.protobuf_to_dict(history)
                        item["revision_at_event"] = rpc_client.resource_revision_from_history(history, event_index)
                except Exception as exc:
                    item["error"] = f"{type(exc).__name__}: {exc}"
                resource_results.append(item)

        sess.last_error = errors[-1]["error"] if errors else None
        return {
            "ok": not errors,
            "session": sess.summary(),
            "event_index": event_index,
            "plan": plan,
            "replies": replies,
            "errors": errors,
            "slot_candidates": slot_candidates,
            "resource_handles": handles,
            "resource_results": resource_results,
        }
    except Exception as exc:
        return {"ok": False, "plan": plan, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_copyrect_artifacts(runs_dir: str | None = None, ps_hash: str | None = None) -> dict[str, Any]:
    """Locate SN2 CopyRectPS trace and shader-inspection artifacts."""
    try:
        return autonomous_fix.sn2_copyrect_artifacts(runs_dir=runs_dir, ps_hash=ps_hash)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_copyrect_signal_report(
    trace_path: str | None = None,
    shader_path: str | None = None,
    ps_hash: str | None = None,
    ps_crc32: str | None = None,
    ps_entry: str | None = None,
) -> dict[str, Any]:
    """Trace CopyRectPS source texture, destination target, and producer evidence."""
    try:
        return autonomous_fix.sn2_copyrect_signal_report(
            trace_path=trace_path,
            shader_path=shader_path,
            ps_hash=ps_hash,
            ps_crc32=ps_crc32,
            ps_entry=ps_entry,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_copyrect_fix_plan(signal_report: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the Nsight-driven fix plan for the SN2 CopyRectPS path."""
    return autonomous_fix.sn2_copyrect_fix_plan(signal_report=signal_report)


@mcp.tool()
async def ngfx_sn2_copyrect_descriptor_probe_plan(
    signal_report: dict[str, Any] | None = None,
    event_index: int | None = None,
    resource_handles: list[dict[str, Any] | str | int] | None = None,
    roi: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Build live BinaryReplay requests for resolving CopyRectPS t0/s0 and target state."""
    try:
        return autonomous_fix.sn2_copyrect_descriptor_probe_plan(
            signal_report=signal_report,
            event_index=event_index,
            resource_handles=resource_handles,
            roi=roi,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_copyrect_slot_candidates(
    descriptor_state_reply: dict[str, Any],
    max_candidates_per_slot: int = 10,
) -> dict[str, Any]:
    """Resolve CopyRectPS t0/s0 slots from a live descriptor-state reply."""
    try:
        return autonomous_fix.sn2_copyrect_slot_candidates(
            descriptor_state_reply,
            max_candidates_per_slot=max_candidates_per_slot,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_copyrect_t0_source_compare(
    left_probe: dict[str, Any],
    right_probe: dict[str, Any],
    max_candidates_per_slot: int = 10,
) -> dict[str, Any]:
    """Compare live left/right CopyRectPS PS t0 resources after descriptor-state resolution."""
    try:
        return autonomous_fix.sn2_copyrect_t0_source_compare(
            left_probe,
            right_probe,
            max_candidates_per_slot=max_candidates_per_slot,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_copyrect_pair_analysis(
    signal_report: dict[str, Any] | None = None,
    trace_path: str | None = None,
    ps_hash: str | None = None,
    max_pairs: int = 12,
) -> dict[str, Any]:
    """Compare left/right CopyRectPS draws and emit concrete Nsight live-probe targets."""
    try:
        return autonomous_fix.sn2_copyrect_pair_analysis(
            signal_report=signal_report,
            trace_path=trace_path,
            ps_hash=ps_hash,
            max_pairs=max_pairs,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_copyrect_right_eye_issue_report(
    signal_report: dict[str, Any] | None = None,
    trace_path: str | None = None,
    ps_hash: str | None = None,
    max_pairs: int = 24,
) -> dict[str, Any]:
    """Report the strongest same-frame CopyRectPS evidence for the SN2 right-eye bug."""
    try:
        return autonomous_fix.sn2_copyrect_right_eye_issue_report(
            signal_report=signal_report,
            trace_path=trace_path,
            ps_hash=ps_hash,
            max_pairs=max_pairs,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_copyrect_source_lineage_report(
    signal_report: dict[str, Any] | None = None,
    trace_path: str | None = None,
    ps_hash: str | None = None,
    max_pairs: int = 24,
    max_records: int = 64,
) -> dict[str, Any]:
    """Mine saved CopyRectPS resource lineage while preserving the table-scan descriptor caveat."""
    try:
        return autonomous_fix.sn2_copyrect_source_lineage_report(
            signal_report=signal_report,
            trace_path=trace_path,
            ps_hash=ps_hash,
            max_pairs=max_pairs,
            max_records=max_records,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_copyrect_runtime_instrumentation_plan(
    trace_path: str | None = None,
    signal_report: dict[str, Any] | None = None,
    issue_report: dict[str, Any] | None = None,
    ps_hash: str | None = None,
) -> dict[str, Any]:
    """Return the runtime hook manifest for proving CopyRectPS t0 and rect state."""
    try:
        return autonomous_fix.sn2_copyrect_runtime_instrumentation_plan(
            trace_path=trace_path,
            signal_report=signal_report,
            issue_report=issue_report,
            ps_hash=ps_hash,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_copyrect_live_state_probe(
    session_handle: str | None = None,
    event_index: int | None = None,
    include_resource_history: bool = True,
    include_resource_info: bool = True,
    max_resource_handles: int = 24,
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """Collect live Nsight state for one SN2 CopyRectPS BinaryReplay event."""
    plan = autonomous_fix.sn2_copyrect_descriptor_probe_plan(event_index=event_index)
    if not session_handle or event_index is None:
        return {
            "ok": False,
            "preview_only": True,
            "error": "session_handle and event_index are required for live probing",
            "plan": plan,
        }
    try:
        sess = frame_debugger_rpc_mod.get_session(session_handle)
        replies: dict[str, Any] = {}
        errors: list[dict[str, Any]] = []
        calls = [
            ("event_details", sess.client.event_details),
            ("api_inspector_state", sess.client.api_inspector_state),
            ("root_parameters", sess.client.root_parameters),
            ("descriptor_state", sess.client.descriptor_state),
        ]
        for name, fn in calls:
            try:
                reply = fn(event_index, timeout=timeout_sec)
                replies[name] = rpc_client.protobuf_to_dict(reply)
            except Exception as exc:
                errors.append({"call": name, "error": f"{type(exc).__name__}: {exc}"})

        descriptor_reply = replies.get("descriptor_state", {})
        slot_candidates = (
            autonomous_fix.sn2_copyrect_slot_candidates({"reply": descriptor_reply})
            if descriptor_reply
            else {"ok": False, "error": "descriptor_state call did not return a reply"}
        )
        handles = autonomous_fix.resource_handles_from_state({"reply": replies}, max_handles=max_resource_handles)
        resource_results = []
        if handles and (include_resource_history or include_resource_info):
            for handle in handles[:max_resource_handles]:
                item: dict[str, Any] = {"handle": handle}
                try:
                    if include_resource_info:
                        info = sess.client.resource_info(
                            accessor=int(handle["accessor"]),
                            misc=int(handle.get("misc", 0)),
                            timeout=timeout_sec,
                        )
                        item["resource_info"] = rpc_client.protobuf_to_dict(info)
                    if include_resource_history:
                        history = sess.client.resource_access_history(
                            accessor=int(handle["accessor"]),
                            misc=int(handle.get("misc", 0)),
                            timeout=timeout_sec,
                        )
                        item["resource_history"] = rpc_client.protobuf_to_dict(history)
                        item["revision_at_event"] = rpc_client.resource_revision_from_history(history, event_index)
                except Exception as exc:
                    item["error"] = f"{type(exc).__name__}: {exc}"
                resource_results.append(item)

        sess.last_error = errors[-1]["error"] if errors else None
        return {
            "ok": not errors,
            "session": sess.summary(),
            "event_index": event_index,
            "plan": plan,
            "replies": replies,
            "errors": errors,
            "slot_candidates": slot_candidates,
            "resource_handles": handles,
            "resource_results": resource_results,
        }
    except Exception as exc:
        return {"ok": False, "plan": plan, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_sn2_copyrect_live_pair_probe(
    session_handle: str | None = None,
    left_event_index: int | None = None,
    right_event_index: int | None = None,
    roi: dict[str, int] | None = None,
    include_resource_history: bool = True,
    include_resource_info: bool = True,
    include_t0_revision: bool = True,
    max_resource_handles: int = 24,
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """Probe paired left/right CopyRectPS events and resolve whether actual PS t0 matches."""
    preview = {
        "left_plan": autonomous_fix.sn2_copyrect_descriptor_probe_plan(event_index=left_event_index),
        "right_plan": autonomous_fix.sn2_copyrect_descriptor_probe_plan(event_index=right_event_index),
        "roi": roi,
        "pair_steps": [
            "Collect live descriptor/root/event state for the left CopyRect event.",
            "Collect live descriptor/root/event state for the right CopyRect event.",
            "Resolve CopyRectPS PS t0 on both events from descriptor_state.",
            "If t0 matches, trace the shared source revision at the right CopyRect event.",
            "If t0 differs, focus on graphics root CBV/view-rect constants and destination state.",
        ],
    }
    if not session_handle or left_event_index is None or right_event_index is None:
        return {
            "ok": False,
            "preview_only": True,
            "error": "session_handle, left_event_index, and right_event_index are required",
            **preview,
        }

    left_probe = await ngfx_sn2_copyrect_live_state_probe(
        session_handle=session_handle,
        event_index=left_event_index,
        include_resource_history=include_resource_history,
        include_resource_info=include_resource_info,
        max_resource_handles=max_resource_handles,
        timeout_sec=timeout_sec,
    )
    right_probe = await ngfx_sn2_copyrect_live_state_probe(
        session_handle=session_handle,
        event_index=right_event_index,
        include_resource_history=include_resource_history,
        include_resource_info=include_resource_info,
        max_resource_handles=max_resource_handles,
        timeout_sec=timeout_sec,
    )
    compare = autonomous_fix.sn2_copyrect_t0_source_compare(left_probe, right_probe)
    t0_revision_results: list[dict[str, Any]] = []
    if include_t0_revision and session_handle and compare.get("ok"):
        try:
            sess = frame_debugger_rpc_mod.get_session(session_handle)
            t0_handles = _copyrect_t0_handles_from_compare(compare)
            seen_handles: set[tuple[int, int]] = set()
            for handle in t0_handles:
                accessor = _safe_int(handle.get("accessor"))
                misc = _safe_int(handle.get("misc")) or 0
                if accessor is None or (accessor, misc) in seen_handles:
                    continue
                seen_handles.add((accessor, misc))
                item: dict[str, Any] = {"handle": handle, "accessor": accessor, "misc": misc}
                try:
                    if include_resource_info:
                        info = sess.client.resource_info(accessor=accessor, misc=misc, timeout=timeout_sec)
                        item["resource_info"] = rpc_client.protobuf_to_dict(info)
                    if include_resource_history:
                        history = sess.client.resource_access_history(accessor=accessor, misc=misc, timeout=timeout_sec)
                        item["resource_history"] = rpc_client.protobuf_to_dict(history)
                        item["revision_at_left_event"] = rpc_client.resource_revision_from_history(history, left_event_index)
                        item["revision_at_right_event"] = rpc_client.resource_revision_from_history(history, right_event_index)
                except Exception as exc:
                    item["error"] = f"{type(exc).__name__}: {exc}"
                t0_revision_results.append(item)
        except Exception as exc:
            t0_revision_results.append({"error": f"{type(exc).__name__}: {exc}"})

    return {
        "ok": bool(left_probe.get("ok") and right_probe.get("ok")),
        "session_handle": session_handle,
        "left_event_index": left_event_index,
        "right_event_index": right_event_index,
        "roi": roi,
        "verdict": compare.get("verdict"),
        "t0_compare": compare,
        "t0_revision_results": t0_revision_results,
        "left_probe": left_probe,
        "right_probe": right_probe,
        "next_branch": _copyrect_live_pair_next_branch(compare),
    }


@mcp.tool()
async def ngfx_eye_issue_event_signatures(
    capture: str | None = None,
    functions_db: str | None = None,
    start: int | None = None,
    end: int | None = None,
    target_kinds: list[str] | None = None,
    lookback_state_count: int = 12,
    max_pair_delta: int = 250,
    limit: int = 5000,
) -> dict[str, Any]:
    """Find candidate stereo event pairs from a saved Nsight function stream."""
    try:
        if functions_db:
            db_path = Path(functions_db)
        elif capture:
            _, cap_path = _resolve_capture(capture)
            db_path = events_mod._cache_root_for(cap_path) / "functions.db"
        else:
            return {"ok": False, "error": "supply capture or functions_db"}
        if not db_path.is_file():
            return {
                "ok": False,
                "error": f"functions.db not found: {db_path}",
                "next_tool": "ngfx_index_events",
                "next_arguments": {"capture": capture} if capture else None,
            }
        return eye_issue_mod.event_signature_index(
            db_path,
            start=start,
            end=end,
            target_kinds=target_kinds,
            lookback_state_count=lookback_state_count,
            max_pair_delta=max_pair_delta,
            limit=limit,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_eye_issue_dump_report(
    capture: str,
    roi: dict[str, int] | None = None,
    suspect_shader_name: str = "CopyRectPS",
    suspect_shader_hash: str | None = "98acf00f2001c218",
    render_width: int | None = None,
    include_shader_chunk_scan: bool = False,
    shader_chunk_max_hits: int = 20,
    force_index_hint: bool = False,
) -> dict[str, Any]:
    """Summarize dump-only evidence, blockers, and next Nsight-only actions for the eye issue."""
    try:
        _, path = _resolve_capture(capture)
        return eye_issue_mod.dump_only_eye_issue_report(
            path,
            roi=roi,
            suspect_shader_name=suspect_shader_name,
            suspect_shader_hash=suspect_shader_hash,
            render_width=render_width,
            include_shader_chunk_scan=include_shader_chunk_scan,
            shader_chunk_max_hits=shader_chunk_max_hits,
            force_index_hint=force_index_hint,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_resource_write_history(
    cpp_project_dir: str,
    resource_sym: str,
    cpp_db_path: str | None = None,
    include_clear: bool = True,
) -> dict[str, Any]:
    """Return every write to ``resource_sym`` in event order — render-target
    binds, compute UAV writes via Dispatch, copy destinations, and
    Clear*View/DiscardResource calls.

    Combined with ``ngfx_resource_producer_lineage`` (which only follows
    graphics OMSetRenderTargets), this surfaces the FULL set of writers
    including the compute and copy paths that the graphics chain misses.
    """
    try:
        return eye_issue_mod.resource_write_history(
            cpp_project_dir=Path(cpp_project_dir),
            cpp_db_path=Path(cpp_db_path) if cpp_db_path else None,
            resource_sym=resource_sym,
            include_clear=include_clear,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_resource_write_history_pair_diff(
    cpp_project_dir: str,
    left_resource_sym: str,
    right_resource_sym: str,
    cpp_db_path: str | None = None,
) -> dict[str, Any]:
    """Diff the write timelines for a LEFT/RIGHT resource pair.

    Surfaces where one eye has writes the other doesn't — copy paths,
    extra clears, UAV-via-Dispatch writes, etc. Most useful when the
    graphics producer chain bottoms out at a resource that's actually
    written via Dispatch or Copy.
    """
    try:
        return eye_issue_mod.resource_write_history_pair_diff(
            cpp_project_dir=Path(cpp_project_dir),
            cpp_db_path=Path(cpp_db_path) if cpp_db_path else None,
            left_resource_sym=left_resource_sym,
            right_resource_sym=right_resource_sym,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_resource_producer_lineage(
    cpp_project_dir: str,
    seed_resource_sym: str,
    cpp_db_path: str | None = None,
    max_depth: int = 4,
    max_inputs_per_level: int = 6,
) -> dict[str, Any]:
    """Recursively trace which draws produced a given render-target resource,
    walking the producer chain backwards through SRV inputs.

    Given a seed resource symbol (e.g. ``NVD3D12MultiBufferedArray_of_ID3D12Resource_uid_3561``),
    finds the OMSetRenderTargets event whose RTV points at that resource,
    captures the producer's PSO + root signature + viewport + scissor +
    SRV inputs + CBV references, and recursively walks the SRV inputs as
    new seeds up to ``max_depth`` levels.

    Output is a tree of producer state per resource. Used to walk back
    from CopyRectPS source textures to find where the right-eye image
    actually diverges from the left.
    """
    try:
        return eye_issue_mod.producer_lineage_trace(
            cpp_project_dir=Path(cpp_project_dir),
            cpp_db_path=Path(cpp_db_path) if cpp_db_path else None,
            seed_resource_sym=seed_resource_sym,
            max_depth=max_depth,
            max_inputs_per_level=max_inputs_per_level,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_producer_lineage_pair_diff(
    cpp_project_dir: str,
    left_resource_sym: str,
    right_resource_sym: str,
    cpp_db_path: str | None = None,
    max_depth: int = 4,
) -> dict[str, Any]:
    """Trace LEFT and RIGHT producer lineages and diff them level-by-level.

    For each level the diff reports whether the LEFT and RIGHT eyes use
    the same PSO / root signature / viewport / scissor, and which SRV
    inputs differ. ``first_asymmetric_shader`` (if non-null) names the
    earliest level where shader logic diverges — that's where to look
    for the actual root cause. When every level is symmetric, the bug
    is in a leaf resource's contents or in per-eye CBV byte ranges.

    Typical SN2 usage:
        left_resource_sym  = "NVD3D12MultiBufferedArray_of_ID3D12Resource_uid_3529"
        right_resource_sym = "NVD3D12MultiBufferedArray_of_ID3D12Resource_uid_3561"
    """
    try:
        return eye_issue_mod.producer_lineage_pair_diff(
            cpp_project_dir=Path(cpp_project_dir),
            cpp_db_path=Path(cpp_db_path) if cpp_db_path else None,
            left_resource_sym=left_resource_sym,
            right_resource_sym=right_resource_sym,
            max_depth=max_depth,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_copyrect_t0_resolution_report(
    cpp_project_dir: str,
    cpp_db_path: str | None = None,
    pso_db_path: str | None = None,
    suspect_shader: str = "CopyRectPS",
    max_pairs: int = 4,
    lookback: int = 200,
) -> dict[str, Any]:
    """Resolve actual sampled state for paired left/right CopyRectPS draws.

    Drives the Track A dump-only path: given a UI-generated Generate-C++-Capture
    project (and its cpp_capture_parser + pso_resolver indexes), this tool
    composes:

    * ``pso_resolver`` — finds PSO symbols whose pixel shader is the
      ``suspect_shader``.
    * ``cpp_capture_parser.query_calls`` — finds the SetPipelineState events
      that bind those PSOs and the draws that follow.
    * ``cpp_capture_parser.descriptor_bindings_for_event`` — pulls the
      effective root-signature / descriptor-heap / pipeline / render-target /
      root-parameter state at each draw.

    For each adjacent left/right pair it emits a field-level diff and a
    verdict label: ``different_pipeline``, ``different_source_or_descriptor_routing``,
    ``different_target``, ``different_source_and_target``, or
    ``identical_state_at_draw``.

    Every result section carries an ``evidence_label`` so callers don't
    confuse proven values with candidates. Missing evidence (no PSOs, no
    draws, or identical state) is surfaced explicitly along with the next
    tool to run.

    Both indexes default to the project-directory-local SQLite files written
    by :func:`cpp_capture_parser.index_cpp_project` and
    :func:`pso_resolver.index_project_psos`. Pass ``cpp_db_path`` /
    ``pso_db_path`` to override.
    """
    try:
        return eye_issue_mod.copyrect_t0_resolution_report(
            cpp_project_dir=Path(cpp_project_dir),
            cpp_db_path=Path(cpp_db_path) if cpp_db_path else None,
            pso_db_path=Path(pso_db_path) if pso_db_path else None,
            suspect_shader=suspect_shader,
            max_pairs=max_pairs,
            lookback=lookback,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _copyrect_t0_handles_from_compare(compare: dict[str, Any]) -> list[dict[str, Any]]:
    handles: list[dict[str, Any]] = []
    for side in ("left", "right"):
        side_info = compare.get(side)
        if not isinstance(side_info, dict):
            continue
        candidates = side_info.get("t0_candidates")
        if not isinstance(candidates, list):
            continue
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            handle = candidate.get("handle")
            if isinstance(handle, dict) and "accessor" in handle:
                handles.append(handle)
    return handles


def _copyrect_live_pair_next_branch(compare: dict[str, Any]) -> dict[str, Any]:
    verdict = compare.get("verdict")
    if verdict == "copyrect_t0_same_source":
        return {
            "focus": "source_descriptor_or_source_producer",
            "reason": "Left and right CopyRectPS resolve to the same sampled PS t0 source.",
            "actions": [
                "Inspect t0_revision_results at the right event.",
                "Trace descriptor creation/copy provenance for that source descriptor.",
                "Patch right-eye CopyRect source descriptor routing or the producer feeding that source.",
            ],
        }
    if verdict == "copyrect_t0_different_source":
        return {
            "focus": "view_rect_cbv_or_destination",
            "reason": "Left and right CopyRectPS sample different PS t0 sources, so the saved table overlap was not the sampled source.",
            "actions": [
                "Dump differing graphics root CBV bytes for the two events.",
                "Decode copy/view rect constants and compare right-eye viewport/scissor/destination state.",
                "Patch right-eye copy rect constants or destination routing.",
            ],
        }
    return {
        "focus": "live_descriptor_state_binding",
        "reason": "Actual CopyRectPS PS t0 could not be resolved for both events.",
        "actions": [
            "Confirm the BinaryReplay event indices map to the CopyRect draw indices.",
            "Collect descriptor_state and root_parameters at the exact left/right events.",
            "If live state remains unavailable, add runtime root-signature range logging for CopyRectPS draws.",
        ],
    }


def _safe_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, str) and value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except (TypeError, ValueError):
        return None


@mcp.tool()
async def ngfx_sn2_repro_plan(
    launch_script: str | None = None,
    output_dir: str | None = None,
    capture_frame_count: int = 1,
    extra_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Return the autonomous Subnautica 2 repro/capture run plan."""
    return autonomous_fix.sn2_repro_plan(
        launch_script=launch_script,
        output_dir=output_dir,
        capture_frame_count=capture_frame_count,
        extra_env=extra_env,
    )


@mcp.tool()
async def ngfx_sn2_repro_run(
    launch_script: str | None = None,
    working_dir: str | None = None,
    output_dir: str | None = None,
    extra_env: dict[str, str] | None = None,
    dry_run: bool = True,
    background: bool = True,
    timeout_sec: int | None = None,
) -> dict[str, Any]:
    """Launch the SN2 repro script or return the exact command in dry-run mode."""
    plan = autonomous_fix.sn2_repro_plan(
        launch_script=launch_script,
        output_dir=output_dir,
        extra_env=extra_env,
    )
    script = plan["launch_script"]
    argv = plan["powershell_command"]
    env = dict(plan["extra_env"])
    if output_dir:
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    if dry_run:
        return {"ok": True, "dry_run": True, "plan": plan}
    if not Path(script).is_file():
        return {"ok": False, "error": f"launch script not found: {script}", "plan": plan}
    if background:
        bg = start_background("__tmp__", argv, tool="powershell", cwd=working_dir, extra_env=env)
        sess = get_sessions().register_launch(
            bg,
            tool="powershell",
            activity="SN2 repro",
            exe=script,
            notes="autonomous SN2 repro launch",
        )
        return {"ok": True, "mode": "background", "plan": plan, "session": sess.summary()}
    res = await run_async(argv, tool="powershell", cwd=working_dir, timeout=timeout_sec, extra_env=env)
    return {"ok": res.ok, "mode": "foreground", "plan": plan, **result_to_dict(res)}


@mcp.tool()
async def ngfx_cpp_capture_from_saved_capture(
    capture: str,
    output_dir: str | None = None,
    wait_for_project: bool = False,
    timeout_sec: float = 900.0,
    index_calls: bool = True,
    index_psos: bool = True,
) -> dict[str, Any]:
    """Alias for the saved-capture C++ export path with no extra user-facing choices."""
    return await ngfx_cpp_capture_dump(
        capture=capture,
        output_dir=output_dir,
        wait_for_project=wait_for_project,
        timeout_sec=timeout_sec,
        index_calls=index_calls,
        index_psos=index_psos,
    )


@mcp.tool()
async def ngfx_pair_eye_events(
    db_path: str,
    render_width: float | None = None,
    right_half_min_x: float | None = None,
    limit: int = 4000,
) -> dict[str, Any]:
    """Pair left-eye draw/dispatch/copy events with their right-eye equivalents."""
    try:
        return autonomous_fix.pair_eye_events(
            Path(db_path),
            render_width=render_width,
            right_half_min_x=right_half_min_x,
            limit=limit,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_resolve_shader_slots(
    db_path: str,
    event_index: int,
    slots: list[str],
    slot_map: dict[str, Any] | None = None,
    lookback: int = 500,
) -> dict[str, Any]:
    """Resolve shader slots like t5/t8/t9 to root params/descriptor evidence when possible."""
    try:
        return autonomous_fix.resolve_shader_slots(
            Path(db_path),
            event_index,
            slots=slots,
            slot_map=slot_map,
            lookback=lookback,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_descriptor_resource_candidates(
    descriptor_state_reply: dict[str, Any],
    slots: list[str],
    slot_map: dict[str, Any] | None = None,
    max_candidates_per_slot: int = 25,
) -> dict[str, Any]:
    """Resolve shader slots to likely resources from a descriptor-state RPC reply."""
    try:
        return autonomous_fix.descriptor_resource_candidates(
            descriptor_state_reply,
            slots=slots,
            slot_map=slot_map,
            max_candidates_per_slot=max_candidates_per_slot,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_trace_roi_history(
    image_accessor: int,
    roi: dict[str, int],
    session_handle: str | None = None,
    grid_x: int = 8,
    grid_y: int = 8,
    image_misc: int = 0,
    image_view_accessor: int | None = None,
    image_view_misc: int = 0,
    aspect: int = 1,
    mip_level: int = 0,
    array_layer: int = 0,
    slice_index: int = 0,
    max_pixels: int = 64,
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """Build or execute a grid of private pixel-history requests for a bad ROI."""
    try:
        grid = autonomous_fix.pixel_history_grid_requests(
            image_accessor=image_accessor,
            image_misc=image_misc,
            image_view_accessor=image_view_accessor,
            image_view_misc=image_view_misc,
            roi=roi,
            grid_x=grid_x,
            grid_y=grid_y,
            aspect=aspect,
            mip_level=mip_level,
            array_layer=array_layer,
            slice_index=slice_index,
        )
        if not session_handle:
            return grid

        sess = frame_debugger_rpc_mod.get_session(session_handle)
        results = []
        failures = []
        for req in grid["requests"][: max(0, max_pixels)]:
            point = req["pixel"]
            try:
                reply = sess.client.pixel_history(
                    image_accessor=image_accessor,
                    image_misc=image_misc,
                    image_view_accessor=image_view_accessor,
                    image_view_misc=image_view_misc,
                    x=point["x"],
                    y=point["y"],
                    aspect=aspect,
                    mip_level=mip_level,
                    array_layer=array_layer,
                    slice_index=slice_index,
                    timeout=timeout_sec,
                )
                results.append({"pixel": point, "reply": rpc_client.protobuf_to_dict(reply)})
            except Exception as exc:
                err = {"pixel": point, "error": f"{type(exc).__name__}: {exc}"}
                failures.append(err)
                results.append(err)
        sess.last_error = failures[-1]["error"] if failures else None
        return {
            "ok": not failures,
            "mode": "live",
            "session": sess.summary(),
            "roi": roi,
            "grid": grid["grid"],
            "requested_pixels": len(grid["requests"]),
            "executed_pixels": len(results),
            "truncated": len(grid["requests"]) > len(results),
            "failures": failures,
            "results": results,
        }
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_resource_producer_graph(
    db_path: str,
    resources: list[str],
    event_index: int | None = None,
    depth: int = 2,
    window: int | None = 1000,
) -> dict[str, Any]:
    """Build a best-effort read/write producer graph for named resources."""
    try:
        return autonomous_fix.resource_producer_graph(
            Path(db_path),
            resources=resources,
            event_index=event_index,
            depth=depth,
            window=window,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_import_uevr_trace(
    trace_path: str,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Import an NDJSON/JSON/CSV UEVR runtime hook trace and summarize it."""
    try:
        return autonomous_fix.import_uevr_trace(
            Path(trace_path),
            db_path=Path(db_path) if db_path else None,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_pso_rehydration_plan(
    suspect_pso: str,
    patched_shader_path: str,
    output_dir: str | None = None,
) -> dict[str, Any]:
    """Generate a C++ plan/snippet for cloning a graphics PSO with a patched pixel shader."""
    try:
        return autonomous_fix.pso_rehydration_plan(
            suspect_pso=suspect_pso,
            patched_shader_path=patched_shader_path,
            output_dir=output_dir,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_shader_probe_execution_plan(
    suspect_pso: str,
    probe_name: str,
    launch_script: str | None = None,
    roi: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Return the run steps for executing and scoring a shader probe."""
    return autonomous_fix.shader_probe_execution_plan(
        suspect_pso=suspect_pso,
        probe_name=probe_name,
        launch_script=launch_script,
        roi=roi,
    )


@mcp.tool()
async def ngfx_diff_hdr_roi(
    before_path: str,
    after_path: str,
    roi: dict[str, int] | None = None,
    width: int | None = None,
    height: int | None = None,
    channels: int = 4,
    format: str = "auto",
) -> dict[str, Any]:
    """Diff an HDR/float ROI from PFM or raw float32 buffers."""
    try:
        return autonomous_fix.diff_hdr_roi(
            Path(before_path),
            Path(after_path),
            roi=roi,
            width=width,
            height=height,
            channels=channels,
            fmt=format,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_autofix_loop_plan(max_trials: int = 12) -> dict[str, Any]:
    """Return the autonomous patch/test/scoring loop for shader fixes."""
    return autonomous_fix.autofix_loop_plan(max_trials=max_trials)


@mcp.tool()
async def ngfx_validate_fix_claim(
    before_score: float,
    after_score: float,
    left_eye_delta: float,
    repeated_runs: int,
    has_first_bad_event: bool,
    has_resource_or_shader_cause: bool,
    min_improvement: float = 0.25,
    max_left_delta: float = 0.03,
) -> dict[str, Any]:
    """Evidence gate for accepting or rejecting an automated visual-fix claim."""
    return autonomous_fix.validate_fix_claim(
        before_score=before_score,
        after_score=after_score,
        left_eye_delta=left_eye_delta,
        repeated_runs=repeated_runs,
        has_first_bad_event=has_first_bad_event,
        has_resource_or_shader_cause=has_resource_or_shader_cause,
        min_improvement=min_improvement,
        max_left_delta=max_left_delta,
    )


@mcp.tool()
async def ngfx_fix_attempt_log(
    log_path: str,
    hypothesis: str | None = None,
    change: str | None = None,
    before_evidence: dict[str, Any] | None = None,
    after_evidence: dict[str, Any] | None = None,
    decision: str = "open",
    notes: str = "",
    read_only: bool = False,
) -> dict[str, Any]:
    """Append-only JSONL log of fix attempts.

    With ``read_only=True`` (or no ``hypothesis``/``change``) the existing
    log is read and summarised. Otherwise one entry is appended.

    ``decision='accept'`` requires both ``before_evidence`` and
    ``after_evidence`` to be non-empty — this is the enforced guard
    against overclaimed fixes (the project's historical failure mode
    documented in NSIGHT_SHADER_DEBUG_AUTONOMY.md).
    """
    if read_only or not hypothesis or not change:
        return autonomous_fix.fix_attempt_log_read(Path(log_path))
    return autonomous_fix.fix_attempt_log_append(
        Path(log_path),
        hypothesis=hypothesis,
        change=change,
        before_evidence=before_evidence,
        after_evidence=after_evidence,
        decision=decision,
        notes=notes,
    )


@mcp.tool()
async def ngfx_fix_claim_evidence_bundle(
    output_zip: str,
    capture_path: str | None = None,
    before_screenshot: str | None = None,
    after_screenshot: str | None = None,
    roi_diff_json: str | None = None,
    event_state_diff_json: str | None = None,
    fix_log_path: str | None = None,
    extra_files: list[str] | None = None,
    require_before_after: bool = True,
) -> dict[str, Any]:
    """Bundle a fix-claim's evidence into a single zip for review.

    Refuses to produce a bundle without both before+after screenshots
    unless ``require_before_after`` is false (used for "open" attempts
    that haven't reached the after-pass yet).
    """
    def _p(x: str | None) -> Path | None:
        return Path(x) if x else None
    return autonomous_fix.fix_claim_evidence_bundle(
        Path(output_zip),
        capture_path=_p(capture_path),
        before_screenshot=_p(before_screenshot),
        after_screenshot=_p(after_screenshot),
        roi_diff_json=_p(roi_diff_json),
        event_state_diff_json=_p(event_state_diff_json),
        fix_log_path=_p(fix_log_path),
        extra_files=[Path(x) for x in (extra_files or [])],
        require_before_after=require_before_after,
    )


# ---------------------------------------------------------------------------
# Escape hatch
# ---------------------------------------------------------------------------


_SUPPORTED_RAW_TOOLS = frozenset(TOOL_DEFINITIONS)


@mcp.tool()
async def ngfx_raw(
    tool: str,
    argv: list[str],
    cwd: str | None = None,
    timeout_sec: int | None = None,
    background: bool = False,
    extra_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Escape hatch — invoke any supported Nsight tool with arbitrary argv.

    ``tool`` must be one of: ``ngfx``, ``ngfx_capture``, ``ngfx_replay``,
    ``ngfx_rpc``, ``ngfx_ui``, ``aftermath_control``, ``aftermath_monitor``,
    ``aftermath_format``, ``remote_monitor``, ``shaderdebugger_configurator``,
    ``glslang``. The leading exe is prepended automatically — supply only
    the arguments.
    """
    if tool not in _SUPPORTED_RAW_TOOLS:
        return {"ok": False, "error": f"unsupported tool {tool!r}; known: {sorted(_SUPPORTED_RAW_TOOLS)}"}
    s = get_settings()
    exe = s.require_tool(tool)
    full = [str(exe), *list(argv)]
    if background:
        bg = start_background("__tmp__", full, tool=tool, cwd=cwd, extra_env=extra_env)
        sess = get_sessions().register_launch(bg, tool=tool, notes="ngfx_raw background")
        return {"mode": "background", **sess.summary()}
    res = await run_async(full, tool=tool, cwd=cwd, timeout=timeout_sec, extra_env=extra_env)
    return result_to_dict(res)


# ---------------------------------------------------------------------------
# Capture-directory discovery + diff (parity with GUI 'Recent Captures')
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_find_recent_captures(
    limit: int = 20,
    kinds: list[str] | None = None,
    extra_dirs: list[str] | None = None,
) -> dict[str, Any]:
    """Look in the standard Nsight output directories (and optionally extra
    dirs) for recent capture / GPU-trace files. Newest first.

    ``kinds`` ⊆ {"graphics_capture", "gpu_trace"} (default: both).
    """
    return captures_mod.find_recent_captures(
        limit=limit,
        kinds=tuple(kinds) if kinds else ("graphics_capture", "gpu_trace"),
        extra_dirs=[Path(d) for d in (extra_dirs or [])],
    )


@mcp.tool()
async def ngfx_list_captures_in_dir(
    directory: str,
    include_subdirs: bool = True,
    kinds: list[str] | None = None,
) -> dict[str, Any]:
    """Enumerate every capture / gputrace file under a directory."""
    files = captures_mod.list_captures_in_dir(
        Path(directory),
        include_subdirs=include_subdirs,
        kinds=tuple(kinds) if kinds else ("graphics_capture", "gpu_trace"),
    )
    return {"directory": directory, "files": [f.to_dict() for f in files]}


@mcp.tool()
async def ngfx_capture_diff(capture_a: str, capture_b: str) -> dict[str, Any]:
    """Diff the parsed ``--metadata`` summaries of two captures.

    Returns ``{only_in_a, only_in_b, changed: {key: [a, b]}, same_count}``.
    """
    _, path_a = _resolve_capture(capture_a)
    _, path_b = _resolve_capture(capture_b)
    a = await capture_info.capture_metadata(path_a)
    b = await capture_info.capture_metadata(path_b)
    return {
        "a": {"path": str(path_a)},
        "b": {"path": str(path_b)},
        "diff": captures_mod.diff_metadata(a, b),
    }


# ---------------------------------------------------------------------------
# Function-stream indexer (Event List parity)
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_index_events(capture: str, force: bool = False) -> dict[str, Any]:
    """Index a capture's function stream into a SQLite DB next to it.

    The DB is keyed by capture mtime — calling again on an unchanged capture
    is a no-op. ``force=True`` rebuilds.
    """
    _, path = _resolve_capture(capture)
    idx = await events_mod.index_capture_functions(path, force=force)
    return idx.to_dict()


def _index_db_for(capture: str) -> Path:
    _, path = _resolve_capture(capture)
    return path.parent / f"{path.name}.ngfxmcp" / "functions.db"


@mcp.tool()
async def ngfx_find_events(
    capture: str,
    kind: str | None = None,
    name_regex: str | None = None,
    start: int | None = None,
    end: int | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    """Filtered search over the indexed function stream.

    Example: ``ngfx_find_events(capture, kind='draw', start=2100, end=2480)``
    returns every draw call inside that index range. ``kind`` ∈ {"draw",
    "dispatch", "copy", "barrier", "present", "ray_tracing", "sync",
    "set_state", "other"}.
    """
    _, path = _resolve_capture(capture)
    db = events_mod._cache_root_for(path) / "functions.db"
    if not db.is_file():
        await events_mod.index_capture_functions(path)
    calls = events_mod.query_calls(
        db,
        kind=kind,
        name_regex=name_regex,
        start=start,
        end=end,
        limit=limit,
        offset=offset,
    )
    return {"count": len(calls), "calls": calls}


@mcp.tool()
async def ngfx_get_event(capture: str, idx: int) -> dict[str, Any]:
    """Look up a single call by index in the indexed function stream."""
    _, path = _resolve_capture(capture)
    db = events_mod._cache_root_for(path) / "functions.db"
    if not db.is_file():
        await events_mod.index_capture_functions(path)
    row = events_mod.get_call(db, idx)
    if row is None:
        return {"ok": False, "error": f"no call at idx={idx}"}
    return row


@mcp.tool()
async def ngfx_event_histogram(
    capture: str, by: str = "name", limit: int = 100
) -> dict[str, Any]:
    """Histogram of recorded calls grouped by ``name`` or ``kind``."""
    _, path = _resolve_capture(capture)
    db = events_mod._cache_root_for(path) / "functions.db"
    if not db.is_file():
        await events_mod.index_capture_functions(path)
    return {"by": by, "rows": events_mod.call_histogram(db, by=by, limit=limit)}


@mcp.tool()
async def ngfx_find_calls_by_arg(
    capture: str,
    substring: str,
    kind: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Search recorded calls by argument substring.

    Nsight's CLI ``--metadata-functions`` output gives function NAMES per
    event but NO argument values — by design. To get per-call args you have
    to run the UI's *Generate C++ Capture* and parse the emitted C++
    sources. This tool is a thin wrapper that:

      * looks for a sibling ``<capture>.ngfxmcp/cpp_capture/`` directory
        (the conventional drop point) and the indexed call DB inside it,
      * if found, runs ``ngfx_cpp_capture_query_calls(contains=substring,
        kind=kind)`` against it.

    If the DB isn't built yet, this returns guidance to run
    ``ngfx_cpp_capture_open_in_ui`` → ``ngfx_cpp_capture_wait_for_project``
    → ``ngfx_cpp_capture_index_calls`` first.
    """
    cap = Path(capture)
    if not cap.is_file():
        return {"ok": False, "error": f"capture not found: {capture}"}
    sibling = cap.parent / f"{cap.name}.ngfxmcp" / "cpp_capture"
    candidates = list(sibling.glob("**/.ngfxmcp_cpp_calls.db")) if sibling.is_dir() else []
    if not candidates:
        return {
            "ok": False,
            "error": (
                "No C++-capture index found for this capture. To enable "
                "argument-level search, run:\n"
                "  1. ngfx_cpp_capture_open_in_ui(capture=<path>)\n"
                "  2. (in ngfx-ui) File → Activity → Generate C++ Capture →"
                f" output to {sibling}\n"
                "  3. ngfx_cpp_capture_wait_for_project(watch_dir=<that dir>)\n"
                "  4. ngfx_cpp_capture_index_calls(project_dir=<returned project_dir>)\n"
                "Then this tool (or ngfx_cpp_capture_query_calls) will work."
            ),
            "expected_index_at": str(sibling),
        }
    db = max(candidates, key=lambda p: p.stat().st_mtime)
    rows = cpp_capture_parser.query_calls(
        db, contains=substring, kind=kind, limit=limit,
    )
    return {"ok": True, "db_path": str(db), "calls": rows, "count": len(rows)}


# ---------------------------------------------------------------------------
# Object index (PSO / shader / resource inventory — GUI 'Resources' parity)
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_index_objects(capture: str, force: bool = False) -> dict[str, Any]:
    """Index every API object recorded in a capture into a SQLite DB.

    Surfaces a histogram by type (Pipeline, ShaderModule, Buffer, Image, ...)
    and by coarse category (pipeline, shader, resource, descriptor, sync,
    command, queue, surface, device, ray_tracing, other). The underlying
    data comes from ``ngfx-replay --metadata-objects``.
    """
    _, path = _resolve_capture(capture)
    idx = await objects_mod.index_capture_objects(path, force=force)
    return idx.to_dict()


@mcp.tool()
async def ngfx_query_objects(
    capture: str,
    type_name: str | None = None,
    category: str | None = None,
    name_regex: str | None = None,
    api: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> dict[str, Any]:
    """Filtered listing of recorded objects.

    Filter by exact ``type_name`` (e.g. "Pipeline", "ShaderModule",
    "DescriptorSetLayout"), ``category`` (pipeline/shader/resource/…), or a
    regex against ``object_name``.
    """
    _, path = _resolve_capture(capture)
    db = events_mod._cache_root_for(path) / "objects.db"
    if not db.is_file():
        await objects_mod.index_capture_objects(path)
    rows = objects_mod.query_objects(
        db,
        type_name=type_name,
        category=category,
        name_regex=name_regex,
        api=api,
        limit=limit,
        offset=offset,
    )
    return {"count": len(rows), "objects": rows}


@mcp.tool()
async def ngfx_get_object(capture: str, uid: int) -> dict[str, Any]:
    """Look up a single recorded object by uid."""
    _, path = _resolve_capture(capture)
    db = events_mod._cache_root_for(path) / "objects.db"
    if not db.is_file():
        await objects_mod.index_capture_objects(path)
    row = objects_mod.get_object(db, uid)
    return row or {"ok": False, "error": f"no object with uid={uid}"}


@mcp.tool()
async def ngfx_object_histogram(capture: str, by: str = "type_name") -> dict[str, Any]:
    """Histogram of recorded objects grouped by ``type_name``, ``category``, or ``api``."""
    _, path = _resolve_capture(capture)
    db = events_mod._cache_root_for(path) / "objects.db"
    if not db.is_file():
        await objects_mod.index_capture_objects(path)
    return {"by": by, "rows": objects_mod.object_histogram(db, by=by)}


@mcp.tool()
async def ngfx_object_query(
    capture: str,
    sql: str,
    params: list[Any] | None = None,
) -> dict[str, Any]:
    """Read-only SQL (SELECT / WITH) against the object index.

    Schema: ``objects(uid INTEGER PRIMARY KEY, type_name TEXT, object_name
    TEXT, api TEXT, access_flags INTEGER, category TEXT, raw_json TEXT)``.
    """
    _, path = _resolve_capture(capture)
    db = events_mod._cache_root_for(path) / "objects.db"
    if not db.is_file():
        await objects_mod.index_capture_objects(path)
    try:
        rows = objects_mod.sql_query_objects(db, sql, params or [])
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    return {"row_count": len(rows), "rows": rows[:1000]}


@mcp.tool()
async def ngfx_list_pipelines(capture: str) -> dict[str, Any]:
    """List every Pipeline / PipelineLayout / DescriptorSetLayout /
    PipelineCache / RootSignature / StateObject in a capture.

    Replaces the GUI 'Pipelines' pane (without per-PSO shader-source view).
    """
    _, path = _resolve_capture(capture)
    db = events_mod._cache_root_for(path) / "objects.db"
    if not db.is_file():
        await objects_mod.index_capture_objects(path)
    rows = objects_mod.query_objects(db, category="pipeline", limit=10000)
    return {"count": len(rows), "pipelines": rows}


@mcp.tool()
async def ngfx_list_shaders(capture: str) -> dict[str, Any]:
    """List every ShaderModule / ShaderProgram / Shader recorded in a capture."""
    _, path = _resolve_capture(capture)
    db = events_mod._cache_root_for(path) / "objects.db"
    if not db.is_file():
        await objects_mod.index_capture_objects(path)
    rows = objects_mod.query_objects(db, category="shader", limit=10000)
    return {"count": len(rows), "shaders": rows}


@mcp.tool()
async def ngfx_list_resources(capture: str) -> dict[str, Any]:
    """List every recorded resource (Buffer / Image / Sampler / DeviceMemory / Heap)."""
    _, path = _resolve_capture(capture)
    db = events_mod._cache_root_for(path) / "objects.db"
    if not db.is_file():
        await objects_mod.index_capture_objects(path)
    rows = objects_mod.query_objects(db, category="resource", limit=10000)
    return {"count": len(rows), "resources": rows}


@mcp.tool()
async def ngfx_event_query(
    capture: str,
    sql: str,
    params: list[Any] | None = None,
) -> dict[str, Any]:
    """Read-only SQL query (SELECT / WITH) against the function index.

    Schema: ``calls(idx INTEGER PRIMARY KEY, name TEXT, args TEXT, ret TEXT,
    kind TEXT, line INTEGER, raw TEXT)``.
    """
    _, path = _resolve_capture(capture)
    db = events_mod._cache_root_for(path) / "functions.db"
    if not db.is_file():
        await events_mod.index_capture_functions(path)
    try:
        rows = events_mod.sql_query(db, sql, params or [])
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    return {"row_count": len(rows), "rows": rows[:1000]}


# ---------------------------------------------------------------------------
# Deep GPU Trace inspection (Trace Analysis parity)
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_gputrace_archive(gputrace: str, max_members: int = 1000) -> dict[str, Any]:
    """Open a .nsight-gputrace as a zip archive and list its members + decode
    any small JSON manifests inline."""
    _, path = _resolve_gputrace(gputrace)
    return gputrace_mod.inspect_archive(path, max_members=max_members)


@mcp.tool()
async def ngfx_gputrace_read_member(
    gputrace: str, member: str, max_chars: int = 200_000
) -> dict[str, Any]:
    """Read a member of the .nsight-gputrace archive as UTF-8 text (no disk
    extraction). Auto-decodes JSON / CSV payloads."""
    _, path = _resolve_gputrace(gputrace)
    return gputrace_mod.read_member_text(path, member, max_chars=max_chars)


@mcp.tool()
async def ngfx_gputrace_extract(gputrace: str, member: str, out_dir: str) -> dict[str, Any]:
    """Extract a specific member of the .nsight-gputrace archive to ``out_dir``."""
    _, path = _resolve_gputrace(gputrace)
    return gputrace_mod.extract_member(path, member, Path(out_dir))


@mcp.tool()
async def ngfx_gputrace_shader_pipeline_search(
    gputrace: str,
    shader_hash: str | None = None,
    shader_name: str | None = None,
    entry_point: str | None = None,
    max_members: int = 2000,
    max_scan_bytes: int = 20_000_000,
    max_hits: int = 100,
) -> dict[str, Any]:
    """Search GPU Trace archive shader/pipeline data for a shader name or hash."""
    _, path = _resolve_gputrace(gputrace)
    return gputrace_mod.search_shader_pipelines(
        path,
        shader_hash=shader_hash,
        shader_name=shader_name,
        entry_point=entry_point,
        max_members=max_members,
        max_scan_bytes=max_scan_bytes,
        max_hits=max_hits,
    )


@mcp.tool()
async def ngfx_list_perf_report(perf_dir: str) -> dict[str, Any]:
    """List the artifacts written by ``ngfx-replay --perf-report-dir``.

    Auto-decodes small JSON/CSV files inline.
    """
    return gputrace_mod.list_perf_report(Path(perf_dir))


@mcp.tool()
async def ngfx_gputrace_export_summary(report_dir: str) -> dict[str, Any]:
    """Summarize Nsight GPU Trace auto-export artifacts such as REPRO_INFO and GPUTRACE_FRAME."""
    return gputrace_mod.export_summary(Path(report_dir))


@mcp.tool()
async def ngfx_gputrace_export_search(
    report_dir: str,
    needles: list[str],
    max_file_bytes: int = 20_000_000,
    max_hits: int = 100,
    context_chars: int = 240,
) -> dict[str, Any]:
    """Search Nsight GPU Trace auto-export files for shader names, hashes, or event text."""
    return gputrace_mod.search_export(
        Path(report_dir),
        needles,
        max_file_bytes=max_file_bytes,
        max_hits=max_hits,
        context_chars=context_chars,
    )


# ---------------------------------------------------------------------------
# WRPV (Nsight 2026 GPU Trace binary report) inspection
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_gputrace_wrpv_search(
    gputrace: str,
    needles: list[str],
    encodings: list[str] | None = None,
    include_hex: bool = True,
    max_hits_per_needle: int = 200,
    context_bytes: int = 48,
) -> dict[str, Any]:
    """Search a binary ``.ngfx-gputrace`` (WRPV container) for needles.

    Each needle is tried under every encoding in ``encodings`` (defaults to
    ``["ascii", "utf-16le"]``). A hex needle of the form ``<hex:DEADBEEF>``
    is searched as raw bytes when ``include_hex`` is true — useful for
    DXBC hashes / SHA1 payload hashes without committing to an encoding.
    """
    _, path = _resolve_gputrace(gputrace)
    enc_tuple: tuple[str, ...] = tuple(encodings) if encodings else ("ascii", "utf-16le")
    return gputrace_mod.wrpv_search(
        path,
        needles,
        encodings=enc_tuple,
        include_hex=include_hex,
        max_hits_per_needle=max_hits_per_needle,
        context_bytes=context_bytes,
    )


@mcp.tool()
async def ngfx_gputrace_wrpv_strings(
    gputrace: str,
    min_len: int = 5,
    max_len: int = 4096,
    encodings: list[str] | None = None,
    limit: int = 5000,
    pattern: str | None = None,
) -> dict[str, Any]:
    """Extract printable strings from a WRPV report with byte offsets.

    ``encodings`` defaults to ``["ascii", "utf-16le"]``. ``pattern`` is an
    optional regex applied to each decoded string before inclusion (e.g.
    ``"^[A-Za-z_][A-Za-z0-9_]*PS$"`` to surface pixel-shader-name candidates).
    """
    _, path = _resolve_gputrace(gputrace)
    enc_tuple: tuple[str, ...] = tuple(encodings) if encodings else ("ascii", "utf-16le")
    return gputrace_mod.wrpv_strings(
        path,
        min_len=min_len,
        max_len=max_len,
        encodings=enc_tuple,
        limit=limit,
        pattern=pattern,
    )


@mcp.tool()
async def ngfx_gputrace_wrpv_sections(
    gputrace: str, max_candidates: int = 64
) -> dict[str, Any]:
    """Best-effort listing of header-like fields in a WRPV report.

    The WRPV layout is not fully reverse-engineered. This surfaces the
    proven part (file magic + size) and candidate u32-LE fields in the
    first 256 bytes that look like section offsets or sizes. Every
    candidate carries an ``evidence_label`` so callers don't treat them
    as ground truth.
    """
    _, path = _resolve_gputrace(gputrace)
    return gputrace_mod.wrpv_sections(path, max_candidates=max_candidates)


@mcp.tool()
async def ngfx_gputrace_wrpv_table_preview(
    gputrace: str, offset: int, length: int = 256, ascii_window: int = 16
) -> dict[str, Any]:
    """Hex+ASCII preview of ``length`` bytes at ``offset`` inside a WRPV report.

    Use after :func:`ngfx_gputrace_wrpv_sections` or
    :func:`ngfx_gputrace_wrpv_search` returns an interesting offset, to
    eyeball the surrounding structure without re-opening the file.
    """
    _, path = _resolve_gputrace(gputrace)
    return gputrace_mod.wrpv_table_preview(
        path, offset=offset, length=length, ascii_window=ascii_window
    )


@mcp.tool()
async def ngfx_gputrace_shader_bindings(
    gputrace: str,
    shader_names: list[str] | None = None,
    dxbc_hashes_hex: list[str] | None = None,
    payload_sha1_hex: list[str] | None = None,
    pdb_names: list[str] | None = None,
) -> dict[str, Any]:
    """Search a WRPV report for shader binding evidence.

    Pass any combination of shader names, DXBC container hashes,
    payload SHA1 hashes, or PDB names. Each is searched as ASCII and
    UTF-16LE, and hashes are also searched as raw bytes. Designed for
    the Subnautica 2 `CopyRectPS` workflow: pass
    ``shader_names=["CopyRectPS"]``,
    ``dxbc_hashes_hex=["529845b997ed9c43ad87a3a1432fd393"]``,
    ``payload_sha1_hex=["81f5800eb6fe36958ffa1c5666016e672a1535fe"]``,
    ``pdb_names=["aab95ca751a813819972cc044ba1d07b.pdb"]``.
    """
    _, path = _resolve_gputrace(gputrace)
    return gputrace_mod.wrpv_shader_binding_search(
        path,
        shader_names=shader_names,
        dxbc_hashes_hex=dxbc_hashes_hex,
        payload_sha1_hex=payload_sha1_hex,
        pdb_names=pdb_names,
    )


# ---------------------------------------------------------------------------
# Nsight project file authoring
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_project_create(
    path: str,
    activity: str = "Graphics Capture",
    exe: str | None = None,
    args: str | None = None,
    working_dir: str | None = None,
    env_pairs: str | None = None,
    platform: str = "Windows",
    hostname: str = "localhost",
    settings: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Write a minimal Nsight project XML at ``path``.

    ``activity`` should match an entry from ``ngfx_list_activities``.
    Subsequent invocations can pass this file via ``project=<path>``.
    """
    return project_mod.create_project(
        Path(path),
        activity=activity,
        exe=exe,
        args=args,
        working_dir=working_dir,
        env_pairs=env_pairs,
        platform=platform,
        hostname=hostname,
        settings=settings,
    )


@mcp.tool()
async def ngfx_project_read(path: str) -> dict[str, Any]:
    """Read an existing Nsight project XML."""
    return project_mod.read_project(Path(path))


@mcp.tool()
async def ngfx_project_update(
    path: str,
    activity: str | None = None,
    exe: str | None = None,
    args: str | None = None,
    working_dir: str | None = None,
    env_pairs: str | None = None,
    set_settings: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Mutate fields of an existing Nsight project file in-place."""
    return project_mod.update_project(
        Path(path),
        activity=activity,
        exe=exe,
        args=args,
        working_dir=working_dir,
        env_pairs=env_pairs,
        set_settings=set_settings,
    )


# ---------------------------------------------------------------------------
# C++ Capture build + run
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_cpp_capture_find_solution(dir_or_sln: str) -> dict[str, Any]:
    """Locate the .sln produced by a Generate-C++-Capture run."""
    sln = cpp_capture.find_solution(Path(dir_or_sln))
    if sln is None:
        return {"ok": False, "error": f"no .sln found under {dir_or_sln}"}
    return {"ok": True, "solution": str(sln)}


@mcp.tool()
async def ngfx_cpp_capture_build(
    dir_or_sln: str,
    configuration: str = "Release",
    platform: str = "x64",
    targets: str | None = None,
    timeout_sec: int | None = 1800,
) -> dict[str, Any]:
    """Invoke MSBuild on a Generate-C++-Capture output directory or .sln.

    Requires Visual Studio 2022 (Community is fine) or the Build Tools, with
    the C++ workload. Returns the produced exe paths on success.
    """
    return await cpp_capture.build_solution(
        Path(dir_or_sln),
        configuration=configuration,
        platform=platform,
        targets=targets,
        timeout_sec=timeout_sec,
    )


@mcp.tool()
async def ngfx_cpp_capture_run(
    exe: str,
    args: list[str] | None = None,
    cwd: str | None = None,
    timeout_sec: int | None = 600,
) -> dict[str, Any]:
    """Run a Generate-C++-Capture exe to verify the repro still works."""
    return await cpp_capture.run_generated_exe(
        Path(exe), args=args, cwd=cwd, timeout_sec=timeout_sec
    )


# ---------------------------------------------------------------------------
# C++ Capture parser — per-call arg / descriptor-binding extraction.
#
# Background: Nsight's CLI (`ngfx-replay --metadata-functions`) returns
# function NAMES per event but no argument values — Nsight does not expose
# per-call D3D12/Vulkan args headless. The CLI activity
# `Generate C++ Capture` is also limited: it requires re-running the
# captured application, so it can't operate on a saved .ngfx-gfxcap.
#
# The workaround these tools enable:
#   1. Open the saved capture in ngfx-ui (`ngfx_cpp_capture_open_in_ui`).
#   2. The human clicks File → Activity → Generate C++ Capture (the UI
#      version DOES work on saved captures) and picks an output dir.
#   3. `ngfx_cpp_capture_wait_for_project` blocks until the .sln lands.
#   4. `ngfx_cpp_capture_index_calls` parses every .cpp file in the
#      project; each command-list/command-buffer call becomes a row keyed
#      by a synthetic event_index (matches the function-stream order).
#   5. `ngfx_cpp_capture_event_args` / `_query_calls` / `_descriptor_bindings`
#      answer per-event arg questions.
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_cpp_capture_dump(
    capture: str | None = None,
    exe: str | None = None,
    args: str | None = None,
    working_dir: str | None = None,
    env_pairs: str | None = None,
    output_dir: str | None = None,
    wait_frames: int | None = None,
    wait_seconds: int | None = None,
    wait_hotkey: bool = False,
    enable_vksc: bool = False,
    project: str | None = None,
    hostname: str | None = None,
    no_timeout: bool = False,
    verbose: bool = False,
    wait_for_project: bool = False,
    timeout_sec: float = 900.0,
    index_calls: bool = True,
    index_psos: bool = True,
) -> dict[str, Any]:
    """One-stop helper for producing a Generate-C++-Capture dump and indexes.

    Supply exactly one mode:

    * ``exe=...`` runs the documented headless ``Generate C++ Capture`` CLI
      activity against a live app launch.
    * ``capture=...`` opens a saved ``.ngfx-gfxcap`` in ``ngfx-ui`` because
      the documented CLI cannot generate C++ from an already-saved capture.
      Set ``wait_for_project=True`` and ``output_dir=...`` to have this call
      wait while the UI export is completed.

    When a project is found, this also indexes command calls and PSO->shader
    mappings so the shader-triage tools can query them immediately.
    """
    if bool(capture) == bool(exe):
        return {"ok": False, "error": "supply exactly one of capture or exe"}

    result: dict[str, Any] = {
        "ok": True,
        "mode": "saved_capture_ui_assisted" if capture else "live_cli",
        "output_dir": output_dir,
        "project": None,
        "call_index": None,
        "pso_index": None,
    }

    if capture:
        cap_path = Path(capture)
        if not cap_path.is_file():
            return {"ok": False, "error": f"capture not found: {capture}"}
        watch_dir = Path(output_dir) if output_dir else cap_path.parent / f"{cap_path.stem}_cpp_capture"
        watch_dir.mkdir(parents=True, exist_ok=True)
        sess = ui_mod.open_in_ui(path=str(cap_path))
        result["session"] = sess
        result["watch_dir"] = str(watch_dir)
        result["headless"] = False
        result["next_steps"] = [
            "In ngfx-ui: File -> Activity... -> Generate C++ Capture",
            f"Pick this output directory: {watch_dir}",
            "After the .sln appears, call ngfx_cpp_capture_dump again with wait_for_project=True or call ngfx_cpp_capture_wait_for_project.",
        ]
        if not wait_for_project:
            return result
        wait_result = await cpp_capture.wait_for_project(watch_dir, timeout_sec=timeout_sec)
        result["project"] = wait_result
        if not wait_result.get("ok"):
            return result
        project_dir = Path(wait_result["project_dir"])
    else:
        live = await ngfx_cpp_capture_launched(
            exe=exe or "",
            args=args,
            working_dir=working_dir,
            env_pairs=env_pairs,
            output_dir=output_dir,
            wait_frames=wait_frames,
            wait_seconds=wait_seconds,
            wait_hotkey=wait_hotkey,
            enable_vksc=enable_vksc,
            project=project,
            hostname=hostname,
            no_timeout=no_timeout,
            verbose=verbose,
            background=False,
        )
        result["generate"] = live
        if not output_dir:
            result["project"] = {
                "ok": False,
                "error": "output_dir was not supplied, so the generated project could not be located automatically",
            }
            return result
        sln = cpp_capture.find_solution(Path(output_dir))
        if sln is None:
            result["project"] = {
                "ok": False,
                "error": f"no .sln found under output_dir after Generate C++ Capture: {output_dir}",
            }
            return result
        result["project"] = {"ok": True, "project_dir": str(sln.parent), "solution": str(sln)}
        project_dir = sln.parent

    if index_calls:
        idx = cpp_capture_parser.index_cpp_project(project_dir)
        result["call_index"] = {"ok": True, **idx.to_dict()}
        if index_psos:
            result["pso_index"] = pso_resolver.index_project_psos(project_dir, db_path=idx.db_path)
    return result


@mcp.tool()
async def ngfx_cpp_capture_open_in_ui(
    capture: str,
    watch_dir: str | None = None,
) -> dict[str, Any]:
    """Open a saved capture in ``ngfx-ui.exe`` so the human can run the UI's
    *Generate C++ Capture* activity against it (the CLI activity can't, it
    requires the original application to re-launch).

    Returns the launch session handle and a step-by-step prompt for the human.
    If ``watch_dir`` is provided, pair this with ``ngfx_cpp_capture_wait_for_project``
    to block until the generated .sln appears.
    """
    cap_path = Path(capture)
    if not cap_path.is_file():
        return {"ok": False, "error": f"capture not found: {capture}"}
    sess = ui_mod.open_in_ui(path=str(cap_path))
    return {
        "ok": True,
        "session": sess,
        "next_steps": [
            "In ngfx-ui: File → Activity… → 'Generate C++ Capture'",
            "Pick an output directory (suggested: same parent as the capture).",
            "Click 'Generate' and wait for the .sln to appear.",
            "Then call ngfx_cpp_capture_wait_for_project(watch_dir=<that dir>)",
            "or ngfx_cpp_capture_index_calls(project_dir=<that dir>) directly.",
        ],
        "watch_dir": watch_dir,
    }


@mcp.tool()
async def ngfx_cpp_capture_wait_for_project(
    watch_dir: str,
    timeout_sec: float = 900.0,
    poll_interval_sec: float = 1.5,
    stable_for_sec: float = 3.0,
) -> dict[str, Any]:
    """Poll ``watch_dir`` until a Generate-C++-Capture project lands and its
    .sln stops growing. Returns the project root + the solution path.

    Use after ``ngfx_cpp_capture_open_in_ui`` to block while the human
    clicks 'Generate' in the UI.
    """
    return await cpp_capture.wait_for_project(
        Path(watch_dir),
        timeout_sec=timeout_sec,
        poll_interval_sec=poll_interval_sec,
        stable_for_sec=stable_for_sec,
    )


@mcp.tool()
async def ngfx_cpp_capture_index_calls(
    project_dir: str,
    db_path: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Walk a Generate-C++-Capture project, parse every command-list /
    command-buffer call, and index them into SQLite for per-event queries.

    The output DB lives at ``project_dir/.ngfxmcp_cpp_calls.db`` by default,
    or wherever ``db_path`` points.
    """
    idx = cpp_capture_parser.index_cpp_project(
        Path(project_dir),
        db_path=Path(db_path) if db_path else None,
        force=force,
    )
    return {"ok": True, **idx.to_dict()}


@mcp.tool()
async def ngfx_cpp_capture_event_args(
    db_path: str,
    event_index: int,
) -> dict[str, Any]:
    """Look up one C++-capture event by its synthetic ``event_index``.

    Returns the parsed call (function name, raw args, structured named args,
    source file + line). The event_index ordering matches the order the
    calls appear in the generated C++ ``play``/``replay`` function — which
    in turn matches the ``ngfx-replay --metadata-functions`` event stream
    (modulo Nsight's bookkeeping events like ``CaptureBegin``).
    """
    rec = cpp_capture_parser.get_call(Path(db_path), event_index)
    if rec is None:
        return {"ok": False, "error": f"event {event_index} not found in {db_path}"}
    return {"ok": True, "call": rec}


@mcp.tool()
async def ngfx_cpp_capture_query_calls(
    db_path: str,
    kind: str | None = None,
    api: str | None = None,
    name: str | None = None,
    name_regex: str | None = None,
    contains: str | None = None,
    start: int | None = None,
    end: int | None = None,
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    """Filtered query against the indexed C++ call stream.

    Filters:
      * ``kind``        — draw / dispatch / copy / descriptor / set_state / ...
      * ``api``         — d3d12 / vulkan / opengl
      * ``name``        — exact function name
      * ``name_regex``  — regex over function name
      * ``contains``    — substring match on raw or named arg JSON
      * ``start``/``end`` — event_index range
    """
    rows = cpp_capture_parser.query_calls(
        Path(db_path),
        kind=kind, api=api, name=name, name_regex=name_regex,
        contains=contains, start=start, end=end,
        limit=limit, offset=offset,
    )
    return {"ok": True, "calls": rows, "count": len(rows)}


@mcp.tool()
async def ngfx_cpp_capture_descriptor_bindings(
    db_path: str,
    event_index: int,
    lookback: int = 500,
) -> dict[str, Any]:
    """Reconstruct the descriptor / root-parameter / vertex+index buffer /
    render-target binding state in effect at ``event_index`` by scanning
    backwards through the indexed C++ call stream.

    This is the answer to "what's bound at root parameter N of event G?"
    and "which CBV/SRV/UAV/descriptor set did this draw use?" — the
    questions Nsight's CLI can't answer on its own.

    ``lookback`` caps how many prior events to scan (default 500 is enough
    for most frames — pipeline/RS changes typically happen O(10s) of events
    before a draw).
    """
    state = cpp_capture_parser.descriptor_bindings_for_event(
        Path(db_path), event_index, lookback=lookback,
    )
    return {"ok": True, **state}


@mcp.tool()
async def ngfx_cpp_capture_sql(db_path: str, sql: str) -> dict[str, Any]:
    """Read-only SELECT/WITH query against the C++ call index DB.

    Useful for ad-hoc joins / aggregations that the dedicated query tools
    don't cover. Schema::

        cpp_calls(event_index INTEGER PK, function_name TEXT, api TEXT,
                  kind TEXT, receiver TEXT, raw_args TEXT, args_json TEXT,
                  named_args_json TEXT, file_path TEXT, line_number INTEGER)

    ``args_json`` is a JSON array of stringified arg tokens; ``named_args_json``
    is the per-call structured-args dict (see ``ngfx_cpp_capture_event_args``).
    """
    import sqlite3 as _sqlite3
    try:
        rows = cpp_capture_parser.sql_query(Path(db_path), sql)
        return {"ok": True, "rows": rows, "count": len(rows)}
    except (ValueError, _sqlite3.Error) as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_capture_descriptor_heap_timeline(
    db_path: str,
    heap_symbol: str | None = None,
    start: int | None = None,
    end: int | None = None,
    limit: int = 5000,
) -> dict[str, Any]:
    """Per-heap timeline of descriptor-related D3D12 calls.

    Returns ``SetDescriptorHeaps`` / ``CopyDescriptors[Simple]`` /
    ``SetGraphicsRootDescriptorTable`` / ``SetComputeRootDescriptorTable`` /
    ``Create*View`` / ``CreateSampler`` calls in event order. When
    ``heap_symbol`` is given, only calls whose args mention that heap are
    returned; otherwise the response groups calls by every distinct heap
    symbol it sees.

    Reads from a cpp_capture index built by ``cpp_capture_parser.index_cpp_project``.
    """
    try:
        return cpp_capture_parser.descriptor_heap_timeline(
            Path(db_path),
            heap_symbol=heap_symbol,
            start=start,
            end=end,
            limit=limit,
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_capture_root_signature_ranges(
    cpp_project_dir: str,
    db_path: str | None = None,
    blob_symbol: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Parse every D3D12 root signature blob referenced by the C++ project.

    Returns a list of root signature blobs (symbol + file:line + parsed
    parameters/descriptor ranges). Set ``blob_symbol`` to parse a single
    blob by name.

    Each parameter carries its type (``DESCRIPTOR_TABLE`` / ``32BIT_CONSTANTS``
    / ``CBV`` / ``SRV`` / ``UAV``), shader visibility, and for table
    parameters the contained descriptor ranges (range type, base register,
    register space, number of descriptors, offset in table).

    This is the missing link for "shader register t0 → root parameter N"
    queries — combine with ``ngfx_shader_reflection_bindings`` (planned)
    or the named-arg index for the actual descriptor handle.
    """
    project = Path(cpp_project_dir).resolve()
    if not project.is_dir():
        return {"ok": False, "error": f"cpp_project_dir not found: {project}"}
    db = Path(db_path).resolve() if db_path else project / ".ngfxmcp_cpp_calls.db"
    if not db.is_file():
        return {
            "ok": False,
            "error": f"cpp_calls index missing: {db}. Run "
            "cpp_capture_parser.index_cpp_project and "
            "pso_resolver.index_project_psos first.",
        }
    try:
        if blob_symbol:
            data = cpp_capture_parser.root_signature_blob_bytes(project, blob_symbol)
            if data is None:
                return {
                    "ok": False,
                    "error": f"blob symbol not found in project: {blob_symbol}",
                }
            return {
                "ok": True,
                "symbol": blob_symbol,
                "blob_size": len(data),
                "parsed": cpp_capture_parser.parse_root_signature_blob(data),
            }
        return cpp_capture_parser.root_signature_summary(
            db, project, limit=limit
        )
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_capture_root_signature_lookup(
    cpp_project_dir: str,
    blob_symbol: str,
    register_class: str,
    register: int,
    space: int = 0,
) -> dict[str, Any]:
    """Resolve a shader register (e.g. ``t0`` in space ``0``) to the root
    parameter + descriptor range that covers it.

    ``register_class`` is one of ``"SRV"``, ``"UAV"``, ``"CBV"``,
    ``"SAMPLER"``. Returns the root parameter index, range type, base
    register, descriptor count, register space, and offset in the table
    — enough to map the shader register to a specific descriptor slot
    in the bound descriptor table.

    This is the missing piece for ``CopyRectPS t0`` resolution.
    """
    project = Path(cpp_project_dir).resolve()
    data = cpp_capture_parser.root_signature_blob_bytes(project, blob_symbol)
    if data is None:
        return {
            "ok": False,
            "error": f"blob symbol not found in project: {blob_symbol}",
        }
    rs = cpp_capture_parser.parse_root_signature_blob(data)
    hit = cpp_capture_parser.find_register_for_root_parameter(
        rs,
        register_class=register_class.upper(),
        register=register,
        space=space,
    )
    if hit is None:
        return {
            "ok": False,
            "error": (
                f"no descriptor table range covers {register_class.lower()}{register} "
                f"space {space} in {blob_symbol}"
            ),
            "root_signature": rs,
        }
    return {"ok": True, "lookup": hit, "blob_symbol": blob_symbol}


# ---------------------------------------------------------------------------
# Shader compilation + Shader Debugger
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_glslang_compile(
    input_file: str,
    output_file: str | None = None,
    target_env: str | None = None,
    stage: str | None = None,
    target: str = "spirv",
    extra_args: list[str] | None = None,
    timeout_sec: int | None = 60,
) -> dict[str, Any]:
    """Compile a GLSL / SPIR-V shader using ``glslang.exe`` (bundled).

    ``target`` ∈ {"spirv", "validate"}.
    """
    return await shaders_mod.glslang_compile(
        input_file,
        output_file=output_file,
        target_env=target_env,
        stage=stage,
        target=target,
        extra_args=extra_args,
        timeout_sec=timeout_sec,
    )


@mcp.tool()
async def ngfx_dxc_compile(
    input_file: str,
    profile: str,
    entry_point: str | None = None,
    output_file: str | None = None,
    defines: list[str] | None = None,
    include_dirs: list[str] | None = None,
    extra_args: list[str] | None = None,
    timeout_sec: int | None = 60,
) -> dict[str, Any]:
    """Compile an HLSL shader via DXC."""
    return await shaders_mod.dxc_compile(
        input_file,
        profile=profile,
        entry_point=entry_point,
        output_file=output_file,
        defines=defines,
        include_dirs=include_dirs,
        extra_args=extra_args,
        timeout_sec=timeout_sec,
    )


@mcp.tool()
async def ngfx_shaderdebugger_configure(
    extra_args: list[str] | None = None,
    timeout_sec: int | None = 60,
) -> dict[str, Any]:
    """Run ``nv-shaderdebugger-configurator.exe`` (use ``extra_args=['--help']`` to discover flags)."""
    return await shaders_mod.shaderdebugger_configure(
        extra_args=extra_args, timeout_sec=timeout_sec
    )


# ---------------------------------------------------------------------------
# UI hand-off
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_open_in_ui(
    path: str | None = None,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Spawn ``ngfx-ui.exe`` to open a capture / gputrace / project file in
    the full Nsight Graphics UI.

    The process is registered as a launch session — you can stop it later via
    ``ngfx_launch_stop``.
    """
    return ui_mod.open_in_ui(path=path, extra_args=extra_args)


# ---------------------------------------------------------------------------
# Capture watcher / wait-for-new-capture
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_wait_for_new_capture(
    dirs: list[str] | None = None,
    kinds: list[str] | None = None,
    timeout_sec: float = 300.0,
    poll_interval_sec: float = 1.5,
    stable_for_sec: float = 2.5,
) -> dict[str, Any]:
    """Poll one or more directories until a new capture (or GPU trace) lands,
    its size stabilises, then return its path.

    Use this for hotkey-driven workflows: start the app in the background
    with ``capture_hotkey=True``, then call this to block until the user
    presses F11 (or until ``timeout_sec`` elapses). If ``dirs`` is omitted,
    the standard Nsight Graphics capture + gputrace output directories are
    used.
    """
    s = get_settings()
    watch_dirs: list[Path] = []
    if dirs:
        watch_dirs.extend(Path(d) for d in dirs)
    else:
        if s.captures_dir.is_dir():
            watch_dirs.append(s.captures_dir)
        if s.gputrace_dir.is_dir():
            watch_dirs.append(s.gputrace_dir)
    return await watch_mod.wait_for_new_capture(
        watch_dirs,
        kinds=tuple(kinds) if kinds else ("graphics_capture", "gpu_trace"),
        timeout_sec=timeout_sec,
        poll_interval_sec=poll_interval_sec,
        stable_for_sec=stable_for_sec,
    )


# ---------------------------------------------------------------------------
# Doctor / health check + tool-help introspection
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_doctor() -> dict[str, Any]:
    """One-shot health check: install discovery, every tool path, layer
    scripts, output-dir writability, ``nvidia-smi`` driver/GPU info, and
    the Vulkan implicit/explicit-layer registry. Reports a list of
    ``issues`` you should fix before running captures.
    """
    return doctor_mod.doctor()


@mcp.tool()
async def ngfx_tool_help(tool: str, flag: str = "--help") -> dict[str, Any]:
    """Run ``<tool> --help`` (or ``--help-all`` for ngfx) to discover the
    exact flags supported by your installed version of any Nsight binary.

    ``tool`` ∈ {"ngfx", "ngfx_capture", "ngfx_replay", "ngfx_rpc",
    "ngfx_ui", "aftermath_control", "aftermath_monitor", "aftermath_format",
    "remote_monitor", "shaderdebugger_configurator", "glslang"}.
    """
    if tool not in TOOL_DEFINITIONS:
        return {"ok": False, "error": f"unknown tool {tool!r}"}
    s = get_settings()
    exe = s.require_tool(tool)
    res = await run_async([str(exe), flag], tool=tool, timeout=30)
    return result_to_dict(res)


# ---------------------------------------------------------------------------
# Function-stream raw sample + cross-capture diff
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_function_stream_sample(
    capture: str, head: int = 50, tail: int = 0
) -> dict[str, Any]:
    """Return the first ``head`` (and optionally last ``tail``) raw lines
    of the recorded function stream.

    Useful for verifying the function-stream parser is recognising your
    Nsight version's output format — if ``ngfx_index_events`` is reporting
    ``unrecognised_lines > 0``, look here to see what the lines actually
    look like and report the format so the parser can be extended.
    """
    _, path = _resolve_capture(capture)
    cache = events_mod._cache_root_for(path)
    dump = cache / "functions.txt"
    if not dump.is_file():
        await events_mod.index_capture_functions(path)
    text = dump.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    return {
        "path": str(dump),
        "total_lines": len(lines),
        "head_lines": lines[:head],
        "tail_lines": lines[-tail:] if tail > 0 else [],
    }


@mcp.tool()
async def ngfx_function_stream_diff(
    capture_a: str, capture_b: str, by: str = "name"
) -> dict[str, Any]:
    """Diff the indexed function streams of two captures.

    ``by`` ∈ {"name", "kind"}. Returns per-bucket counts in A vs B, plus
    the delta. Useful for regression triage ("which API calls are new in
    capture B vs A?").
    """
    _, path_a = _resolve_capture(capture_a)
    _, path_b = _resolve_capture(capture_b)
    db_a = events_mod._cache_root_for(path_a) / "functions.db"
    db_b = events_mod._cache_root_for(path_b) / "functions.db"
    if not db_a.is_file():
        await events_mod.index_capture_functions(path_a)
    if not db_b.is_file():
        await events_mod.index_capture_functions(path_b)
    a_hist = {row[by]: row["count"] for row in events_mod.call_histogram(db_a, by=by, limit=10000)}
    b_hist = {row[by]: row["count"] for row in events_mod.call_histogram(db_b, by=by, limit=10000)}
    keys = sorted(set(a_hist) | set(b_hist))
    rows: list[dict[str, Any]] = []
    for k in keys:
        ac = a_hist.get(k, 0)
        bc = b_hist.get(k, 0)
        if ac != bc:
            rows.append({by: k, "count_a": ac, "count_b": bc, "delta": bc - ac})
    rows.sort(key=lambda r: abs(r["delta"]), reverse=True)
    return {
        "by": by,
        "captures": {"a": str(path_a), "b": str(path_b)},
        "changed_buckets": rows[:500],
        "total_a": sum(a_hist.values()),
        "total_b": sum(b_hist.values()),
    }


# ---------------------------------------------------------------------------
# Triage macro
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_capture_quick_triage(capture: str, top_n: int = 20) -> dict[str, Any]:
    """Run the full 'first look' pipeline on a capture in one call:

      * register a session handle,
      * parse ``--metadata`` summary,
      * build the function index,
      * dump a kind histogram,
      * dump the top-``top_n`` API calls by frequency,
      * fetch the first 25 draws and the first 25 dispatches (if any).

    Designed to be the very first tool you call after capturing — the
    response is a compact pre-digested view the model can reason about
    without round-tripping for each piece.
    """
    sess, path = _resolve_capture(capture)
    if sess is None:
        sess = get_sessions().open_capture(path)
    summary = await capture_info.capture_metadata(path)
    sess.metadata = summary
    sess.metadata_mtime = path.stat().st_mtime
    fn_idx = await events_mod.index_capture_functions(path)
    obj_idx = await objects_mod.index_capture_objects(path)
    fn_db = events_mod._cache_root_for(path) / "functions.db"
    obj_db = events_mod._cache_root_for(path) / "objects.db"
    return {
        "handle": sess.handle,
        "path": str(path),
        "summary": summary,
        "function_index": fn_idx.to_dict(),
        "object_index": obj_idx.to_dict(),
        "kind_histogram": events_mod.call_histogram(fn_db, by="kind"),
        "top_calls_by_name": events_mod.call_histogram(fn_db, by="name", limit=top_n),
        "first_draws": events_mod.query_calls(fn_db, kind="draw", limit=25),
        "first_dispatches": events_mod.query_calls(fn_db, kind="dispatch", limit=25),
        "first_barriers": events_mod.query_calls(fn_db, kind="barrier", limit=25),
        "pipelines": objects_mod.query_objects(obj_db, category="pipeline", limit=top_n),
        "shaders": objects_mod.query_objects(obj_db, category="shader", limit=top_n),
        "top_resources": objects_mod.query_objects(obj_db, category="resource", limit=top_n),
    }


# ---------------------------------------------------------------------------
# Redistributables + registry
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_list_d3d12_redist(preview: bool = False) -> dict[str, Any]:
    """List the bundled D3D12 Agility SDK redistributable shipped with
    Nsight Graphics. Pass ``preview=True`` for the preview SDK.

    Useful when building Generate-C++-Capture exes that need a matching
    D3D12 runtime alongside them.
    """
    return redist_mod.list_d3d12_redist(preview=preview)


@mcp.tool()
async def ngfx_list_runtime_dlls() -> dict[str, Any]:
    """List the runtime DLLs (DXC, DXIL, Aftermath, WinPixEventRuntime,
    DirectStorage, NGX/DLSS) bundled in the Nsight Graphics host bin dir.
    """
    return redist_mod.list_runtime_dlls()


@mcp.tool()
async def ngfx_registry_restore(
    dry_run: bool = True, timeout_sec: int | None = 60
) -> dict[str, Any]:
    """Run the bundled ``RegistryRestore.ps1`` to restore Nsight Graphics'
    registry keys to defaults.

    Defaults to ``dry_run=True`` (passes ``-WhatIf`` to PowerShell).
    Genuinely restoring requires elevation; if you see Access Denied,
    re-run elevated.
    """
    path = redist_mod.find_registry_restore_script()
    if path is None:
        return {"ok": False, "error": "RegistryRestore.ps1 not found in host bin dir."}
    argv = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(path),
    ]
    if dry_run:
        argv.append("-WhatIf")
    res = await run_async(argv, tool="RegistryRestore.ps1", timeout=timeout_sec)
    return {**result_to_dict(res), "script_path": str(path), "dry_run": dry_run}


# ---------------------------------------------------------------------------
# MCP Prompts — workflow templates
# ---------------------------------------------------------------------------


@mcp.prompt()
def triage_capture(capture_path: str) -> str:
    """Triage a Graphics Capture file with the right tool sequence."""
    return (
        f"Triage the Graphics Capture at {capture_path!r}. Run these in order:\n"
        f"  1. ngfx_capture_quick_triage(capture={capture_path!r}) — registers it, builds the index, returns a one-shot overview.\n"
        f"  2. Look at the kind_histogram in the result. If draw/dispatch counts look surprising, run ngfx_find_events with the relevant kind to drill in.\n"
        f"  3. If you need full state for a specific call, ngfx_get_event(capture, idx).\n"
        f"  4. If you need to compare against a known-good capture, ngfx_capture_diff + ngfx_function_stream_diff.\n"
        f"Hand off to the UI with ngfx_open_in_ui only if interactive shader-source profiling is needed."
    )


@mcp.prompt()
def hotkey_capture_workflow(exe: str, output_dir: str) -> str:
    """Drive an interactive F11-triggered capture workflow."""
    return (
        f"Capture-on-hotkey workflow for {exe!r}:\n"
        f"  1. ngfx_capture_launched(exe={exe!r}, output_dir={output_dir!r}, "
        f"capture_hotkey=True, bundle_replayer=True, background=True) — returns a launch handle.\n"
        f"  2. Tell the user to play to the spot and press F11.\n"
        f"  3. ngfx_wait_for_new_capture(dirs=[{output_dir!r}]) — blocks until a .ngfx-gfxcap appears and stabilises.\n"
        f"  4. ngfx_capture_quick_triage(capture=<path>) — index + summary.\n"
        f"  5. ngfx_launch_stop(<handle>) to clean up the launcher process."
    )


@mcp.prompt()
def gpu_trace_headless_workflow(exe: str, architecture: str) -> str:
    """Drive a headless GPU Trace run + inspect the report."""
    return (
        f"Headless GPU Trace workflow for {exe!r} on {architecture!r}:\n"
        f"  1. ngfx_gputrace_archs() — confirm the architecture name is accepted.\n"
        f"  2. ngfx_gputrace_launched(exe={exe!r}, architecture={architecture!r}, "
        f"metric_set_name='Top-Level Triage', limit_to_frames=1, set_gpu_clocks='base', auto_export=True).\n"
        f"  3. ngfx_find_recent_captures(kinds=['gpu_trace'], limit=1) to locate the report.\n"
        f"  4. ngfx_open_gputrace(<path>) and ngfx_gputrace_archive(<handle>) to inspect.\n"
        f"  5. For specific manifest data, ngfx_gputrace_read_member(<handle>, 'metrics.json')."
    )


@mcp.prompt()
def ngfx_sdk_integration(api: str, activity: str) -> str:
    """Embed the NGFX in-app SDK in a {api} app to drive {activity} from inside the process."""
    return (
        f"Integrate the NGFX in-app SDK for {api}/{activity}:\n"
        f"  1. ngfx_environment() — confirm SDK headers are discoverable.\n"
        f"  2. ngfx_sdk_snippet(activity={activity!r}, api={api!r}) — get the starter C++.\n"
        f"  3. Add the headers' include_dir to your build, drop the snippet near your "
        f"device init, and wire the start/stop calls into your frame loop.\n"
        f"  4. If you need additional entry points (FrameBoundary, WaitForStatus), "
        f"ngfx_sdk_reference() then ngfx_sdk_header_text(<header>) for full signatures."
    )


# ---------------------------------------------------------------------------
# Proto schema reference (extracted from ngfx-replay binary)
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_proto_schemas() -> dict[str, Any]:
    """Return the protobuf schema inventory extracted from the Nsight binaries.

    The .ngfx-gfxcap capture format is internally protobuf-serialized using
    messages in the ``NV.*`` namespace across 22 .proto files. This tool
    returns:

      * the list of .proto files referenced inside the binaries,
      * every ``Pb*`` message name (~590),
      * every fully-qualified type FQN (~470),
      * a per-namespace histogram.

    Useful for answering "is there a schema for X?" — e.g. PbRootParameter,
    PbBlobEntry (shader bytecode), PbPCSamples (source-level shader profiler).
    """
    return proto_schemas.scan_default_binaries()


@mcp.tool()
async def ngfx_proto_search(pattern: str, limit: int = 200) -> dict[str, Any]:
    """Regex-search the extracted protobuf schema for a name or FQN.

    Examples:
      * pattern='RootParam'     → finds PbRootParameter, PbRootDescriptor, ...
      * pattern='ShaderProf'    → finds PbPCSamples, PbSASSPatchingSession, ...
      * pattern='AccelStructure' → finds ray-tracing AS messages.
    """
    return proto_schemas.search_schemas(pattern, limit=limit)


@mcp.tool()
async def ngfx_proto_describe(message_fqn: str) -> dict[str, Any]:
    """Return the full field-level schema for a protobuf message extracted
    from Nsight's binaries.

    Unlike ``ngfx_proto_schemas`` (which only knows message names), this
    decodes the embedded ``FileDescriptorProto`` blobs and returns the
    real schema — field names, numbers, types, repeated-ness, nested
    messages — recovered via ``google.protobuf.descriptor_pool``.

    ``message_fqn`` is the fully qualified name without the leading dot,
    e.g. ``"NV.EventParameters.Messages.PbFunctionCallDesc"`` or
    ``"NV.PbRootParameter"``. Use ``ngfx_proto_search`` to discover names.
    """
    try:
        reg = proto_descriptors.get_registry()
        return {"ok": True, "schema": reg.describe(message_fqn)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_proto_list_messages(pattern: str | None = None) -> dict[str, Any]:
    """List every fully-qualified message name in the decoded schema pool.

    Optionally filter by a regex ``pattern`` (case-sensitive). The pool is
    built from ``FileDescriptorProto`` blobs embedded in ``ngfx-replay.exe``
    and contains nested types as well as top-level ones.
    """
    try:
        reg = proto_descriptors.get_registry()
        msgs = reg.list_messages()
        if pattern:
            import re as _re
            rx = _re.compile(pattern)
            msgs = [m for m in msgs if rx.search(m)]
        return {"ok": True, "count": len(msgs), "messages": msgs[:1000],
                "truncated": len(msgs) > 1000}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_proto_extract_descriptors(binary_path: str | None = None) -> dict[str, Any]:
    """Re-extract FileDescriptorProto blobs from a Nsight binary and rebuild
    the in-process schema registry.

    Defaults to ``ngfx-replay.exe`` of the active install. Call this once
    after upgrading Nsight or pointing the MCP at a different install root
    — subsequent ``ngfx_proto_describe`` / ``ngfx_proto_list_messages`` calls
    will use the freshly-decoded schemas.
    """
    try:
        b = Path(binary_path) if binary_path else None
        reg = proto_descriptors.build_registry(b)
        return {
            "ok": True,
            "binary_path": str(reg.binary_path),
            "file_count": len(reg.files),
            "summaries": [s.to_dict() for s in reg.summaries],
            "total_messages_in_pool": len(reg.list_messages()),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Capture diff — "git diff for captures"
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_event_stream_diff(
    capture_a: str,
    capture_b: str,
    cluster_min_size: int = 2,
    histogram_min_abs_delta: int = 1,
    args_max_diffs: int = 100,
) -> dict[str, Any]:
    """Diff the per-event function streams of two captures (deeper than
    ``ngfx_capture_diff`` which only diffs the metadata summaries).

    Returns:
      * **function name histogram delta** — "10 more vkCmdBindPipeline in B",
      * **kind histogram delta** — draw / dispatch / barrier counts,
      * **alignment clusters** — contiguous spans inserted/deleted/replaced
        between A and B (computed via LCS over function-name sequences),
      * **arg diff** (optional) — for events that align by position AND
        function name, list pairs where parsed args differ. Requires both
        captures to have a sibling C++-Capture index — produce one with
        ``ngfx_cpp_capture_open_in_ui`` + ``ngfx_cpp_capture_index_calls``.

    Both captures must have their events index built first
    (``ngfx_index_events``).
    """
    try:
        diff = capture_diff_mod.diff_captures(
            Path(capture_a), Path(capture_b),
            cluster_min_size=cluster_min_size,
            histogram_min_abs_delta=histogram_min_abs_delta,
            args_max_diffs=args_max_diffs,
        )
        return {"ok": True, **diff.to_dict()}
    except (FileNotFoundError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Object handle / UID resolver
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_resolve_handle(
    capture: str,
    uid: int | None = None,
    object_name: str | None = None,
    extra_needles: list[str] | None = None,
    max_mentions: int = 1000,
) -> dict[str, Any]:
    """Look up an API object by uid or name, find its create call, and
    enumerate every C++-capture event that mentions it — bucketed by role
    (create / write / bind / draw / dispatch / barrier / destroy / other).

    Requires:
      * objects index built (``ngfx_index_objects``),
      * events index built (``ngfx_index_events``),
      * for the per-mention list: a sibling C++-Capture index. Without
        one we still return the object record + best-effort create-call
        location, just with ``mentions=[]``.

    Pass ``object_name`` for the canonical Nsight name (e.g. "Buffer_91")
    or ``uid`` for the integer id.
    """
    try:
        result = handle_resolver.resolve_handle(
            Path(capture), uid=uid, object_name=object_name,
            extra_needles=extra_needles, max_mentions=max_mentions,
        )
        return {"ok": True, **result.to_dict()}
    except (FileNotFoundError, LookupError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# PSO → DXBC / SPIR-V hash mapping
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_pso_index(
    project_dir: str,
    db_path: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Walk a Generate-C++-Capture project and index PSO → shader-hash
    mappings into SQLite.

    Nsight's CLI does NOT expose the PSO→DXBC-hash link in metadata. The
    generated C++ does: shader bytecode is emitted as ``static const
    unsigned char g_<name>[] = { ... };`` arrays, and PSO creation calls
    reference those byte-array symbols (D3D12) or vkCreateShaderModule
    handles (Vulkan).

    This parses both, hashes blobs (DXBC: built-in MD5 from the container
    bytes 4..20; SPIR-V: SHA-1 of the full blob; ShaderToggler: CRC32 of
    the full bytecode), and writes two tables
    alongside the existing C++-Capture index DB::

        shader_blobs(symbol, format, hash_hex, hash_source,
                     shader_toggler_crc32, declared_byte_count,
                     file_path, line_number, head_hex)
        pso_shaders(pso_symbol, stage, shader_symbol, api, creator,
                    file_path, line_number)

    Run this AFTER ``ngfx_cpp_capture_index_calls`` against the same
    project dir — both tables coexist in the same .db file.
    """
    return pso_resolver.index_project_psos(
        Path(project_dir),
        db_path=Path(db_path) if db_path else None,
        force=force,
    )


@mcp.tool()
async def ngfx_pso_get(db_path: str, pso_symbol: str) -> dict[str, Any]:
    """Look up one PSO's shader stages: each entry is ``{shader_symbol,
    format (dxbc/dxil/spirv), hash_hex, hash_source, declared_byte_count,
    head_hex}``.

    The DXBC hash is the 128-bit MD5 baked into the DXBC container by the
    Microsoft compiler — the same bytes Nsight / PIX / RenderDoc display
    as the shader identity. For SPIR-V, ``hash_hex`` is SHA-1 of the blob.
    """
    rec = pso_resolver.get_pso(Path(db_path), pso_symbol)
    if rec is None:
        return {"ok": False, "error": f"PSO {pso_symbol!r} not in index"}
    return {"ok": True, **rec}


@mcp.tool()
async def ngfx_pso_list(
    db_path: str,
    api: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> dict[str, Any]:
    """List every indexed PSO with a one-line stage summary
    (``VS:g_VS_xxx, PS:g_PS_yyy``). Filter by ``api`` (``d3d12``/
    ``vulkan``)."""
    rows = pso_resolver.list_psos(Path(db_path), api=api, limit=limit, offset=offset)
    return {"ok": True, "psos": rows, "count": len(rows)}


@mcp.tool()
async def ngfx_pso_find_by_shader(
    db_path: str,
    shader_symbol: str | None = None,
    hash_hex: str | None = None,
    shader_toggler_crc32: str | None = None,
) -> dict[str, Any]:
    """Reverse lookup: which PSOs use a given shader? Supply EITHER the
    C-level shader symbol (e.g. ``g_VS_0x1234``), a DXBC/SPIR-V hash, OR
    ShaderToggler's 8-hex-digit CRC32. Useful when a shader-debugger,
    perf trace, or ShaderToggler.ini gives you a hash and you want to know
    every PSO it's bound to."""
    try:
        rows = pso_resolver.find_psos_using_shader(
            Path(db_path),
            shader_symbol=shader_symbol,
            hash_hex=hash_hex,
            shader_toggler_crc32=shader_toggler_crc32,
        )
        return {"ok": True, "pso_references": rows, "count": len(rows)}
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_shader_blobs_list(
    db_path: str,
    format: str | None = None,
    hash_hex: str | None = None,
    shader_toggler_crc32: str | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    """List indexed shader bytecode blobs from a C++-Capture project.
    Filter by ``format`` (``dxbc``/``dxil``/``spirv``/``unknown``) and/or
    ``hash_hex`` (DXBC/SPIR-V exact match) and/or ``shader_toggler_crc32``
    (ShaderToggler's 8-hex-digit CRC32)."""
    rows = pso_resolver.list_shader_blobs(
        Path(db_path),
        format=format,
        hash_hex=hash_hex,
        shader_toggler_crc32=shader_toggler_crc32,
        limit=limit,
    )
    return {"ok": True, "blobs": rows, "count": len(rows)}


@mcp.tool()
async def ngfx_shader_blobs_find_crc32(
    db_path: str,
    crc32_hex: str | None = None,
    crc32_decimal: int | None = None,
    limit: int = 500,
) -> dict[str, Any]:
    """Find shader bytecode blobs by ShaderToggler's hash.

    ShaderToggler stores decimal uint32 values in ``ShaderToggler.ini`` but
    debug notes often use the same value as 8 hex digits. Supply exactly one
    of ``crc32_hex`` (e.g. ``1cf439e7``) or ``crc32_decimal``.
    """
    try:
        rows = pso_resolver.find_shader_blobs_by_shader_toggler_crc32(
            Path(db_path),
            crc32_hex=crc32_hex,
            crc32_decimal=crc32_decimal,
            limit=limit,
        )
        return {"ok": True, "blobs": rows, "count": len(rows)}
    except (ValueError, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_shader_blob_dump(
    db_path: str,
    output_path: str,
    shader_symbol: str | None = None,
    crc32_hex: str | None = None,
    crc32_decimal: int | None = None,
) -> dict[str, Any]:
    """Write one indexed shader bytecode blob back to disk.

    Use ``shader_symbol`` for an exact dump, or supply exactly one
    ShaderToggler CRC form (``crc32_hex`` or ``crc32_decimal``). When a CRC
    matches multiple identical emitted symbols, the first indexed symbol is
    dumped and ``match_count`` reports how many matched.
    """
    try:
        return pso_resolver.dump_shader_blob(
            Path(db_path),
            Path(output_path),
            shader_symbol=shader_symbol,
            crc32_hex=crc32_hex,
            crc32_decimal=crc32_decimal,
        )
    except (LookupError, ValueError, FileNotFoundError, OSError) as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_shader_reflection_bindings(
    blob_path: str | None = None,
    cpp_project_dir: str | None = None,
    shader_symbol: str | None = None,
) -> dict[str, Any]:
    """Parse the RDEF (resource binding) chunk of a DXBC/DXIL shader container.

    Two input modes:

    * ``blob_path`` — raw DXBC/DXIL bytes on disk (typically produced by
      ``ngfx_shader_blob_dump`` or extracted from a capture).
    * ``cpp_project_dir`` + ``shader_symbol`` — pull the bytes from the
      named ``static unsigned char[]`` array in the C++ project on disk.

    Returns a list of resource bindings — each one carries the resource
    name, register class (``SRV`` / ``UAV`` / ``CBV`` / ``SAMPLER``),
    shader register (e.g. ``t0``, ``s0``, ``b1``), register space, and
    bind count. This is the missing link from "shader register" to
    "named resource" used by the CopyRectPS t0 resolution flow.
    """
    if blob_path:
        try:
            data = Path(blob_path).read_bytes()
        except OSError as exc:
            return {"ok": False, "error": f"failed to read blob: {exc}"}
    elif cpp_project_dir and shader_symbol:
        data = cpp_capture_parser.root_signature_blob_bytes(
            Path(cpp_project_dir), shader_symbol
        )
        if data is None:
            return {
                "ok": False,
                "error": f"shader symbol not found in project: {shader_symbol}",
            }
    else:
        return {
            "ok": False,
            "error": "supply either blob_path or (cpp_project_dir + shader_symbol)",
        }
    try:
        return pso_resolver.shader_reflection_bindings(data)
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


@mcp.tool()
async def ngfx_shader_disassembly_summary(
    blob_path: str,
    timeout_sec: int = 30,
) -> dict[str, Any]:
    """Best-effort shader disassembly summary via ``dxc.exe -dumpbin``.

    Runs ``dxc -dumpbin`` against the DXBC/DXIL bytes at ``blob_path`` and
    returns the captured stdout. When dxc is not on PATH or the dump
    fails, returns the RDEF reflection bindings instead so callers still
    get usable structured data.
    """
    import shutil

    blob = Path(blob_path)
    if not blob.is_file():
        return {"ok": False, "error": f"blob not found: {blob}"}
    dxc = shutil.which("dxc")
    if not dxc:
        # Graceful fallback: structured reflection only.
        reflection = pso_resolver.shader_reflection_bindings(blob.read_bytes())
        return {
            "ok": True,
            "tool_used": "rdef_fallback",
            "tool_note": "dxc.exe not on PATH; surfacing structured reflection instead.",
            "reflection": reflection,
        }
    try:
        result = subprocess.run(  # noqa: S603 - trusted dxc path resolution
            [dxc, "-dumpbin", str(blob)],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": f"dxc invocation failed: {exc}"}
    return {
        "ok": result.returncode == 0,
        "tool_used": "dxc",
        "command": [dxc, "-dumpbin", str(blob)],
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


# ---------------------------------------------------------------------------
# Frame cost analysis — top-N expensive draws/dispatches/regions
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_top_n_costs(
    report_or_trace: str,
    n: int = 20,
    kind_filter: str | None = None,
    name_regex: str | None = None,
    csv_basename_hint: str | None = None,
) -> dict[str, Any]:
    """Return the top-N most expensive actions by GPU time across all CSVs
    in a ``ngfx-replay --perf-report-dir`` output, or a
    ``.nsight-gputrace`` archive.

    Column names vary across Nsight versions — this sniffs each CSV for
    plausible "time" / "name" / "kind" columns rather than hardcoding.
    Filters:
      * ``kind_filter`` — substring match against the kind column (or
        name, if no kind col), case-insensitive ("draw", "dispatch").
      * ``name_regex`` — regex over the row name.
      * ``csv_basename_hint`` — limit scan to CSVs matching this hint.

    Returns each row's source CSV, optional event_index, name, kind,
    GPU time (ns), and % of total. Use this to triage "where is the
    frame spending time?" without scrolling the GPU Trace GUI.
    """
    return frame_costs.top_n_costs(
        Path(report_or_trace),
        n=n,
        kind_filter=kind_filter,
        name_regex=name_regex,
        csv_basename_hint=csv_basename_hint,
    )


# ---------------------------------------------------------------------------
# Low-level capture-file inspection (RE-derived)
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_capture_format_info(capture: str) -> dict[str, Any]:
    """Structural inspection of a .ngfx-gfxcap file.

    Returns the file magic, size, SHA-256, and a tentative interpretation of
    the first few header fields. The format is internally protobuf-based —
    see ``ngfx_proto_schemas`` for the message schema reference.

    For content-level questions (objects, calls, summary, screenshot), use
    the JSON-backed tools (``ngfx_capture_summary``, ``ngfx_index_objects``,
    ``ngfx_index_events``) instead — they wrap ``ngfx-replay --metadata*``
    which gives reliable structured output without reinventing the parser.
    """
    _, path = _resolve_capture(capture)
    hdr = capture_format_mod.inspect_header(path)
    return hdr.to_dict()


@mcp.tool()
async def ngfx_capture_lz4_decompress(
    capture: str,
    offset: int,
    length: int,
    uncompressed_size_hint: int | None = None,
) -> dict[str, Any]:
    """Experimental: attempt LZ4-block decompression of a byte range from a
    capture file. Useful for probing the chunk layout. Returns a hex preview
    of the decompressed bytes plus sizes; for unknown blocks, pass a
    generous ``uncompressed_size_hint`` (defaults to ``len(data) * 8``).
    """
    _, path = _resolve_capture(capture)
    data = path.read_bytes()
    end = offset + length
    if offset < 0 or end > len(data):
        return {
            "ok": False,
            "error": f"range [{offset}, {end}] out of bounds (file size {len(data)})",
        }
    chunk = data[offset:end]
    return capture_format_mod.lz4_decompress_block(
        chunk, uncompressed_size_hint=uncompressed_size_hint
    )


@mcp.tool()
async def ngfx_decode_protobuf_wire(
    capture: str, offset: int, length: int, max_fields: int = 200
) -> dict[str, Any]:
    """Experimental: decode a byte range as generic protobuf wire format.

    Returns the parsed top-level fields (field number, wire type, value
    preview). Use after ``ngfx_capture_lz4_decompress`` if you've located a
    decompressed protobuf payload and want to see its top-level structure
    without knowing the schema. Cross-reference field numbers with
    ``ngfx_proto_search`` to match against the schema.
    """
    _, path = _resolve_capture(capture)
    data = path.read_bytes()
    end = offset + length
    if offset < 0 or end > len(data):
        return {
            "ok": False,
            "error": f"range [{offset}, {end}] out of bounds (file size {len(data)})",
        }
    return capture_format_mod.decode_protobuf_wire(
        data[offset:end], max_fields=max_fields
    )


# ---------------------------------------------------------------------------
# Direct capture-file decoder (header / chunks / TOC / events)
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_capture_decode_header(capture: str) -> dict[str, Any]:
    """Decode the wrapper header of a ``.ngfx-capture`` / ``.ngfx-gfxcap``.

    Returns the 4-byte ``nlyp`` file-magic check plus the parsed 48-byte
    mini-header of the first chunk: version, compression flag, compressed
    + uncompressed sizes, chunk-id (``kind``) and its absolute offset.

    The full format is documented in :mod:`nsight_graphics_mcp.capture_decoder`.
    """
    try:
        _, path = _resolve_capture(capture)
        hdr = capture_decoder_mod.decode_header(path)
        return {"ok": True, **hdr.to_dict()}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_capture_decode_chunks(
    capture: str,
    max_chunks: int = 256,
) -> dict[str, Any]:
    """List the first ``max_chunks`` chunks of a capture file.

    Each chunk has a 48-byte mini-header (``elif`` magic + version +
    compression flag + sizes + chunk-id + self-offset). The list is sliced
    to ``max_chunks`` because real captures contain tens of thousands of
    chunks.
    """
    try:
        _, path = _resolve_capture(capture)
        return {"ok": True, **capture_decoder_mod.chunk_summary(path, max_chunks=max_chunks)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_capture_decode_toc(capture: str) -> dict[str, Any]:
    """Decode the ``NV.PbTableOfContents`` chunk of a capture file.

    The TOC is the canonical index built by ``ngfx-capture``: it lists the
    chunk IDs that hold per-event function info, per-resource info, plus
    capture metadata (process name, GPU, primary API, frame counts, UUID,
    thread list).

    Returns a structured dict with ``uuid``, ``num_chunks``, ``num_threads``,
    ``function_info_chunk_ids``, ``resource_info_chunk_ids``, ``metadata``,
    ``api_info``, and ``thread_info``. Requires Nsight Graphics installed
    (the proto descriptor pool is built from ``ngfx-replay.exe``).
    """
    try:
        _, path = _resolve_capture(capture)
        return capture_decoder_mod.parse_table_of_contents(path)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_capture_decompress_chunk_by_id(
    capture: str,
    chunk_id: int,
    preview_bytes: int = 256,
) -> dict[str, Any]:
    """Locate the chunk whose ``kind`` (chunk-id) equals ``chunk_id`` and
    decompress it.

    Returns the chunk header + a hex preview of the first ``preview_bytes``
    bytes of the decompressed payload. Useful for inspecting chunks listed
    in ``ngfx_capture_decode_toc``'s ``function_info_chunk_ids`` /
    ``resource_info_chunk_ids``.
    """
    try:
        _, path = _resolve_capture(capture)
        hdr = capture_decoder_mod.find_chunk_by_kind(path, chunk_id)
        if hdr is None:
            return {"ok": False, "error": f"no chunk with kind={chunk_id} found"}
        data = capture_decoder_mod.decompress_chunk(path, hdr)
        return {
            "ok": True,
            "chunk": hdr.to_dict(),
            "decompressed_size": len(data),
            "preview_hex": data[:preview_bytes].hex(),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_capture_search_payloads(
    capture: str,
    needles: list[str],
    max_chunks: int | None = None,
    max_chunk_uncompressed: int = 32 * 1024 * 1024,
    max_hits: int = 100,
    context_bytes: int = 96,
) -> dict[str, Any]:
    """Search decompressed capture chunks for shader names, hashes, or raw hex bytes."""
    try:
        _, path = _resolve_capture(capture)
        return capture_decoder_mod.search_payloads(
            path,
            needles,
            max_chunks=max_chunks,
            max_chunk_uncompressed=max_chunk_uncompressed,
            max_hits=max_hits,
            context_bytes=context_bytes,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_capture_shader_chunks(
    capture: str,
    shader_name: str | None = None,
    shader_hash: str | None = None,
    max_chunks: int | None = None,
    max_chunk_uncompressed: int = 64 * 1024 * 1024,
    max_hits: int = 200,
    max_strings: int = 80,
) -> dict[str, Any]:
    """Find DXBC/DXIL shader blobs embedded in decompressed capture chunks."""
    try:
        _, path = _resolve_capture(capture)
        return capture_decoder_mod.shader_chunks(
            path,
            shader_name=shader_name,
            shader_hash=shader_hash,
            max_chunks=max_chunks,
            max_chunk_uncompressed=max_chunk_uncompressed,
            max_hits=max_hits,
            max_strings=max_strings,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_capture_chunk_references(
    capture: str,
    target_chunk_id: int | None = None,
    needles: list[str] | None = None,
    include_numeric_chunk_id_refs: bool = True,
    exclude_chunk_ids: list[int] | None = None,
    max_chunks: int | None = None,
    max_chunk_uncompressed: int = 32 * 1024 * 1024,
    max_hits: int = 200,
    context_bytes: int = 96,
) -> dict[str, Any]:
    """Search decompressed capture chunks for references to a chunk id or byte/string needles."""
    try:
        _, path = _resolve_capture(capture)
        return capture_decoder_mod.chunk_references(
            path,
            target_chunk_id=target_chunk_id,
            needles=needles or [],
            include_numeric_chunk_id_refs=include_numeric_chunk_id_refs,
            exclude_chunk_ids=exclude_chunk_ids or [],
            max_chunks=max_chunks,
            max_chunk_uncompressed=max_chunk_uncompressed,
            max_hits=max_hits,
            context_bytes=context_bytes,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_capture_decode_events(
    capture: str,
    start: int = 0,
    limit: int = 200,
    max_chunks_scanned: int | None = None,
) -> dict[str, Any]:
    """Best-effort scan for serialised ``PbFunctionCallDesc`` records.

    .. note::
       In current Nsight captures the per-event records live in a binary
       fixed-stride table, not as repeated ``PbFunctionCallDesc`` messages.
       This tool will usually return zero events for real captures — that's
       expected. Use ``ngfx_index_events`` / ``ngfx_find_events`` for
       reliable per-event data (they wrap ``ngfx-replay --metadata-functions``).

       This tool remains useful for: (a) verifying the chunk iterator finds
       all chunks, (b) inspecting future captures that may switch to a
       protobuf-encoded event stream.
    """
    try:
        _, path = _resolve_capture(capture)
        return capture_decoder_mod.decode_events(
            path, start=start, limit=limit, max_chunks_scanned=max_chunks_scanned,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@mcp.tool()
async def ngfx_capture_event_args(
    capture: str,
    event_index: int,
) -> dict[str, Any]:
    """Look up the per-event arguments at ``event_index`` via direct
    capture decoding.

    Companion to ``ngfx_cpp_capture_event_args`` (which works from a
    Generate-C++-Capture project) — same response shape so callers can
    swap between them.

    See the caveats on ``ngfx_capture_decode_events`` — current captures
    don't store events as protobuf messages, so this typically returns
    ``ok: false`` with a "not found" error. For reliable per-event lookup
    use ``ngfx_cpp_capture_event_args`` or ``ngfx_find_events``.
    """
    try:
        _, path = _resolve_capture(capture)
        rec = capture_decoder_mod.event_args(path, event_index)
        if rec is None:
            return {
                "ok": False,
                "error": (
                    f"event {event_index} not found via direct decoding "
                    "(per-event records are in a binary table, not protobuf)"
                ),
            }
        return {"ok": True, "call": rec}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ---------------------------------------------------------------------------
# Extra replay flags discovered via RE
# ---------------------------------------------------------------------------


@mcp.tool()
async def ngfx_replay_screenshot(
    capture: str,
    output_dir: str,
    frame_indices: list[int] | None = None,
    frame_count: int | None = None,
    start_frame: int | None = None,
    timeout_sec: int | None = None,
) -> dict[str, Any]:
    """Replay a capture and dump per-frame screenshots to ``output_dir``.

    Uses ``ngfx-replay --replay-screenshot --replay-screenshot-*`` flags
    (discovered via reverse-engineering — these aren't in the public
    ``--help``). Lets you grab the actual rendered output of arbitrary
    frames from a capture without opening the UI.

    Provide exactly one of:
      * ``frame_indices`` — comma-separated frame indices (1-based).
      * ``frame_count`` + ``start_frame`` — a contiguous range.
    """
    _, path = _resolve_capture(capture)
    s = get_settings()
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    argv: list[str] = [
        str(s.require_tool("ngfx_replay")),
        "--quiet",
        "--no-block-on-incompatibility",
        "--replay-screenshot",
        str(out),
    ]
    if frame_indices:
        argv += ["--replay-screenshot-indices", ",".join(str(i) for i in frame_indices)]
    elif frame_count is not None:
        argv += ["--replay-screenshot-count", str(frame_count)]
        if start_frame is not None:
            argv += ["--replay-screenshot-start", str(start_frame)]
    argv.append(str(path))
    res = await run_async(argv, tool="ngfx-replay", timeout=timeout_sec)
    files = sorted(out.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True) if out.is_dir() else []
    return {
        **result_to_dict(res),
        "output_dir": str(out),
        "files": [str(f) for f in files[:50]],
    }


@mcp.tool()
async def ngfx_replay_gpu_frametimes(
    capture: str,
    loop_count: int = 1,
    perf_report_dir: str | None = None,
    timeout_sec: int | None = None,
) -> dict[str, Any]:
    """Replay a capture with GPU frametime collection enabled.

    Uses the (undocumented) ``--collect-gpu-frametimes`` flag along with
    ``--perf-report-dir`` to capture per-frame GPU timings into a directory
    you can inspect with ``ngfx_list_perf_report``.
    """
    _, path = _resolve_capture(capture)
    s = get_settings()
    argv: list[str] = [str(s.require_tool("ngfx_replay")), "--quiet", "--collect-gpu-frametimes"]
    if loop_count > 1:
        argv += ["-n", str(loop_count)]
    if perf_report_dir:
        Path(perf_report_dir).mkdir(parents=True, exist_ok=True)
        argv += ["--perf-report-dir", perf_report_dir]
    argv.append(str(path))
    res = await run_async(argv, tool="ngfx-replay", timeout=timeout_sec)
    return result_to_dict(res)


@mcp.tool()
async def ngfx_replay_run_advanced(
    capture: str,
    extra_flags: list[str] | None = None,
    timeout_sec: int | None = None,
) -> dict[str, Any]:
    """Run ``ngfx-replay`` with arbitrary flags discovered via reverse-engineering.

    A non-exhaustive list of flags surfaced by binary analysis (i.e. not in
    public ``--help``) that you can pass via ``extra_flags``:

      * ``--collect-gpu-frametimes`` — per-frame GPU timing
      * ``--diagnostic-checkpoints`` / ``--no-diagnostic-checkpoints``
      * ``--inject-full-frame-perf-marker``
      * ``--enable-rtcore-dump`` — ray-tracing core memory dump
      * ``--enable-ray-tracing-validation``
      * ``--validation`` — generic API validation
      * ``--max-gpu-bound`` — limit GPU concurrency
      * ``--optimize-with-object-metadata-file <file>``
      * ``--no-app-profile`` / ``--no-nv-app-profile-override``
      * ``--no-block-on-incompatibility``
      * ``--no-nvapi-replay`` / ``--no-nvapi-latency-marker-replay``
      * ``--no-nvtech-replay``
      * ``--no-ngx-replay`` / ``--no-nrc-replay``
      * ``--no-dstorage-replay``
      * ``--no-bundled-dlss-plugins`` / ``--bundled-dlss-plugins <dir>``
      * ``--present-fse`` / ``--present-fse-secondary-window``
      * ``--multibuffer`` / ``--multibuffer-record-and-sync`` / ``--multibuffer-wfi-on-frame-end``
      * ``--minimal-sync-after-reset`` / ``--skip-explicit-cpu-wait``
      * ``--record-unsubmitted-commands``
      * ``--build-invalid-gpu-memory-objects``
      * ``--force-reallocate-gpu-memory-objects``, ``--force-reset-gpu-memory-objects``
      * ``--force-reallocate-placed-resources``
      * ``--force-dx12-recycle_commandlists-after-ecl``
      * ``--force-dx12-increasing-fence-values``
      * ``--force-dx12-force-patched-execute-indirect``
      * ``--force-trace-rays-dimensions-to-zero``
      * ``--enable-dx12-application-specific-driver-state``
      * ``--enable-dx12-recreate-at-gpuva``
      * ``--force-dx12-agility-original`` / ``--force-dx12-agility-preview`` / ``--force-disable-dx12-agility``
      * ``--override-dx12-agility <ver>`` / ``--override-dx12-memory-pool-for-uma <mode>``
      * ``--enable-capture-replay-shader-group-handles`` / ``--no-capture-replay-shader-group-handles``
      * ``--disable-micro-maps``
      * ``--timeout-interval <sec>``
      * ``--temp-resource-dir <dir>``
      * ``--no-user-input``
      * ``--message-prefix-info <str>`` / ``--message-prefix-warning <str>`` / ``--message-prefix-error <str>``

    Always prefer the typed tools (``ngfx_replay_run``,
    ``ngfx_replay_screenshot``, ``ngfx_replay_gpu_frametimes``) when
    available; use this for flags they don't surface.
    """
    _, path = _resolve_capture(capture)
    s = get_settings()
    argv: list[str] = [str(s.require_tool("ngfx_replay")), "--quiet"]
    if extra_flags:
        argv.extend(extra_flags)
    argv.append(str(path))
    res = await run_async(argv, tool="ngfx-replay", timeout=timeout_sec)
    return result_to_dict(res)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def serve(*, transport: str = "stdio") -> None:
    """Run the MCP server on the requested transport.

    ``transport`` ∈ {"stdio", "sse", "streamable-http"}.
    """
    if transport == "stdio":
        mcp.run()
    elif transport == "sse":
        mcp.run(transport="sse")
    elif transport == "streamable-http":
        mcp.run(transport="streamable-http")
    else:
        raise ValueError(f"unknown transport: {transport}")


if __name__ == "__main__":
    serve()
