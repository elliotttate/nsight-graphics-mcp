"""nsight-graphics-mcp — FastMCP server exposing every documented Nsight
Graphics CLI workflow as an MCP tool, plus an NGFX-SDK reference + codegen
layer for in-app integration.

Surface area:

* ``ngfx_environment`` — install / SDK / tool discovery.
* ``ngfx_*_launched`` / ``ngfx_*_attached`` — one-shot launchers for each of
  the four documented activities (Graphics Capture, GPU Trace Profiler,
  Generate C++ Capture, OpenGL Frame Debugger).
* ``ngfx_capture_*`` — direct headless capture via ``ngfx-capture.exe`` (no
  Nsight UI required; produces a ``.ngfx-gfxcap`` file you can replay later).
* ``ngfx_replay_*`` — drive ``ngfx-replay.exe``: replay a capture, dump
  metadata, embed-screenshot, bundle replayer, etc.
* ``ngfx_open_capture`` / ``ngfx_open_gputrace`` — register a session handle
  so subsequent queries can chain off it.
* ``ngfx_aftermath_*`` — Aftermath crash-dump configuration + monitoring.
* ``ngfx_remote_monitor_*`` — start/stop the remote-monitor headless daemon.
* ``ngfx_rpc_start`` — start the headless RPC server.
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
import os
import shlex
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import (
    capture_diff as capture_diff_mod,
    capture_format as capture_format_mod,
    capture_info,
    captures as captures_mod,
    cpp_capture,
    cpp_capture_parser,
    doctor as doctor_mod,
    events as events_mod,
    frame_costs,
    gputrace as gputrace_mod,
    handle_resolver,
    layers,
    objects as objects_mod,
    project as project_mod,
    proto_descriptors,
    proto_schemas,
    redist as redist_mod,
    sdk,
    shaders as shaders_mod,
    ui as ui_mod,
    watch as watch_mod,
)
from .cli import (
    BackgroundProcess,
    CliError,
    build_argv,
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
    LaunchSession,
    SessionManager,
    get_sessions,
)


mcp = FastMCP(
    "nsight-graphics-mcp",
    instructions=(
        "MCP server for NVIDIA Nsight Graphics. Run ngfx_environment first to confirm the install. "
        "For headless capture, use ngfx_capture_launched (drives ngfx-capture.exe and produces a "
        ".ngfx-gfxcap with a bundled replayer). For driving the full Nsight UI activities — "
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
    """Accept either an open capture handle or a path to a .ngfx-gfxcap file."""
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
    """
    s = get_settings()
    flags = _activity_flags(
        frame_count=frame_count,
        frame_index=frame_index,
        elapsed_time=elapsed_time_ms,
        hotkey_capture=hotkey_capture,
        hud_position=hud_position,
        non_portable=non_portable,
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
    sess, path = _resolve_capture(capture)
    s = get_settings()
    argv: list[str] = [str(s.require_tool("ngfx_replay"))]
    if quiet:
        argv.append("--quiet")
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
    return {"mode": "foreground", **result_to_dict(res)}


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
    return {
        **sess.summary(),
        "stdout_tail": sess.bg.recent_stdout(tail_lines),
        "stderr_tail": sess.bg.recent_stderr(tail_lines),
    }


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
async def ngfx_list_perf_report(perf_dir: str) -> dict[str, Any]:
    """List the artifacts written by ``ngfx-replay --perf-report-dir``.

    Auto-decodes small JSON/CSV files inline.
    """
    return gputrace_mod.list_perf_report(Path(perf_dir))


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
    import asyncio

    root = Path(watch_dir)
    root.mkdir(parents=True, exist_ok=True)

    def _snapshot() -> dict[Path, float]:
        return {p: p.stat().st_mtime for p in root.rglob("*.sln")}

    baseline = _snapshot()
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout_sec
    while loop.time() < deadline:
        current = _snapshot()
        new_paths = [p for p, m in current.items()
                     if p not in baseline or baseline[p] != m]
        if new_paths:
            target = max(new_paths, key=lambda p: current[p])
            # wait for stability
            last_size = -1
            stable_since: float | None = None
            stable_deadline = loop.time() + 60.0
            while loop.time() < stable_deadline:
                try:
                    size = target.stat().st_size
                except OSError:
                    size = -1
                now = loop.time()
                if size != last_size:
                    last_size = size
                    stable_since = now
                elif stable_since is not None and (now - stable_since) >= stable_for_sec:
                    return {
                        "ok": True,
                        "project_dir": str(target.parent),
                        "solution": str(target),
                        "size_bytes": size,
                    }
                await asyncio.sleep(poll_interval_sec)
            return {
                "ok": True,
                "project_dir": str(target.parent),
                "solution": str(target),
                "note": "size never fully stabilised, returning anyway",
            }
        await asyncio.sleep(poll_interval_sec)
    return {"ok": False, "timed_out": True, "watched_dir": str(root)}


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
    argv: list[str] = [str(s.require_tool("ngfx_replay")), "--quiet", "--replay-screenshot", str(out)]
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
