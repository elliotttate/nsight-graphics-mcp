"""Helpers for working with the output of the "Generate C++ Capture" activity.

The activity emits a folder containing a Visual Studio solution (``*.sln``),
project files, source files, and any data resources. This module:

  * locates the solution + the main exe target,
  * invokes MSBuild to compile it,
  * runs the generated exe and captures its output.

We deliberately do not try to parse the C++ to answer per-event queries —
that's the job of the function-stream indexer (``events.py``). If you need
"what's bound at root param N of event G?", build the C++ project AND open
the matching ``.ngfx-gfxcap`` with ``ngfx_open_capture`` then use the event
tools. They complement each other.
"""

from __future__ import annotations

import asyncio
import difflib
import json
import shutil
import sqlite3
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .cli import result_to_dict, run_async

_D3D_CPP_CAPTURE_SERIALIZER_REMOVED = (
    "Serializing apps to C++ capture using D3D11 or D3D12 is no longer supported"
)


def classify_generate_cpp_capture_output(
    *,
    stdout: str = "",
    stderr: str = "",
    returncode: int | None = None,
) -> dict[str, Any] | None:
    """Classify known ``Generate C++ Capture`` terminal output.

    Nsight 2026.1 can still expose the activity but refuse D3D11/D3D12 C++
    serialization after replay initialization. Treat that as a product-level
    capability boundary, not as a missing private executor binding.
    """
    combined = f"{stdout}\n{stderr}"
    if _D3D_CPP_CAPTURE_SERIALIZER_REMOVED in combined:
        return {
            "ok": False,
            "status": "d3d11_d3d12_cpp_capture_serializer_removed",
            "retryable": False,
            "returncode": returncode,
            "message": _D3D_CPP_CAPTURE_SERIALIZER_REMOVED,
            "nsight_guidance": "please migrate to the Graphics Capture Activity",
            "impact": (
                "A private Pylon/BinaryReplay executor can still launch the path, "
                "but this Nsight build refuses to serialize D3D11/D3D12 replay "
                "streams into a C++ Capture project."
            ),
            "recommended_mcp_path": [
                "Use Graphics Capture Activity captures as the canonical artifact.",
                "Use frame-debugger/RPC/event/resource-revision tools for shader triage.",
                "Use replay screenshots and pixel/resource history instead of generated C++ replay editing.",
            ],
        }
    if "No such output directory:" in combined:
        return {
            "ok": False,
            "status": "output_dir_missing",
            "retryable": True,
            "returncode": returncode,
            "message": "Generate C++ Capture requires the output directory to exist before launch.",
        }
    return None


def find_solution(dir_or_file: Path) -> Path | None:
    """Locate the .sln inside a Generate-C++-Capture output dir, or accept it directly."""
    if dir_or_file.is_file() and dir_or_file.suffix.lower() == ".sln":
        return dir_or_file
    if not dir_or_file.is_dir():
        return None
    slns = list(dir_or_file.glob("*.sln"))
    if not slns:
        slns = list(dir_or_file.rglob("*.sln"))
    if not slns:
        return None
    return sorted(slns, key=lambda p: len(p.parts))[0]


def list_exes(build_dir: Path) -> list[Path]:
    return sorted(build_dir.rglob("*.exe"), key=lambda p: p.stat().st_mtime, reverse=True)


async def wait_for_project(
    watch_dir: Path,
    *,
    timeout_sec: float = 900.0,
    poll_interval_sec: float = 1.5,
    stable_for_sec: float = 3.0,
) -> dict[str, Any]:
    """Poll a directory until a Generate-C++-Capture project appears."""
    root = watch_dir
    root.mkdir(parents=True, exist_ok=True)

    def _snapshot() -> dict[Path, float]:
        return {p: p.stat().st_mtime for p in root.rglob("*.sln")}

    baseline = _snapshot()
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout_sec
    while loop.time() < deadline:
        current = _snapshot()
        new_paths = [p for p, m in current.items() if p not in baseline or baseline[p] != m]
        if new_paths:
            target = max(new_paths, key=lambda p: current[p])
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


def _find_msbuild() -> Path | None:
    """Best-effort MSBuild discovery (vswhere → typical install paths → PATH)."""
    vswhere = Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe")
    if vswhere.is_file():
        try:
            import subprocess

            proc = subprocess.run(
                [
                    str(vswhere),
                    "-latest",
                    "-requires",
                    "Microsoft.Component.MSBuild",
                    "-find",
                    r"MSBuild\**\Bin\MSBuild.exe",
                    "-utf8",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in proc.stdout.splitlines():
                p = Path(line.strip())
                if p.is_file():
                    return p
        except (OSError, subprocess.TimeoutExpired):
            pass
    typical = [
        Path(r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe"),
        Path(r"C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"),
        Path(r"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"),
        Path(r"C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"),
    ]
    for p in typical:
        if p.is_file():
            return p
    msbuild = shutil.which("msbuild")
    return Path(msbuild) if msbuild else None


async def build_solution(
    dir_or_sln: Path,
    *,
    configuration: str = "Release",
    platform: str = "x64",
    targets: str | None = None,
    timeout_sec: float | None = 1800,
) -> dict[str, Any]:
    """Invoke MSBuild on a C++-capture project."""
    sln = find_solution(dir_or_sln)
    if sln is None:
        return {"ok": False, "error": f"no .sln found at {dir_or_sln}"}
    msbuild = _find_msbuild()
    if msbuild is None:
        return {
            "ok": False,
            "error": (
                "MSBuild.exe not found. Install Visual Studio 2022 (Community is "
                "sufficient) or the Build Tools, with the 'Desktop development with C++' workload."
            ),
        }
    argv: list[str] = [
        str(msbuild),
        str(sln),
        f"/p:Configuration={configuration}",
        f"/p:Platform={platform}",
        "/m",
        "/nologo",
        "/verbosity:minimal",
    ]
    if targets:
        argv.append(f"/t:{targets}")
    res = await run_async(argv, tool="msbuild", timeout=timeout_sec, cwd=sln.parent)
    out = result_to_dict(res)
    if res.ok:
        out["exes"] = [str(p) for p in list_exes(sln.parent)][:20]
        out["solution"] = str(sln)
    return out


async def run_generated_exe(
    exe: Path,
    *,
    args: list[str] | None = None,
    cwd: str | None = None,
    timeout_sec: float | None = 600,
) -> dict[str, Any]:
    """Run a generated C++-capture exe to verify the repro builds + runs."""
    if not exe.is_file():
        return {"ok": False, "error": f"exe not found: {exe}"}
    argv = [str(exe), *(args or [])]
    res = await run_async(argv, tool="cpp-capture-exe", timeout=timeout_sec, cwd=cwd)
    return result_to_dict(res)


def _inventory_project(project_dir: Path) -> dict[str, Any]:
    suffix_counts: dict[str, int] = {}
    files: list[Path] = []
    for p in project_dir.rglob("*"):
        if not p.is_file():
            continue
        files.append(p)
        suffix = p.suffix.lower() or "<none>"
        suffix_counts[suffix] = suffix_counts.get(suffix, 0) + 1
    source_count = sum(suffix_counts.get(ext, 0) for ext in (".cpp", ".cxx", ".cc", ".c"))
    header_count = sum(suffix_counts.get(ext, 0) for ext in (".h", ".hpp", ".hxx"))
    return {
        "file_count": len(files),
        "source_count": source_count,
        "header_count": header_count,
        "suffix_counts": suffix_counts,
    }


def _load_cpp_function_sequence(db_path: Path, *, limit: int | None = None) -> list[str]:
    conn = sqlite3.connect(db_path)
    try:
        sql = "SELECT function_name FROM cpp_calls ORDER BY event_index"
        params: list[Any] = []
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)
        return [str(r[0]) for r in conn.execute(sql, params).fetchall()]
    finally:
        conn.close()


def _sequence_alignment_summary(
    expected: list[str],
    actual: list[str],
    *,
    max_clusters: int = 30,
    sample_size: int = 12,
) -> dict[str, Any]:
    sm = difflib.SequenceMatcher(a=expected, b=actual, autojunk=False)
    matching_blocks = sm.get_matching_blocks()
    matched = sum(block.size for block in matching_blocks)
    clusters: list[dict[str, Any]] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        clusters.append(
            {
                "kind": tag,
                "expected_range": [i1, i2],
                "actual_range": [j1, j2],
                "expected_size": i2 - i1,
                "actual_size": j2 - j1,
                "expected_sample": expected[i1 : i1 + sample_size],
                "actual_sample": actual[j1 : j1 + sample_size],
            }
        )
    clusters.sort(key=lambda c: -max(int(c["expected_size"]), int(c["actual_size"])))
    denom = max(len(expected), len(actual), 1)
    return {
        "expected_count": len(expected),
        "actual_count": len(actual),
        "matched_count": matched,
        "match_ratio": round(matched / denom, 6),
        "opcode_count": len(sm.get_opcodes()),
        "cluster_count": len(clusters),
        "clusters": clusters[:max_clusters],
        "truncated_clusters": len(clusters) > max_clusters,
    }


async def validate_cpp_capture_export(
    project_dir: Path,
    *,
    capture: Path | None = None,
    db_path: Path | None = None,
    index_calls: bool = True,
    index_psos: bool = True,
    force_index: bool = False,
    metadata_timeout_sec: float | None = 300.0,
    compare_event_sequence: bool = True,
    max_compare_events: int = 20000,
) -> dict[str, Any]:
    """Validate and optionally index a generated C++ Capture project.

    The checks are intentionally pragmatic: solution exists, source files
    exist, the call index has records, and when a source capture is supplied
    the metadata function count is compared against the C++ call count.
    """
    from . import capture_info, cpp_capture_parser, pso_resolver

    project_dir = project_dir.resolve()
    sln = find_solution(project_dir)
    inventory = _inventory_project(project_dir) if project_dir.is_dir() else {}
    checks: list[dict[str, Any]] = [
        {
            "name": "project_dir_exists",
            "ok": project_dir.is_dir(),
            "value": str(project_dir),
        },
        {
            "name": "solution_exists",
            "ok": sln is not None,
            "value": str(sln) if sln else None,
        },
        {
            "name": "source_files_present",
            "ok": bool(inventory.get("source_count", 0)),
            "value": inventory.get("source_count", 0),
        },
    ]

    call_index: dict[str, Any] | None = None
    pso_index: dict[str, Any] | None = None
    if index_calls and project_dir.is_dir():
        idx = cpp_capture_parser.index_cpp_project(project_dir, db_path=db_path, force=force_index)
        call_index = {"ok": True, **idx.to_dict()}
        checks.append(
            {
                "name": "call_index_has_records",
                "ok": idx.record_count > 0,
                "value": idx.record_count,
                "db_path": str(idx.db_path),
            }
        )
        if index_psos:
            pso_index = pso_resolver.index_project_psos(project_dir, db_path=idx.db_path, force=force_index)
    elif index_calls:
        checks.append({"name": "call_index_has_records", "ok": False, "value": 0})

    capture_metadata: dict[str, Any] | None = None
    event_sequence_alignment: dict[str, Any] | None = None
    if capture is not None and capture.is_file():
        try:
            max_records = max_compare_events if compare_event_sequence else 0
            funcs = await capture_info.capture_metadata_functions(
                capture,
                timeout=metadata_timeout_sec,
                max_records=max_records,
            )
            capture_metadata = {
                "capture": str(capture),
                "function_count_total": funcs.get("function_count_total"),
                "truncated": funcs.get("truncated"),
            }
            if call_index is not None and isinstance(funcs.get("function_count_total"), int):
                expected = int(funcs["function_count_total"])
                actual = int(call_index.get("record_count") or 0)
                delta = actual - expected
                checks.append(
                    {
                        "name": "event_count_matches_metadata",
                        "ok": expected == actual,
                        "expected_metadata_functions": expected,
                        "actual_cpp_calls": actual,
                        "delta": delta,
                        "severity": "warning",
                    }
                )
            records = funcs.get("functions")
            if compare_event_sequence and call_index is not None and isinstance(records, list):
                expected_seq = [str(r.get("function_name") or "") for r in records]
                actual_seq = _load_cpp_function_sequence(Path(call_index["db_path"]), limit=max_compare_events)
                event_sequence_alignment = _sequence_alignment_summary(expected_seq, actual_seq)
                checks.append(
                    {
                        "name": "event_sequence_lcs_match",
                        "ok": event_sequence_alignment["match_ratio"] >= 0.98
                        and not funcs.get("truncated", False),
                        "match_ratio": event_sequence_alignment["match_ratio"],
                        "matched_count": event_sequence_alignment["matched_count"],
                        "expected_compared": event_sequence_alignment["expected_count"],
                        "actual_compared": event_sequence_alignment["actual_count"],
                        "severity": "warning",
                    }
                )
        except Exception as exc:
            capture_metadata = {
                "capture": str(capture),
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
            checks.append(
                {
                    "name": "capture_metadata_functions_readable",
                    "ok": False,
                    "error": capture_metadata["error"],
                    "severity": "warning",
                }
            )

    hard_failures = [c for c in checks if not c.get("ok") and c.get("severity") != "warning"]
    warning_failures = [c for c in checks if not c.get("ok") and c.get("severity") == "warning"]
    return {
        "ok": not hard_failures,
        "project_dir": str(project_dir),
        "solution": str(sln) if sln else None,
        "inventory": inventory,
        "checks": checks,
        "hard_failure_count": len(hard_failures),
        "warning_count": len(warning_failures),
        "call_index": call_index,
        "pso_index": pso_index,
        "capture_metadata": capture_metadata,
        "event_sequence_alignment": event_sequence_alignment,
    }


def saved_cpp_output_dir_settings_plan(
    output_dir: Path,
    *,
    organization: str = "NVIDIA Corporation",
    application: str = "Nsight Graphics",
    registry_key: str | None = None,
) -> dict[str, Any]:
    """Return candidate Qt/QSettings locations for C++ serialization output."""
    output_dir = output_dir.resolve()
    key = registry_key or rf"HKCU\Software\{organization}\{application}"
    escaped_key = key.replace("'", "''")
    escaped_value = str(output_dir).replace("'", "''")
    return {
        "ok": True,
        "setting_name": "Serialization Save Directory",
        "output_dir": str(output_dir),
        "qsettings": {
            "organization": organization,
            "application": application,
            "registry_key": key,
            "confidence": "candidate_default_qsettings_path",
            "evidence": (
                "BattlePlugin reads Nvda::Graphics::Settings::SerializationSaveDirectory through QSettings(); "
                "ngfx-ui.exe and BattlePlugin.dll embed 'NVIDIA Corporation' and 'Nsight Graphics' strings."
            ),
        },
        "powershell_preview": (
            f"New-Item -Path 'Registry::{escaped_key}' -Force | Out-Null; "
            f"New-ItemProperty -Path 'Registry::{escaped_key}' "
            f"-Name 'Serialization Save Directory' -Value '{escaped_value}' "
            "-PropertyType String -Force | Out-Null"
        ),
        "caveat": (
            "QSettings() uses the Nsight process organization/application names. "
            "Override organization/application or registry_key if IDA/live registry evidence shows a different path."
        ),
    }


def set_saved_cpp_output_dir_setting(
    output_dir: Path,
    *,
    organization: str = "NVIDIA Corporation",
    application: str = "Nsight Graphics",
    registry_key: str | None = None,
    write: bool = False,
) -> dict[str, Any]:
    """Preview or write the candidate Windows QSettings registry value."""
    plan = saved_cpp_output_dir_settings_plan(
        output_dir,
        organization=organization,
        application=application,
        registry_key=registry_key,
    )
    if not write:
        return {**plan, "written": False}
    key = str(plan["qsettings"]["registry_key"])
    ps = plan["powershell_preview"]
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return {
        **plan,
        "written": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
        "registry_key": key,
    }


D3D_CPP_CAPTURE_DEPRECATION_MESSAGE = (
    "Serializing apps to C++ capture using D3D11 or D3D12 is no longer supported"
)

# NVIDIA's deprecation timeline for D3D11/D3D12 C++ Capture export, verified
# against the release notes shipped with each version:
#
#   2025.5  — D3D12 still works; release-notes "Deprecations" section warns it
#             will be removed in a future release.
#   2026.1  — D3D12 raises the runtime error in
#             ``D3D_CPP_CAPTURE_DEPRECATION_MESSAGE`` and refuses to export.
#             Vulkan still works but is now in the same warned state.
#
# Mapping is keyed by the major.minor prefix of the install directory.
# Add more entries as new versions ship.
D3D_CPP_CAPTURE_STATUS_BY_VERSION: dict[str, dict[str, Any]] = {
    "2024": {"d3d_works": True, "vulkan_works": True, "notes": "fully supported"},
    "2025.4": {"d3d_works": True, "vulkan_works": True, "notes": "fully supported"},
    "2025.5": {
        "d3d_works": True,
        "vulkan_works": True,
        "notes": "D3D12 supported; release notes warn of upcoming removal.",
    },
    "2025.6": {
        "d3d_works": True,
        "vulkan_works": True,
        "notes": "treat as 2025.5 unless probed live.",
    },
    "2026.1": {
        "d3d_works": False,
        "vulkan_works": True,
        "notes": (
            "D3D11/D3D12 C++ Capture export was removed; activity errors out "
            "with 'Serializing apps to C++ capture using D3D11 or D3D12 is no "
            "longer supported'. Vulkan still works but is now deprecation-"
            "warned."
        ),
    },
    "2026.2": {
        "d3d_works": False,
        "vulkan_works": True,
        "notes": "treat as 2026.1 unless probed live.",
    },
}


def _version_status_from_install_root(install_root: Path) -> dict[str, Any]:
    """Look up the D3D-capture status table from the install path's version."""
    name = install_root.name
    # name looks like "Nsight Graphics 2026.1.0" — pull the version token.
    parts = name.split()
    version = next(
        (
            p
            for p in parts
            if p[:4].isdigit() and "." in p
        ),
        None,
    )
    if version is None:
        return {
            "version": None,
            "d3d_works": None,
            "vulkan_works": None,
            "notes": f"could not parse version from install root: {name!r}",
        }
    # Try most-specific first: "2026.1.0" -> "2026.1" -> "2026".
    keys = []
    bits = version.split(".")
    for i in range(len(bits), 0, -1):
        keys.append(".".join(bits[:i]))
    for key in keys:
        if key in D3D_CPP_CAPTURE_STATUS_BY_VERSION:
            return {"version": version, **D3D_CPP_CAPTURE_STATUS_BY_VERSION[key]}
    return {
        "version": version,
        "d3d_works": None,
        "vulkan_works": None,
        "notes": (
            f"no deprecation table entry for {version!r}; assuming D3D works "
            "unless proven otherwise."
        ),
    }


def saved_capture_route_probe(
    install_root: Path,
    *,
    extra_dlls: list[Path] | None = None,
    needles_extra: list[str] | None = None,
) -> dict[str, Any]:
    """Probe the installed Nsight to decide which saved-capture → C++ project
    route is alive in this version.

    Runs ``ngfx.exe --help`` (parses the activity list) and scans the
    plugin DLLs and main executables for the marker strings the
    documented routes rely on. The result classifies which paths are
    likely to work and which are blocked, with the evidence inline.

    The probe is read-only — it does not launch any activity. Call
    ``saved_capture_route_probe(install_root=Path('...'))`` and feed the
    result into the chooser; the corresponding launcher tools live in
    :mod:`server` (``ngfx_cpp_capture_against_replay``,
    ``ngfx_cpp_capture_launched``).
    """
    import subprocess

    install_root = Path(install_root).resolve()
    host = install_root / "host" / "windows-desktop-nomad-x64"
    ngfx_exe = host / "ngfx.exe"
    if not ngfx_exe.is_file():
        return {"ok": False, "error": f"ngfx.exe not found at {ngfx_exe}"}

    # --- (1) CLI activity list -------------------------------------------------
    activities: list[str] = []
    help_text = ""
    cpp_capture_options: list[str] = []
    try:
        result = subprocess.run(  # noqa: S603
            [str(ngfx_exe), "--help"], capture_output=True, text=True, timeout=30, check=False
        )
        help_text = result.stdout or ""
        in_section = False
        for line in help_text.splitlines():
            if "--activity" in line:
                in_section = True
                continue
            if in_section:
                s = line.strip()
                if not s:
                    if activities:
                        break
                    continue
                if s.startswith("--") or "should be one of" in s:
                    continue
                if line.startswith("  ") and not line.startswith("    "):
                    break
                activities.append(s)
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "error": f"ngfx.exe --help failed: {type(exc).__name__}: {exc}",
        }

    cli_activity_alive = "Generate C++ Capture" in activities

    # Deprecation lookup — the runtime error message is built dynamically (not
    # a static string in any DLL), so version-gating is the reliable signal.
    # See ``D3D_CPP_CAPTURE_STATUS_BY_VERSION`` for the per-release mapping.
    version_status = _version_status_from_install_root(install_root)
    d3d_cpp_capture_deprecated = version_status.get("d3d_works") is False
    deprecation_evidence = [
        {
            "source": "release_notes_lookup",
            "version": version_status.get("version"),
            "notes": version_status.get("notes"),
        }
    ]

    # Look for saved-capture-specific flag in --help-all (best-effort).
    try:
        ha = subprocess.run(  # noqa: S603
            [str(ngfx_exe), "--help-all"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        block = None
        for line in (ha.stdout or "").splitlines():
            if "Generate C++ Capture activity options" in line:
                block = []
                continue
            if block is not None:
                if not line.strip():
                    if cpp_capture_options:
                        break
                    continue
                if line.endswith("activity options:"):
                    break
                cpp_capture_options.append(line.rstrip())
    except Exception:  # noqa: BLE001
        pass

    has_saved_capture_flag = any(
        any(tok in line.lower() for tok in ("--capture", "--input", "saved capture", "replay"))
        for line in cpp_capture_options
    )

    # --- (2) Binary marker scan -----------------------------------------------
    markers = {
        "activity_name_ascii":      b"Generate C++ Capture",
        "request_generate_capture": b"RequestGenerateCaptureCommand",
        "wait_for_capture":         b"WaitForCaptureCompletedCommand",
        "request_save_capture":     b"RequestSaveCaptureCommand",
        "platform_activity_manager": b"IPlatformActivityManager",
        "pylon_replay_fusion":      b"IPylonReplayFusionActivity",
        "cli_command_line":         b"CliCommandLine",
    }
    ui_markers_utf16 = {
        "launch_menu_label":        "Launch for Generate C++ Capture".encode("utf-16le"),
        "attach_menu_label":        "Attach for Generate C++ Capture".encode("utf-16le"),
    }
    for needle in needles_extra or []:
        markers[needle] = needle.encode()

    candidate_paths: list[Path] = [
        host / "ngfx.exe",
        host / "ngfx-ui.exe",
        host / "ngfx-rpc.exe",
        host / "ngfx-replay.exe",
        host / "PylonReplay_PluginInterface.dll",
    ]
    if host.is_dir():
        for sub in host.rglob("*.dll"):
            candidate_paths.append(sub)
    if extra_dlls:
        candidate_paths.extend(extra_dlls)
    seen: set[str] = set()
    paths_unique: list[Path] = []
    for p in candidate_paths:
        if p.is_file() and str(p) not in seen:
            seen.add(str(p))
            paths_unique.append(p)

    hits: dict[str, list[dict[str, Any]]] = {k: [] for k in markers}
    hits_ui: dict[str, list[dict[str, Any]]] = {k: [] for k in ui_markers_utf16}
    for path in paths_unique:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        for key, needle in markers.items():
            c = data.count(needle)
            if c:
                hits[key].append({"count": c, "path": str(path)})
        for key, needle in ui_markers_utf16.items():
            c = data.count(needle)
            if c:
                hits_ui[key].append({"count": c, "path": str(path)})

    # --- (3) Classify routes --------------------------------------------------
    pylon_backend_present = bool(
        hits["request_generate_capture"] and hits["wait_for_capture"]
    )
    ui_menu_live_app_present = bool(
        hits_ui["launch_menu_label"] or hits_ui["attach_menu_label"]
    )
    routes: dict[str, dict[str, Any]] = {}

    d3d_dead_note = (
        "Nsight refuses with: "
        f"{D3D_CPP_CAPTURE_DEPRECATION_MESSAGE!r} (verified live 2026-05-20 on a "
        "D3D12 capture; the activity reaches 'Generating C++ capture' and then "
        "errors out)."
    )

    routes["cli_live_app"] = {
        "alive": cli_activity_alive and not d3d_cpp_capture_deprecated,
        "alive_for_vulkan_only": cli_activity_alive and d3d_cpp_capture_deprecated,
        "tool": "ngfx_cpp_capture_launched",
        "needs_live_app": True,
        "needs_saved_capture_replay": False,
        "evidence": {
            "in_activity_list": cli_activity_alive,
            "options": cpp_capture_options,
            "d3d_deprecated": d3d_cpp_capture_deprecated,
        },
        "note": (
            "Launch the live application with ``--activity 'Generate C++ Capture'``. "
            "Vulkan/VulkanSC paths may still work. " + d3d_dead_note
            if d3d_cpp_capture_deprecated
            else "Launch the live application with ``--activity 'Generate C++ Capture'``."
        ),
    }

    routes["replay_attach"] = {
        "alive": (
            cli_activity_alive
            and not has_saved_capture_flag
            and pylon_backend_present
            and not d3d_cpp_capture_deprecated
        ),
        "alive_for_vulkan_only": (
            cli_activity_alive
            and pylon_backend_present
            and d3d_cpp_capture_deprecated
        ),
        "tool": "ngfx_cpp_capture_against_replay",
        "needs_live_app": False,
        "needs_saved_capture_replay": True,
        "evidence": {
            "activity_in_list": cli_activity_alive,
            "pylon_backend_present": pylon_backend_present,
            "request_generate_capture_hits": hits["request_generate_capture"],
            "wait_for_capture_hits": hits["wait_for_capture"],
            "has_dedicated_saved_capture_flag": has_saved_capture_flag,
            "d3d_deprecated": d3d_cpp_capture_deprecated,
        },
        "note": (
            (
                "Run ``ngfx --activity 'Generate C++ Capture'`` with ``ngfx-replay.exe`` "
                "as the launched exe and the saved capture path as the replay input — "
                "mirrors the proven ``ngfx_gputrace_capture_replay`` pattern. "
            )
            + (d3d_dead_note if d3d_cpp_capture_deprecated else "")
        ),
    }

    routes["ui_menu_saved_capture"] = {
        "alive": False,  # confirmed absent in 2026.1.0 — only Launch/Attach labels exist
        "tool": "ngfx_cpp_capture_saved_ui_automation_attempt",
        "needs_live_app": False,
        "needs_saved_capture_replay": False,
        "evidence": {
            "launch_attach_menu_present": ui_menu_live_app_present,
            "saved_capture_menu_label_found": False,
        },
        "note": (
            "Nsight 2026.1.0 only exposes 'Launch for Generate C++ Capture' / "
            "'Attach for Generate C++ Capture' menu actions; the previously "
            "expected saved-capture-input menu item is gone in this version."
        ),
    }

    routes["pylon_in_process_activity_manager"] = {
        "alive": False,  # the callable entrypoint is not exposed outside the UI process
        "tool": "ngfx_cpp_capture_saved_headless_attempt:pylon",
        "evidence": {
            "iplatformactivitymanager_hits": hits["platform_activity_manager"],
            "ipylonreplayfusionactivity_hits": hits["pylon_replay_fusion"],
        },
        "note": (
            "Symbols + Pylon activity backend are present but the entrypoint is "
            "only callable from inside ngfx-ui.exe; Frida-injection is required."
        ),
    }

    routes["direct_binaryreplay_rpc"] = {
        "alive": False,
        "tool": "ngfx_cpp_capture_saved_direct_rpc_export",
        "evidence": {
            "cli_command_line_hits": hits["cli_command_line"],
            "request_save_capture_hits": hits["request_save_capture"],
        },
        "note": (
            "RequestSaveCapture / RequestGenerateCapture commands are dispatched "
            "over the TPS named pipe; needs the BinaryReplay session-bind handshake "
            "(Gap 1) before they can be invoked from an external client."
        ),
    }

    routes["direct_capture_functioninfo_decode"] = {
        "alive": None,  # implementation-pending; doesn't require Nsight at all
        "tool": "ngfx_capture_decode_d3d12_args  (TODO)",
        "needs_live_app": False,
        "needs_saved_capture_replay": False,
        "evidence": {
            "version_proof": True,
            "depends_on": "FunctionInfo per-event arg decoder (Gap 3)",
        },
        "note": (
            "Direct decode of the saved capture's FunctionInfo chunks. Version-proof "
            "and Nsight-independent. Implementation pending in capture_decoder.py."
        ),
    }

    # Pick the recommended route.
    if routes["replay_attach"]["alive"]:
        recommended = "replay_attach"
    elif routes["cli_live_app"]["alive"]:
        recommended = "cli_live_app"
    else:
        recommended = "direct_capture_functioninfo_decode"

    return {
        "ok": True,
        "install_root": str(install_root),
        "ngfx_exe": str(ngfx_exe),
        "activities": activities,
        "cpp_capture_activity_options": cpp_capture_options,
        "ngfx_help_tail": help_text[-1500:],
        "d3d_cpp_capture_deprecated": d3d_cpp_capture_deprecated,
        "d3d_cpp_capture_deprecation_evidence": deprecation_evidence,
        "routes": routes,
        "recommended_route": recommended,
        "hits_ascii": hits,
        "hits_utf16le": hits_ui,
    }


def capture_replayer_compatibility(
    capture: Path,
    replayer_install_root: Path,
) -> dict[str, Any]:
    """Check whether ``capture`` is replayable by the picked install's
    ``ngfx-replay.exe``.

    Reads the capture's recorded ``MetaData.NsightVersion`` from the
    file's protobuf TOC (no replayer invocation; no device init) and
    compares it against the install's version. Forward compatibility
    (older capture → newer replayer) is officially supported by NVIDIA;
    backward compatibility is **not** — a newer capture may use feature
    enum values the older replayer doesn't recognise, observed at
    runtime as ``Unexpected D3D12_FEATURE value: NN``.
    """
    from . import capture_decoder as cd

    capture = Path(capture).resolve()
    if not capture.is_file():
        return {"ok": False, "error": f"capture not found: {capture}"}

    try:
        toc = cd.parse_table_of_contents(capture)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"failed to read capture TOC: {exc}"}
    md = toc.get("metadata") or {}
    cap_version: str | None = md.get("nsight_version") or None

    replayer_version = _version_status_from_install_root(
        Path(replayer_install_root).resolve()
    ).get("version")

    def _vk(s: str | None) -> tuple:
        if not s:
            return ()
        try:
            return tuple(int(x) for x in s.split("."))
        except ValueError:
            return ()

    cap_v = _vk(cap_version)
    rep_v = _vk(replayer_version)
    recapture_required = bool(cap_v and rep_v and cap_v > rep_v)
    return {
        "ok": True,
        "capture": str(capture),
        "capture_nsight_version": cap_version,
        "process_file_name": md.get("process_file_name"),
        "process_command_line": md.get("process_command_line"),
        "primary_api": md.get("primary_api"),
        "replayer_install_root": str(replayer_install_root),
        "replayer_version": replayer_version,
        "recapture_required": recapture_required,
        "compatible": not recapture_required,
        "rationale": (
            f"Capture was recorded with Nsight {cap_version}, replayer is "
            f"Nsight {replayer_version}. "
            + (
                "Newer capture cannot be reliably loaded by an older replayer "
                "(observed at runtime: 'Unexpected D3D12_FEATURE value: 64'). "
                "Recapture the application with the picked install's "
                "ngfx-capture.exe to produce a compatible artifact."
                if recapture_required
                else "Capture version is not newer than replayer version; should load."
            )
        ),
    }


def recapture_with_picked_install_plan(
    capture: Path,
    install_root: Path,
    output_path: Path | None = None,
) -> dict[str, Any]:
    """Emit the command that re-captures the original application with the
    picked install's ``ngfx-capture.exe``.

    The plan reads ``process_file_name`` and ``process_command_line`` out
    of the saved capture's TOC so the caller doesn't have to remember
    the exact launch arguments. The output is a planned argv plus a
    one-line shell command — ngfx-capture is **not** invoked from here
    (recapturing requires running the actual application, which the
    caller should do interactively).
    """
    from . import capture_decoder as cd

    capture = Path(capture).resolve()
    install_root = Path(install_root).resolve()
    if not capture.is_file():
        return {"ok": False, "error": f"capture not found: {capture}"}
    host = install_root / "host" / "windows-desktop-nomad-x64"
    capture_exe = host / "ngfx-capture.exe"
    if not capture_exe.is_file():
        return {
            "ok": False,
            "error": f"ngfx-capture.exe not found at {capture_exe}",
        }
    toc = cd.parse_table_of_contents(capture)
    md = toc.get("metadata") or {}
    process = md.get("process_file_name")
    cmdline = md.get("process_command_line", "") or ""
    if not process:
        return {
            "ok": False,
            "error": "capture metadata has no process_file_name; cannot reconstruct launch",
        }

    # The captured command line begins with the exe; everything else is args.
    # Strip the leading exe token, respecting "quoted" paths.
    args_str = cmdline.strip()
    if args_str.startswith('"'):
        end = args_str.find('"', 1)
        if end >= 0:
            args_str = args_str[end + 1 :].strip()
        else:
            args_str = ""
    else:
        bits = args_str.split(None, 1)
        args_str = bits[1] if len(bits) > 1 else ""

    out_path = Path(output_path).resolve() if output_path else (
        capture.parent / f"{capture.stem}_recaptured_{install_root.name.replace(' ', '_')}.ngfx-capture"
    )

    argv = [
        str(capture_exe),
        "--exe", str(process),
        "--args", args_str,
        "--frame-count", "1",
        "--hotkey-capture",
        "--output", str(out_path),
    ]
    return {
        "ok": True,
        "evidence_label": "plan",
        "capture_exe": str(capture_exe),
        "process_file_name": process,
        "process_command_line": cmdline,
        "output_capture_path": str(out_path),
        "argv": argv,
        "shell_command": subprocess_list2cmdline_safe(argv),
        "notes": [
            "ngfx-capture launches the live application — the user must run "
            "this interactively (the app needs to reach the same scene as the "
            "original capture for the bug to reproduce).",
            "Press F11 to capture once the bug repro point is on screen "
            "(matches --hotkey-capture). Adjust --frame-count if multi-frame "
            "captures are needed.",
            "After capture, the output file is compatible with this install's "
            "ngfx-replay.exe and the Generate C++ Capture activity, which "
            "unblocks the full SN2 autonomy chain.",
        ],
    }


def subprocess_list2cmdline_safe(argv: list[str]) -> str:
    import subprocess
    return subprocess.list2cmdline(argv)


def _strip_leading_exe(cmdline: str) -> str:
    """Strip the leading exe token from a captured command line, respecting
    a leading quoted path."""
    s = cmdline.strip()
    if not s:
        return ""
    if s.startswith('"'):
        end = s.find('"', 1)
        return s[end + 1 :].strip() if end >= 0 else ""
    bits = s.split(None, 1)
    return bits[1] if len(bits) > 1 else ""


async def recapture_with_picked_install_run(
    capture: Path,
    install_root: Path,
    *,
    frame: int | None = None,
    countdown_ms: int | None = None,
    output_path: Path | None = None,
    terminate_after_capture: bool = True,
    no_hud: bool = True,
    additional_args: list[str] | None = None,
    additional_env: dict[str, str] | None = None,
    timeout_sec: float = 900.0,
    wait_for_output_extra_sec: float = 30.0,
) -> dict[str, Any]:
    """Re-run the captured application via the picked install's ``ngfx-capture.exe``
    with a deterministic frame/countdown trigger, then wait for the new
    capture file to appear on disk.

    This is the autonomous recapture path that closes the 2026.1.0 → 2025.5
    version-compat wall without any human intervention. The captured exe
    path, args, and (if ``frame`` is omitted) the original
    ``MetaData.CaptureBeginFrame`` are read from the source capture's TOC,
    so the only thing the caller has to supply is the source capture +
    the picked install root.

    Trigger selection:

    * If both ``frame`` and ``countdown_ms`` are None, defaults to the
      source capture's ``CaptureBeginFrame`` (e.g. 1698 for the SN2
      capture). That matches the original repro point as long as the
      application's boot path is deterministic.
    * If ``frame`` is set, ``--capture-frame`` is used.
    * If ``countdown_ms`` is set, ``--capture-countdown-timer`` is used.

    ``--terminate-after-capture`` is on by default so the game exits cleanly
    after the capture lands. Polls the output path until it appears or
    until the process exits + ``wait_for_output_extra_sec`` has elapsed.
    """
    import asyncio
    from . import capture_decoder as cd

    capture = Path(capture).resolve()
    install_root = Path(install_root).resolve()
    if not capture.is_file():
        return {"ok": False, "error": f"capture not found: {capture}"}

    host = install_root / "host" / "windows-desktop-nomad-x64"
    capture_exe = host / "ngfx-capture.exe"
    if not capture_exe.is_file():
        return {
            "ok": False,
            "error": f"ngfx-capture.exe not found at {capture_exe}",
        }

    toc = cd.parse_table_of_contents(capture)
    md = toc.get("metadata") or {}
    process = md.get("process_file_name")
    cmdline = md.get("process_command_line", "") or ""
    capture_begin_frame = md.get("capture_begin_frame") or 0
    if not process:
        return {
            "ok": False,
            "error": "capture metadata has no process_file_name; cannot reconstruct launch",
        }
    if frame is None and countdown_ms is None:
        if not capture_begin_frame or int(capture_begin_frame) < 1:
            return {
                "ok": False,
                "error": (
                    "neither frame nor countdown_ms specified, and source "
                    "capture has no usable CaptureBeginFrame metadata"
                ),
            }
        frame = int(capture_begin_frame)

    if output_path is None:
        output_path = (
            capture.parent
            / f"{capture.stem}_recap_{install_root.name.replace(' ', '_')}.ngfx-capture"
        )
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()  # ngfx-capture refuses to overwrite an existing path

    args_after_exe = _strip_leading_exe(cmdline)

    argv: list[str] = [str(capture_exe), "--exe", str(process)]
    if args_after_exe:
        argv.extend(["--args", args_after_exe])
    if terminate_after_capture:
        argv.append("--terminate-after-capture")
    if no_hud:
        argv.append("--no-hud")
    if frame is not None:
        argv.extend(["--capture-frame", str(int(frame))])
    if countdown_ms is not None:
        argv.extend(["--capture-countdown-timer", str(int(countdown_ms))])
    argv.extend(["-o", str(output_path)])
    if additional_args:
        argv.extend(additional_args)

    env = None
    if additional_env:
        import os
        env = dict(os.environ)
        env.update(additional_env)

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    stdout_buf: list[bytes] = []
    stderr_buf: list[bytes] = []
    async def _drain(stream, buf):
        if stream is None:
            return
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                break
            buf.append(chunk)
    drain_tasks = [
        asyncio.create_task(_drain(proc.stdout, stdout_buf)),
        asyncio.create_task(_drain(proc.stderr, stderr_buf)),
    ]
    timed_out = False
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        timed_out = True
        proc.kill()
        await proc.wait()
    await asyncio.gather(*drain_tasks, return_exceptions=True)

    # Wait briefly for the capture file to materialise after the process exits.
    deadline = asyncio.get_event_loop().time() + wait_for_output_extra_sec
    while not output_path.is_file() and asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(0.5)

    out_exists = output_path.is_file()
    out_size = output_path.stat().st_size if out_exists else 0
    stdout = b"".join(stdout_buf).decode("utf-8", errors="replace")
    stderr = b"".join(stderr_buf).decode("utf-8", errors="replace")
    return {
        "ok": bool(out_exists and out_size > 0 and not timed_out),
        "timed_out": timed_out,
        "return_code": proc.returncode,
        "argv": argv,
        "source_capture": str(capture),
        "source_nsight_version": md.get("nsight_version"),
        "source_capture_begin_frame": capture_begin_frame,
        "trigger": {
            "frame": frame,
            "countdown_ms": countdown_ms,
        },
        "install_root": str(install_root),
        "output_capture_path": str(output_path),
        "output_exists": out_exists,
        "output_size_bytes": out_size,
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-2000:],
    }


async def cpp_capture_full_autonomy(
    capture: Path,
    *,
    install_root: Path | None = None,
    api_hint: str = "d3d12",
    frame: int | None = None,
    countdown_ms: int | None = None,
    output_capture_path: Path | None = None,
    output_cpp_dir: Path | None = None,
    terminate_after_capture: bool = True,
    timeout_sec: float = 900.0,
    index_psos: bool = True,
    force_index: bool = False,
    install_roots: list[Path] | None = None,
) -> dict[str, Any]:
    """End-to-end autonomous chain: pick install → compat check → recapture
    if needed → C++ Capture against replay → index project.

    The only mandatory input is ``capture``. The picker chooses the
    newest installed Nsight whose Generate C++ Capture activity still
    supports ``api_hint``; the compatibility check decides whether a
    recapture is needed; the recapture step uses the source capture's
    ``CaptureBeginFrame`` as the deterministic trigger unless ``frame``
    or ``countdown_ms`` is supplied.

    Returns a structured chain of step results. The terminal
    ``project_dir`` field, when present, points at the emitted C++
    project ready for the resolution tools.
    """
    capture = Path(capture).resolve()
    if not capture.is_file():
        return {"ok": False, "error": f"capture not found: {capture}"}

    chain: dict[str, Any] = {"capture": str(capture)}

    # Step 1 — pick the install.
    if install_root is None:
        if install_roots is None:
            from .config import discover_install_roots
            install_roots = [Path(r) for r in discover_install_roots()]
        picked = pick_cpp_capture_capable_install(install_roots, api_hint=api_hint)
        chain["pick_install"] = picked
        if not picked.get("recommended"):
            return {
                "ok": False,
                "stage": "pick_install",
                "error": picked.get("rationale"),
                "chain": chain,
            }
        install_root = Path(picked["recommended"]["install_root"]).resolve()
    chain["install_root"] = str(install_root)

    # Step 2 — compatibility check against the source capture.
    compat = capture_replayer_compatibility(capture, install_root)
    chain["compatibility"] = compat
    if not compat.get("ok"):
        return {"ok": False, "stage": "compatibility", "error": compat.get("error"), "chain": chain}

    # Step 3 — recapture if required.
    if compat.get("recapture_required"):
        recap = await recapture_with_picked_install_run(
            capture,
            install_root,
            frame=frame,
            countdown_ms=countdown_ms,
            output_path=output_capture_path,
            terminate_after_capture=terminate_after_capture,
            timeout_sec=timeout_sec,
        )
        chain["recapture"] = recap
        if not recap.get("ok"):
            return {
                "ok": False,
                "stage": "recapture",
                "error": (
                    "recapture failed; see chain.recapture.stdout_tail / "
                    "stderr_tail for details"
                ),
                "chain": chain,
            }
        cpp_input = Path(recap["output_capture_path"]).resolve()
    else:
        cpp_input = capture

    # Step 4 — Generate C++ Capture against ngfx-replay replaying the
    # (now compatible) capture, then index. The wrapping logic lives in
    # the server module to share argv composition with the standalone
    # tool; here we expose just the path so the caller can chain.
    chain["cpp_input_capture"] = str(cpp_input)
    chain["next_step"] = {
        "tool": "ngfx_cpp_capture_against_replay",
        "args": {
            "capture": str(cpp_input),
            "output_dir": str(output_cpp_dir) if output_cpp_dir else None,
            "auto_index": True,
            "index_psos": index_psos,
            "force_index": force_index,
        },
        "note": (
            "Call ngfx_cpp_capture_against_replay against cpp_input_capture "
            "to emit + index the C++ project. The MCP server's "
            "ngfx_cpp_capture_full_autonomy tool chains this automatically."
        ),
    }
    return {"ok": True, "chain": chain}


def pick_cpp_capture_capable_install(
    install_roots: list[Path],
    *,
    api_hint: str = "d3d12",
) -> dict[str, Any]:
    """Walk every installed Nsight Graphics version and pick the newest one
    whose Generate C++ Capture activity still supports ``api_hint``.

    Default ``api_hint`` is ``"d3d12"`` (the SN2 / common case). Switch to
    ``"vulkan"`` for Vulkan captures.

    Returns ``{"recommended": Path | None, "candidates": [...], "rationale": str}``.
    The recommended install is the highest version among those that still
    support the requested API. If none are capable, ``recommended`` is
    None and ``rationale`` explains the next step (typically: install an
    older version like Nsight 2025.5).
    """
    api_key = api_hint.lower()
    candidates: list[dict[str, Any]] = []
    for root in install_roots:
        root = Path(root).resolve()
        if not root.is_dir():
            continue
        info = _version_status_from_install_root(root)
        api_works = (
            info.get("d3d_works") if api_key.startswith("d3d") else info.get("vulkan_works")
        )
        candidates.append(
            {
                "install_root": str(root),
                "version": info.get("version"),
                "api_works": api_works,
                "notes": info.get("notes"),
            }
        )

    def _version_key(s: str | None) -> tuple:
        if not s:
            return ()
        try:
            return tuple(int(x) for x in s.split("."))
        except ValueError:
            return ()

    working = [c for c in candidates if c["api_works"] is True]
    working.sort(key=lambda c: _version_key(c["version"]), reverse=True)
    if working:
        recommended = working[0]
        rationale = (
            f"Use {recommended['install_root']} (version {recommended['version']}) "
            f"for ``Generate C++ Capture`` of {api_hint} captures. "
            f"{recommended['notes']}"
        )
        return {
            "ok": True,
            "recommended": recommended,
            "candidates": candidates,
            "rationale": rationale,
        }
    return {
        "ok": True,
        "recommended": None,
        "candidates": candidates,
        "rationale": (
            f"No installed Nsight Graphics version supports {api_hint} C++ Capture "
            "export. Either install an older release (e.g. Nsight Graphics 2025.5, "
            "which still supports D3D12 C++ Capture as a deprecated-but-working "
            "feature) or use the direct FunctionInfo capture decoder (Gap 3) once "
            "it is implemented."
        ),
    }


async def saved_capture_ui_automation_attempt(
    capture: Path,
    output_dir: Path,
    *,
    timeout_sec: float = 120.0,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Best-effort Windows UI Automation fallback for Generate C++ Capture.

    The implementation intentionally depends on optional ``pywinauto``. If it
    is not installed, the tool returns a precise blocker instead of claiming
    support. If installed, it opens Nsight UI and attempts the menu/dialog flow;
    callers should still use ``wait_for_project`` and validation afterwards.
    """
    capture = capture.resolve()
    output_dir = output_dir.resolve()
    plan = {
        "backend": "pywinauto",
        "capture": str(capture),
        "output_dir": str(output_dir),
        "steps": [
            "Open capture in ngfx-ui.exe.",
            "Select File -> Activity... (or equivalent Activity menu item).",
            "Choose Generate C++ Capture.",
            "Set the output directory.",
            "Confirm/generate and wait for a .sln under output_dir.",
        ],
    }
    if dry_run:
        return {"ok": True, "dry_run": True, "plan": plan}
    try:
        from pywinauto import Application
        from pywinauto.timings import TimeoutError as PywinautoTimeoutError
    except Exception as exc:
        return {
            "ok": False,
            "status": "pywinauto_unavailable",
            "error": f"{type(exc).__name__}: {exc}",
            "plan": plan,
        }

    from . import ui as ui_mod

    output_dir.mkdir(parents=True, exist_ok=True)
    session = ui_mod.open_in_ui(path=str(capture))
    pid = int(session.get("pid") or 0)
    if pid <= 0:
        return {"ok": False, "status": "ui_launch_pid_missing", "session": session, "plan": plan}
    try:
        app = Application(backend="uia").connect(process=pid, timeout=timeout_sec)
        win = app.top_window()
        win.wait("visible", timeout=timeout_sec)
        automation_log: list[str] = ["connected_to_top_window"]
        menu_attempts = [
            "File->Activity...",
            "File->Activity",
            "Activity->Generate C++ Capture",
            "File->Generate C++ Capture",
        ]
        selected = None
        for menu_path in menu_attempts:
            try:
                win.menu_select(menu_path)
                selected = menu_path
                automation_log.append(f"menu_select:{menu_path}")
                break
            except Exception as exc:
                automation_log.append(f"menu_select_failed:{menu_path}:{type(exc).__name__}")
        return {
            "ok": selected is not None,
            "status": "menu_selected_needs_dialog_completion" if selected else "menu_not_found",
            "session": session,
            "selected_menu": selected,
            "automation_log": automation_log,
            "plan": plan,
            "next_step": "Call ngfx_cpp_capture_wait_for_project after the dialog generates output.",
        }
    except PywinautoTimeoutError as exc:
        return {"ok": False, "status": "ui_timeout", "error": str(exc), "session": session, "plan": plan}
    except Exception as exc:
        return {
            "ok": False,
            "status": "ui_automation_failed",
            "error": f"{type(exc).__name__}: {exc}",
            "session": session,
            "plan": plan,
        }


def shader_fix_regression_score(
    *,
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
    improvement = before_score - after_score
    relative = improvement / before_score if before_score else 0.0
    checks = [
        {
            "name": "roi_improved",
            "ok": improvement >= min_improvement,
            "value": improvement,
            "threshold": min_improvement,
        },
        {
            "name": "repeated_runs",
            "ok": repeated_runs >= 2,
            "value": repeated_runs,
            "threshold": 2,
        },
    ]
    if left_eye_delta is not None:
        checks.append(
            {
                "name": "left_eye_not_regressed",
                "ok": abs(left_eye_delta) <= max_left_eye_delta,
                "value": left_eye_delta,
                "threshold": max_left_eye_delta,
            }
        )
    if event_sequence_match_ratio is not None:
        checks.append(
            {
                "name": "event_sequence_stable",
                "ok": event_sequence_match_ratio >= min_event_sequence_match,
                "value": event_sequence_match_ratio,
                "threshold": min_event_sequence_match,
            }
        )
    if pso_coverage_ratio is not None:
        checks.append(
            {
                "name": "pso_coverage_ok",
                "ok": pso_coverage_ratio >= min_pso_coverage,
                "value": pso_coverage_ratio,
                "threshold": min_pso_coverage,
            }
        )
    failed = [c for c in checks if not c["ok"]]
    return {
        "ok": not failed,
        "decision": "accept" if not failed else "reject",
        "before_score": before_score,
        "after_score": after_score,
        "absolute_improvement": improvement,
        "relative_improvement": round(relative, 6),
        "checks": checks,
        "failed_checks": failed,
    }


def bundle_saved_capture_artifacts(
    out_zip: Path,
    *,
    capture: Path | None = None,
    project_dir: Path | None = None,
    validation: dict[str, Any] | None = None,
    extra_files: list[Path] | None = None,
    include_project_sources: bool = False,
) -> dict[str, Any]:
    """Create a compact handoff bundle for an autonomous shader-fix run."""
    out_zip = out_zip.resolve()
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "capture": str(capture) if capture else None,
        "project_dir": str(project_dir) if project_dir else None,
        "validation": validation,
        "included_files": [],
    }
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if capture and capture.is_file():
            zf.write(capture, f"capture/{capture.name}")
            manifest["included_files"].append(f"capture/{capture.name}")
        if validation is not None:
            data = json.dumps(validation, indent=2, sort_keys=True)
            zf.writestr("reports/export_validation.json", data)
            manifest["included_files"].append("reports/export_validation.json")
        if project_dir and project_dir.is_dir():
            sln = find_solution(project_dir)
            db = project_dir / ".ngfxmcp_cpp_calls.db"
            for p in [sln, db]:
                if p and p.is_file():
                    arc = f"project/{p.relative_to(project_dir).as_posix()}"
                    zf.write(p, arc)
                    manifest["included_files"].append(arc)
            if include_project_sources:
                for p in project_dir.rglob("*"):
                    if p.is_file() and p.suffix.lower() in {".cpp", ".cxx", ".cc", ".c", ".h", ".hpp", ".hxx"}:
                        arc = f"project/{p.relative_to(project_dir).as_posix()}"
                        zf.write(p, arc)
                        manifest["included_files"].append(arc)
        for p in extra_files or []:
            if p.is_file():
                arc = f"extra/{p.name}"
                zf.write(p, arc)
                manifest["included_files"].append(arc)
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
    return {
        "ok": True,
        "zip_path": str(out_zip),
        "file_count": len(manifest["included_files"]) + 1,
        "manifest": manifest,
    }


def _blocked_attempt(backend: str, status: str, reason: str, **extra: Any) -> dict[str, Any]:
    return {
        "backend": backend,
        "ok": False,
        "attempted": False,
        "status": status,
        "reason": reason,
        **extra,
    }


async def saved_capture_headless_attempt(
    capture: Path,
    *,
    output_dir: Path | None = None,
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
    """Try every known saved-capture -> C++ Capture route and validate output.

    Private routes currently return structured blockers when the remaining
    NVIDIA-internal binding is not available. The UI fallback can launch the UI
    and/or wait for a project; once a project exists, validation/indexing runs
    without further user input.
    """
    from . import cpp_bridge_re
    from . import ui as ui_mod

    capture = capture.resolve()
    if not capture.is_file():
        return {"ok": False, "error": f"capture not found: {capture}"}
    watch_dir = (output_dir or (capture.parent / f"{capture.stem}_cpp_capture")).resolve()
    requested = backends or ["pylon_private_activity_manager", "direct_frame_debugger_rpc", "ui_automation"]
    attempts: list[dict[str, Any]] = []

    existing = find_solution(watch_dir)
    if existing is not None:
        validation = await validate_cpp_capture_export(
            existing.parent,
            capture=capture,
            index_calls=index_calls,
            index_psos=index_psos,
            force_index=force_index,
        )
        return {
            "ok": validation["ok"],
            "status": "existing_project_validated",
            "capture": str(capture),
            "output_dir": str(watch_dir),
            "attempts": attempts,
            "validation": validation,
        }

    if "pylon_private_activity_manager" in requested or "pylon" in requested:
        handoff = cpp_bridge_re.pylon_saved_capture_handoff_preview(
            str(capture),
            additional_args=additional_args,
            environment=environment,
            output_dir=str(watch_dir),
        )
        attempts.append(
            _blocked_attempt(
                "pylon_private_activity_manager",
                "blocked_requires_in_process_pylon_activity_manager",
                (
                    "The final Pylon launcher map is pinned, but the callable private "
                    "IPlatformActivityManager/IPylonReplayFusionActivity entrypoint has not "
                    "been exposed outside the Nsight UI process."
                ),
                handoff_preview=handoff,
                next_tool="ngfx_cpp_capture_saved_pylon_handoff_preview",
            )
        )

    if "direct_frame_debugger_rpc" in requested or "direct_rpc" in requested:
        rpc_plan = cpp_bridge_re.frame_debugger_serialize_rpc_plan(
            output_dir=str(watch_dir),
            rpc_session_handle=rpc_session_handle,
        )
        attempts.append(
            _blocked_attempt(
                "direct_frame_debugger_rpc",
                "blocked_requires_binaryreplay_session_binding",
                (
                    "FrameDebugger serialize protobufs and method ids are known, but the "
                    "live BinaryReplay namespace/session/slot binding and MCP-side file "
                    "transfer callback loop are not proven working yet."
                ),
                rpc_plan=rpc_plan,
            )
        )

    if "ui_automation" in requested or "ui_fallback" in requested:
        if not launch_ui_fallback:
            attempts.append(
                _blocked_attempt(
                    "ui_automation",
                    "disabled",
                    "UI fallback launch was disabled by launch_ui_fallback=False.",
                )
            )
        else:
            watch_dir.mkdir(parents=True, exist_ok=True)
            automation = await saved_capture_ui_automation_attempt(capture, watch_dir, timeout_sec=timeout_sec)
            session = automation.get("session")
            if automation.get("status") == "pywinauto_unavailable":
                session = ui_mod.open_in_ui(path=str(capture))
            ui_attempt: dict[str, Any] = {
                "backend": "ui_automation",
                "ok": bool(automation.get("ok")),
                "attempted": True,
                "status": automation.get("status", "ui_opened_private_export_still_requires_generate_action"),
                "session": session,
                "watch_dir": str(watch_dir),
                "automation": automation,
                "automation_driver": {
                    "available": automation.get("status") != "pywinauto_unavailable",
                    "reason": (
                        "The UI fallback can wait/index once the Generate C++ Capture "
                        "project appears. pywinauto automation is best-effort because "
                        "Nsight UI menu/dialog automation varies by version."
                    ),
                },
            }
            if wait_for_project:
                wait_result = await wait_for_project_fn(watch_dir, timeout_sec=timeout_sec)
                ui_attempt["wait_result"] = wait_result
                if wait_result.get("ok"):
                    validation = await validate_cpp_capture_export(
                        Path(wait_result["project_dir"]),
                        capture=capture,
                        index_calls=index_calls,
                        index_psos=index_psos,
                        force_index=force_index,
                    )
                    ui_attempt["validation"] = validation
                    ui_attempt["ok"] = validation["ok"]
                    ui_attempt["status"] = "project_found_validated"
                    attempts.append(ui_attempt)
                    return {
                        "ok": validation["ok"],
                        "status": "ui_fallback_project_validated",
                        "capture": str(capture),
                        "output_dir": str(watch_dir),
                        "attempts": attempts,
                        "validation": validation,
                    }
            attempts.append(ui_attempt)

    return {
        "ok": False,
        "status": "no_backend_completed_export",
        "capture": str(capture),
        "output_dir": str(watch_dir),
        "attempts": attempts,
        "remaining_gap": (
            "Need either a callable in-process Pylon activity-manager bridge, a proven "
            "BinaryReplay session/file-transfer executor, or a bundled Windows UI "
            "Automation driver that can drive the Generate C++ Capture dialog."
        ),
    }


async def wait_for_project_fn(
    watch_dir: Path,
    *,
    timeout_sec: float = 900.0,
    poll_interval_sec: float = 1.5,
    stable_for_sec: float = 3.0,
) -> dict[str, Any]:
    return await wait_for_project(
        watch_dir,
        timeout_sec=timeout_sec,
        poll_interval_sec=poll_interval_sec,
        stable_for_sec=stable_for_sec,
    )
