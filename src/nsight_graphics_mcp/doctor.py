"""Health-check helper: combines install discovery, driver/GPU detection,
layer registration, and SDK reachability into a single report.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .config import (
    NGFX_INSTALL_ROOT_ENV,
    TOOL_DEFINITIONS,
    discover_install_roots,
    discover_sdk_versions,
    find_tool,
    get_settings,
    host_bin_dir,
)
from .layers import LAYER_SCRIPTS


def _nvidia_smi() -> dict[str, Any]:
    smi = shutil.which("nvidia-smi")
    if not smi:
        return {"available": False, "reason": "nvidia-smi not on PATH"}
    try:
        proc = subprocess.run(
            [smi, "--query-gpu=name,driver_version,memory.total,uuid", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "reason": str(exc)}
    if proc.returncode != 0:
        return {"available": False, "reason": proc.stderr.strip()[:400]}
    gpus: list[dict[str, str]] = []
    for line in proc.stdout.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 4:
            gpus.append(
                {
                    "name": parts[0],
                    "driver_version": parts[1],
                    "memory_total_mib": parts[2],
                    "uuid": parts[3],
                }
            )
    return {"available": True, "gpus": gpus}


def _check_vk_layer_registry() -> dict[str, Any]:
    """Best-effort: check whether the NV ngfx capture VK layer is registered
    for the current user. We just look for the per-user JSON manifest path
    referenced by the typical layer install scripts.
    """
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return {"available": False, "reason": "winreg not available"}
    layers: dict[str, Any] = {}
    for hive_name, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
        for sub in (
            r"Software\Khronos\Vulkan\ImplicitLayers",
            r"Software\Khronos\Vulkan\ExplicitLayers",
        ):
            try:
                with winreg.OpenKey(hive, sub) as key:
                    i = 0
                    while True:
                        try:
                            name, _value, _type = winreg.EnumValue(key, i)
                        except OSError:
                            break
                        i += 1
                        base = Path(name).name.lower()
                        if "ngfx" in base or "ngfx_capture" in base or "gpu_trace" in base or "nomad" in base:
                            layers.setdefault(f"{hive_name}/{sub}", []).append(name)
            except OSError:
                continue
    return {"available": True, "registered_layers": layers}


def doctor() -> dict[str, Any]:
    """Combined health check report."""
    s = get_settings()
    out: dict[str, Any] = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "env_overrides": {
            k: os.environ.get(k)
            for k in (NGFX_INSTALL_ROOT_ENV, "NSIGHT_GRAPHICS_MCP_CACHE_DIR")
        },
    }

    # install discovery
    roots = discover_install_roots()
    out["installs"] = {
        "count": len(roots),
        "all": [str(r) for r in roots],
        "selected": str(s.install_root) if s.install_root else None,
    }
    out["sdks"] = (
        [str(p) for p in discover_sdk_versions(s.install_root)]
        if s.install_root else []
    )

    # tool discovery
    tools: dict[str, str | None] = {}
    missing: list[str] = []
    for key in TOOL_DEFINITIONS:
        p = find_tool(key, install_root=s.install_root)
        tools[key] = str(p) if p else None
        if p is None:
            missing.append(key)
    out["tools_found"] = tools
    out["tools_missing"] = missing

    # layer scripts
    bin_dir = host_bin_dir(s.install_root)
    if bin_dir is not None:
        layer_scripts = {}
        for key, name in LAYER_SCRIPTS.items():
            layer_scripts[key] = (bin_dir / name).is_file()
        out["layer_scripts_present"] = layer_scripts

    # output dirs writability
    dirs: dict[str, dict[str, Any]] = {}
    for label, p in (
        ("captures_dir", s.captures_dir),
        ("gputrace_dir", s.gputrace_dir),
        ("cache_dir", s.cache_dir),
    ):
        info: dict[str, Any] = {"path": str(p), "exists": p.exists()}
        if p.exists():
            info["is_dir"] = p.is_dir()
            probe = p / ".ngfxmcp_write_probe"
            try:
                probe.write_text("ok", encoding="utf-8")
                probe.unlink(missing_ok=True)
                info["writable"] = True
            except OSError as exc:
                info["writable"] = False
                info["write_error"] = str(exc)
        else:
            info["writable"] = None
        dirs[label] = info
    out["dirs"] = dirs

    out["gpu"] = _nvidia_smi()
    out["vulkan_layer_registry"] = _check_vk_layer_registry()

    # final verdict
    issues: list[str] = []
    if not roots:
        issues.append("no Nsight Graphics install detected")
    elif missing:
        issues.append(f"{len(missing)} tools missing: {missing}")
    if out["gpu"].get("available") is False:
        issues.append(f"nvidia-smi: {out['gpu'].get('reason')}")
    out["issues"] = issues
    out["ok"] = not issues
    return out
