"""Vulkan / VulkanSC / OpenXR layer install helpers.

The Nsight Graphics installation ships several layer-install batch scripts
inside ``host/windows-desktop-nomad-x64`` that register layers in the
Windows registry. We surface them as MCP tools so a remote agent can enable
the NGFX capture/trace layers and the shader debugger layer for the current
user (or system-wide, with elevation).

Scripts (set ``--global`` for system-wide, default is per-user):

  * LAYER_NGFX_INSTALL.bat          — convenience meta-installer
  * VK_LAYER_NV_ngfx_capture.bat    — Vulkan capture layer
  * VK_LAYER_NV_GPU_Trace.bat       — Vulkan GPU Trace layer
  * VK_LAYER_NV_nomad.bat           — Vulkan Nomad debugger layer
  * VK_LAYER_NV_shader_debugger.bat — Vulkan shader debugger layer
  * VKSC_LAYER_NV_ngfx_capture.bat  — Vulkan SC capture layer
  * VKSC_LAYER_NV_GPU_Trace.bat     — Vulkan SC GPU Trace layer
  * VKSC_LAYER_NV_nomad.bat         — Vulkan SC Nomad debugger layer
  * XR_LAYER_NV_ngfx_capture.bat    — OpenXR capture layer
  * XR_LAYER_NV_nomad.bat           — OpenXR Nomad debugger layer
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .cli import run_async
from .config import Settings, get_settings, host_bin_dir


LAYER_SCRIPTS = {
    "ngfx_install": "LAYER_NGFX_INSTALL.bat",
    "vk_ngfx_capture": "VK_LAYER_NV_ngfx_capture.bat",
    "vk_gpu_trace": "VK_LAYER_NV_GPU_Trace.bat",
    "vk_nomad": "VK_LAYER_NV_nomad.bat",
    "vk_shader_debugger": "VK_LAYER_NV_shader_debugger.bat",
    "vksc_ngfx_capture": "VKSC_LAYER_NV_ngfx_capture.bat",
    "vksc_gpu_trace": "VKSC_LAYER_NV_GPU_Trace.bat",
    "vksc_nomad": "VKSC_LAYER_NV_nomad.bat",
    "xr_ngfx_capture": "XR_LAYER_NV_ngfx_capture.bat",
    "xr_nomad": "XR_LAYER_NV_nomad.bat",
}


def list_layer_scripts(settings: Settings | None = None) -> dict[str, Any]:
    s = settings or get_settings()
    bin_dir = host_bin_dir(s.install_root)
    if bin_dir is None:
        return {"ok": False, "error": "Nsight Graphics host bin dir not resolved."}
    out: dict[str, Any] = {"ok": True, "host_bin_dir": str(bin_dir), "scripts": {}}
    for key, name in LAYER_SCRIPTS.items():
        p = bin_dir / name
        out["scripts"][key] = {
            "name": name,
            "path": str(p),
            "present": p.is_file(),
        }
    return out


async def run_layer_script(
    layer_key: str,
    *,
    uninstall: bool = False,
    global_install: bool = False,
    settings: Settings | None = None,
    timeout: float | None = 60.0,
) -> dict[str, Any]:
    """Run a Nsight Graphics layer (un)install batch script.

    The batch scripts accept ``/uninstall`` and ``/global`` switches —
    we forward those.
    """
    s = settings or get_settings()
    name = LAYER_SCRIPTS.get(layer_key)
    if name is None:
        return {"ok": False, "error": f"unknown layer_key {layer_key!r}. Known: {sorted(LAYER_SCRIPTS)}"}
    bin_dir = host_bin_dir(s.install_root)
    if bin_dir is None:
        return {"ok": False, "error": "Nsight Graphics host bin dir not resolved."}
    script = bin_dir / name
    if not script.is_file():
        return {"ok": False, "error": f"layer script not found: {script}"}
    argv: list[str] = ["cmd.exe", "/c", str(script)]
    if uninstall:
        argv.append("/uninstall")
    if global_install:
        argv.append("/global")
    res = await run_async(argv, tool=name, timeout=timeout, cwd=bin_dir)
    return {
        "ok": res.ok,
        "returncode": res.returncode,
        "script": str(script),
        "cmdline": res.cmdline,
        "stdout_tail": res.stdout[-4000:],
        "stderr_tail": res.stderr[-4000:],
        "note": (
            "System-wide install (/global) requires Administrator. If you see "
            "Access Denied / RegOpenKeyEx failures, run the MCP host elevated, "
            "or omit global_install=True for per-user install."
        ),
    }
