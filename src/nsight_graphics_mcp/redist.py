"""Inspect and surface the bundled redistributables that ship with Nsight
Graphics.

The host bin directory contains:
  * ``D3D12/``         — Microsoft Agility SDK redistributable (current).
  * ``D3D12_preview/`` — Microsoft Agility SDK redistributable (preview).
  * ``GFSDK_Aftermath_Lib.x64.dll`` — NVIDIA Aftermath helper.
  * ``dxcompiler.dll`` / ``dxil.dll`` — DXC runtime + DXIL signer.
  * ``RegistryRestore.ps1`` — restores Nsight Graphics registry keys.

The agility SDK dirs are useful when building Generate-C++-Capture projects
that need a matching D3D12 runtime — copy ``D3D12Core.dll`` and
``d3d12SDKLayers.dll`` (if needed) next to the produced exe and set
``D3D12SDKVersion`` in the source.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import Settings, get_settings, host_bin_dir


def list_d3d12_redist(*, preview: bool = False, settings: Settings | None = None) -> dict[str, Any]:
    s = settings or get_settings()
    bin_dir = host_bin_dir(s.install_root)
    if bin_dir is None:
        return {"ok": False, "error": "Nsight Graphics host bin dir not resolved."}
    sub = "D3D12_preview" if preview else "D3D12"
    d = bin_dir / sub
    if not d.is_dir():
        return {"ok": False, "error": f"{sub}/ not present at {d}"}
    files: list[dict[str, Any]] = []
    for p in sorted(d.rglob("*")):
        if p.is_file():
            files.append({"path": str(p), "name": p.name, "size_bytes": p.stat().st_size})
    return {"ok": True, "dir": str(d), "preview": preview, "files": files}


def list_runtime_dlls(*, settings: Settings | None = None) -> dict[str, Any]:
    """List the DXC / Aftermath / DXIL DLLs bundled with the install."""
    s = settings or get_settings()
    bin_dir = host_bin_dir(s.install_root)
    if bin_dir is None:
        return {"ok": False, "error": "Nsight Graphics host bin dir not resolved."}
    targets = [
        "dxcompiler.dll",
        "dxil.dll",
        "d3dcompiler_47.dll",
        "GFSDK_Aftermath_Lib.x64.dll",
        "WinPixEventRuntime.dll",
        "dstorage.dll",
        "dstoragecore.dll",
        "nvngx_dlss.dll",
        "nvngx_dlssd.dll",
        "nvngx_deepdvc.dll",
    ]
    found: list[dict[str, Any]] = []
    for name in targets:
        p = bin_dir / name
        if p.is_file():
            found.append({"name": name, "path": str(p), "size_bytes": p.stat().st_size})
    return {"ok": True, "host_bin_dir": str(bin_dir), "dlls": found}


def find_registry_restore_script(*, settings: Settings | None = None) -> Path | None:
    s = settings or get_settings()
    bin_dir = host_bin_dir(s.install_root)
    if bin_dir is None:
        return None
    p = bin_dir / "RegistryRestore.ps1"
    return p if p.is_file() else None
