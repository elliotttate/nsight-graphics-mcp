"""Shader compilation helpers.

Nsight Graphics ships ``dxcompiler.dll`` + ``glslang.exe`` alongside its host
binaries. We surface a small wrapper around each so the MCP can compile HLSL
or GLSL during a shader-iteration loop (e.g. before re-replaying a capture
with modified shaders, or for verifying that an edit still compiles).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .cli import run_async, result_to_dict
from .config import Settings, find_tool, get_settings, host_bin_dir


async def glslang_compile(
    input_file: str,
    *,
    output_file: str | None = None,
    target_env: str | None = None,
    stage: str | None = None,
    target: str = "spirv",
    extra_args: list[str] | None = None,
    settings: Settings | None = None,
    timeout_sec: float | None = 60,
) -> dict[str, Any]:
    """Invoke ``glslang.exe`` (bundled with Nsight Graphics).

    ``target`` ∈ {"spirv", "validate"}.
    ``stage``  ∈ {"vert","frag","comp","tesc","tese","geom","rgen","rchit","rmiss","rcall","rint","rahit","mesh","task"} (optional).
    ``target_env`` e.g. ``vulkan1.3``, ``opengl4.5``.
    """
    s = settings or get_settings()
    exe = s.require_tool("glslang")
    argv: list[str] = [str(exe)]
    if target == "spirv":
        argv.append("-V")
    elif target == "validate":
        # default behavior; no flag needed
        pass
    if target_env:
        argv += ["--target-env", target_env]
    if stage:
        argv += ["-S", stage]
    if output_file:
        argv += ["-o", output_file]
    if extra_args:
        argv += list(extra_args)
    argv.append(input_file)
    res = await run_async(argv, tool="glslang", timeout=timeout_sec)
    return result_to_dict(res)


async def dxc_compile(
    input_file: str,
    *,
    output_file: str | None = None,
    profile: str | None = None,
    entry_point: str | None = None,
    defines: list[str] | None = None,
    include_dirs: list[str] | None = None,
    extra_args: list[str] | None = None,
    settings: Settings | None = None,
    timeout_sec: float | None = 60,
) -> dict[str, Any]:
    """Invoke the Microsoft DirectX Shader Compiler bundled with Nsight Graphics.

    Looks for ``dxc.exe`` next to ``dxcompiler.dll`` in the Nsight host bin
    directory; falls back to ``dxc`` on PATH.

    ``profile`` is the shader profile (e.g. ``ps_6_6``, ``vs_6_6``).
    """
    s = settings or get_settings()
    bin_dir = host_bin_dir(s.install_root)
    dxc = None
    if bin_dir is not None:
        cand = bin_dir / "dxc.exe"
        if cand.is_file():
            dxc = cand
    if dxc is None:
        from shutil import which
        which_dxc = which("dxc")
        if which_dxc:
            dxc = Path(which_dxc)
    if dxc is None:
        return {
            "ok": False,
            "error": (
                "dxc.exe not found. The DirectX Shader Compiler ships separately; "
                "install it from https://github.com/microsoft/DirectXShaderCompiler/releases"
            ),
        }
    argv: list[str] = [str(dxc)]
    if profile:
        argv += ["-T", profile]
    if entry_point:
        argv += ["-E", entry_point]
    for d in defines or []:
        argv += ["-D", d]
    for inc in include_dirs or []:
        argv += ["-I", inc]
    if output_file:
        argv += ["-Fo", output_file]
    if extra_args:
        argv += list(extra_args)
    argv.append(input_file)
    res = await run_async(argv, tool="dxc", timeout=timeout_sec)
    return result_to_dict(res)


async def shaderdebugger_configure(
    extra_args: list[str] | None = None,
    settings: Settings | None = None,
    timeout_sec: float | None = 60,
) -> dict[str, Any]:
    """Run ``nv-shaderdebugger-configurator.exe`` with the given args.

    Use ``extra_args=["--help"]`` first to see what your install supports.
    """
    s = settings or get_settings()
    exe = s.require_tool("shaderdebugger_configurator")
    argv = [str(exe), *(list(extra_args) if extra_args else [])]
    res = await run_async(argv, tool="nv-shaderdebugger-configurator", timeout=timeout_sec)
    return result_to_dict(res)
