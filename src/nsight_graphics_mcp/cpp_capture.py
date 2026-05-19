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

import shutil
from pathlib import Path
from typing import Any

from .cli import run_async, result_to_dict


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
