"""Subprocess wrappers for the Nsight Graphics command-line tools.

The Nsight Graphics CLI surface is several different binaries, not a single
batch tool like pixtool. We wrap each one with a small "argument builder" so
the MCP can construct invocations declaratively, plus a process runner that:

* runs synchronously with timeout, OR
* runs in the background and tails stdout/stderr into ring buffers (used for
  long-running ``--activity 'GPU Trace Profiler' --start-after-hotkey`` style
  launches the user drives interactively).

Quoting on Windows is subtle when option values contain spaces — we pass the
argv via Python's default ``subprocess.run(list)`` since the Nsight CLIs use
CLI11/boost::program_options, both of which accept the standard
``CommandLineToArgvW`` form. This is simpler than the pix-mcp ``=value`` trick
because the Nsight tools accept ``--flag value`` as well as ``--flag=value``.
"""

from __future__ import annotations

import asyncio
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from .config import Settings, get_settings


ArgValue = str | int | float | Path


@dataclass
class CliResult:
    tool: str
    returncode: int
    stdout: str
    stderr: str
    cmdline: list[str]
    duration_sec: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def raise_for_status(self) -> None:
        if not self.ok:
            raise CliError(
                f"{self.tool} exited with code {self.returncode}\n"
                f"cmdline: {' '.join(shlex.quote(p) for p in self.cmdline)}\n"
                f"stderr: {self.stderr.strip()}\n"
                f"stdout tail: {self.stdout[-2000:]}"
            )


class CliError(RuntimeError):
    pass


def render_flag(name: str, value: ArgValue | bool | None) -> list[str]:
    """Render one ``(--name, value)`` pair to argv tokens.

    * ``True`` → bare flag (``--name``).
    * ``False`` / ``None`` → omitted.
    * Anything else → ``--name``, ``str(value)`` as two separate tokens.

    Python identifiers with underscores translate to kebab-case (``frame_count``
    → ``--frame-count``).
    """
    if value is None or value is False:
        return []
    flag = "--" + name.replace("_", "-")
    if value is True:
        return [flag]
    return [flag, str(value)]


def build_argv(
    exe: Path,
    *,
    positional: Sequence[ArgValue] = (),
    flags: dict[str, ArgValue | bool | None] | None = None,
    extra: Sequence[str] = (),
) -> list[str]:
    """Assemble a single CLI argv list."""
    out: list[str] = [str(exe)]
    for p in positional:
        out.append(str(p))
    for name, value in (flags or {}).items():
        out.extend(render_flag(name, value))
    out.extend(extra)
    return out


def run(
    argv: Sequence[str],
    *,
    cwd: Path | str | None = None,
    timeout: float | None = None,
    tool: str = "ngfx",
    check: bool = False,
    settings: Settings | None = None,
    extra_env: dict[str, str] | None = None,
) -> CliResult:
    """Run a Nsight CLI to completion."""
    s = settings or get_settings()
    t0 = time.monotonic()
    env = None
    if extra_env:
        import os

        env = {**os.environ, **extra_env}
    try:
        proc = subprocess.run(
            list(argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            timeout=timeout if timeout is not None else s.cli_timeout_sec,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise CliError(
            f"{tool} timed out after {exc.timeout}s\n"
            f"cmdline: {' '.join(shlex.quote(p) for p in argv)}"
        ) from exc
    dt = time.monotonic() - t0
    result = CliResult(
        tool=tool,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        cmdline=list(argv),
        duration_sec=dt,
    )
    if check:
        result.raise_for_status()
    return result


async def run_async(
    argv: Sequence[str],
    *,
    cwd: Path | str | None = None,
    timeout: float | None = None,
    tool: str = "ngfx",
    check: bool = False,
    settings: Settings | None = None,
    extra_env: dict[str, str] | None = None,
) -> CliResult:
    return await asyncio.to_thread(
        run,
        argv,
        cwd=cwd,
        timeout=timeout,
        tool=tool,
        check=check,
        settings=settings,
        extra_env=extra_env,
    )


@dataclass
class BackgroundProcess:
    """A long-running Nsight CLI subprocess (e.g. ``ngfx --activity ...`` driving an
    interactive session, or ``nv-nsight-remote-monitor.exe``).

    Captures stdout/stderr into bounded ring buffers so the MCP can surface
    recent output back to the caller without blocking.
    """

    handle: str
    tool: str
    proc: subprocess.Popen
    cmdline: list[str]
    started_at: float
    stdout_buf: list[str] = field(default_factory=list)
    stderr_buf: list[str] = field(default_factory=list)
    _stdout_thread: threading.Thread | None = None
    _stderr_thread: threading.Thread | None = None
    max_buffer_lines: int = 4000

    def is_running(self) -> bool:
        return self.proc.poll() is None

    def returncode(self) -> int | None:
        return self.proc.poll()

    def recent_stdout(self, n: int = 200) -> str:
        return "".join(self.stdout_buf[-n:])

    def recent_stderr(self, n: int = 200) -> str:
        return "".join(self.stderr_buf[-n:])

    def terminate(self, timeout: float = 5.0) -> int:
        if self.is_running():
            self.proc.terminate()
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=timeout)
        return self.proc.returncode or 0


def start_background(
    handle: str,
    argv: Sequence[str],
    *,
    tool: str = "ngfx",
    cwd: Path | str | None = None,
    extra_env: dict[str, str] | None = None,
) -> BackgroundProcess:
    """Spawn a Nsight CLI in the background and pump stdio into buffers."""
    import os

    env = None
    if extra_env:
        env = {**os.environ, **extra_env}
    proc = subprocess.Popen(
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=str(cwd) if cwd else None,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        bufsize=1,
        env=env,
    )
    bg = BackgroundProcess(
        handle=handle,
        tool=tool,
        proc=proc,
        cmdline=list(argv),
        started_at=time.monotonic(),
    )

    def _pump(stream, buf: list[str]) -> None:
        try:
            for line in stream:
                buf.append(line)
                if len(buf) > bg.max_buffer_lines:
                    del buf[: len(buf) - bg.max_buffer_lines]
        except Exception:
            pass

    bg._stdout_thread = threading.Thread(
        target=_pump, args=(proc.stdout, bg.stdout_buf), daemon=True
    )
    bg._stderr_thread = threading.Thread(
        target=_pump, args=(proc.stderr, bg.stderr_buf), daemon=True
    )
    bg._stdout_thread.start()
    bg._stderr_thread.start()
    return bg


def result_to_dict(r: CliResult, *, tail: int = 4000) -> dict[str, object]:
    return {
        "tool": r.tool,
        "ok": r.ok,
        "returncode": r.returncode,
        "duration_sec": round(r.duration_sec, 3),
        "cmdline": r.cmdline,
        "stdout_tail": r.stdout[-tail:],
        "stderr_tail": r.stderr[-tail:],
    }


# ---------------------------------------------------------------------------
# High-level builders for the ngfx-driven activities
# ---------------------------------------------------------------------------


def ngfx_activity_argv(
    settings: Settings,
    *,
    activity: str,
    exe: Path | str | None = None,
    args: str | None = None,
    working_dir: Path | str | None = None,
    env_pairs: str | None = None,
    output_dir: Path | str | None = None,
    project: Path | str | None = None,
    hostname: str | None = None,
    attach_pid: int | None = None,
    use_proxy: bool = False,
    verbose: bool = False,
    no_timeout: bool = False,
    launch_detached: bool = False,
    platform: str | None = None,
    activity_flags: dict[str, ArgValue | bool | None] | None = None,
) -> list[str]:
    """Build a full ``ngfx.exe --activity '<name>' ...`` argv.

    ``activity`` must be one of:
      * "OpenGL Frame Debugger"
      * "Generate C++ Capture"
      * "Graphics Capture"
      * "GPU Trace Profiler"
    """
    ngfx = settings.require_tool("ngfx")
    argv: list[str] = [str(ngfx), "--activity", activity]
    if platform:
        argv += ["--platform", platform]
    if project:
        argv += ["--project", str(project)]
    if output_dir:
        argv += ["--output-dir", str(output_dir)]
    if hostname:
        argv += ["--hostname", hostname]
    if attach_pid is not None:
        argv += ["--attach-pid", str(attach_pid)]
    if use_proxy:
        argv += ["--use-proxy"]
    if verbose:
        argv += ["--verbose"]
    if no_timeout:
        argv += ["--no-timeout"]
    if launch_detached:
        argv += ["--launch-detached"]
    if exe is not None:
        argv += ["--exe", str(exe)]
    if working_dir is not None:
        argv += ["--dir", str(working_dir)]
    if args is not None:
        argv += ["--args", args]
    if env_pairs is not None:
        argv += ["--env", env_pairs]
    if activity_flags:
        for name, value in activity_flags.items():
            argv += render_flag(name, value)
    return argv
