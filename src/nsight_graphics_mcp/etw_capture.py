"""ETW kernel-file capture helpers.

These wrap the built-in Windows ``logman`` / ``tracerpt`` tools to capture
file/pipe I/O between ``ngfx-ui.exe`` and ``ngfx-rpc.exe`` at the kernel
level. This is one of the three documented bypasses for the shared-memory
wall described in NSIGHT_SHADER_DEBUG_AUTONOMY.md: ETW sees every file
handle operation regardless of how the user-mode shim is implemented.

Limits:

* ETW exposes handle id + file/pipe path + read/write sizes — **not** the
  buffer contents. Combined with the proto pool's method-id catalogue
  the message sizes can still narrow ``(category, method)``.
* Requires admin / "Performance Log Users" group on Windows.
* The capture must be stopped before the ETL file is finalized.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

# Microsoft-Windows-Kernel-File provider GUID.
KERNEL_FILE_GUID = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}"
# Microsoft-Windows-Kernel-Process — used to filter by image name.
KERNEL_PROCESS_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"


def _logman_path() -> str | None:
    return shutil.which("logman")


def _tracerpt_path() -> str | None:
    return shutil.which("tracerpt")


def etw_environment() -> dict[str, Any]:
    """Probe the environment for ``logman`` / ``tracerpt`` availability."""
    return {
        "ok": True,
        "logman": _logman_path(),
        "tracerpt": _tracerpt_path(),
        "kernel_file_provider": KERNEL_FILE_GUID,
        "kernel_process_provider": KERNEL_PROCESS_GUID,
        "notes": [
            "Both tools are built into Windows; no install needed.",
            "Capture requires admin / Performance Log Users group.",
        ],
    }


def etw_capture_start(
    session_name: str,
    output_etl: Path,
    *,
    extra_providers: list[str] | None = None,
    buffer_size_kb: int = 1024,
    max_file_mb: int = 256,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Create + start a kernel-file ETW session via ``logman``.

    Returns the structured invocation result, including the command line
    that would be run when ``dry_run`` is true. Callers should set
    ``dry_run=True`` from within tests so the OS-level side effect is
    never triggered.
    """
    logman = _logman_path()
    if logman is None and not dry_run:
        return {"ok": False, "error": "logman not on PATH"}

    output_etl = Path(output_etl).resolve()
    output_etl.parent.mkdir(parents=True, exist_ok=True)

    providers = [KERNEL_FILE_GUID, KERNEL_PROCESS_GUID]
    if extra_providers:
        providers.extend(extra_providers)

    create_cmd: list[str] = [
        logman or "logman",
        "create",
        "trace",
        session_name,
        "-o",
        str(output_etl),
        "-ets",
        "-bs",
        str(buffer_size_kb),
        "-max",
        str(max_file_mb),
        "-mode",
        "Circular",
    ]
    for guid in providers:
        create_cmd.extend(["-p", guid, "0xffffffffffffffff", "0xff"])

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "session_name": session_name,
            "output_etl": str(output_etl),
            "command": create_cmd,
            "note": "no command was executed; pass dry_run=False to run.",
        }

    try:
        result = subprocess.run(  # noqa: S603 - command built from sanitized inputs
            create_cmd, capture_output=True, text=True, check=False
        )
    except OSError as exc:
        return {"ok": False, "error": f"logman invocation failed: {exc}"}
    return {
        "ok": result.returncode == 0,
        "session_name": session_name,
        "output_etl": str(output_etl),
        "command": create_cmd,
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def etw_capture_stop(session_name: str, *, dry_run: bool = False) -> dict[str, Any]:
    """Stop a kernel-file ETW session previously started."""
    logman = _logman_path()
    if logman is None and not dry_run:
        return {"ok": False, "error": "logman not on PATH"}
    cmd = [logman or "logman", "stop", session_name, "-ets"]
    if dry_run:
        return {"ok": True, "dry_run": True, "command": cmd}
    try:
        result = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, check=False
        )
    except OSError as exc:
        return {"ok": False, "error": f"logman stop failed: {exc}"}
    return {
        "ok": result.returncode == 0,
        "command": cmd,
        "return_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def etw_capture_summary(
    etl_path: Path,
    *,
    output_xml: Path | None = None,
    output_csv: Path | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Convert an ETL trace to XML/CSV via ``tracerpt`` and summarize counts.

    Even without parsing the XML/CSV, the conversion fact alone is useful
    in CI: it confirms the trace landed on disk. When ``dry_run`` is true
    only the command line is returned.
    """
    etl_path = Path(etl_path).resolve()
    if not dry_run and not etl_path.is_file():
        return {"ok": False, "error": f"etl not found: {etl_path}"}
    tracerpt = _tracerpt_path()
    if tracerpt is None and not dry_run:
        return {"ok": False, "error": "tracerpt not on PATH"}

    if output_xml is None:
        output_xml = etl_path.with_suffix(".xml")
    if output_csv is None:
        output_csv = etl_path.with_suffix(".csv")

    cmd = [
        tracerpt or "tracerpt",
        str(etl_path),
        "-o",
        str(output_xml),
        "-of",
        "XML",
        "-y",
    ]
    csv_cmd = [
        tracerpt or "tracerpt",
        str(etl_path),
        "-o",
        str(output_csv),
        "-of",
        "CSV",
        "-y",
    ]
    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "xml_command": cmd,
            "csv_command": csv_cmd,
            "output_xml": str(output_xml),
            "output_csv": str(output_csv),
        }

    try:
        xml = subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, check=False
        )
        csv = subprocess.run(  # noqa: S603
            csv_cmd, capture_output=True, text=True, check=False
        )
    except OSError as exc:
        return {"ok": False, "error": f"tracerpt invocation failed: {exc}"}

    out: dict[str, Any] = {
        "ok": xml.returncode == 0 and csv.returncode == 0,
        "xml_path": str(output_xml),
        "csv_path": str(output_csv),
        "xml_return_code": xml.returncode,
        "csv_return_code": csv.returncode,
    }
    # Best-effort summary: count lines in the CSV per event name.
    try:
        if output_csv.is_file():
            with output_csv.open("r", encoding="utf-8", errors="replace") as fh:
                counts: dict[str, int] = {}
                for line in fh:
                    field = line.split(",", 2)[0].strip().strip('"')
                    if not field:
                        continue
                    counts[field] = counts.get(field, 0) + 1
            top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:50]
            out["top_event_counts"] = top
            out["total_events"] = sum(counts.values())
    except OSError as exc:
        out["csv_parse_error"] = str(exc)
    return out
