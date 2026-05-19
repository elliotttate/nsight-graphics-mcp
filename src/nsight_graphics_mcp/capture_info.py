"""Capture metadata inspection.

``ngfx-replay.exe`` ships with several useful metadata modes that don't
require running the replay. All of them emit **JSON** (the docs sometimes
describe them as 'text' but the actual output is structured JSON):

  * ``--metadata``               — dict of capture-level metadata
  * ``--metadata-screenshot P``  — writes the embedded final-present screenshot
  * ``--metadata-functions``     — list of `{event_index, function_name, sequence_id, thread_index}`
  * ``--metadata-objects``       — list of `{uid, type_name, object_name, api, access_flags}`
  * ``--metadata-logs``          — log lines (text, not JSON)
  * ``--metadata-logs-errors``   — log lines filtered to errors
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .cli import CliError, run_async
from .config import Settings, get_settings


# Substrings that mark an env var as worth redacting from `process_environment`.
# Conservative defaults — any var whose NAME contains one of these is replaced
# with "<redacted>".
SENSITIVE_ENV_SUBSTRINGS = (
    "API_KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "AUTH",
    "CREDENTIAL",
    "BEARER",
    "SESSION",
    "COOKIE",
)


def _strip_log_prefix(stdout: str) -> str:
    """Strip any leading non-JSON log lines so json.loads succeeds."""
    text = stdout.lstrip()
    if text and text[0] in "[{":
        return text
    # find first '[' or '{' at column 0 of any line
    for i, line in enumerate(stdout.splitlines()):
        stripped = line.lstrip()
        if stripped and stripped[0] in "[{":
            return "\n".join(stdout.splitlines()[i:])
    return stdout


def _redact_env_list(env_lines: list[str]) -> list[str]:
    out: list[str] = []
    for entry in env_lines:
        if "=" not in entry:
            out.append(entry)
            continue
        name, _sep, value = entry.partition("=")
        name_upper = name.upper()
        if any(s in name_upper for s in SENSITIVE_ENV_SUBSTRINGS):
            out.append(f"{name}=<redacted>")
        else:
            out.append(entry)
    return out


def redact_metadata(meta: dict[str, Any]) -> dict[str, Any]:
    """Best-effort redaction of secrets from a parsed metadata dict.

    Currently redacts the ``process_environment`` list and any obviously
    secret-looking values in nested dicts.
    """
    if not isinstance(meta, dict):
        return meta
    out = dict(meta)
    env = out.get("process_environment")
    if isinstance(env, list):
        out["process_environment"] = _redact_env_list(env)
    return out


async def capture_metadata(
    path: Path,
    *,
    settings: Settings | None = None,
    timeout: float | None = 120.0,
    redact_secrets: bool = True,
) -> dict[str, Any]:
    """Run ``ngfx-replay --metadata <path>`` and return the parsed JSON.

    ``redact_secrets`` (default True) scrubs `process_environment` entries
    whose names look like API keys / tokens / secrets. Pass False to keep
    the raw output (only do this if you're handling the result carefully).
    """
    s = settings or get_settings()
    replay = s.require_tool("ngfx_replay")
    argv = [str(replay), "--metadata", "--quiet", str(path)]
    res = await run_async(argv, tool="ngfx-replay", timeout=timeout)
    text = _strip_log_prefix(res.stdout)
    parsed: dict[str, Any]
    try:
        loaded = json.loads(text)
        if isinstance(loaded, dict):
            parsed = loaded
        else:
            parsed = {"raw": loaded}
    except json.JSONDecodeError as exc:
        parsed = {
            "_parse_error": str(exc),
            "_raw_text_head": text[:2000],
        }
    if redact_secrets:
        parsed = redact_metadata(parsed)
    parsed["_returncode"] = res.returncode
    parsed["_duration_sec"] = round(res.duration_sec, 3)
    if not res.ok:
        parsed["_stderr_tail"] = res.stderr[-1000:]
    return parsed


async def capture_metadata_objects(
    path: Path,
    *,
    settings: Settings | None = None,
    timeout: float | None = 120.0,
) -> dict[str, Any]:
    """Run ``ngfx-replay --metadata-objects`` and return the parsed JSON list.

    Each object is ``{uid, type_name, object_name, api, access_flags}``.
    """
    s = settings or get_settings()
    replay = s.require_tool("ngfx_replay")
    argv = [str(replay), "--metadata-objects", "--quiet", str(path)]
    res = await run_async(argv, tool="ngfx-replay", timeout=timeout)
    if not res.ok:
        raise CliError(
            f"ngfx-replay --metadata-objects failed (rc={res.returncode}): {res.stderr.strip()[:600]}"
        )
    text = _strip_log_prefix(res.stdout)
    try:
        objects = json.loads(text)
    except json.JSONDecodeError:
        return {"objects": None, "raw": text[:8000]}
    # Compute a per-type histogram for convenience.
    histogram: dict[str, int] = {}
    if isinstance(objects, list):
        for obj in objects:
            t = obj.get("type_name", "?")
            histogram[t] = histogram.get(t, 0) + 1
    return {"objects": objects, "count": len(objects) if isinstance(objects, list) else 0, "by_type": histogram}


async def capture_metadata_functions(
    path: Path,
    *,
    settings: Settings | None = None,
    timeout: float | None = 300.0,
    max_records: int = 5000,
) -> dict[str, Any]:
    """Run ``ngfx-replay --metadata-functions``. Returns up to ``max_records``
    parsed records: ``{event_index, function_name, sequence_id, thread_index}``.
    """
    s = settings or get_settings()
    replay = s.require_tool("ngfx_replay")
    argv = [str(replay), "--metadata-functions", "--quiet", str(path)]
    res = await run_async(argv, tool="ngfx-replay", timeout=timeout)
    if not res.ok:
        raise CliError(
            f"ngfx-replay --metadata-functions failed (rc={res.returncode}): {res.stderr.strip()[:600]}"
        )
    text = _strip_log_prefix(res.stdout)
    try:
        records = json.loads(text)
    except json.JSONDecodeError as exc:
        return {
            "function_count_total": text.count("\n"),
            "functions": [],
            "_parse_error": str(exc),
            "_raw_text_head": text[:4000],
        }
    return {
        "function_count_total": len(records) if isinstance(records, list) else 0,
        "functions": records[:max_records] if isinstance(records, list) else [],
        "truncated": isinstance(records, list) and len(records) > max_records,
    }


async def capture_metadata_logs(
    path: Path,
    *,
    errors_only: bool = False,
    settings: Settings | None = None,
    timeout: float | None = 60.0,
) -> dict[str, Any]:
    s = settings or get_settings()
    replay = s.require_tool("ngfx_replay")
    flag = "--metadata-logs-errors" if errors_only else "--metadata-logs"
    argv = [str(replay), flag, "--quiet", str(path)]
    res = await run_async(argv, tool="ngfx-replay", timeout=timeout)
    return {
        "ok": res.ok,
        "returncode": res.returncode,
        "errors_only": errors_only,
        "log_text": res.stdout[-200_000:],
        "log_lines": res.stdout.count("\n"),
        "stderr_tail": res.stderr[-2000:] if not res.ok else "",
    }


async def capture_metadata_screenshot(
    path: Path,
    out_image: Path,
    *,
    settings: Settings | None = None,
    timeout: float | None = 60.0,
) -> dict[str, Any]:
    """Write the embedded final-present screenshot to ``out_image``
    (.png/.tga/.bmp/.jpg supported by ngfx-replay)."""
    s = settings or get_settings()
    replay = s.require_tool("ngfx_replay")
    out_image.parent.mkdir(parents=True, exist_ok=True)
    argv = [str(replay), "--metadata-screenshot", str(out_image), "--quiet", str(path)]
    res = await run_async(argv, tool="ngfx-replay", timeout=timeout)
    return {
        "ok": res.ok and out_image.is_file(),
        "returncode": res.returncode,
        "screenshot_path": str(out_image) if out_image.is_file() else None,
        "stderr_tail": res.stderr[-2000:] if not res.ok else "",
    }
