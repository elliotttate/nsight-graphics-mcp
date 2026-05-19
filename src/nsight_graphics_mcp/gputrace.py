"""Deep ``.nsight-gputrace`` inspection.

GPU Trace reports are zip-like archives containing manifest JSON files, per-
range / per-action records, embedded shader info, and a summary screenshot.
We don't claim to fully parse the binary records (their schema is private),
but we surface the manifest JSON and counter-value JSON the GUI uses to
populate its tables, plus a member-listing and best-effort member extraction.

For runtime-driven analysis, prefer ``ngfx-replay --perf-report-dir <dir>``
which writes a folder of CSV/JSON perf-report artifacts you can read directly.
"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from pathlib import Path
from typing import Any


JSON_MANIFEST_NAMES = (
    "manifest.json",
    "summary.json",
    "metrics.json",
    "ranges.json",
    "shader_pipelines.json",
    "top_down_calls.json",
)


def inspect_archive(path: Path, *, max_members: int = 1000) -> dict[str, Any]:
    """List members of the gputrace archive with sizes + best-effort manifest decode."""
    out: dict[str, Any] = {
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "container": "unknown",
    }
    if not zipfile.is_zipfile(path):
        with path.open("rb") as fh:
            head = fh.read(64)
        out["head_hex"] = head.hex()
        return out
    out["container"] = "zip"
    members: list[dict[str, Any]] = []
    manifests: dict[str, Any] = {}
    with zipfile.ZipFile(path) as zf:
        for zi in zf.infolist()[:max_members]:
            members.append(
                {
                    "name": zi.filename,
                    "size": zi.file_size,
                    "compressed": zi.compress_size,
                    "is_dir": zi.is_dir(),
                }
            )
            base = Path(zi.filename).name
            if base in JSON_MANIFEST_NAMES and zi.file_size <= 10_000_000:
                try:
                    with zf.open(zi) as fh:
                        data = json.load(fh)
                    manifests[zi.filename] = data
                except (json.JSONDecodeError, OSError):
                    pass
    out["member_count"] = len(members)
    out["members"] = members
    out["manifests"] = manifests
    return out


def extract_member(path: Path, member: str, out_dir: Path) -> dict[str, Any]:
    """Extract a specific archive member to ``out_dir``."""
    if not zipfile.is_zipfile(path):
        return {"ok": False, "error": "not a zip-format gputrace file"}
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as zf:
        try:
            info = zf.getinfo(member)
        except KeyError:
            return {"ok": False, "error": f"member not found: {member}"}
        zf.extract(info, path=out_dir)
    extracted = out_dir / member
    return {
        "ok": True,
        "member": member,
        "extracted_path": str(extracted),
        "size_bytes": extracted.stat().st_size if extracted.is_file() else None,
    }


def read_member_text(path: Path, member: str, *, max_chars: int = 200_000) -> dict[str, Any]:
    """Read a member as UTF-8 text (no extraction to disk)."""
    if not zipfile.is_zipfile(path):
        return {"ok": False, "error": "not a zip-format gputrace file"}
    with zipfile.ZipFile(path) as zf:
        try:
            info = zf.getinfo(member)
        except KeyError:
            return {"ok": False, "error": f"member not found: {member}"}
        with zf.open(info) as fh:
            data = fh.read()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return {"ok": False, "error": "member is not UTF-8 text", "bytes": len(data)}
    out: dict[str, Any] = {
        "ok": True,
        "member": member,
        "bytes": len(text),
        "truncated": len(text) > max_chars,
        "text": text[:max_chars],
    }
    # opportunistic JSON / CSV decode
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            out["json"] = json.loads(text)
        except json.JSONDecodeError:
            pass
    elif "," in text and "\n" in text:
        reader = csv.DictReader(io.StringIO(text))
        try:
            out["csv_rows"] = list(reader)[:1000]
        except csv.Error:
            pass
    return out


def list_perf_report(perf_dir: Path) -> dict[str, Any]:
    """Enumerate the artifacts ``ngfx-replay --perf-report-dir`` writes.

    Returns each file's path + size, plus opportunistic JSON/CSV decoding of
    small files. The exact filenames depend on the Nsight version.
    """
    if not perf_dir.is_dir():
        return {"ok": False, "error": f"perf-report directory not found: {perf_dir}"}
    out: list[dict[str, Any]] = []
    for p in sorted(perf_dir.rglob("*")):
        if p.is_dir():
            continue
        info: dict[str, Any] = {
            "path": str(p),
            "size_bytes": p.stat().st_size,
            "name": p.name,
        }
        if p.suffix.lower() in (".json", ".csv") and p.stat().st_size <= 5_000_000:
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
                if p.suffix.lower() == ".json":
                    info["json"] = json.loads(text)
                else:
                    info["csv_rows"] = list(csv.DictReader(io.StringIO(text)))[:1000]
            except (json.JSONDecodeError, csv.Error, OSError):
                pass
        out.append(info)
    return {"ok": True, "dir": str(perf_dir), "files": out}
