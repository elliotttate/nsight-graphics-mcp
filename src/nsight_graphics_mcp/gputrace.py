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
import re
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
            head = fh.read(2_000_000)
        out["head_hex"] = head.hex()
        if head.startswith(b"WRPV"):
            out["container"] = "wrpv"
            out["magic"] = "WRPV"
            out["strings_preview"] = _ascii_strings(head, limit=200)
            out["notes"] = [
                "Nsight 2026 GPU Trace uses a binary WRPV container on this machine.",
                "Use ngfx_gputrace_export_summary/search on the auto-export folder for structured data.",
            ]
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
        if p.suffix.lower() in (".json", ".csv", ".tsv", ".txt", ".xls") and p.stat().st_size <= 5_000_000:
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
                if p.suffix.lower() == ".json":
                    info["json"] = json.loads(text)
                elif p.suffix.lower() == ".csv":
                    info["csv_rows"] = list(csv.DictReader(io.StringIO(text)))[:1000]
                else:
                    info.update(_decode_tab_text(text))
            except (json.JSONDecodeError, csv.Error, OSError):
                pass
        out.append(info)
    return {"ok": True, "dir": str(perf_dir), "files": out}


def export_summary(report_dir: Path) -> dict[str, Any]:
    """Summarize Nsight GPU Trace auto-export artifacts."""
    listing = list_perf_report(report_dir)
    if not listing.get("ok"):
        return listing
    files = listing["files"]
    repro = _first_key_values(files, "REPRO_INFO.xls")
    tags = _read_small_text(report_dir / "ReportGeneratorTags.txt")
    metrics: dict[str, Any] = {}
    for name in ("GPUTRACE_FRAME.xls", "GPUTRACE_REGIMES.xls"):
        file_info = next((item for item in files if item["name"] == name), None)
        if not file_info:
            continue
        if file_info.get("key_values"):
            metrics[name] = {
                "metric_count": len(file_info["key_values"]),
                "sample": dict(list(file_info["key_values"].items())[:40]),
            }
        elif file_info.get("tsv_rows"):
            metrics[name] = {
                "row_count": len(file_info["tsv_rows"]),
                "columns": file_info.get("columns", [])[:60],
                "sample_rows": file_info["tsv_rows"][:5],
            }
    trace_files = sorted(str(p) for p in report_dir.glob("*.ngfx-gputrace"))
    return {
        "ok": True,
        "dir": str(report_dir),
        "trace_files": trace_files,
        "tags": tags,
        "repro_info": repro,
        "metrics": metrics,
        "files": files,
    }


def search_export(
    report_dir: Path,
    needles: list[str],
    *,
    max_file_bytes: int = 20_000_000,
    max_hits: int = 100,
    context_chars: int = 240,
) -> dict[str, Any]:
    """Search Nsight GPU Trace export files for strings/hashes."""
    normalized = _normalise_needles(*needles)
    if not normalized:
        return {"ok": False, "error": "supply at least one needle"}
    if not report_dir.is_dir():
        return {"ok": False, "error": f"report directory not found: {report_dir}"}
    hits: list[dict[str, Any]] = []
    scanned_files = 0
    skipped_files = 0
    for path in sorted(p for p in report_dir.rglob("*") if p.is_file()):
        if len(hits) >= max_hits:
            break
        if path.stat().st_size > max_file_bytes:
            skipped_files += 1
            continue
        scanned_files += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped_files += 1
            continue
        lower = text.lower()
        for needle in normalized:
            pos = lower.find(needle)
            while pos >= 0:
                start = max(0, pos - context_chars)
                end = min(len(text), pos + len(needle) + context_chars)
                hits.append(
                    {
                        "file": str(path),
                        "relative_file": str(path.relative_to(report_dir)),
                        "needle": needle,
                        "offset": pos,
                        "snippet": text[start:end],
                    }
                )
                if len(hits) >= max_hits:
                    break
                pos = lower.find(needle, pos + max(1, len(needle)))
            if len(hits) >= max_hits:
                break
    return {
        "ok": True,
        "dir": str(report_dir),
        "needles": normalized,
        "scanned_files": scanned_files,
        "skipped_files": skipped_files,
        "hit_count": len(hits),
        "hits": hits,
    }


def search_shader_pipelines(
    path: Path,
    *,
    shader_hash: str | None = None,
    shader_name: str | None = None,
    entry_point: str | None = None,
    max_members: int = 2000,
    max_scan_bytes: int = 20_000_000,
    max_hits: int = 100,
) -> dict[str, Any]:
    """Search a GPU Trace archive for shader/pipeline evidence.

    GPU Trace member names and JSON schemas vary between Nsight versions. This
    search deliberately treats the archive as semi-structured data: it scans
    shader/pipeline-looking JSON and CSV members, then returns matching JSON
    paths or CSV rows. This is the practical replacement path when C++ Capture
    is unavailable but the LLM needs "which shader/pipeline did this trace see?"
    evidence.
    """
    needles = _normalise_needles(shader_hash, shader_name, entry_point)
    if not needles:
        return {"ok": False, "error": "supply shader_hash, shader_name, or entry_point"}
    if not zipfile.is_zipfile(path):
        return {"ok": False, "error": "not a zip-format gputrace file", "path": str(path)}

    hits: list[dict[str, Any]] = []
    scanned_members = 0
    skipped_members = 0
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist()[:max_members]:
            if info.is_dir():
                continue
            member_lower = info.filename.lower()
            if not _looks_shader_relevant_member(member_lower):
                continue
            if info.file_size > max_scan_bytes:
                skipped_members += 1
                continue
            scanned_members += 1
            try:
                data = zf.read(info)
            except OSError:
                skipped_members += 1
                continue
            try:
                text = data.decode("utf-8", errors="replace")
            except OSError:
                skipped_members += 1
                continue
            matched = _matched_needles(text, needles)
            if not matched:
                continue
            hit: dict[str, Any] = {
                "member": info.filename,
                "size_bytes": info.file_size,
                "matched_needles": matched,
                "text_snippet": _snippet_for_needles(text, matched),
            }
            stripped = text.lstrip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    payload = json.loads(text)
                    hit["format"] = "json"
                    hit["json_matches"] = _json_match_paths(payload, matched, limit=40)
                    hit["json_preview"] = _json_preview(payload)
                except json.JSONDecodeError:
                    hit["format"] = "text"
            elif "," in text and "\n" in text:
                hit["format"] = "csv"
                hit["csv_rows"] = _csv_matching_rows(text, matched, limit=25)
            else:
                hit["format"] = "text"
            hits.append(hit)
            if len(hits) >= max_hits:
                break
    return {
        "ok": True,
        "path": str(path),
        "needles": needles,
        "scanned_members": scanned_members,
        "skipped_members": skipped_members,
        "hit_count": len(hits),
        "hits": hits,
        "notes": [
            "Schemas are private/versioned; matches are evidence, not a full pipeline-state decode.",
            "For exact event/resource provenance, pair this with live replay RPC pixel/resource history.",
        ],
    }


def _normalise_needles(*values: str | None) -> list[str]:
    out: list[str] = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        lowered = text.lower()
        if lowered.startswith("0x"):
            lowered = lowered[2:]
        out.append(lowered)
    return out


def _looks_shader_relevant_member(member_lower: str) -> bool:
    return any(
        token in member_lower
        for token in (
            "shader",
            "pipeline",
            "top_down",
            "topdown",
            "source",
            "sass",
            "dxil",
            "dxbc",
            "spirv",
        )
    )


def _matched_needles(text: str, needles: list[str]) -> list[str]:
    lower = text.lower()
    return [needle for needle in needles if needle in lower]


def _snippet_for_needles(text: str, needles: list[str], *, radius: int = 320) -> str:
    lower = text.lower()
    positions = [lower.find(needle) for needle in needles if lower.find(needle) >= 0]
    if not positions:
        return text[: radius * 2]
    pos = min(positions)
    start = max(0, pos - radius)
    end = min(len(text), pos + radius)
    return text[start:end]


def _json_match_paths(payload: Any, needles: list[str], *, limit: int) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []

    def visit(value: Any, path: str) -> None:
        if len(matches) >= limit:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                key_path = f"{path}.{key}" if path else str(key)
                if any(needle in str(key).lower() for needle in needles):
                    matches.append({"path": key_path, "kind": "key", "value_preview": _preview(child)})
                    if len(matches) >= limit:
                        return
                visit(child, key_path)
        elif isinstance(value, list):
            for idx, child in enumerate(value):
                visit(child, f"{path}[{idx}]")
                if len(matches) >= limit:
                    return
        else:
            text = str(value)
            matched = _matched_needles(text, needles)
            if matched:
                matches.append(
                    {
                        "path": path,
                        "kind": "value",
                        "matched_needles": matched,
                        "value_preview": _preview(value),
                    }
                )

    visit(payload, "")
    return matches


def _json_preview(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {str(k): _json_preview(v) for k, v in list(payload.items())[:12]}
    if isinstance(payload, list):
        return [_json_preview(v) for v in payload[:5]]
    return _preview(payload)


def _preview(value: Any, *, max_chars: int = 240) -> Any:
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text = str(value)
    return text if len(text) <= max_chars else text[:max_chars] + "..."


def _csv_matching_rows(text: str, needles: list[str], *, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        row_text = json.dumps(row, sort_keys=True).lower()
        matched = [needle for needle in needles if needle in row_text]
        if matched:
            rows.append({"matched_needles": matched, "row": row})
            if len(rows) >= limit:
                break
    return rows


def _decode_tab_text(text: str) -> dict[str, Any]:
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return {}
    if all("\t" in line for line in lines) and all(len(line.split("\t")) == 2 for line in lines[:200]):
        return {
            "format": "key_value_tsv",
            "key_values": {key: value for key, value in (line.split("\t", 1) for line in lines)},
        }
    if "\t" in lines[0]:
        reader = csv.DictReader(io.StringIO(text), delimiter="\t")
        try:
            rows = list(reader)[:1000]
        except csv.Error:
            rows = []
        return {
            "format": "table_tsv",
            "columns": reader.fieldnames or [],
            "tsv_rows": rows,
        }
    return {"format": "text", "text_preview": text[:20_000]}


def _first_key_values(files: list[dict[str, Any]], name: str) -> dict[str, str]:
    for item in files:
        if item.get("name") == name and isinstance(item.get("key_values"), dict):
            return item["key_values"]
    return {}


def _read_small_text(path: Path, *, max_chars: int = 20_000) -> str | None:
    if not path.is_file() or path.stat().st_size > max_chars:
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:max_chars]
    except OSError:
        return None


def _ascii_strings(data: bytes, *, limit: int) -> list[str]:
    strings: list[str] = []
    for match in re.finditer(rb"[ -~]{5,}", data):
        strings.append(match.group(0).decode("latin-1", errors="replace"))
        if len(strings) >= limit:
            break
    return strings


# ---------------------------------------------------------------------------
# WRPV deep inspection
# ---------------------------------------------------------------------------
#
# The Nsight Graphics 2026 GPU Trace report is a binary "WRPV" container,
# not a zip. The exact internal layout is not fully reverse-engineered, but
# the file starts with a `WRPV` magic and contains generic event/function
# strings plus shader/pipeline binding records. The helpers below are
# explicitly best-effort: they search the file for content and surface
# header bytes that look like they could be offsets/sizes, but they label
# every output as one of:
#
#   * ``proven``     — backed by a known check in Nsight binaries
#   * ``inferred``   — derived from a strong heuristic
#   * ``candidate``  — a plausible reading worth investigating
#
# That contract is meant to satisfy the "Phase 1: more honest reports"
# requirement in NSIGHT_SHADER_DEBUG_AUTONOMY.md.


WRPV_MAGIC = b"WRPV"
_MIN_ASCII_RUN = 4
_MAX_ASCII_RUN = 4096


def wrpv_is_wrpv(path: Path) -> bool:
    """Return True iff ``path`` begins with the WRPV magic."""
    try:
        with path.open("rb") as fh:
            return fh.read(4) == WRPV_MAGIC
    except OSError:
        return False


def wrpv_search(
    path: Path,
    needles: list[str],
    *,
    encodings: tuple[str, ...] = ("ascii", "utf-16le"),
    include_hex: bool = True,
    max_hits_per_needle: int = 200,
    context_bytes: int = 48,
) -> dict[str, Any]:
    """Search a WRPV report for needles using multiple encodings.

    For each needle, every encoding produces a list of byte offsets.
    A short ``context`` preview (hex + ascii) is included so callers can
    eyeball the surrounding structure without re-opening the file.

    A hex needle (``"<hex:DEADBEEF>"``) is supported when ``include_hex``
    is true, useful for searching raw byte patterns (resource IDs, DXBC
    hashes) without committing to an encoding.
    """
    if not path.is_file():
        return {"ok": False, "error": f"file not found: {path}"}
    blob = path.read_bytes()
    out: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "size_bytes": len(blob),
        "is_wrpv": blob.startswith(WRPV_MAGIC),
        "encodings_used": list(encodings),
        "evidence_label": "proven",
        "hits": {},
    }
    for needle in needles:
        per_needle: list[dict[str, Any]] = []
        patterns: list[tuple[str, bytes]] = []
        if needle.startswith("<hex:") and needle.endswith(">"):
            if not include_hex:
                continue
            hex_text = needle[5:-1].replace(" ", "")
            try:
                patterns.append(("hex", bytes.fromhex(hex_text)))
            except ValueError:
                per_needle.append({"error": f"bad hex needle: {needle}"})
        else:
            for enc in encodings:
                try:
                    patterns.append((enc, needle.encode(enc)))
                except (UnicodeEncodeError, LookupError):
                    continue
        for enc, pat in patterns:
            if not pat:
                continue
            start = 0
            hits = 0
            while hits < max_hits_per_needle:
                idx = blob.find(pat, start)
                if idx < 0:
                    break
                ctx_lo = max(0, idx - context_bytes)
                ctx_hi = min(len(blob), idx + len(pat) + context_bytes)
                per_needle.append(
                    {
                        "encoding": enc,
                        "offset": idx,
                        "match_bytes": len(pat),
                        "context_hex": blob[ctx_lo:ctx_hi].hex(),
                        "context_ascii": "".join(
                            chr(b) if 32 <= b < 127 else "."
                            for b in blob[ctx_lo:ctx_hi]
                        ),
                    }
                )
                hits += 1
                start = idx + max(1, len(pat))
        out["hits"][needle] = per_needle
    return out


def wrpv_strings(
    path: Path,
    *,
    min_len: int = 5,
    max_len: int = _MAX_ASCII_RUN,
    encodings: tuple[str, ...] = ("ascii", "utf-16le"),
    limit: int = 5000,
    pattern: str | None = None,
) -> dict[str, Any]:
    """Extract printable strings (ASCII + UTF-16LE) with byte offsets.

    Optional ``pattern`` is a regex applied to each decoded string before
    inclusion. Useful for narrowing to shader-name-like or hex-hash-like
    output. All offsets are bytes into the file as observed; the caller
    can re-read context with :func:`wrpv_search`.
    """
    if not path.is_file():
        return {"ok": False, "error": f"file not found: {path}"}
    blob = path.read_bytes()
    rx_filter = re.compile(pattern) if pattern else None
    if min_len < _MIN_ASCII_RUN:
        min_len = _MIN_ASCII_RUN
    if max_len > _MAX_ASCII_RUN:
        max_len = _MAX_ASCII_RUN

    results: list[dict[str, Any]] = []

    if "ascii" in encodings:
        ascii_re = re.compile(rb"[ -~]{%d,%d}" % (min_len, max_len))
        for m in ascii_re.finditer(blob):
            text = m.group(0).decode("ascii", errors="replace")
            if rx_filter and not rx_filter.search(text):
                continue
            results.append({"offset": m.start(), "encoding": "ascii", "text": text})
            if len(results) >= limit:
                break

    if "utf-16le" in encodings and len(results) < limit:
        u16_re = re.compile(
            (rb"(?:[ -~]\x00){%d,%d}" % (min_len, max_len))
        )
        for m in u16_re.finditer(blob):
            try:
                text = m.group(0).decode("utf-16le", errors="replace")
            except UnicodeDecodeError:
                continue
            if rx_filter and not rx_filter.search(text):
                continue
            results.append(
                {"offset": m.start(), "encoding": "utf-16le", "text": text}
            )
            if len(results) >= limit:
                break

    return {
        "ok": True,
        "path": str(path),
        "size_bytes": len(blob),
        "is_wrpv": blob.startswith(WRPV_MAGIC),
        "min_len": min_len,
        "max_len": max_len,
        "pattern": pattern,
        "encodings_used": list(encodings),
        "count": len(results),
        "limit_hit": len(results) >= limit,
        "evidence_label": "proven",
        "strings": results,
    }


def wrpv_sections(path: Path, *, max_candidates: int = 64) -> dict[str, Any]:
    """Best-effort listing of header-like u32/u64 fields that *could* be
    section offsets or sizes.

    The WRPV header layout is **not** reverse-engineered. This function
    reads the first 4 KiB, decodes the file size, and emits candidate
    pairs of ``(little-endian u32 at offset X, plausible interpretation)``
    so callers can investigate. Every entry is labelled ``candidate``.

    For the proven part (just the magic), the result also includes a
    fixed-confidence "header" block.
    """
    if not path.is_file():
        return {"ok": False, "error": f"file not found: {path}"}
    head = path.read_bytes()[:4096]
    file_size = path.stat().st_size

    proven: dict[str, Any] = {
        "magic_offset": 0,
        "magic": head[:4].decode("ascii", errors="replace"),
        "is_wrpv": head.startswith(WRPV_MAGIC),
        "file_size_bytes": file_size,
    }

    candidates: list[dict[str, Any]] = []
    # Scan the next 256 bytes for u32 / u64 values that look like
    # offsets or sizes (>= 4 to skip noise, <= file_size).
    import struct
    for off in range(4, min(256, len(head) - 8), 4):
        u32_le = struct.unpack_from("<I", head, off)[0]
        if 16 <= u32_le <= file_size:
            kind = "offset_or_size_u32_le"
            note = "within-file u32 LE; could be section offset or size"
            if u32_le == file_size:
                note = "u32 LE equals file size"
            elif u32_le % 16 == 0 and u32_le > 64:
                note = "u32 LE is 16-byte-aligned within file; plausible section offset"
            candidates.append(
                {
                    "offset": off,
                    "kind": kind,
                    "value_dec": u32_le,
                    "value_hex": f"0x{u32_le:08x}",
                    "note": note,
                    "evidence_label": "candidate",
                }
            )
            if len(candidates) >= max_candidates:
                break

    return {
        "ok": True,
        "path": str(path),
        "proven": proven,
        "candidate_fields": candidates,
        "notes": [
            "WRPV layout is not fully reverse-engineered; fields beyond the "
            "magic are candidates only.",
            "Pair this output with ngfx_gputrace_wrpv_strings + wrpv_search "
            "to validate any candidate offset.",
        ],
        "evidence_label": "candidate",
    }


def wrpv_table_preview(
    path: Path, *, offset: int, length: int = 256, ascii_window: int = 16
) -> dict[str, Any]:
    """Read ``length`` bytes from ``offset`` and emit a hex+ascii dump.

    Useful for eyeballing a section after :func:`wrpv_sections` or
    :func:`wrpv_search` identifies a candidate location.
    """
    if not path.is_file():
        return {"ok": False, "error": f"file not found: {path}"}
    size = path.stat().st_size
    if offset < 0 or offset >= size:
        return {
            "ok": False,
            "error": f"offset {offset} out of range (file size {size})",
        }
    length = max(1, min(length, size - offset, 8192))
    with path.open("rb") as fh:
        fh.seek(offset)
        chunk = fh.read(length)

    lines: list[str] = []
    for i in range(0, len(chunk), ascii_window):
        row = chunk[i : i + ascii_window]
        hex_part = " ".join(f"{b:02x}" for b in row)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{offset + i:08x}  {hex_part:<{ascii_window * 3}}  {ascii_part}")

    return {
        "ok": True,
        "path": str(path),
        "offset": offset,
        "length": len(chunk),
        "preview": "\n".join(lines),
        "evidence_label": "proven",
    }


def wrpv_shader_binding_search(
    path: Path,
    *,
    shader_names: list[str] | None = None,
    dxbc_hashes_hex: list[str] | None = None,
    payload_sha1_hex: list[str] | None = None,
    pdb_names: list[str] | None = None,
) -> dict[str, Any]:
    """Convenience wrapper that searches a WRPV report for the kinds of
    evidence the autonomy doc lists (shader names, DXBC container hashes,
    payload SHA1, PDB names).

    All needles are tried against ASCII + UTF-16LE; hashes are tried both
    as their hex-string form and as raw bytes (``<hex:...>``).
    """
    needles: list[str] = []
    if shader_names:
        needles.extend(shader_names)
    if pdb_names:
        needles.extend(pdb_names)
    if dxbc_hashes_hex:
        for h in dxbc_hashes_hex:
            needles.append(h.lower())
            needles.append(h.upper())
            needles.append(f"<hex:{h.lower().replace(' ', '')}>")
    if payload_sha1_hex:
        for h in payload_sha1_hex:
            needles.append(h.lower())
            needles.append(h.upper())
            needles.append(f"<hex:{h.lower().replace(' ', '')}>")
    if not needles:
        return {"ok": False, "error": "no needles provided"}
    return wrpv_search(path, needles)
