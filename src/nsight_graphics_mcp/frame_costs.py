"""Top-N expensive draws / dispatches / regions from a GPU Trace report.

Two input shapes we handle:

  * A directory written by ``ngfx-replay --perf-report-dir <dir>`` —
    contains CSV/JSON files with per-action / per-range timings.
  * A ``.nsight-gputrace`` archive — contains the same data zipped up
    with manifest JSON. We extract the relevant member to a temp dir
    and reuse the directory path.

The CSV column names Nsight uses are version-dependent (and have varied
across releases), so this module sniffs the columns and picks the most
plausible "name", "time" and "kind" fields rather than hardcoding.
"""

from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


# Columns that look like a timing measurement, in priority order. First
# match wins.
TIME_COLUMN_PATTERNS: tuple[str, ...] = (
    r"gpu.?time.?ns",
    r"duration.?ns",
    r"elapsed.?ns",
    r"gpu.?time.?us",
    r"duration.?us",
    r"gpu.?time.?ms",
    r"duration.?ms",
    r"gpu.?time",
    r"duration",
    r"elapsed",
    r"time",
)
NAME_COLUMN_PATTERNS: tuple[str, ...] = (
    r"^name$", r"function.?name", r"action.?name", r"range.?name", r"call",
)
KIND_COLUMN_PATTERNS: tuple[str, ...] = (
    r"^kind$", r"category", r"type",
)
INDEX_COLUMN_PATTERNS: tuple[str, ...] = (
    r"^event.?index$", r"^action.?index$", r"^range.?index$", r"^id$", r"^idx$",
)


def _pick_column(field_names: list[str], patterns: tuple[str, ...]) -> str | None:
    lc = [(f, f.lower()) for f in field_names]
    for pat in patterns:
        rx = re.compile(pat)
        for orig, low in lc:
            if rx.search(low):
                return orig
    return None


def _to_float_ns(value: str, column_name: str) -> float | None:
    """Coerce a CSV cell to a float in nanoseconds. Recognise units in
    the column name (ns/us/ms/s)."""
    if value is None:
        return None
    s = value.strip().replace(",", "")
    if not s:
        return None
    # strip explicit unit suffix on the value itself
    m = re.match(r"^([+-]?\d+(?:\.\d+)?)\s*(ns|us|µs|ms|s)?$", s, re.IGNORECASE)
    if m:
        num = float(m.group(1))
        unit = (m.group(2) or "").lower()
    else:
        try:
            num = float(s)
        except ValueError:
            return None
        unit = ""
    if not unit:
        cn = column_name.lower()
        if "ns" in cn:
            unit = "ns"
        elif "us" in cn or "µs" in cn:
            unit = "us"
        elif "ms" in cn:
            unit = "ms"
        elif re.search(r"\bsec\b|seconds?\b|_s\b", cn):
            unit = "s"
    mult = {"ns": 1.0, "us": 1_000.0, "µs": 1_000.0, "ms": 1_000_000.0, "s": 1e9, "": 1.0}[unit]
    return num * mult


@dataclass
class CostSource:
    path: Path
    name_col: str | None
    time_col: str | None
    kind_col: str | None
    index_col: str | None
    row_count: int


def _scan_csv(path: Path) -> tuple[CostSource, list[dict[str, str]]] | None:
    """Read a CSV file; return its column-sniff + raw rows, if it has a
    plausible timing column."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        return None
    fields = list(reader.fieldnames or [])
    time_col = _pick_column(fields, TIME_COLUMN_PATTERNS)
    if time_col is None:
        return None
    name_col = _pick_column(fields, NAME_COLUMN_PATTERNS)
    kind_col = _pick_column(fields, KIND_COLUMN_PATTERNS)
    index_col = _pick_column(fields, INDEX_COLUMN_PATTERNS)
    return CostSource(
        path=path,
        name_col=name_col,
        time_col=time_col,
        kind_col=kind_col,
        index_col=index_col,
        row_count=len(rows),
    ), rows


def _iter_perf_report_csvs(report_dir: Path) -> Iterable[Path]:
    for p in sorted(report_dir.rglob("*.csv")):
        if p.is_file():
            yield p


def _maybe_extract_from_gputrace(path: Path, out_dir: Path) -> Path | None:
    """If ``path`` is a .nsight-gputrace zip, extract its CSVs to
    ``out_dir`` and return that dir."""
    if not zipfile.is_zipfile(path):
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path) as zf:
        members = [zi for zi in zf.infolist()
                   if not zi.is_dir() and zi.filename.lower().endswith((".csv", ".json"))]
        for zi in members:
            zf.extract(zi, path=out_dir)
    return out_dir


def top_n_costs(
    report_or_trace: Path,
    *,
    n: int = 20,
    kind_filter: str | None = None,
    name_regex: str | None = None,
    csv_basename_hint: str | None = None,
) -> dict[str, Any]:
    """Return the top ``n`` rows by GPU time across all CSVs in a
    ``ngfx-replay --perf-report-dir`` output (or a ``.nsight-gputrace`` zip).

    ``kind_filter`` (case-insensitive substring) and ``name_regex`` narrow
    down which rows are considered. ``csv_basename_hint`` constrains the
    scan to specific CSVs (e.g. ``"actions.csv"``).
    """
    if not report_or_trace.exists():
        return {"ok": False, "error": f"path not found: {report_or_trace}"}

    # if .gputrace archive, unzip to a temp side-dir
    work_dir = report_or_trace
    if report_or_trace.is_file():
        sidecar = report_or_trace.parent / f"{report_or_trace.name}.ngfxmcp" / "perf_unpack"
        work_dir = _maybe_extract_from_gputrace(report_or_trace, sidecar) or report_or_trace.parent
    elif not report_or_trace.is_dir():
        return {"ok": False, "error": f"not a directory or gputrace archive: {report_or_trace}"}

    candidates: list[tuple[CostSource, list[dict[str, str]]]] = []
    for csv_path in _iter_perf_report_csvs(work_dir):
        if csv_basename_hint and csv_basename_hint.lower() not in csv_path.name.lower():
            continue
        scan = _scan_csv(csv_path)
        if scan is not None:
            candidates.append(scan)

    if not candidates:
        return {
            "ok": False,
            "error": (
                "no CSVs with a recognised timing column found. Confirm "
                "this is an ngfx-replay --perf-report-dir output, or that "
                "the .nsight-gputrace archive contains per-action CSVs."
            ),
            "scanned_dir": str(work_dir),
        }

    name_rx = re.compile(name_regex) if name_regex else None
    kind_lc = kind_filter.lower() if kind_filter else None

    all_rows: list[dict[str, Any]] = []
    sources_used: list[dict[str, Any]] = []
    for src, rows in candidates:
        kept = 0
        for r in rows:
            tn_str = r.get(src.time_col, "")
            tn = _to_float_ns(tn_str, src.time_col)
            if tn is None:
                continue
            name = r.get(src.name_col, "") if src.name_col else ""
            kind = r.get(src.kind_col, "") if src.kind_col else ""
            if kind_lc and kind_lc not in kind.lower() and kind_lc not in name.lower():
                continue
            if name_rx and not name_rx.search(name):
                continue
            ev_idx_str = r.get(src.index_col, "") if src.index_col else ""
            ev_idx = None
            if ev_idx_str:
                try:
                    ev_idx = int(float(ev_idx_str))
                except ValueError:
                    pass
            all_rows.append({
                "source_csv": src.path.name,
                "event_index": ev_idx,
                "name": name,
                "kind": kind,
                "gpu_time_ns": tn,
                "raw": r,
            })
            kept += 1
        sources_used.append({
            "csv": str(src.path),
            "row_count": src.row_count,
            "rows_used": kept,
            "time_col": src.time_col,
            "name_col": src.name_col,
            "kind_col": src.kind_col,
        })

    all_rows.sort(key=lambda r: r["gpu_time_ns"], reverse=True)
    top = all_rows[:n]
    total_ns = sum(r["gpu_time_ns"] for r in all_rows)
    for r in top:
        r["pct_of_total"] = (r["gpu_time_ns"] / total_ns * 100.0) if total_ns else None
        # drop raw to keep payload small unless requested
        r.pop("raw", None)
    return {
        "ok": True,
        "report_dir": str(work_dir),
        "sources": sources_used,
        "total_rows_considered": len(all_rows),
        "total_gpu_time_ns": total_ns,
        "top": top,
    }
