"""Diff two captures.

"Git-diff for captures." Given two ``.ngfx-gfxcap`` (or ``.ngfx-capture``)
files — typically a known-good capture and a regressed one — produce a
structured diff covering:

  * per-function histogram delta ("10 more vkCmdBindPipeline in B"),
  * per-kind histogram delta ("3 fewer draws in B"),
  * sequence-alignment delta — clusters of inserted/deleted events,
  * optional arg-level diff if both captures have a C++-Capture-derived
    call index next to them (see :mod:`cpp_capture_parser`).

The function-name level diff works on any pair of captures using only the
existing :mod:`events` indexer; the arg-level diff requires both captures
to have been processed through the C++-Capture workflow first.
"""

from __future__ import annotations

import difflib
import sqlite3
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from . import cpp_capture_parser, events


def _ensure_event_index(capture: Path) -> Path:
    """Ensure ``events.index_capture_functions`` has run; return DB path."""
    # The indexer is async; we re-use its sibling-cache convention.
    cache = events._cache_root_for(capture)
    db = cache / "functions.db"
    if not db.is_file():
        raise FileNotFoundError(
            f"events index missing for {capture}; call "
            f"ngfx_index_events(capture=...) first."
        )
    return db


def _load_function_sequence(db_path: Path) -> list[tuple[int, str, str]]:
    """Return [(event_index, function_name, kind), ...] for a capture."""
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            "SELECT event_index, function_name, kind FROM calls ORDER BY event_index"
        ).fetchall()
        return [(int(r[0]), r[1], r[2]) for r in rows]
    finally:
        conn.close()


def _kind_histogram(seq: list[tuple[int, str, str]]) -> dict[str, int]:
    c: Counter[str] = Counter()
    for _, _, k in seq:
        c[k] += 1
    return dict(c)


def _name_histogram(seq: list[tuple[int, str, str]]) -> Counter[str]:
    c: Counter[str] = Counter()
    for _, n, _ in seq:
        c[n] += 1
    return c


@dataclass
class CaptureDiff:
    a_path: Path
    b_path: Path
    a_event_count: int
    b_event_count: int
    function_name_delta: list[tuple[str, int, int, int]]  # (name, a_count, b_count, delta)
    kind_delta: list[tuple[str, int, int, int]]
    alignment_clusters: list[dict[str, Any]]
    args_diff: list[dict[str, Any]] | None  # None if either side lacks cpp index

    def to_dict(self) -> dict[str, Any]:
        return {
            "a_path": str(self.a_path),
            "b_path": str(self.b_path),
            "a_event_count": self.a_event_count,
            "b_event_count": self.b_event_count,
            "function_name_delta": [
                {"function_name": n, "a_count": a, "b_count": b, "delta": d}
                for n, a, b, d in self.function_name_delta
            ],
            "kind_delta": [
                {"kind": k, "a_count": a, "b_count": b, "delta": d}
                for k, a, b, d in self.kind_delta
            ],
            "alignment_clusters": self.alignment_clusters,
            "args_diff_available": self.args_diff is not None,
            "args_diff": self.args_diff or [],
        }


def diff_captures(
    capture_a: Path,
    capture_b: Path,
    *,
    cluster_min_size: int = 2,
    histogram_min_abs_delta: int = 1,
    args_window_size: int | None = 500,
    args_max_diffs: int = 100,
) -> CaptureDiff:
    """Diff two captures. Requires ``events`` index built for both."""
    db_a = _ensure_event_index(capture_a)
    db_b = _ensure_event_index(capture_b)
    seq_a = _load_function_sequence(db_a)
    seq_b = _load_function_sequence(db_b)

    # --- function-name histogram delta ---
    name_a = _name_histogram(seq_a)
    name_b = _name_histogram(seq_b)
    all_names = set(name_a) | set(name_b)
    name_delta: list[tuple[str, int, int, int]] = []
    for n in all_names:
        a, b = name_a[n], name_b[n]
        d = b - a
        if abs(d) >= histogram_min_abs_delta:
            name_delta.append((n, a, b, d))
    name_delta.sort(key=lambda r: (-abs(r[3]), r[0]))

    # --- kind histogram delta ---
    kind_a = Counter(_kind_histogram(seq_a))
    kind_b = Counter(_kind_histogram(seq_b))
    all_kinds = set(kind_a) | set(kind_b)
    kind_delta: list[tuple[str, int, int, int]] = []
    for k in all_kinds:
        a, b = kind_a[k], kind_b[k]
        d = b - a
        kind_delta.append((k, a, b, d))
    kind_delta.sort(key=lambda r: (-abs(r[3]), r[0]))

    # --- sequence alignment via difflib (LCS over function names) ---
    names_a = [n for _, n, _ in seq_a]
    names_b = [n for _, n, _ in seq_b]
    sm = difflib.SequenceMatcher(a=names_a, b=names_b, autojunk=False)
    clusters: list[dict[str, Any]] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        size = max(i2 - i1, j2 - j1)
        if size < cluster_min_size:
            continue
        cluster = {
            "kind": tag,  # 'replace' / 'insert' / 'delete'
            "a_range": [i1, i2],
            "b_range": [j1, j2],
            "a_size": i2 - i1,
            "b_size": j2 - j1,
            "a_sample": names_a[i1:i1 + 12],
            "b_sample": names_b[j1:j1 + 12],
        }
        clusters.append(cluster)
    clusters.sort(key=lambda c: -max(c["a_size"], c["b_size"]))
    clusters = clusters[:50]

    # --- optional arg-level diff via cpp_capture indexes ---
    args_diff = _maybe_arg_diff(
        capture_a, capture_b, sm, seq_a, seq_b,
        window=args_window_size, max_diffs=args_max_diffs,
    )

    return CaptureDiff(
        a_path=capture_a,
        b_path=capture_b,
        a_event_count=len(seq_a),
        b_event_count=len(seq_b),
        function_name_delta=name_delta,
        kind_delta=kind_delta,
        alignment_clusters=clusters,
        args_diff=args_diff,
    )


def _find_cpp_index_for(capture: Path) -> Path | None:
    """Find a sibling cpp-capture index DB if one exists."""
    sibling = capture.parent / f"{capture.name}.ngfxmcp" / "cpp_capture"
    if not sibling.is_dir():
        return None
    dbs = list(sibling.glob("**/.ngfxmcp_cpp_calls.db"))
    if not dbs:
        return None
    return max(dbs, key=lambda p: p.stat().st_mtime)


def _maybe_arg_diff(
    capture_a: Path,
    capture_b: Path,
    sm: difflib.SequenceMatcher,
    seq_a: list[tuple[int, str, str]],
    seq_b: list[tuple[int, str, str]],
    *,
    window: int | None,
    max_diffs: int,
) -> list[dict[str, Any]] | None:
    """For event pairs that align (same function name at corresponding
    indices), compare their parsed args from the cpp_capture indexes."""
    db_a = _find_cpp_index_for(capture_a)
    db_b = _find_cpp_index_for(capture_b)
    if not db_a or not db_b:
        return None

    out: list[dict[str, Any]] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            continue
        # window-limit how many we look at per cluster
        span = i2 - i1
        if window is not None and span > window:
            i2 = i1 + window
            j2 = j1 + window
        for ai, bj in zip(range(i1, i2), range(j1, j2), strict=False):
            ev_a = seq_a[ai][0]
            ev_b = seq_b[bj][0]
            ca = cpp_capture_parser.get_call(db_a, ev_a)
            cb = cpp_capture_parser.get_call(db_b, ev_b)
            if not ca or not cb:
                continue
            if ca["function_name"] != cb["function_name"]:
                continue
            if ca["args"] == cb["args"]:
                continue
            out.append({
                "function_name": ca["function_name"],
                "a_event_index": ev_a,
                "b_event_index": ev_b,
                "a_args": ca["args"],
                "b_args": cb["args"],
                "a_named": ca["named_args"],
                "b_named": cb["named_args"],
            })
            if len(out) >= max_diffs:
                return out
    return out
