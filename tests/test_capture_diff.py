"""Tests for capture_diff using synthetic events.db side-files.

We don't run ngfx-replay here — instead we hand-build the SQLite tables
that ``events.index_capture_functions`` would have produced.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from nsight_graphics_mcp import capture_diff, events


def _build_events_db(capture: Path, calls: list[tuple[str, str]]) -> Path:
    """``calls`` is [(function_name, kind), ...]; event_index is assigned
    sequentially. Returns the DB path."""
    capture.parent.mkdir(parents=True, exist_ok=True)
    capture.write_bytes(b"FAKE")  # so mtime resolution works
    cache = events._cache_root_for(capture)
    db = cache / "functions.db"
    if db.exists():
        db.unlink()
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE calls(
            event_index   INTEGER PRIMARY KEY,
            function_name TEXT,
            sequence_id   INTEGER NOT NULL DEFAULT 0,
            thread_index  INTEGER NOT NULL DEFAULT 0,
            kind          TEXT
        );
        CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);
    """)
    conn.executemany(
        "INSERT INTO calls(event_index, function_name, sequence_id, thread_index, kind) "
        "VALUES (?, ?, 0, 0, ?)",
        [(i, name, kind) for i, (name, kind) in enumerate(calls)],
    )
    conn.commit()
    conn.close()
    return db


def test_diff_histogram_picks_up_added_draw(tmp_path: Path) -> None:
    a = tmp_path / "a.ngfx-gfxcap"
    b = tmp_path / "b.ngfx-gfxcap"
    _build_events_db(a, [
        ("vkCmdBindPipeline", "set_state"),
        ("vkCmdDraw", "draw"),
    ])
    _build_events_db(b, [
        ("vkCmdBindPipeline", "set_state"),
        ("vkCmdDraw", "draw"),
        ("vkCmdDraw", "draw"),
        ("vkCmdDraw", "draw"),
    ])
    diff = capture_diff.diff_captures(a, b)
    name_deltas = {row[0]: row[3] for row in diff.function_name_delta}
    assert name_deltas["vkCmdDraw"] == 2
    kind_deltas = {row[0]: row[3] for row in diff.kind_delta}
    assert kind_deltas["draw"] == 2


def test_diff_alignment_clusters_picks_up_insertion(tmp_path: Path) -> None:
    a = tmp_path / "a.ngfx-gfxcap"
    b = tmp_path / "b.ngfx-gfxcap"
    common_prefix = [("vkCmdBindPipeline", "set_state")] * 3
    common_suffix = [("vkCmdDraw", "draw")] * 3
    inserted = [("vkCmdPipelineBarrier", "barrier")] * 4
    _build_events_db(a, common_prefix + common_suffix)
    _build_events_db(b, common_prefix + inserted + common_suffix)
    diff = capture_diff.diff_captures(a, b, cluster_min_size=2)
    insert_clusters = [c for c in diff.alignment_clusters if c["kind"] == "insert"]
    assert insert_clusters, f"expected an insert cluster, got {diff.alignment_clusters}"
    assert insert_clusters[0]["b_size"] >= 4
    assert "vkCmdPipelineBarrier" in insert_clusters[0]["b_sample"]


def test_diff_no_arg_diff_without_cpp_index(tmp_path: Path) -> None:
    a = tmp_path / "a.ngfx-gfxcap"
    b = tmp_path / "b.ngfx-gfxcap"
    _build_events_db(a, [("vkCmdDraw", "draw")])
    _build_events_db(b, [("vkCmdDraw", "draw")])
    diff = capture_diff.diff_captures(a, b)
    assert diff.args_diff is None
