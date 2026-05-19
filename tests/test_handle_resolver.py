"""Tests for handle_resolver using synthetic objects + events + cpp_capture DBs."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from nsight_graphics_mcp import cpp_capture_parser, events, handle_resolver


def _build_objects_db(capture: Path, objs: list[tuple[int, str, str, str, str]]) -> None:
    """objs = [(uid, type_name, object_name, api, category), ...]"""
    capture.parent.mkdir(parents=True, exist_ok=True)
    capture.write_bytes(b"FAKE")
    cache = events._cache_root_for(capture)
    db = cache / "objects.db"
    if db.exists():
        db.unlink()
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE objects(
            uid          INTEGER PRIMARY KEY,
            type_name    TEXT NOT NULL,
            object_name  TEXT NOT NULL,
            api          TEXT NOT NULL,
            access_flags INTEGER NOT NULL DEFAULT 0,
            category     TEXT NOT NULL,
            raw_json     TEXT NOT NULL DEFAULT '{}'
        );
    """)
    conn.executemany(
        "INSERT INTO objects(uid, type_name, object_name, api, access_flags, category, raw_json) "
        "VALUES (?,?,?,?,0,?,'{}')",
        objs,
    )
    conn.commit()
    conn.close()


def _build_events_db(capture: Path, calls: list[tuple[str, str]]) -> None:
    cache = events._cache_root_for(capture)
    db = cache / "functions.db"
    if db.exists():
        db.unlink()
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE calls(
            event_index   INTEGER PRIMARY KEY,
            function_name TEXT,
            sequence_id   INTEGER DEFAULT 0,
            thread_index  INTEGER DEFAULT 0,
            kind          TEXT
        );
    """)
    conn.executemany(
        "INSERT INTO calls VALUES (?, ?, 0, 0, ?)",
        [(i, n, k) for i, (n, k) in enumerate(calls)],
    )
    conn.commit()
    conn.close()


def _make_cpp_index_dir(capture: Path) -> Path:
    """Create the sibling cpp_capture dir for a fake project."""
    d = capture.parent / f"{capture.name}.ngfxmcp" / "cpp_capture" / "Generated"
    d.mkdir(parents=True, exist_ok=True)
    return d


def test_resolve_handle_without_cpp_returns_object_record_only(tmp_path: Path) -> None:
    cap = tmp_path / "cap.ngfx-gfxcap"
    _build_objects_db(cap, [(91, "Buffer", "Buffer_91", "Vulkan", "resource")])
    _build_events_db(cap, [
        ("vkCreateInstance", "other"),
        ("vkCreateBuffer", "resource"),
        ("vkCmdDraw", "draw"),
    ])
    res = handle_resolver.resolve_handle(cap, uid=91)
    assert res.uid == 91
    assert res.type_name == "Buffer"
    assert res.create_call is not None
    assert res.create_call["function_name"] == "vkCreateBuffer"
    assert res.mentions == []  # no cpp index
    assert res.mentions_by_role == {}


def test_resolve_handle_with_cpp_finds_mentions_and_roles(tmp_path: Path) -> None:
    cap = tmp_path / "cap.ngfx-gfxcap"
    _build_objects_db(cap, [(91, "Buffer", "Buffer_91", "Vulkan", "resource")])
    _build_events_db(cap, [("vkCreateBuffer", "resource"), ("vkCmdDraw", "draw")])
    # Build a sibling cpp_capture project with calls that mention Buffer_91
    cpp_dir = _make_cpp_index_dir(cap)
    (cpp_dir / "frame.cpp").write_text(
        "void play(VkCommandBuffer cmd) {\n"
        "    vkCmdBindIndexBuffer(cmd, g_Buffer_91, 0, VK_INDEX_TYPE_UINT16);\n"
        "    vkCmdBindVertexBuffers(cmd, 0, 1, &g_Buffer_91, &offset);\n"
        "    vkCmdCopyBuffer(cmd, g_Buffer_91, g_Buffer_42, 1, &region);\n"
        "    vkCmdDraw(cmd, 3, 1, 0, 0);\n"
        "    vkDestroyBuffer(device, g_Buffer_91, nullptr);\n"
        "}\n",
        encoding="utf-8",
    )
    cpp_capture_parser.index_cpp_project(cpp_dir.parent)  # writes .ngfxmcp_cpp_calls.db at cpp_dir.parent
    res = handle_resolver.resolve_handle(cap, uid=91)
    assert res.mention_count >= 3
    roles = res.mentions_by_role
    assert "bind" in roles
    assert "write" in roles  # CopyBuffer is a write op


def test_resolve_handle_unknown_uid_raises(tmp_path: Path) -> None:
    cap = tmp_path / "cap.ngfx-gfxcap"
    _build_objects_db(cap, [(91, "Buffer", "Buffer_91", "Vulkan", "resource")])
    _build_events_db(cap, [("vkCreateBuffer", "resource")])
    with pytest.raises(LookupError):
        handle_resolver.resolve_handle(cap, uid=999)


def test_resolve_handle_needs_uid_or_name(tmp_path: Path) -> None:
    cap = tmp_path / "cap.ngfx-gfxcap"
    _build_objects_db(cap, [(1, "Buffer", "Buffer_1", "Vulkan", "resource")])
    _build_events_db(cap, [])
    with pytest.raises(ValueError):
        handle_resolver.resolve_handle(cap)
