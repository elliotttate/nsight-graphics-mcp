"""Object-JSON indexer.

``ngfx-replay --metadata-objects`` emits a JSON array of every API object
recorded in the capture::

    [
      {"uid": 1, "type_name": "Instance", "object_name": "Instance_1",
       "api": "Vulkan", "access_flags": 0},
      {"uid": 51, "type_name": "Pipeline", "object_name": "Pipeline_51", ...},
      {"uid": 91, "type_name": "ShaderModule", "object_name": "ShaderModule_91", ...},
      ...
    ]

We classify each by category (pipeline / shader / resource / descriptor /
sync / queue / command / surface / device / unknown), index into SQLite for
fast queries, and expose:

  * a per-type histogram (the "what's in this capture" overview),
  * filtered listings (every Pipeline, every ShaderModule, by name / uid),
  * arbitrary read-only SQL.

This gives the LLM parity with the Nsight UI's "Resources" / "Pipelines"
panes without needing to crack the binary capture format.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .capture_info import capture_metadata_objects
from .cli import run_async
from .config import Settings, get_settings
from .events import _cache_root_for, _strip_log_prefix


# Map type_name → coarse category
_PIPELINE_TYPES = {
    "Pipeline",                # Vulkan VkPipeline / D3D12 PSO
    "PipelineLayout",          # Vulkan VkPipelineLayout
    "PipelineCache",
    "RootSignature",           # D3D12
    "StateObject",             # D3D12 ray-tracing
    "PipelineState",
    "GraphicsPipelineState",
    "ComputePipelineState",
    "DescriptorSetLayout",
}
_SHADER_TYPES = {
    "ShaderModule",            # Vulkan
    "ShaderProgram",           # OpenGL
    "Shader",
    "ShaderCache",
}
_RESOURCE_TYPES = {
    "Buffer", "BufferView",
    "Image", "ImageView", "Texture", "TextureView",
    "Sampler",
    "DeviceMemory", "Heap",
    "Resource",
}
_DESCRIPTOR_TYPES = {
    "DescriptorPool", "DescriptorSet",
    "DescriptorHeap",
    "QueryPool", "QueryHeap",
}
_SYNC_TYPES = {
    "Fence", "Semaphore", "Event",
}
_COMMAND_TYPES = {
    "CommandPool", "CommandBuffer",
    "CommandQueue", "CommandList", "CommandAllocator", "CommandSignature",
}
_QUEUE_TYPES = {
    "Queue",
}
_SURFACE_TYPES = {
    "SurfaceKHR", "SwapchainKHR",
    "SwapChain", "Surface",
}
_DEVICE_TYPES = {
    "Instance", "PhysicalDevice", "Device",
    "Adapter", "Factory",
}
_RT_TYPES = {
    "AccelerationStructureKHR",
    "AccelerationStructure",
}


def categorise(type_name: str) -> str:
    if type_name in _PIPELINE_TYPES:
        return "pipeline"
    if type_name in _SHADER_TYPES:
        return "shader"
    if type_name in _RESOURCE_TYPES:
        return "resource"
    if type_name in _DESCRIPTOR_TYPES:
        return "descriptor"
    if type_name in _SYNC_TYPES:
        return "sync"
    if type_name in _COMMAND_TYPES:
        return "command"
    if type_name in _QUEUE_TYPES:
        return "queue"
    if type_name in _SURFACE_TYPES:
        return "surface"
    if type_name in _DEVICE_TYPES:
        return "device"
    if type_name in _RT_TYPES:
        return "ray_tracing"
    return "other"


@dataclass
class ObjectIndex:
    capture_path: Path
    dump_path: Path
    db_path: Path
    object_count: int
    type_histogram: dict[str, int] = field(default_factory=dict)
    category_histogram: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capture_path": str(self.capture_path),
            "dump_path": str(self.dump_path),
            "db_path": str(self.db_path),
            "object_count": self.object_count,
            "type_histogram": self.type_histogram,
            "category_histogram": self.category_histogram,
        }


async def index_capture_objects(
    capture: Path,
    *,
    settings: Settings | None = None,
    force: bool = False,
    timeout: float | None = 300.0,
) -> ObjectIndex:
    """Run ``ngfx-replay --metadata-objects`` once, parse JSON, build SQLite
    side-DB. Subsequent invocations on an unchanged capture are no-ops.
    """
    s = settings or get_settings()
    replay = s.require_tool("ngfx_replay")
    capture_path = capture.resolve()
    cache = _cache_root_for(capture_path)
    dump_path = cache / "objects.json"
    db_path = cache / "objects.db"
    fingerprint_path = cache / "objects.mtime"

    src_mtime = capture_path.stat().st_mtime
    if not force and dump_path.is_file() and db_path.is_file() and fingerprint_path.is_file():
        try:
            cached_mtime = float(fingerprint_path.read_text(encoding="utf-8").strip())
            if abs(cached_mtime - src_mtime) < 0.5:
                return _load_index_summary(capture_path, dump_path, db_path)
        except (OSError, ValueError):
            pass

    argv = [str(replay), "--metadata-objects", "--quiet", str(capture_path)]
    res = await run_async(argv, tool="ngfx-replay", timeout=timeout, check=True)
    text = _strip_log_prefix(res.stdout)
    dump_path.write_text(text, encoding="utf-8")
    fingerprint_path.write_text(f"{src_mtime}", encoding="utf-8")

    try:
        objects = json.loads(text)
        if not isinstance(objects, list):
            objects = []
    except json.JSONDecodeError:
        objects = []

    if db_path.is_file():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE objects(
                uid          INTEGER PRIMARY KEY,
                type_name    TEXT NOT NULL,
                object_name  TEXT NOT NULL,
                api          TEXT NOT NULL,
                access_flags INTEGER NOT NULL,
                category     TEXT NOT NULL,
                raw_json     TEXT NOT NULL
            );
            CREATE INDEX i_objects_type     ON objects(type_name);
            CREATE INDEX i_objects_category ON objects(category);
            CREATE INDEX i_objects_name     ON objects(object_name);
            CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);
            """
        )
        rows = []
        for obj in objects:
            try:
                t = str(obj["type_name"])
                rows.append(
                    (
                        int(obj["uid"]),
                        t,
                        str(obj.get("object_name", f"{t}_{obj.get('uid')}")),
                        str(obj.get("api", "")),
                        int(obj.get("access_flags", 0)),
                        categorise(t),
                        json.dumps(obj, sort_keys=True),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        conn.executemany(
            "INSERT OR REPLACE INTO objects(uid, type_name, object_name, api, access_flags, category, raw_json) "
            "VALUES (?,?,?,?,?,?,?)",
            rows,
        )
        conn.execute("INSERT INTO meta(k, v) VALUES (?, ?)", ("capture_path", str(capture_path)))
        conn.commit()
    finally:
        conn.close()

    return _load_index_summary(capture_path, dump_path, db_path)


def _load_index_summary(capture: Path, dump_path: Path, db_path: Path) -> ObjectIndex:
    conn = sqlite3.connect(db_path)
    try:
        n = conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0]
        types = dict(conn.execute("SELECT type_name, COUNT(*) FROM objects GROUP BY type_name").fetchall())
        cats = dict(conn.execute("SELECT category, COUNT(*) FROM objects GROUP BY category").fetchall())
    finally:
        conn.close()
    return ObjectIndex(
        capture_path=capture,
        dump_path=dump_path,
        db_path=db_path,
        object_count=n,
        type_histogram=types,
        category_histogram=cats,
    )


def _connect(db_path: Path) -> sqlite3.Connection:
    if not db_path.is_file():
        raise FileNotFoundError(f"object index not built: {db_path}")
    return sqlite3.connect(db_path)


def query_objects(
    db_path: Path,
    *,
    type_name: str | None = None,
    category: str | None = None,
    name_regex: str | None = None,
    api: str | None = None,
    limit: int = 500,
    offset: int = 0,
) -> list[dict[str, Any]]:
    conn = _connect(db_path)
    try:
        clauses: list[str] = []
        params: list[Any] = []
        if type_name:
            clauses.append("type_name = ?")
            params.append(type_name)
        if category:
            clauses.append("category = ?")
            params.append(category)
        if api:
            clauses.append("api = ?")
            params.append(api)
        if name_regex:
            try:
                re.compile(name_regex)
            except re.error as exc:
                raise ValueError(f"invalid regex {name_regex!r}: {exc}") from exc
            conn.create_function("regexp", 2, lambda pat, val: 1 if val and re.search(pat, val) else 0)
            clauses.append("regexp(?, object_name) = 1")
            params.append(name_regex)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            f"SELECT uid, type_name, object_name, api, access_flags, category, raw_json "
            f"FROM objects {where} ORDER BY uid LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        rows = conn.execute(sql, params).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            try:
                raw = json.loads(r[6])
            except json.JSONDecodeError:
                raw = None
            out.append(
                {
                    "uid": r[0],
                    "type_name": r[1],
                    "object_name": r[2],
                    "api": r[3],
                    "access_flags": r[4],
                    "category": r[5],
                    "raw": raw,
                }
            )
        return out
    finally:
        conn.close()


def get_object(db_path: Path, uid: int) -> dict[str, Any] | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT uid, type_name, object_name, api, access_flags, category, raw_json FROM objects WHERE uid = ?",
            (uid,),
        ).fetchone()
        if not row:
            return None
        try:
            raw = json.loads(row[6])
        except json.JSONDecodeError:
            raw = None
        return {
            "uid": row[0],
            "type_name": row[1],
            "object_name": row[2],
            "api": row[3],
            "access_flags": row[4],
            "category": row[5],
            "raw": raw,
        }
    finally:
        conn.close()


def object_histogram(db_path: Path, by: str = "type_name") -> list[dict[str, Any]]:
    if by not in ("type_name", "category", "api"):
        raise ValueError(f"by must be 'type_name', 'category', or 'api'; got {by!r}")
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            f"SELECT {by} k, COUNT(*) c FROM objects GROUP BY {by} ORDER BY c DESC"
        ).fetchall()
        return [{by: r[0], "count": r[1]} for r in rows]
    finally:
        conn.close()


def sql_query_objects(db_path: Path, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
    text = sql.lstrip().lower()
    if not (text.startswith("select") or text.startswith("with")):
        raise ValueError("ngfx_object_query is read-only: pass SELECT/WITH queries only")
    conn = _connect(db_path)
    try:
        cur = conn.execute(sql, tuple(params))
        cols = [c[0] for c in cur.description] if cur.description else []
        rows = cur.fetchall()
        return [dict(zip(cols, row)) for row in rows]
    finally:
        conn.close()
