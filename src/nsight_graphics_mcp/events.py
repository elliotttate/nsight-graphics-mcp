"""Function-stream indexer (Event List parity).

``ngfx-replay --metadata-functions`` emits a JSON array of records::

    [
      {"event_index": 0, "function_name": "CaptureBegin", "sequence_id": 0, "thread_index": 0},
      {"event_index": 1, "function_name": "vkCreateGraphicsPipelines", ...},
      ...
    ]

We index the array into SQLite for fast filtering, classify each function
into a coarse kind (draw / dispatch / copy / barrier / present / ray_tracing
/ sync / set_state / pipeline / descriptor / resource / cmd_buffer / other),
and expose pythonic queries.

Note: the function records do **not** include argument values — that's a
deliberate Nsight design choice for the lightweight `--metadata-functions`
mode. To answer "what's bound at root parameter N of event G?" we cross
over to the C++ Capture pathway (see ``cpp_capture_resources.py``).
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .cli import run_async
from .config import Settings, default_cache_dir, get_settings


@dataclass
class CallRecord:
    event_index: int
    function_name: str
    sequence_id: int
    thread_index: int
    kind: str


_DRAW = {
    "DrawInstanced", "DrawIndexedInstanced", "ExecuteIndirect",
    "vkCmdDraw", "vkCmdDrawIndexed", "vkCmdDrawIndirect",
    "vkCmdDrawIndexedIndirect", "vkCmdDrawIndirectCount",
    "vkCmdDrawIndexedIndirectCount", "vkCmdDrawMeshTasksEXT",
    "vkCmdDrawMeshTasksIndirectEXT", "vkCmdDrawMeshTasksIndirectCountEXT",
    "glDrawArrays", "glDrawElements", "glDrawArraysInstanced",
    "glDrawElementsInstanced", "glDrawElementsBaseVertex",
    "glDrawArraysInstancedBaseInstance",
    "glDrawElementsInstancedBaseVertexBaseInstance",
}
_DISPATCH = {
    "Dispatch", "DispatchMesh",
    "vkCmdDispatch", "vkCmdDispatchIndirect", "vkCmdDispatchBase",
    "glDispatchCompute", "glDispatchComputeIndirect",
}
_COPY = {
    "CopyResource", "CopyBufferRegion", "CopyTextureRegion", "CopyTiles",
    "ResolveSubresource", "ResolveSubresourceRegion",
    "vkCmdCopyBuffer", "vkCmdCopyImage", "vkCmdCopyBufferToImage",
    "vkCmdCopyImageToBuffer", "vkCmdBlitImage", "vkCmdResolveImage",
    "vkCmdFillBuffer", "vkCmdClearColorImage", "vkCmdClearDepthStencilImage",
    "vkCmdCopyAccelerationStructureKHR", "vkCmdUpdateBuffer",
    "vkCmdClearAttachments",
    "glCopyBufferSubData", "glCopyImageSubData",
}
_BARRIER = {
    "ResourceBarrier", "Barrier",
    "vkCmdPipelineBarrier", "vkCmdPipelineBarrier2",
    "vkCmdWaitEvents", "vkCmdSetEvent", "vkCmdResetEvent",
    "glMemoryBarrier", "glMemoryBarrierByRegion",
}
_PRESENT = {
    "Present", "Present1",
    "vkQueuePresentKHR", "vkAcquireNextImageKHR",
    "wglSwapBuffers", "glXSwapBuffers", "eglSwapBuffers",
}
_RAY_TRACING = {
    "DispatchRays", "BuildRaytracingAccelerationStructure",
    "EmitRaytracingAccelerationStructurePostbuildInfo",
    "vkCmdTraceRaysKHR", "vkCmdTraceRaysIndirectKHR", "vkCmdTraceRaysIndirect2KHR",
    "vkCmdBuildAccelerationStructuresKHR",
    "vkCmdBuildAccelerationStructuresIndirectKHR",
}
_SYNC = {
    "Wait", "Signal", "WaitForSingleObject",
    "vkQueueWaitIdle", "vkDeviceWaitIdle", "vkWaitSemaphores",
    "vkWaitForFences", "vkResetFences",
    "glClientWaitSync", "glWaitSync",
    "ExecuteCommandLists", "vkQueueSubmit", "vkQueueSubmit2",
}
_PIPELINE = {
    "vkCreateGraphicsPipelines", "vkCreateComputePipelines", "vkCreateRayTracingPipelinesKHR",
    "vkDestroyPipeline", "vkCmdBindPipeline",
    "CreateGraphicsPipelineState", "CreateComputePipelineState", "CreateStateObject",
    "SetPipelineState",
}
_DESCRIPTOR = {
    "vkAllocateDescriptorSets", "vkUpdateDescriptorSets",
    "vkCmdBindDescriptorSets", "vkCmdPushDescriptorSetKHR",
    "vkCreateDescriptorPool", "vkCreateDescriptorSetLayout",
    "CopyDescriptors", "CopyDescriptorsSimple",
    "CreateDescriptorHeap", "SetDescriptorHeaps",
}
_RESOURCE = {
    "vkCreateBuffer", "vkCreateImage", "vkCreateImageView", "vkCreateBufferView",
    "vkDestroyBuffer", "vkDestroyImage",
    "vkAllocateMemory", "vkMapMemory", "vkUnmapMemory", "vkFlushMappedMemoryRanges",
    "CreateCommittedResource", "CreateReservedResource", "CreatePlacedResource",
    "CreateHeap",
}
_CMDBUF = {
    "vkBeginCommandBuffer", "vkEndCommandBuffer", "vkResetCommandPool",
    "vkResetCommandBuffer", "vkCmdBeginRendering", "vkCmdEndRendering",
    "vkCmdBeginRenderPass", "vkCmdEndRenderPass",
    "vkCmdBindIndexBuffer", "vkCmdBindVertexBuffers",
    "vkCmdPushConstants",
    "Reset", "Close",
}
_SET_STATE_PREFIXES = (
    "Set", "Bind", "IASet", "OMSet", "RSSet", "VSSet", "PSSet", "CSSet", "GSSet",
    "HSSet", "DSSet",
    "vkCmdSet", "vkCmdBind", "vkCmdPush",
    "glBind", "glUseProgram", "glUniform", "glProgramUniform",
)


def classify(name: str) -> str:
    candidates = _function_name_candidates(name)
    if any(candidate in _DRAW for candidate in candidates):
        return "draw"
    if any(candidate in _DISPATCH for candidate in candidates):
        return "dispatch"
    if any(candidate in _COPY for candidate in candidates):
        return "copy"
    if any(candidate in _BARRIER for candidate in candidates):
        return "barrier"
    if any(candidate in _PRESENT for candidate in candidates):
        return "present"
    if any(candidate in _RAY_TRACING for candidate in candidates):
        return "ray_tracing"
    if any(candidate in _SYNC for candidate in candidates):
        return "sync"
    if any(candidate in _PIPELINE for candidate in candidates):
        return "pipeline"
    if any(candidate in _DESCRIPTOR for candidate in candidates):
        return "descriptor"
    if any(candidate in _RESOURCE for candidate in candidates):
        return "resource"
    if any(candidate in _CMDBUF for candidate in candidates):
        return "cmd_buffer"
    if any(candidate.startswith(p) for candidate in candidates for p in _SET_STATE_PREFIXES):
        return "set_state"
    return "other"


def _function_name_candidates(name: str) -> tuple[str, ...]:
    """Return raw + API-method suffix forms used by Nsight metadata streams."""
    if "_" not in name:
        return (name,)
    suffix = name.rsplit("_", 1)[-1]
    if suffix == name:
        return (name,)
    return (name, suffix)


@dataclass
class CallIndex:
    capture_path: Path
    dump_path: Path
    db_path: Path
    record_count: int
    kind_histogram: dict[str, int] = field(default_factory=dict)
    name_histogram_top: list[tuple[str, int]] = field(default_factory=list)
    thread_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "capture_path": str(self.capture_path),
            "dump_path": str(self.dump_path),
            "db_path": str(self.db_path),
            "record_count": self.record_count,
            "thread_count": self.thread_count,
            "kind_histogram": self.kind_histogram,
            "name_histogram_top": self.name_histogram_top,
        }


def _cache_root_for(capture: Path) -> Path:
    """Drop dump + DB next to the capture; fall back to LOCALAPPDATA cache
    if that's read-only."""
    try:
        sibling = capture.parent / f"{capture.name}.ngfxmcp"
        sibling.mkdir(exist_ok=True)
        probe = sibling / ".write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return sibling
    except OSError:
        cache = default_cache_dir() / "captures" / capture.stem
        cache.mkdir(parents=True, exist_ok=True)
        return cache


def _strip_log_prefix(stdout: str) -> str:
    text = stdout.lstrip()
    if text and text[0] in "[{":
        return text
    for i, line in enumerate(stdout.splitlines()):
        stripped = line.lstrip()
        if stripped and stripped[0] in "[{":
            return "\n".join(stdout.splitlines()[i:])
    return stdout


async def index_capture_functions(
    capture: Path,
    *,
    settings: Settings | None = None,
    force: bool = False,
    timeout: float | None = 600.0,
) -> CallIndex:
    """Run ``ngfx-replay --metadata-functions`` if needed, parse JSON, build
    SQLite side-DB. Subsequent invocations on an unchanged capture are no-ops.
    """
    s = settings or get_settings()
    replay = s.require_tool("ngfx_replay")
    capture_path = capture.resolve()
    cache = _cache_root_for(capture_path)
    dump_path = cache / "functions.json"
    db_path = cache / "functions.db"
    fingerprint_path = cache / "functions.mtime"

    src_mtime = capture_path.stat().st_mtime
    if not force and dump_path.is_file() and db_path.is_file() and fingerprint_path.is_file():
        try:
            cached_mtime = float(fingerprint_path.read_text(encoding="utf-8").strip())
            if abs(cached_mtime - src_mtime) < 0.5:
                return _load_index_summary(capture_path, dump_path, db_path)
        except (OSError, ValueError):
            pass

    argv = [str(replay), "--metadata-functions", "--quiet", str(capture_path)]
    res = await run_async(argv, tool="ngfx-replay", timeout=timeout, check=True)
    text = _strip_log_prefix(res.stdout)
    dump_path.write_text(text, encoding="utf-8")
    fingerprint_path.write_text(f"{src_mtime}", encoding="utf-8")

    try:
        records = json.loads(text)
        if not isinstance(records, list):
            records = []
    except json.JSONDecodeError:
        records = []

    if db_path.is_file():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE calls(
                event_index   INTEGER PRIMARY KEY,
                function_name TEXT NOT NULL,
                sequence_id   INTEGER NOT NULL,
                thread_index  INTEGER NOT NULL,
                kind          TEXT NOT NULL
            );
            CREATE INDEX i_calls_name  ON calls(function_name);
            CREATE INDEX i_calls_kind  ON calls(kind);
            CREATE INDEX i_calls_seq   ON calls(sequence_id);
            CREATE INDEX i_calls_thread ON calls(thread_index);
            CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);
            """
        )
        rows = []
        for rec in records:
            try:
                rows.append(
                    (
                        int(rec["event_index"]),
                        str(rec["function_name"]),
                        int(rec.get("sequence_id", 0)),
                        int(rec.get("thread_index", 0)),
                        classify(str(rec["function_name"])),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        conn.executemany(
            "INSERT OR REPLACE INTO calls(event_index, function_name, sequence_id, thread_index, kind) VALUES (?,?,?,?,?)",
            rows,
        )
        conn.execute("INSERT INTO meta(k, v) VALUES (?, ?)", ("capture_path", str(capture_path)))
        conn.commit()
    finally:
        conn.close()

    return _load_index_summary(capture_path, dump_path, db_path)


def _load_index_summary(capture: Path, dump_path: Path, db_path: Path) -> CallIndex:
    conn = sqlite3.connect(db_path)
    try:
        n = conn.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
        kinds = dict(conn.execute("SELECT kind, COUNT(*) FROM calls GROUP BY kind").fetchall())
        names = conn.execute(
            "SELECT function_name, COUNT(*) c FROM calls GROUP BY function_name ORDER BY c DESC LIMIT 50"
        ).fetchall()
        thread_count = conn.execute("SELECT COUNT(DISTINCT thread_index) FROM calls").fetchone()[0]
    finally:
        conn.close()
    return CallIndex(
        capture_path=capture,
        dump_path=dump_path,
        db_path=db_path,
        record_count=n,
        kind_histogram=kinds,
        name_histogram_top=names,
        thread_count=thread_count,
    )


def _connect(db_path: Path) -> sqlite3.Connection:
    if not db_path.is_file():
        raise FileNotFoundError(f"call index not built: {db_path}")
    return sqlite3.connect(db_path)


def query_calls(
    db_path: Path,
    *,
    kind: str | None = None,
    name_regex: str | None = None,
    name: str | None = None,
    start: int | None = None,
    end: int | None = None,
    thread_index: int | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Filtered scan over the call index."""
    conn = _connect(db_path)
    try:
        clauses: list[str] = []
        params: list[Any] = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if name:
            clauses.append("function_name = ?")
            params.append(name)
        if start is not None:
            clauses.append("event_index >= ?")
            params.append(start)
        if end is not None:
            clauses.append("event_index <= ?")
            params.append(end)
        if thread_index is not None:
            clauses.append("thread_index = ?")
            params.append(thread_index)
        if name_regex:
            try:
                re.compile(name_regex)
            except re.error as exc:
                raise ValueError(f"invalid regex {name_regex!r}: {exc}") from exc
            conn.create_function("regexp", 2, lambda pat, val: 1 if val and re.search(pat, val) else 0)
            clauses.append("regexp(?, function_name) = 1")
            params.append(name_regex)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            f"SELECT event_index, function_name, sequence_id, thread_index, kind "
            f"FROM calls {where} ORDER BY event_index LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        rows = conn.execute(sql, params).fetchall()
        return [
            {
                "event_index": r[0],
                "function_name": r[1],
                "sequence_id": r[2],
                "thread_index": r[3],
                "kind": r[4],
            }
            for r in rows
        ]
    finally:
        conn.close()


def get_call(db_path: Path, event_index: int) -> dict[str, Any] | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT event_index, function_name, sequence_id, thread_index, kind FROM calls WHERE event_index = ?",
            (event_index,),
        ).fetchone()
        if not row:
            return None
        return {
            "event_index": row[0],
            "function_name": row[1],
            "sequence_id": row[2],
            "thread_index": row[3],
            "kind": row[4],
        }
    finally:
        conn.close()


def call_histogram(db_path: Path, by: str = "function_name", limit: int = 100) -> list[dict[str, Any]]:
    aliases = {"name": "function_name", "kind": "kind", "thread": "thread_index"}
    column = aliases.get(by, by)
    if column not in ("function_name", "kind", "thread_index"):
        raise ValueError(f"by must be 'name'/'function_name', 'kind', or 'thread'; got {by!r}")
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            f"SELECT {column} k, COUNT(*) c FROM calls GROUP BY {column} ORDER BY c DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [{by: r[0], "count": r[1]} for r in rows]
    finally:
        conn.close()


def sql_query(db_path: Path, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
    """Read-only ``SELECT``/``WITH`` query against the call index."""
    text = sql.lstrip().lower()
    if not (text.startswith("select") or text.startswith("with")):
        raise ValueError("ngfx_event_query is read-only: pass SELECT/WITH queries only")
    conn = _connect(db_path)
    try:
        cur = conn.execute(sql, tuple(params))
        cols = [c[0] for c in cur.description] if cur.description else []
        rows = cur.fetchall()
        return [dict(zip(cols, row, strict=False)) for row in rows]
    finally:
        conn.close()
