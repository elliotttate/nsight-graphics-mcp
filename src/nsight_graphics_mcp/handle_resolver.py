"""Object handle / UID resolver.

The "wait, what wrote to this buffer?" tool. Cross-references the
:mod:`objects` index (which knows every API object by uid + type + name)
with the C++-Capture call index (which has full per-call args) and the
function-stream :mod:`events` index (which has name + kind ordering).

Given a uid or an object name like ``Buffer_91``, return:

  * the object record (type, category, api, access flags),
  * the create-call event_index (if discoverable),
  * every call whose args mention the uid / object name,
  * those calls bucketed by what they do to the object (create / write /
    bind / draw / barrier / destroy / other).

Handle-mention discovery uses the cpp_capture index when present. Without
it we can still find the create call by matching the type's typical
constructor call near the start of the stream, but we can't enumerate
writes/binds because the function stream has no arg values.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import cpp_capture_parser, events


# ---------------------------------------------------------------------------
# Per-API call classification: which calls create / write / bind which type.
# Keep small — extend as needed for new APIs.
# ---------------------------------------------------------------------------


_CREATE_CALLS_BY_TYPE = {
    "Buffer":             {"vkCreateBuffer", "CreateBuffer", "CreateCommittedResource",
                           "CreatePlacedResource", "CreateReservedResource", "glGenBuffers", "glCreateBuffers"},
    "BufferView":         {"vkCreateBufferView"},
    "Image":              {"vkCreateImage", "CreateCommittedResource",
                           "CreatePlacedResource", "CreateReservedResource"},
    "ImageView":          {"vkCreateImageView"},
    "Texture":            {"CreateCommittedResource", "CreateTexture", "glGenTextures", "glCreateTextures"},
    "TextureView":        {"vkCreateImageView", "CreateShaderResourceView",
                           "CreateUnorderedAccessView", "CreateRenderTargetView", "CreateDepthStencilView"},
    "Sampler":            {"vkCreateSampler", "CreateSampler", "glGenSamplers"},
    "Pipeline":           {"vkCreateGraphicsPipelines", "vkCreateComputePipelines",
                           "vkCreateRayTracingPipelinesKHR",
                           "CreateGraphicsPipelineState", "CreateComputePipelineState",
                           "CreateStateObject"},
    "PipelineLayout":     {"vkCreatePipelineLayout"},
    "RootSignature":      {"CreateRootSignature"},
    "ShaderModule":       {"vkCreateShaderModule"},
    "DescriptorPool":     {"vkCreateDescriptorPool", "CreateDescriptorHeap"},
    "DescriptorSet":      {"vkAllocateDescriptorSets"},
    "DescriptorSetLayout":{"vkCreateDescriptorSetLayout"},
    "CommandBuffer":      {"vkAllocateCommandBuffers"},
    "CommandPool":        {"vkCreateCommandPool"},
    "CommandList":        {"CreateCommandList", "CreateCommandList1"},
    "CommandAllocator":   {"CreateCommandAllocator"},
    "CommandQueue":       {"CreateCommandQueue"},
    "AccelerationStructureKHR": {"vkCreateAccelerationStructureKHR"},
    "Fence":              {"vkCreateFence", "CreateFence"},
    "Semaphore":          {"vkCreateSemaphore"},
}

_WRITE_CALL_KEYWORDS = ("Update", "Copy", "Clear", "Resolve", "Fill",
                        "Discard", "WriteBufferImmediate", "Map", "Unmap")
_BIND_CALL_KEYWORDS  = ("Bind", "Set", "IASet", "OMSet", "RSSet", "VSSet",
                        "PSSet", "CSSet", "HSSet", "DSSet", "GSSet")
_BARRIER_CALL_KEYWORDS = ("Barrier",)


def _classify_role(function_name: str) -> str:
    if any(function_name.startswith(p) for p in _BARRIER_CALL_KEYWORDS):
        return "barrier"
    if any(p in function_name for p in _WRITE_CALL_KEYWORDS):
        return "write"
    if any(function_name.startswith(p) for p in _BIND_CALL_KEYWORDS) or function_name.startswith("vkCmdBind"):
        return "bind"
    if function_name.startswith("Draw") or function_name.startswith("vkCmdDraw"):
        return "draw"
    if function_name.startswith("Dispatch") or function_name.startswith("vkCmdDispatch"):
        return "dispatch"
    if function_name.startswith("vkDestroy") or function_name.startswith("Destroy") or function_name == "Release":
        return "destroy"
    return "other"


@dataclass
class ObjectLookup:
    uid: int | None
    object_name: str
    type_name: str
    category: str
    api: str
    create_call: dict[str, Any] | None
    mention_count: int
    mentions_by_role: dict[str, int]
    mentions: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "object_name": self.object_name,
            "type_name": self.type_name,
            "category": self.category,
            "api": self.api,
            "create_call": self.create_call,
            "mention_count": self.mention_count,
            "mentions_by_role": self.mentions_by_role,
            "mentions": self.mentions,
        }


def _objects_db_for(capture: Path) -> Path:
    db = events._cache_root_for(capture) / "objects.db"
    if not db.is_file():
        raise FileNotFoundError(
            f"objects index missing for {capture}; call ngfx_index_objects() first."
        )
    return db


def _events_db_for(capture: Path) -> Path:
    db = events._cache_root_for(capture) / "functions.db"
    if not db.is_file():
        raise FileNotFoundError(
            f"events index missing for {capture}; call ngfx_index_events() first."
        )
    return db


def _find_cpp_db_for(capture: Path) -> Path | None:
    """Sibling cpp-capture index, if one exists for this capture."""
    sibling = capture.parent / f"{capture.name}.ngfxmcp" / "cpp_capture"
    if not sibling.is_dir():
        return None
    dbs = list(sibling.glob("**/.ngfxmcp_cpp_calls.db"))
    return max(dbs, key=lambda p: p.stat().st_mtime) if dbs else None


def _resolve_object_record(
    objects_db: Path, *, uid: int | None, object_name: str | None
) -> dict[str, Any] | None:
    conn = sqlite3.connect(objects_db)
    try:
        if uid is not None:
            row = conn.execute(
                "SELECT uid, type_name, object_name, api, access_flags, category "
                "FROM objects WHERE uid = ?", (uid,),
            ).fetchone()
        elif object_name is not None:
            row = conn.execute(
                "SELECT uid, type_name, object_name, api, access_flags, category "
                "FROM objects WHERE object_name = ?", (object_name,),
            ).fetchone()
        else:
            return None
        if not row:
            return None
        return {
            "uid": int(row[0]),
            "type_name": row[1],
            "object_name": row[2],
            "api": row[3],
            "access_flags": int(row[4]),
            "category": row[5],
        }
    finally:
        conn.close()


def _find_create_call(events_db: Path, type_name: str) -> dict[str, Any] | None:
    """Pick the FIRST event in the stream that matches a known create
    function for this type. Naive — works because per-process capture is
    started before any work is recorded, so the create stream is in order."""
    create_names = _CREATE_CALLS_BY_TYPE.get(type_name)
    if not create_names:
        return None
    conn = sqlite3.connect(events_db)
    try:
        marks = ",".join("?" * len(create_names))
        row = conn.execute(
            f"SELECT event_index, function_name, kind FROM calls "
            f"WHERE function_name IN ({marks}) ORDER BY event_index LIMIT 1",
            list(create_names),
        ).fetchone()
        if not row:
            return None
        return {"event_index": int(row[0]), "function_name": row[1], "kind": row[2]}
    finally:
        conn.close()


def _find_mentions(
    cpp_db: Path, needles: list[str], *, max_mentions: int = 1000,
) -> list[dict[str, Any]]:
    """Find every cpp_call whose raw_args or named_args_json contains any
    of the given needles. Each needle is matched as a substring (cheap
    LIKE query) — good enough because handle names are unique strings."""
    if not needles:
        return []
    conn = sqlite3.connect(cpp_db)
    try:
        clauses = " OR ".join(
            ["raw_args LIKE ? OR named_args_json LIKE ?"] * len(needles)
        )
        params: list[Any] = []
        for n in needles:
            params.extend([f"%{n}%", f"%{n}%"])
        sql = (
            "SELECT event_index, function_name, api, kind, raw_args, "
            "named_args_json, file_path, line_number "
            f"FROM cpp_calls WHERE {clauses} "
            f"ORDER BY event_index LIMIT {int(max_mentions)}"
        )
        rows = conn.execute(sql, params).fetchall()
        return [
            {
                "event_index": int(r[0]),
                "function_name": r[1],
                "api": r[2],
                "kind": r[3],
                "raw_args": r[4],
                "named_args": json.loads(r[5]) if r[5] else {},
                "file_path": r[6],
                "line_number": int(r[7]),
            }
            for r in rows
        ]
    finally:
        conn.close()


def resolve_handle(
    capture: Path,
    *,
    uid: int | None = None,
    object_name: str | None = None,
    extra_needles: list[str] | None = None,
    max_mentions: int = 1000,
) -> ObjectLookup:
    """Look up an object by uid or name, find its create call + every
    cpp-capture event that mentions it, role-classified."""
    if uid is None and not object_name:
        raise ValueError("must supply uid or object_name")

    obj_db = _objects_db_for(capture)
    ev_db = _events_db_for(capture)
    cpp_db = _find_cpp_db_for(capture)

    rec = _resolve_object_record(obj_db, uid=uid, object_name=object_name)
    if rec is None:
        raise LookupError(
            f"no object with uid={uid} / name={object_name!r} in objects index"
        )

    create = _find_create_call(ev_db, rec["type_name"])

    # Build the needle list: the canonical object name (Buffer_91), and
    # any g_*_<UID> naming Nsight's C++ capture emits.
    needles = [rec["object_name"]]
    needles.append(f"_{rec['uid']}")  # catches g_Buffer_91, g_VBV_91 etc.
    if extra_needles:
        needles.extend(extra_needles)

    mentions: list[dict[str, Any]] = []
    if cpp_db is not None:
        mentions = _find_mentions(cpp_db, needles, max_mentions=max_mentions)

    role_hist: dict[str, int] = {}
    for m in mentions:
        role = _classify_role(m["function_name"])
        role_hist[role] = role_hist.get(role, 0) + 1
        m["role"] = role

    return ObjectLookup(
        uid=rec["uid"],
        object_name=rec["object_name"],
        type_name=rec["type_name"],
        category=rec["category"],
        api=rec["api"],
        create_call=create,
        mention_count=len(mentions),
        mentions_by_role=role_hist,
        mentions=mentions,
    )
