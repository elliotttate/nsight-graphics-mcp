"""Parse a Generate-C++-Capture project to recover per-event argument values.

Why this exists
---------------
``ngfx-replay --metadata-functions`` only gives function NAMES per event,
not arguments. To answer "what's bound at root parameter N of event G?"
or "which CBV did this draw use?" we need argument values. Reverse-
engineering Nsight's proprietary protobuf is multi-hour work; the
shortcut taken here is:

  1. Generate a self-contained C++ project from the capture (either via
     the CLI ``ngfx --activity 'Generate C++ Capture' ...`` *or* via the
     UI's File menu — the UI path is the only one that works against a
     **saved** ``.ngfx-gfxcap`` because the CLI activity requires re-
     running the captured application).
  2. Walk the emitted ``.cpp`` files and index every command-list /
     command-buffer call: name, raw arg text, file:line. Each call gets
     a synthetic ``event_index`` assigned in emit order across the
     "play" function. That ordering matches the function stream
     ``ngfx-replay --metadata-functions`` produces (Nsight emits both
     from the same internal event list).
  3. For descriptor / resource-binding calls we also pull out the named
     arguments (root param index, slot, GPU descriptor handle, buffer
     view symbol). For draws/dispatches we capture the topology /
     vertex / index args.

The parser is deliberately regex-based — it doesn't try to be a C++
front-end. The generated code is straight-line, single-statement per
line, with no macros, so regex is enough.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .events import classify  # reuse the kind-classifier from the function stream


# ---------------------------------------------------------------------------
# Regex catalogue
# ---------------------------------------------------------------------------

# A "command-list call" looks like one of:
#   pCommandList->SetGraphicsRootDescriptorTable(0, g_GpuDescHandle_3);
#   m_CmdList->Draw(...);
#   commandList.IASetVertexBuffers(0, 1, &g_VBV_2);
#
# Vulkan calls are free functions taking a command buffer first:
#   vkCmdBindDescriptorSets(cmd, ..., 0, 1, &g_DescSet_5, 0, nullptr);
#   vkCmdDraw(commandBuffer, 36, 1, 0, 0);
#
# OpenGL (less common in Nsight outputs but supported):
#   glDrawElements(GL_TRIANGLES, 36, GL_UNSIGNED_SHORT, 0);

_RE_D3D_CALL = re.compile(
    r"""
    (?:^|[\s;{}])
    (?P<receiver>[A-Za-z_]\w*)\s*      # cmd-list-ish receiver
    (?:->|\.)
    (?P<func>[A-Za-z_]\w*)\s*
    \(
        (?P<args>.*?)
    \)\s*;
    """,
    re.VERBOSE,
)

_RE_VK_CALL = re.compile(
    r"""
    (?:^|[\s;{}])
    (?P<func>vkCmd[A-Za-z]\w*)\s*
    \(
        (?P<args>.*?)
    \)\s*;
    """,
    re.VERBOSE,
)

_RE_GL_CALL = re.compile(
    r"""
    (?:^|[\s;{}])
    (?P<func>gl(?:Draw|Dispatch|Bind|Use|Uniform|MemoryBarrier|Begin|End)[A-Za-z]\w*)\s*
    \(
        (?P<args>.*?)
    \)\s*;
    """,
    re.VERBOSE,
)

# Receivers that indicate a D3D12 command list or D3D11 device context.
# We don't want to match every method call; only ones on a likely cmd-list
# variable. The list below covers what Nsight typically emits.
_LIKELY_CMDLIST_RECEIVERS = {
    "pCommandList", "pCmdList", "pCL", "commandList", "cmdList", "cl",
    "pGraphicsCmdList", "pComputeCmdList", "pCopyCmdList",
    "pDeviceContext", "pContext", "ctx", "deviceContext",
    "pCommandQueue", "pQueue", "queue", "commandQueue",
}

# D3D12 method-name patterns that are bona-fide command-stream entries.
# Anything else on a cmd-list receiver (e.g. AddRef, Release) is filtered
# out. Loose: any method whose name starts with one of these prefixes.
_CMDLIST_METHOD_PREFIXES = (
    "Set", "Bind", "Draw", "Dispatch", "Copy", "Clear",
    "Resolve", "Resource", "Reset", "Close", "Execute",
    "IASet", "OMSet", "RSSet", "VSSet", "PSSet", "CSSet",
    "HSSet", "DSSet", "GSSet", "SOSet",
    "ClearRenderTargetView", "ClearDepthStencilView",
    "ClearUnorderedAccessView", "DiscardResource", "BeginQuery", "EndQuery",
    "EndRenderPass", "BeginRenderPass", "BeginRendering", "EndRendering",
    "ResourceBarrier", "Barrier", "WriteBufferImmediate", "AtomicCopyBuffer",
    "Present", "Signal", "Wait",
)


def _is_cmdlist_method(func: str) -> bool:
    if func.startswith("vkCmd") or func.startswith("gl"):
        return True
    return any(func.startswith(p) for p in _CMDLIST_METHOD_PREFIXES)


# ---------------------------------------------------------------------------
# Argument splitting (handles nested parens/braces and "string" literals)
# ---------------------------------------------------------------------------


def split_args(s: str) -> list[str]:
    """Split a comma-separated C-style argument list, respecting balanced
    parens/braces/angle-brackets/quotes."""
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    in_str: str | None = None
    i = 0
    while i < len(s):
        c = s[i]
        if in_str:
            buf.append(c)
            if c == "\\" and i + 1 < len(s):
                buf.append(s[i + 1])
                i += 2
                continue
            if c == in_str:
                in_str = None
        elif c in ('"', "'"):
            buf.append(c)
            in_str = c
        elif c in "([{<":
            buf.append(c)
            depth += 1
        elif c in ")]}>":
            buf.append(c)
            depth = max(0, depth - 1)
        elif c == "," and depth == 0:
            out.append("".join(buf).strip())
            buf = []
        else:
            buf.append(c)
        i += 1
    if buf:
        out.append("".join(buf).strip())
    return out


# ---------------------------------------------------------------------------
# Per-event extraction
# ---------------------------------------------------------------------------


# Specific extractors for descriptor-binding calls. Each takes the raw
# arg list (list[str]) and returns a JSON-safe dict of named fields.
def _extract_d3d_root_descriptor_table(args: list[str]) -> dict[str, Any]:
    return {"root_param_index": args[0] if args else None,
            "gpu_descriptor_handle": args[1] if len(args) > 1 else None}


def _extract_d3d_root_cbv_srv_uav(args: list[str]) -> dict[str, Any]:
    return {"root_param_index": args[0] if args else None,
            "buffer_location": args[1] if len(args) > 1 else None}


def _extract_d3d_root_32bit_constants(args: list[str]) -> dict[str, Any]:
    return {"root_param_index": args[0] if args else None,
            "num_32bit_values": args[1] if len(args) > 1 else None,
            "src_data": args[2] if len(args) > 2 else None,
            "dest_offset_in_32bit_values": args[3] if len(args) > 3 else None}


def _extract_d3d_set_descriptor_heaps(args: list[str]) -> dict[str, Any]:
    return {"num_descriptor_heaps": args[0] if args else None,
            "descriptor_heaps": args[1] if len(args) > 1 else None}


def _extract_d3d_set_root_signature(args: list[str]) -> dict[str, Any]:
    return {"root_signature": args[0] if args else None}


def _extract_d3d_ia_set_vertex_buffers(args: list[str]) -> dict[str, Any]:
    return {"start_slot": args[0] if args else None,
            "num_views": args[1] if len(args) > 1 else None,
            "views": args[2] if len(args) > 2 else None}


def _extract_d3d_ia_set_index_buffer(args: list[str]) -> dict[str, Any]:
    return {"view": args[0] if args else None}


def _extract_d3d_om_set_render_targets(args: list[str]) -> dict[str, Any]:
    return {"num_render_target_descriptors": args[0] if args else None,
            "render_target_descriptors": args[1] if len(args) > 1 else None,
            "rts_single_handle_to_descriptor_range": args[2] if len(args) > 2 else None,
            "depth_stencil_descriptor": args[3] if len(args) > 3 else None}


def _extract_d3d_draw_instanced(args: list[str]) -> dict[str, Any]:
    return {"vertex_count_per_instance": args[0] if args else None,
            "instance_count": args[1] if len(args) > 1 else None,
            "start_vertex_location": args[2] if len(args) > 2 else None,
            "start_instance_location": args[3] if len(args) > 3 else None}


def _extract_d3d_draw_indexed_instanced(args: list[str]) -> dict[str, Any]:
    return {"index_count_per_instance": args[0] if args else None,
            "instance_count": args[1] if len(args) > 1 else None,
            "start_index_location": args[2] if len(args) > 2 else None,
            "base_vertex_location": args[3] if len(args) > 3 else None,
            "start_instance_location": args[4] if len(args) > 4 else None}


def _extract_d3d_dispatch(args: list[str]) -> dict[str, Any]:
    return {"thread_group_count_x": args[0] if args else None,
            "thread_group_count_y": args[1] if len(args) > 1 else None,
            "thread_group_count_z": args[2] if len(args) > 2 else None}


def _extract_d3d_set_pipeline_state(args: list[str]) -> dict[str, Any]:
    return {"pipeline_state": args[0] if args else None}


def _extract_vk_bind_descriptor_sets(args: list[str]) -> dict[str, Any]:
    # vkCmdBindDescriptorSets(cmd, pipelineBindPoint, layout,
    #   firstSet, descriptorSetCount, pDescriptorSets,
    #   dynamicOffsetCount, pDynamicOffsets)
    return {"command_buffer": args[0] if args else None,
            "pipeline_bind_point": args[1] if len(args) > 1 else None,
            "layout": args[2] if len(args) > 2 else None,
            "first_set": args[3] if len(args) > 3 else None,
            "descriptor_set_count": args[4] if len(args) > 4 else None,
            "p_descriptor_sets": args[5] if len(args) > 5 else None,
            "dynamic_offset_count": args[6] if len(args) > 6 else None,
            "p_dynamic_offsets": args[7] if len(args) > 7 else None}


def _extract_vk_bind_pipeline(args: list[str]) -> dict[str, Any]:
    return {"command_buffer": args[0] if args else None,
            "pipeline_bind_point": args[1] if len(args) > 1 else None,
            "pipeline": args[2] if len(args) > 2 else None}


def _extract_vk_bind_vertex_buffers(args: list[str]) -> dict[str, Any]:
    return {"command_buffer": args[0] if args else None,
            "first_binding": args[1] if len(args) > 1 else None,
            "binding_count": args[2] if len(args) > 2 else None,
            "p_buffers": args[3] if len(args) > 3 else None,
            "p_offsets": args[4] if len(args) > 4 else None}


def _extract_vk_bind_index_buffer(args: list[str]) -> dict[str, Any]:
    return {"command_buffer": args[0] if args else None,
            "buffer": args[1] if len(args) > 1 else None,
            "offset": args[2] if len(args) > 2 else None,
            "index_type": args[3] if len(args) > 3 else None}


def _extract_vk_push_constants(args: list[str]) -> dict[str, Any]:
    return {"command_buffer": args[0] if args else None,
            "layout": args[1] if len(args) > 1 else None,
            "stage_flags": args[2] if len(args) > 2 else None,
            "offset": args[3] if len(args) > 3 else None,
            "size": args[4] if len(args) > 4 else None,
            "p_values": args[5] if len(args) > 5 else None}


def _extract_vk_draw(args: list[str]) -> dict[str, Any]:
    return {"command_buffer": args[0] if args else None,
            "vertex_count": args[1] if len(args) > 1 else None,
            "instance_count": args[2] if len(args) > 2 else None,
            "first_vertex": args[3] if len(args) > 3 else None,
            "first_instance": args[4] if len(args) > 4 else None}


def _extract_vk_draw_indexed(args: list[str]) -> dict[str, Any]:
    return {"command_buffer": args[0] if args else None,
            "index_count": args[1] if len(args) > 1 else None,
            "instance_count": args[2] if len(args) > 2 else None,
            "first_index": args[3] if len(args) > 3 else None,
            "vertex_offset": args[4] if len(args) > 4 else None,
            "first_instance": args[5] if len(args) > 5 else None}


def _extract_vk_dispatch(args: list[str]) -> dict[str, Any]:
    return {"command_buffer": args[0] if args else None,
            "group_count_x": args[1] if len(args) > 1 else None,
            "group_count_y": args[2] if len(args) > 2 else None,
            "group_count_z": args[3] if len(args) > 3 else None}


# Function-name -> (api, extractor)
_EXTRACTORS: dict[str, tuple[str, Any]] = {
    # D3D12 — descriptor / root parameter bindings
    "SetGraphicsRootSignature":           ("d3d12", _extract_d3d_set_root_signature),
    "SetComputeRootSignature":            ("d3d12", _extract_d3d_set_root_signature),
    "SetDescriptorHeaps":                 ("d3d12", _extract_d3d_set_descriptor_heaps),
    "SetGraphicsRootDescriptorTable":     ("d3d12", _extract_d3d_root_descriptor_table),
    "SetComputeRootDescriptorTable":      ("d3d12", _extract_d3d_root_descriptor_table),
    "SetGraphicsRootConstantBufferView":  ("d3d12", _extract_d3d_root_cbv_srv_uav),
    "SetComputeRootConstantBufferView":   ("d3d12", _extract_d3d_root_cbv_srv_uav),
    "SetGraphicsRootShaderResourceView":  ("d3d12", _extract_d3d_root_cbv_srv_uav),
    "SetComputeRootShaderResourceView":   ("d3d12", _extract_d3d_root_cbv_srv_uav),
    "SetGraphicsRootUnorderedAccessView": ("d3d12", _extract_d3d_root_cbv_srv_uav),
    "SetComputeRootUnorderedAccessView":  ("d3d12", _extract_d3d_root_cbv_srv_uav),
    "SetGraphicsRoot32BitConstant":       ("d3d12", _extract_d3d_root_32bit_constants),
    "SetGraphicsRoot32BitConstants":      ("d3d12", _extract_d3d_root_32bit_constants),
    "SetComputeRoot32BitConstant":        ("d3d12", _extract_d3d_root_32bit_constants),
    "SetComputeRoot32BitConstants":       ("d3d12", _extract_d3d_root_32bit_constants),
    "IASetVertexBuffers":                 ("d3d12", _extract_d3d_ia_set_vertex_buffers),
    "IASetIndexBuffer":                   ("d3d12", _extract_d3d_ia_set_index_buffer),
    "OMSetRenderTargets":                 ("d3d12", _extract_d3d_om_set_render_targets),
    "SetPipelineState":                   ("d3d12", _extract_d3d_set_pipeline_state),
    "DrawInstanced":                      ("d3d12", _extract_d3d_draw_instanced),
    "DrawIndexedInstanced":               ("d3d12", _extract_d3d_draw_indexed_instanced),
    "Dispatch":                           ("d3d12", _extract_d3d_dispatch),
    # Vulkan
    "vkCmdBindDescriptorSets":  ("vulkan", _extract_vk_bind_descriptor_sets),
    "vkCmdBindPipeline":        ("vulkan", _extract_vk_bind_pipeline),
    "vkCmdBindVertexBuffers":   ("vulkan", _extract_vk_bind_vertex_buffers),
    "vkCmdBindVertexBuffers2":  ("vulkan", _extract_vk_bind_vertex_buffers),
    "vkCmdBindIndexBuffer":     ("vulkan", _extract_vk_bind_index_buffer),
    "vkCmdPushConstants":       ("vulkan", _extract_vk_push_constants),
    "vkCmdDraw":                ("vulkan", _extract_vk_draw),
    "vkCmdDrawIndexed":         ("vulkan", _extract_vk_draw_indexed),
    "vkCmdDispatch":            ("vulkan", _extract_vk_dispatch),
}


@dataclass
class ParsedCall:
    event_index: int
    function_name: str
    api: str
    kind: str
    receiver: str | None
    raw_args: str
    args: list[str]
    named_args: dict[str, Any]
    file_path: str
    line_number: int


# ---------------------------------------------------------------------------
# File walk + extraction
# ---------------------------------------------------------------------------


def _candidate_files(root: Path) -> list[Path]:
    """All .cpp / .cxx / .c / .cc files under root, sorted for stable ordering."""
    exts = {".cpp", ".cxx", ".cc", ".c"}
    files = sorted(p for p in root.rglob("*") if p.suffix.lower() in exts)
    return files


def _parse_file(path: Path, start_index: int) -> list[ParsedCall]:
    """Stream-parse a .cpp file; return calls that look like command-stream
    entries. Calls are numbered sequentially starting at ``start_index``."""
    out: list[ParsedCall] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out

    # Some emit styles split call args across multiple lines. Fold them.
    # We do a cheap statement join: any line that doesn't end with ';' AND
    # contains an unclosed '(' is merged with the next line. This is good
    # enough for Nsight's emit.
    folded: list[tuple[int, str]] = []  # (line_no, joined_text)
    pending: list[str] = []
    pending_start = 0
    depth = 0
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if not line:
            continue
        # Block boundaries are NOT statements — never fold across them.
        # Any `{` or `}` ends the current pending and is emitted as its
        # own (skipped) line, then the next statement starts fresh.
        if line.endswith("{") or line.endswith("}") or line in ("{", "}"):
            if pending:
                folded.append((pending_start, " ".join(pending)))
            folded.append((n, line))
            pending = []
            depth = 0
            continue
        if not pending:
            pending_start = n
        pending.append(line)
        depth += line.count("(") - line.count(")")
        if line.endswith(";") and depth <= 0:
            folded.append((pending_start, " ".join(pending)))
            pending = []
            depth = 0
    if pending:
        folded.append((pending_start, " ".join(pending)))

    idx = start_index
    for line_no, line in folded:
        # Skip declarations / comments / preprocessor; quick reject.
        stripped = line.lstrip()
        if (not stripped or stripped.startswith("//") or stripped.startswith("/*")
                or stripped.startswith("#") or stripped.startswith("*")):
            continue
        m_vk = _RE_VK_CALL.search(line)
        m_d3 = None
        m_gl = None
        if not m_vk:
            m_d3 = _RE_D3D_CALL.search(line)
            if not m_d3:
                m_gl = _RE_GL_CALL.search(line)
        if not (m_vk or m_d3 or m_gl):
            continue

        if m_vk:
            func = m_vk.group("func")
            raw_args = m_vk.group("args")
            receiver = None
            api = "vulkan"
        elif m_d3:
            func = m_d3.group("func")
            raw_args = m_d3.group("args")
            receiver = m_d3.group("receiver")
            if receiver not in _LIKELY_CMDLIST_RECEIVERS:
                # Filter: only methods called on a known cmd-list-ish receiver
                # AND with a command-list-shaped method name pass through.
                if not _is_cmdlist_method(func):
                    continue
            elif not _is_cmdlist_method(func):
                continue
            api = "d3d12"
        else:
            func = m_gl.group("func")
            raw_args = m_gl.group("args")
            receiver = None
            api = "opengl"

        args = split_args(raw_args)
        api_or_default, extractor = _EXTRACTORS.get(func, (api, None))
        named = extractor(args) if extractor else {}
        out.append(ParsedCall(
            event_index=idx,
            function_name=func,
            api=api_or_default,
            kind=classify(func),
            receiver=receiver,
            raw_args=raw_args,
            args=args,
            named_args=named,
            file_path=str(path),
            line_number=line_no,
        ))
        idx += 1
    return out


# ---------------------------------------------------------------------------
# Indexer (SQLite)
# ---------------------------------------------------------------------------


SCHEMA = """
CREATE TABLE IF NOT EXISTS cpp_calls(
    event_index   INTEGER PRIMARY KEY,
    function_name TEXT NOT NULL,
    api           TEXT NOT NULL,
    kind          TEXT NOT NULL,
    receiver      TEXT,
    raw_args      TEXT NOT NULL,
    args_json     TEXT NOT NULL,
    named_args_json TEXT NOT NULL,
    file_path     TEXT NOT NULL,
    line_number   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS i_cpp_calls_name ON cpp_calls(function_name);
CREATE INDEX IF NOT EXISTS i_cpp_calls_kind ON cpp_calls(kind);
CREATE INDEX IF NOT EXISTS i_cpp_calls_api  ON cpp_calls(api);
CREATE TABLE IF NOT EXISTS cpp_meta(k TEXT PRIMARY KEY, v TEXT);
"""


@dataclass
class CppCaptureIndex:
    project_dir: Path
    db_path: Path
    record_count: int
    file_count: int
    kind_histogram: dict[str, int] = field(default_factory=dict)
    function_histogram_top: list[tuple[str, int]] = field(default_factory=list)
    api_histogram: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_dir": str(self.project_dir),
            "db_path": str(self.db_path),
            "record_count": self.record_count,
            "file_count": self.file_count,
            "kind_histogram": self.kind_histogram,
            "function_histogram_top": self.function_histogram_top,
            "api_histogram": self.api_histogram,
        }


def index_cpp_project(project_dir: Path, *, db_path: Path | None = None, force: bool = False) -> CppCaptureIndex:
    """Walk ``project_dir`` recursively for ``.cpp``/``.cxx`` files, parse
    command-stream calls, and load them into a SQLite database next to the
    project (or at ``db_path`` if supplied).
    """
    project_dir = project_dir.resolve()
    if db_path is None:
        db_path = project_dir / ".ngfxmcp_cpp_calls.db"
    if force and db_path.exists():
        db_path.unlink()

    files = _candidate_files(project_dir)
    all_calls: list[ParsedCall] = []
    idx = 0
    for f in files:
        calls = _parse_file(f, idx)
        all_calls.extend(calls)
        idx += len(calls)

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.execute("DELETE FROM cpp_calls")
        conn.execute("DELETE FROM cpp_meta")
        conn.executemany(
            "INSERT INTO cpp_calls(event_index, function_name, api, kind, receiver, "
            "raw_args, args_json, named_args_json, file_path, line_number) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    c.event_index, c.function_name, c.api, c.kind, c.receiver,
                    c.raw_args, json.dumps(c.args), json.dumps(c.named_args),
                    c.file_path, c.line_number,
                )
                for c in all_calls
            ],
        )
        conn.execute("INSERT INTO cpp_meta(k, v) VALUES (?, ?)",
                     ("project_dir", str(project_dir)))
        conn.execute("INSERT INTO cpp_meta(k, v) VALUES (?, ?)",
                     ("file_count", str(len(files))))
        conn.commit()

        kinds = dict(conn.execute("SELECT kind, COUNT(*) FROM cpp_calls GROUP BY kind").fetchall())
        apis = dict(conn.execute("SELECT api, COUNT(*) FROM cpp_calls GROUP BY api").fetchall())
        names = conn.execute(
            "SELECT function_name, COUNT(*) c FROM cpp_calls GROUP BY function_name ORDER BY c DESC LIMIT 50"
        ).fetchall()
    finally:
        conn.close()

    return CppCaptureIndex(
        project_dir=project_dir,
        db_path=db_path,
        record_count=len(all_calls),
        file_count=len(files),
        kind_histogram=kinds,
        function_histogram_top=names,
        api_histogram=apis,
    )


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def _connect(db_path: Path) -> sqlite3.Connection:
    if not db_path.is_file():
        raise FileNotFoundError(f"C++ call index not built: {db_path}")
    return sqlite3.connect(db_path)


def _row_to_dict(row: tuple) -> dict[str, Any]:
    return {
        "event_index": row[0],
        "function_name": row[1],
        "api": row[2],
        "kind": row[3],
        "receiver": row[4],
        "raw_args": row[5],
        "args": json.loads(row[6]),
        "named_args": json.loads(row[7]),
        "file_path": row[8],
        "line_number": row[9],
    }


def get_call(db_path: Path, event_index: int) -> dict[str, Any] | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT event_index, function_name, api, kind, receiver, raw_args, "
            "args_json, named_args_json, file_path, line_number "
            "FROM cpp_calls WHERE event_index = ?",
            (event_index,),
        ).fetchone()
        return _row_to_dict(row) if row else None
    finally:
        conn.close()


def query_calls(
    db_path: Path,
    *,
    kind: str | None = None,
    api: str | None = None,
    name: str | None = None,
    name_regex: str | None = None,
    contains: str | None = None,
    start: int | None = None,
    end: int | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict[str, Any]]:
    conn = _connect(db_path)
    try:
        clauses: list[str] = []
        params: list[Any] = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if api:
            clauses.append("api = ?")
            params.append(api)
        if name:
            clauses.append("function_name = ?")
            params.append(name)
        if start is not None:
            clauses.append("event_index >= ?")
            params.append(start)
        if end is not None:
            clauses.append("event_index <= ?")
            params.append(end)
        if contains:
            clauses.append("(raw_args LIKE ? OR named_args_json LIKE ?)")
            params.extend([f"%{contains}%", f"%{contains}%"])
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
            "SELECT event_index, function_name, api, kind, receiver, raw_args, "
            "args_json, named_args_json, file_path, line_number "
            f"FROM cpp_calls {where} ORDER BY event_index LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        rows = conn.execute(sql, params).fetchall()
        return [_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def descriptor_bindings_for_event(db_path: Path, event_index: int, *, lookback: int = 200) -> dict[str, Any]:
    """Return the descriptor / root-parameter binding state that was in
    effect at ``event_index`` by walking backwards from that event until
    we hit a pipeline change or run out of ``lookback`` events.

    For D3D12 we accumulate the most recent Set*Root*/SetDescriptorHeaps/
    IA*/OM* calls keyed by their root param index / slot.
    For Vulkan we accumulate the most recent vkCmdBindDescriptorSets per
    first_set value, plus the most recent vkCmdBindPipeline /
    vkCmdBindVertexBuffers / vkCmdBindIndexBuffer / vkCmdPushConstants.

    Useful for "what was the shader reading from at draw N?" without
    re-reading the entire event stream.
    """
    state: dict[str, Any] = {
        "event_index": event_index,
        "d3d12": {
            "root_signature": None,
            "descriptor_heaps": None,
            "pipeline_state": None,
            "root_params": {},        # root_param_index -> {kind, ...}
            "vertex_buffers": None,
            "index_buffer": None,
            "render_targets": None,
        },
        "vulkan": {
            "pipeline": None,
            "descriptor_sets": {},    # first_set -> args
            "vertex_buffers": None,
            "index_buffer": None,
            "push_constants_last": None,
        },
        "scanned": 0,
    }

    conn = _connect(db_path)
    try:
        target = conn.execute(
            "SELECT api FROM cpp_calls WHERE event_index = ?", (event_index,)
        ).fetchone()
        if not target:
            return {"error": f"event {event_index} not in cpp call index"}

        rows = conn.execute(
            "SELECT event_index, function_name, api, kind, named_args_json "
            "FROM cpp_calls WHERE event_index < ? AND event_index >= ? "
            "ORDER BY event_index DESC",
            (event_index, max(0, event_index - lookback)),
        ).fetchall()

        for r in rows:
            state["scanned"] += 1
            ev, fn, api, kind, named_json = r
            named = json.loads(named_json) if named_json else {}
            d3 = state["d3d12"]
            vk = state["vulkan"]

            if api == "d3d12":
                if fn.endswith("RootSignature") and d3["root_signature"] is None:
                    d3["root_signature"] = {"event_index": ev, "value": named.get("root_signature")}
                elif fn == "SetDescriptorHeaps" and d3["descriptor_heaps"] is None:
                    d3["descriptor_heaps"] = {"event_index": ev, **named}
                elif fn == "SetPipelineState" and d3["pipeline_state"] is None:
                    d3["pipeline_state"] = {"event_index": ev, "value": named.get("pipeline_state")}
                elif fn == "IASetVertexBuffers" and d3["vertex_buffers"] is None:
                    d3["vertex_buffers"] = {"event_index": ev, **named}
                elif fn == "IASetIndexBuffer" and d3["index_buffer"] is None:
                    d3["index_buffer"] = {"event_index": ev, **named}
                elif fn == "OMSetRenderTargets" and d3["render_targets"] is None:
                    d3["render_targets"] = {"event_index": ev, **named}
                elif fn.startswith("SetGraphicsRoot") or fn.startswith("SetComputeRoot"):
                    idx = named.get("root_param_index")
                    if idx is not None and idx not in d3["root_params"]:
                        d3["root_params"][idx] = {"event_index": ev, "call": fn, **named}
            elif api == "vulkan":
                if fn == "vkCmdBindPipeline" and vk["pipeline"] is None:
                    vk["pipeline"] = {"event_index": ev, **named}
                elif fn in ("vkCmdBindVertexBuffers", "vkCmdBindVertexBuffers2") and vk["vertex_buffers"] is None:
                    vk["vertex_buffers"] = {"event_index": ev, **named}
                elif fn == "vkCmdBindIndexBuffer" and vk["index_buffer"] is None:
                    vk["index_buffer"] = {"event_index": ev, **named}
                elif fn == "vkCmdBindDescriptorSets":
                    fs = named.get("first_set")
                    if fs is not None and fs not in vk["descriptor_sets"]:
                        vk["descriptor_sets"][fs] = {"event_index": ev, **named}
                elif fn == "vkCmdPushConstants" and vk["push_constants_last"] is None:
                    vk["push_constants_last"] = {"event_index": ev, **named}
    finally:
        conn.close()
    return state


def sql_query(db_path: Path, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
    """Read-only ``SELECT``/``WITH`` query against the C++ call index."""
    text = sql.lstrip().lower()
    if not (text.startswith("select") or text.startswith("with")):
        raise ValueError("cpp_capture sql is read-only: pass SELECT/WITH only")
    conn = _connect(db_path)
    try:
        cur = conn.execute(sql, tuple(params))
        cols = [c[0] for c in cur.description] if cur.description else []
        rows = cur.fetchall()
        return [dict(zip(cols, row)) for row in rows]
    finally:
        conn.close()
