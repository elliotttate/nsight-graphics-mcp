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
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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

# Nsight Graphics 2025.5+ Generate-C++-Capture emits free-function calls
# instead of method calls. Example:
#   My_ID3D12GraphicsCommandList_SetPipelineState(
#       D3D12StaticCast<ID3D12GraphicsCommandList*>(NV..._uid_7806_instance_0),
#       pID3D12PipelineState__uid_279);
# The interface class is encoded in the function name. The first
# positional arg is the receiver — we strip it so downstream extractors
# can keep using positional args 0..N-1 for the method's documented args.
_RE_D3D_NEW_CALL = re.compile(
    r"""
    (?:^|[\s;{}])
    My_(?P<iface>ID3D12[A-Za-z0-9]+ | ID3D11[A-Za-z0-9]+)_(?P<func>[A-Za-z_]\w*)\s*
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


def _extract_d3d_rs_set_viewports(args: list[str]) -> dict[str, Any]:
    return {"num_viewports": args[0] if args else None,
            "viewports": args[1] if len(args) > 1 else None}


def _extract_d3d_rs_set_scissor_rects(args: list[str]) -> dict[str, Any]:
    return {"num_rects": args[0] if args else None,
            "rects": args[1] if len(args) > 1 else None}


def _extract_d3d_clear_render_target_view(args: list[str]) -> dict[str, Any]:
    return {"render_target_view": args[0] if args else None,
            "color_rgba": args[1] if len(args) > 1 else None,
            "num_rects": args[2] if len(args) > 2 else None,
            "rects": args[3] if len(args) > 3 else None}


def _extract_d3d_clear_depth_stencil_view(args: list[str]) -> dict[str, Any]:
    return {"depth_stencil_view": args[0] if args else None,
            "clear_flags": args[1] if len(args) > 1 else None,
            "depth": args[2] if len(args) > 2 else None,
            "stencil": args[3] if len(args) > 3 else None,
            "num_rects": args[4] if len(args) > 4 else None,
            "rects": args[5] if len(args) > 5 else None}


def _extract_d3d_copy_resource(args: list[str]) -> dict[str, Any]:
    return {"dst_resource": args[0] if args else None,
            "src_resource": args[1] if len(args) > 1 else None}


def _extract_d3d_copy_texture_region(args: list[str]) -> dict[str, Any]:
    return {"dst": args[0] if args else None,
            "dst_x": args[1] if len(args) > 1 else None,
            "dst_y": args[2] if len(args) > 2 else None,
            "dst_z": args[3] if len(args) > 3 else None,
            "src": args[4] if len(args) > 4 else None,
            "src_box": args[5] if len(args) > 5 else None}


def _extract_d3d_resolve_subresource(args: list[str]) -> dict[str, Any]:
    return {"dst_resource": args[0] if args else None,
            "dst_subresource": args[1] if len(args) > 1 else None,
            "src_resource": args[2] if len(args) > 2 else None,
            "src_subresource": args[3] if len(args) > 3 else None,
            "format": args[4] if len(args) > 4 else None}


def _extract_d3d_resource_barrier(args: list[str]) -> dict[str, Any]:
    return {"num_barriers": args[0] if args else None,
            "barriers": args[1] if len(args) > 1 else None}


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


def _extract_d3d_execute_indirect(args: list[str]) -> dict[str, Any]:
    return {"command_signature": args[0] if args else None,
            "max_command_count": args[1] if len(args) > 1 else None,
            "argument_buffer": args[2] if len(args) > 2 else None,
            "argument_buffer_offset": args[3] if len(args) > 3 else None,
            "count_buffer": args[4] if len(args) > 4 else None,
            "count_buffer_offset": args[5] if len(args) > 5 else None}


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
    "RSSetViewports":                     ("d3d12", _extract_d3d_rs_set_viewports),
    "RSSetScissorRects":                  ("d3d12", _extract_d3d_rs_set_scissor_rects),
    "SetPipelineState":                   ("d3d12", _extract_d3d_set_pipeline_state),
    "ClearRenderTargetView":              ("d3d12", _extract_d3d_clear_render_target_view),
    "ClearDepthStencilView":              ("d3d12", _extract_d3d_clear_depth_stencil_view),
    "CopyResource":                       ("d3d12", _extract_d3d_copy_resource),
    "CopyTextureRegion":                  ("d3d12", _extract_d3d_copy_texture_region),
    "ResolveSubresource":                 ("d3d12", _extract_d3d_resolve_subresource),
    "ResourceBarrier":                    ("d3d12", _extract_d3d_resource_barrier),
    "DrawInstanced":                      ("d3d12", _extract_d3d_draw_instanced),
    "DrawIndexedInstanced":               ("d3d12", _extract_d3d_draw_indexed_instanced),
    "Dispatch":                           ("d3d12", _extract_d3d_dispatch),
    "ExecuteIndirect":                    ("d3d12", _extract_d3d_execute_indirect),
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
        # Skip pure comment / preprocessor lines outright so they don't
        # get glued onto the next statement during folding. (Nsight 2025.5
        # emits `// Draw #54 [0...665]` markers right before each draw call;
        # without this skip the folder joins them and the parser drops the
        # composite as a comment line.)
        stripped_line = line.lstrip()
        if (
            stripped_line.startswith("//")
            or stripped_line.startswith("/*")
            or stripped_line.startswith("*")
            or stripped_line.startswith("#")
        ):
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
        m_d3_new = None
        m_gl = None
        if not m_vk:
            # Try the 2025.5+ free-function format first — its `My_` prefix
            # is unambiguous, so it never accidentally matches old-style
            # method calls.
            m_d3_new = _RE_D3D_NEW_CALL.search(line)
            if not m_d3_new:
                m_d3 = _RE_D3D_CALL.search(line)
                if not m_d3:
                    m_gl = _RE_GL_CALL.search(line)
        if not (m_vk or m_d3 or m_d3_new or m_gl):
            continue

        if m_vk:
            func = m_vk.group("func")
            raw_args = m_vk.group("args")
            receiver = None
            api = "vulkan"
        elif m_d3_new:
            iface = m_d3_new.group("iface")
            func = m_d3_new.group("func")
            raw_args = m_d3_new.group("args")
            # Filter to bona-fide command-list interfaces; otherwise device-
            # level calls (CreatePipelineState, CreateRootSignature, etc.)
            # leak in.
            if not (
                iface.startswith("ID3D12GraphicsCommandList")
                or iface.startswith("ID3D11DeviceContext")
                or iface == "ID3D12CommandList"
            ):
                continue
            if not _is_cmdlist_method(func):
                continue
            # Strip the receiver (first positional arg) so downstream
            # extractors keep using args[0..N-1] for the documented args.
            full_args = split_args(raw_args)
            if not full_args:
                continue
            receiver = full_args[0]
            args = full_args[1:]
            raw_args = ", ".join(args)
            api = "d3d12"
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
            continue
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
            ev, fn, api, _kind, named_json = r
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
        return [dict(zip(cols, row, strict=False)) for row in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Descriptor heap timeline
# ---------------------------------------------------------------------------


_HEAP_EVENT_FUNCTIONS = (
    "SetDescriptorHeaps",
    "CopyDescriptors",
    "CopyDescriptorsSimple",
    "SetGraphicsRootDescriptorTable",
    "SetComputeRootDescriptorTable",
    "CreateShaderResourceView",
    "CreateUnorderedAccessView",
    "CreateConstantBufferView",
    "CreateRenderTargetView",
    "CreateDepthStencilView",
    "CreateSampler",
)


def descriptor_heap_timeline(
    db_path: Path,
    *,
    heap_symbol: str | None = None,
    start: int | None = None,
    end: int | None = None,
    limit: int = 5000,
) -> dict[str, Any]:
    """Return the per-heap timeline of descriptor-related calls.

    Surfaces, in event order: ``SetDescriptorHeaps``, ``CopyDescriptors[Simple]``,
    ``SetGraphicsRootDescriptorTable`` / ``SetComputeRootDescriptorTable``, and
    the ``Create*View`` / ``CreateSampler`` calls that populate slots. Grouped
    by heap symbol when ``heap_symbol`` is given, otherwise by the heap
    referenced in each call's args.
    """
    conn = _connect(db_path)
    try:
        clauses = ["function_name IN ({})".format(
            ",".join("?" * len(_HEAP_EVENT_FUNCTIONS))
        )]
        params: list[Any] = list(_HEAP_EVENT_FUNCTIONS)
        if start is not None:
            clauses.append("event_index >= ?")
            params.append(start)
        if end is not None:
            clauses.append("event_index <= ?")
            params.append(end)
        if heap_symbol:
            clauses.append("(raw_args LIKE ? OR named_args_json LIKE ?)")
            params.extend([f"%{heap_symbol}%", f"%{heap_symbol}%"])
        sql = (
            "SELECT event_index, function_name, raw_args, named_args_json "
            f"FROM cpp_calls WHERE {' AND '.join(clauses)} "
            "ORDER BY event_index LIMIT ?"
        )
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    by_heap: dict[str, list[dict[str, Any]]] = {}
    timeline: list[dict[str, Any]] = []
    for ev_idx, fn, raw_args, named_json in rows:
        named = json.loads(named_json) if named_json else {}
        entry = {
            "event_index": ev_idx,
            "function_name": fn,
            "raw_args": raw_args,
            "named_args": named,
        }
        timeline.append(entry)
        # Bucketing heuristic: any token in raw_args that looks like a heap
        # symbol (``g_DescHeaps_*`` or contains "Heap"). Without per-arg
        # types we have to scan textually.
        for token in re.findall(r"[A-Za-z_]\w*", raw_args or ""):
            if "Heap" in token or "DescHeap" in token:
                by_heap.setdefault(token, []).append(entry)
    return {
        "ok": True,
        "db_path": str(db_path),
        "heap_filter": heap_symbol,
        "event_count": len(timeline),
        "timeline": timeline,
        "by_heap_symbol": by_heap,
        "evidence_label": "proven",
    }


# ---------------------------------------------------------------------------
# D3D12 root signature blob parsing
# ---------------------------------------------------------------------------
#
# Format reference: Microsoft's D3D12 root signature serialised blob.
# A versioned root signature blob is a flat little-endian binary; the public
# bits the parser needs:
#
#   DWORD Version              (1 or 2)
#   DWORD NumParameters
#   DWORD ParametersOffset
#   DWORD NumStaticSamplers
#   DWORD StaticSamplersOffset
#   DWORD Flags
#
# For each parameter (v1.0: 12 bytes, v1.1: 16 bytes):
#   DWORD ParameterType   (0 = DescriptorTable, 1 = 32BitConstants,
#                          2 = CBV, 3 = SRV, 4 = UAV)
#   DWORD ShaderVisibility
#   DWORD <type-specific offset/value>
#
# For a descriptor-table parameter the type-specific value is the offset
# (from blob start) to:
#   DWORD NumDescriptorRanges
#   DWORD DescriptorRangesOffset
# followed by the ranges, each (v1.0: 20 bytes, v1.1: 24 bytes):
#   DWORD RangeType       (0 SRV, 1 UAV, 2 CBV, 3 SAMPLER)
#   DWORD NumDescriptors
#   DWORD BaseShaderRegister
#   DWORD RegisterSpace
#   DWORD OffsetInDescriptorsFromTableStart
#  (+ DWORD Flags for v1.1)
#
# This implementation parses the public top-level header and
# descriptor-table ranges. Root constants and root CBV/SRV/UAV parameters
# are recorded with their type but their inline data is not decoded
# (just surfaced as raw bytes) — that's enough for "which register space
# is t0 in?" queries.


_ROOT_PARAM_TYPE = {
    0: "DESCRIPTOR_TABLE",
    1: "32BIT_CONSTANTS",
    2: "CBV",
    3: "SRV",
    4: "UAV",
}
_DESC_RANGE_TYPE = {
    0: "SRV",
    1: "UAV",
    2: "CBV",
    3: "SAMPLER",
}
_SHADER_VIS = {
    0: "ALL",
    1: "VERTEX",
    2: "HULL",
    3: "DOMAIN",
    4: "GEOMETRY",
    5: "PIXEL",
    6: "AMPLIFICATION",
    7: "MESH",
}


def parse_root_signature_blob(data: bytes) -> dict[str, Any]:
    """Decode a serialised D3D12 root signature blob.

    Returns a structured dict with header fields, root parameters, and the
    descriptor ranges contained in each table parameter. Unknown bytes are
    surfaced as ``raw_hex`` so callers can drill further without losing
    information.
    """
    import struct

    if len(data) < 24:
        return {
            "ok": False,
            "error": f"blob too small ({len(data)} bytes); need >= 24 for header",
        }
    (
        version,
        num_params,
        params_offset,
        num_static_samplers,
        static_samplers_offset,
        flags,
    ) = struct.unpack_from("<IIIIII", data, 0)

    if version not in (1, 2):
        return {
            "ok": False,
            "error": f"unsupported root signature version {version}",
            "header": {
                "version": version,
                "head_hex": data[:24].hex(),
            },
        }

    param_stride = 12 if version == 1 else 16
    range_stride = 20 if version == 1 else 24

    parameters: list[dict[str, Any]] = []
    for i in range(num_params):
        off = params_offset + i * param_stride
        if off + param_stride > len(data):
            parameters.append(
                {
                    "index": i,
                    "error": f"parameter {i} extends past blob end",
                }
            )
            continue
        ptype, vis, data_field = struct.unpack_from("<III", data, off)
        param: dict[str, Any] = {
            "index": i,
            "type_id": ptype,
            "type": _ROOT_PARAM_TYPE.get(ptype, f"unknown({ptype})"),
            "shader_visibility_id": vis,
            "shader_visibility": _SHADER_VIS.get(vis, f"unknown({vis})"),
            "raw_hex": data[off : off + param_stride].hex(),
        }
        if ptype == 0:
            tbl_off = data_field
            if tbl_off + 8 <= len(data):
                num_ranges, ranges_off = struct.unpack_from("<II", data, tbl_off)
                ranges: list[dict[str, Any]] = []
                for ri in range(num_ranges):
                    roff = ranges_off + ri * range_stride
                    if roff + range_stride > len(data):
                        ranges.append({"index": ri, "error": "range past blob end"})
                        continue
                    fields = struct.unpack_from(
                        "<IIIII", data, roff
                    )
                    range_entry = {
                        "index": ri,
                        "range_type_id": fields[0],
                        "range_type": _DESC_RANGE_TYPE.get(
                            fields[0], f"unknown({fields[0]})"
                        ),
                        "num_descriptors": fields[1],
                        "base_shader_register": fields[2],
                        "register_space": fields[3],
                        "offset_in_descriptors_from_table_start": fields[4],
                    }
                    if version == 2:
                        flags = struct.unpack_from(
                            "<I", data, roff + 20
                        )[0]
                        range_entry["flags"] = flags
                    ranges.append(range_entry)
                param["num_ranges"] = num_ranges
                param["ranges_offset"] = ranges_off
                param["ranges"] = ranges
            else:
                param["error"] = "descriptor table descriptor extends past blob end"
        elif ptype == 1:
            # 32BIT_CONSTANTS: data_field points to ShaderRegister/RegisterSpace/Num32BitValues
            if data_field + 12 <= len(data):
                sreg, space, n32 = struct.unpack_from("<III", data, data_field)
                param["shader_register"] = sreg
                param["register_space"] = space
                param["num_32bit_values"] = n32
        elif ptype in (2, 3, 4):
            # Root CBV / SRV / UAV: data_field points to ShaderRegister/RegisterSpace[+Flags v1.1]
            descr_size = 8 if version == 1 else 12
            if data_field + descr_size <= len(data):
                sreg, space = struct.unpack_from("<II", data, data_field)
                param["shader_register"] = sreg
                param["register_space"] = space
                if version == 2:
                    param["flags"] = struct.unpack_from(
                        "<I", data, data_field + 8
                    )[0]
        parameters.append(param)

    return {
        "ok": True,
        "header": {
            "version": version,
            "num_parameters": num_params,
            "parameters_offset": params_offset,
            "num_static_samplers": num_static_samplers,
            "static_samplers_offset": static_samplers_offset,
            "flags": flags,
        },
        "parameters": parameters,
        "blob_size": len(data),
        "evidence_label": "proven",
    }


def find_register_for_root_parameter(
    root_sig: dict[str, Any],
    *,
    register_class: str,
    register: int,
    space: int = 0,
) -> dict[str, Any] | None:
    """Look up which root parameter and range covers ``register`` in
    ``register_class`` ("SRV"/"UAV"/"CBV"/"SAMPLER") at ``space``.

    Returns the parameter index, range, and offset, or None if no
    descriptor table range covers it. This is the workhorse for
    "shader register t0 → root parameter X" queries.
    """
    if not root_sig.get("ok"):
        return None
    for param in root_sig.get("parameters", []):
        if param.get("type") != "DESCRIPTOR_TABLE":
            continue
        for r in param.get("ranges", []):
            if r.get("range_type") != register_class:
                continue
            if r.get("register_space") != space:
                continue
            base = r.get("base_shader_register", 0)
            n = r.get("num_descriptors", 0)
            if base <= register < base + n:
                return {
                    "root_parameter_index": param["index"],
                    "shader_visibility": param.get("shader_visibility"),
                    "range_type": r["range_type"],
                    "base_shader_register": base,
                    "num_descriptors": n,
                    "register_space": space,
                    "offset_in_table": r.get("offset_in_descriptors_from_table_start"),
                    "evidence_label": "proven",
                }
    return None


def find_root_signature_blobs(
    db_path: Path, *, limit: int = 50
) -> list[dict[str, Any]]:
    """Return the shader_blobs whose declared usage suggests they are
    serialized root signature blobs.

    Heuristic: a blob whose data is passed to ``CreateRootSignature`` is a
    root signature blob. We look up the cpp_calls table for
    ``CreateRootSignature`` events and join the referenced symbol back to
    shader_blobs. Falls back to a name-based filter on shader_blobs alone
    if cpp_calls has no such events.
    """
    conn = _connect(db_path)
    referenced_symbols: list[str] = []
    try:
        try:
            rows = conn.execute(
                "SELECT event_index, raw_args FROM cpp_calls WHERE function_name = 'CreateRootSignature' LIMIT ?",
                (limit * 4,),
            ).fetchall()
        except sqlite3.OperationalError:
            rows = []
        for _ev_idx, raw_args in rows:
            for tok in re.findall(r"[A-Za-z_]\w*", raw_args or ""):
                if "RootSig" in tok or "RS_" in tok:
                    referenced_symbols.append(tok)
        # Dedup preserving order.
        seen: set[str] = set()
        referenced_symbols = [
            s for s in referenced_symbols
            if not (s in seen or seen.add(s))
        ]

        blobs: list[dict[str, Any]] = []
        # If pso_resolver has populated shader_blobs, enrich with file/line.
        sb_rows: list[tuple] = []
        try:
            if referenced_symbols:
                placeholders = ",".join("?" * len(referenced_symbols))
                sb_rows = conn.execute(
                    f"SELECT symbol, file_path, line_number, declared_byte_count, head_hex "
                    f"FROM shader_blobs WHERE symbol IN ({placeholders})",
                    referenced_symbols,
                ).fetchall()
            else:
                sb_rows = conn.execute(
                    "SELECT symbol, file_path, line_number, declared_byte_count, head_hex "
                    "FROM shader_blobs WHERE symbol LIKE '%RootSig%' OR symbol LIKE '%RS_%' LIMIT ?",
                    (limit,),
                ).fetchall()
        except sqlite3.OperationalError:
            sb_rows = []

        sb_by_symbol = {row[0]: row for row in sb_rows}
        # Emit shader_blobs entries first when present, plus any
        # CreateRootSignature-referenced symbol that wasn't in shader_blobs.
        for sym in referenced_symbols or list(sb_by_symbol):
            row = sb_by_symbol.get(sym)
            if row is not None:
                _, fp, ln, n, head = row
                blobs.append(
                    {
                        "symbol": sym,
                        "file_path": fp,
                        "line_number": ln,
                        "declared_byte_count": n,
                        "head_hex": head,
                    }
                )
            else:
                blobs.append(
                    {
                        "symbol": sym,
                        "file_path": None,
                        "line_number": None,
                        "declared_byte_count": None,
                        "head_hex": None,
                    }
                )
        return blobs[:limit]
    finally:
        conn.close()


def root_signature_blob_bytes(
    project_dir: Path, blob_symbol: str
) -> bytes | None:
    """Return the raw bytes of a static byte-array named ``blob_symbol``
    declared anywhere under ``project_dir``.

    Uses the same regex as ``parse_shader_arrays`` to extract the array
    body. Returns None when not found.
    """
    rx = re.compile(
        r"static\s+(?:const\s+)?(?:unsigned\s+)?(?:char|uint8_t|BYTE)\s+"
        + re.escape(blob_symbol)
        + r"\s*\[[^\]]*\]\s*=\s*\{(?P<body>[^}]+)\}\s*;",
        re.DOTALL,
    )
    for path in project_dir.rglob("*"):
        if path.suffix.lower() not in (".cpp", ".cxx", ".cc", ".c", ".h", ".hpp"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = rx.search(text)
        if not m:
            continue
        body = m.group("body")
        out = bytearray()
        for tok in re.finditer(r"0x([0-9a-fA-F]+)", body):
            try:
                out.append(int(tok.group(1), 16) & 0xFF)
            except ValueError:
                continue
        return bytes(out)
    return None


_RE_CREATE_ROOT_SIGNATURE = re.compile(
    r"CreateRootSignature\s*\(\s*"
    r"\d+\s*,\s*"           # NodeMask
    r"(?P<blob>[A-Za-z_]\w*)"  # pBlobWithRootSignature symbol
)


def find_create_root_signature_calls(project_dir: Path) -> list[dict[str, Any]]:
    """Scan project source for ``CreateRootSignature(0, <symbol>, ...)``
    and return the per-call (symbol, file:line) entries.

    Does not require a populated SQLite index — works on the raw C++
    project that Nsight emits.
    """
    out: list[dict[str, Any]] = []
    for path in project_dir.rglob("*"):
        if path.suffix.lower() not in (".cpp", ".cxx", ".cc", ".c", ".h", ".hpp"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _RE_CREATE_ROOT_SIGNATURE.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            out.append(
                {
                    "blob_symbol": m.group("blob"),
                    "file_path": str(path),
                    "line_number": line_no,
                }
            )
    return out


def root_signature_summary(
    db_path: Path | None, project_dir: Path, *, limit: int = 50
) -> dict[str, Any]:
    """End-to-end: find every root signature blob referenced by the project,
    parse each, and surface a structured summary keyed by blob symbol.

    Two discovery paths, used in order:

    1. Scan project source for ``CreateRootSignature(0, <sym>, ...)`` —
       works without any indexed database.
    2. If a cpp_calls index db is provided and has ``CreateRootSignature``
       events (rare; cpp_capture_parser usually skips device-level calls),
       enrich with shader_blobs metadata when populated.
    """
    by_symbol: dict[str, dict[str, Any]] = {}
    for call in find_create_root_signature_calls(project_dir):
        sym = call["blob_symbol"]
        by_symbol.setdefault(
            sym,
            {
                "symbol": sym,
                "file_path": call.get("file_path"),
                "line_number": call.get("line_number"),
                "declared_byte_count": None,
                "head_hex": None,
            },
        )

    if db_path is not None and Path(db_path).is_file():
        try:
            for blob in find_root_signature_blobs(Path(db_path), limit=limit):
                sym = blob["symbol"]
                if sym in by_symbol:
                    by_symbol[sym].update(
                        {
                            k: v
                            for k, v in blob.items()
                            if v is not None and k != "symbol"
                        }
                    )
                else:
                    by_symbol[sym] = blob
        except sqlite3.DatabaseError:
            pass

    out: list[dict[str, Any]] = []
    for entry in list(by_symbol.values())[:limit]:
        sym = entry["symbol"]
        data = root_signature_blob_bytes(project_dir, sym)
        if data is None:
            entry["parsed"] = {"ok": False, "error": "blob bytes not found in project"}
        else:
            entry["parsed"] = parse_root_signature_blob(data)
        out.append(entry)
    return {
        "ok": True,
        "blob_count": len(out),
        "root_signatures": out,
        "evidence_label": "proven" if out else "missing",
    }
