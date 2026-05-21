"""Shader-debugging orchestration helpers.

This module does not perform pixel history or shader patching by itself yet.
It collects the reverse-engineering facts that make those tools possible and
turns them into a concise readiness report for MCP callers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import ida_re


PRIORITY_RE_TARGETS = (
    "ngfx_rpc",
    "ngfx_replay",
    "frame_debugger_native",
    "frame_debugger_d3d12",
    "frame_debugger_vulkan",
)

HIGHLIGHT_PATTERNS = {
    "rpc_session": r"TargetHandshake|AttachMessage|Connection|TryGetMethodHandler|session ID|m_handshakeData",
    "frame_debugger_services": r"IPixelHistoryService|IShaderService|IObjectBrowserService|IFrameDebugger",
    "pixel_history": r"PixelHistory|PbPixelHistory",
    "resource_history": r"LookupResource|ResourceRevision|ApiDataRevision|ResourceEnumeration",
    "d3d12_state": r"RootParameter|RootSignature|DescriptorHeap|Descriptor|PipelineState|RenderTarget|DepthStencil",
    "vulkan_state": r"DescriptorSet|PipelineLayout|ShaderModule|RenderPass|Framebuffer|ImageView|Sampler",
    "shader_state": r"ShaderSass|ShaderDelete|ProgramLink|PipelineSass|ShaderStage",
    "replay_metadata": r"metadata|screenshot|perf-report|gpu-frametime|resource|shader|pipeline",
}


def _facts_path_for_target(target: str) -> Path | None:
    try:
        binary = ida_re.resolve_binary(target)
    except Exception:
        return None
    p = ida_re.cache_dir_for_binary(binary) / "facts.json"
    return p if p.is_file() else None


def reverse_engineering_status() -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    ready_count = 0
    for target in PRIORITY_RE_TARGETS:
        facts_path = _facts_path_for_target(target)
        item: dict[str, Any] = {"target": target, "facts_ready": facts_path is not None}
        if facts_path is not None:
            facts = ida_re.load_facts(facts_path)
            item["facts_path"] = str(facts_path)
            item["summary"] = ida_re.summarize_facts(facts)
            ready_count += 1
        targets.append(item)

    highlights: dict[str, list[dict[str, Any]]] = {}
    for name, pattern in HIGHLIGHT_PATTERNS.items():
        hits: list[dict[str, Any]] = []
        for target in PRIORITY_RE_TARGETS:
            facts_path = _facts_path_for_target(target)
            if facts_path is None:
                continue
            try:
                result = ida_re.search_facts(facts_path, pattern, limit=5)
            except Exception:
                continue
            for hit in result.get("hits", [])[:3]:
                brief = hit.get("item", {})
                hits.append(
                    {
                        "target": target,
                        "section": hit.get("section"),
                        "ea": brief.get("ea"),
                        "name": brief.get("name"),
                        "value": brief.get("value"),
                    }
                )
                if len(hits) >= 8:
                    break
            if len(hits) >= 8:
                break
        highlights[name] = hits

    return {
        "ok": ready_count == len(PRIORITY_RE_TARGETS),
        "ready_count": ready_count,
        "target_count": len(PRIORITY_RE_TARGETS),
        "targets": targets,
        "highlights": highlights,
        "implementation_sequence": [
            {
                "tool": "ngfx_frame_debugger_rpc_bootstrap",
                "purpose": "Use the TargetHandshake/session facts to open the same frame-debugger service layer the UI uses.",
                "depends_on": ["ngfx_rpc", "frame_debugger_native"],
            },
            {
                "tool": "ngfx_frame_debugger_event_state",
                "purpose": "Call request methods for event details, descriptors/root params, pipeline state, render targets, and shader state.",
                "depends_on": ["frame_debugger_native", "frame_debugger_d3d12", "frame_debugger_vulkan"],
            },
            {
                "tool": "ngfx_pixel_history",
                "purpose": "Send PbPixelHistoryRequestMessage and decode PbPixelHistoryReplyMessage for a target pixel.",
                "depends_on": ["frame_debugger_native"],
            },
            {
                "tool": "ngfx_resource_revision_at_event",
                "purpose": "Use LookupResourceRevision/HandleAtEvent patterns to walk resource history across draws/copies/dispatches.",
                "depends_on": ["frame_debugger_native"],
            },
            {
                "tool": "ngfx_shader_variant_test",
                "purpose": "Patch generated C++ capture shader blobs, rebuild, replay, snapshot/diff, and report whether the visual bug moved.",
                "depends_on": ["ngfx_replay", "frame_debugger_native"],
            },
        ],
    }
