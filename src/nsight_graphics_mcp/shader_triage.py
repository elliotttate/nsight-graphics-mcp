"""Shader visual-bug triage helpers.

This module composes the existing capture, C++-capture, descriptor, and PSO
indexes into higher-level reports that are useful to an LLM debugging a visual
bug. The implementation is intentionally evidence-first: tools report what was
observed from the available indexes, and explicitly call out gaps that still
require the Nsight frame-debugger RPC or an app-side hook.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import cpp_capture_parser, pso_resolver, shader_debug

DEFAULT_LEFT_PATTERNS = (
    r"\bleft\b",
    r"\bLEFT\b",
    r"StereoPass[_: ]*Left",
    r"eSSE_LEFT_EYE",
    r"ViewIndex[^0-9]*0\b",
    r"EyeIndex[^0-9]*0\b",
)

DEFAULT_RIGHT_PATTERNS = (
    r"\bright\b",
    r"\bRIGHT\b",
    r"StereoPass[_: ]*Right",
    r"eSSE_RIGHT_EYE",
    r"ViewIndex[^0-9]*1\b",
    r"EyeIndex[^0-9]*1\b",
)

DRAW_OR_DISPATCH_KINDS = {"draw", "dispatch", "ray_tracing"}
PIXEL_WRITE_KINDS = {"draw", "dispatch", "copy", "ray_tracing"}

STATE_FUNCTIONS = {
    "RSSetViewports",
    "RSSetScissorRects",
    "vkCmdSetViewport",
    "vkCmdSetScissor",
    "SetPipelineState",
    "vkCmdBindPipeline",
    "OMSetRenderTargets",
    "vkCmdBeginRendering",
    "vkCmdBeginRenderPass",
}

WRITE_NAME_HINTS = (
    "Update",
    "Copy",
    "Clear",
    "Resolve",
    "Fill",
    "Discard",
    "WriteBufferImmediate",
    "Map",
    "Unmap",
)

BIND_NAME_HINTS = (
    "Bind",
    "Set",
    "IASet",
    "OMSet",
    "RSSet",
    "VSSet",
    "PSSet",
    "CSSet",
    "HSSet",
    "DSSet",
    "GSSet",
)


@dataclass
class EyeState:
    eye: str
    confidence: str
    reason: str
    source_event: int | None = None


def shader_triage_plan(
    *,
    issue: str | None = None,
    handoff_path: str | None = None,
    suspect_pso: str | None = None,
    suspect_shader_crc32: str | None = None,
) -> dict[str, Any]:
    """Return the build/run plan for end-to-end shader bug triage."""
    handoff = _read_handoff_summary(handoff_path)
    suspect = {
        "pso": suspect_pso,
        "shader_toggler_crc32": _normalise_crc32_loose(suspect_shader_crc32),
    }
    return {
        "ok": True,
        "issue": issue,
        "handoff": handoff,
        "suspect": suspect,
        "plan": [
            {
                "phase": "Capture and index",
                "tools": [
                    "ngfx_capture_launched or ngfx_graphics_capture_launched",
                    "ngfx_index_events",
                    "ngfx_cpp_capture_open_in_ui",
                    "ngfx_cpp_capture_index_calls",
                    "ngfx_pso_index",
                ],
                "evidence_goal": "Get event order, argument values, descriptor state, and PSO->shader identity.",
            },
            {
                "phase": "Eye-aware event classification",
                "tools": ["ngfx_eye_event_index", "ngfx_compare_eye_passes", "ngfx_find_missing_eye_dispatches"],
                "evidence_goal": "Find left/right asymmetries before touching shaders.",
            },
            {
                "phase": "First-bad-event localization",
                "tools": [
                    "ngfx_event_state",
                    "ngfx_trace_resource_lineage",
                    "ngfx_pixel_history",
                    "ngfx_resource_revision_at_event",
                ],
                "evidence_goal": "Tie the wrong pixels to one draw/dispatch and its bound inputs.",
            },
            {
                "phase": "PSO identity and swap path",
                "tools": ["ngfx_pso_bind_trace", "ngfx_pso_swap_harness_plan"],
                "evidence_goal": "Bypass missed PSO creation paths by acting at bind/draw time.",
            },
            {
                "phase": "Shader probes",
                "tools": ["ngfx_shader_probe_plan", "ngfx_event_state"],
                "evidence_goal": "Generate targeted shader variants for suspected terms instead of random edits.",
            },
            {
                "phase": "Visual oracle",
                "tools": ["ngfx_resource_revision_at_event(include_image_subresource_data=True)", "ngfx_diff_hdr_roi"],
                "evidence_goal": "Use HDR/float ROI comparisons, not clamped 8-bit PPM, to prevent false wins.",
            },
        ],
        "private_rpc_gap": shader_debug.reverse_engineering_status()["implementation_sequence"][:4],
    }


def eye_event_index(
    db_path: Path,
    *,
    start: int | None = None,
    end: int | None = None,
    left_patterns: Iterable[str] | None = None,
    right_patterns: Iterable[str] | None = None,
    render_width: float | None = None,
    right_half_min_x: float | None = None,
    include_state_events: bool = False,
    limit: int = 2000,
) -> dict[str, Any]:
    """Classify indexed C++-capture events as left/right/both/unknown.

    Classification uses explicit string patterns first, then viewport/scissor
    numeric hints, then inherited state from the latest classified viewport or
    state event. It is intentionally conservative and marks inherited results as
    lower confidence.
    """
    rows = _read_cpp_rows(db_path, start=start, end=end, limit=limit)
    left_re = _compile_any(tuple(left_patterns or DEFAULT_LEFT_PATTERNS))
    right_re = _compile_any(tuple(right_patterns or DEFAULT_RIGHT_PATTERNS))
    threshold = right_half_min_x
    if threshold is None and render_width:
        threshold = float(render_width) / 2.0

    current = EyeState("unknown", "none", "no classified state seen")
    indexed: list[dict[str, Any]] = []
    state_events: list[dict[str, Any]] = []

    for row in rows:
        direct = _classify_call_eye(row, left_re, right_re, threshold)
        if direct.eye != "unknown":
            current = EyeState(
                direct.eye,
                direct.confidence,
                direct.reason,
                source_event=row["event_index"],
            )

        if row["function_name"] in STATE_FUNCTIONS:
            state_events.append(
                {
                    "event_index": row["event_index"],
                    "function_name": row["function_name"],
                    "eye": direct.eye,
                    "confidence": direct.confidence,
                    "reason": direct.reason,
                    "raw_args": row["raw_args"],
                }
            )

        should_emit = row["kind"] in PIXEL_WRITE_KINDS or (
            include_state_events and row["function_name"] in STATE_FUNCTIONS
        )
        if not should_emit:
            continue

        if direct.eye == "unknown" and current.eye != "unknown":
            eye = current.eye
            confidence = "inherited"
            reason = f"inherited from event {current.source_event}: {current.reason}"
            source_event = current.source_event
        else:
            eye = direct.eye
            confidence = direct.confidence
            reason = direct.reason
            source_event = row["event_index"] if direct.eye != "unknown" else None

        indexed.append(
            {
                "event_index": row["event_index"],
                "function_name": row["function_name"],
                "kind": row["kind"],
                "api": row["api"],
                "eye": eye,
                "confidence": confidence,
                "reason": reason,
                "source_event": source_event,
                "raw_args": row["raw_args"],
                "named_args": row["named_args"],
            }
        )

    return {
        "ok": True,
        "db_path": str(db_path),
        "range": {"start": start, "end": end, "limit": limit},
        "classification_inputs": {
            "left_patterns": list(left_patterns or DEFAULT_LEFT_PATTERNS),
            "right_patterns": list(right_patterns or DEFAULT_RIGHT_PATTERNS),
            "render_width": render_width,
            "right_half_min_x": threshold,
        },
        "summary": _eye_summary(indexed),
        "events": indexed,
        "state_events": state_events[:200],
        "notes": _eye_index_notes(indexed, threshold),
    }


def compare_eye_passes(
    db_path: Path,
    *,
    start: int | None = None,
    end: int | None = None,
    left_patterns: Iterable[str] | None = None,
    right_patterns: Iterable[str] | None = None,
    render_width: float | None = None,
    right_half_min_x: float | None = None,
    limit: int = 4000,
) -> dict[str, Any]:
    """Compare classified left/right draw/dispatch/copy counts."""
    idx = eye_event_index(
        db_path,
        start=start,
        end=end,
        left_patterns=left_patterns,
        right_patterns=right_patterns,
        render_width=render_width,
        right_half_min_x=right_half_min_x,
        include_state_events=False,
        limit=limit,
    )
    events = idx["events"]
    left = Counter((e["kind"], e["function_name"]) for e in events if e["eye"] == "left")
    right = Counter((e["kind"], e["function_name"]) for e in events if e["eye"] == "right")
    all_keys = sorted(set(left) | set(right))
    deltas = []
    for key in all_keys:
        l_count = left.get(key, 0)
        r_count = right.get(key, 0)
        if l_count != r_count:
            deltas.append(
                {
                    "kind": key[0],
                    "function_name": key[1],
                    "left_count": l_count,
                    "right_count": r_count,
                    "delta_left_minus_right": l_count - r_count,
                }
            )
    deltas.sort(key=lambda d: (abs(d["delta_left_minus_right"]), d["kind"], d["function_name"]), reverse=True)
    return {
        "ok": True,
        "db_path": str(db_path),
        "summary": idx["summary"],
        "asymmetries": deltas[:200],
        "left_only": [d for d in deltas if d["left_count"] and not d["right_count"]][:100],
        "right_only": [d for d in deltas if d["right_count"] and not d["left_count"]][:100],
        "notes": idx["notes"],
    }


def find_missing_eye_dispatches(
    db_path: Path,
    *,
    start: int | None = None,
    end: int | None = None,
    left_patterns: Iterable[str] | None = None,
    right_patterns: Iterable[str] | None = None,
    render_width: float | None = None,
    right_half_min_x: float | None = None,
    limit: int = 4000,
) -> dict[str, Any]:
    """Highlight dispatch/ray-tracing calls present for one eye but not the other."""
    cmp = compare_eye_passes(
        db_path,
        start=start,
        end=end,
        left_patterns=left_patterns,
        right_patterns=right_patterns,
        render_width=render_width,
        right_half_min_x=right_half_min_x,
        limit=limit,
    )
    dispatch_deltas = [
        d for d in cmp["asymmetries"]
        if d["kind"] in {"dispatch", "ray_tracing"}
    ]
    left_missing_right = [
        d for d in dispatch_deltas if d["left_count"] > d["right_count"]
    ]
    right_missing_left = [
        d for d in dispatch_deltas if d["right_count"] > d["left_count"]
    ]
    return {
        "ok": True,
        "db_path": str(db_path),
        "dispatch_asymmetries": dispatch_deltas[:200],
        "left_has_more": left_missing_right[:100],
        "right_has_more": right_missing_left[:100],
        "interpretation": (
            "If a resource consumed by a later right-eye draw depends on a dispatch listed in "
            "left_has_more, inspect that resource's last writer before patching the pixel shader."
        ),
        "notes": cmp["notes"],
    }


def event_state(
    db_path: Path,
    event_index: int,
    *,
    lookback: int = 500,
    context: int = 8,
) -> dict[str, Any]:
    """Return one event plus surrounding calls, descriptor state, and PSO info."""
    call = cpp_capture_parser.get_call(db_path, event_index)
    if call is None:
        return {"ok": False, "error": f"event {event_index} not found in {db_path}"}
    bindings = cpp_capture_parser.descriptor_bindings_for_event(db_path, event_index, lookback=lookback)
    before = cpp_capture_parser.query_calls(
        db_path,
        start=max(0, event_index - context),
        end=event_index - 1,
        limit=context,
    )
    after = cpp_capture_parser.query_calls(
        db_path,
        start=event_index + 1,
        end=event_index + context,
        limit=context,
    )
    pso_symbol = _bound_pipeline_symbol(bindings)
    pso_info = _safe_get_pso(db_path, pso_symbol) if pso_symbol else None
    recent_writes = _recent_writer_calls(db_path, event_index, lookback=min(lookback, 200))
    return {
        "ok": True,
        "db_path": str(db_path),
        "event_index": event_index,
        "call": call,
        "bindings": bindings,
        "bound_pipeline": pso_symbol,
        "pso": pso_info,
        "recent_writes": recent_writes,
        "context": {"before": before, "after": after},
        "gaps": [
            "Descriptor-table handle to concrete SRV/UAV resource mapping still requires Generate C++ Capture symbols or frame-debugger RPC.",
            "Per-pixel first-writer attribution still requires pixel-history/resource-revision RPC.",
        ],
    }


def trace_resource_lineage(
    db_path: Path,
    resource: str,
    *,
    event_index: int | None = None,
    window: int | None = None,
    max_mentions: int = 300,
) -> dict[str, Any]:
    """Find calls that mention a resource/symbol and bucket them by role."""
    start = None if event_index is None or window is None else max(0, event_index - window)
    end = None if event_index is None or window is None else event_index + window
    rows = cpp_capture_parser.query_calls(
        db_path,
        contains=resource,
        start=start,
        end=end,
        limit=max_mentions,
    )
    mentions = []
    role_hist: Counter[str] = Counter()
    for row in rows:
        role = _classify_resource_role(row["function_name"], row["kind"])
        role_hist[role] += 1
        mentions.append({**row, "role": role})

    last_before = None
    next_after = None
    if event_index is not None:
        before = [m for m in mentions if m["event_index"] < event_index]
        after = [m for m in mentions if m["event_index"] > event_index]
        writer_before = [m for m in before if m["role"] in {"write", "dispatch", "copy", "clear", "resolve"}]
        last_before = writer_before[-1] if writer_before else (before[-1] if before else None)
        next_after = after[0] if after else None

    return {
        "ok": True,
        "db_path": str(db_path),
        "resource": resource,
        "event_index": event_index,
        "window": window,
        "mention_count": len(mentions),
        "mentions_by_role": dict(role_hist),
        "last_relevant_before_event": last_before,
        "next_relevant_after_event": next_after,
        "mentions": mentions,
        "interpretation": (
            "A missing or left-only producer normally shows up as a write/dispatch/copy mention "
            "before the left-eye consumer with no equivalent right-eye mention."
        ),
    }


def pso_bind_trace(
    db_path: Path,
    *,
    pso_symbol: str | None = None,
    shader_hash: str | None = None,
    shader_toggler_crc32: str | None = None,
    pso_contains: str | None = None,
    lookahead: int = 40,
    limit: int = 200,
) -> dict[str, Any]:
    """Trace SetPipelineState/vkCmdBindPipeline events and following draws."""
    targets = _resolve_pso_targets(
        db_path,
        pso_symbol=pso_symbol,
        shader_hash=shader_hash,
        shader_toggler_crc32=shader_toggler_crc32,
        pso_contains=pso_contains,
    )
    binds: list[dict[str, Any]] = []
    search_terms = sorted(set(t["pso_symbol"] for t in targets if t.get("pso_symbol")))
    if not search_terms and pso_contains:
        search_terms = [pso_contains]

    if search_terms:
        seen: set[int] = set()
        for term in search_terms:
            rows = _pipeline_bind_rows(db_path, contains=term, limit=limit)
            for row in rows:
                if row["event_index"] in seen:
                    continue
                seen.add(row["event_index"])
                binds.append(_bind_with_following_work(db_path, row, lookahead=lookahead))
    else:
        rows = _pipeline_bind_rows(db_path, contains=None, limit=limit)
        binds = [_bind_with_following_work(db_path, row, lookahead=lookahead) for row in rows]

    binds.sort(key=lambda b: b["bind"]["event_index"])
    return {
        "ok": True,
        "db_path": str(db_path),
        "targets": targets,
        "bind_count": len(binds),
        "binds": binds[:limit],
        "notes": [
            "This works even when PSO creation hooks missed the original creation path, as long as the replay/C++ capture contains the bind.",
            "Use pso_contains for runtime labels such as pso3069 when the generated C++ symbol is not known.",
        ],
    }


def shader_probe_plan(
    *,
    shader_name: str | None = None,
    pseudocode_path: str | None = None,
    suspect_terms: Iterable[str] | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Generate a structured probe plan for a suspect shader."""
    terms = list(suspect_terms or ())
    pseudo_summary = _pseudocode_term_summary(pseudocode_path, terms)
    inferred_terms = _infer_probe_terms(pseudo_summary, terms)
    probes = _probe_catalog(shader_name=shader_name, terms=inferred_terms)
    result = {
        "ok": True,
        "shader_name": shader_name,
        "pseudocode": pseudo_summary,
        "suspect_terms": inferred_terms,
        "probes": probes,
        "execution_harness": {
            "preferred": "right-eye-only SetPipelineState PSO swap",
            "fallback": "generated C++ capture shader byte-array edit + rebuild + replay",
            "required_oracle": "HDR/float ROI diff of the right-eye sky/water region",
        },
    }
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        result["output_path"] = str(out)
    return result


def pso_swap_harness_plan(
    *,
    suspect_pso_label: str | None = None,
    suspect_shader_crc32: str | None = None,
    patched_pso_label: str = "g_sn2PatchedPso",
    right_eye_predicate: str | None = None,
    output_dir: str | None = None,
) -> dict[str, Any]:
    """Generate a D3D12 bind-time PSO swap harness plan/snippet.

    This targets the failure mode where PSO creation hooks miss the original
    graphics PSO, but SetPipelineState and Draw calls still expose the bound
    object at runtime.
    """
    crc = _normalise_crc32_loose(suspect_shader_crc32)
    predicate = right_eye_predicate or "IsRightEyeFromViewportOrStereoConstants(commandList)"
    label = suspect_pso_label or "suspect PSO"
    header = _pso_swap_header()
    source = _pso_swap_source(
        suspect_label=label,
        suspect_crc32=crc,
        patched_pso_label=patched_pso_label,
        right_eye_predicate=predicate,
    )
    result: dict[str, Any] = {
        "ok": True,
        "strategy": "deferred draw-time PSO swap",
        "why": (
            "Swap at draw time instead of creation time. This still works when "
            "CreateGraphicsPipelineState/CreatePipelineState hooks miss a cached "
            "or pipeline-library PSO path."
        ),
        "hook_points": [
            "ID3D12GraphicsCommandList::SetPipelineState",
            "ID3D12GraphicsCommandList::DrawInstanced",
            "ID3D12GraphicsCommandList::DrawIndexedInstanced",
            "ID3D12GraphicsCommandList::Dispatch",
            "ID3D12GraphicsCommandList::ExecuteIndirect",
            "ID3D12GraphicsCommandList::RSSetViewports",
            "ID3D12GraphicsCommandList::SetGraphicsRootConstantBufferView",
            "ID3D12GraphicsCommandList::SetGraphicsRoot32BitConstants",
            "ID3D12Device::CreateGraphicsPipelineState",
            "ID3D12Device2::CreatePipelineState",
            "ID3D12Device1::CreatePipelineLibrary",
            "ID3D12PipelineLibrary::LoadGraphicsPipeline",
        ],
        "runtime_state": [
            "Map ID3D12PipelineState* -> PsoIdentity when creation is visible.",
            "Record the latest PSO bound per command list in SetPipelineState.",
            "Record eye state from viewport and stereo constants before draw.",
            "At draw/dispatch, if current PSO is suspect and the eye predicate is right-eye, bind the patched PSO, issue work, then restore the original PSO.",
        ],
        "suspect": {
            "pso_label": suspect_pso_label,
            "shader_toggler_crc32": crc,
            "patched_pso_label": patched_pso_label,
            "right_eye_predicate": predicate,
        },
        "files": {},
        "snippets": {
            "header": header,
            "source": source,
        },
        "validation_sequence": [
            "Log every SetPipelineState pointer and following draw/dispatch event for the suspect label/hash.",
            "Run once with swap disabled and confirm right-eye bad ROI reproduces.",
            "Run with swap enabled for right-eye only and confirm left-eye output is unchanged.",
            "Run shader probes through the same swap path before committing a real shader edit.",
        ],
    }
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        header_path = out / "ngfx_pso_swap_harness.h"
        source_path = out / "ngfx_pso_swap_harness.cpp"
        header_path.write_text(header, encoding="utf-8")
        source_path.write_text(source, encoding="utf-8")
        result["files"] = {"header": str(header_path), "source": str(source_path)}
    return result


def shader_bug_triage(
    *,
    capture: str | None = None,
    cpp_db: str | None = None,
    handoff_path: str | None = None,
    suspect_pso: str | None = None,
    suspect_shader_hash: str | None = None,
    suspect_shader_crc32: str | None = None,
    pso_contains: str | None = None,
    roi: dict[str, Any] | None = None,
    render_width: float | None = None,
    right_half_min_x: float | None = None,
    limit: int = 4000,
) -> dict[str, Any]:
    """Produce a single LLM-ready shader-bug triage report."""
    handoff = _read_handoff_summary(handoff_path)
    report: dict[str, Any] = {
        "ok": True,
        "capture": capture,
        "cpp_db": cpp_db,
        "handoff": handoff,
        "roi": roi,
        "suspects": {
            "pso": suspect_pso,
            "pso_contains": pso_contains,
            "shader_hash": suspect_shader_hash,
            "shader_toggler_crc32": _normalise_crc32_loose(suspect_shader_crc32),
        },
        "evidence_level": "plan-only",
        "available_evidence": {},
        "blocking_gaps": [],
        "recommended_next_actions": [],
    }

    if cpp_db:
        db = Path(cpp_db)
        report["evidence_level"] = "cpp-capture-indexed"
        try:
            report["available_evidence"]["eye_compare"] = compare_eye_passes(
                db,
                render_width=render_width,
                right_half_min_x=right_half_min_x,
                limit=limit,
            )
            report["available_evidence"]["missing_dispatches"] = find_missing_eye_dispatches(
                db,
                render_width=render_width,
                right_half_min_x=right_half_min_x,
                limit=limit,
            )
            report["available_evidence"]["pso_bind_trace"] = pso_bind_trace(
                db,
                pso_symbol=suspect_pso,
                shader_hash=suspect_shader_hash,
                shader_toggler_crc32=suspect_shader_crc32,
                pso_contains=pso_contains,
                limit=200,
            )
            first_draw = _first_suspect_draw(report["available_evidence"]["pso_bind_trace"])
            if first_draw is not None:
                report["available_evidence"]["first_suspect_event_state"] = event_state(
                    db,
                    first_draw,
                    lookback=500,
                    context=8,
                )
        except (FileNotFoundError, sqlite3.Error, ValueError) as exc:
            report["available_evidence"]["error"] = str(exc)
            report["blocking_gaps"].append(f"C++ capture index could not be analysed: {exc}")
    else:
        report["blocking_gaps"].append(
            "No C++ capture index supplied. Run ngfx_cpp_capture_open_in_ui, generate C++ capture, then ngfx_cpp_capture_index_calls."
        )

    if capture and not cpp_db:
        report["recommended_next_actions"].append(
            "Open the saved capture in Nsight UI and generate a C++ capture so descriptor/event arguments are available."
        )
    if roi is None:
        report["blocking_gaps"].append(
            "No explicit ROI supplied. Add the right-eye bad sky/water rectangle so pixel-history and visual-oracle tools can target it."
        )
    report["blocking_gaps"].append(
        "Live pixel history/resource revision calls still require completing the frame-debugger RPC client from the IDA facts."
    )
    report["recommended_next_actions"].extend(_ranked_next_actions(report))
    report["probe_plan"] = shader_probe_plan(
        shader_name=suspect_pso or pso_contains,
        suspect_terms=("t5", "t8", "t9", "screenTile", "SV_Position", "View[148]", "volumeUV"),
    )
    report["pso_swap_harness"] = pso_swap_harness_plan(
        suspect_pso_label=suspect_pso or pso_contains,
        suspect_shader_crc32=suspect_shader_crc32,
    )
    return report


def _read_cpp_rows(
    db_path: Path,
    *,
    start: int | None,
    end: int | None,
    limit: int,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if start is not None:
        clauses.append("event_index >= ?")
        params.append(start)
    if end is not None:
        clauses.append("event_index <= ?")
        params.append(end)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = (
        "SELECT event_index, function_name, api, kind, receiver, raw_args, "
        "args_json, named_args_json, file_path, line_number "
        f"FROM cpp_calls {where} ORDER BY event_index LIMIT ?"
    )
    params.append(int(limit))
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()
    return [_cpp_row_to_dict(r) for r in rows]


def _cpp_row_to_dict(row: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "event_index": int(row[0]),
        "function_name": row[1],
        "api": row[2],
        "kind": row[3],
        "receiver": row[4],
        "raw_args": row[5],
        "args": json.loads(row[6]) if row[6] else [],
        "named_args": json.loads(row[7]) if row[7] else {},
        "file_path": row[8],
        "line_number": int(row[9]),
    }


def _compile_any(patterns: tuple[str, ...]) -> re.Pattern[str] | None:
    if not patterns:
        return None
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.IGNORECASE)


def _classify_call_eye(
    row: dict[str, Any],
    left_re: re.Pattern[str] | None,
    right_re: re.Pattern[str] | None,
    right_half_min_x: float | None,
) -> EyeState:
    haystack = " ".join(
        [
            row.get("function_name") or "",
            row.get("raw_args") or "",
            json.dumps(row.get("named_args") or {}, sort_keys=True),
        ]
    )
    left = bool(left_re.search(haystack)) if left_re else False
    right = bool(right_re.search(haystack)) if right_re else False
    if left and right:
        return EyeState("both", "medium", "matched both left and right text patterns")
    if left:
        return EyeState("left", "high", "matched left text pattern")
    if right:
        return EyeState("right", "high", "matched right text pattern")

    if right_half_min_x is not None and row["function_name"] in {
        "RSSetViewports",
        "RSSetScissorRects",
        "vkCmdSetViewport",
        "vkCmdSetScissor",
    }:
        numeric = _classify_numeric_view_state(row, right_half_min_x)
        if numeric.eye != "unknown":
            return numeric
    return EyeState("unknown", "none", "no eye marker found")


def _classify_numeric_view_state(row: dict[str, Any], right_half_min_x: float) -> EyeState:
    nums = _numeric_literals(row.get("raw_args") or "")
    if not nums:
        return EyeState("unknown", "none", "no numeric viewport/scissor literals")

    # Generated D3D12 calls usually look like RSSetViewports(count, {x, y, w, h...});
    # Vulkan calls usually look like vkCmdSetViewport(cmd, first, count, {x, y, w, h...}).
    # Use the first rectangle/viewport x coordinate, not width/height, or left-eye
    # viewports with width >= half-width would be misclassified as right-eye.
    fn = row["function_name"]
    if fn.startswith("vkCmd"):
        x = nums[2] if len(nums) >= 3 else nums[0]
    else:
        x = nums[1] if len(nums) >= 2 else nums[0]
    if x >= right_half_min_x:
        return EyeState("right", "medium", f"viewport/scissor x >= {right_half_min_x:g}")
    if 0.0 <= x < right_half_min_x:
        return EyeState("left", "low", f"viewport/scissor numeric values below {right_half_min_x:g}")
    return EyeState("unknown", "none", "viewport/scissor numbers were not half-width-like")


def _numeric_literals(text: str) -> list[float]:
    out: list[float] = []
    for match in re.finditer(r"(?<![A-Za-z_])[-+]?(?:\d+\.\d+|\d+)(?:[fFuUlL]*)", text):
        token = re.sub(r"[fFuUlL]+$", "", match.group(0))
        try:
            out.append(float(token))
        except ValueError:
            pass
    return out


def _eye_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    by_eye = Counter(e["eye"] for e in events)
    by_eye_kind: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    by_eye_name: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for e in events:
        by_eye_kind[e["eye"]][e["kind"]] += 1
        by_eye_name[e["eye"]][e["function_name"]] += 1
    return {
        "total_indexed_events": len(events),
        "by_eye": dict(by_eye),
        "by_eye_kind": {eye: dict(hist) for eye, hist in by_eye_kind.items()},
        "top_names_by_eye": {
            eye: dict(Counter(hist).most_common(20))
            for eye, hist in by_eye_name.items()
        },
    }


def _eye_index_notes(events: list[dict[str, Any]], threshold: float | None) -> list[str]:
    notes: list[str] = []
    unknown = sum(1 for e in events if e["eye"] == "unknown")
    if unknown:
        notes.append(f"{unknown} indexed draw/dispatch/copy events remain unknown; add eye-specific regexes or viewport width.")
    if threshold is None:
        notes.append("No render_width/right_half_min_x was provided, so viewport half classification was limited.")
    inherited = sum(1 for e in events if e["confidence"] == "inherited")
    if inherited:
        notes.append(f"{inherited} events inherited eye state from a previous classified state call.")
    return notes


def _bound_pipeline_symbol(bindings: dict[str, Any]) -> str | None:
    d3 = bindings.get("d3d12", {})
    vk = bindings.get("vulkan", {})
    value = None
    if d3.get("pipeline_state"):
        value = d3["pipeline_state"].get("value")
    elif vk.get("pipeline"):
        value = vk["pipeline"].get("pipeline")
    return _clean_symbol(value)


def _clean_symbol(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    text = text.strip("&*() ")
    if not text:
        return None
    return text


def _safe_get_pso(db_path: Path, pso_symbol: str | None) -> dict[str, Any] | None:
    if not pso_symbol:
        return None
    try:
        return pso_resolver.get_pso(db_path, pso_symbol)
    except (FileNotFoundError, sqlite3.Error):
        return None


def _recent_writer_calls(db_path: Path, event_index: int, *, lookback: int) -> list[dict[str, Any]]:
    rows = cpp_capture_parser.query_calls(
        db_path,
        start=max(0, event_index - lookback),
        end=event_index - 1,
        limit=lookback,
    )
    out: list[dict[str, Any]] = []
    for row in rows:
        role = _classify_resource_role(row["function_name"], row["kind"])
        if role in {"write", "dispatch", "copy", "clear", "resolve"}:
            out.append({**row, "role": role})
    return out[-50:]


def _classify_resource_role(function_name: str, kind: str) -> str:
    if "Barrier" in function_name:
        return "barrier"
    if "Clear" in function_name:
        return "clear"
    if "Resolve" in function_name:
        return "resolve"
    if "Copy" in function_name:
        return "copy"
    if kind == "dispatch":
        return "dispatch"
    if kind == "draw":
        return "draw"
    if any(h in function_name for h in WRITE_NAME_HINTS):
        return "write"
    if any(function_name.startswith(h) for h in BIND_NAME_HINTS) or function_name.startswith("vkCmdBind"):
        return "bind"
    if function_name.startswith("Create") or function_name.startswith("vkCreate"):
        return "create"
    if function_name.startswith("Destroy") or function_name.startswith("vkDestroy") or function_name == "Release":
        return "destroy"
    return "other"


def _resolve_pso_targets(
    db_path: Path,
    *,
    pso_symbol: str | None,
    shader_hash: str | None,
    shader_toggler_crc32: str | None,
    pso_contains: str | None,
) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    if pso_symbol:
        info = _safe_get_pso(db_path, pso_symbol)
        targets.append({"pso_symbol": pso_symbol, "source": "explicit", "pso": info})
    if shader_hash:
        try:
            for hit in pso_resolver.find_psos_using_shader(db_path, hash_hex=shader_hash):
                targets.append({**hit, "source": "shader_hash"})
        except (FileNotFoundError, sqlite3.Error, ValueError):
            pass
    if shader_toggler_crc32:
        try:
            for hit in pso_resolver.find_psos_using_shader(
                db_path,
                shader_toggler_crc32=_normalise_crc32_loose(shader_toggler_crc32),
            ):
                targets.append({**hit, "source": "shader_toggler_crc32"})
        except (FileNotFoundError, sqlite3.Error, ValueError):
            pass
    if pso_contains and not targets:
        targets.append({"pso_symbol": pso_contains, "source": "contains"})
    dedup: dict[str, dict[str, Any]] = {}
    for t in targets:
        key = str(t.get("pso_symbol"))
        dedup.setdefault(key, t)
    return list(dedup.values())


def _pipeline_bind_rows(db_path: Path, *, contains: str | None, limit: int) -> list[dict[str, Any]]:
    rows = []
    for name in ("SetPipelineState", "vkCmdBindPipeline"):
        rows.extend(
            cpp_capture_parser.query_calls(
                db_path,
                name=name,
                contains=contains,
                limit=limit,
            )
        )
    rows.sort(key=lambda r: r["event_index"])
    return rows[:limit]


def _bind_with_following_work(db_path: Path, bind: dict[str, Any], *, lookahead: int) -> dict[str, Any]:
    start = bind["event_index"] + 1
    end = bind["event_index"] + lookahead
    rows = cpp_capture_parser.query_calls(db_path, start=start, end=end, limit=lookahead)
    work = []
    for row in rows:
        if row["function_name"] in {"SetPipelineState", "vkCmdBindPipeline"}:
            break
        if row["kind"] in DRAW_OR_DISPATCH_KINDS:
            work.append(row)
    return {"bind": bind, "following_work": work, "following_work_count": len(work)}


def _pseudocode_term_summary(pseudocode_path: str | None, terms: list[str]) -> dict[str, Any]:
    if not pseudocode_path:
        return {"path": None, "available": False}
    path = Path(pseudocode_path)
    if not path.is_file():
        return {"path": str(path), "available": False, "error": "file not found"}
    text = path.read_text(encoding="utf-8", errors="replace")
    default_terms = ["t5", "t8", "t9", "screenTile", "SV_Position", "View[148]", "volumeUV", "fogClip"]
    wanted = list(dict.fromkeys([*terms, *default_terms]))
    hits = {}
    for term in wanted:
        pattern = re.escape(term)
        matches = []
        for m in re.finditer(pattern, text, re.IGNORECASE):
            line_no = text.count("\n", 0, m.start()) + 1
            line = _line_at(text, m.start())
            matches.append({"line": line_no, "text": line[:240]})
            if len(matches) >= 5:
                break
        if matches:
            hits[term] = matches
    return {
        "path": str(path),
        "available": True,
        "size_bytes": path.stat().st_size,
        "term_hits": hits,
    }


def _line_at(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end < 0:
        end = len(text)
    return text[start:end].strip()


def _infer_probe_terms(pseudo_summary: dict[str, Any], explicit_terms: list[str]) -> list[str]:
    terms = list(dict.fromkeys(explicit_terms))
    if pseudo_summary.get("available"):
        for term in pseudo_summary.get("term_hits", {}):
            if term not in terms:
                terms.append(term)
    for default in ("t5", "t8", "t9", "screenTile", "SV_Position", "View[148]", "volumeUV"):
        if default not in terms:
            terms.append(default)
    return terms


def _probe_catalog(*, shader_name: str | None, terms: list[str]) -> list[dict[str, Any]]:
    has = {t.lower(): t for t in terms}
    probes: list[dict[str, Any]] = []
    if "t8" in has or "t9" in has:
        probes.append(
            {
                "name": "visualize_volumetric_textures",
                "target": shader_name,
                "edits": [
                    "Output t8 sample luminance as grayscale.",
                    "Output t9 sample luminance as grayscale.",
                    "Output abs(t8 - t9) or contribution delta if both are sampled.",
                ],
                "question_answered": "Are right-eye volumetric inputs black, uninitialized, or left-eye mismatched?",
            }
        )
    if "t5" in has:
        probes.append(
            {
                "name": "visualize_volume_tint",
                "target": shader_name,
                "edits": ["Output t5 sample RGB before final composition."],
                "question_answered": "Is the volume tint/lighting LUT already wrong before basepass composition?",
            }
        )
    if "screentile" in has or "sv_position" in has or "view[148]" in has:
        probes.append(
            {
                "name": "visualize_stereo_tile_math",
                "target": shader_name,
                "edits": [
                    "Output screenTile.x/y modulo as color.",
                    "Output SV_Position.x - View[148].x normalized to eye width.",
                    "Force the right-eye viewport offset path to the left-eye offset as an A/B test.",
                ],
                "question_answered": "Is the right eye sampling the wrong half/tile of a stereo-dependent texture?",
            }
        )
    if "volumeuv" in has:
        probes.append(
            {
                "name": "visualize_volume_uv",
                "target": shader_name,
                "edits": ["Output volumeUV.xy as RG and invalid/out-of-range volumeUV as magenta."],
                "question_answered": "Does the right eye compute invalid UVs into the volume textures?",
            }
        )
    probes.append(
        {
            "name": "disable_suspect_volumetric_terms",
            "target": shader_name,
            "edits": [
                "Zero the sampled volumetric contribution.",
                "Clamp negative/NaN/inf contribution before final color.",
                "Replace t8/t9 contribution with neutral 1.0 or 0.0 in separate variants.",
            ],
            "question_answered": "Does the blown-out sky disappear when suspect terms are neutralized?",
        }
    )
    return probes


def _pso_swap_header() -> str:
    return """#pragma once

#include <d3d12.h>
#include <cstdint>

namespace NgfxMcpShaderFix {

struct PsoIdentity {
    uint32_t shader_crc32 = 0;
    const char* label = nullptr;
    bool suspect = false;
};

void RegisterPso(ID3D12PipelineState* pso, PsoIdentity identity);
void SetPatchedPso(ID3D12PipelineState* pso);
void OnSetPipelineState(ID3D12GraphicsCommandList* commandList, ID3D12PipelineState* pso);
void OnRSSetViewports(ID3D12GraphicsCommandList* commandList, UINT count, const D3D12_VIEWPORT* viewports);
void OnGraphicsRootConstantBufferView(ID3D12GraphicsCommandList* commandList, UINT rootParameterIndex, D3D12_GPU_VIRTUAL_ADDRESS address);
bool IsRightEyeFromViewportOrStereoConstants(ID3D12GraphicsCommandList* commandList);
bool ShouldSwapForDraw(ID3D12GraphicsCommandList* commandList);
void BeforeDraw(ID3D12GraphicsCommandList* commandList);
void AfterDraw(ID3D12GraphicsCommandList* commandList);

}  // namespace NgfxMcpShaderFix
"""


def _pso_swap_source(
    *,
    suspect_label: str,
    suspect_crc32: str | None,
    patched_pso_label: str,
    right_eye_predicate: str,
) -> str:
    source = """#include "ngfx_pso_swap_harness.h"

#include <mutex>
#include <unordered_map>

namespace NgfxMcpShaderFix {
namespace {

struct CommandListState {
    ID3D12PipelineState* currentPso = nullptr;
    ID3D12PipelineState* swappedFrom = nullptr;
    bool lastViewportLooksRightEye = false;
};

std::mutex g_mutex;
std::unordered_map<ID3D12PipelineState*, PsoIdentity> g_psoIdentity;
std::unordered_map<ID3D12GraphicsCommandList*, CommandListState> g_cmdState;
ID3D12PipelineState* g_patchedPso = nullptr;

bool IsSuspect(ID3D12PipelineState* pso) {
    if (!pso) {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_psoIdentity.find(pso);
    if (it == g_psoIdentity.end()) {
        return false;
    }
    return it->second.suspect;
}

}  // namespace

void RegisterPso(ID3D12PipelineState* pso, PsoIdentity identity) {
    if (!pso) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    g_psoIdentity[pso] = identity;
}

void SetPatchedPso(ID3D12PipelineState* pso) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_patchedPso = pso;
}

void OnSetPipelineState(ID3D12GraphicsCommandList* commandList, ID3D12PipelineState* pso) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_cmdState[commandList].currentPso = pso;
}

void OnRSSetViewports(ID3D12GraphicsCommandList* commandList, UINT count, const D3D12_VIEWPORT* viewports) {
    if (!commandList || !viewports || count == 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    // Replace this with app-specific eye detection when stereo constants are known.
    g_cmdState[commandList].lastViewportLooksRightEye = viewports[0].TopLeftX > 0.0f;
}

void OnGraphicsRootConstantBufferView(ID3D12GraphicsCommandList* commandList, UINT rootParameterIndex, D3D12_GPU_VIRTUAL_ADDRESS address) {
    (void)commandList;
    (void)rootParameterIndex;
    (void)address;
    // Optional: copy or tag the known stereo/view constant buffer here, then make
    // IsRightEyeFromViewportOrStereoConstants use the real eye field.
}

bool IsRightEyeFromViewportOrStereoConstants(ID3D12GraphicsCommandList* commandList) {
    std::lock_guard<std::mutex> lock(g_mutex);
    auto it = g_cmdState.find(commandList);
    return it != g_cmdState.end() && it->second.lastViewportLooksRightEye;
}

bool ShouldSwapForDraw(ID3D12GraphicsCommandList* commandList) {
    ID3D12PipelineState* current = nullptr;
    ID3D12PipelineState* patched = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_cmdState.find(commandList);
        if (it == g_cmdState.end()) {
            return false;
        }
        current = it->second.currentPso;
        patched = g_patchedPso;
    }
    return patched && IsSuspect(current) && __RIGHT_EYE_PREDICATE__;
}

void BeforeDraw(ID3D12GraphicsCommandList* commandList) {
    if (!ShouldSwapForDraw(commandList)) {
        return;
    }
    ID3D12PipelineState* patched = nullptr;
    ID3D12PipelineState* original = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto& state = g_cmdState[commandList];
        original = state.currentPso;
        patched = g_patchedPso;
        state.swappedFrom = original;
        state.currentPso = patched;
    }
    commandList->SetPipelineState(patched);
}

void AfterDraw(ID3D12GraphicsCommandList* commandList) {
    ID3D12PipelineState* restore = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto& state = g_cmdState[commandList];
        restore = state.swappedFrom;
        state.swappedFrom = nullptr;
        if (restore) {
            state.currentPso = restore;
        }
    }
    if (restore) {
        commandList->SetPipelineState(restore);
    }
}

// Integration notes:
// 1. In your SetPipelineState hook, call OnSetPipelineState(commandList, pso)
//    after forwarding the real call.
// 2. In DrawInstanced/DrawIndexedInstanced/Dispatch/ExecuteIndirect hooks,
//    call BeforeDraw(commandList), forward the real call, then call
//    AfterDraw(commandList).
// 3. Register the original PSO with suspect=true once a creation hook,
//    shader hunter hash, or manual pointer log identifies it.
// 4. SetPatchedPso(__PATCHED_PSO_LABEL__) after creating the patched PSO.
// 5. Suspect label: __SUSPECT_LABEL__; suspect ShaderToggler CRC32: __SUSPECT_CRC32__.

}  // namespace NgfxMcpShaderFix
"""
    return (
        source.replace("__RIGHT_EYE_PREDICATE__", right_eye_predicate)
        .replace("__PATCHED_PSO_LABEL__", patched_pso_label)
        .replace("__SUSPECT_LABEL__", suspect_label)
        .replace("__SUSPECT_CRC32__", suspect_crc32 or "unknown")
    )


def _read_handoff_summary(handoff_path: str | None) -> dict[str, Any] | None:
    if not handoff_path:
        return None
    path = Path(handoff_path)
    if not path.is_file():
        return {"path": str(path), "available": False, "error": "file not found"}
    text = path.read_text(encoding="utf-8", errors="replace")
    keywords = [
        "UNFIXED",
        "pso3069",
        "0x166DBA88",
        "t5",
        "t8",
        "t9",
        "Nanite",
        "VSM",
        "SetPipelineState",
        "CreateGraphicsPipelineState",
        "CreatePipelineState",
    ]
    hits = {k: len(re.findall(re.escape(k), text, re.IGNORECASE)) for k in keywords}
    return {
        "path": str(path),
        "available": True,
        "size_bytes": path.stat().st_size,
        "keyword_hits": {k: v for k, v in hits.items() if v},
        "first_lines": text.splitlines()[:20],
    }


def _normalise_crc32_loose(value: str | None) -> str | None:
    if value is None:
        return None
    s = str(value).strip().lower()
    if not s:
        return None
    if s.startswith("0x"):
        s = s[2:]
    try:
        if re.fullmatch(r"[0-9a-f]{1,8}", s):
            return f"{int(s, 16):08x}"
        return f"{int(s, 10):08x}"
    except ValueError:
        return value


def _first_suspect_draw(pso_trace: dict[str, Any]) -> int | None:
    for bind in pso_trace.get("binds", []):
        for work in bind.get("following_work", []):
            if work.get("kind") in DRAW_OR_DISPATCH_KINDS:
                return int(work["event_index"])
    return None


def _ranked_next_actions(report: dict[str, Any]) -> list[str]:
    evidence = report.get("available_evidence", {})
    actions: list[str] = []
    missing = evidence.get("missing_dispatches", {})
    if missing.get("left_has_more"):
        actions.append(
            "Inspect left_has_more dispatches first; this matches the known risk that right-eye producer work is missing."
        )
    trace = evidence.get("pso_bind_trace", {})
    if trace.get("bind_count"):
        actions.append(
            "Use ngfx_event_state on the first suspect following_work event, then trace its bound t5/t8/t9 resources."
        )
    else:
        actions.append(
            "Add/runtime-enable app-side SetPipelineState logging for the suspect PSO, because no indexed bind matched the supplied suspect."
        )
    actions.append(
        "Run shader probes only after resource lineage is known; otherwise a missing producer may be mistaken for a pixel-shader bug."
    )
    return actions
