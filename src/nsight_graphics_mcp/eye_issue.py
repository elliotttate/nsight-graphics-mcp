"""Nsight-only eye-issue triage from saved capture sidecars.

The lightweight ``ngfx-replay --metadata-functions`` stream has no arguments,
so it cannot directly say "CopyRectPS sampled this SRV". It can still do useful
work: identify repeated left/right-looking event signatures, prove which deeper
path is missing, and produce exact event indices to feed live replay RPC once
the BinaryReplay session is bound.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import Counter, defaultdict
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import capture_decoder, cpp_capture_parser, deep_capture, events, pso_resolver

PIXEL_EVENT_KINDS = {"draw", "dispatch", "copy", "ray_tracing"}
STATE_CONTEXT_KINDS = {"set_state", "pipeline", "descriptor", "resource", "cmd_buffer", "barrier"}


def event_signature_index(
    functions_db: Path,
    *,
    start: int | None = None,
    end: int | None = None,
    target_kinds: list[str] | None = None,
    lookback_state_count: int = 12,
    max_pair_delta: int = 250,
    limit: int = 5000,
) -> dict[str, Any]:
    """Build repeated event signatures from the name-only function stream.

    A signature is the ordered list of recent state/pipeline/descriptor call
    names on the same thread before a draw/dispatch/copy. It is intentionally
    argument-free: useful for finding likely stereo left/right pairs from a
    saved dump even before C++ Capture or live RPC can provide descriptors.
    """
    calls = _read_calls(functions_db, start=start, end=end)
    requested_kinds = set(target_kinds or PIXEL_EVENT_KINDS)
    state_by_thread: dict[int, list[dict[str, Any]]] = defaultdict(list)
    targets: list[dict[str, Any]] = []

    for call in calls:
        thread = int(call["thread_index"])
        if call["kind"] in STATE_CONTEXT_KINDS:
            state_by_thread[thread].append(call)
            if len(state_by_thread[thread]) > max(lookback_state_count * 3, 64):
                state_by_thread[thread] = state_by_thread[thread][-max(lookback_state_count * 3, 64):]
        if call["kind"] not in requested_kinds:
            continue
        context = [
            item
            for item in state_by_thread[thread]
            if item["event_index"] < call["event_index"]
        ][-lookback_state_count:]
        signature_names = [item["function_name"] for item in context]
        signature = _signature_hash(signature_names)
        targets.append(
            {
                **call,
                "signature": signature,
                "signature_names": signature_names,
                "context_events": context,
            }
        )
        if len(targets) >= limit:
            break

    by_signature: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for target in targets:
        by_signature[target["signature"]].append(target)

    pairs: list[dict[str, Any]] = []
    for signature, group in by_signature.items():
        if len(group) < 2:
            continue
        ordered = sorted(group, key=lambda item: item["event_index"])
        for left, right in pairwise(ordered):
            if left["function_name"] != right["function_name"]:
                continue
            delta = int(right["event_index"]) - int(left["event_index"])
            if delta <= 0 or delta > max_pair_delta:
                continue
            pairs.append(
                {
                    "signature": signature,
                    "function_name": left["function_name"],
                    "kind": left["kind"],
                    "left_candidate": _compact_event(left),
                    "right_candidate": _compact_event(right),
                    "delta_events": delta,
                    "confidence": _pair_confidence(left, right, delta),
                    "why": (
                        "same function and same recent state-call signature in close event order; "
                        "metadata has no arguments, so treat as a candidate left/right pair"
                    ),
                }
            )
    pairs.sort(key=lambda item: (_confidence_rank(item["confidence"]), item["delta_events"]))

    signature_rows = [
        {
            "signature": signature,
            "count": len(group),
            "function_histogram": dict(Counter(item["function_name"] for item in group).most_common(10)),
            "kind_histogram": dict(Counter(item["kind"] for item in group).most_common(10)),
            "first_event": group[0]["event_index"],
            "last_event": group[-1]["event_index"],
            "signature_names": group[0]["signature_names"],
        }
        for signature, group in by_signature.items()
    ]
    signature_rows.sort(key=lambda item: item["count"], reverse=True)
    return {
        "ok": True,
        "functions_db": str(functions_db),
        "range": {"start": start, "end": end, "limit": limit},
        "target_count": len(targets),
        "target_kind_histogram": dict(Counter(item["kind"] for item in targets)),
        "signature_count": len(by_signature),
        "top_signatures": signature_rows[:100],
        "pair_count": len(pairs),
        "candidate_pairs": pairs[:500],
        "caveat": (
            "These are name-only signatures. Use live descriptor/root/pixel-history RPC or a C++ "
            "call index to prove source texture, constants, viewport, and render target."
        ),
    }


def dump_only_eye_issue_report(
    capture: Path,
    *,
    roi: dict[str, int] | None = None,
    suspect_shader_name: str = "CopyRectPS",
    suspect_shader_hash: str | None = "98acf00f2001c218",
    render_width: int | None = None,
    include_shader_chunk_scan: bool = False,
    shader_chunk_max_hits: int = 20,
    force_index_hint: bool = False,
) -> dict[str, Any]:
    """Report what can and cannot be solved from a saved Nsight dump alone."""
    cap = capture.resolve()
    sidecar = events._cache_root_for(cap)
    functions_db = sidecar / "functions.db"
    objects_db = sidecar / "objects.db"
    cap_report = deep_capture.deep_capture_capability_report(capture=str(cap), probe_cli_help=False)
    toc = capture_decoder.parse_table_of_contents(cap) if cap.is_file() else {"ok": False, "error": "capture missing"}
    function_summary = _function_db_summary(functions_db) if functions_db.is_file() else None
    object_summary = _object_db_summary(objects_db, suspect_shader_name, suspect_shader_hash) if objects_db.is_file() else None
    signatures = (
        event_signature_index(functions_db, limit=2500)
        if functions_db.is_file()
        else {"ok": False, "error": "functions.db missing; run ngfx_index_events first"}
    )
    shader_chunk_scan = (
        capture_decoder.shader_chunks(
            cap,
            shader_name=suspect_shader_name,
            shader_hash=suspect_shader_hash,
            max_hits=shader_chunk_max_hits,
        )
        if include_shader_chunk_scan and cap.is_file()
        else None
    )
    return {
        "ok": cap.is_file(),
        "capture": {
            "path": str(cap),
            "exists": cap.is_file(),
            "size_bytes": cap.stat().st_size if cap.is_file() else None,
            "sidecar_dir": str(sidecar),
            "functions_db": str(functions_db) if functions_db.is_file() else None,
            "objects_db": str(objects_db) if objects_db.is_file() else None,
        },
        "target": {
            "issue": "right-eye visual mismatch",
            "suspect_shader_name": suspect_shader_name,
            "suspect_shader_hash": suspect_shader_hash,
            "roi": roi,
            "render_width": render_width,
        },
        "toc": _toc_summary(toc),
        "function_stream": function_summary,
        "object_index": object_summary,
        "event_signatures": signatures,
        "shader_chunks": shader_chunk_scan,
        "deep_capability": {
            "replacement_assessment": cap_report.get("replacement_assessment"),
            "capability_matrix": cap_report.get("capability_matrix"),
            "ranked_next_steps": cap_report.get("ranked_next_steps"),
        },
        "dump_only_verdict": _dump_only_verdict(function_summary, object_summary, signatures),
        "next_nsight_only_actions": _next_nsight_actions(
            cap,
            sidecar,
            functions_db.is_file(),
            objects_db.is_file(),
            suspect_shader_name,
            suspect_shader_hash,
            roi,
            force_index_hint=force_index_hint,
        ),
    }


def _read_calls(functions_db: Path, *, start: int | None, end: int | None) -> list[dict[str, Any]]:
    conn = sqlite3.connect(functions_db)
    conn.row_factory = sqlite3.Row
    try:
        clauses: list[str] = []
        params: list[Any] = []
        if start is not None:
            clauses.append("event_index >= ?")
            params.append(start)
        if end is not None:
            clauses.append("event_index <= ?")
            params.append(end)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = conn.execute(
            "SELECT event_index, function_name, sequence_id, thread_index, kind "
            f"FROM calls {where} ORDER BY event_index",
            params,
        ).fetchall()
        calls = [dict(row) for row in rows]
        for call in calls:
            stored_kind = str(call.get("kind", "other"))
            effective_kind = events.classify(str(call["function_name"]))
            call["stored_kind"] = stored_kind
            call["kind"] = effective_kind if effective_kind != "other" else stored_kind
        return calls
    finally:
        conn.close()


def _signature_hash(names: list[str]) -> str:
    text = "\n".join(names)
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _compact_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_index": event["event_index"],
        "function_name": event["function_name"],
        "kind": event["kind"],
        "thread_index": event["thread_index"],
        "context_tail": event.get("signature_names", [])[-6:],
    }


def _pair_confidence(left: dict[str, Any], right: dict[str, Any], delta: int) -> str:
    if left["kind"] == "draw" and delta <= 80:
        return "medium"
    if delta <= 25:
        return "medium"
    return "low"


def _confidence_rank(label: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(label, 9)


def _function_db_summary(functions_db: Path) -> dict[str, Any]:
    conn = sqlite3.connect(functions_db)
    try:
        total = conn.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
        rows = conn.execute("SELECT function_name, kind FROM calls").fetchall()
        by_kind = dict(Counter(events.classify(name) if events.classify(name) != "other" else kind for name, kind in rows))
        stored_by_kind = dict(conn.execute("SELECT kind, COUNT(*) FROM calls GROUP BY kind").fetchall())
        top_names = [
            {"function_name": name, "count": count}
            for name, count in conn.execute(
                "SELECT function_name, COUNT(*) c FROM calls GROUP BY function_name ORDER BY c DESC LIMIT 30"
            ).fetchall()
        ]
        target_preview_names = {
            name
            for name, _kind in rows
            if events.classify(name) in PIXEL_EVENT_KINDS | STATE_CONTEXT_KINDS
        }
        key_events = [
            {
                "event_index": idx,
                "function_name": name,
                "kind": events.classify(name) if events.classify(name) != "other" else kind,
            }
            for idx, name, kind in conn.execute(
                "SELECT event_index, function_name, kind FROM calls ORDER BY event_index"
            ).fetchall()
            if name in target_preview_names
        ]
        return {
            "db_path": str(functions_db),
            "record_count": total,
            "kind_histogram": by_kind,
            "stored_kind_histogram": stored_by_kind,
            "effective_reclassification_applied": by_kind != stored_by_kind,
            "top_names": top_names,
            "key_events_preview": key_events[:80],
            "argument_values_available": False,
        }
    finally:
        conn.close()


def _object_db_summary(objects_db: Path, shader_name: str, shader_hash: str | None) -> dict[str, Any]:
    conn = sqlite3.connect(objects_db)
    conn.row_factory = sqlite3.Row
    needles = [shader_name.lower()]
    if shader_hash:
        needles.append(shader_hash.lower().removeprefix("0x"))
    try:
        total = conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0]
        by_category = dict(conn.execute("SELECT category, COUNT(*) FROM objects GROUP BY category").fetchall())
        matches: list[dict[str, Any]] = []
        for row in conn.execute(
            "SELECT uid, type_name, object_name, api, category, raw_json FROM objects ORDER BY uid"
        ):
            text = json.dumps(dict(row), sort_keys=True).lower()
            if any(needle and needle in text for needle in needles):
                item = dict(row)
                item.pop("raw_json", None)
                matches.append(item)
        return {
            "db_path": str(objects_db),
            "object_count": total,
            "category_histogram": by_category,
            "suspect_matches": matches[:100],
            "suspect_match_count": len(matches),
            "shader_mapping_available": bool(matches),
        }
    finally:
        conn.close()


def _toc_summary(toc: dict[str, Any]) -> dict[str, Any]:
    if not toc.get("ok"):
        return toc
    return {
        "ok": True,
        "metadata": toc.get("metadata"),
        "num_chunks": toc.get("num_chunks"),
        "num_threads": toc.get("num_threads"),
        "function_info_chunk_ids": toc.get("function_info_chunk_ids"),
        "resource_info_chunk_ids": toc.get("resource_info_chunk_ids"),
        "api_info": toc.get("api_info"),
    }


def _dump_only_verdict(
    function_summary: dict[str, Any] | None,
    object_summary: dict[str, Any] | None,
    signatures: dict[str, Any],
) -> dict[str, Any]:
    blockers: list[str] = []
    if not function_summary:
        blockers.append("function stream sidecar missing")
    elif not function_summary.get("argument_values_available"):
        blockers.append("metadata-functions has no argument values")
    if not object_summary:
        blockers.append("object sidecar missing")
    elif not object_summary.get("shader_mapping_available"):
        blockers.append("metadata-objects has no CopyRectPS/hash to PSO mapping")
    if not signatures.get("candidate_pairs"):
        blockers.append("no repeated event-signature candidate pairs found")
    return {
        "can_fully_prove_from_dump_only": False,
        "can_propose_candidate_event_pairs": bool(signatures.get("candidate_pairs")),
        "blockers": blockers,
        "required_to_fully_prove": [
            "CopyRectPS PSO/event mapping from GPU Trace shader pipeline data or live frame-debugger state",
            "PS t0 descriptor resource at left/right CopyRect events",
            "source resource revision/history before right-eye CopyRect",
            "pixel history over the bad right-eye ROI",
        ],
    }


def _next_nsight_actions(
    capture: Path,
    sidecar: Path,
    has_functions: bool,
    has_objects: bool,
    shader_name: str,
    shader_hash: str | None,
    roi: dict[str, int] | None,
    *,
    force_index_hint: bool,
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    if force_index_hint or not has_functions:
        actions.append(
            {
                "rank": 1,
                "tool": "ngfx_index_events",
                "arguments": {"capture": str(capture)},
                "goal": "Build the event-name sidecar used by dump-only pair signatures.",
            }
        )
    if force_index_hint or not has_objects:
        actions.append(
            {
                "rank": 2,
                "tool": "ngfx_index_objects",
                "arguments": {"capture": str(capture)},
                "goal": "Build the object sidecar and search for named shader/pipeline evidence.",
            }
        )
    actions.extend(
        [
            {
                "rank": 3,
                "tool": "ngfx_eye_issue_event_signatures",
                "arguments": {"capture": str(capture), "target_kinds": ["draw"]},
                "goal": "Pick candidate left/right draw event pairs from saved metadata.",
            },
            {
                "rank": 4,
                "tool": "ngfx_capture_shader_chunks",
                "arguments": {
                    "capture": str(capture),
                    "shader_name": shader_name,
                    "shader_hash": shader_hash,
                },
                "goal": "Map the suspect shader name/hash to embedded DXBC/DXIL capture chunk IDs.",
            },
            {
                "rank": 5,
                "tool": "ngfx_capture_chunk_references",
                "arguments": {
                    "capture": str(capture),
                    "target_chunk_id": "<chunk_id from rank 4>",
                    "needles": [needle for needle in (shader_name, shader_hash) if needle],
                    "include_numeric_chunk_id_refs": False,
                    "exclude_chunk_ids": ["<chunk_id from rank 4>"],
                },
                "goal": "Find other saved-capture chunks that reference the suspect shader chunk or identity.",
            },
            {
                "rank": 6,
                "tool": "ngfx_capture_search_payloads",
                "arguments": {
                    "capture": str(capture),
                    "needles": [needle for needle in (shader_name, shader_hash) if needle],
                    "max_chunk_uncompressed": 33_554_432,
                },
                "goal": "Check whether the saved capture payload contains the suspect shader name/hash at all.",
            },
            {
                "rank": 7,
                "tool": "ngfx_gputrace_capture_replay",
                "arguments": {
                    "capture": str(capture),
                    "output_dir": str(sidecar / "gputrace_replay"),
                    "real_time_shader_profiler": True,
                    "auto_export": True,
                },
                "goal": "Collect shader pipeline/source/binding evidence from the saved capture replay.",
            },
            {
                "rank": 8,
                "tool": "ngfx_gputrace_shader_pipeline_search",
                "arguments": {
                    "gputrace": "<trace produced by rank 7>",
                    "shader_name": shader_name,
                    "shader_hash": shader_hash,
                },
                "goal": "Find CopyRectPS or its hash in GPU Trace shader pipeline data.",
            },
            {
                "rank": 9,
                "tool": "ngfx_rpc_open_capture_session",
                "arguments": {"capture": str(capture), "launch_capture": True},
                "goal": "Open live replay RPC so descriptor state, resource revisions, and pixel history can be queried.",
            },
            {
                "rank": 10,
                "tool": "ngfx_sn2_copyrect_live_pair_probe",
                "arguments": {
                    "session_handle": "<from rank 9>",
                    "left_event_index": "<candidate left event>",
                    "right_event_index": "<candidate right event>",
                    "roi": roi,
                },
                "goal": "Resolve actual CopyRectPS t0/s0 resources and branch to source-vs-rect fix.",
            },
        ]
    )
    if roi:
        actions.append(
            {
                "rank": 11,
                "tool": "ngfx_trace_roi_history",
                "arguments": {
                    "session_handle": "<from rank 9>",
                    "image_accessor": "<right-eye render target or CopyRectPS source accessor>",
                    "roi": roi,
                },
                "goal": "Run Nsight pixel history over the bad right-eye ROI once the resource handle is known.",
            }
        )
    return actions


# ---------------------------------------------------------------------------
# CopyRectPS t0 resolution report (Track A)
# ---------------------------------------------------------------------------
#
# Composes pso_resolver + cpp_capture_parser to answer "what did the
# right-eye CopyRectPS draw actually sample at t0?" using a UI-generated
# Generate-C++-Capture project as the data source. No live RPC required.


def _candidate_pso_symbols(pso_db: Path, shader_name: str) -> list[dict[str, Any]]:
    """Return the PSO records whose pixel-shader entry references ``shader_name``.

    The pso_resolver index links each PSO symbol to its compiled shader
    blobs and entry points. We look up shader blobs by name and then
    backtrack to the PSOs that bind them.
    """
    blobs = pso_resolver.list_shader_blobs(pso_db, limit=10_000)
    candidates: list[str] = []
    for blob in blobs:
        for key in ("shader_symbol", "entry_point", "name", "symbol", "label"):
            val = blob.get(key)
            if isinstance(val, str) and shader_name in val:
                candidates.append(blob.get("shader_symbol") or val)
                break
    candidates = sorted({c for c in candidates if c})
    psos: list[dict[str, Any]] = []
    for sym in candidates:
        hits = pso_resolver.find_psos_using_shader(pso_db, shader_symbol=sym)
        if hits:
            psos.extend(hits)
    seen: set[str] = set()
    uniq: list[dict[str, Any]] = []
    for pso in psos:
        sym = pso.get("pso_symbol") or pso.get("symbol")
        if sym and sym not in seen:
            seen.add(sym)
            uniq.append(pso)
    return uniq


def _draws_using_psos(
    cpp_db: Path, pso_symbols: list[str], *, limit: int = 200
) -> list[dict[str, Any]]:
    """Find draws that occur after a SetPipelineState(pso_symbol) and before
    the next SetPipelineState.

    Returns one entry per CopyRectPS-bound draw in event order, each carrying
    the originating SetPipelineState event for traceability.
    """
    if not pso_symbols:
        return []
    pipeline_events: list[dict[str, Any]] = []
    for sym in pso_symbols:
        hits = cpp_capture_parser.query_calls(
            cpp_db, name="SetPipelineState", contains=sym, limit=2000
        )
        for h in hits:
            pipeline_events.append(
                {
                    "event_index": h["event_index"],
                    "pso_symbol": sym,
                    "set_pso_event": h,
                }
            )
    pipeline_events.sort(key=lambda r: r["event_index"])

    draws: list[dict[str, Any]] = []
    for pe in pipeline_events:
        following = cpp_capture_parser.query_calls(
            cpp_db,
            kind="draw",
            start=pe["event_index"] + 1,
            end=pe["event_index"] + 64,
            limit=8,
        )
        for d in following:
            draws.append(
                {
                    "event_index": d["event_index"],
                    "function_name": d["function_name"],
                    "set_pso_event_index": pe["event_index"],
                    "pso_symbol": pe["pso_symbol"],
                    "draw_args": d.get("named_args") or d.get("args"),
                    "file_path": d.get("file_path"),
                    "line_number": d.get("line_number"),
                }
            )
            if len(draws) >= limit:
                return draws
    return draws


def _state_signature(state: dict[str, Any]) -> dict[str, Any]:
    """Reduce a descriptor_bindings_for_event state to a comparable shape."""
    d3 = state.get("d3d12") or {}
    rt = d3.get("render_targets") or {}
    rp_summary: list[dict[str, Any]] = []
    for idx, info in sorted((d3.get("root_params") or {}).items()):
        try:
            idx_int = int(idx)
        except (TypeError, ValueError):
            idx_int = idx
        rp_summary.append(
            {
                "root_param_index": idx_int,
                "call": info.get("call"),
                "gpu_descriptor_handle": info.get("gpu_descriptor_handle"),
                "buffer_location": info.get("buffer_location"),
                "src_data": info.get("src_data"),
                "num_32bit_values": info.get("num_32bit_values"),
            }
        )
    return {
        "pipeline_event": (d3.get("pipeline_state") or {}).get("event_index"),
        "pipeline_value": (d3.get("pipeline_state") or {}).get("value"),
        "root_signature": (d3.get("root_signature") or {}).get("value"),
        "render_targets": {
            "event_index": rt.get("event_index"),
            "num_render_targets": rt.get("num_render_targets"),
            "render_target_descriptors": rt.get("render_target_descriptors")
            or rt.get("render_targets"),
            "depth_stencil": rt.get("depth_stencil_descriptor")
            or rt.get("depth_stencil"),
        },
        "root_params": rp_summary,
    }


def _compare_states(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Field-level diff of two state signatures with verdict suggestions."""
    diffs: list[dict[str, Any]] = []

    def _push(field: str, lv: Any, rv: Any) -> None:
        if lv != rv:
            diffs.append({"field": field, "left": lv, "right": rv})

    _push("root_signature", left.get("root_signature"), right.get("root_signature"))
    _push(
        "render_targets",
        left.get("render_targets"),
        right.get("render_targets"),
    )

    by_idx_left = {
        rp["root_param_index"]: rp for rp in left.get("root_params") or []
    }
    by_idx_right = {
        rp["root_param_index"]: rp for rp in right.get("root_params") or []
    }
    all_indices = sorted(set(by_idx_left) | set(by_idx_right), key=str)
    for idx in all_indices:
        l = by_idx_left.get(idx)
        r = by_idx_right.get(idx)
        if l != r:
            diffs.append(
                {
                    "field": f"root_param[{idx}]",
                    "left": l,
                    "right": r,
                }
            )

    # Verdict heuristic.
    same_pipeline = (
        left.get("pipeline_value") == right.get("pipeline_value")
        and left.get("pipeline_value") is not None
    )
    rt_differs = left.get("render_targets") != right.get("render_targets")
    any_rp_differs = any(d["field"].startswith("root_param[") for d in diffs)

    if not same_pipeline:
        verdict_label = "different_pipeline"
        verdict = (
            "Left and right CopyRectPS draws use different PSOs. Compare the "
            "PSO root signatures and shader blobs before treating this as a "
            "descriptor-routing bug."
        )
    elif any_rp_differs and rt_differs:
        verdict_label = "different_source_and_target"
        verdict = (
            "Both root parameters and render targets differ between eyes. "
            "Likely descriptor routing or target-binding bug; confirm against "
            "the root-signature ranges and the actual sampled descriptor for t0."
        )
    elif any_rp_differs:
        verdict_label = "different_source_or_descriptor_routing"
        verdict = (
            "Root-parameter state differs between eyes. The bound resource "
            "for at least one root slot is different — strong candidate for "
            "the t0 source divergence. Mapping shader register t0 → root "
            "parameter requires root-signature parsing or shader reflection."
        )
    elif rt_differs:
        verdict_label = "different_target"
        verdict = (
            "Same source bindings but render targets differ. Look at the "
            "destination subresource selection (likely the right-eye array "
            "slice or texture) and the viewport/scissor/copy-rect constants."
        )
    else:
        verdict_label = "identical_state_at_draw"
        verdict = (
            "Left and right CopyRectPS draws have identical visible state. "
            "If pixels still diverge, the bug is upstream of the copy "
            "(producer of the t0 source) or in 32-bit root constants whose "
            "values are not currently surfaced. Re-run with shader "
            "reflection + root-signature ranges to drill further."
        )

    return {
        "verdict_label": verdict_label,
        "verdict": verdict,
        "field_diffs": diffs,
        "diff_count": len(diffs),
    }


_RE_CREATE_RTV = re.compile(
    r'D3D12CreateRenderTargetView\([^,]+,\s*(?P<res_sym>[A-Za-z0-9_]+),'
    r'\s*D3D12InitRTV[A-Za-z0-9_]+\([^)]*?\),\s*'
    r'(?P<heap>[A-Za-z0-9_]+),\s*(?P<slot>\d+)u\)',
)
_RE_CREATE_SRV = re.compile(
    r'D3D12CreateShaderResourceView\([^,]+,\s*(?P<res_sym>[A-Za-z0-9_]+),'
    r'\s*D3D12InitSRV[A-Za-z0-9_]+\([^)]*?\),\s*'
    r'(?P<heap>[A-Za-z0-9_]+),\s*(?P<slot>\d+)u\)',
)
_RE_PLACED_RES = re.compile(
    r'D3D12CreatePlacedResource\(.+?'
    r'(?P<sym>NVD3D12MultiBufferedArray_of_ID3D12Resource_uid_\d+|pID3D12Resource__uid_\d+)'
    r'\s*,\s*L"(?P<name>[^"]+)"',
    re.DOTALL,
)
_RE_COMMITTED_RES = re.compile(
    r'D3D12CreateCommittedResource\(.+?'
    r'(?P<sym>NVD3D12MultiBufferedArray_of_ID3D12Resource_uid_\d+|pID3D12Resource__uid_\d+)'
    r'\s*,\s*L"(?P<name>[^"]+)"',
    re.DOTALL,
)
_RE_OFFSET_CPU = re.compile(
    r'OffsetCPUDescriptor\((?P<slot>\d+)u,\s*(?P<heap>[A-Za-z0-9_]+)'
)
_RE_OFFSET_GPU = re.compile(
    r'OffsetGPUDescriptor\((?P<slot>\d+)u,\s*(?P<heap>[A-Za-z0-9_]+)'
)
_RE_SET_PSO = re.compile(
    r'My_ID3D12GraphicsCommandList_SetPipelineState\([^,]+,\s*'
    r'(?P<pso>pID3D12PipelineState__uid_\d+)\)'
)
_RE_SET_ROOTSIG = re.compile(
    r'My_ID3D12GraphicsCommandList_SetGraphicsRootSignature\([^,]+,\s*'
    r'(?P<rs>pID3D12RootSignature__uid_\d+)\)'
)
_RE_OM_SET_RT = re.compile(
    r'My_ID3D12GraphicsCommandList_OMSetRenderTargets\((.*?)\)\s*;',
    re.DOTALL,
)
_RE_VIEWPORT = re.compile(
    r'D3D12_VIEWPORT[^=]*=\s*\{\s*\{\s*([^}]+?)\}\s*\}'
)
_RE_SCISSOR = re.compile(
    r'D3D12_RECT[^=]*=\s*\{\s*\{\s*([^}]+?)\}\s*\}'
)
_RE_CBV = re.compile(
    r'My_ID3D12GraphicsCommandList_SetGraphicsRootConstantBufferView\([^,]+,\s*'
    r'(?P<rp>\d+)u,\s*\(My_ID3D12Resource_GetGPUVirtualAddress\('
    r'(?P<res>[A-Za-z0-9_]+)\)\s*\+\s*(?P<off>\d+)\)\)'
)


_RE_CREATE_UAV = re.compile(
    r'D3D12CreateUnorderedAccessView\([^,]+,\s*(?P<res_sym>[A-Za-z0-9_]+)'
    r'(?:\s*,\s*[A-Za-z0-9_]+)?'  # optional counter resource (UAV with counter)
    r'\s*,\s*D3D12InitUAV[A-Za-z0-9_]+\([^)]*?\),\s*'
    r'(?P<heap>[A-Za-z0-9_]+),\s*(?P<slot>\d+)u\)',
)


def _build_setup_views_index(project_dir: Path) -> dict[str, Any]:
    """Scan FrameSetup*.cpp once and build a lookup of:
    - rtv[(heap_sym, slot)] -> resource_sym
    - srv[(heap_sym, slot)] -> resource_sym
    - uav[(heap_sym, slot)] -> resource_sym
    - resource_names[resource_sym] -> debug name
    """
    rtv: dict[tuple[str, int], str] = {}
    srv: dict[tuple[str, int], str] = {}
    uav: dict[tuple[str, int], str] = {}
    names: dict[str, str] = {}
    for fname in ("FrameSetup00.cpp", "FrameSetup01.cpp", "FrameSetup02.cpp",
                  "FrameSetup03.cpp", "FrameSetup04.cpp"):
        f = project_dir / fname
        if not f.is_file():
            continue
        text = f.read_text(encoding="utf-8", errors="replace")
        for m in _RE_CREATE_RTV.finditer(text):
            rtv[(m.group("heap"), int(m.group("slot")))] = m.group("res_sym")
        for m in _RE_CREATE_SRV.finditer(text):
            srv[(m.group("heap"), int(m.group("slot")))] = m.group("res_sym")
        for m in _RE_CREATE_UAV.finditer(text):
            uav[(m.group("heap"), int(m.group("slot")))] = m.group("res_sym")
    # Resource names live in Resources*.cpp
    for f in project_dir.glob("Resources*.cpp"):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _RE_PLACED_RES.finditer(text):
            names[m.group("sym")] = m.group("name")
        for m in _RE_COMMITTED_RES.finditer(text):
            names[m.group("sym")] = m.group("name")
    return {"rtv": rtv, "srv": srv, "uav": uav, "names": names}


def _contiguous_srv_range(
    setup_views: dict[str, Any],
    heap_sym_cpu: str,
    base_slot: int,
    *,
    max_run: int = 16,
) -> list[dict[str, Any]]:
    """Return the contiguous SRV slots starting at ``base_slot`` in ``heap_sym_cpu``,
    stopping at the first slot that wasn't populated by CreateShaderResourceView.

    Many shaders bind a descriptor table that spans multiple SRVs. Without
    parsing the root signature we don't know the exact range, but UE5 emits
    its CreateShaderResourceView calls in contiguous blocks, so walking
    until the first gap is a reliable heuristic.
    """
    out: list[dict[str, Any]] = []
    for offset in range(max_run):
        slot = base_slot + offset
        sym = setup_views["srv"].get((heap_sym_cpu, slot))
        if sym is None:
            break
        out.append(
            {
                "slot": slot,
                "offset_from_base": offset,
                "resource_sym": sym,
                "resource_name": setup_views["names"].get(sym),
            }
        )
    return out


def _producer_event_for_resource(
    project_dir: Path,
    db_path: Path,
    resource_sym: str,
    setup_views: dict[str, Any],
) -> dict[str, Any] | None:
    """Find the OMSetRenderTargets event that uses any RTV pointing at
    ``resource_sym``, then capture the producer's PSO + state.

    Picks the FIRST such event in event-order (most upstream producer for
    this frame). Returns None if no producer is found.
    """
    rtvs_for_res = [
        (heap, slot)
        for (heap, slot), sym in setup_views["rtv"].items()
        if sym == resource_sym
    ]
    if not rtvs_for_res:
        return None
    conn = sqlite3.connect(db_path)
    try:
        candidates: list[dict[str, Any]] = []
        all_om = conn.execute(
            "SELECT event_index, file_path, line_number, raw_args FROM cpp_calls "
            "WHERE function_name='OMSetRenderTargets' ORDER BY event_index"
        ).fetchall()
        # For each OMSetRenderTargets, look up the declaration of the
        # temp_NNN CPU descriptor handle it references in the surrounding
        # source. If that declaration uses one of the (heap, slot) pairs
        # for our target resource, this is a producer event.
        for ev, src_path, ln, raw in all_om:
            text_lines = Path(src_path).read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            # Look back up to 10 lines for the matching OffsetCPUDescriptor
            lo = max(0, ln - 10)
            window = "\n".join(text_lines[lo:ln])
            for heap, slot in rtvs_for_res:
                # The window contains the declaration like:
                #   D3D12_CPU_DESCRIPTOR_HANDLE ... = {OffsetCPUDescriptor(16u, <heap>, ...)};
                # or with multiple slots if it's an MRT.
                pattern = (
                    r"OffsetCPUDescriptor\(\s*"
                    + str(slot)
                    + r"u\s*,\s*"
                    + re.escape(heap)
                )
                if re.search(pattern, window):
                    candidates.append(
                        {
                            "event_index": ev,
                            "file_path": src_path,
                            "line_number": ln,
                            "rtv_heap": heap,
                            "rtv_slot": slot,
                            "raw_args_head": raw[:200],
                        }
                    )
                    break  # one match per OMSet is enough
        if not candidates:
            return None
        candidates.sort(key=lambda c: c["event_index"])
        return candidates[0]
    finally:
        conn.close()


def _scan_producer_state(
    project_dir: Path,
    producer_event: dict[str, Any],
    setup_views: dict[str, Any],
) -> dict[str, Any]:
    """Open the producer's source file and pull the PSO / root sig /
    viewport / scissor / SRV inputs / CBV references that surround the
    OMSetRenderTargets call.

    Returns a structured snapshot.
    """
    src = Path(producer_event["file_path"])
    ln = producer_event["line_number"]
    text = src.read_text(encoding="utf-8", errors="replace").splitlines()
    # Look back up to 60 lines for the SetPSO/SetRootSig/Viewport/Scissor,
    # and forward up to 5 lines for any trailing CBVs.
    lo = max(0, ln - 60)
    hi = min(len(text), ln + 30)
    window = "\n".join(text[lo:hi])

    pso = _RE_SET_PSO.search(window)
    rs = _RE_SET_ROOTSIG.search(window)
    vp = _RE_VIEWPORT.search(window)
    sc = _RE_SCISSOR.search(window)

    # Collect SRV bindings: SetGraphicsRootDescriptorTable preceded by an
    # OffsetGPUDescriptor block. We look for blocks of:
    #   D3D12_GPU_DESCRIPTOR_HANDLE myBaseDescriptor = OffsetGPUDescriptor(<slot>u, <heap>, ...);
    #   My_ID3D12GraphicsCommandList_SetGraphicsRootDescriptorTable(<list>, <rp>u, myBaseDescriptor);
    rp_to_descr: dict[int, dict[str, Any]] = {}
    for m in re.finditer(
        r"OffsetGPUDescriptor\((?P<slot>\d+)u,\s*(?P<heap>[A-Za-z0-9_]+)[^)]*\);\s*"
        r"(?:[^;]*;\s*)*?"  # any number of intervening statements (lenient)
        r"My_ID3D12GraphicsCommandList_SetGraphicsRootDescriptorTable\([^,]+,\s*"
        r"(?P<rp>\d+)u,\s*myBaseDescriptor\)",
        window,
    ):
        rp = int(m.group("rp"))
        slot = int(m.group("slot"))
        heap = m.group("heap")
        # Heap name like "..._dh_4386_36_gpubegin" — strip suffix to match SRV table key.
        cpu_heap = None
        srv_range: list[dict[str, Any]] = []
        cpu_heap_match = re.match(r"(.+_dh_\d+_\d+)_gpubegin", heap)
        if cpu_heap_match:
            base = cpu_heap_match.group(1)
            cpu_heap = f"{base}_cpubegin"
            srv_range = _contiguous_srv_range(setup_views, cpu_heap, slot)
        base_sym = srv_range[0]["resource_sym"] if srv_range else None
        if rp not in rp_to_descr:
            rp_to_descr[rp] = {
                "gpu_heap": heap,
                "cpu_heap": cpu_heap,
                "base_slot": slot,
                "srv_resource_sym": base_sym,
                "srv_resource_name": setup_views["names"].get(base_sym or "")
                if base_sym
                else None,
                "srv_range": srv_range,
                "srv_range_size": len(srv_range),
            }

    cbvs = {}
    for m in _RE_CBV.finditer(window):
        cbvs[int(m.group("rp"))] = {
            "resource": m.group("res"),
            "offset": int(m.group("off")),
        }

    return {
        "event_index": producer_event["event_index"],
        "source_loc": f"{src.name}:{ln}",
        "rtv_heap": producer_event["rtv_heap"],
        "rtv_slot": producer_event["rtv_slot"],
        "pso": pso.group("pso") if pso else None,
        "root_signature": rs.group("rs") if rs else None,
        "viewport": vp.group(1).strip() if vp else None,
        "scissor": sc.group(1).strip() if sc else None,
        "srv_tables": rp_to_descr,
        "cbvs": cbvs,
    }


def resource_write_history(
    *,
    cpp_project_dir: Path,
    cpp_db_path: Path | None = None,
    resource_sym: str,
    include_clear: bool = True,
) -> dict[str, Any]:
    """Find every write to ``resource_sym`` in event order — render-target
    binds, compute UAV writes (via Dispatch), copy-as-destination, and
    Clear*View calls.

    Returns a structured timeline so callers can see, e.g., that
    "Texture2D 960" was first cleared, then filled by a compute Dispatch
    at event N, then read as an SRV by event M. Useful when the
    graphics-only producer chain bottoms out at a resource that has no
    OMSetRenderTargets writer.
    """
    cpp_project_dir = Path(cpp_project_dir).resolve()
    db = (cpp_db_path or cpp_project_dir / ".ngfxmcp_cpp_calls.db").resolve()
    if not db.is_file():
        return {"ok": False, "error": f"cpp_calls index missing: {db}"}
    setup_views = _build_setup_views_index(cpp_project_dir)

    # The C++ project usually references a resource by its symbol name
    # directly in command-list calls. Search for the symbol substring in
    # raw_args of every kind=copy / kind=dispatch / kind=set_state event.
    conn = sqlite3.connect(db)
    timeline: list[dict[str, Any]] = []
    try:
        # --- (1) Render-target binds — already covered by the producer
        # trace, but include here for completeness in the timeline.
        rtv_heap_slots = [
            (heap, slot)
            for (heap, slot), sym in setup_views["rtv"].items()
            if sym == resource_sym
        ]
        if rtv_heap_slots:
            all_om = conn.execute(
                "SELECT event_index, file_path, line_number, raw_args FROM cpp_calls "
                "WHERE function_name='OMSetRenderTargets' ORDER BY event_index"
            ).fetchall()
            for ev, src, ln, raw in all_om:
                try:
                    text = Path(src).read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                lo = max(0, ln - 10)
                window = "\n".join(text[lo:ln])
                for heap, slot in rtv_heap_slots:
                    if re.search(
                        rf"OffsetCPUDescriptor\(\s*{slot}u\s*,\s*{re.escape(heap)}",
                        window,
                    ):
                        timeline.append(
                            {
                                "event_index": ev,
                                "kind": "rtv_bind",
                                "function_name": "OMSetRenderTargets",
                                "via_heap": heap,
                                "via_slot": slot,
                                "file": Path(src).name,
                                "line": ln,
                            }
                        )
                        break

        # --- (2) Copy destinations: CopyTextureRegion / CopyBufferRegion /
        # CopyResource — first positional arg (after the receiver) is the dest.
        for fn in (
            "CopyTextureRegion",
            "CopyBufferRegion",
            "CopyResource",
            "CopyTiles",
            "ResolveSubresource",
        ):
            for ev, src, ln, raw in conn.execute(
                "SELECT event_index, file_path, line_number, raw_args FROM cpp_calls "
                "WHERE function_name = ? ORDER BY event_index", (fn,),
            ).fetchall():
                # raw_args has the receiver stripped, so position 0 is the destination.
                args_head = raw.split(",", 1)[0] if raw else ""
                if resource_sym in args_head:
                    timeline.append(
                        {
                            "event_index": ev,
                            "kind": "copy_dest",
                            "function_name": fn,
                            "raw_args_head": raw[:200],
                            "file": Path(src).name,
                            "line": ln,
                        }
                    )

        # --- (3) UAV writes via Dispatch — find UAV slots pointing at this
        # resource, then Dispatch events whose surrounding source binds those
        # slots via SetComputeRootDescriptorTable.
        uav_heap_slots = [
            (heap, slot)
            for (heap, slot), sym in setup_views["uav"].items()
            if sym == resource_sym
        ]
        if uav_heap_slots:
            dispatches = conn.execute(
                "SELECT event_index, file_path, line_number FROM cpp_calls "
                "WHERE function_name IN ('Dispatch', 'DispatchMesh', 'ExecuteIndirect') "
                "ORDER BY event_index"
            ).fetchall()
            for ev, src, ln in dispatches:
                try:
                    text = Path(src).read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                lo = max(0, ln - 60)
                window = "\n".join(text[lo:ln])
                for heap, slot in uav_heap_slots:
                    # UAV heap on GPU side is the same heap as CBV/SRV but the
                    # bind path uses SetComputeRootDescriptorTable. The CPU
                    # heap symbol ends in `_cpubegin`; the GPU one ends in
                    # `_gpubegin`. Convert.
                    cpu_heap = heap
                    gpu_heap_match = re.match(r"(.+_dh_\d+_\d+)_cpubegin", heap)
                    gpu_heap = (
                        f"{gpu_heap_match.group(1)}_gpubegin"
                        if gpu_heap_match
                        else heap
                    )
                    if re.search(
                        rf"OffsetGPUDescriptor\(\s*{slot}u\s*,\s*{re.escape(gpu_heap)}",
                        window,
                    ):
                        timeline.append(
                            {
                                "event_index": ev,
                                "kind": "uav_write_via_dispatch",
                                "function_name": "Dispatch (or variant)",
                                "via_heap": gpu_heap,
                                "via_slot": slot,
                                "file": Path(src).name,
                                "line": ln,
                            }
                        )
                        break

        # --- (4) ClearRenderTargetView / ClearUnorderedAccessView (which take
        # a resource pointer as one of the args).
        if include_clear:
            for fn in (
                "ClearRenderTargetView",
                "ClearUnorderedAccessViewUint",
                "ClearUnorderedAccessViewFloat",
                "ClearDepthStencilView",
                "DiscardResource",
            ):
                for ev, src, ln, raw in conn.execute(
                    "SELECT event_index, file_path, line_number, raw_args FROM cpp_calls "
                    "WHERE function_name = ? ORDER BY event_index", (fn,),
                ).fetchall():
                    if resource_sym in raw:
                        timeline.append(
                            {
                                "event_index": ev,
                                "kind": "clear_or_discard",
                                "function_name": fn,
                                "raw_args_head": raw[:200],
                                "file": Path(src).name,
                                "line": ln,
                            }
                        )
    finally:
        conn.close()

    timeline.sort(key=lambda e: e["event_index"])
    return {
        "ok": True,
        "resource_sym": resource_sym,
        "resource_name": setup_views["names"].get(resource_sym),
        "rtv_heap_slots": rtv_heap_slots,
        "uav_heap_slots": uav_heap_slots,
        "write_event_count": len(timeline),
        "timeline": timeline,
    }


def resource_write_history_pair_diff(
    *,
    cpp_project_dir: Path,
    cpp_db_path: Path | None = None,
    left_resource_sym: str,
    right_resource_sym: str,
) -> dict[str, Any]:
    """Compare write timelines for a LEFT/RIGHT resource pair.

    Surfaces where one eye has writes that the other doesn't (and vice
    versa). Most useful when the graphics producer chain bottoms out at
    a resource that's actually populated via Dispatch or Copy.
    """
    left = resource_write_history(
        cpp_project_dir=cpp_project_dir,
        cpp_db_path=cpp_db_path,
        resource_sym=left_resource_sym,
    )
    right = resource_write_history(
        cpp_project_dir=cpp_project_dir,
        cpp_db_path=cpp_db_path,
        resource_sym=right_resource_sym,
    )
    if not (left.get("ok") and right.get("ok")):
        return {"ok": False, "left": left, "right": right}
    # Bucket by kind/function and compare counts.
    def _by_kind(tl):
        out: dict[str, int] = {}
        for e in tl:
            key = f"{e['kind']}:{e['function_name']}"
            out[key] = out.get(key, 0) + 1
        return out
    l_kinds = _by_kind(left["timeline"])
    r_kinds = _by_kind(right["timeline"])
    return {
        "ok": True,
        "left": {
            "resource_sym": left_resource_sym,
            "resource_name": left["resource_name"],
            "write_event_count": left["write_event_count"],
            "by_kind": l_kinds,
            "timeline": left["timeline"],
        },
        "right": {
            "resource_sym": right_resource_sym,
            "resource_name": right["resource_name"],
            "write_event_count": right["write_event_count"],
            "by_kind": r_kinds,
            "timeline": right["timeline"],
        },
        "kind_count_diff": {
            k: {"left": l_kinds.get(k, 0), "right": r_kinds.get(k, 0)}
            for k in set(l_kinds) | set(r_kinds)
            if l_kinds.get(k, 0) != r_kinds.get(k, 0)
        },
    }


def producer_lineage_trace(
    *,
    cpp_project_dir: Path,
    cpp_db_path: Path | None = None,
    seed_resource_sym: str,
    max_depth: int = 4,
    max_inputs_per_level: int = 6,
) -> dict[str, Any]:
    """Recursively walk a render-graph from ``seed_resource_sym`` back to its
    source producers.

    At each level the producer event is the first ``OMSetRenderTargets``
    that binds an RTV pointing at the current resource. We capture the
    PSO, root signature, viewport, scissor, SRV inputs (resolved to
    concrete resource UIDs via the FrameSetup view table), and CBV
    references. Then we recurse on the SRV input resources.

    Cycles are broken by tracking visited resources. Depth is capped.
    Returns a tree as nested dicts.
    """
    cpp_project_dir = Path(cpp_project_dir).resolve()
    if not cpp_project_dir.is_dir():
        return {"ok": False, "error": f"project dir not found: {cpp_project_dir}"}
    db = (cpp_db_path or cpp_project_dir / ".ngfxmcp_cpp_calls.db").resolve()
    if not db.is_file():
        return {"ok": False, "error": f"cpp_calls index missing: {db}"}

    setup_views = _build_setup_views_index(cpp_project_dir)
    visited: set[str] = set()

    def _walk(sym: str, depth: int) -> dict[str, Any]:
        if depth > max_depth:
            return {
                "resource_sym": sym,
                "resource_name": setup_views["names"].get(sym),
                "depth_limit_reached": True,
            }
        if sym in visited:
            return {
                "resource_sym": sym,
                "resource_name": setup_views["names"].get(sym),
                "cycle_break": True,
            }
        visited.add(sym)
        node: dict[str, Any] = {
            "resource_sym": sym,
            "resource_name": setup_views["names"].get(sym),
        }
        prod_event = _producer_event_for_resource(
            cpp_project_dir, db, sym, setup_views,
        )
        if not prod_event:
            node["producer"] = None
            return node
        snapshot = _scan_producer_state(cpp_project_dir, prod_event, setup_views)
        node["producer"] = snapshot
        # Recurse on EVERY SRV in EVERY descriptor table.
        children: list[dict[str, Any]] = []
        emitted = 0
        for rp, entry in sorted(snapshot["srv_tables"].items()):
            for srv_entry in entry.get("srv_range") or []:
                child_sym = srv_entry.get("resource_sym")
                if not child_sym:
                    continue
                if emitted >= max_inputs_per_level:
                    break
                child_node = _walk(child_sym, depth + 1)
                children.append(
                    {
                        "rp": rp,
                        "base_slot": entry["base_slot"],
                        "slot": srv_entry["slot"],
                        "offset_in_table": srv_entry["offset_from_base"],
                        **child_node,
                    }
                )
                emitted += 1
            if emitted >= max_inputs_per_level:
                break
        node["children"] = children
        return node

    return {
        "ok": True,
        "cpp_project_dir": str(cpp_project_dir),
        "cpp_db_path": str(db),
        "seed_resource_sym": seed_resource_sym,
        "seed_resource_name": setup_views["names"].get(seed_resource_sym),
        "max_depth": max_depth,
        "tree": _walk(seed_resource_sym, 0),
    }


def producer_lineage_pair_diff(
    *,
    cpp_project_dir: Path,
    cpp_db_path: Path | None = None,
    left_resource_sym: str,
    right_resource_sym: str,
    max_depth: int = 4,
) -> dict[str, Any]:
    """Trace both eyes' producer lineages and diff them level-by-level.

    Highlights the first level where the producer's PSO, root signature,
    or symmetric SRV-input pattern differs — that's the most likely
    location of the divergent behavior.
    """
    left = producer_lineage_trace(
        cpp_project_dir=cpp_project_dir,
        cpp_db_path=cpp_db_path,
        seed_resource_sym=left_resource_sym,
        max_depth=max_depth,
    )
    right = producer_lineage_trace(
        cpp_project_dir=cpp_project_dir,
        cpp_db_path=cpp_db_path,
        seed_resource_sym=right_resource_sym,
        max_depth=max_depth,
    )
    if not (left.get("ok") and right.get("ok")):
        return {
            "ok": False,
            "error": "one or both lineage traces failed",
            "left": left,
            "right": right,
        }

    findings: list[dict[str, Any]] = []

    def _flatten(node: dict[str, Any], depth: int = 0, path: tuple[int, ...] = ()) -> list[dict[str, Any]]:
        out = [
            {
                "depth": depth,
                "path": path,
                "resource_sym": node.get("resource_sym"),
                "resource_name": node.get("resource_name"),
                "producer": node.get("producer"),
            }
        ]
        for i, child in enumerate(node.get("children") or []):
            if "resource_sym" in child:
                out.extend(_flatten(child, depth + 1, path + (i,)))
        return out

    l_nodes = _flatten(left["tree"])
    r_nodes = _flatten(right["tree"])

    # Pair by depth + path
    max_len = max(len(l_nodes), len(r_nodes))
    by_path_l = {n["path"]: n for n in l_nodes}
    by_path_r = {n["path"]: n for n in r_nodes}
    all_paths = sorted(set(by_path_l) | set(by_path_r))
    for p in all_paths:
        l_n = by_path_l.get(p)
        r_n = by_path_r.get(p)
        if l_n is None or r_n is None:
            findings.append(
                {
                    "path": p,
                    "structural_mismatch": True,
                    "left_present": l_n is not None,
                    "right_present": r_n is not None,
                }
            )
            continue
        l_p = l_n.get("producer") or {}
        r_p = r_n.get("producer") or {}
        diff: dict[str, Any] = {}
        for key in ("pso", "root_signature", "viewport", "scissor"):
            if l_p.get(key) != r_p.get(key):
                diff[key] = {"left": l_p.get(key), "right": r_p.get(key)}
        # Compare srv_tables by root parameter index — walk the FULL range,
        # not just the base SRV. UE5 tables often have 3-5 contiguous SRVs;
        # only one of them may be asymmetric.
        srv_diff: dict[str, Any] = {}
        srv_l = l_p.get("srv_tables") or {}
        srv_r = r_p.get("srv_tables") or {}
        for rp_k in set(srv_l) | set(srv_r):
            l_entry = srv_l.get(rp_k) or {}
            r_entry = srv_r.get(rp_k) or {}
            l_range = l_entry.get("srv_range") or []
            r_range = r_entry.get("srv_range") or []
            # Pair by table offset (offset_from_base) so we compare slot
            # N+k on each side independent of the heap-instance base.
            l_by_off = {s["offset_from_base"]: s for s in l_range}
            r_by_off = {s["offset_from_base"]: s for s in r_range}
            offs_diff = []
            for off in sorted(set(l_by_off) | set(r_by_off)):
                ls = l_by_off.get(off)
                rs = r_by_off.get(off)
                lv = (ls or {}).get("resource_sym")
                rv = (rs or {}).get("resource_sym")
                if lv != rv:
                    offs_diff.append(
                        {
                            "offset_in_table": off,
                            "left_sym": lv,
                            "left_name": (ls or {}).get("resource_name"),
                            "right_sym": rv,
                            "right_name": (rs or {}).get("resource_name"),
                        }
                    )
            if offs_diff:
                srv_diff[str(rp_k)] = {
                    "left_range_size": len(l_range),
                    "right_range_size": len(r_range),
                    "diffs": offs_diff,
                }
        if srv_diff:
            diff["srv_inputs"] = srv_diff
        # Symmetric-PSO judgement: same PSO + same root sig means shader is symmetric
        symmetric_shader = (
            l_p.get("pso") == r_p.get("pso")
            and l_p.get("root_signature") == r_p.get("root_signature")
        )
        findings.append(
            {
                "path": p,
                "depth": l_n["depth"],
                "left_resource_sym": l_n.get("resource_sym"),
                "left_resource_name": l_n.get("resource_name"),
                "right_resource_sym": r_n.get("resource_sym"),
                "right_resource_name": r_n.get("resource_name"),
                "symmetric_shader": symmetric_shader,
                "left_producer_event": l_p.get("event_index"),
                "right_producer_event": r_p.get("event_index"),
                "diff": diff,
            }
        )

    # Identify the first level where shaders diverge (asymmetric PSO) — that
    # would mean the bug is in distinct shader logic. Otherwise the chain is
    # all "same shader, different per-eye inputs", and the bug is in one of
    # the leaf inputs.
    first_asymmetric_shader = next(
        (f for f in findings if not f.get("symmetric_shader") and "left_resource_sym" in f),
        None,
    )

    return {
        "ok": True,
        "left_seed": left_resource_sym,
        "right_seed": right_resource_sym,
        "max_depth": max_depth,
        "left_tree": left["tree"],
        "right_tree": right["tree"],
        "level_findings": findings,
        "first_asymmetric_shader": first_asymmetric_shader,
        "summary": (
            "All traced levels use symmetric shader logic (same PSO + root signature). "
            "The right-eye anomaly must originate from the per-eye input textures, "
            "the per-eye CBV byte ranges, or a leaf resource whose population is "
            "asymmetric. Inspect the deepest distinct input pair for the actual "
            "root cause."
            if first_asymmetric_shader is None
            else f"First asymmetric producer at depth "
                 f"{first_asymmetric_shader['depth']}: left "
                 f"{first_asymmetric_shader['left_producer_event']} vs right "
                 f"{first_asymmetric_shader['right_producer_event']} — different "
                 "shader logic."
        ),
    }


def setup_names_lookup(producer_state: dict[str, Any], rp_k) -> str | None:
    """Helper: pull the resource_name out of a producer state's srv_tables."""
    srv = (producer_state.get("srv_tables") or {}).get(rp_k) or {}
    return srv.get("srv_resource_name")


def copyrect_t0_resolution_report(
    *,
    cpp_project_dir: Path,
    cpp_db_path: Path | None = None,
    pso_db_path: Path | None = None,
    suspect_shader: str = "CopyRectPS",
    max_pairs: int = 4,
    lookback: int = 200,
) -> dict[str, Any]:
    """Resolve the actual sampled state for paired left/right ``CopyRectPS`` draws
    using a UI-generated Generate-C++-Capture project as the data source.

    Required inputs:

    * ``cpp_project_dir`` — the path to the C++ project Nsight emitted from
      the saved capture (File → Generate C++ Capture in the UI today; or via
      the headless Pylon bridge once that lands).
    * ``cpp_db_path`` — optional override for the C++-call index location.
      Defaults to ``cpp_project_dir/.ngfxmcp_cpp_calls.db``.
    * ``pso_db_path`` — optional override for the PSO index location.
      Defaults to ``cpp_project_dir/.ngfxmcp_pso_index.db``.

    Pipeline:

    1. Look up PSO symbols whose pixel shader is ``suspect_shader`` via
       :func:`pso_resolver.list_shader_blobs` + ``find_psos_using_shader``.
    2. Find ``SetPipelineState`` events that bind those PSOs in the C++ call
       index, then the first few draws that follow each.
    3. For every such draw, pull
       :func:`cpp_capture_parser.descriptor_bindings_for_event`.
    4. Pair adjacent draws as left/right (sequential order matches the
       common stereo pattern). For each pair, diff state signatures and
       emit a verdict.

    Every output field carries an ``evidence_label``: ``proven`` if the
    value is read straight from the indexed C++ args, ``inferred`` if it's
    derived from sibling state (e.g. pipeline lookback), or ``candidate``
    if no source backs it yet.
    """
    cpp_project_dir = cpp_project_dir.resolve()
    if not cpp_project_dir.is_dir():
        return {"ok": False, "error": f"cpp_project_dir not found: {cpp_project_dir}"}

    # cpp_capture_parser and pso_resolver share the same .ngfxmcp_cpp_calls.db
    # by default; the caller can still override either path independently.
    default_db = cpp_project_dir / ".ngfxmcp_cpp_calls.db"
    cpp_db = (cpp_db_path or default_db).resolve()
    pso_db = (pso_db_path or default_db).resolve()

    missing: list[str] = []
    if not cpp_db.is_file():
        missing.append(f"cpp_calls index: {cpp_db}")
    if not pso_db.is_file() and pso_db != cpp_db:
        missing.append(f"pso index: {pso_db}")
    if missing:
        return {
            "ok": False,
            "error": "missing index databases — run cpp_capture_parser.index_cpp_project "
            "and pso_resolver.index_project_psos against this C++ project first.",
            "missing": missing,
        }

    psos = _candidate_pso_symbols(pso_db, suspect_shader)
    pso_symbols = [p.get("pso_symbol") for p in psos if p.get("pso_symbol")]
    draws = _draws_using_psos(cpp_db, pso_symbols, limit=max_pairs * 4)

    pairs: list[dict[str, Any]] = []
    for left_draw, right_draw in pairwise(draws[: max_pairs * 2]):
        l_state = cpp_capture_parser.descriptor_bindings_for_event(
            cpp_db, left_draw["event_index"], lookback=lookback
        )
        r_state = cpp_capture_parser.descriptor_bindings_for_event(
            cpp_db, right_draw["event_index"], lookback=lookback
        )
        l_sig = _state_signature(l_state)
        r_sig = _state_signature(r_state)
        compare = _compare_states(l_sig, r_sig)
        pairs.append(
            {
                "left": {
                    "event_index": left_draw["event_index"],
                    "function_name": left_draw["function_name"],
                    "pso_symbol": left_draw["pso_symbol"],
                    "draw_args": left_draw["draw_args"],
                    "state": l_sig,
                    "evidence_label": "proven",
                },
                "right": {
                    "event_index": right_draw["event_index"],
                    "function_name": right_draw["function_name"],
                    "pso_symbol": right_draw["pso_symbol"],
                    "draw_args": right_draw["draw_args"],
                    "state": r_sig,
                    "evidence_label": "proven",
                },
                "comparison": compare,
            }
        )
        if len(pairs) >= max_pairs:
            break

    missing_evidence: list[str] = []
    if not psos:
        missing_evidence.append(
            f"No PSOs found whose pixel shader is {suspect_shader!r}. "
            "Verify the shader name and re-run pso_resolver.index_project_psos."
        )
    if not draws:
        missing_evidence.append(
            "No SetPipelineState→Draw chains for the candidate PSOs were found "
            "in the C++ call index. Try a larger project, confirm the project "
            "is a full Nsight Generate-C++-Capture export, and re-run "
            "cpp_capture_parser.index_cpp_project."
        )
    if pairs and all(
        not p["comparison"]["field_diffs"] for p in pairs
    ):
        missing_evidence.append(
            "All paired draws have identical visible state. The most likely "
            "remaining culprits — root constants and the actual sampled "
            "descriptor for shader register t0 — require root-signature "
            "parsing or shader reflection (ngfx_shader_reflection_bindings / "
            "ngfx_capture_root_signature_ranges, both planned)."
        )

    return {
        "ok": True,
        "cpp_project_dir": str(cpp_project_dir),
        "cpp_db_path": str(cpp_db),
        "pso_db_path": str(pso_db),
        "suspect_shader": suspect_shader,
        "candidate_pso_count": len(psos),
        "candidate_pso_symbols": pso_symbols,
        "copyrect_draws_found": len(draws),
        "paired_count": len(pairs),
        "pairs": pairs,
        "missing_evidence": missing_evidence,
        "next_actions": [
            {
                "tool": "ngfx_shader_reflection_bindings",
                "purpose": "Map shader register t0 to root parameter / descriptor "
                "table for a precise t0 verdict.",
            },
            {
                "tool": "ngfx_capture_root_signature_ranges",
                "purpose": "Decode the root signature object the suspect PSO uses, "
                "so descriptor indices in the diff can be resolved to resources.",
            },
            {
                "tool": "ngfx_pixel_history",
                "purpose": "Once Gap 1 lands, run a pixel history on a known-bad "
                "right-eye pixel and the matching left-eye control.",
            },
        ],
    }
