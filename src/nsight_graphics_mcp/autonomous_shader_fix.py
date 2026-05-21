"""Autonomous shader-fix utility layer.

These helpers are intentionally deterministic and file-oriented so an LLM can
run them in a loop: launch repros, pair eye events, build pixel-history request
grids, inspect resource producer graphs, import runtime hook traces, score HDR
ROI diffs, and validate whether a claimed fix has enough evidence.
"""

from __future__ import annotations

import csv
import json
import math
import re
import sqlite3
import struct
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from . import proto_descriptors, rpc_client, shader_triage

SN2_DEFAULTS = {
    "game_exe": r"E:\Github\Subnautica 2\Subnautica2\Binaries\Win64\Subnautica2-Win64-Shipping.exe",
    "launch_script": r"E:\Github\Subnautica 2\moddingkit\runs\launch_uevr_only.ps1",
    "handoff_path": r"E:\Github\Subnautica 2\moddingkit\runs\HANDOFF_2026-05-20.md",
    "uevr_root": r"E:\Github\UEVRJ",
    "uevr_backend": r"E:\Github\UEVRJ\build\bin\uevr\UEVRBackend.dll",
    "captures_dir": r"E:\Github\Subnautica 2\captures",
    "runs_dir": r"E:\Github\Subnautica 2\moddingkit\runs",
}

SN2_FOG_DEFAULTS = {
    "lead_pso": "0x221FA167CE0",
    "ps_hash": "9a29f7f299902d2c",
    "ps_entry": "VoxelizePS",
    "gs_hash": "399d1b7f3e1e20bd",
    "gs_entry": "VoxelizeGS",
    "expected_draw_count": 77,
    "expected_left_eye_bucket": "1",
    "fog_on_name": "fog_clean_on_20260520_152134.json",
    "fog_off_name": "fog_clean_off_20260520_152134.json",
    "ps_shader_name": "fog_voxelize_ps_9a29f7f299902d2c_clean.json",
    "gs_shader_name": "fog_voxelize_gs_399d1b7f3e1e20bd.json",
}

SN2_FOG_SHADER_SLOTS = [
    {"slot": "gs_t0", "stage": "GS", "type": "srv", "bind_point": 0, "space": 0, "role": "VoxelizeGS structured input buffer"},
    {"slot": "gs_cb0", "stage": "GS", "type": "cbv", "bind_point": 0, "space": 0, "role": "GS globals"},
    {"slot": "gs_cb1", "stage": "GS", "type": "cbv", "bind_point": 1, "space": 0, "role": "View"},
    {"slot": "gs_cb2", "stage": "GS", "type": "cbv", "bind_point": 2, "space": 0, "role": "VoxelizeVolumePass"},
    {"slot": "ps_t0", "stage": "PS", "type": "srv", "bind_point": 0, "space": 0, "role": "VoxelizePS buffer input 0"},
    {"slot": "ps_t1", "stage": "PS", "type": "srv", "bind_point": 1, "space": 0, "role": "VoxelizePS buffer input 1"},
    {"slot": "ps_t2", "stage": "PS", "type": "srv", "bind_point": 2, "space": 0, "role": "VoxelizePS structured input buffer"},
    {"slot": "ps_cb0", "stage": "PS", "type": "cbv", "bind_point": 0, "space": 0, "role": "View"},
    {"slot": "ps_cb1", "stage": "PS", "type": "cbv", "bind_point": 1, "space": 0, "role": "VoxelizeVolumePass"},
    {"slot": "ps_cb2", "stage": "PS", "type": "cbv", "bind_point": 2, "space": 0, "role": "Material"},
]

SN2_COPYRECT_DEFAULTS = {
    "ps_hash": "98acf00f2001c218",
    "ps_crc32": "0xE85849AA",
    "ps_entry": "CopyRectPS",
    "shader_name": r"fog_ab_20260520_154436\broad_probe_gen\98acf00f2001c218.inspection.json",
    "preferred_trace_names": [
        r"fog_ab_20260520_154436\fog1.json",
        r"fog_ab_20260520_154436\broad_probe_all\capture.json",
        r"fog_ab_20260520_154436\post_fix_probe_validation\all_disabled_runtime_on_after.json",
        "live_after_compact_fog1.json",
        "fog_replay_on_20260520_153554.json",
        "fog_clean_on_20260520_152134.json",
    ],
}

SN2_COPYRECT_SHADER_SLOTS = [
    {"slot": "ps_t0", "stage": "PS", "type": "srv", "bind_point": 0, "space": 0, "role": "CopyRectPS source texture"},
    {"slot": "ps_s0", "stage": "PS", "type": "sampler", "bind_point": 0, "space": 0, "role": "CopyRectPS source sampler"},
]


def sn2_repro_plan(
    *,
    launch_script: str | None = None,
    output_dir: str | None = None,
    capture_frame_count: int = 1,
    extra_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    script = launch_script or SN2_DEFAULTS["launch_script"]
    out = output_dir or str(Path(SN2_DEFAULTS["runs_dir"]) / "autonomous_repro")
    env = {
        "UEVR_SN2_SKYATMOS_SKIP_RIGHT": "1",
        "UEVR_SN2_CAPTURE_RT_SNAPSHOTS": "1",
        "UEVR_SN2_SHADER_HUNTER": "1",
        **(extra_env or {}),
    }
    return {
        "ok": True,
        "defaults": SN2_DEFAULTS,
        "launch_script": script,
        "output_dir": out,
        "capture_frame_count": capture_frame_count,
        "extra_env": env,
        "powershell_command": [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script,
        ],
        "artifacts_expected": [
            "Nsight .ngfx-gfxcap",
            "UEVR hook trace NDJSON/SQLite",
            "right/left eye screenshots or RT snapshots",
            "stderr/stdout launch logs",
        ],
    }


def sn2_fog_artifacts(*, runs_dir: str | Path | None = None) -> dict[str, Any]:
    """Locate the current SN2 clean fog oracle artifacts.

    The clean r.Fog on/off traces are the most useful repro oracle for this
    bug. This resolver prefers the known-good filenames from the May 20 run,
    then falls back to the newest matching artifact so the MCP can keep working
    after a fresh repro without a human supplying paths.
    """

    root = Path(runs_dir or SN2_DEFAULTS["runs_dir"])
    specs = {
        "fog_on_path": (SN2_FOG_DEFAULTS["fog_on_name"], "fog_clean_on_*.json"),
        "fog_off_path": (SN2_FOG_DEFAULTS["fog_off_name"], "fog_clean_off_*.json"),
        "ps_shader_path": (SN2_FOG_DEFAULTS["ps_shader_name"], f"fog_voxelize_ps_{SN2_FOG_DEFAULTS['ps_hash']}*.json"),
        "gs_shader_path": (SN2_FOG_DEFAULTS["gs_shader_name"], f"fog_voxelize_gs_{SN2_FOG_DEFAULTS['gs_hash']}*.json"),
    }
    artifacts: dict[str, Any] = {}
    missing = []
    for key, (preferred_name, pattern) in specs.items():
        preferred = root / preferred_name
        selected = preferred if preferred.is_file() else _latest_matching_file(root, pattern)
        artifacts[key] = {
            "path": str(selected) if selected else str(preferred),
            "exists": bool(selected and selected.is_file()),
            "preferred_path": str(preferred),
            "pattern": pattern,
        }
        if not artifacts[key]["exists"]:
            missing.append(key)
    return {
        "ok": not missing,
        "runs_dir": str(root),
        "defaults": SN2_FOG_DEFAULTS,
        "artifacts": artifacts,
        "missing": missing,
    }


def sn2_fog_signal_report(
    *,
    fog_on_path: str | Path | None = None,
    fog_off_path: str | Path | None = None,
    ps_shader_path: str | Path | None = None,
    gs_shader_path: str | Path | None = None,
    lead_pso: str | None = None,
    ps_hash: str | None = None,
    gs_hash: str | None = None,
    expected_draw_count: int | None = None,
    expected_left_eye_bucket: int | str | None = None,
) -> dict[str, Any]:
    """Evaluate the clean r.Fog on/off signal for the SN2 fog voxelization bug."""

    artifacts = sn2_fog_artifacts()
    paths = artifacts["artifacts"]
    on_path = Path(fog_on_path or paths["fog_on_path"]["path"])
    off_path = Path(fog_off_path or paths["fog_off_path"]["path"])
    ps_path = Path(ps_shader_path or paths["ps_shader_path"]["path"])
    gs_path = Path(gs_shader_path or paths["gs_shader_path"]["path"])
    target = {
        "lead_pso": _norm_hex(lead_pso or SN2_FOG_DEFAULTS["lead_pso"]),
        "ps_hash": _norm_hash(ps_hash or SN2_FOG_DEFAULTS["ps_hash"]),
        "gs_hash": _norm_hash(gs_hash or SN2_FOG_DEFAULTS["gs_hash"]),
        "expected_draw_count": int(expected_draw_count or SN2_FOG_DEFAULTS["expected_draw_count"]),
        "expected_left_eye_bucket": _eye_bucket_key(
            expected_left_eye_bucket if expected_left_eye_bucket is not None else SN2_FOG_DEFAULTS["expected_left_eye_bucket"]
        ),
    }

    fog_on = _load_json_file(on_path)
    fog_off = _load_json_file(off_path) if off_path.is_file() else None
    ps_shader = _load_json_file(ps_path) if ps_path.is_file() else None
    gs_shader = _load_json_file(gs_path) if gs_path.is_file() else None

    on = _sn2_fog_trace_summary(fog_on, label="r.Fog 1", target=target)
    off = _sn2_fog_trace_summary(fog_off, label="r.Fog 0", target=target) if fog_off is not None else None
    shader_evidence = {
        "ps": _shader_dump_summary(ps_shader, expected_hash=target["ps_hash"], expected_entry=SN2_FOG_DEFAULTS["ps_entry"]),
        "gs": _shader_dump_summary(gs_shader, expected_hash=target["gs_hash"], expected_entry=SN2_FOG_DEFAULTS["gs_entry"]),
    }

    checks = {
        "fog_on_actual_draws_present": on["actual_draw_count"] > 0,
        "fog_on_draw_count_matches_expected": on["actual_draw_count"] == target["expected_draw_count"],
        "fog_on_all_actual_draws_left_only": _histogram_only_key(on["eye_bucket_histogram"], target["expected_left_eye_bucket"]),
        "fog_on_ranked_candidate_present": on["ranked_candidate"] is not None,
        "fog_on_stage_hashes_match": on["stage_hash_match"]["ps"] and on["stage_hash_match"]["gs"],
        "fog_off_actual_draws_absent": off is not None and off["actual_draw_count"] == 0,
        "ps_dump_matches": shader_evidence["ps"]["matches_expected_hash"] and shader_evidence["ps"]["matches_expected_entry"],
        "gs_dump_matches": shader_evidence["gs"]["matches_expected_hash"] and shader_evidence["gs"]["matches_expected_entry"],
    }
    warnings = []
    if off and off["shader_aggregate"] is not None and off["actual_draw_count"] == 0:
        warnings.append(
            "r.Fog 0 still has historical shader aggregate evidence for the lead PSO; use actual recent_draw_events, not aggregate presence, as the disappearance signal."
        )
    if on["actual_draw_count"] != target["expected_draw_count"]:
        warnings.append("Lead PSO draw count differs from the current clean oracle; rerun the r.Fog pair before accepting a fix.")
    if not checks["fog_on_all_actual_draws_left_only"]:
        warnings.append("Lead PSO is not left-eye-only in the r.Fog-on trace; the target signal has changed.")

    required = (
        "fog_on_actual_draws_present",
        "fog_on_draw_count_matches_expected",
        "fog_on_all_actual_draws_left_only",
        "fog_on_stage_hashes_match",
        "fog_off_actual_draws_absent",
    )
    ok = all(checks[name] for name in required)
    report = {
        "ok": ok,
        "target": target,
        "paths": {
            "fog_on_path": str(on_path),
            "fog_off_path": str(off_path),
            "ps_shader_path": str(ps_path),
            "gs_shader_path": str(gs_path),
        },
        "checks": checks,
        "warnings": warnings,
        "fog_on": on,
        "fog_off": off,
        "shader_evidence": shader_evidence,
        "fix_targets": _sn2_fog_fix_targets(on, target),
        "next_actions": [
            "Treat the lead PSO as 0x221FA167CE0, not the earlier pso3069 dead-end.",
            "Trigger runtime instrumentation on exact pipeline_state first, then fall back to PS+GS hash matching.",
            "Probe the geometry shader before the pixel shader because VoxelizeGS writes SV_RenderTargetArrayIndex.",
            "Use live FrameDebugger pixel history/resource revisions on the voxel volume writes and consumers.",
            "Do not rely on saved-capture C++ export for D3D12 on Nsight 2026.1; the serializer reports that path removed.",
        ],
    }
    report["fix_plan"] = sn2_fog_fix_plan(signal_report=report)
    return report


def sn2_fog_fix_plan(signal_report: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the autonomous implementation plan for fixing the SN2 fog signal."""

    target = (signal_report or {}).get("target", {})
    lead_pso = target.get("lead_pso") or _norm_hex(SN2_FOG_DEFAULTS["lead_pso"])
    ps_hash = target.get("ps_hash") or SN2_FOG_DEFAULTS["ps_hash"]
    gs_hash = target.get("gs_hash") or SN2_FOG_DEFAULTS["gs_hash"]
    expected_draw_count = target.get("expected_draw_count") or SN2_FOG_DEFAULTS["expected_draw_count"]
    expected_eye = target.get("expected_left_eye_bucket") or SN2_FOG_DEFAULTS["expected_left_eye_bucket"]
    fix_targets = (signal_report or {}).get("fix_targets", {})
    return {
        "ok": True,
        "goal": "Make the fog voxelization pass either run symmetrically for both eyes or stop leaking a left-only voxel result into the right-eye view.",
        "oracle": {
            "r.Fog 1": f"{lead_pso} appears as {expected_draw_count} actual draws, all eye_bucket {expected_eye}",
            "r.Fog 0": f"{lead_pso} has zero actual recent_draw_events",
            "acceptance": [
                "r.Fog 1 no longer produces a right-eye artifact in the HDR/viewport ROI.",
                "Lead fog voxelization evidence is explainable: symmetric left/right writes, intentional single-pass shared output, or removed consumer dependency.",
                "r.Fog 0 remains lead-PSO absent in actual draw events.",
                "Left-eye ROI delta stays within the configured regression threshold.",
            ],
        },
        "primary_trigger": {
            "pipeline_state": lead_pso,
            "stage_hash_fallback": {"ps_hash": ps_hash, "gs_hash": gs_hash},
            "root_signature": fix_targets.get("root_signature"),
            "reason": "The clean r.Fog differential ties the visual signal to this exact VoxelizePS/VoxelizeGS PSO.",
        },
        "mcp_loop": [
            "ngfx_sn2_fog_artifacts()",
            "ngfx_sn2_fog_signal_report()",
            "ngfx_rpc_open_capture_session(capture=<fresh Graphics Capture>)",
            "ngfx_resource_revision_at_event / ngfx_pixel_history on the voxel volume and right-eye ROI",
            "ngfx_shader_probe_execution_plan(suspect_pso='0x221FA167CE0', probe_name=<matrix entry>)",
            "patch runtime hook or shader bytecode, launch repro, then rerun ngfx_sn2_fog_signal_report and ROI scoring",
        ],
        "runtime_hook_requirements": [
            "Log SetPipelineState, SetGraphicsRootSignature, root descriptor/table writes, OMSetRenderTargets, viewport/scissor, and DrawIndexedInstanced for every matching draw.",
            "Track the current eye bucket independently from viewport and VR submit metadata; do not infer right-eye absence from screen half alone.",
            "Capture original PSO descriptors at creation time and cached-blob restore time so a patched clone can be built even when CreateGraphicsPipelineState is bypassed later.",
            "Support draw-time PSO swap keyed by exact ID3D12PipelineState pointer and by PS+GS hash pair.",
            "Dump per-draw descriptor resource identities for GS t0 and PS t0/t1/t2 plus cb0/cb1/cb2.",
        ],
        "shader_probe_matrix": [
            {
                "name": "gs_rt_array_index_constant_right",
                "stage": "GS",
                "purpose": "Prove whether the missing eye is controlled by SV_RenderTargetArrayIndex/slice routing.",
                "patch": "Force the GS SV_RenderTargetArrayIndex output to the right-eye/slice candidate for matching draws.",
            },
            {
                "name": "gs_duplicate_left_to_right_slice",
                "stage": "GS",
                "purpose": "Test whether duplicating emitted primitives into a second slice fixes the right-eye fog without changing density math.",
                "patch": "Emit the original primitive stream and a second stream with the alternate render-target array index.",
            },
            {
                "name": "gs_disable_lead_draw",
                "stage": "GS",
                "purpose": "Confirm causality by removing the voxelization write from the bad frame.",
                "patch": "Cull matching draws or emit no vertices for the lead PSO only.",
            },
            {
                "name": "ps_output_slice_debug_color",
                "stage": "PS",
                "purpose": "Make pixel-history results visually and numerically separable per fog target.",
                "patch": "Write fixed color/alpha markers to SV_Target0/1/2 for matching draws.",
            },
            {
                "name": "ps_zero_density_alpha",
                "stage": "PS",
                "purpose": "Determine whether the artifact is fog density/opacity rather than geometry slice selection.",
                "patch": "Preserve RGB where useful but force the density/alpha output path to zero.",
            },
        ],
        "private_frame_debugger_requirements": [
            "Pixel history on representative left-eye fog pixels and bad right-eye ROI pixels.",
            "Resource revision at the first and last lead-PSO draw events.",
            "Access history for the voxel volume resources written by the lead PSO and consumed by later fog/lighting passes.",
            "Event state snapshots around the first lead draw, the last lead draw, and the first right-eye consumer of the written voxel volume.",
        ],
        "failure_modes_to_guard": [
            "Mistaking shader aggregate history for actual r.Fog-on/off draw presence.",
            "Patching an obsolete pso3069 path that the current cached-blob pipeline does not use.",
            "Accepting a visual improvement without left-eye regression and r.Fog 0 controls.",
            "Assuming GS is harmless even though it owns SV_RenderTargetArrayIndex.",
        ],
    }


def sn2_fog_descriptor_probe_plan(
    *,
    signal_report: dict[str, Any] | None = None,
    event_index: int | None = None,
    resource_handles: list[dict[str, Any] | str | int] | None = None,
    roi: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Build the concrete live-state requests for the SN2 fog lead draw."""

    report = signal_report or sn2_fog_signal_report()
    representative = report.get("fix_targets", {}).get("representative_draw", {})
    event_requests = _binary_replay_event_request_previews(event_index) if event_index is not None else []
    handles = _normalise_resource_handles(resource_handles or [])
    resource_requests = _resource_request_previews(handles, event_index=event_index) if handles else []
    return {
        "ok": report.get("ok", False),
        "target": report.get("target", {}),
        "note": (
            "Clean hook draw_index values identify the lead PSO draw ordinal, but live Nsight RPC calls require a "
            "BinaryReplay event_index from the opened Graphics Capture."
        ),
        "representative_hook_draw": representative,
        "hook_descriptor_evidence": {
            "rtv0": representative.get("rtv0"),
            "root_signature": representative.get("root_signature"),
            "graphics_root_descriptor_tables": representative.get("graphics_root_descriptor_tables", []),
            "graphics_root_descriptor_table_resource_hash": representative.get("graphics_root_descriptor_table_resource_hash", []),
            "descriptor_reads": representative.get("descriptor_reads", []),
        },
        "shader_slots_to_resolve": SN2_FOG_SHADER_SLOTS,
        "live_event_index": event_index,
        "live_event_requests": event_requests,
        "resource_handles": handles,
        "resource_requests": resource_requests,
        "roi": roi,
        "next_mcp_calls": [
            "ngfx_rpc_open_capture_session(pid=<ngfx-rpc pid>) or ngfx_rpc_open_capture_session(pipename=<ngfx-ui pipename>)",
            "ngfx_sn2_fog_live_state_probe(session_handle=<handle>, event_index=<lead BinaryReplay event>)",
            "ngfx_sn2_fog_slot_candidates(descriptor_state_reply=<probe descriptor_state reply>)",
            "ngfx_resource_revision_at_event(session_handle=<handle>, accessor=<candidate>, event_index=<lead event>)",
            "ngfx_trace_roi_history(session_handle=<handle>, image_accessor=<bad/right-eye target>, roi=<right-eye ROI>)",
        ],
    }


def sn2_fog_slot_candidates(
    descriptor_state_reply: dict[str, Any],
    *,
    max_candidates_per_slot: int = 10,
) -> dict[str, Any]:
    """Resolve the VoxelizeGS/VoxelizePS slots from a live descriptor-state reply."""

    slot_map = {
        item["slot"]: {
            "register_space": item["space"],
            "register": item["bind_point"],
            "type": item["type"],
            "stage": item["stage"],
        }
        for item in SN2_FOG_SHADER_SLOTS
    }
    result = descriptor_resource_candidates(
        descriptor_state_reply,
        slots=[item["slot"] for item in SN2_FOG_SHADER_SLOTS],
        slot_map=slot_map,
        max_candidates_per_slot=max_candidates_per_slot,
    )
    result["shader_slots"] = SN2_FOG_SHADER_SLOTS
    result["resource_handles"] = resource_handles_from_state(descriptor_state_reply)
    return result


def resource_handles_from_state(reply: dict[str, Any], *, max_handles: int = 64) -> list[dict[str, Any]]:
    """Extract unique ``NV.PbApiDataHandle``-shaped objects from a JSON reply."""

    handles = []
    seen = set()
    for resource in _extract_resource_handles(reply):
        handle = _normalise_resource_handle(resource)
        if handle is None:
            continue
        key = (handle["accessor"], handle["misc"])
        if key in seen:
            continue
        seen.add(key)
        handles.append({**handle, "source": resource.get("path"), "name": resource.get("name")})
        if len(handles) >= max_handles:
            break
    return handles


def sn2_fog_probe_manifest(
    *,
    signal_report: dict[str, Any] | None = None,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Create the GS-first trial manifest consumed by the autonomous fix loop."""

    report = signal_report or sn2_fog_signal_report()
    plan = report.get("fix_plan") or sn2_fog_fix_plan(signal_report=report)
    manifest = {
        "ok": report.get("ok", False),
        "target": report.get("fix_targets", {}),
        "validation_oracle": plan["oracle"],
        "trial_order": [
            "gs_rt_array_index_constant_right",
            "gs_duplicate_left_to_right_slice",
            "gs_disable_lead_draw",
            "ps_output_slice_debug_color",
            "ps_zero_density_alpha",
        ],
        "trials": plan["shader_probe_matrix"],
        "runtime_trigger": plan["primary_trigger"],
        "required_runtime_features": plan["runtime_hook_requirements"],
        "required_nsight_features": plan["private_frame_debugger_requirements"],
        "acceptance_gate": [
            "Run clean r.Fog on/off pair.",
            "Run ngfx_sn2_fog_signal_report and require the lead signal to stay explainable.",
            "Run HDR/ROI score and require right-eye improvement with left-eye regression under threshold.",
            "Preserve r.Fog 0 control: zero actual lead-PSO draws.",
        ],
    }
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        manifest["output_path"] = str(out)
    return manifest


def sn2_copyrect_artifacts(
    *,
    runs_dir: str | Path | None = None,
    ps_hash: str | None = None,
) -> dict[str, Any]:
    """Locate SN2 CopyRectPS trace and shader-inspection artifacts.

    CopyRectPS is a small t0/s0 -> SV_Target copy shader. The important
    evidence is not shader math; it is the source texture, destination target,
    view rect, and producer chain for the source texture.
    """

    root = Path(runs_dir or SN2_DEFAULTS["runs_dir"])
    target_hash = _norm_hash(ps_hash or SN2_COPYRECT_DEFAULTS["ps_hash"])
    preferred_traces = []
    for rel in SN2_COPYRECT_DEFAULTS["preferred_trace_names"]:
        path = root / rel
        if path.is_file():
            preferred_traces.append(
                {
                    "path": str(path),
                    "exists": True,
                    "contains_target_hash": _file_contains_text(path, target_hash),
                    "mtime": path.stat().st_mtime,
                }
            )

    selected_trace = next((Path(item["path"]) for item in preferred_traces if item["contains_target_hash"]), None)
    if selected_trace is None:
        selected_trace = _latest_file_containing_text(root, target_hash, pattern="*.json")

    preferred_shader = root / SN2_COPYRECT_DEFAULTS["shader_name"]
    selected_shader = preferred_shader if preferred_shader.is_file() else _latest_recursive_matching_file(root, f"*{target_hash}*.json")
    return {
        "ok": bool(selected_trace and selected_trace.is_file() and selected_shader and selected_shader.is_file()),
        "runs_dir": str(root),
        "defaults": SN2_COPYRECT_DEFAULTS,
        "artifacts": {
            "trace_path": {
                "path": str(selected_trace) if selected_trace else "",
                "exists": bool(selected_trace and selected_trace.is_file()),
                "preferred_candidates": preferred_traces,
            },
            "shader_path": {
                "path": str(selected_shader) if selected_shader else str(preferred_shader),
                "exists": bool(selected_shader and selected_shader.is_file()),
                "preferred_path": str(preferred_shader),
                "pattern": f"*{target_hash}*.json",
            },
        },
        "missing": [
            name
            for name, item in {
                "trace_path": selected_trace,
                "shader_path": selected_shader,
            }.items()
            if not (item and item.is_file())
        ],
    }


def sn2_copyrect_signal_report(
    *,
    trace_path: str | Path | None = None,
    shader_path: str | Path | None = None,
    ps_hash: str | None = None,
    ps_crc32: str | None = None,
    ps_entry: str | None = None,
) -> dict[str, Any]:
    """Trace CopyRectPS source/destination state from Nsight/UEVR JSON artifacts."""

    artifacts = sn2_copyrect_artifacts(ps_hash=ps_hash)
    target = {
        "ps_hash": _norm_hash(ps_hash or SN2_COPYRECT_DEFAULTS["ps_hash"]),
        "ps_crc32": _norm_crc32(ps_crc32 or SN2_COPYRECT_DEFAULTS["ps_crc32"]),
        "ps_entry": ps_entry or SN2_COPYRECT_DEFAULTS["ps_entry"],
    }
    trace_file = Path(trace_path or artifacts["artifacts"]["trace_path"]["path"])
    shader_file = Path(shader_path or artifacts["artifacts"]["shader_path"]["path"])
    trace = _load_json_file(trace_file) if trace_file.is_file() else None
    shader = _load_json_file(shader_file) if shader_file.is_file() else None

    copyrect = _sn2_copyrect_trace_summary(trace, target=target)
    shader_evidence = _copyrect_shader_summary(shader, target=target)
    checks = {
        "copyrect_candidate_present": copyrect["candidate_count"] > 0,
        "copyrect_actual_draws_present": copyrect["actual_draw_count"] > 0,
        "copyrect_source_t0_visible": copyrect["source_read_count"] > 0,
        "copyrect_targets_visible": copyrect["target_write_count"] > 0,
        "shader_hash_matches": shader_evidence["matches_expected_hash"],
        "shader_entry_or_shape_matches": shader_evidence["matches_expected_entry"] or shader_evidence["shape"]["looks_like_copyrect"],
    }
    warnings = []
    if not checks["copyrect_source_t0_visible"]:
        warnings.append("No descriptor read for CopyRectPS t0 is visible in this artifact; use live descriptor-state RPC at the CopyRect event.")
    if copyrect["issue_flags"].get("cross_eye_source_read"):
        warnings.append("At least one CopyRect event reads a source whose producer eye differs from the copy draw eye.")
    if copyrect["issue_flags"].get("same_source_for_left_and_right"):
        warnings.append("Left and right CopyRect draws appear to use the same source resource; validate whether that is intended for this pass.")
    if copyrect["issue_flags"].get("right_eye_missing"):
        warnings.append("The artifact has CopyRect left-eye draws but no right-eye CopyRect draws for the matching PSO/hash.")

    report = {
        "ok": checks["copyrect_candidate_present"] and checks["shader_entry_or_shape_matches"],
        "target": target,
        "paths": {
            "trace_path": str(trace_file),
            "shader_path": str(shader_file),
        },
        "checks": checks,
        "warnings": warnings,
        "copyrect": copyrect,
        "shader_evidence": shader_evidence,
        "next_actions": [
            "Use ngfx_sn2_copyrect_descriptor_probe_plan to choose the exact BinaryReplay event requests.",
            "Use ngfx_sn2_copyrect_live_state_probe at the CopyRect event to resolve t0/s0 and the destination RTV.",
            "Run resource access history on the t0 source and destination; the fix should change source/rect routing, not CopyRectPS math.",
            "Only patch CopyRectPS for diagnostic color probes; production fix should target the bad source texture, view rect, or right-eye copy source selection.",
        ],
    }
    report["fix_plan"] = sn2_copyrect_fix_plan(signal_report=report)
    return report


def sn2_copyrect_fix_plan(signal_report: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the Nsight-driven plan for fixing the CopyRectPS path."""

    report = signal_report or {}
    target = report.get("target", {})
    copyrect = report.get("copyrect", {})
    primary = copyrect.get("primary_candidate") or {}
    return {
        "ok": True,
        "goal": "Find why the right-eye CopyRectPS draw copies the wrong source/rect, then fix the source texture or view-rect binding upstream.",
        "primary_trigger": {
            "ps_hash": target.get("ps_hash", SN2_COPYRECT_DEFAULTS["ps_hash"]),
            "ps_crc32": target.get("ps_crc32", SN2_COPYRECT_DEFAULTS["ps_crc32"]),
            "entry": target.get("ps_entry", SN2_COPYRECT_DEFAULTS["ps_entry"]),
            "pipeline_state": primary.get("pipeline_state"),
            "root_signature": primary.get("root_signature"),
        },
        "why_not_shader_math_first": [
            "CopyRectPS is a tiny t0/s0 copy to SV_Target.",
            "If the right eye is wrong at this shader, the bug is usually the source SRV, source subrect, destination rect, or producer of the source texture.",
            "A shader patch can prove causality, but a real fix should route the correct right-eye source or rect before the copy.",
        ],
        "mcp_loop": [
            "ngfx_sn2_copyrect_artifacts()",
            "ngfx_sn2_copyrect_signal_report()",
            "ngfx_rpc_open_capture_session(capture=<fresh Graphics Capture>)",
            "ngfx_sn2_copyrect_live_state_probe(session_handle=<handle>, event_index=<CopyRect event>)",
            "ngfx_resource_access_history(accessor=<t0 source>) and ngfx_resource_revision_at_event(..., event_index=<CopyRect event>)",
            "ngfx_trace_roi_history(image_accessor=<destination>, roi=<bad right-eye ROI>)",
        ],
        "evidence_to_collect": [
            "CopyRectPS event id/global id for left and right eye.",
            "PS t0 resource handle, resource info, subresource, descriptor index, and descriptor table/root parameter.",
            "Bound viewport/scissor/source rect constants at the CopyRect draw.",
            "Destination RTV/image handle and pixel history for the bad ROI.",
            "Producer event/resource revision for the t0 source before the right-eye CopyRect.",
        ],
        "fix_hypotheses": [
            {
                "name": "right_copy_reads_left_source",
                "test": "Right-eye CopyRect t0 source handle equals left source or producer_eye_bucket is left.",
                "fix": "Redirect the right-eye CopyRect source SRV/descriptor table to the right-eye source texture.",
            },
            {
                "name": "right_copy_source_rect_is_left_rect",
                "test": "Left/right t0 differs but viewport/scissor or copy rect constants are identical/left-biased.",
                "fix": "Patch the view-rect constants or upstream UEVR view rect for the right-eye CopyRect pass.",
            },
            {
                "name": "source_texture_already_bad",
                "test": "Pixel history/resource revision shows bad pixels already present in the t0 source before CopyRectPS.",
                "fix": "Move upstream to the source producer event and repeat the same t0/destination trace there.",
            },
            {
                "name": "destination_rect_or_array_slice_wrong",
                "test": "Correct source sampled but CopyRect writes wrong destination region/slice.",
                "fix": "Patch right-eye destination viewport/scissor/RTV binding rather than the shader.",
            },
        ],
        "acceptance_gate": [
            "Right-eye ROI improves after routing/rect fix.",
            "Left-eye ROI stays within regression threshold.",
            "CopyRectPS right-eye source and destination are explainable from Nsight descriptor/resource history.",
            "The previous fog/voxelization signal is not used as proof unless CopyRect's source history leads there.",
        ],
    }


def sn2_copyrect_descriptor_probe_plan(
    *,
    signal_report: dict[str, Any] | None = None,
    event_index: int | None = None,
    resource_handles: list[dict[str, Any] | str | int] | None = None,
    roi: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Build live Nsight BinaryReplay requests for a CopyRectPS event."""

    report = signal_report or sn2_copyrect_signal_report()
    representative = report.get("copyrect", {}).get("representative_draw") or {}
    event_requests = _binary_replay_event_request_previews(event_index) if event_index is not None else []
    handles = _normalise_resource_handles(resource_handles or _copyrect_resource_handle_inputs(representative))
    return {
        "ok": report.get("ok", False),
        "target": report.get("target", {}),
        "note": "Hook draw_index values are not Nsight BinaryReplay event indices; map to an event_index in the opened capture before live probing.",
        "representative_hook_draw": representative,
        "shader_slots_to_resolve": SN2_COPYRECT_SHADER_SLOTS,
        "hook_descriptor_evidence": {
            "source_reads": _copyrect_source_reads(representative),
            "target_writes": _copyrect_target_writes(representative),
            "graphics_root_descriptor_tables": representative.get("graphics_root_descriptor_tables", []),
            "graphics_root_cbvs": representative.get("graphics_root_cbvs", []),
        },
        "live_event_index": event_index,
        "live_event_requests": event_requests,
        "resource_handles": handles,
        "resource_requests": _resource_request_previews(handles, event_index=event_index) if handles else [],
        "roi": roi,
        "next_mcp_calls": [
            "ngfx_sn2_copyrect_live_state_probe(session_handle=<handle>, event_index=<CopyRect event>)",
            "ngfx_sn2_copyrect_slot_candidates(descriptor_state_reply=<descriptor_state reply>)",
            "ngfx_resource_access_history(session_handle=<handle>, accessor=<t0 source>)",
            "ngfx_trace_roi_history(session_handle=<handle>, image_accessor=<destination>, roi=<right-eye ROI>)",
        ],
    }


def sn2_copyrect_slot_candidates(
    descriptor_state_reply: dict[str, Any],
    *,
    max_candidates_per_slot: int = 10,
) -> dict[str, Any]:
    """Resolve CopyRectPS t0/s0 from a live descriptor-state reply."""

    slot_map = {
        item["slot"]: {
            "register_space": item["space"],
            "register": item["bind_point"],
            "type": item["type"],
            "stage": item["stage"],
        }
        for item in SN2_COPYRECT_SHADER_SLOTS
    }
    result = descriptor_resource_candidates(
        descriptor_state_reply,
        slots=[item["slot"] for item in SN2_COPYRECT_SHADER_SLOTS],
        slot_map=slot_map,
        max_candidates_per_slot=max_candidates_per_slot,
    )
    result["shader_slots"] = SN2_COPYRECT_SHADER_SLOTS
    result["resource_handles"] = resource_handles_from_state(descriptor_state_reply)
    return result


def sn2_copyrect_t0_source_compare(
    left_probe: dict[str, Any],
    right_probe: dict[str, Any],
    *,
    max_candidates_per_slot: int = 10,
) -> dict[str, Any]:
    """Compare resolved live PS t0 candidates for paired CopyRectPS events."""

    left_slots = _copyrect_slot_candidates_from_probe(left_probe, max_candidates_per_slot=max_candidates_per_slot)
    right_slots = _copyrect_slot_candidates_from_probe(right_probe, max_candidates_per_slot=max_candidates_per_slot)
    left_t0 = _copyrect_slot_resource_candidates(left_slots, "ps_t0")
    right_t0 = _copyrect_slot_resource_candidates(right_slots, "ps_t0")
    left_keys = {_resource_compare_key(item["resource"]) for item in left_t0 if item.get("resource")}
    right_keys = {_resource_compare_key(item["resource"]) for item in right_t0 if item.get("resource")}
    overlap = sorted(left_keys & right_keys)
    verdict = "copyrect_t0_unresolved"
    if left_t0 and right_t0:
        verdict = "copyrect_t0_same_source" if overlap else "copyrect_t0_different_source"
    elif left_t0:
        verdict = "right_copyrect_t0_unresolved"
    elif right_t0:
        verdict = "left_copyrect_t0_unresolved"

    return {
        "ok": bool(left_t0 and right_t0),
        "verdict": verdict,
        "left": {
            "event_index": left_probe.get("event_index"),
            "slot_status": left_slots.get("slots", {}).get("ps_t0", {}).get("status"),
            "t0_candidates": left_t0,
        },
        "right": {
            "event_index": right_probe.get("event_index"),
            "slot_status": right_slots.get("slots", {}).get("ps_t0", {}).get("status"),
            "t0_candidates": right_t0,
        },
        "same_t0_resources": overlap,
        "interpretation": _copyrect_t0_compare_interpretation(verdict),
        "next_steps": [
            "If verdict is copyrect_t0_same_source, trace that resource revision and descriptor provenance before the right-eye CopyRect.",
            "If verdict is copyrect_t0_different_source, dump the differing graphics root CBV bytes and decode view/copy rect constants.",
            "If either side is unresolved, capture descriptor_state/root-parameter replies at the exact CopyRect BinaryReplay event.",
        ],
    }


def sn2_copyrect_pair_analysis(
    *,
    signal_report: dict[str, Any] | None = None,
    trace_path: str | Path | None = None,
    ps_hash: str | None = None,
    max_pairs: int = 12,
) -> dict[str, Any]:
    """Compare left/right CopyRectPS draws and produce concrete live-probe targets."""

    report = signal_report or sn2_copyrect_signal_report(trace_path=trace_path, ps_hash=ps_hash)
    path_text = str(trace_path or report.get("paths", {}).get("trace_path", ""))
    trace_file = Path(path_text) if path_text else None
    trace = _load_json_file(trace_file) if trace_file and trace_file.is_file() else None
    target = report.get("target") or {
        "ps_hash": _norm_hash(ps_hash or SN2_COPYRECT_DEFAULTS["ps_hash"]),
        "ps_crc32": _norm_crc32(SN2_COPYRECT_DEFAULTS["ps_crc32"]),
        "ps_entry": SN2_COPYRECT_DEFAULTS["ps_entry"],
    }

    draws = _recent_draw_events(trace)
    candidates = _copyrect_candidate_records(trace, target)
    candidate_blocks = []
    all_pairs = []
    seen_candidate_keys = set()
    for candidate in candidates:
        psos = _record_pso_values(candidate["record"])
        candidate_key = tuple(sorted(psos))
        if candidate_key in seen_candidate_keys:
            continue
        seen_candidate_keys.add(candidate_key)
        actual = [draw for draw in draws if _event_pso(draw) in psos] if psos else []
        actual.sort(key=lambda item: (_int_or_none(item.get("frame")) or 0, _int_or_none(item.get("draw_index")) or 0))
        pairs = _copyrect_detailed_pairs(actual, max_pairs=max_pairs)
        all_pairs.extend(pairs)
        candidate_blocks.append(
            {
                "candidate": _copyrect_candidate_summary(candidate, actual),
                "left_draw_count": sum(1 for draw in actual if _copyrect_eye(draw) == "left"),
                "right_draw_count": sum(1 for draw in actual if _copyrect_eye(draw) == "right"),
                "paired_count": len(pairs),
                "pairs": pairs,
                "unpaired_draws": _copyrect_unpaired_draws(actual, max_items=max_pairs),
            }
        )

    hook_draw_indices = sorted(
        {
            idx
            for pair in all_pairs
            for idx in (pair.get("left_draw_index"), pair.get("right_draw_index"))
            if idx is not None
        }
    )
    return {
        "ok": bool(report.get("ok") and candidate_blocks),
        "target": target,
        "paths": report.get("paths", {}),
        "summary": {
            "candidate_count": len(candidates),
            "copyrect_actual_draw_count": report.get("copyrect", {}).get("actual_draw_count"),
            "pair_count": len(all_pairs),
            "hook_draw_indices_to_map": hook_draw_indices[: max_pairs * 2],
            "issue_flags": report.get("copyrect", {}).get("issue_flags", {}),
        },
        "candidate_blocks": candidate_blocks[:8],
        "probe_priorities": _copyrect_pair_probe_priorities(candidate_blocks, report),
        "next_mcp_calls": [
            "Map hook draw_index values to BinaryReplay event_index values in the opened Nsight capture.",
            "Run ngfx_sn2_copyrect_live_state_probe for the mapped left and right CopyRect events.",
            "Run ngfx_sn2_copyrect_slot_candidates on each descriptor_state reply to resolve PS t0 and PS s0; saved descriptor_reads are only bound-table scans.",
            "Run ngfx_resource_access_history and ngfx_resource_revision_at_event on the resolved PS t0 source and destination RTV resources.",
            "Dump or inspect graphics root CBV slot 2 for the paired events; that is the likely view/copy-rect constant source.",
        ],
    }


def sn2_copyrect_right_eye_issue_report(
    *,
    signal_report: dict[str, Any] | None = None,
    trace_path: str | Path | None = None,
    ps_hash: str | None = None,
    max_pairs: int = 24,
) -> dict[str, Any]:
    """Return the strongest same-frame right-eye CopyRectPS issue evidence."""

    analysis = sn2_copyrect_pair_analysis(
        signal_report=signal_report,
        trace_path=trace_path,
        ps_hash=ps_hash,
        max_pairs=max_pairs,
    )
    pairs = [pair for block in analysis.get("candidate_blocks", []) for pair in block.get("pairs", [])]
    ranked = sorted(pairs, key=_copyrect_issue_score, reverse=True)
    suspect = ranked[0] if ranked else None
    verdict = "insufficient_same_frame_copyrect_pairs"
    if suspect:
        flags = suspect.get("flags", {})
        if flags.get("same_source_descriptor") and flags.get("graphics_root_cbv_changed"):
            verdict = "right_eye_copyrect_reads_same_t0_descriptor_with_different_rect_constants"
        elif flags.get("same_source_descriptor_candidate") and flags.get("graphics_root_cbv_changed"):
            verdict = "right_eye_copyrect_table_scan_has_same_source_candidate_with_different_rect_constants"
        elif flags.get("same_source") and flags.get("graphics_root_cbv_changed"):
            verdict = "right_eye_copyrect_table_scan_has_shared_source_candidate_with_different_rect_constants"
        elif flags.get("same_source"):
            verdict = "right_eye_copyrect_table_scan_has_shared_source_candidate"
        elif flags.get("graphics_root_cbv_changed") or flags.get("graphics_root_table_hash_changed"):
            verdict = "right_eye_copyrect_binding_or_rect_state_differs"
        elif flags.get("right_descriptor_reads_missing"):
            verdict = "right_eye_copyrect_source_missing_from_saved_trace"
        else:
            verdict = "copyrect_requires_live_resource_lineage"

    return {
        "ok": bool(suspect),
        "verdict": verdict,
        "target": analysis.get("target", {}),
        "paths": analysis.get("paths", {}),
        "suspect_pair": suspect,
        "ranked_pairs": ranked[:max_pairs],
        "summary": {
            **analysis.get("summary", {}),
            "same_frame_pair_count": len(pairs),
            "shared_source_pair_count": sum(1 for pair in pairs if pair.get("flags", {}).get("same_source")),
            "scanned_descriptor_candidate_pair_count": sum(
                1 for pair in pairs if pair.get("flags", {}).get("same_source_descriptor_candidate")
            ),
            "proven_t0_descriptor_pair_count": sum(1 for pair in pairs if pair.get("flags", {}).get("same_source_descriptor")),
            "cbv_changed_pair_count": sum(1 for pair in pairs if pair.get("flags", {}).get("graphics_root_cbv_changed")),
        },
        "descriptor_read_caveat": {
            "saved_trace_descriptor_reads": "bound_descriptor_table_scan",
            "proven_shader_use_requires": "live Nsight descriptor state or shader-use reflection that maps CopyRectPS t0 to the descriptor.",
            "copyrect_shader_use": "CopyRectPS samples PS t0/s0; scanned SRV entries are candidates until t0 is resolved.",
        },
        "interpretation": [
            "CopyRectPS itself is a t0/s0 -> SV_Target copy shader; the bug evidence is in its bound source, destination, or rect/view constants.",
            "Saved hook descriptor_reads are a scan of the bound table, not proof that CopyRectPS sampled every listed SRV.",
            "A same-frame right-eye CopyRect draw whose bound table scan contains the same source candidate as the left-eye copy is suspicious, but PS t0 must be resolved before calling it the sampled source.",
            "Graphics root CBV slot 2 and descriptor-table hash changes are the next constants to dump because they are the likely source of copy/view rect selection.",
        ],
        "next_nsight_mcp_calls": [
            "Create or open a fresh .ngfx-capture for the same repro frame.",
            "Use ngfx_rpc_find_live_events to map suspect_pair.left_event_key and suspect_pair.right_event_key to BinaryReplay event_index values.",
            "Use ngfx_sn2_copyrect_live_state_probe on both event_index values.",
            "Use ngfx_sn2_copyrect_slot_candidates on both descriptor_state replies and require PS t0 before selecting the source resource.",
            "Use ngfx_resource_revision_at_event for the resolved PS t0 source and right destination resources.",
        ],
    }


def sn2_copyrect_source_lineage_report(
    *,
    signal_report: dict[str, Any] | None = None,
    trace_path: str | Path | None = None,
    ps_hash: str | None = None,
    max_pairs: int = 24,
    max_records: int = 64,
) -> dict[str, Any]:
    """Mine saved CopyRect trace lineage without treating table scans as shader-use proof."""

    issue = sn2_copyrect_right_eye_issue_report(
        signal_report=signal_report,
        trace_path=trace_path,
        ps_hash=ps_hash,
        max_pairs=max_pairs,
    )
    path_text = str(trace_path or issue.get("paths", {}).get("trace_path", ""))
    trace_file = Path(path_text) if path_text else None
    trace = _load_json_file(trace_file) if trace_file and trace_file.is_file() else None
    suspect = issue.get("suspect_pair") if isinstance(issue.get("suspect_pair"), dict) else None
    if not isinstance(trace, dict) or not suspect:
        return {
            "ok": False,
            "verdict": issue.get("verdict", "insufficient_trace"),
            "paths": issue.get("paths", {}),
            "error": "source lineage requires a saved trace and a suspect CopyRect pair",
            "issue_report": issue,
        }

    draws = _recent_draw_events(trace)
    left_draw = _find_draw_by_event_key(draws, suspect.get("left_event_key", {}))
    right_draw = _find_draw_by_event_key(draws, suspect.get("right_event_key", {}))
    frame = suspect.get("right_frame", suspect.get("left_frame"))
    resources = _copyrect_lineage_resource_groups(suspect)
    all_resources = sorted({resource for values in resources.values() for resource in values})
    descriptor_evidence = _copyrect_descriptor_evidence_summary(suspect)
    frame_window = _copyrect_same_frame_window(
        draws,
        frame=frame,
        left_draw_index=suspect.get("left_draw_index"),
        right_draw_index=suspect.get("right_draw_index"),
        resources=all_resources,
        max_records=max_records,
    )

    return {
        "ok": True,
        "verdict": issue.get("verdict"),
        "paths": issue.get("paths", {}),
        "target": issue.get("target", {}),
        "suspect_pair": suspect,
        "descriptor_evidence": descriptor_evidence,
        "resource_groups": resources,
        "saved_trace_lineage": {
            "same_frame_draws_touching_resources": _copyrect_records_for_resources(
                draws,
                all_resources,
                frame=frame,
                max_items=max_records,
            ),
            "same_frame_window": frame_window,
            "barriers": _copyrect_records_for_resources(
                _trace_d3d12_list(trace, "recent_barriers"),
                all_resources,
                frame=frame,
                max_items=max_records,
            ),
            "all_frame_barriers": _copyrect_records_for_resources(
                _trace_d3d12_list(trace, "recent_barriers"),
                all_resources,
                max_items=max_records,
            ),
            "render_target_binds": _copyrect_records_for_resources(
                _trace_d3d12_list(trace, "recent_bindings"),
                sorted(set(resources.get("left_targets", []) + resources.get("right_targets", []))),
                frame=frame,
                max_items=max_records,
            ),
            "all_frame_render_target_binds": _copyrect_records_for_resources(
                _trace_d3d12_list(trace, "recent_bindings"),
                sorted(set(resources.get("left_targets", []) + resources.get("right_targets", []))),
                max_items=max_records,
            ),
            "root_binds_for_pair_command_lists": _copyrect_root_binds_for_pair(
                trace,
                left_draw=left_draw,
                right_draw=right_draw,
                frame=frame,
                max_items=max_records,
            ),
            "prior_target_producer_chains": {
                "left": _copyrect_prior_target_chains(left_draw, draws),
                "right": _copyrect_prior_target_chains(right_draw, draws),
            },
        },
        "remaining_gap": {
            "name": "resolve_actual_copyrect_t0_source",
            "why": "The saved descriptor_reads array is a bound-table scan. CopyRectPS samples t0, so the MCP must map PS t0 to one descriptor before it can identify the actual sampled source.",
            "blocked_until": [
                "live descriptor_state for the left/right CopyRect events",
                "root signature descriptor-range metadata for root parameter 0",
                "resource info/history for the resolved PS t0 resource and right destination",
            ],
        },
        "next_nsight_mcp_calls": [
            "ngfx_rpc_find_live_events(...) for suspect_pair.left_event_key and suspect_pair.right_event_key",
            "ngfx_sn2_copyrect_live_state_probe(session_handle=<handle>, event_index=<left CopyRect event>)",
            "ngfx_sn2_copyrect_live_state_probe(session_handle=<handle>, event_index=<right CopyRect event>)",
            "ngfx_sn2_copyrect_slot_candidates(descriptor_state_reply=<each live reply>)",
            "ngfx_resource_revision_at_event(accessor=<resolved PS t0 source>, event_index=<right CopyRect event>)",
        ],
        "runtime_instrumentation_to_add_if_live_state_is_unavailable": [
            "For CopyRectPS draws only, log the descriptor range base shader register/space for each root table.",
            "Log the descriptor entry that maps specifically to PS t0, not the whole scanned table.",
            "Dump graphics root CBV bytes for the differing root slot so the copy/view rect constants can be decoded.",
            "Record source/destination resource desc, subresource, viewport, and scissor for the paired CopyRect draws.",
        ],
    }


def sn2_copyrect_runtime_instrumentation_plan(
    *,
    trace_path: str | Path | None = None,
    signal_report: dict[str, Any] | None = None,
    issue_report: dict[str, Any] | None = None,
    ps_hash: str | None = None,
) -> dict[str, Any]:
    """Return the runtime hook manifest needed when live Nsight t0 state is unavailable."""

    issue = issue_report or sn2_copyrect_right_eye_issue_report(
        signal_report=signal_report,
        trace_path=trace_path,
        ps_hash=ps_hash,
    )
    suspect = issue.get("suspect_pair") if isinstance(issue.get("suspect_pair"), dict) else {}
    return {
        "ok": bool(suspect),
        "target": issue.get("target") or {
            "ps_hash": _norm_hash(ps_hash or SN2_COPYRECT_DEFAULTS["ps_hash"]),
            "ps_crc32": _norm_crc32(SN2_COPYRECT_DEFAULTS["ps_crc32"]),
            "ps_entry": SN2_COPYRECT_DEFAULTS["ps_entry"],
        },
        "suspect_pair": suspect,
        "purpose": "Log the actual CopyRectPS PS t0 descriptor and differing copy/view constants without relying on saved table scans.",
        "event_filter": {
            "pixel_shader_hash": _norm_hash((issue.get("target") or {}).get("ps_hash") or ps_hash or SN2_COPYRECT_DEFAULTS["ps_hash"]),
            "pixel_shader_crc32": _norm_crc32((issue.get("target") or {}).get("ps_crc32") or SN2_COPYRECT_DEFAULTS["ps_crc32"]),
            "entry": SN2_COPYRECT_DEFAULTS["ps_entry"],
            "pipeline_states": sorted({str(item) for item in [suspect.get("pso"), suspect.get("left_event_key", {}).get("pipeline_state"), suspect.get("right_event_key", {}).get("pipeline_state")] if item}),
            "draw_indices": [
                idx
                for idx in (suspect.get("left_draw_index"), suspect.get("right_draw_index"))
                if idx is not None
            ],
            "frames": sorted(
                {
                    str(frame)
                    for frame in (suspect.get("left_frame"), suspect.get("right_frame"))
                    if frame is not None
                }
            ),
        },
        "must_log_per_copyrect_draw": [
            {
                "name": "event_identity",
                "fields": [
                    "frame",
                    "draw_index",
                    "eye_bucket",
                    "command_list",
                    "pipeline_state",
                    "root_signature",
                    "arg0..arg4",
                ],
            },
            {
                "name": "root_signature_descriptor_ranges",
                "fields": [
                    "root_parameter_index",
                    "range_type",
                    "base_shader_register",
                    "register_space",
                    "num_descriptors",
                    "offset_in_descriptors_from_table_start",
                    "shader_visibility",
                ],
                "acceptance": "Must identify which root table entry maps to PS t0/s0.",
            },
            {
                "name": "resolved_copyrect_t0_descriptor",
                "fields": [
                    "root_parameter_index",
                    "descriptor_index",
                    "gpu_descriptor_handle",
                    "cpu_descriptor_handle_or_source_cpu",
                    "srv_desc",
                    "resource_pointer",
                    "resource_debug_name",
                    "resource_desc",
                    "resource_current_state_if_known",
                ],
                "acceptance": "This is the actual sampled CopyRectPS t0 descriptor, not a scan of the whole bound table.",
            },
            {
                "name": "copyrect_sampler_s0",
                "fields": [
                    "root_parameter_index",
                    "descriptor_index",
                    "sampler_desc",
                ],
            },
            {
                "name": "graphics_root_cbv_bytes",
                "fields": [
                    "slot",
                    "gpu_virtual_address",
                    "byte_count",
                    "first_256_bytes_hex",
                    "u32_words",
                    "float_words",
                    "hash64",
                ],
                "slots_to_prioritize": sorted((suspect.get("graphics_root_cbvs") or {}).get("left", {}).keys()),
                "acceptance": "Left/right differing slots must have byte dumps so view/copy rect constants can be decoded.",
            },
            {
                "name": "output_state",
                "fields": [
                    "viewport",
                    "scissor_rect",
                    "OMSetRenderTargets RTV descriptors",
                    "RTV resources and descs",
                    "DSV resource if bound",
                    "resource barriers for source and destination around the draw",
                ],
            },
            {
                "name": "descriptor_provenance",
                "fields": [
                    "CreateShaderResourceView calls for the t0 resource",
                    "CopyDescriptors/CopyDescriptorsSimple writes covering the t0 descriptor",
                    "SetDescriptorHeaps",
                    "SetGraphicsRootDescriptorTable for the t0 root parameter",
                    "descriptor heap base/increment size",
                ],
            },
        ],
        "minimal_json_record_schema": {
            "event": "CopyRectPSResolved",
            "frame": 0,
            "draw_index": 0,
            "eye_bucket": 0,
            "pso": "0x0",
            "root_signature": "0x0",
            "t0": {
                "root_parameter": 0,
                "descriptor_index": 0,
                "cpu": "0x0",
                "gpu": "0x0",
                "resource": "0x0",
                "resource_desc": {},
                "srv_desc": {},
                "proven_shader_register": 0,
                "register_space": 0,
            },
            "s0": {"root_parameter": 0, "descriptor_index": 0, "sampler_desc": {}},
            "cbv_slots": [{"slot": 2, "gpu_va": "0x0", "bytes_hex": "", "u32": [], "f32": [], "hash64": "0x0"}],
            "viewport": {},
            "scissor": {},
            "rtv0": {"descriptor": "0x0", "resource": "0x0", "resource_desc": {}},
        },
        "decision_rule_after_logging": [
            "If left/right CopyRectPS t0 resource or SRV desc is identical, fix right-eye source descriptor routing or the producer of that resource.",
            "If left/right CopyRectPS t0 differs, compare CBV bytes, viewport/scissor, and RTV state; fix right-eye copy/view rect or destination routing.",
            "If t0 differs and CBV/output state also matches, inspect the right t0 producer chain before CopyRect.",
        ],
    }


def pair_eye_events(
    db_path: Path,
    *,
    render_width: float | None = None,
    right_half_min_x: float | None = None,
    limit: int = 4000,
) -> dict[str, Any]:
    idx = shader_triage.eye_event_index(
        db_path,
        render_width=render_width,
        right_half_min_x=right_half_min_x,
        limit=limit,
    )
    left = [e for e in idx["events"] if e["eye"] == "left"]
    right = [e for e in idx["events"] if e["eye"] == "right"]
    right_buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in right:
        right_buckets[(event["kind"], event["function_name"])].append(event)

    pairs: list[dict[str, Any]] = []
    missing_right: list[dict[str, Any]] = []
    for event in left:
        key = (event["kind"], event["function_name"])
        candidates = right_buckets.get(key, [])
        if candidates:
            match = candidates.pop(0)
            pairs.append({"left": event, "right": match, "delta_events": match["event_index"] - event["event_index"]})
        else:
            missing_right.append(event)
    remaining_right = [event for bucket in right_buckets.values() for event in bucket]
    return {
        "ok": True,
        "summary": idx["summary"],
        "pair_count": len(pairs),
        "pairs": pairs[:1000],
        "missing_right": missing_right[:500],
        "right_only": remaining_right[:500],
        "notes": idx["notes"],
    }


def resolve_shader_slots(
    db_path: Path,
    event_index: int,
    *,
    slots: list[str],
    slot_map: dict[str, Any] | None = None,
    lookback: int = 500,
) -> dict[str, Any]:
    state = shader_triage.event_state(db_path, event_index, lookback=lookback)
    if not state.get("ok"):
        return state
    bindings = state.get("bindings", {})
    root_params = bindings.get("d3d12", {}).get("root_params", {})
    resolved: dict[str, Any] = {}
    blockers: list[str] = []
    for slot in slots:
        spec = (slot_map or {}).get(slot, {})
        root_param = str(spec.get("root_param_index", spec.get("root_param", "")))
        descriptor_offset = spec.get("descriptor_offset")
        if root_param and root_param in root_params:
            resolved[slot] = {
                "status": "mapped_by_slot_map",
                "root_param_index": root_param,
                "descriptor_offset": descriptor_offset,
                "binding": root_params[root_param],
            }
        else:
            resolved[slot] = {
                "status": "unresolved",
                "reason": "Need root-signature register space mapping or frame-debugger descriptor-state RPC.",
                "available_root_params": root_params,
            }
            blockers.append(f"{slot}: no slot_map root_param_index and no automatic root-signature register mapping")
    return {
        "ok": True,
        "event_index": event_index,
        "bound_pipeline": state.get("bound_pipeline"),
        "slots": resolved,
        "blockers": blockers,
        "next_tool": "ngfx_frame_debugger_rpc_schema + ngfx_rpc_call_binary_replay(MethodDescriptorStateRequest)",
    }


def descriptor_resource_candidates(
    descriptor_state_reply: dict[str, Any],
    *,
    slots: list[str],
    slot_map: dict[str, Any] | None = None,
    max_candidates_per_slot: int = 25,
) -> dict[str, Any]:
    """Map shader slots to likely resources from a descriptor-state RPC reply.

    Nsight's private descriptor-state protobuf is version-sensitive. This
    resolver therefore works on the JSON-shaped reply and scores descriptor
    nodes by stable concepts: shader register, register space, root parameter,
    descriptor index/offset, and literal slot names.
    """
    reply = descriptor_state_reply.get("reply", descriptor_state_reply)
    nodes = list(_walk_descriptor_nodes(reply))
    out: dict[str, Any] = {}
    for slot in slots:
        spec = (slot_map or {}).get(slot, {})
        scored = []
        for path, node in nodes:
            score, reasons = _score_descriptor_node(slot, spec, node)
            if score <= 0:
                continue
            scored.append(
                {
                    "score": score,
                    "path": path,
                    "reasons": reasons,
                    "resources": _extract_resource_handles(node),
                    "descriptor": node,
                }
            )
        scored.sort(key=lambda item: item["score"], reverse=True)
        out[slot] = {
            "status": "candidates" if scored else "unresolved",
            "candidate_count": len(scored),
            "candidates": scored[:max_candidates_per_slot],
        }
    return {
        "ok": True,
        "slots": out,
        "notes": [
            "Use this with ngfx_rpc_call_binary_replay(MethodDescriptorStateRequest) output.",
            "Candidates are scored because protobuf field names vary across Nsight builds.",
        ],
    }


def roi_grid_points(roi: dict[str, int], *, grid_x: int = 8, grid_y: int = 8) -> list[dict[str, int]]:
    x0 = int(roi.get("x", roi.get("left", 0)))
    y0 = int(roi.get("y", roi.get("top", 0)))
    w = int(roi.get("w", roi.get("width", 1)))
    h = int(roi.get("h", roi.get("height", 1)))
    points = []
    for gy in range(max(1, grid_y)):
        for gx in range(max(1, grid_x)):
            x = x0 + min(w - 1, round((gx + 0.5) * w / max(1, grid_x)))
            y = y0 + min(h - 1, round((gy + 0.5) * h / max(1, grid_y)))
            points.append({"x": int(x), "y": int(y)})
    return points


def pixel_history_grid_requests(
    *,
    image_accessor: int,
    roi: dict[str, int],
    grid_x: int = 8,
    grid_y: int = 8,
    image_misc: int = 0,
    image_view_accessor: int | None = None,
    image_view_misc: int = 0,
    aspect: int = 1,
    mip_level: int = 0,
    array_layer: int = 0,
    slice_index: int = 0,
) -> dict[str, Any]:
    reg = proto_descriptors.get_registry()
    requests = []
    for point in roi_grid_points(roi, grid_x=grid_x, grid_y=grid_y):
        req = rpc_client.build_pixel_history_request(
            reg,
            image_accessor=image_accessor,
            image_misc=image_misc,
            image_view_accessor=image_view_accessor,
            image_view_misc=image_view_misc,
            x=point["x"],
            y=point["y"],
            aspect=aspect,
            mip_level=mip_level,
            array_layer=array_layer,
            slice_index=slice_index,
        )
        requests.append(
            {
                "pixel": point,
                "method": rpc_client.RpcClient.METHOD_PIXEL_HISTORY,
                "request_fqn": "NV.Pylon.Replay.PbPixelHistoryRequest",
                "reply_fqn": "NV.Pylon.Replay.PbPixelHistoryReply",
                "body_hex": req.SerializeToString().hex(),
                "request": rpc_client.protobuf_to_dict(req),
            }
        )
    return {"ok": True, "roi": roi, "grid": {"x": grid_x, "y": grid_y}, "requests": requests}


def resource_producer_graph(
    db_path: Path,
    *,
    resources: list[str],
    event_index: int | None = None,
    depth: int = 2,
    window: int | None = 1000,
) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    queue = [(r, 0) for r in resources]
    seen: set[tuple[str, int]] = set()
    while queue:
        resource, level = queue.pop(0)
        if (resource, level) in seen or level > depth:
            continue
        seen.add((resource, level))
        lineage = shader_triage.trace_resource_lineage(db_path, resource, event_index=event_index, window=window)
        nodes[resource] = {
            "resource": resource,
            "level": level,
            "mention_count": lineage.get("mention_count", 0),
            "mentions_by_role": lineage.get("mentions_by_role", {}),
            "last_relevant_before_event": lineage.get("last_relevant_before_event"),
        }
        writer = lineage.get("last_relevant_before_event")
        if writer and level < depth:
            for dep in _extract_symbols(writer.get("raw_args", "")):
                if dep != resource:
                    edges.append({"from": dep, "to": resource, "via_event": writer.get("event_index")})
                    queue.append((dep, level + 1))
    return {"ok": True, "root_resources": resources, "event_index": event_index, "nodes": nodes, "edges": edges}


def import_uevr_trace(trace_path: Path, *, db_path: Path | None = None) -> dict[str, Any]:
    events = _read_trace_events(trace_path)
    if db_path:
        _write_trace_db(db_path, events)
    hist = Counter(str(e.get("function") or e.get("event") or e.get("name") or "unknown") for e in events)
    eye_hist = Counter(str(e.get("eye", "unknown")) for e in events)
    pso_hist = Counter(str(e.get("pso", e.get("pipeline_state", "unknown"))) for e in events)
    return {
        "ok": True,
        "trace_path": str(trace_path),
        "db_path": str(db_path) if db_path else None,
        "event_count": len(events),
        "function_histogram": dict(hist.most_common(50)),
        "eye_histogram": dict(eye_hist),
        "pso_histogram": dict(pso_hist.most_common(50)),
        "events_preview": events[:20],
    }


def pso_rehydration_plan(
    *,
    suspect_pso: str,
    patched_shader_path: str,
    output_dir: str | None = None,
) -> dict[str, Any]:
    header = f"""// Generated PSO rehydration plan for {suspect_pso}
// Fill the captured D3D12_GRAPHICS_PIPELINE_STATE_DESC from Nsight C++ Capture
// or runtime logging, replace PS bytecode with {patched_shader_path}, then call
// ID3D12Device::CreateGraphicsPipelineState.
"""
    source = f"""#include <d3d12.h>
#include <wrl/client.h>

using Microsoft::WRL::ComPtr;

HRESULT CreatePatched_{_safe_ident(suspect_pso)}(
    ID3D12Device* device,
    const D3D12_GRAPHICS_PIPELINE_STATE_DESC& originalDesc,
    const void* patchedShader,
    SIZE_T patchedShaderSize,
    ID3D12PipelineState** outPso) {{
    D3D12_GRAPHICS_PIPELINE_STATE_DESC desc = originalDesc;
    desc.PS.pShaderBytecode = patchedShader;
    desc.PS.BytecodeLength = patchedShaderSize;
    return device->CreateGraphicsPipelineState(&desc, IID_PPV_ARGS(outPso));
}}
"""
    files = {}
    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        h = out / "ngfx_pso_rehydrate.h"
        cpp = out / "ngfx_pso_rehydrate.cpp"
        h.write_text(header, encoding="utf-8")
        cpp.write_text(source, encoding="utf-8")
        files = {"header": str(h), "source": str(cpp)}
    return {
        "ok": True,
        "suspect_pso": suspect_pso,
        "patched_shader_path": patched_shader_path,
        "required_inputs": [
            "original PSO desc or equivalent state",
            "root signature pointer",
            "RTV/DSV formats",
            "blend/raster/depth/input-layout state",
            "patched shader bytecode",
        ],
        "snippets": {"header": header, "source": source},
        "files": files,
    }


def shader_probe_execution_plan(
    *,
    suspect_pso: str,
    probe_name: str,
    launch_script: str | None = None,
    roi: dict[str, int] | None = None,
) -> dict[str, Any]:
    return {
        "ok": True,
        "suspect_pso": suspect_pso,
        "probe_name": probe_name,
        "launch_script": launch_script or SN2_DEFAULTS["launch_script"],
        "roi": roi,
        "steps": [
            "Generate or select patched probe shader bytecode.",
            "Create patched PSO with ngfx_pso_rehydration_plan output.",
            "Enable draw-time PSO swap for right eye only.",
            "Launch repro and capture HDR/float ROI output.",
            "Score probe output with ngfx_diff_hdr_roi.",
            "Record whether probe explains the right-eye artifact.",
        ],
    }


def diff_hdr_roi(
    before_path: Path,
    after_path: Path,
    *,
    roi: dict[str, int] | None = None,
    width: int | None = None,
    height: int | None = None,
    channels: int = 4,
    fmt: str = "auto",
) -> dict[str, Any]:
    before, bw, bh, bc = _load_float_image(before_path, width=width, height=height, channels=channels, fmt=fmt)
    after, aw, ah, ac = _load_float_image(after_path, width=width, height=height, channels=channels, fmt=fmt)
    if (bw, bh, bc) != (aw, ah, ac):
        raise ValueError(f"image shapes differ: {(bw, bh, bc)} vs {(aw, ah, ac)}")
    x0 = int((roi or {}).get("x", 0))
    y0 = int((roi or {}).get("y", 0))
    rw = int((roi or {}).get("w", (roi or {}).get("width", bw - x0)))
    rh = int((roi or {}).get("h", (roi or {}).get("height", bh - y0)))
    diffs = []
    luminance_before = []
    luminance_after = []
    for y in range(max(0, y0), min(bh, y0 + rh)):
        for x in range(max(0, x0), min(bw, x0 + rw)):
            i = (y * bw + x) * bc
            b = before[i:i + bc]
            a = after[i:i + ac]
            d = math.sqrt(sum((a[c] - b[c]) ** 2 for c in range(min(3, bc))))
            diffs.append(d)
            luminance_before.append(_luma(b))
            luminance_after.append(_luma(a))
    return {
        "ok": True,
        "shape": {"width": bw, "height": bh, "channels": bc},
        "roi": {"x": x0, "y": y0, "w": rw, "h": rh},
        "pixel_count": len(diffs),
        "mean_rgb_delta": sum(diffs) / len(diffs) if diffs else 0.0,
        "max_rgb_delta": max(diffs) if diffs else 0.0,
        "mean_luma_before": sum(luminance_before) / len(luminance_before) if luminance_before else 0.0,
        "mean_luma_after": sum(luminance_after) / len(luminance_after) if luminance_after else 0.0,
    }


def autofix_loop_plan(*, max_trials: int = 12) -> dict[str, Any]:
    return {
        "ok": True,
        "max_trials": max_trials,
        "loop": [
            "Run ngfx_sn2_fog_artifacts and ngfx_sn2_fog_signal_report to establish the current clean r.Fog oracle.",
            "Run ngfx_sn2_repro_run(dry_run=false) and collect Graphics Capture plus runtime hook traces.",
            "Open a live frame-debugger RPC session for pixel history, resource revisions, and descriptor/resource state.",
            "Target the lead fog PSO 0x221FA167CE0 with PS 9a29f7f299902d2c and GS 399d1b7f3e1e20bd; do not spend trials on the obsolete pso3069 path.",
            "Use ngfx_trace_roi_history and ngfx_resource_revision_at_event around the 77 lead draws and downstream right-eye consumers.",
            "Choose one GS/PS hypothesis from ngfx_sn2_fog_fix_plan and generate a shader probe or draw-time PSO swap.",
            "Build UEVR/hook, run repro, score HDR ROI.",
            "Validate with ngfx_sn2_fog_signal_report plus ngfx_validate_fix_claim before accepting.",
        ],
        "stop_conditions": [
            "right-eye ROI improved over threshold",
            "left-eye ROI changed less than threshold",
            "same result repeats in at least two runs",
            "first bad event/resource explanation is present",
        ],
    }


def validate_fix_claim(
    *,
    before_score: float,
    after_score: float,
    left_eye_delta: float,
    repeated_runs: int,
    has_first_bad_event: bool,
    has_resource_or_shader_cause: bool,
    min_improvement: float = 0.25,
    max_left_delta: float = 0.03,
) -> dict[str, Any]:
    improvement = before_score - after_score
    relative = improvement / before_score if before_score else 0.0
    checks = {
        "right_eye_improved": relative >= min_improvement,
        "left_eye_unchanged": abs(left_eye_delta) <= max_left_delta,
        "repeated": repeated_runs >= 2,
        "first_bad_event_known": has_first_bad_event,
        "cause_known": has_resource_or_shader_cause,
    }
    return {
        "ok": all(checks.values()),
        "checks": checks,
        "before_score": before_score,
        "after_score": after_score,
        "absolute_improvement": improvement,
        "relative_improvement": relative,
        "decision": "accept" if all(checks.values()) else "reject",
    }


def _latest_matching_file(root: Path, pattern: str) -> Path | None:
    if not root.is_dir():
        return None
    matches = [p for p in root.glob(pattern) if p.is_file()]
    if not matches:
        return None
    return max(matches, key=lambda p: (p.stat().st_mtime, p.name))


def _latest_recursive_matching_file(root: Path, pattern: str) -> Path | None:
    if not root.is_dir():
        return None
    matches = [p for p in root.rglob(pattern) if p.is_file()]
    if not matches:
        return None
    return max(matches, key=lambda p: (p.stat().st_mtime, p.name))


def _file_contains_text(path: Path, needle: str) -> bool:
    if not needle or not path.is_file():
        return False
    try:
        return needle.lower() in path.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False


def _latest_file_containing_text(root: Path, needle: str, *, pattern: str = "*.json", max_scan: int = 400) -> Path | None:
    if not root.is_dir() or not needle:
        return None
    files = sorted(
        (p for p in root.rglob(pattern) if p.is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for path in files[:max_scan]:
        if _file_contains_text(path, needle):
            return path
    return None


def _load_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def _sn2_fog_trace_summary(trace: dict[str, Any] | None, *, label: str, target: dict[str, Any]) -> dict[str, Any]:
    lead_pso = target["lead_pso"]
    draws = _recent_draw_events(trace)
    actual_draws = [d for d in draws if _event_pso(d) == lead_pso]
    prior_producer_draws = [d for d in draws if _norm_hex(d.get("prior_rtv0_producer_pso")) == lead_pso]
    draw_indices = [_int_or_none(d.get("draw_index", d.get("event_index", d.get("idx")))) for d in actual_draws]
    draw_indices = [i for i in draw_indices if i is not None]
    ranked_candidate = _find_pso_record(_ranked_candidates(trace), lead_pso=lead_pso)
    shader_aggregate = _find_pso_record(_shader_aggregates(trace), lead_pso=lead_pso)
    distinct_pair = _find_pso_record(_distinct_shader_pairs(trace), lead_pso=lead_pso)
    records = [ranked_candidate, shader_aggregate, distinct_pair]
    return {
        "label": label,
        "recent_draw_event_count": len(draws),
        "actual_draw_count": len(actual_draws),
        "eye_bucket_histogram": dict(Counter(_eye_bucket_key(d.get("eye_bucket", d.get("eye", "unknown"))) for d in actual_draws)),
        "frame_histogram": dict(Counter(str(d.get("frame", "unknown")) for d in actual_draws)),
        "kind_histogram": dict(Counter(str(d.get("kind", d.get("event", "unknown"))) for d in actual_draws)),
        "draw_index_range": {
            "min": min(draw_indices) if draw_indices else None,
            "max": max(draw_indices) if draw_indices else None,
        },
        "draw_samples": _sample_events(actual_draws),
        "prior_rtv0_producer_pso_count": len(prior_producer_draws),
        "prior_rtv0_producer_eye_histogram": dict(
            Counter(_eye_bucket_key(d.get("eye_bucket", d.get("eye", "unknown"))) for d in prior_producer_draws)
        ),
        "ranked_candidate": _compact_record(ranked_candidate),
        "shader_aggregate": _compact_record(shader_aggregate),
        "distinct_shader_pair": _compact_record(distinct_pair),
        "stage_hash_evidence": [_shader_stage_facts(record) for record in records if record],
        "stage_hash_match": {
            "ps": any(_record_stage_hash(record, "ps") == target["ps_hash"] for record in records if record),
            "gs": any(_record_stage_hash(record, "gs") == target["gs_hash"] for record in records if record),
        },
    }


def _sn2_copyrect_trace_summary(trace: dict[str, Any] | None, *, target: dict[str, Any]) -> dict[str, Any]:
    draws = _recent_draw_events(trace)
    candidates = _copyrect_candidate_records(trace, target)
    candidate_summaries = []
    matching_draws: list[dict[str, Any]] = []
    seen_draws = set()
    for candidate in candidates:
        psos = _record_pso_values(candidate["record"])
        actual = [draw for draw in draws if _event_pso(draw) in psos] if psos else []
        for draw in actual:
            key = (
                draw.get("frame"),
                draw.get("draw_index", draw.get("event_index", draw.get("idx"))),
                _event_pso(draw),
            )
            if key not in seen_draws:
                seen_draws.add(key)
                matching_draws.append(draw)
        candidate_summaries.append(_copyrect_candidate_summary(candidate, actual))

    matching_draws.sort(key=lambda item: (_int_or_none(item.get("frame")) or 0, _int_or_none(item.get("draw_index")) or 0))
    representative = _copyrect_representative_draw(matching_draws, candidates)
    source_reads = [read for draw in matching_draws for read in _copyrect_source_reads(draw)]
    target_writes = [write for draw in matching_draws for write in _copyrect_target_writes(draw)]
    source_by_eye = _copyrect_resource_histogram_by_eye(matching_draws, source=True)
    target_by_eye = _copyrect_resource_histogram_by_eye(matching_draws, source=False)
    return {
        "recent_draw_event_count": len(draws),
        "candidate_count": len(candidates),
        "primary_candidate": candidate_summaries[0] if candidate_summaries else None,
        "candidates": candidate_summaries[:12],
        "actual_draw_count": len(matching_draws),
        "eye_bucket_histogram": dict(Counter(_eye_bucket_key(d.get("eye_bucket", d.get("eye", "unknown"))) for d in matching_draws)),
        "eye_histogram": dict(Counter(_copyrect_eye(d) for d in matching_draws)),
        "draw_index_range": _draw_index_range(matching_draws),
        "representative_draw": _compact_copyrect_draw(representative) if representative else None,
        "draw_samples": [_compact_copyrect_draw(draw) for draw in _sample_raw_events(matching_draws)],
        "source_read_count": len(source_reads),
        "target_write_count": len(target_writes),
        "source_resources_by_eye": source_by_eye,
        "target_resources_by_eye": target_by_eye,
        "source_producers": _copyrect_source_producer_summary(matching_draws),
        "paired_draws": _copyrect_pair_draws(matching_draws),
        "issue_flags": _copyrect_issue_flags(matching_draws, source_by_eye),
    }


def _copyrect_candidate_records(trace: dict[str, Any] | None, target: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    sources = [
        ("ranked_candidate", _ranked_candidates(trace)),
        ("shader_aggregate", _shader_aggregates(trace)),
        ("distinct_shader_pair", _distinct_shader_pairs(trace)),
    ]
    seen = set()
    for source_name, source_records in sources:
        for index, record in enumerate(source_records):
            if not _record_matches_copyrect(record, target):
                continue
            pso_key = tuple(sorted(_record_pso_values(record)))
            key = (source_name, index, pso_key, _record_stage_hash(record, "ps"), _record_stage_crc32(record, "ps"))
            if key in seen:
                continue
            seen.add(key)
            records.append({"source": source_name, "index": index, "record": record})
    records.sort(key=lambda item: (0 if item["source"] == "ranked_candidate" else 1, item["index"]))
    return records


def _record_matches_copyrect(record: dict[str, Any], target: dict[str, Any]) -> bool:
    target_hash = _norm_hash(target.get("ps_hash"))
    target_crc = _norm_crc32(target.get("ps_crc32"))
    record_hash = _record_stage_hash(record, "ps")
    record_crc = _norm_crc32(_record_stage_crc32(record, "ps"))
    return bool((target_hash and record_hash == target_hash) or (target_crc and record_crc == target_crc))


def _copyrect_candidate_summary(candidate: dict[str, Any], actual_draws: list[dict[str, Any]]) -> dict[str, Any]:
    record = candidate["record"]
    compact = _compact_record(record) or {}
    psos = sorted(_record_pso_values(record))
    compact.update(
        {
            "source": candidate["source"],
            "rank_index": candidate["index"],
            "pipeline_states": psos,
            "pipeline_state": compact.get("pipeline_state") or (psos[0] if psos else None),
            "actual_draw_count": len(actual_draws),
            "eye_bucket_histogram": dict(Counter(_eye_bucket_key(d.get("eye_bucket", d.get("eye", "unknown"))) for d in actual_draws)),
            "draw_index_range": _draw_index_range(actual_draws),
        }
    )
    return compact


def _copyrect_representative_draw(draws: list[dict[str, Any]], candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    if draws:
        right = [draw for draw in draws if _copyrect_eye(draw) == "right"]
        return right[0] if right else draws[0]
    for candidate in candidates:
        reps = candidate["record"].get("representative_draws")
        if isinstance(reps, list):
            for item in reps:
                if isinstance(item, dict):
                    return item
    return None


def _copyrect_source_reads(event: dict[str, Any]) -> list[dict[str, Any]]:
    reads = event.get("descriptor_reads")
    if not isinstance(reads, list):
        return []
    out = []
    for read in reads:
        if not isinstance(read, dict):
            continue
        dtype = str(read.get("descriptor_type", read.get("type", ""))).lower()
        if dtype and "srv" not in dtype and "texture" not in dtype:
            continue
        if not _resource_key(read):
            continue
        keep = {
            "descriptor_type",
            "root_parameter",
            "descriptor_index",
            "descriptor_cpu",
            "descriptor_source_cpu",
            "stage",
            "shader_stage",
            "shaderRegister",
            "shader_register",
            "register",
            "registerSpace",
            "register_space",
            "space",
            "bind_point",
            "resource",
            "name",
            "producer_draw",
            "producer_frame",
            "producer_eye_bucket",
            "producer_kind",
            "producer_pso",
            "producer_target_index",
        }
        out.append({key: read.get(key) for key in keep if key in read})
    return out


def _copyrect_target_writes(event: dict[str, Any]) -> list[dict[str, Any]]:
    writes = event.get("render_target_writes")
    out = []
    if isinstance(writes, list):
        for write in writes:
            if isinstance(write, dict):
                out.append(
                    {
                        key: write.get(key)
                        for key in (
                            "descriptor",
                            "resource",
                            "name",
                            "target_index",
                            "prior_producer_draw",
                            "prior_producer_eye_bucket",
                            "prior_producer_pso",
                            "prior_producer_kind",
                        )
                        if key in write
                    }
                )
    if not out and (event.get("rtv0_resource") or event.get("rtv0")):
        out.append({"resource": event.get("rtv0_resource"), "descriptor": event.get("rtv0"), "target_index": 0})
    return out


def _compact_copyrect_draw(event: dict[str, Any]) -> dict[str, Any]:
    compact = _compact_event(event)
    compact["eye"] = _copyrect_eye(event)
    compact["source_reads"] = _truncate_value(_copyrect_source_reads(event), max_list=8)
    compact["target_writes"] = _truncate_value(_copyrect_target_writes(event), max_list=4)
    if "rtv0_resource" in event:
        compact["rtv0_resource"] = event["rtv0_resource"]
    if "graphics_root_cbvs" in event:
        compact["graphics_root_cbvs"] = _truncate_value(event.get("graphics_root_cbvs"), max_list=16)
    return compact


def _copyrect_resource_histogram_by_eye(draws: list[dict[str, Any]], *, source: bool) -> dict[str, dict[str, int]]:
    hist: dict[str, Counter[str]] = defaultdict(Counter)
    for draw in draws:
        eye = _copyrect_eye(draw)
        items = _copyrect_source_reads(draw) if source else _copyrect_target_writes(draw)
        for item in items:
            key = _resource_key(item)
            if key:
                hist[eye][key] += 1
    return {eye: dict(counter) for eye, counter in hist.items()}


def _copyrect_source_producer_summary(draws: list[dict[str, Any]]) -> list[dict[str, Any]]:
    producers = []
    seen = set()
    for draw in draws:
        draw_eye = _copyrect_eye(draw)
        for read in _copyrect_source_reads(draw):
            producer_draw = _int_or_none(read.get("producer_draw"))
            producer_pso = _norm_hex(read.get("producer_pso"))
            if not producer_draw and not producer_pso:
                continue
            key = (draw.get("draw_index"), _resource_key(read), producer_draw, producer_pso)
            if key in seen:
                continue
            seen.add(key)
            producers.append(
                {
                    "copy_draw_index": draw.get("draw_index", draw.get("event_index")),
                    "copy_eye": draw_eye,
                    "source_resource": _resource_key(read),
                    "producer_draw": producer_draw,
                    "producer_frame": read.get("producer_frame"),
                    "producer_eye_bucket": read.get("producer_eye_bucket"),
                    "producer_eye": _copyrect_eye_from_value(read.get("producer_eye_bucket")),
                    "producer_kind": read.get("producer_kind"),
                    "producer_pso": producer_pso,
                    "producer_target_index": read.get("producer_target_index"),
                }
            )
    return producers[:100]


def _copyrect_pair_draws(draws: list[dict[str, Any]], max_pairs: int = 24) -> list[dict[str, Any]]:
    left = [draw for draw in draws if _copyrect_eye(draw) == "left"]
    right = [draw for draw in draws if _copyrect_eye(draw) == "right"]
    pairs = []
    for ldraw, rdraw in zip(left, right, strict=False):
        lsrc = [_resource_key(read) for read in _copyrect_source_reads(ldraw) if _resource_key(read)]
        rsrc = [_resource_key(read) for read in _copyrect_source_reads(rdraw) if _resource_key(read)]
        ldst = [_resource_key(write) for write in _copyrect_target_writes(ldraw) if _resource_key(write)]
        rdst = [_resource_key(write) for write in _copyrect_target_writes(rdraw) if _resource_key(write)]
        pairs.append(
            {
                "left_draw_index": ldraw.get("draw_index", ldraw.get("event_index")),
                "right_draw_index": rdraw.get("draw_index", rdraw.get("event_index")),
                "left_sources": lsrc,
                "right_sources": rsrc,
                "left_targets": ldst,
                "right_targets": rdst,
                "same_source": bool(set(lsrc) & set(rsrc)) if lsrc and rsrc else False,
                "same_target": bool(set(ldst) & set(rdst)) if ldst and rdst else False,
            }
        )
        if len(pairs) >= max_pairs:
            break
    return pairs


def _copyrect_detailed_pairs(draws: list[dict[str, Any]], *, max_pairs: int) -> list[dict[str, Any]]:
    by_pso_frame: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = defaultdict(lambda: {"left": [], "right": []})
    for draw in draws:
        pso = _event_pso(draw) or "unknown"
        frame = _copyrect_frame_key(draw)
        eye = _copyrect_eye(draw)
        if eye in {"left", "right"}:
            by_pso_frame[(pso, frame)][eye].append(draw)
    pairs = []
    for (pso, _frame), bucket in sorted(by_pso_frame.items(), key=lambda item: (item[0][0], _frame_sort_key(item[0][1]))):
        left = sorted(bucket["left"], key=lambda item: _int_or_none(item.get("draw_index")) or 0)
        right = sorted(bucket["right"], key=lambda item: _int_or_none(item.get("draw_index")) or 0)
        for ldraw, rdraw in zip(left, right, strict=False):
            pairs.append(_copyrect_pair_detail(ldraw, rdraw, pso=pso))
            if len(pairs) >= max_pairs:
                return pairs
    return pairs


def _copyrect_unpaired_draws(draws: list[dict[str, Any]], *, max_items: int) -> list[dict[str, Any]]:
    out = []
    by_pso_frame: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = defaultdict(lambda: {"left": [], "right": []})
    for draw in draws:
        pso = _event_pso(draw) or "unknown"
        frame = _copyrect_frame_key(draw)
        eye = _copyrect_eye(draw)
        if eye in {"left", "right"}:
            by_pso_frame[(pso, frame)][eye].append(draw)
    for (pso, frame), bucket in sorted(by_pso_frame.items(), key=lambda item: (item[0][0], _frame_sort_key(item[0][1]))):
        left = sorted(bucket["left"], key=lambda item: _int_or_none(item.get("draw_index")) or 0)
        right = sorted(bucket["right"], key=lambda item: _int_or_none(item.get("draw_index")) or 0)
        longer = left if len(left) > len(right) else right
        side = "left" if len(left) > len(right) else "right"
        for draw in longer[min(len(left), len(right)) :]:
            out.append(
                {
                    "pso": pso,
                    "frame": frame,
                    "side": side,
                    "draw": _compact_copyrect_draw(draw),
                }
            )
            if len(out) >= max_items:
                return out
    return out


def _copyrect_pair_detail(left: dict[str, Any], right: dict[str, Any], *, pso: str) -> dict[str, Any]:
    left_sources = [_resource_key(read) for read in _copyrect_source_reads(left) if _resource_key(read)]
    right_sources = [_resource_key(read) for read in _copyrect_source_reads(right) if _resource_key(read)]
    left_targets = [_resource_key(write) for write in _copyrect_target_writes(left) if _resource_key(write)]
    right_targets = [_resource_key(write) for write in _copyrect_target_writes(right) if _resource_key(write)]
    source_overlap = sorted(set(left_sources) & set(right_sources))
    target_overlap = sorted(set(left_targets) & set(right_targets))
    left_tables = _root_slot_values(left, "graphics_root_descriptor_tables")
    right_tables = _root_slot_values(right, "graphics_root_descriptor_tables")
    left_table_hash = _root_slot_values(left, "graphics_root_descriptor_table_resource_hash", value_key="hash")
    right_table_hash = _root_slot_values(right, "graphics_root_descriptor_table_resource_hash", value_key="hash")
    left_cbvs = _root_slot_values(left, "graphics_root_cbvs")
    right_cbvs = _root_slot_values(right, "graphics_root_cbvs")
    left_descriptor_candidates = _descriptor_index_candidates(left)
    right_descriptor_candidates = _descriptor_index_candidates(right)
    descriptor_overlap = _descriptor_candidate_overlap(left_descriptor_candidates, right_descriptor_candidates)
    detail = {
        "pso": pso,
        "left_event_key": _copyrect_event_key(left, pso=pso),
        "right_event_key": _copyrect_event_key(right, pso=pso),
        "left_draw_index": left.get("draw_index", left.get("event_index")),
        "right_draw_index": right.get("draw_index", right.get("event_index")),
        "left_frame": left.get("frame"),
        "right_frame": right.get("frame"),
        "draw_index_delta": (_int_or_none(right.get("draw_index")) or 0) - (_int_or_none(left.get("draw_index")) or 0),
        "root_signature_same": left.get("root_signature") == right.get("root_signature"),
        "left_sources": left_sources,
        "right_sources": right_sources,
        "source_overlap": source_overlap,
        "source_only_left": sorted(set(left_sources) - set(right_sources)),
        "source_only_right": sorted(set(right_sources) - set(left_sources)),
        "left_targets": left_targets,
        "right_targets": right_targets,
        "target_overlap": target_overlap,
        "graphics_root_tables": {"left": left_tables, "right": right_tables, "same": left_tables == right_tables},
        "graphics_root_table_hashes": {"left": left_table_hash, "right": right_table_hash, "same": left_table_hash == right_table_hash},
        "graphics_root_cbvs": {"left": left_cbvs, "right": right_cbvs, "same": left_cbvs == right_cbvs},
        "descriptor_read_counts": {
            "left": _list_len(left.get("descriptor_reads")),
            "right": _list_len(right.get("descriptor_reads")),
        },
        "descriptor_index_candidates": {
            "left": left_descriptor_candidates,
            "right": right_descriptor_candidates,
        },
        "source_descriptor_overlap": descriptor_overlap,
        "prior_rtv0_producers": {
            "left": _prior_rtv0_summary(left),
            "right": _prior_rtv0_summary(right),
        },
        "view_rect_state": {
            "left": _copyrect_view_rect_state(left),
            "right": _copyrect_view_rect_state(right),
        },
    }
    detail["flags"] = {
        "same_source": bool(source_overlap) if left_sources and right_sources else False,
        "same_source_descriptor": any(item.get("proven_copyrect_t0") for item in descriptor_overlap),
        "same_source_descriptor_candidate": bool(descriptor_overlap),
        "same_target": bool(target_overlap) if left_targets and right_targets else False,
        "right_descriptor_reads_missing": _list_len(right.get("descriptor_reads")) == 0,
        "left_descriptor_reads_missing": _list_len(left.get("descriptor_reads")) == 0,
        "graphics_root_table_hash_changed": left_table_hash != right_table_hash,
        "graphics_root_cbv_changed": left_cbvs != right_cbvs,
        "right_prior_rtv0_missing": _norm_hex(right.get("prior_rtv0_producer_pso")) in (None, "0x0"),
    }
    detail["classification"] = _copyrect_pair_classification(detail)
    return detail


def _copyrect_issue_score(pair: dict[str, Any]) -> tuple[int, int, int, int, int, int]:
    flags = pair.get("flags", {})
    return (
        20 if flags.get("same_source_descriptor") else 0,
        12 if flags.get("same_source_descriptor_candidate") else 0,
        10 if flags.get("same_source") else 0,
        6 if flags.get("graphics_root_cbv_changed") else 0,
        4 if flags.get("graphics_root_table_hash_changed") else 0,
        3 if not flags.get("right_descriptor_reads_missing") else 0,
    )


def _copyrect_pair_classification(pair: dict[str, Any]) -> str:
    flags = pair.get("flags", {})
    if flags.get("same_source_descriptor"):
        return "left_and_right_share_copyrect_t0_source_descriptor"
    if flags.get("same_source_descriptor_candidate"):
        return "left_and_right_share_scanned_copy_source_descriptor_candidate"
    if flags.get("same_source"):
        return "left_and_right_share_scanned_copy_source_candidate"
    if flags.get("right_descriptor_reads_missing"):
        return "right_source_not_visible_in_saved_trace"
    if flags.get("graphics_root_cbv_changed") or flags.get("graphics_root_table_hash_changed"):
        return "left_right_binding_or_rect_state_differs"
    if flags.get("right_prior_rtv0_missing"):
        return "right_destination_has_no_prior_lineage"
    return "needs_live_resource_lineage"


def _copyrect_pair_probe_priorities(candidate_blocks: list[dict[str, Any]], report: dict[str, Any]) -> list[dict[str, Any]]:
    priorities = []
    seen = set()

    def add(name: str, reason: str, calls: list[str], pair: dict[str, Any] | None = None) -> None:
        if name in seen:
            return
        seen.add(name)
        item: dict[str, Any] = {"name": name, "reason": reason, "calls": calls}
        if pair:
            item["example_pair"] = {
                "pso": pair.get("pso"),
                "left_event_key": pair.get("left_event_key"),
                "right_event_key": pair.get("right_event_key"),
                "left_draw_index": pair.get("left_draw_index"),
                "right_draw_index": pair.get("right_draw_index"),
                "classification": pair.get("classification"),
            }
        priorities.append(item)

    issue_flags = report.get("copyrect", {}).get("issue_flags", {})
    for block in candidate_blocks:
        for pair in block.get("pairs", []):
            flags = pair.get("flags", {})
            if flags.get("same_source"):
                add(
                    "verify_shared_source_resource",
                    "A left/right CopyRect pair's bound-table scan contains at least one common source resource candidate.",
                    [
                        "ngfx_sn2_copyrect_slot_candidates(descriptor_state_reply=<left/right live replies>)",
                        "ngfx_resource_access_history(accessor=<shared PS t0 source>)",
                        "ngfx_resource_revision_at_event(accessor=<shared PS t0 source>, event_index=<right CopyRect event>)",
                        "ngfx_trace_roi_history(image_accessor=<right destination>, roi=<bad ROI>)",
                    ],
                    pair,
                )
            if flags.get("right_descriptor_reads_missing"):
                add(
                    "resolve_right_t0_live",
                    "The saved trace does not show right-eye descriptor reads for a CopyRect draw.",
                    [
                        "ngfx_sn2_copyrect_live_state_probe(session_handle=<handle>, event_index=<right event>)",
                        "ngfx_sn2_copyrect_slot_candidates(descriptor_state_reply=<right descriptor_state>)",
                    ],
                    pair,
                )
            if flags.get("graphics_root_cbv_changed"):
                add(
                    "dump_copy_rect_cbv",
                    "Graphics root CBV bindings differ across the pair; this is the likely source for view/copy rect constants.",
                    [
                        "ngfx_sn2_copyrect_live_state_probe(..., event_index=<left event>)",
                        "ngfx_sn2_copyrect_live_state_probe(..., event_index=<right event>)",
                        "ngfx_resource_revision_at_event(accessor=<graphics root CBV slot 2>, event_index=<paired events>)",
                    ],
                    pair,
                )
            if flags.get("right_prior_rtv0_missing"):
                add(
                    "trace_right_destination_lineage",
                    "The right CopyRect destination has missing or zero prior RTV producer evidence.",
                    [
                        "ngfx_resource_access_history(accessor=<right destination RTV>)",
                        "ngfx_resource_revision_at_event(accessor=<right destination RTV>, event_index=<right CopyRect event>)",
                    ],
                    pair,
                )
    if issue_flags.get("no_source_producer_lineage"):
        add(
            "open_live_capture_for_source_lineage",
            "Saved JSON has source reads but no producer draw lineage; use the private FrameDebugger RPC on the live capture.",
            [
                "ngfx_rpc_open_capture_session(capture=<fresh .ngfx-gfxcap>)",
                "ngfx_sn2_copyrect_live_state_probe(session_handle=<handle>, event_index=<mapped CopyRect event>)",
            ],
        )
    return priorities


def _root_slot_values(event: dict[str, Any], key: str, *, value_key: str = "value") -> dict[str, Any]:
    values = {}
    items = event.get(key)
    if not isinstance(items, list):
        return values
    for item in items:
        if not isinstance(item, dict):
            continue
        slot = item.get("slot", item.get("root_parameter", item.get("rootParameterIndex")))
        if slot is None:
            continue
        values[str(slot)] = item.get(value_key, item.get("hash", item.get("value")))
    return values


def _copyrect_event_key(event: dict[str, Any], *, pso: str | None = None) -> dict[str, Any]:
    return {
        "frame": event.get("frame"),
        "draw_index": event.get("draw_index", event.get("event_index")),
        "event_index": event.get("event_index"),
        "eye": _copyrect_eye(event),
        "eye_bucket": event.get("eye_bucket"),
        "pipeline_state": pso or _event_pso(event),
    }


def _copyrect_frame_key(event: dict[str, Any]) -> str:
    return str(event.get("frame", "unknown"))


def _frame_sort_key(value: str) -> tuple[int, str]:
    ivalue = _int_or_none(value)
    return (ivalue if ivalue is not None else 10**9, value)


def _descriptor_index_candidates(event: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for read in _copyrect_source_reads(event):
        shader_register = _descriptor_shader_register(read)
        register_space = _descriptor_register_space(read)
        proven_t0 = _descriptor_is_copyrect_t0(read)
        out.append(
            {
                "root_parameter": read.get("root_parameter"),
                "descriptor_index": read.get("descriptor_index"),
                "resource": _resource_key(read),
                "shader_register": shader_register,
                "register_space": register_space,
                "proven_copyrect_t0": proven_t0,
                "evidence_kind": "shader_register_t0" if proven_t0 else "bound_table_scan_candidate",
            }
        )
    return out[:16]


def _descriptor_candidate_overlap(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> list[dict[str, Any]]:
    left_keys = {
        (
            str(item.get("root_parameter")),
            str(item.get("descriptor_index")),
            str(item.get("resource")),
        )
        for item in left
        if item.get("resource")
    }
    out = []
    seen = set()
    for item in right:
        key = (
            str(item.get("root_parameter")),
            str(item.get("descriptor_index")),
            str(item.get("resource")),
        )
        if key in left_keys and key not in seen:
            seen.add(key)
            left_item = next(
                candidate
                for candidate in left
                if (
                    str(candidate.get("root_parameter")),
                    str(candidate.get("descriptor_index")),
                    str(candidate.get("resource")),
                )
                == key
            )
            proven_t0 = bool(left_item.get("proven_copyrect_t0") and item.get("proven_copyrect_t0"))
            out.append(
                {
                    "root_parameter": item.get("root_parameter"),
                    "descriptor_index": item.get("descriptor_index"),
                    "resource": item.get("resource"),
                    "shader_register": item.get("shader_register", left_item.get("shader_register")),
                    "register_space": item.get("register_space", left_item.get("register_space")),
                    "proven_copyrect_t0": proven_t0,
                    "evidence_kind": "shader_register_t0" if proven_t0 else "bound_table_scan_candidate",
                }
            )
    return out


def _descriptor_shader_register(read: dict[str, Any]) -> int | None:
    for key in ("shaderRegister", "shader_register", "register", "bind_point", "BindPoint"):
        value = _int_or_none(read.get(key))
        if value is not None:
            return value
    return None


def _descriptor_register_space(read: dict[str, Any]) -> int | None:
    for key in ("registerSpace", "register_space", "space", "Space"):
        value = _int_or_none(read.get(key))
        if value is not None:
            return value
    return None


def _descriptor_is_copyrect_t0(read: dict[str, Any]) -> bool:
    dtype = str(read.get("descriptor_type", read.get("type", ""))).lower()
    stage = str(read.get("stage", read.get("shader_stage", "PS"))).upper()
    shader_register = _descriptor_shader_register(read)
    register_space = _descriptor_register_space(read)
    return bool(
        ("srv" in dtype or "texture" in dtype)
        and stage in {"", "PS", "PIXEL"}
        and shader_register == 0
        and (register_space in (None, 0))
    )


def _copyrect_descriptor_evidence_summary(pair: dict[str, Any]) -> dict[str, Any]:
    overlaps = pair.get("source_descriptor_overlap") if isinstance(pair.get("source_descriptor_overlap"), list) else []
    proven = [item for item in overlaps if isinstance(item, dict) and item.get("proven_copyrect_t0")]
    return {
        "copyrect_shader_source": "PS t0",
        "saved_trace_descriptor_reads": "bound_descriptor_table_scan",
        "scanned_overlap_count": len(overlaps),
        "proven_t0_overlap_count": len(proven),
        "requires_live_t0_resolution": not bool(proven),
        "overlap_candidates": overlaps,
        "caveat": "Do not treat table-scan descriptor_reads as the sampled CopyRectPS source until PS t0 is mapped through live descriptor state or root-signature range metadata.",
    }


def _copyrect_slot_candidates_from_probe(probe: dict[str, Any], *, max_candidates_per_slot: int) -> dict[str, Any]:
    if not isinstance(probe, dict):
        return {"ok": False, "slots": {}, "error": "probe must be a dict"}
    if isinstance(probe.get("slots"), dict) and "ps_t0" in probe["slots"]:
        return probe
    slot_candidates = probe.get("slot_candidates")
    if isinstance(slot_candidates, dict) and isinstance(slot_candidates.get("slots"), dict):
        return slot_candidates
    replies = probe.get("replies")
    if isinstance(replies, dict) and isinstance(replies.get("descriptor_state"), dict):
        return sn2_copyrect_slot_candidates(
            {"reply": replies["descriptor_state"]},
            max_candidates_per_slot=max_candidates_per_slot,
        )
    return sn2_copyrect_slot_candidates(probe, max_candidates_per_slot=max_candidates_per_slot)


def _copyrect_slot_resource_candidates(slot_report: dict[str, Any], slot: str) -> list[dict[str, Any]]:
    slot_info = slot_report.get("slots", {}).get(slot, {}) if isinstance(slot_report.get("slots"), dict) else {}
    candidates = slot_info.get("candidates") if isinstance(slot_info, dict) else None
    if not isinstance(candidates, list):
        return []
    out = []
    seen = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        resources = candidate.get("resources")
        if not isinstance(resources, list):
            resources = _extract_resource_handles(candidate.get("descriptor", {}))
        if not resources:
            descriptor = candidate.get("descriptor") if isinstance(candidate.get("descriptor"), dict) else {}
            resource = _resource_key(descriptor)
            resources = [{"name": resource}] if resource else []
        for resource in resources:
            if not isinstance(resource, dict):
                continue
            key = _resource_key(resource)
            if not key:
                continue
            dedupe = (_resource_compare_key(key), candidate.get("path"))
            if dedupe in seen:
                continue
            seen.add(dedupe)
            out.append(
                {
                    "resource": key,
                    "score": candidate.get("score"),
                    "path": candidate.get("path"),
                    "reasons": candidate.get("reasons", []),
                    "handle": {k: resource.get(k) for k in ("accessor", "misc", "name") if k in resource},
                }
            )
    return out[:16]


def _copyrect_t0_compare_interpretation(verdict: str) -> list[str]:
    if verdict == "copyrect_t0_same_source":
        return [
            "Live descriptor state resolves left and right CopyRectPS t0 to at least one common resource.",
            "The fix should focus on right-eye source descriptor routing or the producer of that shared source before CopyRect.",
        ]
    if verdict == "copyrect_t0_different_source":
        return [
            "Live descriptor state resolves different CopyRectPS t0 resources for left and right.",
            "The saved table-scan overlap was not the sampled source; focus next on graphics root CBV/view-rect constants and destination routing.",
        ]
    return [
        "The actual CopyRectPS t0 source is still unresolved.",
        "Use live descriptor_state at the exact BinaryReplay event or add runtime root-signature descriptor-range logging.",
    ]


def _copyrect_lineage_resource_groups(pair: dict[str, Any]) -> dict[str, list[str]]:
    scanned_overlap = [
        str(item.get("resource"))
        for item in pair.get("source_descriptor_overlap", [])
        if isinstance(item, dict) and item.get("resource")
    ]
    proven_overlap = [
        str(item.get("resource"))
        for item in pair.get("source_descriptor_overlap", [])
        if isinstance(item, dict) and item.get("resource") and item.get("proven_copyrect_t0")
    ]
    return {
        "proven_t0_source_overlap": sorted(set(proven_overlap)),
        "scanned_source_descriptor_overlap": sorted(set(scanned_overlap)),
        "source_resource_overlap": sorted(str(item) for item in set(pair.get("source_overlap") or []) if item),
        "left_sources": sorted(str(item) for item in set(pair.get("left_sources") or []) if item),
        "right_sources": sorted(str(item) for item in set(pair.get("right_sources") or []) if item),
        "left_targets": sorted(str(item) for item in set(pair.get("left_targets") or []) if item),
        "right_targets": sorted(str(item) for item in set(pair.get("right_targets") or []) if item),
    }


def _trace_d3d12_list(trace: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = trace.get("d3d12", {}).get(key) if isinstance(trace.get("d3d12"), dict) else None
    if not isinstance(value, list):
        value = trace.get(key)
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _find_draw_by_event_key(draws: list[dict[str, Any]], event_key: Any) -> dict[str, Any] | None:
    if not isinstance(event_key, dict):
        return None
    frame = event_key.get("frame")
    draw_index = _int_or_none(event_key.get("draw_index", event_key.get("event_index")))
    event_index = _int_or_none(event_key.get("event_index"))
    pso = _norm_hex(event_key.get("pipeline_state"))
    for draw in draws:
        if frame is not None and str(draw.get("frame")) != str(frame):
            continue
        current_draw = _int_or_none(draw.get("draw_index", draw.get("event_index")))
        current_event = _int_or_none(draw.get("event_index"))
        if draw_index is not None and current_draw != draw_index:
            continue
        if event_index is not None and current_event not in (None, event_index):
            continue
        if pso and _event_pso(draw) != pso:
            continue
        return draw
    return None


def _copyrect_same_frame_window(
    draws: list[dict[str, Any]],
    *,
    frame: Any,
    left_draw_index: Any,
    right_draw_index: Any,
    resources: list[str],
    max_records: int,
) -> list[dict[str, Any]]:
    left = _int_or_none(left_draw_index)
    right = _int_or_none(right_draw_index)
    if left is None and right is None:
        return []
    low = min(idx for idx in (left, right) if idx is not None) - 8
    high = max(idx for idx in (left, right) if idx is not None) + 8
    wanted = {_resource_compare_key(resource) for resource in resources if resource}
    window_draws = []
    anchors = [idx for idx in (left, right) if idx is not None]
    for draw in draws:
        if frame is not None and str(draw.get("frame")) != str(frame):
            continue
        draw_index = _int_or_none(draw.get("draw_index", draw.get("event_index")))
        if draw_index is None or draw_index < low or draw_index > high:
            continue
        window_draws.append(draw)
    if len(window_draws) > max_records and anchors:
        ranked = sorted(
            window_draws,
            key=lambda draw: (
                min(abs((_int_or_none(draw.get("draw_index", draw.get("event_index"))) or 0) - anchor) for anchor in anchors),
                _int_or_none(draw.get("draw_index", draw.get("event_index"))) or 0,
            ),
        )
        keep_ids = {id(draw) for draw in ranked[:max_records]}
        window_draws = [draw for draw in window_draws if id(draw) in keep_ids]
    out = []
    for draw in window_draws:
        refs = _copyrect_record_resource_refs(draw)
        item = {
            "resource_refs": sorted(refs & wanted) if wanted else [],
            "record": _compact_lineage_record(draw),
        }
        out.append(item)
    return out


def _copyrect_records_for_resources(
    records: list[dict[str, Any]],
    resources: list[str],
    *,
    frame: Any = None,
    max_items: int = 64,
) -> list[dict[str, Any]]:
    wanted = {_resource_compare_key(resource) for resource in resources if resource}
    if not wanted:
        return []
    out = []
    for record in records:
        if frame is not None and str(record.get("frame")) != str(frame):
            continue
        refs = _copyrect_record_resource_refs(record)
        matched = refs & wanted
        if not matched:
            continue
        out.append({"resource_refs": sorted(matched), "record": _compact_lineage_record(record)})
        if len(out) >= max_items:
            break
    return out


def _copyrect_root_binds_for_pair(
    trace: dict[str, Any],
    *,
    left_draw: dict[str, Any] | None,
    right_draw: dict[str, Any] | None,
    frame: Any,
    max_items: int,
) -> list[dict[str, Any]]:
    command_lists = {
        str(draw.get("command_list"))
        for draw in (left_draw, right_draw)
        if isinstance(draw, dict) and draw.get("command_list")
    }
    if not command_lists:
        return []
    out = []
    for bind in _trace_d3d12_list(trace, "recent_root_binds"):
        if frame is not None and str(bind.get("frame")) != str(frame):
            continue
        if str(bind.get("command_list")) not in command_lists:
            continue
        out.append({"record": _compact_lineage_record(bind)})
        if len(out) >= max_items:
            break
    return out


def _copyrect_prior_target_chains(event: dict[str, Any] | None, draws: list[dict[str, Any]], *, max_depth: int = 6) -> list[dict[str, Any]]:
    if not isinstance(event, dict):
        return []
    chains = []
    for target in _copyrect_target_writes(event):
        prior_draw = _int_or_none(target.get("prior_producer_draw", event.get("prior_rtv0_producer_draw")))
        prior_frame = target.get("prior_producer_frame", event.get("prior_rtv0_producer_frame", event.get("frame")))
        chain = []
        seen = set()
        while prior_draw and len(chain) < max_depth:
            key = (str(prior_frame), prior_draw)
            if key in seen:
                break
            seen.add(key)
            producer = _find_draw_by_frame_draw(draws, frame=prior_frame, draw_index=prior_draw)
            if producer is None:
                chain.append({"frame": prior_frame, "draw_index": prior_draw, "missing_from_saved_trace": True})
                break
            chain.append(
                {
                    "frame": producer.get("frame"),
                    "draw_index": producer.get("draw_index", producer.get("event_index")),
                    "eye": _copyrect_eye(producer),
                    "pipeline_state": _event_pso(producer),
                    "targets": [_resource_key(item) for item in _copyrect_target_writes(producer) if _resource_key(item)],
                    "source_candidates": [_resource_key(item) for item in _copyrect_source_reads(producer) if _resource_key(item)],
                }
            )
            next_target = _copyrect_target_writes(producer)
            if not next_target:
                break
            prior_draw = _int_or_none(next_target[0].get("prior_producer_draw", producer.get("prior_rtv0_producer_draw")))
            prior_frame = next_target[0].get("prior_producer_frame", producer.get("prior_rtv0_producer_frame", producer.get("frame")))
        chains.append({"target": _resource_key(target), "chain": chain})
    return chains


def _find_draw_by_frame_draw(draws: list[dict[str, Any]], *, frame: Any, draw_index: int) -> dict[str, Any] | None:
    for draw in draws:
        if frame is not None and str(draw.get("frame")) != str(frame):
            continue
        if _int_or_none(draw.get("draw_index", draw.get("event_index"))) == draw_index:
            return draw
    return None


def _copyrect_record_resource_refs(record: dict[str, Any]) -> set[str]:
    refs = set()
    for _path, child in _walk_all_dicts(record):
        for key in ("resource", "resource_name", "debugName", "name", "rtv0_resource"):
            value = child.get(key)
            if isinstance(value, dict | list) or value in (None, "", 0, "0x0"):
                continue
            refs.add(_resource_compare_key(value))
    return refs


def _resource_compare_key(value: Any) -> str:
    return _norm_hex(value) or str(value)


def _compact_lineage_record(record: dict[str, Any]) -> dict[str, Any]:
    keep = (
        "frame",
        "event_index",
        "draw_index",
        "kind",
        "source",
        "pipeline_state",
        "eye_bucket",
        "command_list",
        "root_signature",
        "root_parameter",
        "pipeline",
        "sequence",
        "value",
        "value_hash",
        "before_state",
        "after_state",
        "subresource",
        "type",
        "detail",
        "rtv0_resource",
    )
    out = {key: record[key] for key in keep if key in record}
    for key in (
        "descriptor_reads",
        "render_target_writes",
        "uav_writes",
        "render_targets",
        "graphics_root_cbvs",
        "graphics_root_descriptor_tables",
        "graphics_root_descriptor_table_resource_hash",
    ):
        if key in record:
            out[key] = _truncate_value(record.get(key), max_list=8)
    return out


def _prior_rtv0_summary(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "draw": _int_or_none(event.get("prior_rtv0_producer_draw")),
        "frame": event.get("prior_rtv0_producer_frame"),
        "pso": _norm_hex(event.get("prior_rtv0_producer_pso")),
    }


def _copyrect_view_rect_state(event: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for key, value in event.items():
        key_lower = key.lower()
        if any(marker in key_lower for marker in ("viewport", "scissor", "rect")):
            out[key] = _truncate_value(value, max_list=8)
    return out


def _list_len(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def _copyrect_issue_flags(draws: list[dict[str, Any]], source_by_eye: dict[str, dict[str, int]]) -> dict[str, bool]:
    eyes = Counter(_copyrect_eye(draw) for draw in draws)
    cross_eye = False
    for draw in draws:
        draw_eye = _copyrect_eye(draw)
        if draw_eye == "unknown":
            continue
        for read in _copyrect_source_reads(draw):
            producer_eye = _copyrect_eye_from_value(read.get("producer_eye_bucket"))
            if producer_eye != "unknown" and producer_eye != draw_eye:
                cross_eye = True
    left_sources = set(source_by_eye.get("left", {}))
    right_sources = set(source_by_eye.get("right", {}))
    return {
        "right_eye_missing": eyes.get("left", 0) > 0 and eyes.get("right", 0) == 0,
        "left_eye_missing": eyes.get("right", 0) > 0 and eyes.get("left", 0) == 0,
        "same_source_for_left_and_right": bool(left_sources & right_sources) if left_sources and right_sources else False,
        "cross_eye_source_read": cross_eye,
        "no_source_producer_lineage": any(_copyrect_source_reads(draw) for draw in draws)
        and not any(_int_or_none(read.get("producer_draw")) for draw in draws for read in _copyrect_source_reads(draw)),
    }


def _copyrect_shader_summary(shader: dict[str, Any] | None, *, target: dict[str, Any]) -> dict[str, Any]:
    summary = _shader_dump_summary(
        shader,
        expected_hash=target["ps_hash"],
        expected_entry=target["ps_entry"],
    )
    disassembly = ""
    if isinstance(shader, dict):
        bytecode = shader.get("bytecode", {}) if isinstance(shader.get("bytecode"), dict) else {}
        disassembly = str(bytecode.get("disassembly", shader.get("disassembly", "")))
    bindings = _resource_binding_lines(disassembly)
    shape = {
        "entry": summary.get("entry"),
        "resource_bindings": bindings,
        "has_t0_texture": any(" T0" in line and "t0" in line for line in bindings) or " t0 " in disassembly.lower(),
        "has_s0_sampler": any(" S0" in line and "s0" in line for line in bindings) or " s0 " in disassembly.lower(),
        "sample_count": disassembly.lower().count("sample"),
        "texture_load_count": disassembly.count("textureLoad"),
        "store_output_count": disassembly.count("storeOutput"),
        "disassembly_length": len(disassembly),
    }
    shape["looks_like_copyrect"] = bool(
        shape["has_t0_texture"]
        and shape["has_s0_sampler"]
        and shape["store_output_count"] > 0
        and shape["disassembly_length"] <= 30000
    )
    summary["shape"] = shape
    return summary


def _resource_binding_lines(disassembly: str) -> list[str]:
    lines = []
    in_bindings = False
    for line in disassembly.splitlines():
        if "Resource Bindings:" in line:
            in_bindings = True
            continue
        if not in_bindings:
            continue
        if "ViewId state:" in line or line.startswith("target ") or line.startswith("define "):
            break
        cleaned = line.strip().lstrip(";").strip()
        if cleaned and any(token in cleaned for token in ("cbuffer", "texture", "sampler", "UAV")):
            lines.append(cleaned)
    return lines


def _copyrect_resource_handle_inputs(event: dict[str, Any]) -> list[dict[str, Any]]:
    handles = []
    for item in [*_copyrect_source_reads(event), *_copyrect_target_writes(event)]:
        for resource in _extract_resource_handles(item):
            handle = _normalise_resource_handle(resource)
            if handle is not None:
                handles.append(handle)
    return handles


def _resource_key(item: dict[str, Any]) -> str:
    for key in ("resource", "name", "resource_name", "debugName", "descriptor"):
        value = item.get(key)
        if value not in (None, "", "0x0", 0):
            return str(value)
    accessor = item.get("accessor", item.get("Accessor"))
    misc = item.get("misc", item.get("Misc", 0))
    if accessor not in (None, "", 0):
        return f"accessor:{accessor}:{misc or 0}"
    return ""


def _copyrect_eye(event: dict[str, Any]) -> str:
    return _copyrect_eye_from_value(event.get("eye_bucket", event.get("eye", event.get("view_index"))))


def _copyrect_eye_from_value(value: Any) -> str:
    key = _eye_bucket_key(value).lower()
    if key in {"1", "left", "l"}:
        return "left"
    if key in {"2", "right", "r"}:
        return "right"
    return "unknown"


def _draw_index_range(draws: list[dict[str, Any]]) -> dict[str, int | None]:
    indices = [_int_or_none(draw.get("draw_index", draw.get("event_index", draw.get("idx")))) for draw in draws]
    indices = [idx for idx in indices if idx is not None]
    return {"min": min(indices) if indices else None, "max": max(indices) if indices else None}


def _sample_raw_events(events: list[dict[str, Any]], *, edge_count: int = 2) -> list[dict[str, Any]]:
    if not events:
        return []
    indexes = list(range(min(edge_count, len(events))))
    indexes.append(len(events) // 2)
    indexes.extend(range(max(0, len(events) - edge_count), len(events)))
    out = []
    seen = set()
    for index in indexes:
        if index in seen or index >= len(events):
            continue
        seen.add(index)
        out.append(events[index])
    return out


def _recent_draw_events(trace: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(trace, dict):
        return []
    candidates = [
        trace.get("d3d12", {}).get("recent_draw_events"),
        trace.get("d3d12", {}).get("draw_events"),
        trace.get("recent_draw_events"),
        trace.get("draw_events"),
        trace.get("events"),
    ]
    for value in candidates:
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _ranked_candidates(trace: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(trace, dict):
        return []
    ranked = trace.get("ranked_candidates", {}).get("ranked", [])
    return [item for item in ranked if isinstance(item, dict)] if isinstance(ranked, list) else []


def _shader_aggregates(trace: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(trace, dict):
        return []
    aggregates = trace.get("shaders", {}).get("d3d12_pso_aggregates", [])
    return [item for item in aggregates if isinstance(item, dict)] if isinstance(aggregates, list) else []


def _distinct_shader_pairs(trace: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(trace, dict):
        return []
    pairs = trace.get("shaders", {}).get("distinct_d3d12_pairs", [])
    return [item for item in pairs if isinstance(item, dict)] if isinstance(pairs, list) else []


def _event_pso(event: dict[str, Any]) -> str | None:
    for key in ("pipeline_state", "bound_pipeline_state", "original_pso", "last_bound_pso", "pso"):
        if key in event:
            return _norm_hex(event.get(key))
    return None


def _find_pso_record(records: list[dict[str, Any]], *, lead_pso: str) -> dict[str, Any] | None:
    for record in records:
        if lead_pso in _record_pso_values(record):
            return record
    return None


def _record_pso_values(record: dict[str, Any]) -> set[str]:
    out = set()
    for key, value in record.items():
        if not isinstance(value, str):
            continue
        if key.lower() in {
            "pipeline_state",
            "bound_pipeline_state",
            "original_pso",
            "last_bound_pso",
            "pso",
            "suspect_pso",
        }:
            norm = _norm_hex(value)
            if norm:
                out.add(norm)
    return out


def _sample_events(events: list[dict[str, Any]], *, edge_count: int = 2) -> list[dict[str, Any]]:
    if not events:
        return []
    indexes = list(range(min(edge_count, len(events))))
    middle = len(events) // 2
    indexes.append(middle)
    indexes.extend(range(max(0, len(events) - edge_count), len(events)))
    samples = []
    seen = set()
    for index in indexes:
        if index in seen or index >= len(events):
            continue
        seen.add(index)
        samples.append(_compact_event(events[index]))
    return samples


def _compact_event(event: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "frame",
        "event_index",
        "draw_index",
        "kind",
        "pipeline_state",
        "eye_bucket",
        "root_signature",
        "prior_rtv0_producer_pso",
        "arg0",
        "arg1",
        "arg2",
        "arg3",
        "arg4",
        "rtv0",
        "dsv",
    )
    out = {key: event[key] for key in keys if key in event}
    for key, value in event.items():
        key_lower = key.lower()
        if key in out:
            continue
        if any(marker in key_lower for marker in ("descriptor", "root_param", "viewport", "scissor")):
            out[key] = _truncate_value(value)
    return out


def _compact_record(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if not record:
        return None
    keep = {
        "pipeline_state",
        "bound_pipeline_state",
        "original_pso",
        "last_bound_pso",
        "root_signature",
        "ps_hash",
        "ps_crc32",
        "gs_hash",
        "gs_crc32",
        "vs_hash",
        "vs_crc32",
        "score",
        "total_samples",
        "hit_count",
        "first_seen_frame",
        "last_seen_frame",
        "reasons",
        "symmetry",
    }
    out = {key: _truncate_value(value) for key, value in record.items() if key in keep}
    if "representative_draws" in record:
        reps = record.get("representative_draws")
        out["representative_draws"] = [_compact_event(item) for item in reps[:3] if isinstance(item, dict)] if isinstance(reps, list) else reps
    stage = _shader_stage_facts(record)
    if stage:
        out["stage_facts"] = stage
    return out


def _truncate_value(value: Any, *, max_list: int = 5, max_string: int = 500) -> Any:
    if isinstance(value, str):
        return value if len(value) <= max_string else value[:max_string] + "...<truncated>"
    if isinstance(value, list):
        return [_truncate_value(item) for item in value[:max_list]]
    if isinstance(value, dict):
        return {str(k): _truncate_value(v) for k, v in list(value.items())[:max_list]}
    return value


def _shader_stage_facts(record: dict[str, Any]) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    for stage in ("vs", "gs", "ps"):
        hash_value = _record_stage_hash(record, stage)
        crc_value = _record_stage_crc32(record, stage)
        if hash_value or crc_value:
            facts[stage] = {"hash": hash_value, "crc32": crc_value}
    return facts


def _record_stage_hash(record: dict[str, Any] | None, stage: str) -> str | None:
    if not isinstance(record, dict):
        return None
    direct = record.get(f"{stage}_hash")
    if direct:
        return _norm_hash(direct)
    markers = {
        "ps": ("ps", "pixel"),
        "gs": ("gs", "geometry"),
        "vs": ("vs", "vertex"),
    }[stage]
    for key, value in _flatten_scalars(record):
        key_lower = key.lower()
        if not isinstance(value, str) or "hash" not in key_lower:
            continue
        if any(marker in key_lower for marker in markers):
            return _norm_hash(value)
    return None


def _record_stage_crc32(record: dict[str, Any] | None, stage: str) -> str | None:
    if not isinstance(record, dict):
        return None
    direct = record.get(f"{stage}_crc32")
    if direct:
        return str(direct)
    markers = {
        "ps": ("ps", "pixel"),
        "gs": ("gs", "geometry"),
        "vs": ("vs", "vertex"),
    }[stage]
    for key, value in _flatten_scalars(record):
        key_lower = key.lower()
        if "crc32" not in key_lower:
            continue
        if any(marker in key_lower for marker in markers):
            return str(value)
    return None


def _shader_dump_summary(
    shader: dict[str, Any] | None,
    *,
    expected_hash: str,
    expected_entry: str,
) -> dict[str, Any]:
    if not isinstance(shader, dict):
        return {
            "ok": False,
            "matches_expected_hash": False,
            "matches_expected_entry": False,
            "error": "shader dump missing",
        }
    bytecode = shader.get("bytecode", {}) if isinstance(shader.get("bytecode"), dict) else {}
    reflection = bytecode.get("reflection", {}) if isinstance(bytecode.get("reflection"), dict) else shader.get("reflection", {})
    disassembly = str(bytecode.get("disassembly", shader.get("disassembly", "")))
    entry = _shader_entry_from_dump(shader, disassembly)
    hashes = {_norm_hash(v) for _, v in _flatten_scalars(shader) if isinstance(v, str) and "hash" in _.lower()}
    hashes.discard("")
    return {
        "ok": True,
        "entry": entry,
        "expected_entry": expected_entry,
        "matches_expected_entry": entry == expected_entry,
        "hashes": sorted(hashes),
        "expected_hash": expected_hash,
        "matches_expected_hash": _norm_hash(expected_hash) in hashes,
        "bytecode_size": bytecode.get("bytecode_size") or bytecode.get("declared_size"),
        "container_kind": bytecode.get("container_kind"),
        "compiler": bytecode.get("compiler"),
        "bound_resource_count": reflection.get("bound_resource_count"),
        "bound_resources": _truncate_value(reflection.get("bound_resources", []), max_list=12),
        "constant_buffers": _truncate_value(reflection.get("constant_buffers", []), max_list=8),
        "disassembly_features": {
            "length": len(disassembly),
            "mentions_sv_render_target_array_index": "SV_RenderTargetArrayIndex" in disassembly,
            "store_output_count": disassembly.count("storeOutput"),
            "raw_buffer_load_count": disassembly.count("rawBufferLoad"),
            "discard_count": disassembly.count("discard"),
            "emit_stream_count": disassembly.count("emitStream"),
            "cut_stream_count": disassembly.count("cutStream"),
        },
    }


def _shader_entry_from_dump(shader: dict[str, Any], disassembly: str) -> str | None:
    for key in ("entry", "entry_point", "entryPoint", "EntryFunctionName"):
        value = shader.get(key)
        if isinstance(value, str) and value:
            return value
    match = re.search(r"EntryFunctionName:\s*([A-Za-z_][A-Za-z0-9_]*)", disassembly)
    if match:
        return match.group(1)
    match = re.search(r"define\s+\w+\s+@([A-Za-z_][A-Za-z0-9_]*)\s*\(", disassembly)
    return match.group(1) if match else None


def _sn2_fog_fix_targets(on_summary: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    first_draw = on_summary["draw_samples"][0] if on_summary.get("draw_samples") else {}
    candidate = on_summary.get("ranked_candidate") or {}
    aggregate = on_summary.get("shader_aggregate") or {}
    stage_facts: dict[str, Any] = {}
    for evidence in on_summary.get("stage_hash_evidence", []):
        for stage, facts in evidence.items():
            stage_facts.setdefault(stage, facts)
    return {
        "lead_pso": target["lead_pso"],
        "root_signature": first_draw.get("root_signature") or candidate.get("root_signature") or aggregate.get("root_signature"),
        "ps_hash": target["ps_hash"],
        "gs_hash": target["gs_hash"],
        "stage_facts": stage_facts,
        "actual_draw_count": on_summary["actual_draw_count"],
        "draw_index_range": on_summary["draw_index_range"],
        "representative_draw": first_draw,
        "ranked_score": candidate.get("score"),
        "symmetry": candidate.get("symmetry"),
    }


def _histogram_only_key(histogram: dict[str, int], expected_key: str) -> bool:
    return bool(histogram) and all(str(key) == expected_key for key, count in histogram.items() if count)


def _norm_hex(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return f"0x{int(text, 16):X}"
    except ValueError:
        return text
    return text


def _norm_hash(value: Any) -> str:
    return str(value).strip().lower()


def _norm_crc32(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, int):
        return f"0x{value & 0xFFFFFFFF:08X}"
    text = str(value).strip()
    if not text:
        return ""
    try:
        return f"0x{int(text, 16 if text.lower().startswith('0x') else 10) & 0xFFFFFFFF:08X}"
    except ValueError:
        return text.upper()


def _eye_bucket_key(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, bool):
        return str(value).lower()
    text = str(value).strip()
    if text.endswith(".0"):
        text = text[:-2]
    return text


def _binary_replay_event_request_previews(event_index: int) -> list[dict[str, Any]]:
    reg = proto_descriptors.get_registry()
    specs = [
        (
            "event_details",
            rpc_client.RpcClient.METHOD_EVENT_DETAILS,
            "NV.Pylon.Replay.PbEventDetailsRequest",
            "NV.Pylon.Replay.PbEventDetailsReply",
        ),
        (
            "api_inspector_state",
            rpc_client.RpcClient.METHOD_API_INSPECTOR_STATE,
            "NV.Pylon.Replay.PbApiInspectorStateRequest",
            "NV.Pylon.Replay.PbApiInspectorStateReply",
        ),
        (
            "root_parameters",
            rpc_client.RpcClient.METHOD_ROOT_PARAMETERS,
            "NV.Pylon.Replay.PbRootParametersRequest",
            "NV.Pylon.Replay.PbRootParametersReply",
        ),
        (
            "descriptor_state",
            rpc_client.RpcClient.METHOD_DESCRIPTOR_STATE,
            "NV.Pylon.Replay.PbDescriptorStateRequest",
            "NV.Pylon.Replay.PbDescriptorStateReply",
        ),
    ]
    out = []
    for name, method, request_fqn, reply_fqn in specs:
        req = _event_index_request(reg, request_fqn, event_index)
        out.append(
            {
                "name": name,
                "category": rpc_client.CATEGORY_BINARY_REPLAY,
                "method": method,
                "request_fqn": request_fqn,
                "reply_fqn": reply_fqn,
                "request": rpc_client.protobuf_to_dict(req),
                "body_hex": req.SerializeToString().hex(),
            }
        )
    return out


def _event_index_request(registry: proto_descriptors.SchemaRegistry, request_fqn: str, event_index: int) -> Any:
    req_cls = registry.message_class(request_fqn)
    req = req_cls()
    if hasattr(req, "FirstEvent"):
        req.FirstEvent = int(event_index)
        if hasattr(req, "EventCount"):
            req.EventCount = 1
        return req
    for fname in ("eventIndex", "EventIndex", "event_index", "index"):
        if hasattr(req, fname):
            setattr(req, fname, int(event_index))
            return req
    raise ValueError(f"{request_fqn} has no known event-index field")


def _resource_request_previews(handles: list[dict[str, Any]], *, event_index: int | None) -> list[dict[str, Any]]:
    reg = proto_descriptors.get_registry()
    out = []
    for handle in handles:
        accessor = int(handle["accessor"])
        misc = int(handle.get("misc", 0))
        history = rpc_client.build_resource_access_history_request(reg, accessor=accessor, misc=misc)
        info = rpc_client.build_resource_info_request(reg, accessor=accessor, misc=misc)
        item: dict[str, Any] = {
            "handle": handle,
            "resource_access_history": {
                "method": rpc_client.RpcClient.METHOD_RESOURCE_ACCESS_HISTORY,
                "request_fqn": "NV.Pylon.Replay.PbResourceAccessHistoryRequest",
                "reply_fqn": "NV.Pylon.Replay.PbResourceAccessHistoryReply",
                "request": rpc_client.protobuf_to_dict(history),
                "body_hex": history.SerializeToString().hex(),
            },
            "resource_info": {
                "method": rpc_client.RpcClient.METHOD_RESOURCE_INFO,
                "request_fqn": "NV.Pylon.Replay.PbResourceInfoRequest",
                "reply_fqn": "NV.Pylon.Replay.PbResourceInfoReply",
                "request": rpc_client.protobuf_to_dict(info),
                "body_hex": info.SerializeToString().hex(),
            },
        }
        if event_index is not None:
            data = rpc_client.build_image_subresource_data_request(reg, accessor=accessor, misc=misc, event_index=event_index)
            item["image_subresource_data"] = {
                "method": rpc_client.RpcClient.METHOD_IMAGE_SUBRESOURCE_DATA,
                "request_fqn": "NV.Pylon.Replay.PbImageSubresourceDataRequest",
                "reply_fqn": "NV.Pylon.Replay.PbImageSubresourceDataReply",
                "request": rpc_client.protobuf_to_dict(data),
                "body_hex": data.SerializeToString().hex(),
            }
        out.append(item)
    return out


def _normalise_resource_handles(handles: list[dict[str, Any] | str | int]) -> list[dict[str, Any]]:
    out = []
    seen = set()
    for value in handles:
        handle = _normalise_resource_handle(value)
        if handle is None:
            continue
        key = (handle["accessor"], handle["misc"])
        if key in seen:
            continue
        seen.add(key)
        out.append(handle)
    return out


def _normalise_resource_handle(value: dict[str, Any] | str | int) -> dict[str, Any] | None:
    if isinstance(value, dict):
        accessor = _int_or_none(value.get("accessor", value.get("Accessor")))
        misc = _int_or_none(value.get("misc", value.get("Misc"))) or 0
        if accessor is None:
            return None
        out = {"accessor": accessor, "misc": misc}
        for key in ("name", "path", "role"):
            if key in value:
                out[key] = value[key]
        return out
    accessor = _int_or_none(value)
    return {"accessor": accessor, "misc": 0} if accessor is not None else None


def _read_trace_events(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
        return data if isinstance(data, list) else data.get("events", [])
    if path.suffix.lower() == ".csv":
        return list(csv.DictReader(text.splitlines()))
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
            continue
        except json.JSONDecodeError:
            pass
        item = {}
        for token in line.replace(",", " ").split():
            if "=" in token:
                k, v = token.split("=", 1)
                item[k.strip()] = v.strip()
        if item:
            events.append(item)
    return events


def _write_trace_db(db_path: Path, events: list[dict[str, Any]]) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            DROP TABLE IF EXISTS uevr_trace;
            CREATE TABLE uevr_trace(
                idx INTEGER PRIMARY KEY,
                event_name TEXT,
                eye TEXT,
                pso TEXT,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX i_uevr_trace_event ON uevr_trace(event_name);
            CREATE INDEX i_uevr_trace_eye ON uevr_trace(eye);
            CREATE INDEX i_uevr_trace_pso ON uevr_trace(pso);
            """
        )
        conn.executemany(
            "INSERT INTO uevr_trace(idx, event_name, eye, pso, raw_json) VALUES (?,?,?,?,?)",
            [
                (
                    i,
                    str(e.get("function") or e.get("event") or e.get("name") or "unknown"),
                    str(e.get("eye", "unknown")),
                    str(e.get("pso", e.get("pipeline_state", "unknown"))),
                    json.dumps(e, sort_keys=True),
                )
                for i, e in enumerate(events)
            ],
        )
        conn.commit()
    finally:
        conn.close()


def _walk_descriptor_nodes(value: Any, path: str = "$") -> list[tuple[str, dict[str, Any]]]:
    nodes: list[tuple[str, dict[str, Any]]] = []
    if isinstance(value, dict):
        if _looks_descriptor_like(value):
            nodes.append((path, value))
        for key, child in value.items():
            nodes.extend(_walk_descriptor_nodes(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            nodes.extend(_walk_descriptor_nodes(child, f"{path}[{index}]"))
    return nodes


def _looks_descriptor_like(node: dict[str, Any]) -> bool:
    text = " ".join(str(k).lower() for k in node)
    markers = (
        "descriptor",
        "resource",
        "image",
        "buffer",
        "accessor",
        "shaderregister",
        "register",
        "rootparameter",
    )
    return any(marker in text for marker in markers)


def _score_descriptor_node(slot: str, spec: dict[str, Any], node: dict[str, Any]) -> tuple[int, list[str]]:
    slot_lower = slot.lower()
    register = _int_or_none(spec.get("register", spec.get("bind_point")))
    if register is None:
        register = _slot_register_number(slot)
    wanted_space = _int_or_none(spec.get("register_space", spec.get("space")))
    wanted_root = _int_or_none(spec.get("root_param_index", spec.get("root_param")))
    wanted_index = _int_or_none(spec.get("descriptor_index", spec.get("descriptor_offset")))
    wanted_type = str(spec.get("type", "")).lower()
    wanted_stage = str(spec.get("stage", "")).lower()
    flat = list(_flatten_scalars(node))
    text = json.dumps(node, sort_keys=True).lower()
    score = 0
    reasons: list[str] = []

    if slot_lower in text:
        score += 6
        reasons.append(f"literal slot {slot}")
    if wanted_type and wanted_type in text:
        score += 3
        reasons.append(f"mentions descriptor type {wanted_type}")
    if wanted_stage and wanted_stage in text:
        score += 2
        reasons.append(f"mentions shader stage {wanted_stage.upper()}")

    for key, value in flat:
        key_lower = key.lower()
        ivalue = _int_or_none(value)
        if register is not None and ivalue == register and any(
            marker in key_lower for marker in ("shaderregister", "shader_register", "base", "register", "binding")
        ):
            score += 8
            reasons.append(f"{key} == shader register {register}")
        if wanted_space is not None and ivalue == wanted_space and "space" in key_lower:
            score += 3
            reasons.append(f"{key} == register space {wanted_space}")
        if wanted_root is not None and ivalue == wanted_root and "root" in key_lower:
            score += 5
            reasons.append(f"{key} == root parameter {wanted_root}")
        if wanted_index is not None and ivalue == wanted_index and any(
            marker in key_lower for marker in ("index", "offset", "descriptor")
        ):
            score += 5
            reasons.append(f"{key} == descriptor index/offset {wanted_index}")
        if isinstance(value, str) and value.lower() == slot_lower:
            score += 8
            reasons.append(f"{key} names {slot}")

    if _extract_resource_handles(node):
        score += 2
        reasons.append("contains resource handle/name fields")
    return score, reasons


def _flatten_scalars(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            out.extend(_flatten_scalars(child, next_prefix))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            out.extend(_flatten_scalars(child, f"{prefix}[{index}]"))
    else:
        out.append((prefix, value))
    return out


def _extract_resource_handles(node: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for path, child in _walk_all_dicts(node):
        keys = {str(k).lower(): k for k in child}
        accessor_key = keys.get("accessor")
        misc_key = keys.get("misc")
        name_key = next(
            (
                keys[k]
                for k in keys
                if k in {"name", "debugname", "resource", "resource_name"}
                and not isinstance(child.get(keys[k]), dict | list)
            ),
            None,
        )
        if accessor_key is None and name_key is None:
            continue
        item = {"path": path}
        if accessor_key is not None:
            item["accessor"] = child.get(accessor_key)
        if misc_key is not None:
            item["misc"] = child.get(misc_key)
        if name_key is not None:
            item["name"] = child.get(name_key)
        if item not in resources:
            resources.append(item)
    resources.sort(key=lambda item: 0 if "accessor" in item else 1)
    return resources


def _walk_all_dicts(value: Any, path: str = "$") -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    if isinstance(value, dict):
        out.append((path, value))
        for key, child in value.items():
            out.extend(_walk_all_dicts(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            out.extend(_walk_all_dicts(child, f"{path}[{index}]"))
    return out


def _slot_register_number(slot: str) -> int | None:
    digits = "".join(c for c in slot if c.isdigit())
    return int(digits) if digits else None


def _int_or_none(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, str) and value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_symbols(text: str) -> list[str]:
    out = []
    for token in text.replace("&", " ").replace(",", " ").replace("(", " ").replace(")", " ").split():
        if token.startswith("g_") and token not in out:
            out.append(token)
    return out


def _safe_ident(value: str) -> str:
    return "".join(c if c.isalnum() or c == "_" else "_" for c in value)


def _load_float_image(
    path: Path,
    *,
    width: int | None,
    height: int | None,
    channels: int,
    fmt: str,
) -> tuple[list[float], int, int, int]:
    actual = fmt.lower()
    if actual == "auto":
        actual = "pfm" if path.suffix.lower() == ".pfm" else "rawf32"
    if actual == "pfm":
        return _load_pfm(path)
    if actual != "rawf32":
        raise ValueError(f"unsupported float image format: {fmt}")
    if width is None or height is None:
        raise ValueError("rawf32 requires width and height")
    data = path.read_bytes()
    count = width * height * channels
    values = list(struct.unpack("<" + "f" * count, data[: count * 4]))
    return values, width, height, channels


def _load_pfm(path: Path) -> tuple[list[float], int, int, int]:
    with path.open("rb") as fh:
        magic = fh.readline().strip()
        if magic not in (b"PF", b"Pf"):
            raise ValueError("not a PFM file")
        dims = fh.readline().decode("ascii").strip().split()
        width, height = int(dims[0]), int(dims[1])
        scale = float(fh.readline().decode("ascii").strip())
        endian = "<" if scale < 0 else ">"
        channels = 3 if magic == b"PF" else 1
        raw = fh.read()
    count = width * height * channels
    return list(struct.unpack(endian + "f" * count, raw[: count * 4])), width, height, channels


def _luma(pixel: list[float]) -> float:
    if len(pixel) == 1:
        return pixel[0]
    return 0.2126 * pixel[0] + 0.7152 * pixel[1] + 0.0722 * pixel[2]


# ---------------------------------------------------------------------------
# Fix attempt log + evidence bundle
# ---------------------------------------------------------------------------
#
# Append-only JSONL log of fix attempts; refuses to mark "accept" without
# before+after evidence. Combined with the evidence-bundle zip below, this
# satisfies the "no overclaimed fix" requirement in
# NSIGHT_SHADER_DEBUG_AUTONOMY.md.


def fix_attempt_log_append(
    log_path: Path,
    *,
    hypothesis: str,
    change: str,
    before_evidence: dict[str, Any] | None = None,
    after_evidence: dict[str, Any] | None = None,
    decision: str = "open",
    notes: str = "",
) -> dict[str, Any]:
    """Append one fix attempt entry to a JSONL log.

    ``decision`` must be ``"open"`` while still gathering evidence,
    ``"accept"`` after a passing validation, or ``"reject"`` when the
    hypothesis failed. ``"accept"`` requires both ``before_evidence``
    and ``after_evidence`` to be present and non-empty — this is the
    enforced guard against overclaimed fixes.
    """
    import datetime
    decision = decision.lower()
    if decision not in {"open", "accept", "reject"}:
        return {"ok": False, "error": f"invalid decision: {decision}"}
    if decision == "accept" and (not before_evidence or not after_evidence):
        return {
            "ok": False,
            "error": (
                "cannot mark fix attempt as 'accept' without both "
                "before_evidence and after_evidence."
            ),
        }

    entry = {
        "ts_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "hypothesis": hypothesis,
        "change": change,
        "before_evidence": before_evidence,
        "after_evidence": after_evidence,
        "decision": decision,
        "notes": notes,
    }
    log_path = Path(log_path).resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    return {"ok": True, "log_path": str(log_path), "entry": entry}


def fix_attempt_log_read(log_path: Path) -> dict[str, Any]:
    """Read all entries from a JSONL fix-attempt log."""
    log_path = Path(log_path).resolve()
    if not log_path.is_file():
        return {"ok": False, "error": f"log not found: {log_path}"}
    entries: list[dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    counts: dict[str, int] = {}
    for e in entries:
        counts[e.get("decision", "open")] = counts.get(e.get("decision", "open"), 0) + 1
    return {
        "ok": True,
        "log_path": str(log_path),
        "entry_count": len(entries),
        "decision_counts": counts,
        "entries": entries,
    }


def fix_claim_evidence_bundle(
    output_zip: Path,
    *,
    capture_path: Path | None = None,
    before_screenshot: Path | None = None,
    after_screenshot: Path | None = None,
    roi_diff_json: Path | None = None,
    event_state_diff_json: Path | None = None,
    fix_log_path: Path | None = None,
    extra_files: list[Path] | None = None,
    require_before_after: bool = True,
) -> dict[str, Any]:
    """Bundle a fix-claim's evidence into a single zip for review.

    By default refuses to produce a bundle that doesn't include at least
    one of each of {before screenshot, after screenshot}. Pass
    ``require_before_after=False`` to override (e.g. for "open" attempts
    that haven't reached the after-pass yet).
    """
    import zipfile
    output_zip = Path(output_zip).resolve()
    output_zip.parent.mkdir(parents=True, exist_ok=True)

    if require_before_after and (
        before_screenshot is None or after_screenshot is None
    ):
        return {
            "ok": False,
            "error": (
                "fix_claim_evidence_bundle requires both before_screenshot "
                "and after_screenshot unless require_before_after=False."
            ),
        }

    members: list[tuple[Path, str]] = []
    def _add(p: Path | None, arcname: str) -> None:
        if p is None:
            return
        p = Path(p)
        if p.is_file():
            members.append((p, arcname))

    _add(capture_path, "capture/" + (capture_path.name if capture_path else ""))
    _add(before_screenshot, "screenshots/before_" + (before_screenshot.name if before_screenshot else ""))
    _add(after_screenshot, "screenshots/after_" + (after_screenshot.name if after_screenshot else ""))
    _add(roi_diff_json, "metrics/roi_diff.json")
    _add(event_state_diff_json, "metrics/event_state_diff.json")
    _add(fix_log_path, "log/fix_attempts.jsonl")
    for extra in extra_files or []:
        p = Path(extra)
        if p.is_file():
            members.append((p, f"extras/{p.name}"))

    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, arc in members:
            zf.write(path, arc)
    return {
        "ok": True,
        "output_zip": str(output_zip),
        "member_count": len(members),
        "members": [arc for _, arc in members],
    }
