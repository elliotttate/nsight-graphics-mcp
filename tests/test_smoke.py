"""Smoke tests that don't require a live capture.

These verify that:
  * the package imports cleanly,
  * the install discovery finds *something* on this machine if Nsight is installed
    (otherwise the test is skipped),
  * the SDK reflection parses the bundled headers,
  * the codegen produces a non-empty C++ snippet,
  * every MCP tool is registered with a unique name.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def test_import_server() -> None:
    from nsight_graphics_mcp import server

    assert server.mcp.name == "nsight-graphics-mcp"


def test_tool_registration() -> None:
    from nsight_graphics_mcp import server

    names = sorted(t.name for t in server.mcp._tool_manager._tools.values())
    # spot-check a few critical names
    for must_have in [
        "ngfx_environment",
        "ngfx_capture_launched",
        "ngfx_deep_capture_capability_report",
        "ngfx_graphics_capture_launched",
        "ngfx_gputrace_launched",
        "ngfx_gputrace_capture_replay",
        "ngfx_gputrace_shader_pipeline_search",
        "ngfx_gputrace_export_summary",
        "ngfx_gputrace_export_search",
        "ngfx_cpp_capture_launched",
        "ngfx_framedebugger_launched",
        "ngfx_replay_run",
        "ngfx_index_events",
        "ngfx_find_events",
        "ngfx_sdk_reference",
        "ngfx_sdk_snippet",
        "ngfx_ida_environment",
        "ngfx_ida_analyze_binary",
        "ngfx_ida_search_facts",
        "ngfx_cpp_capture_saved_bridge_re_analyze",
        "ngfx_cpp_capture_saved_bridge_re_report",
        "ngfx_cpp_capture_saved_pylon_handoff_preview",
        "ngfx_pylon_private_bridge_re_report",
        "ngfx_pylon_bridge_probe_plan",
        "ngfx_pylon_activity_manager_static_binding_report",
        "ngfx_pylon_bridge_helper_scaffold",
        "ngfx_pylon_bridge_probe_log_analyze",
        "ngfx_pylon_private_binding_from_probe",
        "ngfx_pylon_direct_call_binding_from_probe",
        "ngfx_pylon_bridge_probe_run",
        "ngfx_pylon_frida_direct_call_run",
        "ngfx_private_executor_readiness_report",
        "ngfx_private_executor_evidence_bundle",
        "ngfx_pylon_private_bridge_invoke",
        "ngfx_pylon_saved_cpp_export",
        "ngfx_cpp_capture_saved_direct_rpc_plan",
        "ngfx_rpc_direct_export_binding_candidate",
        "ngfx_cpp_capture_saved_direct_rpc_export",
        "ngfx_cpp_capture_saved_file_transfer_apply",
        "ngfx_cpp_capture_saved_output_dir_setting",
        "ngfx_cpp_capture_saved_export_validate",
        "ngfx_cpp_capture_saved_ui_automation_attempt",
        "ngfx_cpp_capture_saved_headless_attempt",
        "ngfx_cpp_capture_saved_artifact_bundle",
        "ngfx_shader_fix_regression_score",
        "ngfx_shader_debug_re_status",
        "ngfx_frame_debugger_rpc_schema",
        "ngfx_pixel_history",
        "ngfx_resource_access_history",
        "ngfx_resource_revision_at_event",
        "ngfx_rpc_open_capture_session",
        "ngfx_rpc_endpoint_resolve",
        "ngfx_rpc_endpoint_probe",
        "ngfx_rpc_capture_session_status",
        "ngfx_rpc_close_capture_session",
        "ngfx_rpc_call_binary_replay",
        "ngfx_rpc_find_live_events",
        "ngfx_rpc_decode_frame",
        "ngfx_rpc_transcript_import",
        "ngfx_rpc_session_binding_report",
        "ngfx_sn2_fog_artifacts",
        "ngfx_sn2_fog_signal_report",
        "ngfx_sn2_fog_fix_plan",
        "ngfx_sn2_fog_descriptor_probe_plan",
        "ngfx_sn2_fog_slot_candidates",
        "ngfx_sn2_fog_probe_manifest",
        "ngfx_sn2_fog_live_state_probe",
        "ngfx_sn2_copyrect_artifacts",
        "ngfx_sn2_copyrect_signal_report",
        "ngfx_sn2_copyrect_fix_plan",
        "ngfx_sn2_copyrect_descriptor_probe_plan",
        "ngfx_sn2_copyrect_slot_candidates",
        "ngfx_sn2_copyrect_t0_source_compare",
        "ngfx_sn2_copyrect_pair_analysis",
        "ngfx_sn2_copyrect_right_eye_issue_report",
        "ngfx_sn2_copyrect_source_lineage_report",
        "ngfx_sn2_copyrect_runtime_instrumentation_plan",
        "ngfx_sn2_copyrect_live_state_probe",
        "ngfx_sn2_copyrect_live_pair_probe",
        "ngfx_eye_issue_event_signatures",
        "ngfx_eye_issue_dump_report",
        "ngfx_sn2_repro_plan",
        "ngfx_sn2_repro_run",
        "ngfx_cpp_capture_from_saved_capture",
        "ngfx_pair_eye_events",
        "ngfx_resolve_shader_slots",
        "ngfx_descriptor_resource_candidates",
        "ngfx_trace_roi_history",
        "ngfx_resource_producer_graph",
        "ngfx_import_uevr_trace",
        "ngfx_pso_rehydration_plan",
        "ngfx_shader_probe_execution_plan",
        "ngfx_diff_hdr_roi",
        "ngfx_autofix_loop_plan",
        "ngfx_validate_fix_claim",
        "ngfx_cpp_capture_dump",
        "ngfx_shader_triage_plan",
        "ngfx_eye_event_index",
        "ngfx_compare_eye_passes",
        "ngfx_find_missing_eye_dispatches",
        "ngfx_event_state",
        "ngfx_trace_resource_lineage",
        "ngfx_pso_bind_trace",
        "ngfx_pso_swap_harness_plan",
        "ngfx_shader_probe_plan",
        "ngfx_shader_bug_triage",
        "ngfx_layer_install",
        "ngfx_raw",
        # direct capture decoder
        "ngfx_capture_decode_header",
        "ngfx_capture_decode_chunks",
        "ngfx_capture_decode_toc",
        "ngfx_capture_decompress_chunk_by_id",
        "ngfx_capture_search_payloads",
        "ngfx_capture_shader_chunks",
        "ngfx_capture_chunk_references",
        "ngfx_capture_decode_events",
        "ngfx_capture_event_args",
    ]:
        assert must_have in names, f"missing tool: {must_have}"
    # all unique
    assert len(names) == len(set(names))


def test_render_flag_shapes() -> None:
    from nsight_graphics_mcp.cli import render_flag

    assert render_flag("frame_count", 3) == ["--frame-count", "3"]
    assert render_flag("verbose", True) == ["--verbose"]
    assert render_flag("verbose", False) == []
    assert render_flag("verbose", None) == []
    assert render_flag("metric_set_name", "Top Level Triage") == [
        "--metric-set-name",
        "Top Level Triage",
    ]


@pytest.mark.skipif(
    os.name != "nt", reason="Nsight Graphics CLIs are Windows-only"
)
def test_install_discovery_or_skip() -> None:
    from nsight_graphics_mcp.config import discover_install_roots

    roots = discover_install_roots()
    if not roots:
        pytest.skip("Nsight Graphics not installed on this machine")
    assert all(r.is_dir() for r in roots)


@pytest.mark.skipif(
    os.name != "nt", reason="Nsight Graphics CLIs are Windows-only"
)
def test_sdk_reference_or_skip() -> None:
    from nsight_graphics_mcp.config import discover_install_roots
    from nsight_graphics_mcp.sdk import generate_snippet, list_headers

    if not discover_install_roots():
        pytest.skip("Nsight Graphics not installed")
    ref = list_headers()
    assert ref["ok"]
    assert ref["headers"], "no NGFX headers found"
    found_one_function = any(h["function_count"] > 0 for h in ref["headers"])
    assert found_one_function, "no NGFX_* functions parsed from headers"

    snip = generate_snippet("GraphicsCapture", "D3D12")
    assert snip["ok"]
    assert "NGFX_GraphicsCapture_Inject_D3D12" in snip["snippet"]


def test_classify_events() -> None:
    from nsight_graphics_mcp.events import classify

    assert classify("DrawIndexedInstanced") == "draw"
    assert classify("ID3D12GraphicsCommandList_DrawIndexedInstanced") == "draw"
    assert classify("vkCmdDispatch") == "dispatch"
    assert classify("ID3D12GraphicsCommandList_Dispatch") == "dispatch"
    assert classify("ID3D12GraphicsCommandList_SetPipelineState") == "pipeline"
    assert classify("ID3D12Device_CopyDescriptors") == "descriptor"
    assert classify("ID3D12GraphicsCommandList_SetGraphicsRootDescriptorTable") == "set_state"
    assert classify("ResourceBarrier") == "barrier"
    assert classify("Present") == "present"
    assert classify("DispatchRays") == "ray_tracing"
    assert classify("Made-up") == "other"
    assert classify("vkCmdSetViewport") == "set_state"


def test_project_roundtrip(tmp_path: Path) -> None:
    from nsight_graphics_mcp.project import create_project, read_project, update_project

    p = tmp_path / "demo.nsight-gfxproj"
    r = create_project(
        p,
        activity="GPU Trace Profiler",
        exe="C:/games/MyGame.exe",
        args="-windowed",
        working_dir="C:/games",
        env_pairs="FOO=1;BAR=2",
    )
    assert r["ok"]
    assert p.is_file()
    read = read_project(p)
    assert read["ok"]
    assert read["Activity"]["attrib"]["name"] == "GPU Trace Profiler"
    upd = update_project(p, activity="Graphics Capture", set_settings={"frame_count": "3"})
    assert upd["ok"]
    re_read = read_project(p)
    assert re_read["Activity"]["attrib"]["name"] == "Graphics Capture"
