from __future__ import annotations

import textwrap
from pathlib import Path

from nsight_graphics_mcp import cpp_capture_parser, shader_triage

TRIAGE_SAMPLE = textwrap.dedent(
    """\
    void play_frame() {
        pCommandList->RSSetViewports(1, {0.0f, 0.0f, 960.0f, 1080.0f, 0.0f, 1.0f});
        pCommandList->RSSetScissorRects(1, {0, 0, 960, 1080});
        pCommandList->SetPipelineState(g_PSO_Sky);
        pCommandList->Dispatch(8, 8, 1);
        pCommandList->DrawIndexedInstanced(36, 1, 0, 0, 0);

        pCommandList->RSSetViewports(1, {960.0f, 0.0f, 960.0f, 1080.0f, 0.0f, 1.0f});
        pCommandList->RSSetScissorRects(1, {960, 0, 1920, 1080});
        pCommandList->SetPipelineState(g_PSO_Sky);
        pCommandList->DrawIndexedInstanced(36, 1, 0, 0, 0);
        pCommandList->CopyResource(g_RightSceneColor, g_LeftSceneColor);
    }
    """
)


def _make_index(tmp_path: Path) -> Path:
    project = tmp_path / "GeneratedCpp"
    project.mkdir()
    (project / "frame.cpp").write_text(TRIAGE_SAMPLE, encoding="utf-8")
    idx = cpp_capture_parser.index_cpp_project(project)
    return idx.db_path


def test_cpp_parser_extracts_triage_state_args(tmp_path: Path) -> None:
    db = _make_index(tmp_path)

    viewports = cpp_capture_parser.query_calls(db, name="RSSetViewports")
    assert len(viewports) == 2
    assert viewports[0]["named_args"]["num_viewports"] == "1"
    assert "960.0f" in viewports[1]["named_args"]["viewports"]

    copies = cpp_capture_parser.query_calls(db, name="CopyResource")
    assert copies[0]["named_args"]["dst_resource"] == "g_RightSceneColor"
    assert copies[0]["named_args"]["src_resource"] == "g_LeftSceneColor"


def test_eye_event_index_and_missing_dispatches(tmp_path: Path) -> None:
    db = _make_index(tmp_path)

    idx = shader_triage.eye_event_index(db, right_half_min_x=960)
    assert idx["summary"]["by_eye"]["left"] == 2
    assert idx["summary"]["by_eye"]["right"] == 2

    missing = shader_triage.find_missing_eye_dispatches(db, right_half_min_x=960)
    assert missing["left_has_more"]
    assert missing["left_has_more"][0]["function_name"] == "Dispatch"
    assert missing["left_has_more"][0]["left_count"] == 1
    assert missing["left_has_more"][0]["right_count"] == 0


def test_pso_bind_trace_and_event_state(tmp_path: Path) -> None:
    db = _make_index(tmp_path)

    trace = shader_triage.pso_bind_trace(db, pso_contains="g_PSO_Sky")
    assert trace["bind_count"] == 2
    assert trace["binds"][0]["following_work_count"] == 2

    draw_event = trace["binds"][0]["following_work"][-1]["event_index"]
    state = shader_triage.event_state(db, draw_event)
    assert state["ok"]
    assert state["bound_pipeline"] == "g_PSO_Sky"
    assert state["bindings"]["d3d12"]["pipeline_state"]["value"] == "g_PSO_Sky"
    assert any(w["function_name"] == "Dispatch" for w in state["recent_writes"])


def test_resource_lineage_and_probe_plan(tmp_path: Path) -> None:
    db = _make_index(tmp_path)

    lineage = shader_triage.trace_resource_lineage(db, "g_RightSceneColor")
    assert lineage["mention_count"] == 1
    assert lineage["mentions_by_role"]["copy"] == 1

    plan = shader_triage.shader_probe_plan(
        shader_name="pso3069_PS",
        suspect_terms=["t5", "t8", "screenTile"],
    )
    names = [p["name"] for p in plan["probes"]]
    assert "visualize_volumetric_textures" in names
    assert "visualize_stereo_tile_math" in names


def test_pso_swap_harness_plan_can_write_files(tmp_path: Path) -> None:
    out_dir = tmp_path / "harness"
    plan = shader_triage.pso_swap_harness_plan(
        suspect_pso_label="pso3069",
        suspect_shader_crc32="0x166DBA88",
        output_dir=str(out_dir),
    )

    assert plan["ok"]
    assert plan["suspect"]["shader_toggler_crc32"] == "166dba88"
    assert "ID3D12GraphicsCommandList::SetPipelineState" in plan["hook_points"]
    assert Path(plan["files"]["header"]).is_file()
    source = Path(plan["files"]["source"]).read_text(encoding="utf-8")
    assert "BeforeDraw" in source
    assert "pso3069" in source
    assert "166dba88" in source
