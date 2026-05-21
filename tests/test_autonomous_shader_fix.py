from __future__ import annotations

import json
import struct
from pathlib import Path

from nsight_graphics_mcp import autonomous_shader_fix as auto
from nsight_graphics_mcp import cpp_capture_parser

SAMPLE_CPP = """\
void play_frame() {
    pCommandList->RSSetViewports(1, {0.0f, 0.0f, 960.0f, 1080.0f, 0.0f, 1.0f});
    pCommandList->SetPipelineState(g_PSO_Sky);
    pCommandList->CopyResource(g_LeftVol, g_ComputeOut);
    pCommandList->Dispatch(8, 8, 1);
    pCommandList->DrawIndexedInstanced(36, 1, 0, 0, 0);
    pCommandList->RSSetViewports(1, {960.0f, 0.0f, 960.0f, 1080.0f, 0.0f, 1.0f});
    pCommandList->SetPipelineState(g_PSO_Sky);
    pCommandList->DrawIndexedInstanced(36, 1, 0, 0, 0);
}
"""


def _db(tmp_path: Path) -> Path:
    project = tmp_path / "cpp"
    project.mkdir()
    (project / "frame.cpp").write_text(SAMPLE_CPP, encoding="utf-8")
    return cpp_capture_parser.index_cpp_project(project).db_path


def test_pair_eye_events_and_slot_resolution(tmp_path: Path) -> None:
    db = _db(tmp_path)
    pairs = auto.pair_eye_events(db, right_half_min_x=960)
    assert pairs["pair_count"] >= 1
    assert pairs["missing_right"]

    slots = auto.resolve_shader_slots(
        db,
        pairs["pairs"][0]["left"]["event_index"],
        slots=["t5"],
        slot_map={"t5": {"root_param_index": "0"}},
    )
    assert slots["ok"]
    assert "t5" in slots["slots"]


def test_descriptor_resource_candidates() -> None:
    reply = {
        "reply": {
            "descriptorTables": [
                {
                    "rootParameterIndex": 2,
                    "descriptors": [
                        {
                            "descriptorIndex": 12,
                            "shaderRegister": 5,
                            "registerSpace": 0,
                            "resource": {
                                "Accessor": 123,
                                "Misc": 4,
                                "name": "RightEyeHistoryTex",
                            },
                        }
                    ],
                }
            ]
        }
    }

    result = auto.descriptor_resource_candidates(
        reply,
        slots=["t5"],
        slot_map={"t5": {"root_param_index": 2, "descriptor_index": 12, "register_space": 0}},
    )

    slot = result["slots"]["t5"]
    assert slot["status"] == "candidates"
    first = slot["candidates"][0]
    assert first["score"] > 0
    assert first["resources"][0]["accessor"] == 123


def test_roi_request_grid_and_repro_plan() -> None:
    grid = auto.pixel_history_grid_requests(
        image_accessor=123,
        roi={"x": 10, "y": 20, "w": 8, "h": 8},
        grid_x=2,
        grid_y=2,
    )
    assert len(grid["requests"]) == 4
    assert grid["requests"][0]["method"] == 70

    plan = auto.sn2_repro_plan(extra_env={"FOO": "BAR"})
    assert plan["extra_env"]["FOO"] == "BAR"
    assert plan["powershell_command"][0] == "powershell"


def test_sn2_fog_signal_report_accepts_clean_oracle(tmp_path: Path) -> None:
    lead = auto.SN2_FOG_DEFAULTS["lead_pso"]
    ps_hash = auto.SN2_FOG_DEFAULTS["ps_hash"]
    gs_hash = auto.SN2_FOG_DEFAULTS["gs_hash"]
    on = tmp_path / "fog_on.json"
    off = tmp_path / "fog_off.json"
    ps = tmp_path / "ps.json"
    gs = tmp_path / "gs.json"
    on.write_text(json.dumps(_fog_trace(draw_count=77, lead=lead, ps_hash=ps_hash, gs_hash=gs_hash)), encoding="utf-8")
    off.write_text(
        json.dumps(_fog_trace(draw_count=0, lead=lead, ps_hash=ps_hash, gs_hash=gs_hash, include_candidate=False)),
        encoding="utf-8",
    )
    ps.write_text(json.dumps(_shader_dump(ps_hash, "VoxelizePS", "ps")), encoding="utf-8")
    gs.write_text(json.dumps(_shader_dump(gs_hash, "VoxelizeGS", "gs")), encoding="utf-8")

    report = auto.sn2_fog_signal_report(
        fog_on_path=on,
        fog_off_path=off,
        ps_shader_path=ps,
        gs_shader_path=gs,
    )

    assert report["ok"]
    assert report["fog_on"]["actual_draw_count"] == 77
    assert report["fog_on"]["eye_bucket_histogram"] == {"1": 77}
    assert report["fog_off"]["actual_draw_count"] == 0
    assert report["checks"]["fog_off_actual_draws_absent"]
    assert report["checks"]["ps_dump_matches"]
    assert report["fix_plan"]["primary_trigger"]["pipeline_state"] == "0x221FA167CE0"
    assert report["warnings"] == [
        "r.Fog 0 still has historical shader aggregate evidence for the lead PSO; use actual recent_draw_events, not aggregate presence, as the disappearance signal."
    ]


def test_sn2_fog_signal_report_rejects_changed_signal(tmp_path: Path) -> None:
    lead = auto.SN2_FOG_DEFAULTS["lead_pso"]
    ps_hash = auto.SN2_FOG_DEFAULTS["ps_hash"]
    gs_hash = auto.SN2_FOG_DEFAULTS["gs_hash"]
    on = tmp_path / "fog_on.json"
    off = tmp_path / "fog_off.json"
    ps = tmp_path / "ps.json"
    gs = tmp_path / "gs.json"
    on.write_text(
        json.dumps(_fog_trace(draw_count=77, lead=lead, ps_hash=ps_hash, gs_hash=gs_hash, right_eye_draws=1)),
        encoding="utf-8",
    )
    off.write_text(json.dumps(_fog_trace(draw_count=1, lead=lead, ps_hash=ps_hash, gs_hash=gs_hash)), encoding="utf-8")
    ps.write_text(json.dumps(_shader_dump(ps_hash, "VoxelizePS", "ps")), encoding="utf-8")
    gs.write_text(json.dumps(_shader_dump(gs_hash, "VoxelizeGS", "gs")), encoding="utf-8")

    report = auto.sn2_fog_signal_report(
        fog_on_path=on,
        fog_off_path=off,
        ps_shader_path=ps,
        gs_shader_path=gs,
    )

    assert not report["ok"]
    assert not report["checks"]["fog_on_draw_count_matches_expected"]
    assert not report["checks"]["fog_on_all_actual_draws_left_only"]
    assert not report["checks"]["fog_off_actual_draws_absent"]


def test_sn2_fog_descriptor_plan_and_slot_candidates(tmp_path: Path) -> None:
    manifest_path = tmp_path / "fog_probe_manifest.json"
    manifest = auto.sn2_fog_probe_manifest(
        signal_report={"ok": True, "fix_targets": {"lead_pso": "0x221FA167CE0"}, "fix_plan": auto.sn2_fog_fix_plan()},
        output_path=manifest_path,
    )
    assert manifest_path.is_file()
    assert manifest["trial_order"][0] == "gs_rt_array_index_constant_right"

    plan = auto.sn2_fog_descriptor_probe_plan(
        signal_report={
            "ok": True,
            "target": {"lead_pso": "0x221FA167CE0"},
            "fix_targets": {"representative_draw": {"rtv0": "0xabc", "graphics_root_descriptor_tables": []}},
        }
    )
    assert plan["shader_slots_to_resolve"][0]["slot"] == "gs_t0"
    assert plan["hook_descriptor_evidence"]["rtv0"] == "0xabc"

    candidates = auto.sn2_fog_slot_candidates(
        {
            "reply": {
                "descriptorTables": [
                    {
                        "stage": "PS",
                        "descriptorType": "srv",
                        "descriptors": [
                            {
                                "shaderRegister": 2,
                                "registerSpace": 0,
                                "resource": {"Accessor": 123, "Misc": 4, "name": "FogStructuredBuffer"},
                            }
                        ],
                    }
                ]
            }
        }
    )
    assert candidates["slots"]["ps_t2"]["status"] == "candidates"
    assert candidates["resource_handles"][0]["accessor"] == 123
    assert candidates["resource_handles"][0]["misc"] == 4


def test_sn2_copyrect_signal_report_traces_bad_source(tmp_path: Path) -> None:
    ps_hash = auto.SN2_COPYRECT_DEFAULTS["ps_hash"]
    trace = tmp_path / "copyrect_trace.json"
    shader = tmp_path / "copyrect_shader.json"
    trace.write_text(json.dumps(_copyrect_trace(ps_hash)), encoding="utf-8")
    shader.write_text(json.dumps(_copyrect_shader_dump(ps_hash)), encoding="utf-8")

    report = auto.sn2_copyrect_signal_report(trace_path=trace, shader_path=shader)

    assert report["ok"]
    assert report["copyrect"]["candidate_count"] == 1
    assert report["copyrect"]["actual_draw_count"] == 2
    assert report["copyrect"]["source_resources_by_eye"]["right"]["left_src"] == 1
    assert report["copyrect"]["issue_flags"]["cross_eye_source_read"]
    assert report["copyrect"]["issue_flags"]["same_source_for_left_and_right"]
    assert report["copyrect"]["paired_draws"][0]["same_source"]
    assert report["shader_evidence"]["shape"]["looks_like_copyrect"]
    assert report["fix_plan"]["fix_hypotheses"][0]["name"] == "right_copy_reads_left_source"


def test_sn2_copyrect_descriptor_plan_and_slot_candidates() -> None:
    report = {
        "ok": True,
        "target": {
            "ps_hash": auto.SN2_COPYRECT_DEFAULTS["ps_hash"],
            "ps_crc32": auto.SN2_COPYRECT_DEFAULTS["ps_crc32"],
            "ps_entry": auto.SN2_COPYRECT_DEFAULTS["ps_entry"],
        },
        "copyrect": {
            "representative_draw": {
                "draw_index": 101,
                "eye_bucket": 2,
                "descriptor_reads": [{"descriptor_type": "SRV", "resource": "left_src"}],
                "render_target_writes": [{"resource": "right_dst"}],
                "graphics_root_descriptor_tables": [{"root_parameter": 0, "descriptor": "0x1234"}],
            }
        },
    }

    plan = auto.sn2_copyrect_descriptor_probe_plan(signal_report=report, event_index=321, roi={"x": 960, "y": 100, "w": 64, "h": 64})

    assert plan["ok"]
    assert plan["live_event_index"] == 321
    assert plan["shader_slots_to_resolve"][0]["slot"] == "ps_t0"
    assert plan["hook_descriptor_evidence"]["source_reads"][0]["resource"] == "left_src"
    assert plan["live_event_requests"]

    candidates = auto.sn2_copyrect_slot_candidates(
        {
            "reply": {
                "descriptorTables": [
                    {
                        "stage": "PS",
                        "descriptorType": "srv",
                        "descriptors": [
                            {
                                "shaderRegister": 0,
                                "registerSpace": 0,
                                "resource": {"Accessor": 456, "Misc": 7, "name": "CopyRectSource"},
                            }
                        ],
                    },
                    {
                        "stage": "PS",
                        "descriptorType": "sampler",
                        "descriptors": [
                            {
                                "shaderRegister": 0,
                                "registerSpace": 0,
                                "name": "CopyRectSampler",
                            }
                        ],
                    },
                ]
            }
        }
    )
    assert candidates["slots"]["ps_t0"]["status"] == "candidates"
    assert candidates["slots"]["ps_s0"]["status"] == "candidates"
    assert candidates["resource_handles"][0]["accessor"] == 456
    assert candidates["resource_handles"][0]["misc"] == 7

    left_probe = {
        "event_index": 10,
        "replies": {
            "descriptor_state": {
                "descriptorTables": [
                    {
                        "stage": "PS",
                        "descriptorType": "srv",
                        "descriptors": [
                            {
                                "shaderRegister": 0,
                                "registerSpace": 0,
                                "resource": {"Accessor": 456, "Misc": 7, "name": "CopyRectSource"},
                            }
                        ],
                    }
                ]
            }
        },
    }
    right_probe = json.loads(json.dumps(left_probe))
    right_probe["event_index"] = 11
    compare = auto.sn2_copyrect_t0_source_compare(left_probe, right_probe)
    assert compare["verdict"] == "copyrect_t0_same_source"
    assert compare["same_t0_resources"] == ["CopyRectSource"]

    right_probe["replies"]["descriptor_state"]["descriptorTables"][0]["descriptors"][0]["resource"] = {
        "Accessor": 999,
        "Misc": 1,
        "name": "RightCopyRectSource",
    }
    compare = auto.sn2_copyrect_t0_source_compare(left_probe, right_probe)
    assert compare["verdict"] == "copyrect_t0_different_source"


def test_sn2_copyrect_pair_analysis_prioritizes_shared_source(tmp_path: Path) -> None:
    ps_hash = auto.SN2_COPYRECT_DEFAULTS["ps_hash"]
    trace = tmp_path / "copyrect_trace.json"
    shader = tmp_path / "copyrect_shader.json"
    trace.write_text(json.dumps(_copyrect_trace(ps_hash)), encoding="utf-8")
    shader.write_text(json.dumps(_copyrect_shader_dump(ps_hash)), encoding="utf-8")
    signal = auto.sn2_copyrect_signal_report(trace_path=trace, shader_path=shader)

    analysis = auto.sn2_copyrect_pair_analysis(signal_report=signal, trace_path=trace)

    assert analysis["ok"]
    assert analysis["summary"]["pair_count"] == 1
    pair = analysis["candidate_blocks"][0]["pairs"][0]
    assert pair["classification"] == "left_and_right_share_scanned_copy_source_descriptor_candidate"
    assert pair["flags"]["same_source"]
    assert pair["flags"]["same_source_descriptor_candidate"]
    assert not pair["flags"]["same_source_descriptor"]
    assert pair["source_descriptor_overlap"][0]["evidence_kind"] == "bound_table_scan_candidate"
    assert pair["left_event_key"]["frame"] == 0
    assert pair["right_event_key"]["frame"] == 0
    assert "verify_shared_source_resource" in {item["name"] for item in analysis["probe_priorities"]}
    assert analysis["summary"]["hook_draw_indices_to_map"] == [100, 101]

    issue = auto.sn2_copyrect_right_eye_issue_report(signal_report=signal, trace_path=trace)
    assert issue["verdict"] == "right_eye_copyrect_table_scan_has_same_source_candidate_with_different_rect_constants"
    assert issue["suspect_pair"]["source_overlap"] == ["left_src"]
    assert issue["descriptor_read_caveat"]["saved_trace_descriptor_reads"] == "bound_descriptor_table_scan"

    lineage = auto.sn2_copyrect_source_lineage_report(signal_report=signal, trace_path=trace)
    assert lineage["ok"]
    assert lineage["descriptor_evidence"]["requires_live_t0_resolution"]
    assert lineage["resource_groups"]["scanned_source_descriptor_overlap"] == ["left_src"]
    assert lineage["saved_trace_lineage"]["barriers"]
    assert lineage["saved_trace_lineage"]["render_target_binds"]
    assert lineage["remaining_gap"]["name"] == "resolve_actual_copyrect_t0_source"

    instrumentation = auto.sn2_copyrect_runtime_instrumentation_plan(issue_report=issue)
    assert instrumentation["ok"]
    assert instrumentation["event_filter"]["draw_indices"] == [100, 101]
    assert instrumentation["minimal_json_record_schema"]["t0"]["proven_shader_register"] == 0
    assert "resolved_copyrect_t0_descriptor" in {item["name"] for item in instrumentation["must_log_per_copyrect_draw"]}


def test_resource_graph_and_uevr_trace_import(tmp_path: Path) -> None:
    db = _db(tmp_path)
    graph = auto.resource_producer_graph(db, resources=["g_LeftVol"], event_index=5)
    assert graph["ok"]
    assert "g_LeftVol" in graph["nodes"]

    trace = tmp_path / "uevr.ndjson"
    trace.write_text(
        "\n".join(
            [
                json.dumps({"event": "SetPipelineState", "eye": "left", "pso": "pso3069"}),
                json.dumps({"event": "DrawIndexedInstanced", "eye": "right", "pso": "pso3069"}),
            ]
        ),
        encoding="utf-8",
    )
    imported = auto.import_uevr_trace(trace, db_path=tmp_path / "trace.db")
    assert imported["event_count"] == 2
    assert imported["pso_histogram"]["pso3069"] == 2


def test_hdr_diff_and_fix_validation(tmp_path: Path) -> None:
    before = tmp_path / "before.raw"
    after = tmp_path / "after.raw"
    before.write_bytes(struct.pack("<" + "f" * 16, *([1.0, 1.0, 1.0, 1.0] * 4)))
    after.write_bytes(struct.pack("<" + "f" * 16, *([0.5, 0.5, 0.5, 1.0] * 4)))

    diff = auto.diff_hdr_roi(before, after, width=2, height=2, channels=4)
    assert diff["mean_luma_after"] < diff["mean_luma_before"]
    assert diff["mean_rgb_delta"] > 0

    verdict = auto.validate_fix_claim(
        before_score=1.0,
        after_score=0.5,
        left_eye_delta=0.01,
        repeated_runs=2,
        has_first_bad_event=True,
        has_resource_or_shader_cause=True,
    )
    assert verdict["ok"]


def test_pso_rehydration_and_probe_plan(tmp_path: Path) -> None:
    plan = auto.pso_rehydration_plan(
        suspect_pso="pso3069",
        patched_shader_path="patched.dxil",
        output_dir=str(tmp_path),
    )
    assert plan["ok"]
    assert Path(plan["files"]["source"]).is_file()
    assert "CreateGraphicsPipelineState" in plan["snippets"]["source"]

    probe = auto.shader_probe_execution_plan(suspect_pso="pso3069", probe_name="visualize_t8")
    assert probe["steps"]


def _fog_trace(
    *,
    draw_count: int,
    lead: str,
    ps_hash: str,
    gs_hash: str,
    include_candidate: bool = True,
    right_eye_draws: int = 0,
) -> dict[str, object]:
    draws = [
        {
            "frame": i // 22,
            "draw_index": 961 + i,
            "kind": "draw_indexed",
            "pipeline_state": lead,
            "eye_bucket": 1,
            "root_signature": "0x22276990220",
            "arg0": 6,
            "arg1": 1,
        }
        for i in range(draw_count)
    ]
    draws.extend(
        {
            "frame": 4,
            "draw_index": 2000 + i,
            "kind": "draw_indexed",
            "pipeline_state": lead,
            "eye_bucket": 0,
            "root_signature": "0x22276990220",
        }
        for i in range(right_eye_draws)
    )
    ranked = []
    if include_candidate:
        ranked.append(
            {
                "pipeline_state": lead,
                "ps_hash": ps_hash,
                "gs_hash": gs_hash,
                "root_signature": "0x22276990220",
                "score": 94.6,
                "symmetry": {"left_count": draw_count, "right_count": right_eye_draws},
            }
        )
    return {
        "d3d12": {"recent_draw_events": draws},
        "ranked_candidates": {"ranked": ranked},
        "shaders": {
            "d3d12_pso_aggregates": [
                {
                    "original_pso": lead,
                    "last_bound_pso": lead,
                    "ps_hash": ps_hash,
                    "ps_crc32": "0x9D14FCF0",
                    "gs_hash": gs_hash,
                    "gs_crc32": "0x6B1ACA8C",
                    "vs_hash": "da5f4dff2ec0b2f0",
                    "total_samples": 8,
                }
            ],
            "distinct_d3d12_pairs": [
                {
                    "bound_pipeline_state": lead,
                    "pixel_shader": {"hash": ps_hash},
                    "geometry_shader": {"hash": gs_hash},
                }
            ],
        },
    }


def _shader_dump(shader_hash: str, entry: str, model: str) -> dict[str, object]:
    return {
        "requested_hash": shader_hash,
        "bytecode": {
            "bytecode_size": 1024,
            "container_kind": "DXIL",
            "disassembly": f"; EntryFunctionName: {entry}\n!dx.shaderModel = !{{!\"{model}\", i32 6, i32 6}}\nSV_RenderTargetArrayIndex\nstoreOutput\nrawBufferLoad\n",
            "reflection": {
                "bound_resource_count": 1,
                "bound_resources": [{"type": "srv", "bind_point": 0, "space": 0}],
                "constant_buffers": [{"type": "cbuffer", "size": 392}],
            },
        },
    }


def _copyrect_trace(ps_hash: str) -> dict[str, object]:
    copy_pso = "0xABC"
    return {
        "d3d12": {
            "recent_draw_events": [
                {
                    "frame": 0,
                    "draw_index": 100,
                    "kind": "draw",
                    "pipeline_state": copy_pso,
                    "eye_bucket": 1,
                    "command_list": "0xCL",
                    "root_signature": "0x1111",
                    "graphics_root_cbvs": [{"slot": 2, "value": "0x1000"}],
                    "graphics_root_descriptor_table_resource_hash": [{"slot": 0, "hash": "0xAAAA"}],
                    "descriptor_reads": [
                        {
                            "descriptor_type": "SRV",
                            "root_parameter": 0,
                            "descriptor_index": 0,
                            "resource": "left_src",
                            "producer_draw": 80,
                            "producer_frame": 0,
                            "producer_eye_bucket": 1,
                            "producer_kind": "draw",
                            "producer_pso": "0xAAA",
                        }
                    ],
                    "render_target_writes": [{"resource": "left_dst", "descriptor": "0xL", "target_index": 0}],
                },
                {
                    "frame": 0,
                    "draw_index": 101,
                    "kind": "draw",
                    "pipeline_state": copy_pso,
                    "eye_bucket": 2,
                    "command_list": "0xCL",
                    "root_signature": "0x1111",
                    "graphics_root_cbvs": [{"slot": 2, "value": "0x2000"}],
                    "graphics_root_descriptor_table_resource_hash": [{"slot": 0, "hash": "0xBBBB"}],
                    "descriptor_reads": [
                        {
                            "descriptor_type": "SRV",
                            "root_parameter": 0,
                            "descriptor_index": 0,
                            "resource": "left_src",
                            "producer_draw": 80,
                            "producer_frame": 0,
                            "producer_eye_bucket": 1,
                            "producer_kind": "draw",
                            "producer_pso": "0xAAA",
                        }
                    ],
                    "render_target_writes": [{"resource": "right_dst", "descriptor": "0xR", "target_index": 0}],
                },
            ],
            "recent_barriers": [
                {
                    "frame": 0,
                    "kind": "ResourceBarrier",
                    "resource": "left_src",
                    "type": "Transition",
                    "before_state": "RT",
                    "after_state": "PSR",
                },
                {
                    "frame": 0,
                    "kind": "ResourceBarrier",
                    "resource": "right_dst",
                    "type": "Transition",
                    "before_state": "PSR",
                    "after_state": "RT",
                },
            ],
            "recent_bindings": [
                {
                    "frame": 0,
                    "kind": "OMSetRenderTargets",
                    "render_targets": [{"resource": "left_dst", "handle": "0xL"}],
                },
                {
                    "frame": 0,
                    "kind": "OMSetRenderTargets",
                    "render_targets": [{"resource": "right_dst", "handle": "0xR"}],
                },
            ],
            "recent_root_binds": [
                {
                    "frame": 0,
                    "kind": "cbv",
                    "pipeline": "graphics",
                    "command_list": "0xCL",
                    "root_parameter": 2,
                    "value": "0x2000",
                }
            ],
        },
        "ranked_candidates": {
            "ranked": [
                {
                    "pipeline_state": copy_pso,
                    "ps_hash": ps_hash,
                    "ps_crc32": "0xE85849AA",
                    "root_signature": "0x1111",
                    "score": 120,
                    "symmetry": {"left_count": 1, "right_count": 1},
                }
            ]
        },
        "shaders": {"d3d12_pso_aggregates": [], "distinct_d3d12_pairs": []},
    }


def _copyrect_shader_dump(shader_hash: str) -> dict[str, object]:
    return {
        "requested_hash": shader_hash,
        "bytecode": {
            "bytecode_size": 768,
            "container_kind": "DXIL",
            "disassembly": f"""\
; EntryFunctionName: CopyRectPS
; Resource Bindings:
; Name                 Type     Format         Dim      HLSL Bind  Count
; S0                   sampler  NA             NA       s0         1
; T0                   texture  f32            2d       t0         1
define void @CopyRectPS() {{
  %sample = call %dx.types.ResRet.f32 @dx.op.sample.f32()
  call void @dx.op.storeOutput.f32()
  ret void
}}
; hash {shader_hash}
""",
            "reflection": {
                "bound_resource_count": 2,
                "bound_resources": [
                    {"type": "sampler", "bind_point": 0, "space": 0, "name": "S0"},
                    {"type": "texture", "bind_point": 0, "space": 0, "name": "T0"},
                ],
            },
        },
    }


# ---------------------------------------------------------------------------
# fix-attempt log + evidence bundle (Track A misc)
# ---------------------------------------------------------------------------


def test_fix_attempt_log_append_then_read(tmp_path: Path) -> None:
    log = tmp_path / "fix_log.jsonl"
    r1 = auto.fix_attempt_log_append(
        log,
        hypothesis="right-eye descriptor swap",
        change="forced t0 to left-eye SRV",
        decision="open",
    )
    assert r1["ok"]
    r2 = auto.fix_attempt_log_append(
        log,
        hypothesis="right-eye descriptor swap",
        change="forced t0 to left-eye SRV",
        before_evidence={"roi_mean": 0.42},
        after_evidence={"roi_mean": 0.05},
        decision="accept",
    )
    assert r2["ok"]

    read = auto.fix_attempt_log_read(log)
    assert read["ok"]
    assert read["entry_count"] == 2
    assert read["decision_counts"]["accept"] == 1
    assert read["decision_counts"]["open"] == 1


def test_fix_attempt_log_rejects_accept_without_evidence(tmp_path: Path) -> None:
    log = tmp_path / "fix_log.jsonl"
    out = auto.fix_attempt_log_append(
        log,
        hypothesis="some claim",
        change="some change",
        decision="accept",
    )
    assert not out["ok"]
    assert "accept" in out["error"].lower()


def test_fix_claim_evidence_bundle_requires_before_after(tmp_path: Path) -> None:
    out = tmp_path / "bundle.zip"
    res = auto.fix_claim_evidence_bundle(
        out,
        capture_path=None,
        before_screenshot=None,
        after_screenshot=None,
    )
    assert not res["ok"]


def test_fix_claim_evidence_bundle_builds_zip(tmp_path: Path) -> None:
    import zipfile

    before = tmp_path / "before.png"
    after = tmp_path / "after.png"
    capture = tmp_path / "capture.ngfx-capture"
    log = tmp_path / "fix_log.jsonl"
    for p, b in [(before, b"P"), (after, b"A"), (capture, b"FAKE"), (log, b'{"x":1}\n')]:
        p.write_bytes(b)

    out = tmp_path / "bundle.zip"
    res = auto.fix_claim_evidence_bundle(
        out,
        capture_path=capture,
        before_screenshot=before,
        after_screenshot=after,
        fix_log_path=log,
    )
    assert res["ok"]
    assert out.is_file()
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
    assert any("before_" in n for n in names)
    assert any("after_" in n for n in names)
    assert "log/fix_attempts.jsonl" in names
