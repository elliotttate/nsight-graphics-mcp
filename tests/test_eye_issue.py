from __future__ import annotations

import sqlite3
from pathlib import Path

from nsight_graphics_mcp import events, eye_issue


def _build_functions_db(capture: Path, rows: list[tuple[int, str, str]]) -> Path:
    capture.parent.mkdir(parents=True, exist_ok=True)
    capture.write_bytes(b"FAKE")
    db = events._cache_root_for(capture) / "functions.db"
    db.unlink(missing_ok=True)
    conn = sqlite3.connect(db)
    try:
        conn.executescript("""
            CREATE TABLE calls(
                event_index   INTEGER PRIMARY KEY,
                function_name TEXT NOT NULL,
                sequence_id   INTEGER NOT NULL DEFAULT 0,
                thread_index  INTEGER NOT NULL DEFAULT 0,
                kind          TEXT NOT NULL
            );
            CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);
        """)
        conn.executemany(
            "INSERT INTO calls(event_index, function_name, sequence_id, thread_index, kind) "
            "VALUES (?, ?, 0, 0, ?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()
    return db


def _build_objects_db(capture: Path) -> Path:
    db = events._cache_root_for(capture) / "objects.db"
    db.unlink(missing_ok=True)
    conn = sqlite3.connect(db)
    try:
        conn.executescript("""
            CREATE TABLE objects(
                uid          INTEGER PRIMARY KEY,
                type_name    TEXT NOT NULL,
                object_name  TEXT NOT NULL,
                api          TEXT NOT NULL,
                access_flags INTEGER NOT NULL DEFAULT 0,
                category     TEXT NOT NULL,
                raw_json     TEXT NOT NULL
            );
        """)
        conn.execute(
            "INSERT INTO objects(uid, type_name, object_name, api, access_flags, category, raw_json) "
            "VALUES (1, 'PipelineState', 'CopyRectPS_PSO', 'D3D12', 0, 'pipeline', ?)",
            ('{"shader":"CopyRectPS","hash":"98acf00f2001c218"}',),
        )
        conn.commit()
    finally:
        conn.close()
    return db


def test_event_signature_index_finds_repeated_draw_pair(tmp_path: Path) -> None:
    capture = tmp_path / "frame.ngfx-capture"
    db = _build_functions_db(
        capture,
        [
            (10, "SetPipelineState", "set_state"),
            (11, "SetGraphicsRootDescriptorTable", "set_state"),
            (12, "DrawIndexedInstanced", "draw"),
            (20, "SetPipelineState", "set_state"),
            (21, "SetGraphicsRootDescriptorTable", "set_state"),
            (22, "DrawIndexedInstanced", "draw"),
        ],
    )

    result = eye_issue.event_signature_index(
        db,
        target_kinds=["draw"],
        lookback_state_count=2,
    )

    assert result["ok"]
    assert result["pair_count"] == 1
    pair = result["candidate_pairs"][0]
    assert pair["left_candidate"]["event_index"] == 12
    assert pair["right_candidate"]["event_index"] == 22
    assert pair["confidence"] == "medium"


def test_event_signature_index_reclassifies_prefixed_d3d12_sidecar(tmp_path: Path) -> None:
    capture = tmp_path / "frame.ngfx-capture"
    db = _build_functions_db(
        capture,
        [
            (10, "ID3D12GraphicsCommandList_SetPipelineState", "other"),
            (11, "ID3D12GraphicsCommandList_SetGraphicsRootDescriptorTable", "other"),
            (12, "ID3D12GraphicsCommandList_DrawIndexedInstanced", "other"),
            (20, "ID3D12GraphicsCommandList_SetPipelineState", "other"),
            (21, "ID3D12GraphicsCommandList_SetGraphicsRootDescriptorTable", "other"),
            (22, "ID3D12GraphicsCommandList_DrawIndexedInstanced", "other"),
        ],
    )

    result = eye_issue.event_signature_index(
        db,
        target_kinds=["draw"],
        lookback_state_count=2,
    )

    assert result["target_kind_histogram"]["draw"] == 2
    assert result["pair_count"] == 1


def test_dump_only_eye_issue_report_lists_nsight_next_actions(
    tmp_path: Path,
    monkeypatch,
) -> None:
    capture = tmp_path / "frame.ngfx-capture"
    _build_functions_db(
        capture,
        [
            (1, "SetPipelineState", "set_state"),
            (2, "DrawIndexedInstanced", "draw"),
            (3, "SetPipelineState", "set_state"),
            (4, "DrawIndexedInstanced", "draw"),
        ],
    )
    _build_objects_db(capture)
    monkeypatch.setattr(
        eye_issue.deep_capture,
        "deep_capture_capability_report",
        lambda **_: {
            "replacement_assessment": {"recommended": "GPU Trace on Graphics Capture replay"},
            "capability_matrix": [],
            "ranked_next_steps": [],
        },
    )
    monkeypatch.setattr(
        eye_issue.capture_decoder,
        "parse_table_of_contents",
        lambda _: {"ok": True, "metadata": {"primary_api": "D3D12"}, "num_chunks": 1},
    )

    report = eye_issue.dump_only_eye_issue_report(
        capture,
        roi={"x": 960, "y": 128, "w": 64, "h": 64},
    )

    assert report["ok"]
    assert report["dump_only_verdict"]["can_fully_prove_from_dump_only"] is False
    tools = [item["tool"] for item in report["next_nsight_only_actions"]]
    assert "ngfx_eye_issue_event_signatures" in tools
    assert "ngfx_gputrace_capture_replay" in tools
    assert "ngfx_gputrace_shader_pipeline_search" in tools
    assert "ngfx_trace_roi_history" in tools


# ---------------------------------------------------------------------------
# CopyRectPS t0 resolution report (Track A)
# ---------------------------------------------------------------------------


import textwrap  # noqa: E402

from nsight_graphics_mcp import cpp_capture_parser, pso_resolver  # noqa: E402


def _dxbc_bytes(byte: int) -> bytes:
    return bytes(
        [0x44, 0x58, 0x42, 0x43]
        + [byte] * 16
        + [0x01, 0x00, 0x00, 0x00]
        + [0x00] * 8
    )


def _bytes_to_array(name: str, data: bytes) -> str:
    body = ", ".join(f"0x{b:02X}" for b in data)
    return f"static const unsigned char {name}[] = {{ {body} }};\n"


def _copyrect_project(tmp_path: Path, *, right_swaps_table: bool) -> Path:
    """Synthetic Nsight Generate-C++-Capture project with two paired
    CopyRectPS draws.

    If ``right_swaps_table`` is True the right-eye draw uses a different
    GPU descriptor handle at root param 0 — the bug shape we expect the
    resolution report to call out.
    """
    proj = tmp_path / "GeneratedCpp"
    proj.mkdir()
    # Shader blob names contain "CopyRectPS" so _candidate_pso_symbols picks them up.
    blobs = (
        _bytes_to_array("g_VS_dxbc_copyrect", _dxbc_bytes(0xAA))
        + _bytes_to_array("g_PS_CopyRectPS_dxbc", _dxbc_bytes(0xCB))
    )
    pso_create = textwrap.dedent(
        """\
        void CreateCopyRectPSO(ID3D12Device* device) {
            D3D12_GRAPHICS_PIPELINE_STATE_DESC psoDesc = {};
            psoDesc.VS = { g_VS_dxbc_copyrect, sizeof(g_VS_dxbc_copyrect) };
            psoDesc.PS = { g_PS_CopyRectPS_dxbc, sizeof(g_PS_CopyRectPS_dxbc) };
            device->CreateGraphicsPipelineState(&psoDesc, IID_PPV_ARGS(&g_PSO_CopyRectPS));
        }
        """
    )

    right_handle = "g_GpuDescHandle_99" if right_swaps_table else "g_GpuDescHandle_3"
    play = textwrap.dedent(
        f"""\
        void play_frame() {{
            // Left eye CopyRectPS draw
            pCommandList->SetGraphicsRootSignature(g_RootSig_0);
            pCommandList->SetDescriptorHeaps(2, g_DescHeaps_0);
            pCommandList->SetPipelineState(g_PSO_CopyRectPS);
            pCommandList->SetGraphicsRootDescriptorTable(0, g_GpuDescHandle_3);
            pCommandList->OMSetRenderTargets(1, &g_RTV_left, FALSE, nullptr);
            pCommandList->RSSetViewports(1, &g_Viewport_left);
            pCommandList->RSSetScissorRects(1, &g_Scissor_left);
            pCommandList->DrawInstanced(3, 1, 0, 0);

            // Right eye CopyRectPS draw
            pCommandList->SetPipelineState(g_PSO_CopyRectPS);
            pCommandList->SetGraphicsRootDescriptorTable(0, {right_handle});
            pCommandList->OMSetRenderTargets(1, &g_RTV_right, FALSE, nullptr);
            pCommandList->RSSetViewports(1, &g_Viewport_right);
            pCommandList->RSSetScissorRects(1, &g_Scissor_right);
            pCommandList->DrawInstanced(3, 1, 0, 0);
        }}
        """
    )
    (proj / "shaders.cpp").write_text(blobs + pso_create, encoding="utf-8")
    (proj / "play.cpp").write_text(play, encoding="utf-8")
    return proj


def test_copyrect_t0_resolution_report_flags_descriptor_routing(tmp_path: Path) -> None:
    proj = _copyrect_project(tmp_path, right_swaps_table=True)
    cpp_capture_parser.index_cpp_project(proj)
    pso_resolver.index_project_psos(proj)

    report = eye_issue.copyrect_t0_resolution_report(cpp_project_dir=proj)
    assert report["ok"], report
    assert report["candidate_pso_count"] >= 1
    assert "g_PSO_CopyRectPS" in report["candidate_pso_symbols"]
    assert report["copyrect_draws_found"] >= 2
    assert report["paired_count"] >= 1

    pair = report["pairs"][0]
    assert pair["left"]["pso_symbol"] == "g_PSO_CopyRectPS"
    assert pair["right"]["pso_symbol"] == "g_PSO_CopyRectPS"
    verdict = pair["comparison"]["verdict_label"]
    # Same PSO, differing root_params + render targets → either
    # "different_source_or_descriptor_routing" or
    # "different_source_and_target".
    assert verdict in {
        "different_source_or_descriptor_routing",
        "different_source_and_target",
    }
    assert pair["comparison"]["diff_count"] >= 1


def test_copyrect_t0_resolution_report_identical_state(tmp_path: Path) -> None:
    proj = _copyrect_project(tmp_path, right_swaps_table=False)
    cpp_capture_parser.index_cpp_project(proj)
    pso_resolver.index_project_psos(proj)

    report = eye_issue.copyrect_t0_resolution_report(cpp_project_dir=proj)
    assert report["ok"]
    # The right-eye render target / viewport / scissor are still distinct
    # symbols in the synthetic project, so we expect different_target rather
    # than identical_state_at_draw.
    pair = report["pairs"][0]
    assert pair["comparison"]["verdict_label"] in {
        "different_target",
        "different_source_and_target",
        "identical_state_at_draw",
    }


def test_copyrect_t0_resolution_report_requires_indexes(tmp_path: Path) -> None:
    proj = tmp_path / "EmptyProject"
    proj.mkdir()
    report = eye_issue.copyrect_t0_resolution_report(cpp_project_dir=proj)
    assert not report["ok"]
    assert "missing" in report
