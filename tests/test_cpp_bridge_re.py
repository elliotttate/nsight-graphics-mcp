from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from nsight_graphics_mcp import cpp_bridge_re, cpp_capture


def _write_facts(path: Path, decompiled: list[dict[str, str]], strings: list[str]) -> Path:
    facts = {
        "ok": True,
        "schema": "nsight-graphics-mcp.ida-facts.v1",
        "input_path": str(path.with_suffix(".dll")),
        "input_sha256": "00" * 32,
        "ida": {"version": "synthetic"},
        "segments": [],
        "entries": [],
        "function_count": len(decompiled),
        "strings": [{"ea": hex(0x1000 + i), "value": s, "xrefs": []} for i, s in enumerate(strings)],
        "functions_by_name": [],
        "selected_functions": [],
        "decompiled": decompiled,
    }
    path.write_text(json.dumps(facts), encoding="utf-8")
    return path


def test_saved_capture_cpp_bridge_report_from_synthetic_facts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        cpp_bridge_re,
        "_frame_debugger_schema",
        lambda: {
            "ok": True,
            "core_methods": {
                "begin_frame_debugging_request": 1,
                "serialize_frame_capture_request": 17,
                "serialize_frame_capture_reply": 43,
                "open_file_notification": 44,
                "append_file_notification": 45,
                "close_file_notification": 46,
            },
            "messages": {},
        },
    )
    battle = _write_facts(
        tmp_path / "battle_facts.json",
        [
            {
                "ea": "0x180028880",
                "name": "sub_180028880",
                "pseudocode": "PbSerializeReplyMessage PbSerializeRequestMessage FileTransferManager",
            },
            {
                "ea": "0x180042890",
                "name": "sub_180042890",
                "pseudocode": "SerializationBindless SerializationKeepOnRemoteMachine InitializeTransaction",
            },
            {
                "ea": "0x18006DA60",
                "name": "sub_18006DA60",
                "pseudocode": "RequestSaveCaptureCommand PbSerializeReplyMessage Serialization succeeded",
            },
        ],
        [
            "RequestSaveCapture",
            "HostSaveDirectory",
            "ngfx-cppcap",
        ],
    )
    pylon = _write_facts(
        tmp_path / "pylon_facts.json",
        [
            {
                "ea": "0x18015D360",
                "name": "sub_18015D360",
                "pseudocode": "Generate C++ Capture",
            },
            {
                "ea": "0x18015E5A0",
                "name": "sub_18015E5A0",
                "pseudocode": "C++ Capture",
            },
            {
                "ea": "0x180116CD0",
                "name": "sub_180116CD0",
                "pseudocode": "platform/%1/executable platform/%1/arguments platform/%1/environment",
            },
            {
                "ea": "0x1801114C0",
                "name": "sub_1801114C0",
                "pseudocode": "--reset --no-reset --multibuffer",
            },
            {
                "ea": "0x180110200",
                "name": "sub_180110200",
                "pseudocode": "%1=%2",
            },
            {
                "ea": "0x180147C20",
                "name": "sub_180147C20",
                "pseudocode": "launcher",
            },
        ],
        [
            "Other Activity",
            "Launch another activity",
            "PylonFusionActivityDialog",
        ],
    )

    report = cpp_bridge_re.saved_capture_cpp_bridge_report(
        battle_facts_path=str(battle),
        pylon_facts_path=str(pylon),
    )

    assert report["ok"]
    assert report["status"] == "pylon_activity_handoff_pinned_direct_rpc_not_yet_live_verified"
    assert report["facts"]["battle_plugin"]["has_cached_facts"]
    assert report["facts"]["pylon_plugin"]["has_cached_facts"]
    assert report["private_protocol"]["frame_debugger_schema"]["core_methods"][
        "serialize_frame_capture_request"
    ] == 17
    assert report["private_protocol"]["direct_rpc_candidate"]["known_gap"]
    assert report["private_protocol"]["direct_rpc_candidate"]["category_binding"]["pylon_replay_category"][
        "BinaryReplay"
    ] == 1
    assert report["private_protocol"]["activity_bridge_candidate"]["pinned"] is True
    assert (
        report["private_protocol"]["activity_bridge_candidate"]["handoff_preview"]["executable_name"]
        == "ngfx-replay.exe"
    )
    assert report["rerun"]["tool"] == "ngfx_cpp_capture_saved_bridge_re_analyze"

    battle_functions = report["battle_plugin_evidence"]["functions"]
    assert battle_functions[0]["ea"] == "0x180028880"
    assert battle_functions[0]["confidence"] == "high"

    pylon_functions = report["pylon_plugin_evidence"]["functions"]
    assert any(f["ea"] == "0x18015D360" and f["confidence"] == "high" for f in pylon_functions)
    assert any(f["ea"] == "0x1801114C0" and f["confidence"] == "high" for f in pylon_functions)


def test_pylon_saved_capture_handoff_preview_builds_platform_launcher_map() -> None:
    preview = cpp_bridge_re.pylon_saved_capture_handoff_preview(
        r"E:\captures\frame.ngfx-gfxcap",
        additional_args=["--reset", "--multibuffer"],
        environment={"A": "1", "B": "two"},
        output_dir=r"E:\captures\cpp",
        install_host_dir=r"C:\Nsight\host\windows-desktop-nomad-x64",
    )

    assert preview["ok"]
    assert preview["activity"]["id"] == 3
    assert preview["activity"]["name"] == "Generate C++ Capture"
    assert preview["executable"].endswith(r"ngfx-replay.exe")
    assert preview["arguments"] == r'"E:\captures\frame.ngfx-gfxcap" --reset --multibuffer'
    assert preview["environment_string"] == "A=1;B=two"
    assert preview["platform_settings"]["platform/win32/device"] == "localhost"
    assert preview["platform_settings"]["platform/win32/arguments"] == preview["arguments"]
    assert preview["project_launcher_object"]["key"] == "launcher"
    assert preview["output_directory_state"]["not_in_pylon_argv"] is True


def test_pylon_private_executor_report_and_probe_plan() -> None:
    report = cpp_bridge_re.pylon_private_executor_re_report()

    assert report["ok"]
    assert report["preferred_path"] == "pylon_in_process_activity_manager"
    assert report["pylon_in_process_activity_manager"]["callsite"] == "PylonPlugin!sub_180116CD0"
    assert "ngfx_pylon_bridge_helper_scaffold" in report["new_mcp_surfaces"].values()

    plan = cpp_bridge_re.pylon_bridge_probe_plan(
        r"E:\captures\frame.ngfx-gfxcap",
        output_dir=r"E:\captures\cpp",
    )
    assert plan["ok"]
    assert plan["handoff_preview"]["activity"]["id"] == 3
    assert any("sub_180116CD0" in probe["function"] for probe in plan["probes"])


def test_pylon_activity_manager_static_binding_report_from_synthetic_facts(tmp_path: Path) -> None:
    pylon = _write_facts(
        tmp_path / "pylon_static_facts.json",
        [
            {
                "ea": "0x180116CD0",
                "name": "sub_180116CD0",
                "pseudocode": """
                v5 = _std_type_info_name(&qword_180678E98, &unk_1806D89E0);
                v10 = _std_type_info_name(&qword_180677640, &unk_1806D89E0);
                if ( (*(unsigned __int8 (__fastcall **)(__int64))(*(_QWORD *)v12 + 240LL))(v12) ) {
                  (*(void (__fastcall **)(__int64, volatile signed __int32 **, _QWORD))(*(_QWORD *)v7 + 208LL))(v7, v51, 0LL);
                  QString::QString((QString *)v57, "platform/%1/device");
                  QString::QString((QString *)v57, "platform/%1/executable");
                  QString::QString((QString *)v54, "platform/%1/arguments");
                  QString::QString((QString *)v54, "platform/%1/workingdir");
                  QString::QString((QString *)v54, "platform/%1/environment");
                  (*(void (__fastcall **)(__int64, volatile signed __int32 **))(*(_QWORD *)v7 + 200LL))(v7, &v48);
                  (*(void (__fastcall **)(__int64))(*(_QWORD *)v7 + 264LL))(v7);
                  (*(void (__fastcall **)(__int64, volatile signed __int32 **))(*(_QWORD *)v7 + 200LL))(v7, v51);
                }
                """,
            },
            {
                "ea": "0x180147480",
                "name": "sub_180147480",
                "pseudocode": "v30 = _std_type_info_name(&qword_18064D2F8, &unk_1806D89E0);",
            },
        ],
        ["platform/%1/executable"],
    )

    report = cpp_bridge_re.pylon_activity_manager_static_binding_report(pylon_facts_path=str(pylon))

    assert report["ok"]
    assert report["direct_reentry"]["function_rva"] == "0x116cd0"
    assert report["direct_reentry"]["signature"] == "void __fastcall(void* saved_capture_activity_page_this)"
    assert report["launcher_keys_confirmed"] == [
        "platform/%1/device",
        "platform/%1/executable",
        "platform/%1/arguments",
        "platform/%1/workingdir",
        "platform/%1/environment",
    ]
    assert [item["offset"] for item in report["activity_manager_vtable_calls_recovered"]] == [208, 200, 264, 200]


def test_pylon_bridge_helper_scaffold_writes_probe_files(tmp_path: Path) -> None:
    result = cpp_bridge_re.pylon_bridge_helper_scaffold(
        tmp_path / "bridge",
        capture=r"E:\captures\frame.ngfx-gfxcap",
        output_dir=r"E:\captures\cpp",
    )

    assert result["ok"]
    files = {Path(path).name for path in result["files"]}
    assert {
        "README.md",
        "frida_pylon_bridge_probe.js",
        "pylon_bridge_protocol.json",
        "pylon_private_binding.schema.json",
        "pylon_private_export_request.example.json",
        "pylon_bridge_probe.cpp",
        "CMakeLists.txt",
    } <= files
    protocol = json.loads((tmp_path / "bridge" / "pylon_bridge_protocol.json").read_text(encoding="utf-8"))
    assert protocol["activity"]["id"] == 3
    assert protocol["handoff_preview"]["output_directory_state"]["requested_output_dir"] == r"E:\captures\cpp"


def test_pylon_bridge_probe_log_analyze_builds_binding_hypotheses(tmp_path: Path) -> None:
    log_path = tmp_path / "probe.ndjson"
    messages = [
        {"type": "send", "payload": {"kind": "ready", "pid": 1234, "base": "0x7ffa00000000"}},
        {
            "type": "send",
            "payload": {
                "kind": "enter",
                "name": "fusion_dialog_accept",
                "thread_id": 10,
                "arg0": "0x1111",
                "arg1": "0x2222",
                "arg2": "0x3333",
            },
        },
        {
            "type": "send",
            "payload": {
                "kind": "enter",
                "name": "saved_capture_other_activity_start",
                "thread_id": 10,
                "arg0": "0xaaaa",
                "arg1": "0xbbbb",
                "arg2": "0xcccc",
                "backtrace": "PylonPlugin!sub_180116CD0",
            },
        },
    ]
    log_path.write_text("\n".join(json.dumps(item) for item in messages), encoding="utf-8")

    report = cpp_bridge_re.pylon_bridge_probe_log_analyze(log_path=log_path)

    assert report["ok"]
    assert report["bridge_ready"] is True
    assert report["binding_hypotheses"]["pylon_module_base"] == "0x7ffa00000000"
    assert report["binding_hypotheses"]["process_id"] == 1234
    assert report["binding_hypotheses"]["saved_capture_start_this_candidate"] == "0xaaaa"
    assert report["functions"]["saved_capture_other_activity_start"]["arg0"]["stable"] is True


def test_pylon_private_binding_from_probe_writes_guarded_binding(tmp_path: Path) -> None:
    log_path = tmp_path / "probe.ndjson"
    log_path.write_text(
        "\n".join(
            [
                'NGFX_MCP_EVENT {"kind":"ready","pid":1234,"base":"0x7ffa00000000"}',
                (
                    'NGFX_MCP_EVENT {"kind":"enter","name":"fusion_dialog_accept",'
                    '"thread_id":10,"arg0":"0x1111"}'
                ),
                (
                    'NGFX_MCP_EVENT {"kind":"enter","name":"saved_capture_other_activity_start",'
                    '"thread_id":10,"arg0":"0xaaaa"}'
                ),
            ]
        ),
        encoding="utf-8",
    )

    result = cpp_bridge_re.pylon_private_binding_from_probe(
        probe_log_path=log_path,
        out_path=tmp_path / "binding.json",
    )

    assert result["ok"]
    assert result["probe_binding_ready"] is True
    assert result["ready"] is False
    assert result["binding"]["saved_capture_start_this"] == "0xaaaa"
    assert result["binding"]["source_process"]["pid"] == 1234
    assert result["binding"]["inprocess_call_ready"] is False
    assert (tmp_path / "binding.json").is_file()


def test_pylon_direct_call_binding_from_probe_is_ready_with_this_pointer(tmp_path: Path) -> None:
    log_path = tmp_path / "probe.ndjson"
    log_path.write_text(
        "\n".join(
            [
                'NGFX_MCP_EVENT {"kind":"ready","pid":1234,"base":"0x7ffa00000000"}',
                (
                    'NGFX_MCP_EVENT {"kind":"enter","name":"saved_capture_other_activity_start",'
                    '"thread_id":10,"arg0":"0xaaaa"}'
                ),
            ]
        ),
        encoding="utf-8",
    )

    result = cpp_bridge_re.pylon_direct_call_binding_from_probe(
        probe_log_path=log_path,
        out_path=tmp_path / "direct_binding.json",
    )

    assert result["ready"] is True
    assert result["binding"]["direct_reentry_call"]["ready_to_attempt"] is True
    assert result["binding"]["direct_reentry_call"]["function_rva"] == "0x116cd0"
    assert result["binding"]["source_process"]["pid"] == 1234
    assert result["binding"]["recommended_invocation"]["tool"] == "ngfx_pylon_frida_direct_call_run"
    assert (tmp_path / "direct_binding.json").is_file()


def test_pylon_bridge_probe_run_dry_run_writes_scaffold(tmp_path: Path) -> None:
    result = cpp_bridge_re.pylon_bridge_probe_run(
        tmp_path / "probe",
        capture=r"E:\captures\frame.ngfx-gfxcap",
        output_dir=r"E:\captures\cpp",
        pid=1234,
        dry_run=True,
    )

    assert result["ok"]
    assert result["status"] == "dry_run"
    assert result["command"][-2:] == ["-l", str(tmp_path / "probe" / "frida_pylon_bridge_probe.js")]
    assert (tmp_path / "probe" / "frida_pylon_bridge_probe.js").is_file()


def test_private_executor_readiness_report_compares_paths(tmp_path: Path) -> None:
    probe_log = tmp_path / "probe.ndjson"
    probe_log.write_text(
        "\n".join(
            [
                'NGFX_MCP_EVENT {"kind":"ready","pid":1234,"base":"0x7ffa00000000"}',
                (
                    'NGFX_MCP_EVENT {"kind":"enter","name":"saved_capture_other_activity_start",'
                    '"thread_id":10,"arg0":"0xaaaa"}'
                ),
            ]
        ),
        encoding="utf-8",
    )

    report = cpp_bridge_re.private_executor_readiness_report(probe_log_path=str(probe_log))

    assert report["ok"]
    assert report["recommended_next_path"] == "pylon_frida_direct_reentry"
    assert report["pylon"]["ready"] is True
    assert report["pylon"]["frida_direct_reentry_ready"] is True
    assert "No RPC transcript supplied." in report["direct_rpc"]["blockers"]


def test_pylon_frida_direct_call_run_dry_run_writes_script(tmp_path: Path) -> None:
    binding = {
        "schema": "nsight-graphics-mcp.pylon-private-binding.v1",
        "target_module": "PylonPlugin.dll",
        "source_process": {"pid": 1234},
        "direct_reentry_call": {
            "ready_to_attempt": True,
            "module_base": "0x7ffa00000000",
            "this_pointer": "0xaaaa",
            "ui_thread_id": "10",
            "function_rva": "0x116cd0",
        },
    }

    result = cpp_bridge_re.pylon_frida_direct_call_run(
        tmp_path / "direct",
        binding=binding,
        pid=1234,
        dry_run=True,
    )

    assert result["ok"]
    assert result["status"] == "dry_run"
    assert result["command"][-2:] == ["-l", str(tmp_path / "direct" / "frida_pylon_direct_call.js")]
    script = (tmp_path / "direct" / "frida_pylon_direct_call.js").read_text(encoding="utf-8")
    assert "NativeFunction" in script
    assert "pylon_direct_call_blocked_stale_process_binding" in script


def test_pylon_private_bridge_invoke_blocks_without_ready_binding(tmp_path: Path) -> None:
    binding = {
        "schema": "nsight-graphics-mcp.pylon-private-binding.v1",
        "inprocess_call_ready": False,
        "missing_private_call_fields": ["call_signature_confirmed"],
    }

    result = cpp_bridge_re.pylon_private_bridge_invoke(
        r"E:\captures\frame.ngfx-gfxcap",
        output_dir=str(tmp_path / "cpp"),
        bridge_exe=str(tmp_path / "missing_bridge.exe"),
        binding=binding,
        dry_run=False,
    )

    assert result["ok"] is False
    assert result["headless_export_invoked"] is False
    assert "call_signature_confirmed" in result["blockers"]
    assert any("Bridge executable not found" in item for item in result["blockers"])


def test_private_executor_evidence_bundle_includes_probe_and_rpc_reports(tmp_path: Path) -> None:
    probe_log = tmp_path / "probe.ndjson"
    probe_log.write_text(
        "\n".join(
            [
                'NGFX_MCP_EVENT {"kind":"ready","base":"0x7ffa00000000"}',
                (
                    'NGFX_MCP_EVENT {"kind":"enter","name":"saved_capture_other_activity_start",'
                    '"thread_id":10,"arg0":"0xaaaa"}'
                ),
            ]
        ),
        encoding="utf-8",
    )
    rpc_frame = cpp_bridge_re.rpc_trace.rpc_client.TransportFrame(
        channel=0,
        body=cpp_bridge_re.rpc_trace.rpc_client.RpcMessage(
            header=cpp_bridge_re.rpc_trace.rpc_client.RpcMessageHeader(category=1, method=17, slot=2),
            body=b"",
        ).pack(),
    ).pack().hex()
    rpc_path = tmp_path / "rpc.json"
    rpc_path.write_text(json.dumps({"frames": [{"wire_hex": rpc_frame}]}), encoding="utf-8")

    result = cpp_bridge_re.private_executor_evidence_bundle(
        tmp_path / "bundle.zip",
        capture=r"E:\captures\frame.ngfx-gfxcap",
        output_dir=r"E:\captures\cpp",
        probe_log_path=str(probe_log),
        rpc_transcript_path=str(rpc_path),
    )

    assert result["ok"]
    assert result["reports"]["probe_analysis_included"] is True
    assert result["reports"]["rpc_transcript_included"] is True
    with zipfile.ZipFile(result["zip_path"]) as zf:
        assert "manifest.json" in zf.namelist()
        assert "reports/pylon_probe_analysis.json" in zf.namelist()
        assert "reports/rpc_transcript_import.json" in zf.namelist()


def test_pylon_saved_cpp_export_returns_honest_private_blocker(tmp_path: Path) -> None:
    result = cpp_bridge_re.pylon_saved_cpp_export(
        r"E:\captures\frame.ngfx-gfxcap",
        output_dir=r"E:\captures\cpp",
        scaffold_dir=str(tmp_path / "bridge"),
    )

    assert result["ok"] is False
    assert result["status"] == "blocked_requires_in_process_pylon_activity_manager"
    assert result["handoff_preview"]["activity"]["name"] == "Generate C++ Capture"
    assert result["scaffold"]["ok"]
    assert result["bridge_invoke"] is None


def test_frame_debugger_serialize_rpc_plan_is_machine_readable() -> None:
    plan = cpp_bridge_re.frame_debugger_serialize_rpc_plan(
        output_dir=r"E:\captures\cpp",
        rpc_session_handle="fdrpc_test",
    )

    assert plan["ok"]
    assert plan["ready_to_send"] is False
    assert plan["rpc_session_handle"] == "fdrpc_test"
    assert plan["category_binding"]["pylon_replay_category"] == 1
    assert plan["request"]["values"]["OutputFolderPath"] == r"E:\captures\cpp"
    assert "MethodPbAppendFileNotification (45)" in plan["required_callback_loop"][1]


def test_file_transfer_apply_open_append_close(tmp_path: Path) -> None:
    out = tmp_path / "cpp"
    opened = cpp_bridge_re.frame_debugger_file_transfer_apply(
        str(out),
        {"kind": "MethodPbOpenFileNotification", "FileId": "1", "RelativePath": "src/replay.cpp"},
    )
    assert opened["ok"]
    appended = cpp_bridge_re.frame_debugger_file_transfer_apply(
        str(out),
        {"kind": "MethodPbAppendFileNotification", "FileId": "1", "Data": "SGVsbG8="},
    )
    assert appended["bytes_written"] == 5
    closed = cpp_bridge_re.frame_debugger_file_transfer_apply(
        str(out),
        {"kind": "MethodPbCloseFileNotification", "FileId": "1"},
    )
    assert closed["open_file_count"] == 0
    assert (out / "src" / "replay.cpp").read_text(encoding="utf-8") == "Hello"


def test_saved_cpp_output_dir_setting_preview(tmp_path: Path) -> None:
    plan = cpp_capture.set_saved_cpp_output_dir_setting(tmp_path / "cpp", write=False)
    assert plan["ok"]
    assert plan["written"] is False
    assert plan["setting_name"] == "Serialization Save Directory"
    assert "New-ItemProperty" in plan["powershell_preview"]


def test_generate_cpp_capture_output_classifier_detects_d3d12_serializer_removal() -> None:
    classification = cpp_capture.classify_generate_cpp_capture_output(
        stdout=(
            "Generating C++ capture...\n"
            "Exporting C++ Capture failed with an internal error\n"
            "Export of C++ Capture could not complete: Serializing apps to C++ capture "
            "using D3D11 or D3D12 is no longer supported - please migrate to the Graphics Capture Activity\n"
        ),
        returncode=1,
    )

    assert classification is not None
    assert classification["status"] == "d3d11_d3d12_cpp_capture_serializer_removed"
    assert classification["retryable"] is False
    assert "Graphics Capture Activity" in classification["nsight_guidance"]


def test_generate_cpp_capture_output_classifier_detects_missing_output_dir() -> None:
    classification = cpp_capture.classify_generate_cpp_capture_output(
        stdout=r"No such output directory: E:\captures\cpp",
        returncode=1,
    )

    assert classification is not None
    assert classification["status"] == "output_dir_missing"
    assert classification["retryable"] is True


def test_shader_fix_regression_score_rejects_weak_fix() -> None:
    score = cpp_capture.shader_fix_regression_score(
        before_score=1.0,
        after_score=0.9,
        repeated_runs=1,
        left_eye_delta=0.1,
    )
    assert score["decision"] == "reject"
    assert {c["name"] for c in score["failed_checks"]} >= {"roi_improved", "repeated_runs"}


async def test_saved_capture_headless_attempt_validates_existing_project(tmp_path: Path) -> None:
    capture = tmp_path / "frame.ngfx-gfxcap"
    capture.write_bytes(b"not a real capture, metadata validation will warn only")
    project = tmp_path / "cpp"
    project.mkdir()
    (project / "Replay.sln").write_text("Microsoft Visual Studio Solution File", encoding="utf-8")
    (project / "replay.cpp").write_text(
        """
        void play_frame() {
            pCommandList->SetPipelineState(g_PSO_1);
            pCommandList->DrawInstanced(3, 1, 0, 0);
        }
        """,
        encoding="utf-8",
    )

    result = await cpp_capture.saved_capture_headless_attempt(
        capture,
        output_dir=project,
        backends=[],
        index_psos=False,
    )

    assert result["ok"]
    assert result["status"] == "existing_project_validated"
    assert result["validation"]["solution"].endswith("Replay.sln")
    assert result["validation"]["call_index"]["record_count"] >= 2


async def test_export_validation_and_artifact_bundle(tmp_path: Path) -> None:
    project = tmp_path / "cpp"
    project.mkdir()
    (project / "Replay.sln").write_text("Microsoft Visual Studio Solution File", encoding="utf-8")
    (project / "replay.cpp").write_text(
        """
        void play_frame() {
            pCommandList->SetPipelineState(g_PSO_1);
            pCommandList->DrawInstanced(3, 1, 0, 0);
        }
        """,
        encoding="utf-8",
    )
    validation = await cpp_capture.validate_cpp_capture_export(project, index_psos=False)
    assert validation["ok"]
    assert validation["event_sequence_alignment"] is None

    bundle = cpp_capture.bundle_saved_capture_artifacts(
        tmp_path / "bundle.zip",
        project_dir=project,
        validation=validation,
        include_project_sources=True,
    )
    assert bundle["ok"]
    with zipfile.ZipFile(bundle["zip_path"]) as zf:
        assert "manifest.json" in zf.namelist()
        assert "reports/export_validation.json" in zf.namelist()


async def test_saved_capture_headless_attempt_reports_private_blockers(tmp_path: Path) -> None:
    capture = tmp_path / "frame.ngfx-gfxcap"
    capture.write_bytes(b"placeholder")
    output = tmp_path / "out"

    result = await cpp_capture.saved_capture_headless_attempt(
        capture,
        output_dir=output,
        backends=["pylon_private_activity_manager", "direct_frame_debugger_rpc"],
        launch_ui_fallback=False,
    )

    assert result["ok"] is False
    assert result["status"] == "no_backend_completed_export"
    statuses = {attempt["backend"]: attempt["status"] for attempt in result["attempts"]}
    assert statuses["pylon_private_activity_manager"] == "blocked_requires_in_process_pylon_activity_manager"
    assert statuses["direct_frame_debugger_rpc"] == "blocked_requires_binaryreplay_session_binding"
