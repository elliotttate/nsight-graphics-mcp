from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from nsight_graphics_mcp import rpc_client, rpc_trace


def _frame_hex(method: int, *, slot: int = 0, request_id: int = 0, seq: int = 0) -> str:
    header = rpc_client.RpcMessageHeader(
        category=rpc_client.CATEGORY_BINARY_REPLAY,
        method=method,
        ticket_id=0x1234 + method,
        request_id=request_id,
        seq=seq,
        slot=slot,
    )
    body = rpc_client.RpcMessage(header=header, body=b"\x0a\x03abc").pack()
    return rpc_client.TransportFrame(channel=2, body=body).pack().hex()


def test_decode_rpc_frame_hex_with_transport_header() -> None:
    decoded = rpc_trace.decode_rpc_frame_hex(_frame_hex(17, slot=5, request_id=9, seq=2))

    assert decoded["ok"]
    assert decoded["input_kind"] == "transport_frame"
    assert decoded["transport"]["channel"] == 2
    assert decoded["rpc"]["category"] == 1
    assert decoded["rpc"]["method"] == 17
    assert decoded["rpc"]["slot"] == 5
    assert decoded["labels"]["method"]["frame_debugger_core"] == "MethodPbSerializeFrameCaptureRequest"
    assert decoded["protobuf_body"]["size"] == 5


def test_import_rpc_transcript_and_binding_report_from_json(tmp_path: Path) -> None:
    path = tmp_path / "rpc_frames.json"
    path.write_text(
        json.dumps(
            {
                "frames": [
                    {"wire_hex": _frame_hex(17, slot=4, request_id=100, seq=1)},
                    {"wire_hex": _frame_hex(44, slot=4, request_id=100, seq=2)},
                    {"wire_hex": _frame_hex(45, slot=4, request_id=100, seq=3)},
                    {"wire_hex": _frame_hex(46, slot=4, request_id=100, seq=4)},
                    {"wire_hex": _frame_hex(43, slot=4, request_id=100, seq=5)},
                ]
            }
        ),
        encoding="utf-8",
    )

    imported = rpc_trace.import_rpc_transcript(transcript_path=path)
    report = imported["session_binding_report"]

    assert imported["ok"]
    assert imported["frame_count"] == 5
    assert report["first_nonzero_slot"]["slot"] == 4
    assert report["direct_saved_cpp_export_ready"] is True
    assert report["serialize_loop_methods_observed"] == [17, 43, 44, 45, 46]


def test_direct_export_binding_candidate_from_complete_transcript(tmp_path: Path) -> None:
    path = tmp_path / "rpc_frames.json"
    path.write_text(
        json.dumps(
            {
                "frames": [
                    {"wire_hex": _frame_hex(17, slot=4, request_id=100, seq=1)},
                    {"wire_hex": _frame_hex(44, slot=4, request_id=100, seq=2)},
                    {"wire_hex": _frame_hex(45, slot=4, request_id=100, seq=3)},
                    {"wire_hex": _frame_hex(46, slot=4, request_id=100, seq=4)},
                    {"wire_hex": _frame_hex(43, slot=4, request_id=100, seq=5)},
                ]
            }
        ),
        encoding="utf-8",
    )

    result = rpc_trace.direct_export_binding_candidate_from_transcript(transcript_path=path)

    assert result["ready"] is True
    assert result["binding"]["slot"] == 4
    assert result["binding"]["transport_channel"] == 2
    assert result["binding"]["serialize_request_frame_index"] == 0
    assert result["binding"]["callback_methods_observed"] == [44, 45, 46]


def test_session_binding_report_lists_blockers_without_slot() -> None:
    decoded = [
        rpc_trace.decode_rpc_frame_hex(_frame_hex(1)),
        rpc_trace.decode_rpc_frame_hex(_frame_hex(8)),
    ]

    report = rpc_trace.session_binding_report(decoded)

    assert report["direct_saved_cpp_export_ready"] is False
    assert report["first_nonzero_slot"] is None
    assert any("slot" in item for item in report["blockers"])


def test_capture_open_sequence_report_static_only() -> None:
    report = rpc_trace.capture_open_sequence_report()
    assert report["ok"]
    known = report["known"]
    assert known["transport_invariants"]["frame_magic"] == "0x54 0x08"
    assert known["transport_invariants"]["wire_header_bytes"] == 24
    assert known["transport_invariants"]["rejected_reply_signature"]["slot"] == 11
    assert any(
        step["category_name"] == "CategoryConnection"
        for step in known["candidate_sequence_for_capture_open"]
    )
    assert report["observed"]["available"] is False


def test_capture_open_sequence_report_with_observed_frames() -> None:
    # A frame on CategoryConnection method 1 (AttachMessage candidate).
    connection_header = rpc_client.RpcMessageHeader(
        category=rpc_client.CATEGORY_CONNECTION,
        method=1,
        ticket_id=0x9001,
        request_id=0,
        seq=0,
        slot=0,
    )
    connection_body = rpc_client.RpcMessage(
        header=connection_header, body=b""
    ).pack()
    connection_frame = (
        rpc_client.TransportFrame(channel=0, body=connection_body).pack().hex()
    )

    decoded = [rpc_trace.decode_rpc_frame_hex(connection_frame)]
    report = rpc_trace.capture_open_sequence_report(decoded_frames=decoded)
    assert report["ok"]
    observed = report["observed"]
    assert observed["available"] is True
    assert observed["frame_count"] == 1
    assert observed["first_connection_frame"] is not None
    # The AttachMessage frame is present, so it should NOT appear in the
    # missing-expected-keys list.
    missing_keys = {
        (m["category"], m["method"], m["slot"])
        for m in observed["missing_expected_keys"]
    }
    assert (rpc_client.CATEGORY_CONNECTION, 1, 0) not in missing_keys
    # But BinaryReplay launch (a later step) should still be missing.
    assert (
        rpc_client.CATEGORY_BINARY_REPLAY,
        rpc_client.RpcClient.METHOD_LAUNCH,
        0,
    ) in missing_keys
