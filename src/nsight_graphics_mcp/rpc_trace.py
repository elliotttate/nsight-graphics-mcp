"""Offline ngfx-rpc frame transcript helpers.

These helpers are deliberately independent from a live ``ngfx-rpc.exe``. They
let an MCP caller decode captured transport frames, identify the header fields
that matter for private BinaryReplay binding, and summarize whether a transcript
contains enough evidence to replay the FrameDebugger serialize request.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from . import rpc_client

SYSTEM_CATEGORY_NAMES = {
    rpc_client.CATEGORY_DIAGNOSTICS: "CategoryDiagnostics",
    rpc_client.CATEGORY_SYSTEM_INFO: "CategorySystemInfo",
    rpc_client.CATEGORY_DISCOVERY: "CategoryDiscovery",
    rpc_client.CATEGORY_HANDSHAKE: "CategoryHandshake",
    rpc_client.CATEGORY_DEVICE_INFO: "CategoryDeviceInfo",
    rpc_client.CATEGORY_CONNECTION: "CategoryConnection",
    rpc_client.CATEGORY_LOCAL_DISCOVERY: "CategoryLocalDiscovery",
}

BINARY_REPLAY_METHOD_NAMES = {
    rpc_client.RpcClient.METHOD_LAUNCH: "MethodLaunchRequest",
    rpc_client.RpcClient.METHOD_METADATA: "MethodMetadataRequest",
    rpc_client.RpcClient.METHOD_EVENT_INFO: "MethodEventInfoRequest",
    rpc_client.RpcClient.METHOD_EVENT_DETAILS: "MethodEventDetailsRequest",
    rpc_client.RpcClient.METHOD_API_INSPECTOR_STATE: "MethodApiInspectorStateRequest",
    rpc_client.RpcClient.METHOD_IMAGE_SUBRESOURCE_DATA: "MethodImageSubresourceDataRequest",
    rpc_client.RpcClient.METHOD_RESOURCE_ACCESS_HISTORY: "MethodResourceAccessHistoryRequest",
    rpc_client.RpcClient.METHOD_RESOURCE_INFO: "MethodResourceInfoRequest",
    rpc_client.RpcClient.METHOD_DESCRIPTOR_STATE: "MethodDescriptorStateRequest",
    rpc_client.RpcClient.METHOD_ROOT_PARAMETERS: "MethodRootParametersRequest",
    rpc_client.RpcClient.METHOD_PIXEL_HISTORY: "MethodPixelHistoryRequest",
}

FRAME_DEBUGGER_CORE_METHOD_NAMES = {
    1: "MethodPbBeginFrameDebuggingRequest",
    17: "MethodPbSerializeFrameCaptureRequest",
    43: "MethodPbSerializeFrameCaptureReply",
    44: "MethodPbOpenFileNotification",
    45: "MethodPbAppendFileNotification",
    46: "MethodPbCloseFileNotification",
}

_HEX_ONLY_RE = re.compile(r"^[0-9a-fA-F\s:_,-]+$")


def _clean_hex(text: str) -> str:
    raw = text.strip()
    if raw.lower().startswith("0x") and re.fullmatch(r"(?i)0x[0-9a-f]+", raw):
        raw = raw[2:]
    if _HEX_ONLY_RE.fullmatch(raw):
        cleaned = re.sub(r"[^0-9a-fA-F]", "", raw)
        if len(cleaned) % 2 == 0:
            return cleaned
    match = re.search(r"(?i)(?:wire_hex|frame_hex|body_hex|hex|data)\s*[:=]\s*[\"']?([0-9a-f\s:_,-]+)", raw)
    if match:
        cleaned = re.sub(r"[^0-9a-fA-F]", "", match.group(1))
        if len(cleaned) % 2 == 0:
            return cleaned
    return re.sub(r"[^0-9a-fA-F]", "", raw)


def _frame_hex_from_item(item: Any) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        for key in ("wire_hex", "frame_hex", "hex", "data", "body_hex"):
            value = item.get(key)
            if isinstance(value, str):
                return value
    raise TypeError(f"unsupported transcript item: {type(item).__name__}")


def _frame_items_from_json(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("frames", "packets", "messages", "records"):
            if isinstance(value.get(key), list):
                return list(value[key])
        return [value]
    raise TypeError(f"unsupported transcript JSON root: {type(value).__name__}")


def _frame_items_from_text(text: str) -> list[str]:
    items: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError:
            value = None
        if value is not None:
            items.extend(_frame_items_from_json(value))
            continue
        cleaned = _clean_hex(stripped)
        if len(cleaned) >= rpc_client.MESSAGE_HEADER_WIRE_SIZE * 2 and len(cleaned) % 2 == 0:
            items.append(cleaned)
    return items


def _labels_for(category: int, method: int) -> dict[str, Any]:
    labels: dict[str, Any] = {
        "category": {
            "system": SYSTEM_CATEGORY_NAMES.get(category),
            "pylon_replay": "CategoryBinaryReplay" if category == rpc_client.CATEGORY_BINARY_REPLAY else None,
        },
        "method": {
            "binary_replay": BINARY_REPLAY_METHOD_NAMES.get(method),
            "frame_debugger_core": FRAME_DEBUGGER_CORE_METHOD_NAMES.get(method),
        },
        "namespace_candidates": [],
    }
    system_category = SYSTEM_CATEGORY_NAMES.get(category)
    if system_category:
        labels["namespace_candidates"].append(
            {"namespace": "NV.TPS.System", "category": system_category, "method": method}
        )
    if category == rpc_client.CATEGORY_BINARY_REPLAY:
        labels["namespace_candidates"].append(
            {
                "namespace": "NV.Pylon.Replay",
                "category": "CategoryBinaryReplay",
                "method": BINARY_REPLAY_METHOD_NAMES.get(method),
            }
        )
        if method in FRAME_DEBUGGER_CORE_METHOD_NAMES:
            labels["namespace_candidates"].append(
                {
                    "namespace": "Nvda.Messaging.Graphics.FrameDebugger",
                    "category": "BinaryReplay/CoreMethod candidate",
                    "method": FRAME_DEBUGGER_CORE_METHOD_NAMES[method],
                }
            )
    return labels


def decode_rpc_frame_hex(
    frame_hex: str,
    *,
    has_transport_header: bool | None = None,
    include_body_hex: bool = False,
    body_preview_bytes: int = 96,
    frame_index: int | None = None,
) -> dict[str, Any]:
    """Decode one ngfx-rpc transport frame or raw RPC message body from hex."""
    cleaned = _clean_hex(frame_hex)
    if not cleaned:
        return {"ok": False, "frame_index": frame_index, "error": "empty hex input"}
    if len(cleaned) % 2:
        return {"ok": False, "frame_index": frame_index, "error": "hex input has odd length"}

    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as exc:
        return {"ok": False, "frame_index": frame_index, "error": str(exc)}

    transport: dict[str, Any] | None = None
    body = raw
    auto_transport = (
        len(raw) >= rpc_client.FRAME_HEADER_SIZE
        and raw[0] == rpc_client.FRAME_MAGIC_0
        and raw[1] == rpc_client.FRAME_MAGIC_1
    )
    use_transport = auto_transport if has_transport_header is None else bool(has_transport_header)
    if use_transport:
        if len(raw) < rpc_client.FRAME_HEADER_SIZE:
            return {"ok": False, "frame_index": frame_index, "error": "transport frame shorter than 8 bytes"}
        try:
            magic_0, magic_1, channel, flag, body_size = rpc_client.TransportFrame.unpack_header(
                raw[: rpc_client.FRAME_HEADER_SIZE]
            )
        except Exception as exc:
            return {"ok": False, "frame_index": frame_index, "error": f"{type(exc).__name__}: {exc}"}
        if has_transport_header is True and (
            magic_0 != rpc_client.FRAME_MAGIC_0 or magic_1 != rpc_client.FRAME_MAGIC_1
        ):
            return {
                "ok": False,
                "frame_index": frame_index,
                "error": f"bad transport magic: 0x{magic_0:02x}{magic_1:02x}",
            }
        available = max(0, len(raw) - rpc_client.FRAME_HEADER_SIZE)
        body = raw[rpc_client.FRAME_HEADER_SIZE : rpc_client.FRAME_HEADER_SIZE + min(body_size, available)]
        transport = {
            "magic": f"0x{magic_0:02x}{magic_1:02x}",
            "channel": channel,
            "flag": flag,
            "declared_body_size": body_size,
            "available_body_size": available,
            "body_truncated": available < body_size,
            "trailing_bytes": max(0, available - body_size),
        }

    result: dict[str, Any] = {
        "ok": True,
        "frame_index": frame_index,
        "input_size": len(raw),
        "input_kind": "transport_frame" if transport else "rpc_message_body",
        "transport": transport,
    }
    if len(body) < rpc_client.MESSAGE_HEADER_WIRE_SIZE:
        result.update(
            {
                "ok": False,
                "error": f"RPC message body shorter than {rpc_client.MESSAGE_HEADER_WIRE_SIZE} bytes",
                "body_size": len(body),
            }
        )
        return result

    try:
        msg = rpc_client.RpcMessage.unpack(body)
    except Exception as exc:
        result.update({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return result

    header = msg.header
    result["rpc"] = {
        "ticket_id": header.ticket_id,
        "request_id": header.request_id,
        "seq": header.seq,
        "category": header.category,
        "method": header.method,
        "slot": header.slot,
        "sertype": header.sertype,
        "rpc_header_hex": body[: rpc_client.MESSAGE_HEADER_WIRE_SIZE].hex(),
    }
    result["labels"] = _labels_for(header.category, header.method)
    body_hex = msg.body.hex()
    body_preview_hex_len = max(0, int(body_preview_bytes)) * 2
    result["protobuf_body"] = {
        "size": len(msg.body),
        "hex_preview": body_hex[:body_preview_hex_len],
        "truncated": len(body_hex) > body_preview_hex_len,
    }
    if include_body_hex:
        result["protobuf_body"]["hex"] = body_hex
    return result


def import_rpc_transcript(
    *,
    transcript_path: str | Path | None = None,
    frames: list[str] | None = None,
    has_transport_header: bool | None = None,
    include_body_hex: bool = False,
) -> dict[str, Any]:
    """Import and decode a JSON, NDJSON, or plain-hex RPC transcript."""
    raw_items: list[Any] = []
    source: dict[str, Any]
    if transcript_path:
        path = Path(transcript_path)
        text = path.read_text(encoding="utf-8")
        try:
            parsed = json.loads(text)
            raw_items = _frame_items_from_json(parsed)
        except json.JSONDecodeError:
            raw_items = _frame_items_from_text(text)
        source = {"kind": "path", "path": str(path)}
    else:
        raw_items = list(frames or [])
        source = {"kind": "inline_frames", "count": len(raw_items)}

    decoded: list[dict[str, Any]] = []
    for index, item in enumerate(raw_items):
        try:
            frame_hex = _frame_hex_from_item(item)
            decoded.append(
                decode_rpc_frame_hex(
                    frame_hex,
                    has_transport_header=has_transport_header,
                    include_body_hex=include_body_hex,
                    frame_index=index,
                )
            )
        except Exception as exc:
            decoded.append({"ok": False, "frame_index": index, "error": f"{type(exc).__name__}: {exc}"})

    return {
        "ok": any(item.get("ok") for item in decoded) if decoded else False,
        "source": source,
        "frame_count": len(decoded),
        "decoded": decoded,
        "session_binding_report": session_binding_report(decoded),
    }


def _counter_dict(counter: Counter[Any]) -> dict[str, int]:
    return {str(key): int(value) for key, value in sorted(counter.items(), key=lambda item: str(item[0]))}


def session_binding_report(decoded_frames: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize private BinaryReplay binding evidence from decoded frames."""
    rpc_frames = [f for f in decoded_frames if f.get("ok") and isinstance(f.get("rpc"), dict)]
    categories: Counter[int] = Counter()
    methods: Counter[str] = Counter()
    slots: Counter[int] = Counter()
    channels: Counter[int] = Counter()
    request_ids: Counter[int] = Counter()
    seqs: Counter[int] = Counter()
    binary_replay_frames: list[dict[str, Any]] = []
    handshake_frames: list[dict[str, Any]] = []
    binding_candidates: list[dict[str, Any]] = []

    for frame in rpc_frames:
        rpc = frame["rpc"]
        category = int(rpc["category"])
        method = int(rpc["method"])
        slot = int(rpc["slot"])
        categories[category] += 1
        methods[f"{category}:{method}"] += 1
        slots[slot] += 1
        if frame.get("transport"):
            channels[int(frame["transport"]["channel"])] += 1
        if int(rpc["request_id"]):
            request_ids[int(rpc["request_id"])] += 1
        if int(rpc["seq"]):
            seqs[int(rpc["seq"])] += 1

        compact = {
            "frame_index": frame.get("frame_index"),
            "ticket_id": rpc["ticket_id"],
            "request_id": rpc["request_id"],
            "seq": rpc["seq"],
            "category": category,
            "method": method,
            "slot": slot,
            "labels": frame.get("labels"),
        }
        if category == rpc_client.CATEGORY_BINARY_REPLAY:
            binary_replay_frames.append(compact)
            if slot or int(rpc["request_id"]) or int(rpc["seq"]):
                binding_candidates.append(compact)
        if category == rpc_client.CATEGORY_HANDSHAKE:
            handshake_frames.append(compact)

    first_nonzero_slot = next(
        (
            {
                "frame_index": f.get("frame_index"),
                "slot": f["rpc"]["slot"],
                "category": f["rpc"]["category"],
                "method": f["rpc"]["method"],
                "ticket_id": f["rpc"]["ticket_id"],
            }
            for f in rpc_frames
            if int(f["rpc"]["slot"])
        ),
        None,
    )
    observed_binary_methods = {
        int(f["rpc"]["method"])
        for f in rpc_frames
        if int(f["rpc"]["category"]) == rpc_client.CATEGORY_BINARY_REPLAY
    }
    serialize_methods = {17, 43, 44, 45, 46}
    has_serialize_loop = serialize_methods.issubset(observed_binary_methods)
    blockers: list[str] = []
    if not first_nonzero_slot:
        blockers.append("No non-zero RPC header slot observed; the private session/slot binder is still missing.")
    if 17 not in observed_binary_methods:
        blockers.append("No candidate MethodPbSerializeFrameCaptureRequest (17) frame was observed.")
    if not has_serialize_loop:
        blockers.append("The serialize request/reply/file-transfer method loop (17,43,44,45,46) is incomplete.")

    return {
        "ok": True,
        "rpc_frame_count": len(rpc_frames),
        "category_counts": _counter_dict(categories),
        "method_counts": _counter_dict(methods),
        "slot_counts": _counter_dict(slots),
        "channel_counts": _counter_dict(channels),
        "nonzero_request_ids": _counter_dict(request_ids),
        "nonzero_seqs": _counter_dict(seqs),
        "first_nonzero_slot": first_nonzero_slot,
        "binary_replay_frame_count": len(binary_replay_frames),
        "binary_replay_frames": binary_replay_frames[:100],
        "handshake_frames": handshake_frames[:20],
        "binding_candidate_frames": binding_candidates[:100],
        "serialize_loop_methods_observed": sorted(m for m in observed_binary_methods if m in serialize_methods),
        "direct_saved_cpp_export_ready": bool(first_nonzero_slot and has_serialize_loop),
        "blockers": blockers,
        "next_capture_guidance": [
            "Start transcript capture before ngfx-ui opens the saved capture so handshake and namespace setup are included.",
            "Keep frames through Generate C++ Capture export so methods 17, 43, 44, 45, and 46 can be correlated.",
            "Preserve transport channel, ticket_id, request_id, seq, and slot fields; these are the binding candidates.",
        ],
    }


def direct_export_binding_candidate(decoded_frames: list[dict[str, Any]]) -> dict[str, Any]:
    """Derive a candidate direct saved-C++ export binding from decoded RPC frames."""
    report = session_binding_report(decoded_frames)
    rpc_frames = [f for f in decoded_frames if f.get("ok") and isinstance(f.get("rpc"), dict)]
    binary_frames = [
        f
        for f in rpc_frames
        if int(f["rpc"]["category"]) == rpc_client.CATEGORY_BINARY_REPLAY
    ]
    serialize_request = next(
        (f for f in binary_frames if int(f["rpc"]["method"]) == 17),
        None,
    )
    serialize_reply = next(
        (f for f in binary_frames if int(f["rpc"]["method"]) == 43),
        None,
    )
    nonzero_slots = sorted({int(f["rpc"]["slot"]) for f in binary_frames if int(f["rpc"]["slot"])})
    channels = sorted(
        {
            int(f["transport"]["channel"])
            for f in binary_frames
            if isinstance(f.get("transport"), dict)
        }
    )
    request_ids = sorted({int(f["rpc"]["request_id"]) for f in binary_frames if int(f["rpc"]["request_id"])})
    seqs = sorted({int(f["rpc"]["seq"]) for f in binary_frames if int(f["rpc"]["seq"])})
    observed_methods = sorted({int(f["rpc"]["method"]) for f in binary_frames})
    callback_methods = [m for m in (44, 45, 46) if m in observed_methods]

    blockers = list(report.get("blockers") or [])
    if len(nonzero_slots) != 1:
        blockers.append(f"Expected one stable non-zero slot; observed {nonzero_slots or 'none'}.")
    if not serialize_request:
        blockers.append("No serialize request frame found for body/header cloning.")
    if not serialize_reply:
        blockers.append("No serialize reply frame found to verify request/reply pairing.")
    if len(channels) > 1:
        blockers.append(f"Multiple transport channels observed for BinaryReplay frames: {channels}.")

    slot = nonzero_slots[0] if len(nonzero_slots) == 1 else None
    channel = channels[0] if len(channels) == 1 else 0
    candidate = {
        "schema": "nsight-graphics-mcp.direct-saved-cpp-rpc-binding.v1",
        "category": rpc_client.CATEGORY_BINARY_REPLAY,
        "category_name": "NV.Pylon.Replay.CategoryBinaryReplay",
        "transport_channel": channel,
        "slot": slot,
        "request_id_mode": "reuse_observed_nonzero" if request_ids else "zero_or_allocator",
        "observed_request_ids": request_ids,
        "seq_mode": "monotonic_observed" if seqs else "zero_or_allocator",
        "observed_seqs": seqs,
        "serialize_request_frame_index": serialize_request.get("frame_index") if serialize_request else None,
        "serialize_reply_frame_index": serialize_reply.get("frame_index") if serialize_reply else None,
        "serialize_methods_observed": report.get("serialize_loop_methods_observed") or [],
        "callback_methods_observed": callback_methods,
        "required_methods": {
            "serialize_request": 17,
            "serialize_reply": 43,
            "open_file_notification": 44,
            "append_file_notification": 45,
            "close_file_notification": 46,
        },
        "header_clone_source": serialize_request.get("rpc") if serialize_request else None,
        "ready_to_attempt_send": not blockers,
    }
    return {
        "ok": True,
        "ready": not blockers,
        "binding": candidate,
        "blockers": blockers,
        "session_binding_report": report,
        "next_steps": [
            "If ready is true, wire this binding into ngfx_cpp_capture_saved_direct_rpc_export with a live session.",
            "If ready is false, capture a complete UI export transcript including methods 17, 43, 44, 45, and 46.",
        ],
    }


def direct_export_binding_candidate_from_transcript(
    *,
    transcript_path: str | Path | None = None,
    frames: list[str] | None = None,
    has_transport_header: bool | None = None,
) -> dict[str, Any]:
    imported = import_rpc_transcript(
        transcript_path=transcript_path,
        frames=frames,
        has_transport_header=has_transport_header,
    )
    candidate = direct_export_binding_candidate(imported["decoded"])
    return {
        **candidate,
        "transcript": {
            "ok": imported.get("ok"),
            "source": imported.get("source"),
            "frame_count": imported.get("frame_count"),
        },
    }


# ---------------------------------------------------------------------------
# Capture-open / session-bind sequence report (static RE summary)
# ---------------------------------------------------------------------------
#
# This is a structured digest of what is currently known about the
# AttachMessage + session-bind flow that ngfx-ui drives before BinaryReplay
# methods become usable. It is intentionally a *static* report — no live
# server is contacted. Use this when planning the PE-patch / ETW /
# pktmon bypass paths described in NSIGHT_SHADER_DEBUG_AUTONOMY.md, and
# when evaluating a captured transcript.


def capture_open_sequence_report(
    transcript_path: str | Path | None = None,
    decoded_frames: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return a static knowledge summary of the BinaryReplay session-open
    handshake plus an optional analysis of a real captured transcript.

    The "static" half names the categories/methods that are known to be
    involved, the wire-format invariants the client must satisfy
    (``is_valid`` at +0 and +2, etc), and the open hypotheses described
    in :doc:`RPC_PROTOCOL.md`. The "observed" half, when given a
    transcript or decoded frames, surfaces:

    * the first ``CategoryConnection`` frame (likely the AttachMessage)
    * the first non-``slot=11`` reply (would prove the session opened)
    * a ranked list of (category, method, slot) keys not yet seen on
      this transcript, so callers know what's still missing.
    """
    known = {
        "transport_invariants": {
            "frame_magic": "0x54 0x08",
            "transport_header_bytes": 8,
            "transport_size_endianness": "big-endian u32 at bytes 4..7",
            "wire_header_bytes": 24,
            "wire_header_layout": {
                "ticket_id_be": "[0..8)",
                "request_id_be": "[8..16)",
                "seq_be": "[16..20)",
                "category_u8": "[20]",
                "method_u8": "[21]",
                "slot_u8": "[22]",
                "flags_u8": "[23] bit0=is_valid bit1=sertype_lsb",
            },
            "is_valid_at_offset_0_too": True,
            "rejected_reply_signature": {
                "category": 0,
                "method": 0,
                "slot": 11,
                "body_size_bytes": 0,
                "interpretation": (
                    "pre-session reject; every sweep frame replied with this "
                    "until the AttachMessage handshake is reproduced"
                ),
            },
        },
        "candidate_sequence_for_capture_open": [
            {
                "step": 1,
                "category": rpc_client.CATEGORY_CONNECTION,
                "category_name": "CategoryConnection",
                "method": 1,
                "method_name": "MethodAttachMessage",
                "evidence": (
                    "ConnectionMethod.proto enumerates "
                    "AttachMessage=1 / TargetAttachedMessage=7. Empty body "
                    "rejected by the live server; the body fields are not "
                    "yet pinned."
                ),
                "evidence_label": "candidate",
            },
            {
                "step": 2,
                "category": rpc_client.CATEGORY_CONNECTION,
                "category_name": "CategoryConnection",
                "method": 7,
                "method_name": "MethodTargetAttachedMessage",
                "evidence": (
                    "Likely reply or follow-up notification carrying the "
                    "session id / slot. Captured-but-unseen on every "
                    "transcript so far."
                ),
                "evidence_label": "candidate",
            },
            {
                "step": 3,
                "category": rpc_client.CATEGORY_HANDSHAKE,
                "category_name": "CategoryHandshake",
                "method": 1,
                "method_name": "MethodHandshakeBegin",
                "evidence": (
                    "PbHandshakeBeginMessage(id=1) verified to round-trip "
                    "at the transport level. Reply is still slot=11 today."
                ),
                "evidence_label": "inferred",
            },
            {
                "step": 4,
                "category": rpc_client.CATEGORY_BINARY_REPLAY,
                "category_name": "CategoryBinaryReplay",
                "method": rpc_client.RpcClient.METHOD_LAUNCH,
                "method_name": "MethodLaunchRequest",
                "evidence": (
                    "Once session is bound, the UI opens a replay launch "
                    "with the saved-capture path; only then do "
                    "MetadataRequest / EventInfoRequest succeed."
                ),
                "evidence_label": "candidate",
            },
        ],
        "blocked_paths_without_handshake": [
            "MethodMetadataRequest (BinaryReplay.8)",
            "MethodEventInfoRequest (BinaryReplay.14)",
            "MethodEventDetailsRequest (BinaryReplay.16)",
            "MethodDescriptorStateRequest (BinaryReplay.63)",
            "MethodRootParametersRequest (BinaryReplay.67)",
            "MethodPixelHistoryRequest (BinaryReplay)",
            "MethodResourceAccessHistoryRequest (BinaryReplay)",
            "MethodImageSubresourceDataRequest (BinaryReplay)",
        ],
        "open_questions": [
            "Exact field layout of PbAttachMessage in ConnectionMethod.proto.",
            "Whether the slot byte carries a session id or a routing key.",
            "Whether the UI sends shared-memory descriptors out-of-band "
            "during the AttachMessage exchange (most likely explanation "
            "for why API hooks see no bytes).",
            "Which method id returns the bound session/capture handle.",
        ],
        "evidence_label": "candidate",
    }

    observed: dict[str, Any] = {
        "available": False,
        "frame_count": 0,
    }
    if decoded_frames is None and transcript_path is not None:
        imported = import_rpc_transcript(transcript_path=transcript_path)
        decoded_frames = imported.get("decoded") or []
        observed["transcript_source"] = imported.get("source")
        observed["available"] = bool(decoded_frames)

    if decoded_frames:
        first_connection: dict[str, Any] | None = None
        first_non_reject_reply: dict[str, Any] | None = None
        seen_keys: set[tuple[int, int, int]] = set()
        for frame in decoded_frames:
            if not frame.get("ok"):
                continue
            rpc = frame.get("rpc")
            if not isinstance(rpc, dict):
                continue
            category = int(rpc.get("category", -1))
            method = int(rpc.get("method", -1))
            slot = int(rpc.get("slot", -1))
            seen_keys.add((category, method, slot))
            if (
                first_connection is None
                and category == rpc_client.CATEGORY_CONNECTION
            ):
                first_connection = frame
            if (
                first_non_reject_reply is None
                and (category, method, slot) != (0, 0, 11)
                and int(rpc.get("request_id", 0))
            ):
                first_non_reject_reply = frame

        # Missing expected keys
        expected = {
            (rpc_client.CATEGORY_CONNECTION, 1, 0),
            (rpc_client.CATEGORY_CONNECTION, 7, 0),
            (rpc_client.CATEGORY_HANDSHAKE, 1, 0),
            (rpc_client.CATEGORY_BINARY_REPLAY, rpc_client.RpcClient.METHOD_LAUNCH, 0),
        }
        missing = sorted(
            (
                {"category": c, "method": m, "slot": s}
                for (c, m, s) in expected
                if (c, m, s) not in seen_keys
            ),
            key=lambda d: (d["category"], d["method"], d["slot"]),
        )

        observed.update(
            {
                "available": True,
                "frame_count": len(decoded_frames),
                "first_connection_frame": first_connection,
                "first_non_reject_reply": first_non_reject_reply,
                "missing_expected_keys": missing,
                "session_binding_report": session_binding_report(decoded_frames),
            }
        )

    return {
        "ok": True,
        "known": known,
        "observed": observed,
    }
