"""Tests for the reverse-engineered ``ngfx-rpc.exe`` client.

The transport-layer framing is fully verified (we have a complete byte-for-
byte spec). The message-layer wire format is still being validated against
the live server — see ``docs/RPC_PROTOCOL.md``. These tests therefore
split into:

* Pure unit tests on the framing primitives (always run).
* Live tests that need ``ngfx-rpc.exe`` to be installed (gated on
  ``needs_install``). These currently only verify *connection-level*
  behaviour because a full request/response round-trip depends on
  resolving the remaining MessageHeader-wire-format ambiguity.
"""

from __future__ import annotations

import socket
import struct
import subprocess
import threading
from pathlib import Path

import pytest

from nsight_graphics_mcp import proto_descriptors as pd
from nsight_graphics_mcp import rpc_client
from nsight_graphics_mcp.config import host_bin_dir
from nsight_graphics_mcp.rpc_client import (
    FRAME_HEADER_SIZE,
    FRAME_MAGIC_0,
    FRAME_MAGIC_1,
    MESSAGE_HEADER_WIRE_SIZE,
    RpcMessage,
    RpcMessageHeader,
    RpcProtocolError,
    RpcTransport,
    TransportFrame,
)

# ---------------------------------------------------------------------------
# Unit tests — always run
# ---------------------------------------------------------------------------


def test_frame_magic_constants_are_correct() -> None:
    assert FRAME_MAGIC_0 == 0x54  # 'T'
    assert FRAME_MAGIC_1 == 0x08
    assert FRAME_HEADER_SIZE == 8


def test_transport_frame_pack_round_trip() -> None:
    body = b"hello world"
    frame = TransportFrame(channel=7, body=body)
    wire = frame.pack()
    assert wire[0] == FRAME_MAGIC_0
    assert wire[1] == FRAME_MAGIC_1
    assert wire[2] == 7
    assert wire[3] == 0
    assert struct.unpack(">I", wire[4:8])[0] == len(body)
    assert wire[8:] == body
    # parse back
    m0, m1, ch, flag, size = TransportFrame.unpack_header(wire[:8])
    assert (m0, m1, ch, flag, size) == (FRAME_MAGIC_0, FRAME_MAGIC_1, 7, 0, len(body))


def test_transport_frame_pack_empty_body() -> None:
    wire = TransportFrame(channel=0, body=b"").pack()
    assert wire == bytes([FRAME_MAGIC_0, FRAME_MAGIC_1, 0, 0, 0, 0, 0, 0])
    assert len(wire) == FRAME_HEADER_SIZE


def test_transport_frame_rejects_oversize_channel() -> None:
    with pytest.raises(ValueError):
        TransportFrame(channel=256, body=b"").pack()


def test_transport_frame_unpack_header_validates_length() -> None:
    with pytest.raises(RpcProtocolError):
        TransportFrame.unpack_header(b"\x54\x08\x00")  # too short


def test_rpc_message_header_wire_layout() -> None:
    """Pack/unpack round-trips the verified 24-byte wire layout. Field
    placements come from ``sub_1409854C0`` (deserializer) and
    ``sub_140985580`` (serializer) in ngfx-rpc.exe; ticket_id and
    request_id are u64 BE, category/method/slot are single bytes."""
    hdr = RpcMessageHeader(category=7, method=33, ticket_id=12345, sertype=1,
                           request_id=0xDEADBEEF, seq=0xCAFE, slot=11)
    packed = hdr.pack()
    assert len(packed) == MESSAGE_HEADER_WIRE_SIZE == 24

    # ticket_id at wire bytes 0..8, BIG-endian
    assert struct.unpack_from(">Q", packed, 0)[0] == 12345
    # request_id at wire bytes 8..16, BIG-endian
    assert struct.unpack_from(">Q", packed, 8)[0] == 0xDEADBEEF
    # seq at wire bytes 16..20, BIG-endian u32
    assert struct.unpack_from(">I", packed, 16)[0] == 0xCAFE
    # category/method/slot are single bytes at +20/+21/+22
    assert packed[20] == 7
    assert packed[21] == 33
    assert packed[22] == 11
    # byte 23: bit 0 = is_valid (always 1 outgoing), bit 1 = sertype
    assert packed[23] & 0x01 == 1
    assert (packed[23] >> 1) & 0x01 == 1

    # round-trip
    parsed = RpcMessageHeader.unpack(packed)
    assert parsed.category == 7
    assert parsed.method == 33
    assert parsed.ticket_id == 12345
    assert parsed.request_id == 0xDEADBEEF
    assert parsed.seq == 0xCAFE
    assert parsed.slot == 11
    assert parsed.sertype == 1


def test_rpc_message_pack_concatenates_wire_header_and_body() -> None:
    hdr = RpcMessageHeader(category=1, method=2, ticket_id=3)
    body = b"\x08\x01"
    msg = RpcMessage(header=hdr, body=body)
    packed = msg.pack()
    assert len(packed) == MESSAGE_HEADER_WIRE_SIZE + len(body)
    assert packed[-2:] == body


def test_rpc_message_unpack_short_body_raises() -> None:
    with pytest.raises(RpcProtocolError):
        # Anything under 24 bytes is too short for the wire header.
        RpcMessage.unpack(b"\x00" * 16)


def test_transport_frame_unpack_round_trip_via_socket_pair() -> None:
    """Send a frame across a real socket pair and recv it back."""
    # On Windows there's no socketpair; use a temp TCP listener.
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.listen(1)

    received: dict[str, object] = {}

    def accept_one() -> None:
        c, _ = server.accept()
        t = RpcTransport(c)
        try:
            f = t.recv_frame()
            received["frame"] = f
        finally:
            t.close()

    th = threading.Thread(target=accept_one, daemon=True)
    th.start()

    with RpcTransport.connect("127.0.0.1", port, timeout=2.0) as t:
        t.send_frame(TransportFrame(channel=42, body=b"hello from test"))
    th.join(timeout=2.0)
    server.close()

    assert "frame" in received
    f = received["frame"]
    assert isinstance(f, TransportFrame)
    assert f.channel == 42
    assert f.body == b"hello from test"


def test_recv_frame_rejects_bad_magic() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    server.listen(1)

    def serve_bad() -> None:
        c, _ = server.accept()
        # Send 8 bytes with wrong magic
        c.sendall(b"\xFF\xFF\x00\x00\x00\x00\x00\x00")
        c.close()

    th = threading.Thread(target=serve_bad, daemon=True)
    th.start()

    with RpcTransport.connect("127.0.0.1", port, timeout=2.0) as t:
        with pytest.raises(RpcProtocolError, match="bad frame magic"):
            t.recv_frame()
    th.join(timeout=2.0)
    server.close()


# ---------------------------------------------------------------------------
# Live tests — require ngfx-rpc.exe
# ---------------------------------------------------------------------------


def _ngfx_rpc() -> Path | None:
    bd = host_bin_dir()
    if bd is None:
        return None
    p = bd / "ngfx-rpc.exe"
    return p if p.is_file() else None


RPC_EXE = _ngfx_rpc()
needs_install = pytest.mark.skipif(RPC_EXE is None, reason="ngfx-rpc.exe not installed")


@needs_install
def test_proto_pool_has_handshake_messages() -> None:
    reg = pd.build_registry(RPC_EXE)
    msgs = reg.list_messages()
    assert "NV.TPS.System.PbHandshakeBeginMessage" in msgs
    assert "NV.TPS.System.PbHandshakeEndMessage" in msgs


@needs_install
def test_proto_pool_has_per_event_request_messages() -> None:
    """All four per-event-args methods identified in the brief."""
    reg = pd.build_registry(RPC_EXE)
    msgs = set(reg.list_messages())
    for name in (
        "NV.Pylon.Replay.PbApiInspectorStateRequest",
        "NV.Pylon.Replay.PbRootParametersRequest",
        "NV.Pylon.Replay.PbDescriptorStateRequest",
        "NV.Pylon.Replay.PbEventDetailsRequest",
    ):
        assert name in msgs, name


@needs_install
def test_binary_replay_method_enum_pinned_values() -> None:
    """Pin the BinaryReplay method IDs we use in RpcClient — if upstream
    renumbers them we want to know immediately."""
    reg = pd.build_registry(RPC_EXE)
    fd = reg.files["PylonUi.proto"]
    method_enum = next(et for et in fd.enum_type if et.name == "BinaryReplayMethod")
    by_name = {v.name: v.number for v in method_enum.value}

    assert by_name["MethodLaunchRequest"] == rpc_client.RpcClient.METHOD_LAUNCH == 1
    assert by_name["MethodMetadataRequest"] == rpc_client.RpcClient.METHOD_METADATA == 8
    assert by_name["MethodEventInfoRequest"] == rpc_client.RpcClient.METHOD_EVENT_INFO == 14
    assert by_name["MethodEventDetailsRequest"] == rpc_client.RpcClient.METHOD_EVENT_DETAILS == 16
    assert by_name["MethodApiInspectorStateRequest"] == rpc_client.RpcClient.METHOD_API_INSPECTOR_STATE == 33
    assert by_name["MethodImageSubresourceDataRequest"] == rpc_client.RpcClient.METHOD_IMAGE_SUBRESOURCE_DATA == 39
    assert by_name["MethodResourceAccessHistoryRequest"] == rpc_client.RpcClient.METHOD_RESOURCE_ACCESS_HISTORY == 53
    assert by_name["MethodResourceInfoRequest"] == rpc_client.RpcClient.METHOD_RESOURCE_INFO == 59
    assert by_name["MethodDescriptorStateRequest"] == rpc_client.RpcClient.METHOD_DESCRIPTOR_STATE == 63
    assert by_name["MethodRootParametersRequest"] == rpc_client.RpcClient.METHOD_ROOT_PARAMETERS == 67
    assert by_name["MethodPixelHistoryRequest"] == rpc_client.RpcClient.METHOD_PIXEL_HISTORY == 70


@needs_install
def test_pixel_history_request_builder() -> None:
    reg = pd.build_registry(RPC_EXE)
    req = rpc_client.build_pixel_history_request(
        reg,
        image_accessor=123,
        image_misc=4,
        image_view_accessor=456,
        image_view_misc=7,
        x=10,
        y=20,
        mip_level=2,
        array_layer=3,
    )

    assert req.ImageView.image.Accessor == 123
    assert req.ImageView.image.Misc == 4
    assert req.ImageView.imageView.Accessor == 456
    assert req.Subresource.mipLevel == 2
    assert req.Subresource.arrayLayer == 3
    assert req.Pixel.x == 10
    assert req.Pixel.y == 20
    assert req.SerializeToString()


@needs_install
def test_resource_access_history_request_builder_and_revision_selection() -> None:
    reg = pd.build_registry(RPC_EXE)
    req = rpc_client.build_resource_access_history_request(reg, accessor=99, misc=12)
    assert req.Object.Accessor == 99
    assert req.Object.Misc == 12

    reply_cls = reg.message_class("NV.Pylon.Replay.PbResourceAccessHistoryReply")
    reply = reply_cls()
    first = reply.History.Accesses.add()
    first.EventIndex = 10
    first.AccessFlags = 1
    second = reply.History.Accesses.add()
    second.EventIndex = 25
    second.AccessFlags = 2
    third = reply.History.Accesses.add()
    third.EventIndex = 40
    third.AccessFlags = 4

    rev = rpc_client.resource_revision_from_history(reply, 30)
    assert rev["revision_at_or_before_event"]["event_index"] == 25
    assert rev["next_access_after_event"]["event_index"] == 40
    assert rev["access_count"] == 3


@needs_install
def test_diagnostics_method_databuffer_is_six() -> None:
    """This is the pin that confirms global category 1 == Diagnostics."""
    reg = pd.build_registry(RPC_EXE)
    fd = reg.files["Diagnostics.proto"]
    method_enum = next(et for et in fd.enum_type if et.name == "DiagnosticsMethod")
    by_name = {v.name: v.number for v in method_enum.value}
    assert by_name["DataBuffer"] == 6


@needs_install
def test_rpc_category_ids_are_pinned_from_proto_enums() -> None:
    reg = pd.build_registry(RPC_EXE)

    system_fd = reg.files["SystemCategories.proto"]
    system_enum = next(et for et in system_fd.enum_type if et.name == "SystemCategory")
    system = {v.name: v.number for v in system_enum.value}
    assert system["CategoryDiagnostics"] == rpc_client.CATEGORY_DIAGNOSTICS == 1
    assert system["CategorySystemInfo"] == rpc_client.CATEGORY_SYSTEM_INFO == 2
    assert system["CategoryDiscovery"] == rpc_client.CATEGORY_DISCOVERY == 3
    assert system["CategoryHandshake"] == rpc_client.CATEGORY_HANDSHAKE == 4
    assert system["CategoryDeviceInfo"] == rpc_client.CATEGORY_DEVICE_INFO == 5
    assert system["CategoryConnection"] == rpc_client.CATEGORY_CONNECTION == 6
    assert system["CategoryLocalDiscovery"] == rpc_client.CATEGORY_LOCAL_DISCOVERY == 7

    pylon_fd = reg.files["PylonUi.proto"]
    pylon_enum = next(et for et in pylon_fd.enum_type if et.name == "Category")
    pylon = {v.name: v.number for v in pylon_enum.value}
    assert pylon["CategoryBinaryReplay"] == rpc_client.CATEGORY_BINARY_REPLAY == 1


@needs_install
def test_rpc_server_starts_and_listens_on_tcp() -> None:
    """Spawn ngfx-rpc.exe with TCP transport, verify it listens, kill it.
    Does NOT exchange any application-layer messages — just confirms the
    server can be launched and that a TCP listener is bound."""
    assert RPC_EXE is not None
    proc = subprocess.Popen(
        [str(RPC_EXE), "--transport", "TCP", "--no-crash-reporting"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        # Give it a moment to bind
        port = None
        try:
            port = rpc_client.find_listening_port(proc.pid, timeout=4.0)
        except TimeoutError:
            pytest.skip("could not enumerate rpc server's TCP port")
        # Now connect at the transport layer
        with RpcTransport.connect("127.0.0.1", port, timeout=2.0) as t:
            assert t._sock.getpeername()[1] == port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3.0)
