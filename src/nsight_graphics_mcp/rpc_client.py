"""Python client for the ngfx-rpc.exe custom RPC transport.

Reverse-engineered from the ngfx-rpc.exe binary (NVIDIA Nsight Graphics
2026.1.0) — see ``docs/RPC_PROTOCOL.md`` for the full wire format derivation.

Status
------
The transport-level **8-byte frame header**, the **24-byte MessageHeader**
wire encoding, and the **dispatch model** (``(category u32, method u32)``)
are reverse-engineered. The remaining live gap for FrameDebugger automation
is the private BinaryReplay namespace/session/slot binding the UI performs
before replay requests are accepted. This module therefore exposes two
layers:

* :class:`RpcTransport` — handles the 8-byte transport framing. Sends/
  receives ``(channelId, payload_bytes)`` tuples. **This layer is robust.**

* :class:`RpcClient` — adds the decoded ``MessageHeader + protobuf-body``
  payload format and the high-level method-call API.

The constants and enums in this file are sourced directly from the
embedded ``*.proto`` files (extracted via
:mod:`nsight_graphics_mcp.proto_descriptors`) so they will track upstream
schema changes automatically.

References (file offsets are in ``ngfx-rpc.exe`` v2026.1.0.0):

  * Dispatcher (header parse + route)        ``sub_140985E50``
  * Transport frame parse (ntohl on size)    ``sub_1409AE2B0``
  * Transport frame build (htonl on size)    ``sub_1409AE2D0``
  * Recv-loop body                           ``sub_1409A3D40``  ("Read header channelId: %u Size: %u")
  * Send-loop body                           ``sub_1409A4760``  ("Write header channelId: %u Size: %u")
  * Header field accessors:
      - category (u32) at +32              ``sub_1409854B0``
      - method   (u32) at +36              ``sub_140985560``
      - is_valid (u8)  at +2               ``sub_140985570``
      - sertype  (u32) at +56              ``sub_140985540``
"""

from __future__ import annotations

import ctypes
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from google.protobuf.json_format import MessageToDict

from . import proto_descriptors

# ---------------------------------------------------------------------------
# Wire-level constants (8-byte transport frame)
# ---------------------------------------------------------------------------

#: First magic byte. Confirmed by reading ``payload_write__sub_1409A4470``:
#: ``v8[12] = 84;``  (where ``v8 + 12`` is the start of the header buffer).
FRAME_MAGIC_0 = 0x54

#: Second magic byte. Confirmed: ``v8[13] = 8;``.
FRAME_MAGIC_1 = 0x08

#: Transport frame header size, in bytes.
#: Confirmed by ``read_header__sub_1409A3D40`` where the recv path checks
#: ``a3 != 8`` immediately after reading the header.
FRAME_HEADER_SIZE = 8

#: Per-frame body length is encoded as a u32 in **network (big-endian)** order.
#: Confirmed by ``sub_1409AE2B0`` (``ntohl(*(u32*)(hdr+4))``) and
#: ``sub_1409AE2D0`` (``htonl(...)`` on the send side).


# ---------------------------------------------------------------------------
# Dispatch enumeration (category IDs)
# ---------------------------------------------------------------------------
#
# System categories are pinned by the embedded ``SystemCategories.proto`` in
# ngfx-rpc.exe. Pylon replay uses its own category namespace from
# ``PylonUi.proto``: ``CategoryBinaryReplay == 1``. The remaining live work is
# not the numeric BinaryReplay category, but the private namespace/session/slot
# setup the UI performs before BinaryReplay requests are accepted.

CATEGORY_DIAGNOSTICS = 1
CATEGORY_SYSTEM_INFO = 2
CATEGORY_DISCOVERY = 3
CATEGORY_HANDSHAKE = 4
CATEGORY_DEVICE_INFO = 5
CATEGORY_CONNECTION = 6
CATEGORY_LOCAL_DISCOVERY = 7

CATEGORY_PYLON_BINARY_REPLAY = 1
CATEGORY_BINARY_REPLAY = CATEGORY_PYLON_BINARY_REPLAY
CATEGORY_WARPVIZ = 1  # WarpViz.proto has a separate category namespace too.


# Channel IDs. ``read_header__sub_1409A3D40`` prints the channel as ``%u`` of
# a single byte at offset +46 (i.e. ``transport_header[2]``). Most traffic
# uses channel 0.
DEFAULT_CHANNEL = 0


# ---------------------------------------------------------------------------
# Transport layer
# ---------------------------------------------------------------------------


class RpcProtocolError(Exception):
    """Raised on any wire-format violation."""


@dataclass
class TransportFrame:
    """One 8-byte-header + body unit."""

    channel: int
    body: bytes
    magic_0: int = FRAME_MAGIC_0
    magic_1: int = FRAME_MAGIC_1
    flag: int = 0  # the 4th header byte; meaning not yet identified

    def pack(self) -> bytes:
        if not (0 <= self.channel <= 0xFF):
            raise ValueError(f"channel out of byte range: {self.channel}")
        if len(self.body) > 0xFFFFFFFF:
            raise ValueError("body too large for u32 size field")
        return bytes([self.magic_0, self.magic_1, self.channel, self.flag]) + \
               struct.pack(">I", len(self.body)) + self.body

    @classmethod
    def unpack_header(cls, hdr: bytes) -> tuple[int, int, int, int, int]:
        """Return ``(magic_0, magic_1, channel, flag, body_size)``."""
        if len(hdr) != FRAME_HEADER_SIZE:
            raise RpcProtocolError(
                f"frame header must be exactly {FRAME_HEADER_SIZE} bytes, got {len(hdr)}"
            )
        magic_0, magic_1, channel, flag = hdr[0], hdr[1], hdr[2], hdr[3]
        body_size = struct.unpack(">I", hdr[4:8])[0]
        return magic_0, magic_1, channel, flag, body_size


class RpcTransport:
    """Synchronous transport for the ngfx-rpc 8-byte framing.

    Supports both TCP and the named-pipe transport used by ngfx-ui. Use as a
    context manager (``with RpcTransport.connect(...) as t``) or call
    :meth:`close` explicitly.
    """

    def __init__(
        self,
        sock: socket.socket | None = None,
        *,
        pipe_handle: int | None = None,
        pipe_name: str | None = None,
    ) -> None:
        self._sock = sock
        self._pipe_handle = pipe_handle
        self._pipe_name = pipe_name
        self._lock = threading.Lock()
        self._closed = False
        self._timeout: float | None = None

    @classmethod
    def connect(cls, host: str, port: int, *, timeout: float = 5.0) -> RpcTransport:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        return cls(s)

    @classmethod
    def connect_named_pipe(cls, pipename: str, *, timeout: float = 5.0) -> RpcTransport:
        """Connect to an ngfx-rpc named pipe such as ``{guid}``.

        Nsight UI launches ngfx-rpc as ``--transport named-pipe --pipename
        {guid}``. Windows exposes that endpoint at ``\\\\.\\pipe\\{guid}``.
        """
        handle = _open_named_pipe(pipename, timeout=timeout)
        return cls(pipe_handle=handle, pipe_name=_normalise_pipe_name(pipename))

    def close(self) -> None:
        if self._closed:
            return
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()
        if self._pipe_handle is not None:
            _close_named_pipe(self._pipe_handle)
        self._closed = True

    def __enter__(self) -> RpcTransport:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def settimeout(self, t: float | None) -> None:
        self._timeout = t
        if self._sock is not None:
            self._sock.settimeout(t)

    # ---- low-level recv helpers ----------------------------------------

    def _recv_exact(self, n: int) -> bytes:
        if self._pipe_handle is not None:
            return _read_named_pipe_exact(self._pipe_handle, n)
        if self._sock is None:
            raise RpcProtocolError("transport is not connected")
        out = bytearray()
        while len(out) < n:
            try:
                chunk = self._sock.recv(n - len(out))
            except TimeoutError as e:
                raise RpcProtocolError(
                    f"timeout while reading {n} bytes (got {len(out)})"
                ) from e
            if not chunk:
                if not out:
                    raise RpcProtocolError("connection closed before any data")
                raise RpcProtocolError(
                    f"connection closed mid-frame ({len(out)}/{n} bytes received)"
                )
            out.extend(chunk)
        return bytes(out)

    # ---- frame API -----------------------------------------------------

    def send_frame(self, frame: TransportFrame) -> None:
        wire = frame.pack()
        with self._lock:
            if self._pipe_handle is not None:
                _write_named_pipe_all(self._pipe_handle, wire)
            elif self._sock is not None:
                self._sock.sendall(wire)
            else:
                raise RpcProtocolError("transport is not connected")

    def recv_frame(self) -> TransportFrame:
        hdr = self._recv_exact(FRAME_HEADER_SIZE)
        magic_0, magic_1, channel, flag, body_size = TransportFrame.unpack_header(hdr)
        if magic_0 != FRAME_MAGIC_0 or magic_1 != FRAME_MAGIC_1:
            raise RpcProtocolError(
                f"bad frame magic: got 0x{magic_0:02x}{magic_1:02x}, "
                f"expected 0x{FRAME_MAGIC_0:02x}{FRAME_MAGIC_1:02x}"
            )
        body = self._recv_exact(body_size) if body_size else b""
        return TransportFrame(channel=channel, body=body, magic_0=magic_0, magic_1=magic_1, flag=flag)


def _normalise_pipe_name(pipename: str) -> str:
    text = str(pipename).strip()
    if text.startswith("\\\\.\\pipe\\"):
        return text
    return f"\\\\.\\pipe\\{text}"


def _open_named_pipe(pipename: str, *, timeout: float) -> int:
    if os.name != "nt":
        raise OSError("ngfx-rpc named-pipe transport is Windows-only")
    path = _normalise_pipe_name(pipename)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = ctypes.c_void_p
    wait_ms = max(1, int(timeout * 1000))
    if not kernel32.WaitNamedPipeW(ctypes.c_wchar_p(path), ctypes.c_uint32(wait_ms)):
        raise ctypes.WinError(ctypes.get_last_error())
    handle = kernel32.CreateFileW(
        ctypes.c_wchar_p(path),
        ctypes.c_uint32(0xC0000000),  # GENERIC_READ | GENERIC_WRITE
        ctypes.c_uint32(0),
        None,
        ctypes.c_uint32(3),  # OPEN_EXISTING
        ctypes.c_uint32(0),
        None,
    )
    if handle in (None, ctypes.c_void_p(-1).value):
        raise ctypes.WinError(ctypes.get_last_error())
    return int(handle)


def _close_named_pipe(handle: int) -> None:
    if os.name != "nt":
        return
    ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(ctypes.c_void_p(handle))


def _read_named_pipe_exact(handle: int, n: int) -> bytes:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    out = bytearray()
    while len(out) < n:
        want = n - len(out)
        buf = ctypes.create_string_buffer(want)
        read = ctypes.c_uint32(0)
        ok = kernel32.ReadFile(
            ctypes.c_void_p(handle),
            buf,
            ctypes.c_uint32(want),
            ctypes.byref(read),
            None,
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        if read.value == 0:
            if not out:
                raise RpcProtocolError("named pipe closed before any data")
            raise RpcProtocolError(f"named pipe closed mid-frame ({len(out)}/{n} bytes received)")
        out.extend(buf.raw[: read.value])
    return bytes(out)


def _write_named_pipe_all(handle: int, data: bytes) -> None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    offset = 0
    while offset < len(data):
        chunk = ctypes.create_string_buffer(data[offset:])
        written = ctypes.c_uint32(0)
        ok = kernel32.WriteFile(
            ctypes.c_void_p(handle),
            chunk,
            ctypes.c_uint32(len(data) - offset),
            ctypes.byref(written),
            None,
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        if written.value == 0:
            raise RpcProtocolError("named pipe write made no progress")
        offset += written.value


# ---------------------------------------------------------------------------
# Message-layer (still partially conjectural — see docs/RPC_PROTOCOL.md)
# ---------------------------------------------------------------------------
#
# The frame body, once unwrapped from the transport header, contains:
#   1. A C++ ``NV::TPS::MessageHeader`` instance, ~60 bytes wide, that
#      carries ``(category u32, method u32, ticketId u64, sertype u32, ...)``.
#   2. The serialized protobuf body for the chosen ``(category, method)``
#      pair.
#
# The exact wire layout of the C++ MessageHeader was NOT observed live;
# we know its in-memory shape but not whether it is sent as a raw struct,
# as a fixed-size sequence of u32/u64 fields, or as a length-prefixed
# protobuf-encoded blob. The class below assumes a **raw struct** layout
# (the simplest possibility) — flip ``RpcMessageHeader.WIRE_LAYOUT`` to
# experiment with other encodings.

#: Wire-format MessageHeader size — recovered from
#: ``sub_140983400`` which rejects frames where ``end - start < 0x18``
#: with the log "Message buffer is too small, less than wire format header size".
MESSAGE_HEADER_WIRE_SIZE = 24

#: In-memory C++ struct size — distinct from the wire size. The C++ side
#: keeps a 60-byte struct internally but serialises it down to 24 bytes
#: on the wire via ``sub_1409854C0`` / ``sub_140985580``.
MESSAGE_HEADER_IN_MEM_SIZE = 60


@dataclass
class RpcMessageHeader:
    """C++ ``NV::TPS::MessageHeader`` — 24 bytes on the wire.

    Wire layout recovered from ``sub_1409854C0`` (deserializer, wire→mem)
    and ``sub_140985580`` (serializer, mem→wire). Both functions agree::

        wire bytes        in-mem offset (60-byte struct)
        [0..8]   u64 BE   ticket_id  → +8
        [8..16]  u64 BE   request_id → +16  (conditional: only if nonzero,
                                              also sets mem[+1] = 1)
        [16..20] u32 BE   ??? (seq?) → +24
        [20]     u8       category   → +32 (zero-extended to u32)
        [21]     u8       method     → +36 (zero-extended to u32)
        [22]     u8       slot/flag  → +40 (zero-extended to u32)
        [23] bit0         is_valid_2 → +2
        [23] bit1         sertype    → +56

    So category and method are single BYTES on the wire (matching the
    proto enums — BinaryReplayMethod has 110 entries, well under 256).
    The previous 60-byte raw-struct dump was the in-memory shape, NOT
    the wire shape — which is why the server dropped every probe.

    NOTE: ``is_valid`` at wire byte 23 bit 0 is set automatically when
    serialising; the caller doesn't need to manage it.
    """

    category: int
    method: int
    ticket_id: int = 0
    sertype: int = 0
    request_id: int = 0       # the conditional u64 at wire [8..16]
    seq: int = 0              # the u32 at wire [16..20] — purpose unknown
    slot: int = 0             # the u8 at wire [22] — purpose unknown

    def pack(self) -> bytes:
        """Emit the 24-byte wire encoding (NOT the 60-byte in-mem struct)."""
        buf = bytearray(MESSAGE_HEADER_WIRE_SIZE)
        struct.pack_into(">Q", buf, 0,  self.ticket_id & 0xFFFFFFFFFFFFFFFF)
        struct.pack_into(">Q", buf, 8,  self.request_id & 0xFFFFFFFFFFFFFFFF)
        struct.pack_into(">I", buf, 16, self.seq & 0xFFFFFFFF)
        buf[20] = self.category & 0xFF
        buf[21] = self.method & 0xFF
        buf[22] = self.slot & 0xFF
        # byte 23: bit 0 = is_valid (always 1 for outgoing), bit 1 = sertype LSB
        buf[23] = 0x01 | ((self.sertype & 0x01) << 1)
        return bytes(buf)

    @classmethod
    def unpack(cls, b: bytes) -> RpcMessageHeader:
        if len(b) < MESSAGE_HEADER_WIRE_SIZE:
            raise RpcProtocolError(
                f"wire header too short: {len(b)} < {MESSAGE_HEADER_WIRE_SIZE}"
            )
        ticket_id = struct.unpack_from(">Q", b, 0)[0]
        request_id = struct.unpack_from(">Q", b, 8)[0]
        seq = struct.unpack_from(">I", b, 16)[0]
        category = b[20]
        method = b[21]
        slot = b[22]
        flags = b[23]
        sertype = (flags >> 1) & 1
        # is_valid is implicit (always 1 for accepted frames)
        return cls(category=category, method=method, ticket_id=ticket_id,
                   sertype=sertype, request_id=request_id, seq=seq, slot=slot)


@dataclass
class RpcMessage:
    """A full ``(header, body)`` RPC message — the payload of one transport frame."""

    header: RpcMessageHeader
    body: bytes  # serialized protobuf bytes

    def pack(self) -> bytes:
        return self.header.pack() + self.body

    @classmethod
    def unpack(cls, b: bytes) -> RpcMessage:
        hdr = RpcMessageHeader.unpack(b)
        return cls(header=hdr, body=b[MESSAGE_HEADER_WIRE_SIZE:])


# ---------------------------------------------------------------------------
# High-level client
# ---------------------------------------------------------------------------


class RpcClient:
    """High-level client that pairs the transport with the proto registry.

    Auto-allocates monotonically-increasing ``ticket_id`` values for each
    call. Provides convenience wrappers for the per-event-args methods
    documented in the parent agent's brief.
    """

    def __init__(self, transport: RpcTransport,
                 registry: proto_descriptors.SchemaRegistry,
                 *, channel: int = DEFAULT_CHANNEL) -> None:
        self.transport = transport
        self.registry = registry
        self.channel = channel
        self._next_ticket = 1
        self._ticket_lock = threading.Lock()

    def _alloc_ticket(self) -> int:
        with self._ticket_lock:
            t = self._next_ticket
            self._next_ticket += 1
            return t

    # ---- generic call --------------------------------------------------

    def call_raw(self, *, category: int, method: int, body: bytes,
                 ticket_id: int | None = None,
                 expect_reply: bool = True,
                 timeout: float | None = None) -> RpcMessage | None:
        """Send one request and (optionally) return one reply."""
        ticket = ticket_id if ticket_id is not None else self._alloc_ticket()
        hdr = RpcMessageHeader(category=category, method=method, ticket_id=ticket)
        msg = RpcMessage(header=hdr, body=body)
        frame = TransportFrame(channel=self.channel, body=msg.pack())
        if timeout is not None:
            self.transport.settimeout(timeout)
        self.transport.send_frame(frame)
        if not expect_reply:
            return None
        reply_frame = self.transport.recv_frame()
        reply_msg = RpcMessage.unpack(reply_frame.body)
        return reply_msg

    def call(self, *, category: int, method: int, request_proto: Any,
             reply_fqn: str, ticket_id: int | None = None,
             timeout: float | None = 10.0) -> Any:
        """High-level call: serialize ``request_proto``, await a reply,
        deserialize it as ``reply_fqn``."""
        body = request_proto.SerializeToString()
        reply = self.call_raw(category=category, method=method, body=body,
                              ticket_id=ticket_id, timeout=timeout)
        if reply is None:
            return None
        cls = self.registry.message_class(reply_fqn)
        return cls.FromString(reply.body)

    # ---- handshake -----------------------------------------------------

    HANDSHAKE_METHOD_BEGIN = 1     # HandshakeMethod.MethodHandshakeBeginMessage

    def handshake(self, *, client_id: int = 1, timeout: float = 5.0) -> Any:
        """Perform the initial handshake. Returns the parsed reply protobuf.

        ``client_id`` is sent as the ``id`` field of ``PbHandshakeBeginMessage``.
        """
        cls_req = self.registry.message_class("NV.TPS.System.PbHandshakeBeginMessage")
        req = cls_req()
        req.id = client_id
        return self.call(
            category=CATEGORY_HANDSHAKE,
            method=self.HANDSHAKE_METHOD_BEGIN,
            request_proto=req,
            reply_fqn="NV.TPS.System.PbHandshakeEndMessage",
            timeout=timeout,
        )

    # ---- BinaryReplay convenience wrappers ----------------------------

    # IDs come from PylonUi.proto::BinaryReplayMethod
    METHOD_LAUNCH = 1
    METHOD_METADATA = 8
    METHOD_EVENT_INFO = 14
    METHOD_EVENT_DETAILS = 16
    METHOD_API_INSPECTOR_STATE = 33
    METHOD_IMAGE_SUBRESOURCE_DATA = 39
    METHOD_RESOURCE_ACCESS_HISTORY = 53
    METHOD_RESOURCE_INFO = 59
    METHOD_DESCRIPTOR_STATE = 63
    METHOD_ROOT_PARAMETERS = 67
    METHOD_PIXEL_HISTORY = 70

    def launch_capture(self, capture_path: Path, **kwargs: Any) -> Any:
        req_cls = self.registry.message_class("NV.Pylon.Replay.PbLaunchRequest")
        req = req_cls()
        # PbLaunchRequest has many fields — only set the ones we know are
        # required; the rest the caller can override via kwargs.
        # See PylonUi.proto for the full schema.
        if hasattr(req, "captureFilePath"):
            req.captureFilePath = str(capture_path)
        if hasattr(req, "capturePath"):
            req.capturePath = str(capture_path)
        for k, v in kwargs.items():
            setattr(req, k, v)
        return self.call(
            category=CATEGORY_BINARY_REPLAY,
            method=self.METHOD_LAUNCH,
            request_proto=req,
            reply_fqn="NV.Pylon.Replay.PbLaunchReply",
            timeout=30.0,
        )

    def event_details(self, event_index: int, *, timeout: float = 10.0) -> Any:
        req_cls = self.registry.message_class("NV.Pylon.Replay.PbEventDetailsRequest")
        req = req_cls()
        if hasattr(req, "FirstEvent"):
            req.FirstEvent = int(event_index)
            req.EventCount = 1
        else:
            for fname in ("eventIndex", "EventIndex", "event_index", "index"):
                if hasattr(req, fname):
                    setattr(req, fname, event_index)
                    break
        return self.call(
            category=CATEGORY_BINARY_REPLAY,
            method=self.METHOD_EVENT_DETAILS,
            request_proto=req,
            reply_fqn="NV.Pylon.Replay.PbEventDetailsReply",
            timeout=timeout,
        )

    def api_inspector_state(self, event_index: int, *, timeout: float = 10.0) -> Any:
        req_cls = self.registry.message_class("NV.Pylon.Replay.PbApiInspectorStateRequest")
        req = req_cls()
        for fname in ("eventIndex", "EventIndex", "event_index", "index"):
            if hasattr(req, fname):
                setattr(req, fname, event_index)
                break
        return self.call(
            category=CATEGORY_BINARY_REPLAY,
            method=self.METHOD_API_INSPECTOR_STATE,
            request_proto=req,
            reply_fqn="NV.Pylon.Replay.PbApiInspectorStateReply",
            timeout=timeout,
        )

    def root_parameters(self, event_index: int, *, timeout: float = 10.0) -> Any:
        req_cls = self.registry.message_class("NV.Pylon.Replay.PbRootParametersRequest")
        req = req_cls()
        for fname in ("eventIndex", "EventIndex", "event_index", "index"):
            if hasattr(req, fname):
                setattr(req, fname, event_index)
                break
        return self.call(
            category=CATEGORY_BINARY_REPLAY,
            method=self.METHOD_ROOT_PARAMETERS,
            request_proto=req,
            reply_fqn="NV.Pylon.Replay.PbRootParametersReply",
            timeout=timeout,
        )

    def descriptor_state(self, event_index: int, *, timeout: float = 10.0) -> Any:
        req_cls = self.registry.message_class("NV.Pylon.Replay.PbDescriptorStateRequest")
        req = req_cls()
        for fname in ("eventIndex", "EventIndex", "event_index", "index"):
            if hasattr(req, fname):
                setattr(req, fname, event_index)
                break
        return self.call(
            category=CATEGORY_BINARY_REPLAY,
            method=self.METHOD_DESCRIPTOR_STATE,
            request_proto=req,
            reply_fqn="NV.Pylon.Replay.PbDescriptorStateReply",
            timeout=timeout,
        )

    def pixel_history(
        self,
        *,
        image_accessor: int,
        x: int,
        y: int,
        image_misc: int = 0,
        image_view_accessor: int | None = None,
        image_view_misc: int = 0,
        aspect: int = 1,
        mip_level: int = 0,
        array_layer: int = 0,
        slice_index: int = 0,
        image_type: int = 3,
        timeout: float = 30.0,
    ) -> Any:
        req = build_pixel_history_request(
            self.registry,
            image_accessor=image_accessor,
            image_misc=image_misc,
            image_view_accessor=image_view_accessor,
            image_view_misc=image_view_misc,
            x=x,
            y=y,
            aspect=aspect,
            mip_level=mip_level,
            array_layer=array_layer,
            slice_index=slice_index,
            image_type=image_type,
        )
        return self.call(
            category=CATEGORY_BINARY_REPLAY,
            method=self.METHOD_PIXEL_HISTORY,
            request_proto=req,
            reply_fqn="NV.Pylon.Replay.PbPixelHistoryReply",
            timeout=timeout,
        )

    def resource_access_history(
        self,
        *,
        accessor: int,
        misc: int = 0,
        timeout: float = 30.0,
    ) -> Any:
        req = build_resource_access_history_request(
            self.registry,
            accessor=accessor,
            misc=misc,
        )
        return self.call(
            category=CATEGORY_BINARY_REPLAY,
            method=self.METHOD_RESOURCE_ACCESS_HISTORY,
            request_proto=req,
            reply_fqn="NV.Pylon.Replay.PbResourceAccessHistoryReply",
            timeout=timeout,
        )

    def resource_info(
        self,
        *,
        accessor: int,
        misc: int = 0,
        timeout: float = 30.0,
    ) -> Any:
        req = build_resource_info_request(self.registry, accessor=accessor, misc=misc)
        return self.call(
            category=CATEGORY_BINARY_REPLAY,
            method=self.METHOD_RESOURCE_INFO,
            request_proto=req,
            reply_fqn="NV.Pylon.Replay.PbResourceInfoReply",
            timeout=timeout,
        )

    def image_subresource_data(
        self,
        *,
        accessor: int,
        event_index: int,
        misc: int = 0,
        aspect: int = 1,
        mip_level: int = 0,
        array_layer: int = 0,
        slice_index: int = 0,
        region: dict[str, int] | None = None,
        timeout: float = 60.0,
    ) -> Any:
        req = build_image_subresource_data_request(
            self.registry,
            accessor=accessor,
            misc=misc,
            event_index=event_index,
            aspect=aspect,
            mip_level=mip_level,
            array_layer=array_layer,
            slice_index=slice_index,
            region=region,
        )
        return self.call(
            category=CATEGORY_BINARY_REPLAY,
            method=self.METHOD_IMAGE_SUBRESOURCE_DATA,
            request_proto=req,
            reply_fqn="NV.Pylon.Replay.PbImageSubresourceDataReply",
            timeout=timeout,
        )


def protobuf_to_dict(message: Any) -> dict[str, Any]:
    """Convert a dynamic protobuf message to a JSON-safe dict."""
    return MessageToDict(
        message,
        preserving_proto_field_name=True,
        use_integers_for_enums=True,
    )


def _api_data_handle(
    registry: proto_descriptors.SchemaRegistry,
    *,
    accessor: int,
    misc: int = 0,
) -> Any:
    cls = registry.message_class("NV.PbApiDataHandle")
    msg = cls()
    msg.Accessor = int(accessor)
    msg.Misc = int(misc)
    return msg


def _image_subresource(
    registry: proto_descriptors.SchemaRegistry,
    *,
    aspect: int = 1,
    mip_level: int = 0,
    array_layer: int = 0,
    slice_index: int = 0,
) -> Any:
    cls = registry.message_class("NV.PbImageSubresource")
    msg = cls()
    msg.aspect = int(aspect)
    msg.mipLevel = int(mip_level)
    msg.arrayLayer = int(array_layer)
    msg.slice = int(slice_index)
    return msg


def _offset2d(
    registry: proto_descriptors.SchemaRegistry,
    *,
    x: int,
    y: int,
) -> Any:
    cls = registry.message_class("NV.PbOffset2D")
    msg = cls()
    msg.x = int(x)
    msg.y = int(y)
    return msg


def build_pixel_history_request(
    registry: proto_descriptors.SchemaRegistry,
    *,
    image_accessor: int,
    x: int,
    y: int,
    image_misc: int = 0,
    image_view_accessor: int | None = None,
    image_view_misc: int = 0,
    aspect: int = 1,
    mip_level: int = 0,
    array_layer: int = 0,
    slice_index: int = 0,
    image_type: int = 3,
) -> Any:
    req_cls = registry.message_class("NV.Pylon.Replay.PbPixelHistoryRequest")
    req = req_cls()
    image = _api_data_handle(registry, accessor=image_accessor, misc=image_misc)
    req.ImageView.image.CopyFrom(image)
    view_accessor = image_accessor if image_view_accessor is None else image_view_accessor
    view = _api_data_handle(registry, accessor=view_accessor, misc=image_view_misc)
    req.ImageView.imageView.CopyFrom(view)
    req.ImageView.imageType = int(image_type)
    req.ImageView.baseMipLevel = int(mip_level)
    req.ImageView.mipLevelCount = 1
    req.ImageView.baseArrayLayer = int(array_layer)
    req.ImageView.arrayLayerCount = 1
    req.Subresource.CopyFrom(
        _image_subresource(
            registry,
            aspect=aspect,
            mip_level=mip_level,
            array_layer=array_layer,
            slice_index=slice_index,
        )
    )
    req.Pixel.CopyFrom(_offset2d(registry, x=x, y=y))
    return req


def build_resource_access_history_request(
    registry: proto_descriptors.SchemaRegistry,
    *,
    accessor: int,
    misc: int = 0,
) -> Any:
    req_cls = registry.message_class("NV.Pylon.Replay.PbResourceAccessHistoryRequest")
    req = req_cls()
    req.Object.CopyFrom(_api_data_handle(registry, accessor=accessor, misc=misc))
    return req


def build_resource_info_request(
    registry: proto_descriptors.SchemaRegistry,
    *,
    accessor: int,
    misc: int = 0,
) -> Any:
    req_cls = registry.message_class("NV.Pylon.Replay.PbResourceInfoRequest")
    req = req_cls()
    req.Object.CopyFrom(_api_data_handle(registry, accessor=accessor, misc=misc))
    return req


def build_image_subresource_data_request(
    registry: proto_descriptors.SchemaRegistry,
    *,
    accessor: int,
    event_index: int,
    misc: int = 0,
    aspect: int = 1,
    mip_level: int = 0,
    array_layer: int = 0,
    slice_index: int = 0,
    region: dict[str, int] | None = None,
) -> Any:
    req_cls = registry.message_class("NV.Pylon.Replay.PbImageSubresourceDataRequest")
    req = req_cls()
    req.object.CopyFrom(_api_data_handle(registry, accessor=accessor, misc=misc))
    req.subresource.CopyFrom(
        _image_subresource(
            registry,
            aspect=aspect,
            mip_level=mip_level,
            array_layer=array_layer,
            slice_index=slice_index,
        )
    )
    req.eventIndex = int(event_index)
    if region:
        _populate_region(req.region, region)
    return req


def resource_revision_from_history(history_reply: Any, event_index: int) -> dict[str, Any]:
    """Select the last resource access at or before ``event_index``."""
    reply_dict = protobuf_to_dict(history_reply)
    history = reply_dict.get("History") or reply_dict.get("history") or {}
    accesses = history.get("Accesses") or history.get("accesses") or []
    normalised: list[dict[str, Any]] = []
    for access in accesses:
        ev = access.get("EventIndex", access.get("eventIndex"))
        try:
            ev_int = int(ev)
        except (TypeError, ValueError):
            continue
        item = dict(access)
        item["event_index"] = ev_int
        normalised.append(item)
    before = [a for a in normalised if a["event_index"] <= int(event_index)]
    after = [a for a in normalised if a["event_index"] > int(event_index)]
    chosen = max(before, key=lambda a: a["event_index"]) if before else None
    return {
        "requested_event_index": int(event_index),
        "access_count": len(normalised),
        "revision_at_or_before_event": chosen,
        "next_access_after_event": min(after, key=lambda a: a["event_index"]) if after else None,
        "all_accesses": normalised,
    }


def _populate_region(region_msg: Any, region: dict[str, int]) -> None:
    """Best-effort fill for PbImageRegion without hard-coding all schema variants."""
    for key, value in region.items():
        if hasattr(region_msg, key):
            setattr(region_msg, key, int(value))
    # Common nested shapes, depending on Nsight schema version.
    for outer, inner in (
        ("offset", ("x", "y", "z")),
        ("extent", ("width", "height", "depth")),
        ("Offset", ("x", "y", "z")),
        ("Extent", ("width", "height", "depth")),
    ):
        if not hasattr(region_msg, outer):
            continue
        nested = getattr(region_msg, outer)
        for key in inner:
            if key in region and hasattr(nested, key):
                setattr(nested, key, int(region[key]))


# ---------------------------------------------------------------------------
# Connection-string helpers
# ---------------------------------------------------------------------------


def find_listening_port(pid: int, timeout: float = 5.0,
                        poll_interval: float = 0.1) -> int:
    """Block until the given pid has a listening TCP port; return that port.

    The Nsight ``ngfx-rpc.exe`` is configured to pick a free port
    dynamically (the documented ``--base-port``/``--port-range-*`` options
    are honoured only when ``--transport TCP`` is requested AND the chosen
    port is available; otherwise the OS picks). The simplest way to learn
    the port from the outside is to enumerate TCP listeners for the pid.

    Uses ``psutil`` if available, falls back to parsing ``netstat -ano``.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        port = _list_listening_ports_for_pid(pid)
        if port is not None:
            return port
        time.sleep(poll_interval)
    raise TimeoutError(f"no listening port for pid {pid} within {timeout}s")


def named_pipe_from_process(pid: int) -> str | None:
    """Return ``--pipename`` from an ngfx-rpc process command line, if present."""
    try:
        import psutil

        cmdline = psutil.Process(int(pid)).cmdline()
    except (ImportError, ValueError):
        return None
    except Exception:
        return None
    for index, token in enumerate(cmdline):
        if token == "--pipename" and index + 1 < len(cmdline):
            return cmdline[index + 1]
        if token.startswith("--pipename="):
            return token.split("=", 1)[1]
    return None


def resolve_process_endpoint(pid: int, *, timeout: float = 5.0) -> dict[str, Any]:
    """Resolve a running ngfx-rpc process to a TCP or named-pipe endpoint."""
    try:
        port = find_listening_port(pid, timeout=timeout)
        return {"transport": "tcp", "host": "127.0.0.1", "port": port, "pid": int(pid)}
    except TimeoutError as tcp_error:
        pipename = named_pipe_from_process(pid)
        if pipename:
            return {
                "transport": "named_pipe",
                "host": "127.0.0.1",
                "port": 0,
                "pipename": pipename,
                "pid": int(pid),
                "tcp_probe_error": str(tcp_error),
            }
        return {"transport": "unknown", "pid": int(pid), "error": str(tcp_error)}


def _list_listening_ports_for_pid(pid: int) -> int | None:
    try:
        import psutil
        for c in psutil.net_connections(kind="tcp"):
            if c.pid == pid and c.status == psutil.CONN_LISTEN:
                return c.laddr.port
        return None
    except ImportError:
        pass
    # Fallback: parse netstat
    import subprocess
    try:
        out = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True, text=True, timeout=5.0,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[-1] == str(pid) and "LISTENING" in line.upper():
            local = parts[1]
            try:
                return int(local.rsplit(":", 1)[1])
            except (IndexError, ValueError):
                continue
    return None
