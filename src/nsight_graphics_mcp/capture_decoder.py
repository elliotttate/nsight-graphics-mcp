"""Direct ``.ngfx-gfxcap`` / ``.ngfx-capture`` decoder.

This module decodes the **container format** of an Nsight Graphics capture
file and exposes the decompressed payloads as Python objects. It is
intentionally independent of the C++-capture parser
(``cpp_capture_parser``) — both code paths solve the same problem
(recovering per-event arguments) through different means.

Status (2026-05)
----------------

  * **Container layout** — fully decoded (see below).
  * **Chunk iteration** — works; reads the chunk stream end-to-end without
    over-reading into the trailer (see ``iter_chunk_headers``).
  * **LZ4 + stored decompression** — works.
  * **Table of contents** — fully decoded via ``parse_table_of_contents``.
    From the TOC we get ``FunctionInfoChunkIds``, ``ResourceInfoChunkIds``,
    plus capture metadata (process name, UUID, GPU, API).
  * **Per-event argument decoding** — **NOT yet decoded**. The function
    info chunk (the chunk whose ID is in ``FunctionInfoChunkIds``) is a
    *binary table* of fixed-stride records, not a sequence of serialised
    ``PbFunctionCallDesc`` messages. Walking that table requires the
    schema-descriptor chunk (a separate chunk holding the embedded
    ``.proto`` descriptors used to materialise per-call arguments).
    See ``docs/CAPTURE_FORMAT.md`` for the open questions.

Container format (reverse-engineered, see ``docs/CAPTURE_FORMAT.md``)
--------------------------------------------------------------------

::

    +----------------------------------------------------------+
    | 0x00  4 bytes  "nlyp"   (constant file-magic prefix)     |
    +----------------------------------------------------------+
    | 0x04  Chunk #0  (mini-header + LZ4-block payload)        |
    | ....  Chunk #1                                           |
    | ....  Chunk #2                                           |
    | ....  ...                                                |
    +----------------------------------------------------------+

The 4-byte ``nlyp`` prefix is followed by a **sequence of chunks**. Every
chunk has the same 48-byte mini-header (little-endian throughout):

==========  ====  =====================================================
offset      size  meaning
==========  ====  =====================================================
``+0x00``   4     magic ``elif``  (= 0x66696c65 = ASCII "file" LE-u32)
``+0x04``   8     u64 version            (observed: ``1``)
``+0x0c``   4     u32 compression_flag    (``1`` = LZ4 block, ``0`` = stored)
``+0x10``   8     u64 compressed_size    (bytes of payload that follow when LZ4;
                                           ``0`` for stored chunks)
``+0x18``   8     u64 uncompressed_size  (decompressed size; the **raw** payload
                                           size when ``compression_flag == 0``)
``+0x20``   8     u64 chunk_kind         (small integer, payload-type id)
``+0x28``   8     u64 self_offset        (this chunk's absolute byte offset)
==========  ====  =====================================================

Immediately after the header come ``compressed_size`` bytes of LZ4 *block*
data (no LZ4 frame header — pass the explicit uncompressed size to
``lz4.block.decompress``).

Chunks are 16-byte aligned: a small amount of zero padding (0..31 bytes)
typically precedes the next chunk's ``elif`` magic.

Per-event records
-----------------

Each chunk's decompressed payload is either:

  * a raw binary blob (resource bytes, shader bytecode, etc.), or
  * a **protobuf message** in the ``NV.*`` namespace.

The chunk_kind value broadly correlates with payload type but a definitive
mapping is not yet known. To find per-event ``PbFunctionCallDesc`` records,
this module:

  1. Iterates every chunk and decompresses it.
  2. Tries to parse the payload as one of a small set of "wrapper" message
     types (``PbFunctionCallDesc`` directly, or repeated-of-it inside a
     larger message we discover dynamically).
  3. Returns each successful match together with its chunk index +
     intra-payload offset.

This is a best-effort decoder. For content-level queries with strong
guarantees, use the JSON-backed metadata tools (``ngfx_capture_summary``,
``ngfx_index_events``, ``ngfx_index_objects``).
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Container constants
# ---------------------------------------------------------------------------

FILE_MAGIC_PREFIX = b"nlyp"           # 4-byte prefix at offset 0
CHUNK_MAGIC = b"elif"                 # 4-byte chunk magic (= "file" LE-u32)
CHUNK_HEADER_SIZE = 48
CHUNK_ALIGN = 16
COMPRESSION_LZ4 = 4   # value seen in the chunk_kind-ish u64 at +0x2c of *file*
                      # header; per-chunk compression flag is in `flags`.

# Per-chunk header struct: <Q I Q Q Q Q  (after 4-byte magic).
_CHUNK_HEADER_STRUCT = struct.Struct("<QIQQQQ")
assert _CHUNK_HEADER_STRUCT.size == 44  # +4 magic == 48


# ---------------------------------------------------------------------------
# Header / chunk dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CaptureHeader:
    """Parsed wrapper header (file-magic + first chunk's mini-header)."""

    path: Path
    file_size: int
    magic_prefix: bytes
    magic_prefix_ok: bool
    first_chunk: ChunkHeader

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "file_size": self.file_size,
            "magic_prefix": self.magic_prefix.hex(),
            "magic_prefix_ascii": self.magic_prefix.decode("latin-1", errors="replace"),
            "magic_prefix_ok": self.magic_prefix_ok,
            "first_chunk": self.first_chunk.to_dict(),
        }


@dataclass
class ChunkHeader:
    """48-byte chunk mini-header."""

    index: int                # 0-based chunk number in file
    offset: int               # absolute byte offset of the ``elif`` magic
    magic: bytes              # always ``b"elif"`` for valid chunks
    version: int              # observed: 1
    compression: int          # 1 = LZ4 block compressed, 0 = stored
    compressed_size: int      # bytes of LZ4 payload that follow (0 when stored)
    uncompressed_size: int    # decompressed size in bytes
    kind: int                 # small int — payload-type-ish indicator
    self_offset: int          # absolute offset of this chunk (= ``offset``)
    payload_start: int        # offset + 48

    @property
    def stored(self) -> bool:
        return self.compression == 0

    @property
    def payload_size_on_disk(self) -> int:
        """Bytes that follow the 48-byte header on disk."""
        return self.uncompressed_size if self.stored else self.compressed_size

    @property
    def payload_end(self) -> int:
        return self.payload_start + self.payload_size_on_disk

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "offset": self.offset,
            "magic": self.magic.decode("latin-1", errors="replace"),
            "version": self.version,
            "compression": self.compression,
            "compressed_size": self.compressed_size,
            "uncompressed_size": self.uncompressed_size,
            "stored": self.stored,
            "payload_size_on_disk": self.payload_size_on_disk,
            "kind": self.kind,
            "self_offset": self.self_offset,
            "payload_start": self.payload_start,
            "payload_end": self.payload_end,
        }


# ---------------------------------------------------------------------------
# Container parser
# ---------------------------------------------------------------------------


def _read_chunk_header(data: bytes, offset: int, index: int) -> ChunkHeader | None:
    """Parse the 48-byte chunk header at ``offset`` (or ``None`` if invalid)."""
    if offset + CHUNK_HEADER_SIZE > len(data):
        return None
    magic = bytes(data[offset:offset + 4])
    if magic != CHUNK_MAGIC:
        return None
    (version, compression, comp, uncomp, kind, self_off) = (
        _CHUNK_HEADER_STRUCT.unpack_from(data, offset + 4)
    )
    return ChunkHeader(
        index=index,
        offset=offset,
        magic=magic,
        version=version,
        compression=compression,
        compressed_size=comp,
        uncompressed_size=uncomp,
        kind=kind,
        self_offset=self_off,
        payload_start=offset + CHUNK_HEADER_SIZE,
    )


def decode_header(path: Path) -> CaptureHeader:
    """Read the file-magic prefix + the first chunk's mini-header.

    Cheap — reads only the first 64 bytes of ``path``.
    """
    with open(path, "rb") as f:
        head = f.read(64)
    size = path.stat().st_size
    magic_prefix = head[:4]
    ok = magic_prefix == FILE_MAGIC_PREFIX
    first = _read_chunk_header(head, 4, 0)
    if first is None:
        # Synthesize a placeholder so the caller still gets a structured reply.
        first = ChunkHeader(
            index=0, offset=4, magic=head[4:8], version=0, compression=0,
            compressed_size=0, uncompressed_size=0, kind=0, self_offset=0,
            payload_start=4 + CHUNK_HEADER_SIZE,
        )
    return CaptureHeader(
        path=path, file_size=size,
        magic_prefix=magic_prefix, magic_prefix_ok=ok,
        first_chunk=first,
    )


def iter_chunk_headers(path: Path, *, max_chunks: int | None = None) -> Iterator[ChunkHeader]:
    """Iterate chunk headers without decompressing payloads.

    Streams ``path`` and yields ``ChunkHeader`` objects in file order. Stops
    on the first invalid header (after best-effort skip of padding bytes).

    Memory-friendly: only the file's tail-end mmap is needed for very large
    captures. For now we mmap-equivalent via incremental reads.
    """
    import mmap

    with open(path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            data: Any = mm
            if data[:4] != FILE_MAGIC_PREFIX:
                return
            offset = 4
            index = 0
            n = len(data)
            while offset < n:
                if max_chunks is not None and index >= max_chunks:
                    return
                # Skip padding (and any chunk-trailer bytes) before the next
                # 'elif' magic. Observed up to ~64 bytes of inter-chunk slack.
                if data[offset:offset + 4] != CHUNK_MAGIC:
                    scan_end = min(offset + 256, n - 4)
                    found = data.find(CHUNK_MAGIC, offset, scan_end)
                    if found == -1:
                        return
                    offset = found
                hdr = _read_chunk_header(data, offset, index)
                if hdr is None:
                    return
                # Validate that the chunk fits inside the file. The capture
                # format ends with a TOC region whose entries look like
                # chunk headers but whose ``self_offset`` points to a *real*
                # earlier chunk and whose ``compressed_size`` would extend
                # past EOF — stop iteration when we hit one of those.
                if hdr.payload_end > n:
                    return
                # Also reject TOC entries whose self_offset disagrees with
                # the actual position: real chunks store their own absolute
                # offset in ``self_offset``.
                if hdr.self_offset != hdr.offset:
                    return
                yield hdr
                index += 1
                # Next chunk starts immediately after payload, aligned up to
                # CHUNK_ALIGN.
                offset = hdr.payload_end
                rem = offset % CHUNK_ALIGN
                if rem != 0:
                    offset += CHUNK_ALIGN - rem


def chunk_summary(path: Path, *, max_chunks: int | None = 256) -> dict[str, Any]:
    """Return a structured listing of the first ``max_chunks`` chunks."""
    chunks = [h.to_dict() for h in iter_chunk_headers(path, max_chunks=max_chunks)]
    total_uncompressed = sum(c["uncompressed_size"] for c in chunks)
    total_compressed = sum(c["compressed_size"] for c in chunks)
    by_kind: dict[int, int] = {}
    for c in chunks:
        by_kind[c["kind"]] = by_kind.get(c["kind"], 0) + 1
    return {
        "path": str(path),
        "chunk_count_listed": len(chunks),
        "total_compressed_bytes_listed": total_compressed,
        "total_uncompressed_bytes_listed": total_uncompressed,
        "chunks_by_kind": dict(sorted(by_kind.items())),
        "chunks": chunks,
    }


# ---------------------------------------------------------------------------
# Chunk lookup by ID (kind)
# ---------------------------------------------------------------------------


def find_chunk_by_kind(path: Path, kind: int) -> ChunkHeader | None:
    """Return the first chunk whose ``kind`` (chunk-id) equals ``kind``.

    The chunk's ``kind`` field is the stable identifier referenced from the
    table of contents (``FunctionInfoChunkIds`` etc.).
    """
    for h in iter_chunk_headers(path):
        if h.kind == kind:
            return h
    return None


# ---------------------------------------------------------------------------
# Decompression
# ---------------------------------------------------------------------------


def decompress_chunk(path: Path, header: ChunkHeader) -> bytes:
    """Read + decompress (or pass-through) the payload of one chunk.

    For ``compression == 1`` (LZ4 block, no frame header), uses
    ``uncompressed_size`` as the destination buffer hint. For
    ``compression == 0`` (stored), returns the raw payload bytes.
    """
    with open(path, "rb") as f:
        f.seek(header.payload_start)
        raw = f.read(header.payload_size_on_disk)
    if header.uncompressed_size == 0:
        return b""
    if header.stored:
        return raw[:header.uncompressed_size]
    try:
        import lz4.block  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("python-lz4 not installed — run `pip install lz4`") from exc
    return lz4.block.decompress(raw, uncompressed_size=header.uncompressed_size)


# ---------------------------------------------------------------------------
# Protobuf decoding helpers
# ---------------------------------------------------------------------------


# Lazy global handle on the proto registry — avoids a hard import dep when
# users only need header / chunk inspection. We bypass
# ``proto_descriptors.get_registry()`` because of a known re-entrant-lock
# deadlock in that helper (it acquires ``_registry_lock`` then synchronously
# calls ``build_registry`` which re-acquires the same non-reentrant lock).
_REGISTRY: Any = None


def _get_registry():
    global _REGISTRY
    if _REGISTRY is None:
        from . import proto_descriptors
        # Prefer the cached registry if someone already built one.
        if proto_descriptors._registry is not None:
            _REGISTRY = proto_descriptors._registry
        else:
            _REGISTRY = proto_descriptors.build_registry()
    return _REGISTRY


def _read_varint(buf: bytes, pos: int) -> tuple[int | None, int]:
    """Decode a protobuf varint. Returns ``(value, new_pos)`` or ``(None, pos)``."""
    result = 0
    shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            return None, pos
    return None, pos


def _looks_like_pbfunctioncalldesc(buf: bytes, max_probe: int = 16) -> bool:
    """Cheap heuristic: does ``buf`` start with a length-delimited (wire type 2)
    field 1 holding ASCII text? ``PbFunctionCallDesc.functionName`` is field 1
    and always a non-empty ASCII string like ``vkCmdDraw`` / ``ExecuteIndirect``.
    """
    if len(buf) < 3:
        return False
    # Expect tag byte 0x0A = (1 << 3) | 2
    if buf[0] != 0x0A:
        return False
    length, after_len = _read_varint(buf, 1)
    if length is None or length < 1 or length > 256:
        return False
    if after_len + length > len(buf):
        return False
    name = buf[after_len:after_len + length]
    # Function names: ASCII, leading letter, characters A-Za-z0-9_.
    if not name:
        return False
    if not (name[0:1].isalpha() or name[:1] == b"_"):
        return False
    for c in name[:max_probe]:
        if not (32 <= c < 127):
            return False
    return True


@dataclass
class DecodedEvent:
    """One ``PbFunctionCallDesc`` extracted from a chunk."""

    event_index: int
    chunk_index: int
    chunk_offset: int          # absolute byte offset of chunk in file
    payload_offset: int        # offset inside the decompressed payload
    function_name: str
    interface_name: str
    arguments: list[Any]
    return_argument: Any | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_index": self.event_index,
            "chunk_index": self.chunk_index,
            "chunk_offset": self.chunk_offset,
            "payload_offset": self.payload_offset,
            "function_name": self.function_name,
            "interface_name": self.interface_name,
            "arguments": self.arguments,
            "return_argument": self.return_argument,
        }


def _argument_to_python(arg: Any) -> Any:
    """Convert a ``PbArgument`` message into a Python-native value.

    Walks the oneof variants and returns dicts / lists / primitives. Falls back
    to a ``{"<unknown>": ...}`` envelope if a field type isn't recognised.
    """
    if arg is None:
        return None

    # Use the protobuf reflection API to enumerate set fields.
    out: dict[str, Any] = {}
    name = getattr(arg, "name", "") or None
    if name:
        out["name"] = name

    for field_desc, value in arg.ListFields():
        fname = field_desc.name
        # Skip the "name" field (already handled).
        if fname == "name":
            continue

        if field_desc.type == field_desc.TYPE_MESSAGE:
            # Recurse into structured args / arrays / nested PbArguments.
            type_name = field_desc.message_type.full_name
            if field_desc.label == field_desc.LABEL_REPEATED:
                out[fname] = [_message_to_python(v) for v in value]
            else:
                out[fname] = _message_to_python(value)
            out.setdefault("_type", type_name)
        elif field_desc.label == field_desc.LABEL_REPEATED:
            out[fname] = list(value)
        else:
            out[fname] = value
    return out


def _message_to_python(msg: Any) -> Any:
    """Generic protobuf -> Python dict converter (best-effort)."""
    if msg is None:
        return None
    # If this is a PbArgument or contains nested PbArguments, recurse.
    if hasattr(msg, "DESCRIPTOR") and msg.DESCRIPTOR.name == "PbArgument":
        return _argument_to_python(msg)
    out: dict[str, Any] = {}
    for field_desc, value in msg.ListFields():
        fname = field_desc.name
        if field_desc.type == field_desc.TYPE_MESSAGE:
            if field_desc.label == field_desc.LABEL_REPEATED:
                out[fname] = [_message_to_python(v) for v in value]
            else:
                out[fname] = _message_to_python(value)
        elif field_desc.label == field_desc.LABEL_REPEATED:
            out[fname] = list(value)
        else:
            out[fname] = value
    return out


def _decode_pb_function_call_desc(buf: bytes, pb_cls: Any) -> Any | None:
    """Try to parse ``buf`` as a ``PbFunctionCallDesc``. Returns ``None`` on failure."""
    try:
        msg = pb_cls()
        msg.MergeFromString(buf)
    except Exception:
        return None
    # Sanity: function_name should be present.
    if not getattr(msg, "functionName", ""):
        return None
    return msg


def _scan_payload_for_events(
    payload: bytes,
    pb_cls: Any,
    *,
    chunk_index: int,
    chunk_offset: int,
    starting_event_index: int,
) -> Iterator[DecodedEvent]:
    """Find length-prefixed ``PbFunctionCallDesc`` records in a decompressed payload.

    Strategy: scan for byte sequences that look like the start of a
    ``PbFunctionCallDesc`` (field 1 = length-prefixed ASCII function name),
    optionally peeled out of an outer length-prefix that came from a parent
    message (varint length + payload).
    """
    pos = 0
    n = len(payload)
    event_index = starting_event_index
    while pos < n:
        # Strategy 1: payload[pos:] *is* a PbFunctionCallDesc.
        if _looks_like_pbfunctioncalldesc(payload[pos:pos + 64]):
            # Try increasing slice sizes until parse succeeds.
            # We don't know the exact length, so attempt parsing the rest of
            # the payload (proto parsers are tolerant of trailing bytes only
            # if we tell them — they aren't, so this often fails). Better:
            # if we're inside a parent that prefixed us with a varint length,
            # peel it.
            msg = _decode_pb_function_call_desc(payload[pos:], pb_cls)
            if msg is not None:
                yield _build_event(msg, event_index, chunk_index, chunk_offset, pos)
                event_index += 1
                # We can't know the consumed length — advance by 1 and rely on
                # heuristic to skip past.
                pos += 1
                continue

        # Strategy 2: peel a varint length prefix.
        length, after = _read_varint(payload, pos)
        if length is not None and 4 <= length <= n - after:
            inner = payload[after:after + length]
            if _looks_like_pbfunctioncalldesc(inner[:64]):
                msg = _decode_pb_function_call_desc(inner, pb_cls)
                if msg is not None:
                    yield _build_event(msg, event_index, chunk_index, chunk_offset, pos)
                    event_index += 1
                    pos = after + length
                    continue

        pos += 1


def _build_event(
    msg: Any,
    event_index: int,
    chunk_index: int,
    chunk_offset: int,
    payload_offset: int,
) -> DecodedEvent:
    args: list[Any] = []
    for a in getattr(msg, "arguments", []):
        args.append(_argument_to_python(a))
    ret = None
    ret_msg = getattr(msg, "returnArgument", None)
    if ret_msg is not None and ret_msg.ByteSize() > 0:
        ret = _argument_to_python(ret_msg)
    return DecodedEvent(
        event_index=event_index,
        chunk_index=chunk_index,
        chunk_offset=chunk_offset,
        payload_offset=payload_offset,
        function_name=getattr(msg, "functionName", ""),
        interface_name=getattr(msg, "interfaceName", ""),
        arguments=args,
        return_argument=ret,
    )


# ---------------------------------------------------------------------------
# Table of contents
# ---------------------------------------------------------------------------


def parse_table_of_contents(path: Path) -> dict[str, Any]:
    """Find and decode the capture's ``NV.PbTableOfContents`` chunk.

    The TOC chunk's ``kind`` is not fixed (the ID is the *value* of field 1
    of the TOC itself, which varies per capture). We probe candidate small-
    to-medium chunks and accept the first whose payload parses as a TOC
    with non-zero ``Version`` and ``NumChunks > 100``.

    Returns a dict like::

      {
        "ok": True,
        "chunk": {...header...},
        "uuid": "...",
        "num_chunks": 22098,
        "num_threads": 28,
        "function_info_chunk_ids": [5],
        "resource_info_chunk_ids": [21421],
        "metadata": {"process_name": ..., "primary_api": ..., ...},
      }
    """
    reg = _get_registry()
    try:
        toc_cls = reg.message_class("NV.PbTableOfContents")
    except Exception as exc:
        return {"ok": False, "error": f"PbTableOfContents not in schema pool: {exc}"}

    # Probe every chunk in the file whose decompressed payload could be a
    # protobuf message (small/medium size, starts with a tag byte). The TOC
    # is usually well under 200 KB.
    for h in iter_chunk_headers(path):
        if h.uncompressed_size > 256 * 1024:
            continue
        try:
            data = decompress_chunk(path, h)
        except Exception:
            continue
        if not data or data[0] > 0x80:
            continue
        toc = toc_cls()
        try:
            toc.ParseFromString(data)
        except Exception:
            continue
        if toc.Version > 0 and toc.NumChunks > 100 and toc.Uuid:
            return _toc_to_dict(h, toc)
    return {"ok": False, "error": "no PbTableOfContents chunk found"}


def _toc_to_dict(header: ChunkHeader, toc: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "ok": True,
        "chunk": header.to_dict(),
        "version": toc.Version,
        "uuid": toc.Uuid,
        "num_chunks": toc.NumChunks,
        "num_threads": toc.NumThreads,
        "function_info_chunk_ids": list(toc.FunctionInfoChunkIds),
        "resource_info_chunk_ids": list(toc.ResourceInfoChunkIds),
        "file_resources": [
            {"sub_path": r.FileSubPath, "chunk_id": r.ChunkID}
            for r in toc.FileResource
        ],
        "user_file_resources": [
            {"id": int(r.ID), "file_path": r.FilePath, "chunk_id": r.ChunkID}
            for r in toc.UserFileResource
        ],
        "thread_info": [
            {"id": t.ID, "name": t.Name} for t in toc.ThreadInfo
        ],
    }
    if toc.HasField("MetaData"):
        md = toc.MetaData
        out["metadata"] = {
            "nsight_version": md.NsightVersion,
            "nsight_branch": md.NsightBranch,
            "process_name": md.ProcessName,
            "process_file_name": md.ProcessFileName,
            "process_command_line": md.ProcessCommandLine,
            "primary_api": md.PrimaryAPI,
            "os_info": md.OsInfo,
            "primary_gpu": md.PrimaryGPU,
            "request_time": md.RequestTime,
            "host_name": md.HostName,
            "capture_begin_frame": md.CaptureBeginFrame,
            "captured_frame_count": md.CapturedFrameCount,
        }
    if toc.HasField("ApiInfo"):
        ai = toc.ApiInfo
        out["api_info"] = {}
        if ai.HasField("D3D12"):
            out["api_info"]["d3d12_resource_count"] = len(ai.D3D12.ResourceInfo)
        if ai.HasField("Vulkan"):
            out["api_info"]["vulkan_resource_count"] = len(ai.Vulkan.ResourceInfo)
            out["api_info"]["vulkan_sc"] = ai.Vulkan.VulkanSC
        if ai.HasField("NGX"):
            out["api_info"]["ngx_plugin_count"] = len(ai.NGX.PluginInfo)
    return out


# ---------------------------------------------------------------------------
# Top-level API
# ---------------------------------------------------------------------------


def decode_events(
    path: Path,
    *,
    start: int = 0,
    limit: int = 200,
    max_chunks_scanned: int | None = None,
) -> dict[str, Any]:
    """Best-effort per-event extraction.

    .. warning::
       This scans chunk payloads for byte sequences that look like
       serialised ``PbFunctionCallDesc`` messages. In current Nsight
       captures the per-event records live in a **binary fixed-stride
       table** (the chunk whose ID is in ``PbTableOfContents.FunctionInfoChunkIds``),
       NOT as repeated ``PbFunctionCallDesc`` messages. So this function
       will usually return zero events for real captures — that's expected.

       For a structured TOC dump (which IS decoded), use
       :func:`parse_table_of_contents` instead. To resolve the binary
       per-event records to function names + args, future work will need
       to (a) decode the fixed-stride record layout and (b) cross-reference
       function IDs against the embedded API descriptor chunk.
    """
    reg = _get_registry()
    pb_cls = reg.message_class("NV.EventParameters.Messages.PbFunctionCallDesc")

    events: list[DecodedEvent] = []
    next_event_index = 0
    chunks_scanned = 0
    chunks_with_events = 0

    for header in iter_chunk_headers(path, max_chunks=max_chunks_scanned):
        chunks_scanned += 1
        # Skip very large chunks — they're typically resource bytes, not
        # the API-call stream. Cap at 4 MiB.
        if header.uncompressed_size > 4 * 1024 * 1024:
            continue
        try:
            payload = decompress_chunk(path, header)
        except Exception:
            continue
        found_here = 0
        for ev in _scan_payload_for_events(
            payload, pb_cls,
            chunk_index=header.index,
            chunk_offset=header.offset,
            starting_event_index=next_event_index,
        ):
            events.append(ev)
            next_event_index += 1
            found_here += 1
            if len(events) - start >= limit and start < len(events):
                break
        if found_here:
            chunks_with_events += 1
        if start < len(events) and len(events) - start >= limit:
            break

    window = events[start:start + limit]
    return {
        "ok": True,
        "path": str(path),
        "chunks_scanned": chunks_scanned,
        "chunks_with_events": chunks_with_events,
        "events_found": len(events),
        "events_returned": len(window),
        "start": start,
        "limit": limit,
        "events": [e.to_dict() for e in window],
        "notes": (
            "Per-event records live in a binary fixed-stride table, not as "
            "PbFunctionCallDesc protobuf messages — this scan typically "
            "returns zero events. Use ngfx_capture_decode_toc or the "
            "JSON-backed `ngfx_index_events` tool for reliable per-event "
            "data."
        ),
    }


def event_args(path: Path, event_index: int) -> dict[str, Any] | None:
    """Return the per-event record at ``event_index`` (linear scan).

    Same caveats as :func:`decode_events`. Returns ``None`` if no event was
    extracted at that index — which is the common case for real captures.
    """
    result = decode_events(path, start=event_index, limit=1)
    if not result["events"]:
        return None
    return result["events"][0]


def search_payloads(
    path: Path,
    needles: Iterable[str],
    *,
    max_chunks: int | None = None,
    max_chunk_uncompressed: int = 32 * 1024 * 1024,
    max_hits: int = 100,
    context_bytes: int = 96,
) -> dict[str, Any]:
    """Search decompressed capture chunk payloads for strings or hex bytes.

    This is intentionally lower-level than ``metadata-objects``. It answers
    "does the saved dump contain CopyRectPS / this shader hash anywhere?" even
    when Nsight's public metadata stream does not expose the object mapping.
    """
    compiled = _compile_needles(needles)
    if not compiled:
        return {"ok": False, "error": "supply at least one non-empty needle"}

    hits: list[dict[str, Any]] = []
    chunks_scanned = 0
    chunks_skipped = 0
    errors: list[dict[str, Any]] = []
    for header in iter_chunk_headers(path, max_chunks=max_chunks):
        if len(hits) >= max_hits:
            break
        if header.uncompressed_size > max_chunk_uncompressed:
            chunks_skipped += 1
            continue
        chunks_scanned += 1
        try:
            payload = decompress_chunk(path, header)
        except Exception as exc:
            chunks_skipped += 1
            if len(errors) < 20:
                errors.append(
                    {
                        "chunk_index": header.index,
                        "chunk_id": header.kind,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
            continue
        payload_lower = payload.lower()
        for needle in compiled:
            haystack = payload_lower if needle["case_insensitive"] else payload
            pos = haystack.find(needle["bytes"])
            while pos >= 0:
                start = max(0, pos - context_bytes)
                end = min(len(payload), pos + len(needle["bytes"]) + context_bytes)
                snippet = payload[start:end]
                hits.append(
                    {
                        "needle": needle["label"],
                        "needle_kind": needle["kind"],
                        "chunk": header.to_dict(),
                        "payload_offset": pos,
                        "context_hex": snippet.hex(),
                        "context_ascii": _ascii_preview(snippet),
                    }
                )
                if len(hits) >= max_hits:
                    break
                pos = haystack.find(needle["bytes"], pos + max(1, len(needle["bytes"])))
            if len(hits) >= max_hits:
                break
    return {
        "ok": True,
        "path": str(path),
        "needles": [item["label"] for item in compiled],
        "chunks_scanned": chunks_scanned,
        "chunks_skipped": chunks_skipped,
        "hit_count": len(hits),
        "hits": hits,
        "errors": errors,
        "notes": [
            "A hit proves the bytes exist somewhere in the saved capture, not which event used them.",
            "Pair hits with GPU Trace shader pipeline search or live replay RPC for exact event/resource provenance.",
        ],
    }


def shader_chunks(
    path: Path,
    *,
    shader_name: str | None = None,
    shader_hash: str | None = None,
    max_chunks: int | None = None,
    max_chunk_uncompressed: int = 64 * 1024 * 1024,
    max_hits: int = 200,
    max_strings: int = 80,
) -> dict[str, Any]:
    """Find DXBC/DXIL shader blobs embedded in capture chunks."""
    wanted_name = shader_name.lower() if shader_name else None
    wanted_hash = _normalise_hash(shader_hash) if shader_hash else None
    records: list[dict[str, Any]] = []
    chunks_scanned = 0
    chunks_skipped = 0
    for header in iter_chunk_headers(path, max_chunks=max_chunks):
        if len(records) >= max_hits:
            break
        if header.uncompressed_size > max_chunk_uncompressed:
            chunks_skipped += 1
            continue
        chunks_scanned += 1
        try:
            payload = decompress_chunk(path, header)
        except Exception:
            chunks_skipped += 1
            continue
        lower = payload.lower()
        dxbc_offsets = _all_offsets(payload, b"DXBC")
        if not dxbc_offsets and b"dxil" not in lower:
            continue
        strings = _ascii_strings(payload, limit=max_strings)
        hash_details = _shader_hash_details(payload, dxbc_offsets)
        hash_candidates = set(hash_details["dxbc_hashes"]) | set(hash_details["sha1_hashes"])
        reasons: list[str] = []
        if wanted_name and any(wanted_name in item.lower() for item in strings):
            reasons.append("shader_name_string")
        if wanted_hash and wanted_hash in hash_candidates:
            reasons.append("shader_hash")
        if wanted_name or wanted_hash:
            if not reasons:
                continue
        records.append(
            {
                "chunk": header.to_dict(),
                "dxbc_offsets": dxbc_offsets,
                "dxil_offsets": _all_offsets(payload, b"DXIL"),
                "hash_candidates": sorted(hash_candidates),
                "dxbc_hashes": hash_details["dxbc_hashes"],
                "sha1_hashes": hash_details["sha1_hashes"],
                "payload_sha1": hash_details["payload_sha1"],
                "strings": strings,
                "name_like_strings": _shader_name_like_strings(strings),
                "pdb_paths": [item for item in strings if item.lower().endswith(".pdb")],
                "match_reasons": reasons,
            }
        )
    return {
        "ok": True,
        "path": str(path),
        "filters": {"shader_name": shader_name, "shader_hash": shader_hash},
        "chunks_scanned": chunks_scanned,
        "chunks_skipped": chunks_skipped,
        "record_count": len(records),
        "records": records,
        "notes": [
            "DXBC header hash is the 16 bytes after the DXBC magic; SHA-1 candidates are also included.",
            "This maps shader names/hashes to capture chunk IDs, not directly to draw events.",
        ],
    }


def chunk_references(
    path: Path,
    *,
    target_chunk_id: int | None = None,
    needles: Iterable[str] | None = None,
    include_numeric_chunk_id_refs: bool = True,
    exclude_chunk_ids: Iterable[int] | None = None,
    max_chunks: int | None = None,
    max_chunk_uncompressed: int = 32 * 1024 * 1024,
    max_hits: int = 200,
    context_bytes: int = 96,
) -> dict[str, Any]:
    """Search capture chunks for references to a chunk id or arbitrary bytes.

    This is a saved-dump graph builder: after ``shader_chunks`` finds a DXBC
    blob chunk, this tool can ask "does any other chunk mention that chunk id,
    shader hash, PDB path, or shader name?" Hits are byte-level evidence, not
    decoded schema fields, but they are often enough to locate the next private
    table to reverse.
    """
    patterns = _reference_patterns(
        target_chunk_id,
        needles or [],
        include_numeric_chunk_id_refs=include_numeric_chunk_id_refs,
    )
    if not patterns:
        return {"ok": False, "error": "supply target_chunk_id or at least one needle"}
    excluded = {int(value) for value in (exclude_chunk_ids or [])}
    hits: list[dict[str, Any]] = []
    chunks_scanned = 0
    chunks_skipped = 0
    errors: list[dict[str, Any]] = []

    for header in iter_chunk_headers(path, max_chunks=max_chunks):
        if len(hits) >= max_hits:
            break
        if header.kind in excluded:
            chunks_skipped += 1
            continue
        if header.uncompressed_size > max_chunk_uncompressed:
            chunks_skipped += 1
            continue
        chunks_scanned += 1
        try:
            payload = decompress_chunk(path, header)
        except Exception as exc:
            chunks_skipped += 1
            if len(errors) < 20:
                errors.append(
                    {
                        "chunk_index": header.index,
                        "chunk_id": header.kind,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
            continue
        payload_lower = payload.lower()
        for pattern in patterns:
            haystack = payload_lower if pattern["case_insensitive"] else payload
            pos = haystack.find(pattern["bytes"])
            while pos >= 0:
                start = max(0, pos - context_bytes)
                end = min(len(payload), pos + len(pattern["bytes"]) + context_bytes)
                snippet = payload[start:end]
                hits.append(
                    {
                        "target_chunk_id": target_chunk_id,
                        "needle": pattern["label"],
                        "reference_kind": pattern["kind"],
                        "chunk": header.to_dict(),
                        "payload_offset": pos,
                        "context_hex": snippet.hex(),
                        "context_ascii": _ascii_preview(snippet),
                    }
                )
                if len(hits) >= max_hits:
                    break
                pos = haystack.find(pattern["bytes"], pos + max(1, len(pattern["bytes"])))
            if len(hits) >= max_hits:
                break

    external_hits = [
        hit
        for hit in hits
        if target_chunk_id is None or hit["chunk"]["kind"] != target_chunk_id
    ]
    return {
        "ok": True,
        "path": str(path),
        "target_chunk_id": target_chunk_id,
        "include_numeric_chunk_id_refs": include_numeric_chunk_id_refs,
        "needles": [pattern["label"] for pattern in patterns],
        "excluded_chunk_ids": sorted(excluded),
        "chunks_scanned": chunks_scanned,
        "chunks_skipped": chunks_skipped,
        "hit_count": len(hits),
        "external_hit_count": len(external_hits),
        "hits": hits,
        "errors": errors,
        "notes": [
            "Numeric chunk-id hits are candidate references; private schemas still need decoding to prove field meaning.",
            "Use exclude_chunk_ids=[target_chunk_id] to suppress self-matches from the source shader chunk.",
        ],
    }


def _compile_needles(needles: Iterable[str]) -> list[dict[str, Any]]:
    compiled: list[dict[str, Any]] = []
    seen: set[tuple[str, bytes]] = set()
    for raw in needles:
        text = str(raw).strip()
        if not text:
            continue
        text_bytes = text.lower().encode("utf-8", errors="replace")
        key = ("text", text_bytes)
        if key not in seen:
            seen.add(key)
            compiled.append(
                {
                    "label": text,
                    "kind": "text",
                    "bytes": text_bytes,
                    "case_insensitive": True,
                }
            )
        hex_text = text.lower().removeprefix("0x").replace(" ", "")
        if len(hex_text) >= 4 and len(hex_text) % 2 == 0:
            try:
                binary = bytes.fromhex(hex_text)
            except ValueError:
                continue
            key = ("hex", binary)
            if key not in seen:
                seen.add(key)
                compiled.append(
                    {
                        "label": text,
                        "kind": "hex_bytes",
                        "bytes": binary,
                        "case_insensitive": False,
                    }
                )
    return compiled


def _reference_patterns(
    target_chunk_id: int | None,
    needles: Iterable[str],
    *,
    include_numeric_chunk_id_refs: bool,
) -> list[dict[str, Any]]:
    patterns = _compile_needles(needles)
    if target_chunk_id is None or not include_numeric_chunk_id_refs:
        return patterns
    chunk_id = int(target_chunk_id)
    numeric: list[dict[str, Any]] = [
        {
            "label": str(chunk_id),
            "kind": "chunk_id_u32_le",
            "bytes": chunk_id.to_bytes(4, "little", signed=False),
            "case_insensitive": False,
        },
        {
            "label": str(chunk_id),
            "kind": "chunk_id_u64_le",
            "bytes": chunk_id.to_bytes(8, "little", signed=False),
            "case_insensitive": False,
        },
        {
            "label": str(chunk_id),
            "kind": "chunk_id_u32_be",
            "bytes": chunk_id.to_bytes(4, "big", signed=False),
            "case_insensitive": False,
        },
        {
            "label": str(chunk_id),
            "kind": "chunk_id_u64_be",
            "bytes": chunk_id.to_bytes(8, "big", signed=False),
            "case_insensitive": False,
        },
        {
            "label": str(chunk_id),
            "kind": "chunk_id_ascii_decimal",
            "bytes": str(chunk_id).encode("ascii"),
            "case_insensitive": False,
        },
        {
            "label": hex(chunk_id),
            "kind": "chunk_id_ascii_hex",
            "bytes": hex(chunk_id).encode("ascii"),
            "case_insensitive": True,
        },
    ]
    seen = {(pattern["kind"], pattern["bytes"]) for pattern in patterns}
    for pattern in numeric:
        key = (pattern["kind"], pattern["bytes"])
        if key not in seen:
            seen.add(key)
            patterns.append(pattern)
    return patterns


def _normalise_hash(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip().lower().removeprefix("0x").replace(" ", "")
    return text or None


def _all_offsets(payload: bytes, needle: bytes) -> list[int]:
    offsets: list[int] = []
    pos = payload.find(needle)
    while pos >= 0:
        offsets.append(pos)
        pos = payload.find(needle, pos + 1)
    return offsets


def _shader_hash_details(payload: bytes, dxbc_offsets: list[int]) -> dict[str, Any]:
    dxbc_hashes: set[str] = set()
    sha1_hashes: set[str] = {hashlib.sha1(payload).hexdigest()}
    for offset in dxbc_offsets:
        if offset + 20 <= len(payload):
            dxbc_hashes.add(payload[offset + 4:offset + 20].hex())
        sha1_hashes.add(hashlib.sha1(payload[offset:]).hexdigest())
    return {
        "dxbc_hashes": sorted(dxbc_hashes),
        "sha1_hashes": sorted(sha1_hashes),
        "payload_sha1": hashlib.sha1(payload).hexdigest(),
    }


_COMMON_SHADER_STRINGS = {
    "DXBC",
    "DXIL",
    "HASH",
    "ISG1",
    "OSG1",
    "PCSG",
    "PRIV",
    "PSV0",
    "RDAT",
    "SFI0",
    "SHDR",
    "STAT",
    "SV_Target",
    "TEXCOORD",
}


def _shader_name_like_strings(strings: list[str]) -> list[str]:
    out: list[str] = []
    for item in strings:
        text = item.strip()
        if not text or text in _COMMON_SHADER_STRINGS:
            continue
        if text.startswith("SV_") or text.lower().endswith(".pdb"):
            continue
        if not any(ch.isalpha() for ch in text):
            continue
        if not all(ch.isalnum() or ch in "_$.:/-" for ch in text):
            continue
        if len(text) > 128:
            continue
        out.append(text)
    return out


def _ascii_strings(payload: bytes, *, limit: int) -> list[str]:
    strings: list[str] = []
    current = bytearray()
    for byte in payload:
        if 32 <= byte < 127:
            current.append(byte)
            continue
        if len(current) >= 4:
            strings.append(current.decode("latin-1", errors="replace"))
            if len(strings) >= limit:
                break
        current.clear()
    if len(strings) < limit and len(current) >= 4:
        strings.append(current.decode("latin-1", errors="replace"))
    return strings


def _ascii_preview(data: bytes) -> str:
    return "".join(chr(byte) if 32 <= byte < 127 else "." for byte in data)
