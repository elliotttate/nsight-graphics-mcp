"""Low-level ``.ngfx-gfxcap`` capture file structural inspection.

Reverse-engineering status (see ``docs/CAPTURE_FORMAT.md``):

  * **Known**: file starts with the 8-byte ASCII magic ``b'nlypelif'``
    (32-bit little-endian "pyln" + "file" — i.e. *Pylon file*).
  * **Known**: payload is protobuf-encoded using messages in the ``NV.*``
    namespace across 22 .proto files. See ``proto_schemas.py``.
  * **Known**: protobuf payloads can be compressed (``PbCompression`` enum:
    NONE / LZ4) and decompressed with the bundled ``lz4`` library.
  * **Partial**: the post-header byte layout (TOC, per-section offsets,
    per-section compression flags) — this requires more RE.
  * **Unknown**: per-resource byte offsets — would require the full
    ``.proto`` reconstruction + protobuf decoding pass.

This module provides the basics that ARE known:

  * Verify a file is a ``.ngfx-gfxcap``.
  * Return its header bytes + size.
  * Compute the SHA-256 fingerprint.
  * Attempt LZ4-block decompression of a byte range (for experimentation).

For any *content-level* question, prefer the JSON-backed tools:

  * ``ngfx_capture_summary`` (``--metadata``)
  * ``ngfx_index_objects`` / ``ngfx_query_objects``
  * ``ngfx_index_events`` / ``ngfx_find_events``
"""

from __future__ import annotations

import hashlib
import io
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CAPTURE_MAGIC = b"nlypelif"  # = "pyln" + "file" stored little-endian
CAPTURE_MAGIC_HEX = CAPTURE_MAGIC.hex()


@dataclass
class CaptureHeader:
    path: Path
    size_bytes: int
    magic_ok: bool
    magic_hex: str
    sha256: str
    header_raw_hex: str
    # Best-effort interpretation; field names are tentative pending RE.
    tentative_version_u64: int | None
    tentative_word_u32: int | None
    tentative_offset_u64_1: int | None
    tentative_offset_u64_2: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "size_bytes": self.size_bytes,
            "magic_ok": self.magic_ok,
            "magic_hex": self.magic_hex,
            "magic_ascii": CAPTURE_MAGIC.decode("ascii"),
            "sha256": self.sha256,
            "header_raw_hex": self.header_raw_hex,
            "tentative_fields": {
                "version_u64": self.tentative_version_u64,
                "word_u32": self.tentative_word_u32,
                "offset_u64_1": self.tentative_offset_u64_1,
                "offset_u64_2": self.tentative_offset_u64_2,
            },
            "notes": [
                "Magic decoded LE: 'pyln' + 'file' → 'Pylon file'.",
                "Field interpretation is tentative — see docs/CAPTURE_FORMAT.md.",
                "Use JSON-backed tools (capture_summary, index_objects) for content-level queries.",
            ],
        }


def inspect_header(path: Path) -> CaptureHeader:
    data = path.read_bytes()
    size = len(data)
    head = data[:64]
    magic = data[:8]
    magic_ok = magic == CAPTURE_MAGIC

    sha = hashlib.sha256(data).hexdigest()

    version = struct.unpack_from("<Q", data, 8)[0] if size >= 16 else None
    word = struct.unpack_from("<I", data, 16)[0] if size >= 20 else None
    off1 = struct.unpack_from("<Q", data, 20)[0] if size >= 28 else None
    off2 = struct.unpack_from("<Q", data, 28)[0] if size >= 36 else None

    return CaptureHeader(
        path=path,
        size_bytes=size,
        magic_ok=magic_ok,
        magic_hex=magic.hex(),
        sha256=sha,
        header_raw_hex=head.hex(),
        tentative_version_u64=version,
        tentative_word_u32=word,
        tentative_offset_u64_1=off1,
        tentative_offset_u64_2=off2,
    )


def lz4_decompress_block(
    data: bytes, *, uncompressed_size_hint: int | None = None
) -> dict[str, Any]:
    """Attempt to LZ4-block-decompress ``data``.

    The Nsight capture payload chunks are LZ4-block-compressed (no frame
    header), so callers need to know the uncompressed size — pass
    ``uncompressed_size_hint`` if you have it. Returns the decompressed
    bytes hex-encoded for safety (small fragments) or just the size for
    large payloads.
    """
    try:
        import lz4.block  # type: ignore[import-not-found]
    except ImportError:
        return {"ok": False, "error": "python-lz4 not installed (pip install lz4)"}
    if uncompressed_size_hint is None:
        # Try a generous default
        uncompressed_size_hint = max(len(data) * 8, 1024 * 1024)
    try:
        out = lz4.block.decompress(data, uncompressed_size=uncompressed_size_hint)
    except Exception as exc:
        return {
            "ok": False,
            "error": f"lz4 block decompress failed: {exc}",
            "input_bytes": len(data),
            "hint": "may need exact uncompressed_size or this is not raw LZ4 block",
        }
    return {
        "ok": True,
        "input_bytes": len(data),
        "output_bytes": len(out),
        "preview_hex": out[:256].hex(),
    }


def decode_protobuf_wire(data: bytes, *, max_fields: int = 200) -> dict[str, Any]:
    """Decode unknown protobuf wire format generically.

    Returns a list of ``{field_number, wire_type, value}`` records for human
    inspection of unknown payloads. Useful for confirming a byte range is
    valid protobuf and seeing its top-level structure without the schema.
    """
    fields: list[dict[str, Any]] = []
    pos = 0
    n = len(data)
    while pos < n and len(fields) < max_fields:
        # varint: tag = (field_number << 3) | wire_type
        tag, pos2 = _read_varint(data, pos)
        if tag is None:
            break
        field_no = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:  # varint
            val, pos2 = _read_varint(data, pos2)
            fields.append({"field": field_no, "wire": "varint", "value": val})
        elif wire_type == 1:  # 64-bit
            if pos2 + 8 > n:
                break
            val = struct.unpack_from("<Q", data, pos2)[0]
            fields.append({"field": field_no, "wire": "fixed64", "value": val})
            pos2 += 8
        elif wire_type == 2:  # length-delimited
            length, pos2 = _read_varint(data, pos2)
            if length is None or pos2 + length > n:
                break
            payload = data[pos2 : pos2 + length]
            preview = payload[:64].hex()
            fields.append(
                {
                    "field": field_no,
                    "wire": "length_delimited",
                    "length": length,
                    "preview_hex": preview,
                    "as_string": (
                        payload.decode("utf-8")
                        if all(32 <= b < 127 for b in payload[:32])
                        else None
                    ),
                }
            )
            pos2 += length
        elif wire_type == 5:  # 32-bit
            if pos2 + 4 > n:
                break
            val = struct.unpack_from("<I", data, pos2)[0]
            fields.append({"field": field_no, "wire": "fixed32", "value": val})
            pos2 += 4
        else:
            fields.append(
                {"field": field_no, "wire": f"unknown_{wire_type}", "stopped_at": pos2}
            )
            break
        pos = pos2
    return {
        "field_count": len(fields),
        "fields": fields,
        "consumed_bytes": pos,
        "total_bytes": n,
        "truncated": len(fields) >= max_fields,
    }


def _read_varint(data: bytes, pos: int) -> tuple[int | None, int]:
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            return None, pos
    return None, pos
