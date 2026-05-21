"""Tests for the direct ``.ngfx-gfxcap`` decoder.

The container-format tests work on a synthetic capture built in-memory.
The end-to-end tests need both Nsight Graphics installed (for the
``proto_descriptors`` registry) AND a real capture file — both are
discovered dynamically and skipped if unavailable.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from nsight_graphics_mcp import capture_decoder as cd
from nsight_graphics_mcp.config import host_bin_dir

# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------


def _ngfx_replay() -> Path | None:
    bd = host_bin_dir()
    if bd is None:
        return None
    p = bd / "ngfx-replay.exe"
    return p if p.is_file() else None


def _find_sample_capture() -> Path | None:
    """Look for a real ``.ngfx-capture`` next to the user's documents."""
    env = os.environ.get("NSIGHT_GRAPHICS_MCP_TEST_CAPTURE")
    if env and Path(env).is_file():
        return Path(env)
    candidates = [
        Path.home() / "Documents" / "NVIDIA Nsight Graphics" / "GraphicsCaptures",
    ]
    for root in candidates:
        if not root.is_dir():
            continue
        for entry in sorted(root.iterdir()):
            if entry.suffix in (".ngfx-capture", ".ngfx-gfxcap") and entry.is_file():
                return entry
    return None


REPLAY = _ngfx_replay()
SAMPLE = _find_sample_capture()

needs_install = pytest.mark.skipif(REPLAY is None, reason="Nsight Graphics not installed")
needs_sample = pytest.mark.skipif(SAMPLE is None, reason="no .ngfx-capture sample found")


# ---------------------------------------------------------------------------
# Synthetic capture builders for hermetic container-format tests
# ---------------------------------------------------------------------------


def _make_chunk_header(
    *,
    compression: int,
    compressed_size: int,
    uncompressed_size: int,
    kind: int,
    self_offset: int,
) -> bytes:
    return cd.CHUNK_MAGIC + struct.pack(
        "<QIQQQQ", 1, compression, compressed_size, uncompressed_size, kind, self_offset
    )


def _build_capture(payload_chunks: list[tuple[int, int, bytes]]) -> bytes:
    """Build a minimal capture file (no TOC) from raw chunks.

    Each ``payload_chunks`` entry is ``(compression, kind, payload_bytes)``.
    For ``compression == 0`` the payload is stored verbatim; for
    ``compression == 1`` we use LZ4 block encode.
    """
    import lz4.block

    buf = bytearray()
    buf += cd.FILE_MAGIC_PREFIX
    for compression, kind, payload in payload_chunks:
        self_off = len(buf)
        if compression == 0:
            on_disk = payload
            comp_size = 0
            uncomp_size = len(payload)
        elif compression == 1:
            on_disk = lz4.block.compress(payload, store_size=False)
            comp_size = len(on_disk)
            uncomp_size = len(payload)
        else:
            raise ValueError("unknown compression")
        buf += _make_chunk_header(
            compression=compression,
            compressed_size=comp_size,
            uncompressed_size=uncomp_size,
            kind=kind,
            self_offset=self_off,
        )
        buf += on_disk
        # Pad to 16-byte alignment.
        rem = len(buf) % cd.CHUNK_ALIGN
        if rem:
            buf += b"\x00" * (cd.CHUNK_ALIGN - rem)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_constants() -> None:
    assert cd.FILE_MAGIC_PREFIX == b"nlyp"
    assert cd.CHUNK_MAGIC == b"elif"
    assert cd.CHUNK_HEADER_SIZE == 48


def test_decode_header_synthetic(tmp_path: Path) -> None:
    p = tmp_path / "fake.ngfx-capture"
    capture = _build_capture([(1, 9, b"hello world" * 64)])
    p.write_bytes(capture)

    hdr = cd.decode_header(p)
    assert hdr.magic_prefix_ok is True
    assert hdr.magic_prefix == b"nlyp"
    assert hdr.first_chunk.magic == b"elif"
    assert hdr.first_chunk.kind == 9
    assert hdr.first_chunk.uncompressed_size == 11 * 64


def test_iter_chunk_headers_synthetic(tmp_path: Path) -> None:
    p = tmp_path / "fake.ngfx-capture"
    payloads = [
        (1, 1, b"AAAA" * 256),
        (1, 2, b"BBBB" * 128),
        (0, 3, b"\x01\x02\x03\x04"),
        (1, 4, b"DDDD" * 64),
    ]
    capture = _build_capture(payloads)
    p.write_bytes(capture)

    headers = list(cd.iter_chunk_headers(p))
    assert len(headers) == 4
    assert [h.kind for h in headers] == [1, 2, 3, 4]
    assert headers[2].stored is True  # the compression=0 chunk
    assert headers[2].uncompressed_size == 4
    # self_offset must equal absolute offset for each real chunk.
    for h in headers:
        assert h.self_offset == h.offset


def test_decompress_chunk_roundtrip_synthetic(tmp_path: Path) -> None:
    p = tmp_path / "fake.ngfx-capture"
    payload_lz4 = b"hello world! " * 200
    payload_raw = b"\xff\xee\xdd\xcc"
    capture = _build_capture([(1, 100, payload_lz4), (0, 200, payload_raw)])
    p.write_bytes(capture)

    headers = list(cd.iter_chunk_headers(p))
    assert len(headers) == 2
    out_lz4 = cd.decompress_chunk(p, headers[0])
    assert out_lz4 == payload_lz4
    out_raw = cd.decompress_chunk(p, headers[1])
    assert out_raw == payload_raw


def test_search_payloads_synthetic(tmp_path: Path) -> None:
    p = tmp_path / "fake.ngfx-capture"
    payload = b"prefix CopyRectPS shader hash 98acf00f2001c218 suffix"
    raw_hash = bytes.fromhex("98acf00f2001c218")
    capture = _build_capture([(1, 100, payload), (0, 200, b"\x00" + raw_hash + b"\x01")])
    p.write_bytes(capture)

    result = cd.search_payloads(p, ["CopyRectPS", "98acf00f2001c218"])

    assert result["ok"]
    assert result["hit_count"] >= 3
    kinds = {hit["needle_kind"] for hit in result["hits"]}
    assert "text" in kinds
    assert "hex_bytes" in kinds


def test_shader_chunks_synthetic(tmp_path: Path) -> None:
    p = tmp_path / "fake.ngfx-capture"
    dxbc_hash = bytes.fromhex("529845b997ed9c43ad87a3a1432fd393")
    payload = b"DXBC" + dxbc_hash + b"\x00" * 32 + b"TEXCOORD\x00CopyRectPS\x00DXIL"
    capture = _build_capture([(1, 100, payload)])
    p.write_bytes(capture)

    result = cd.shader_chunks(
        p,
        shader_name="CopyRectPS",
        shader_hash="529845b997ed9c43ad87a3a1432fd393",
    )

    assert result["ok"]
    assert result["record_count"] == 1
    record = result["records"][0]
    assert record["chunk"]["kind"] == 100
    assert record["dxbc_offsets"] == [0]
    assert "529845b997ed9c43ad87a3a1432fd393" in record["hash_candidates"]
    assert record["dxbc_hashes"] == ["529845b997ed9c43ad87a3a1432fd393"]
    assert record["payload_sha1"] in record["sha1_hashes"]
    assert "CopyRectPS" in record["name_like_strings"]
    assert set(record["match_reasons"]) == {"shader_name_string", "shader_hash"}


def test_chunk_references_synthetic(tmp_path: Path) -> None:
    p = tmp_path / "fake.ngfx-capture"
    shader_payload = b"DXBC" + (b"\x11" * 16) + b"\x00CopyRectPS\x00"
    ref_payload = b"refs:" + struct.pack("<I", 100) + b":CopyRectPS"
    capture = _build_capture([(1, 100, shader_payload), (1, 200, ref_payload)])
    p.write_bytes(capture)

    result = cd.chunk_references(
        p,
        target_chunk_id=100,
        needles=["CopyRectPS"],
        exclude_chunk_ids=[100],
    )

    assert result["ok"]
    assert result["hit_count"] >= 2
    assert result["external_hit_count"] == result["hit_count"]
    hit_kinds = {hit["reference_kind"] for hit in result["hits"]}
    assert "chunk_id_u32_le" in hit_kinds
    assert "text" in hit_kinds
    assert {hit["chunk"]["kind"] for hit in result["hits"]} == {200}

    text_only = cd.chunk_references(
        p,
        target_chunk_id=100,
        needles=["CopyRectPS"],
        include_numeric_chunk_id_refs=False,
        exclude_chunk_ids=[100],
    )
    assert text_only["hit_count"] == 1
    assert text_only["hits"][0]["reference_kind"] == "text"


def test_chunk_summary_synthetic(tmp_path: Path) -> None:
    p = tmp_path / "fake.ngfx-capture"
    capture = _build_capture([(1, 1, b"AAAA" * 64), (1, 2, b"BBBB" * 64)])
    p.write_bytes(capture)

    s = cd.chunk_summary(p)
    assert s["chunk_count_listed"] == 2
    assert s["chunks_by_kind"] == {1: 1, 2: 1}


def test_iter_stops_when_payload_exceeds_eof(tmp_path: Path) -> None:
    """The TOC region at the end of a real capture has 'elif'-looking
    records whose compressed_size would extend past EOF. The iterator
    must stop instead of returning garbage chunks."""
    p = tmp_path / "fake.ngfx-capture"
    buf = bytearray(_build_capture([(1, 1, b"X" * 64)]))
    # Append a 'fake TOC entry' that claims a huge payload.
    buf += cd.CHUNK_MAGIC + struct.pack("<QIQQQQ", 1, 1, 9_999_999, 9_999_999, 999, 0xDEAD_BEEF)
    p.write_bytes(bytes(buf))

    headers = list(cd.iter_chunk_headers(p))
    # Only the one real chunk; the fake TOC entry is rejected.
    assert len(headers) == 1
    assert headers[0].kind == 1


# ---------------------------------------------------------------------------
# End-to-end tests against a real sample capture
# ---------------------------------------------------------------------------


@needs_install
@needs_sample
def test_real_capture_header_decodes() -> None:
    hdr = cd.decode_header(SAMPLE)
    assert hdr.magic_prefix_ok is True
    assert hdr.first_chunk.magic == b"elif"
    assert hdr.first_chunk.version == 1


@needs_install
@needs_sample
def test_real_capture_iterates_many_chunks() -> None:
    headers = list(cd.iter_chunk_headers(SAMPLE, max_chunks=512))
    assert len(headers) >= 50
    # Every header should fit inside the file.
    sz = SAMPLE.stat().st_size
    for h in headers:
        assert h.payload_end <= sz


@needs_install
@needs_sample
def test_real_capture_decompress_first_chunks() -> None:
    headers = list(cd.iter_chunk_headers(SAMPLE, max_chunks=10))
    assert headers, "no chunks iterated"
    for h in headers:
        data = cd.decompress_chunk(SAMPLE, h)
        assert len(data) == h.uncompressed_size


@needs_install
@needs_sample
def test_real_capture_chunk_summary() -> None:
    s = cd.chunk_summary(SAMPLE, max_chunks=64)
    assert s["chunk_count_listed"] >= 1
    assert s["chunks_by_kind"]


@needs_install
@needs_sample
def test_real_capture_parse_toc() -> None:
    """The TOC chunk is decoded into the structured dict and includes
    capture metadata + chunk-id pointers."""
    toc = cd.parse_table_of_contents(SAMPLE)
    assert toc["ok"] is True
    assert toc["uuid"]
    assert toc["num_chunks"] > 100
    assert toc["num_threads"] > 0
    assert toc["function_info_chunk_ids"]
    assert toc["resource_info_chunk_ids"]
    md = toc.get("metadata", {})
    assert md.get("process_name")
    assert md.get("primary_api") in ("D3D12", "Vulkan", "OpenGL", "")


@needs_install
@needs_sample
def test_real_capture_find_function_info_chunk() -> None:
    """The chunk-id referenced by the TOC's ``FunctionInfoChunkIds`` must
    exist in the file."""
    toc = cd.parse_table_of_contents(SAMPLE)
    fi_ids = toc["function_info_chunk_ids"]
    assert fi_ids
    h = cd.find_chunk_by_kind(SAMPLE, fi_ids[0])
    assert h is not None
    assert h.uncompressed_size > 0
    # Make sure we can decompress it.
    data = cd.decompress_chunk(SAMPLE, h)
    assert len(data) == h.uncompressed_size
