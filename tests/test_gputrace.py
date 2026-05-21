from __future__ import annotations

import json
import zipfile
from pathlib import Path

from nsight_graphics_mcp import gputrace


def test_search_shader_pipelines_finds_json_shader_hash(tmp_path: Path) -> None:
    trace = tmp_path / "capture.nsight-gputrace"
    payload = {
        "pipelines": [
            {
                "name": "CopyRectPS",
                "pixel_shader": {
                    "entry": "MainPS",
                    "hash": "98acf00f2001c218",
                },
            }
        ]
    }
    with zipfile.ZipFile(trace, "w") as zf:
        zf.writestr("reports/shader_pipelines.json", json.dumps(payload))
        zf.writestr("reports/unrelated.txt", "no shader details here")

    result = gputrace.search_shader_pipelines(
        trace,
        shader_name="CopyRectPS",
        shader_hash="98acf00f2001c218",
    )

    assert result["ok"]
    assert result["hit_count"] == 1
    hit = result["hits"][0]
    assert hit["member"] == "reports/shader_pipelines.json"
    assert hit["format"] == "json"
    assert hit["json_matches"]


def test_search_shader_pipelines_requires_a_needle(tmp_path: Path) -> None:
    trace = tmp_path / "capture.nsight-gputrace"
    with zipfile.ZipFile(trace, "w") as zf:
        zf.writestr("reports/shader_pipelines.json", "{}")

    result = gputrace.search_shader_pipelines(trace)

    assert not result["ok"]
    assert "supply" in result["error"]


def test_inspect_wrpv_binary_trace(tmp_path: Path) -> None:
    trace = tmp_path / "capture.ngfx-gputrace"
    trace.write_bytes(b"WRPV" + b"\x00" * 16 + b"Trace Shader Bindings\x00Collect Shader Pipelines")

    result = gputrace.inspect_archive(trace)

    assert result["container"] == "wrpv"
    assert result["magic"] == "WRPV"
    assert any("Trace Shader Bindings" in item for item in result["strings_preview"])


def test_export_summary_and_search_parse_tab_exports(tmp_path: Path) -> None:
    (tmp_path / "ReportGeneratorTags.txt").write_text("GPU Trace Data | BASE", encoding="utf-8")
    base = tmp_path / "BASE"
    base.mkdir()
    (base / "REPRO_INFO.xls").write_text(
        "Process File Name\tngfx-replay.exe\n"
        "API\tDirect3D 12\n"
        "Trace Shader Bindings\tYes\n"
        "Collect Shader Pipelines\tYes\n",
        encoding="utf-8",
    )
    (base / "GPUTRACE_FRAME.xls").write_text(
        "metric_a\t1\nmetric_b\t2\n",
        encoding="utf-8",
    )
    (base / "GPUTRACE_REGIMES.xls").write_text(
        "flattened_event_name\tmetric\nDraw CopyRectPS\t3\n",
        encoding="utf-8",
    )

    summary = gputrace.export_summary(tmp_path)
    assert summary["ok"]
    assert summary["repro_info"]["Process File Name"] == "ngfx-replay.exe"
    assert summary["repro_info"]["Trace Shader Bindings"] == "Yes"
    assert summary["metrics"]["GPUTRACE_FRAME.xls"]["metric_count"] == 2

    search = gputrace.search_export(tmp_path, ["CopyRectPS"])
    assert search["ok"]
    assert search["hit_count"] == 1
    assert Path(search["hits"][0]["relative_file"]).parts == ("BASE", "GPUTRACE_REGIMES.xls")


# ---------------------------------------------------------------------------
# WRPV deep inspection
# ---------------------------------------------------------------------------


def _synth_wrpv(tmp_path: Path) -> Path:
    """Build a synthetic WRPV-like file with embedded ASCII + UTF-16LE
    needles plus a raw byte pattern. Layout (no real WRPV format claim):

        0000  WRPV
        0004  <16 bytes of zero>
        0014  ASCII: "CopyRectPS"           (no NUL)
        001f  UTF-16LE: "DrawIndexedInstanced"
        0048  raw bytes 0xDEADBEEFCAFEBABE
        0050  ASCII: "aab95ca751a813819972cc044ba1d07b.pdb"
        ...   padding to some plausible size
    """
    blob = bytearray()
    blob += b"WRPV"
    blob += b"\x00" * 16
    blob += b"CopyRectPS\x00"
    blob += "DrawIndexedInstanced".encode("utf-16le") + b"\x00\x00"
    blob += bytes.fromhex("DEADBEEFCAFEBABE")
    blob += b"\x00"
    blob += b"aab95ca751a813819972cc044ba1d07b.pdb\x00"
    # plausible end-of-file padding so size offsets exist
    blob += b"\x00" * 4096
    path = tmp_path / "synth.ngfx-gputrace"
    path.write_bytes(bytes(blob))
    return path


def test_wrpv_is_wrpv_round_trip(tmp_path: Path) -> None:
    wrpv = _synth_wrpv(tmp_path)
    assert gputrace.wrpv_is_wrpv(wrpv) is True
    non = tmp_path / "non.gputrace"
    non.write_bytes(b"NOPE" + b"\x00" * 100)
    assert gputrace.wrpv_is_wrpv(non) is False


def test_wrpv_search_finds_ascii_utf16_and_hex(tmp_path: Path) -> None:
    wrpv = _synth_wrpv(tmp_path)
    out = gputrace.wrpv_search(
        wrpv,
        ["CopyRectPS", "DrawIndexedInstanced", "<hex:DEADBEEFCAFEBABE>"],
    )
    assert out["ok"]
    assert out["is_wrpv"] is True
    hits_copyrect = out["hits"]["CopyRectPS"]
    assert any(h["encoding"] == "ascii" for h in hits_copyrect)
    hits_draw = out["hits"]["DrawIndexedInstanced"]
    assert any(h["encoding"] == "utf-16le" for h in hits_draw)
    hits_hex = out["hits"]["<hex:DEADBEEFCAFEBABE>"]
    assert len(hits_hex) == 1
    assert hits_hex[0]["match_bytes"] == 8


def test_wrpv_search_handles_bad_hex(tmp_path: Path) -> None:
    wrpv = _synth_wrpv(tmp_path)
    out = gputrace.wrpv_search(wrpv, ["<hex:ZZZZ>"])
    assert out["ok"]
    # No raise; the bad-hex error is captured per-needle
    bad = out["hits"]["<hex:ZZZZ>"]
    assert bad and "error" in bad[0]


def test_wrpv_strings_extracts_with_offsets_and_filter(tmp_path: Path) -> None:
    wrpv = _synth_wrpv(tmp_path)
    out = gputrace.wrpv_strings(wrpv, min_len=5, limit=200)
    assert out["ok"]
    texts = [s["text"] for s in out["strings"]]
    assert any(t == "CopyRectPS" for t in texts)
    assert any("DrawIndexedInstanced" in t for t in texts)
    assert any(".pdb" in t for t in texts)

    filtered = gputrace.wrpv_strings(
        wrpv, min_len=5, limit=200, pattern=r"PS$"
    )
    assert filtered["ok"]
    assert all("PS" in s["text"] for s in filtered["strings"])
    assert any(s["text"] == "CopyRectPS" for s in filtered["strings"])


def test_wrpv_sections_labels_candidates(tmp_path: Path) -> None:
    wrpv = _synth_wrpv(tmp_path)
    out = gputrace.wrpv_sections(wrpv)
    assert out["ok"]
    assert out["proven"]["magic"] == "WRPV"
    assert out["proven"]["is_wrpv"] is True
    # Every candidate must carry the explicit evidence label so
    # downstream tools don't accidentally treat them as proof.
    for cand in out["candidate_fields"]:
        assert cand["evidence_label"] == "candidate"


def test_wrpv_table_preview_returns_hex_and_ascii(tmp_path: Path) -> None:
    wrpv = _synth_wrpv(tmp_path)
    # Offset 0 should preview the WRPV magic.
    out = gputrace.wrpv_table_preview(wrpv, offset=0, length=32)
    assert out["ok"]
    assert "WRPV" in out["preview"]
    # Reject out-of-range offsets cleanly.
    bad = gputrace.wrpv_table_preview(wrpv, offset=10_000_000, length=32)
    assert not bad["ok"]


def test_wrpv_shader_binding_search_composes(tmp_path: Path) -> None:
    wrpv = _synth_wrpv(tmp_path)
    out = gputrace.wrpv_shader_binding_search(
        wrpv,
        shader_names=["CopyRectPS"],
        pdb_names=["aab95ca751a813819972cc044ba1d07b.pdb"],
        dxbc_hashes_hex=["DEADBEEFCAFEBABE"],
    )
    assert out["ok"]
    # Shader name hit via ASCII.
    assert out["hits"]["CopyRectPS"]
    # Hex hash hit via raw bytes.
    assert out["hits"]["<hex:deadbeefcafebabe>"]
    # PDB name hit via ASCII.
    assert out["hits"]["aab95ca751a813819972cc044ba1d07b.pdb"]


def test_wrpv_shader_binding_search_requires_needles(tmp_path: Path) -> None:
    wrpv = _synth_wrpv(tmp_path)
    out = gputrace.wrpv_shader_binding_search(wrpv)
    assert not out["ok"]
