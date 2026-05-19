"""Tests for frame_costs against synthetic perf-report CSVs.

We can't rely on a real ``.nsight-gputrace`` being available in CI, so
build the CSV outputs by hand mimicking what ``ngfx-replay
--perf-report-dir`` writes.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from nsight_graphics_mcp import frame_costs


ACTIONS_CSV = textwrap.dedent(
    """\
    event_index,name,kind,gpu_time_ns
    0,vkCmdBindPipeline,set_state,12000
    1,vkCmdDraw,draw,450000
    2,vkCmdDraw,draw,120000
    3,vkCmdDispatch,dispatch,860000
    4,vkCmdCopyBuffer,copy,32000
    5,vkCmdDraw,draw,18000
    """
)

RANGES_CSV_MS = textwrap.dedent(
    """\
    range_index,range_name,duration_ms
    0,FrameStart,1.5
    1,GBuffer,4.25
    2,Lighting,7.1
    3,Postprocess,2.3
    """
)


def _build_perf_dir(tmp: Path) -> Path:
    d = tmp / "perf_report"
    d.mkdir()
    (d / "actions.csv").write_text(ACTIONS_CSV, encoding="utf-8")
    (d / "ranges.csv").write_text(RANGES_CSV_MS, encoding="utf-8")
    return d


def test_top_n_ranks_across_csvs_with_unit_conversion(tmp_path: Path) -> None:
    """Cross-CSV ranking respects unit conversion: Lighting (7.1ms) beats
    vkCmdDispatch (860,000ns) even though both come from different CSVs."""
    d = _build_perf_dir(tmp_path)
    out = frame_costs.top_n_costs(d, n=5)
    assert out["ok"]
    top = out["top"]
    names = [r["name"] for r in top]
    # ranges.csv is in milliseconds: Lighting 7.1ms = 7_100_000ns dominates.
    assert names[0] == "Lighting"
    assert names[1] == "GBuffer"          # 4.25ms = 4_250_000ns
    assert names[2] == "Postprocess"      # 2.3ms = 2_300_000ns
    assert names[3] == "FrameStart"       # 1.5ms = 1_500_000ns
    assert names[4] == "vkCmdDispatch"    # 860_000ns — top of actions.csv


def test_top_n_kind_filter(tmp_path: Path) -> None:
    d = _build_perf_dir(tmp_path)
    out = frame_costs.top_n_costs(d, n=10, kind_filter="draw")
    assert out["ok"]
    for row in out["top"]:
        assert "draw" in (row["kind"].lower() + row["name"].lower())
    # 3 vkCmdDraw entries
    assert len(out["top"]) == 3


def test_top_n_name_regex(tmp_path: Path) -> None:
    d = _build_perf_dir(tmp_path)
    out = frame_costs.top_n_costs(d, n=10, name_regex="^vkCmd")
    assert out["ok"]
    for row in out["top"]:
        assert row["name"].startswith("vkCmd")


def test_top_n_handles_unit_conversion_ms_to_ns(tmp_path: Path) -> None:
    d = tmp_path / "p2"
    d.mkdir()
    (d / "ranges.csv").write_text(RANGES_CSV_MS, encoding="utf-8")
    out = frame_costs.top_n_costs(d, n=1)
    assert out["ok"]
    # Lighting was 7.1 ms → 7_100_000 ns
    assert out["top"][0]["name"] == "Lighting"
    assert out["top"][0]["gpu_time_ns"] == 7_100_000


def test_top_n_no_csv_returns_clean_error(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    out = frame_costs.top_n_costs(empty, n=10)
    assert not out["ok"]
    assert "no CSVs" in out["error"]
