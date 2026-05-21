from __future__ import annotations

from pathlib import Path

from nsight_graphics_mcp import etw_capture


def test_etw_environment_returns_logman_and_tracerpt_paths() -> None:
    info = etw_capture.etw_environment()
    assert info["ok"]
    # logman/tracerpt may be None on non-Windows; the field must always exist.
    assert "logman" in info
    assert "tracerpt" in info
    assert info["kernel_file_provider"].startswith("{")


def test_etw_capture_start_dry_run_builds_command(tmp_path: Path) -> None:
    out = etw_capture.etw_capture_start(
        "session_x",
        tmp_path / "x.etl",
        dry_run=True,
    )
    assert out["ok"] and out["dry_run"]
    assert out["session_name"] == "session_x"
    cmd = out["command"]
    assert "logman" in cmd[0].lower()
    assert "create" in cmd and "trace" in cmd
    # Both providers should be on the command line.
    assert etw_capture.KERNEL_FILE_GUID in cmd
    assert etw_capture.KERNEL_PROCESS_GUID in cmd


def test_etw_capture_stop_dry_run() -> None:
    out = etw_capture.etw_capture_stop("session_x", dry_run=True)
    assert out["ok"] and out["dry_run"]
    assert "stop" in out["command"]
    assert "session_x" in out["command"]


def test_etw_capture_summary_dry_run(tmp_path: Path) -> None:
    out = etw_capture.etw_capture_summary(
        tmp_path / "fake.etl",
        dry_run=True,
    )
    assert out["ok"] and out["dry_run"]
    assert "-of" in out["xml_command"]
    assert "XML" in out["xml_command"]
    assert "-of" in out["csv_command"]
    assert "CSV" in out["csv_command"]
