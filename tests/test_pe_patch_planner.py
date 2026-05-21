from __future__ import annotations

from pathlib import Path

from nsight_graphics_mcp import pe_patch_planner


def test_build_patch_plan_includes_known_sites(tmp_path: Path) -> None:
    fake_exe = tmp_path / "ngfx-rpc.exe"
    fake_exe.write_bytes(b"MZ" + b"\x00" * 64)
    plan = pe_patch_planner.build_patch_plan(fake_exe)
    assert plan["ok"]
    assert plan["evidence_label"] == "candidate"
    assert "PLAN ONLY" in plan["warning"]
    symbols = [s["symbol"] for s in plan["patch_sites"]]
    assert "payload_write__sub_1409A4470" in symbols
    assert "read_header__sub_1409A3D40" in symbols
    assert "hdr_serialize__sub_140985580" in symbols
    # The trampoline template carries every marker we'll need to patch.
    hex_blob = plan["trampoline_template_hex"]
    assert "11cc11cc" in hex_blob.lower()
    assert "22cc22cc" in hex_blob.lower()
    assert "55cc55cc" in hex_blob.lower()


def test_build_patch_plan_filters_by_site(tmp_path: Path) -> None:
    fake_exe = tmp_path / "ngfx-rpc.exe"
    fake_exe.write_bytes(b"MZ")
    plan = pe_patch_planner.build_patch_plan(
        fake_exe, sites=["read_header__sub_1409A3D40"]
    )
    assert plan["ok"]
    symbols = [s["symbol"] for s in plan["patch_sites"]]
    assert symbols == ["read_header__sub_1409A3D40"]


def test_generate_ida_script_writes_file(tmp_path: Path) -> None:
    fake_exe = tmp_path / "ngfx-rpc.exe"
    fake_exe.write_bytes(b"MZ")
    out = tmp_path / "patch_ngfx_rpc.py"
    res = pe_patch_planner.generate_ida_script(fake_exe, out)
    assert res["ok"]
    assert out.is_file()
    script_text = out.read_text(encoding="utf-8")
    assert "TARGET_EXE" in script_text
    assert "TRAMPOLINE_TEMPLATE" in script_text
    assert str(fake_exe) in script_text
