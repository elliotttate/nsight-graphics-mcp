"""Tests for pso_resolver against synthetic D3D12 + Vulkan C++ that mimics
Nsight's Generate-C++-Capture emit style."""

from __future__ import annotations

import hashlib
import textwrap
from pathlib import Path

from nsight_graphics_mcp import pso_resolver


# DXBC blob: magic "DXBC", then a 16-byte hash, then a few padding bytes.
# Each entry is `0xNN, ` to mirror Nsight's emit. The 16-byte hash here is
# all-ones (0xAA) so it's easy to assert.
def _dxbc_array(name: str, hash_byte: int) -> str:
    head = (
        ["0x44", "0x58", "0x42", "0x43"]              # DXBC magic
        + [f"0x{hash_byte:02X}"] * 16                  # hash
        + ["0x01", "0x00", "0x00", "0x00"]             # version
        + ["0x00"] * 8                                 # filler
    )
    return f"static const unsigned char {name}[] = {{ {', '.join(head)} }};\n"


def _spirv_array(name: str) -> str:
    # SPIR-V magic 0x07230203 → little-endian: 03 02 23 07
    body = ["0x03", "0x02", "0x23", "0x07"] + ["0x00"] * 16
    return f"static const uint8_t {name}[] = {{ {', '.join(body)} }};\n"


D3D12_SAMPLE = (
    _dxbc_array("g_VS_dxbc_aaa", 0xAA)
    + _dxbc_array("g_PS_dxbc_bbb", 0xBB)
    + _dxbc_array("g_CS_dxbc_ccc", 0xCC)
    + textwrap.dedent("""\
        void CreateGraphicsPSO_0(ID3D12Device* device) {
            D3D12_GRAPHICS_PIPELINE_STATE_DESC psoDesc = {};
            psoDesc.VS = { g_VS_dxbc_aaa, sizeof(g_VS_dxbc_aaa) };
            psoDesc.PS = { g_PS_dxbc_bbb, sizeof(g_PS_dxbc_bbb) };
            device->CreateGraphicsPipelineState(&psoDesc, IID_PPV_ARGS(&g_PSO_0));
        }

        void CreateComputePSO_1(ID3D12Device* device) {
            D3D12_COMPUTE_PIPELINE_STATE_DESC psoDesc = {};
            psoDesc.CS = { g_CS_dxbc_ccc, sizeof(g_CS_dxbc_ccc) };
            device->CreateComputePipelineState(&psoDesc, IID_PPV_ARGS(&g_PSO_1));
        }
    """)
)

VK_SAMPLE = (
    _spirv_array("g_VS_spirv_111")
    + _spirv_array("g_FS_spirv_222")
    + textwrap.dedent("""\
        void CreateGraphicsPipeline_Vk(VkDevice device) {
            VkShaderModuleCreateInfo vsInfo = { .codeSize = sizeof(g_VS_spirv_111),
                                                .pCode = (uint32_t*)g_VS_spirv_111 };
            vkCreateShaderModule(device, &vsInfo, nullptr, &g_ShaderModule_10);
            VkShaderModuleCreateInfo fsInfo = { .codeSize = sizeof(g_FS_spirv_222),
                                                .pCode = (uint32_t*)g_FS_spirv_222 };
            vkCreateShaderModule(device, &fsInfo, nullptr, &g_ShaderModule_11);

            VkPipelineShaderStageCreateInfo stages[2] = {};
            stages[0].stage = VK_SHADER_STAGE_VERTEX_BIT;
            stages[0].module = g_ShaderModule_10;
            stages[1].stage = VK_SHADER_STAGE_FRAGMENT_BIT;
            stages[1].module = g_ShaderModule_11;

            VkGraphicsPipelineCreateInfo info = {};
            info.stageCount = 2;
            info.pStages = stages;
            vkCreateGraphicsPipelines(device, VK_NULL_HANDLE, 1, &info, nullptr, &g_Pipeline_0);
        }
    """)
)


def _make_proj(tmp_path: Path) -> Path:
    proj = tmp_path / "GeneratedCpp"
    proj.mkdir()
    (proj / "d3d12.cpp").write_text(D3D12_SAMPLE, encoding="utf-8")
    (proj / "vulkan.cpp").write_text(VK_SAMPLE, encoding="utf-8")
    return proj


def test_extracts_dxbc_hash_from_emitted_array(tmp_path: Path) -> None:
    proj = _make_proj(tmp_path)
    summary = pso_resolver.index_project_psos(proj)
    assert summary["ok"]
    db = Path(summary["db_path"])
    blobs = pso_resolver.list_shader_blobs(db, format="dxbc")
    by_sym = {b["symbol"]: b for b in blobs}
    assert "g_VS_dxbc_aaa" in by_sym
    # 16 bytes of 0xAA → "aa" * 16
    assert by_sym["g_VS_dxbc_aaa"]["hash_hex"] == "aa" * 16
    assert by_sym["g_VS_dxbc_aaa"]["hash_source"] == "dxbc-builtin"
    assert by_sym["g_PS_dxbc_bbb"]["hash_hex"] == "bb" * 16
    assert by_sym["g_CS_dxbc_ccc"]["hash_hex"] == "cc" * 16


def test_extracts_spirv_sha1_from_emitted_array(tmp_path: Path) -> None:
    proj = _make_proj(tmp_path)
    summary = pso_resolver.index_project_psos(proj)
    db = Path(summary["db_path"])
    blobs = pso_resolver.list_shader_blobs(db, format="spirv")
    assert len(blobs) == 2
    # Sanity: hashes look like sha1
    for b in blobs:
        assert b["hash_source"] == "sha1-of-blob"
        assert len(b["hash_hex"]) == 40


def test_d3d12_pso_links_to_correct_shaders(tmp_path: Path) -> None:
    proj = _make_proj(tmp_path)
    summary = pso_resolver.index_project_psos(proj)
    db = Path(summary["db_path"])
    rec = pso_resolver.get_pso(db, "g_PSO_0")
    assert rec is not None
    assert rec["api"] == "d3d12"
    assert "VS" in rec["stages"] and "PS" in rec["stages"]
    assert rec["stages"]["VS"]["shader_symbol"] == "g_VS_dxbc_aaa"
    assert rec["stages"]["VS"]["hash_hex"] == "aa" * 16
    assert rec["stages"]["PS"]["shader_symbol"] == "g_PS_dxbc_bbb"

    cpso = pso_resolver.get_pso(db, "g_PSO_1")
    assert cpso is not None
    assert "CS" in cpso["stages"]
    assert cpso["stages"]["CS"]["shader_symbol"] == "g_CS_dxbc_ccc"
    assert cpso["stages"]["CS"]["hash_hex"] == "cc" * 16


def test_vulkan_pso_links_modules_to_stage_flags(tmp_path: Path) -> None:
    proj = _make_proj(tmp_path)
    summary = pso_resolver.index_project_psos(proj)
    db = Path(summary["db_path"])
    rec = pso_resolver.get_pso(db, "g_Pipeline_0")
    assert rec is not None
    assert rec["api"] == "vulkan"
    # VS → g_ShaderModule_10, PS (FRAGMENT) → g_ShaderModule_11
    assert rec["stages"].get("VS", {}).get("shader_symbol") == "g_ShaderModule_10"
    assert rec["stages"].get("PS", {}).get("shader_symbol") == "g_ShaderModule_11"


def test_reverse_lookup_by_hash(tmp_path: Path) -> None:
    proj = _make_proj(tmp_path)
    summary = pso_resolver.index_project_psos(proj)
    db = Path(summary["db_path"])
    hits = pso_resolver.find_psos_using_shader(db, hash_hex="aa" * 16)
    assert len(hits) == 1
    assert hits[0]["pso_symbol"] == "g_PSO_0"
    assert hits[0]["stage"] == "VS"


def test_list_psos_groups_by_pso(tmp_path: Path) -> None:
    proj = _make_proj(tmp_path)
    summary = pso_resolver.index_project_psos(proj)
    db = Path(summary["db_path"])
    rows = pso_resolver.list_psos(db)
    psos = {r["pso_symbol"]: r for r in rows}
    assert "g_PSO_0" in psos and "g_PSO_1" in psos and "g_Pipeline_0" in psos
    assert "VS:g_VS_dxbc_aaa" in psos["g_PSO_0"]["stage_summary"]
    assert "PS:g_PS_dxbc_bbb" in psos["g_PSO_0"]["stage_summary"]


def test_summary_counts_are_correct(tmp_path: Path) -> None:
    proj = _make_proj(tmp_path)
    summary = pso_resolver.index_project_psos(proj)
    assert summary["shader_blob_count"] == 5  # 3 DXBC + 2 SPIR-V
    assert summary["pso_count"] == 3
    assert summary["shader_format_histogram"] == {"dxbc": 3, "spirv": 2}
