"""Tests for pso_resolver against synthetic D3D12 + Vulkan C++ that mimics
Nsight's Generate-C++-Capture emit style."""

from __future__ import annotations

import textwrap
import zlib
from pathlib import Path

from nsight_graphics_mcp import pso_resolver


# DXBC blob: magic "DXBC", then a 16-byte hash, then a few padding bytes.
# Each entry is `0xNN, ` to mirror Nsight's emit. The 16-byte hash here is
# all-ones (0xAA) so it's easy to assert.
def _crc_hex(data: bytes) -> str:
    return f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"


def _bytes_to_array(name: str, data: bytes, c_type: str = "unsigned char") -> str:
    body = ", ".join(f"0x{b:02X}" for b in data)
    return f"static const {c_type} {name}[] = {{ {body} }};\n"


def _dxbc_bytes(hash_byte: int) -> bytes:
    return bytes(
        [0x44, 0x58, 0x42, 0x43]        # DXBC magic
        + [hash_byte] * 16              # hash
        + [0x01, 0x00, 0x00, 0x00]      # version
        + [0x00] * 8                    # filler
    )


def _dxbc_array(name: str, hash_byte: int) -> str:
    return _bytes_to_array(name, _dxbc_bytes(hash_byte))


def _spirv_bytes() -> bytes:
    # SPIR-V magic 0x07230203 → little-endian: 03 02 23 07
    return bytes([0x03, 0x02, 0x23, 0x07] + [0x00] * 16)


def _spirv_array(name: str) -> str:
    return _bytes_to_array(name, _spirv_bytes(), c_type="uint8_t")


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
    assert by_sym["g_VS_dxbc_aaa"]["shader_toggler_crc32"] == _crc_hex(_dxbc_bytes(0xAA))
    assert by_sym["g_VS_dxbc_aaa"]["shader_toggler_crc32_decimal"] == int(_crc_hex(_dxbc_bytes(0xAA)), 16)
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


def test_reverse_lookup_by_shader_toggler_crc32(tmp_path: Path) -> None:
    proj = _make_proj(tmp_path)
    summary = pso_resolver.index_project_psos(proj)
    db = Path(summary["db_path"])
    hits = pso_resolver.find_psos_using_shader(
        db,
        shader_toggler_crc32=_crc_hex(_dxbc_bytes(0xBB)),
    )
    assert len(hits) == 1
    assert hits[0]["pso_symbol"] == "g_PSO_0"
    assert hits[0]["stage"] == "PS"


def test_find_shader_blob_by_shader_toggler_decimal(tmp_path: Path) -> None:
    proj = _make_proj(tmp_path)
    summary = pso_resolver.index_project_psos(proj)
    db = Path(summary["db_path"])
    crc = _crc_hex(_dxbc_bytes(0xCC))
    blobs = pso_resolver.find_shader_blobs_by_shader_toggler_crc32(
        db,
        crc32_decimal=int(crc, 16),
    )
    assert len(blobs) == 1
    assert blobs[0]["symbol"] == "g_CS_dxbc_ccc"
    assert blobs[0]["pso_references"][0]["pso_symbol"] == "g_PSO_1"


def test_dump_shader_blob_by_shader_toggler_crc32(tmp_path: Path) -> None:
    proj = _make_proj(tmp_path)
    summary = pso_resolver.index_project_psos(proj)
    db = Path(summary["db_path"])
    out = tmp_path / "dumped.dxbc"
    result = pso_resolver.dump_shader_blob(
        db,
        out,
        crc32_hex=_crc_hex(_dxbc_bytes(0xBB)),
    )
    assert result["ok"]
    assert result["shader_symbol"] == "g_PS_dxbc_bbb"
    assert result["bytes_written"] == len(_dxbc_bytes(0xBB))
    assert out.read_bytes() == _dxbc_bytes(0xBB)


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


# ---------------------------------------------------------------------------
# DXBC / RDEF reflection
# ---------------------------------------------------------------------------


def _build_synthetic_dxbc_with_rdef(
    bindings: list[dict],
    *,
    rd11: bool = False,
) -> bytes:
    """Build a synthetic DXBC container containing exactly one RDEF chunk
    with the given resource bindings.

    Each binding dict: ``{"name": str, "input_type": int, "register": int,
    "register_space": int, "bind_count": int}``.
    """
    import struct

    # ---- Build RDEF chunk body ----
    binding_stride = 40 if rd11 else 32
    body = bytearray()

    # base header is 28 bytes
    base_header_size = 28
    rb_offset = base_header_size
    rb_size = len(bindings) * binding_stride
    # Names live after the bindings table.
    names_off = rb_offset + rb_size
    name_blob = bytearray()
    name_offsets: list[int] = []
    for b in bindings:
        name_offsets.append(names_off + len(name_blob))
        name_blob += b["name"].encode("ascii") + b"\x00"

    # base header
    body += struct.pack(
        "<IIIIIII",
        0,                      # constant_buffers_count
        0,                      # constant_buffers_offset
        len(bindings),          # resource_bindings_count
        rb_offset,              # resource_bindings_offset
        0xFFFE0500,             # shader_version (PS 5.0 just as a placeholder)
        0,                      # flags
        0,                      # creator_offset
    )
    assert len(body) == base_header_size

    # bindings
    for b, name_off in zip(bindings, name_offsets, strict=False):
        body += struct.pack(
            "<IIIIIIII",
            name_off,
            b["input_type"],
            0,                  # return_type
            0,                  # dimension
            0,                  # sample_count
            b["register"],
            b["bind_count"],
            0,                  # flags
        )
        if rd11:
            body += struct.pack("<II", b["register_space"], b.get("resource_id", 0))

    body += name_blob

    # ---- Build the DXBC container around the RDEF chunk ----
    rdef_chunk_header_size = 8
    rdef_chunk_total = rdef_chunk_header_size + len(body)
    container_header_size = 32   # magic(4) + hash(16) + version(4) + total(4) + count(4)
    chunk_index_size = 4         # one chunk → one offset
    rdef_chunk_offset = container_header_size + chunk_index_size

    container = bytearray()
    container += b"DXBC"
    container += b"\x00" * 16
    container += struct.pack("<III", 1, 0, 1)  # version, total_size (patched), chunk_count
    container += struct.pack("<I", rdef_chunk_offset)
    container += b"RDEF" + struct.pack("<I", len(body))
    container += body
    # Patch total_size at offset 24 (version=20..23, total=24..27, count=28..31).
    struct.pack_into("<I", container, 24, len(container))
    return bytes(container)


def test_parse_dxbc_container_lists_chunks() -> None:
    blob = _build_synthetic_dxbc_with_rdef(
        [{"name": "diffuse", "input_type": 2, "register": 0, "register_space": 0, "bind_count": 1}]
    )
    out = pso_resolver.parse_dxbc_container(blob)
    assert out["ok"]
    assert out["magic"] == "DXBC"
    assert out["chunk_count"] == 1
    assert out["chunks"][0]["fourcc"] == "RDEF"


def test_shader_reflection_bindings_decodes_register_names() -> None:
    bindings = [
        {"name": "diffuse_tex", "input_type": 2, "register": 0, "register_space": 0, "bind_count": 1},
        {"name": "linear_sampler", "input_type": 3, "register": 0, "register_space": 0, "bind_count": 1},
        {"name": "constants", "input_type": 0, "register": 1, "register_space": 0, "bind_count": 1},
    ]
    blob = _build_synthetic_dxbc_with_rdef(bindings)
    out = pso_resolver.shader_reflection_bindings(blob)
    assert out["ok"]
    assert out["rdef"]["resource_bindings_count"] == 3
    by_name = {b["name"]: b for b in out["bindings"]}
    assert by_name["diffuse_tex"]["register"] == "t0"
    assert by_name["diffuse_tex"]["register_class"] == "SRV"
    assert by_name["linear_sampler"]["register"] == "s0"
    assert by_name["linear_sampler"]["register_class"] == "SAMPLER"
    assert by_name["constants"]["register"] == "b1"
    assert by_name["constants"]["register_class"] == "CBV"


def test_shader_reflection_bindings_rejects_non_dxbc() -> None:
    out = pso_resolver.shader_reflection_bindings(b"NOPE" + b"\x00" * 100)
    assert not out["ok"]
    assert "magic" in out["error"].lower()
