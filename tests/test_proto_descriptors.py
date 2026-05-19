"""Smoke tests for proto_descriptors: extract real FileDescriptorProtos
from the installed Nsight binary and verify the schema pool is well-formed.

Skipped if Nsight Graphics isn't installed locally.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nsight_graphics_mcp import proto_descriptors as pd
from nsight_graphics_mcp.config import host_bin_dir


def _ngfx_replay() -> Path | None:
    bd = host_bin_dir()
    if bd is None:
        return None
    p = bd / "ngfx-replay.exe"
    return p if p.is_file() else None


REPLAY = _ngfx_replay()
needs_install = pytest.mark.skipif(REPLAY is None, reason="Nsight Graphics not installed")


@needs_install
def test_extract_descriptors_finds_all_22_protos() -> None:
    summaries, files = pd.extract_descriptors(REPLAY)
    assert len(summaries) >= 20  # 22 expected; allow 2 of slack if formats change
    assert any(s.proto_file.endswith("EventParameters.proto") for s in summaries)
    assert any(s.proto_file.endswith("Objects.proto") for s in summaries)


@needs_install
def test_registry_pool_contains_pb_function_call_desc() -> None:
    reg = pd.build_registry(REPLAY)
    msgs = reg.list_messages()
    assert "NV.EventParameters.Messages.PbFunctionCallDesc" in msgs
    assert "NV.EventParameters.Messages.PbArgument" in msgs


@needs_install
def test_describe_pb_function_call_desc_has_arguments_field() -> None:
    reg = pd.build_registry(REPLAY)
    d = reg.describe("NV.EventParameters.Messages.PbFunctionCallDesc")
    field_names = {f["name"] for f in d["fields"]}
    assert "functionName" in field_names
    assert "arguments" in field_names
    # 'arguments' is a repeated PbArgument
    arg_field = next(f for f in d["fields"] if f["name"] == "arguments")
    assert arg_field["is_message"] is True
    assert arg_field["type_name"] == "NV.EventParameters.Messages.PbArgument"
    assert arg_field["is_repeated"] is True


@needs_install
def test_message_class_can_be_instantiated() -> None:
    reg = pd.build_registry(REPLAY)
    cls = reg.message_class("NV.EventParameters.Messages.PbFunctionCallDesc")
    inst = cls()
    inst.functionName = "vkCmdDraw"
    blob = inst.SerializeToString()
    # round-trip
    inst2 = cls.FromString(blob)
    assert inst2.functionName == "vkCmdDraw"
