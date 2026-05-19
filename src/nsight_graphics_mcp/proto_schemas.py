"""Protobuf schema extraction + reference.

Reverse-engineered from ``ngfx-replay.exe`` and friends: the capture file
format is **protobuf-serialized**, using messages in the ``NV.*`` namespace
across several ``.proto`` files referenced in the binary. This module
extracts message names + their source .proto filenames so the MCP can
answer "what's the schema for a captured pipeline / shader / descriptor?"
without needing to recompile protoc against the headers.

The schema fragments inside the binary are real ``FileDescriptorProto``
encodings. We can pull out at minimum:

  * the list of ``.proto`` files referenced,
  * the list of message names per file,
  * the cross-references (which messages reference which other messages).

A future pass could attempt full ``.proto`` reconstruction with
``proto_pb`` / `protobuf-inspector`, but the above is already enough for
the LLM to navigate the capture format conceptually.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Settings, get_settings, host_bin_dir


# Strings of the form  \n  LEN  ProtoFileName  where LEN < 0x80 and the name
# ends in ".proto". This is the field-1 (string) of a FileDescriptorProto.
PROTO_FILENAME_RE = re.compile(
    rb"\x0a(?P<len>[\x01-\x7f])(?P<name>[\x20-\x7e]{1,128}\.proto)"
)

# Strings of the form ``.NV.<segment>(.<segment>)*<terminator>`` where each
# segment is a CamelCase identifier (typical FQN of a protobuf type).
PROTO_TYPE_FQN_RE = re.compile(rb"\.NV(?:\.[A-Za-z_][A-Za-z0-9_]*){1,8}")

# Strings of the form ``\n LEN Pb...`` (a message name inside DescriptorProto).
# Field 1 of DescriptorProto is the name (string), so its wire prefix is
# 0x0a 0x?? then the name. Most messages start with "Pb".
PROTO_MESSAGE_NAME_RE = re.compile(
    rb"\x0a(?P<len>[\x01-\x7f])(?P<name>Pb[A-Z][A-Za-z0-9_]{1,80})"
)


@dataclass
class ProtoSchemaInventory:
    binary_path: Path
    proto_files: list[str]
    type_fqns: list[str]
    message_names: list[str]
    by_namespace: dict[str, list[str]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary_path": str(self.binary_path),
            "proto_files": self.proto_files,
            "proto_file_count": len(self.proto_files),
            "type_fqns": self.type_fqns,
            "type_fqn_count": len(self.type_fqns),
            "message_names": self.message_names,
            "message_count": len(self.message_names),
            "by_namespace": self.by_namespace,
            "namespace_count": len(self.by_namespace),
        }


def extract_inventory(binary_path: Path) -> ProtoSchemaInventory:
    """Scan a binary for protobuf descriptor fragments."""
    data = binary_path.read_bytes()

    proto_files = sorted(
        {
            m.group("name").decode("ascii", errors="replace")
            for m in PROTO_FILENAME_RE.finditer(data)
            if int(m.group("len")[0]) == len(m.group("name"))
        }
    )
    type_fqns_raw = sorted(
        {
            m.group(0).decode("ascii", errors="replace").rstrip(".")
            for m in PROTO_TYPE_FQN_RE.finditer(data)
        }
    )
    # Filter to plausible FQNs (each non-empty part must start with a letter).
    # FQNs start with a leading "." (proto absolute form), so split() yields a
    # leading empty element we ignore.
    type_fqns = []
    for fqn in type_fqns_raw:
        parts = [p for p in fqn.split(".") if p]
        if parts and all(p[0].isalpha() or p[0] == "_" for p in parts):
            type_fqns.append(fqn)

    message_names = sorted(
        {
            m.group("name").decode("ascii", errors="replace")
            for m in PROTO_MESSAGE_NAME_RE.finditer(data)
            if int(m.group("len")[0]) == len(m.group("name"))
        }
    )

    by_namespace: dict[str, list[str]] = {}
    for fqn in type_fqns:
        ns, _sep, tail = fqn.rpartition(".")
        by_namespace.setdefault(ns, []).append(tail)
    for ns in by_namespace:
        by_namespace[ns] = sorted(set(by_namespace[ns]))

    return ProtoSchemaInventory(
        binary_path=binary_path,
        proto_files=proto_files,
        type_fqns=type_fqns,
        message_names=message_names,
        by_namespace=by_namespace,
    )


def default_target_binaries(settings: Settings | None = None) -> list[Path]:
    """Binaries worth scanning for protobuf fragments."""
    s = settings or get_settings()
    bin_dir = host_bin_dir(s.install_root)
    if bin_dir is None:
        return []
    candidates = [
        bin_dir / "ngfx-replay.exe",
        bin_dir / "ngfx-capture.exe",
        bin_dir / "PylonReplay_PluginInterface.dll",
        bin_dir / "Nvda.Graphics.FrameDebugger.Native.dll",
    ]
    return [p for p in candidates if p.is_file()]


def scan_default_binaries(settings: Settings | None = None) -> dict[str, Any]:
    """Run schema extraction over every default Nsight binary we have."""
    out: dict[str, Any] = {"binaries": []}
    combined_files: set[str] = set()
    combined_messages: set[str] = set()
    combined_fqns: set[str] = set()
    for p in default_target_binaries(settings):
        try:
            inv = extract_inventory(p)
        except OSError as exc:
            out["binaries"].append({"path": str(p), "error": str(exc)})
            continue
        out["binaries"].append(inv.to_dict())
        combined_files.update(inv.proto_files)
        combined_messages.update(inv.message_names)
        combined_fqns.update(inv.type_fqns)
    out["aggregate"] = {
        "proto_file_count": len(combined_files),
        "proto_files": sorted(combined_files),
        "message_count": len(combined_messages),
        "message_names": sorted(combined_messages),
        "type_fqn_count": len(combined_fqns),
    }
    return out


def search_schemas(
    pattern: str, *, settings: Settings | None = None, limit: int = 200
) -> dict[str, Any]:
    """Search the extracted protobuf inventory by regex.

    Looks across proto filenames, message names, and FQNs.
    """
    try:
        rx = re.compile(pattern)
    except re.error as exc:
        return {"ok": False, "error": str(exc)}
    hits: list[dict[str, Any]] = []
    for p in default_target_binaries(settings):
        try:
            inv = extract_inventory(p)
        except OSError:
            continue
        for name in inv.proto_files:
            if rx.search(name):
                hits.append({"binary": p.name, "kind": "proto_file", "name": name})
                if len(hits) >= limit:
                    break
        for name in inv.message_names:
            if rx.search(name):
                hits.append({"binary": p.name, "kind": "message", "name": name})
                if len(hits) >= limit:
                    break
        for fqn in inv.type_fqns:
            if rx.search(fqn):
                hits.append({"binary": p.name, "kind": "fqn", "name": fqn})
                if len(hits) >= limit:
                    break
        if len(hits) >= limit:
            break
    return {"ok": True, "pattern": pattern, "hits": hits, "truncated": len(hits) >= limit}
