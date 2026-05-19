"""Extract full FileDescriptorProto blobs from Nsight binaries.

The existing :mod:`proto_schemas` module pulls out proto filenames and
message names by regex — fast, but it loses the field-level schema. This
module goes further: it finds each ``FileDescriptorProto`` blob embedded
in the binary's read-only data, then decodes it with the standard
``google.protobuf.descriptor_pb2`` so we recover the *full* schema —
fields, types, nested messages, enums, options.

How
---
1. Scan for the wire-format signature of a FileDescriptorProto::

       0x0a  LEN  "<name>.proto"

   This is field 1 (``name``) of FileDescriptorProto encoded as a
   length-delimited string. ``LEN`` is a single varint byte for any name
   shorter than 128 chars (every .proto filename Nsight uses fits).

2. Starting at each candidate offset, walk the protobuf wire format
   byte by byte. A FileDescriptorProto consists only of length-delimited
   (wire type 2) and varint (wire type 0) fields, so the walk terminates
   cleanly the moment we hit a byte that can't be a valid tag.

3. Try ``FileDescriptorProto.FromString`` on each ``[start, end)`` slice.
   If it parses AND its ``name`` field matches the embedded filename, we
   have a real descriptor.

4. All recovered descriptors are loaded into a single
   ``google.protobuf.descriptor_pool.DescriptorPool`` from which we can
   look up any message by FQN and dynamically build instances.

If the wire-walk over-runs (some byte sequences happen to look valid for
~MB before hitting a bad tag), we cap the trial size at 4 MiB. Real
Nsight .proto files are well under 200 KB.
"""

from __future__ import annotations

import re
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

from .config import Settings, get_settings, host_bin_dir


_FILENAME_RE = re.compile(
    rb"\x0a(?P<len>[\x01-\x7f])(?P<name>[\x20-\x7e]{1,128}\.proto)"
)
MAX_DESCRIPTOR_SIZE = 4 * 1024 * 1024  # 4 MiB cap


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Return ``(value, bytes_consumed)`` or ``(0, 0)`` on malformed input."""
    shift = 0
    value = 0
    n = 0
    while pos + n < len(data) and n < 10:
        b = data[pos + n]
        value |= (b & 0x7F) << shift
        n += 1
        if not (b & 0x80):
            return value, n
        shift += 7
    return 0, 0


def _walk_message(data: bytes, start: int, cap: int) -> int:
    """Walk wire-format fields starting at ``start`` for up to ``cap`` bytes.
    Returns the absolute end offset (or ``start`` if the very first byte is
    not a valid tag)."""
    pos = start
    end_cap = min(len(data), start + cap)
    while pos < end_cap:
        tag, n = _read_varint(data, pos)
        if n == 0:
            return pos
        wire = tag & 0x07
        field = tag >> 3
        # valid protobuf wire types are {0,1,2,5}; field number > 0
        if field == 0 or wire not in (0, 1, 2, 5):
            return pos
        pos += n
        if pos > end_cap:
            return start  # malformed
        if wire == 0:  # varint
            _, n2 = _read_varint(data, pos)
            if n2 == 0:
                return pos
            pos += n2
        elif wire == 1:  # 64-bit
            pos += 8
        elif wire == 5:  # 32-bit
            pos += 4
        else:  # wire == 2, length-delimited
            length, n2 = _read_varint(data, pos)
            if n2 == 0:
                return pos
            pos += n2 + length
        if pos > end_cap:
            return start  # ran past cap → reject
    return pos


@dataclass
class ExtractedDescriptor:
    proto_file: str
    binary_offset: int
    blob_size: int
    package: str
    message_names: list[str]
    enum_names: list[str]
    dependencies: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "proto_file": self.proto_file,
            "binary_offset": self.binary_offset,
            "blob_size": self.blob_size,
            "package": self.package,
            "message_count": len(self.message_names),
            "messages": self.message_names,
            "enum_count": len(self.enum_names),
            "enums": self.enum_names,
            "dependencies": self.dependencies,
        }


def extract_descriptors(binary_path: Path) -> tuple[
    list[ExtractedDescriptor], dict[str, descriptor_pb2.FileDescriptorProto]
]:
    """Extract every FileDescriptorProto we can find in ``binary_path``.

    Returns ``(summaries, by_name)`` where ``by_name`` is keyed by the
    .proto filename and holds the raw FileDescriptorProto messages.
    """
    data = binary_path.read_bytes()
    summaries: list[ExtractedDescriptor] = []
    by_name: dict[str, descriptor_pb2.FileDescriptorProto] = {}

    for m in _FILENAME_RE.finditer(data):
        expected_name = m.group("name").decode("ascii", errors="replace")
        if int(m.group("len")[0]) != len(m.group("name")):
            continue
        offset = m.start()
        end = _walk_message(data, offset, MAX_DESCRIPTOR_SIZE)
        if end <= offset + 4:
            continue
        blob = data[offset:end]
        # Try the natural end first; if it doesn't decode, retry by
        # shrinking. Some descriptors are followed by other rdata that
        # happens to fit a partial protobuf tag — the walker over-runs.
        # Binary-search the largest end that parses AND has matching name.
        attempts = [end]
        # also try a few smaller boundaries — bisect by halving the
        # remainder once if needed
        if end - offset > 64:
            attempts.append(offset + (end - offset) // 2)
        decoded: descriptor_pb2.FileDescriptorProto | None = None
        chosen_blob: bytes | None = None
        # First try the walker's natural end — this is correct for the
        # vast majority of descriptors. If it doesn't decode, shrink.
        for ea in attempts:
            try:
                fd = descriptor_pb2.FileDescriptorProto.FromString(data[offset:ea])
            except Exception:
                continue
            if fd.name == expected_name:
                decoded = fd
                chosen_blob = data[offset:ea]
                break
        if decoded is None:
            # Fall back to byte-by-byte shrink from natural end.
            for ea in range(end, offset + 16, -1):
                try:
                    fd = descriptor_pb2.FileDescriptorProto.FromString(data[offset:ea])
                except Exception:
                    continue
                if fd.name == expected_name:
                    decoded = fd
                    chosen_blob = data[offset:ea]
                    break
                # short-circuit: once we have a valid name match we keep
                # the LARGEST such slice
            if decoded is None:
                continue
        # If we already have this filename, prefer the larger blob (more
        # complete descriptor — sometimes the same proto appears in
        # multiple translation units with progressively fuller field sets)
        if expected_name in by_name:
            prev = by_name[expected_name]
            if len(prev.SerializeToString()) >= len(chosen_blob):
                continue
        by_name[expected_name] = decoded
        summaries.append(ExtractedDescriptor(
            proto_file=decoded.name,
            binary_offset=offset,
            blob_size=len(chosen_blob),
            package=decoded.package,
            message_names=sorted(md.name for md in decoded.message_type),
            enum_names=sorted(ed.name for ed in decoded.enum_type),
            dependencies=list(decoded.dependency),
        ))
    summaries.sort(key=lambda s: s.proto_file)
    return summaries, by_name


# ---------------------------------------------------------------------------
# Schema registry (cached across MCP tool calls)
# ---------------------------------------------------------------------------


@dataclass
class SchemaRegistry:
    binary_path: Path
    pool: descriptor_pool.DescriptorPool
    factory: message_factory.MessageFactory
    files: dict[str, descriptor_pb2.FileDescriptorProto]
    summaries: list[ExtractedDescriptor]

    def message_class(self, fq_name: str) -> Any:
        """Look up a message by fully qualified name (e.g. ``NV.PbApiInfo``)."""
        fq = fq_name.lstrip(".")
        desc = self.pool.FindMessageTypeByName(fq)
        # protobuf 5.x renamed GetPrototype → GetMessageClass; support both.
        get_cls = getattr(message_factory, "GetMessageClass", None)
        if get_cls is not None:
            return get_cls(desc)
        return self.factory.GetPrototype(desc)

    def list_messages(self) -> list[str]:
        out: list[str] = []
        for fd in self.files.values():
            pkg = fd.package
            for md in fd.message_type:
                _collect_message_fqns(md, f"{pkg}.{md.name}" if pkg else md.name, out)
        return sorted(out)

    def describe(self, fq_name: str) -> dict[str, Any]:
        fq = fq_name.lstrip(".")
        desc = self.pool.FindMessageTypeByName(fq)
        return _describe_descriptor(desc)


def _collect_message_fqns(md: descriptor_pb2.DescriptorProto, prefix: str, out: list[str]) -> None:
    out.append(prefix)
    for nested in md.nested_type:
        _collect_message_fqns(nested, f"{prefix}.{nested.name}", out)


def _describe_descriptor(desc: Any) -> dict[str, Any]:
    fields = []
    for f in desc.fields:
        # upb FieldDescriptor uses different attribute names than pure-python
        label = getattr(f, "label", None)
        if label is None:
            label = 3 if getattr(f, "is_repeated", False) else (
                2 if getattr(f, "is_required", False) else 1
            )
        type_name = ""
        msg_type = getattr(f, "message_type", None)
        enum_type = getattr(f, "enum_type", None)
        if msg_type is not None:
            type_name = msg_type.full_name
        elif enum_type is not None:
            type_name = enum_type.full_name
        fields.append({
            "name": f.name,
            "number": f.number,
            "type": f.type,            # 1..18 (TYPE_DOUBLE..TYPE_SINT64)
            "type_name": type_name or None,
            "label": label,            # 1=optional, 2=required, 3=repeated
            "is_repeated": label == 3,
            "is_message": f.type == 11,
            "is_enum": f.type == 14,
        })
    nested = [
        {"name": n.name, "full_name": n.full_name}
        for n in getattr(desc, "nested_types", [])
    ]
    return {
        "full_name": desc.full_name,
        "name": desc.name,
        "field_count": len(fields),
        "fields": fields,
        "nested": nested,
    }


# Reentrant: get_registry() acquires it then synchronously calls
# build_registry() on first use, which itself reacquires before storing.
_registry_lock = threading.RLock()
_registry: SchemaRegistry | None = None


def build_registry(binary_path: Path | None = None,
                   settings: Settings | None = None) -> SchemaRegistry:
    """Build (or rebuild) the schema registry for the given binary.

    Default binary is ``ngfx-replay.exe`` from the active Nsight install.
    """
    global _registry
    if binary_path is None:
        s = settings or get_settings()
        bin_dir = host_bin_dir(s.install_root)
        if bin_dir is None:
            raise FileNotFoundError("Nsight Graphics install not found")
        binary_path = bin_dir / "ngfx-replay.exe"
    binary_path = binary_path.resolve()

    summaries, files = extract_descriptors(binary_path)

    pool = descriptor_pool.DescriptorPool()
    # Sort by dependency order — files with fewer deps first. We do best-
    # effort topological-ish ordering by repeating until all add cleanly.
    remaining = dict(files)
    added: set[str] = set()
    progress = True
    while remaining and progress:
        progress = False
        for name in list(remaining):
            fd = remaining[name]
            if all(dep in added or dep not in files for dep in fd.dependency):
                try:
                    pool.Add(fd)
                    added.add(name)
                    remaining.pop(name)
                    progress = True
                except Exception:
                    # leave for later, maybe a missing dep that comes in
                    # another iteration
                    pass
    # any leftovers — try forcing
    for name, fd in remaining.items():
        try:
            pool.Add(fd)
            added.add(name)
        except Exception:
            pass

    factory = message_factory.MessageFactory(pool=pool)
    reg = SchemaRegistry(
        binary_path=binary_path,
        pool=pool,
        factory=factory,
        files=files,
        summaries=summaries,
    )
    with _registry_lock:
        _registry = reg
    return reg


def get_registry() -> SchemaRegistry:
    with _registry_lock:
        if _registry is None:
            return build_registry()
        return _registry
