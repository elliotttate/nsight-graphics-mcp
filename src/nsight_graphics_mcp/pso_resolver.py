"""PSO → DXBC / SPIR-V hash mapping.

The Nsight CLI doesn't expose the link between a PSO (D3D12 pipeline /
Vulkan VkPipeline) and the shader bytecode hashes it uses. The protobuf
schema embedded in ``ngfx-replay.exe`` *does* — see
``NV.Pylon.Replay.PbPipelineShaderStageInfo`` (fields ``pipeline``,
``driverAppHash``, ``stage``) — but parsing the .ngfx-gfxcap directly is
work in progress (see :mod:`capture_decoder`).

This module recovers the same information from the *Generate C++
Capture* emitted source — which is the most reliable path that works
today because:

  1. Shader bytecode is emitted as a flat ``static const unsigned char
     g_<name>[] = { 0x44, 0x58, 0x42, 0x43, ... };`` array.
  2. The first 20 bytes of every DXBC blob are the magic (``"DXBC"``)
     followed by a 128-bit hash NVIDIA / Microsoft use to identify the
     compiled shader — *exactly the DXBC hash* the user usually means.
     SPIR-V doesn't have a built-in hash; we compute SHA-1 of the blob
     so SPIR-V shaders still get a stable identity.
  3. PSO creation calls (``CreateGraphicsPipelineState`` /
     ``CreateComputePipelineState`` / ``vkCreateGraphicsPipelines`` /
     ``vkCreateComputePipelines`` / ``vkCreateRayTracingPipelinesKHR``)
     reference those byte-array symbols (D3D12) or
     ``vkCreateShaderModule`` handles (Vulkan) in the same source file
     — usually the same emitted function.

The output is a SQLite table ``pso_shaders`` alongside
``cpp_calls`` in the existing C++-capture index DB. Lookup by PSO name
returns ``{stage: {shader_symbol, blob_size, format, hash, source_loc}}``.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Shader bytecode extraction
# ---------------------------------------------------------------------------


# static const unsigned char g_VS_dxbc_xxx[] = { 0x44, 0x58, ... };
# also matches: static const BYTE / std::uint8_t / unsigned __int8 / uint8_t
_RE_SHADER_ARRAY = re.compile(
    r"""
    static \s+ const \s+
    (?: unsigned \s+ char | uint8_t | std::uint8_t | BYTE | unsigned\s+__int8 )
    \s+ (?P<name>\w+)
    \s* \[\s*(?:\d+)?\s*\] \s* =
    \s* \{ (?P<body> [^}]* ) \} \s* ;
    """,
    re.DOTALL | re.VERBOSE,
)

# A leading run of hex / decimal byte literals — we only need the first ~24
# bytes of any blob to identify the magic + hash, so don't materialise the
# whole multi-MB shader.
_RE_BYTE_LITERAL = re.compile(r"0[xX][0-9a-fA-F]{1,2}|\b\d{1,3}\b")


def _parse_leading_bytes(body: str, max_bytes: int = 24) -> bytes:
    out = bytearray()
    for tok in _RE_BYTE_LITERAL.finditer(body):
        s = tok.group(0)
        try:
            v = int(s, 0)
        except ValueError:
            continue
        if 0 <= v <= 0xFF:
            out.append(v)
            if len(out) >= max_bytes:
                break
    return bytes(out)


def _full_byte_count(body: str) -> int:
    """Cheap upper bound: count integer-shaped tokens. Good enough for
    'how big is this blob' without parsing every byte."""
    return sum(1 for _ in _RE_BYTE_LITERAL.finditer(body))


def _full_blob_bytes(body: str) -> bytes:
    out = bytearray()
    for tok in _RE_BYTE_LITERAL.finditer(body):
        try:
            v = int(tok.group(0), 0)
        except ValueError:
            continue
        if 0 <= v <= 0xFF:
            out.append(v)
    return bytes(out)


DXBC_MAGIC = b"DXBC"
SPIRV_MAGIC_LE = b"\x03\x02\x23\x07"  # 0x07230203 in little-endian
SPIRV_MAGIC_BE = b"\x07\x23\x02\x03"


@dataclass
class ShaderBlob:
    symbol: str            # the C-level symbol e.g. "g_VS_xxxx"
    file_path: str
    line_number: int
    declared_byte_count: int
    format: str            # "dxbc" | "dxil" | "spirv" | "unknown"
    hash_hex: str | None   # DXBC: built-in MD5; SPIR-V: SHA-1; unknown: None
    hash_source: str       # "dxbc-builtin" | "sha1-of-blob" | None
    shader_toggler_crc32: str
    head_hex: str          # first 24 bytes for visibility


def _identify_blob(leading: bytes, full_size: int, body: str | None) -> tuple[str, str | None, str]:
    """Return (format, hash_hex, hash_source). Body is parsed for SPIR-V
    when needed; passing None skips that and returns no hash for SPIR-V."""
    if len(leading) >= 20 and leading[:4] == DXBC_MAGIC:
        # DXBC / DXIL share the container; bytes 4..20 are the MD5 hash.
        # Distinguish by checking for DXIL chunk magic later if needed.
        return "dxbc", leading[4:20].hex(), "dxbc-builtin"
    if len(leading) >= 4 and leading[:4] in (SPIRV_MAGIC_LE, SPIRV_MAGIC_BE):
        if body is None:
            return "spirv", None, ""
        full = _full_blob_bytes(body)
        return "spirv", hashlib.sha1(full).hexdigest(), "sha1-of-blob"
    return "unknown", None, ""


def shader_toggler_crc32(blob: bytes) -> str:
    """Return the ShaderToggler identity hash for a shader bytecode blob.

    ShaderToggler computes ``compute_crc32(shader_desc.code, code_size)``
    in its ReShade ``init_pipeline`` callback. That implementation is the
    standard reflected CRC32 used by zlib.
    """
    return f"{zlib.crc32(blob) & 0xFFFFFFFF:08x}"


def parse_shader_arrays(text: str, path: Path) -> list[ShaderBlob]:
    out: list[ShaderBlob] = []
    for m in _RE_SHADER_ARRAY.finditer(text):
        name = m.group("name")
        body = m.group("body")
        leading = _parse_leading_bytes(body, max_bytes=24)
        if not leading:
            continue
        full = _full_blob_bytes(body)
        declared = _full_byte_count(body)
        fmt, h, src = _identify_blob(leading, declared, body if leading[:4] in (SPIRV_MAGIC_LE, SPIRV_MAGIC_BE) else None)
        line_no = text.count("\n", 0, m.start()) + 1
        out.append(ShaderBlob(
            symbol=name,
            file_path=str(path),
            line_number=line_no,
            declared_byte_count=declared,
            format=fmt,
            hash_hex=h,
            hash_source=src,
            shader_toggler_crc32=shader_toggler_crc32(full),
            head_hex=leading.hex(),
        ))
    return out


# ---------------------------------------------------------------------------
# PSO → shader association
# ---------------------------------------------------------------------------


# D3D12 PSO creation entry points. We can't write a regex that matches
# the full call because it may contain nested parens (IID_PPV_ARGS(&g_PSO_0));
# instead we match the call site, then walk balanced parens to extract args.
_RE_D3D_PSO_CREATE_START = re.compile(
    r"""
    \b (?P<creator>
        CreateGraphicsPipelineState | CreateComputePipelineState
        | CreateStateObject | CreatePipelineState
      ) \s* \(
    """,
    re.VERBOSE,
)
# Inside the call args, find the last `& <symbol>` — that's the output PSO.
_RE_AMP_NAME = re.compile(r"&\s*([A-Za-z_]\w*)")


def _balanced_args(text: str, open_paren_pos: int) -> tuple[str, int] | None:
    """Given the offset of an opening '(', return (inside_text, close_pos)."""
    depth = 1
    i = open_paren_pos + 1
    while i < len(text):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren_pos + 1:i], i
        i += 1
    return None

# Vulkan: vkCreateGraphicsPipelines(device, cache, count, infos, alloc, &g_Pipeline_0);
# vkCreateComputePipelines, vkCreateRayTracingPipelinesKHR have the same trailing
# pointer-to-output-handle pattern.
_RE_VK_PSO_CREATE = re.compile(
    r"""
    \b vk(?: CreateGraphicsPipelines | CreateComputePipelines
           | CreateRayTracingPipelinesKHR | CreateRayTracingPipelinesNV ) \s* \(
    [^)]*?
    & \s* (?P<pso>\w+)
    \s* \) \s* ;
    """,
    re.DOTALL | re.VERBOSE,
)

# Vulkan: vkCreateShaderModule(device, &info, alloc, &g_ShaderModule_42);
_RE_VK_CREATE_SHADER_MODULE = re.compile(
    r"""
    \b vkCreateShaderModule \s* \(
    [^)]*? & \s* (?P<module>\w+) \s* \) \s* ;
    """,
    re.DOTALL | re.VERBOSE,
)

# Vulkan: stage_info.module = g_ShaderModule_42;
_RE_VK_STAGE_MODULE_ASSIGN = re.compile(
    r"""
    (?:\.|->) module \s* = \s* (?P<module>\w+) \s* ;
    """,
    re.VERBOSE,
)

# Vulkan: VkShaderStageFlagBits stage = VK_SHADER_STAGE_VERTEX_BIT;
# Or: stage_info.stage = VK_SHADER_STAGE_FRAGMENT_BIT;
_RE_VK_STAGE_FLAG = re.compile(
    r"VK_SHADER_STAGE_(?P<flag>VERTEX|FRAGMENT|COMPUTE|GEOMETRY|TESSELLATION_CONTROL|"
    r"TESSELLATION_EVALUATION|RAYGEN|ANY_HIT|CLOSEST_HIT|MISS|INTERSECTION|CALLABLE|"
    r"TASK|MESH)_BIT(?:_KHR|_NV)?"
)

# D3D12 PSO desc field assignments. Two common emit styles:
#   psoDesc.VS = { g_VS_xxx, sizeof(g_VS_xxx) };
#   psoDesc.VS.pShaderBytecode = g_VS_xxx;
# Plus shader stages: VS, PS, GS, HS, DS, CS, AS, MS.
_D3D_STAGES = ("VS", "PS", "GS", "HS", "DS", "CS", "AS", "MS")

_RE_D3D_STAGE_INIT = re.compile(
    r"""
    \. (?P<stage> VS | PS | GS | HS | DS | CS | AS | MS )
    \s* = \s* \{ \s* (?P<sym> \w+ )
    """,
    re.VERBOSE,
)

_RE_D3D_STAGE_PTR = re.compile(
    r"""
    \. (?P<stage> VS | PS | GS | HS | DS | CS | AS | MS )
    \s* \. \s* pShaderBytecode \s* = \s* (?P<sym> \w+ ) \s* ;
    """,
    re.VERBOSE,
)


@dataclass
class PSORecord:
    pso_symbol: str
    api: str           # "d3d12" | "vulkan"
    creator: str       # the function name that created it
    file_path: str
    line_number: int
    stages: dict[str, dict[str, Any]] = field(default_factory=dict)  # stage_name -> {shader_symbol, format, hash_hex}


# ---------------------------------------------------------------------------
# Top-level indexer
# ---------------------------------------------------------------------------


PSO_SCHEMA = """
CREATE TABLE IF NOT EXISTS shader_blobs(
    symbol               TEXT PRIMARY KEY,
    file_path            TEXT NOT NULL,
    line_number          INTEGER NOT NULL,
    declared_byte_count  INTEGER NOT NULL,
    format               TEXT NOT NULL,
    hash_hex             TEXT,
    hash_source          TEXT,
    shader_toggler_crc32 TEXT,
    head_hex             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS i_shader_blobs_hash ON shader_blobs(hash_hex);
CREATE INDEX IF NOT EXISTS i_shader_blobs_format ON shader_blobs(format);

CREATE TABLE IF NOT EXISTS pso_shaders(
    pso_symbol      TEXT NOT NULL,
    stage           TEXT NOT NULL,
    shader_symbol   TEXT NOT NULL,
    api             TEXT NOT NULL,
    creator         TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    line_number     INTEGER NOT NULL,
    PRIMARY KEY (pso_symbol, stage)
);
CREATE INDEX IF NOT EXISTS i_pso_shaders_pso ON pso_shaders(pso_symbol);
CREATE INDEX IF NOT EXISTS i_pso_shaders_shader ON pso_shaders(shader_symbol);
CREATE INDEX IF NOT EXISTS i_pso_shaders_api ON pso_shaders(api);
"""


def _ensure_column(conn: sqlite3.Connection, table: str, name: str, definition: str) -> None:
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if name not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def _ensure_shader_blobs_crc32_column(conn: sqlite3.Connection) -> None:
    has_shader_blobs = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'shader_blobs'"
    ).fetchone()
    if not has_shader_blobs:
        return
    _ensure_column(conn, "shader_blobs", "shader_toggler_crc32", "TEXT")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS i_shader_blobs_shader_toggler_crc32 "
        "ON shader_blobs(shader_toggler_crc32)"
    )


def _find_enclosing_function(text: str, pso_match_end: int) -> tuple[int, int]:
    """Return (start_offset, end_offset) of the function body containing
    the given offset. Uses brace matching — picks the closest enclosing
    pair of ``{...}`` whose ``{`` is preceded by a function-signature-ish
    line. Falls back to a +/-4KB window if we can't isolate one."""
    # Walk backwards to find the matching '{' depth zero
    depth = 0
    open_pos = -1
    for i in range(pso_match_end, -1, -1):
        c = text[i]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth == 0:
                open_pos = i
                break
            depth -= 1
    if open_pos < 0:
        return max(0, pso_match_end - 4096), min(len(text), pso_match_end + 4096)
    # Walk forward from open_pos to find the matching '}'
    depth = 1
    close_pos = -1
    for i in range(open_pos + 1, len(text)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                close_pos = i
                break
    if close_pos < 0:
        close_pos = min(len(text), open_pos + 8192)
    return open_pos, close_pos


_D3D_VK_STAGE_MAP = {
    "VERTEX": "VS",
    "FRAGMENT": "PS",
    "COMPUTE": "CS",
    "GEOMETRY": "GS",
    "TESSELLATION_CONTROL": "HS",
    "TESSELLATION_EVALUATION": "DS",
    "TASK": "AS",
    "MESH": "MS",
    "RAYGEN": "RGEN",
    "ANY_HIT": "AHIT",
    "CLOSEST_HIT": "CHIT",
    "MISS": "MISS",
    "INTERSECTION": "ISECT",
    "CALLABLE": "CALL",
}


def _associate_d3d_pso(text: str, body_start: int, body_end: int) -> dict[str, str]:
    """Find .VS/.PS/.../.MS = { sym, ... } assignments and `.<stage>.pShaderBytecode = sym;`
    inside ``text[body_start:body_end]``. Returns ``{stage: shader_symbol}``."""
    body = text[body_start:body_end]
    out: dict[str, str] = {}
    for m in _RE_D3D_STAGE_INIT.finditer(body):
        out.setdefault(m.group("stage"), m.group("sym"))
    for m in _RE_D3D_STAGE_PTR.finditer(body):
        out.setdefault(m.group("stage"), m.group("sym"))
    return out


def _associate_vk_pso(text: str, body_start: int, body_end: int,
                      module_to_stage: dict[str, str]) -> dict[str, str]:
    """For each `.module = g_ShaderModule_N;` inside the enclosing function,
    look at the nearby `VK_SHADER_STAGE_<X>_BIT` flag to assign a stage."""
    body = text[body_start:body_end]
    out: dict[str, str] = {}
    # iterate stage-flag positions
    flag_positions = [(m.start(), m.group("flag")) for m in _RE_VK_STAGE_FLAG.finditer(body)]
    for mm in _RE_VK_STAGE_MODULE_ASSIGN.finditer(body):
        module_sym = mm.group("module")
        # nearest stage flag (in either direction) within 800 chars
        best: tuple[int, str] | None = None
        for pos, flag in flag_positions:
            dist = abs(pos - mm.start())
            if dist > 800:
                continue
            if best is None or dist < best[0]:
                best = (dist, flag)
        stage_label = _D3D_VK_STAGE_MAP.get(best[1], best[1]) if best else module_to_stage.get(module_sym, "UNKNOWN")
        out.setdefault(stage_label, module_sym)
    return out


def index_project_psos(project_dir: Path, *, db_path: Path | None = None,
                       force: bool = False) -> dict[str, Any]:
    """Walk every .cpp/.cxx file in ``project_dir`` and build a
    ``shader_blobs`` + ``pso_shaders`` SQLite index."""
    project_dir = project_dir.resolve()
    if db_path is None:
        db_path = project_dir / ".ngfxmcp_cpp_calls.db"
    files = sorted(p for p in project_dir.rglob("*")
                   if p.suffix.lower() in (".cpp", ".cxx", ".cc", ".c"))

    all_blobs: list[ShaderBlob] = []
    all_psos: list[PSORecord] = []
    module_to_stage: dict[str, str] = {}  # vkCreateShaderModule symbol → guessed stage

    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        all_blobs.extend(parse_shader_arrays(text, path))

        # Vulkan: collect (module_symbol → stage hint) from vkCreateShaderModule + nearby flag
        for m in _RE_VK_CREATE_SHADER_MODULE.finditer(text):
            module = m.group("module")
            # look ahead/behind ~400 chars for a stage flag (best-effort)
            lo = max(0, m.start() - 400)
            hi = min(len(text), m.end() + 400)
            win = text[lo:hi]
            sm = _RE_VK_STAGE_FLAG.search(win)
            if sm:
                module_to_stage[module] = _D3D_VK_STAGE_MAP.get(sm.group("flag"), sm.group("flag"))

        # D3D12 PSOs: find each create call site, walk balanced parens to
        # get the call args, then pick the last `& <sym>` reference as
        # the output PSO (handles IID_PPV_ARGS macro).
        for m in _RE_D3D_PSO_CREATE_START.finditer(text):
            open_paren_pos = m.end() - 1
            walked = _balanced_args(text, open_paren_pos)
            if walked is None:
                continue
            args, close_pos = walked
            amp_refs = _RE_AMP_NAME.findall(args)
            if not amp_refs:
                continue
            # heuristic: output PSO is the last "& <sym>" — convention
            # for D3D12 is `(&desc, IID_PPV_ARGS(&pso))`.
            pso = amp_refs[-1]
            body_start, body_end = _find_enclosing_function(text, close_pos)
            stages = _associate_d3d_pso(text, body_start, body_end)
            line_no = text.count("\n", 0, m.start()) + 1
            all_psos.append(PSORecord(
                pso_symbol=pso, api="d3d12",
                creator=m.group("creator"),
                file_path=str(path), line_number=line_no,
                stages={st: {"shader_symbol": sym} for st, sym in stages.items()},
            ))

        # Vulkan PSOs
        for m in _RE_VK_PSO_CREATE.finditer(text):
            pso = m.group("pso")
            body_start, body_end = _find_enclosing_function(text, m.end())
            stages = _associate_vk_pso(text, body_start, body_end, module_to_stage)
            line_no = text.count("\n", 0, m.start()) + 1
            creator = re.search(r"vkCreate\w+Pipelines\w*", m.group(0))
            all_psos.append(PSORecord(
                pso_symbol=pso, api="vulkan",
                creator=creator.group(0) if creator else "?",
                file_path=str(path), line_number=line_no,
                stages={st: {"shader_symbol": sym} for st, sym in stages.items()},
            ))

    # build the DB
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(PSO_SCHEMA)
        _ensure_shader_blobs_crc32_column(conn)
        if force:
            conn.execute("DELETE FROM shader_blobs")
            conn.execute("DELETE FROM pso_shaders")
        # Insert blobs (dedup by symbol)
        seen_syms: set[str] = set()
        rows = []
        for b in all_blobs:
            if b.symbol in seen_syms:
                continue
            seen_syms.add(b.symbol)
            rows.append((b.symbol, b.file_path, b.line_number,
                         b.declared_byte_count, b.format, b.hash_hex,
                         b.hash_source, b.shader_toggler_crc32, b.head_hex))
        conn.executemany(
            "INSERT OR REPLACE INTO shader_blobs(symbol, file_path, line_number, "
            "declared_byte_count, format, hash_hex, hash_source, shader_toggler_crc32, head_hex) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            rows,
        )
        # Insert PSO→shader rows
        pso_rows = []
        for p in all_psos:
            for stage, info in p.stages.items():
                pso_rows.append((p.pso_symbol, stage, info["shader_symbol"],
                                 p.api, p.creator, p.file_path, p.line_number))
        conn.executemany(
            "INSERT OR REPLACE INTO pso_shaders(pso_symbol, stage, shader_symbol, "
            "api, creator, file_path, line_number) VALUES (?,?,?,?,?,?,?)",
            pso_rows,
        )
        conn.commit()
        n_blobs = conn.execute("SELECT COUNT(*) FROM shader_blobs").fetchone()[0]
        n_psos = conn.execute("SELECT COUNT(DISTINCT pso_symbol) FROM pso_shaders").fetchone()[0]
        n_rows = conn.execute("SELECT COUNT(*) FROM pso_shaders").fetchone()[0]
        fmt_hist = dict(conn.execute(
            "SELECT format, COUNT(*) FROM shader_blobs GROUP BY format").fetchall())
    finally:
        conn.close()

    return {
        "ok": True,
        "project_dir": str(project_dir),
        "db_path": str(db_path),
        "shader_blob_count": n_blobs,
        "pso_count": n_psos,
        "pso_stage_count": n_rows,
        "shader_format_histogram": fmt_hist,
    }


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def _connect(db_path: Path) -> sqlite3.Connection:
    if not db_path.is_file():
        raise FileNotFoundError(f"index DB not found: {db_path}")
    return sqlite3.connect(db_path)


def _crc32_decimal(crc32_hex: str | None) -> int | None:
    return int(crc32_hex, 16) if crc32_hex else None


def _normalise_shader_toggler_crc32(
    *,
    crc32_hex: str | None = None,
    crc32_decimal: int | str | None = None,
) -> str:
    if (crc32_hex is None) == (crc32_decimal is None):
        raise ValueError("supply exactly one of crc32_hex or crc32_decimal")
    if crc32_hex is not None:
        s = str(crc32_hex).strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        value = int(s, 16)
    else:
        value = int(str(crc32_decimal).strip(), 10)
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("CRC32 value is outside uint32 range")
    return f"{value:08x}"


def get_pso(db_path: Path, pso_symbol: str) -> dict[str, Any] | None:
    conn = _connect(db_path)
    try:
        _ensure_shader_blobs_crc32_column(conn)
        rows = conn.execute(
            "SELECT pso.stage, pso.shader_symbol, pso.api, pso.creator, "
            "pso.file_path, pso.line_number, "
            "blob.format, blob.hash_hex, blob.hash_source, blob.declared_byte_count, "
            "blob.shader_toggler_crc32, blob.head_hex "
            "FROM pso_shaders pso "
            "LEFT JOIN shader_blobs blob ON blob.symbol = pso.shader_symbol "
            "WHERE pso.pso_symbol = ? ORDER BY pso.stage",
            (pso_symbol,),
        ).fetchall()
        if not rows:
            return None
        head = rows[0]
        return {
            "pso_symbol": pso_symbol,
            "api": head[2],
            "creator": head[3],
            "source": {"file_path": head[4], "line_number": head[5]},
            "stages": {
                r[0]: {
                    "shader_symbol": r[1],
                    "format": r[6],
                    "hash_hex": r[7],
                    "hash_source": r[8],
                    "declared_byte_count": r[9],
                    "shader_toggler_crc32": r[10],
                    "shader_toggler_crc32_decimal": _crc32_decimal(r[10]),
                    "head_hex": r[11],
                }
                for r in rows
            },
        }
    finally:
        conn.close()


def list_psos(db_path: Path, *, api: str | None = None, limit: int = 500,
              offset: int = 0) -> list[dict[str, Any]]:
    conn = _connect(db_path)
    try:
        clauses, params = [], []
        if api:
            clauses.append("api = ?")
            params.append(api)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            "SELECT pso_symbol, api, creator, MIN(file_path) AS file_path, "
            "MIN(line_number) AS line_number, "
            "GROUP_CONCAT(stage || ':' || shader_symbol, ', ') AS stage_summary "
            f"FROM pso_shaders {where} "
            "GROUP BY pso_symbol, api, creator ORDER BY pso_symbol LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        return [
            {
                "pso_symbol": r[0],
                "api": r[1],
                "creator": r[2],
                "file_path": r[3],
                "line_number": r[4],
                "stage_summary": r[5],
            }
            for r in conn.execute(sql, params).fetchall()
        ]
    finally:
        conn.close()


def find_psos_using_shader(db_path: Path, *, shader_symbol: str | None = None,
                           hash_hex: str | None = None,
                           shader_toggler_crc32: str | None = None) -> list[dict[str, Any]]:
    """Reverse lookup: which PSOs reference a given shader symbol or hash?"""
    supplied = sum(x is not None for x in (shader_symbol, hash_hex, shader_toggler_crc32))
    if supplied != 1:
        raise ValueError("supply exactly one of shader_symbol, hash_hex, or shader_toggler_crc32")
    conn = _connect(db_path)
    try:
        _ensure_shader_blobs_crc32_column(conn)
        if shader_symbol:
            target_syms = [shader_symbol]
        elif hash_hex:
            target_syms = [r[0] for r in conn.execute(
                "SELECT symbol FROM shader_blobs WHERE hash_hex = ?", (hash_hex.lower(),)
            ).fetchall()]
            if not target_syms:
                return []
        else:
            target_crc32 = _normalise_shader_toggler_crc32(crc32_hex=shader_toggler_crc32)
            target_syms = [r[0] for r in conn.execute(
                "SELECT symbol FROM shader_blobs WHERE shader_toggler_crc32 = ?",
                (target_crc32,),
            ).fetchall()]
            if not target_syms:
                return []
        marks = ",".join("?" * len(target_syms))
        rows = conn.execute(
            f"SELECT pso_symbol, stage, shader_symbol, api FROM pso_shaders "
            f"WHERE shader_symbol IN ({marks}) ORDER BY pso_symbol",
            target_syms,
        ).fetchall()
        return [
            {"pso_symbol": r[0], "stage": r[1], "shader_symbol": r[2], "api": r[3]}
            for r in rows
        ]
    finally:
        conn.close()


def list_shader_blobs(db_path: Path, *, format: str | None = None,
                      hash_hex: str | None = None,
                      shader_toggler_crc32: str | None = None,
                      limit: int = 500) -> list[dict[str, Any]]:
    conn = _connect(db_path)
    try:
        _ensure_shader_blobs_crc32_column(conn)
        clauses, params = [], []
        if format:
            clauses.append("format = ?")
            params.append(format)
        if hash_hex:
            clauses.append("hash_hex = ?")
            params.append(hash_hex.lower())
        if shader_toggler_crc32:
            clauses.append("shader_toggler_crc32 = ?")
            params.append(_normalise_shader_toggler_crc32(crc32_hex=shader_toggler_crc32))
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        rows = conn.execute(
            f"SELECT symbol, format, hash_hex, hash_source, shader_toggler_crc32, declared_byte_count, "
            f"file_path, line_number, head_hex FROM shader_blobs {where} "
            f"ORDER BY symbol LIMIT ?", params,
        ).fetchall()
        return [
            {
                "symbol": r[0], "format": r[1], "hash_hex": r[2],
                "hash_source": r[3],
                "shader_toggler_crc32": r[4],
                "shader_toggler_crc32_decimal": _crc32_decimal(r[4]),
                "declared_byte_count": r[5],
                "file_path": r[6], "line_number": r[7], "head_hex": r[8],
            }
            for r in rows
        ]
    finally:
        conn.close()


def find_shader_blobs_by_shader_toggler_crc32(
    db_path: Path,
    *,
    crc32_hex: str | None = None,
    crc32_decimal: int | str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    target = _normalise_shader_toggler_crc32(
        crc32_hex=crc32_hex,
        crc32_decimal=crc32_decimal,
    )
    blobs = list_shader_blobs(db_path, shader_toggler_crc32=target, limit=limit)
    conn = _connect(db_path)
    try:
        for blob in blobs:
            refs = conn.execute(
                "SELECT pso_symbol, stage, api, creator, file_path, line_number "
                "FROM pso_shaders WHERE shader_symbol = ? ORDER BY pso_symbol, stage",
                (blob["symbol"],),
            ).fetchall()
            blob["pso_references"] = [
                {
                    "pso_symbol": r[0],
                    "stage": r[1],
                    "api": r[2],
                    "creator": r[3],
                    "file_path": r[4],
                    "line_number": r[5],
                }
                for r in refs
            ]
    finally:
        conn.close()
    return blobs


def _shader_blob_bytes_from_source(file_path: Path, shader_symbol: str) -> bytes:
    text = file_path.read_text(encoding="utf-8", errors="replace")
    for m in _RE_SHADER_ARRAY.finditer(text):
        if m.group("name") == shader_symbol:
            blob = _full_blob_bytes(m.group("body"))
            if not blob:
                raise LookupError(f"shader array {shader_symbol!r} has no byte literals")
            return blob
    raise LookupError(f"shader array {shader_symbol!r} not found in {file_path}")


def dump_shader_blob(
    db_path: Path,
    output_path: Path,
    *,
    shader_symbol: str | None = None,
    crc32_hex: str | None = None,
    crc32_decimal: int | str | None = None,
) -> dict[str, Any]:
    if shader_symbol is None:
        matches = find_shader_blobs_by_shader_toggler_crc32(
            db_path,
            crc32_hex=crc32_hex,
            crc32_decimal=crc32_decimal,
            limit=1000,
        )
        if not matches:
            target = _normalise_shader_toggler_crc32(
                crc32_hex=crc32_hex,
                crc32_decimal=crc32_decimal,
            )
            raise LookupError(f"no shader blob has ShaderToggler CRC32 {target}")
        selected = matches[0]
        match_count = len(matches)
    else:
        matches = list_shader_blobs(db_path, limit=1_000_000)
        by_symbol = {m["symbol"]: m for m in matches}
        selected = by_symbol.get(shader_symbol)
        if selected is None:
            raise LookupError(f"shader symbol {shader_symbol!r} not in index")
        match_count = 1

    blob = _shader_blob_bytes_from_source(Path(selected["file_path"]), selected["symbol"])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(blob)
    return {
        "ok": True,
        "shader_symbol": selected["symbol"],
        "format": selected["format"],
        "hash_hex": selected["hash_hex"],
        "shader_toggler_crc32": selected["shader_toggler_crc32"],
        "shader_toggler_crc32_decimal": selected["shader_toggler_crc32_decimal"],
        "source_file": selected["file_path"],
        "source_line": selected["line_number"],
        "output_path": str(output_path),
        "bytes_written": len(blob),
        "match_count": match_count,
    }


# ---------------------------------------------------------------------------
# DXBC / DXIL container reflection (RDEF chunk)
# ---------------------------------------------------------------------------
#
# Public Microsoft format. The DXBC container layout:
#   [4]  magic   'DXBC'
#   [16] hash    MD5-ish container hash
#   [4]  version (always 1)
#   [4]  total_size
#   [4]  chunk_count
#   [chunk_count * 4] chunk_offsets (each into the container)
# Each chunk:
#   [4]  fourcc (e.g. 'RDEF', 'ISGN', 'OSGN', 'DXIL', 'STAT')
#   [4]  chunk_size (bytes following this header)
#   [chunk_size] chunk data
#
# RDEF (Resource Definition) chunk layout:
#   [4]  constant_buffers_count
#   [4]  constant_buffers_offset
#   [4]  resource_bindings_count
#   [4]  resource_bindings_offset
#   [4]  shader_version
#   [4]  flags
#   [4]  creator_offset
#
# ResourceBinding entry (32 bytes):
#   [4]  name_offset             (offset from RDEF chunk start to NUL-terminated name)
#   [4]  shader_input_type
#   [4]  resource_return_type
#   [4]  resource_dimension
#   [4]  sample_count
#   [4]  bind_point              (= shader register, e.g. 0 for t0)
#   [4]  bind_count
#   [4]  flags


_SHADER_INPUT_TYPE = {
    0: "CBUFFER",
    1: "TBUFFER",
    2: "TEXTURE",
    3: "SAMPLER",
    4: "UAV_RWTYPED",
    5: "STRUCTURED",
    6: "UAV_RWSTRUCTURED",
    7: "BYTEADDRESS",
    8: "UAV_RWBYTEADDRESS",
    9: "UAV_APPEND_STRUCTURED",
    10: "UAV_CONSUME_STRUCTURED",
    11: "UAV_RWSTRUCTURED_WITH_COUNTER",
    12: "RTACCELERATIONSTRUCTURE",
    13: "UAV_FEEDBACKTEXTURE",
}

_REGISTER_CLASS_FROM_INPUT_TYPE = {
    0: "CBV",      # CBUFFER → b register
    1: "SRV",      # TBUFFER → t register
    2: "SRV",      # TEXTURE → t register
    3: "SAMPLER",  # SAMPLER → s register
    4: "UAV",
    5: "SRV",
    6: "UAV",
    7: "SRV",
    8: "UAV",
    9: "UAV",
    10: "UAV",
    11: "UAV",
    12: "SRV",
    13: "UAV",
}

# RD11 variant of RDEF (DX11+) extends the binding entry to 40 bytes by
# appending: [4] register_space, [4] resource_id. Detect via the
# constant_buffers_offset being > 28 (the base RDEF header), but the
# simpler probe is the RD11 marker DWORD = 0x46443131 right after the
# 7-DWORD base header in some shaders compiled with /Fc. We detect by
# size alone: if the binding stride times count fits 40, prefer RD11.


def parse_dxbc_container(data: bytes) -> dict[str, Any]:
    """Decode a DXBC / DXIL container header and chunk index.

    Returns ``{"ok": True, "magic": "DXBC", "chunks": [{fourcc, offset, size}...]}``
    or ``{"ok": False, "error": ...}``.
    """
    import struct

    if len(data) < 32 or data[:4] != b"DXBC":
        return {
            "ok": False,
            "error": "not a DXBC container (magic mismatch or too short)",
            "magic": data[:4].decode("latin-1", errors="replace") if data else "",
        }
    hash16 = data[4:20].hex()
    version, total_size, chunk_count = struct.unpack_from("<III", data, 20)
    chunks: list[dict[str, Any]] = []
    for i in range(chunk_count):
        off = struct.unpack_from("<I", data, 32 + i * 4)[0]
        if off + 8 > len(data):
            continue
        fourcc = data[off : off + 4]
        size = struct.unpack_from("<I", data, off + 4)[0]
        chunks.append(
            {
                "fourcc": fourcc.decode("latin-1", errors="replace"),
                "offset": off,
                "size": size,
            }
        )
    return {
        "ok": True,
        "magic": "DXBC",
        "hash16": hash16,
        "version": version,
        "total_size": total_size,
        "chunk_count": chunk_count,
        "chunks": chunks,
        "evidence_label": "proven",
    }


def parse_rdef_chunk(data: bytes, chunk_offset: int, chunk_size: int) -> dict[str, Any]:
    """Decode an RDEF (Resource Definition) chunk's resource binding table.

    The chunk is read relative to ``chunk_offset`` inside ``data``. Returns
    a structured list of resource bindings (name, shader register, register
    space, type) so callers can map ``t0`` / ``s0`` / ``b1`` etc to names.
    """
    import struct

    body_offset = chunk_offset + 8
    if body_offset + 28 > len(data):
        return {"ok": False, "error": "RDEF chunk too small for base header"}
    (
        cb_count,
        cb_offset,
        rb_count,
        rb_offset,
        shader_version,
        flags,
        creator_offset,
    ) = struct.unpack_from("<IIIIIII", data, body_offset)

    # Detect RD11 by trying the next DWORD which should be 60 (sizeof RD11) for SM 5.1+.
    rd11 = False
    extra_size = 0
    if body_offset + 32 <= len(data):
        marker_or_size = struct.unpack_from("<I", data, body_offset + 28)[0]
        # On RD11 shaders the marker dword equals 60 (interface slots) or 28 etc.
        # We use binding-stride probing instead: if rb_count and rb_offset are set,
        # check whether 40-byte stride fits inside chunk_size.
        if rb_count and rb_offset:
            stride32 = 32
            stride40 = 40
            extent32 = rb_offset + rb_count * stride32
            extent40 = rb_offset + rb_count * stride40
            if extent40 <= chunk_size and (
                marker_or_size in (60, 28) or extent32 > chunk_size
            ):
                rd11 = True
                extra_size = 8
    binding_stride = 32 + (8 if rd11 else 0)

    bindings: list[dict[str, Any]] = []
    rdef_base = body_offset
    for i in range(rb_count):
        off = rdef_base + rb_offset + i * binding_stride
        if off + binding_stride > len(data):
            bindings.append({"index": i, "error": "binding past chunk end"})
            continue
        fields = struct.unpack_from("<IIIIIIII", data, off)
        name_off, sit, return_type, dim, sample_count, bind_point, bind_count, b_flags = fields
        name_abs = rdef_base + name_off
        end = data.find(b"\x00", name_abs)
        if end == -1:
            end = min(name_abs + 256, len(data))
        name = data[name_abs:end].decode("latin-1", errors="replace")
        entry: dict[str, Any] = {
            "index": i,
            "name": name,
            "shader_input_type_id": sit,
            "shader_input_type": _SHADER_INPUT_TYPE.get(sit, f"unknown({sit})"),
            "register_class": _REGISTER_CLASS_FROM_INPUT_TYPE.get(sit, "?"),
            "resource_return_type": return_type,
            "resource_dimension": dim,
            "sample_count": sample_count,
            "shader_register": bind_point,
            "bind_count": bind_count,
            "flags": b_flags,
        }
        if rd11 and off + 40 <= len(data):
            space, res_id = struct.unpack_from("<II", data, off + 32)
            entry["register_space"] = space
            entry["resource_id"] = res_id
        else:
            entry["register_space"] = 0
        # Map to canonical register notation like "t0 space0".
        cls = entry["register_class"]
        if cls in ("SRV", "UAV", "SAMPLER", "CBV"):
            letter = {"SRV": "t", "UAV": "u", "SAMPLER": "s", "CBV": "b"}[cls]
            entry["register"] = f"{letter}{bind_point}"
        bindings.append(entry)
    return {
        "ok": True,
        "constant_buffers_count": cb_count,
        "constant_buffers_offset": cb_offset,
        "resource_bindings_count": rb_count,
        "resource_bindings_offset": rb_offset,
        "shader_version_raw": shader_version,
        "flags": flags,
        "creator_offset": creator_offset,
        "rd11": rd11,
        "binding_stride": binding_stride,
        "bindings": bindings,
        "evidence_label": "proven",
    }


def shader_reflection_bindings(data: bytes) -> dict[str, Any]:
    """High-level entry point: parse a DXBC/DXIL container and return its
    resource binding table (RDEF chunk) plus a list of every chunk fourcc.
    """
    container = parse_dxbc_container(data)
    if not container["ok"]:
        return container
    rdef = next((c for c in container["chunks"] if c["fourcc"] == "RDEF"), None)
    if rdef is None:
        return {
            "ok": True,
            "container": container,
            "rdef": {"ok": False, "error": "no RDEF chunk in container"},
            "bindings": [],
        }
    rdef_parsed = parse_rdef_chunk(data, rdef["offset"], rdef["size"])
    return {
        "ok": True,
        "container": container,
        "rdef": rdef_parsed,
        "bindings": rdef_parsed.get("bindings", []),
        "evidence_label": "proven",
    }
