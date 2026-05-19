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


def parse_shader_arrays(text: str, path: Path) -> list[ShaderBlob]:
    out: list[ShaderBlob] = []
    for m in _RE_SHADER_ARRAY.finditer(text):
        name = m.group("name")
        body = m.group("body")
        leading = _parse_leading_bytes(body, max_bytes=24)
        if not leading:
            continue
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
                         b.hash_source, b.head_hex))
        conn.executemany(
            "INSERT OR REPLACE INTO shader_blobs(symbol, file_path, line_number, "
            "declared_byte_count, format, hash_hex, hash_source, head_hex) "
            "VALUES (?,?,?,?,?,?,?,?)",
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


def get_pso(db_path: Path, pso_symbol: str) -> dict[str, Any] | None:
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT pso.stage, pso.shader_symbol, pso.api, pso.creator, "
            "pso.file_path, pso.line_number, "
            "blob.format, blob.hash_hex, blob.hash_source, blob.declared_byte_count, blob.head_hex "
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
                    "head_hex": r[10],
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
                           hash_hex: str | None = None) -> list[dict[str, Any]]:
    """Reverse lookup: which PSOs reference a given shader symbol or hash?"""
    if not shader_symbol and not hash_hex:
        raise ValueError("must supply shader_symbol or hash_hex")
    conn = _connect(db_path)
    try:
        if shader_symbol:
            target_syms = [shader_symbol]
        else:
            target_syms = [r[0] for r in conn.execute(
                "SELECT symbol FROM shader_blobs WHERE hash_hex = ?", (hash_hex,)
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
                      hash_hex: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
    conn = _connect(db_path)
    try:
        clauses, params = [], []
        if format:
            clauses.append("format = ?")
            params.append(format)
        if hash_hex:
            clauses.append("hash_hex = ?")
            params.append(hash_hex)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        rows = conn.execute(
            f"SELECT symbol, format, hash_hex, hash_source, declared_byte_count, "
            f"file_path, line_number, head_hex FROM shader_blobs {where} "
            f"ORDER BY symbol LIMIT ?", params,
        ).fetchall()
        return [
            {
                "symbol": r[0], "format": r[1], "hash_hex": r[2],
                "hash_source": r[3], "declared_byte_count": r[4],
                "file_path": r[5], "line_number": r[6], "head_hex": r[7],
            }
            for r in rows
        ]
    finally:
        conn.close()
