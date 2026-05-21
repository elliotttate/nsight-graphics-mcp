"""IDA Pro headless reverse-engineering helpers.

This module is deliberately small and file-oriented: it discovers a local IDA
install, launches IDA in auto-analysis/headless mode with an IDAPython exporter,
and caches compact JSON facts per binary hash. The facts are then cheap for MCP
tools to search without repeatedly opening the same 20+ MB Nsight binaries.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .cli import run_async, result_to_dict
from .config import get_settings, host_bin_dir


IDA_ENV = "NSIGHT_GRAPHICS_MCP_IDA"

_COMMON_IDA_ROOTS = (
    r"C:\Program Files\IDA Professional 9.3",
    r"C:\Program Files\IDA Professional 9.2",
    r"C:\Program Files\IDA Professional 9.1",
    r"C:\Program Files\IDA Professional 9.0",
    r"C:\Program Files\IDA Home (PC) 9.3",
    r"C:\Program Files\IDA Home (PC) 9.2",
    r"C:\Program Files\IDA Home (PC) 9.1",
    r"C:\Program Files\IDA Home (PC) 9.0",
    r"C:\Program Files\IDA Free 9.3",
    r"C:\Program Files\IDA Free 9.2",
    r"C:\Program Files\IDA Free 9.1",
    r"C:\Program Files\IDA Free 9.0",
)

_TARGET_BINARIES: dict[str, str] = {
    "ngfx": "ngfx.exe",
    "ngfx_capture": "ngfx-capture.exe",
    "ngfx_replay": "ngfx-replay.exe",
    "ngfx_rpc": "ngfx-rpc.exe",
    "ngfx_ui": "ngfx-ui.exe",
    "shaderdebugger_configurator": "nv-shaderdebugger-configurator.exe",
    "frame_debugger_native": "Nvda.Graphics.FrameDebugger.Native.dll",
    "frame_debugger_d3d12": "Nvda.Graphics.FrameDebuggerUi.D3D12.Native.dll",
    "frame_debugger_vulkan": "Nvda.Graphics.FrameDebuggerUi.Vulkan.Native.dll",
    "frame_debugger_opengl": "Nvda.Graphics.FrameDebuggerUi.OpenGL.Native.dll",
    "frame_debugger_common": "Nvda.Graphics.FrameDebuggerUi.Common.Native.dll",
    "pylon_replay_plugin": "PylonReplay_PluginInterface.dll",
    "battle_plugin": "Plugins/BattlePlugin/BattlePlugin.dll",
    "pylon_plugin": "Plugins/PylonPlugin/PylonPlugin.dll",
    "pylon_frame_debugger_plugin": "Plugins/PylonFrameDebuggerPlugin/PylonFrameDebuggerPlugin.dll",
    "shader_debugger_plugin": "Plugins/ShaderDebuggerPlugin.dll",
    "warpviz_plugin": "Plugins/WarpVizPlugin/WarpVizPlugin.dll",
}

DEFAULT_STRING_PATTERNS = [
    r"ApiInspector|RootParameter|DescriptorState|EventDetails|PixelHistory",
    r"Shader|Pipeline|PSO|RenderTarget|DepthStencil|UAV|SRV|CBV",
    r"MethodMap|TryGetMethodHandler|Message buffer|slot|ticket|BinaryReplay",
    r"replay-screenshot|perf-report|metadata|resource|dump",
]

DEFAULT_FUNCTION_PATTERNS = [
    r"ApiInspector|RootParameter|Descriptor|EventDetails|Pixel",
    r"Shader|Pipeline|RenderTarget|Resource|Replay",
]


@dataclass
class IdaInstall:
    root: Path
    exe: Path
    edition: str
    version_hint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "exe": str(self.exe),
            "edition": self.edition,
            "version_hint": self.version_hint,
        }


def _version_hint(path: Path) -> str:
    m = re.search(r"(\d+\.\d+)", path.name)
    return m.group(1) if m else ""


def _edition(path: Path) -> str:
    n = path.name.lower()
    if "professional" in n:
        return "professional"
    if "home" in n:
        return "home"
    if "free" in n:
        return "free"
    return "unknown"


def _candidate_exes(root: Path) -> list[Path]:
    # IDA 9.x ships idat.exe for text/headless mode. Some older layouts use
    # idat64.exe; include both so overrides remain useful.
    names = ("idat64.exe", "idat.exe", "ida64.exe", "ida.exe")
    return [root / n for n in names if (root / n).is_file()]


def discover_ida_installs() -> list[IdaInstall]:
    candidates: list[Path] = []
    override = os.environ.get(IDA_ENV)
    if override:
        p = Path(override)
        candidates.append(p.parent if p.is_file() else p)

    for root in _COMMON_IDA_ROOTS:
        p = Path(root)
        if p.is_dir():
            candidates.append(p)

    # Also scan top-level Program Files dirs for future version names.
    for base in (Path(r"C:\Program Files"), Path(r"C:\Program Files (x86)")):
        if not base.is_dir():
            continue
        try:
            for child in base.iterdir():
                if child.is_dir() and re.search(r"IDA|Hex-Rays|HexRays", child.name, re.I):
                    candidates.append(child)
        except OSError:
            pass

    seen: set[Path] = set()
    installs: list[IdaInstall] = []
    for root in candidates:
        try:
            root = root.resolve()
        except OSError:
            continue
        if root in seen:
            continue
        seen.add(root)
        exes = _candidate_exes(root)
        if not exes:
            continue
        # Prefer text-mode IDA for headless automation.
        exe = next((p for p in exes if p.name.lower().startswith("idat")), exes[0])
        installs.append(
            IdaInstall(
                root=root,
                exe=exe,
                edition=_edition(root),
                version_hint=_version_hint(root),
            )
        )

    edition_rank = {"professional": 0, "home": 1, "free": 2, "unknown": 3}

    def key(inst: IdaInstall) -> tuple[int, tuple[int, ...]]:
        nums = tuple(int(x) for x in re.findall(r"\d+", inst.version_hint))
        return (edition_rank.get(inst.edition, 9), tuple(-x for x in nums))

    return sorted(installs, key=key)


def best_ida() -> IdaInstall | None:
    installs = discover_ida_installs()
    return installs[0] if installs else None


def _sha256_file(path: Path) -> str:
    h = sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_binary(target: str) -> Path:
    p = Path(target).expanduser()
    if p.is_file():
        return p.resolve()
    key = target.strip()
    if key not in _TARGET_BINARIES:
        raise FileNotFoundError(
            f"{target!r} is not a file and not a known target. Known targets: {sorted(_TARGET_BINARIES)}"
        )
    s = get_settings()
    bd = host_bin_dir(s.install_root)
    if bd is None:
        raise FileNotFoundError("Nsight Graphics host bin dir not found")
    out = bd / Path(_TARGET_BINARIES[key])
    if not out.is_file():
        raise FileNotFoundError(f"known target {key!r} not found at {out}")
    return out.resolve()


def cache_dir_for_binary(binary: Path) -> Path:
    s = get_settings()
    digest = _sha256_file(binary)[:12]
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", binary.name)
    return s.ensure_cache_dir() / "ida" / f"{stem}_{digest}"


def exporter_script() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    script = repo_root / "tools" / "ida_export_facts.py"
    if not script.is_file():
        raise FileNotFoundError(f"IDA exporter script not found: {script}")
    return script


async def analyze_binary(
    target: str,
    *,
    ida_path: str | None = None,
    force: bool = False,
    string_patterns: list[str] | None = None,
    function_patterns: list[str] | None = None,
    selected_functions: list[str] | None = None,
    max_strings: int = 500,
    max_functions: int = 200,
    max_decompile: int = 40,
    max_pseudocode_chars: int = 16000,
    timeout_sec: int | None = 1800,
) -> dict[str, Any]:
    """Run IDA headless against ``target`` and return the export summary.

    ``target`` can be a filesystem path or one of ``known_targets()``.
    """
    binary = resolve_binary(target)
    ida = _resolve_ida(ida_path)
    out_dir = cache_dir_for_binary(binary)
    out_dir.mkdir(parents=True, exist_ok=True)
    facts_path = out_dir / "facts.json"
    log_path = out_dir / "ida.log"
    cfg_path = out_dir / "export_config.json"
    db_path = out_dir / f"{binary.stem}.i64"

    custom_export = any(
        x is not None
        for x in (string_patterns, function_patterns, selected_functions)
    )

    if facts_path.is_file() and not force and not custom_export:
        facts = load_facts(facts_path)
        return {
            "ok": bool(facts.get("ok", True)),
            "cached": True,
            "target": target,
            "binary": str(binary),
            "binary_sha256": _sha256_file(binary),
            "cache_dir": str(out_dir),
            "facts_path": str(facts_path),
            "log_path": str(log_path),
            "summary": summarize_facts(facts),
        }

    if force:
        for p in out_dir.glob(f"{binary.stem}.*"):
            if p.suffix.lower() in {".i64", ".id0", ".id1", ".id2", ".nam", ".til"}:
                try:
                    p.unlink()
                except OSError:
                    pass
    for p in (facts_path, log_path):
        try:
            p.unlink()
        except OSError:
            pass

    cfg = {
        "output_json": str(facts_path),
        "string_patterns": string_patterns if string_patterns is not None else DEFAULT_STRING_PATTERNS,
        "function_patterns": function_patterns if function_patterns is not None else DEFAULT_FUNCTION_PATTERNS,
        "selected_functions": selected_functions or [],
        "max_strings": max_strings,
        "max_xrefs_per_string": 40,
        "max_functions": max_functions,
        "max_decompile": max_decompile,
        "max_pseudocode_chars": max_pseudocode_chars,
        "max_entries": 300,
    }
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    script_arg = f"{exporter_script()} {cfg_path}"
    open_existing_database = db_path.is_file() and not force
    argv = [
        str(ida.exe),
        "-A",
        f"-L{log_path}",
        f"-S{script_arg}",
    ]
    if open_existing_database:
        argv.append(str(db_path))
    else:
        argv.insert(3, f"-o{db_path}")
        argv.append(str(binary))
    t0 = time.monotonic()
    res = await run_async(argv, tool="idat", timeout=timeout_sec)
    duration = round(time.monotonic() - t0, 3)

    facts = load_facts(facts_path) if facts_path.is_file() else {}
    ok = res.ok and bool(facts.get("ok", False))
    return {
        **result_to_dict(res, tail=8000),
        "ok": ok,
        "ida": ida.to_dict(),
        "cached": False,
        "target": target,
        "binary": str(binary),
        "binary_sha256": _sha256_file(binary),
        "cache_dir": str(out_dir),
        "facts_path": str(facts_path) if facts_path.is_file() else None,
        "log_path": str(log_path),
        "database_path": str(db_path) if db_path.exists() else None,
        "duration_sec": duration,
        "summary": summarize_facts(facts) if facts else None,
        "ida_log_tail": log_path.read_text(encoding="utf-8", errors="replace")[-8000:] if log_path.is_file() else "",
    }


def _resolve_ida(ida_path: str | None) -> IdaInstall:
    if ida_path:
        p = Path(ida_path)
        exe = p if p.is_file() else next(iter(_candidate_exes(p)), None)
        if exe is None or not exe.is_file():
            raise FileNotFoundError(f"IDA executable not found at {ida_path}")
        root = exe.parent
        return IdaInstall(root=root, exe=exe.resolve(), edition=_edition(root), version_hint=_version_hint(root))
    ida = best_ida()
    if ida is None:
        raise FileNotFoundError(
            f"IDA headless executable not found. Set {IDA_ENV}=<idat.exe or IDA install dir>."
        )
    return ida


def load_facts(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def summarize_facts(facts: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": facts.get("schema"),
        "input_path": facts.get("input_path"),
        "input_sha256": facts.get("input_sha256"),
        "ida_version": (facts.get("ida") or {}).get("version"),
        "segment_count": len(facts.get("segments") or []),
        "entry_count": len(facts.get("entries") or []),
        "function_count": facts.get("function_count"),
        "string_hit_count": len(facts.get("strings") or []),
        "functions_by_name_count": len(facts.get("functions_by_name") or []),
        "selected_function_count": len(facts.get("selected_functions") or []),
        "decompiled_count": len(facts.get("decompiled") or []),
        "decompiler_error": facts.get("decompiler_error"),
    }


def search_facts(path: str | Path, pattern: str, *, limit: int = 100) -> dict[str, Any]:
    facts = load_facts(path)
    rx = re.compile(pattern, re.IGNORECASE)
    hits: list[dict[str, Any]] = []

    def add(section: str, item: dict[str, Any], text: str) -> bool:
        if not rx.search(text):
            return False
        hits.append({"section": section, "item": item})
        return len(hits) >= limit

    for item in facts.get("strings") or []:
        text = item.get("value", "")
        if add("strings", item, text):
            break
    if len(hits) < limit:
        for item in facts.get("functions_by_name") or []:
            text = item.get("name", "")
            if add("functions_by_name", item, text):
                break
    if len(hits) < limit:
        for item in facts.get("selected_functions") or []:
            text = item.get("name", "")
            if add("selected_functions", item, text):
                break
    if len(hits) < limit:
        for item in facts.get("decompiled") or []:
            text = "\n".join([item.get("name", ""), item.get("pseudocode", ""), item.get("error", "")])
            if add("decompiled", item, text):
                break

    return {
        "ok": True,
        "facts_path": str(Path(path)),
        "pattern": pattern,
        "hits": hits,
        "count": len(hits),
        "truncated": len(hits) >= limit,
    }


def known_targets() -> dict[str, str]:
    return dict(_TARGET_BINARIES)


def command_preview(target: str, *, ida_path: str | None = None) -> dict[str, Any]:
    """Return the command shape for debugging without running IDA."""
    binary = resolve_binary(target)
    ida = _resolve_ida(ida_path)
    out_dir = cache_dir_for_binary(binary)
    return {
        "ok": True,
        "ida": ida.to_dict(),
        "binary": str(binary),
        "cache_dir": str(out_dir),
        "command_shape": [
            str(ida.exe),
            "-A",
            "-L<cache>/ida.log",
            "-o<cache>/<binary>.i64",
            "-S<repo>/tools/ida_export_facts.py <cache>/export_config.json",
            str(binary),
        ],
        "shell_preview": " ".join(shlex.quote(x) for x in [
            str(ida.exe),
            "-A",
            "-L<cache>/ida.log",
            "-o<cache>/<binary>.i64",
            "-S<repo>/tools/ida_export_facts.py <cache>/export_config.json",
            str(binary),
        ]),
    }


def run_ida_version(ida_path: str | None = None) -> dict[str, Any]:
    """Best-effort version probe using the selected IDA executable."""
    ida = _resolve_ida(ida_path)
    try:
        proc = subprocess.run(
            [str(ida.exe), "-h"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        return {
            "ok": proc.returncode == 0,
            "ida": ida.to_dict(),
            "returncode": proc.returncode,
            "stdout_tail": proc.stdout[-2000:],
            "stderr_tail": proc.stderr[-2000:],
        }
    except Exception as exc:
        return {"ok": False, "ida": ida.to_dict(), "error": str(exc)}
