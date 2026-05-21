"""IDA Pro headless exporter for nsight-graphics-mcp.

Run by IDA, not by regular Python. The wrapper in
``nsight_graphics_mcp.ida_re`` invokes this with::

    idat.exe -A -L<log> -S"<this_script> <config.json>" <binary>

The script writes a compact JSON fact file: matching strings, xrefs to those
strings, functions selected by name/address/xref, and bounded Hex-Rays
pseudocode where the local IDA license supports decompilation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import traceback
from pathlib import Path

import ida_auto
import ida_bytes
import ida_entry
import ida_funcs
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_name
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc


def _argv() -> list[str]:
    argv = list(getattr(idc, "ARGV", []) or [])
    if len(argv) <= 1:
        argv = list(sys.argv)
    return argv


def _load_config() -> dict:
    argv = _argv()
    if len(argv) < 2:
        raise RuntimeError(f"expected config path in idc.ARGV/sys.argv, got {argv!r}")
    path = Path(argv[1])
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _sha256(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _json_safe_text(s: object, max_chars: int = 4096) -> str:
    text = str(s)
    if len(text) > max_chars:
        return text[:max_chars] + "...<truncated>"
    return text


def _compile_patterns(patterns: list[str]) -> list[re.Pattern]:
    out = []
    for pat in patterns:
        try:
            out.append(re.compile(pat, re.IGNORECASE))
        except re.error:
            pass
    return out


def _matches_any(text: str, patterns: list[re.Pattern]) -> bool:
    return any(rx.search(text) for rx in patterns)


def _func_dict(ea: int) -> dict | None:
    f = ida_funcs.get_func(ea)
    if not f:
        return None
    return {
        "ea": f"0x{f.start_ea:x}",
        "end_ea": f"0x{f.end_ea:x}",
        "name": ida_funcs.get_func_name(f.start_ea) or ida_name.get_name(f.start_ea),
        "size": int(f.end_ea - f.start_ea),
    }


def _current_segments() -> list[dict]:
    out = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue
        out.append({
            "name": ida_segment.get_segm_name(seg),
            "start_ea": f"0x{seg.start_ea:x}",
            "end_ea": f"0x{seg.end_ea:x}",
            "size": int(seg.end_ea - seg.start_ea),
            "perm": int(seg.perm),
        })
    return out


def _entries(limit: int) -> list[dict]:
    out = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        name = ida_entry.get_entry_name(ordinal)
        out.append({"ordinal": int(ordinal), "ea": f"0x{ea:x}", "name": name})
        if len(out) >= limit:
            break
    return out


def _ida_info() -> dict:
    info = {"version": ida_kernwin.get_kernel_version()}
    try:
        info["procname"] = ida_ida.inf_get_procname()
    except Exception:
        info["procname"] = None
    try:
        info["is_64bit"] = bool(ida_ida.inf_is_64bit())
    except Exception:
        info["is_64bit"] = None
    try:
        info["filetype"] = int(ida_ida.inf_get_filetype())
    except Exception:
        info["filetype"] = None
    return info


def _string_value(s) -> str:
    try:
        return str(s)
    except Exception:
        try:
            return ida_bytes.get_strlit_contents(s.ea, s.length, s.type).decode("utf-8", "replace")
        except Exception:
            return ""


def _collect_strings(patterns: list[re.Pattern], *, max_strings: int, max_xrefs_per_string: int) -> tuple[list[dict], dict[int, dict]]:
    strings = idautils.Strings(default_setup=True)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16])

    hits: list[dict] = []
    funcs_by_ea: dict[int, dict] = {}
    for s in strings:
        value = _string_value(s)
        if not value or (patterns and not _matches_any(value, patterns)):
            continue
        xrefs = []
        for xr in idautils.XrefsTo(s.ea, 0):
            fd = _func_dict(xr.frm)
            rec = {
                "from": f"0x{xr.frm:x}",
                "type": int(xr.type),
                "function": fd,
            }
            xrefs.append(rec)
            if fd:
                funcs_by_ea[int(fd["ea"], 16)] = fd
            if len(xrefs) >= max_xrefs_per_string:
                break
        hits.append({
            "ea": f"0x{s.ea:x}",
            "length": int(getattr(s, "length", 0) or 0),
            "type": int(getattr(s, "type", 0) or 0),
            "value": _json_safe_text(value, 2000),
            "xrefs": xrefs,
        })
        if len(hits) >= max_strings:
            break
    return hits, funcs_by_ea


def _collect_functions_by_name(patterns: list[re.Pattern], limit: int) -> list[dict]:
    out = []
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea) or ida_name.get_name(ea) or ""
        if patterns and not _matches_any(name, patterns):
            continue
        fd = _func_dict(ea)
        if fd:
            out.append(fd)
        if len(out) >= limit:
            break
    return out


def _parse_ea_or_name(selector: str) -> int | None:
    s = selector.strip()
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        if s.isdigit():
            return int(s, 10)
    except ValueError:
        pass
    ea = ida_name.get_name_ea(idaapi.BADADDR, s)
    if ea != idaapi.BADADDR:
        f = ida_funcs.get_func(ea)
        return f.start_ea if f else ea
    return None


def _decompile_functions(functions: list[dict], *, max_functions: int, max_chars_per_function: int) -> tuple[list[dict], str | None]:
    if max_functions <= 0:
        return [], None
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return [], "Hex-Rays decompiler plugin is not available for this IDA install/license."
    except Exception as exc:
        return [], f"Hex-Rays init failed: {exc}"

    out = []
    seen: set[int] = set()
    for fd in functions:
        try:
            ea = int(str(fd["ea"]), 16)
        except Exception:
            continue
        f = ida_funcs.get_func(ea)
        if not f or f.start_ea in seen:
            continue
        seen.add(f.start_ea)
        try:
            cfunc = ida_hexrays.decompile(f.start_ea)
            lines = []
            if cfunc:
                for sl in cfunc.get_pseudocode():
                    lines.append(ida_lines_tag_remove(sl.line))
            text = "\n".join(lines)
            out.append({
                **(_func_dict(f.start_ea) or fd),
                "ok": bool(cfunc),
                "pseudocode": _json_safe_text(text, max_chars_per_function),
                "truncated": len(text) > max_chars_per_function,
            })
        except Exception as exc:
            out.append({**(_func_dict(f.start_ea) or fd), "ok": False, "error": str(exc)})
        if len(out) >= max_functions:
            break
    return out, None


def ida_lines_tag_remove(line: str) -> str:
    try:
        import ida_lines

        return ida_lines.tag_remove(line)
    except Exception:
        return line


def main() -> int:
    cfg = _load_config()
    out_path = Path(cfg["output_json"])
    out_path.parent.mkdir(parents=True, exist_ok=True)

    ida_auto.auto_wait()

    input_path = ida_nalt.get_input_file_path()
    string_patterns = _compile_patterns(list(cfg.get("string_patterns") or []))
    function_patterns = _compile_patterns(list(cfg.get("function_patterns") or []))

    max_strings = int(cfg.get("max_strings", 500))
    max_xrefs = int(cfg.get("max_xrefs_per_string", 40))
    max_functions = int(cfg.get("max_functions", 200))
    max_decompile = int(cfg.get("max_decompile", 40))
    max_pseudocode_chars = int(cfg.get("max_pseudocode_chars", 16000))

    strings, xref_funcs = _collect_strings(
        string_patterns,
        max_strings=max_strings,
        max_xrefs_per_string=max_xrefs,
    )
    name_funcs = _collect_functions_by_name(function_patterns, max_functions)

    selected: dict[int, dict] = {}
    explicit_order: list[int] = []
    for fd in xref_funcs.values():
        selected[int(fd["ea"], 16)] = fd
    for fd in name_funcs:
        selected[int(fd["ea"], 16)] = fd
    for selector in cfg.get("selected_functions") or []:
        ea = _parse_ea_or_name(str(selector))
        if ea is None:
            continue
        f = ida_funcs.get_func(ea)
        fd = _func_dict(f.start_ea if f else ea)
        if fd:
            key = int(fd["ea"], 16)
            selected[key] = fd
            explicit_order.append(key)

    ordered_keys: list[int] = []
    seen_keys: set[int] = set()
    for key in explicit_order:
        if key not in seen_keys and key in selected:
            ordered_keys.append(key)
            seen_keys.add(key)
    for key in sorted(selected):
        if key not in seen_keys:
            ordered_keys.append(key)
            seen_keys.add(key)
    selected_functions = [selected[k] for k in ordered_keys[:max_functions]]
    decompiled, decompiler_error = _decompile_functions(
        selected_functions,
        max_functions=max_decompile,
        max_chars_per_function=max_pseudocode_chars,
    )

    facts = {
        "ok": True,
        "schema": "nsight-graphics-mcp.ida-facts.v1",
        "input_path": input_path,
        "input_sha256": _sha256(input_path) if input_path else None,
        "ida": _ida_info(),
        "imagebase": f"0x{idaapi.get_imagebase():x}",
        "segments": _current_segments(),
        "entries": _entries(int(cfg.get("max_entries", 300))),
        "function_count": sum(1 for _ in idautils.Functions()),
        "string_patterns": list(cfg.get("string_patterns") or []),
        "function_patterns": list(cfg.get("function_patterns") or []),
        "strings": strings,
        "functions_by_name": name_funcs,
        "selected_functions": selected_functions,
        "decompiler_error": decompiler_error,
        "decompiled": decompiled,
    }
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(facts, f, indent=2)
    return 0


try:
    rc = main()
except Exception as exc:
    cfg = {}
    try:
        cfg = _load_config()
        out_path = Path(cfg.get("output_json", "ida_export_error.json"))
    except Exception:
        out_path = Path(os.getcwd()) / "ida_export_error.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "ok": False,
                "error": str(exc),
                "traceback": traceback.format_exc(),
                "argv": _argv(),
            },
            f,
            indent=2,
        )
    rc = 1

idc.qexit(rc)
