"""IDA-side script: load existing .i64, decompile functions containing specific
addresses, write JSON output to a fixed path."""

import json
import os
import sys
from pathlib import Path

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_name
import idaapi
import idautils
import idc


def _argv():
    argv = list(getattr(idc, "ARGV", []) or [])
    if len(argv) <= 1:
        argv = list(sys.argv)
    return argv


def main():
    argv = _argv()
    out_path = Path(argv[1]) if len(argv) > 1 else Path("ida_fog_decompile_out.json")
    targets_va = [int(a, 16) for a in argv[2:]]
    print(f"[fog_decompile] out_path={out_path}", flush=True)
    print(f"[fog_decompile] target VAs: {[hex(t) for t in targets_va]}", flush=True)

    ida_auto.auto_wait()
    ok_init = ida_hexrays.init_hexrays_plugin()
    print(f"[fog_decompile] hexrays_init={ok_init}", flush=True)

    out = {"image_base": hex(idaapi.get_imagebase()), "results": []}

    for va in targets_va:
        entry = {"target_va": hex(va)}
        f = ida_funcs.get_func(va)
        if not f:
            entry["error"] = "no function at this VA"
            out["results"].append(entry)
            continue
        start = f.start_ea
        end = f.end_ea
        name = ida_funcs.get_func_name(start) or f"sub_{start:X}"
        entry["function_name"] = name
        entry["function_start"] = hex(start)
        entry["function_end"] = hex(end)
        entry["function_size"] = end - start
        # Decompile — IDA 9.0 API: str(cfunc) returns the pseudocode lines
        # joined with newlines; tag_remove strips colorisation tags.
        try:
            cfunc = ida_hexrays.decompile(start)
            if cfunc is None:
                entry["pseudocode"] = None
                entry["error"] = "decompile returned None"
            else:
                # Join all pseudocode lines explicitly — cfunc.get_pseudocode()
                # returns a vector of simpleline_t, each with a `.line` field.
                lines = []
                try:
                    pc = cfunc.get_pseudocode()
                    for sl in pc:
                        lines.append(ida_lines.tag_remove(sl.line))
                except Exception:
                    pass
                if not lines:
                    # Fallback — older API
                    lines = [str(cfunc)]
                text = "\n".join(lines)
                if len(text) > 80000:
                    text = text[:80000] + "\n...<truncated>"
                entry["pseudocode"] = text
        except Exception as exc:
            entry["error"] = f"decompile exception: {type(exc).__name__}: {exc}"
        # Code at exact VA (a few bytes)
        try:
            entry["bytes_at_va"] = bytes(idc.get_bytes(va, 16) or b"").hex()
            entry["disasm_line"] = ida_lines.tag_remove(idc.generate_disasm_line(va, 0) or "")
        except Exception as exc:
            entry["disasm_error"] = str(exc)
        out["results"].append(entry)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"[fog_decompile] wrote {out_path} with {len(out['results'])} entries", flush=True)
    idc.qexit(0)


main()
