"""IDA script: dump xrefs to a function, plus decompile other targets."""

import json
import sys
from pathlib import Path

import ida_auto
import ida_funcs
import ida_hexrays
import ida_lines
import ida_xref
import idaapi
import idautils
import idc


def main():
    argv = list(getattr(idc, "ARGV", []) or [])
    if len(argv) <= 1:
        argv = list(sys.argv)
    out_path = Path(argv[1])
    xref_va = int(argv[2], 16)
    decompile_vas = [int(a, 16) for a in argv[3:]]
    print(f"[xrefs_filter] out_path={out_path}", flush=True)
    print(f"[xrefs_filter] xref target VA=0x{xref_va:x}", flush=True)
    print(f"[xrefs_filter] decompile VAs: {[hex(v) for v in decompile_vas]}", flush=True)

    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()

    out = {"image_base": hex(idaapi.get_imagebase()), "xrefs": [], "decompiled": []}

    # XRefs to xref_va — list every code-ref and the calling function.
    for xref in idautils.CodeRefsTo(xref_va, 0):
        f = ida_funcs.get_func(xref)
        out["xrefs"].append({
            "from_ea": hex(xref),
            "from_function": ida_funcs.get_func_name(f.start_ea) if f else None,
            "from_function_start": hex(f.start_ea) if f else None,
            "from_function_end": hex(f.end_ea) if f else None,
            "disasm": ida_lines.tag_remove(idc.generate_disasm_line(xref, 0) or ""),
        })

    # Decompile each requested function.
    for va in decompile_vas:
        f = ida_funcs.get_func(va)
        if not f:
            out["decompiled"].append({"target_va": hex(va), "error": "no function"})
            continue
        try:
            cfunc = ida_hexrays.decompile(f.start_ea)
            if cfunc is None:
                out["decompiled"].append({
                    "target_va": hex(va),
                    "function_name": ida_funcs.get_func_name(f.start_ea),
                    "function_start": hex(f.start_ea),
                    "function_end": hex(f.end_ea),
                    "error": "decompile returned None",
                })
                continue
            lines = []
            try:
                for sl in cfunc.get_pseudocode():
                    lines.append(ida_lines.tag_remove(sl.line))
            except Exception:
                pass
            text = "\n".join(lines) if lines else str(cfunc)
            if len(text) > 80000:
                text = text[:80000] + "\n...<truncated>"
            out["decompiled"].append({
                "target_va": hex(va),
                "function_name": ida_funcs.get_func_name(f.start_ea),
                "function_start": hex(f.start_ea),
                "function_end": hex(f.end_ea),
                "size": f.end_ea - f.start_ea,
                "pseudocode": text,
            })
        except Exception as exc:
            out["decompiled"].append({
                "target_va": hex(va),
                "error": f"decompile exception: {type(exc).__name__}: {exc}",
            })

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"[xrefs_filter] wrote {out_path}: xrefs={len(out['xrefs'])} decompiled={len(out['decompiled'])}", flush=True)
    idc.qexit(0)


main()
