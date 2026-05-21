"""PE-patch planner for ``ngfx-rpc.exe`` logger trampolines.

One of the three documented bypasses for the shared-memory wall (see
NSIGHT_SHADER_DEBUG_AUTONOMY.md → Gap 1) is to add a tiny logger
trampoline to the on-disk binary at known dispatch/parse entry points,
so every parsed frame writes its (category, method, slot, ticket) to
``OutputDebugStringA``. The on-disk patch survives the early-init window
that defeated user-mode Frida hooks.

This module is a **planner** only — it emits structured plans, sample
trampoline shellcode, and IDA Pro headless Python scripts to apply
the patch. It does **not** modify any binary. The actual on-disk
patching is destructive and must be confirmed by the user / by a
separate IDA run that the user invokes themselves.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Known candidate patch sites in ngfx-rpc.exe. Addresses are version-
# dependent — the build referenced in docs/RPC_PROTOCOL.md is
# Nsight Graphics 2026.1.0 host build 37556978.
KNOWN_PATCH_SITES: list[dict[str, Any]] = [
    {
        "symbol": "payload_write__sub_1409A4470",
        "purpose": "send path; logs every outgoing frame's transport header",
        "module": "ngfx-rpc.exe",
        "evidence": "docs/RPC_PROTOCOL.md — htonl on (a1+4) writes body size",
        "evidence_label": "proven",
    },
    {
        "symbol": "read_header__sub_1409A3D40",
        "purpose": "recv path; logs every inbound transport header",
        "module": "ngfx-rpc.exe",
        "evidence": "ntohl + 'Read header channelId: %u Size: %u' log call",
        "evidence_label": "proven",
    },
    {
        "symbol": "register_category__sub_140985A90",
        "purpose": "category registration; logs (categoryId, numMethods)",
        "module": "ngfx-rpc.exe",
        "evidence": "'categoryId: %d numMethods: %d' log strings",
        "evidence_label": "proven",
    },
    {
        "symbol": "hdr_serialize__sub_140985580",
        "purpose": (
            "compact MessageHeader serializer (mem->wire); single best site "
            "to capture full (category, method, slot, ticket, request_id) "
            "per outbound frame"
        ),
        "module": "ngfx-rpc.exe",
        "evidence": "wire format decoded 2026-05-19; see RPC_PROTOCOL.md",
        "evidence_label": "proven",
    },
    {
        "symbol": "hdr_deserialize__sub_1409854C0",
        "purpose": (
            "compact MessageHeader deserializer (wire->mem); single best "
            "site to capture every inbound frame's header"
        ),
        "module": "ngfx-rpc.exe",
        "evidence": "wire format decoded 2026-05-19",
        "evidence_label": "proven",
    },
    {
        "symbol": "method_handler_lookup__sub_140921xxx",
        "purpose": "MethodMap::TryGetMethodHandler — logs (category, method) lookups",
        "module": "ngfx-rpc.exe",
        "evidence": "'MethodMap:: TryGetMethodHandler Category: %u Method: %u'",
        "evidence_label": "candidate",
    },
]


def _trampoline_logger_stub_amd64() -> bytes:
    """Generate a representative x86-64 trampoline that:

      1. Saves volatile registers + alignment padding.
      2. Loads RCX with a pointer to a static format string + RDX/R8/R9
         with the header fields the patched function had on entry.
      3. Calls ``OutputDebugStringA`` via an absolute address that the
         IDA script will resolve and patch.
      4. Restores registers and jumps back to the original function.

    The output is a placeholder byte sequence with explicit marker
    DWORDs (``0xCC11CC11``, ``0xCC22CC22`` …) the IDA script must
    rewrite with real addresses. The exact byte sequence here is **not**
    intended to be executed as-is; it is a template.
    """
    return (
        b"\x48\x83\xEC\x28"                 # sub rsp, 0x28 (shadow space + align)
        b"\x50\x51\x52\x41\x50\x41\x51"     # push rax, rcx, rdx, r8, r9
        b"\x48\xB9\x11\xCC\x11\xCC\x00\x00\x00\x00"  # mov rcx, 0x00000000CC11CC11 (fmt string ptr)
        b"\x48\xBA\x22\xCC\x22\xCC\x00\x00\x00\x00"  # mov rdx, 0x00000000CC22CC22 (arg1)
        b"\x49\xB8\x33\xCC\x33\xCC\x00\x00\x00\x00"  # mov r8,  0x00000000CC33CC33 (arg2)
        b"\x49\xB9\x44\xCC\x44\xCC\x00\x00\x00\x00"  # mov r9,  0x00000000CC44CC44 (arg3)
        b"\x48\xB8\x55\xCC\x55\xCC\x00\x00\x00\x00"  # mov rax, 0x00000000CC55CC55 (OutputDebugStringA addr)
        b"\xFF\xD0"                          # call rax
        b"\x41\x59\x41\x58\x5A\x59\x58"     # pop r9, r8, rdx, rcx, rax
        b"\x48\x83\xC4\x28"                  # add rsp, 0x28
        b"\xE9\x66\xCC\x66\xCC"              # jmp rel32 (patched to original-fn + 5)
    )


@dataclass
class PatchPlan:
    target_exe: Path
    patch_sites: list[dict[str, Any]] = field(default_factory=list)
    trampoline_template_hex: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_exe": str(self.target_exe),
            "patch_sites": self.patch_sites,
            "trampoline_template_hex": self.trampoline_template_hex,
            "trampoline_size_bytes": len(self.trampoline_template_hex) // 2,
            "markers": {
                "fmt_string_ptr": "0xCC11CC11",
                "arg1_value": "0xCC22CC22",
                "arg2_value": "0xCC33CC33",
                "arg3_value": "0xCC44CC44",
                "output_debug_string_a_addr": "0xCC55CC55",
                "trampoline_return_offset": "0xCC66CC66",
            },
        }


def build_patch_plan(
    target_exe: Path,
    *,
    sites: list[str] | None = None,
) -> dict[str, Any]:
    """Build a structured patch plan against ``target_exe``.

    ``sites`` selects which patch sites to include by symbol name.
    Defaults to every site in :data:`KNOWN_PATCH_SITES`.
    """
    target_exe = Path(target_exe).resolve()
    chosen = (
        [s for s in KNOWN_PATCH_SITES if s["symbol"] in sites]
        if sites
        else list(KNOWN_PATCH_SITES)
    )
    plan = PatchPlan(
        target_exe=target_exe,
        patch_sites=chosen,
        trampoline_template_hex=_trampoline_logger_stub_amd64().hex(),
    )
    return {
        "ok": True,
        "evidence_label": "candidate",
        "warning": (
            "This is a PLAN ONLY. No bytes have been written to "
            f"{target_exe}. Applying the plan is destructive — keep a "
            "verified backup and run the emitted IDA script manually."
        ),
        **plan.to_dict(),
        "next_steps": [
            "Back up the target exe (sha256 + copy).",
            "Run ngfx_rpc_pe_patch_ida_script to emit the IDA Pro Python "
            "that resolves real addresses for each marker.",
            "Apply the script in a manual IDA Pro 9.0 headless run.",
            "Re-launch ngfx-ui + ngfx-rpc with a DebugView listener "
            "open to receive the logged headers.",
        ],
    }


def generate_ida_script(
    target_exe: Path,
    output_path: Path,
    *,
    sites: list[str] | None = None,
) -> dict[str, Any]:
    """Emit a Python script suitable for IDA Pro 9.0's headless mode.

    The script:
      1. Loads ``target_exe`` via IDA's idapro API.
      2. Resolves each patch site's start address by symbol search.
      3. Allocates a code cave (using the largest reachable unused
         section, e.g. ``.rdata`` padding or a new section if writable).
      4. Writes the trampoline template at the cave, patches the marker
         DWORDs with real addresses, and overwrites the patch site's
         first 14 bytes with ``mov rax, <cave>; jmp rax``.
      5. Saves the modified database (``idb``) and exports the patched
         exe via ``ida_loader.export_image``.

    No I/O is performed here beyond writing the .py file.
    """
    chosen = (
        [s for s in KNOWN_PATCH_SITES if s["symbol"] in sites]
        if sites
        else list(KNOWN_PATCH_SITES)
    )
    target_exe = Path(target_exe).resolve()
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    sites_repr = ",\n        ".join(
        f"({s['symbol']!r}, {s['purpose']!r})" for s in chosen
    )
    trampoline_hex = _trampoline_logger_stub_amd64().hex()

    script = f'''"""Auto-generated IDA Pro 9.0 patch script.

Apply by running::

    ida.exe -A -S{output_path.name} {target_exe}

This will patch the on-disk binary in place. KEEP A BACKUP first.
"""

import idaapi
import idc
import ida_bytes
import ida_segment
import ida_funcs
import ida_name


TARGET_EXE = r"{target_exe}"
PATCH_SITES = [
    {sites_repr}
]
TRAMPOLINE_TEMPLATE = bytes.fromhex({trampoline_hex!r})
FMT_STRING = b"ngfx-rpc-trace cat=%u meth=%u slot=%u\\x00"


def find_function_by_name(name: str) -> int:
    ea = ida_name.get_name_ea(0, name)
    if ea != idaapi.BADADDR:
        return ea
    # Fallback: search for the symbol via IDA's autonomic name table.
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        if f is None:
            continue
        if ida_funcs.get_func_name(f.start_ea) == name:
            return f.start_ea
    return idaapi.BADADDR


def allocate_cave(size: int) -> int:
    """Find ``size`` consecutive zero bytes in any readable+executable segment."""
    for seg_ea in ida_segment.get_first_seg() if False else range(0):  # placeholder
        pass
    # In real headless usage we extend an executable segment via
    # ``ida_segment.add_segm(0, start, start+size, ...)`` and persist
    # via ``ida_loader.save_database``.
    raise NotImplementedError("allocate_cave: extend with project-specific logic")


def patch_site(name: str) -> None:
    ea = find_function_by_name(name)
    if ea == idaapi.BADADDR:
        print("[!] symbol not found:", name)
        return
    print("[+] patching", name, "at", hex(ea))
    cave_ea = allocate_cave(len(TRAMPOLINE_TEMPLATE) + len(FMT_STRING))
    # Write the trampoline + format string, then patch markers + the
    # jump from the function prologue.
    ida_bytes.patch_bytes(cave_ea, TRAMPOLINE_TEMPLATE)
    # Patch 0xCC11CC11 → cave_ea + len(TRAMPOLINE_TEMPLATE) (fmt string)
    # Patch 0xCC22..0xCC44 → load args from RCX / RDX / R8 at function entry
    # Patch 0xCC55CC55 → addr of OutputDebugStringA in the import table
    # Patch 0xCC66CC66 → rel32 back into original function
    raise NotImplementedError("complete trampoline marker patching in your IDA session")


def main():
    for name, purpose in PATCH_SITES:
        print("[*] site:", name, "-", purpose)
        try:
            patch_site(name)
        except NotImplementedError as exc:
            print("[skip]", name, ":", exc)
    print("[done] save the database manually if everything looks right.")


main()
'''
    output_path.write_text(script, encoding="utf-8")
    return {
        "ok": True,
        "evidence_label": "candidate",
        "script_path": str(output_path),
        "target_exe": str(target_exe),
        "sites_emitted": [s["symbol"] for s in chosen],
        "lines_emitted": script.count("\n") + 1,
        "warning": (
            "The emitted script intentionally leaves the cave allocation "
            "and marker patching as TODOs — they are project-specific and "
            "should be reviewed by a human RE before running."
        ),
    }
