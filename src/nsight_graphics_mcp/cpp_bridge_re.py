"""Reverse-engineering helpers for saved capture -> C++ Capture export.

Nsight's documented ``Generate C++ Capture`` CLI handles live application
launches. Saved ``.ngfx-gfxcap`` exports are driven by private UI/plugin code.
This module packages the IDA findings for that private bridge so MCP callers
can rerun the analysis and consume the current evidence without hand-reading
the decompiler cache.
"""

from __future__ import annotations

import base64
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

from . import ida_re, proto_descriptors, rpc_trace
from .config import host_bin_dir

BRIDGE_STRING_PATTERNS = [
    r"C\+\+ Capture|Generate C\+\+|CppCapture|CppCaptures|ngfx-cppcap|nsight-gfxcppcap",
    r"Serialization|Serialize|RequestSaveCapture|SaveCapture|HostSaveDirectory",
    r"FileTransfer|Transaction|FrameDebugger|Other Activity|PylonFusionActivityDialog",
]

BATTLE_SELECTED_FUNCTIONS = [
    # Command/action registration around C++ export.
    "0x18001BC20",
    # UI/output selection and auto export.
    "0x180020160",
    "0x18001F1B0",
    "0x180023A10",
    "0x180025560",
    # Actual serialize request path and its helper object.
    "0x180028880",
    "0x180041430",
    "0x1800414B0",
    "0x180041770",
    "0x180042000",
    "0x180042290",
    "0x1800427D0",
    "0x180042890",
    "0x180042EC0",
    "0x180042ED0",
    "0x180043150",
    # Artifact/output population.
    "0x18004F530",
    "0x18004F7A0",
    "0x180050D10",
    "0x180051040",
    "0x180051A80",
    "0x180052260",
    # Scripted activity step and command handler.
    "0x18006ACA0",
    "0x18006D1D0",
    "0x18006DA60",
]

PYLON_SELECTED_FUNCTIONS = [
    # Saved-capture platform launcher settings and helpers.
    "0x180110200",
    "0x1801114C0",
    # Saved capture details UI and activity selection.
    "0x180111D90",
    "0x1801156B0",
    "0x180115B40",
    "0x180116CD0",
    # Activity id/name mapping.
    "0x180119210",
    "0x18015D360",
    "0x18015E5A0",
    # Fusion activity dialog used by "Other Activity".
    "0x180147480",
    "0x180147C20",
    "0x1801486E0",
    "0x18016E7F0",
    "0x18016FB40",
]

_BATTLE_TARGET = "battle_plugin"
_PYLON_TARGET = "pylon_plugin"
_PYLON_PLATFORM = "win32"
_PYLON_REPLAY_EXE = "ngfx-replay.exe"
_PYLON_ACTIVITY_ID = 3
_PYLON_ACTIVITY_NAME = "Generate C++ Capture"
_PYLON_ACTIVITY_SHORT_NAME = "C++ Capture"
_PYLON_IMAGE_BASE = 0x180000000
_PYLON_SAVED_CAPTURE_START_VA = 0x180116CD0
_PYLON_SAVED_CAPTURE_START_RVA = _PYLON_SAVED_CAPTURE_START_VA - _PYLON_IMAGE_BASE

PYLON_PRIVATE_EXECUTOR_FUNCTIONS = {
    "environment_builder": {
        "ea": "0x180110200",
        "role": "Builds the semicolon-joined launcher environment string.",
    },
    "extra_args_builder": {
        "ea": "0x1801114C0",
        "role": "Flattens selected replay option pages into extra ngfx-replay args.",
    },
    "saved_capture_other_activity_start": {
        "ea": "0x180116CD0",
        "role": "Builds platform launcher settings and calls the private activity manager.",
    },
    "fusion_dialog_ctor": {
        "ea": "0x180147480",
        "role": "Selects the replay fusion activity by id and creates the settings widget.",
    },
    "fusion_dialog_accept": {
        "ea": "0x180147C20",
        "role": "Persists accepted launcher settings into JsonProject['launcher'].",
    },
    "activity_full_name": {
        "ea": "0x18015D360",
        "role": "Maps activity id 3 to Generate C++ Capture.",
    },
    "activity_short_name": {
        "ea": "0x18015E5A0",
        "role": "Maps activity id 3 to C++ Capture.",
    },
}

_STATIC_CALL_RE = re.compile(
    r"\(\*\((?P<return_type>[^()]+?)\s*\(__fastcall\s*\*\*\)\((?P<args>[^)]*)\)\)"
    r"\(\*\(_QWORD \*\)(?P<object>[^+)]*)\s*\+\s*(?P<offset>\d+)LL\)\)\((?P<call_args>[^;]+)\);"
)


def _pylon_quote_capture_arg(capture: str | Path) -> str:
    """Mirror Pylon's saved-capture argument shape: a quoted capture path."""
    return '"' + str(capture).replace('"', r'\"') + '"'


def _pylon_environment_string(environment: dict[str, str] | None) -> str:
    if not environment:
        return ""
    return ";".join(f"{key}={value}" for key, value in environment.items())


def pylon_saved_capture_handoff_preview(
    capture: str,
    *,
    additional_args: list[str] | None = None,
    environment: dict[str, str] | None = None,
    output_dir: str | None = None,
    platform: str = _PYLON_PLATFORM,
    install_host_dir: str | None = None,
) -> dict[str, Any]:
    """Build the saved-capture Generate C++ Capture handoff Pylon constructs.

    This is a deterministic preview of the in-process Pylon activity-manager
    settings recovered from ``PylonPlugin.dll``. It intentionally does not
    claim to execute a headless export; the private activity-manager call is
    still inside the Nsight process.
    """
    args = list(additional_args or [])
    host_dir = Path(install_host_dir) if install_host_dir else host_bin_dir()
    executable = str((host_dir / _PYLON_REPLAY_EXE).resolve()) if host_dir else _PYLON_REPLAY_EXE
    arguments = " ".join([_pylon_quote_capture_arg(capture), *args]).strip()
    env_string = _pylon_environment_string(environment)
    prefix = f"platform/{platform}"
    platform_settings = {
        f"{prefix}/device": "localhost",
        f"{prefix}/executable": executable,
        f"{prefix}/arguments": arguments,
        f"{prefix}/workingdir": "",
        f"{prefix}/environment": env_string,
    }
    return {
        "ok": True,
        "mode": "pylon_saved_capture_generate_cpp_handoff_preview",
        "headless_export_invoked": False,
        "activity": {
            "id": _PYLON_ACTIVITY_ID,
            "name": _PYLON_ACTIVITY_NAME,
            "short_name": _PYLON_ACTIVITY_SHORT_NAME,
        },
        "capture_path": str(capture),
        "platform": platform,
        "executable_name": _PYLON_REPLAY_EXE,
        "executable": executable,
        "arguments": arguments,
        "additional_args": args,
        "environment_string": env_string,
        "platform_settings": platform_settings,
        "project_launcher_object": {
            "key": "launcher",
            "value": platform_settings,
            "source": "PylonFusionActivityDialog persists accepted settings into JsonProject['launcher'].",
        },
        "output_directory_state": {
            "requested_output_dir": output_dir,
            "not_in_pylon_argv": True,
            "source": (
                "BattlePlugin chooses the C++ output directory through project service state or "
                "QSettings key Nvda::Graphics::Settings::SerializationSaveDirectory."
            ),
            "qsettings_key": "Serialization Save Directory",
        },
        "reverse_engineering_evidence": {
            "pylon_start_path": "PylonPlugin!sub_180116CD0",
            "additional_args_builder": "PylonPlugin!sub_1801114C0",
            "environment_builder": "PylonPlugin!sub_180110200",
            "dialog_launcher_persistence": "PylonPlugin!sub_180147C20 via sub_1801486E0",
            "activity_id_mapper": "PylonPlugin!sub_18015D360 maps id 3 to Generate C++ Capture.",
        },
        "remaining_gap": (
            "The final argv/config handoff is pinned. A fully headless export still needs an "
            "in-process call into Pylon's private activity manager or the direct FrameDebugger "
            "Core RPC session binding."
        ),
    }


def pylon_private_executor_re_report(
    *,
    battle_facts_path: str | None = None,
    pylon_facts_path: str | None = None,
) -> dict[str, Any]:
    """Return the build plan for the remaining private saved-C++ executor.

    This is narrower than :func:`saved_capture_cpp_bridge_report`: it focuses
    on what an MCP needs to become the executor, not just what was recovered.
    """
    bridge = saved_capture_cpp_bridge_report(
        battle_facts_path=battle_facts_path,
        pylon_facts_path=pylon_facts_path,
    )
    return {
        "ok": True,
        "status": "private_executor_not_yet_invoked_bridge_scaffold_available",
        "preferred_path": "pylon_in_process_activity_manager",
        "secondary_path": "binaryreplay_session_slot_binder",
        "pylon_in_process_activity_manager": {
            "ready_inputs": [
                "saved .ngfx-gfxcap path",
                "activity id 3 (Generate C++ Capture)",
                "platform/win32 launcher map",
                "QSettings Serialization Save Directory or project-service output directory state",
            ],
            "callsite": "PylonPlugin!sub_180116CD0",
            "image_base": hex(_PYLON_IMAGE_BASE),
            "functions": PYLON_PRIVATE_EXECUTOR_FUNCTIONS,
            "activity_manager_vtable_offsets_from_re": ["+200", "+264", "+200"],
            "unknowns_to_pin": [
                "The concrete activity-manager/service pointer used by sub_180116CD0.",
                "The UI-thread dispatch requirement for invoking the activity manager outside the button handler.",
                "Whether JsonProject['launcher'] can be populated headlessly before the manager call.",
                "Whether the C++ output directory must be set through QSettings, project service state, or both.",
            ],
            "probe_strategy": [
                "Attach to ngfx-ui.exe with the generated probe before opening the saved capture.",
                "Intercept sub_180147480/sub_180147C20 to capture the activity object, JsonProject, and launcher settings.",
                "Intercept sub_180116CD0 and record this pointer, arguments, call stack, and the callee pointer at vtable +200/+264.",
                "Replay the call from an injected helper on the UI thread with a known capture/output directory.",
            ],
        },
        "binaryreplay_session_slot_binder": {
            "ready_inputs": [
                "24-byte MessageHeader wire format",
                "transport frame format",
                "FrameDebugger Core method ids 17, 43, 44, 45, 46",
                "MCP-side file transfer callback primitive",
            ],
            "unknowns_to_pin": [
                "Which ngfx-ui/ngfx-rpc frame establishes the BinaryReplay namespace/session.",
                "How the RPC header slot/request_id/seq fields are populated for saved-capture FrameDebugger traffic.",
                "Whether the serialize request body is dispatched as FrameDebugger Core inside BinaryReplay or through a plugin-local category.",
            ],
            "probe_strategy": [
                "Capture an RPC transcript from ngfx-ui launch through a successful manual Generate C++ Capture export.",
                "Decode it with ngfx_rpc_transcript_import and inspect ngfx_rpc_session_binding_report.",
                "Promote the first stable non-zero slot/request_id/seq pattern into the direct RPC executor.",
            ],
        },
        "new_mcp_surfaces": {
            "probe_scaffold": "ngfx_pylon_bridge_helper_scaffold",
            "private_re_report": "ngfx_pylon_private_bridge_re_report",
            "private_probe_plan": "ngfx_pylon_bridge_probe_plan",
            "static_activity_manager_binding": "ngfx_pylon_activity_manager_static_binding_report",
            "private_probe_log_analyze": "ngfx_pylon_bridge_probe_log_analyze",
            "private_probe_run": "ngfx_pylon_bridge_probe_run",
            "direct_call_binding": "ngfx_pylon_direct_call_binding_from_probe",
            "frida_direct_call": "ngfx_pylon_frida_direct_call_run",
            "private_evidence_bundle": "ngfx_private_executor_evidence_bundle",
            "honest_pylon_export_entrypoint": "ngfx_pylon_saved_cpp_export",
            "rpc_decode": "ngfx_rpc_decode_frame",
            "rpc_transcript_import": "ngfx_rpc_transcript_import",
            "rpc_binding_report": "ngfx_rpc_session_binding_report",
            "direct_rpc_export_entrypoint": "ngfx_cpp_capture_saved_direct_rpc_export",
        },
        "bridge_report": bridge,
    }


def pylon_bridge_probe_plan(
    capture: str | None = None,
    *,
    output_dir: str | None = None,
    additional_args: list[str] | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Return a concrete probe plan for pinning Pylon's private executor."""
    preview = (
        pylon_saved_capture_handoff_preview(
            capture,
            additional_args=additional_args,
            environment=environment,
            output_dir=output_dir,
        )
        if capture
        else None
    )
    return {
        "ok": True,
        "status": "probe_plan_ready",
        "target_process": "ngfx-ui.exe",
        "target_module": "PylonPlugin.dll",
        "image_base": hex(_PYLON_IMAGE_BASE),
        "capture_path": capture,
        "output_dir": output_dir,
        "handoff_preview": preview,
        "probes": [
            {
                "function": "PylonPlugin!sub_180147480",
                "reason": "Record selected activity id and IPylonReplayFusionActivity object.",
            },
            {
                "function": "PylonPlugin!sub_180147C20",
                "reason": "Record JsonProject['launcher'] persistence and settings object layout.",
            },
            {
                "function": "PylonPlugin!sub_180116CD0",
                "reason": "Record the final saved-capture activity-manager handoff.",
            },
            {
                "function": "Activity-manager vtable call targets at +200/+264",
                "reason": "Identify the actual private executor interface and invocation signature.",
            },
        ],
        "success_criteria": [
            "A probe run captures the same platform/win32 launcher map as ngfx_cpp_capture_saved_pylon_handoff_preview.",
            "The activity-manager object pointer and vtable targets are stable across two manual exports.",
            "The injected helper can schedule the call on the UI thread and emit a C++ Capture project into output_dir.",
        ],
        "scaffold_tool": "ngfx_pylon_bridge_helper_scaffold",
    }


def _pylon_rva_expr(va: str) -> str:
    return f"ptr('{va}').sub(ptr('0x{_PYLON_IMAGE_BASE:x}')).add(base)"


def _pylon_probe_script() -> str:
    function_lines = []
    for name, item in PYLON_PRIVATE_EXECUTOR_FUNCTIONS.items():
        function_lines.append(f"  {name}: '{item['ea']}',")
    function_map = "\n".join(function_lines)
    return f"""'use strict';

const moduleName = 'PylonPlugin.dll';
const imageBase = ptr('0x{_PYLON_IMAGE_BASE:x}');
const functions = {{
{function_map}
}};

function log(message) {{
  console.log('[pylon-bridge] ' + message);
}}

function emit(payload) {{
  send(payload);
  console.log('NGFX_MCP_EVENT ' + JSON.stringify(payload));
}}

function addrFromVa(base, vaString) {{
  return ptr(vaString).sub(imageBase).add(base);
}}

function hookFunction(base, name, vaString) {{
  const target = addrFromVa(base, vaString);
  log('hook ' + name + ' at ' + target + ' (VA ' + vaString + ')');
  Interceptor.attach(target, {{
    onEnter(args) {{
      this.name = name;
      this.tid = Process.getCurrentThreadId();
      this.arg0 = args[0];
      this.arg1 = args[1];
      this.arg2 = args[2];
      const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .slice(0, 12)
        .map(DebugSymbol.fromAddress)
        .join(' | ');
      emit({{
        kind: 'enter',
        name,
        target: target.toString(),
        thread_id: this.tid,
        arg0: this.arg0.toString(),
        arg1: this.arg1.toString(),
        arg2: this.arg2.toString(),
        backtrace: bt,
      }});
    }},
    onLeave(retval) {{
      emit({{
        kind: 'leave',
        name: this.name,
        thread_id: this.tid,
        retval: retval.toString(),
      }});
    }},
  }});
}}

const module = Process.getModuleByName(moduleName);
const base = module.base;
log(moduleName + ' base=' + base + ' size=' + module.size);
Object.keys(functions).forEach((name) => hookFunction(base, name, functions[name]));

emit({{
  kind: 'ready',
  module: moduleName,
  pid: Process.id,
  base: base.toString(),
  image_base: imageBase.toString(),
  functions,
}});
"""


def _pylon_probe_cpp() -> str:
    return r"""#include <windows.h>
#include <string>

// This DLL is the native half of the private Pylon bridge. It intentionally
// refuses to call private Nsight functions until a binding JSON produced by
// ngfx_pylon_private_binding_from_probe has filled in the missing call fields.
//
// Expected flow:
//   1. Inject this DLL into ngfx-ui.exe.
//   2. Send a request over \\.\pipe\ngfx_pylon_bridge_<pid>.
//   3. Once call_signature_confirmed and inprocess_call_ready are true in the
//      binding JSON, wire the activity-manager call below.

static void Log(const wchar_t* message) {
    OutputDebugStringW(L"[ngfx-pylon-bridge] ");
    OutputDebugStringW(message);
    OutputDebugStringW(L"\n");
}

extern "C" __declspec(dllexport) DWORD WINAPI NgfxPylonBridgeProbeThread(void*) {
    HMODULE pylon = GetModuleHandleW(L"PylonPlugin.dll");
    if (!pylon) {
        Log(L"PylonPlugin.dll is not loaded");
        return 1;
    }
    Log(L"PylonPlugin.dll is loaded; waiting for confirmed private binding before invocation");
    return 0;
}

extern "C" __declspec(dllexport) int NgfxPylonBridgeInvokeFromJson(const wchar_t* requestJsonPath) {
    if (!requestJsonPath || !*requestJsonPath) {
        Log(L"request JSON path is missing");
        return 2;
    }
    Log(L"private invoke requested, but call_signature_confirmed is still required");
    return 3;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        HANDLE thread = CreateThread(nullptr, 0, NgfxPylonBridgeProbeThread, nullptr, 0, nullptr);
        if (thread) {
            CloseHandle(thread);
        }
    }
    return TRUE;
}
"""


def _pylon_binding_schema() -> str:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Nsight Pylon Private Binding",
        "type": "object",
        "required": ["schema", "target_module", "activity", "functions", "probe_binding_ready"],
        "properties": {
            "schema": {"const": "nsight-graphics-mcp.pylon-private-binding.v1"},
            "target_process": {"type": "string"},
            "target_module": {"type": "string"},
            "pylon_module_base": {"type": ["string", "null"]},
            "image_base": {"type": "string"},
            "source_process": {"type": "object"},
            "activity": {"type": "object"},
            "functions": {"type": "object"},
            "saved_capture_start_this": {"type": ["string", "null"]},
            "ui_thread_candidates": {"type": "array", "items": {"type": "string"}},
            "probe_binding_ready": {"type": "boolean"},
            "inprocess_call_ready": {"type": "boolean"},
            "missing_private_call_fields": {"type": "array", "items": {"type": "string"}},
        },
    }
    return json.dumps(schema, indent=2, sort_keys=True)


def _pylon_request_example(capture: str | None, output_dir: str | None) -> str:
    request = {
        "schema": "nsight-graphics-mcp.pylon-private-export-request.v1",
        "capture": capture or r"E:\captures\frame.ngfx-gfxcap",
        "output_dir": output_dir or r"E:\captures\cpp",
        "activity_id": _PYLON_ACTIVITY_ID,
        "dry_run": True,
    }
    return json.dumps(request, indent=2, sort_keys=True)


def pylon_bridge_helper_scaffold(
    out_dir: str | Path,
    *,
    capture: str | None = None,
    output_dir: str | None = None,
    additional_args: list[str] | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Write a private Pylon bridge helper scaffold for future executor work."""
    root = Path(out_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    handoff = (
        pylon_saved_capture_handoff_preview(
            capture,
            additional_args=additional_args,
            environment=environment,
            output_dir=output_dir,
        )
        if capture
        else None
    )
    protocol = {
        "schema": "nsight-graphics-mcp.pylon-private-bridge.v1",
        "status": "probe_scaffold_not_executor",
        "target_process": "ngfx-ui.exe",
        "target_module": "PylonPlugin.dll",
        "image_base": hex(_PYLON_IMAGE_BASE),
        "functions": PYLON_PRIVATE_EXECUTOR_FUNCTIONS,
        "activity": {
            "id": _PYLON_ACTIVITY_ID,
            "name": _PYLON_ACTIVITY_NAME,
            "short_name": _PYLON_ACTIVITY_SHORT_NAME,
        },
        "handoff_preview": handoff,
        "vtable_offsets_to_pin": ["+200", "+264", "+200"],
        "remaining_private_bindings": [
            "activity-manager/service object pointer",
            "UI-thread invocation trampoline",
            "JsonProject/project-service pointer",
            "output-directory state setter",
        ],
    }
    readme = f"""# Nsight Pylon Private Bridge Probe

Generated by `ngfx_pylon_bridge_helper_scaffold`.

This scaffold is for pinning the private saved-capture -> Generate C++ Capture
executor inside `ngfx-ui.exe`. It does not claim to export captures by itself.

## Current Targets

- Process: `ngfx-ui.exe`
- Module: `PylonPlugin.dll`
- Image base used by IDA: `{hex(_PYLON_IMAGE_BASE)}`
- Activity id: `{_PYLON_ACTIVITY_ID}` (`{_PYLON_ACTIVITY_NAME}`)

## Probe Order

1. Attach `frida_pylon_bridge_probe.js` before opening the saved capture.
2. Manually run Generate C++ Capture once.
3. Save the emitted messages and decode any ngfx-rpc frames with `ngfx_rpc_transcript_import`.
4. Promote the stable object pointers/vtable targets into `pylon_bridge_probe.cpp`.

The required handoff map is stored in `pylon_bridge_protocol.json`.
"""
    cmake = """cmake_minimum_required(VERSION 3.20)
project(ngfx_pylon_bridge_probe LANGUAGES CXX)

add_library(ngfx_pylon_bridge_probe SHARED pylon_bridge_probe.cpp)
target_compile_features(ngfx_pylon_bridge_probe PRIVATE cxx_std_20)
target_compile_definitions(ngfx_pylon_bridge_probe PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
"""
    files = {
        "README.md": readme,
        "frida_pylon_bridge_probe.js": _pylon_probe_script(),
        "pylon_bridge_protocol.json": json.dumps(protocol, indent=2, sort_keys=True),
        "pylon_private_binding.schema.json": _pylon_binding_schema(),
        "pylon_private_export_request.example.json": _pylon_request_example(capture, output_dir),
        "pylon_bridge_probe.cpp": _pylon_probe_cpp(),
        "CMakeLists.txt": cmake,
    }
    written = []
    for name, text in files.items():
        path = root / name
        path.write_text(text, encoding="utf-8")
        written.append(str(path))
    return {
        "ok": True,
        "status": "scaffold_written",
        "out_dir": str(root),
        "files": written,
        "protocol": protocol,
    }


def _probe_log_items_from_json(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("messages", "events", "records", "items"):
            if isinstance(value.get(key), list):
                return list(value[key])
        return [value]
    raise TypeError(f"unsupported probe log JSON root: {type(value).__name__}")


def _probe_log_items_from_text(text: str) -> list[Any]:
    items: list[Any] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "NGFX_MCP_EVENT " in stripped:
            _prefix, _sep, payload = stripped.partition("NGFX_MCP_EVENT ")
            try:
                items.extend(_probe_log_items_from_json(json.loads(payload)))
            except json.JSONDecodeError:
                pass
            continue
        try:
            items.extend(_probe_log_items_from_json(json.loads(stripped)))
        except json.JSONDecodeError:
            continue
    return items


def _normalise_probe_payload(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    payload = item.get("payload") if item.get("type") == "send" else item
    return payload if isinstance(payload, dict) else None


def _stable_values(events: list[dict[str, Any]], field: str, limit: int = 8) -> dict[str, Any]:
    values = [str(event[field]) for event in events if field in event and event[field] is not None]
    unique = sorted(set(values))
    return {
        "unique_count": len(unique),
        "values": unique[:limit],
        "truncated": len(unique) > limit,
        "stable": len(unique) == 1 and bool(unique),
    }


def pylon_bridge_probe_log_analyze(
    *,
    log_path: str | Path | None = None,
    messages: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Analyze Frida probe output and produce private binding hypotheses."""
    if log_path:
        path = Path(log_path)
        text = path.read_text(encoding="utf-8")
        try:
            raw_items = _probe_log_items_from_json(json.loads(text))
        except json.JSONDecodeError:
            raw_items = _probe_log_items_from_text(text)
        source = {"kind": "path", "path": str(path)}
    else:
        raw_items = list(messages or [])
        source = {"kind": "inline_messages", "count": len(raw_items)}

    payloads = [payload for item in raw_items if (payload := _normalise_probe_payload(item)) is not None]
    ready = [p for p in payloads if p.get("kind") == "ready"]
    enters = [p for p in payloads if p.get("kind") == "enter"]
    leaves = [p for p in payloads if p.get("kind") == "leave"]
    by_name: dict[str, list[dict[str, Any]]] = {}
    for event in enters:
        by_name.setdefault(str(event.get("name") or ""), []).append(event)

    function_reports = {}
    for name, events in sorted(by_name.items()):
        function_reports[name] = {
            "enter_count": len(events),
            "thread_ids": sorted({str(event.get("thread_id")) for event in events if event.get("thread_id")}),
            "arg0": _stable_values(events, "arg0"),
            "arg1": _stable_values(events, "arg1"),
            "arg2": _stable_values(events, "arg2"),
            "sample_backtrace": next((event.get("backtrace") for event in events if event.get("backtrace")), None),
        }

    has_start = "saved_capture_other_activity_start" in by_name
    has_dialog = "fusion_dialog_ctor" in by_name or "fusion_dialog_accept" in by_name
    stable_start_this = (
        function_reports.get("saved_capture_other_activity_start", {})
        .get("arg0", {})
        .get("stable")
    )
    hypotheses = {
        "pylon_module_base": ready[-1].get("base") if ready else None,
        "process_id": ready[-1].get("pid") if ready else None,
        "has_saved_capture_start_call": has_start,
        "has_dialog_project_events": has_dialog,
        "saved_capture_start_this_candidate": (
            function_reports.get("saved_capture_other_activity_start", {}).get("arg0", {}).get("values", [None])[0]
            if stable_start_this
            else None
        ),
        "ui_thread_candidates": sorted({str(event.get("thread_id")) for event in enters if event.get("thread_id")}),
    }
    blockers: list[str] = []
    if not has_start:
        blockers.append("Probe log does not include saved_capture_other_activity_start/sub_180116CD0.")
    if not has_dialog:
        blockers.append("Probe log does not include fusion dialog/project persistence events.")
    if not stable_start_this:
        blockers.append("No stable arg0/this pointer was observed for saved_capture_other_activity_start.")

    return {
        "ok": bool(payloads),
        "source": source,
        "payload_count": len(payloads),
        "ready_count": len(ready),
        "enter_count": len(enters),
        "leave_count": len(leaves),
        "functions": function_reports,
        "binding_hypotheses": hypotheses,
        "bridge_ready": bool(has_start and stable_start_this),
        "blockers": blockers,
        "next_actions": [
            "If bridge_ready is false, attach before opening the saved capture and repeat the manual export.",
            "Once arg0/this and UI thread are stable, extend pylon_bridge_probe.cpp to invoke the pinned activity-manager path.",
            "Correlate the same run with ngfx_rpc_session_binding_report if direct BinaryReplay export remains preferable.",
        ],
    }


def _pylon_static_facts(pylon_facts_path: str | Path | None = None) -> tuple[str | None, dict[str, Any] | None]:
    cached = _cached_facts_path(_PYLON_TARGET)
    path = str(pylon_facts_path or cached) if (pylon_facts_path or cached) else None
    return path, _load_optional(path)


def _pylon_decompiled_function(facts: dict[str, Any] | None, ea: str) -> dict[str, Any] | None:
    return _decompiled_index(facts).get(ea.lower())


def _extract_vtable_calls(pseudocode: str) -> list[dict[str, Any]]:
    calls = []
    seen_sources: set[str] = set()
    for match in _STATIC_CALL_RE.finditer(pseudocode):
        try:
            offset = int(match.group("offset"))
        except ValueError:
            continue
        source = match.group(0)
        seen_sources.add(source)
        calls.append(
            {
                "offset": offset,
                "offset_hex": f"0x{offset:x}",
                "object_expr": re.sub(r"\s+", " ", match.group("object")).strip(),
                "prototype_args": re.sub(r"\s+", " ", match.group("args")).strip(),
                "call_args": re.sub(r"\s+", " ", match.group("call_args")).strip(),
                "return_type": re.sub(r"\s+", " ", match.group("return_type")).strip(),
                "source": source,
                "_position": match.start(),
            }
        )
    broad_re = re.compile(r"(?P<source>\(\*\([^;]+?\+\s*(?P<offset>\d+)LL\)\)\((?P<call_args>[^;]+)\);)")
    for match in broad_re.finditer(pseudocode):
        source = match.group("source")
        if source in seen_sources:
            continue
        seen_sources.add(source)
        calls.append(
            {
                "offset": int(match.group("offset")),
                "offset_hex": f"0x{int(match.group('offset')):x}",
                "object_expr": None,
                "prototype_args": None,
                "call_args": re.sub(r"\s+", " ", match.group("call_args")).strip(),
                "return_type": None,
                "source": source,
                "_position": match.start(),
            }
        )
    position = 0
    for raw_line in pseudocode.splitlines():
        line = raw_line.strip()
        if "))((" in line or "))(" not in line:
            position += len(raw_line) + 1
            continue
        offset_match = re.search(r"\+\s*(\d+)LL", line)
        if not offset_match or line in seen_sources:
            position += len(raw_line) + 1
            continue
        seen_sources.add(line)
        call_args = line.rsplit("))(", 1)[-1].rstrip(";")
        calls.append(
            {
                "offset": int(offset_match.group(1)),
                "offset_hex": f"0x{int(offset_match.group(1)):x}",
                "object_expr": None,
                "prototype_args": None,
                "call_args": re.sub(r"\s+", " ", call_args).strip(),
                "return_type": None,
                "source": line,
                "_position": position,
            }
        )
        position += len(raw_line) + 1
    calls.sort(key=lambda item: int(item.pop("_position", 0)))
    return calls


def pylon_activity_manager_static_binding_report(
    *,
    pylon_facts_path: str | None = None,
) -> dict[str, Any]:
    """Extract the static direct-call and vtable binding from Pylon IDA facts."""
    facts_path, facts = _pylon_static_facts(pylon_facts_path)
    start_func = _pylon_decompiled_function(facts, "0x180116CD0")
    dialog_func = _pylon_decompiled_function(facts, "0x180147480")
    start_pseudo = str((start_func or {}).get("pseudocode") or "")
    dialog_pseudo = str((dialog_func or {}).get("pseudocode") or "")
    start_calls = _extract_vtable_calls(start_pseudo)
    dialog_calls = _extract_vtable_calls(dialog_pseudo)
    manager_offsets = [call for call in start_calls if call["offset"] in {200, 208, 264}]
    readiness_offsets = [call for call in start_calls if call["offset"] == 240]
    service_queries = []
    for symbol in ("qword_180678E98", "qword_180677640", "qword_18064D2F8"):
        if symbol in start_pseudo or symbol in dialog_pseudo:
            service_queries.append(
                {
                    "type_descriptor_symbol": symbol,
                    "appears_in_saved_capture_start": symbol in start_pseudo,
                    "appears_in_fusion_dialog": symbol in dialog_pseudo,
                }
            )
    launcher_keys = [
        "platform/%1/device",
        "platform/%1/executable",
        "platform/%1/arguments",
        "platform/%1/workingdir",
        "platform/%1/environment",
    ]
    keys_present = [key for key in launcher_keys if key in start_pseudo]
    direct_reentry = {
        "strategy": "frida_or_native_direct_member_function_reentry",
        "function": "PylonPlugin!sub_180116CD0",
        "function_va": hex(_PYLON_SAVED_CAPTURE_START_VA),
        "function_rva": hex(_PYLON_SAVED_CAPTURE_START_RVA),
        "signature": "void __fastcall(void* saved_capture_activity_page_this)",
        "this_pointer_source": "Probe event name=saved_capture_other_activity_start arg0",
        "why_this_is_lowest_risk": (
            "The function already builds the Qt launcher QVariant map, quotes the saved capture path, "
            "sets platform/win32 launcher fields, calls the private activity manager, and restores settings."
        ),
    }
    vtable_sequence = [
        {
            "order": 1,
            "offset": 208,
            "role": "snapshot_or_clone_current_launcher_settings",
            "expected_call_shape": "fn(activity_manager, out_settings_ref, flags=0)",
        },
        {
            "order": 2,
            "offset": 200,
            "role": "apply_synthesized_launcher_settings",
            "expected_call_shape": "fn(activity_manager, synthesized_settings_ref)",
        },
        {
            "order": 3,
            "offset": 264,
            "role": "start_or_invoke_selected_activity",
            "expected_call_shape": "fn(activity_manager)",
        },
        {
            "order": 4,
            "offset": 200,
            "role": "restore_previous_launcher_settings",
            "expected_call_shape": "fn(activity_manager, original_settings_ref)",
        },
    ]
    blockers = []
    if not facts:
        blockers.append("No PylonPlugin IDA facts were available.")
    if not start_func:
        blockers.append("PylonPlugin!sub_180116CD0 pseudocode was not available.")
    if len(manager_offsets) < 4:
        blockers.append("Could not statically recover the full +208/+200/+264/+200 activity-manager sequence.")
    if len(keys_present) != len(launcher_keys):
        blockers.append("Could not confirm every platform/win32 launcher key in sub_180116CD0.")
    return {
        "ok": not blockers or bool(start_func),
        "facts_path": facts_path,
        "status": "direct_reentry_callsite_pinned" if not blockers else "static_binding_incomplete",
        "direct_reentry": direct_reentry,
        "service_queries": service_queries,
        "readiness_gate": {
            "candidate_object": "service from qword_180677640",
            "vtable_offset": 240,
            "calls": readiness_offsets,
        },
        "activity_manager_vtable_sequence": vtable_sequence,
        "activity_manager_vtable_calls_recovered": manager_offsets,
        "launcher_keys_confirmed": keys_present,
        "all_saved_capture_start_vtable_calls": start_calls,
        "fusion_dialog_vtable_calls": dialog_calls,
        "blockers": blockers,
        "next_step": "Use ngfx_pylon_direct_call_binding_from_probe to combine this static callsite with a live probe this-pointer.",
    }


def pylon_private_binding_from_probe(
    *,
    probe_log_path: str | Path | None = None,
    analysis: dict[str, Any] | None = None,
    out_path: str | Path | None = None,
) -> dict[str, Any]:
    """Convert probe analysis into the binding JSON consumed by the bridge."""
    probe_analysis = analysis or pylon_bridge_probe_log_analyze(log_path=probe_log_path)
    hypotheses = probe_analysis.get("binding_hypotheses") or {}
    functions = probe_analysis.get("functions") or {}
    start_report = functions.get("saved_capture_other_activity_start") or {}
    missing = [
        "activity_manager_object_or_service_pointer",
        "activity_manager_vtable_call_targets_at_+200_+264_+200",
        "call_signature_confirmed",
        "ui_thread_dispatch_trampoline",
        "project_launcher_or_settings_object_pointer",
    ]
    probe_ready = bool(probe_analysis.get("bridge_ready"))
    if probe_ready:
        missing = [
            item
            for item in missing
            if item
            not in {
                "activity_manager_object_or_service_pointer",
            }
        ]
    static_report = pylon_activity_manager_static_binding_report()
    direct_call_ready = bool(
        probe_ready
        and hypotheses.get("pylon_module_base")
        and hypotheses.get("saved_capture_start_this_candidate")
        and hypotheses.get("ui_thread_candidates")
    )
    binding = {
        "schema": "nsight-graphics-mcp.pylon-private-binding.v1",
        "target_process": "ngfx-ui.exe",
        "target_module": "PylonPlugin.dll",
        "image_base": hex(_PYLON_IMAGE_BASE),
        "pylon_module_base": hypotheses.get("pylon_module_base"),
        "source_process": {
            "pid": hypotheses.get("process_id"),
            "binding_scope": (
                "process_lifetime_scoped; the saved_capture_start_this pointer is only valid "
                "inside the ngfx-ui.exe process observed by the probe"
            ),
        },
        "activity": {
            "id": _PYLON_ACTIVITY_ID,
            "name": _PYLON_ACTIVITY_NAME,
            "short_name": _PYLON_ACTIVITY_SHORT_NAME,
        },
        "functions": PYLON_PRIVATE_EXECUTOR_FUNCTIONS,
        "saved_capture_start_this": hypotheses.get("saved_capture_start_this_candidate"),
        "saved_capture_start_arg_report": start_report,
        "ui_thread_candidates": hypotheses.get("ui_thread_candidates") or [],
        "vtable_offsets_to_pin": ["+200", "+264", "+200"],
        "direct_reentry_call": {
            **static_report["direct_reentry"],
            "module_base": hypotheses.get("pylon_module_base"),
            "this_pointer": hypotheses.get("saved_capture_start_this_candidate"),
            "ui_thread_id": (hypotheses.get("ui_thread_candidates") or [None])[0],
            "ready_to_attempt": direct_call_ready,
        },
        "static_binding": static_report,
        "probe_binding_ready": probe_ready,
        "inprocess_call_ready": False,
        "missing_private_call_fields": missing,
        "source": {
            "probe_log_path": str(probe_log_path) if probe_log_path else None,
            "analysis_source": probe_analysis.get("source"),
        },
        "notes": [
            "This file is intentionally not enough to call private Nsight code until inprocess_call_ready is true.",
            "The next RE pass must identify the exact activity-manager interface and UI-thread dispatch trampoline.",
        ],
    }
    if out_path:
        path = Path(out_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(binding, indent=2, sort_keys=True), encoding="utf-8")
    blockers = list(probe_analysis.get("blockers") or [])
    if missing:
        blockers.extend(f"Missing {item}." for item in missing)
    return {
        "ok": True,
        "ready": bool(binding["inprocess_call_ready"]),
        "direct_reentry_ready": direct_call_ready,
        "probe_binding_ready": probe_ready,
        "binding": binding,
        "binding_path": str(Path(out_path).resolve()) if out_path else None,
        "blockers": blockers,
    }


def pylon_direct_call_binding_from_probe(
    *,
    probe_log_path: str | Path | None = None,
    analysis: dict[str, Any] | None = None,
    out_path: str | Path | None = None,
) -> dict[str, Any]:
    """Build the experimental Frida/native direct-call binding for sub_180116CD0."""
    base = pylon_private_binding_from_probe(
        probe_log_path=probe_log_path,
        analysis=analysis,
    )
    binding = dict(base["binding"])
    direct = dict(binding.get("direct_reentry_call") or {})
    blockers = []
    for field in ("module_base", "this_pointer", "ui_thread_id"):
        if not direct.get(field):
            blockers.append(f"Missing direct reentry field: {field}.")
    if not direct.get("function_rva"):
        blockers.append("Missing direct reentry function RVA.")
    direct["ready_to_attempt"] = not blockers
    binding["direct_reentry_call"] = direct
    binding["recommended_invocation"] = {
        "tool": "ngfx_pylon_frida_direct_call_run",
        "dry_run_first": True,
        "requires_allow_experimental_call": True,
    }
    if out_path:
        path = Path(out_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(binding, indent=2, sort_keys=True), encoding="utf-8")
    return {
        "ok": True,
        "ready": not blockers,
        "binding": binding,
        "binding_path": str(Path(out_path).resolve()) if out_path else None,
        "blockers": blockers,
    }


def _resolve_frida(frida_path: str | Path | None) -> str | None:
    if frida_path:
        candidate = Path(frida_path)
        return str(candidate) if candidate.is_file() else None
    return shutil.which("frida.exe") or shutil.which("frida")


def _probe_run_command(
    *,
    frida_exe: str,
    script_path: Path,
    pid: int | None = None,
    process_name: str = "ngfx-ui.exe",
    spawn_exe: str | None = None,
) -> list[str]:
    if pid is not None:
        return [frida_exe, "-p", str(pid), "-l", str(script_path)]
    if spawn_exe:
        return [frida_exe, "-f", spawn_exe, "-l", str(script_path), "--no-pause"]
    return [frida_exe, "-n", process_name, "-l", str(script_path)]


def pylon_bridge_probe_run(
    out_dir: str | Path,
    *,
    capture: str | None = None,
    output_dir: str | None = None,
    additional_args: list[str] | None = None,
    environment: dict[str, str] | None = None,
    pid: int | None = None,
    process_name: str = "ngfx-ui.exe",
    spawn_exe: str | None = None,
    frida_path: str | None = None,
    script_path: str | None = None,
    timeout_sec: float = 120.0,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run the generated Frida Pylon probe and analyze collected output."""
    root = Path(out_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    scaffold = None
    if script_path:
        script = Path(script_path).resolve()
    else:
        scaffold = pylon_bridge_helper_scaffold(
            root,
            capture=capture,
            output_dir=output_dir,
            additional_args=additional_args,
            environment=environment,
        )
        script = root / "frida_pylon_bridge_probe.js"

    frida_exe = _resolve_frida(frida_path)
    command_preview = _probe_run_command(
        frida_exe=frida_exe or "frida",
        script_path=script,
        pid=pid,
        process_name=process_name,
        spawn_exe=spawn_exe,
    )
    if dry_run:
        return {
            "ok": True,
            "status": "dry_run",
            "out_dir": str(root),
            "script_path": str(script),
            "frida_found": frida_exe is not None,
            "command": command_preview,
            "scaffold": scaffold,
            "next_step": "Run with dry_run=False while manually triggering Generate C++ Capture in Nsight UI.",
        }
    if frida_exe is None:
        return {
            "ok": False,
            "status": "frida_not_found",
            "out_dir": str(root),
            "script_path": str(script),
            "command": command_preview,
            "scaffold": scaffold,
            "install_hint": "Install Frida CLI or pass frida_path to ngfx_pylon_bridge_probe_run.",
        }

    stdout_path = root / "frida_probe_stdout.log"
    stderr_path = root / "frida_probe_stderr.log"
    combined_path = root / "frida_probe_combined.ndjson"
    command = _probe_run_command(
        frida_exe=frida_exe,
        script_path=script,
        pid=pid,
        process_name=process_name,
        spawn_exe=spawn_exe,
    )
    timed_out = False
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.terminate()
            try:
                stdout, stderr = proc.communicate(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate(timeout=5.0)
    except OSError as exc:
        return {
            "ok": False,
            "status": "frida_launch_failed",
            "error": str(exc),
            "command": command,
            "script_path": str(script),
        }

    stdout_path.write_text(stdout or "", encoding="utf-8")
    stderr_path.write_text(stderr or "", encoding="utf-8")
    combined_path.write_text((stdout or "") + "\n" + (stderr or ""), encoding="utf-8")
    analysis = pylon_bridge_probe_log_analyze(log_path=combined_path)
    return {
        "ok": bool(analysis.get("ok")),
        "status": "probe_collected" if analysis.get("ok") else "probe_ran_no_events",
        "timed_out": timed_out,
        "returncode": proc.returncode,
        "command": command,
        "out_dir": str(root),
        "script_path": str(script),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "combined_log_path": str(combined_path),
        "analysis": analysis,
        "scaffold": scaffold,
    }


def _pylon_frida_direct_call_script(binding: dict[str, Any]) -> str:
    direct = binding.get("direct_reentry_call") or {}
    function_rva = str(direct.get("function_rva") or hex(_PYLON_SAVED_CAPTURE_START_RVA))
    this_pointer = str(direct.get("this_pointer") or "0x0")
    ui_thread_id = direct.get("ui_thread_id")
    return f"""'use strict';

const binding = {json.dumps(binding, indent=2, sort_keys=True)};
const moduleName = binding.target_module || 'PylonPlugin.dll';
const functionRva = ptr('{function_rva}');
const thisPointer = ptr('{this_pointer}');
const uiThreadId = {json.dumps(ui_thread_id)};
const expectedProcessId = binding.source_process && binding.source_process.pid !== undefined
  ? Number(binding.source_process.pid)
  : null;

function emit(payload) {{
  send(payload);
  console.log('NGFX_MCP_EVENT ' + JSON.stringify(payload));
}}

function invoke() {{
  const currentPid = Process.id;
  emit({{
    kind: 'pylon_direct_call_process_binding',
    current_pid: currentPid,
    expected_pid: expectedProcessId,
  }});
  if (expectedProcessId !== null && currentPid !== expectedProcessId) {{
    emit({{
      kind: 'pylon_direct_call_blocked_stale_process_binding',
      current_pid: currentPid,
      expected_pid: expectedProcessId,
    }});
    throw new Error('stale Pylon direct-call binding: probe PID does not match attached process PID');
  }}
  const mod = Process.getModuleByName(moduleName);
  const target = mod.base.add(functionRva);
  emit({{
    kind: 'pylon_direct_call_about_to_invoke',
    module: moduleName,
    module_base: mod.base.toString(),
    target: target.toString(),
    function_rva: functionRva.toString(),
    this_pointer: thisPointer.toString(),
    thread_id: Process.getCurrentThreadId(),
  }});
  const fn = new NativeFunction(target, 'void', ['pointer'], {{ exceptions: 'propagate' }});
  fn(thisPointer);
  emit({{
    kind: 'pylon_direct_call_returned',
    thread_id: Process.getCurrentThreadId(),
  }});
}}

if (thisPointer.isNull()) {{
  throw new Error('this_pointer is null; run ngfx_pylon_direct_call_binding_from_probe first');
}}

if (uiThreadId !== null && uiThreadId !== undefined && typeof Process.runOnThread === 'function') {{
  emit({{ kind: 'pylon_direct_call_scheduling_on_thread', thread_id: uiThreadId }});
  Process.runOnThread(Number(uiThreadId), invoke);
}} else {{
  emit({{ kind: 'pylon_direct_call_invoking_on_frida_thread', requested_thread_id: uiThreadId }});
  invoke();
}}
"""


def pylon_frida_direct_call_run(
    out_dir: str | Path,
    *,
    binding_path: str | None = None,
    binding: dict[str, Any] | None = None,
    pid: int | None = None,
    process_name: str = "ngfx-ui.exe",
    frida_path: str | None = None,
    timeout_sec: float = 120.0,
    dry_run: bool = True,
    allow_experimental_call: bool = False,
) -> dict[str, Any]:
    """Attempt the experimental Frida direct re-entry call into sub_180116CD0."""
    root = Path(out_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    loaded_binding = binding or _load_json_file(binding_path)
    if loaded_binding is None:
        return {
            "ok": False,
            "status": "missing_binding",
            "blockers": ["No direct-call binding was supplied."],
        }
    direct = loaded_binding.get("direct_reentry_call") or {}
    blockers = []
    if not direct.get("ready_to_attempt"):
        blockers.append("Binding direct_reentry_call.ready_to_attempt is false.")
    for field in ("module_base", "this_pointer", "function_rva"):
        if not direct.get(field):
            blockers.append(f"Binding missing direct_reentry_call.{field}.")
    if not allow_experimental_call and not dry_run:
        blockers.append("allow_experimental_call must be true for a non-dry-run private call.")

    script_path = root / "frida_pylon_direct_call.js"
    script_path.write_text(_pylon_frida_direct_call_script(loaded_binding), encoding="utf-8")
    frida_exe = _resolve_frida(frida_path)
    command = _probe_run_command(
        frida_exe=frida_exe or "frida",
        script_path=script_path,
        pid=pid,
        process_name=process_name,
    )
    if dry_run or blockers:
        return {
            "ok": not blockers,
            "status": "dry_run" if dry_run and not blockers else "blocked_or_dry_run",
            "headless_export_invoked": False,
            "out_dir": str(root),
            "script_path": str(script_path),
            "frida_found": frida_exe is not None,
            "command": command,
            "binding": loaded_binding,
            "blockers": blockers,
        }
    if frida_exe is None:
        return {
            "ok": False,
            "status": "frida_not_found",
            "headless_export_invoked": False,
            "script_path": str(script_path),
            "command": command,
            "blockers": ["Frida CLI was not found."],
        }

    stdout_path = root / "frida_direct_call_stdout.log"
    stderr_path = root / "frida_direct_call_stderr.log"
    combined_path = root / "frida_direct_call_combined.ndjson"
    real_command = _probe_run_command(
        frida_exe=frida_exe,
        script_path=script_path,
        pid=pid,
        process_name=process_name,
    )
    try:
        proc = subprocess.run(
            real_command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "ok": False,
            "status": "frida_direct_call_failed_to_launch",
            "headless_export_invoked": False,
            "error": f"{type(exc).__name__}: {exc}",
            "command": real_command,
            "script_path": str(script_path),
        }
    stdout_path.write_text(proc.stdout or "", encoding="utf-8")
    stderr_path.write_text(proc.stderr or "", encoding="utf-8")
    combined_path.write_text((proc.stdout or "") + "\n" + (proc.stderr or ""), encoding="utf-8")
    analysis = pylon_bridge_probe_log_analyze(log_path=combined_path)
    returned = any(
        event.get("kind") == "pylon_direct_call_returned"
        for event in _probe_log_items_from_text(combined_path.read_text(encoding="utf-8"))
        if isinstance(event, dict)
    )
    return {
        "ok": proc.returncode == 0 and returned,
        "status": "direct_call_returned" if returned else "direct_call_no_return_event",
        "headless_export_invoked": True,
        "returncode": proc.returncode,
        "command": real_command,
        "script_path": str(script_path),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "combined_log_path": str(combined_path),
        "analysis": analysis,
    }


def private_executor_evidence_bundle(
    out_zip: str | Path,
    *,
    capture: str | None = None,
    output_dir: str | None = None,
    probe_log_path: str | None = None,
    rpc_transcript_path: str | None = None,
    extra_files: list[str | Path] | None = None,
) -> dict[str, Any]:
    """Bundle private executor evidence for an autonomous follow-up pass."""
    out = Path(out_zip).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    bridge_report = pylon_private_executor_re_report()
    handoff = (
        pylon_saved_capture_handoff_preview(capture, output_dir=output_dir)
        if capture
        else None
    )
    probe_analysis = (
        pylon_bridge_probe_log_analyze(log_path=probe_log_path)
        if probe_log_path
        else None
    )
    rpc_import = (
        rpc_trace.import_rpc_transcript(transcript_path=rpc_transcript_path)
        if rpc_transcript_path
        else None
    )
    manifest = {
        "schema": "nsight-graphics-mcp.private-executor-evidence.v1",
        "capture": capture,
        "output_dir": output_dir,
        "probe_log_path": probe_log_path,
        "rpc_transcript_path": rpc_transcript_path,
        "bridge_ready": bool((probe_analysis or {}).get("bridge_ready")),
        "direct_rpc_ready": bool(
            ((rpc_import or {}).get("session_binding_report") or {}).get("direct_saved_cpp_export_ready")
        ),
        "recommended_next_path": (
            "pylon_in_process_activity_manager"
            if bool((probe_analysis or {}).get("bridge_ready"))
            else (
                "direct_binaryreplay_rpc"
                if bool(((rpc_import or {}).get("session_binding_report") or {}).get("direct_saved_cpp_export_ready"))
                else "collect_more_private_binding_evidence"
            )
        ),
    }
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, indent=2, sort_keys=True))
        zf.writestr("reports/pylon_private_bridge_re_report.json", json.dumps(bridge_report, indent=2, sort_keys=True))
        if handoff:
            zf.writestr("reports/pylon_handoff_preview.json", json.dumps(handoff, indent=2, sort_keys=True))
        if probe_analysis:
            zf.writestr("reports/pylon_probe_analysis.json", json.dumps(probe_analysis, indent=2, sort_keys=True))
        if rpc_import:
            zf.writestr("reports/rpc_transcript_import.json", json.dumps(rpc_import, indent=2, sort_keys=True))
        for raw in extra_files or []:
            path = Path(raw)
            if path.is_file():
                zf.write(path, f"extra/{path.name}")
        for raw in (probe_log_path, rpc_transcript_path):
            if raw and Path(raw).is_file():
                path = Path(raw)
                zf.write(path, f"inputs/{path.name}")
    return {
        "ok": True,
        "zip_path": str(out),
        "manifest": manifest,
        "reports": {
            "probe_analysis_included": probe_analysis is not None,
            "rpc_transcript_included": rpc_import is not None,
            "handoff_preview_included": handoff is not None,
        },
    }


def _load_json_file(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(str(path))
    return json.loads(p.read_text(encoding="utf-8"))


def private_executor_readiness_report(
    *,
    probe_log_path: str | None = None,
    rpc_transcript_path: str | None = None,
    pylon_binding_path: str | None = None,
    pylon_binding: dict[str, Any] | None = None,
    bridge_exe: str | None = None,
) -> dict[str, Any]:
    """Compare the Pylon and direct-RPC paths and report exact blockers."""
    probe_analysis = pylon_bridge_probe_log_analyze(log_path=probe_log_path) if probe_log_path else None
    binding_report = None
    binding = pylon_binding or _load_json_file(pylon_binding_path)
    if binding is None and probe_analysis is not None:
        binding_report = pylon_private_binding_from_probe(analysis=probe_analysis)
        binding = binding_report["binding"]
    direct_reentry = (binding or {}).get("direct_reentry_call") or {}

    rpc_candidate = (
        rpc_trace.direct_export_binding_candidate_from_transcript(transcript_path=rpc_transcript_path)
        if rpc_transcript_path
        else None
    )
    bridge_path = Path(bridge_exe) if bridge_exe else None
    bridge_exists = bool(bridge_path and bridge_path.is_file())
    pylon_blockers: list[str] = []
    if binding is None:
        pylon_blockers.append("No Pylon binding was supplied or derivable from a probe log.")
    else:
        pylon_blockers.extend(str(item) for item in binding.get("missing_private_call_fields") or [])
        if not binding.get("inprocess_call_ready"):
            pylon_blockers.append("Pylon binding has inprocess_call_ready=false.")
        if not direct_reentry.get("ready_to_attempt"):
            pylon_blockers.append("Pylon direct reentry binding is not ready to attempt.")
    if bridge_exe and not bridge_exists:
        pylon_blockers.append(f"Bridge executable not found: {bridge_exe}")
    elif not bridge_exe and not direct_reentry.get("ready_to_attempt"):
        pylon_blockers.append("No native bridge executable supplied.")

    direct_blockers = list((rpc_candidate or {}).get("blockers") or [])
    if rpc_candidate is None:
        direct_blockers.append("No RPC transcript supplied.")

    native_bridge_ready = bool(binding and binding.get("inprocess_call_ready") and bridge_exists)
    frida_direct_ready = bool(binding and direct_reentry.get("ready_to_attempt"))
    direct_ready = bool(rpc_candidate and rpc_candidate.get("ready"))
    if frida_direct_ready:
        recommended = "pylon_frida_direct_reentry"
    elif native_bridge_ready:
        recommended = "pylon_native_bridge"
    elif direct_ready:
        recommended = "direct_binaryreplay_rpc"
    else:
        recommended = "collect_more_private_binding_evidence"
    return {
        "ok": True,
        "recommended_next_path": recommended,
        "pylon": {
            "ready": bool(native_bridge_ready or frida_direct_ready),
            "native_bridge_ready": native_bridge_ready,
            "frida_direct_reentry_ready": frida_direct_ready,
            "binding": binding,
            "binding_report": binding_report,
            "bridge_exe": bridge_exe,
            "bridge_exe_exists": bridge_exists,
            "blockers": pylon_blockers,
        },
        "direct_rpc": {
            "ready": direct_ready,
            "binding_candidate": (rpc_candidate or {}).get("binding"),
            "blockers": direct_blockers,
        },
        "next_actions": [
            "If Pylon is blocked, collect a probe log that includes sub_180116CD0 and activity-manager vtable targets.",
            "If direct RPC is blocked, collect a full manual export transcript including methods 17, 43, 44, 45, and 46.",
            "Once either path reports ready, rerun the corresponding export entrypoint with dry_run=False.",
        ],
    }


def pylon_private_bridge_invoke(
    capture: str,
    *,
    output_dir: str,
    bridge_exe: str | None = None,
    binding_path: str | None = None,
    binding: dict[str, Any] | None = None,
    request_path: str | None = None,
    timeout_sec: float = 900.0,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Guarded wrapper for the future native in-process Pylon bridge."""
    loaded_binding = binding or _load_json_file(binding_path)
    blockers: list[str] = []
    if loaded_binding is None:
        blockers.append("No Pylon private binding supplied.")
    elif not loaded_binding.get("inprocess_call_ready"):
        blockers.extend(str(item) for item in loaded_binding.get("missing_private_call_fields") or [])
        blockers.append("Binding has inprocess_call_ready=false.")
    if not bridge_exe:
        blockers.append("No bridge executable supplied.")
    bridge_path = Path(bridge_exe).resolve() if bridge_exe else None
    if bridge_path and not bridge_path.is_file():
        blockers.append(f"Bridge executable not found: {bridge_path}")

    req_path = Path(request_path).resolve() if request_path else Path(output_dir).resolve() / "ngfx_pylon_bridge_request.json"
    req_path.parent.mkdir(parents=True, exist_ok=True)
    request = {
        "schema": "nsight-graphics-mcp.pylon-private-export-request.v1",
        "capture": str(capture),
        "output_dir": str(output_dir),
        "binding_path": str(binding_path) if binding_path else None,
        "activity_id": _PYLON_ACTIVITY_ID,
        "dry_run": dry_run,
    }
    req_path.write_text(json.dumps(request, indent=2, sort_keys=True), encoding="utf-8")
    command = [str(bridge_path), "--request", str(req_path)] if bridge_path else None
    if dry_run or blockers:
        return {
            "ok": False,
            "status": "blocked_or_dry_run",
            "headless_export_invoked": False,
            "request_path": str(req_path),
            "command": command,
            "blockers": blockers,
            "binding": loaded_binding,
        }

    try:
        proc = subprocess.run(
            command or [],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "ok": False,
            "status": "bridge_launch_failed",
            "error": f"{type(exc).__name__}: {exc}",
            "request_path": str(req_path),
            "command": command,
        }
    return {
        "ok": proc.returncode == 0,
        "status": "bridge_invoked" if proc.returncode == 0 else "bridge_failed",
        "headless_export_invoked": True,
        "returncode": proc.returncode,
        "request_path": str(req_path),
        "command": command,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def pylon_saved_cpp_export(
    capture: str,
    *,
    output_dir: str | None = None,
    additional_args: list[str] | None = None,
    environment: dict[str, str] | None = None,
    scaffold_dir: str | None = None,
    bridge_exe: str | None = None,
    binding_path: str | None = None,
    binding: dict[str, Any] | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Honest Pylon private-export entrypoint.

    It packages every input the private executor needs and optionally writes
    the helper scaffold. It returns a blocker until the in-process bridge is
    implemented or a captured activity-manager binding is supplied.
    """
    handoff = pylon_saved_capture_handoff_preview(
        capture,
        additional_args=additional_args,
        environment=environment,
        output_dir=output_dir,
    )
    scaffold = (
        pylon_bridge_helper_scaffold(
            scaffold_dir,
            capture=capture,
            output_dir=output_dir,
            additional_args=additional_args,
            environment=environment,
        )
        if scaffold_dir
        else None
    )
    invoke = None
    if bridge_exe or binding_path or binding:
        invoke = pylon_private_bridge_invoke(
            capture,
            output_dir=output_dir or str(Path(capture).with_suffix("")) + "_cpp",
            bridge_exe=bridge_exe,
            binding_path=binding_path,
            binding=binding,
            dry_run=dry_run,
        )
    return {
        "ok": False,
        "status": invoke["status"] if invoke else "blocked_requires_in_process_pylon_activity_manager",
        "headless_export_invoked": bool((invoke or {}).get("headless_export_invoked")),
        "capture": str(capture),
        "output_dir": output_dir,
        "handoff_preview": handoff,
        "scaffold": scaffold,
        "bridge_invoke": invoke,
        "required_private_binding": {
            "callsite": "PylonPlugin!sub_180116CD0",
            "activity_id": _PYLON_ACTIVITY_ID,
            "vtable_offsets_to_pin": ["+200", "+264", "+200"],
            "tool_to_generate_probe": "ngfx_pylon_bridge_helper_scaffold",
            "tool_to_extract_binding": "ngfx_pylon_private_binding_from_probe",
        },
        "next_tool": "ngfx_pylon_bridge_probe_plan",
    }


def frame_debugger_serialize_rpc_plan(
    *,
    output_dir: str,
    rpc_session_handle: str | None = None,
    host_save_directory: str | None = None,
    copy_redist_requirements: bool = True,
    target_is_remote: bool = False,
    keep_on_remote_machine: bool = False,
) -> dict[str, Any]:
    """Return the direct FrameDebugger serialize-RPC plan.

    This packages the recovered BattlePlugin protocol into a deterministic
    MCP-readable shape. It does not send packets; live BinaryReplay binding
    and file-transfer callback handling remain separate executor work.
    """
    schema = _frame_debugger_schema()
    return {
        "ok": True,
        "mode": "frame_debugger_core_serialize_rpc_plan",
        "ready_to_send": False,
        "rpc_session_handle": rpc_session_handle,
        "category_binding": {
            "pylon_replay_category": 1,
            "source": "ngfx-rpc.exe PylonUi.proto: CategoryBinaryReplay == 1",
            "remaining_gap": "UI-private namespace/session/slot setup before BinaryReplay requests are accepted.",
        },
        "core_methods": schema.get("core_methods"),
        "request": {
            "message": "Nvda.Messaging.Graphics.FrameDebugger.PbSerializeRequestMessage",
            "fields_recovered": [
                "OutputFolderPath",
                "OutputFolderIsBasePath",
                "TransactionId",
                "AlwaysAllowBindlessSerialization",
                "TargetIsRemote",
                "CopyRedistRequirementsToOutput",
                "HostRequestTime",
                "HostSaveDirectory",
                "HostVersion",
                "KeepOnRemoteMachine",
            ],
            "values": {
                "OutputFolderPath": output_dir,
                "HostSaveDirectory": host_save_directory or output_dir,
                "CopyRedistRequirementsToOutput": copy_redist_requirements,
                "TargetIsRemote": target_is_remote,
                "KeepOnRemoteMachine": keep_on_remote_machine,
            },
        },
        "required_callback_loop": [
            "Handle MethodPbOpenFileNotification (44) by opening/creating the requested output file.",
            "Handle MethodPbAppendFileNotification (45) by appending payload bytes to the active file.",
            "Handle MethodPbCloseFileNotification (46) by closing the active file handle.",
            "Stop when MethodPbSerializeFrameCaptureReply (43) reports success/failure.",
        ],
        "battleplugin_evidence": {
            "serialize_path": "BattlePlugin!sub_180028880",
            "request_builder": "BattlePlugin!sub_180042890",
            "transaction_finalizer": "BattlePlugin!sub_1800427D0",
            "command_handler": "BattlePlugin!sub_18006DA60",
        },
        "remaining_gap": (
            "The protobuf and method ids are pinned. A working executor still needs the live "
            "BinaryReplay namespace/session/slot binding plus MCP-side file-transfer callbacks."
        ),
    }


def _notification_value(notification: dict[str, Any], *names: str) -> Any:
    lowered = {str(k).lower(): v for k, v in notification.items()}
    for name in names:
        if name in notification:
            return notification[name]
        value = lowered.get(name.lower())
        if value is not None:
            return value
    return None


def _safe_output_path(output_dir: Path, relative: str) -> Path:
    root = output_dir.resolve()
    target = (root / relative).resolve()
    if target != root and root not in target.parents:
        raise ValueError(f"file-transfer path escapes output_dir: {relative}")
    return target


def _decode_notification_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, list):
        return bytes(int(x) & 0xFF for x in value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return b""
        try:
            return base64.b64decode(text, validate=True)
        except Exception:
            try:
                return bytes.fromhex(text.replace(" ", ""))
            except ValueError:
                return text.encode("utf-8")
    raise TypeError(f"unsupported notification data payload type: {type(value).__name__}")


def frame_debugger_file_transfer_apply(
    output_dir: str,
    notification: dict[str, Any],
    *,
    state_path: str | None = None,
) -> dict[str, Any]:
    """Apply one recovered FrameDebugger file-transfer notification.

    This is the MCP-side callback primitive needed by the direct serialize RPC
    route. It accepts decoded notification dictionaries with flexible field
    names so it can be wired to the exact protobuf dict shape once the live
    executor is finished.
    """
    root = Path(output_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    state_file = Path(state_path).resolve() if state_path else root / ".ngfxmcp_file_transfer_state.json"
    if state_file.is_file():
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            state = {}
    else:
        state = {}
    files: dict[str, str] = dict(state.get("files") or {})

    raw_kind = _notification_value(notification, "kind", "notification_kind", "method_name", "method")
    kind = str(raw_kind or "").lower()
    tx = str(_notification_value(notification, "transaction_id", "TransactionId", "transactionId") or "default")
    file_id = str(_notification_value(notification, "file_id", "FileId", "fileHandle", "handle") or tx)

    if "open" in kind or kind in {"44", "methodpbopenfilenotification"}:
        rel = _notification_value(
            notification,
            "relative_path",
            "RelativePath",
            "path",
            "Path",
            "file_path",
            "FilePath",
            "name",
            "Name",
        )
        if not rel:
            raise ValueError("open notification missing file path")
        target = _safe_output_path(root, str(rel))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"")
        files[file_id] = str(target)
        action = "open"
        bytes_written = 0
    elif "append" in kind or kind in {"45", "methodpbappendfilenotification"}:
        target_s = files.get(file_id)
        if not target_s:
            rel = _notification_value(notification, "relative_path", "RelativePath", "path", "Path", "file_path", "FilePath")
            if not rel:
                raise ValueError(f"append notification has no open file for id {file_id!r}")
            target = _safe_output_path(root, str(rel))
            files[file_id] = str(target)
        else:
            target = Path(target_s)
        payload = _decode_notification_bytes(
            _notification_value(notification, "data", "Data", "payload", "Payload", "bytes", "Bytes", "data_base64")
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("ab") as f:
            f.write(payload)
        action = "append"
        bytes_written = len(payload)
    elif "close" in kind or kind in {"46", "methodpbclosefilenotification"}:
        target_s = files.pop(file_id, None)
        target = Path(target_s) if target_s else None
        action = "close"
        bytes_written = 0
    else:
        raise ValueError(f"unsupported file-transfer notification kind: {raw_kind!r}")

    state["files"] = files
    state_file.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    return {
        "ok": True,
        "action": action,
        "transaction_id": tx,
        "file_id": file_id,
        "path": str(target) if target else None,
        "bytes_written": bytes_written,
        "state_path": str(state_file),
        "open_file_count": len(files),
    }


def _cached_facts_path(target: str) -> Path | None:
    try:
        binary = ida_re.resolve_binary(target)
    except Exception:
        return None
    path = ida_re.cache_dir_for_binary(binary) / "facts.json"
    return path if path.is_file() else None


def _load_optional(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    return ida_re.load_facts(p)


def _decompiled_index(facts: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for item in (facts or {}).get("decompiled") or []:
        ea = str(item.get("ea") or "").lower()
        if ea:
            out[ea] = item
    return out


def _function_evidence(
    facts: dict[str, Any] | None,
    selectors: list[tuple[str, str, list[str]]],
) -> list[dict[str, Any]]:
    dec = _decompiled_index(facts)
    out: list[dict[str, Any]] = []
    for ea, role, needles in selectors:
        item = dec.get(ea.lower())
        pseudo = str((item or {}).get("pseudocode") or "")
        hits = [n for n in needles if re.search(re.escape(n), pseudo, re.IGNORECASE)]
        out.append(
            {
                "ea": ea,
                "name": (item or {}).get("name"),
                "role": role,
                "cached": item is not None,
                "confidence": "high" if item is not None and hits else ("medium" if item is not None else "needs_ida"),
                "matched_terms": hits,
            }
        )
    return out


def _string_hits(facts: dict[str, Any] | None, pattern: str, *, limit: int = 40) -> list[dict[str, Any]]:
    rx = re.compile(pattern, re.IGNORECASE)
    hits: list[dict[str, Any]] = []
    for item in (facts or {}).get("strings") or []:
        value = str(item.get("value") or "")
        if not rx.search(value):
            continue
        hits.append(
            {
                "ea": item.get("ea"),
                "value": value[:500],
                "xrefs": item.get("xrefs") or [],
            }
        )
        if len(hits) >= limit:
            break
    return hits


def _frame_debugger_schema() -> dict[str, Any]:
    try:
        battle = ida_re.resolve_binary(_BATTLE_TARGET)
        _summaries, files = proto_descriptors.extract_descriptors(battle)
        fd = files.get("PB.Messaging.Graphics.FrameDebugger.proto")
        if fd is None:
            raise KeyError("PB.Messaging.Graphics.FrameDebugger.proto not found")
        core = next(ed for ed in fd.enum_type if ed.name == "CoreMethod")
        enum_values = {v.name: v.number for v in core.value}
        messages: dict[str, list[dict[str, Any]]] = {}
        for md in fd.message_type:
            if md.name in {
                "PbBeginFrameDebuggingRequest",
                "PbSerializeRequestMessage",
                "PbSerializeReplyMessage",
                "PbFileTransferTransactionId",
                "PbOpenFileNotification",
                "PbAppendFileNotification",
                "PbCloseFileNotification",
            }:
                messages[md.name] = [
                    {
                        "name": f.name,
                        "number": f.number,
                        "type": f.type,
                        "type_name": f.type_name or None,
                        "label": f.label,
                    }
                    for f in md.field
                ]
        return {
            "ok": True,
            "source": str(battle),
            "core_methods": {
                "begin_frame_debugging_request": enum_values.get("MethodPbBeginFrameDebuggingRequest"),
                "serialize_frame_capture_request": enum_values.get("MethodPbSerializeFrameCaptureRequest"),
                "serialize_frame_capture_reply": enum_values.get("MethodPbSerializeFrameCaptureReply"),
                "open_file_notification": enum_values.get("MethodPbOpenFileNotification"),
                "append_file_notification": enum_values.get("MethodPbAppendFileNotification"),
                "close_file_notification": enum_values.get("MethodPbCloseFileNotification"),
            },
            "messages": messages,
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "core_methods": {
                "begin_frame_debugging_request": 1,
                "serialize_frame_capture_request": 17,
                "serialize_frame_capture_reply": 43,
                "open_file_notification": 44,
                "append_file_notification": 45,
                "close_file_notification": 46,
            },
            "note": "Fallback values are from the Nsight Graphics 2026.1 BattlePlugin RE pass.",
        }


async def analyze_saved_cpp_bridge(
    *,
    ida_path: str | None = None,
    force: bool = False,
    include_pylon: bool = True,
    timeout_sec: int | None = 1800,
) -> dict[str, Any]:
    """Run the targeted IDA passes needed for the saved-capture C++ bridge."""
    results: dict[str, Any] = {}
    common = {
        "ida_path": ida_path,
        "force": force,
        "string_patterns": BRIDGE_STRING_PATTERNS,
        "function_patterns": [r"Serialize|Serialization|Capture|Activity|FileTransfer|Fusion|Launch"],
        "max_strings": 400,
        "max_functions": 300,
        "max_decompile": 100,
        "timeout_sec": timeout_sec,
    }
    try:
        results["battle_plugin"] = await ida_re.analyze_binary(
            _BATTLE_TARGET,
            selected_functions=BATTLE_SELECTED_FUNCTIONS,
            max_pseudocode_chars=100_000,
            **common,
        )
    except Exception as exc:
        results["battle_plugin"] = {"ok": False, "error": str(exc)}

    if include_pylon:
        try:
            results["pylon_plugin"] = await ida_re.analyze_binary(
                _PYLON_TARGET,
                selected_functions=PYLON_SELECTED_FUNCTIONS,
                max_pseudocode_chars=140_000,
                **common,
            )
        except Exception as exc:
            results["pylon_plugin"] = {"ok": False, "error": str(exc)}

    return {
        "ok": all(bool(v.get("ok")) for v in results.values()),
        "targets": results,
        "report_tool": "ngfx_cpp_capture_saved_bridge_re_report",
    }


def saved_capture_cpp_bridge_report(
    *,
    battle_facts_path: str | None = None,
    pylon_facts_path: str | None = None,
) -> dict[str, Any]:
    """Return the distilled RE state for fully headless saved C++ export."""
    cached_battle = _cached_facts_path(_BATTLE_TARGET)
    cached_pylon = _cached_facts_path(_PYLON_TARGET)
    battle_path = battle_facts_path or (str(cached_battle) if cached_battle else None)
    pylon_path = pylon_facts_path or (str(cached_pylon) if cached_pylon else None)
    battle = _load_optional(battle_path)
    pylon = _load_optional(pylon_path)

    battle_evidence = _function_evidence(
        battle,
        [
            (
                "0x180028880",
                "Actual SerializeCapturedFrame path. Validates session/capture state, initializes file transfer, registers file callbacks, then sends PbSerializeRequestMessage.",
                ["PbSerializeReplyMessage", "PbSerializeRequestMessage", "FileTransferManager"],
            ),
            (
                "0x180042890",
                "Prepares output directory, bindless/remote flags, HostSaveDirectory, and FileTransferTransactionId.",
                ["SerializationBindless", "SerializationKeepOnRemoteMachine", "InitializeTransaction"],
            ),
            (
                "0x1800427D0",
                "Finalizes or terminates the file-transfer transaction after serialization.",
                ["FinalizeTransaction", "TerminateTransaction"],
            ),
            (
                "0x18006ACA0",
                "Adds scripted activity step RequestSaveCapture when activity mode is Generate C++ Capture.",
                ["RequestSaveCapture", "Generating C++ capture"],
            ),
            (
                "0x18006DA60",
                "Command handler for RequestSaveCapture. Builds request state, processes PbSerializeReplyMessage, finalizes transfer, and marks success/failure.",
                ["RequestSaveCaptureCommand", "PbSerializeReplyMessage", "Serialization succeeded"],
            ),
        ],
    )

    pylon_evidence = _function_evidence(
        pylon,
        [
            (
                "0x18015D360",
                "Activity id to full activity name: id 3 is Generate C++ Capture.",
                ["Generate C++ Capture"],
            ),
            (
                "0x18015E5A0",
                "Activity id to short activity name: id 3 is C++ Capture.",
                ["C++ Capture"],
            ),
            (
                "0x180115B40",
                "Saved capture Start button dispatch. Selection index 2 routes to Other Activity.",
                ["sub_180116CD0"],
            ),
            (
                "0x180116CD0",
                "Other Activity start path. Builds platform launcher settings around the saved capture and asks the platform activity manager to launch the selected activity.",
                ["platform/%1/executable", "platform/%1/arguments", "platform/%1/environment"],
            ),
            (
                "0x1801114C0",
                "Builds the extra ngfx-replay arguments by flattening selected replay option pages.",
                ["--reset", "--no-reset", "--multibuffer", "QString::split"],
            ),
            (
                "0x180110200",
                "Builds the semicolon-joined environment string passed to the platform launcher.",
                ["%1=%2"],
            ),
            (
                "0x180147480",
                "PylonFusionActivityDialog chooses the requested activity by id, requires IPylonReplayFusionActivity, and persists settings under the project launcher object.",
                ["IPylonReplayFusionActivity", "launcher"],
            ),
            (
                "0x180147C20",
                "Persists accepted activity-launcher settings back into JsonProject['launcher'].",
                ["launcher", "JsonProject", "QJsonObject"],
            ),
        ],
    )

    schema = _frame_debugger_schema()
    handoff_preview = pylon_saved_capture_handoff_preview(r"C:\path\to\capture.ngfx-gfxcap")
    return {
        "ok": True,
        "status": "pylon_activity_handoff_pinned_direct_rpc_not_yet_live_verified",
        "facts": {
            "battle_plugin": {
                "facts_path": battle_path,
                "summary": ida_re.summarize_facts(battle) if battle else None,
                "has_cached_facts": battle is not None,
            },
            "pylon_plugin": {
                "facts_path": pylon_path,
                "summary": ida_re.summarize_facts(pylon) if pylon else None,
                "has_cached_facts": pylon is not None,
            },
        },
        "private_protocol": {
            "frame_debugger_schema": schema,
            "direct_rpc_candidate": {
                "category_binding": {
                    "system_categories": {
                        "source": "ngfx-rpc.exe SystemCategories.proto",
                        "Diagnostics": 1,
                        "SystemInfo": 2,
                        "Discovery": 3,
                        "Handshake": 4,
                        "DeviceInfo": 5,
                        "Connection": 6,
                        "LocalDiscovery": 7,
                    },
                    "pylon_replay_category": {
                        "source": "ngfx-rpc.exe PylonUi.proto",
                        "BinaryReplay": 1,
                        "note": (
                            "This is in the NV.Pylon.Replay category namespace. "
                            "The remaining live binding question is how ngfx-ui places that "
                            "namespace/session on the transport before BinaryReplay requests work."
                        ),
                    },
                },
                "sequence": [
                    "Open/start an ngfx-rpc session with a saved capture loaded into frame debugging.",
                    "Send CoreMethod MethodPbBeginFrameDebuggingRequest (1) if the capture is not already in frame debugging.",
                    "Create/initialize a FileTransferTransactionId and send MethodPbSerializeFrameCaptureRequest (17) with PbSerializeRequestMessage.",
                    "Handle MethodPbOpenFileNotification (44), MethodPbAppendFileNotification (45), and MethodPbCloseFileNotification (46) until MethodPbSerializeFrameCaptureReply (43).",
                    "Index the emitted C++ project with ngfx_cpp_capture_index_calls.",
                ],
                "known_gap": "The FrameDebugger Core RPC category/session binding still needs a live ngfx-ui/ngfx-rpc sniff or additional handler-registration RE before direct sends can be marked working.",
            },
            "activity_bridge_candidate": {
                "pinned": True,
                "handoff_preview": handoff_preview,
                "platform_settings_keys": list(handoff_preview["platform_settings"].keys()),
                "sequence": [
                    "Use Pylon saved-capture Other Activity with selected activity id 3 (Generate C++ Capture).",
                    "Persist or synthesize the launcher settings that PylonFusionActivityDialog writes under the project 'launcher' object.",
                    "Start the private platform activity manager path without showing the dialog.",
                ],
                "known_gap": (
                    "The Pylon argv/config handoff is pinned: executable ngfx-replay.exe, quoted "
                    "saved-capture argument, flattened extra replay args, semicolon-joined environment, "
                    "and JsonProject['launcher'] persistence. The unpinned part is invoking Pylon's "
                    "private activity manager outside the UI process."
                ),
            },
        },
        "battle_plugin_evidence": {
            "strings": _string_hits(
                battle,
                r"C\+\+ Capture|RequestSaveCapture|PbSerialize|FileTransfer|ngfx-cppcap|HostSaveDirectory",
            ),
            "functions": battle_evidence,
        },
        "pylon_plugin_evidence": {
            "strings": _string_hits(
                pylon,
                r"Other Activity|Launch another activity|Generate C\+\+ Capture|C\+\+ Capture|PylonFusionActivityDialog",
            ),
            "functions": pylon_evidence,
        },
        "current_best_plan": [
            "Call ngfx_cpp_capture_saved_headless_attempt first; it tries each backend and validates/indexes any existing or newly emitted project.",
            "Use ngfx_cpp_capture_saved_pylon_handoff_preview to synthesize the exact launcher map for a saved capture.",
            "Try an in-process/UI-private bridge that calls the Pylon platform activity manager with that launcher map.",
            "In parallel, keep the direct FrameDebugger RPC route as the cleaner long-term path once the BinaryReplay namespace/session setup is pinned.",
        ],
        "rerun": {
            "tool": "ngfx_cpp_capture_saved_bridge_re_analyze",
            "battle_target": _BATTLE_TARGET,
            "pylon_target": _PYLON_TARGET,
        },
    }
