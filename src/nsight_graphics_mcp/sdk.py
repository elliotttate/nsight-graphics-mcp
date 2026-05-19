"""NGFX in-app SDK helpers.

Two kinds of value-add:

  1. **Reference**: enumerate the headers shipped in
     ``<install>/SDKs/NsightGraphicsSDK/<ver>/include`` and extract the
     ``NGFX_*`` function declarations so the LLM can answer "what's the
     entry point to start a GPU Trace from inside a Vulkan app?" without
     re-reading every header.

  2. **Codegen**: produce a ready-to-paste C++ snippet that integrates the
     in-app SDK for a chosen (activity, API) pair: load the runtime, init
     the activity, and start/stop a capture or trace at frame boundaries.

These rely on the headers at
``C:/Program Files/NVIDIA Corporation/Nsight Graphics .../SDKs/NsightGraphicsSDK/<ver>/include``
which is the same SDK that the in-app capture libraries are built against.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .config import Settings, discover_sdk_versions, get_settings


NGFX_FUNC_RE = re.compile(
    r"NGFX_Result\s+(NGFX_[A-Za-z0-9_]+)\s*\(\s*([^)]*)\s*\)",
    re.MULTILINE,
)


def _parse_brief(text: str, fn_start: int) -> str | None:
    """Pull the ``@brief`` line from the doxygen comment immediately above the
    function declaration at ``fn_start``."""
    # back up to the nearest /**
    before = text[:fn_start]
    open_idx = before.rfind("/**")
    if open_idx < 0:
        return None
    close_idx = before.find("*/", open_idx)
    if close_idx < 0 or close_idx > fn_start:
        return None
    block = before[open_idx + 3 : close_idx]
    # Find @brief line
    m = re.search(r"@brief\s+(.+?)(?:\n\s*\*\s*[@\n]|\Z)", block, re.DOTALL)
    if not m:
        # fallback: first non-empty stripped line of the block
        for line in block.splitlines():
            stripped = line.lstrip(" *").strip()
            if stripped:
                return stripped
        return None
    return re.sub(r"\s+", " ", m.group(1).strip()).strip()


def list_headers(settings: Settings | None = None) -> dict[str, Any]:
    """List all NGFX headers + per-header function declarations."""
    s = settings or get_settings()
    if s.sdk_root is None:
        if s.install_root:
            sdks = discover_sdk_versions(s.install_root)
            if sdks:
                s.sdk_root = sdks[0]
    if s.sdk_root is None:
        return {"ok": False, "error": "No NGFX SDK found alongside the Nsight Graphics install."}
    include = s.sdk_root / "include"
    if not include.is_dir():
        return {"ok": False, "error": f"NGFX include dir not found at {include}"}

    headers: list[dict[str, Any]] = []
    for hdr in sorted(include.glob("*.h")):
        text = hdr.read_text(encoding="utf-8", errors="replace")
        fns: list[dict[str, Any]] = []
        for m in NGFX_FUNC_RE.finditer(text):
            fns.append(
                {
                    "name": m.group(1),
                    "params": re.sub(r"\s+", " ", m.group(2)).strip(),
                    "brief": _parse_brief(text, m.start()),
                }
            )
        headers.append(
            {
                "header": hdr.name,
                "path": str(hdr),
                "function_count": len(fns),
                "functions": fns,
            }
        )

    impl = include / "Impl"
    impl_headers: list[dict[str, Any]] = []
    if impl.is_dir():
        for hdr in sorted(impl.glob("*.h")):
            impl_headers.append({"header": f"Impl/{hdr.name}", "path": str(hdr)})

    return {
        "ok": True,
        "sdk_root": str(s.sdk_root),
        "include_dir": str(include),
        "headers": headers,
        "impl_headers": impl_headers,
    }


def grep_sdk(pattern: str, *, settings: Settings | None = None, max_hits: int = 200) -> dict[str, Any]:
    """Run a simple line-level search across the NGFX include directory.

    Useful for answering "where is ``NGFX_FrameBoundary_D3D12_Params`` defined?"
    without needing a full source-indexer.
    """
    s = settings or get_settings()
    if s.sdk_root is None:
        return {"ok": False, "error": "No NGFX SDK found."}
    include = s.sdk_root / "include"
    if not include.is_dir():
        return {"ok": False, "error": f"NGFX include dir not found at {include}"}

    try:
        rx = re.compile(pattern)
    except re.error as exc:
        return {"ok": False, "error": f"invalid regex: {exc}"}

    hits: list[dict[str, Any]] = []
    for hdr in sorted(include.rglob("*.h")):
        try:
            text = hdr.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                hits.append(
                    {
                        "path": str(hdr.relative_to(include)),
                        "line": i,
                        "text": line.strip(),
                    }
                )
                if len(hits) >= max_hits:
                    return {
                        "ok": True,
                        "pattern": pattern,
                        "hits": hits,
                        "truncated": True,
                    }
    return {"ok": True, "pattern": pattern, "hits": hits, "truncated": False}


# ---------------------------------------------------------------------------
# Codegen
# ---------------------------------------------------------------------------


SUPPORTED_APIS = ("D3D12", "Vulkan", "OpenGL", "CUDA", "CUDART")
SUPPORTED_ACTIVITIES = ("GraphicsCapture", "GPUTrace", "FrameBoundary")


_SNIPPET_TEMPLATE_GRAPHICS_CAPTURE = r"""// SPDX-License-Identifier: Apache-2.0
// Generated by nsight-graphics-mcp. Drop this into your application to drive
// Nsight Graphics Graphics Capture from inside the process.
//
// Build requirements:
//   * Include path: <NSIGHT_INSTALL>/SDKs/NsightGraphicsSDK/<ver>/include
//   * No .lib to link — the headers are header-only. The runtime is loaded
//     from the Nsight Graphics installation at runtime via NGFX_LoadLibrary.
//
// Reference headers:
//   * NGFX_GraphicsCapture_{api}.h
//   * NGFX_GraphicsCapture_Common.h

#include <NGFX_GraphicsCapture_{api}.h>
#include <NGFX_GraphicsCapture_Common.h>

// Initialise once, near startup, after creating your {api} device/instance.
static bool NgfxStartGraphicsCapture_{api}(const NGFX_PathChar* installationPath /* may be NULL to auto-discover */)
{{
    NGFX_GraphicsCapture_InjectionSettings settings = {{}};
    NGFX_GraphicsCapture_InjectionSettings_SetDefaults(&settings);
    settings.frameCount            = 1;            // capture a single frame
    settings.terminateAfterCapture = false;
    settings.outputDir             = "captures";   // or NULL for cwd

    NGFX_GraphicsCapture_Inject_{api}_Params inject = {{}};
    inject.installationPath = installationPath;    // resolved by host if NULL
    inject.settings         = &settings;
    if (NGFX_GraphicsCapture_Inject_{api}(&inject) != NGFX_Result_Success) return false;

    NGFX_GraphicsCapture_InitializeActivity_{api}_Params init = {{}};
    // Fill API-specific fields (device/queue handles) — see
    //   NGFX_GraphicsCapture_{api}_Types.h
    if (NGFX_GraphicsCapture_InitializeActivity_{api}(&init) != NGFX_Result_Success) return false;
    return true;
}}

// Call when you want to start a one-shot capture. The next frame boundary
// (Present/SwapBuffers, or an explicit NGFX_FrameBoundary call) starts the
// capture, and it ends after ``settings.frameCount`` frames.
static bool NgfxRequestCapture_{api}()
{{
    NGFX_GraphicsCapture_RequestCapture_{api}_Params params = {{}};
    return NGFX_GraphicsCapture_RequestCapture_{api}(&params) == NGFX_Result_Success;
}}
"""

_SNIPPET_TEMPLATE_GPU_TRACE = r"""// SPDX-License-Identifier: Apache-2.0
// Generated by nsight-graphics-mcp. Drop this into your application to drive
// Nsight Graphics GPU Trace from inside the process.
//
// Build requirements:
//   * Include path: <NSIGHT_INSTALL>/SDKs/NsightGraphicsSDK/<ver>/include
//   * No .lib to link — the headers are header-only. The runtime is loaded
//     from the Nsight Graphics installation at runtime.
//
// Reference headers:
//   * NGFX_GPUTrace_{api}.h
//   * NGFX_GPUTrace_Common.h

#include <NGFX_GPUTrace_{api}.h>
#include <NGFX_GPUTrace_Common.h>

static bool NgfxInitializeGPUTrace_{api}(const NGFX_PathChar* installationPath)
{{
    NGFX_GPUTrace_InjectionSettings settings = {{}};
    NGFX_GPUTrace_InjectionSettings_SetDefaults(&settings);
    settings.startEvent          = NGFX_GPUTrace_StartEvent_Manual;
    settings.stopEvent           = NGFX_GPUTrace_StopEvent_Frame;
    settings.stopParams.frameCount = 1;
    settings.maxDurationMs       = 1000;
    settings.collectScreenshot   = true;
    settings.gpuClockMode        = NGFX_GPUTrace_GPUClockMode_LockToBase;

    NGFX_GPUTrace_Inject_{api}_Params inject = {{}};
    inject.installationPath = installationPath;
    inject.settings         = &settings;
    if (NGFX_GPUTrace_Inject_{api}(&inject) != NGFX_Result_Success) return false;

    NGFX_GPUTrace_InitializeActivity_{api}_Params init = {{}};
    // Fill API-specific fields (device/instance handles) — see
    //   NGFX_GPUTrace_{api}_Types.h
    if (NGFX_GPUTrace_InitializeActivity_{api}(&init) != NGFX_Result_Success) return false;

    NGFX_GPUTrace_ActivateTrace_{api}_Params activate = {{}};
    if (NGFX_GPUTrace_ActivateTrace_{api}(&activate) != NGFX_Result_Success) return false;
    return true;
}}

// Bracket the work you want traced.
static bool NgfxStartTrace_{api}()
{{
    NGFX_GPUTrace_StartTrace_{api}_Params params = {{}};
    return NGFX_GPUTrace_StartTrace_{api}(&params) == NGFX_Result_Success;
}}
static bool NgfxStopTrace_{api}()
{{
    NGFX_GPUTrace_StopTrace_{api}_Params params = {{}};
    return NGFX_GPUTrace_StopTrace_{api}(&params) == NGFX_Result_Success;
}}
"""


_SNIPPET_TEMPLATE_FRAME_BOUNDARY = r"""// SPDX-License-Identifier: Apache-2.0
// Generated by nsight-graphics-mcp. Frame-boundary helper for the NGFX SDK.
// Calling this at the start of every frame is what gives Graphics Capture
// and GPU Trace a portable "frame" delimiter independent of Present().
//
// Reference header: NGFX_{api}.h

#include <NGFX_{api}.h>

// Call at frame start. Pass any output resources / queues you want NGFX to
// treat as the "frame output" — see NGFX_{api}_Types.h for the full struct.
static bool NgfxFrameBoundary_{api}()
{{
    NGFX_FrameBoundary_{api}_Params params = {{}};
    // Fill API-specific handles before calling.
    return NGFX_FrameBoundary_{api}(&params) == NGFX_Result_Success;
}}
"""


def generate_snippet(activity: str, api: str, *, settings: Settings | None = None) -> dict[str, Any]:
    """Generate a C++ integration snippet for ``(activity, api)``.

    ``activity`` ∈ ``{"GraphicsCapture", "GPUTrace", "FrameBoundary"}``
    ``api``      ∈ ``{"D3D12", "Vulkan", "OpenGL", "CUDA", "CUDART"}``
    """
    if activity not in SUPPORTED_ACTIVITIES:
        return {
            "ok": False,
            "error": f"activity must be one of {SUPPORTED_ACTIVITIES}, got {activity!r}",
        }
    if api not in SUPPORTED_APIS:
        return {
            "ok": False,
            "error": f"api must be one of {SUPPORTED_APIS}, got {api!r}",
        }
    s = settings or get_settings()
    if activity == "GraphicsCapture":
        if api not in ("D3D12", "Vulkan"):
            return {
                "ok": False,
                "error": f"GraphicsCapture activity supports only D3D12 and Vulkan, got {api!r}",
            }
        snippet = _SNIPPET_TEMPLATE_GRAPHICS_CAPTURE.format(api=api)
        headers = [f"NGFX_GraphicsCapture_{api}.h", "NGFX_GraphicsCapture_Common.h"]
    elif activity == "GPUTrace":
        snippet = _SNIPPET_TEMPLATE_GPU_TRACE.format(api=api)
        headers = [f"NGFX_GPUTrace_{api}.h", "NGFX_GPUTrace_Common.h"]
    else:  # FrameBoundary
        snippet = _SNIPPET_TEMPLATE_FRAME_BOUNDARY.format(api=api)
        headers = [f"NGFX_{api}.h"]

    include_dir = (s.sdk_root / "include") if s.sdk_root else None
    return {
        "ok": True,
        "activity": activity,
        "api": api,
        "snippet": snippet,
        "include_dir": str(include_dir) if include_dir else None,
        "headers_used": headers,
    }
