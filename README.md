# nsight-graphics-mcp

An MCP (Model Context Protocol) server for **NVIDIA Nsight Graphics** on
Windows. It wraps the entire Nsight Graphics command-line surface
(`ngfx.exe`, `ngfx-capture.exe`, `ngfx-replay.exe`, `ngfx-rpc.exe`, the
`nv-aftermath-*` tools, `nv-nsight-remote-monitor.exe`, the layer-install
batch scripts, the NGFX in-app SDK headers, `glslang.exe`, and the bundled
DXC) so an LLM agent can drive Graphics Capture, GPU Trace Profiler,
Generate C++ Capture, OpenGL Frame Debugger, Aftermath crash analysis, and
in-app integration end-to-end — without the Nsight UI.

> Why a wrapper? The Nsight Graphics CLIs are scriptable, but their
> outputs are coarse: `ngfx-replay --metadata-functions` dumps the entire
> recorded API stream to stdout, `--metadata-objects` dumps every API
> object as JSON, `.nsight-gputrace` reports are zip-like archives, and
> the NGFX in-app SDK is a tree of headers. `nsight-graphics-mcp` indexes
> those coarse outputs into per-capture SQLite databases, peeks inside
> the archives, parses the SDK headers, and exposes precise queries the
> LLM can call instantly without re-running the CLI.

## What it can do

### Drive the four documented activities (`ngfx.exe --activity`)

| Activity | MCP tool (launched) | MCP tool (attached) |
| --- | --- | --- |
| Graphics Capture | `ngfx_graphics_capture_launched` | `ngfx_graphics_capture_attached` |
| GPU Trace Profiler | `ngfx_gputrace_launched` | `ngfx_gputrace_attached` |
| Generate C++ Capture | `ngfx_cpp_capture_launched` | (use `ngfx_raw` with `--attach-pid`) |
| OpenGL Frame Debugger | `ngfx_framedebugger_launched` | (use `ngfx_raw` with `--attach-pid`) |

Each one accepts the full set of activity-specific flags from `ngfx
--help-all` — start triggers (`--start-after-frames` / `--start-after-ms`
/ `--start-after-hotkey` / `--start-with-ngfx-sdk` / …), stop triggers
(`--limit-to-frames` / `--max-duration-ms` / `--stop-with-ngfx-sdk` / …),
per-arch metric-set selection, GPU clock locking, shader-pipeline
collection toggles, and so on.

Pass `background=True` to keep `ngfx.exe` running so you can hit the
capture / trace hotkey in-app — the call returns a launch-session handle
you can poll with `ngfx_launch_status` and terminate with
`ngfx_launch_stop`.

### Headless capture (`ngfx-capture.exe`) — no Nsight UI required

| Tool | What it does |
| --- | --- |
| `ngfx_capture_launched` | Run `ngfx-capture.exe` directly. Produces a `.ngfx-gfxcap` with a bundled replayer. Supports all triggers, compression, HVVM modes, delimiter modes, troubleshooting knobs, and ray-tracing options from `ngfx-capture --help`. |
| `ngfx_capture_recapture` | `--recapture` an existing capture with current format. |
| `ngfx_capture_recompress` | `--recompress` for higher compression / format upgrades. |

### Object index (Pipelines / Shaders / Resources — GUI 'Resources' pane parity)

| Tool | What it answers |
| --- | --- |
| `ngfx_index_objects` | Index every API object recorded into a SQLite DB (categorised: pipeline / shader / resource / descriptor / sync / command / queue / surface / device / ray_tracing / other). |
| `ngfx_query_objects` | Filter by `type_name` / `category` / `name_regex` / `api`. |
| `ngfx_get_object` | Look up a single object by uid. |
| `ngfx_object_histogram` | Histogram by `type_name`, `category`, or `api`. |
| `ngfx_object_query` | Read-only SQL against the object index. |
| `ngfx_list_pipelines` | Every Pipeline / PipelineLayout / DescriptorSetLayout / PipelineCache / RootSignature / StateObject. |
| `ngfx_list_shaders` | Every ShaderModule / ShaderProgram / Shader. |
| `ngfx_list_resources` | Every Buffer / Image / Sampler / DeviceMemory / Heap. |

### Protobuf schema reference (RE-derived)

The internal capture format is protobuf-encoded in the `NV.*` namespace.
The MCP extracts the schema directly from the Nsight binaries so the LLM
can navigate the format conceptually without re-running protoc.

Two layers are exposed:

* **Inventory only (fast)** — string-scan for proto filenames and message
  names. No protobuf decoder required.
* **Full FileDescriptorProto extraction** — walks the embedded descriptor
  blobs in `ngfx-replay.exe`, decodes them with
  `google.protobuf.descriptor_pb2`, and builds a `DescriptorPool` so any
  message can be looked up by FQN and dynamically instantiated. Recovers
  all 22 .proto files + 648 messages including the critical
  `NV.EventParameters.Messages.PbFunctionCallDesc` (which has the per-call
  `functionName` + repeated `PbArgument arguments` that `--metadata-functions`
  hides).

| Tool | What it answers |
| --- | --- |
| `ngfx_proto_schemas` | Inventory of every .proto file (22+), Pb* message (~2000+), and FQN extracted from `ngfx-replay.exe` / `ngfx-capture.exe` / `PylonReplay_PluginInterface.dll`. |
| `ngfx_proto_search` | Regex-grep the inventory. E.g. `pattern='RootParam'` → `PbRootParameter`, `PbRootDescriptor`, `PbRootParametersInfo`, ... |
| `ngfx_proto_describe` | **Full field-level schema** for any message FQN (field name, number, type, repeated, nested). Backed by extracted `FileDescriptorProto` blobs. |
| `ngfx_proto_list_messages` | List every FQN in the decoded schema pool (including nested types), optionally regex-filtered. |
| `ngfx_proto_extract_descriptors` | Re-extract `FileDescriptorProto` blobs from a Nsight binary and rebuild the in-process schema registry. Call once after upgrading Nsight. |

### Low-level capture-format probing (experimental, RE-derived)

| Tool | What it answers |
| --- | --- |
| `ngfx_capture_format_info` | Magic check (`nlypelif` = "Pylon file"), SHA-256, tentative header field interpretation. See `docs/CAPTURE_FORMAT.md`. |
| `ngfx_capture_lz4_decompress` | Attempt LZ4-block decompression of a byte range from a capture file. |
| `ngfx_decode_protobuf_wire` | Generic protobuf-wire-format decoder over a byte range (returns top-level fields without needing the schema). |

### Capture session management + inspection

| Tool | What it answers |
| --- | --- |
| `ngfx_open_capture` | Register a `.ngfx-gfxcap` and get a session handle. |
| `ngfx_list_captures` / `ngfx_close_capture` | Manage open capture handles. |
| `ngfx_find_recent_captures` | Search the default Nsight output dirs (and any extras) for recent capture / gputrace files. Newest first. |
| `ngfx_list_captures_in_dir` | Enumerate captures under any directory. |
| `ngfx_capture_summary` | Parsed `ngfx-replay --metadata` (cached per mtime). |
| `ngfx_capture_objects` | Full JSON of every API object recorded (`--metadata-objects`). |
| `ngfx_capture_functions` | Recorded function stream (`--metadata-functions`) — raw lines. |
| `ngfx_capture_logs` | Embedded application + driver log messages. |
| `ngfx_capture_screenshot` | Write the embedded final-present screenshot to PNG/TGA/BMP/JPG. |
| `ngfx_capture_diff` | Diff the parsed summaries of two captures. |

### Fine-grained event queries (built on a SQLite index of the function stream)

| Tool | What it answers |
| --- | --- |
| `ngfx_index_events` | Build / refresh the per-capture function index. |
| `ngfx_find_events` | "All draws between events 2100 and 2480", "every `vkCmdPipelineBarrier2`", "every `Dispatch*` in the first 500 calls". |
| `ngfx_get_event` | Full per-call record by index. |
| `ngfx_event_histogram` | Histogram by `name` or `kind` (draw / dispatch / copy / barrier / present / ray_tracing / sync / set_state / other). |
| `ngfx_find_calls_by_arg` | "Every call that mentions this resource handle / name". |
| `ngfx_event_query` | Read-only SQL (SELECT / WITH) against the index. |

### Replay (`ngfx-replay.exe`)

| Tool | What it does |
| --- | --- |
| `ngfx_replay_run` | Replay a capture with full control: loop count, perf-report-dir, device selection (name / vendor / index), present mode, vsync, multibuffering, reset mode, … |
| `ngfx_replay_screenshot` | Dump per-frame rendered output during replay (uses RE-discovered `--replay-screenshot*` flags). No UI required. |
| `ngfx_replay_gpu_frametimes` | Per-frame GPU timing collection (RE-discovered `--collect-gpu-frametimes`). |
| `ngfx_replay_run_advanced` | Run `ngfx-replay` with arbitrary flags — surfaces ~65 hidden flags discovered by binary analysis (validation modes, NVAPI/NGX/NRC/DLSS toggles, force-* recovery modes, etc.). |
| `ngfx_replay_bundle_extract` | Extract a bundled-replayer capture's contents to a dir without running it. |
| `ngfx_replay_metadata` | Direct passthrough to `--metadata`. |

### GPU Trace report inspection

| Tool | What it does |
| --- | --- |
| `ngfx_open_gputrace` | Register a `.nsight-gputrace` file as a session handle. |
| `ngfx_gputrace_inspect` | Quick member listing + container check. |
| `ngfx_gputrace_archive` | Full zip listing + auto-decoded manifest JSON. |
| `ngfx_gputrace_read_member` | Read a member as UTF-8 (auto-decodes JSON / CSV). |
| `ngfx_gputrace_extract` | Extract a member to disk. |
| `ngfx_list_perf_report` | Enumerate `ngfx-replay --perf-report-dir` artifacts with auto-decoded JSON/CSV inline. |
| `ngfx_gputrace_archs` | List GPU architectures accepted by `--architecture`. |

### Generate C++ Capture → build → run

The CLI activity (`ngfx --activity 'Generate C++ Capture'`) requires the
original application to launch — it can't run against a saved capture.
The MCP also exposes the UI-driven path for that case (see next section).

| Tool | What it does |
| --- | --- |
| `ngfx_cpp_capture_launched` | Run the Generate-C++-Capture activity (CLI; relaunches the app). |
| `ngfx_cpp_capture_find_solution` | Locate the produced `.sln`. |
| `ngfx_cpp_capture_build` | MSBuild the project (auto-discovers MSBuild via vswhere). |
| `ngfx_cpp_capture_run` | Run the produced exe and capture its output. |

### Per-call argument extraction (C++ Capture → SQLite index)

Nsight's CLI (`ngfx-replay --metadata-functions`) returns function NAMES
per event but **no argument values** — it's a deliberate design choice.
To answer "what's bound at root parameter N of event G?" or "which CBV
did this draw use?" you need argument values.

The workflow these tools enable:

1. Open a saved capture in the Nsight UI (which CAN run *Generate C++
   Capture* on saved captures, unlike the CLI activity).
2. Click *File → Activity → Generate C++ Capture*, pick an output dir.
3. The MCP parses the emitted `.cpp` files and indexes every command-list
   / command-buffer call into SQLite, keyed by a synthetic `event_index`
   that matches `--metadata-functions` order.
4. Per-event queries — full structured args for ~25 common
   D3D12/Vulkan/OpenGL descriptor / draw / dispatch calls.
5. `ngfx_cpp_capture_descriptor_bindings` walks backwards from any
   draw/dispatch to reconstruct the **full root-param + descriptor heap +
   CBV/SRV/UAV + VBV/IBV + RT state in effect at that event** — the
   missing-piece answer for "what's bound here?"

| Tool | What it does |
| --- | --- |
| `ngfx_cpp_capture_open_in_ui` | Open a saved capture in `ngfx-ui.exe` with step-by-step prompts for the human. |
| `ngfx_cpp_capture_wait_for_project` | Poll a directory until the generated `.sln` lands and its size stabilises. |
| `ngfx_cpp_capture_index_calls` | Walk all `.cpp` files in a generated project, parse command-list calls, write a SQLite index to `<project>/.ngfxmcp_cpp_calls.db`. |
| `ngfx_cpp_capture_event_args` | Single-event lookup (function name, raw + structured args, source `file:line`). |
| `ngfx_cpp_capture_query_calls` | Filtered query: kind / api / name / regex / contains / event range. |
| `ngfx_cpp_capture_descriptor_bindings` | Reconstruct full bound state at an event by scanning backwards (D3D12 root params + descriptor heaps + IA/OM/RTs; Vulkan pipeline + descriptor sets per `first_set` + VB/IB/push constants). |
| `ngfx_cpp_capture_sql` | Read-only SELECT/WITH escape hatch against the index. |

The same parser is used by `ngfx_find_calls_by_arg` and by
`ngfx_resolve_handle` when a sibling C++-Capture index is present.

### Capture-stream diff (event-level)

| Tool | What it does |
| --- | --- |
| `ngfx_capture_diff` | Diff the parsed `--metadata` summaries of two captures (high-level: device, frame counts, version). |
| `ngfx_event_stream_diff` | **Deeper:** diff the per-event function streams via LCS. Returns per-function histogram delta, per-kind histogram delta, contiguous insert/delete/replace clusters, and (if both captures have a C++-Capture index) per-event arg diffs. |
| `ngfx_function_stream_diff` | Lightweight name-only diff over raw `--metadata-functions` output. |

### PSO → DXBC / SPIR-V hash mapping

Nsight's CLI does **not** expose the link between a PSO (D3D12 pipeline /
Vulkan VkPipeline) and the shader bytecode hashes it uses. The protobuf
schema *does* have it (`NV.Pylon.Replay.PbPipelineShaderStageInfo` —
fields `pipeline`, `driverAppHash`, `stage`) but extracting it from a
saved `.ngfx-gfxcap` is part of the in-progress capture decoder.

The path that works today: parse the *Generate C++ Capture* emitted
source. Shader bytecode is emitted as flat `static const unsigned char`
arrays — DXBC blobs have the Microsoft compiler's 128-bit MD5 hash baked
in at bytes 4..20 of the container (the exact bytes Nsight / PIX /
RenderDoc display as the shader identity). For SPIR-V we compute SHA-1
of the blob so Vulkan shaders still get a stable identity.

PSO creation calls (`CreateGraphicsPipelineState` /
`CreateComputePipelineState` / `vkCreateGraphicsPipelines` /
`vkCreateComputePipelines` / `vkCreateRayTracingPipelinesKHR`) reference
those byte-array symbols (D3D12) or `vkCreateShaderModule` handles
(Vulkan). The indexer matches them up.

| Tool | What it answers |
| --- | --- |
| `ngfx_pso_index` | Walk a C++-Capture project, parse every shader byte-array + every PSO creation call, write `shader_blobs` + `pso_shaders` tables to the existing C++-Capture index DB. |
| `ngfx_pso_get` | Look up one PSO's full stage map: each stage → `{shader_symbol, format (dxbc/dxil/spirv), hash_hex, hash_source, declared_byte_count, head_hex}`. |
| `ngfx_pso_list` | Enumerate every indexed PSO with a one-line stage summary (`VS:g_VS_xxx, PS:g_PS_yyy`). |
| `ngfx_pso_find_by_shader` | Reverse lookup: given a shader symbol OR a DXBC/SPIR-V hash, which PSOs use it (and as which stage)? Useful when a shader-debugger or perf trace gives you a hash. |
| `ngfx_shader_blobs_list` | Enumerate every indexed shader byte-array (filterable by format / hash). |

### Object handle / UID resolver

"What wrote to this buffer?" without the GUI. Given a uid or canonical
name (e.g. `Buffer_91`), cross-references the objects index, the events
index, and (when present) the C++-Capture index.

| Tool | What it does |
| --- | --- |
| `ngfx_resolve_handle` | Find an object's create call + every event that mentions it, bucketed by role (create / write / bind / draw / dispatch / barrier / destroy / other). Degrades to "create call only" when a C++-Capture index isn't built for the capture. |

### Frame cost analysis (top-N expensive actions)

| Tool | What it does |
| --- | --- |
| `ngfx_top_n_costs` | Top-N rows by GPU time across all CSVs in a `ngfx-replay --perf-report-dir` output, or a `.nsight-gputrace` archive (auto-unzips). Sniffs column names (no hardcoded schema) and normalises units (ns/µs/ms/s). Filters: `kind_filter`, `name_regex`, `csv_basename_hint`. |

### Aftermath / Remote / RPC

| Tool | What it does |
| --- | --- |
| `ngfx_aftermath_control` | Configure Aftermath crash-dump generation. |
| `ngfx_aftermath_monitor_start` | Watch for GPU crashes/hangs in the background. |
| `ngfx_aftermath_format` | Format an existing crash dump. |
| `ngfx_remote_monitor_start` | Start `nv-nsight-remote-monitor` headless for remote UI debugging. |
| `ngfx_rpc_start` | Start `ngfx-rpc.exe` (replayer RPC server) on TCP / named pipe / domain socket. |

### Layer (un)install for Vulkan / VulkanSC / OpenXR

| Tool | What it does |
| --- | --- |
| `ngfx_layer_list` | List every layer-install batch script shipped with Nsight Graphics and whether each is present. |
| `ngfx_layer_install` | Run a layer (un)install script. Supports per-user + system-wide (`global_install=True`). |

### NGFX in-app SDK (header-only C/C++ runtime)

| Tool | What it does |
| --- | --- |
| `ngfx_sdk_reference` | Enumerate every header in the SDK and its parsed `NGFX_*` function declarations + briefs. |
| `ngfx_sdk_grep` | Regex search across the NGFX include tree. |
| `ngfx_sdk_header_text` | Return the raw text of any SDK header (e.g. `NGFX_GPUTrace_D3D12.h`). |
| `ngfx_sdk_snippet` | Codegen a ready-to-paste C++ snippet for `(activity, api)` — e.g. `(GPUTrace, Vulkan)` → an init + start/stop pair. |

### Project files + UI hand-off

| Tool | What it does |
| --- | --- |
| `ngfx_project_create` / `ngfx_project_read` / `ngfx_project_update` | Author / read / mutate `.nsight-gfxproj` XML so subsequent `ngfx --project <file>` invocations are reproducible. |
| `ngfx_open_in_ui` | Spawn the full Nsight Graphics UI with a capture / gputrace / project preloaded. |

### Shader compilation

| Tool | What it does |
| --- | --- |
| `ngfx_glslang_compile` | Compile GLSL → SPIR-V (uses bundled `glslang.exe`). |
| `ngfx_dxc_compile` | Compile HLSL via DXC (bundled `dxc.exe` if present, else `dxc` on PATH). |
| `ngfx_shaderdebugger_configure` | Run `nv-shaderdebugger-configurator.exe`. |

### Discovery + escape hatch

| Tool | What it does |
| --- | --- |
| `ngfx_environment` | Resolved install path, SDK path, per-tool exe paths, default capture / GPU-trace dirs. |
| `ngfx_list_installs` | Every Nsight Graphics version detected. |
| `ngfx_version` | `ngfx --version`. |
| `ngfx_list_activities` | The exact activity-name strings `ngfx --activity` accepts. |
| `ngfx_launch_status` / `ngfx_list_launches` / `ngfx_launch_stop` | Manage long-running background processes spawned by any of the tools above. |
| `ngfx_raw` | Invoke any of the Nsight tools (`ngfx`, `ngfx_capture`, `ngfx_replay`, `ngfx_rpc`, `ngfx_ui`, `aftermath_*`, `remote_monitor`, `shaderdebugger_configurator`, `glslang`) with arbitrary argv. The exe path is prepended automatically. |

## How big is the surface?

**110 MCP tools** as of this writing, grouped by the sections below.
Run `nsight-graphics-mcp --list-tools` (or import the package and inspect
`server`) for an up-to-date enumeration.

## Install

```powershell
git clone https://github.com/elliotttate/nsight-graphics-mcp
cd nsight-graphics-mcp
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

Runtime dependencies (auto-installed):
* `mcp>=1.2` — MCP server SDK
* `pydantic>=2.0` — schema validation for MCP tool params
* `psutil>=5.9` — process / handle introspection for launch sessions
* `protobuf>=4.21` — decoding the embedded `FileDescriptorProto` blobs
  used by `proto_descriptors` / `ngfx_proto_describe`

Requires **Windows** and **NVIDIA Nsight Graphics** installed (default
location `C:\Program Files\NVIDIA Corporation\Nsight Graphics <version>`).
The MCP auto-discovers the newest installed version; override with
`NSIGHT_GRAPHICS_MCP_INSTALL_ROOT=<path>` or per-tool overrides
(`NSIGHT_GRAPHICS_MCP_NGFX`, `NSIGHT_GRAPHICS_MCP_NGFX_CAPTURE`,
`NSIGHT_GRAPHICS_MCP_NGFX_REPLAY`, …).

Quick smoke test:

```powershell
nsight-graphics-mcp --help
.venv\Scripts\python.exe -c "from nsight_graphics_mcp.config import get_settings; import json; print(json.dumps(get_settings().installation_info(), indent=2, default=str))"
```

## Wiring it into Claude Code / Claude Desktop

Add to your MCP config (`claude_desktop_config.json` or the CLI equivalent):

```json
{
  "mcpServers": {
    "nsight-graphics": {
      "command": "E:/github/nsight-graphics-mcp/.venv/Scripts/nsight-graphics-mcp.exe",
      "args": [],
      "env": {
        "NSIGHT_GRAPHICS_MCP_INSTALL_ROOT": "C:/Program Files/NVIDIA Corporation/Nsight Graphics 2026.1.0"
      }
    }
  }
}
```

(Set `NSIGHT_GRAPHICS_MCP_INSTALL_ROOT` only if auto-discovery isn't
finding the right install — pass the directory that contains
`host/windows-desktop-nomad-x64/`.)

## Typical workflows

### 1. Capture, then analyze

```
ngfx_capture_launched(
    exe="C:/games/MyGame.exe",
    args=["-windowed"],
    output_file="mygame.ngfx-gfxcap",
    output_dir="C:/captures",
    capture_frame=120,
    bundle_replayer=True,
)

ngfx_open_capture("C:/captures/mygame.ngfx-gfxcap")
ngfx_capture_summary(capture="<handle>")
ngfx_index_events(capture="<handle>")
ngfx_event_histogram(capture="<handle>", by="kind")
```

### 2. Interactive: launch, press F11 in-game, find the capture

```
ngfx_capture_launched(
    exe="C:/games/MyGame.exe",
    output_dir="C:/captures",
    capture_hotkey=True,
    background=True,
)
# ...play, hit F11...
ngfx_find_recent_captures(limit=5)
ngfx_open_capture("<newest path>")
```

### 3. "What draw inside marker X is most expensive?" (no UI)

```
ngfx_gputrace_launched(
    exe="C:/games/MyGame.exe",
    architecture="Blackwell GB20x",
    metric_set_name="Top-Level Triage",
    multi_pass_metrics=True,
    real_time_shader_profiler=True,
    limit_to_frames=1,
    auto_export=True,
)

# Find newest .nsight-gputrace
ngfx_find_recent_captures(kinds=["gpu_trace"], limit=1)
ngfx_open_gputrace("<path>")
ngfx_gputrace_archive(gputrace="<handle>")
ngfx_gputrace_read_member(gputrace="<handle>", member="metrics.json")
```

### 4. In-app SDK integration

```
ngfx_sdk_reference()                                    # discover all entry points
ngfx_sdk_snippet(activity="GraphicsCapture", api="D3D12")
ngfx_sdk_grep(pattern="NGFX_GPUTrace_StartEvent_")      # find struct fields / enums
ngfx_sdk_header_text(header="NGFX_GraphicsCapture_D3D12_Types.h")
```

### 5. Find every call that touches a specific resource

```
ngfx_index_events(capture="<h>")
ngfx_find_calls_by_arg(capture="<h>", substring="0x000001E1ABCD0000", limit=200)
ngfx_find_events(capture="<h>", kind="barrier", start=2000, end=3000)
```

### 6. Generate a C++ repro and verify it builds

```
ngfx_cpp_capture_launched(
    exe="C:/games/MyGame.exe",
    wait_frames=120,
    output_dir="C:/repros/mygame_frame120",
)
ngfx_cpp_capture_find_solution(dir_or_sln="C:/repros/mygame_frame120")
ngfx_cpp_capture_build(dir_or_sln="C:/repros/mygame_frame120")
ngfx_cpp_capture_run(exe="<produced .exe>")
```

### 7. Enable Vulkan capture layer for the current user

```
ngfx_layer_list()
ngfx_layer_install(layer="vk_ngfx_capture")
# ... run your Vulkan app, capture via F11, then:
ngfx_layer_install(layer="vk_ngfx_capture", uninstall=True)
```

### 8. Hand off to the UI when needed

```
ngfx_open_in_ui(path="C:/captures/mygame.ngfx-gfxcap")
```

### 9. Escape hatch — anything not exposed by a typed tool

```
ngfx_raw(tool="ngfx_replay", argv=[
  "--metadata-objects", "--quiet", "C:/captures/mygame.ngfx-gfxcap",
])
```

### 10. Per-call argument extraction (UI roundtrip → SQLite index)

When `--metadata-functions` only gives you function names but you need
"what's bound at root parameter 3 of event 18742?":

```
ngfx_cpp_capture_open_in_ui(capture="C:/captures/mygame.ngfx-gfxcap")
# (human clicks File → Activity → Generate C++ Capture, picks output dir)

ngfx_cpp_capture_wait_for_project(
    watch_dir="C:/captures/mygame.ngfx-gfxcap.ngfxmcp/cpp_capture")
# → returns {project_dir: "...", solution: "...sln"}

ngfx_cpp_capture_index_calls(project_dir="<project_dir>")
# → builds <project_dir>/.ngfxmcp_cpp_calls.db

ngfx_cpp_capture_descriptor_bindings(
    db_path="<project_dir>/.ngfxmcp_cpp_calls.db",
    event_index=18742,
)
# → {d3d12: {root_signature, descriptor_heaps, pipeline_state,
#            root_params: {0: {call, ...}, 1: {...}}, vertex_buffers,
#            index_buffer, render_targets}, ...}
```

### 11. "What wrote to this buffer?"

```
ngfx_index_objects(capture="C:/captures/mygame.ngfx-gfxcap")
ngfx_index_events(capture="C:/captures/mygame.ngfx-gfxcap")
# (optional but recommended: run the C++ Capture flow first)

ngfx_resolve_handle(
    capture="C:/captures/mygame.ngfx-gfxcap",
    object_name="Buffer_91",
)
# → {uid, type_name, category, create_call: {event_index, function_name},
#    mention_count, mentions_by_role: {bind: 14, write: 2, draw: 0, ...},
#    mentions: [...]}
```

### 12. Frame perf triage — top-N expensive draws

```
ngfx_gputrace_launched(
    exe="C:/games/MyGame.exe", architecture="Blackwell GB20x",
    limit_to_frames=1, auto_export=True,
)
# ngfx writes a .nsight-gputrace; or use --perf-report-dir to get CSVs:
ngfx_replay_run_advanced(
    capture="C:/captures/mygame.ngfx-gfxcap",
    extra_args=["--perf-report-dir", "C:/perf/mygame"],
)
ngfx_top_n_costs(report_or_trace="C:/perf/mygame", n=20, kind_filter="draw")
```

### 13. Capture diff — what changed between good and bad?

```
ngfx_index_events(capture="C:/captures/good.ngfx-gfxcap")
ngfx_index_events(capture="C:/captures/bad.ngfx-gfxcap")
ngfx_event_stream_diff(
    capture_a="C:/captures/good.ngfx-gfxcap",
    capture_b="C:/captures/bad.ngfx-gfxcap",
    cluster_min_size=2,
)
# → function/kind histogram deltas + LCS-aligned insert/delete clusters,
# + arg-level diff if both have a C++-Capture index.
```

### 14. PSO → DXBC hash lookup

Nsight's CLI hides the link between a PSO and the shader bytecode hashes
it uses; this recovers it from the C++-Capture emitted source:

```
# After ngfx_cpp_capture_index_calls has written the .db,
ngfx_pso_index(project_dir="C:/.../GeneratedCpp")
# → {shader_blob_count, pso_count, shader_format_histogram: {dxbc: N, spirv: M}, ...}

ngfx_pso_get(
    db_path="C:/.../GeneratedCpp/.ngfxmcp_cpp_calls.db",
    pso_symbol="g_PSO_42",
)
# → {pso_symbol, api: 'd3d12', creator: 'CreateGraphicsPipelineState',
#    stages: {VS: {shader_symbol, hash_hex (DXBC MD5), format: 'dxbc', ...},
#             PS: {...}}}

# Reverse: given a hash from a perf tool / shader debugger,
ngfx_pso_find_by_shader(db_path="...", hash_hex="aabbccdd...")
# → [{pso_symbol, stage, shader_symbol, api}, ...]
```

### 15. Browse the protobuf schema (RE-derived)

```
ngfx_proto_search(pattern="RootParam")
# → ["PbRootParameter", "PbRootDescriptor", ...]

ngfx_proto_describe(message_fqn="NV.EventParameters.Messages.PbFunctionCallDesc")
# → {full_name, fields: [{name: 'functionName', ...},
#                       {name: 'arguments', is_repeated: True,
#                        type_name: 'NV.EventParameters.Messages.PbArgument'},
#                       ...]}
```

## How the function index works

The first time you call `ngfx_index_events`, the MCP runs

```
ngfx-replay --metadata-functions --quiet <capture> > <cache>/functions.txt
```

and writes both the dump and a SQLite DB (`<capture>.ngfxmcp/functions.db`)
next to the capture. Schema:

```sql
calls(
  idx   INTEGER PRIMARY KEY,
  name  TEXT,
  args  TEXT,
  ret   TEXT,
  kind  TEXT,   -- draw|dispatch|copy|barrier|present|ray_tracing|sync|set_state|other
  line  INTEGER,
  raw   TEXT
);
```

The index is keyed by the capture's mtime, so subsequent re-captures
auto-invalidate it.

## Caveats

- **Windows only.** The Nsight Graphics CLIs are Win32-native (Windows
  10 / 11 x64).
- **Nsight Graphics must be installed.** Set
  `NSIGHT_GRAPHICS_MCP_INSTALL_ROOT` if auto-discovery doesn't pick the
  right version.
- The function-stream parser is regex-based against `ngfx-replay`'s
  human-readable output. Lines that don't match the `Name(args)` shape
  are bucketed under `unrecognised_lines` and remain accessible via
  `ngfx_capture_functions` (raw passthrough).
- Some interactive UI features — the per-shader source profiler scroll,
  PSO browser, screenshot scrubber, frame-debugger pixel history — are
  not fully replicable headless. Use `ngfx_open_in_ui` for those.
- System-wide layer install (`global_install=True`) requires running the
  MCP host elevated.
- The DirectX Shader Compiler (`dxc.exe`) is not always shipped with
  Nsight Graphics; install it separately if `ngfx_dxc_compile` reports it
  missing.

## Layout

```
src/nsight_graphics_mcp/
  config.py              # install / SDK / per-tool discovery + cache paths
  cli.py                 # generic subprocess wrappers (sync + async + background)
  session.py             # capture / gputrace / launch session registries
  capture_info.py        # ngfx-replay --metadata* parsers
  captures.py            # capture-dir discovery + diff (Recent Captures parity)
  capture_diff.py        # event-stream LCS diff between two captures
  capture_format.py      # low-level .ngfx-gfxcap inspection (RE-derived)
  events.py              # function-stream indexer (Event List parity)
  gputrace.py            # .nsight-gputrace zip inspection
  cpp_capture.py         # MSBuild + run for Generate-C++-Capture output
  cpp_capture_parser.py  # walk emitted .cpp, index per-call args into SQLite
  proto_schemas.py       # name-only protobuf schema inventory
  proto_descriptors.py   # full FileDescriptorProto extraction → DescriptorPool
  handle_resolver.py     # object handle → create call + role-bucketed mentions
  pso_resolver.py        # PSO → DXBC/SPIR-V hash mapping (Nsight CLI gap)
  frame_costs.py         # Top-N by GPU time from perf-report dirs / gputrace zips
  objects.py             # object index (Resources / Pipelines pane parity)
  project.py             # .nsight-gfxproj XML authoring
  shaders.py             # glslang + DXC + shaderdebugger configurator wrappers
  layers.py              # Vulkan/VKSC/XR layer (un)install scripts
  sdk.py                 # NGFX in-app SDK header reference + codegen
  ui.py                  # ngfx-ui.exe hand-off
  watch.py               # capture-dir watcher (for hotkey-driven flows)
  redist.py              # bundled D3D12 Agility SDK / DXC / DLSS / etc. inventory
  doctor.py              # one-shot health check
  server.py              # FastMCP server registering every tool
  __main__.py            # console entry point

tests/                   # pytest suite — synthetic data for the parsers,
                         # real-binary tests for proto_descriptors when
                         # Nsight Graphics is installed locally.
docs/
  CAPTURE_FORMAT.md      # RE notes on the .ngfx-gfxcap wrapper
```

## License

MIT.

## Full tool reference

Auto-generated from `server.py` docstrings. **110 tools** organised by
the section comments in `server.py` — the order matches what you'd
discover scrolling the file.

### environment + discovery

- **`ngfx_environment`** — Report the resolved Nsight Graphics install + per-tool paths + cache dirs.
- **`ngfx_list_installs`** — List every Nsight Graphics install detected on this machine.
- **`ngfx_version`** — Return the version reported by ``ngfx.exe --version``.
- **`ngfx_list_activities`** — List the activity names that ``ngfx.exe`` accepts (parsed from --help).

### Graphics Capture activity (via ngfx.exe)

- **`ngfx_graphics_capture_launched`** — Run ``ngfx --activity 'Graphics Capture' --exe <exe> ...``.
- **`ngfx_graphics_capture_attached`** — Same as ``ngfx_graphics_capture_launched`` but attaches to a running PID.

### Headless Graphics Capture via ngfx-capture.exe

- **`ngfx_capture_launched`** — Run ``ngfx-capture.exe`` directly (no Nsight UI required).
- **`ngfx_capture_recapture`** — Recapture / recompress an existing ``.ngfx-gfxcap`` with the current format.
- **`ngfx_capture_recompress`** — Recompress an existing capture without re-running the application.

### Capture session management + metadata

- **`ngfx_open_capture`** — Register a capture file path as a session handle.
- **`ngfx_list_captures`** — List all opened capture sessions.
- **`ngfx_close_capture`** — _(no docstring)_
- **`ngfx_capture_summary`** — High-level summary of a capture (runs ``ngfx-replay --metadata``).
- **`ngfx_capture_objects`** — Run ``ngfx-replay --metadata-objects``: full JSON list of every API object recorded in the capture (devices, queues, pipelines, resources...).
- **`ngfx_capture_functions`** — Dump the recorded function stream (``ngfx-replay --metadata-functions``).
- **`ngfx_capture_logs`** — Dump captured application/driver log messages embedded in the capture.
- **`ngfx_capture_screenshot`** — Write the embedded final-present screenshot to a file.

### Replay (ngfx-replay.exe)

- **`ngfx_replay_run`** — Replay a capture with ``ngfx-replay.exe`` and return its output.
- **`ngfx_replay_bundle_extract`** — Extract a bundled-replayer capture's contents to a directory without running the replay.
- **`ngfx_replay_metadata`** — Direct passthrough to ``ngfx-replay --metadata`` (parsed key/value).

### GPU Trace Profiler

- **`ngfx_gputrace_archs`** — Return the list of GPU architectures accepted by ``--architecture``.
- **`ngfx_gputrace_launched`** — Run ``ngfx --activity 'GPU Trace Profiler' --exe <exe> ...``.
- **`ngfx_gputrace_attached`** — Attach GPU Trace to a running process by PID. Defaults to hotkey-driven.

### GPU Trace report session management

- **`ngfx_open_gputrace`** — Register a .nsight-gputrace path as a session handle.
- **`ngfx_list_gputraces`** — _(no docstring)_
- **`ngfx_close_gputrace`** — _(no docstring)_
- **`ngfx_gputrace_inspect`** — Best-effort inspection of a ``.nsight-gputrace`` file.

### Generate C++ Capture activity

- **`ngfx_cpp_capture_launched`** — Run ``ngfx --activity 'Generate C++ Capture' ...``.

### OpenGL Frame Debugger

- **`ngfx_framedebugger_launched`** — Run ``ngfx --activity 'OpenGL Frame Debugger' ...``.

### Launch / background process management

- **`ngfx_launch_status`** — Status + recent stdout/stderr of a background launch.
- **`ngfx_list_launches`** — _(no docstring)_
- **`ngfx_launch_stop`** — _(no docstring)_

### Remote monitor / RPC

- **`ngfx_remote_monitor_start`** — Start ``nv-nsight-remote-monitor.exe`` headless on this machine so a remote Nsight UI can connect. Returns a launch handle — call ``ngfx_launch_stop`` to terminate it.
- **`ngfx_rpc_start`** — Start ``ngfx-rpc.exe`` (the replayer UI server) headless.

### Aftermath (crash-dump tools)

- **`ngfx_aftermath_control`** — Run ``nv-aftermath-control.exe`` with the provided args.
- **`ngfx_aftermath_monitor_start`** — Start ``nv-aftermath-monitor.exe`` in the background to watch for GPU crashes / hangs and write dump files.
- **`ngfx_aftermath_format`** — Run ``nv-aftermath-format.exe`` against an existing crash dump.

### Layer install helpers

- **`ngfx_layer_list`** — List the Vulkan / VulkanSC / OpenXR layer install scripts shipped with the Nsight Graphics install, and whether each one is present.
- **`ngfx_layer_install`** — Run a Nsight Graphics layer install script.

### NGFX SDK helpers (in-app integration)

- **`ngfx_sdk_reference`** — Enumerate every header in the NGFX in-app SDK, with parsed function declarations (name, params, brief) for each.
- **`ngfx_sdk_grep`** — Regex-search across the NGFX header tree (returns matched filename, line number, and matched line text).
- **`ngfx_sdk_snippet`** — Generate a C++ integration snippet for an (activity, API) pair.
- **`ngfx_sdk_header_text`** — Return the raw text of an NGFX SDK header.

### Escape hatch

- **`ngfx_raw`** — Escape hatch — invoke any supported Nsight tool with arbitrary argv.

### Capture-directory discovery + diff (parity with GUI 'Recent Captures')

- **`ngfx_find_recent_captures`** — Look in the standard Nsight output directories (and optionally extra dirs) for recent capture / GPU-trace files. Newest first.
- **`ngfx_list_captures_in_dir`** — Enumerate every capture / gputrace file under a directory.
- **`ngfx_capture_diff`** — Diff the parsed ``--metadata`` summaries of two captures.

### Function-stream indexer (Event List parity)

- **`ngfx_index_events`** — Index a capture's function stream into a SQLite DB next to it.
- **`ngfx_find_events`** — Filtered search over the indexed function stream.
- **`ngfx_get_event`** — Look up a single call by index in the indexed function stream.
- **`ngfx_event_histogram`** — Histogram of recorded calls grouped by ``name`` or ``kind``.
- **`ngfx_find_calls_by_arg`** — Search recorded calls by argument substring.

### Object index (PSO / shader / resource inventory — GUI 'Resources' parity)

- **`ngfx_index_objects`** — Index every API object recorded in a capture into a SQLite DB.
- **`ngfx_query_objects`** — Filtered listing of recorded objects.
- **`ngfx_get_object`** — Look up a single recorded object by uid.
- **`ngfx_object_histogram`** — Histogram of recorded objects grouped by ``type_name``, ``category``, or ``api``.
- **`ngfx_object_query`** — Read-only SQL (SELECT / WITH) against the object index.
- **`ngfx_list_pipelines`** — List every Pipeline / PipelineLayout / DescriptorSetLayout / PipelineCache / RootSignature / StateObject in a capture.
- **`ngfx_list_shaders`** — List every ShaderModule / ShaderProgram / Shader recorded in a capture.
- **`ngfx_list_resources`** — List every recorded resource (Buffer / Image / Sampler / DeviceMemory / Heap).
- **`ngfx_event_query`** — Read-only SQL query (SELECT / WITH) against the function index.

### Deep GPU Trace inspection (Trace Analysis parity)

- **`ngfx_gputrace_archive`** — Open a .nsight-gputrace as a zip archive and list its members + decode any small JSON manifests inline.
- **`ngfx_gputrace_read_member`** — Read a member of the .nsight-gputrace archive as UTF-8 text (no disk extraction). Auto-decodes JSON / CSV payloads.
- **`ngfx_gputrace_extract`** — Extract a specific member of the .nsight-gputrace archive to ``out_dir``.
- **`ngfx_list_perf_report`** — List the artifacts written by ``ngfx-replay --perf-report-dir``.

### Nsight project file authoring

- **`ngfx_project_create`** — Write a minimal Nsight project XML at ``path``.
- **`ngfx_project_read`** — Read an existing Nsight project XML.
- **`ngfx_project_update`** — Mutate fields of an existing Nsight project file in-place.

### C++ Capture build + run

- **`ngfx_cpp_capture_find_solution`** — Locate the .sln produced by a Generate-C++-Capture run.
- **`ngfx_cpp_capture_build`** — Invoke MSBuild on a Generate-C++-Capture output directory or .sln.
- **`ngfx_cpp_capture_run`** — Run a Generate-C++-Capture exe to verify the repro still works.
- **`ngfx_cpp_capture_open_in_ui`** — Open a saved capture in ``ngfx-ui.exe`` so the human can run the UI's *Generate C++ Capture* activity against it (the CLI activity can't, it requires the original application to re-launch).
- **`ngfx_cpp_capture_wait_for_project`** — Poll ``watch_dir`` until a Generate-C++-Capture project lands and its .sln stops growing. Returns the project root + the solution path.
- **`ngfx_cpp_capture_index_calls`** — Walk a Generate-C++-Capture project, parse every command-list / command-buffer call, and index them into SQLite for per-event queries.
- **`ngfx_cpp_capture_event_args`** — Look up one C++-capture event by its synthetic ``event_index``.
- **`ngfx_cpp_capture_query_calls`** — Filtered query against the indexed C++ call stream.
- **`ngfx_cpp_capture_descriptor_bindings`** — Reconstruct the descriptor / root-parameter / vertex+index buffer / render-target binding state in effect at ``event_index`` by scanning backwards through the indexed C++ call stream.
- **`ngfx_cpp_capture_sql`** — Read-only SELECT/WITH query against the C++ call index DB.

### Shader compilation + Shader Debugger

- **`ngfx_glslang_compile`** — Compile a GLSL / SPIR-V shader using ``glslang.exe`` (bundled).
- **`ngfx_dxc_compile`** — Compile an HLSL shader via DXC.
- **`ngfx_shaderdebugger_configure`** — Run ``nv-shaderdebugger-configurator.exe`` (use ``extra_args=['--help']`` to discover flags).

### UI hand-off

- **`ngfx_open_in_ui`** — Spawn ``ngfx-ui.exe`` to open a capture / gputrace / project file in the full Nsight Graphics UI.

### Capture watcher / wait-for-new-capture

- **`ngfx_wait_for_new_capture`** — Poll one or more directories until a new capture (or GPU trace) lands, its size stabilises, then return its path.

### Doctor / health check + tool-help introspection

- **`ngfx_doctor`** — One-shot health check: install discovery, every tool path, layer scripts, output-dir writability, ``nvidia-smi`` driver/GPU info, and the Vulkan implicit/explicit-layer registry. Reports a list of ``issues`` you should fix before running captures.
- **`ngfx_tool_help`** — Run ``<tool> --help`` (or ``--help-all`` for ngfx) to discover the exact flags supported by your installed version of any Nsight binary.

### Function-stream raw sample + cross-capture diff

- **`ngfx_function_stream_sample`** — Return the first ``head`` (and optionally last ``tail``) raw lines of the recorded function stream.
- **`ngfx_function_stream_diff`** — Diff the indexed function streams of two captures.

### Triage macro

- **`ngfx_capture_quick_triage`** — Run the full 'first look' pipeline on a capture in one call:

### Redistributables + registry

- **`ngfx_list_d3d12_redist`** — List the bundled D3D12 Agility SDK redistributable shipped with Nsight Graphics. Pass ``preview=True`` for the preview SDK.
- **`ngfx_list_runtime_dlls`** — List the runtime DLLs (DXC, DXIL, Aftermath, WinPixEventRuntime, DirectStorage, NGX/DLSS) bundled in the Nsight Graphics host bin dir.
- **`ngfx_registry_restore`** — Run the bundled ``RegistryRestore.ps1`` to restore Nsight Graphics' registry keys to defaults.

### Proto schema reference (extracted from ngfx-replay binary)

- **`ngfx_proto_schemas`** — Return the protobuf schema inventory extracted from the Nsight binaries.
- **`ngfx_proto_search`** — Regex-search the extracted protobuf schema for a name or FQN.
- **`ngfx_proto_describe`** — Return the full field-level schema for a protobuf message extracted from Nsight's binaries.
- **`ngfx_proto_list_messages`** — List every fully-qualified message name in the decoded schema pool.
- **`ngfx_proto_extract_descriptors`** — Re-extract FileDescriptorProto blobs from a Nsight binary and rebuild the in-process schema registry.

### Capture diff — "git diff for captures"

- **`ngfx_event_stream_diff`** — Diff the per-event function streams of two captures (deeper than ``ngfx_capture_diff`` which only diffs the metadata summaries).

### Object handle / UID resolver

- **`ngfx_resolve_handle`** — Look up an API object by uid or name, find its create call, and enumerate every C++-capture event that mentions it — bucketed by role (create / write / bind / draw / dispatch / barrier / destroy / other).

### PSO → DXBC / SPIR-V hash mapping

- **`ngfx_pso_index`** — Walk a Generate-C++-Capture project and index PSO → shader-hash mappings into SQLite.
- **`ngfx_pso_get`** — Look up one PSO's shader stages: each entry is ``{shader_symbol, format (dxbc/dxil/spirv), hash_hex, hash_source, declared_byte_count, head_hex}``.
- **`ngfx_pso_list`** — List every indexed PSO with a one-line stage summary (``VS:g_VS_xxx, PS:g_PS_yyy``). Filter by ``api`` (``d3d12``/ ``vulkan``).
- **`ngfx_pso_find_by_shader`** — Reverse lookup: which PSOs use a given shader? Supply EITHER the C-level shader symbol (e.g. ``g_VS_0x1234``) OR a DXBC/SPIR-V hash. Useful when a shader-debugger or perf trace gives you a hash and you want to know every PSO it's bound to.
- **`ngfx_shader_blobs_list`** — List indexed shader bytecode blobs from a C++-Capture project. Filter by ``format`` (``dxbc``/``dxil``/``spirv``/``unknown``) and/or ``hash_hex`` (exact match).

### Frame cost analysis — top-N expensive draws/dispatches/regions

- **`ngfx_top_n_costs`** — Return the top-N most expensive actions by GPU time across all CSVs in a ``ngfx-replay --perf-report-dir`` output, or a ``.nsight-gputrace`` archive.

### Low-level capture-file inspection (RE-derived)

- **`ngfx_capture_format_info`** — Structural inspection of a .ngfx-gfxcap file.
- **`ngfx_capture_lz4_decompress`** — Experimental: attempt LZ4-block decompression of a byte range from a capture file. Useful for probing the chunk layout. Returns a hex preview of the decompressed bytes plus sizes; for unknown blocks, pass a generous ``uncompressed_size_hint`` (defaults to ``len(data) * 8``).
- **`ngfx_decode_protobuf_wire`** — Experimental: decode a byte range as generic protobuf wire format.

### Extra replay flags discovered via RE

- **`ngfx_replay_screenshot`** — Replay a capture and dump per-frame screenshots to ``output_dir``.
- **`ngfx_replay_gpu_frametimes`** — Replay a capture with GPU frametime collection enabled.
- **`ngfx_replay_run_advanced`** — Run ``ngfx-replay`` with arbitrary flags discovered via reverse-engineering.

