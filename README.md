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
| `ngfx_capture_launched` | Run `ngfx-capture.exe` directly. Produces a `.ngfx-capture` / `.ngfx-gfxcap` with a bundled replayer. Supports all triggers, compression, HVVM modes, delimiter modes, troubleshooting knobs, and ray-tracing options from `ngfx-capture --help`. |
| `ngfx_capture_recapture` | `--recapture` an existing capture with current format. |
| `ngfx_capture_recompress` | `--recompress` for higher compression / format upgrades. |

### Deep Nsight-only capture capability report

| Tool | What it does |
| --- | --- |
| `ngfx_deep_capture_capability_report` | Inspect the selected Nsight install, SDK headers, relevant plugins, optional capture path, and CLI help to rank the deepest available Nsight-only path for shader/render debugging. It explicitly separates the current Graphics Capture replacement path from legacy/optional C++ Capture and returns the MCP tool chain to use next. |

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

### Direct `.ngfx-gfxcap` decoder (RE-derived, no UI required)

Decodes the capture wrapper format end-to-end — no `ngfx-replay` /
`ngfx-ui` roundtrip needed for the metadata layer. The wrapper is fully
reverse-engineered: `nlyp` file-magic, then a sequence of chunks each
prefixed by a 48-byte mini-header (`elif` magic + version + compression
flag + compressed/uncompressed sizes + chunk-id + self-offset), payload
either LZ4-block compressed or stored, 16-byte aligned. The file ends
with a TOC region of `elif`-magic records pointing back to chunk
offsets. One chunk holds a serialised `NV.PbTableOfContents` with the
UUID, frame counts, GPU info, primary API, and lists of
`FunctionInfoChunkIds` + `ResourceInfoChunkIds`.

| Tool | What it answers |
| --- | --- |
| `ngfx_capture_decode_header` | Parse the wrapper header — magic / chunk count / TOC location. |
| `ngfx_capture_decode_chunks` | Iterate the chunk stream — id, size, compression flag, payload offset. |
| `ngfx_capture_decode_toc` | Decode the `PbTableOfContents` chunk: UUID, GPU, primary API, per-thread info, FunctionInfo + ResourceInfo chunk lists. |
| `ngfx_capture_decompress_chunk_by_id` | Pull a single chunk and decompress its LZ4 payload to raw bytes. |
| `ngfx_capture_search_payloads` | Search decompressed chunk payloads for shader names, hashes, or raw hex bytes when metadata-objects is too shallow. |
| `ngfx_capture_shader_chunks` | Find embedded DXBC/DXIL shader chunks and compute hash candidates from a saved capture. |
| `ngfx_capture_chunk_references` | Search decompressed chunks for references to a shader chunk id, hash, PDB path, or name. |
| `ngfx_capture_decode_events` | Best-effort per-event decode (limited — see caveat below). |
| `ngfx_capture_event_args` | Single-event arg lookup. Same shape as the C++-Capture-derived `ngfx_cpp_capture_event_args` once the FunctionInfo binary layout is fully RE'd. |

**Caveat (work in progress).** The chunks listed by
`FunctionInfoChunkIds` hold a *binary fixed-stride table*, not
`PbFunctionCallDesc` protobuf messages — Nsight stores the per-event
arg stream as packed C-style records, not protobuf. The wrapper +
TOC are fully decoded so the metadata layer works headless today; the
per-record layout of FunctionInfo is the remaining RE work for direct
arg extraction. Until that's done, use the C++-Capture roundtrip path
above for arg-level queries.

### ngfx-rpc custom transport client (RE-derived, partial)

`ngfx-rpc.exe` is the "Replayer UI Server" — a long-running process the
Nsight UI connects to over TCP / named-pipe / domain-socket. It speaks
a **custom length-prefixed protobuf protocol** (not standard gRPC, even
though its 30 .proto files contain ~50 `Request`/`Reply` message pairs
that look gRPC-shaped). The transport layer is fully decoded; the
per-message header encoding is decoded statically but not yet verified
over a live round-trip (see caveat below).

**Wire format (verified):**

```
byte 0   = 0x54 ('T')   magic
byte 1   = 0x08         magic
byte 2   = channel_id   u8
byte 3   = 0x00         flag/padding
byte 4-7 = body_size    u32 BIG-ENDIAN
byte 8+  = body (length = body_size)
```

**Dispatch model:** `(category u32, method u32)` keyed 2-D handler table.
Method enums (already in the proto pool) include `BinaryReplayMethod`
with 110 entries — `MethodApiInspectorStateRequest=33`,
`MethodRootParametersRequest=67`, etc. System category ids are pinned from
`ngfx-rpc.exe::SystemCategories.proto`; Pylon replay uses its own category
namespace where `CategoryBinaryReplay=1`. The remaining live blocker is the
private namespace/session/slot binding the UI performs before BinaryReplay
requests are accepted.

| Tool | What it does |
| --- | --- |
| `ngfx_rpc_protocol_info` | Return the decoded transport spec + the in-process method-enum tables (no live connection needed). |
| `ngfx_rpc_transport_connect` | Open a TCP / named-pipe / domain-socket connection to a running `ngfx-rpc.exe` and return a session handle. |
| `ngfx_rpc_send_raw_frame` | Send an arbitrary framed message and read the reply — escape hatch for experimenting with the protocol. |
| `ngfx_frame_debugger_rpc_schema` | Describe the private BinaryReplay pixel/resource history methods, ids, request schemas, and handle shapes. |
| `ngfx_pixel_history` | Call `MethodPixelHistoryRequest` (`70`) for an image handle + pixel coordinate, or preview the exact protobuf body. |
| `ngfx_resource_access_history` | Call `MethodResourceAccessHistoryRequest` (`53`) for an API data handle, or preview the request body. |
| `ngfx_resource_revision_at_event` | Derive the resource revision at an event from access history, optionally reusing a persistent RPC session and fetching resource info or image subresource data. |
| `ngfx_rpc_open_capture_session` / `ngfx_rpc_capture_session_status` / `ngfx_rpc_close_capture_session` | Keep a private frame-debugger RPC connection open across MCP calls. |
| `ngfx_rpc_call_binary_replay` | Call an arbitrary BinaryReplay method on a persistent frame-debugger RPC session. |

**Caveat (live-round-trip work in progress).** ngfx-rpc's TCP server is
one-shot: it exits the moment the first client session ends. That makes
iterative "guess header → observe reply" probing impractical (the first
attempt at the most-likely `MessageHeader` layout crashes the server,
and relaunching takes ~30s). The structural header layout was recovered
statically from IDA (`is_valid u8@+2, category u32@+32, method u32@+36,
ticket_id u64@+48, sertype u32@+56`, 60 bytes total) but isn't yet
confirmed on-wire. The two remaining angles are:

1. **`pktmon` capture of a real ngfx-ui ↔ ngfx-rpc exchange** — the
   schema pool decodes every observed message; recovers handshake +
   real method calls by observation.
2. **IDA on `NV::TPS::ProtoBufMessage::Serialize`** — read the exact
   serialiser bytes the C++ side emits.

Both are documented in `docs/RPC_PROTOCOL.md`.

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
| `ngfx_gputrace_shader_pipeline_search` | Search shader/pipeline-looking GPU Trace members for a shader name, hash, or entry point. |
| `ngfx_list_perf_report` | Enumerate `ngfx-replay --perf-report-dir` artifacts with auto-decoded JSON/CSV inline. |
| `ngfx_gputrace_export_summary` | Summarize Nsight GPU Trace auto-export folders, including `REPRO_INFO.xls` and metric tables. |
| `ngfx_gputrace_export_search` | Search exported GPU Trace text/XLS files for shader names, hashes, or event text. |
| `ngfx_gputrace_archs` | List GPU architectures accepted by `--architecture`. |

### Generate C++ Capture → build → run

Nsight 2026's durable replacement path for D3D12/Vulkan persistence is
Graphics Capture (`ngfx-capture` / `ngfx-replay`) plus Graphics Debugger live
replay. C++ Capture is still useful when it emits a project because the MCP
can index generated source for per-call arguments, but the saved-capture
exporter is private UI/plugin code and some Nsight builds can refuse D3D11/D3D12
C++ serialization with guidance to migrate to Graphics Capture. Use
`ngfx_deep_capture_capability_report` first when deciding whether C++ export,
live replay RPC, GPU Trace-on-replay, or raw `.ngfx-capture` decoding is the
right next step.

The CLI activity (`ngfx --activity 'Generate C++ Capture'`) requires the
original application to launch — it can't run against a saved capture.
The MCP also exposes the UI-driven path for that case (see next section).

| Tool | What it does |
| --- | --- |
| `ngfx_cpp_capture_launched` | Run the Generate-C++-Capture activity (CLI; relaunches the app). |
| `ngfx_cpp_capture_dump` | One-stop C++ capture dump helper: live app via CLI, or saved `.ngfx-gfxcap` via UI-assisted export, then optional call/PSO indexing. |
| `ngfx_cpp_capture_saved_bridge_re_analyze` | Run targeted IDA passes over Nsight's private saved-capture C++ export plugins. |
| `ngfx_cpp_capture_saved_bridge_re_report` | Summarize the recovered private serialize protocol, Pylon activity bridge, and remaining headless gap. |
| `ngfx_cpp_capture_saved_pylon_handoff_preview` | Emit the pinned Pylon platform-launcher map for saved-capture Generate C++ Capture: `ngfx-replay.exe`, quoted capture argv, extra replay args, environment string, and `JsonProject['launcher']` settings. |
| `ngfx_cpp_capture_saved_direct_rpc_plan` | Emit the recovered FrameDebugger serialize request + file-transfer callback plan for the direct RPC route. |
| `ngfx_cpp_capture_saved_file_transfer_apply` | Apply one decoded FrameDebugger open/append/close file-transfer notification to disk for the direct RPC executor. |
| `ngfx_cpp_capture_saved_output_dir_setting` | Preview or write the candidate Qt/QSettings `Serialization Save Directory` value used by BattlePlugin. |
| `ngfx_cpp_capture_saved_ui_automation_attempt` | Best-effort `pywinauto` UI fallback for the Generate C++ Capture dialog, with structured blockers if automation is unavailable. |
| `ngfx_cpp_capture_saved_headless_attempt` | One entrypoint that tries the pinned Pylon bridge, direct RPC route, and UI fallback, then validates/indexes any project that appears. |
| `ngfx_cpp_capture_saved_export_validate` | Validate an emitted C++ Capture project, compare against capture metadata when available, and build call/PSO indexes. |
| `ngfx_cpp_capture_saved_artifact_bundle` | Bundle capture/export validation/project artifacts into a zip for autonomous handoff and review. |
| `ngfx_cpp_capture_find_solution` | Locate the produced `.sln`. |
| `ngfx_cpp_capture_build` | MSBuild the project (auto-discovers MSBuild via vswhere). |
| `ngfx_cpp_capture_run` | Run the produced exe and capture its output. |

The saved-capture → C++ path is still private NVIDIA plugin code. The RE
tools above preserve the current evidence: `BattlePlugin` sends
`PbSerializeRequestMessage` through the FrameDebugger service and handles file
transfer notifications, while `PylonPlugin` exposes the UI activity bridge
that maps activity id 3 to *Generate C++ Capture*. The Pylon argv/config
handoff is pinned now: the bridge uses `ngfx-replay.exe`, passes the saved
capture as the first quoted argument, appends flattened replay-option args,
passes a semicolon-joined environment string, and persists the platform map
under `JsonProject['launcher']`. The remaining fully-headless gap is invoking
Pylon's private activity manager outside the UI process, or completing the
direct FrameDebugger Core RPC namespace/session binding.

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
of the blob so Vulkan shaders still get a stable identity. We also compute
ShaderToggler's hash for every blob: CRC32 over the full raw shader
bytecode, reported as both 8 hex digits and unsigned decimal.

PSO creation calls (`CreateGraphicsPipelineState` /
`CreateComputePipelineState` / `vkCreateGraphicsPipelines` /
`vkCreateComputePipelines` / `vkCreateRayTracingPipelinesKHR`) reference
those byte-array symbols (D3D12) or `vkCreateShaderModule` handles
(Vulkan). The indexer matches them up.

| Tool | What it answers |
| --- | --- |
| `ngfx_pso_index` | Walk a C++-Capture project, parse every shader byte-array + every PSO creation call, write `shader_blobs` + `pso_shaders` tables to the existing C++-Capture index DB. |
| `ngfx_pso_get` | Look up one PSO's full stage map: each stage → `{shader_symbol, format (dxbc/dxil/spirv), hash_hex, hash_source, shader_toggler_crc32, declared_byte_count, head_hex}`. |
| `ngfx_pso_list` | Enumerate every indexed PSO with a one-line stage summary (`VS:g_VS_xxx, PS:g_PS_yyy`). |
| `ngfx_pso_find_by_shader` | Reverse lookup: given a shader symbol, DXBC/SPIR-V hash, or ShaderToggler CRC32, which PSOs use it (and as which stage)? |
| `ngfx_shader_blobs_list` | Enumerate every indexed shader byte-array (filterable by format, DXBC/SPIR-V hash, or ShaderToggler CRC32). |
| `ngfx_shader_blobs_find_crc32` | Find shader byte-arrays by ShaderToggler CRC32, accepting either hex (`1cf439e7`) or decimal. |
| `ngfx_shader_blob_dump` | Write a matched generated-C++ shader byte-array back to disk as raw DXBC/DXIL/SPIR-V bytes. |

### Shader visual-bug triage

These tools compose C++-Capture event args, PSO identity, descriptor state,
and IDA-derived Nsight RE facts into reports an LLM can use to localise a
visual bug before patching shaders.

| Tool | What it answers |
| --- | --- |
| `ngfx_shader_triage_plan` | Concrete capture/index/compare/probe plan for a visual bug handoff. |
| `ngfx_eye_issue_dump_report` | Nsight-only dump report for the right-eye issue: capture TOC, sidecar status, dump-only blockers, and next actions. |
| `ngfx_eye_issue_event_signatures` | Candidate left/right event pairs from saved `metadata-functions` when only the `.ngfx-capture` dump exists. |
| `ngfx_eye_event_index` | Classify C++-Capture events as left/right/both/unknown using stereo regexes, viewport/scissor half hints, and inherited state. |
| `ngfx_compare_eye_passes` | Left/right count deltas for draws, dispatches, copies, and ray-tracing work. |
| `ngfx_find_missing_eye_dispatches` | Dispatch/ray-tracing asymmetries, useful for missing producer work before a bad draw. |
| `ngfx_event_state` | One event plus surrounding calls, descriptor/root state, render targets, recent writes, and PSO details. |
| `ngfx_trace_resource_lineage` | Every indexed call mentioning a resource/symbol, bucketed by create/bind/write/copy/dispatch/draw/barrier role. |
| `ngfx_pso_bind_trace` | `SetPipelineState` / `vkCmdBindPipeline` binds and the following draw/dispatch work, even when creation hooks missed the PSO. |
| `ngfx_pso_swap_harness_plan` | Generate a D3D12 draw-time PSO swap harness plan and optional C++ snippet files for right-eye-only shader patch trials. |
| `ngfx_shader_probe_plan` | Probe variants for terms such as `t5`, `t8`, `t9`, `screenTile`, `SV_Position`, `View[148]`, and `volumeUV`. |
| `ngfx_shader_bug_triage` | Single LLM-ready report from handoff, capture path, C++ index, suspect PSO/hash/CRC, and ROI. |

### Autonomous shader-fix loop helpers

| Tool | What it answers |
| --- | --- |
| `ngfx_sn2_repro_plan` / `ngfx_sn2_repro_run` | Build or run the Subnautica 2 launch-script repro with the expected capture/log artifacts. |
| `ngfx_cpp_capture_from_saved_capture` | Saved-capture C++ export wrapper around the best available UI-assisted path. |
| `ngfx_pair_eye_events` | Pair classified left-eye and right-eye events and report missing counterparts. |
| `ngfx_resolve_shader_slots` | Resolve shader slots such as `t5`/`t8`/`t9` to root-param evidence when a slot map or descriptor state is available. |
| `ngfx_descriptor_resource_candidates` | Score likely resource handles for shader slots from a private descriptor-state RPC reply. |
| `ngfx_trace_roi_history` | Generate or execute a grid of private pixel-history requests over a bad ROI. |
| `ngfx_resource_producer_graph` | Build a best-effort read/write producer graph for named resources. |
| `ngfx_import_uevr_trace` | Import NDJSON/JSON/CSV UEVR runtime hook traces into a summary or SQLite DB. |
| `ngfx_pso_rehydration_plan` | Generate a C++ plan/snippet for cloning a graphics PSO with patched shader bytecode. |
| `ngfx_shader_probe_execution_plan` | Emit the closed-loop run steps for a specific shader probe. |
| `ngfx_diff_hdr_roi` | Diff PFM/raw-float HDR ROI data without clamping to 8-bit. |
| `ngfx_autofix_loop_plan` | Return the autonomous patch/test/scoring loop. |
| `ngfx_validate_fix_claim` | Evidence gate for accepting/rejecting an automated visual-fix claim. |
| `ngfx_shader_fix_regression_score` | Score before/after fix metrics with repeatability, left-eye drift, event-sequence, and PSO coverage gates. |

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

### IDA Pro headless RE bridge

The shipped headers cover in-app capture/trace control, but saved-capture
frame-debugger state, pixel history, resource history, and several replay/RPC
paths live behind Nsight's internal binaries. The MCP can drive IDA Pro
headless to cache compact JSON facts for those gaps.

| Tool | What it does |
| --- | --- |
| `ngfx_ida_environment` | Discover IDA Pro/Home/Free installs and list known Nsight RE targets. Override with `NSIGHT_GRAPHICS_MCP_IDA`. |
| `ngfx_ida_analyze_binary` | Run IDA headless over a target such as `ngfx_rpc`, `ngfx_replay`, `frame_debugger_native`, `frame_debugger_d3d12`, or `frame_debugger_vulkan`; exports strings, xrefs, selected functions, and bounded Hex-Rays pseudocode into the MCP cache. |
| `ngfx_ida_search_facts` | Regex-search cached IDA facts without re-running IDA. |
| `ngfx_ida_fact_summary` | Summarize a facts JSON. |
| `ngfx_ida_command_preview` | Show the exact headless command shape without running it. |
| `ngfx_shader_debug_re_status` | Check whether the RE facts needed for shader-debug automation are cached and show the implementation sequence for pixel history, resource history, event state, and shader variant testing. |

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

**221 MCP tools** as of this writing, grouped by the sections below.
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

# ShaderToggler hash path: hex notes and decimal ShaderToggler.ini values both work.
ngfx_shader_blobs_find_crc32(db_path="...", crc32_hex="1cf439e7")
ngfx_shader_blob_dump(db_path="...", crc32_hex="1cf439e7", output_path="C:/tmp/1cf439e7.dxil")
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
  CAPTURE_FORMAT.md                 # RE notes on the .ngfx-gfxcap wrapper
  RPC_PROTOCOL.md                   # RE notes on ngfx-rpc.exe transport
  NSIGHT_SHADER_DEBUG_AUTONOMY.md   # current shader-debugging status/plan
```

## License

MIT.

## Full tool reference

Auto-generated from `server.py` docstrings. **221 tools** organised by
the section comments in `server.py` — the order matches what you'd
discover scrolling the file.

### environment + discovery

- **`ngfx_environment`** — Report the resolved Nsight Graphics install + per-tool paths + cache dirs.
- **`ngfx_list_installs`** — List every Nsight Graphics install detected on this machine.
- **`ngfx_deep_capture_capability_report`** — Rank Graphics Capture, live replay RPC, GPU Trace-on-replay, C++ Capture, and raw capture decoding for deep shader/render debugging from a saved dump.
- **`ngfx_version`** — Return the version reported by ``ngfx.exe --version``.
- **`ngfx_list_activities`** — List the activity names that ``ngfx.exe`` accepts (parsed from --help).

### Graphics Capture activity (via ngfx.exe)

- **`ngfx_graphics_capture_launched`** — Run ``ngfx --activity 'Graphics Capture' --exe <exe> ...``.
- **`ngfx_graphics_capture_attached`** — Same as ``ngfx_graphics_capture_launched`` but attaches to a running PID.

### Headless Graphics Capture via ngfx-capture.exe

- **`ngfx_capture_launched`** — Run ``ngfx-capture.exe`` directly (no Nsight UI required).
- **`ngfx_capture_recapture`** — Recapture / recompress an existing ``.ngfx-capture`` / ``.ngfx-gfxcap`` with the current format.
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
- **`ngfx_gputrace_capture_replay`** — Run GPU Trace Profiler against `ngfx-replay.exe` for a saved Graphics Capture, using replay-begin/replay-end triggers.

### GPU Trace report session management

- **`ngfx_open_gputrace`** — Register a .nsight-gputrace path as a session handle.
- **`ngfx_list_gputraces`** — _(no docstring)_
- **`ngfx_close_gputrace`** — _(no docstring)_
- **`ngfx_gputrace_inspect`** — Best-effort inspection of a ``.nsight-gputrace`` file.
- **`ngfx_gputrace_shader_pipeline_search`** — Search shader/pipeline GPU Trace data for a shader hash, name, or entry point.

### Generate C++ Capture activity

- **`ngfx_cpp_capture_launched`** — Run ``ngfx --activity 'Generate C++ Capture' ...``.
- **`ngfx_cpp_capture_saved_bridge_re_analyze`** — Run the targeted IDA passes for the private saved-capture -> C++ bridge.
- **`ngfx_cpp_capture_saved_bridge_re_report`** — Summarize current RE evidence for fully headless saved C++ export.
- **`ngfx_cpp_capture_saved_pylon_handoff_preview`** — Preview the pinned Pylon launcher settings for saved-capture Generate C++ Capture.
- **`ngfx_cpp_capture_saved_direct_rpc_plan`** — Preview the direct FrameDebugger serialize-RPC request/callback plan.
- **`ngfx_cpp_capture_saved_file_transfer_apply`** — Apply one FrameDebugger serialize file-transfer notification to disk.
- **`ngfx_cpp_capture_saved_output_dir_setting`** — Preview or write the candidate QSettings output-dir value for C++ export.
- **`ngfx_cpp_capture_saved_export_validate`** — Validate and index a saved-capture Generate-C++-Capture export.
- **`ngfx_cpp_capture_saved_ui_automation_attempt`** — Best-effort pywinauto UI fallback for saved-capture C++ export.
- **`ngfx_cpp_capture_saved_headless_attempt`** — Try all known saved-capture -> C++ export routes, then validate output.
- **`ngfx_cpp_capture_saved_artifact_bundle`** — Bundle capture/export validation artifacts into one zip.

### OpenGL Frame Debugger

- **`ngfx_framedebugger_launched`** — Run ``ngfx --activity 'OpenGL Frame Debugger' ...``.

### Launch / background process management

- **`ngfx_launch_status`** — Status + recent stdout/stderr of a background launch.
- **`ngfx_list_launches`** — _(no docstring)_
- **`ngfx_launch_stop`** — _(no docstring)_

### Remote monitor / RPC

- **`ngfx_remote_monitor_start`** — Start ``nv-nsight-remote-monitor.exe`` headless on this machine so a remote Nsight UI can connect. Returns a launch handle — call ``ngfx_launch_stop`` to terminate it.
- **`ngfx_rpc_start`** — Start ``ngfx-rpc.exe`` (the replayer UI server) headless.
- **`ngfx_rpc_protocol_info`** — Return everything we know about the ``ngfx-rpc.exe`` custom wire protocol — handy as a self-describing reference for callers writing their own clients. The full derivation lives in ``docs/RPC_PROTOCOL.md`` (in this repo).
- **`ngfx_rpc_transport_connect`** — Open one TCP transport connection to a running ``ngfx-rpc.exe`` and immediately close it. Useful as a smoke test: it verifies the server is reachable and that the 8-byte frame magic checks out.
- **`ngfx_rpc_send_raw_frame`** — Low-level escape hatch: send one transport frame and (optionally) await one reply frame. Useful for protocol RE work.
- **`ngfx_frame_debugger_rpc_schema`** — Describe the private BinaryReplay RPC methods used for pixel/resource history.
- **`ngfx_pixel_history`** — Call Nsight's private BinaryReplay pixel-history method or preview the exact protobuf request.
- **`ngfx_resource_access_history`** — Call Nsight's private resource-access-history method for one API handle.
- **`ngfx_resource_revision_at_event`** — Derive a resource revision at an event from private resource history, with optional persistent-session reuse.
- **`ngfx_rpc_open_capture_session`** — Open a persistent frame-debugger RPC session and optionally launch a capture.
- **`ngfx_rpc_capture_session_status`** — List persistent frame-debugger RPC sessions, or summarize one handle.
- **`ngfx_rpc_close_capture_session`** — Close a persistent frame-debugger RPC session.
- **`ngfx_rpc_call_binary_replay`** — Call an arbitrary BinaryReplay method on an open frame-debugger RPC session.

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
- **`ngfx_gputrace_shader_pipeline_search`** — Search shader/pipeline-looking archive members for CopyRectPS-style shader evidence.
- **`ngfx_list_perf_report`** — List the artifacts written by ``ngfx-replay --perf-report-dir``.
- **`ngfx_gputrace_export_summary`** — Summarize Nsight GPU Trace auto-export folders.
- **`ngfx_gputrace_export_search`** — Search exported GPU Trace text/XLS files for shader names, hashes, or event text.

### Nsight project file authoring

- **`ngfx_project_create`** — Write a minimal Nsight project XML at ``path``.
- **`ngfx_project_read`** — Read an existing Nsight project XML.
- **`ngfx_project_update`** — Mutate fields of an existing Nsight project file in-place.

### C++ Capture build + run

- **`ngfx_cpp_capture_find_solution`** — Locate the .sln produced by a Generate-C++-Capture run.
- **`ngfx_cpp_capture_build`** — Invoke MSBuild on a Generate-C++-Capture output directory or .sln.
- **`ngfx_cpp_capture_run`** — Run a Generate-C++-Capture exe to verify the repro still works.
- **`ngfx_cpp_capture_dump`** — One-stop helper for producing a C++ Capture dump and indexing it. Uses the headless CLI for live app launches and the UI-assisted path for saved captures.
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
- **`ngfx_pso_get`** — Look up one PSO's shader stages: each entry is ``{shader_symbol, format (dxbc/dxil/spirv), hash_hex, hash_source, shader_toggler_crc32, declared_byte_count, head_hex}``.
- **`ngfx_pso_list`** — List every indexed PSO with a one-line stage summary (``VS:g_VS_xxx, PS:g_PS_yyy``). Filter by ``api`` (``d3d12``/ ``vulkan``).
- **`ngfx_pso_find_by_shader`** — Reverse lookup: which PSOs use a given shader? Supply the C-level shader symbol (e.g. ``g_VS_0x1234``), a DXBC/SPIR-V hash, or a ShaderToggler CRC32.
- **`ngfx_shader_blobs_list`** — List indexed shader bytecode blobs from a C++-Capture project. Filter by ``format`` (``dxbc``/``dxil``/``spirv``/``unknown``), ``hash_hex`` (exact match), and/or ``shader_toggler_crc32``.
- **`ngfx_shader_blobs_find_crc32`** — Find shader bytecode blobs by ShaderToggler CRC32, accepting either hex or decimal.
- **`ngfx_shader_blob_dump`** — Dump one indexed shader bytecode blob to disk by shader symbol or ShaderToggler CRC32.

### Shader visual-bug triage orchestration

- **`ngfx_shader_triage_plan`** — Return the concrete MCP workflow for localising and fixing a shader visual bug.
- **`ngfx_eye_issue_dump_report`** — Summarize saved-capture evidence, dump-only blockers, and the next Nsight-only actions for the right-eye issue.
- **`ngfx_eye_issue_event_signatures`** — Build candidate left/right event pairs from name-only saved function metadata.
- **`ngfx_eye_event_index`** — Classify C++-Capture events as left/right/both/unknown using stereo regexes, viewport/scissor half hints, and inherited state.
- **`ngfx_compare_eye_passes`** — Compare left/right draw/dispatch/copy counts from a C++-Capture index.
- **`ngfx_find_missing_eye_dispatches`** — Find dispatch/ray-tracing asymmetries between classified eyes.
- **`ngfx_event_state`** — Return a draw/dispatch event, nearby calls, bound descriptors, and PSO info.
- **`ngfx_trace_resource_lineage`** — Find C++-Capture calls that mention a resource/symbol and bucket by role.
- **`ngfx_pso_bind_trace`** — Trace SetPipelineState/vkCmdBindPipeline and following draw/dispatch work.
- **`ngfx_pso_swap_harness_plan`** — Generate a D3D12 draw-time PSO swap harness plan and optional C++ files.
- **`ngfx_shader_probe_plan`** — Generate a targeted shader-probe plan for suspect terms such as t5/t8/t9.
- **`ngfx_shader_bug_triage`** — Produce one LLM-ready shader-bug report from capture/index/handoff evidence.
- **`ngfx_sn2_repro_plan`** — Build the exact Subnautica 2 launch-script repro command and expected artifacts.
- **`ngfx_sn2_repro_run`** — Dry-run or execute the Subnautica 2 repro launch script with capture-friendly environment.
- **`ngfx_cpp_capture_from_saved_capture`** — Export Generate-C++-Capture output from a saved capture via the available Nsight path.
- **`ngfx_pair_eye_events`** — Pair left/right draw, dispatch, copy, and ray-tracing events and report missing counterparts.
- **`ngfx_resolve_shader_slots`** — Resolve shader resource slots such as `t5`, `t8`, and `t9` to root/descriptor evidence where available.
- **`ngfx_descriptor_resource_candidates`** — Score likely resource handles for shader slots from a private descriptor-state RPC reply.
- **`ngfx_trace_roi_history`** — Generate or execute private pixel-history requests for a grid over a suspect ROI.
- **`ngfx_resource_producer_graph`** — Build a best-effort graph of resource producers/readers from a C++-Capture index.
- **`ngfx_import_uevr_trace`** — Import UEVR hook traces from JSON, NDJSON, CSV, or key/value logs into summaries or SQLite.
- **`ngfx_pso_rehydration_plan`** — Generate a C++ clone/recreate plan for testing patched shader bytecode in a graphics PSO.
- **`ngfx_shader_probe_execution_plan`** — Emit the closed-loop steps for a concrete shader probe trial.
- **`ngfx_diff_hdr_roi`** — Compare raw/PFM float image ROI data without 8-bit clamping.
- **`ngfx_autofix_loop_plan`** — Return the autonomous patch/test/score loop used to drive repeated fix trials.
- **`ngfx_validate_fix_claim`** — Reject or accept fix claims using improvement, repeatability, left-eye drift, and causality gates.
- **`ngfx_shader_fix_regression_score`** — Score whether a shader-fix run is acceptable or regressed.

### Frame cost analysis — top-N expensive draws/dispatches/regions

- **`ngfx_top_n_costs`** — Return the top-N most expensive actions by GPU time across all CSVs in a ``ngfx-replay --perf-report-dir`` output, or a ``.nsight-gputrace`` archive.

### Low-level capture-file inspection (RE-derived)

- **`ngfx_capture_format_info`** — Structural inspection of a .ngfx-gfxcap file.
- **`ngfx_capture_lz4_decompress`** — Experimental: attempt LZ4-block decompression of a byte range from a capture file. Useful for probing the chunk layout. Returns a hex preview of the decompressed bytes plus sizes; for unknown blocks, pass a generous ``uncompressed_size_hint`` (defaults to ``len(data) * 8``).
- **`ngfx_decode_protobuf_wire`** — Experimental: decode a byte range as generic protobuf wire format.

### Direct capture-file decoder (header / chunks / TOC / events)

- **`ngfx_capture_decode_header`** — Decode the wrapper header of a ``.ngfx-capture`` / ``.ngfx-gfxcap``.
- **`ngfx_capture_decode_chunks`** — List the first ``max_chunks`` chunks of a capture file.
- **`ngfx_capture_decode_toc`** — Decode the ``NV.PbTableOfContents`` chunk of a capture file.
- **`ngfx_capture_decompress_chunk_by_id`** — Locate the chunk whose ``kind`` (chunk-id) equals ``chunk_id`` and decompress it.
- **`ngfx_capture_search_payloads`** — Search decompressed capture chunks for shader names, hashes, or raw hex bytes.
- **`ngfx_capture_shader_chunks`** — Find embedded DXBC/DXIL shader blobs in a saved capture and return chunk IDs, strings, and hash candidates.
- **`ngfx_capture_chunk_references`** — Search decompressed capture chunks for references to a chunk id or arbitrary byte/string needles.
- **`ngfx_capture_decode_events`** — Best-effort scan for serialised ``PbFunctionCallDesc`` records.
- **`ngfx_capture_event_args`** — Look up the per-event arguments at ``event_index`` via direct capture decoding.

### Extra replay flags discovered via RE

- **`ngfx_replay_screenshot`** — Replay a capture and dump per-frame screenshots to ``output_dir``.
- **`ngfx_replay_gpu_frametimes`** — Replay a capture with GPU frametime collection enabled.
- **`ngfx_replay_run_advanced`** — Run ``ngfx-replay`` with arbitrary flags discovered via reverse-engineering.

