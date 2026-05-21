# Nsight MCP shader-debugging autonomy status

Date: 2026-05-20

This document captures the current state of the Nsight Graphics MCP work for
autonomous shader and render-debugging. The immediate motivating case is the
Subnautica 2 right-eye visual issue, but the goal is broader: make the MCP deep
enough that an LLM can diagnose a shader/rendering bug from Nsight artifacts,
prove exactly where the visual error first appears, and drive the fix/validation
loop with no user-guided visual inspection.

The short version: the MCP has grown from a wrapper around Nsight CLIs into a
large reverse-engineered capture, replay, GPU Trace, RPC, and shader-triage
toolchain. The remaining hard gaps are all on private Nsight internals: the live
Frame Debugger/BinaryReplay session binding, deeper decoding of the WRPV GPU
Trace report container, and direct per-event argument/resource decoding from
saved capture chunks. Until those are finished, dump-only analysis can narrow
the problem substantially, but it cannot yet always prove the actual sampled
descriptor/resource at a specific shader event from Nsight alone.

## Purpose

The MCP should let an LLM answer these questions from a capture:

- Which draw/dispatch first produces the bad pixel or bad region?
- Is the shader itself wrong, or is it copying/sampling a bad input?
- Which pipeline state, shader entry point, root signature, descriptor, resource
  revision, render target, viewport/scissor, and constants were involved?
- What is the equivalent left-eye event, and how does its bound state differ?
- Which earlier event produced the bad input resource?
- What exact intervention should be tried next?
- Did the intervention actually fix the visual signal without regressing the
  control cases?

For the Subnautica 2 issue, the current working conclusion is that the most
useful confirmed shader is `CopyRectPS`, a small copy shader that samples
`t0/s0` and writes `SV_Target`. That points away from a complex fog shader bug
and toward one of these:

- bad right-eye source texture
- bad source rectangle or UV/view constants
- bad destination rectangle or right-eye render target selection
- bad producer of the source texture
- mismatched left/right descriptor routing

The MCP therefore needs to prove the actual `CopyRectPS` `t0` source, target,
viewport/scissor/rect state, and producer chain.

## Scope and constraints

The current requested direction is Nsight-only:

- Do not switch to PIX for the solution path.
- Avoid future UEVR/game-specific work unless it is only used as historical
  context. The desired path is capture/dump driven through Nsight MCP.
- Use IDA Pro headless and static reverse engineering for private Nsight pieces
  that are not covered by the public headers.
- Treat "C++ Capture" as legacy/uncertain in current Nsight versions. Prefer the
  current Graphics Capture, replay, GPU Trace, and private RPC replacement paths,
  while keeping old Nsight versions as an optional fallback if needed.
- Be explicit about evidence quality. A scanned descriptor table is not proof
  that a shader used every descriptor in that table.

## Current repository state

The repo is `E:\Github\nsight-graphics-mcp`.

Current tool count: 241 MCP tools (+20 landed in this session).

Existing markdown docs before this file:

- `README.md`
- `docs/CAPTURE_FORMAT.md`
- `docs/RPC_PROTOCOL.md`

Major new or heavily modified areas in the current working tree:

- `src/nsight_graphics_mcp/capture_decoder.py`
- `src/nsight_graphics_mcp/events.py`
- `src/nsight_graphics_mcp/gputrace.py`
- `src/nsight_graphics_mcp/rpc_client.py`
- `src/nsight_graphics_mcp/frame_debugger_rpc.py`
- `src/nsight_graphics_mcp/cpp_bridge_re.py`
- `src/nsight_graphics_mcp/ida_re.py`
- `src/nsight_graphics_mcp/shader_triage.py`
- `src/nsight_graphics_mcp/shader_debug.py`
- `src/nsight_graphics_mcp/autonomous_shader_fix.py`
- `src/nsight_graphics_mcp/eye_issue.py`
- `src/nsight_graphics_mcp/deep_capture.py`
- `src/nsight_graphics_mcp/server.py`
- matching focused tests under `tests/`

The working tree is intentionally dirty. Do not reset or revert unrelated
changes. Several files contain work from multiple passes and should be treated
as in-progress infrastructure.

## What has been built

### Nsight command surface

The MCP wraps the main Nsight command-line surfaces:

- `ngfx.exe` activities:
  - Graphics Capture
  - GPU Trace Profiler
  - Generate C++ Capture, where still available
  - OpenGL Frame Debugger
- `ngfx-capture.exe`:
  - launched captures
  - recapture
  - recompress
- `ngfx-replay.exe`:
  - replay
  - metadata
  - metadata functions
  - metadata objects
  - logs
  - screenshots
  - advanced replay flags
- `ngfx-rpc.exe`:
  - startup
  - transport probing
  - raw frame send/receive
  - partial BinaryReplay/Frame Debugger tooling
- Nsight SDK headers:
  - header search
  - SDK reference
  - snippets
- bundled shader tools:
  - DXC
  - glslang
- IDA headless helpers:
  - binary fact extraction
  - function/string search
  - private bridge analysis

### Capture/session management

The MCP can:

- find recent captures
- register/open captures
- summarize captures
- extract final screenshots
- extract logs
- list and diff captures
- run `ngfx-replay`
- extract a replay bundle
- run advanced replay paths

These tools are the basic automation layer that lets an LLM start from a
`.ngfx-capture` or `.ngfx-gfxcap` and build an analysis session without opening
the Nsight UI.

### Event and object indexes

The MCP can index Nsight metadata into SQLite:

- function stream/event index from `--metadata-functions`
- object index from `--metadata-objects`
- event queries by function name, range, and category
- object queries by type/category/name/API
- pipeline, shader, and resource listings
- histograms
- read-only SQL helpers

This is reliable for the information Nsight exposes through documented replay
metadata. The key limitation is that the metadata function stream is shallow:
it gives event/function ordering and names, but not full root arguments,
descriptor contents, or resource revisions at each event.

### Event classification

`events.py` was fixed to classify Nsight D3D12 function names correctly.
Names such as `ID3D12GraphicsCommandList_DrawIndexedInstanced` were previously
falling into `other`. The classifier now recognizes suffix-style D3D12 names
and classifies draw, dispatch, copy, pipeline, descriptor, and state-setting
calls.

This matters because dump-only eye pairing depends on separating real draw work
from descriptor setup and unrelated API calls.

### Direct capture decoder

`capture_decoder.py` now understands the outer Pylon capture wrapper:

- file magic
- chunk headers
- chunk sizes
- compression flag
- LZ4 block decompression
- chunk IDs
- chunk offsets
- table-of-contents chunk
- metadata summary

It also includes experimental payload search and shader extraction helpers:

- `search_payloads(...)`
- `shader_chunks(...)`
- `chunk_references(...)`

These can search decompressed capture chunks for shader names, hashes, PDB
paths, DXBC/DXIL markers, and references to a shader chunk.

Known direct decoder limitation: the FunctionInfo chunks are not a stream of
simple protobuf `PbFunctionCallDesc` messages. They appear to be packed
fixed-stride binary records with auxiliary schema/string tables. That direct
per-event argument layout still needs reverse engineering.

### Protobuf schema extraction

The MCP can extract embedded `FileDescriptorProto` data from Nsight binaries and
build a schema registry. This exposes many internal message names and fields
without requiring NVIDIA documentation.

Useful namespaces include:

- `NV.EventParameters.Messages`
- `NV.Pylon.Replay`
- `NV.WarpViz`
- `NV.ShaderProfiler.Messages`
- `NV.ObjectBrowser.Messages`
- shader, descriptor, root-parameter, resource, and pipeline messages

This schema knowledge is needed for both capture decoding and private
Frame Debugger RPC calls.

### GPU Trace capture from saved capture replay

`ngfx_gputrace_capture_replay` was added and fixed so the MCP can launch GPU
Trace against `ngfx-replay.exe` replaying a saved capture.

Important behavior:

- This is not live injection into the original game process.
- The usual top-left in-game Nsight overlay is not expected when tracing
  `ngfx-replay.exe`.
- The evidence of success is the generated GPU Trace report and exported report
  files, not an in-game overlay.

The tool now supports the flags that were required in practice:

- create output directory before launch
- `--no-block-on-incompatibility`
- `--enable-dx12-application-specific-driver-state`
- `--present-hidden`
- loop count
- max duration
- optional no-timeout behavior
- auto-export

### GPU Trace report handling

`gputrace.py` can inspect both older zip-like `.nsight-gputrace` reports and
the newer binary `WRPV` report format observed in Nsight Graphics 2026.1.0.

Current capabilities:

- inspect archive/report container
- detect `WRPV`
- list/export text report folders
- parse simple tabular `.xls`/text exports
- summarize auto-export directories
- search exported GPU Trace text/XLS data
- search shader/pipeline-looking members for zip-like reports

Current limitation: the `WRPV` binary report itself is not deeply decoded yet.
String scans show useful generic event/function text, but the shader pipeline
table and shader binding data are not yet exposed as structured records.

### RPC protocol and Frame Debugger groundwork

`docs/RPC_PROTOCOL.md`, `rpc_client.py`, and `frame_debugger_rpc.py` capture a
large amount of reverse-engineered `ngfx-rpc.exe` knowledge.

Known and verified live (2026-05-19):

- `ngfx-rpc.exe` is not standard gRPC; the embedded `FileDescriptorProto`
  blobs carry zero `ServiceDescriptorProto` entries.
- The 8-byte transport frame header is fully decoded:
  - byte 0 = `0x54` (`'T'`), byte 1 = `0x08` (magic/version)
  - byte 2 = channel id (u8)
  - byte 3 = flag/padding (always observed 0)
  - bytes 4..7 = body size, big-endian u32
- The 24-byte on-wire `MessageHeader` (a compact serialization of the
  60-byte in-memory `NV::TPS::MessageHeader`) is decoded:
  - bytes 0..7  ticket_id (u64 big-endian)
  - bytes 8..15 request_id (u64 big-endian)
  - bytes 16..19 seq (u32 big-endian, purpose unknown)
  - byte 20 category, byte 21 method, byte 22 slot/flag
  - byte 23 flags (bit 0 = is_valid, bit 1 = sertype LSB)
- Category and method are single bytes on the wire — confirmed by the
  binary's "Message buffer is too small, less than wire format header size"
  check on `< 0x18` bytes.
- Dispatch is keyed by `(category, method)`. Method ids come from the
  embedded `*Method` proto enums (e.g. `BinaryReplayMethod` has 110 entries).
- `BinaryReplayMethod` has many methods relevant to Frame Debugger state:
  `MetadataRequest`, `EventInfoRequest`, `EventDetailsRequest`,
  `ApiInspectorStateRequest`, `DescriptorStateRequest`,
  `RootParametersRequest`.
- The TCP session is not one-shot when frames are well-formed — 33+ frames
  on a single connection were verified. The earlier "server exits on first
  frame" observation was a symptom of malformed input, not a hard limit.

Verified round-trip (live, 2026-05-19): the client sent a Handshake frame
(category=2 method=1 ticket=1 valid=1, body `08 01`) and the server replied
with a correlated `ticket_id=1 request_id=1` reply header. The transport
layer is working end-to-end.

MCP tools now cover:

- protocol info
- endpoint resolve/probe
- raw transport connect
- raw frame send/receive
- RPC transcript import/decode
- session binding reports
- private Frame Debugger schema descriptions
- pixel history request preview/call scaffolding
- resource access history scaffolding
- resource revision at event scaffolding
- open/close persistent private replay sessions
- arbitrary BinaryReplay method calls through a session

Current limitation — pre-session reject state. A sweep over every
reasonable `(channel, category, method, body)` combination produced an
identical reply for every attempt:

```
cat=0 meth=0 slot=11 flags=0 body=(empty)
```

The constant `slot=11` regardless of input strongly suggests a fixed
"rejected / route to error sink" path. The server is in a pre-session
state until something — almost certainly a `CategoryConnection`
`AttachMessage`/`TargetAttachedMessage` exchange or a session-id assignment
via the `slot` field — has happened. That session-setup step is the main
remaining hard gap for Frame Debugger RPC use.

### Live UI-to-RPC sniffer attempt and shared-memory wall

`tools/frida_rpc_sniff.py` is a Frida-based sniffer that hooks the I/O paths
between `ngfx-ui.exe` and `ngfx-rpc.exe`. It is now committed but did not yet
capture a real session handshake. Hooks installed:

- `ws2_32!send / recv / WSASend / WSARecv`
- `kernel32!CreateFileW / CreateNamedPipeW / WriteFile / ReadFile`
- `ntdll!NtWriteFile / NtReadFile`

`tools/rpc_sweep.py` was used in parallel to confirm the pre-session reject
result described above.

Three Frida attach/spawn modes were attempted on 2026-05-19. All three failed
in distinct ways:

| Mode | Outcome |
| --- | --- |
| `frida.attach()` runtime injection on a running ngfx-ui | ngfx-ui crashes shortly after attach |
| Custom `frida.spawn()` with child-watchdog for the rpc child | Hooks install cleanly into both processes; the sniffer process dies before any pipe I/O is captured |
| `frida-trace -f` (Frida's CLI tracer) | ngfx-ui process is alive but its main window never appears; init stalls under the trace agent |

The hooks did fire on unrelated traffic (Qt internals, the auto-updater pipe),
proving they're installed correctly. They observed **zero** bytes of the
ngfx-ui ↔ ngfx-rpc exchange.

Working hypothesis: bulk request/response data is moved through **shared
memory** (`CreateFileMapping` + `MapViewOfFile`), with the named pipe carrying
only tiny control/notification frames that all fly in the first ~100 ms before
any user-mode hook can attach. Memory-mapped read/writes have no per-byte
syscall, so user-mode API hooking fundamentally cannot see them.

That means the practical paths to capture the session-setup bytes are:

1. **PE-patch `ngfx-rpc.exe`** (or `ngfx-ui.exe`) with IDA Pro 9.0 headless to
   add a tiny logger trampoline at known I/O entry points. Survives the
   early-init window because the hook is permanent in the on-disk binary.
2. **ETW kernel trace** via `logman` / `xperf` with
   `Microsoft-Windows-Kernel-File` (and friends). Sees every file-handle
   operation at kernel level, bypassing any user-mode injection issue. Buffer
   bytes are not exposed by ETW, but message sizes + handle identity combined
   with the schema pool may still let us infer `(category, method)` patterns.
3. **Procmon** with bootlog — easier than ETW, signed kernel driver, less
   complete.
4. **Pktmon on loopback** forcing rpc into TCP transport
   (`--transport TCP --base-port N`). The shared-memory fast path likely
   doesn't apply to the TCP transport, so loopback packet capture should show
   the real frames. Open question: whether `ngfx-ui` can be steered to a
   non-default `ngfx-rpc.exe` instance.
5. **Skip sniffing entirely**: statically RE the `CategoryConnection`
   AttachMessage call site in `ngfx-ui` and reconstruct the session-setup
   frame from disassembly. Slower than capture, but doesn't depend on
   defeating shared-memory I/O.

The committed sniffer remains useful: if the eventual capture path is
TCP-forced or pipe-mode, the existing hooks will already decode whatever
bytes do flow through Winsock or `NtReadFile`/`NtWriteFile`.

### Private C++ capture/replacement bridge work

Several tools and helpers were added for the "saved capture to C++ capture" or
replacement bridge problem:

- saved C++ bridge RE analysis
- Pylon handoff preview
- private executor readiness/evidence bundles
- Pylon bridge helper scaffold
- Pylon activity-manager static binding report
- probe log analysis
- direct call binding from probe data
- Frida direct-call run helpers
- private bridge invoke helpers
- saved C++ export wrappers
- direct RPC export plans
- output-dir setting helpers
- export validation
- UI automation fallback attempts
- headless attempt wrappers
- artifact bundles

This area exists because current Nsight appears to have moved away from the old
Generate C++ Capture workflow as the primary path. The likely replacement is a
combination of Graphics Capture, replay, GPU Trace, and private Pylon/BinaryReplay
APIs. The exact headless private invocation remains incomplete.

### Subnautica 2 focused triage tools

`autonomous_shader_fix.py`, `shader_triage.py`, and `eye_issue.py` add focused
tools for the motivating problem:

- clean repro plan
- fog signal report
- CopyRectPS signal report
- CopyRectPS fix plan
- descriptor probe plan
- slot candidate extraction
- t0 source comparison
- left/right event pairing
- source lineage report
- live state probe request generation
- live pair probe analysis
- dump-only eye issue report
- event signature pairing
- resource producer graph
- ROI/HDR diff helpers
- fix claim validation
- regression scoring

The important caveat is that some of these tools consume richer artifacts when
available. If the only input is shallow metadata, the tools must report
candidate evidence instead of claiming proof.

## Actual capture and evidence so far

Main saved capture path:

```text
E:\Github\Subnautica 2\captures\nsight_mcp_20260520\Subnautica2-Win64-Shipping_2026_05_20_14_41_12.ngfx-capture
```

MCP sidecar path:

```text
E:\Github\Subnautica 2\captures\nsight_mcp_20260520\Subnautica2-Win64-Shipping_2026_05_20_14_41_12.ngfx-capture.ngfxmcp
```

Generated GPU Trace from replay:

```text
E:\Github\Subnautica 2\captures\nsight_mcp_20260520\Subnautica2-Win64-Shipping_2026_05_20_14_41_12.ngfx-capture.ngfxmcp\gputrace_replay_long\ngfx-replay_2026_05_20_17_20_37.ngfx-gputrace
```

Auto-export output includes:

- `ReportGeneratorTags.txt`
- `BASE\REPRO_INFO.xls`
- `BASE\D3DPERF_EVENTS.xls`
- `BASE\FRAME.xls`
- `BASE\GPUTRACE_FRAME.xls`
- `BASE\GPUTRACE_REGIMES.xls`

`REPRO_INFO.xls` confirms:

- process: `ngfx-replay.exe`
- API: `Direct3D 12`
- Trace Shader Bindings: `Yes`
- Collect Shader Pipelines: `Yes`
- Real-Time Shader Profiler: `Enabled`
- Start After: `Replay Pass Start`
- Limited To: `Replay Pass End`
- Max Duration: `5000 ms`

This means Nsight successfully traced replay of the saved capture. It does not
mean Nsight injected into the live game process.

### Incompatibility dialog

The UI dialog reported:

```text
D3D11 Device Creation is not supported
```

That appeared during capture/replay tooling. The current interpretation is:

- the successful useful trace is D3D12 replay of the saved capture
- the dialog is a replay/capture compatibility warning
- `--no-block-on-incompatibility` should be used to avoid blocking automation
- if replay output is valid and report data is produced, this dialog is not by
  itself proof that the replay trace failed

### Overlay question

The absence of the usual top-left Nsight overlay does not prove failure in this
path. The successful GPU Trace path attached to `ngfx-replay.exe` while replaying
a saved capture, not to the original game process. For this workflow, success is
measured by the generated `.ngfx-gputrace` and exported report data.

### r.Fog differential signal

Earlier clean r.Fog testing produced a strong signal:

- `r.Fog 1`: left-only fog voxelization PSO appears
- `r.Fog 0`: that PSO disappears
- lead PSO: `0x221FA167CE0`
- PS: `9a29f7f299902d2c` / `VoxelizePS`
- GS: `399d1b7f3e1e20bd` / `VoxelizeGS`
- draws: 77, all left-eye only

That was useful as a repro oracle, but the later stronger shader-level finding
is `CopyRectPS`. The current analysis should not overfocus on editing
`VoxelizePS`/`VoxelizeGS` unless resource lineage proves that the bad
`CopyRectPS` source was produced by that fog path.

### CopyRectPS saved-capture evidence

Direct capture shader scanning found `CopyRectPS` embedded in the saved capture.

Known values:

- shader name: `CopyRectPS`
- DXBC hash: `529845b997ed9c43ad87a3a1432fd393`
- payload SHA1: `81f5800eb6fe36958ffa1c5666016e672a1535fe`
- PDB-like string: `aab95ca751a813819972cc044ba1d07b.pdb`
- saved capture chunk: `22155`
- chunk index: `22125`

Important negative evidence:

- previous suspected hash `98acf00f2001c218` did not match a saved-capture
  shader chunk
- external text/hash references to `CopyRectPS`, the DXBC hash, SHA1, or PDB
  were not found outside the shader chunk in the direct capture chunk scan
- numeric chunk-id reference scans produced false positives and should not be
  treated as reliable unless paired with other evidence

### GPU Trace WRPV evidence

The generated `.ngfx-gputrace` report is a binary `WRPV` container, not a zip.

Observed:

- file starts with `WRPV`
- generated report size was about 82 MB
- generic strings such as `Shader`, `Pipeline`, `DrawIndexedInstanced`,
  `ExecuteIndirect`, `SetPipelineState`, and descriptor-related D3D12 function
  names appear in the binary

Not found by raw search:

- `CopyRectPS` ASCII
- DXBC hash ASCII or raw bytes
- payload SHA1 ASCII or raw bytes
- `DXBC`
- `DXIL`

Interpretation: the auto-exported tables and raw string scan are not enough.
Either the shader pipeline table is encoded in a structure we have not decoded,
or this GPU Trace export path does not preserve the shader identity in the
places searched.

## Problems encountered

### 1. Public SDK is not enough

The installed Nsight headers expose in-app control points, but not a full public
SDK for saved-capture introspection, Frame Debugger state, pixel history, or
resource revision queries. The MCP therefore needs reverse engineering of:

- Pylon capture file structure
- embedded proto schemas
- `ngfx-rpc.exe` transport and message headers
- BinaryReplay session binding
- WRPV GPU Trace report records
- private saved-capture to replay/activity manager invocations

### 2. Generate C++ Capture has a narrow but real headless gap

The Generate C++ Capture path itself still works in Nsight Graphics 2026.1.0,
and `cpp_capture_parser.py` is a working regex-based indexer that lifts
per-event arguments (root descriptor tables, CBVs, pipeline-state, viewport,
scissor, draw/dispatch args) out of the emitted C++ project into a SQLite
index. Combined with `pso_resolver.py` and the `ngfx_cpp_capture_*` MCP tools,
this is **the most direct working dump-only path** for "what was actually
bound at event N?" today.

The real constraint is narrower: the `ngfx --activity 'Generate C++ Capture'`
CLI activity requires re-running the captured application. To generate a C++
project from a **saved** `.ngfx-gfxcap` / `.ngfx-capture`, the only path that
currently works is the Nsight UI's File menu. That's the piece that breaks
"no manual UI work" autonomy until either:

1. the private executor/Pylon-bridge invocation that the UI menu uses is
   reverse-engineered and called headlessly (the `cpp_bridge_re.py` /
   `pylon_bridge_*` work), or
2. the BinaryReplay session binding (Gap 1) is solved and per-event args are
   pulled via RPC directly, bypassing C++ Capture, or
3. WRPV report decoding (Gap 2) exposes equivalent state from a GPU Trace
   pass without needing C++ Capture at all.

Practical implication for the Subnautica 2 issue: a one-time UI-driven
Generate C++ Capture on the saved capture would unblock `CopyRectPS t0`
resolution today using already-shipped tooling. The autonomy-only path
needs one of the three substitutes above.

### 3. Metadata is shallow

`ngfx-replay --metadata-functions` is good for ordering and function names. It
is not enough to answer:

- what descriptor was actually sampled by `CopyRectPS t0`
- what root table range maps to `t0`
- what resource revision existed at event N
- what the pixel history was for a coordinate
- what subresource contents were read or written

This is the core reason the MCP needs private Frame Debugger RPC and deeper
capture decoding.

### 4. Direct FunctionInfo chunk decoding is incomplete

The saved capture wrapper and TOC are decoded, but the per-event FunctionInfo
payload layout is not finished. It is not simply a stream of protobuf messages.

Needed:

- identify fixed-stride record layout
- map function IDs to names and schemas
- map argument payload offsets to typed data
- expose event arguments in the same shape as richer C++/Frame Debugger output

Until this lands, dump-only event analysis remains partly dependent on
`ngfx-replay --metadata-functions`.

### 5. Private RPC binding is incomplete

The transport and much of the message structure is known. The remaining blocker
is the private binding that makes BinaryReplay methods accepted:

- category namespace
- session/slot handle
- replay/capture handle
- activity initialization order
- any UI-generated handshake token or feature registration

Without this, tools like live pixel history and resource revision are mostly
request builders or partial clients. They need a working bound session to
produce authoritative answers.

### 6. `ngfx-rpc.exe` is hard to probe interactively

Update (2026-05-19): the "one-shot TCP session" observation from the earlier
session was wrong — it was a symptom of sending malformed frames that the
server rejected by closing. With well-formed frames (verified 24-byte wire
MessageHeader, `is_valid` bit set at byte +0 of the in-memory header) the TCP
server accepts 33+ frames on a single connection. The interactive-probing
fragility is real but smaller than originally framed.

Remaining fragility:

- The server still exits if a frame is malformed; iterative bit-flipping is
  expensive because each bad frame costs a relaunch.
- The named-pipe transport re-arms after a closed session
  (`AsioFeatureServer received session closed. Setup named pipe again.`),
  which is friendlier than TCP for iteration, but the binding glue to
  `ngfx-ui` is different so it's not a drop-in.
- The bulk handshake bytes appear to flow through shared memory (see the
  sniffer attempt above), so user-mode hooks alone do not produce a real
  transcript.

Better approaches:

- finish IDA tracing of the `CategoryConnection.AttachMessage` send site in
  `ngfx-ui` and the matching receive/bind site in `ngfx-rpc`
- PE-patch a logger trampoline on the dispatch/parse entry in `ngfx-rpc.exe`
  to dump live category/method/slot/ticket as the UI drives it
- ETW kernel-file trace of the named-pipe handles
- force TCP transport on `ngfx-rpc.exe` and use `pktmon` on loopback, if the
  UI can be steered to a non-default rpc instance

### 7. WRPV is not yet decoded

Nsight 2026 GPU Trace produces a binary `WRPV` report container. It is not the
older zip-like report that some tooling expected.

Needed:

- parse WRPV header/table layout
- locate record boundaries
- identify string table/dictionary encoding
- extract event/function rows
- extract shader pipeline rows
- extract shader binding rows
- map GPU Trace event IDs back to capture/replay event IDs

Until this exists, GPU Trace confirms that replay/profiling ran, but it does not
yet provide the deep shader pipeline binding proof needed for the eye issue.

### 8. Descriptor table scans are not shader-use proof

The saved `descriptor_reads` style data seen in some artifacts is a scan of a
bound table, not reflection proof that every listed descriptor was sampled.

For `CopyRectPS`, the shader should sample `t0` and `s0`. The MCP must map:

- shader register `t0`
- register space
- root signature range
- descriptor table base
- descriptor index
- resolved resource/view

Only then can it claim "this is the actual sampled source".

### 9. Historical fix claims overclaimed

The handoff noted misleading memory entries named like:

- `sn2_RIGHT_EYE_FIX_WORKS_*.md`
- `sn2_RIGHT_EYE_FIX_FINAL_*.md`

Those should be edited or deleted by whoever maintains the external memory
store. The honest current status is that the bug is not fixed.

### 10. The PSO substitution path hit a dead end

The earlier DXIL/PSO substitution attempt ran into a path where the target PSO
entered through neither `CreateGraphicsPipelineState` nor
`CreatePipelineState` hooks. It likely came from a cached blob or alternate
loading path.

This is a useful lesson for the MCP design: the analysis should first prove the
bad event, bound state, and source resource. Shader patching should be a
diagnostic/fix loop step, not the first assumption.

## Current theory for the right-eye issue

The strongest current theory is:

1. The bad visual signal reaches or appears at a `CopyRectPS` draw.
2. `CopyRectPS` is a simple copy shader, not the likely source of complex
   stereo logic.
3. Therefore the bug is probably in one of:
   - the source SRV bound to `t0`
   - the constants/rect/viewport/scissor used to copy
   - the destination target or array slice
   - the earlier producer of the copied source texture
4. To solve this from Nsight alone, the MCP must compare paired left/right
   `CopyRectPS` events and prove:
   - actual `t0` source resource and view
   - actual `s0` sampler, mostly for completeness
   - RTV/destination resource and subresource
   - viewport and scissor
   - root constants/CBV bytes relevant to copy rect/UV transform
   - resource access history for source and destination
   - pixel history for bug ROI

If left and right sample the same `t0` resource but only right is wrong, then
focus on rect/view constants, viewport/scissor, render target selection, or the
source resource containing stereo-packed data with wrong UV selection.

If left and right sample different `t0` resources, then focus on descriptor
routing or the producer of the right-eye source.

If the bad pixels are already present in the right-eye source before
`CopyRectPS`, then `CopyRectPS` is only the reveal/copy event and the producer
chain is the real fix target.

If the source is correct before `CopyRectPS` but destination becomes wrong at
`CopyRectPS`, then inspect copy constants, SRV view desc, sampling coordinates,
viewport/scissor, and target/subresource state.

## What the MCP still needs

### Gap 1: working live BinaryReplay/Frame Debugger session binding

This is the highest value gap.

Needed result:

- given a saved capture, start the private replay/Frame Debugger backend
- open or bind a capture session
- call BinaryReplay methods successfully
- query event state, root parameters, descriptor state, pixel history, resource
  access history, and image/subresource data

Why it matters:

- this is the most direct path to "what did this shader actually sample?"
- it avoids guessing from shallow metadata and table scans
- it can provide pixel history and resource revision at event

Status:

- Transport layer is verified live (8-byte frame header + 24-byte compact
  MessageHeader), with a correlated ticket_id round-trip.
- A `(channel, category, method, body)` sweep proved the server is in a
  fixed pre-session reject state (`cat=0 meth=0 slot=11`). The blocker is a
  session-setup step, not the wire format.
- The Frida sniffer attempts on 2026-05-19 did not capture session bytes —
  shared memory is the most likely transport for the bulk handshake (see
  "Live UI-to-RPC sniffer attempt and shared-memory wall" above).

Implementation plan (revised):

1. Choose one of the capture paths that survives the shared-memory wall:
   - PE-patch + IDA Pro headless to add a logger trampoline in `ngfx-rpc.exe`
     at the dispatch/parse entry, or
   - ETW kernel trace via `logman` / `xperf` plus the `Kernel-File` provider,
     or
   - force TCP transport on `ngfx-rpc.exe` and run `pktmon` on loopback,
     accepting that ngfx-ui may not be steerable to a non-default rpc.
2. In parallel, use IDA headless on `ngfx-ui.exe`, `ngfx-rpc.exe`,
   `PylonReplay_PluginInterface.dll`, and relevant plugins to identify the
   capture-open and Frame Debugger session initialization sequence directly
   from disassembly. The committed `cpp_bridge_re.py` and `ida_re.py` helpers
   should be extended to extract the `CategoryConnection.AttachMessage` send
   site and any session-id/slot population code.
3. Extract concrete method IDs, category IDs, handle fields, and
   request/response message names from the embedded proto pool and
   decompiled call sites. The proto pool already exposes them; the missing
   piece is the **order** and **handle fields** of the setup sequence.
4. If a real transcript is obtained, decode it with existing
   `ngfx_rpc_transcript_import` and `ngfx_rpc_decode_frame`. Otherwise
   reconstruct the sequence from static RE alone.
5. Add a deterministic `ngfx_rpc_open_capture_session` implementation that
   does the observed initialization sequence and returns a bound session
   handle, slot id, and category namespace.
6. Use persistent sessions so multi-call analysis works on a single TCP
   connection (now confirmed not to be one-shot for well-formed frames).
7. Add focused tests for message encoding and response decoding with
   synthetic frames at both the transport-frame and MessageHeader layers.

Acceptance criteria:

- `ngfx_rpc_open_capture_session(capture=...)` returns a bound session handle.
- `ngfx_rpc_call_binary_replay(...)` can call at least one harmless known
  method and receive a non-`slot=11` reply.
- `ngfx_pixel_history(...)` returns actual pixel contributors for a coordinate.
- `ngfx_resource_revision_at_event(...)` returns an event-bounded revision or
  a clear "not available" error from Nsight, not a transport/protocol failure.

### Gap 2: WRPV GPU Trace decoder

Needed result:

- parse binary WRPV reports enough to expose shader pipeline/binding/event rows
  as structured MCP data

Why it matters:

- current Nsight GPU Trace output on this machine is WRPV, not zip-like
- auto-exported text tables do not include the shader identity needed for
  `CopyRectPS`
- GPU Trace had shader binding/pipeline collection enabled, so useful data may
  exist inside WRPV but remain hidden

Implementation plan:

1. Add raw WRPV search tools:
   - ASCII search
   - UTF-16LE search
   - hex/raw byte search
   - contextual string extraction around offsets
2. Parse the WRPV header:
   - magic
   - version
   - table offsets/sizes
   - record counts if present
3. Identify record boundaries using known strings and protobuf-like patterns.
4. Search Nsight binaries/plugins for WRPV reader code:
   - `WarpVizPlugin`
   - `ShaderProfilerPlugin.dll`
   - `nvperf_grfx_host.dll`
   - report generator components
5. Use IDA headless facts to identify:
   - WRPV magic checks
   - version switches
   - table readers
   - decompression/dictionary code if any
   - row/schema descriptors
6. Expose structured tools:
   - `ngfx_gputrace_wrpv_search`
   - `ngfx_gputrace_wrpv_strings`
   - `ngfx_gputrace_wrpv_tables`
   - `ngfx_gputrace_shader_bindings`
   - `ngfx_gputrace_event_map`

Acceptance criteria:

- For a WRPV report, the MCP can list tables/sections.
- It can extract draw/copy/dispatch event rows.
- It can extract shader pipeline or shader binding records if present.
- It can map GPU Trace rows back to replay/capture events well enough for
  paired left/right analysis.

### Gap 3: direct saved-capture event argument decoding

Needed result:

- decode the FunctionInfo chunks inside `.ngfx-capture`/`.ngfx-gfxcap` without
  depending on shallow `--metadata-functions`

Why it matters:

- fully dump-only Nsight analysis should not require a live replay backend for
  every basic query
- direct event args would expose more state from saved captures even when RPC is
  unavailable

Implementation plan:

1. Use IDA on `ngfx-replay.exe` and Pylon replay DLLs to locate FunctionInfo
   readers.
2. Identify the fixed-stride record layout:
   - function ID
   - event index
   - thread ID
   - timestamps
   - argument offset/size
   - object/resource handles
3. Identify the function-name and argument-schema mapping chunk.
4. Add typed decoders for the most important D3D12 calls first:
   - `SetPipelineState`
   - `SetGraphicsRootDescriptorTable`
   - `SetGraphicsRootConstantBufferView`
   - `SetGraphicsRoot32BitConstants`
   - `OMSetRenderTargets`
   - `RSSetViewports`
   - `RSSetScissorRects`
   - `DrawInstanced`
   - `DrawIndexedInstanced`
   - copy/resolve calls
   - resource barriers
5. Add generic fallback wire/record dumps for unknown events.

Acceptance criteria:

- `ngfx_capture_event_args` returns useful typed arguments for common D3D12
  render-state calls.
- `ngfx_eye_issue_dump_report` can resolve a `CopyRectPS` pair's nearby root
  state from saved capture alone.
- Unknown records are still inspectable as structured hex/field candidates.

### Gap 4: actual `CopyRectPS t0` resolution

Needed result:

- prove the actual source texture sampled by `CopyRectPS` for both eyes

Why it matters:

- this is the central missing fact for the Subnautica 2 issue
- without it, the MCP can only list candidate descriptors

Implementation plan:

1. Use live BinaryReplay descriptor/root state once Gap 1 is solved.
2. In parallel, add dump-only root signature and descriptor range extraction from
   objects/capture chunks.
3. Map shader reflection binding:
   - `CopyRectPS` reads `t0`
   - register space
   - descriptor range
   - root parameter index
   - descriptor table base
   - descriptor index
4. Resolve descriptor to:
   - resource handle
   - view type
   - format
   - mip
   - array slice
   - dimensions
   - resource name if available
5. Compare left/right events.

Acceptance criteria:

- A report can say "left CopyRectPS event X sampled resource A view V, right
  CopyRectPS event Y sampled resource B view W" with evidence source.
- The report explicitly distinguishes "actual sampled descriptor" from
  "candidate descriptor found in bound table".

### Gap 5: resource revision and pixel-history extraction

Needed result:

- identify the resource revision and event chain that produced the bad pixel

Why it matters:

- a copy shader bug is usually upstream of the copy
- pixel history/resource history is the most direct way to find the first bad
  writer

Implementation plan:

1. Finish live BinaryReplay pixel history call.
2. Finish live resource access history call.
3. Add grid sampling over the right-eye ROI:
   - several representative bad pixels
   - matching left-eye pixels
   - edge/control pixels
4. For each pixel, build:
   - final target history
   - `CopyRectPS` source history
   - immediate producer event
   - previous good/bad revision boundary
5. Expose a producer graph:
   - nodes are resources/revisions/events
   - edges are read/write/copy/resolve/sample relationships

Acceptance criteria:

- The MCP can report the first event where a selected right-eye pixel diverges.
- It can classify whether the error was already present in `CopyRectPS t0`.
- It can name the immediate upstream producer if the source was already bad.

### Gap 6: image/subresource dumping from Nsight alone

Needed result:

- export or read resource/subresource contents at a selected event/revision

Why it matters:

- visual proof should be generated by the MCP, not by manual UI inspection
- ROI diff and image previews need actual texture bytes

Implementation plan:

1. Use BinaryReplay image/subresource methods if available.
2. If RPC cannot export image data directly, reverse engineer the file-transfer
   notification path already partially implemented in `cpp_bridge_re.py`.
3. Add resource dump tools:
   - dump render target at event
   - dump SRV source at event
   - dump selected mip/slice
   - dump ROI to image/float array
4. Add common image comparison:
   - luminance diff
   - absolute RGB diff
   - HDR-aware diff
   - stereo half/array-slice comparison

Acceptance criteria:

- The MCP can produce a small artifact bundle with left/right source and target
  ROI images for the suspect event pair.
- The report includes numeric diff metrics and image paths.

### Gap 7: stable headless private executor

Needed result:

- private Nsight operations that the UI can do should be runnable headlessly by
  the MCP

Why it matters:

- user does not want manual UI work
- C++ capture/project generation, Frame Debugger, resource export, and report
  generation may all route through private Pylon executor calls

Implementation plan:

1. Continue IDA headless analysis of:
   - Pylon activity manager
   - BinaryReplay session binder
   - saved capture open path
   - report/file export path
2. Decide between two practical paths:
   - in-process Pylon activity-manager call
   - out-of-process BinaryReplay RPC/session binder
3. Add a small helper executable or Frida path only if direct Python/RPC cannot
   cross the boundary safely.
4. Keep the MCP API stable and return evidence bundles for any private call:
   - command line
   - loaded binaries
   - method/category IDs
   - request preview
   - response/error
   - output artifact paths

Acceptance criteria:

- Given a saved capture path, the MCP can run the private operation that the UI
  would have run and collect artifacts.
- Failure is diagnosable from structured error data, not a silent timeout.

### Gap 8: autonomous fix and validation loop

Needed result:

- after identifying the cause, the MCP should drive candidate fixes and reject
  overclaims

Why it matters:

- the previous handoff explicitly contained overclaimed "working fix" entries
- the final system must distinguish "changed the image" from "fixed the issue"

Implementation plan:

1. Define fix hypotheses from evidence:
   - descriptor/source routing
   - view rect/constants
   - target/subresource routing
   - upstream producer shader/state
   - diagnostic shader probe only
2. For each hypothesis, produce:
   - expected event/state change
   - expected ROI metric change
   - expected control behavior
3. Require validation gates:
   - right-eye ROI improves
   - left eye does not regress
   - r.Fog control still behaves as expected if relevant
   - no unrelated large-frame diff
   - same capture/replay conditions
4. Keep a negative-results log so failed hypotheses do not repeat.

Acceptance criteria:

- `ngfx_validate_fix_claim` refuses a fix claim without before/after evidence.
- The MCP can emit a ranked next-fix plan from the current failed evidence.
- A final "fixed" report includes event-level proof and visual metrics.

## Planned build order

### Phase 1: Make dump-only reports more honest and complete

Goal: maximize value from saved captures even before private RPC is fully
working.

Tasks:

- add WRPV raw search tools
- add WRPV string extraction with offsets
- add stronger negative-evidence reporting for missing shader IDs
- improve `ngfx_eye_issue_dump_report`
- include capture shader chunk facts in the eye report
- explicitly classify evidence as:
  - proven
  - inferred
  - candidate
  - missing
- add report sections for:
  - `CopyRectPS` chunk evidence
  - left/right paired draw candidates
  - unresolved sampled `t0`
  - next required private query

Deliverable:

- one command/tool call that produces a self-contained dump-only report for the
  saved capture and clearly says what is still unproven.

### Phase 2: Decode WRPV enough to extract tables

Goal: stop treating GPU Trace 2026 reports as opaque binary blobs.

Tasks:

- implement `ngfx_gputrace_wrpv_search`
- implement `ngfx_gputrace_wrpv_strings`
- reverse engineer the header/table structure
- add table/section listing
- find event row table
- find shader/pipeline/binding row table, if present
- add tests with synthetic WRPV fixtures

Deliverable:

- WRPV reports become queryable MCP artifacts instead of just "binary report
  exists".

### Phase 3: Finish private BinaryReplay session binding

Goal: make live Frame Debugger methods work without the UI.

Prerequisite: the 2026-05-19 sniffer attempt showed user-mode hooks cannot
see the ngfx-ui ↔ ngfx-rpc bulk handshake (likely shared memory). Pick one
of the bypass paths before continuing this phase: PE-patch + IDA trampoline,
ETW kernel-file trace, pktmon on a forced-TCP rpc, or full static RE of the
`CategoryConnection.AttachMessage` send site.

Tasks:

- capture or reconstruct the UI initialization sequence via the chosen path
- pin capture/session/slot handle fields and the order of setup frames
- implement reliable session open
- call harmless state methods and confirm the reply is not the
  `cat=0 meth=0 slot=11` reject pattern
- call event/root/descriptor state methods
- call pixel/resource history methods

Deliverable:

- `ngfx_rpc_open_capture_session` plus `ngfx_pixel_history` and
  `ngfx_resource_revision_at_event` work against the saved capture replay.

### Phase 4: Prove `CopyRectPS t0`

Goal: answer the central issue question.

Tasks:

- identify paired left/right `CopyRectPS` events
- fetch live descriptor/root state for both
- map shader `t0` to actual descriptor
- fetch resource/view metadata
- compare source/destination/rect state
- generate a concise verdict:
  - same source, bad rect/target/producer
  - different source, descriptor routing bug
  - source already bad, trace producer
  - source good, copy/rect/target bug

Deliverable:

- an evidence-backed CopyRectPS right-eye issue report.

### Phase 5: Resource lineage and pixel proof

Goal: find the first bad event, not just the first visible copy.

Tasks:

- run pixel history on right-eye bad ROI and left-eye control ROI
- run resource access history on CopyRectPS source and destination
- build producer graph
- dump relevant ROI images
- identify first divergent revision/event

Deliverable:

- a report that says exactly where the visual bug appears and what event wrote
  the bad data.

### Phase 6: Fix loop support

Goal: let the LLM select and validate a fix without user help.

Tasks:

- encode fix hypotheses from the evidence
- generate minimal diagnostic probes only when needed
- run before/after captures or replays
- compute ROI and event/state diffs
- reject insufficient fix claims
- keep failed-attempt memory local to the run

Deliverable:

- a complete "hypothesis -> change -> capture -> compare -> accept/reject"
  loop with structured artifacts.

## IDA Pro headless targets

The useful IDA targets are likely:

- `ngfx-rpc.exe`
- `ngfx-ui.exe`
- `ngfx-replay.exe`
- `PylonReplay_PluginInterface.dll`
- Pylon activity manager related DLLs
- `Plugins\ShaderProfilerPlugin.dll`
- `Plugins\WarpVizPlugin\*`
- `nvperf_grfx_host.dll`
- any report generator or WarpViz reader DLL found by string search for:
  - `WRPV`
  - `BinaryReplay`
  - `PixelHistory`
  - `ResourceAccessHistory`
  - `ApiInspector`
  - `RootParameters`
  - `DescriptorView`
  - `ShaderProfiler`

Specific RE questions:

- Where is the WRPV magic checked?
- What is the WRPV file/table header layout?
- Are WRPV records protobuf, fixed structs, FlatBuffers-like, or custom?
- Which code extracts shader pipelines from GPU Trace?
- Which UI call opens a saved capture into BinaryReplay?
- Which request creates/binds the replay session?
- Which handle fields are required by PixelHistory and ResourceAccessHistory?
- How does the private file-transfer/export path deliver image data or C++
  project files?
- Is there a current replacement for Generate C++ Capture, and which backend
  method invokes it?

## Suggested MCP tools to add next

High priority:

- [x] `ngfx_gputrace_wrpv_search`  — shipped
- [x] `ngfx_gputrace_wrpv_strings` — shipped
- [x] `ngfx_gputrace_wrpv_sections` — shipped
- [x] `ngfx_gputrace_wrpv_table_preview` — shipped
- [x] `ngfx_gputrace_shader_bindings` — shipped
- [x] `ngfx_rpc_capture_open_sequence_report` — shipped
- [x] `ngfx_rpc_observed_session_import` — already covered by existing
      `ngfx_rpc_transcript_import`
- [ ] `ngfx_binary_replay_session_bind` — blocked on Gap 1 (live session)
- [ ] `ngfx_binary_replay_event_state` — blocked on Gap 1
- [ ] `ngfx_binary_replay_descriptor_state` — blocked on Gap 1
- [ ] `ngfx_binary_replay_root_parameters` — blocked on Gap 1
- [ ] `ngfx_binary_replay_image_subresource_dump` — blocked on Gap 1
- [x] `ngfx_copyrect_t0_resolution_report` — shipped (dump-only path
      via `cpp_capture_parser` + `pso_resolver`)
- [ ] `ngfx_pixel_history_roi_grid` — blocked on Gap 1
- [ ] `ngfx_resource_revision_graph` — blocked on Gap 1

Track B sniffer-wall bypasses:

- [x] `ngfx_rpc_etw_environment` — shipped
- [x] `ngfx_rpc_etw_capture_start` / `_stop` / `_summary` — shipped
      (wraps logman + tracerpt with dry-run support)
- [x] `ngfx_rpc_pe_patch_plan` — shipped (planner; emits structured
      plan + trampoline template, no patching)
- [x] `ngfx_rpc_pe_patch_ida_script` — shipped (emits IDA Pro 9.0
      headless Python script with TODOs for marker patching)

Medium priority:

- [ ] `ngfx_capture_functioninfo_layout_probe`
- [ ] `ngfx_capture_decode_d3d12_args`
- [x] `ngfx_capture_root_signature_ranges` — shipped (parses serialised
      D3D12 root signature v1.0/v1.1 blobs from the C++ project)
- [x] `ngfx_capture_root_signature_lookup` — shipped (shader register
      → root parameter / range resolver)
- [x] `ngfx_capture_descriptor_heap_timeline` — shipped (per-heap
      timeline of SetDescriptorHeaps / CopyDescriptors /
      SetGraphicsRootDescriptorTable / Create*View)
- [ ] `ngfx_capture_resource_lifetime_graph`
- [x] `ngfx_shader_reflection_bindings` — shipped (DXBC RDEF chunk
      parser exposes shader register → resource name table)
- [x] `ngfx_shader_disassembly_summary` — shipped (best-effort via
      `dxc -dumpbin` with RDEF-reflection fallback)
- [x] `ngfx_fix_attempt_log` — shipped (append-only JSONL; refuses
      `decision='accept'` without before+after evidence)
- [x] `ngfx_fix_claim_evidence_bundle` — shipped (zip bundler;
      requires before+after screenshots by default)

Lower priority but useful:

- old Nsight version compatibility matrix
- automatic old-version C++ Capture fallback
- UI automation fallback with stronger window/dialog handling
- capture/replay incompatibility classifier
- report artifact packager
- generated markdown summary from any MCP investigation run

## Ideal end-to-end autonomous workflow

The final LLM-driven workflow should look like this:

1. Input:
   - saved Nsight capture path
   - optional expected bad ROI or screenshot comparison
2. Capture prep:
   - decode capture header/TOC
   - index functions
   - index objects
   - extract shader chunks
   - detect API/GPU/Nsight version
3. Candidate discovery:
   - find eye-paired draws
   - find asymmetric draws/resources
   - locate known suspect shaders such as `CopyRectPS`
   - build candidate bad events
4. State proof:
   - bind private BinaryReplay session
   - fetch event state for candidate pairs
   - resolve root params and descriptors
   - prove actual shader inputs/outputs
5. Pixel proof:
   - run pixel history for bad/control points
   - trace source and destination resource revisions
   - dump ROI images
6. Diagnosis:
   - classify source bad vs copy bad vs target bad vs rect bad
   - identify upstream producer if needed
7. Fix planning:
   - produce ranked hypotheses
   - generate diagnostic probes only when they answer a missing proof point
8. Validation:
   - rerun capture/replay
   - compare event state
   - compare ROI metrics
   - verify controls
9. Final report:
   - first bad event
   - exact bad state
   - fix location
   - validation evidence
   - remaining risks

## Acceptance criteria for "solved by Nsight MCP"

The project is successful when an LLM can run the MCP against the saved capture
and produce a report with all of the following:

- the exact first event where the right-eye visual output becomes wrong
- the paired left-eye event used as control
- the pipeline and shader identity for both events
- the actual sampled `CopyRectPS t0` resource/view for both eyes
- the destination target/subresource for both eyes
- relevant viewport/scissor/copy-rect/root-constant/CBV differences
- pixel history for at least one bad right-eye pixel and one left-eye control
  pixel
- resource revision history for the source and destination resources
- a producer graph leading to the first bad writer if the copy source is already
  bad
- a fix hypothesis tied to the proven bad state
- before/after validation that checks both right-eye improvement and left-eye
  non-regression
- explicit evidence labels so candidates are not presented as proof

## Current next step

After the 2026-05-19 RPC work and the 2026-05-20 tool batch (+20 tools,
221 → 241), the practical next-step ranking has shifted.
Three independent tracks, in priority order:

### Track A — unblock `CopyRectPS t0` for Subnautica 2

**Important reality check (2026-05-20):** the earlier draft of this section
claimed "the only autonomy gap is one UI click in the Nsight Graphics File
menu." That was wrong, and the live diagnostic confirms it:

- The Nsight 2026.1.0 UI has **no** "saved capture → Generate C++ Capture"
  menu item; the activity's UI labels are only `Launch for Generate C++ Capture`
  and `Attach for Generate C++ Capture` (both require a live application).
- Running `ngfx.exe --activity "Generate C++ Capture"` against
  `ngfx-replay.exe` replaying the saved capture (the same trick that powers
  `ngfx_gputrace_capture_replay`) reaches the activity backend, attaches,
  prepares the export — and then the activity refuses with the runtime
  error: *"Export of C++ Capture could not complete: Serializing apps to
  C++ capture using D3D11 or D3D12 is no longer supported - please
  migrate to the Graphics Capture Activity."*
- The Nsight Graphics 2026.1 release notes list the same removal under
  Deprecations; the prior 2025.5 release notes call it out as a future
  deprecation while still supporting D3D12.

So **NVIDIA has removed D3D11/D3D12 C++ Capture export entirely in
2026.1.0**. Every Nsight-provided route is dead for D3D12:

- ❌ UI menu (`saved-capture → Generate C++ Capture`) — gone in 2026.1.0
- ❌ `ngfx_cpp_capture_launched` (live-app `--activity`) — hits the runtime error
- ❌ `ngfx_cpp_capture_against_replay` (replay-attach pattern) — same error
- ❌ `pylon_in_process_activity_manager` (Frida-inject backend) — same error
- ❌ `direct_binaryreplay_rpc` (`RequestGenerateCapture` over the TPS pipe)
  — same error; same backend
- ❌ pywinauto UI fallback — no menu item to click

For the SN2 issue there are exactly two routes left, and both have
real cost:

#### Track A1 — sidecar install of Nsight Graphics 2025.5 + autonomous recapture

NVIDIA 2025.5 still supports D3D12 Generate C++ Capture (it's
deprecation-warned, not removed). The full programmatic workflow is
now exposed as a single MCP tool: `ngfx_cpp_capture_full_autonomy`,
which chains every step below. The expanded steps:

1. Install Nsight Graphics 2025.5 alongside 2026.1.0. They coexist; pick
   the older for the C++ Capture step only.
2. Run `ngfx_cpp_capture_pick_install(api="d3d12")` — the picker walks
   every installed version and picks the newest one whose Generate C++
   Capture activity still supports D3D12. Verified output for the SN2
   case: it picks `Nsight Graphics 2025.5.0`.
3. Run `ngfx_cpp_capture_compatibility_check(capture, picked_install)`.
   The check reads the saved capture's recorded `MetaData.NsightVersion`
   straight from the TOC protobuf (no replayer invocation) and compares
   it to the install version. For the SN2 case it returns
   `recapture_required: True` (capture was made with 2026.1.0,
   replayer is 2025.5.0; old replayer can't handle the new
   `D3D12_FEATURE = 64` enum value).
4. Run `ngfx_capture_recapture_with_install(capture)` to actually
   execute the recapture. The tool reads the source capture's
   `MetaData.CaptureBeginFrame` (1698 for the SN2 case) and passes it
   to 2025.5's `ngfx-capture.exe --capture-frame 1698
   --terminate-after-capture`. The exe path and args come straight
   from the source capture's stored `ProcessFileName` and
   `ProcessCommandLine`. The application launches, ngfx-capture
   triggers automatically at the recorded frame, the application
   exits cleanly — no human input required as long as the app's boot
   path is deterministic. Pass `countdown_ms=…` instead of `frame=…`
   to trigger by elapsed time, or pass either explicitly to override
   the auto-detection. (For a "just emit the argv, don't run it"
   variant, use `ngfx_cpp_capture_recapture_plan`.)
5. Run `ngfx_cpp_capture_against_replay(recaptured_path)` — the C++
   Capture activity replays the (now-compatible) capture and emits a
   C++ project. With the recaptured artifact the activity completes
   instead of hitting the "no longer supported" error (which is gated
   by the **runtime** version, not the activity flow).
6. Index the emitted project with `cpp_capture_parser.index_cpp_project`
   + `pso_resolver.index_project_psos`.
7. Everything downstream (`ngfx_copyrect_t0_resolution_report`,
   `ngfx_capture_root_signature_ranges`,
   `ngfx_capture_root_signature_lookup`,
   `ngfx_shader_reflection_bindings`,
   `ngfx_capture_descriptor_heap_timeline`, the `ngfx_fix_attempt_log`
   audit trail) is already shipped and works against the indexed
   project.

Cost: one ~1GB Nsight 2025.5 install. Once it's present, the chain
runs to completion via a single `ngfx_cpp_capture_full_autonomy(capture)`
call — no UI work, no human input. The only assumption is that the
application's boot path is deterministic enough to reach the same
scene at the same frame number; if not, pass an explicit
`countdown_ms` to trigger by elapsed time, or wire a visual-cue
trigger via `mcp__gemma-screen-observer__` (Option 2 in this section).

#### Track A2 — direct FunctionInfo decoder (Gap 3)

The version-proof answer: decode the per-event records out of the saved
`.ngfx-gfxcap` / `.ngfx-capture` file directly, with no Nsight involvement.

The outer Pylon wrapper, chunk headers, table-of-contents, and chunk
decompression are already implemented in `capture_decoder.py`. What
remains is the fixed-stride record layout of the FunctionInfo chunk
(the chunk whose ID is in `PbTableOfContents.FunctionInfoChunkIds`),
plus the function-name and argument-schema mapping.

That's the work tracked under "Gap 4: direct FunctionInfo chunk decoding
is incomplete" earlier in this document. It is the only path that is
durable across Nsight versions, and it is the right long-term answer
now that NVIDIA has explicitly removed the C++ Capture exporter for
D3D12.

#### What the probe tells you

`ngfx_cpp_capture_route_probe` classifies every documented route as
alive or dead for the installed Nsight version, using the
release-notes mapping in `cpp_capture.D3D_CPP_CAPTURE_STATUS_BY_VERSION`.
On a 2026.1.0-only install it returns:

```
recommended_route: direct_capture_functioninfo_decode
d3d_cpp_capture_deprecated: True
replay_attach.alive: False        (alive_for_vulkan_only: True)
cli_live_app.alive: False         (alive_for_vulkan_only: True)
```

Use `ngfx_cpp_capture_pick_install(api="d3d12")` first — if an older
sidecar install is available the picker recommends it and the workflow
continues into the recapture path above. Only if no working install
is available is Gap 3 (direct decoder) the right next move.

#### 2026.1.0-only programmatic paths

If the sidecar 2025.5 install is not an option, the only programmatic
ways to extract per-event arguments from a saved D3D12 capture in
2026.1.0 are:

- **Gap 3 — direct FunctionInfo decoder.** `capture_decoder.py` already
  decodes the outer wrapper, the TOC, and chunk decompression. The
  FunctionInfo chunk (kind `5`, ID in `function_info_chunk_ids`) is
  loaded but its per-event record layout is not yet decoded. The
  payload is fixed-stride binary, not protobuf — this is the work
  that's been called out as Gap 3 / Gap 4 throughout this document.
- **Gap 1 — BinaryReplay RPC session binding.** The TPS named-pipe
  transport and 24-byte MessageHeader are decoded; the
  `CategoryConnection.AttachMessage` handshake is the remaining piece.
  Once it's reproduced, `RequestGenerateCapture` / per-event RPCs all
  become callable without the UI. Note: even with this finished, the
  Pylon backend still raises the D3D12 deprecation error for actual
  C++ Capture export; the win is direct event/state RPCs, not C++
  project emission.
- **UI scraping (last resort).** Drive `ngfx-ui.exe` via pywinauto:
  open the capture, start Graphics Debugging, navigate to the event,
  scrape the API Inspector text. Brittle, but matches what a human
  would do manually. Existing scaffold:
  `ngfx_cpp_capture_saved_ui_automation_attempt`.

### Track B — finish the autonomy gap

In parallel with Track A. Three bypass paths are now wrapped as MCP tools:

- `ngfx_rpc_pe_patch_plan` + `ngfx_rpc_pe_patch_ida_script` — planner for
  the PE-patch + IDA Pro 9.0 headless trampoline at the rpc
  dispatch/parse entry (most informative, hardest to set up). Outputs
  are plan + script — the actual patch must be reviewed before running.
- `ngfx_rpc_etw_environment` / `_capture_start` / `_capture_stop` /
  `_capture_summary` — wraps Windows `logman` + `tracerpt` against the
  kernel-file provider (easiest; only gives handles + sizes, but
  bypasses every user-mode hook).
- pktmon on loopback with forced-TCP rpc — easy if `ngfx-ui` can be
  steered to a non-default rpc instance. Not yet wrapped as a tool.
- `ngfx_rpc_capture_open_sequence_report` — consolidates the static RE
  knowledge plus an analysis of any captured transcript, so the planner
  can see which `(category, method, slot)` keys are still missing.

Goal: capture the `CategoryConnection.AttachMessage` exchange and any
session-id/slot assignment, then implement the eventual
`ngfx_rpc_open_capture_session` so subsequent calls stop hitting the
`cat=0 meth=0 slot=11` reject path.

If all three bypasses fail, fall back to pure-static RE of the
AttachMessage send site in `ngfx-ui.exe` and reconstruct the setup
sequence from disassembly — slower but no live-capture dependency.

### Track C — WRPV decoding

Raw inspection tools are now shipped:

- `ngfx_gputrace_wrpv_search` — multi-encoding (ASCII + UTF-16LE + raw
  hex) needle search with context dumps
- `ngfx_gputrace_wrpv_strings` — printable-string extraction with byte
  offsets and an optional regex filter
- `ngfx_gputrace_wrpv_sections` — candidate header-field listing
  (proven for magic + size, candidate for every other DWORD)
- `ngfx_gputrace_wrpv_table_preview` — hex+ASCII dump at an offset
- `ngfx_gputrace_shader_bindings` — convenience wrapper bundling the
  Subnautica 2 evidence (`CopyRectPS`, DXBC hash, payload SHA1, PDB)

Next concrete WRPV decoding steps (still pending):

1. Run `ngfx_gputrace_shader_bindings` against the SN2 WRPV report and
   check whether `CopyRectPS` / its hash / its PDB name appear at all.
2. Use IDA on Nsight plugins (`WarpVizPlugin`, `ShaderProfilerPlugin`)
   to identify the matching reader code and pin the header layout.
3. Promote the WRPV section candidates to a proven format spec; add
   `ngfx_gputrace_wrpv_event_rows` / `_shader_pipelines` table-typed
   helpers once the records are decoded.

### Honest status

Until Track B lands or Track A is run end-to-end:

- the MCP can gather and correlate a lot of Nsight evidence from the dump
- the bug is not fixed
- `CopyRectPS` is the strongest current event/shader lead
- the actual sampled right-eye source texture is still unresolved
- the transport layer to `ngfx-rpc` is verified working, but the session is
  in a fixed reject state until the AttachMessage handshake is reproduced
- the one fully-autonomous path that's also dump-only requires either Track
  B to succeed, or WRPV to expose shader-binding records, or the headless
  Pylon-bridge work in `cpp_bridge_re.py` to land
