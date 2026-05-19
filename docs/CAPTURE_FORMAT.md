# `.ngfx-gfxcap` capture file format — reverse-engineering notes

These notes describe what's known about the Nsight Graphics capture file
format, derived from binary analysis of `ngfx-replay.exe` (Nsight Graphics
2026.1.0). The format is **proprietary** and **undocumented** by NVIDIA;
treat anything below as best-effort.

If you only need to *read* captures (events, objects, summary,
screenshots), use the JSON-backed tools instead — they wrap
`ngfx-replay --metadata*` and don't depend on any of this:

  * `ngfx_capture_summary`     → `--metadata`
  * `ngfx_capture_objects`     → `--metadata-objects`
  * `ngfx_capture_functions`   → `--metadata-functions`
  * `ngfx_index_objects`       → indexed `--metadata-objects` in SQLite
  * `ngfx_index_events`        → indexed `--metadata-functions` in SQLite

This document is for the cases those aren't enough — e.g. extracting raw
resource bytes, full PSO bytecode, or shader-source profiling data.

## File magic

Every `.ngfx-gfxcap` starts with 8 ASCII bytes:

```
0x00:  6e 6c 79 70 65 6c 69 66    "nlypelif"
```

Read as two little-endian 32-bit words, this is `"pyln" + "file"` —
i.e. the codename "Pylon file". `Pylon` is the internal name for the
Nsight Graphics replay engine (see `PylonReplay_PluginInterface.dll` in
the host bin dir and the protobuf namespace `NV.Pylon.Replay.*`).

## Header (tentative)

The 56 bytes after the magic look like a fixed-size header. Sample from
a known-good capture:

```
0x08:  01 00 00 00 00 00 00 00    u64  version = 1
0x10:  01 00 00 00                u32  flags or sub-version = 1
0x14:  cc 1c 00 00 00 00 00 00    u64  ? (tentative: header size = 0x1ccc = 7372)
0x1c:  00 39 00 00 00 00 00 00    u64  ? (tentative: uncompressed payload size = 0x3900 = 14592)
0x24:  04 00 00 00 00 00 00 00    u64  ? (tentative: compression = LZ4)
0x2c:  04 00 00 00 00 00 00 00    u64  ?
0x34:  00 11 00 01 00 ff 03 40    starts looking like LZ4 block data
```

Field interpretation is **tentative** — confirmed by structural fit but
not by direct decompilation. Pending more RE work.

## Payload encoding

The payload is **protobuf**-encoded using messages in the `NV.*`
namespace across 22 .proto files. Key namespaces:

| Namespace | Messages | Purpose |
| --- | --- | --- |
| `.NV` | 212 | Core types, pipelines, descriptors, root params |
| `.NV.WarpViz` | 92 | Data transport layer (chunks, compression) |
| `.NV.ShaderProfiler.Messages` | 61 | Source-level shader profiler reports, SASS patching, PC sampling |
| `.NV.Pylon.Replay` | 36 | Replay engine state |
| `.NV.EventParameters.Messages` | 16 | Per-API event params |
| `.NV.Pylon` | 15 | Pylon engine common |
| `.NV.ObjectBrowser.Messages` | 5 | UI object browser data |

Use `ngfx_proto_schemas()` to enumerate everything and
`ngfx_proto_search(pattern)` to grep.

### .proto files referenced

```
ApiInspector/ApiInspectorMessages.proto
BinaryFileInterface.proto
DescriptorView/DescriptorViewMessages.proto
GeometryInspector/GeometryInspectorMessages.proto
Gfx/Messages/Common.proto
Gfx/Messages/EventParameters.proto
Gfx/Messages/Objects.proto
Gfx/Messages/Shader.proto
MemoryView/MemoryViewMessages.proto
ObjectBrowserMessages.proto
PixelHistoryView/PixelHistoryViewMessages.proto
PylonUi.proto
RootParametersMessages/RootParametersMessages.proto
ShaderBrowser/ShaderBrowserMessages.proto
ShaderCompileTools/ShaderCompileToolsMessages.proto
ShaderEditorView/ShaderEditorViewMessages.proto
ShaderInfo/ShaderInfo.proto
ShaderProfiler/Messages/Report.proto
ShaderView/ShaderViewMessages.proto
WarpViz.proto
... (plus 2 more)
```

### Highlights of the schema

Messages relevant to common questions:

* **Root parameter bindings** — `PbRootParameter`, `PbRootDescriptor`,
  `PbRootConstants`, `PbRootDescriptorFlags`, `PbRootParameterType`,
  `PbRootParameterVisibility`, `PbRootParametersInfo`
* **Pipelines** — `PbPipelineState`, `PbGraphicsPipelineH`,
  `PbComputePipelineH`, `PbBoundShaderId`, `PbBoundShaderMetadata`,
  `PbShaderStateMetadata`
* **Shaders** — `PbShaderState`, `PbShaderStageDescription`,
  `PbShaderInstanceH`, `PbBlobEntry` (shader bytecode payload),
  `PbBlobTable`, `PbCodeBlockOrigin`
* **Shader-source profiler** — `PbPCSamples`, `PbPCSamplingSession`,
  `PbPCMetricMetaData`, `PbPerPcDerivedMetrics`, `PbPerfMarker`,
  `PbSASSPatchingSession`, `PbSASSPatchingShaderBlock`,
  `PbSASSCounters`, `PbCounterUpdateBlock`
* **Resources / memory** — `PbBuffer`, `PbBufferView`, `PbResourceInfo`,
  `PbAccelerationStructure`, `PbApiDataHandle`
* **Descriptors** — `PbDescriptor`, `PbDescriptorResource`,
  `PbBindingInfo`, `PbBindingType`
* **Compression** — `PbCompression` enum (`NONE`, `LZ4`)
* **Transport** — `PbChunkId`, `PbEventHeader`, `PbGetChunkRequest`,
  `PbGetChunkReply`, `PbTraceSource`

## Compression

Capture payloads (chunks) can be either uncompressed or LZ4-block
compressed. The `PbCompression` enum lists `COMPRESSION_NONE` and
`COMPRESSION_LZ4`. ZSTD is supported by `ngfx-capture.exe` for new
captures (`--compression-library-zstd`).

LZ4 decompression uses the raw block format (no frame header). Pass the
uncompressed size hint to `lz4.block.decompress`.

## Hidden CLI flags discovered

`ngfx-replay.exe` accepts ~125 distinct `--flag` strings; about 65 of
them are NOT in the public `--help` output. Notable hidden ones:

* `--replay-screenshot <dir>` + `--replay-screenshot-count`,
  `--replay-screenshot-indices`, `--replay-screenshot-start`,
  `--replay-screenshot-frames` — dump per-frame rendered output during
  replay, no UI required.
* `--collect-gpu-frametimes` — per-frame GPU timing.
* `--validation`, `--enable-ray-tracing-validation`,
  `--diagnostic-checkpoints`, `--enable-rtcore-dump` — diagnostic modes.
* `--optimize-with-object-metadata-file <file>` — pass an external
  object-metadata file to optimise replay.
* `--no-aftermath-replay`, `--no-app-profile`,
  `--no-nv-app-profile-override`, `--no-nv-app-profile-process-name`,
  `--no-nvapi-replay`, `--no-nvapi-latency-marker-replay`,
  `--no-nvtech-replay`, `--no-ngx-replay`, `--no-nrc-replay`,
  `--no-dstorage-replay` — selectively disable NVIDIA-specific replay
  paths for repro / isolation.
* `--present-fse`, `--present-fse-secondary-window` — fullscreen
  exclusive presentation modes during replay.
* `--multibuffer`, `--multibuffer-record-and-sync`,
  `--multibuffer-wfi-on-frame-end` — replay-time multibuffering modes.
* `--bundled-dlss-plugins <dir>`, `--no-bundled-dlss-plugins`.
* `--force-dx12-agility-original`, `--force-dx12-agility-preview`,
  `--force-disable-dx12-agility`, `--override-dx12-agility <ver>`,
  `--override-dx12-memory-pool-for-uma`,
  `--enable-dx12-application-specific-driver-state`,
  `--enable-dx12-recreate-at-gpuva`,
  `--force-dx12-recycle_commandlists-after-ecl`,
  `--force-dx12-increasing-fence-values`,
  `--force-dx12-force-patched-execute-indirect`.
* `--enable-capture-replay-shader-group-handles`, `--disable-micro-maps`,
  `--force-trace-rays-dimensions-to-zero`,
  `--build-invalid-gpu-memory-objects`,
  `--force-reallocate-gpu-memory-objects`,
  `--force-reset-gpu-memory-objects`,
  `--force-reallocate-placed-resources`.
* `--record-unsubmitted-commands`, `--minimal-sync-after-reset`,
  `--skip-explicit-cpu-wait`, `--skip-wait-on-cpu-poll`.
* `--temp-resource-dir <dir>`, `--timeout-interval <sec>`,
  `--max-gpu-bound`, `--max-vidmem-bytes-reset-allocation`,
  `--max-worker-threads`, `--no-user-input`,
  `--no-multithreaded-record`, `--no-multithreaded-init`,
  `--no-multithreaded-pipeline-create`,
  `--no-multithreaded-rt-pipeline-create`,
  `--no-multithreaded-cpu-data-reset`,
  `--no-block-on-incompatibility`, `--no-sysmem-fallback`,
  `--no-pipeline-caches`, `--no-internal-pipeline-caches`,
  `--no-memory-mapped-file`, `--no-stack-in-crash-reporting`,
  `--no-crash-reporting`, `--show-hud`, `--no-initialized-in-frame-detection`,
  `--no-internal-perf-markers`, `--inject-full-frame-perf-marker`.

Surfaced via `ngfx_replay_screenshot`, `ngfx_replay_gpu_frametimes`, and
the generic `ngfx_replay_run_advanced`.

## What's NOT (yet) known

* Exact byte layout of the post-magic header (the 56 bytes immediately
  following `nlypelif`).
* Per-chunk offsets / table-of-contents — the file looks like multiple
  framed sections but the framing format isn't fully decoded.
* The mapping from `PbBlobEntry` payloads to specific resource UIDs
  (would let us extract raw resource bytes / shader bytecode).
* The `PbEncryptedData` payload structure (some blobs are encrypted with
  a `PbMethod` enum we haven't decoded).

## How to keep going

If you want to push this further:

1. **Reconstruct .proto files**. The descriptor fragments are embedded
   in `ngfx-replay.exe` and `PylonReplay_PluginInterface.dll`. They can
   be extracted by scanning for `FileDescriptorProto` markers and reassembled
   with `protobuf-inspector` or by writing a custom extractor.
2. **Decompile the file-open path** in `PylonReplay_PluginInterface.dll`
   to learn the exact section TOC layout. Hex-Rays should make short
   work of the header parser.
3. **Build a shadow `ngfx-replay` extension** that uses the NGFX SDK to
   load a capture in-process and dump the resource data via the same
   internal APIs the UI uses.

The MCP exposes the building blocks for (1) and (2): `ngfx_proto_schemas`,
`ngfx_capture_format_info`, `ngfx_capture_lz4_decompress`, and
`ngfx_decode_protobuf_wire`.
