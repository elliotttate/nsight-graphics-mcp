# ngfx-rpc.exe transport protocol — reverse-engineered notes

Target binary:
`C:\Program Files\NVIDIA Corporation\Nsight Graphics 2026.1.0\host\windows-desktop-nomad-x64\ngfx-rpc.exe`
(SHA: build 37556978, public-release)

This document captures everything we know about the `ngfx-rpc.exe` custom RPC
protocol from static analysis of the binary. It is **not** standard gRPC: the
embedded `FileDescriptorProto` blobs carry zero `ServiceDescriptorProto`
entries, and the binary contains no `/<service>/<method>` literal strings.

## Process model

`ngfx-rpc.exe` is the *server*; `ngfx-ui.exe` is its *client*. The server
self-describes as "NVIDIA Nsight Graphics Replayer UI Server".

CLI surface (verbatim from `ngfx-rpc.exe --help`):

```
--transport ENUM:value in {TCP->1,domain-socket->2,named-pipe->4} OR {1,2,4} REQUIRED
--pipename TEXT            Name of the named-pipe or the domain-socket
--base-port UINT           TCP base port
--port-range-begin UINT    TCP port range begin
--port-range-end UINT      TCP port range end
--no-crash-reporting
--no-stack-in-crash-reporting
--attach                   Trigger a debug attach point before starting server
```

When started with `--transport TCP` the server binds to a free port
(controlled by the `NV_TCP_SERVER_PORT_BIND_RETRIES` env var; observed
default seems to ignore `--base-port` in practice and pick a port from the
dynamic range).

**Session lifetime**: the TCP server appears to handle exactly one client
session. When the TCP connection closes the server exits. For named-pipe
transport the same string `AsioFeatureServer received session closed.
Setup named pipe again.` indicates the pipe is re-armed for another client
— TCP has no equivalent re-arm path. The implication for clients: keep
the TCP connection open for the full duration of work; reconnecting means
relaunching `ngfx-rpc.exe`.

## Wire format (transport layer) — confirmed

Every wire unit is an **8-byte header** followed by a body. All offsets
and byte values come from decompiled functions in the binary.

```
byte 0   = 0x54         (magic 'T')
byte 1   = 0x08         (magic / version?)
byte 2   = channelId    (u8 — 0 for the default channel)
byte 3   = 0x00         (flag/padding — never observed non-zero)
byte 4-7 = body_size    (u32, BIG-ENDIAN / network byte order)
byte 8+  = body         (body_size bytes)
```

Evidence:

* **Send path** — `payload_write__sub_1409A4470.c`:

  ```c
  v8[12] = 84;          // 0x54
  v8[13] = 8;
  ...
  v9[14] = channelId;
  sub_1409AE2D0(v9 + 12);   // htonl on (v9 + 12 + 4) = (v9 + 16) = wire bytes 4..7
  ```

  `sub_1409AE2D0` is exactly `htonl(*(u32*)(a1+4))`.

* **Recv path** — `read_header__sub_1409A3D40.c`:

  ```c
  if (... a3 != 8) { /* error */ }     // header is exactly 8 bytes
  sub_1409AE2B0(a1 + 44);              // ntohl on (a1+44+4) = (a1+48) = body size
  log("Read header channelId: %u Size: %u", *(u8*)(a1 + 46));
  v7 = *(u32*)(a1 + 48);               // read body size
  v8 = sub_140040E10(v7);              // alloc body buffer
  ```

  `sub_1409AE2B0` is exactly `ntohl(*(u32*)(a1+4))`. So wire byte 2 is
  channelId and wire bytes 4..7 are the body size as big-endian u32.

The transport-layer log strings exposed by the binary that we relied on:

* `"Read header channelId: %u Size: %u"`
* `"Write header channelId: %u Size: %u"`
* `"Payload Read of %d bytes"`
* `"Payload Write of %d bytes"`
* `"Partial payload. Remaining = %u bytes"`
* `"bytesTransferred > m_payloadReadBytesRemaining"`

## Dispatch model — confirmed

The server keeps a 2-D handler table indexed by `(category, method)`.
Each method-slot is 64 bytes wide (a `std::function` instance is stored
at `slot + 56`). See `register_category__sub_140985A90.c` for the table
maintenance code; key log strings:

* `"NumCategories: %d"`
* `"categoryId: %d numMethods: %d"`
* `"MethodMap:: TryGetMethodHandler Category: %u Method: %u"`
* `"InvalidCategoryId"` / `"InvalidMethodId"` (in the error-code enum)
* `"Feature %s(%u) not found. Category: %u MethodId: %u"`

Method ids come straight from the embedded `*.proto` `*Method` enums:

| Category enum            | Source `.proto`        | Notes |
|--------------------------|------------------------|-------|
| `HandshakeMethod`        | `Handshake.proto`      | 4 methods |
| `ConnectionMethod`       | `Connection.proto`     | 7 methods (Attach/Detach/Terminate) |
| `DiscoveryMethod`        | `Discovery.proto`      | 3 methods |
| `LocalDiscoveryMethod`   | `Discovery.proto`      | 2 methods |
| `DiagnosticsMethod`      | `Diagnostics.proto`    | 6 methods (Ping/DataBuffers) |
| `DeviceInfoMethod`       | `DeviceInfo.proto`     | 3 methods |
| `SystemInfoMethod`       | `SystemInfo.proto`     | 3 methods |
| `BinaryReplayMethod`     | `PylonUi.proto`        | 110 methods (per-event args!) |
| `WarpVizTargetMethod`    | `WarpViz.proto`        | 8 methods |
| `WarpVizHostMethod`      | `WarpViz.proto`        | 8 methods |
| `WarpVizChunkMethod`     | `WarpViz.proto`        | 2 methods |

### Global category numbering — partially pinned

The 2-D dispatch table is keyed by a **global category id**, not by the
proto package. We pinned the value for `Diagnostics`:

In `ping_recv__sub_1407D28B0.c` the `DataBufferMessage` is constructed
with two adjacent dwords baked into the binary:

```c
v10[14] = dword_14128FE40;   // = 0x00000001  -> category = 1
v10[15] = dword_14128FE44;   // = 0x00000006  -> method   = 6
```

`DiagnosticsMethod::DataBuffer == 6` confirms category-id 1 is
`Diagnostics`. The other category ids are unknown without further
pinning; the binary registers the SystemService handlers
(`AttachMessage`, `DetachMessage`, `PingRequestMessage`,
`DataBuffersRequestMessage`, `GetProcessInfoRequestMessage`,
`GetSystemInfoRequestMessage`, `GetDeviceInfoRequestMessage`,
`PbTargetHandshakeBeginMessage`, `TerminateMessage`) in a known order
that *suggests* the global numbering follows the order they're registered.

## Per-message in-memory `MessageHeader` layout — confirmed

The `NV::TPS::MessageHeader` C++ class is 60 bytes wide (zero-initialised
by `hdr_init__sub_140985480.c`):

| Offset | Type      | Field        | Source |
|--------|-----------|--------------|--------|
| +0     | u16       | flags?       | zero-init in `sub_140985480` |
| +2     | u8        | is_valid     | `hdr_is_valid__sub_140985570.c` returns this |
| +8     | u64       | (ptr/handle) | zero-init |
| +16    | u64       | (ptr/handle) | zero-init |
| +24    | u64       | (ptr/handle) | zero-init |
| +32    | **u32**   | **category** | `hdr_get_category__sub_1409854B0.c` returns this |
| +36    | **u32**   | **method**   | `hdr_get_method__sub_140985560.c` returns this |
| +40    | u32       | flags2?      | |
| +48    | u64       | **ticket_id**| likely; the `"Transaction with ticketId = %llu"` log uses a u64 |
| +56    | u32       | sertype      | `hdr_get_sertype__sub_140985540.c` returns `*(u32*)(a1+56)` |

## Per-message wire format — UNRESOLVED

This is the **single remaining blocker**. We know the body of one
transport frame contains:

1. A serialized form of the C++ `MessageHeader` (carrying category /
   method / ticket_id / sertype).
2. The serialized protobuf body for the chosen `(category, method)` pair.

We do **not** know the exact on-wire encoding of (1). The three plausible
candidates, in decreasing order of likelihood:

* **A.** Raw memcpy of the 60-byte C++ struct (little-endian native order
  on x86_64).
* **B.** A fixed-size sequence of `(u32 category, u32 method, u64 ticket,
  u32 sertype)` totalling 20 bytes, with no padding.
* **C.** A protobuf-encoded `MessageHeader` (but we cannot find a
  corresponding `.proto` for it in the embedded schema, so this is
  unlikely).

### Why we couldn't disambiguate

1. **The server crashes on any malformed input.** Sending a transport
   frame whose body the server cannot deserialise causes the server
   process to exit (likely an unhandled `std::bad_alloc` or a guard
   `__debugbreak`). The single-shot TCP session model means we can't
   probe iteratively without relaunching for every attempt.

2. **`ngfx-ui.exe` couldn't be coerced into talking to a TCP proxy.**
   Without packet capture we have no observed real exchange to compare
   against. `ngfx-ui.exe --help` produces no output (it appears to need
   a UI context).

3. **The dispatcher's call to "get header from message"
   (`(*(_QWORD *)*a3 + 8LL)(*a3)`) is a virtual dispatch through the
   `ProtoBufMessage` vtable.** That virtual function is the one that
   actually parses the on-wire bytes into the C++ MessageHeader. The
   vtable's first slot is the parse function, but it goes through
   another layer of indirection that we did not fully chase.

### Suggested next angles

* **`pktmon` capture** of an interaction between a real `ngfx-ui` and a
  real `ngfx-rpc` (let the UI spawn its own rpc child, then sniff the
  loopback traffic via `pktmon start --comp --capture` with a TCP
  filter).
* **`ProtoBufMessage::Serialize` chase** — the vtable at
  `&NV::TPS::ProtoBufMessage::``vftable`` (RTTI string
  `.?AVProtoBufMessage@TPS@NV@@`) has a `Serialize(Buffer&)` slot. Its
  implementation will reveal whether the C++ header is written as raw
  bytes or via the protobuf encoder.
* **Try the **named-pipe** transport.** The named-pipe loop calls
  `AsioFeatureServer received session closed. Setup named pipe again.`
  so the server doesn't exit between sessions — much easier to iterate
  probes against.

## Implementation status

The Python client in
`src/nsight_graphics_mcp/rpc_client.py` implements:

* `class RpcTransport` — fully functional 8-byte framing, send/recv,
  validates magic bytes. **Tested live against `ngfx-rpc.exe`** — sends
  and receives bytes cleanly.
* `class RpcMessage` / `class RpcMessageHeader` — **conjectural** raw-struct
  layout (option A above). When this turns out to be wrong, edit
  `RpcMessageHeader.WIRE_LAYOUT` and add a new encoder. The class is
  designed for easy swapping.
* `class RpcClient` — high-level method wrappers
  (`handshake`, `event_details`, `api_inspector_state`,
  `root_parameters`, `descriptor_state`). These will start working as
  soon as `RpcMessageHeader.pack()` produces the correct wire bytes.

## Sample bytes — the first send attempt

For reference, the bytes that our client *currently* sends as the first
handshake attempt are:

```
54 08 00 00 00 00 00 4a                      ; transport header (size = 74)
00 00 01                                     ; MessageHeader[0..2] = flags=0, is_valid=1
00 00 00 00 00 00 00 00 00 00 00 00 00 00    ; MessageHeader[3..16] = zeros
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ; MessageHeader[17..31] = zeros
02 00 00 00                                  ; MessageHeader[32..35] = category=2 (handshake)
01 00 00 00                                  ; MessageHeader[36..39] = method=1   (Begin)
00 00 00 00                                  ; MessageHeader[40..43] = zeros
01 00 00 00 00 00 00 00                      ; MessageHeader[48..55] = ticket_id=1
00 00 00 00                                  ; MessageHeader[56..59] = sertype=0
08 01                                        ; protobuf body: PbHandshakeBeginMessage(id=1)
```

The server currently crashes on this input (rather than replying), so we
have evidence that the message-header wire layout is **not** the raw
60-byte struct. The next thing to try is option B (the compact 20-byte
layout) — flip `RpcMessageHeader.WIRE_LAYOUT = "compact"` once that
encoder is added.
