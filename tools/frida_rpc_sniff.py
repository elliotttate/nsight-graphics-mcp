"""Frida-based TCP sniffer for the ngfx-ui ↔ ngfx-rpc exchange.

Attaches to ngfx-ui.exe (and/or ngfx-rpc.exe) and hooks Winsock
``send`` / ``WSASend`` / ``recv`` / ``WSARecv`` in ``ws2_32.dll``.
Every captured buffer is parsed as the verified-correct wire format
(8-byte transport frame header + 24-byte MessageHeader + protobuf body)
and decoded against the schema pool from :mod:`proto_descriptors`.

Usage::

    # spawn first or attach to a running process:
    python tools/frida_rpc_sniff.py --attach ngfx-ui.exe
    python tools/frida_rpc_sniff.py --attach ngfx-rpc.exe
    python tools/frida_rpc_sniff.py --attach-all

The script keeps running until interrupted; every captured frame prints
a one-line summary plus a hex dump.
"""

from __future__ import annotations

import argparse
import struct
import sys
import time
from pathlib import Path

import frida

# Make the parent package importable when running from the repo
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from nsight_graphics_mcp import proto_descriptors as pd  # noqa: E402


HOOK_JS = r"""
/*
 * Hook ws2_32.dll's send/recv/WSASend/WSARecv. Forward every captured
 * buffer to the Python side as a `send({...}, byteArray)` message.
 */

/* Frida 17 deprecated Module.getExportByName at the global Module level;
   use the per-module API. Falls back to scanning all loaded modules in
   case the module isn't loaded yet at hook time. */
function resolveExport(modName, exportName) {
    try {
        var mod = Process.findModuleByName(modName);
        if (mod) {
            var fn = mod.findExportByName(exportName);
            if (fn) return fn;
        }
    } catch (e) { /* ignore */ }
    // Last-ditch: scan everything
    for (var m of Process.enumerateModules()) {
        if (m.name.toLowerCase() === modName.toLowerCase()) {
            try {
                var f = m.findExportByName(exportName);
                if (f) return f;
            } catch (e) { /* keep scanning */ }
        }
    }
    throw new Error('export not found: ' + modName + '!' + exportName);
}

function bufBytes(ptr, len) {
    if (len <= 0) return null;
    try { return Memory.readByteArray(ptr, len); }
    catch (e) { return null; }
}

function hookSend() {
    var sendPtr = resolveExport('ws2_32.dll', 'send');
    Interceptor.attach(sendPtr, {
        onEnter: function (args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.len = args[2].toInt32();
        },
        onLeave: function (retval) {
            var sent = retval.toInt32();
            if (sent > 0) {
                var data = bufBytes(this.buf, sent);
                if (data) send({type: 'send', fd: this.fd, len: sent,
                                ts: Date.now(),
                                thread: Process.getCurrentThreadId()}, data);
            }
        }
    });
}

function hookRecv() {
    var recvPtr = resolveExport('ws2_32.dll', 'recv');
    Interceptor.attach(recvPtr, {
        onEnter: function (args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
        },
        onLeave: function (retval) {
            var got = retval.toInt32();
            if (got > 0) {
                var data = bufBytes(this.buf, got);
                if (data) send({type: 'recv', fd: this.fd, len: got,
                                ts: Date.now(),
                                thread: Process.getCurrentThreadId()}, data);
            }
        }
    });
}

function hookWSASend() {
    // WSASend(SOCKET, LPWSABUF lpBuffers, DWORD dwBufferCount, ...)
    // WSABUF { ULONG len; char* buf; }
    var p = resolveExport('ws2_32.dll', 'WSASend');
    Interceptor.attach(p, {
        onEnter: function (args) {
            this.fd = args[0].toInt32();
            this.bufs = args[1];
            this.count = args[2].toInt32();
        },
        onLeave: function (retval) {
            for (var i = 0; i < this.count; i++) {
                var bufStruct = this.bufs.add(i * Process.pointerSize * 2);
                var blen = bufStruct.readU32();
                var bptr = bufStruct.add(Process.pointerSize).readPointer();
                if (blen > 0) {
                    var data = bufBytes(bptr, blen);
                    if (data) send({type: 'wsasend', fd: this.fd, len: blen,
                                    ts: Date.now(),
                                    thread: Process.getCurrentThreadId()}, data);
                }
            }
        }
    });
}

function hookWSARecv() {
    var p = resolveExport('ws2_32.dll', 'WSARecv');
    Interceptor.attach(p, {
        onEnter: function (args) {
            this.fd = args[0].toInt32();
            this.bufs = args[1];
            this.count = args[2].toInt32();
        },
        onLeave: function (retval) {
            for (var i = 0; i < this.count; i++) {
                var bufStruct = this.bufs.add(i * Process.pointerSize * 2);
                var blen = bufStruct.readU32();
                var bptr = bufStruct.add(Process.pointerSize).readPointer();
                if (blen > 0) {
                    var data = bufBytes(bptr, blen);
                    if (data) send({type: 'wsarecv', fd: this.fd, len: blen,
                                    ts: Date.now(),
                                    thread: Process.getCurrentThreadId()}, data);
                }
            }
        }
    });
}

/* Named-pipe hooks. ngfx-ui actually uses named pipes by default
   (`--transport named-pipe`), so the Winsock hooks above see nothing
   for the real handshake. WriteFile/ReadFile see everything but are
   noisy — we filter by inspecting the first 2 bytes for the 'T 08'
   RPC frame magic and only log buffers that match. */

/* Track which file handles look like RPC named pipes so we can filter
   noisy WriteFile/ReadFile activity (font cache, registry, etc.). */
var rpcHandles = {};

function hookCreateFileW() {
    var p = resolveExport('kernel32.dll', 'CreateFileW');
    Interceptor.attach(p, {
        onEnter: function (args) {
            this.name = args[0].readUtf16String();
        },
        onLeave: function (retval) {
            var fn = this.name || '';
            if (fn && fn.toLowerCase().indexOf('\\pipe\\') >= 0) {
                rpcHandles[retval.toString()] = fn;
                send({type: 'pipe_open', handle: retval.toString(), path: fn,
                      ts: Date.now(),
                      thread: Process.getCurrentThreadId()});
            }
        }
    });
}

function hookCreateNamedPipe() {
    var p = resolveExport('kernel32.dll', 'CreateNamedPipeW');
    Interceptor.attach(p, {
        onEnter: function (args) {
            this.name = args[0].readUtf16String();
        },
        onLeave: function (retval) {
            var fn = this.name || '';
            rpcHandles[retval.toString()] = fn;
            send({type: 'pipe_create', handle: retval.toString(), path: fn,
                  ts: Date.now(),
                  thread: Process.getCurrentThreadId()});
        }
    });
}

function looksLikeRpcFrame(buf, len) {
    if (len < 8) return false;
    try {
        var b0 = buf.readU8();
        var b1 = buf.add(1).readU8();
        return b0 === 0x54 && b1 === 0x08;
    } catch (e) { return false; }
}

function hookWriteFile() {
    var p = resolveExport('kernel32.dll', 'WriteFile');
    Interceptor.attach(p, {
        onEnter: function (args) {
            this.handle = args[0].toString();
            this.buf = args[1];
            this.len = args[2].toInt32();
            this.isRpc = rpcHandles[this.handle] !== undefined
                          || looksLikeRpcFrame(this.buf, this.len);
        },
        onLeave: function (retval) {
            if (!this.isRpc || this.len <= 0) return;
            var data = bufBytes(this.buf, this.len);
            if (data) send({type: 'pipe_write', handle: this.handle,
                            path: rpcHandles[this.handle] || null,
                            len: this.len, ts: Date.now(),
                            thread: Process.getCurrentThreadId()}, data);
        }
    });
}

function hookReadFile() {
    var p = resolveExport('kernel32.dll', 'ReadFile');
    Interceptor.attach(p, {
        onEnter: function (args) {
            this.handle = args[0].toString();
            this.buf = args[1];
            this.lenReq = args[2].toInt32();
            this.lenOut = args[3];
            this.isRpc = rpcHandles[this.handle] !== undefined;
        },
        onLeave: function (retval) {
            if (!this.isRpc) {
                // Late check: maybe it's a pipe handle we missed but the
                // buffer is short and starts with T 08
                if (looksLikeRpcFrame(this.buf, Math.min(this.lenReq, 8))) {
                    this.isRpc = true;
                } else {
                    return;
                }
            }
            var actual = this.lenReq;
            try {
                if (!this.lenOut.isNull()) actual = this.lenOut.readU32();
            } catch (e) { /* fall through */ }
            if (actual <= 0) return;
            var data = bufBytes(this.buf, actual);
            if (data) send({type: 'pipe_read', handle: this.handle,
                            path: rpcHandles[this.handle] || null,
                            len: actual, ts: Date.now(),
                            thread: Process.getCurrentThreadId()}, data);
        }
    });
}

/* NTDLL-level hooks — catch I/O that bypasses kernel32 (async / OVERLAPPED
   / IOCP all go through these). NtWriteFile/NtReadFile signature:
     NTSTATUS Nt{Write,Read}File(
       HANDLE FileHandle,        // args[0]
       HANDLE Event,             // args[1]
       PIO_APC_ROUTINE Apc,      // args[2]
       PVOID ApcContext,         // args[3]
       PIO_STATUS_BLOCK Iosb,    // args[4]
       PVOID Buffer,             // args[5]
       ULONG Length,             // args[6]
       PLARGE_INTEGER ByteOff,   // args[7]
       PULONG Key);              // args[8]

   IO_STATUS_BLOCK { NTSTATUS Status; ULONG_PTR Information; } — the
   Information field carries the actual byte count after the call. */

function hookNtWriteFile() {
    var p = resolveExport('ntdll.dll', 'NtWriteFile');
    Interceptor.attach(p, {
        onEnter: function (args) {
            this.handle = args[0].toString();
            this.iosb = args[4];
            this.buf = args[5];
            this.length = args[6].toInt32();
            // Check magic NOW (buffer is filled by caller before the call)
            this.isRpc = looksLikeRpcFrame(this.buf, this.length)
                          || rpcHandles[this.handle] !== undefined;
        },
        onLeave: function (retval) {
            if (!this.isRpc || this.length <= 0) return;
            // For sync calls, we can read iosb.Information for actual bytes
            // written. For async (STATUS_PENDING=0x103), the count isn't
            // ready until the completion. Best-effort read regardless.
            var actual = this.length;
            try {
                if (!this.iosb.isNull()) {
                    actual = this.iosb.add(Process.pointerSize).readULong();
                    if (actual <= 0 || actual > this.length) actual = this.length;
                }
            } catch (e) { /* fall through */ }
            var data = bufBytes(this.buf, actual);
            if (data) send({type: 'pipe_write', handle: this.handle,
                            path: rpcHandles[this.handle] || '(nt)',
                            len: actual, ts: Date.now(),
                            thread: Process.getCurrentThreadId()}, data);
        }
    });
}

function hookNtReadFile() {
    var p = resolveExport('ntdll.dll', 'NtReadFile');
    Interceptor.attach(p, {
        onEnter: function (args) {
            this.handle = args[0].toString();
            this.iosb = args[4];
            this.buf = args[5];
            this.lenReq = args[6].toInt32();
            // On entry, buffer is empty — we'll inspect on leave
        },
        onLeave: function (retval) {
            // STATUS_SUCCESS = 0; STATUS_PENDING = 0x103. For PENDING,
            // the buffer may not be filled yet — but for sync reads we
            // can read it now.
            var actual = this.lenReq;
            try {
                if (!this.iosb.isNull()) {
                    actual = this.iosb.add(Process.pointerSize).readULong();
                    if (actual <= 0 || actual > this.lenReq) actual = this.lenReq;
                }
            } catch (e) { /* fall through */ }
            if (actual <= 0) return;
            var isRpc = looksLikeRpcFrame(this.buf, Math.min(actual, 8))
                         || rpcHandles[this.handle] !== undefined;
            if (!isRpc) return;
            var data = bufBytes(this.buf, actual);
            if (data) send({type: 'pipe_read', handle: this.handle,
                            path: rpcHandles[this.handle] || '(nt)',
                            len: actual, ts: Date.now(),
                            thread: Process.getCurrentThreadId()}, data);
        }
    });
}

try { hookSend(); } catch (e) { send({type: 'err', where: 'send', msg: e.toString()}); }
try { hookRecv(); } catch (e) { send({type: 'err', where: 'recv', msg: e.toString()}); }
try { hookWSASend(); } catch (e) { send({type: 'err', where: 'wsasend', msg: e.toString()}); }
try { hookWSARecv(); } catch (e) { send({type: 'err', where: 'wsarecv', msg: e.toString()}); }
try { hookCreateFileW(); } catch (e) { send({type: 'err', where: 'createfile', msg: e.toString()}); }
try { hookCreateNamedPipe(); } catch (e) { send({type: 'err', where: 'createpipe', msg: e.toString()}); }
try { hookWriteFile(); } catch (e) { send({type: 'err', where: 'writefile', msg: e.toString()}); }
try { hookReadFile(); } catch (e) { send({type: 'err', where: 'readfile', msg: e.toString()}); }
try { hookNtWriteFile(); } catch (e) { send({type: 'err', where: 'ntwritefile', msg: e.toString()}); }
try { hookNtReadFile(); } catch (e) { send({type: 'err', where: 'ntreadfile', msg: e.toString()}); }

send({type: 'hooked', pid: Process.id, name: Process.mainModule.name});
"""


def parse_frame(b: bytes) -> dict | None:
    """Best-effort parse of one or more concatenated transport frames in b."""
    if len(b) < 8:
        return None
    if b[0] != 0x54 or b[1] != 0x08:
        return None  # not an RPC frame
    channel = b[2]
    flag = b[3]
    size = struct.unpack(">I", b[4:8])[0]
    out = {"channel": channel, "flag": flag, "size": size}
    body = b[8:8 + size]
    if len(body) >= 24:
        rh = body[:24]
        out["ticket"] = struct.unpack(">Q", rh[0:8])[0]
        out["request_id"] = struct.unpack(">Q", rh[8:16])[0]
        out["seq"] = struct.unpack(">I", rh[16:20])[0]
        out["category"] = rh[20]
        out["method"] = rh[21]
        out["slot"] = rh[22]
        out["flags"] = rh[23]
        out["proto_body"] = body[24:]
    return out


def hex_dump(b: bytes, max_bytes: int = 256) -> str:
    out = []
    for i in range(0, min(len(b), max_bytes), 16):
        chunk = b[i:i + 16]
        hex_part = " ".join(f"{x:02x}" for x in chunk)
        ascii_part = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        out.append(f"  {i:04x}  {hex_part:<48}  {ascii_part}")
    if len(b) > max_bytes:
        out.append(f"  ... ({len(b) - max_bytes} more bytes)")
    return "\n".join(out)


CATEGORY_NAMES = {
    0: "Invalid", 1: "Diagnostics", 2: "SystemInfo", 3: "Discovery",
    4: "Handshake", 5: "DeviceInfo", 6: "Connection", 7: "LocalDiscovery",
}


def on_message(message, data, log_file=None):
    if message["type"] == "error":
        print(f"[!] frida error: {message.get('description')}")
        return
    if message["type"] != "send":
        print(f"[?] unknown msg: {message}")
        return
    p = message.get("payload")
    if not isinstance(p, dict):
        print(f"[?] non-dict payload: {p}")
        return
    pt = p.get("type", "?")

    # Control messages from the JS hook itself
    if pt == "hooked":
        print(f"[+] hooked pid={p.get('pid')} ({p.get('name')})")
        return
    if pt == "err":
        print(f"[!] hook setup error in {p.get('where')}: {p.get('msg')}")
        return
    if pt in ("pipe_open", "pipe_create"):
        ev = "opened" if pt == "pipe_open" else "created"
        line = (f"[+] pipe {ev}: {p.get('path')!r} handle={p.get('handle')} "
                f"thread={p.get('thread')}")
        print(line)
        if log_file:
            log_file.write(line + "\n"); log_file.flush()
        return

    # Data messages — send/recv (sockets) or pipe_write/pipe_read (named pipe)
    direction = ">>>" if pt in ("send", "wsasend", "pipe_write") else "<<<"
    length = p.get("len", 0)
    ts = p.get("ts", 0)
    line = (f"\n[{ts}] {direction} {pt:8s} fd={p.get('fd', '?')} "
            f"len={length} (thread {p.get('thread', '?')})")
    print(line)
    if log_file:
        log_file.write(line + "\n")
    if data is None:
        return
    frame = parse_frame(data)
    if frame is not None:
        cat_name = CATEGORY_NAMES.get(frame["category"], f"?{frame['category']}")
        summary = (f"  transport: ch={frame['channel']} flag={frame['flag']} "
                   f"size={frame['size']}")
        if "ticket" in frame:
            summary += (f"\n  header: ticket={frame['ticket']} "
                        f"request_id={frame['request_id']} seq={frame['seq']} "
                        f"cat={frame['category']}({cat_name}) "
                        f"meth={frame['method']} slot={frame['slot']} "
                        f"flags={frame['flags']:#04x}")
        if frame.get("proto_body"):
            summary += f"\n  proto body: {len(frame['proto_body'])} bytes"
        print(summary)
        if log_file:
            log_file.write(summary + "\n")
    dump = hex_dump(data)
    print(dump)
    if log_file:
        log_file.write(dump + "\n")
        log_file.flush()


def attach(target, log_path: Path | None) -> frida.core.Session:
    print(f"[*] attaching to {target!r}")
    session = frida.attach(target)
    script = session.create_script(HOOK_JS)
    log_file = open(log_path, "a", encoding="utf-8") if log_path else None
    script.on("message", lambda m, d: on_message(m, d, log_file))
    script.load()
    return session


def _poll_for_children(device, parent_pid: int, hook_pid_fn,
                       names_of_interest: set[str], stop_evt) -> None:
    """Background thread: poll the process list every 250ms for new
    processes whose parent is ``parent_pid``. Attaches the sniffer
    hooks to each one. This is a Windows workaround for the fact that
    frida.Device.enable_spawn_gating() is "not yet supported on this OS"
    in Frida 17.x.
    """
    import time as _t
    seen = set()
    while not stop_evt.is_set():
        try:
            for p in device.enumerate_processes():
                if p.pid in seen:
                    continue
                # Filter: must look like one of our interesting children
                if names_of_interest and p.name.lower() not in {n.lower() for n in names_of_interest}:
                    continue
                # Skip ourselves / the parent
                if p.pid == parent_pid:
                    continue
                seen.add(p.pid)
                # Verify parent chain via psutil if available; else just
                # trust the name match.
                try:
                    import psutil
                    ppid = psutil.Process(p.pid).ppid()
                    if ppid != parent_pid:
                        continue
                except Exception:
                    pass
                print(f"[+] watchdog: new child {p.name} pid={p.pid}; "
                      f"attaching hooks")
                try:
                    hook_pid_fn(p.pid, p.name)
                except Exception as e:
                    print(f"[!] watchdog hook failed for pid={p.pid}: {e}")
        except Exception as e:
            print(f"[!] watchdog iteration error: {e}")
        stop_evt.wait(0.25)


def spawn(exe_path: str, args: list[str], log_path: Path | None,
          *, follow_children: bool = False
          ) -> tuple[frida.core.Session, int]:
    """Spawn a process suspended, load hooks, then resume.

    More reliable than attach() for processes that crash on runtime
    code injection (Qt apps often do). The hooks are installed before
    a single instruction of the target runs.

    If ``follow_children`` is True, also installs hooks into every
    child process the target spawns — necessary to catch ngfx-rpc
    when ngfx-ui forks it.
    """
    device = frida.get_local_device()
    log_file = open(log_path, "a", encoding="utf-8") if log_path else None

    def _hook_pid(pid: int, name: str) -> frida.core.Session:
        s = device.attach(pid)
        scr = s.create_script(HOOK_JS)
        scr.on("message", lambda m, d: on_message(m, d, log_file))
        scr.load()
        print(f"[*] hooks loaded into {name} pid={pid}")
        return s

    print(f"[*] spawning {exe_path!r} suspended")
    pid = device.spawn([exe_path] + list(args))
    print(f"[*] spawned suspended pid={pid}; attaching")
    session = _hook_pid(pid, Path(exe_path).name)

    if follow_children:
        # Windows Frida 17.x doesn't support spawn-gating — use polling
        # watchdog instead. Catches ngfx-rpc within ~250ms of its launch.
        import threading
        stop_evt = threading.Event()
        watchdog = threading.Thread(
            target=_poll_for_children,
            args=(device, pid, _hook_pid, {"ngfx-rpc.exe"}, stop_evt),
            daemon=True, name="child-watchdog",
        )
        watchdog.start()
        print("[*] child watchdog running (polls every 250ms for ngfx-rpc)")

    print(f"[*] resuming root pid={pid}")
    device.resume(pid)
    return session, pid


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--attach", action="append", default=[],
                    help="process name or PID to attach to (repeatable)")
    ap.add_argument("--attach-all", action="store_true",
                    help="attach to every running ngfx-* process")
    ap.add_argument("--spawn", default=None,
                    help="path to an exe to spawn suspended + hook + resume "
                         "(more reliable than --attach for Qt apps that crash "
                         "on runtime injection)")
    ap.add_argument("--spawn-arg", action="append", default=[],
                    help="argument to pass to --spawn (repeatable)")
    ap.add_argument("--follow-children", action="store_true",
                    help="with --spawn, enable spawn-gating so children get "
                         "hooks too (catches ngfx-rpc when ngfx-ui forks it)")
    ap.add_argument("--log", default=None, help="append output to this file")
    args = ap.parse_args()

    targets = list(args.attach)
    if args.attach_all:
        # Frida 17.x dropped the top-level enumerate_processes; use the
        # local device's method directly.
        device = frida.get_local_device()
        for p in device.enumerate_processes():
            if p.name.lower().startswith("ngfx") or "nsight" in p.name.lower():
                targets.append(p.name)

    log_path = Path(args.log).resolve() if args.log else None
    sessions = []

    if args.spawn:
        try:
            sess, _pid = spawn(args.spawn, args.spawn_arg, log_path,
                                follow_children=args.follow_children)
            sessions.append(sess)
        except Exception as e:
            print(f"[!] failed to spawn {args.spawn!r}: {e}")

    if not targets and not args.spawn:
        print("no targets — pass --attach <name|pid> / --attach-all / --spawn <exe>")
        return 2

    for t in targets:
        try:
            sessions.append(attach(t, log_path))
        except frida.ProcessNotFoundError:
            print(f"[!] {t!r} not running")
        except Exception as e:
            print(f"[!] failed to attach to {t!r}: {e}")

    if not sessions:
        return 3
    print("[*] sniffing — Ctrl+C to stop")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    for s in sessions:
        try:
            s.detach()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
