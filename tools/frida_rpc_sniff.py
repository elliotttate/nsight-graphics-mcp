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

try { hookSend(); } catch (e) { send({type: 'err', where: 'send', msg: e.toString()}); }
try { hookRecv(); } catch (e) { send({type: 'err', where: 'recv', msg: e.toString()}); }
try { hookWSASend(); } catch (e) { send({type: 'err', where: 'wsasend', msg: e.toString()}); }
try { hookWSARecv(); } catch (e) { send({type: 'err', where: 'wsarecv', msg: e.toString()}); }

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

    # Data messages — actual send/recv buffers
    direction = ">>>" if pt in ("send", "wsasend") else "<<<"
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


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--attach", action="append", default=[],
                    help="process name or PID to attach to (repeatable)")
    ap.add_argument("--attach-all", action="store_true",
                    help="attach to every running ngfx-* process")
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

    if not targets:
        print("no targets — pass --attach <name|pid> or --attach-all")
        return 2

    log_path = Path(args.log).resolve() if args.log else None
    sessions = []
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
