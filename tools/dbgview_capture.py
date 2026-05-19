"""DebugView-style OutputDebugString listener.

OutputDebugString protocol (well-documented):
* Section ``\\Global??\\DBWIN_BUFFER`` (or ``\\BaseNamedObjects\\``) — 4KB shared mem
  layout: u32 ProcessId, then up to 4092 bytes of UTF-8 message.
* Event ``DBWIN_BUFFER_READY`` — listener signals "buffer free, send next"
* Event ``DBWIN_DATA_READY`` — sender signals "message in buffer"

Race the server: launch ngfx-rpc, immediately start listening, send our
probe via a side thread, capture every OutputDebugString message until
the probe finishes.
"""

import ctypes
import ctypes.wintypes as wt
import mmap
import socket
import struct
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(r"E:/Github/nsight-graphics-mcp/src")))
from nsight_graphics_mcp.rpc_client import RpcMessageHeader, RpcMessage, TransportFrame


k32 = ctypes.windll.kernel32
k32.OpenEventW.argtypes = [wt.DWORD, wt.BOOL, wt.LPCWSTR]
k32.OpenEventW.restype = wt.HANDLE
k32.CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR]
k32.CreateEventW.restype = wt.HANDLE
k32.CreateFileMappingW.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.DWORD, wt.LPCWSTR]
k32.CreateFileMappingW.restype = wt.HANDLE
k32.OpenFileMappingW.argtypes = [wt.DWORD, wt.BOOL, wt.LPCWSTR]
k32.OpenFileMappingW.restype = wt.HANDLE
k32.MapViewOfFile.argtypes = [wt.HANDLE, wt.DWORD, wt.DWORD, wt.DWORD, ctypes.c_size_t]
k32.MapViewOfFile.restype = ctypes.c_void_p
k32.SetEvent.argtypes = [wt.HANDLE]
k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.GetLastError.restype = wt.DWORD

EVENT_MODIFY_STATE = 0x0002
SYNCHRONIZE = 0x100000
FILE_MAP_READ = 0x0004
PAGE_READWRITE = 0x04
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102


def open_dbwin():
    """Open the global DBWIN buffer + events. Returns (buf_ptr, buf_ready, data_ready)."""
    # CREATE the events + buffer if they don't exist (listener owns them)
    buf_ready = k32.CreateEventW(None, False, True, "DBWIN_BUFFER_READY")
    data_ready = k32.CreateEventW(None, False, False, "DBWIN_DATA_READY")
    if not buf_ready or not data_ready:
        raise RuntimeError(f"event create failed: {k32.GetLastError()}")
    h_map = k32.CreateFileMappingW(wt.HANDLE(-1), None, PAGE_READWRITE, 0, 4096, "DBWIN_BUFFER")
    if not h_map:
        raise RuntimeError(f"mapping failed: {k32.GetLastError()}")
    ptr = k32.MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, 0)
    if not ptr:
        raise RuntimeError(f"map view failed: {k32.GetLastError()}")
    return ptr, buf_ready, data_ready


def listen(ptr, buf_ready, data_ready, stop_evt, msgs):
    """Poll DBWIN_DATA_READY; on each signal read the buffer, parse, push."""
    while not stop_evt.is_set():
        rc = k32.WaitForSingleObject(data_ready, 200)
        if rc == WAIT_TIMEOUT:
            continue
        if rc != WAIT_OBJECT_0:
            break
        # Buffer: [pid u32 LE][NUL-terminated UTF-8 message]
        raw = (ctypes.c_char * 4096).from_address(ptr)[:]
        pid = struct.unpack("<I", raw[:4])[0]
        end = raw.find(b"\x00", 4)
        if end < 0:
            end = 4096
        msg = raw[4:end].decode("utf-8", errors="replace").rstrip()
        if msg:
            msgs.append((pid, msg))
        k32.SetEvent(buf_ready)


def send_probe(port=50500):
    """One TCP connection that sends a handshake probe."""
    time.sleep(1.5)  # let listener start
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    try:
        s.connect(("127.0.0.1", port))
        h = RpcMessageHeader(category=4, method=1, ticket_id=1)
        body = bytes([0x08, 0x01])
        msg = RpcMessage(header=h, body=body)
        frame = TransportFrame(channel=0, body=msg.pack())
        s.sendall(frame.pack())
        # try to read any reply
        try:
            reply = s.recv(4096)
            print(f"[probe] reply: {len(reply)} bytes")
        except socket.timeout:
            print("[probe] no reply (timeout)")
    finally:
        s.close()


if __name__ == "__main__":
    print("[listener] opening DBWIN buffer ...")
    ptr, buf_ready, data_ready = open_dbwin()
    print("[listener] ready, capturing for ~8 sec")
    stop = threading.Event()
    msgs = []
    t = threading.Thread(target=listen, args=(ptr, buf_ready, data_ready, stop, msgs), daemon=True)
    t.start()
    pt = threading.Thread(target=send_probe, daemon=True)
    pt.start()
    time.sleep(8)
    stop.set()
    t.join(timeout=1)
    print(f"\n[result] captured {len(msgs)} debug messages")
    for pid, m in msgs:
        print(f"  pid={pid}: {m}")
