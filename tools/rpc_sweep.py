"""Second sweep — send VALID protobuf bodies built from the schema pool
rather than empty bodies. Also try varying the `slot` byte (was always 0
before; maybe the server requires a specific slot)."""

import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(r"E:/Github/nsight-graphics-mcp/src")))
from nsight_graphics_mcp.rpc_client import RpcMessageHeader, RpcMessage, TransportFrame
from nsight_graphics_mcp import proto_descriptors as pd


def send(s, cat, meth, body=b"", ticket=1, channel=0, slot=0):
    h = RpcMessageHeader(category=cat, method=meth, ticket_id=ticket, slot=slot)
    msg = RpcMessage(header=h, body=body)
    frame = TransportFrame(channel=channel, body=msg.pack())
    s.sendall(frame.pack())


def recv_one(s, timeout=1.0):
    s.settimeout(timeout)
    hdr = b""
    while len(hdr) < 8:
        try:
            c = s.recv(8 - len(hdr))
            if not c:
                return None
            hdr += c
        except socket.timeout:
            return None
    size = struct.unpack(">I", hdr[4:8])[0]
    body = b""
    while len(body) < size:
        try:
            c = s.recv(size - len(body))
            if not c:
                break
            body += c
        except socket.timeout:
            break
    return hdr + body


def parse(b):
    if not b or len(b) < 32:
        return None
    size = struct.unpack(">I", b[4:8])[0]
    rh = b[8:32]
    return dict(
        size=size, chan=b[2],
        tk=struct.unpack(">Q", rh[0:8])[0],
        rq=struct.unpack(">Q", rh[8:16])[0],
        sq=struct.unpack(">I", rh[16:20])[0],
        cat=rh[20], meth=rh[21], slot=rh[22], fl=rh[23],
        body=b[32:32 + size - 24] if size > 24 else b"",
    )


def main():
    rpc_exe = Path(r"C:/Program Files/NVIDIA Corporation/Nsight Graphics 2026.1.0/host/windows-desktop-nomad-x64/ngfx-rpc.exe")
    reg = pd.build_registry(rpc_exe)

    # Build valid protobuf request bodies
    HSB = reg.message_class("NV.TPS.System.PbHandshakeBeginMessage")()
    HSB.id = 1
    hs_body = HSB.SerializeToString()
    print(f"PbHandshakeBeginMessage body: {hs_body.hex()}")

    PING = reg.message_class("NV.TPS.System.PingRequestMessage")()
    try:
        ping_body = PING.SerializeToString()
        print(f"PingRequestMessage body: {ping_body.hex()}")
    except Exception as e:
        ping_body = b""
        print(f"PingRequest: {e}")

    # GetSystemInfo / GetDeviceInfo / GetProcessInfo
    try:
        GSI = reg.message_class("NV.TPS.System.GetSystemInfoRequestMessage")()
        gsi_body = GSI.SerializeToString()
        print(f"GetSystemInfoRequest body: {gsi_body.hex()}")
    except Exception as e:
        gsi_body = b""
        print(f"GetSystemInfoRequest: {e}")

    probes = [
        # ch, cat, meth, slot, body, label
        (0, 4, 1, 0, hs_body, "Hsh.HandshakeBegin"),
        (0, 1, 2, 0, ping_body, "Diag.PingRequest"),
        (0, 2, 2, 0, gsi_body, "SysInfo.GetSystemInfo"),
        # Try slot variations on handshake
        (0, 4, 1, 1, hs_body, "Hsh.HandshakeBegin slot=1"),
        (0, 4, 1, 11, hs_body, "Hsh.HandshakeBegin slot=11"),
        # Try channel 1
        (1, 4, 1, 0, hs_body, "Hsh.HandshakeBegin ch=1"),
        # Try Pylon BinaryReplay launch with empty body
        (0, 1, 1, 0, b"", "BR.Launch ch=0 (empty)"),
        (1, 1, 1, 0, b"", "BR.Launch ch=1 (empty)"),
    ]

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 50500))
    print("connected")
    ticket = 0
    for ch, cat, meth, slot, body, label in probes:
        ticket += 1
        try:
            send(s, cat=cat, meth=meth, body=body, ticket=ticket,
                 channel=ch, slot=slot)
            r = recv_one(s, timeout=0.8)
            p = parse(r) if r else None
            if p is None:
                print(f"  {label}: ch={ch} cat={cat} m={meth} slot={slot}  TIMEOUT/CLOSE")
                break
            interesting = (p["cat"] != 0 or p["meth"] != 0
                           or p["slot"] not in (0, 0x0b) or p["body"])
            flag = "*" if interesting else " "
            body_hint = f" body={len(p['body'])}b" if p["body"] else ""
            print(f"  {flag} {label} (body={len(body)}b): -> "
                  f"cat={p['cat']} m={p['meth']} slot={p['slot']} fl={p['fl']}"
                  f"{body_hint}")
            if p["body"]:
                print("    body: " + " ".join(f"{b:02x}" for b in p["body"][:64]))
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"  {label}: SOCKET ERR {e}")
            break
    s.close()


if __name__ == "__main__":
    main()
