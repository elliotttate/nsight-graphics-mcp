"""Persistent private frame-debugger RPC sessions.

The stateless RPC tools are good for request previews and one-shot calls. This
module keeps an ngfx-rpc TCP connection open across MCP calls so an autonomous
agent can load a capture, issue multiple BinaryReplay requests, and close the
session explicitly.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import proto_descriptors, rpc_client


def _new_handle() -> str:
    return f"fdrpc_{secrets.token_hex(4)}"


@dataclass
class FrameDebuggerRpcSession:
    handle: str
    host: str
    port: int
    transport_kind: str
    transport: rpc_client.RpcTransport
    client: rpc_client.RpcClient
    pipename: str | None = None
    capture_path: str | None = None
    opened_at: float = field(default_factory=time.monotonic)
    last_error: str | None = None
    launch_reply: dict[str, Any] | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "host": self.host,
            "port": self.port,
            "transport": self.transport_kind,
            "pipename": self.pipename,
            "capture_path": self.capture_path,
            "uptime_sec": round(time.monotonic() - self.opened_at, 2),
            "last_error": self.last_error,
            "has_launch_reply": self.launch_reply is not None,
        }


_lock = threading.Lock()
_sessions: dict[str, FrameDebuggerRpcSession] = {}


def open_session(
    *,
    host: str,
    port: int,
    transport_kind: str = "tcp",
    pipename: str | None = None,
    capture_path: str | None = None,
    launch_capture: bool = False,
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """Open and register a persistent RPC session."""
    reg = proto_descriptors.get_registry()
    if transport_kind == "named_pipe":
        if not pipename:
            raise ValueError("pipename is required for named_pipe transport")
        transport = rpc_client.RpcTransport.connect_named_pipe(pipename, timeout=timeout_sec)
    else:
        transport = rpc_client.RpcTransport.connect(host, port, timeout=timeout_sec)
    client = rpc_client.RpcClient(transport, reg)
    handle = _new_handle()
    session = FrameDebuggerRpcSession(
        handle=handle,
        host=host,
        port=port,
        transport_kind=transport_kind,
        pipename=pipename,
        transport=transport,
        client=client,
        capture_path=capture_path,
    )
    try:
        if capture_path and launch_capture:
            reply = client.launch_capture(Path(capture_path))
            session.launch_reply = rpc_client.protobuf_to_dict(reply)
    except Exception as exc:
        session.last_error = f"{type(exc).__name__}: {exc}"
    with _lock:
        _sessions[handle] = session
    return {"ok": session.last_error is None, "session": session.summary(), "launch_reply": session.launch_reply}


def get_session(handle: str) -> FrameDebuggerRpcSession:
    with _lock:
        sess = _sessions.get(handle)
    if sess is None:
        raise KeyError(f"frame-debugger RPC session not found: {handle}")
    return sess


def list_sessions() -> list[dict[str, Any]]:
    with _lock:
        return [s.summary() for s in _sessions.values()]


def close_session(handle: str) -> dict[str, Any]:
    with _lock:
        sess = _sessions.pop(handle, None)
    if sess is None:
        return {"ok": False, "error": f"frame-debugger RPC session not found: {handle}"}
    sess.transport.close()
    return {"ok": True, "closed": sess.summary()}


def call_binary_replay(
    handle: str,
    *,
    method: int,
    request_fqn: str,
    reply_fqn: str,
    request_body_hex: str = "",
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """Call one BinaryReplay method on an open session."""
    sess = get_session(handle)
    try:
        reg = sess.client.registry
        cls = reg.message_class(request_fqn)
        body = bytes.fromhex(request_body_hex.replace(" ", ""))
        req = cls.FromString(body) if body else cls()
        reply = sess.client.call(
            category=rpc_client.CATEGORY_BINARY_REPLAY,
            method=method,
            request_proto=req,
            reply_fqn=reply_fqn,
            timeout=timeout_sec,
        )
        sess.last_error = None
        return {
            "ok": True,
            "session": sess.summary(),
            "method": method,
            "request_fqn": request_fqn,
            "reply_fqn": reply_fqn,
            "reply": rpc_client.protobuf_to_dict(reply),
        }
    except Exception as exc:
        sess.last_error = f"{type(exc).__name__}: {exc}"
        return {"ok": False, "session": sess.summary(), "error": sess.last_error}
