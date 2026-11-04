"""WP-E provider-logging proxy (separate OS process) -- the ONLY key holder.

This is the proxy the campaign runner starts. It wraps nim_transport
(global concurrency semaphore + queue, 429 Retry-After / jittered backoff,
5xx/timeout retries) so transport retries never consume an agent decision
turn and never fabricate a decision: on exhausted retries the transport
status is returned with no invented choices.

The NIM key is read HERE and only here, from --key-source
(file:/path | env:NAME). It is never printed, logged or forwarded to
agents. Agents authenticate with per-agent proxy tokens; the agent
identity in every provider_log record comes from the token map, never
from the request body.

One atomic provider_log record per agent call, with the same fields as
tests/legion_scale/scale_provider_logger.py: proxy_log_id, agent,
upstream, model, provider_response_id, http_status, status, usage,
request_messages, response_content, t_start_mono, t_end_mono (plus
t_start/t_end, durations, sha256s, transport retry counts).

Dry-run: --key-source stub (or --allow-no-key) with --upstream pointing
at a local stub model server; no real key is read in that mode.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from nim_transport import NimTransport  # noqa: E402
import attempt as attempt_mod  # noqa: E402
import attempt_authority as auth_mod  # noqa: E402

CONFIG = {}
TRANSPORT: NimTransport | None = None
_LOG_LOCK = threading.Lock()
_LOG_SEQ = [0]
_ATTEMPT_FILE = os.environ.get("STRUCT_ATTEMPT_FILE") or ""


def _attempt_terminal():
    """Live authority only (E6g): configured authority not RUNNING = deny.

    No authority configured = legacy unit harness with no attempt context.
    """
    if not os.environ.get(auth_mod.ENV_URL):
        return False
    try:
        st = auth_mod.client_from_env("status").status()
    except Exception:
        return True
    return st.get("state") != "RUNNING"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def read_key(key_source: str) -> str:
    if not key_source or key_source == "stub":
        return ""
    if key_source.startswith("env:"):
        return os.environ.get(key_source[4:], "").strip()
    if key_source.startswith("file:"):
        return Path(key_source[5:]).read_text(encoding="utf-8").strip()
    return ""


def append_log(rec):
    if _attempt_terminal():
        return  # writer rejects after terminal: no provider-log mutation
    rec.setdefault("t_end", time.time())
    rec.setdefault("t_end_mono", time.monotonic())
    uid = os.environ.get("STRUCT_ATTEMPT_UID")
    wid = os.environ.get("STRUCT_WORLD_INSTANCE_ID")
    if os.environ.get(auth_mod.ENV_URL):
        try:
            st = auth_mod.client_from_env("status").status()
            uid = uid or st.get("attempt_uid")
            wid = wid or st.get("world_instance_id")
        except Exception:
            pass
    if uid:
        rec.setdefault("attempt_uid", uid)
    if wid:
        rec.setdefault("world_instance_id", wid)
    data = (json.dumps(rec, default=str) + "\n").encode("utf-8")
    with _LOG_LOCK:
        _LOG_SEQ[0] += 1
        rec["seq"] = _LOG_SEQ[0]
        data = (json.dumps(rec, default=str) + "\n").encode("utf-8")
        fd = os.open(CONFIG["log"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                if n <= 0:
                    raise OSError("os.write wrote no bytes")
                view = view[n:]
        finally:
            os.close(fd)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body: bytes, extra_headers=None):
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, str(v))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, json.dumps({"ok": True}).encode())
        return self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        if _attempt_terminal():
            return self._send(403, json.dumps(
                {"error": "attempt terminal"}).encode())
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b"{}"
        token_map = CONFIG["token_map"]
        agent = token_map.get(self.headers.get("X-Legion-Proxy-Token", ""))
        log_id = f"plog-{uuid.uuid4().hex[:16]}"
        rec = {"proxy_log_id": log_id, "t_start": time.time(),
               "t_start_mono": time.monotonic(), "agent": agent,
               "path": self.path, "upstream": CONFIG["upstream"],
               "request_sha256": _sha(raw)}
        allow_no_key = CONFIG.get("allow_no_key") or CONFIG["key_source"] == "stub"
        if self.path != "/v1/chat/completions" or agent is None or (not CONFIG["key"] and not allow_no_key):
            rec.update(status="REFUSED", http_status=403,
                       reason="bad path, unknown agent token, or no key configured")
            append_log(rec)
            return self._send(403, json.dumps(
                {"error": rec["reason"], "legion_proxy_log_id": log_id}).encode())
        try:
            req_obj = json.loads(raw or b"{}")
        except ValueError:
            req_obj = {}
        rec.update(model=req_obj.get("model"),
                   request_messages=req_obj.get("messages"))
        upstream = CONFIG["upstream"]
        key = CONFIG["key"]

        def call_fn():
            up = urllib.request.Request(
                f"{upstream}/chat/completions", data=raw, method="POST",
                headers={"Content-Type": "application/json",
                         **({"Authorization": f"Bearer {key}"} if key else {})})
            try:
                with urllib.request.urlopen(up, timeout=170) as r:
                    return r.status, r.read(), dict(r.headers.items())
            except urllib.error.HTTPError as e:
                return e.code, e.read(), dict(e.headers.items() if e.headers else {})
            except (TimeoutError, ConnectionError, OSError):
                raise

        t0 = time.time()
        result = TRANSPORT.execute(call_fn)
        status, body = result.status, result.payload
        if body is None:
            body = json.dumps({"error": "transport_error"}).encode()
            status = status or 599
        if isinstance(body, str):
            body = body.encode()
        rec.update(http_status=status, duration_s=round(time.time() - t0, 3),
                   response_sha256=_sha(body),
                   transport_retries=result.transport_retries,
                   attempts=result.attempts,
                   upstream_attempts=result.attempts,
                   retry_after_s=getattr(result, "retry_after_s", None),
                   transport_cooldown_s=getattr(result, "cooldown_s", None))
        try:
            resp = json.loads(body)
        except ValueError:
            resp = {"raw": body[:500].decode("utf-8", "replace")}
        if isinstance(resp, dict):
            rec.update(provider_response_id=resp.get("id"),
                       provider_model=resp.get("model"), usage=resp.get("usage"),
                       response_content=((resp.get("choices") or [{}])[0].get("message") or {}).get("content"))
            resp["legion_proxy_log_id"] = log_id
        rec["status"] = "OK" if status == 200 else "UPSTREAM_ERROR"
        append_log(rec)
        extra = {}
        if status == 429:
            ra = getattr(result, "retry_after_s", None)
            extra["Retry-After"] = str(int(ra)) if ra else "30"
        self._send(status if 100 <= status <= 599 else 502,
                   json.dumps(resp).encode(), extra_headers=extra)

    def log_message(self, *args):
        pass


def _watch_parent():
    """P0-15: die with the campaign core; never outlive the attempt."""
    parent = os.getppid()
    def _run():
        while True:
            time.sleep(0.5)
            try:
                if os.getppid() != parent:
                    os._exit(4)
            except Exception:
                return
    threading.Thread(target=_run, daemon=True).start()


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--log", required=True)
    p.add_argument("--token-map", required=True,
                   help="JSON file {proxy_token: agent_id}")
    p.add_argument("--upstream", required=True)
    p.add_argument("--key-source", default="stub",
                   help="file:/path | env:NAME | stub")
    p.add_argument("--allow-no-key", action="store_true")
    p.add_argument("--max-concurrency", type=int,
                   default=int(os.environ.get("NIM_MAX_CONCURRENCY", "8")))
    p.add_argument("--attempt-file", default="")
    p.add_argument("--max-retries", type=int, default=3,
                   help="P1-3: bounded retries per agent call (was 6 = 7 upstream attempts/call)")
    args = p.parse_args(argv)
    global _ATTEMPT_FILE
    if args.attempt_file:
        _ATTEMPT_FILE = args.attempt_file
        os.environ["STRUCT_ATTEMPT_FILE"] = args.attempt_file
    token_map = json.loads(Path(args.token_map).read_text(encoding="utf-8"))
    # Accept either {token: agent} or {agent: token}; normalise to token->agent.
    # Token values are uuid-like hex; agent ids start with "agent:".
    if token_map and all(str(k).startswith("agent:") for k in token_map):
        token_map = {v: k for k, v in token_map.items()}
    CONFIG.update(log=args.log, token_map=token_map,
                  upstream=args.upstream.rstrip("/"),
                  key_source=args.key_source, allow_no_key=args.allow_no_key,
                  key=read_key(args.key_source))
    os.makedirs(os.path.dirname(os.path.abspath(args.log)), exist_ok=True)
    Path(args.log).touch(exist_ok=True)
    try:
        _LOG_SEQ[0] = sum(1 for line in Path(args.log).read_text(
            encoding="utf-8", errors="ignore").splitlines() if line.strip())
    except OSError:
        _LOG_SEQ[0] = 0
    global TRANSPORT
    TRANSPORT = NimTransport(max_concurrency=args.max_concurrency,
                             max_retries=args.max_retries)
    _watch_parent()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    server.serve_forever(poll_interval=0.1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
