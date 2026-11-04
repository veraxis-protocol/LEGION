"""LEGION scale provider-logging proxy (separate OS process). The ONLY holder of the provider API key.

Identical CLI, behaviour and record schema to tests/legion_mini/provider_logger.py.
The only difference is the write path: writes are serialized with a module-level
lock, encoded once, and written with os.write on an O_APPEND fd (looping until
all bytes are written) so concurrent threads cannot interleave/torn records.

Agents call POST /v1/chat/completions with header X-Legion-Proxy-Token. The proxy maps that token to an agent identity
(tokens are issued by the mission host per agent at launch; agents never see the provider key), forwards the request to
the OpenAI-compatible upstream, and appends one record per call to the provider log:
  proxy_log_id, agent (from the token mapping, not from the request), upstream url/model, provider response id,
  usage tokens, HTTP status, duration, sha256 of request/response bodies, the request messages and response content.
The Authorization header and key are never logged. Nothing in the log is written by an agent.
argv: PORT LOG_JSONL TOKEN_MAP_JSON UPSTREAM_BASE_URL KEY_SOURCE(env:NAME|file:/path)"""
import hashlib, json, os, sys, threading, time, uuid, urllib.request, urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

PORT, LOG, TOKENS, UPSTREAM, KEY_SOURCE = int(sys.argv[1]), sys.argv[2], json.loads(sys.argv[3]), sys.argv[4].rstrip("/"), sys.argv[5]
# KEY_SOURCE is "env:NAME" or "file:/path" (owner-designated). The key value is never printed or logged.
if KEY_SOURCE.startswith("env:"):
    KEY = os.environ.get(KEY_SOURCE[4:], "").strip()
elif KEY_SOURCE.startswith("file:"):
    KEY = open(KEY_SOURCE[5:]).read().strip()
else:
    KEY = ""

_LOG_LOCK = threading.Lock()


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class H(BaseHTTPRequestHandler):
    def _send(self, code, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        agent = TOKENS.get(self.headers.get("X-Legion-Proxy-Token", ""))
        log_id = f"plog-{uuid.uuid4().hex[:16]}"
        rec = {"proxy_log_id": log_id, "t_start": time.time(), "t_start_mono": time.monotonic(), "agent": agent, "path": self.path, "upstream": UPSTREAM,
               "request_sha256": sha(raw)}
        if self.path != "/v1/chat/completions" or agent is None or not KEY:
            rec.update(status="REFUSED", reason="bad path, unknown agent token, or no key configured")
            self._log(rec)
            return self._send(403, json.dumps({"error": rec["reason"], "legion_proxy_log_id": log_id}).encode())
        req_obj = json.loads(raw or b"{}")
        rec.update(model=req_obj.get("model"), request_messages=req_obj.get("messages"))
        up = urllib.request.Request(f"{UPSTREAM}/chat/completions", data=raw, method="POST",
                                    headers={"Content-Type": "application/json", "Authorization": f"Bearer {KEY}"})
        t0 = time.time()
        try:
            with urllib.request.urlopen(up, timeout=170) as r:
                status, body = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, body = e.code, e.read()
        except Exception as e:
            status, body = 599, json.dumps({"error": type(e).__name__}).encode()
        rec.update(http_status=status, duration_s=round(time.time() - t0, 3), response_sha256=sha(body))
        try:
            resp = json.loads(body)
        except ValueError:
            resp = {"raw": body[:500].decode("utf-8", "replace")}
        if isinstance(resp, dict):
            rec.update(provider_response_id=resp.get("id"), provider_model=resp.get("model"), usage=resp.get("usage"),
                       response_content=((resp.get("choices") or [{}])[0].get("message") or {}).get("content"))
            resp["legion_proxy_log_id"] = log_id
        rec["status"] = "OK" if status == 200 else "UPSTREAM_ERROR"
        self._log(rec)
        self._send(status, json.dumps(resp).encode())

    def _log(self, rec):
        rec["t_end"], rec["t_end_mono"] = time.time(), time.monotonic()
        data = (json.dumps(rec, default=str) + "\n").encode("utf-8")
        with _LOG_LOCK:
            fd = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("os.write wrote no bytes")
                    view = view[written:]
            finally:
                os.close(fd)

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
