"""Local stub 'model' server -- ONLY for dry-run tests (never a campaign).

Implements POST /chat/completions (OpenAI-shaped) so the real agent NIM
path (struct_agent.run_nim -> provider_proxy -> here) can run with no NIM
key and no network beyond loopback.

Behaviour is driven by a stub plan file (env STUB_PLAN_FILE or
--plan-file): {"roles": {agent_id: [action, ...]}} (same shape as the
scripted plan) or {agent_id: [...]}. Each call for an agent returns its
next planned action as the message content, with a unique
provider_response_id (stub-resp-<n>). A step may carry "_force": true to
be returned even when the causal view says its task is not yet eligible
(used to demonstrate premature-action refusals). Otherwise, if the causal
view in the prompt says the planned task is PENDING (dependencies open),
the stub returns an idle action without consuming the step, so dependent
steps are retried after their dependencies confirm.

When the plan is exhausted the stub returns {"action":"idle"}.
This server never touches the world: it only answers model calls.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PLAN = {}
COUNTERS = {}
LOCK = threading.Lock()
SEQ = [0]
DELAY_S = 0.0
STORM_429 = [0]  # first N upstream calls get HTTP 429 (test D, E6b)


def load_plan(path):
    if not path or not os.path.exists(path):
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("roles"), dict):
        return data["roles"]
    return data if isinstance(data, dict) else {}


def parse_observation(messages):
    for m in reversed(messages or []):
        content = m.get("content") or ""
        if "OBSERVATION:" in content:
            try:
                return json.loads(content.split("OBSERVATION:", 1)[1].strip())
            except ValueError:
                return {}
    return {}


def task_state(obs, task_id):
    view = obs.get("causal_view") or {}
    for ob in view.get("obligations") or []:
        if ob.get("task_id") == task_id:
            return ob.get("state")
    return None


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if DELAY_S > 0:
            time.sleep(DELAY_S)  # deliberately slow stub (P0-13 regression)
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except ValueError:
            req = {}
        obs = parse_observation(req.get("messages"))
        agent = obs.get("agent_id") or ""
        with LOCK:
            SEQ[0] += 1
            n = SEQ[0]
            if n <= STORM_429[0]:
                body = json.dumps({"error": "rate limited (stub storm)"}).encode()
                try:
                    self.send_response(429)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Retry-After", "0")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                return
            steps = PLAN.get(agent) or []
            idx = COUNTERS.get(agent, 0)
            action = {"action": "idle", "seconds": 0.5}
            if idx < len(steps):
                step = dict(steps[idx])
                force = bool(step.pop("_force", False))
                state = task_state(obs, step.get("task"))
                if force or state != "PENDING" or step.get("action") == "idle":
                    COUNTERS[agent] = idx + 1
                    action = step
                # else: dependencies still open -> idle without consuming
            # Dynamic (public, prompt-derived) fill-ins for dry-run plans:
            view = obs.get("causal_view") or {}
            shared_ids = [e.get("observation_id") for e in view.get("shared_evidence") or []
                          if str((e.get("agent_id") or "")).startswith("agent:s100-delegate-")]
            my_ids = [r.get("observation_id") for r in obs.get("my_recent_records") or []
                      if r.get("observation_id")]
            if action.get("action") == "send" and shared_ids:
                action["body"] = f"{action.get('body') or ''} evidence: {' '.join(shared_ids)}"
            if action.get("action") == "analyze":
                refs = action.get("evidence_refs")
                if refs == "$my_obs_ids":
                    action["evidence_refs"] = my_ids
                elif isinstance(refs, list) and "$my_obs_ids" in refs:
                    action["evidence_refs"] = my_ids + [r for r in refs if r != "$my_obs_ids"]
        content = json.dumps(action)
        return self._send(200, {
            "id": f"stub-resp-{n}",
            "model": req.get("model") or "stub-model",
            "choices": [{"message": {"role": "assistant", "content": content},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })

    def log_message(self, *args):
        pass


def _watch_parent():
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
    p.add_argument("--plan-file", default=os.environ.get("STUB_PLAN_FILE", ""))
    p.add_argument("--delay-s", type=float,
                   default=float(os.environ.get("STUB_DELAY_S", "0") or 0),
                   help="deliberate per-call delay for slow-mission tests")
    p.add_argument("--storm-429-count", type=int,
                   default=int(os.environ.get("CAUSAL_STUB_429_COUNT", "0") or 0),
                   help="first N upstream calls return HTTP 429 (E6b test D)")
    args = p.parse_args(argv)
    global PLAN, DELAY_S
    PLAN = load_plan(args.plan_file)
    STORM_429[0] = max(0, int(args.storm_429_count or 0))
    DELAY_S = max(0.0, float(args.delay_s or 0))
    _watch_parent()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    server.serve_forever(poll_interval=0.1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
