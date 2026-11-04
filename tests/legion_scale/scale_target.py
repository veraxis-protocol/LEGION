"""LEGION scale native target (TEST-ONLY). Separate OS process, stdlib only.

argv: PORT LOG_JSONL MANIFEST_JSON. State stage_by_shard initialised from manifest zero_state.
POST /apply requires Authorization: Bearer $SRE_TARGET_TOKEN; native invariant
stage == stage_by_shard[target_id]+1 else 409, no mutation. Idempotent per command_id.
GET /state, GET /effects (read-only)."""
import json, os, sys, threading, time, uuid
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

PORT, LOG, MANIFEST = int(sys.argv[1]), sys.argv[2], sys.argv[3]
TOKEN = os.environ["SRE_TARGET_TOKEN"]
MAN = json.load(open(MANIFEST))
STATE = {"stage_by_shard": dict(MAN["zero_state"]["stage_by_shard"])}
EFFECTS: list[dict] = []
SEEN: dict[str, dict] = {}
LOCK = threading.Lock()


def log(rec):
    with open(LOG, "a") as fh:
        fh.write(json.dumps({"t": time.time(), "mono": time.monotonic(), **rec}) + "\n")


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        with LOCK:
            if self.path == "/state":
                return self._send(200, {"stage_by_shard": dict(STATE["stage_by_shard"]), "pid": os.getpid()})
            if self.path == "/effects":
                return self._send(200, {"effects": json.loads(json.dumps(EFFECTS))})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/apply":
            return self._send(404, {"error": "not found"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        except ValueError:
            body = {}
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            log({"event": "REFUSED_UNAUTHENTICATED", "req": body}); return self._send(401, {"error": "actuator credential required"})
        cmd, tid, stage = body.get("command_id"), body.get("target_id"), body.get("stage")
        if not cmd or tid not in STATE["stage_by_shard"] or not isinstance(stage, int) or not body.get("obligation_id"):
            log({"event": "REFUSED_MALFORMED", "req": body}); return self._send(400, {"error": "malformed"})
        with LOCK:
            if cmd in SEEN:
                log({"event": "DUPLICATE", "req": body})
                return self._send(200, {"status": "duplicate", "effect": SEEN[cmd], "state": {"stage_by_shard": dict(STATE["stage_by_shard"])}})
            cur = STATE["stage_by_shard"][tid]
            if stage != cur + 1:
                log({"event": "REFUSED_OUT_OF_ORDER", "req": body, "current_stage": cur})
                return self._send(409, {"status": "out_of_order", "error": f"stage {stage} != current+1 ({cur+1})", "state": {"stage_by_shard": dict(STATE["stage_by_shard"])}})
            pre = {"stage_by_shard": dict(STATE["stage_by_shard"])}
            STATE["stage_by_shard"][tid] = stage
            effect = {"effect_id": f"effect-{uuid.uuid4().hex[:12]}", "seq": len(EFFECTS) + 1, "applied": True,
                      "verb": "apply_transition", "obligation_id": body.get("obligation_id"), "actor": body.get("actor"),
                      "system": body.get("system"), "target_id": tid, "target": tid, "stage": stage, "command_id": cmd,
                      "governance_seal_sha256": body.get("seal_sha256"), "params_hash": body.get("params_hash"),
                      "pre": pre, "post": {"stage_by_shard": dict(STATE["stage_by_shard"])},
                      "applied_at": time.time(), "applied_mono": time.monotonic()}
            EFFECTS.append(effect); SEEN[cmd] = effect
            log({"event": "APPLIED", "effect": effect})
            return self._send(200, {"status": "applied", "effect": effect, "state": {"stage_by_shard": dict(STATE["stage_by_shard"])}})

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
