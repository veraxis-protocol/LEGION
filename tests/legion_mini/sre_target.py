"""LEGION-MINI-003 disposable native service (TEST-ONLY). Separate OS process; the real two-step service repair.

State starts exactly at {"config_restored": false, "service_running": false, "service_healthy": false, "generation": 0}.
  POST /apply   mutation; requires the actuator-only bearer token (env SRE_TARGET_TOKEN, given to the gateway only).
                Idempotent per command_id: a repeated command_id is answered "duplicate" and changes nothing.
  GET  /state   native state (read-only)            GET /effects  append-only effect log (read-only)
Semantics: restore_config(generation=1) writes generation-1 config. restart_service starts the process; it is
healthy only if the config was restored first (a restart before the config leaves it running but unhealthy).
argv: PORT LOG_JSONL. Optional env SRE_TARGET_APPLY_DELAY_S delays the HTTP answer AFTER applying (fault injection)."""
import json, os, sys, threading, time, uuid
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

PORT, LOG = int(sys.argv[1]), sys.argv[2]
TOKEN = os.environ["SRE_TARGET_TOKEN"]
DELAY = float(os.environ.get("SRE_TARGET_APPLY_DELAY_S", "0"))
STATE = {"config_restored": False, "service_running": False, "service_healthy": False, "generation": 0}
EFFECTS: list[dict] = []
SEEN: dict[str, dict] = {}
LOCK = threading.Lock()
VERBS = {"restore_config", "restart_service"}


def log(rec):
    with open(LOG, "a") as fh:
        fh.write(json.dumps({"t": time.time(), **rec}) + "\n")


class H(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        with LOCK:
            if self.path == "/state":
                return self._send(200, {**STATE, "target": "demo-service", "pid": os.getpid()})
            if self.path == "/effects":
                return self._send(200, {"effects": json.loads(json.dumps(EFFECTS))})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/apply":
            return self._send(404, {"error": "not found"})
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            log({"event": "REFUSED_UNAUTHENTICATED", "req": body})
            return self._send(401, {"error": "actuator credential required"})
        verb, cmd = body.get("verb"), body.get("command_id")
        if verb not in VERBS or body.get("target") != "demo-service" or not cmd:
            log({"event": "REFUSED_MALFORMED", "req": body})
            return self._send(400, {"error": "malformed"})
        with LOCK:
            if cmd in SEEN:
                log({"event": "DUPLICATE", "req": body})
                resp = {"status": "duplicate", "effect": SEEN[cmd], "state": dict(STATE)}
            else:
                pre = dict(STATE)
                if verb == "restore_config":
                    STATE["config_restored"] = body.get("generation") == 1
                    STATE["generation"] = int(body.get("generation", 0))
                else:
                    STATE["service_running"] = True
                    STATE["service_healthy"] = STATE["config_restored"] and STATE["generation"] == 1
                effect = {"effect_id": f"effect-{uuid.uuid4().hex[:12]}", "seq": len(EFFECTS) + 1, "applied": True,
                          "verb": verb, "actor": body.get("actor"), "system": body.get("system"), "target": "demo-service",
                          "generation": body.get("generation"), "command_id": cmd, "governance_seal_sha256": body.get("seal_sha256"),
                          "params_hash": body.get("params_hash"), "pre": pre, "post": dict(STATE), "applied_at": time.time(),
                          "applied_mono": time.monotonic()}
                EFFECTS.append(effect)
                SEEN[cmd] = effect
                log({"event": "APPLIED", "effect": effect})
                resp = {"status": "applied", "effect": effect, "state": dict(STATE)}
        if DELAY:
            time.sleep(DELAY)            # fault-injection window: effect applied, answer not yet returned
        self._send(200, resp)

    def log_message(self, *a):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
