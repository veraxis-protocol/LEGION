"""Independent LEGION structural readback (separate OS process, stdlib only).

argv: WORLD_URL READER_TOKEN OUT_DIR

Loops on ``GET /effects?after=..&wait_s=5`` (reader bearer token). For
each new effect it re-reads ``/state`` and the full ledger, confirms the
effect is present in the ledger with that command_id, and appends a
READBACK_EFFECT record to ``OUT_DIR/READBACK.jsonl``.

On SIGTERM it takes one final ``/state`` (+ ``/effects``) read into
``OUT_DIR/NATIVE_STATE_AFTER.json`` as ``{read_mono, state, effects}``
and copies ``/log`` into ``OUT_DIR/WORLD_LOG_READBACK.jsonl``, then exits.
Nothing here writes to the world; every call is a reader GET.
"""

import hashlib
import json
import os
import signal
import sys
import threading
import time
import urllib.error
import urllib.request

WORLD_URL = sys.argv[1].rstrip("/")
READER_TOKEN = sys.argv[2]
OUT_DIR = sys.argv[3]
os.makedirs(OUT_DIR, exist_ok=True)

_ATTEMPT_FILE = os.environ.get("STRUCT_ATTEMPT_FILE") or ""
_ATTEMPT_UID = os.environ.get("STRUCT_ATTEMPT_UID")
_WORLD_INSTANCE_ID = os.environ.get("STRUCT_WORLD_INSTANCE_ID")
_SEQ = [0]


def _stamp(rec):
    global _ATTEMPT_UID, _WORLD_INSTANCE_ID
    # E6g: live authority only for terminal control; env identity for stamping
    if os.environ.get("STRUCT_AUTHORITY_URL"):
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "causal_007"))
            import attempt_authority as _auth
            _st = _auth.client_from_env("world").status()
            if _st.get("state") in ("COMPLETED", "INTERRUPTED"):
                return None
            _ATTEMPT_UID = _ATTEMPT_UID or _st.get("attempt_uid")
            _WORLD_INSTANCE_ID = _WORLD_INSTANCE_ID or _st.get("world_instance_id")
        except Exception:
            return None
    _SEQ[0] += 1
    if _ATTEMPT_UID:
        rec.setdefault("attempt_uid", _ATTEMPT_UID)
    if _WORLD_INSTANCE_ID:
        rec.setdefault("world_instance_id", _WORLD_INSTANCE_ID)
    rec["seq"] = _SEQ[0]
    return rec

STOP = False


def _on_signal(signum, frame):
    global STOP
    STOP = True


signal.signal(signal.SIGTERM, _on_signal)
try:
    signal.signal(signal.SIGINT, _on_signal)
except (ValueError, OSError):
    pass


def get(path, timeout=10):
    req = urllib.request.Request(
        f"{WORLD_URL}{path}", method="GET",
        headers={"Authorization": f"Bearer {READER_TOKEN}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def parse_state(payload):
    if isinstance(payload, dict) and isinstance(payload.get("state"), dict) and \
            set(payload) <= {"state", "effects", "world_id", "seq"}:
        return payload["state"]
    return payload


def parse_effects(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return payload.get("effects") or []
    return []


def state_sha256(state):
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"),
                           default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def append_readback(record):
    stamped = _stamp(dict(record))
    if stamped is None:
        return
    with open(os.path.join(OUT_DIR, "READBACK.jsonl"), "a") as fh:
        fh.write(json.dumps(stamped, default=str) + "\n")
        fh.flush()


def _watch_parent():
    parent = os.getppid()
    def _run():
        while not STOP:
            time.sleep(0.5)
            try:
                if os.getppid() != parent:
                    os._exit(4)
            except Exception:
                return
    threading.Thread(target=_run, daemon=True).start()


def main():
    _watch_parent()
    # JSONL outputs must exist (0 bytes) even with zero effects, so an
    # empty run is distinguishable from lost evidence. Create at startup,
    # before the first long-poll.
    for _name in ("READBACK.jsonl", "WORLD_LOG_READBACK.jsonl"):
        open(os.path.join(OUT_DIR, _name), "a").close()
    after = 0
    seen_effect_ids = set()
    while not STOP:
        try:
            payload = get(f"/effects?after={after}&wait_s=5", timeout=12)
        except Exception:
            if STOP:
                break
            time.sleep(0.2)
            continue
        effects = parse_effects(payload)
        for effect in effects:
            seq = effect.get("seq")
            if isinstance(seq, int) and seq > after:
                after = seq
            effect_id = effect.get("effect_id")
            if effect_id in seen_effect_ids:
                continue
            seen_effect_ids.add(effect_id)
            try:
                state = parse_state(get("/state"))
                ledger = parse_effects(get("/effects?after=0&wait_s=0"))
            except Exception:
                if STOP:
                    break
                continue
            confirmed = any(
                e.get("effect_id") == effect_id and
                e.get("command_id") == effect.get("command_id")
                for e in ledger
            )
            append_readback({
                "kind": "READBACK_EFFECT",
                "provenance": "struct_readback",
                "independent": True,
                "effect_id": effect_id,
                "command_id": effect.get("command_id"),
                "confirmed": bool(confirmed),
                "state_sha256": state_sha256(state),
                "t_mono": time.monotonic(),
            })
    # Final read on SIGTERM (the world must still be up at this point).
    try:
        state = parse_state(get("/state"))
        effects = parse_effects(get("/effects?after=0&wait_s=0"))
    except Exception:
        state, effects = {}, []
    final = {"read_mono": time.monotonic(), "state": state, "effects": effects}
    with open(os.path.join(OUT_DIR, "NATIVE_STATE_AFTER.json"), "w") as fh:
        json.dump(final, fh, indent=1)
    try:
        log_payload = get("/log")
        if isinstance(log_payload, dict):
            records = log_payload.get("records") or []
            lines = [json.dumps(r, default=str) for r in records]
        elif isinstance(log_payload, list):
            lines = [json.dumps(r, default=str) for r in log_payload]
        else:
            lines = []
    except Exception:
        lines = []
    with open(os.path.join(OUT_DIR, "WORLD_LOG_READBACK.jsonl"), "w") as fh:
        for line in lines:
            fh.write(line + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
