"""LEGION structural world server (separate OS process, stdlib only).

argv: PORT WORLD_JSON OUT_DIR TOKENS_JSON_PATH
TOKENS_JSON = {"agents": {token: agent_id}, "actuator": token, "reader": token}

Serves the DSL HTTP API from WORLD_DSL.md. Identity comes only from
``X-Legion-World-Token`` for agent endpoints; ``/actuate`` requires the
actuator bearer token and ``/state`` / ``/effects`` / ``/log`` require
the reader bearer token. Anything unauthorised is 403 + DENIED_REQUEST.

Append-only logging: one module-level lock, one O_APPEND fd, an
``os.write`` loop until every byte is written (mirroring
``tests/legion_scale/scale_provider_logger.py``). Every record carries
``seq``, ``kind``, ``t_mono`` (time.monotonic) and ``t_rel``.
"""

import copy
import hashlib
import json
import os
import signal
import sys
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "causal_007"))
from world_engine import World  # noqa: E402
import attempt as _attempt  # noqa: E402
import attempt_authority as _auth  # noqa: E402

ATTEMPT_FILE = os.environ.get("STRUCT_ATTEMPT_FILE") or ""
ATTEMPT_UID = os.environ.get("STRUCT_ATTEMPT_UID") or None
WORLD_INSTANCE_ID = os.environ.get("STRUCT_WORLD_INSTANCE_ID") or None
USED_NONCES = set()
# P0-01: commands released with no effect are tombstoned here and never executed.
FENCED_COMMANDS = set()


def _world_client():
    return _auth.client_from_env("world")


_TERMINAL_CACHE = {"t": 0.0, "value": False}


def _attempt_terminal():
    """Live authority check (E6e), cached 1 s for the log path only.

    Unreachable authority is NOT terminal evidence, but /actuate denies
    on unreachability separately with a fresh (uncached) verification.
    """
    now = time.monotonic()
    if now - _TERMINAL_CACHE["t"] < 1.0:
        return _TERMINAL_CACHE["value"]
    try:
        value = _world_client().status().get("state") in _attempt.TERMINAL
    except Exception:
        value = False
    _TERMINAL_CACHE.update(t=now, value=value)
    return value


def _authority_running():
    try:
        st = _world_client().status()
        return st if st.get("state") == "RUNNING" else None
    except Exception:
        return None


def _attempt_identity():
    try:
        st = _world_client().status()
        return st.get("attempt_uid"), st.get("world_instance_id")
    except Exception:
        return None, None

PORT = int(sys.argv[1])
WORLD_JSON = sys.argv[2]
OUT_DIR = sys.argv[3]
TOKENS_JSON_PATH = sys.argv[4]

os.makedirs(OUT_DIR, exist_ok=True)
WORLD_BYTES = open(WORLD_JSON, "rb").read()
SPEC = json.loads(WORLD_BYTES.decode("utf-8"))
WORLD_SHA256 = hashlib.sha256(WORLD_BYTES).hexdigest()
TOKENS = json.load(open(TOKENS_JSON_PATH))
AGENT_TOKENS = TOKENS.get("agents") or {}
ACTUATOR_TOKEN = TOKENS.get("actuator")
READER_TOKEN = TOKENS.get("reader")

WORLD = World(SPEC)
START_MONO = time.monotonic()

LOG_PATH = os.path.join(OUT_DIR, "WORLD_LOG.jsonl")
_LOG_LOCK = threading.Lock()
_LOG_FD = os.open(LOG_PATH, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
_SEQ = [0]
LOG_RECORDS = []
# WO008-MUSE-001: journal epoch = live authority epoch at record time.
# WORLD_START and every later record carry it; an EPOCH_TRANSITION record
# (authenticated Authority proof) is the only way it changes.
CURRENT_EPOCH = [None]

WORLD_LOCK = threading.RLock()
EVENT_COND = threading.Condition()
INBOX = {}  # agent_id -> [message dicts]
STOP = threading.Event()


def _new_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def log_record(kind, _switch_epoch=None, **fields):
    """Append one record; returns the stored record (with seq/times)."""
    if fields.get("attempt_uid") and ATTEMPT_UID and \
            fields["attempt_uid"] != ATTEMPT_UID:
        raise ValueError("foreign attempt_uid")
    if fields.get("world_instance_id") and WORLD_INSTANCE_ID and \
            fields["world_instance_id"] != WORLD_INSTANCE_ID:
        raise ValueError("foreign world_instance_id")
    if _attempt_terminal():
        # Terminal attempt: writers reject; no further world-log mutation.
        return {"seq": _SEQ[0], "kind": kind, "refused_terminal": True}
    t_mono = time.monotonic()
    with _LOG_LOCK:
        _SEQ[0] += 1
        rec = {"seq": _SEQ[0], "kind": kind, "t_mono": t_mono,
               "t_rel": t_mono - START_MONO, **fields}
        if _switch_epoch is not None:
            # P0-03: the certified transition record is the FIRST record of
            # the new epoch; the switch happens inside the same lock, after
            # the write, so no record can carry the new epoch before it.
            rec["epoch"] = int(_switch_epoch)
        elif CURRENT_EPOCH[0] is not None:
            rec.setdefault("epoch", CURRENT_EPOCH[0])
        if ATTEMPT_UID:
            rec.setdefault("attempt_uid", ATTEMPT_UID)
        if WORLD_INSTANCE_ID:
            rec.setdefault("world_instance_id", WORLD_INSTANCE_ID)
        data = (json.dumps(rec, default=str) + "\n").encode("utf-8")
        view = memoryview(data)
        while view:
            written = os.write(_LOG_FD, view)
            if written <= 0:
                raise OSError("os.write wrote no bytes")
            view = view[written:]
        LOG_RECORDS.append(rec)
        if _switch_epoch is not None:
            CURRENT_EPOCH[0] = int(_switch_epoch)
        return rec


def log_refusal_record(kind, **fields):
    """Append a refusal record even for a terminal attempt (E6c/F).

    A refusal record effects nothing: no state change, no effect ledger
    entry. It is the append-only evidence that an identity was rejected,
    so it must be writable exactly when all effect writers are refused.
    Stamped with this world's (attempt_uid, world_instance_id, seq).
    """
    t_mono = time.monotonic()
    with _LOG_LOCK:
        _SEQ[0] += 1
        rec = {"seq": _SEQ[0], "kind": kind, "t_mono": t_mono,
               "t_rel": t_mono - START_MONO, **fields}
        # WO008-MUSE-001: the journal's own epoch is record_epoch; a
        # rejected permit's claimed epoch is preserved separately as
        # rejected_permit_epoch and never becomes record identity.
        if CURRENT_EPOCH[0] is not None:
            rec.setdefault("record_epoch", CURRENT_EPOCH[0])
        if ATTEMPT_UID:
            rec.setdefault("attempt_uid", ATTEMPT_UID)
        if WORLD_INSTANCE_ID:
            rec.setdefault("world_instance_id", WORLD_INSTANCE_ID)
        data = (json.dumps(rec, default=str) + "\n").encode("utf-8")
        view = memoryview(data)
        while view:
            written = os.write(_LOG_FD, view)
            if written <= 0:
                raise OSError("os.write wrote no bytes")
            view = view[written:]
        LOG_RECORDS.append(rec)
        return rec


def fire_due_events():
    """Fire every due event once, logging ENV_EVENT. Caller handles cond."""
    with WORLD_LOCK:
        due = WORLD.due_events(WORLD.now_rel(), list(WORLD.effect_ledger))
        fired = []
        for event in due:
            result = WORLD.fire(event)
            if result is not None:
                rec = log_record("ENV_EVENT", event_id=event.get("event_id"))
                fired.append(rec)
    if fired:
        with EVENT_COND:
            EVENT_COND.notify_all()
    return fired


def _event_thread():
    while not STOP.is_set():
        try:
            fire_due_events()
        except Exception:
            pass
        STOP.wait(0.2)


class Handler(BaseHTTPRequestHandler):
    # --------------------------------------------------------------
    def _send(self, code, obj):
        try:
            body = json.dumps(obj, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b"{}"
        try:
            obj = json.loads(raw or b"{}")
        except ValueError:
            return {}
        return obj if isinstance(obj, dict) else {}

    def _agent(self):
        return AGENT_TOKENS.get(self.headers.get("X-Legion-World-Token", ""))

    def _denied(self, path):
        log_record("DENIED_REQUEST", method=self.command, path=path)
        self._send(403, {"error": "forbidden"})

    def _bearer_ok(self, expected):
        return expected is not None and \
            self.headers.get("Authorization", "") == f"Bearer {expected}"

    # --------------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path, query = parsed.path, urllib.parse.parse_qs(parsed.query)
        if path == "/observe":
            agent_id = self._agent()
            if agent_id is None:
                return self._denied(path)
            with WORLD_LOCK:
                notices = list(WORLD.notices.get(agent_id, []))
                tasks = WORLD.tasks_for(agent_id)
            inbox = [copy.deepcopy(m) for m in INBOX.get(agent_id, [])]
            mine = [r for r in LOG_RECORDS if r.get("agent_id") == agent_id][-30:]
            return self._send(200, {
                "agent_id": agent_id,
                "now_rel": time.monotonic() - START_MONO,
                "tasks": tasks,
                "notices": notices,
                "inbox": inbox,
                "my_records": copy.deepcopy(mine),
            })
        if path in ("/state", "/effects", "/log"):
            if not self._bearer_ok(READER_TOKEN):
                return self._denied(path)
            if path == "/state":
                with WORLD_LOCK:
                    return self._send(200, WORLD.get_state())
            if path == "/log":
                return self._send(200, {"records": copy.deepcopy(LOG_RECORDS)})
            # /effects with optional long-poll.
            try:
                after = int((query.get("after") or ["0"])[0])
            except ValueError:
                after = 0
            try:
                wait_s = float((query.get("wait_s") or ["0"])[0])
            except ValueError:
                wait_s = 0.0
            deadline = time.monotonic() + max(0.0, wait_s)
            while True:
                with WORLD_LOCK:
                    entries = [copy.deepcopy(e) for e in WORLD.effect_ledger
                               if int(e.get("seq", 0)) > after]
                    last_seq = WORLD.effect_ledger[-1]["seq"] if WORLD.effect_ledger else 0
                if entries or wait_s <= 0 or time.monotonic() >= deadline or STOP.is_set():
                    return self._send(200, {"effects": entries, "seq": last_seq})
                with EVENT_COND:
                    EVENT_COND.wait(timeout=min(0.5, max(0.0, deadline - time.monotonic())))
            # unreachable
        return self._send(404, {"error": "not found"})

    # --------------------------------------------------------------
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        body = self._body()

        if path == "/epoch-transition":
            return self._epoch_transition(path, body)

        if path == "/actuate":
            return self._actuate(path, body)

        agent_endpoints = ("/read", "/send", "/wait", "/analyze", "/reconcile", "/done")
        if path not in agent_endpoints:
            return self._send(404, {"error": "not found"})
        if _authority_running() is None:
            return self._send(403, {"error": "attempt authority unavailable or not RUNNING"})
        agent_id = self._agent()
        if agent_id is None:
            return self._denied(path)
        # Untrusted metadata only: stored on agent records, never authority.
        decision_ref = self.headers.get("X-Legion-Decision-Ref")
        task_id = body.get("task_id")
        with WORLD_LOCK:
            task = WORLD.task_for(agent_id, task_id)
        if task is None:
            return self._denied(path)

        if path == "/read":
            tool = body.get("tool")
            args = body.get("args") or {}
            with WORLD_LOCK:
                if not WORLD.can_read(agent_id, task_id, tool):
                    return self._denied(path)
                status, data = WORLD.call_read(tool, args)
            if status != 200:
                return self._send(status, data)
            obs_id = _new_id("obs")
            log_record("OBSERVATION", observation_id=obs_id, agent_id=agent_id,
                       task_id=task_id, tool=tool, args=args, facts=data,
                       decision_ref=decision_ref)
            return self._send(200, {"observation_id": obs_id, "data": data})

        if path == "/send":
            to = body.get("to")
            msg_body = body.get("body")
            with WORLD_LOCK:
                allowed = WORLD.can_send(agent_id, task_id, to)
            if not allowed or not isinstance(msg_body, str):
                if not allowed:
                    return self._denied(path)
                return self._send(400, {"error": "body must be a string"})
            msg_id = _new_id("msg")
            digest = hashlib.sha256(msg_body.encode("utf-8")).hexdigest()
            rec = log_record("MESSAGE_DELIVERED", message_id=msg_id, agent_id=agent_id,
                             recipient=to, task_id=task_id, body_sha256=digest,
                             decision_ref=decision_ref)
            INBOX.setdefault(to, []).append({
                "message_id": msg_id, "agent_id": agent_id, "sender": agent_id,
                "recipient": to, "task_id": task_id, "body": msg_body,
                "t_mono": rec["t_mono"], "t_rel": rec["t_rel"],
            })
            return self._send(200, {"message_id": msg_id, "status": "delivered"})

        if path == "/wait":
            return self._wait(agent_id, task_id, body, decision_ref=decision_ref)

        if path == "/analyze":
            answer = body.get("answer")
            evidence_refs = body.get("evidence_refs") or []
            with WORLD_LOCK:
                status, payload = WORLD.analyze(task, answer, agent_id=agent_id)
            if status != 200:
                return self._send(status, payload)
            rec_id = _new_id("ana")
            log_record("ANALYSIS_RECORD", record_id=rec_id, agent_id=agent_id,
                       task_id=task_id, facts=answer, evidence_refs=evidence_refs,
                       decision_ref=decision_ref)
            return self._send(200, {"record_id": rec_id, "status": "recorded",
                                    "task_id": task_id, "answer": answer})

        if path == "/reconcile":
            command_id = body.get("command_id")
            with WORLD_LOCK:
                entry = WORLD.reconcile(command_id)
            found = entry is not None
            rec_id = _new_id("rec")
            log_record("RECONCILE", record_id=rec_id, agent_id=agent_id,
                       task_id=task_id, command_id=command_id, found=found,
                       effect_id=entry.get("effect_id") if entry else None,
                       decision_ref=decision_ref)
            return self._send(200, {"found": found,
                                    "effect_id": entry.get("effect_id") if entry else None,
                                    "effect": entry})

        if path == "/done":
            log_record("AGENT_DONE", agent_id=agent_id, task_id=task_id,
                       note=body.get("note"), decision_ref=decision_ref)
            return self._send(200, {"status": "done"})

        return self._send(404, {"error": "not found"})

    # --------------------------------------------------------------
    def _wait(self, agent_id, task_id, body, decision_ref=None):
        event_id = body.get("event_id")
        seconds = body.get("seconds")
        max_s = body.get("max_s")
        try:
            cap = min(float(max_s), 150.0) if max_s is not None else 150.0
        except (TypeError, ValueError):
            return self._send(400, {"error": "max_s must be a number"})
        if cap < 0:
            cap = 0.0
        deadline = time.monotonic() + cap
        # A seconds-wait is satisfied only if the full requested span
        # fits inside the capped wait; otherwise it times out at the cap.
        seconds_deadline = None
        if seconds is not None:
            try:
                seconds_deadline = time.monotonic() + float(seconds)
            except (TypeError, ValueError):
                return self._send(400, {"error": "seconds must be a number"})
        while True:
            fire_due_events()
            with WORLD_LOCK:
                fired = event_id is not None and event_id in WORLD.fired_events()
            now = time.monotonic()
            satisfied = False
            if event_id is not None:
                satisfied = fired
            elif seconds_deadline is not None:
                satisfied = now >= seconds_deadline
            if satisfied:
                log_record("WAIT_OBSERVED", agent_id=agent_id, task_id=task_id,
                           event_id=event_id, decision_ref=decision_ref)
                return self._send(200, {"waited": True, "event_id": event_id,
                                        "seconds": seconds})
            if now >= deadline or STOP.is_set():
                return self._send(200, {"waited": False})
            with EVENT_COND:
                EVENT_COND.wait(timeout=0.2)

    # --------------------------------------------------------------
    def _epoch_transition(self, path, body):
        """Journal an authenticated Authority epoch transition (I4).

        Verifies the proof MAC + hash chain locally against the authority
        key, checks it against live Authority status, appends exactly one
        EPOCH_TRANSITION record (historical records are never rewritten),
        then confirms with Authority. Admissions under the new epoch
        stay denied until confirmation succeeds.
        """
        if not self._bearer_ok(ACTUATOR_TOKEN):
            return self._denied(path)
        proof = body.get("transition_proof") or body.get("proof")
        import hashlib as _hl
        import hmac as _hm
        key = _auth.key_from_env()
        err = None
        if not isinstance(proof, dict) or key is None:
            err = "transition proof missing/unverifiable"
        else:
            b = {k: v for k, v in proof.items() if k not in ("mac", "chain_hash")}
            chain = _hl.sha256(_auth.canonical(
                {"prev": proof.get("prev_chain_hash"), "body": b})).hexdigest()
            mac = _hm.new(key, _auth.canonical({**b, "chain_hash": chain}),
                          _hl.sha256).hexdigest()
            if chain != proof.get("chain_hash") or \
                    not _hm.compare_digest(mac, str(proof.get("mac") or "")):
                err = "transition proof MAC/chain invalid"
            elif proof.get("attempt_uid") != ATTEMPT_UID or \
                    proof.get("world_instance_id") != WORLD_INSTANCE_ID:
                err = "transition proof identity mismatch"
            elif CURRENT_EPOCH[0] is not None and (
                    int(proof.get("from_epoch") or -1) != CURRENT_EPOCH[0]
                    or int(proof.get("to_epoch") or -1) != CURRENT_EPOCH[0] + 1):
                err = "transition proof epoch sequence invalid"
        if err is None:
            try:
                st = _world_client().status()
                if int(st.get("epoch") or -1) != int(proof.get("to_epoch") or -2):
                    err = "transition proof does not match live authority epoch"
            except Exception as exc:
                err = f"attempt authority unavailable ({exc})"
        if err is not None:
            # P0-02 (hypothesis, Lekha's text unavailable): a refused proof is
            # not a permit and changes no epoch; record it as such so feed
            # consumers can never read its to_epoch as an epoch in force.
            log_refusal_record("EPOCH_TRANSITION_REFUSED", error=err,
                               refused_proof_to_epoch=(proof or {}).get("to_epoch")
                               if isinstance(proof, dict) else None,
                               epoch_changed=False)
            return self._send(403, {"error": err})
        rec = log_record("EPOCH_TRANSITION", _switch_epoch=int(proof["to_epoch"]),
                         from_epoch=proof.get("from_epoch"),
                         to_epoch=proof.get("to_epoch"),
                         transition_proof=proof,
                         chain_hash=proof.get("chain_hash"))
        try:
            _world_client().confirm_transition(proof)
        except Exception as exc:
            return self._send(503, {"error": f"transition journaled but unconfirmed: {exc}",
                                    "seq": rec["seq"], "epoch": CURRENT_EPOCH[0]})
        return self._send(200, {"status": "transition_confirmed",
                                "epoch": CURRENT_EPOCH[0], "seq": rec["seq"]})

    # --------------------------------------------------------------
    def _actuate(self, path, body):
        supplied_attempt = body.get("attempt_uid")
        permit = body.get("permit")
        if not self._bearer_ok(ACTUATOR_TOKEN):
            log_refusal_record(
                "WRITE_REFUSED", status=403, command_id=body.get("command_id"),
                task_id=body.get("task_id"), agent_id=body.get("agent_id"),
                tool=body.get("tool"), target=body.get("target"),
                args=body.get("args") or {}, error="actuator token invalid",
                rejected_attempt_uid=supplied_attempt,
                permit_id=(permit or {}).get("permit_id") if isinstance(permit, dict) else None,
                permit_verified=False)
            return self._send(403, {"error": "forbidden"})
        # Independent verification at the world commit boundary (E6e):
        # live authority status + MAC/freshness/epoch/identity + replay.
        try:
            reason = _world_client().verify_fresh(
                permit, task_id=body.get("task_id"),
                command_id=body.get("command_id"))
        except Exception as exc:
            reason = f"attempt authority unavailable ({exc})"
        if reason is None and permit.get("nonce") in USED_NONCES:
            reason = "permit nonce replayed"
        if reason is None and supplied_attempt and \
                supplied_attempt != permit.get("attempt_uid"):
            reason = "attempt identity mismatch"
        if reason is not None:
            terminal = _attempt_terminal()
            log_refusal_record(
                "WRITE_REFUSED", status=403, command_id=body.get("command_id"),
                task_id=body.get("task_id"), agent_id=body.get("agent_id"),
                tool=body.get("tool"), target=body.get("target"),
                args=body.get("args") or {},
                error=("attempt terminal" if terminal else reason),
                rejected_attempt_uid=supplied_attempt or (permit or {}).get("attempt_uid")
                if isinstance(permit, dict) else supplied_attempt,
                permit_id=(permit or {}).get("permit_id") if isinstance(permit, dict) else None,
                rejected_permit_epoch=(permit or {}).get("epoch") if isinstance(permit, dict) else None,
                permit_verified=False)
            return self._send(403, {
                "error": "attempt terminal" if terminal else reason,
                "rejected_attempt_uid": supplied_attempt})
        body["_permit"] = permit
        # WO008-MUSE-001 commit reservation: no execution without a
        # durably registered reservation from live Authority (I2), and no
        # admission until any epoch transition is journaled + confirmed.
        reservation = None
        try:
            _st = _world_client().status()
            if CURRENT_EPOCH[0] is not None and \
                    int(_st.get("epoch") or -1) != CURRENT_EPOCH[0]:
                reason = "epoch transition not journaled in world log"
            elif _st.get("transition_count") and \
                    int(_st.get("confirmed_to_epoch") or 0) < int(_st.get("epoch") or 0):
                reason = "epoch transition unconfirmed"
            else:
                reservation = _world_client().begin_commit(
                    permit, task_id=body.get("task_id"),
                    command_id=body.get("command_id"))
                if reservation.get("state") == "COMMITTED":
                    reason = "command already committed (reservation replay)"
                    reservation = None
                elif reservation.get("state") == "RELEASED_NO_EFFECT" or \
                        body.get("command_id") in FENCED_COMMANDS:
                    reason = "command fenced: released with no effect"
                    reservation = None
                else:
                    # Q3: exactly one executor per reservation.
                    _owner = f"{WORLD_INSTANCE_ID}:{threading.get_ident()}:{uuid.uuid4().hex[:8]}"
                    reservation = _world_client().claim_execution(
                        reservation["reservation_id"], _owner)
                    reservation["_owner"] = _owner
        except Exception as exc:
            reason = f"commit reservation refused ({exc})"
        if reason is not None:
            log_refusal_record(
                "WRITE_REFUSED", status=403, command_id=body.get("command_id"),
                task_id=body.get("task_id"), agent_id=body.get("agent_id"),
                tool=body.get("tool"), target=body.get("target"),
                args=body.get("args") or {}, error=reason,
                rejected_attempt_uid=supplied_attempt,
                permit_id=(permit or {}).get("permit_id") if isinstance(permit, dict) else None,
                rejected_permit_epoch=(permit or {}).get("epoch") if isinstance(permit, dict) else None,
                permit_verified=False)
            return self._send(403, {"error": reason})
        if os.environ.get("STRUCT_FAULT_CRASH_BEFORE_EFFECT"):
            os._exit(70)  # deterministic E8 injection: after reservation, before effect
        command_id = body.get("command_id")
        task_id = body.get("task_id")
        agent_id = body.get("agent_id")
        tool = body.get("tool")
        target = body.get("target")
        args = body.get("args") or {}

        def refused(status, error):
            # Release the reservation only with proof of no effect:
            # the world ledger has no entry for this command (checked
            # by the caller under WORLD_LOCK on the paths that reach a
            # write decision; pre-write refusals never executed).
            if reservation is not None:
                try:
                    with WORLD_LOCK:
                        no_eff = WORLD.reconcile(command_id) is None
                        if no_eff:
                            # P0-01: fence first (durable tombstone + in-memory
                            # set checked before every write), THEN attest.
                            FENCED_COMMANDS.add(command_id)
                            tomb = log_record("TOMBSTONE", command_id=command_id,
                                              reservation_id=reservation["reservation_id"],
                                              epoch=reservation.get("epoch"))
                    if no_eff:
                        _world_client().finalize_commit(
                            reservation["reservation_id"],
                            attestation=_auth.make_world_attestation(
                                _auth.key_from_env(), kind="NO_EFFECT",
                                reservation=reservation, owner=reservation.get("_owner"),
                                world_log_seq=tomb["seq"], fenced=True))
                except Exception:
                    pass  # stays EXECUTING/IN_FLIGHT: revocation blocks, fail closed
            log_record("WRITE_REFUSED", status=status, command_id=command_id,
                       task_id=task_id, agent_id=agent_id, tool=tool,
                       target=target, args=args, error=error)
            return self._send(status, {"error": error})

        if not command_id or not tool or target is None:
            return refused(400, "command_id, tool and target are required")
        with WORLD_LOCK:
            if command_id in FENCED_COMMANDS:
                return refused(409, "command fenced: released with no effect")
            task = WORLD.task_for(agent_id, task_id)
            if task is None:
                return refused(403, "task does not belong to agent")
            if task.get("write_tool") != tool or task.get("target") != target:
                return refused(403, "tool/target not authorised for task")
            # WO008-03: independent semantic binding at the world
            # consequence boundary, from CURRENT world state. This only
            # tightens the permit/tool/target checks above; a refusal
            # here produces no NATIVE_EFFECT and no state mutation.
            try:
                sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "causal_007"))
                from action_binding import world_semantic_refusal as _wsr
                _sem = _wsr(SPEC, WORLD.get_state(), task, tool, target, args)
            except Exception as exc:  # fail closed at the commit boundary
                _sem = f"BINDING_UNAVAILABLE:{type(exc).__name__}"
            if _sem is not None:
                return refused(403, _sem)
            status, result = WORLD.call_write(command_id, tool, target, args)
            entry = None
            if isinstance(result, dict) and result.get("effect_id"):
                entry = WORLD.reconcile(command_id)
        if status == "LOST_REPLY" or (isinstance(status, int) and status == 200):
            USED_NONCES.add((body.get("_permit") or {}).get("nonce"))
            if isinstance(result, dict) and result.get("duplicate"):
                # Idempotent recovery: effect already durable; finalize
                # the reservation against it, never re-execute (I8/E8).
                _eff0 = entry or result
                _rcpt0 = next((r.get("receipt_id") for r in LOG_RECORDS
                               if r.get("kind") == "RECEIPT"
                               and r.get("effect_id") == _eff0.get("effect_id")), None)
                _rseq0 = next((r.get("seq") for r in LOG_RECORDS
                               if r.get("kind") == "RECEIPT" and r.get("receipt_id") == _rcpt0), None)
                if reservation is not None and _rcpt0 and _rseq0 is not None:
                    try:
                        _world_client().finalize_commit(
                            reservation["reservation_id"],
                            attestation=_auth.make_world_attestation(
                                _auth.key_from_env(), kind="COMMITTED",
                                reservation=reservation, owner=reservation.get("_owner"),
                                effect_id=_eff0.get("effect_id"), receipt_id=_rcpt0,
                                world_log_seq=_rseq0))
                    except Exception:
                        pass  # stays IN_FLIGHT/UNKNOWN-reconcilable, no duplicate
                return self._send(200, {"status": "duplicate", "effect": result})
            eff = entry or result
            _permit = body.get("_permit") or {}
            log_record("NATIVE_EFFECT", epoch=(reservation or {}).get("epoch", CURRENT_EPOCH[0]),
                       effect_id=eff.get("effect_id"),
                       command_id=command_id, task_id=task_id, agent_id=agent_id,
                       tool=tool, target=target, args=args,
                       effects_applied=eff.get("effects_applied"),
                       permit_id=_permit.get("permit_id"),
                       permit_epoch=_permit.get("epoch"), permit_verified=True,
                       reservation_id=reservation["reservation_id"] if reservation else None,
                       idempotency_key=reservation["idempotency_key"] if reservation else None)
            receipt_id = _new_id("rcpt")
            _rcpt_rec = log_record("RECEIPT", epoch=(reservation or {}).get("epoch", CURRENT_EPOCH[0]),
                       receipt_id=receipt_id, effect_id=eff.get("effect_id"),
                       command_id=command_id, task_id=task_id, agent_id=agent_id,
                       tool=tool, target=target, args=args,
                       permit_id=_permit.get("permit_id"),
                       permit_epoch=_permit.get("epoch"), permit_verified=True,
                       reservation_id=reservation["reservation_id"] if reservation else None)
            if os.environ.get("STRUCT_FAULT_CRASH_AFTER_EFFECT"):
                os._exit(70)  # deterministic E8 injection: effect+receipt durable, finalize never sent
            # Finalize via Authority; failure preserves UNKNOWN (I5):
            # the effect stays exactly-once and the reply is not success.
            if reservation is not None:
                try:
                    _world_client().finalize_commit(
                        reservation["reservation_id"],
                        attestation=_auth.make_world_attestation(
                            _auth.key_from_env(), kind="COMMITTED",
                            reservation=reservation, owner=reservation.get("_owner"),
                            effect_id=eff.get("effect_id"), receipt_id=receipt_id,
                            world_log_seq=_rcpt_rec["seq"]))
                except Exception as exc:
                    log_record("COMMIT_UNKNOWN",
                               reservation_id=reservation["reservation_id"],
                               effect_id=eff.get("effect_id"),
                               receipt_id=receipt_id, command_id=command_id,
                               error=f"finalize failed: {exc}")
                    return self._send(503, {
                        "status": "UNKNOWN",
                        "effect_id": eff.get("effect_id"),
                        "receipt_id": receipt_id,
                        "reservation_id": reservation["reservation_id"]})
            with EVENT_COND:
                EVENT_COND.notify_all()
            if status == "LOST_REPLY":
                # The reply is lost, not the receipt/effect (logged above).
                # Hold the connection 35 s, then close without a response.
                try:
                    time.sleep(35)
                finally:
                    try:
                        self.connection.shutdown(2)
                    except OSError:
                        pass
                    try:
                        self.connection.close()
                    except OSError:
                        pass
                return
            return self._send(200, {"status": "applied", "effect_id": eff.get("effect_id"),
                                    "receipt_id": receipt_id, "effect": result})
        # 4xx/5xx from /actuate.
        error = result.get("error") if isinstance(result, dict) else "write refused"
        return refused(int(status), error)

    def log_message(self, *args):
        pass


def _watch_parent():
    parent = os.getppid()
    def _run():
        while not STOP.is_set():
            time.sleep(0.5)
            try:
                if os.getppid() != parent:
                    os._exit(4)
            except Exception:
                return
    threading.Thread(target=_run, daemon=True).start()


def main():
    global ATTEMPT_UID, WORLD_INSTANCE_ID
    # E6e: no world without a live attempt authority. The single-use
    # world capability is verified+consumed at the authority (files are
    # evidence only); missing/unreachable/terminal/foreign/reused => refuse.
    try:
        _st = _world_client().status()
    except Exception as exc:
        print(f"REFUSED: attempt authority unavailable: {exc}",
              file=sys.stderr, flush=True)
        return 3
    if _st.get("state") in _attempt.TERMINAL:
        print(f"REFUSED: attempt terminal ({_st.get('state')})",
              file=sys.stderr, flush=True)
        return 3
    if _st.get("state") != "RUNNING":
        print(f"REFUSED: attempt is {_st.get('state')}, not RUNNING",
              file=sys.stderr, flush=True)
        return 3
    ATTEMPT_UID, WORLD_INSTANCE_ID = _st.get("attempt_uid"), _st.get("world_instance_id")
    CURRENT_EPOCH[0] = int(_st.get("epoch") or 1)
    if ATTEMPT_UID and os.environ.get("STRUCT_ATTEMPT_UID") and \
            os.environ["STRUCT_ATTEMPT_UID"] != ATTEMPT_UID:
        print("REFUSED: foreign attempt_uid", file=sys.stderr, flush=True)
        return 3
    try:
        _world_client().consume_capability(
            os.environ.get(_auth.ENV_CAPABILITY) or "")
    except Exception as exc:
        print(f"REFUSED: world capability: {exc}", file=sys.stderr, flush=True)
        return 3
    # E6g: authority capability above is the sole world-start authority;
    # no file capability is believed.
    # P0-14: a second World in the same attempt is impossible. If the
    # run dir already has a WORLD_START, fail closed before touching state.
    if os.path.exists(LOG_PATH):
        try:
            with open(LOG_PATH, encoding="utf-8", errors="ignore") as fh:
                if "WORLD_START" in fh.read():
                    print("REFUSED: WORLD_START already present; attempt already started",
                          file=sys.stderr, flush=True)
                    return 3
        except OSError:
            pass
    _watch_parent()
    # NATIVE_STATE_BEFORE at start, then WORLD_START as log record 1.
    before = {"read_mono": time.monotonic(), "state": WORLD.get_state(), "effects": []}
    with open(os.path.join(OUT_DIR, "NATIVE_STATE_BEFORE.json"), "w") as fh:
        json.dump(before, fh, indent=1)
    log_record("WORLD_START", world_id=SPEC.get("world_id"),
               world_sha256=WORLD_SHA256, pid=os.getpid())

    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    server.daemon_threads = True

    def _on_signal(signum, frame):
        STOP.set()
        with EVENT_COND:
            EVENT_COND.notify_all()

    signal.signal(signal.SIGTERM, _on_signal)
    try:
        signal.signal(signal.SIGINT, _on_signal)
    except (ValueError, OSError):
        pass

    events_thread = threading.Thread(target=_event_thread, daemon=True)
    events_thread.start()
    serve_thread = threading.Thread(target=server.serve_forever,
                                    kwargs={"poll_interval": 0.1}, daemon=True)
    serve_thread.start()
    try:
        while not STOP.wait(0.2):
            pass
    finally:
        server.shutdown()
        server.server_close()
        events_thread.join(timeout=2)
        try:
            os.fsync(_LOG_FD)
        except OSError:
            pass
        try:
            os.close(_LOG_FD)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
