"""Attempt authority service (WO-LEGION100-CAUSAL-CLOSURE-007, E6e).

ONE authoritative source of attempt state. The supervisor spawns this
process per attempt; it alone holds, in memory only:

  attempt_uid, world_instance_id, state, monotonically increasing epoch
  (bumped on EVERY lifecycle transition), and the per-attempt HMAC key.

The key, gate/world/supervisor tokens and the world-capability plaintext
never touch the run directory and never enter an agent's environment.
They reach the gate (mission-host process) and the world (world_server
process) only through their own inherited spawn environment.

Files in the run directory (attempt.json etc.) are EVIDENCE, never
authority: nothing in the gate or the world believes them any more.

Permit format (JSON, MAC'd):
  {permit_id, attempt_uid, world_instance_id, epoch, task_id,
   command_id, nonce, exp} + "mac" = HMAC-SHA256(key, canonical payload)

Permits are issued ONLY while state == RUNNING. On any transition out of
RUNNING the epoch is bumped; on a terminal transition the key is
destroyed, so no permit can ever verify again.

Run standalone (supervisor-owned):
  python -I attempt_authority.py --port N
Env (authority process only): ATTEMPT_AUTHORITY_UID,
ATTEMPT_AUTHORITY_SUPERVISOR_TOKEN, ATTEMPT_AUTHORITY_GATE_TOKEN,
ATTEMPT_AUTHORITY_WORLD_TOKEN.
Stdlib only.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REGISTERED = "REGISTERED"
RUNNING = "RUNNING"
COMPLETED = "COMPLETED"
INTERRUPTED = "INTERRUPTED"
TERMINAL = frozenset({COMPLETED, INTERRUPTED})
_TRANSITIONS = {REGISTERED: frozenset({RUNNING, INTERRUPTED}),
                RUNNING: frozenset({COMPLETED, INTERRUPTED}),
                COMPLETED: frozenset(), INTERRUPTED: frozenset()}

ENV_URL = "STRUCT_AUTHORITY_URL"
ENV_KEY = "STRUCT_AUTHORITY_KEY"
ENV_GATE_TOKEN = "STRUCT_AUTHORITY_GATE_TOKEN"
ENV_WORLD_TOKEN = "STRUCT_AUTHORITY_WORLD_TOKEN"
ENV_CAPABILITY = "STRUCT_WORLD_CAPABILITY"
ENV_STATUS_TOKEN = "STRUCT_AUTHORITY_STATUS_TOKEN"


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode()


def make_permit(key: bytes, *, attempt_uid, world_instance_id, epoch,
                task_id, command_id, ttl_s=300.0) -> dict:
    permit = {"permit_id": "prm-" + uuid.uuid4().hex[:16],
              "attempt_uid": attempt_uid,
              "world_instance_id": world_instance_id,
              "epoch": int(epoch), "task_id": task_id,
              "command_id": command_id, "nonce": uuid.uuid4().hex,
              "exp": time.time() + float(ttl_s)}
    permit["mac"] = hmac.new(key, canonical(
        {k: v for k, v in permit.items() if k != "mac"}),
        hashlib.sha256).hexdigest()
    return permit


def verify_permit(key, permit, *, attempt_uid=None, world_instance_id=None,
                  epoch=None, task_id=None, command_id=None):
    """Return None if valid, else the refusal reason. Deny by default."""
    if key is None:
        return "permit unverifiable: authority key destroyed/unavailable"
    if not isinstance(permit, dict) or not permit.get("mac"):
        return "permit missing"
    expected = hmac.new(key, canonical(
        {k: v for k, v in permit.items() if k != "mac"}),
        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(permit["mac"]), expected):
        return "permit MAC invalid"
    if time.time() > float(permit.get("exp") or 0):
        return "permit expired"
    if attempt_uid is not None and permit.get("attempt_uid") != attempt_uid:
        return "permit attempt_uid mismatch"
    if world_instance_id is not None and \
            permit.get("world_instance_id") != world_instance_id:
        return "permit world_instance_id mismatch"
    if epoch is not None and int(permit.get("epoch") or -1) != int(epoch):
        return "permit epoch stale"
    if task_id is not None and permit.get("task_id") != task_id:
        return "permit task_id mismatch"
    if command_id is not None and permit.get("command_id") != command_id:
        return "permit command_id mismatch"
    return None


def key_from_env(env=None):
    raw = (os.environ if env is None else env).get(ENV_KEY) or ""
    try:
        return bytes.fromhex(raw) if raw else None
    except ValueError:
        return None


RES_IN_FLIGHT = "IN_FLIGHT"
RES_COMMITTED = "COMMITTED"
RES_RELEASED = "RELEASED_NO_EFFECT"
RES_UNKNOWN = "UNKNOWN"
# LOGIC-ZTL-LEGION-001: one owner may execute a reservation (claim), and the
# two outcomes are absorbing: a COMMITTED or RELEASED reservation never moves.
RES_EXECUTING = "EXECUTING"
RES_STATES = frozenset({RES_IN_FLIGHT, RES_EXECUTING, RES_COMMITTED, RES_RELEASED, RES_UNKNOWN})
RES_ABSORBING = frozenset({RES_COMMITTED, RES_RELEASED})
RES_PENDING = frozenset({RES_IN_FLIGHT, RES_EXECUTING})


class AuthorityStoreCorrupt(RuntimeError):
    """The durable store exists but cannot be trusted: fail closed (D11)."""


def _attest_key(key):
    # Domain-separated from permit MACs: an attestation can never verify as a
    # permit and vice versa.
    return hmac.new(key, b"LEGION-WORLD-ATTESTATION-v1", hashlib.sha256).digest()


def make_world_attestation(key, *, kind, reservation, owner=None, effect_id=None,
                           receipt_id=None, world_log_seq=None, fenced=False):
    """World evidence for finalize_commit, bound to ONE reservation.

    kind COMMITTED: effect_id + receipt_id journaled by the world.
    kind NO_EFFECT: the world has journaled a TOMBSTONE for command_id and
    will refuse any later execution of it (fenced=True is required).
    """
    body = {"kind": kind, "reservation_id": reservation["reservation_id"],
            "command_id": reservation.get("command_id"),
            "attempt_uid": reservation.get("attempt_uid"),
            "world_instance_id": reservation.get("world_instance_id"),
            "epoch": reservation.get("epoch"), "owner": owner,
            "effect_id": effect_id, "receipt_id": receipt_id,
            "world_log_seq": world_log_seq, "fenced": bool(fenced)}
    return {**body, "mac": hmac.new(_attest_key(key), canonical(body),
                                    hashlib.sha256).hexdigest()}


def verify_world_attestation(key, att, reservation):
    """None if `att` is an authentic world attestation for `reservation`."""
    if key is None:
        return "attestation unverifiable: authority key unavailable"
    if not isinstance(att, dict) or not att.get("mac"):
        return "world attestation missing"
    body = {k: v for k, v in att.items() if k != "mac"}
    expected = hmac.new(_attest_key(key), canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(att.get("mac")), expected):
        return "world attestation MAC invalid"
    for f in ("reservation_id", "command_id", "attempt_uid", "world_instance_id", "epoch"):
        if att.get(f) != reservation.get(f):
            return f"world attestation not bound to this reservation ({f})"
    if att.get("world_log_seq") is None:
        return "world attestation names no journal record"
    if att.get("kind") == "COMMITTED":
        if not att.get("effect_id") or not att.get("receipt_id"):
            return "COMMITTED attestation without effect_id/receipt_id"
    elif att.get("kind") == "NO_EFFECT":
        if att.get("fenced") is not True:
            return "NO_EFFECT attestation without a world fence (tombstone)"
    else:
        return "unknown attestation kind"
    return None


def _fsync_dir(path):
    try:
        fd = os.open(path or ".", os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _store_problem(data):
    """Schema check of a loaded store; None if acceptable."""
    if not isinstance(data, dict):
        return "not an object"
    if data.get("state") not in (REGISTERED, RUNNING, COMPLETED, INTERRUPTED):
        return f"state {data.get('state')!r}"
    ep = data.get("epoch")
    if not isinstance(ep, int) or isinstance(ep, bool) or ep < 1:
        return f"epoch {ep!r}"
    if not isinstance(data.get("attempt_uid"), str):
        return "attempt_uid"
    res = data.get("reservations", {})
    if not isinstance(res, dict) or any(
            not isinstance(r, dict) or r.get("state") not in RES_STATES
            for r in res.values()):
        return "reservations"
    if not isinstance(data.get("transitions", []), list):
        return "transitions"
    return None


class AuthorityState:
    """Durable authority state (WO008-MUSE-001).

    begin_commit/advance_epoch are serialized by this process's lock AND
    every mutation is fsync-persisted (atomic replace) BEFORE the response
    is returned, when a store path is configured. A reservation therefore
    survives authority crash; an IN_FLIGHT/UNKNOWN reservation blocks
    epoch revocation until the world reconciles it (I8).
    """

    def __init__(self, attempt_uid, *, key=None, store_path=None):
        self.attempt_uid = attempt_uid
        self.world_instance_id = None
        self.state = REGISTERED
        self.epoch = 1
        self.key = key if key is not None else secrets.token_bytes(32)
        self._cap_hash = None
        self._cap_consumed = False
        self.lock = threading.RLock()
        self.store_path = store_path or os.environ.get(
            "ATTEMPT_AUTHORITY_STORE") or None
        self.revoking = False
        self.reservations = {}   # reservation_id -> dict (durable)
        self.transitions = []    # authenticated epoch transition chain
        self.confirmed_to_epoch = None
        # D08: after advance_epoch, no admission until the world journals and
        # confirms the transition proof.
        self.awaiting_confirm = False
        # P0-01: command_id -> reservation_id released with a world fence.
        self.fenced_commands = {}
        if self.store_path:
            self._load()

    # ---------------------------------------------------------- durability
    def _persist(self):
        if not self.store_path:
            return
        data = {"attempt_uid": self.attempt_uid,
                "world_instance_id": self.world_instance_id,
                "state": self.state, "epoch": self.epoch,
                "key_hex": self.key.hex() if self.key else None,
                "cap_hash": self._cap_hash,
                "cap_consumed": self._cap_consumed,
                "revoking": self.revoking,
                "reservations": self.reservations,
                "transitions": self.transitions,
                "confirmed_to_epoch": self.confirmed_to_epoch,
                "awaiting_confirm": self.awaiting_confirm,
                "fenced_commands": self.fenced_commands}
        d = os.path.dirname(os.path.abspath(self.store_path))
        os.makedirs(d, exist_ok=True)
        tmp = self.store_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.store_path)
        _fsync_dir(d)

    def _load(self):
        # D11: a MISSING store is a fresh attempt; a store that exists but
        # cannot be read or validated is never silently re-initialised.
        if not os.path.exists(self.store_path):
            return
        try:
            data = json.loads(open(self.store_path, encoding="utf-8").read())
        except (OSError, ValueError) as exc:
            raise AuthorityStoreCorrupt(f"authority store unreadable: {exc}") from exc
        problem = _store_problem(data)
        if problem:
            raise AuthorityStoreCorrupt(f"authority store invalid: {problem}")
        if data.get("attempt_uid") != self.attempt_uid:
            raise ValueError("authority store attempt mismatch")
        self.world_instance_id = data.get("world_instance_id")
        self.state = data.get("state") or REGISTERED
        self.epoch = int(data.get("epoch") or 1)
        if data.get("key_hex"):
            self.key = bytes.fromhex(data["key_hex"])
        self._cap_hash = data.get("cap_hash")
        self._cap_consumed = bool(data.get("cap_consumed"))
        self.revoking = bool(data.get("revoking"))
        self.reservations = dict(data.get("reservations") or {})
        self.transitions = list(data.get("transitions") or [])
        self.confirmed_to_epoch = data.get("confirmed_to_epoch")
        self.awaiting_confirm = bool(data.get("awaiting_confirm"))
        self.fenced_commands = dict(data.get("fenced_commands") or {})
        if self.state in TERMINAL:
            self.key = None

    def status(self):
        with self.lock:
            return {"attempt_uid": self.attempt_uid,
                    "world_instance_id": self.world_instance_id,
                    "state": self.state, "epoch": self.epoch,
                    "revoking": self.revoking,
                    "transition_count": len(self.transitions),
                    "confirmed_to_epoch": self.confirmed_to_epoch,
                    "awaiting_confirm": self.awaiting_confirm,
                    "reservations": {
                        rid: r.get("state") for rid, r in
                        sorted(self.reservations.items())}}

    def transition(self, to_state, *, world_instance_id=None):
        with self.lock:
            if self.state in TERMINAL:
                raise ValueError(f"attempt terminal ({self.state})")
            if to_state not in _TRANSITIONS.get(self.state, frozenset()):
                raise ValueError(f"illegal transition {self.state}->{to_state}")
            if world_instance_id is not None:
                self.world_instance_id = world_instance_id
            self.state = to_state
            self.epoch += 1
            if to_state in TERMINAL:
                self.key = None  # destroyed: nothing verifies ever again
            self._persist()
            return self.status()

    # ------------------------------------------------- commit reservations
    def begin_commit(self, permit, *, task_id=None, command_id=None):
        """Durably register a commit reservation BEFORE any execution.

        Validates MAC/expiry/nonce/command/task/identity against LIVE
        state, requires RUNNING + current epoch + no revocation in
        progress. Returns (reservation, None) or (None, reason). The
        reservation is fsync-persisted before this returns (I2). Retry
        with the same permit nonce+command returns the existing
        reservation (crash recovery); nonce/command reuse with different
        binding is denied (E4).
        """
        with self.lock:
            if self.revoking:
                return None, "commit refused: epoch revocation in progress"
            if self.state != RUNNING:
                return None, f"commit refused: attempt is {self.state}, not RUNNING"
            if self.awaiting_confirm:
                return None, "commit refused: epoch transition not confirmed by the world journal"
            if command_id in self.fenced_commands:
                return None, "commit refused: command fenced (released with no effect)"
            err = verify_permit(
                self.key, permit, attempt_uid=self.attempt_uid,
                world_instance_id=self.world_instance_id, epoch=self.epoch,
                task_id=task_id, command_id=command_id)
            if err:
                return None, err
            if not permit.get("nonce"):
                return None, "permit nonce missing"
            idem = hashlib.sha256(canonical({
                "attempt_uid": self.attempt_uid,
                "world_instance_id": self.world_instance_id,
                "command_id": command_id,
                "nonce": permit.get("nonce")})).hexdigest()
            for r in self.reservations.values():
                if r.get("nonce") == permit.get("nonce") and \
                        r.get("command_id") != command_id:
                    return None, "permit nonce replayed for another command"
                if r.get("command_id") == command_id and \
                        r.get("nonce") != permit.get("nonce"):
                    return None, "command already reserved with another nonce"
                if r.get("idempotency_key") == idem:
                    return dict(r), None  # idempotent retry / recovery
            reservation = {
                "reservation_id": "rsv-" + uuid.uuid4().hex[:16],
                "idempotency_key": idem,
                "permit_id": permit.get("permit_id"),
                "nonce": permit.get("nonce"),
                "command_id": command_id, "task_id": task_id,
                "attempt_uid": self.attempt_uid,
                "world_instance_id": self.world_instance_id,
                "epoch": self.epoch, "state": RES_IN_FLIGHT,
                "effect_id": None, "receipt_id": None,
                "created_seq": len(self.reservations) + 1}
            self.reservations[reservation["reservation_id"]] = reservation
            self._persist()  # durable BEFORE execution is authorized
            return dict(reservation), None

    def claim_execution(self, reservation_id, owner):
        """Q3: exactly one owner may execute a reservation.

        CAS IN_FLIGHT -> EXECUTING(owner), only in the reservation's own
        epoch with no revocation pending. The same owner re-claiming is
        idempotent; any other claimant is refused.
        """
        with self.lock:
            r = self.reservations.get(reservation_id or "")
            if r is None:
                return None, "unknown reservation"
            if not owner:
                return None, "claim without owner"
            if r["state"] == RES_EXECUTING:
                if r.get("owner") == owner:
                    return dict(r), None
                return None, "reservation already claimed by another executor"
            if r["state"] != RES_IN_FLIGHT:
                return None, f"reservation is {r['state']}, not claimable"
            if self.revoking or self.awaiting_confirm or r.get("epoch") != self.epoch:
                return None, "claim refused: epoch revoked or transition unconfirmed"
            r.update(state=RES_EXECUTING, owner=owner)
            self._persist()
            return dict(r), None

    def finalize_commit(self, reservation_id, *, attestation=None, unknown=False):
        """Finalize ONLY from an authentic world attestation (D09/D10).

        COMMITTED and RELEASED_NO_EFFECT are absorbing. A missing or
        invalid attestation changes nothing: the reservation stays pending
        and keeps blocking revocation (fail closed). `unknown=True` records
        that the outcome could not be established (blocks revocation, I8).
        """
        with self.lock:
            r = self.reservations.get(reservation_id or "")
            if r is None:
                return None, "unknown reservation"
            if unknown and attestation is None:
                if r["state"] in RES_ABSORBING:
                    return dict(r), None
                r["state"] = RES_UNKNOWN
                self._persist()
                return dict(r), None
            err = verify_world_attestation(self.key, attestation, r)
            if err:
                return None, err
            kind = attestation["kind"]
            if r["state"] in RES_ABSORBING:
                same = (kind == "COMMITTED" and r["state"] == RES_COMMITTED
                        and r.get("effect_id") == attestation.get("effect_id")) or \
                       (kind == "NO_EFFECT" and r["state"] == RES_RELEASED)
                if same:
                    return dict(r), None
                return None, f"reservation already {r['state']}; conflicting {kind} refused"
            if kind == "COMMITTED":
                r.update(state=RES_COMMITTED, effect_id=attestation["effect_id"],
                         receipt_id=attestation["receipt_id"],
                         world_log_seq=attestation["world_log_seq"])
            else:  # NO_EFFECT, fenced
                if r["state"] == RES_EXECUTING and attestation.get("owner") != r.get("owner"):
                    return None, "NO_EFFECT for an executing reservation must come from its owner"
                if r["state"] == RES_UNKNOWN:
                    return None, "UNKNOWN can only be resolved by reconciliation evidence of an effect"
                r.update(state=RES_RELEASED, world_log_seq=attestation["world_log_seq"])
                self.fenced_commands[r.get("command_id")] = r["reservation_id"]
            self._persist()
            return dict(r), None

    def verify_transition_proof(self, proof):
        """None if proof is the authentic head of the transition chain."""
        if not isinstance(proof, dict) or self.key is None:
            return "transition proof unverifiable"
        body = {k: v for k, v in proof.items() if k not in ("mac", "chain_hash")}
        expected_chain = hashlib.sha256(canonical({
            "prev": proof.get("prev_chain_hash"), "body": body})).hexdigest()
        if proof.get("chain_hash") != expected_chain:
            return "transition chain hash mismatch"
        expected_mac = hmac.new(self.key, canonical(
            {**body, "chain_hash": expected_chain}),
            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(proof.get("mac") or ""), expected_mac):
            return "transition proof MAC invalid"
        if proof.get("attempt_uid") != self.attempt_uid or \
                proof.get("world_instance_id") != self.world_instance_id:
            return "transition proof identity mismatch"
        if int(proof.get("to_epoch") or -1) != self.epoch:
            return "transition proof epoch is not current"
        if not self.transitions or \
                self.transitions[-1].get("chain_hash") != proof.get("chain_hash"):
            return "transition proof is not the chain head"
        return None

    def confirm_transition(self, proof):
        with self.lock:
            err = self.verify_transition_proof(proof)
            if err:
                return None, err
            self.confirmed_to_epoch = int(proof["to_epoch"])
            self.awaiting_confirm = False
            self._persist()
            return self.status(), None

    def advance_epoch(self):
        """Durable revocation barrier (WO008-MUSE-001).

        Linearization: revoking=True is persisted first (new reservations
        denied from that instant), then every IN_FLIGHT reservation must
        be resolved; UNKNOWN blocks completion forever (I8). Only then
        is the epoch durably advanced and an authenticated, hash-chained
        transition proof issued. Admissions resume only after the world
        journals the proof and it is confirmed (confirm_transition).
        """
        with self.lock:
            if self.state in TERMINAL:
                raise ValueError("attempt terminal")
            if not self.revoking:
                self.revoking = True
                self._persist()  # barrier is durable before any denial relies on it
            unknown = [r["reservation_id"] for r in self.reservations.values()
                       if r["state"] == RES_UNKNOWN]
            if unknown:
                raise ValueError(
                    f"REVOCATION_BLOCKED_UNKNOWN:{','.join(sorted(unknown))}")
            inflight = [r["reservation_id"] for r in self.reservations.values()
                        if r["state"] in RES_PENDING]
            if inflight:
                raise ValueError(
                    f"REVOCATION_PENDING_IN_FLIGHT:{','.join(sorted(inflight))}")
            if self.key is None:
                raise ValueError("authority key unavailable")
            prev = self.transitions[-1]["chain_hash"] if self.transitions else "GENESIS"
            body = {"attempt_uid": self.attempt_uid,
                    "world_instance_id": self.world_instance_id,
                    "from_epoch": self.epoch, "to_epoch": self.epoch + 1,
                    "prev_chain_hash": prev}
            chain = hashlib.sha256(canonical(
                {"prev": prev, "body": body})).hexdigest()
            proof = {**body, "chain_hash": chain,
                     "mac": hmac.new(self.key, canonical(
                         {**body, "chain_hash": chain}),
                         hashlib.sha256).hexdigest()}
            self.transitions.append(proof)
            self.epoch += 1
            self.revoking = False
            self.awaiting_confirm = True
            self._persist()
            out = self.status()
            out["transition_proof"] = dict(proof)
            return out

    def issue_permit(self, *, task_id, command_id, ttl_s=300.0):
        with self.lock:
            if self.state != RUNNING or self.key is None:
                return None, f"permit issuance refused: attempt is {self.state}, not RUNNING"
            if self.awaiting_confirm:
                return None, "permit issuance refused: epoch transition not confirmed"
            return make_permit(self.key, attempt_uid=self.attempt_uid,
                               world_instance_id=self.world_instance_id,
                               epoch=self.epoch, task_id=task_id,
                               command_id=command_id, ttl_s=ttl_s), None

    def mint_capability(self):
        with self.lock:
            if self.state != RUNNING:
                return None, f"capability refused: attempt is {self.state}"
            token = secrets.token_hex(32)
            self._cap_hash = hashlib.sha256(token.encode()).hexdigest()
            self._cap_consumed = False
            self._persist()
            return token, None

    def consume_capability(self, token):
        with self.lock:
            if self.state in TERMINAL:
                return f"capability refused: attempt terminal ({self.state})"
            if self.state != RUNNING:
                return f"capability refused: attempt is {self.state}, not RUNNING"
            if self._cap_consumed:
                return "capability already consumed"
            got = hashlib.sha256((token or "").encode()).hexdigest()
            if not token or not self._cap_hash or \
                    not hmac.compare_digest(got, self._cap_hash):
                return "capability mismatch"
            self._cap_consumed = True
            self._persist()
            return None


def make_server(state: AuthorityState, *, supervisor_token, gate_token,
                world_token, port=0, status_token=""):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, obj):
            body = json.dumps(obj, default=str).encode()
            try:
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                pass

        def _body(self):
            try:
                n = int(self.headers.get("Content-Length", "0") or "0")
            except ValueError:
                n = 0
            try:
                obj = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return {}
            return obj if isinstance(obj, dict) else {}

        def _role(self):
            auth = self.headers.get("Authorization", "")
            for role, tok in (("supervisor", supervisor_token),
                              ("gate", gate_token), ("world", world_token),
                              ("status", status_token)):
                if tok and auth == f"Bearer {tok}":
                    return role
            return None

        def do_GET(self):
            if self.path == "/health":
                return self._send(200, {"ok": True})
            if self.path == "/status":
                if self._role() is None:
                    return self._send(403, {"error": "forbidden"})
                return self._send(200, state.status())
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            body = self._body()
            role = self._role()
            if self.path == "/transition":
                if role != "supervisor":
                    return self._send(403, {"error": "forbidden"})
                try:
                    st = state.transition(
                        body.get("to_state") or "",
                        world_instance_id=body.get("world_instance_id"))
                except ValueError as exc:
                    return self._send(409, {"error": str(exc)})
                return self._send(200, st)
            if self.path == "/advance-epoch":
                if role != "supervisor":
                    return self._send(403, {"error": "forbidden"})
                try:
                    return self._send(200, state.advance_epoch())
                except ValueError as exc:
                    return self._send(409, {"error": str(exc)})
            if self.path == "/permit":
                if role != "gate":
                    return self._send(403, {"error": "forbidden"})
                permit, err = state.issue_permit(
                    task_id=body.get("task_id"),
                    command_id=body.get("command_id"),
                    ttl_s=float(body.get("ttl_s") or 300.0))
                if permit is None:
                    return self._send(403, {"error": err})
                return self._send(200, {"permit": permit})
            if self.path == "/begin-commit":
                if role != "world":
                    return self._send(403, {"error": "forbidden"})
                reservation, err = state.begin_commit(
                    body.get("permit"), task_id=body.get("task_id"),
                    command_id=body.get("command_id"))
                if reservation is None:
                    return self._send(403, {"error": err})
                return self._send(200, {"reservation": reservation})
            if self.path == "/finalize-commit":
                if role != "world":
                    return self._send(403, {"error": "forbidden"})
                reservation, err = state.finalize_commit(
                    body.get("reservation_id"),
                    attestation=body.get("attestation"),
                    unknown=bool(body.get("unknown")))
                if reservation is None:
                    return self._send(409, {"error": err})
                return self._send(200, {"reservation": reservation})
            if self.path == "/claim-execution":
                if role != "world":
                    return self._send(403, {"error": "forbidden"})
                reservation, err = state.claim_execution(
                    body.get("reservation_id"), body.get("owner"))
                if reservation is None:
                    return self._send(409, {"error": err})
                return self._send(200, {"reservation": reservation})
            if self.path == "/confirm-transition":
                if role not in ("world", "supervisor"):
                    return self._send(403, {"error": "forbidden"})
                st, err = state.confirm_transition(body.get("proof"))
                if st is None:
                    return self._send(403, {"error": err})
                return self._send(200, st)
            if self.path == "/world-capability":
                if role != "supervisor":
                    return self._send(403, {"error": "forbidden"})
                token, err = state.mint_capability()
                if token is None:
                    return self._send(403, {"error": err})
                return self._send(200, {"token": token})
            if self.path == "/consume-world-capability":
                if role != "world":
                    return self._send(403, {"error": "forbidden"})
                err = state.consume_capability(body.get("token") or "")
                if err:
                    return self._send(403, {"error": err})
                return self._send(200, state.status())
            return self._send(404, {"error": "not found"})

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


class AuthorityClient:
    """Gate/world/supervisor client. Every failure is a denial reason."""

    def __init__(self, url, token, *, key=None, timeout=3.0):
        self.url = (url or "").rstrip("/")
        self.token = token or ""
        self.key = key
        self.timeout = timeout

    def _call(self, method, path, body=None):
        if not self.url:
            raise AuthorityUnavailable("attempt authority not configured")
        req = urllib.request.Request(
            self.url + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.token}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read().decode() or "{}")
            except Exception:
                return exc.code, {}
        except Exception as exc:
            raise AuthorityUnavailable(
                f"attempt authority unreachable: {type(exc).__name__}") from exc

    def status(self):
        code, payload = self._call("GET", "/status")
        if code != 200:
            raise AuthorityUnavailable(f"attempt authority status {code}")
        return payload

    def request_permit(self, *, task_id, command_id, ttl_s=300.0):
        code, payload = self._call("POST", "/permit", {
            "task_id": task_id, "command_id": command_id, "ttl_s": ttl_s})
        if code != 200 or not isinstance(payload.get("permit"), dict):
            raise AuthorityUnavailable(
                f"permit refused: {(payload or {}).get('error') or code}")
        return payload["permit"]

    def verify_fresh(self, permit, *, task_id=None, command_id=None):
        """Local MAC verification + live epoch/state check. None = valid."""
        st = self.status()  # raises AuthorityUnavailable -> caller DENYs
        if st.get("state") != RUNNING:
            return f"attempt is {st.get('state')}, not RUNNING"
        return verify_permit(
            self.key, permit, attempt_uid=st.get("attempt_uid"),
            world_instance_id=st.get("world_instance_id"),
            epoch=st.get("epoch"), task_id=task_id, command_id=command_id)

    def transition(self, to_state, *, world_instance_id=None):
        code, payload = self._call("POST", "/transition", {
            "to_state": to_state, "world_instance_id": world_instance_id})
        if code != 200:
            raise AuthorityUnavailable(
                f"transition refused: {(payload or {}).get('error') or code}")
        return payload

    def advance_epoch(self):
        code, payload = self._call("POST", "/advance-epoch", {})
        if code != 200:
            raise AuthorityUnavailable("advance-epoch refused")
        return payload

    # LOGIC-ZTL-LEGION-001: the world called begin_commit/finalize_commit on
    # this client, but the methods did not exist, so every /actuate failed at
    # the reservation step (AttributeError swallowed as a refusal).
    def begin_commit(self, permit, *, task_id=None, command_id=None):
        code, payload = self._call("POST", "/begin-commit", {
            "permit": permit, "task_id": task_id, "command_id": command_id})
        if code != 200 or not isinstance(payload.get("reservation"), dict):
            raise AuthorityUnavailable(
                f"begin-commit refused: {(payload or {}).get('error') or code}")
        return payload["reservation"]

    def claim_execution(self, reservation_id, owner):
        code, payload = self._call("POST", "/claim-execution", {
            "reservation_id": reservation_id, "owner": owner})
        if code != 200 or not isinstance(payload.get("reservation"), dict):
            raise AuthorityUnavailable(
                f"claim refused: {(payload or {}).get('error') or code}")
        return payload["reservation"]

    def finalize_commit(self, reservation_id, *, attestation=None, unknown=False):
        code, payload = self._call("POST", "/finalize-commit", {
            "reservation_id": reservation_id, "attestation": attestation,
            "unknown": bool(unknown)})
        if code != 200 or not isinstance(payload.get("reservation"), dict):
            raise AuthorityUnavailable(
                f"finalize refused: {(payload or {}).get('error') or code}")
        return payload["reservation"]

    def confirm_transition(self, proof):
        code, payload = self._call("POST", "/confirm-transition",
                                   {"proof": proof})
        if code != 200:
            raise AuthorityUnavailable(
                f"confirm-transition refused: {(payload or {}).get('error') or code}")
        return payload

    def mint_capability(self):
        code, payload = self._call("POST", "/world-capability", {})
        if code != 200:
            raise AuthorityUnavailable(
                f"capability refused: {(payload or {}).get('error') or code}")
        return payload["token"]

    def consume_capability(self, token):
        code, payload = self._call(
            "POST", "/consume-world-capability", {"token": token or ""})
        if code != 200:
            raise AuthorityUnavailable(
                f"world capability refused: {(payload or {}).get('error') or code}")
        return payload


class AuthorityUnavailable(RuntimeError):
    pass


def client_from_env(role, env=None):
    e = os.environ if env is None else env
    token_env = {"gate": ENV_GATE_TOKEN, "world": ENV_WORLD_TOKEN,
                 "status": ENV_STATUS_TOKEN}.get(role)
    token = e.get(token_env) if token_env else ""
    if role == "status" and not token:
        token = e.get(ENV_GATE_TOKEN) or e.get(ENV_WORLD_TOKEN) or ""
    return AuthorityClient(e.get(ENV_URL) or "",
                           token,
                           key=key_from_env(e))


class TestAuthority:
    """Explicit TEST authority for unit tests (no admit-without-authority).

    In-process loopback server with a known key; the ONLY sanctioned way
    for a unit test to obtain a gate/world authority context.
    """

    def __init__(self, attempt_uid=None, world_instance_id=None,
                 store_path=None):
        self.state = AuthorityState(attempt_uid or uuid.uuid4().hex,
                                    store_path=store_path)
        self.supervisor_token = secrets.token_hex(16)
        self.gate_token = secrets.token_hex(16)
        self.world_token = secrets.token_hex(16)
        self.status_token = secrets.token_hex(16)
        self.server = make_server(
            self.state, supervisor_token=self.supervisor_token,
            gate_token=self.gate_token, world_token=self.world_token,
            status_token=self.status_token)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05},
                                       daemon=True)
        self.thread.start()
        self.supervisor = AuthorityClient(self.url, self.supervisor_token)
        self.state.transition(RUNNING, world_instance_id=(
            world_instance_id or uuid.uuid4().hex))
        self.capability = self.supervisor.mint_capability()

    @property
    def attempt_uid(self):
        return self.state.attempt_uid

    @property
    def world_instance_id(self):
        return self.state.world_instance_id

    @property
    def epoch(self):
        return self.state.epoch

    def env(self, role="gate"):
        out = {ENV_URL: self.url, ENV_KEY: self.state.key.hex()
               if self.state.key else "",
               ENV_GATE_TOKEN: self.gate_token,
               ENV_WORLD_TOKEN: self.world_token,
               ENV_STATUS_TOKEN: self.status_token}
        if role == "world":
            out[ENV_CAPABILITY] = self.capability
        return out

    def gate_client(self):
        return AuthorityClient(self.url, self.gate_token, key=self.state.key)

    def world_client(self):
        return AuthorityClient(self.url, self.world_token, key=self.state.key)

    def transition(self, to_state):
        return self.supervisor.transition(to_state)

    def kill(self):
        """Simulate authority death (N3): server gone, clients DENY."""
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass

    def stop(self):
        self.kill()


def main():
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", type=int, required=True)
    args = p.parse_args()
    state = AuthorityState(os.environ["ATTEMPT_AUTHORITY_UID"],
                           key=bytes.fromhex(os.environ["ATTEMPT_AUTHORITY_KEY"]))
    server = make_server(
        state,
        supervisor_token=os.environ["ATTEMPT_AUTHORITY_SUPERVISOR_TOKEN"],
        gate_token=os.environ["ATTEMPT_AUTHORITY_GATE_TOKEN"],
        world_token=os.environ["ATTEMPT_AUTHORITY_WORLD_TOKEN"],
        status_token=os.environ.get("ATTEMPT_AUTHORITY_STATUS_TOKEN", ""),
        port=args.port)
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
