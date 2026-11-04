"""WP-A/B/C authoritative causal sidecar (separate OS process, stdlib only).

This is the component that sits between agents and the world in the real
mission host (test_struct_mission.py). It is NOT inside any agent process.

argv/env:
  --port N --world-file SPEC.json --world-url URL --reader-token TOK
  --out CAUSAL_CONTROLLER.jsonl --gate-commits GATE_COMMITS.jsonl
  --readback READBACK.jsonl --tokens world_tokens.json [--poll-s 0.1]

State is fed ONLY from independent logs: the world server's /log (reader
token), the CAGE gate's GATE_COMMITS.jsonl and the readback process's
READBACK.jsonl (counted/observed; effects it confirms are already in the
world log as NATIVE_EFFECT). Before every check it synchronously pulls any
new world/gate records into the CausalRegistry, so a dependency confirmed
in the world is visible to the very next agent decision.

HTTP API (agent identity is proven by X-Legion-World-Token, mapped to an
agent_id from world_tokens.json -- never trusted from the request body):
  POST /check       {agent_id, action, decision_ref} -> verdict + view
  POST /check_exit  {agent_id, reason}               -> verdict
  POST /note_result {agent_id, action, http_status, payload} -> {hint}
  GET  /view?agent_id=...                            -> WP-B view
  GET  /health                                       -> {ok, fed, ...}

Refusals are appended to CAUSAL_CONTROLLER.jsonl (atomic, one record per
line) and are never written to WORLD_LOG. The sidecar exposes no endpoint
that performs a world/gate action: it can only refuse, explain or suggest.
Admitted actions are executed by the agent itself against the unchanged
world server / CAGE gate, carrying its own decision_ref.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent.parent))  # repo root for tests.* imports if needed
# causal_007 is importable as a package relative to legion_struct/
sys.path.insert(0, str(HERE))  # for direct module imports below

from causal_registry import CausalRegistry  # noqa: E402
from sidecar import CausalSidecar  # noqa: E402
import attempt as attempt_mod  # noqa: E402
import attempt_authority as auth_mod  # noqa: E402


class CausalState:
    def __init__(self, spec, world_url, reader_token, out_path,
                 gate_path=None, readback_path=None, tokens_path=None):
        self.registry = CausalRegistry(spec)
        self.world_url = (world_url or "").rstrip("/")
        self.reader_token = reader_token or ""
        self.gate_path = gate_path
        self.readback_path = readback_path
        self._fed_world = 0
        self._fed_gate = 0
        self._fed_readback = 0
        self.readback_seen = 0
        # WO008-02 feed integrity: unavailable until a refresh succeeds
        # when a world feed is configured; a failed refresh never becomes [].
        self._feed_unavailable = False
        self.feed_error = None
        self._lock = threading.Lock()
        self._log_lock = threading.Lock()
        self.out_path = str(out_path)
        os.makedirs(os.path.dirname(os.path.abspath(self.out_path)), exist_ok=True)
        Path(self.out_path).touch(exist_ok=True)
        self.token_to_agent = {}
        if tokens_path and os.path.exists(tokens_path):
            try:
                data = json.loads(Path(tokens_path).read_text(encoding="utf-8"))
                self.token_to_agent = dict(data.get("agents") or {})
            except (OSError, ValueError):
                self.token_to_agent = {}
        self.sidecar = CausalSidecar(self.registry, log=self._append_log)
        self._segments = [self.registry.epoch]
        self._anchor_epoch = self.registry.epoch
        self._current_epoch = self.registry.epoch
        self._appender = None
        # StampedAppender identity comes from live authority, not files
        self._appender = attempt_mod.StampedAppender(self.out_path, Path(self.out_path).parent)

    @property
    def feed_unavailable(self):
        return self._feed_unavailable

    @feed_unavailable.setter
    def feed_unavailable(self, value):
        self._feed_unavailable = bool(value)
        self.registry.set_feed_unavailable(bool(value), self.feed_error)

    def _set_feed(self, ok, reason=None):
        if not ok:
            if reason == "STALE_EPOCH_FEED":
                try:
                    import inspect as _inspect
                    _count = getattr(self, "_epoch_ctx_count", 0)
                    if _count < 5:
                        self._epoch_ctx_count = _count + 1
                        _caller = _inspect.currentframe().f_back
                        _recs = _caller.f_locals.get("records", [])
                        _live, _configured = self._live_authority_status()
                        _epochs = [
                            self._record_epoch(r)
                            for r in _recs
                            if isinstance(r, dict)
                        ]
                        _context = {
                            "refresh_line": _caller.f_lineno,
                            "registry_epoch": self.registry.epoch,
                            "live_epoch": _live.get("epoch")
                                if isinstance(_live, dict) else None,
                            "feed_count": len(_recs),
                            "first_record_epoch":
                                _epochs[0] if _epochs else None,
                            "last_record_epoch":
                                _epochs[-1] if _epochs else None,
                            "distinct_record_epochs": sorted(
                                {v for v in _epochs if type(v) is int}
                            ),
                            "known_segments": list(
                                getattr(self, "_segments", [])
                            ),
                            "fed_world": self._fed_world,
                        }
                        with open(self.out_path + ".epoch_ctx", "a",
                                  encoding="utf-8") as _diag:
                            _diag.write(
                                "EPOCH_CTX=" +
                                json.dumps(_context, sort_keys=True) +
                                "\n"
                            )
                except Exception:
                    pass
            _code = reason if isinstance(reason, str) else "UNKNOWN"
            if not _code or any(c not in
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
                for c in _code):
                _code = "UNKNOWN"
            try:
                with open(self.out_path + ".feed_diag", "a",
                          encoding="utf-8") as _diag:
                    _diag.write("FEED_DIAG_CODE=" + _code + "\n")
            except OSError:
                pass
        self.feed_error = None if ok else (reason or "EVIDENCE_FEED_UNAVAILABLE")
        self._feed_unavailable = not ok
        self.registry.set_feed_unavailable(not ok, self.feed_error)
        return ok

    def attempt_terminal(self):
        """Live authority only (E6g): configured authority not RUNNING = deny."""
        if not os.environ.get(auth_mod.ENV_URL):
            return False
        try:
            st = auth_mod.client_from_env("status").status()
        except Exception:
            try:
                st = auth_mod.client_from_env("gate").status()
            except Exception:
                return True
        return st.get("state") != "RUNNING"

    # ---------------------------------------------------------- logging
    def _append_log(self, rec):
        if self._appender is not None:
            try:
                self._appender.append(rec)
            except attempt_mod.AttemptError:
                pass  # terminal/foreign: writer rejects, no mutation
            return
        data = (json.dumps(rec, default=str) + "\n").encode("utf-8")
        with self._log_lock:
            fd = os.open(self.out_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                view = memoryview(data)
                while view:
                    n = os.write(fd, view)
                    if n <= 0:
                        raise OSError("os.write wrote no bytes")
                    view = view[n:]
            finally:
                os.close(fd)

    # ---------------------------------------------------------- feeding
    def _fetch_world_records(self):
        if not self.world_url:
            return []
        req = urllib.request.Request(f"{self.world_url}/log", method="GET")
        if self.reader_token:
            req.add_header("Authorization", f"Bearer {self.reader_token}")
        with urllib.request.urlopen(req, timeout=5) as r:
            payload = json.loads(r.read().decode("utf-8"))
        if isinstance(payload, dict):
            return list(payload.get("records") or [])
        return list(payload)

    def _read_jsonl_strict(self, path):
        """(records, error): any unreadable/malformed line fails closed."""
        if not path or not os.path.exists(path):
            return [], None
        out = []
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        return [], "UNREADABLE_FEED_RECORD"
                    if not isinstance(rec, dict):
                        return [], "UNREADABLE_FEED_RECORD"
                    out.append(rec)
        except OSError:
            return [], "UNREADABLE_FEED"
        return out, None

    def _read_gate_records(self):
        records, _err = self._read_jsonl_strict(self.gate_path)
        return records

    # ------------------------------------------------ epoch-aware ledger
    def _live_authority_status(self):
        """(status|None, configured): live Authority is the only source
        for what the CURRENT epoch is; historical segments are verified
        against their own authenticated transition chain (I1/I3)."""
        if not os.environ.get(auth_mod.ENV_URL):
            return None, False
        try:
            return auth_mod.client_from_env("status").status(), True
        except Exception:
            try:
                return auth_mod.client_from_env("world").status(), True
            except Exception:
                return None, True

    @staticmethod
    def _record_epoch(rec):
        # A refusal's journal epoch is record_epoch; the rejected
        # permit's claimed epoch is evidence about the permit only.
        # P0-02 (LOGIC-ZTL-LEGION-001): EVERY refusal record carries the
        # trusted record_epoch (log_refusal_record), not only WRITE_REFUSED;
        # an EPOCH_TRANSITION_REFUSED must not read as MISSING_EPOCH_FEED.
        if type(rec.get("record_epoch")) is int:
            return rec.get("record_epoch")
        return rec.get("epoch", rec.get("permit_epoch"))

    def _verify_transition(self, proof, cur_epoch, prev_chain,
                           expected_attempt, expected_world):
        import hashlib as _hl
        import hmac as _hm
        key = auth_mod.key_from_env()
        if not isinstance(proof, dict) or key is None:
            return "UNVERIFIED_TRANSITION_FEED"
        body = {k: v for k, v in proof.items() if k not in ("mac", "chain_hash")}
        chain = _hl.sha256(auth_mod.canonical(
            {"prev": proof.get("prev_chain_hash"), "body": body})).hexdigest()
        mac = _hm.new(key, auth_mod.canonical({**body, "chain_hash": chain}),
                      _hl.sha256).hexdigest()
        if chain != proof.get("chain_hash") or \
                not _hm.compare_digest(mac, str(proof.get("mac") or "")):
            return "FORGED_TRANSITION_FEED"
        if expected_attempt and proof.get("attempt_uid") != expected_attempt:
            return "CROSS_ATTEMPT_FEED"
        if expected_world and proof.get("world_instance_id") != expected_world:
            return "CROSS_WORLD_FEED"
        if proof.get("prev_chain_hash") != prev_chain:
            return "FORGED_TRANSITION_FEED"
        if int(proof.get("from_epoch") or -1) != cur_epoch or \
                int(proof.get("to_epoch") or -1) != cur_epoch + 1:
            return "FORGED_TRANSITION_FEED"
        return None

    def _validate_world_feed(self, records):
        """Epoch-aware journal validation (WO008-MUSE-001).

        One append-only journal, monotonic global seq, immutable record
        epoch. Records are verified against the segment they were
        written in: the anchor segment (spec epoch, or the WORLD_START
        epoch anchored by live Authority identity), then each segment
        opened only by an authenticated, hash-chained EPOCH_TRANSITION
        proof. A record from another segment, a future epoch without a
        transition, a forged/missing transition, or a current segment
        that does not match live Authority all fail closed. Historical
        records are never rewritten or reinterpreted (I4).
        """
        if not isinstance(records, list):
            return "UNREADABLE_FEED"
        if len(records) < self._fed_world:
            return "TRUNCATED_FEED"
        seqs = []
        for r in records:
            if not isinstance(r, dict):
                return "UNREADABLE_FEED_RECORD"
            seq = r.get("seq")
            if type(seq) is not int:  # present, exact int, bool excluded
                return "UNREADABLE_FEED_RECORD"
            seqs.append(seq)
        if seqs:
            if seqs != sorted(seqs) or len(set(seqs)) != len(seqs):
                return "OUT_OF_ORDER_FEED"
            if any(b - a != 1 for a, b in zip(seqs, seqs[1:])):
                return "TRUNCATED_FEED"
        expected_attempt = getattr(self.registry, "attempt_uid", None)
        expected_world = (getattr(self.registry, "expected_world_instance_id", None)
                          or getattr(self.registry, "world_instance_id", None))
        live, configured = self._live_authority_status()
        if configured and live is None:
            return "EVIDENCE_FEED_UNAVAILABLE"
        if live is not None:
            trusted_instance = live.get("world_instance_id")
            if not isinstance(trusted_instance, str) or not trusted_instance:
                return "CROSS_WORLD_FEED"
            expected_world = trusted_instance
            self._trusted_world_instance_id = trusted_instance
            if expected_attempt and live.get("attempt_uid") not in (None, expected_attempt):
                return "CROSS_ATTEMPT_FEED"
            if expected_world and live.get("world_instance_id") not in (None, expected_world):
                return "CROSS_WORLD_FEED"
        cur = self.registry.epoch
        anchor = cur
        prev_chain = "GENESIS"
        segments = [cur]
        for idx, rec in enumerate(records):
            if rec.get("attempt_state") in ("COMPLETED", "INTERRUPTED", "TERMINAL") or \
                    rec.get("state") in ("COMPLETED", "INTERRUPTED") and rec.get("kind") == "ATTEMPT_TERMINAL" or \
                    rec.get("terminal_epoch") is True or rec.get("kind") == "ATTEMPT_TERMINAL":
                return "TERMINAL_EPOCH_FEED"
            # Explicit matching identity: absence is not a match.
            if not rec.get("attempt_uid") or \
                    (expected_attempt and rec.get("attempt_uid") != expected_attempt):
                return "CROSS_ATTEMPT_FEED"
            if not rec.get("world_instance_id") or \
                    (expected_world and rec.get("world_instance_id") != expected_world):
                return "CROSS_WORLD_FEED"
            if rec.get("kind") == "WORLD_START":
                if rec.get("world_id") != self.registry.world_id:
                    return "CROSS_SCENARIO_FEED"
            elif rec.get("world_id") is not None:
                if rec.get("world_id") != self.registry.world_id:
                    return "CROSS_SCENARIO_FEED"
            if rec.get("kind") == "EPOCH_TRANSITION":
                proof = rec.get("transition_proof")
                err = self._verify_transition(
                    proof, cur, prev_chain, expected_attempt, expected_world)
                if err:
                    return err
                cur = int(proof["to_epoch"])
                prev_chain = proof["chain_hash"]
                segments.append(cur)
                continue
            epoch = self._record_epoch(rec)
            if idx == 0 and rec.get("kind") == "WORLD_START" and \
                    type(epoch) is int and epoch != cur:
                # Anchor re-base: only live Authority identity may anchor
                # a start epoch different from the spec epoch.
                if live is not None and \
                        rec.get("attempt_uid") == live.get("attempt_uid") and \
                        rec.get("world_instance_id") == live.get("world_instance_id") and \
                        epoch <= int(live.get("epoch") or epoch):
                    cur = anchor = epoch
                    segments = [cur]
                else:
                    return "STALE_EPOCH_FEED"
            if type(epoch) is not int:
                return "MISSING_EPOCH_FEED"
            if epoch != cur:
                return "STALE_EPOCH_FEED"
        if live is not None and int(live.get("epoch") or -1) != cur:
            return "STALE_EPOCH_FEED"
        self._segments = segments
        self._anchor_epoch = anchor
        self._current_epoch = cur
        return None

    def _validate_aux_feed(self, records):
        """Gate/readback records that carry identity/epoch/seq must carry
        them exactly and for this attempt/world/epoch; malformed typed
        fields are unknown evidence, never silently accepted."""
        for rec in records or []:
            if not isinstance(rec, dict):
                return "UNREADABLE_FEED_RECORD"
            if "seq" in rec and type(rec.get("seq")) is not int:
                return "UNREADABLE_FEED_RECORD"
            if rec.get("attempt_uid") and self.registry.attempt_uid and \
                    rec.get("attempt_uid") != self.registry.attempt_uid:
                return "CROSS_ATTEMPT_FEED"
            trusted_world = getattr(
                self, "_trusted_world_instance_id", None)
            if trusted_world is None:
                trusted_world = (
                    getattr(self.registry, "expected_world_instance_id", None)
                    or getattr(self.registry, "world_instance_id", None))
            if rec.get("world_instance_id") and trusted_world and \
                    rec.get("world_instance_id") != trusted_world:
                return "CROSS_WORLD_FEED"
            epoch = rec.get("epoch", rec.get("permit_epoch"))
            # Epoch-aware: an aux record is valid in ANY authenticated
            # journal segment (historical segments stay valid as history;
            # they never grant current authority by themselves, I3).
            known = getattr(self, "_segments", None) or [self.registry.epoch]
            if epoch is not None and (type(epoch) is not int or epoch not in known):
                try:
                    import inspect as _inspect

                    _caller = _inspect.currentframe().f_back

                    if _caller.f_locals.get("gates") is records:
                        _source = "gate"
                    elif _caller.f_locals.get("readbacks") is records:
                        _source = "readback"
                    else:
                        _source = "unknown"

                    _count = getattr(self, "_aux_ctx_count", 0)

                    if _count < 12:
                        self._aux_ctx_count = _count + 1

                        _context = {
                            "source": _source,
                            "record_kind": rec.get("kind"),
                            "record_seq": rec.get("seq"),
                            "record_epoch": epoch,
                            "record_epoch_type": type(epoch).__name__,
                            "permit_epoch": rec.get("permit_epoch"),
                            "known_segments": list(known),
                            "registry_epoch": self.registry.epoch,
                        }

                        with open(
                            self.out_path + ".aux_ctx",
                            "a",
                            encoding="utf-8"
                        ) as _log:
                            _log.write(
                                "AUX_EPOCH_CTX=" +
                                json.dumps(_context, sort_keys=True) +
                                "\n"
                            )

                except Exception:
                    pass

                return "STALE_EPOCH_FEED"
        return None

    def refresh(self):
        """Pull new world/gate/readback records into the registry.

        WO008-02: a failed, truncated, out-of-order, unreadable, stale-epoch
        or terminal-epoch feed is EVIDENCE_FEED_UNAVAILABLE -- never [] and
        never silently the previously confirmed state for new decisions.
        Recovery is only a later refresh that independently succeeds.
        Returns True iff the feed is usable after this refresh.
        """
        with self._lock:
            records = []
            if self.world_url:
                try:
                    records = self._fetch_world_records()
                except Exception:
                    return self._set_feed(False, "EVIDENCE_FEED_UNAVAILABLE")
                err = self._validate_world_feed(records)
                if err:
                    return self._set_feed(False, err)
            gates, gerr = self._read_jsonl_strict(self.gate_path) \
                if self.gate_path else ([], None)
            if gerr:
                return self._set_feed(False, gerr)
            gerr = self._validate_aux_feed(gates)
            if gerr:
                return self._set_feed(False, gerr)
            if len(gates) < self._fed_gate:
                return self._set_feed(False, "TRUNCATED_FEED")
            readbacks, rerr = self._read_jsonl_strict(self.readback_path) \
                if self.readback_path else ([], None)
            if rerr:
                return self._set_feed(False, rerr)
            rerr = self._validate_aux_feed(readbacks)
            if rerr:
                return self._set_feed(False, rerr)
            if len(readbacks) < self._fed_readback:
                return self._set_feed(False, "TRUNCATED_FEED")
            # All sources validated before any ingestion / counter advance.
            if self.world_url and len(records) > self._fed_world:
                # Apply the authenticated segment walk to the registry as
                # records are folded in: historical records keep their
                # original epoch; the registry's current epoch advances
                # only across a verified EPOCH_TRANSITION (I4).
                if getattr(self, "_anchor_epoch", None) is not None:
                    self.registry.epoch = self._anchor_epoch
                for rec in records[self._fed_world:]:
                    if rec.get("kind") == "EPOCH_TRANSITION":
                        self.registry.epoch = int(
                            rec["transition_proof"]["to_epoch"])
                    self.registry.ingest([rec])
                self._fed_world = len(records)
            if len(gates) > self._fed_gate:
                self.registry.ingest([], gate_records=gates[self._fed_gate:])
                self._fed_gate = len(gates)
            if len(readbacks) > self._fed_readback:
                self.registry.ingest(readbacks[self._fed_readback:])
                self._fed_readback = len(readbacks)
            self.readback_seen = len(readbacks)
            # WO008-01 runtime call site: records folded in above are causal
            # state transitions -- resolve conditional activations from
            # fresh verified observations (fail-closed resolve_activation)
            # before any check/check_exit/view uses them, rather than
            # leaving activation to any test-driven call.
            for task_id, outcome, oid in self.registry.activation_candidates():
                ok, _why = self.registry.resolve_activation(
                    task_id, outcome, evidence_refs=[oid],
                    source=f"verified-observation:{oid}",
                    epoch=self.registry.epoch)
                if ok:
                    ob = self.registry.obligations[task_id]
                    ob.activation_origin = "derived"
                    ob.activation_auto = True
            return self._set_feed(True)

    def agent_for_token(self, token):
        return self.token_to_agent.get(token or "")


STATE: CausalState | None = None


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj, default=str).encode("utf-8")
        try:
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

    def _authed_agent(self, body):
        """Agent identity comes from the world token, never the body."""
        token_agent = STATE.agent_for_token(self.headers.get("X-Legion-World-Token", ""))
        claimed = body.get("agent_id")
        if token_agent is not None:
            if claimed is not None and claimed != token_agent:
                return None
            return token_agent
        # No token map loaded (unit use): fall back to claimed id.
        return claimed

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            return self._send(200, {"ok": not STATE.feed_unavailable,
                                    "feed_unavailable": STATE.feed_unavailable,
                                    "feed_error": STATE.feed_error,
                                    "fed_world": STATE._fed_world,
                                    "fed_gate": STATE._fed_gate,
                                    "readback_seen": STATE.readback_seen,
                                    "summary": STATE.registry.summary()})
        if parsed.path == "/view":
            agent = (parse_qs(parsed.query).get("agent_id") or [None])[0]
            token_agent = STATE.agent_for_token(self.headers.get("X-Legion-World-Token", ""))
            if token_agent is not None:
                agent = token_agent
            if not agent:
                return self._send(400, {"error": "agent_id required"})
            STATE.refresh()
            if STATE.feed_unavailable:
                return self._send(503, {"error": "EVIDENCE_FEED_UNAVAILABLE",
                                        "code": "EVIDENCE_FEED_UNAVAILABLE",
                                        "allowed": False, "next_required": None,
                                        "feed_error": STATE.feed_error})
            return self._send(200, STATE.sidecar.next_required(agent))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        body = self._body()
        agent = self._authed_agent(body)
        if agent is None:
            return self._send(403, {"error": "world token does not match agent_id"})
        if self.path == "/check":
            if not agent:
                return self._send(400, {"error": "agent_id required"})
            if STATE.attempt_terminal():
                return self._send(200, {
                    "allowed": False, "code": "ATTEMPT_TERMINAL",
                    "hint": "attempt is terminal; no action may proceed",
                    "next_required": None, "transient": False,
                    "underlying_code": None, "observation_only": False,
                    "stale_refs": [], "valid_refs": [], "view": {}})
            STATE.refresh()
            verdict = STATE.sidecar.check(agent, body.get("action") or {},
                                          body.get("decision_ref") or "")
            view = STATE.sidecar.next_required(agent)
            return self._send(200, {**verdict.to_dict(), "view": view})
        if self.path == "/check_exit":
            if STATE.attempt_terminal():
                return self._send(200, {
                    "allowed": False, "code": "ATTEMPT_TERMINAL",
                    "hint": "attempt is terminal", "next_required": None,
                    "transient": False, "underlying_code": None,
                    "observation_only": False, "stale_refs": [], "valid_refs": []})
            STATE.refresh()
            verdict = STATE.sidecar.check_exit(agent, body.get("reason") or "")
            return self._send(200, verdict.to_dict())
        if self.path == "/note_result":
            hint = STATE.sidecar.note_result(agent, body.get("action") or {},
                                             int(body.get("http_status") or 0),
                                             body.get("payload") or {})
            return self._send(200, {"hint": hint})
        return self._send(404, {"error": "not found"})

    def log_message(self, *args):
        pass


def _watch_parent(stop):
    parent = os.getppid()
    def _run():
        while not stop.is_set():
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
    p.add_argument("--world-file", required=True)
    p.add_argument("--world-url", default="")
    p.add_argument("--reader-token", default="")
    p.add_argument("--out", required=True)
    p.add_argument("--gate-commits", default="")
    p.add_argument("--readback", default="")
    p.add_argument("--tokens", default="")
    p.add_argument("--poll-s", type=float, default=0.1)
    args = p.parse_args(argv)
    spec = json.loads(Path(args.world_file).read_text(encoding="utf-8"))
    global STATE
    STATE = CausalState(spec, args.world_url, args.reader_token, args.out,
                        gate_path=args.gate_commits or None,
                        readback_path=args.readback or None,
                        tokens_path=args.tokens or None)
    stop = threading.Event()
    _watch_parent(stop)

    def _poll():
        while not stop.wait(max(0.02, args.poll_s)):
            try:
                STATE.refresh()
            except Exception:
                pass

    threading.Thread(target=_poll, daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        stop.set()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
