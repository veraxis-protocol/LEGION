"""WP-B/C host-side causal host: scripted/NIM decisions -> sidecar -> world.

Every world effect here originates from a decider-supplied action carrying
its decision_ref; the host/sidecar only refuses, explains or forwards.
Used by the deterministic smoke/mechanism tests and as the reference wiring
that run_campaign.ps1's host enables via STRUCT_CAUSAL=1.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from world_engine import World  # noqa: E402
from causal_007.causal_registry import CausalRegistry  # noqa: E402
from causal_007.sidecar import CausalSidecar  # noqa: E402


class CausalHost:
    """In-process world + registry + sidecar. Deciders are callables
    fn(agent_id, view) -> action dict | None. No decider, no action.

    SYNTHETIC READBACK NOTICE: this host manufactures its own RECEIPT and
    READBACK_EFFECT records in-process (see _apply). That triplet can close
    obligations in isolated deterministic tests, but it is NOT independent
    readback and must never be claimed as such: ``readback_independence``
    is ``SYNTHETIC_NOT_INDEPENDENT`` and ``independent_write_status()``
    therefore stays UNVERIFIED for every task served by this host.
    Independent confirmation requires a separate process (e.g.
    struct_readback against a native world_server) whose records carry
    independent provenance and a state hash matching an independently
    observed state.
    """

    readback_independence = "SYNTHETIC_NOT_INDEPENDENT"
    independent_readback = False

    def __init__(self, spec):
        self.spec = copy.deepcopy(spec)
        self.world = World(self.spec)
        self.registry = CausalRegistry(self.spec)
        self.log = []
        self.sidecar = CausalSidecar(self.registry, log=self.log.append)
        self.world_records = []
        self._obs_n = 0
        self._fed = 0

    def _sync(self):
        if self._fed < len(self.world_records):
            self.registry.ingest(self.world_records[self._fed:])
            self._fed = len(self.world_records)
            # WO008-01 runtime call site: every newly logged record is a
            # causal-state transition -- resolve conditional activations
            # from fresh verified observations (fail-closed
            # resolve_activation) before the next sidecar check, instead
            # of leaving activation to any test-driven call.
            for task_id, outcome, oid in self.registry.activation_candidates():
                ok, _why = self.registry.resolve_activation(
                    task_id, outcome, evidence_refs=[oid],
                    source=f"verified-observation:{oid}",
                    epoch=self.registry.epoch)
                if ok:
                    ob = self.registry.obligations[task_id]
                    ob.activation_origin = "derived"
                    ob.activation_auto = True

    # -- translate a forwarded (admissible) action into a world record
    def _apply(self, agent_id, action, decision_ref):
        kind, task_id = action.get("action"), action.get("task")
        task = self.world.task_for(agent_id, task_id) or {}
        if kind == "read":
            status, data = self.world.call_read(action.get("tool"), action.get("args") or {})
            if status == 200:
                self._obs_n += 1
                rec = {"kind": "OBSERVATION", "agent_id": agent_id, "task_id": task_id,
                       "observation_id": f"obs-{self._obs_n}", "facts": data,
                       "epoch": self.registry.epoch,
                       "attempt_uid": self.spec.get("attempt_uid"),
                       "world_instance_id": self.spec.get("world_instance_id")
                       or self.spec.get("world_id"),
                       "tool": action.get("tool"), "args": action.get("args") or {},
                       "decision_ref": decision_ref}
                self.world_records.append(rec)
                return 200, {"observation_id": rec["observation_id"], "data": data}
            hint = self.sidecar.note_result(agent_id, action, status, data)
            return status, {**data, "causal_hint": hint}
        if kind == "send":
            body = action.get("body") or ""
            rec = {"kind": "MESSAGE_DELIVERED", "agent_id": agent_id, "task_id": task_id,
                   "recipient": action.get("to"), "message_id": f"msg-{len(self.world_records)}",
                   "body": body,
                   "body_sha256": hashlib.sha256(str(body).encode()).hexdigest(),
                   "facts": action.get("facts") or action.get("content"),
                   "evidence_refs": action.get("evidence_refs") or [],
                   "decision_ref": decision_ref}
            self.world_records.append(rec)
            return 200, {"message_id": rec["message_id"]}
        if kind == "wait":
            ev = action.get("event_id") or task.get("wait_for")
            fired = self.world.fire(ev) if ev else None
            if ev and ev not in self.world.fired_events():
                # event not yet due/fired in this deterministic host: not observed
                return 200, {"waited": False}
            rec = {"kind": "WAIT_OBSERVED", "agent_id": agent_id, "task_id": task_id,
                   "event_id": ev, "decision_ref": decision_ref}
            self.world_records.append(rec)
            return 200, {"waited": True, "event_id": ev}
        if kind == "analyze":
            status, payload = self.world.analyze(task, action.get("answer") or {},
                                                 agent_id=agent_id)
            if status == 200:
                rec = {"kind": "ANALYSIS_RECORD", "agent_id": agent_id, "task_id": task_id,
                       "facts": action.get("answer"), "evidence_refs": action.get("evidence_refs") or [],
                       "record_id": f"ana-{len(self.world_records)}", "decision_ref": decision_ref}
                self.world_records.append(rec)
            return status, payload
        if kind == "write":
            # Consequential writes stay under the governed gate in the real
            # host; here the deterministic engine applies them and the
            # registry closes only on the resulting NATIVE_EFFECT record.
            command_id = f"cmd-{len(self.world_records)}-{task_id}"
            status, result = self.world.call_write(
                command_id, action.get("tool"),
                action.get("target"), action.get("args") or {})
            if status in (200, "LOST_REPLY"):
                # WO008-02: emit the actual producer triplet (same schemas
                # as world_server /actuate + struct_readback): the effect
                # alone is EXECUTED_UNVERIFIED until receipt + independent
                # readback with matching identity arrive.
                ident = {"attempt_uid": self.spec.get("attempt_uid"),
                         "world_instance_id": self.spec.get("world_instance_id")
                         or self.spec.get("world_id"),
                         "epoch": self.registry.epoch,
                         "permit_epoch": self.registry.epoch}
                rec = {"kind": "NATIVE_EFFECT", "agent_id": agent_id, "task_id": task_id,
                       "effect_id": result.get("effect_id"),
                       "command_id": command_id, "tool": action.get("tool"),
                       "target": action.get("target"),
                       "args": action.get("args") or {},
                       "effects_applied": copy.deepcopy(result.get("effects_applied") or []),
                       "delegate_result_ref": action.get("delegate_result_ref"),
                       "evidence_refs": action.get("evidence_refs") or [],
                       "permit_verified": True, **ident,
                       "decision_ref": decision_ref}
                self.world_records.append(rec)
                self.world_records.append({
                    "kind": "RECEIPT", "agent_id": agent_id, "task_id": task_id,
                    "receipt_id": f"rcpt-{command_id}",
                    "provenance": "synthetic_host", "independent": False,
                    "effect_id": result.get("effect_id"),
                    "command_id": command_id, "tool": action.get("tool"),
                    "target": action.get("target"),
                    "args": action.get("args") or {},
                    "permit_verified": True, **ident})
                state_sha = hashlib.sha256(json.dumps(
                    self.world.get_state() if hasattr(self.world, "get_state")
                    else getattr(self.world, "state", {}),
                    sort_keys=True, default=str).encode()).hexdigest()
                self.world_records.append({
                    "kind": "READBACK_EFFECT", "agent_id": agent_id,
                    "provenance": "synthetic_host", "independent": False,
                    "task_id": task_id, "effect_id": result.get("effect_id"),
                    "command_id": command_id, "confirmed": True,
                    "state_sha256": state_sha, **ident})
                return 200, result
            hint = self.sidecar.note_result(agent_id, action,
                                            status if isinstance(status, int) else 0, result)
            return (status if isinstance(status, int) else 0), {**result, "causal_hint": hint}
        if kind == "refuse":
            self.registry.note_gate_refusal(task_id)
            return 200, {"status": "REFUSED_BY_AGENT"}
        if kind == "reconcile":
            entry = self.world.reconcile(action.get("command_id"))
            rec = {"kind": "RECONCILE", "agent_id": agent_id, "task_id": task_id,
                   "command_id": action.get("command_id"), "found": entry is not None,
                   "decision_ref": decision_ref}
            self.world_records.append(rec)
            return 200, {"found": entry is not None}
        if kind == "done":
            rec = {"kind": "AGENT_DONE", "agent_id": agent_id, "task_id": task_id,
                   "decision_ref": decision_ref}
            self.world_records.append(rec)
            return 200, {"status": "done"}
        return 200, {"status": "idle"}

    def step(self, agent_id, action, decision_ref):
        """One agent decision through the sidecar. Returns (verdict, result)."""
        if action is None:
            return None, None
        self._sync()
        verdict = self.sidecar.check(agent_id, action, decision_ref)
        if not verdict.allowed:
            return verdict, None
        status, payload = self._apply(agent_id, action, decision_ref)
        self._sync()
        return verdict, (status, payload)

    def independent_write_status(self, task_id):
        """This host's readback is synthetic: never independent."""
        return "UNVERIFIED"

    def run_deciders(self, deciders, max_steps=400):
        """deciders: {agent_id: fn(host, agent_id) -> action|None}."""
        for _ in range(max_steps):
            progressed = False
            for agent_id, fn in deciders.items():
                action = fn(self, agent_id)
                if action is None:
                    continue
                progressed = True
                self.step(agent_id, action, f"scripted:{agent_id}")
            if not progressed:
                break
        self._sync()
        return self.registry.summary()


def evaluate_independent_readback(effect, receipt, readback,
                                  independent_state_sha256=None,
                                  independent_effect_ids=None,
                                  pre_effect_state_sha256=None,
                                  post_effect_state_sha256=None):
    """(status, reason): independent confirmation of a consequential effect.

    VERIFIED only when a readback carrying independent provenance (a
    separate process, never ``synthetic_host``) confirms the exact
    effect/command identity of a matching receipt, the effect is present
    in the independently observed ledger, the readback state hash equals
    the independently observed post-state hash, and that post-state
    actually differs from the pre-effect state when both are supplied.
    Any forgery, alteration, synthetic provenance, missing ledger entry
    or no-op success reply stays UNVERIFIED.
    """
    if not isinstance(effect, dict) or not effect.get("effect_id"):
        return "UNVERIFIED", "EFFECT_MISSING"
    if not isinstance(receipt, dict) or receipt.get("effect_id") != effect.get("effect_id") \
            or receipt.get("command_id") != effect.get("command_id") \
            or not receipt.get("receipt_id"):
        return "UNVERIFIED", "RECEIPT_MISMATCH"
    if not isinstance(readback, dict):
        return "UNVERIFIED", "READBACK_MISSING"
    if readback.get("provenance") == "synthetic_host" or \
            readback.get("independent") is False:
        return "UNVERIFIED", "READBACK_NOT_INDEPENDENT"
    if readback.get("independent") is not True and \
            readback.get("provenance") not in ("struct_readback", "independent_process"):
        return "UNVERIFIED", "READBACK_PROVENANCE_UNPROVEN"
    if readback.get("confirmed") is not True:
        return "UNVERIFIED", "READBACK_UNCONFIRMED"
    if readback.get("effect_id") != effect.get("effect_id") or \
            readback.get("command_id") != effect.get("command_id"):
        return "UNVERIFIED", "READBACK_IDENTITY_MISMATCH"
    if independent_effect_ids is not None and \
            effect.get("effect_id") not in set(independent_effect_ids):
        return "UNVERIFIED", "EFFECT_NOT_IN_INDEPENDENT_LEDGER"
    observed = independent_state_sha256 or post_effect_state_sha256
    if observed is not None and readback.get("state_sha256") != observed:
        return "UNVERIFIED", "READBACK_STATE_SHA_MISMATCH"
    if pre_effect_state_sha256 is not None and post_effect_state_sha256 is not None \
            and pre_effect_state_sha256 == post_effect_state_sha256:
        return "UNVERIFIED", "NO_ACTUAL_STATE_CHANGE"
    return "VERIFIED", "INDEPENDENT_READBACK_VERIFIED"
