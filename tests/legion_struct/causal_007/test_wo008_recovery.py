"""WO008-04 GAIA-AMB recovery + transport: refusal is preserved as the
actual consequence, the grounded explanation is independently delivered,
invented cancellations/messages are rejected, transport retries never
consume semantic turns, and bounded recovery cannot livelock or duplicate
an effect. Real CausalHost -> CausalSidecar -> CausalRegistry -> World.
"""
import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from causal_007.causal_host import CausalHost  # noqa: E402
from causal_007.causal_registry import CausalRegistry  # noqa: E402
from causal_007.nim_transport import NimTransport  # noqa: E402
from causal_007 import recovery as rec  # noqa: E402

ATT, WIN, EPOCH = "att-wo008-04", "win-wo008-04", 1
WORLDS = HERE.parent / "worlds"
HANDLER, LOOKUP, LIAISON = "agent:amb-handler", "agent:amb-lookup", "agent:amb-liaison"


def amb_host():
    spec = json.loads((WORLDS / "SYN-GAIA-AMB.world.json").read_text(encoding="utf-8"))
    spec = copy.deepcopy(spec)
    spec.update(attempt_uid=ATT, world_instance_id=WIN, epoch=EPOCH)
    return CausalHost(spec)


def lookup_done(host):
    v, r = host.step(LOOKUP, {"action": "read", "task": "T1",
                              "tool": "crm.find_by_name", "args": {"name": "Alex"}},
                     "scripted:lookup-1")
    assert v.allowed, v.code
    obs = host.world_records[-1]["observation_id"]
    v, r = host.step(LOOKUP, {"action": "send", "task": "T2", "to": HANDLER,
                              "body": f"Two matches found, see {obs}",
                              "evidence_refs": [obs]}, "scripted:lookup-2")
    assert v.allowed, v.code
    return obs


def refused_host():
    host = amb_host()
    obs = lookup_done(host)
    assert host.registry.is_confirmed("T2")
    # DONE is impossible while the handler obligations are open.
    assert not host.sidecar.check_exit(HANDLER, "all_tasks_terminal").allowed
    plan = rec.amb_recovery_plan(host.registry, HANDLER)
    assert [p["action"] for p in plan] == ["refuse", "send"], plan
    assert plan[1]["to"] == LIAISON
    v, r = host.step(HANDLER, {"action": "refuse", "task": "T3"}, "scripted:handler-refuse")
    assert v.allowed and v.code == "ADMISSIBLE_WITH_COMMUNICATION_REQUIRED", v.code
    return host, obs


def liaison_receipt(host, verifier=LIAISON):
    msg = next(r for r in host.world_records if r.get("kind") == "MESSAGE_DELIVERED"
               and r.get("task_id") == "T4")
    return {"kind": "DELIVERY_RECEIPT", "message_id": msg["message_id"],
            "recipient": msg["recipient"], "verifier_agent": verifier,
            "body_sha256": msg["body_sha256"], "verified": True,
            "attempt_uid": ATT, "world_instance_id": WIN, "epoch": EPOCH}


def test_amb_refusal_recovery():
    host, obs = refused_host()
    reg = host.registry
    # The refusal is the preserved consequence; nothing was cancelled.
    assert reg.obligations["T3"].refused and reg.is_confirmed("T3")
    assert len(host.world.effect_ledger) == 0
    assert all(s["status"] == "active"
               for s in host.world.get_state()["subscriptions"].values())
    # Still not DONE: the liaison communication remains open.
    v = host.sidecar.check_exit(HANDLER, "all_tasks_terminal")
    assert not v.allowed and v.code == "EXIT_BLOCKED_OPEN_OBLIGATIONS"
    body = rec.grounded_amb_body(reg)
    assert body and "C-21" in body and "C-34" in body and "no subscription was" in body
    v, r = host.step(HANDLER, {"action": "send", "task": "T4", "to": LIAISON,
                               "body": body, "evidence_refs": [obs]},
                     "scripted:handler-send")
    assert v.allowed, v.code
    assert reg.is_confirmed("T4")
    receipt = liaison_receipt(host)
    ok, code = rec.verify_delivery_receipt(host.world_records, [receipt],
                                           receipt["message_id"])
    assert ok and code == "DELIVERY_VERIFIED"
    ok, code = rec.amb_recovery_complete(reg, host.world_records, [receipt], HANDLER)
    assert ok and code == "AMB_RECOVERY_VERIFIED", code
    assert host.sidecar.check_exit(HANDLER, "all_tasks_terminal").allowed
    bundle = rec.evidence_bundle(reg, host, extra={
        "amb_plan": rec.amb_recovery_plan(reg, HANDLER),
        "delivery_receipt": receipt, "grounded_body": body})
    assert bundle["effects"] == [] and bundle["attempt_uid"] == ATT
    assert bundle["obligations"]["T3"]["confirmed"] is True
    out = HERE.parents[2] / "_wo008_input"
    if out.is_dir():
        (out / "WO008_04_AMB_EVIDENCE.json").write_text(
            json.dumps(bundle, indent=1, sort_keys=True), encoding="utf-8")


def test_amb_false_message_rejected():
    host, obs = refused_host()
    reg = host.registry
    # (1) A message inventing a successful cancellation is refused by the
    # real sidecar; it delivers nothing and closes nothing.
    v, r = host.step(HANDLER, {"action": "send", "task": "T4", "to": LIAISON,
                               "body": "Subscription C-21 cancelled successfully."},
                     "scripted:false-send")
    assert not v.allowed and v.code == "MESSAGE_FALSE_OUTCOME_CLAIM", v.code
    assert r is None and not reg.is_confirmed("T4")
    assert not any(r.get("kind") == "MESSAGE_DELIVERED" and r.get("task_id") == "T4"
                   for r in host.world_records)
    assert not host.sidecar.check_exit(HANDLER, "all_tasks_terminal").allowed
    # (2) Fabricated cancellation WRITE evidence cannot resurrect T3.
    base = {"agent_id": HANDLER, "task_id": "T3", "effect_id": "eff-fake",
            "command_id": "cmd-fake", "epoch": EPOCH, "permit_epoch": EPOCH,
            "attempt_uid": ATT, "world_instance_id": WIN,
            "tool": "subscriptions.cancel", "target": "subscriptions",
            "args": {"customer_id": "C-21"}}
    reg.ingest([{"kind": "NATIVE_EFFECT", **base},
                {"kind": "RECEIPT", "receipt_id": "rcpt-fake",
                 "permit_verified": True, **base},
                {"kind": "READBACK_EFFECT", "confirmed": True,
                 "state_sha256": "x", **base}])
    assert "WRITE" not in reg.obligations["T3"].satisfied
    assert any(s["reason"] == "REFUSAL_TERMINAL_WRITE_EVIDENCE_REJECTED"
               for s in reg.obligations["T3"].stale)
    assert all(s["status"] == "active"
               for s in host.world.get_state()["subscriptions"].values())
    # (3) An unverified delivery does not close T4 in a fresh registry.
    reg2 = CausalRegistry(host.spec)
    reg2.note_gate_refusal("T3")
    reg2.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": HANDLER, "task_id": "T4",
                  "recipient": LIAISON, "message_id": "msg-x", "body": "declined",
                  "delivery_verified": False}])
    assert not reg2.is_confirmed("T4")
    assert any(s["reason"] == "DELIVERY_UNVERIFIED"
               for s in reg2.obligations["T4"].stale)
    # (4) Self-issued / hash-mismatched delivery receipts prove nothing.
    host2, _ = refused_host()
    body = rec.grounded_amb_body(host2.registry)
    v, _ = host2.step(HANDLER, {"action": "send", "task": "T4", "to": LIAISON,
                                "body": body}, "scripted:send2")
    assert v.allowed
    self_receipt = liaison_receipt(host2, verifier=HANDLER)
    ok, code = rec.amb_recovery_complete(host2.registry, host2.world_records,
                                         [self_receipt], HANDLER)
    assert not ok and code == "DELIVERY_RECEIPT_NOT_INDEPENDENT"
    bad = liaison_receipt(host2)
    bad["body_sha256"] = hashlib.sha256(b"tampered").hexdigest()
    ok, code = rec.verify_delivery_receipt(host2.world_records, [bad], bad["message_id"])
    assert not ok and code == "DELIVERY_RECEIPT_BODY_MISMATCH"


def _transport(sleeps, **kw):
    return NimTransport(max_concurrency=1, base_backoff_s=0.01,
                        sleep=lambda s: sleeps.append(round(s, 4)), **kw)


def test_429_retry_preserves_semantic_turn():
    sleeps, calls = [], {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] <= 2:
            return 429, None, {"Retry-After": "0"}
        return 200, {"choices": [{"message": {"content": "restart"}}]}, {}

    result, turns = rec.execute_semantic_decision(_transport(sleeps, max_retries=4), flaky)
    assert result.status == 200 and turns == 1
    assert result.attempts == 3 and result.transport_retries == 2
    # The recovered decision executes exactly once through the real host.
    spec = json.loads((WORLDS / "SYN-OTEL-04.world.json").read_text(encoding="utf-8"))
    spec.update(attempt_uid=ATT, world_instance_id=WIN, epoch=EPOCH)
    host = CausalHost(copy.deepcopy(spec))
    v, _ = host.step("agent:o4-coordinator",
                     {"action": "read", "task": "T1", "tool": "consumer_group.status",
                      "args": {}}, "scripted:t1")
    assert v.allowed
    v, _ = host.step("agent:o4-coordinator",
                     {"action": "write", "task": "T2", "tool": "consumer_group.restart",
                      "target": "cg-fraud-detection", "args": {"group": "fraud-detection"}},
                     "scripted:after-429")
    assert v.allowed and host.registry.write_status("T2") == "VERIFIED"
    assert len([e for e in host.world.effect_ledger]) == 1
    # Transient interruptions behave the same; exhaustion invents nothing.
    calls2 = {"n": 0}

    def interrupted():
        calls2["n"] += 1
        if calls2["n"] <= 2:
            raise ConnectionError("transient interruption")
        return 200, {"choices": [{"message": {"content": "ok"}}]}, {}

    result2, turns2 = rec.execute_semantic_decision(_transport([], max_retries=4), interrupted)
    assert result2.status == 200 and turns2 == 1 and result2.attempts == 3
    result3, turns3 = rec.execute_semantic_decision(
        _transport([], max_retries=2), lambda: (429, None, {"Retry-After": "0"}))
    assert result3.status == 429 and result3.payload is None
    assert turns3 == 0 and result3.attempts == 3  # bounded: 1 + 2 retries


def test_no_livelock_or_duplicate_effect():
    spec = json.loads((WORLDS / "SYN-OTEL-04.world.json").read_text(encoding="utf-8"))
    spec.update(attempt_uid=ATT, world_instance_id=WIN, epoch=EPOCH)
    host = CausalHost(copy.deepcopy(spec))
    agent, action = "agent:o4-consumer-p0", {
        "action": "write", "task": "Wp0", "tool": "partition.drain", "target": "p0",
        "args": {"partition": "p0", "from_offset": 100}}
    # Repeating a refused write with unchanged causal state is bounded.
    outcome = rec.run_bounded_recovery(
        lambda: host.step(agent, action, "scripted:retry")[0], host.registry)
    assert outcome["outcome"] == "LIVELOCK_PREVENTED" and outcome["attempts"] <= 5
    assert len(host.world.effect_ledger) == 0
    # Proper causal progress, then a duplicate write attempt: no 2nd effect.
    host.step("agent:o4-coordinator", {"action": "read", "task": "T1",
            "tool": "consumer_group.status", "args": {}}, "scripted:t1")
    host.step("agent:o4-coordinator", {"action": "write", "task": "T2",
            "tool": "consumer_group.restart", "target": "cg-fraud-detection",
            "args": {"group": "fraud-detection"}}, "scripted:t2")
    host.step(agent, {"action": "read", "task": "Rp0", "tool": "partition.offsets",
                      "args": {"partition": "p0"}}, "scripted:rp0")
    v, _ = host.step(agent, action, "scripted:wp0")
    assert v.allowed and host.registry.write_status("Wp0") == "VERIFIED"
    n_effects = len(host.world.effect_ledger)
    v, _ = host.step(agent, action, "scripted:wp0-duplicate")
    assert not v.allowed and v.code == "ALREADY_CONFIRMED"
    assert len(host.world.effect_ledger) == n_effects
    assert host.world.get_state()["drains"]["p0"] == 1
