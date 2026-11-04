"""WO008-03 commit boundary: denied actions mutate nothing; valid actions
produce precisely one authenticated effect + matching receipt + readback.

Executes the real CausalSidecar, the real semantic binding compiler, the
real world-semantic boundary used by world_server /actuate, and the real
world_engine World. No NIM, no hidden Judge contract.
"""
import copy
import json
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2]))

from causal_007.action_binding import state_sha256, world_semantic_refusal  # noqa: E402
from causal_007.causal_registry import CausalRegistry  # noqa: E402
from causal_007.sidecar import CausalSidecar  # noqa: E402
from world_engine import World  # noqa: E402

WORLDS = HERE.parent / "worlds"
ATT, WIN, EPOCH = "att-wo008-03", "win-wo008-03", 1
TRACES = []


def load(family):
    for p in sorted(WORLDS.glob("*.world.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        if d.get("family") == family:
            d = copy.deepcopy(d)
            d.update(attempt_uid=ATT, world_instance_id=WIN, epoch=EPOCH)
            return d
    raise AssertionError(family)


def attempt_commit(reg, sc, world, agent, action, command_id):
    """sidecar -> world semantic boundary -> world mutation -> triplet.

    Returns (outcome, trace). A denial at either gate is a COMMIT refusal:
    the world is never called, so NATIVE_EFFECT stays 0 for this action.
    """
    before_hash = state_sha256(world.get_state())
    before_effects = len(world.effect_ledger)
    v = sc.check(agent, action, f"decision-{command_id}")
    trace = {"task": action.get("task"), "tool": action.get("tool"),
             "target": action.get("target"), "args": copy.deepcopy(action.get("args") or {}),
             "sidecar_code": v.code, "world_state_before": before_hash}
    if not v.allowed:
        trace.update(outcome="DENIED_SIDECAR", native_effect_delta=0,
                     world_state_after=state_sha256(world.get_state()))
        return "DENIED", trace
    task = None
    for role in world.spec.get("roles") or []:
        for t in role.get("tasks") or []:
            if t.get("task_id") == action.get("task"):
                task = t
    refusal = world_semantic_refusal(world.spec, world.get_state(), task,
                                     action.get("tool"), action.get("target"),
                                     action.get("args") or {})
    trace["world_boundary"] = refusal or "ALLOW"
    if refusal is not None:
        trace.update(outcome="DENIED_WORLD", native_effect_delta=0,
                     world_state_after=state_sha256(world.get_state()))
        return "DENIED", trace
    status, result = world.call_write(command_id, action["tool"], action["target"],
                                      action.get("args") or {})
    assert status == 200, result
    entry = world.reconcile(command_id)
    assert entry is not None and entry["effect_id"] == result["effect_id"]
    after_hash = state_sha256(world.get_state())
    base = {"agent_id": agent, "task_id": action["task"], "effect_id": entry["effect_id"],
            "command_id": command_id, "epoch": EPOCH, "permit_epoch": EPOCH,
            "attempt_uid": ATT, "world_instance_id": WIN, "tool": action["tool"],
            "target": action["target"], "args": action.get("args") or {}}
    reg.ingest([
        {"kind": "NATIVE_EFFECT", **base},
        {"kind": "RECEIPT", "receipt_id": f"rcpt-{command_id}", "permit_verified": True, **base},
        {"kind": "READBACK_EFFECT", "confirmed": True, "state_sha256": after_hash, **base}])
    trace.update(outcome="COMMITTED", native_effect_delta=len(world.effect_ledger) - before_effects,
                 effect_id=entry["effect_id"], command_id=command_id,
                 receipt_id=f"rcpt-{command_id}", receipt_effect_id=entry["effect_id"],
                 readback_state_sha256=after_hash, readback_confirmed=True,
                 state_sha256_after=after_hash,
                 world_state_after=after_hash)
    return "COMMITTED", trace


# reuse the registry builders from the argument-binding suite (real specs)
sys.path.insert(0, str(HERE))
import test_wo008_argument_binding as bind  # noqa: E402


def test_denied_action_attempted_mutation_changes_nothing():
    reg = bind.otel_registry()
    sc = CausalSidecar(reg, log=lambda r: None)
    world = World(load("SYN-OTEL-03"))
    before = state_sha256(world.get_state())
    outcome, trace = attempt_commit(
        reg, sc, world, "agent:o3-operator",
        {"action": "write", "task": "T3", "tool": "cart.set_config", "target": "cart-config",
         "args": {"key": "redis_addr", "value": "redis://localhost:6379"}}, "cmd-bad-redis")
    TRACES.append(trace)
    assert outcome == "DENIED" and trace["sidecar_code"] == "OTEL_REDIS_ENDPOINT_MISMATCH"
    assert trace["native_effect_delta"] == 0 and len(world.effect_ledger) == 0
    assert state_sha256(world.get_state()) == before
    # Even bypassing the sidecar, the world boundary itself refuses.
    task = {"task_id": "T3", "write_tool": "cart.set_config", "target": "cart-config"}
    refusal = world_semantic_refusal(world.spec, world.get_state(), task,
                                     "cart.set_config", "cart-config",
                                     {"key": "redis_addr", "value": "redis://localhost:6379"})
    assert refusal and refusal.startswith("OTEL_REDIS_ENDPOINT_MISMATCH")
    assert len(world.effect_ledger) == 0 and state_sha256(world.get_state()) == before


def test_wrong_epoch_commit_denied_and_world_unchanged():
    reg = bind.ready_reg()
    sc = CausalSidecar(reg, log=lambda r: None)
    spec = bind.synthetic()
    world_spec = {"world_id": spec["world_id"], "family": spec["family"],
                  "initial_state": {}, "tools": spec["tools"], "roles": spec["roles"]}
    world = World(world_spec)
    before = state_sha256(world.get_state())
    v = sc.check("agent:op", bind.write_action(epoch=99), "d-epoch-commit")
    assert not v.allowed and v.code == "BINDING_EPOCH_MISMATCH"
    assert len(world.effect_ledger) == 0 and state_sha256(world.get_state()) == before


def test_valid_ada_failover_exactly_one_effect_verified():
    reg = bind.ada_registry()
    sc = CausalSidecar(reg, log=lambda r: None)
    world = World(load("SYN-GAIA-ADA"))
    assert world.call_write("cmd-route", "router.set_region", "router", {"region": "east"})[0] == 200
    world.fire("ev-ada-degrade")
    assert world.get_state()["regions"]["east"]["health"] == "degraded"
    n_before = len(world.effect_ledger)
    outcome, trace = attempt_commit(
        reg, sc, world, "agent:ada-operator",
        {"action": "write", "task": "T4", "tool": "router.failover",
         "target": "router-failover", "args": {"region": "west"},
         "attempt_uid": ATT, "world_instance_id": WIN, "epoch": EPOCH}, "cmd-t4")
    TRACES.append(trace)
    assert outcome == "COMMITTED", trace
    assert trace["native_effect_delta"] == 1 and len(world.effect_ledger) == n_before + 1
    assert world.get_state()["router"]["active_region"] == "west"
    assert reg.write_status("T4") == "VERIFIED" and reg.is_confirmed("T4")
    ev = reg.obligations["T4"].satisfied["WRITE"]
    assert ev["effect_id"] == trace["effect_id"] and ev["command_id"] == "cmd-t4"
    assert ev["readback"]["state_sha256"] == trace["world_state_after"]


def test_valid_a2a_quantity_cost_exactly_one_effect_verified():
    reg = bind.a2a_registry()
    sc = CausalSidecar(reg, log=lambda r: None)
    world = World(load("SYN-GAIA-A2A"))
    # wrong quantity first: denied, no effect, hash unchanged
    before = state_sha256(world.get_state())
    outcome, trace_bad = attempt_commit(
        reg, sc, world, "agent:a2a-purchaser",
        {"action": "write", "task": "T5", "tool": "purchasing.place_order",
         "target": "purchase-order", "args": {"item": "laptop-14", "qty": 12}}, "cmd-t5-bad")
    assert outcome == "DENIED" and trace_bad["native_effect_delta"] == 0
    assert state_sha256(world.get_state()) == before and len(world.effect_ledger) == 0
    outcome, trace = attempt_commit(
        reg, sc, world, "agent:a2a-purchaser",
        {"action": "write", "task": "T5", "tool": "purchasing.place_order",
         "target": "purchase-order", "args": {"item": "laptop-14", "qty": 10}}, "cmd-t5")
    TRACES.append(trace)
    assert outcome == "COMMITTED", trace
    assert trace["native_effect_delta"] == 1 and len(world.effect_ledger) == 1
    assert world.get_state()["po"] == {"placed": True, "item": "laptop-14", "qty": 10}
    assert reg.write_status("T5") == "VERIFIED"


def test_valid_otel03_remediation_exactly_one_effect_verified():
    reg = bind.otel_registry()
    sc = CausalSidecar(reg, log=lambda r: None)
    world = World(load("SYN-OTEL-03"))
    outcome, trace = attempt_commit(
        reg, sc, world, "agent:o3-operator",
        {"action": "write", "task": "T3", "tool": "cart.set_config", "target": "cart-config",
         "args": {"key": "redis_addr", "value": "redis-cart:6379"}}, "cmd-t3")
    TRACES.append(trace)
    assert outcome == "COMMITTED", trace
    assert trace["native_effect_delta"] == 1
    assert world.get_state()["cart"]["config"]["redis_addr"] == "redis-cart:6379"
    assert reg.write_status("T3") == "VERIFIED"
    # restart then completes the remediation (derived readiness flips)
    outcome2, trace2 = attempt_commit(
        reg, sc, world, "agent:o3-operator",
        {"action": "write", "task": "T4", "tool": "cart.restart", "target": "cart",
         "args": {"service": "cart"}}, "cmd-t4")
    TRACES.append(trace2)
    assert outcome2 == "COMMITTED", trace2
    assert world.get_state()["cart"]["readiness"] == "ready"
    assert world.get_state()["cart"]["flow_result"] == "ok"
    assert reg.write_status("T4") == "VERIFIED"


def test_valid_commit_receipt_readback_and_state_hash_match():
    """Positive trace: receipt + readback + state hash all match the effect."""
    reg = bind.otel_registry()
    sc = CausalSidecar(reg, log=lambda r: None)
    world = World(load("SYN-OTEL-03"))
    outcome, trace = attempt_commit(
        reg, sc, world, "agent:o3-operator",
        {"action": "write", "task": "T3", "tool": "cart.set_config", "target": "cart-config",
         "args": {"key": "redis_addr", "value": "redis-cart:6379"}}, "cmd-receipt-readback")
    TRACES.append(trace)
    assert outcome == "COMMITTED", trace
    ev = reg.obligations["T3"].satisfied["WRITE"]
    # receipt: matching receipt identity, permit and effect/command binding
    receipt = ev["receipt"]
    assert ev["receipt_id"] == receipt["receipt_id"] == "rcpt-cmd-receipt-readback"
    assert receipt["permit_verified"] is True
    assert receipt["effect_id"] == trace["effect_id"] == ev["effect_id"]
    assert receipt["command_id"] == trace["command_id"] == ev["command_id"]
    assert receipt["attempt_uid"] == ATT and receipt["world_instance_id"] == WIN
    assert receipt["epoch"] == EPOCH
    # readback: independent confirmed readback bound to the same effect
    readback = ev["readback"]
    assert readback["confirmed"] is True
    assert readback["effect_id"] == trace["effect_id"]
    assert readback["command_id"] == trace["command_id"]
    # state: readback state hash equals the post-commit world state hash
    assert readback["state_sha256"] == trace["world_state_after"]
    assert trace["world_state_after"] == state_sha256(world.get_state())
    assert trace["world_state_before"] != trace["world_state_after"]
    assert world.get_state()["cart"]["config"]["redis_addr"] == "redis-cart:6379"
    assert reg.write_status("T3") == "VERIFIED"


def test_zz_trace_artifact_with_hashes():
    # Self-contained negative counterexample + positive trace, persisted.
    reg = bind.otel_registry()
    sc = CausalSidecar(reg, log=lambda r: None)
    world = World(load("SYN-OTEL-03"))
    neg_outcome, neg = attempt_commit(
        reg, sc, world, "agent:o3-operator",
        {"action": "write", "task": "T3", "tool": "cart.set_config", "target": "cart-config",
         "args": {"key": "redis_addr", "value": "redis://localhost:6379"}}, "cmd-trace-bad")
    pos_outcome, pos = attempt_commit(
        reg, sc, world, "agent:o3-operator",
        {"action": "write", "task": "T3", "tool": "cart.set_config", "target": "cart-config",
         "args": {"key": "redis_addr", "value": "redis-cart:6379"}}, "cmd-trace-good")
    assert neg_outcome == "DENIED" and neg["native_effect_delta"] == 0
    assert neg["world_state_before"] == neg["world_state_after"]
    assert pos_outcome == "COMMITTED" and pos["native_effect_delta"] == 1
    assert pos["world_state_before"] != pos["world_state_after"]
    artifact = {"negative_counterexample": neg, "positive_execution": pos,
                "suite_traces": TRACES}
    out_dir = HERE.parents[2] / "_wo008_input"
    if out_dir.is_dir():
        (out_dir / "WO008_03_TRACES.json").write_text(
            json.dumps(artifact, indent=1, sort_keys=True), encoding="utf-8")
    assert artifact["negative_counterexample"]["world_state_before"]
    assert artifact["positive_execution"]["effect_id"]
