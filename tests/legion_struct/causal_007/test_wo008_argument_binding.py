"""WO008-03 argument binding: public-contract binding at the sidecar and
the CAGE HARD tier (real functions, real world specs, no NIM)."""
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

from causal_007.action_binding import compile_action_binding, validate_action_binding  # noqa: E402
from causal_007.causal_registry import CausalRegistry  # noqa: E402
from causal_007.sidecar import CausalSidecar  # noqa: E402

WORLDS = HERE.parent / "worlds"
ATT, WIN, EPOCH = "att-wo008-03", "win-wo008-03", 1


def load(family):
    for p in sorted(WORLDS.glob("*.world.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        if d.get("family") == family:
            d = copy.deepcopy(d)
            d.update(attempt_uid=ATT, world_instance_id=WIN, epoch=EPOCH)
            return d
    raise AssertionError(family)


def triplet(reg, task, agent, tool, target, args, suffix="1"):
    base = {"agent_id": agent, "task_id": task, "effect_id": f"eff-{suffix}",
            "command_id": f"cmd-{suffix}", "epoch": EPOCH, "permit_epoch": EPOCH,
            "attempt_uid": ATT, "world_instance_id": WIN,
            "tool": tool, "target": target, "args": args}
    reg.ingest([
        {"kind": "NATIVE_EFFECT", **base},
        {"kind": "RECEIPT", "receipt_id": f"rcpt-{suffix}", "permit_verified": True, **base},
        {"kind": "READBACK_EFFECT", "confirmed": True, "state_sha256": "s", **base}])


# ---------------------------------------------------------------- ADA registry
def ada_registry():
    reg = CausalRegistry(load("SYN-GAIA-ADA"))
    healthy = {"regions": {"east": {"health": "healthy", "latency_ms": 20},
                           "west": {"health": "healthy", "latency_ms": 45}}}
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:ada-monitor", "task_id": "T1",
                 "observation_id": "obs-t1", "epoch": EPOCH, "facts": healthy}])
    triplet(reg, "T2", "agent:ada-operator", "router.set_region", "router",
            {"region": "east"}, "t2")
    reg.ingest([{"kind": "WAIT_OBSERVED", "agent_id": "agent:ada-monitor", "task_id": "T3",
                 "event_id": "ev-ada-degrade"}])
    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": "agent:ada-monitor", "task_id": "T5",
                 "recipient": "agent:ada-operator", "message_id": "m-t5"}])
    # Fresh post-degradation destination health, read under T4 itself.
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:ada-operator", "task_id": "T4",
                 "observation_id": "obs-t4-fresh", "epoch": EPOCH,
                 "facts": {"regions": {"east": {"health": "degraded", "latency_ms": 950},
                                       "west": {"health": "healthy", "latency_ms": 45}}}}])
    assert reg.is_confirmed("T5")
    return reg


def test_ada_valid_failover_bound_and_admitted():
    reg = ada_registry()
    sc = CausalSidecar(reg, log=lambda r: None)
    action = {"action": "write", "task": "T4", "tool": "router.failover",
              "target": "router-failover", "args": {"region": "west"},
              "attempt_uid": ATT, "world_instance_id": WIN, "epoch": EPOCH}
    ok, code, b = validate_action_binding(
        reg, "T4", tool="router.failover", target="router-failover",
        args={"region": "west"}, attempt_uid=ATT, world_instance_id=WIN, epoch=EPOCH)
    assert ok and code == "BINDING_OK", b.to_dict()
    assert b.necessity == "T" and b.dependencies_verified
    assert "obs-t4-fresh" in b.necessity_evidence_refs
    assert b.attempt_uid == ATT and b.world_instance_id == WIN and b.epoch == EPOCH
    v = sc.check("agent:ada-operator", action, "d-ada-ok")
    assert v.allowed, v.to_dict()


def test_ada_wrong_destination_denied():
    reg = ada_registry()
    sc = CausalSidecar(reg, log=lambda r: None)
    v = sc.check("agent:ada-operator",
                 {"action": "write", "task": "T4", "tool": "router.failover",
                  "target": "router-failover", "args": {"region": "east"}}, "d-ada-east")
    assert not v.allowed and v.code == "ADA_WRONG_DESTINATION", v.to_dict()


def test_ada_no_fresh_degradation_evidence_not_proven():
    spec = load("SYN-GAIA-ADA")
    reg = CausalRegistry(spec)  # nothing confirmed: deps also open at sidecar
    ok, code, b = validate_action_binding(
        reg, "T4", tool="router.failover", target="router-failover", args={"region": "west"})
    assert not ok and b.necessity in ("T", "Z")  # never proven necessity
    assert code in ("BINDING_DEPENDENCIES_UNVERIFIED", "ADA_DESTINATION_HEALTH_UNVERIFIED")


# ---------------------------------------------------------------- A2A registry
def a2a_registry(with_price=True):
    reg = CausalRegistry(load("SYN-GAIA-A2A"))
    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": "agent:a2a-requester", "task_id": "T1",
                 "recipient": "agent:a2a-finance", "message_id": "m1"}])
    facts = [{"observation_id": "obs-budget", "facts": {"budget_remaining_usd": 10000}}]
    if with_price:
        facts.append({"observation_id": "obs-price", "facts": {"unit_price_usd": 1000}})
    for f in facts:
        reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:a2a-finance",
                     "task_id": "T2", "epoch": EPOCH, **f}])
    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": "agent:a2a-finance", "task_id": "T3",
                 "recipient": "agent:a2a-requester", "message_id": "m3"}])
    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": "agent:a2a-requester", "task_id": "T4",
                 "recipient": "agent:a2a-purchaser", "message_id": "m4"}])
    assert reg.is_confirmed("T4")
    return reg


def test_a2a_quantity_10_grounded_in_price_and_budget():
    reg = a2a_registry()
    ok, code, b = validate_action_binding(
        reg, "T5", tool="purchasing.place_order", target="purchase-order",
        args={"item": "laptop-14", "qty": 10})
    assert ok, b.to_dict()
    assert b.expected_args == {"item": "laptop-14", "qty": 10}  # 10000 / 1000
    sc = CausalSidecar(reg, log=lambda r: None)
    v = sc.check("agent:a2a-purchaser",
                 {"action": "write", "task": "T5", "tool": "purchasing.place_order",
                  "target": "purchase-order", "args": {"item": "laptop-14", "qty": 10}}, "d-a2a-ok")
    assert v.allowed, v.to_dict()


@pytest.mark.parametrize("qty", [12, 9, 11, 0])
def test_a2a_wrong_quantity_denied(qty):
    reg = a2a_registry()
    ok, code, _b = validate_action_binding(
        reg, "T5", tool="purchasing.place_order", target="purchase-order",
        args={"item": "laptop-14", "qty": qty})
    assert not ok and code == "A2A_QUANTITY_MISMATCH"


def test_a2a_cost_not_grounded_without_observed_price():
    # Earn the upstream handoff, then remove its price proof to isolate the
    # final binding's independent missing-evidence check. An initial handoff
    # without price is now correctly rejected before this boundary.
    reg = a2a_registry(with_price=True)
    reg.observations.pop("obs-price")
    ok, code, b = validate_action_binding(
        reg, "T5", tool="purchasing.place_order", target="purchase-order",
        args={"item": "laptop-14", "qty": 10})
    assert not ok and code == "A2A_COST_NOT_GROUNDED" and b.necessity == "Z"


# ---------------------------------------------------------------- OTEL-03
def otel_registry():
    reg = CausalRegistry(load("SYN-OTEL-03"))
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:o3-diag", "task_id": "T1",
                 "observation_id": "obs-t1", "epoch": EPOCH,
                 "facts": {"config": {"redis_addr": "redis-cart:6380"},
                           "readiness": "failing"}}])
    reg.ingest([{"kind": "ANALYSIS_RECORD", "agent_id": "agent:o3-diag", "task_id": "T2",
                 "facts": {"cause": "redis_unreachable_wrong_port",
                           "correct_redis_addr": "redis-cart:6379"},
                 "evidence_refs": ["obs-t1"]}])
    assert reg.is_confirmed("T2")
    return reg


def test_otel03_confirmed_redis_endpoint_bound():
    reg = otel_registry()
    ok, code, b = validate_action_binding(
        reg, "T3", tool="cart.set_config", target="cart-config",
        args={"key": "redis_addr", "value": "redis-cart:6379"})
    assert ok and b.expected_args == {"key": "redis_addr", "value": "redis-cart:6379"}, b.to_dict()
    sc = CausalSidecar(reg, log=lambda r: None)
    v = sc.check("agent:o3-operator",
                 {"action": "write", "task": "T3", "tool": "cart.set_config",
                  "target": "cart-config",
                  "args": {"key": "redis_addr", "value": "redis-cart:6379"}}, "d-otel-ok")
    assert v.allowed, v.to_dict()


@pytest.mark.parametrize("value", ["redis://localhost:6379", "localhost:6379",
                                   "redis-cart:6380", "redis://redis-cart:6379"])
def test_otel03_wrong_redis_endpoint_denied(value):
    reg = otel_registry()
    sc = CausalSidecar(reg, log=lambda r: None)
    v = sc.check("agent:o3-operator",
                 {"action": "write", "task": "T3", "tool": "cart.set_config",
                  "target": "cart-config", "args": {"key": "redis_addr", "value": value}},
                 f"d-otel-{value}")
    assert not v.allowed and v.code == "OTEL_REDIS_ENDPOINT_MISMATCH", v.to_dict()


def test_otel03_probe_disable_is_not_necessity():
    reg = otel_registry()
    ok, code, b = validate_action_binding(
        reg, "T7", tool="cart.disable_probe", target="cart-probe", args={"service": "cart"})
    assert not ok and b.necessity in ("F", "Z") and code in (
        "NECESSITY_FALSE", "NECESSITY_UNKNOWN")
    sc = CausalSidecar(reg, log=lambda r: None)
    v = sc.check("agent:o3-operator",
                 {"action": "write", "task": "T7", "tool": "cart.disable_probe",
                  "target": "cart-probe", "args": {"service": "cart"}}, "d-otel-t7")
    assert not v.allowed  # conditional alternative: registry presence != necessity


# ---------------------------------------------------------------- generic binding
def synthetic(requirement=None, activation=None):
    w = {"task_id": "W", "kinds": ["WRITE"], "read_tools": ["t.get"],
         "write_tool": "t.exec", "target": "target", "recipients": [],
         "depends_on": ["R"], "gate_facts": [],
         "bound_args": {"mode": "safe", "level": 2}}
    if requirement:
        w["requirement"] = requirement
        w["activation"] = activation
        w["activation_predicate"] = {"field": "v", "equals": 1}
    return {"world_id": "SYNTH-W008-03", "family": "SYNTH-W008-03",
            "attempt_uid": ATT, "world_instance_id": WIN, "epoch": EPOCH,
            "tools": {"t.get": {"kind": "read", "params": {}, "returns": {}},
                      "t.exec": {"kind": "write", "params": {}, "returns": {}}},
            "roles": [{"agent_id": "agent:op", "tasks": [
                {"task_id": "R", "kinds": ["READ"], "read_tools": ["t.get"],
                 "depends_on": [], "recipients": []}, w]}]}


def ready_reg(**kw):
    reg = CausalRegistry(synthetic(**kw))
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:op", "task_id": "R",
                 "observation_id": "obs-r", "epoch": EPOCH, "facts": {"v": 1}}])
    return reg


def write_action(**over):
    a = {"action": "write", "task": "W", "tool": "t.exec", "target": "target",
         "args": {"mode": "safe", "level": 2}}
    a.update(over)
    return a


def test_wrong_tool_denied():
    sc = CausalSidecar(ready_reg(), log=lambda r: None)
    v = sc.check("agent:op", write_action(tool="t.get"), "d1")
    assert not v.allowed and v.code == "BINDING_TOOL_MISMATCH", v.to_dict()


def test_wrong_target_denied():
    sc = CausalSidecar(ready_reg(), log=lambda r: None)
    v = sc.check("agent:op", write_action(target="elsewhere"), "d1")
    assert not v.allowed and v.code == "BINDING_TARGET_MISMATCH", v.to_dict()


def test_wrong_arguments_denied():
    sc = CausalSidecar(ready_reg(), log=lambda r: None)
    v = sc.check("agent:op", write_action(args={"mode": "safe", "level": 3}), "d1")
    assert not v.allowed and v.code == "BINDING_ARGS_MISMATCH", v.to_dict()


def test_false_necessity_denied():
    reg = ready_reg(requirement="CONDITIONAL", activation="F")
    ok, code, b = validate_action_binding(
        reg, "W", tool="t.exec", target="target", args={"mode": "safe", "level": 2})
    assert not ok and code == "NECESSITY_FALSE" and b.necessity == "F"
    sc = CausalSidecar(reg, log=lambda r: None)
    v = sc.check("agent:op", write_action(), "d1")
    assert not v.allowed and v.code == "NOT_REQUIRED", v.to_dict()


def test_unknown_necessity_denied():
    reg = CausalRegistry(synthetic(requirement="CONDITIONAL", activation="Z"))
    reg.obligations["W"].activation_predicate = "unstructured public brief"
    ok, code, b = validate_action_binding(
        reg, "W", tool="t.exec", target="target", args={"mode": "safe", "level": 2})
    assert not ok and code == "NECESSITY_UNKNOWN" and b.necessity == "Z"
    sc = CausalSidecar(reg, log=lambda r: None)
    v = sc.check("agent:op", write_action(), "d1")
    assert not v.allowed and v.code == "ACTIVATION_UNRESOLVED", v.to_dict()


def test_wrong_epoch_and_attempt_denied():
    reg = ready_reg()
    ok, code, _ = validate_action_binding(
        reg, "W", tool="t.exec", target="target", args={"mode": "safe", "level": 2}, epoch=99)
    assert not ok and code == "BINDING_EPOCH_MISMATCH"
    ok, code, _ = validate_action_binding(
        reg, "W", tool="t.exec", target="target", args={"mode": "safe", "level": 2},
        attempt_uid="att-foreign")
    assert not ok and code == "BINDING_ATTEMPT_MISMATCH"
    sc = CausalSidecar(reg, log=lambda r: None)
    v = sc.check("agent:op", write_action(epoch=99), "d-epoch")
    assert not v.allowed and v.code == "BINDING_EPOCH_MISMATCH", v.to_dict()
    v = sc.check("agent:op", write_action(attempt_uid="att-foreign"), "d-att")
    assert not v.allowed and v.code == "BINDING_ATTEMPT_MISMATCH", v.to_dict()


def test_binding_identity_covers_bound_fields():
    reg = ready_reg()
    b1 = compile_action_binding(reg, "W", tool="t.exec", target="target",
                                args={"mode": "safe", "level": 2})
    b2 = compile_action_binding(reg, "W", tool="t.exec", target="target",
                                args={"mode": "safe", "level": 9})
    assert b1.ok and not b2.ok and b1.binding_id != b2.binding_id
    assert b1.dependents == reg.dependents_of("W")
    assert b1.attempt_uid == ATT and b1.world_instance_id == WIN and b1.epoch == EPOCH


# ---------------------------------------------------------------- CAGE HARD tier
def test_hard_tier_enforces_server_bound_binding():
    import asyncio as _a
    from struct_plugin import StructNodes, StructTaskTier
    spec = {"world_id": "SYNTH-TIER", "family": "SYNTH-TIER", "tools": {
                "t.exec": {"kind": "write", "params": {"level": {"type": "integer"}},
                           "returns": {}}},
            "roles": [{"agent_id": "agent:op", "tasks": [
                {"task_id": "W", "kinds": ["WRITE"], "write_tool": "t.exec",
                 "target": "target", "depends_on": []}]}]}
    nodes = StructNodes(spec)
    tier = StructTaskTier(nodes)
    base = {"task_id": "W", "tool": "t.exec", "target": "target", "args": {"level": 2}}

    async def codes(params):
        vs = await tier.evaluate("struct_W", params)
        return {v.code for v in vs}

    denied = _a.run(codes({**base, "bound_binding_ok": False,
                           "bound_binding_code": "ADA_WRONG_DESTINATION",
                           "bound_necessity": "T"}))
    assert "ADA_WRONG_DESTINATION" in denied
    mismatched = _a.run(codes({**base, "bound_binding_ok": True,
                               "bound_expected_args": json.dumps({"level": 2}),
                               "args": {"level": 3}}))
    assert "BINDING_ARGS_MISMATCH" in mismatched
    allowed = _a.run(codes({**base, "bound_binding_ok": True,
                            "bound_expected_args": json.dumps({"level": 2})}))
    assert "BINDING_ARGS_MISMATCH" not in allowed
    assert not any(c.startswith(("ADA_", "BINDING", "NECESSITY", "OTEL", "A2A"))
                   for c in allowed)
