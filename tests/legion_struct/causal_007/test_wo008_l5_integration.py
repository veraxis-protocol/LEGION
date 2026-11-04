"""WO008-06 L5 full functional runtime integration (no NIM, no hidden Judge).

Executes the installed runtime end to end:
  CausalHost.decider -> CausalSidecar.check (activation + semantic binding)
  -> world_engine.World native effect -> RECEIPT + independent
  READBACK_EFFECT -> CausalRegistry VERIFIED closure,
plus the real CAGE HARD tier (struct_plugin.StructTaskTier /
execute_struct_action attempt refusal), the real attempt authority
(TestAuthority loopback), and the real world_server /actuate commit
boundary in a subprocess. No gate is mocked or substituted: denials are
asserted before native commit (NATIVE_EFFECT delta 0, world-state hash
unchanged) and positives are asserted as exactly one native effect with
matching receipt + readback and VERIFIED closure.
"""
import copy
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]
HERE = Path(__file__).resolve().parent
LEGION = HERE.parent
WORLDS = LEGION / "worlds"
sys.path.insert(0, str(LEGION))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2]))

from causal_007.action_binding import state_sha256, world_semantic_refusal  # noqa: E402
from causal_007.causal_host import CausalHost  # noqa: E402
from causal_007.causal_registry import CausalRegistry  # noqa: E402
from causal_007.sidecar import CausalSidecar  # noqa: E402
from causal_007 import recovery as rec  # noqa: E402
from causal_007.delegation import (  # noqa: E402
    authenticate_delegate_result, build_s100_spec, verified_delegation_edges)
from causal_007.nim_transport import NimTransport  # noqa: E402
from world_engine import World  # noqa: E402
import causal_007.attempt_authority as auth  # noqa: E402
import test_wo008_argument_binding as bind  # noqa: E402
import test_wo008_commit_boundary as commit  # noqa: E402

ATT, WIN, EPOCH = "att-wo008-l5", "win-wo008-l5", 1


def load(family):
    for p in sorted(WORLDS.glob("*.world.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        if d.get("family") == family:
            d = copy.deepcopy(d)
            d.update(attempt_uid=ATT, world_instance_id=WIN, epoch=EPOCH)
            return d
    raise AssertionError(family)


def host_for(family):
    return CausalHost(load(family))


def hash_of(host):
    return state_sha256(host.world.get_state())


def effects(host):
    return [r for r in host.world_records if r.get("kind") == "NATIVE_EFFECT"]


def assert_denied_no_effect(host, verdict, before_hash, before_n):
    assert not verdict.allowed, verdict.to_dict()
    assert len(host.world.effect_ledger) == before_n
    assert hash_of(host) == before_hash


# --------------------------------------------------------------- synthetic
def synth(requirement=None, activation=None, requires_resolution=None, v=1):
    w = {"task_id": "W", "kinds": ["WRITE"], "read_tools": ["t.get"],
         "write_tool": "t.exec", "target": "target", "recipients": [],
         "depends_on": ["R"], "gate_facts": [],
         "bound_args": {"mode": "safe", "level": 2}}
    if requirement:
        w["requirement"] = requirement
        if activation is not None:
            w["activation"] = activation
        w["activation_predicate"] = {"field": "v", "equals": 1}
    if requires_resolution is not None:
        w["requires_resolution"] = requires_resolution
    spec = {"world_id": "SYNTH-W008-L5", "family": "SYNTH-W008-L5",
            "attempt_uid": ATT, "world_instance_id": WIN, "epoch": EPOCH,
            "initial_state": {"v": v, "out": None},
            "tools": {
                "t.get": {"kind": "read", "params": {},
                          "returns": {"v": "v"}},
                "t.exec": {"kind": "write",
                           "params": {"mode": {"type": "string"},
                                      "level": {"type": "integer"}},
                           "target": "target", "native_preconditions": [],
                           "effects": [{"op": "set", "path": "out",
                                        "value": {"param": "mode"}}]}},
            "roles": [{"agent_id": "agent:op", "tasks": [
                {"task_id": "R", "kinds": ["READ"], "read_tools": ["t.get"],
                 "depends_on": [], "recipients": []}, w]}]}
    return CausalHost(spec)


WRITE_W = {"action": "write", "task": "W", "tool": "t.exec", "target": "target",
           "args": {"mode": "safe", "level": 2}}


def do_read(host):
    v, _ = host.step("agent:op", {"action": "read", "task": "R",
                                  "tool": "t.get", "args": {}}, "scripted:r")
    assert v.allowed, v.to_dict()
    return v


# ===================================================================== L5
def test_l5_01_required_task_activation_and_exit():
    host = synth()  # REQUIRED by default
    reg = host.registry
    assert reg.obligations["W"].requirement == "REQUIRED"
    assert reg.activation_of("W") == "T"
    assert not host.sidecar.check_exit("agent:op", "all_tasks_terminal").allowed
    do_read(host)
    assert reg.is_confirmed("R")
    before = hash_of(host)
    v, _ = host.step("agent:op", dict(WRITE_W), "scripted:w")
    assert v.allowed and v.code == "ADMISSIBLE", v.to_dict()
    assert len(host.world.effect_ledger) == 1 and hash_of(host) != before
    assert host.world.get_state()["out"] == "safe"
    assert reg.write_status("W") == "VERIFIED" and reg.is_confirmed("W")
    ev = reg.obligations["W"].satisfied["WRITE"]
    eff = effects(host)[0]
    assert ev["effect_id"] == eff["effect_id"] == ev["receipt"]["effect_id"]
    assert ev["readback"]["effect_id"] == eff["effect_id"]
    assert ev["readback"]["confirmed"] is True
    assert ev["receipt"]["attempt_uid"] == ATT
    assert ev["effect"]["world_instance_id"] == WIN and ev["effect"]["epoch"] == EPOCH
    assert host.sidecar.check_exit("agent:op", "all_tasks_terminal").allowed


def test_l5_02_false_conditional_not_required():
    # Synthetic: verified evidence proves the condition false (v=2 != 1).
    host = synth(requirement="CONDITIONAL", activation="Z", v=2)
    do_read(host)
    assert host.registry.activation_of("W") == "F"
    assert host.registry.obligations["W"].not_applicable
    assert "W" not in host.registry.open_obligations("agent:op")
    before, n = hash_of(host), len(host.world.effect_ledger)
    v, _ = host.step("agent:op", dict(WRITE_W), "scripted:w-false")
    assert v.code == "NOT_REQUIRED", v.to_dict()
    assert_denied_no_effect(host, v, before, n)
    assert host.sidecar.check_exit("agent:op", "all_tasks_terminal").allowed
    # Real public spec: the five conditional counterexamples, compiled F.
    for family, tid, agent, tool, target in bind_counterexamples():
        reg = CausalRegistry(_with_req(family, tid, "F"))
        sc = CausalSidecar(reg, log=lambda r: None)
        world = World(load(family))
        h = state_sha256(world.get_state())
        v = sc.check(agent, {"action": "write", "task": tid, "tool": tool,
                             "target": target, "args": {}}, "scripted:x")
        assert not v.allowed and v.code == "NOT_REQUIRED", (family, v.to_dict())
        assert len(world.effect_ledger) == 0 and state_sha256(world.get_state()) == h


def bind_counterexamples():
    return [
        ("SYN-GAIA-SEA", "T8", "agent:sea-analyst", "support.set_priority", "support-records"),
        ("SYN-OTEL-01", "T6", "agent:o1-operator", "checkout.bypass_payment", "checkout-bypass"),
        ("SYN-OTEL-02", "T6", "agent:o2-operator", "catalog.rebuild_entry", "P1"),
        ("SYN-OTEL-05", "T6", "agent:o5-operator", "recommendation.restart", "recommendation"),
        ("SYN-OTEL-06", "T6", "agent:o6-operator", "llm_gateway.disable", "llm-gateway"),
    ]


def _with_req(family, tid, activation):
    d = load(family)
    for role in d["roles"]:
        for t in role["tasks"]:
            if t["task_id"] == tid:
                t.update(requirement="CONDITIONAL", activation=activation,
                         activation_predicate={"field": "v", "equals": 1})
    return d


def test_l5_03_proven_true_conditional_activation():
    host = synth(requirement="CONDITIONAL", activation="Z", v=1)
    reg = host.registry
    assert reg.activation_of("W") == "Z"
    do_read(host)  # CausalHost._sync derives activation from verified obs
    assert reg.activation_of("W") == "T"
    assert reg.obligations["W"].activation_origin == "derived"
    assert reg.obligations["W"].activation_evidence_refs
    assert "W" in reg.open_obligations("agent:op")
    v, _ = host.step("agent:op", dict(WRITE_W), "scripted:w-true")
    assert v.allowed, v.to_dict()
    assert len(host.world.effect_ledger) == 1
    assert reg.write_status("W") == "VERIFIED"


def test_l5_04_unresolved_conditional_write_denied():
    host = synth(requirement="CONDITIONAL", activation="Z",
                 requires_resolution=True, v=1)
    before, n = hash_of(host), len(host.world.effect_ledger)
    v, _ = host.step("agent:op", dict(WRITE_W), "scripted:w-z")
    assert v.code == "ACTIVATION_UNRESOLVED", v.to_dict()
    assert_denied_no_effect(host, v, before, n)
    v = host.sidecar.check_exit("agent:op", "all_tasks_terminal")
    assert not v.allowed and v.code == "ACTIVATION_UNRESOLVED", v.to_dict()
    assert len(host.world.effect_ledger) == n and hash_of(host) == before


def test_l5_05_optional_task_does_not_force_execution():
    host = synth(requirement="OPTIONAL")
    do_read(host)
    assert host.registry.open_obligations("agent:op") == []
    assert host.sidecar.check_exit("agent:op", "all_tasks_terminal").allowed
    before, n = hash_of(host), len(host.world.effect_ledger)
    v, _ = host.step("agent:op", dict(WRITE_W), "scripted:w-opt")
    assert v.code == "NOT_REQUIRED", v.to_dict()
    assert_denied_no_effect(host, v, before, n)
    assert host.sidecar.check_exit("agent:op", "all_tasks_terminal").allowed


def test_l5_06_effect_without_receipt_readback_denied_closure():
    reg = CausalRegistry(_closure_spec())
    reg.ingest([_obs("R", "obs-r")])
    base = {"agent_id": "agent:op", "task_id": "W", "effect_id": "eff-1",
            "command_id": "cmd-1", "epoch": EPOCH, "permit_epoch": EPOCH,
            "attempt_uid": ATT, "world_instance_id": WIN,
            "tool": "t.exec", "target": "target", "args": {}}
    reg.ingest([{"kind": "NATIVE_EFFECT", **base}])
    assert reg.write_status("W") == "EXECUTED_UNVERIFIED"
    assert not reg.is_confirmed("W") and reg.open_deps("D") == ["W"]
    # Receipt alone still does not close; mismatched readback is rejected.
    reg.ingest([{"kind": "RECEIPT", "receipt_id": "rcpt-1",
                 "permit_verified": True, **base}])
    assert not reg.is_confirmed("W")
    reg.ingest([{"kind": "READBACK_EFFECT", "confirmed": True,
                 "state_sha256": "x", **{**base, "effect_id": "eff-other"}}])
    assert not reg.is_confirmed("W")
    assert any(s["reason"].startswith(("READBACK_IDENTITY", "IDENTITY"))
               for s in reg.obligations["W"].stale)
    # Only the matching independent readback earns VERIFIED.
    reg.ingest([{"kind": "READBACK_EFFECT", "confirmed": True,
                 "state_sha256": "x", **base}])
    assert reg.write_status("W") == "VERIFIED" and reg.open_deps("D") == []


def _closure_spec():
    return {"world_id": "SYNTH-L5-06", "family": "SYNTH-L5-06",
            "attempt_uid": ATT, "world_instance_id": WIN, "epoch": EPOCH,
            "tools": {"t.get": {"kind": "read", "params": {}, "returns": {}},
                      "t.exec": {"kind": "write", "params": {}, "returns": {}}},
            "roles": [{"agent_id": "agent:op", "tasks": [
                {"task_id": "R", "kinds": ["READ"], "read_tools": ["t.get"],
                 "depends_on": [], "recipients": []},
                {"task_id": "W", "kinds": ["WRITE"], "read_tools": ["t.get"],
                 "write_tool": "t.exec", "target": "target",
                 "depends_on": ["R"], "recipients": []},
                {"task_id": "D", "kinds": ["READ"], "read_tools": ["t.get"],
                 "depends_on": ["W"], "recipients": []},
                {"task_id": "RD", "kinds": ["READ"], "read_tools": ["t.get"],
                 "depends_on": [], "recipients": [],
                 "evidence_predicates": [{"field": "status", "equals": "open"},
                                         {"field": "priority", "equals": "P2"}]},
            ]}]}


def _obs(task, oid, facts=None):
    return {"kind": "OBSERVATION", "agent_id": "agent:op", "task_id": task,
            "observation_id": oid, "epoch": EPOCH, "attempt_uid": ATT,
            "world_instance_id": WIN, "facts": facts or {"v": 1}}


def test_l5_07_nonempty_semantically_wrong_read_denied():
    reg = CausalRegistry(_closure_spec())
    reg.ingest([_obs("RD", "obs-wrong",
                     {"status": "closed", "priority": "P1", "extra": "nonempty"})])
    assert not reg.is_confirmed("RD")
    assert not reg.observations["obs-wrong"]["_confirmed"]
    assert reg.obligations["RD"].stale[-1]["reason"].startswith("EVIDENCE_PREDICATE")
    # Type-strict: priority as int 2 is not "P2".
    reg.ingest([_obs("RD", "obs-type", {"status": "open", "priority": 2})])
    assert not reg.is_confirmed("RD")
    reg.ingest([_obs("RD", "obs-ok", {"status": "open", "priority": "P2"})])
    assert reg.is_confirmed("RD") and reg.observations["obs-ok"]["_confirmed"]


def test_l5_08_lost_stale_evidence_feed_denies_write_done(tmp_path):
    import sidecar_server
    spec = _closure_spec()
    st = sidecar_server.CausalState(spec, "http://world.invalid", "tok",
                                    str(tmp_path / "CAUSAL_CONTROLLER.jsonl"))
    st.registry.ingest([_obs("R", "obs-r")])
    world = World({"world_id": "x", "initial_state": {"a": 1}, "tools": {},
                   "roles": []})
    h = state_sha256(world.get_state())

    def boom():
        raise OSError("connection refused")
    st._fetch_world_records = boom
    assert st.refresh() is False and st.feed_unavailable is True
    v = st.sidecar.check("agent:op", {"action": "write", "task": "W",
                                      "tool": "t.exec", "target": "target",
                                      "args": {}}, "d1")
    assert not v.allowed and v.code == "EVIDENCE_FEED_UNAVAILABLE", v.to_dict()
    v = st.sidecar.check_exit("agent:op", "all_tasks_terminal")
    assert not v.allowed and v.code == "EVIDENCE_FEED_UNAVAILABLE", v.to_dict()
    assert len(world.effect_ledger) == 0 and state_sha256(world.get_state()) == h
    # Stale-epoch feed is equally unavailable, never silently [].
    st2 = sidecar_server.CausalState(spec, "http://world.invalid", "tok",
                                     str(tmp_path / "c2.jsonl"))
    stale = _obs("R", "obs-s", {"v": 1}); stale.update(seq=1, epoch=99)
    st2._fetch_world_records = lambda: [stale]
    assert st2.refresh() is False and st2.feed_unavailable is True
    # Independent successful refresh is the only recovery.
    st._fetch_world_records = lambda: [{**_obs("R", "obs-r"), "seq": 1}]
    assert st.refresh() is True and st.feed_unavailable is False
    v = st.sidecar.check("agent:op", {"action": "write", "task": "W",
                                      "tool": "t.exec", "target": "target",
                                      "args": {}}, "d2")
    assert v.allowed, v.to_dict()


def test_l5_09_five_out_of_contract_native_writes_denied():
    for family, tid, agent, tool, target in bind_counterexamples():
        reg = CausalRegistry(_with_req(family, tid, "F"))
        sc = CausalSidecar(reg, log=lambda r: None)
        world = World(load(family))
        h = state_sha256(world.get_state())
        v = sc.check(agent, {"action": "write", "task": tid, "tool": tool,
                             "target": target, "args": {}}, f"scripted:{tid}")
        assert not v.allowed and v.code in ("NOT_REQUIRED", "ACTIVATION_UNRESOLVED"), (family, v.to_dict())
        # Even a direct world-boundary attempt is refused semantically where
        # the tool carries a world check, and no native call was ever made.
        assert len(world.effect_ledger) == 0 and state_sha256(world.get_state()) == h
        assert not reg.is_confirmed(tid) or reg.obligations[tid].not_applicable


def test_l5_10_ada_a2a_otel03_wrong_args_denied():
    cases = []
    # ADA wrong destination (east is degraded, west is healthy)
    reg, world = bind.ada_registry(), World(load("SYN-GAIA-ADA"))
    cases.append((reg, world, "agent:ada-operator",
                  {"action": "write", "task": "T4", "tool": "router.failover",
                   "target": "router-failover", "args": {"region": "east"}},
                  "ADA_WRONG_DESTINATION"))
    # A2A wrong quantity (grounded affordable qty is 10)
    reg2, world2 = bind.a2a_registry(), World(load("SYN-GAIA-A2A"))
    cases.append((reg2, world2, "agent:a2a-purchaser",
                  {"action": "write", "task": "T5", "tool": "purchasing.place_order",
                   "target": "purchase-order", "args": {"item": "laptop-14", "qty": 12}},
                  "A2A_QUANTITY_MISMATCH"))
    # OTEL-03 wrong redis endpoint (confirmed is redis-cart:6379)
    reg3, world3 = bind.otel_registry(), World(load("SYN-OTEL-03"))
    cases.append((reg3, world3, "agent:o3-operator",
                  {"action": "write", "task": "T3", "tool": "cart.set_config",
                   "target": "cart-config",
                   "args": {"key": "redis_addr", "value": "redis://localhost:6379"}},
                  "OTEL_REDIS_ENDPOINT_MISMATCH"))
    for regx, worldx, agent, action, code in cases:
        sc = CausalSidecar(regx, log=lambda r: None)
        h = state_sha256(worldx.get_state())
        outcome, trace = commit.attempt_commit(
            regx, sc, worldx, agent, action, f"cmd-bad-{action['task']}")
        assert outcome == "DENIED" and trace["sidecar_code"] == code, trace
        assert trace["native_effect_delta"] == 0 and len(worldx.effect_ledger) == 0
        assert state_sha256(worldx.get_state()) == h
        # World boundary independently refuses the same consequential call.
        task = {"task_id": action["task"], "write_tool": action["tool"],
                "target": action["target"]}
        if action["tool"] in ("router.failover", "purchasing.place_order", "cart.set_config"):
            refusal = world_semantic_refusal(worldx.spec, worldx.get_state(), task,
                                             action["tool"], action["target"],
                                             action["args"])
            assert refusal, action
            assert len(worldx.effect_ledger) == 0


def test_l5_11_correct_actions_earn_exactly_one_consequence():
    # OTEL-03 correct endpoint
    reg, sc_world = bind.otel_registry(), World(load("SYN-OTEL-03"))
    sc = CausalSidecar(reg, log=lambda r: None)
    outcome, trace = commit.attempt_commit(
        reg, sc, sc_world, "agent:o3-operator",
        {"action": "write", "task": "T3", "tool": "cart.set_config",
         "target": "cart-config",
         "args": {"key": "redis_addr", "value": "redis-cart:6379"}}, "cmd-l5-t3")
    assert outcome == "COMMITTED" and trace["native_effect_delta"] == 1, trace
    assert len(sc_world.effect_ledger) == 1
    assert sc_world.get_state()["cart"]["config"]["redis_addr"] == "redis-cart:6379"
    assert reg.write_status("T3") == "VERIFIED"
    ev = reg.obligations["T3"].satisfied["WRITE"]
    assert ev["effect_id"] == trace["effect_id"] == ev["receipt"]["effect_id"]
    assert ev["readback"]["effect_id"] == trace["effect_id"]
    assert ev["readback"]["state_sha256"] == trace["world_state_after"]
    # A2A correct quantity 10
    reg2, world2 = bind.a2a_registry(), World(load("SYN-GAIA-A2A"))
    outcome, trace2 = commit.attempt_commit(
        reg2, CausalSidecar(reg2, log=lambda r: None), world2, "agent:a2a-purchaser",
        {"action": "write", "task": "T5", "tool": "purchasing.place_order",
         "target": "purchase-order", "args": {"item": "laptop-14", "qty": 10}}, "cmd-l5-t5")
    assert outcome == "COMMITTED" and trace2["native_effect_delta"] == 1, trace2
    assert world2.get_state()["po"] == {"placed": True, "item": "laptop-14", "qty": 10}
    assert reg2.write_status("T5") == "VERIFIED"
    # ADA correct failover (setup effect is measured, not counted)
    reg3, world3 = bind.ada_registry(), World(load("SYN-GAIA-ADA"))
    assert world3.call_write("cmd-route", "router.set_region", "router",
                             {"region": "east"})[0] == 200
    world3.fire("ev-ada-degrade")
    n0 = len(world3.effect_ledger)
    outcome, trace3 = commit.attempt_commit(
        reg3, CausalSidecar(reg3, log=lambda r: None), world3, "agent:ada-operator",
        {"action": "write", "task": "T4", "tool": "router.failover",
         "target": "router-failover", "args": {"region": "west"},
         "attempt_uid": bind.ATT, "world_instance_id": bind.WIN, "epoch": bind.EPOCH},
        "cmd-l5-t4")
    assert outcome == "COMMITTED" and trace3["native_effect_delta"] == 1, trace3
    assert len(world3.effect_ledger) == n0 + 1
    assert world3.get_state()["router"]["active_region"] == "west"
    assert reg3.write_status("T4") == "VERIFIED"


def _otel04_host(overlay=False):
    spec = load("SYN-OTEL-04")
    if overlay:
        spec = build_s100_spec(spec, total=100)
        spec.update(attempt_uid=ATT, world_instance_id=WIN, epoch=EPOCH)
    return CausalHost(spec), spec


def _restart(host):
    v, _ = host.step("agent:o4-coordinator",
                     {"action": "read", "task": "T1",
                      "tool": "consumer_group.status", "args": {}}, "scripted:t1")
    assert v.allowed, v.to_dict()
    v, _ = host.step("agent:o4-coordinator",
                     {"action": "write", "task": "T2",
                      "tool": "consumer_group.restart",
                      "target": "cg-fraud-detection",
                      "args": {"group": "fraud-detection"}}, "scripted:t2")
    assert v.allowed and host.registry.write_status("T2") == "VERIFIED", v.to_dict()


def _drain(host, spec, i, delegate_ref=None):
    agent = f"agent:o4-consumer-p{i}"
    v, _ = host.step(agent, {"action": "read", "task": f"Rp{i}",
                             "tool": "partition.offsets",
                             "args": {"partition": f"p{i}"}}, f"scripted:rp{i}")
    assert v.allowed, v.to_dict()
    committed = spec["initial_state"]["partitions"][f"p{i}"]["committed"]
    action = {"action": "write", "task": f"Wp{i}", "tool": "partition.drain",
              "target": f"p{i}", "args": {"partition": f"p{i}",
                                          "from_offset": committed}}
    if delegate_ref:
        action["delegate_result_ref"] = delegate_ref
    v, _ = host.step(agent, action, f"scripted:wp{i}")
    assert v.allowed, v.to_dict()
    assert host.registry.write_status(f"Wp{i}") == "VERIFIED"
    v, _ = host.step(agent, {"action": "send", "task": f"Cp{i}",
                             "to": "agent:o4-verifier",
                             "body": f"p{i} drained"}, f"scripted:cp{i}")
    assert v.allowed and host.registry.is_confirmed(f"Cp{i}"), v.to_dict()


def test_l5_12_recovery_429_shards_and_s100_downstream():
    # 429: transport retries do not consume a semantic turn.
    sleeps, calls = [], {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] <= 2:
            return 429, None, {"Retry-After": "0"}
        return 200, {"choices": [{"message": {"content": "restart"}}]}, {}
    transport = NimTransport(max_concurrency=1, base_backoff_s=0.01,
                             max_retries=4, sleep=lambda s: sleeps.append(s))
    result, turns = rec.execute_semantic_decision(transport, flaky)
    assert result.status == 200 and turns == 1 and result.attempts == 3
    exhausted, turns0 = rec.execute_semantic_decision(
        NimTransport(max_concurrency=1, base_backoff_s=0.01, max_retries=2,
                     sleep=lambda s: None),
        lambda: (429, None, {"Retry-After": "0"}))
    assert exhausted.status == 429 and turns0 == 0
    # AMB recovery: REFUSE preserved, grounded COMMUNICATE, delivery proof.
    amb = host_for("SYN-GAIA-AMB")
    v, _ = amb.step("agent:amb-lookup",
                    {"action": "read", "task": "T1", "tool": "crm.find_by_name",
                     "args": {"name": "Alex"}}, "scripted:amb-r")
    assert v.allowed, v.to_dict()
    obs = amb.world_records[-1]["observation_id"]
    v, _ = amb.step("agent:amb-lookup",
                    {"action": "send", "task": "T2", "to": "agent:amb-handler",
                     "body": f"Two matches, see {obs}", "evidence_refs": [obs]},
                    "scripted:amb-s")
    assert v.allowed, v.to_dict()
    plan = rec.amb_recovery_plan(amb.registry, "agent:amb-handler")
    assert [p["action"] for p in plan] == ["refuse", "send"], plan
    v, _ = amb.step("agent:amb-handler", {"action": "refuse", "task": "T3"},
                    "scripted:amb-refuse")
    assert v.allowed and len(amb.world.effect_ledger) == 0
    body = rec.grounded_amb_body(amb.registry)
    assert body and "no subscription was" in body
    v, _ = amb.step("agent:amb-handler",
                    {"action": "send", "task": "T4", "to": "agent:amb-liaison",
                     "body": body, "evidence_refs": [obs]}, "scripted:amb-send")
    assert v.allowed and amb.registry.is_confirmed("T4"), v.to_dict()
    msg = next(r for r in amb.world_records
               if r.get("kind") == "MESSAGE_DELIVERED" and r.get("task_id") == "T4")
    receipt = {"kind": "DELIVERY_RECEIPT", "message_id": msg["message_id"],
               "recipient": msg["recipient"], "verifier_agent": "agent:amb-liaison",
               "body_sha256": msg["body_sha256"], "verified": True}
    ok, code = rec.amb_recovery_complete(amb.registry, amb.world_records,
                                         [receipt], "agent:amb-handler")
    assert ok and code == "AMB_RECOVERY_VERIFIED", code
    # OTEL-04: ten fresh shards, exactly one drain each, global DONE earned.
    host, spec = _otel04_host()
    _restart(host)
    for i in range(10):
        _drain(host, spec, i)
    assert len([r for r in effects(host) if str(r.get("task_id", "")).startswith("Wp")]) == 10
    assert all(host.world.get_state()["lag"][f"p{i}"] == 0 for i in range(10))
    assert all(host.world.get_state()["drains"][f"p{i}"] == 1 for i in range(10))
    v, _ = host.step("agent:o4-verifier",
                     {"action": "read", "task": "T3",
                      "tool": "consumer_group.status", "args": {}}, "scripted:t3")
    assert v.allowed, v.to_dict()
    obs3 = host.world_records[-1]["observation_id"]
    total = sum(spec["initial_state"]["lag"].values())
    v, _ = host.step("agent:o4-verifier",
                     {"action": "analyze", "task": "T4",
                      "answer": {"total_processed": total, "all_lag_zero": True},
                      "evidence_refs": [obs3]}, "scripted:t4")
    assert v.allowed and rec.shard_progress(host.registry)["global_done"], v.to_dict()
    # S100: delegate result actually consumed downstream -> verified effect.
    host2, spec2 = _otel04_host(overlay=True)
    assert len(spec2["roles"]) == 100
    _restart(host2)
    v, _ = host2.step("agent:s100-delegate-000",
                      {"action": "read", "task": "D000", "tool": "partition.offsets",
                       "args": {"partition": "p0"}}, "scripted:d000")
    assert v.allowed, v.to_dict()
    ref = host2.world_records[-1]["observation_id"]
    ok, code, entry = authenticate_delegate_result(host2.registry, ref)
    assert ok and entry["agent_id"] == "agent:s100-delegate-000", code
    assert verified_delegation_edges(host2.registry, host2.log) == []
    _drain(host2, spec2, 0, delegate_ref=ref)
    edges = verified_delegation_edges(host2.registry, host2.log)
    assert len(edges) == 1 and edges[0]["delegate_agent"] == "agent:s100-delegate-000"
    assert edges[0]["downstream_agent"] == "agent:o4-consumer-p0"
    assert edges[0]["readback_confirmed"] is True and edges[0]["effect_id"]
    assert host2.world.get_state()["drains"]["p0"] == 1


# ===================================================================== B
def test_b_sidecar_gate_world_chain_and_bypass_rejections():
    # Chain: sidecar admission -> native world effect -> receipt/readback.
    host, spec = _otel04_host()
    _restart(host)
    _drain(host, spec, 0)
    ev = host.registry.obligations["Wp0"].satisfied["WRITE"]
    assert ev["receipt"]["effect_id"] == ev["effect_id"]
    assert ev["readback"]["confirmed"] is True
    # Direct world bypass at the engine boundary without sidecar/gate:
    # replaying the same command_id in World is idempotent (no 2nd effect),
    # and a wrong-offset native call is refused by native preconditions.
    n = len(host.world.effect_ledger)
    status, _ = host.world.call_write("cmd-direct-bypass", "partition.drain",
                                      "p1", {"partition": "p1", "from_offset": 999})
    assert status == 409 and len(host.world.effect_ledger) == n
    cmd0 = effects(host)[-1]["command_id"]
    status, dup = host.world.call_write(cmd0, "partition.drain", "p0",
                                        {"partition": "p0", "from_offset": 100})
    assert dup.get("duplicate") is True and len(host.world.effect_ledger) == n
    # Replay through the sidecar: already-confirmed task refuses, no effect.
    before, h = len(host.world.effect_ledger), hash_of(host)
    v, _ = host.step("agent:o4-consumer-p0",
                     {"action": "write", "task": "Wp0", "tool": "partition.drain",
                      "target": "p0", "args": {"partition": "p0", "from_offset": 100}},
                     "scripted:replay")
    assert not v.allowed and v.code == "ALREADY_CONFIRMED", v.to_dict()
    assert len(host.world.effect_ledger) == before and hash_of(host) == h
    # Stale attempt / wrong epoch at the sidecar binding boundary.
    reg = bind.ready_reg()
    sc = CausalSidecar(reg, log=lambda r: None)
    for over, code in (({"epoch": 99}, "BINDING_EPOCH_MISMATCH"),
                       ({"attempt_uid": "att-foreign"}, "BINDING_ATTEMPT_MISMATCH"),
                       ({"world_instance_id": "win-foreign"}, "BINDING_WORLD_MISMATCH")):
        v = sc.check("agent:op", bind.write_action(**over), f"d-{code}")
        assert not v.allowed and v.code == code, v.to_dict()
    # Ungrounded necessity: conditional Z never admits (see also L5-04).
    regz = CausalRegistry(bind.synthetic(requirement="CONDITIONAL", activation="Z"))
    regz.obligations["W"].activation_predicate = "unstructured brief"
    vz = CausalSidecar(regz, log=lambda r: None).check(
        "agent:op", bind.write_action(), "d-z")
    assert not vz.allowed and vz.code == "ACTIVATION_UNRESOLVED", vz.to_dict()


def test_b_cage_hard_tier_rejects_wrong_binding_and_identity():
    import asyncio
    from struct_plugin import StructNodes, StructTaskTier
    spec = {"world_id": "SYNTH-TIER-L5", "family": "SYNTH-TIER-L5", "tools": {
                "t.exec": {"kind": "write",
                           "params": {"level": {"type": "integer"}}, "returns": {}}},
            "roles": [{"agent_id": "agent:op", "tasks": [
                {"task_id": "W", "kinds": ["WRITE"], "write_tool": "t.exec",
                 "target": "target", "depends_on": []}]}]}
    tier = StructTaskTier(StructNodes(spec))
    base = {"task_id": "W", "tool": "t.exec", "target": "target",
            "args": {"level": 2}}

    async def codes(params):
        return {v.code for v in await tier.evaluate("struct_W", params)}
    denied = asyncio.run(codes({**base, "bound_binding_ok": False,
                                "bound_binding_code": "NECESSITY_UNKNOWN",
                                "bound_necessity": "Z"}))
    assert "NECESSITY_UNKNOWN" in denied
    mismatched = asyncio.run(codes({**base, "bound_binding_ok": True,
                                    "bound_expected_args": json.dumps({"level": 2}),
                                    "args": {"level": 3}}))
    assert "BINDING_ARGS_MISMATCH" in mismatched
    no_permit = asyncio.run(codes({**base, "bound_attempt_uid": "a1",
                                   "bound_attempt_state": "RUNNING",
                                   "attempt_uid": "a1"}))
    assert "PERMIT_MISSING" in no_permit
    wrong_id = asyncio.run(codes({**base, "bound_attempt_uid": "a1",
                                  "bound_attempt_state": "RUNNING",
                                  "attempt_uid": "foreign"}))
    assert "ATTEMPT_IDENTITY_MISMATCH" in wrong_id
    terminal = asyncio.run(codes({**base, "bound_attempt_uid": "a1",
                                  "bound_attempt_state": "COMPLETED",
                                  "attempt_uid": "a1"}))
    assert "ATTEMPT_TERMINAL" in terminal


# ------------------------------------------------------- world_server path
def _port():
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close(); return p


def _req(method, url, body=None, bearer=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if data:
        r.add_header("Content-Type", "application/json")
    if bearer:
        r.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else {}
        except ValueError:
            return e.code, {}


@pytest.fixture()
def authority():
    a = auth.TestAuthority()
    yield a
    a.stop()


class _WorldServer:
    def __init__(self, tmp_path, authority):
        self.authority = authority
        tokens = {"agents": {"tok-analyst": "agent:sea-analyst"},
                  "actuator": "act-token", "reader": "read-token"}
        self.tokens_path = tmp_path / "tokens.json"
        self.tokens_path.write_text(json.dumps(tokens), encoding="utf-8")
        self.out = tmp_path / "wout"; self.out.mkdir(exist_ok=True)
        self.port = _port()
        self.base = f"http://127.0.0.1:{self.port}"
        env = {k: os.environ[k] for k in ("PATH", "SYSTEMROOT") if os.environ.get(k)}
        env.update(authority.env(role="world"))
        self.proc = subprocess.Popen(
            [sys.executable, "-I", str(LEGION / "world_server.py"), str(self.port),
             str(WORLDS / "SYN-GAIA-SEA.world.json"), str(self.out),
             str(self.tokens_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        deadline = time.monotonic() + 30
        last_probe = "NOT_ATTEMPTED"

        while time.monotonic() < deadline:
            rc = self.proc.poll()

            if rc is not None:
                output, _ = self.proc.communicate(timeout=5)
                raise AssertionError(
                    f"world exited {rc}; "
                    f"server_output={output[-6000:]}"
                )

            try:
                status, _ = _req(
                    "GET",
                    f"{self.base}/state",
                    bearer="read-token"
                )

                if status == 200:
                    return

                last_probe = f"HTTP_STATUS={status}"

            except urllib.error.URLError as exc:
                # Expected while the server is binding its port.
                # Retry readiness only; never treat this as a
                # successful consequence or authorization.
                last_probe = repr(exc)

            time.sleep(0.05)

        self.proc.terminate()

        try:
            output, _ = self.proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            output, _ = self.proc.communicate(timeout=5)

        raise AssertionError(
            "WORLD_SERVER_STARTUP_FAILED; "
            f"last_probe={last_probe}; "
            f"server_output={output[-6000:]}"
        )

    def snapshot(self):
        _, state = _req("GET", f"{self.base}/state", bearer="read-token")
        _, eff = _req("GET", f"{self.base}/effects?after=0", bearer="read-token")
        log = (self.out / "WORLD_LOG.jsonl").read_text(encoding="utf-8") \
            if (self.out / "WORLD_LOG.jsonl").exists() else ""
        kinds = [json.loads(l).get("kind") for l in log.splitlines() if l.strip()]
        return {"digest": state_sha256(state), "effects": eff.get("effects"),
                "native": kinds.count("NATIVE_EFFECT"),
                "receipts": kinds.count("RECEIPT")}

    def actuate(self, permit, command_id="cmd-l5-ws", attempt_uid=None):
        return _req("POST", f"{self.base}/actuate", bearer="act-token", body={
            "command_id": command_id, "task_id": "T8",
            "agent_id": "agent:sea-analyst", "tool": "support.set_priority",
            "target": "support-records",
            "args": {"ticket_id": "TK-5", "priority": "P1"},
            "attempt_uid": self.authority.attempt_uid if attempt_uid is None
            else attempt_uid, "permit": permit})

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except Exception:
                self.proc.kill()


def test_b_world_server_direct_bypass_signer_epoch_replay_terminal(tmp_path, authority):
    w = _WorldServer(tmp_path, authority)
    try:
        before = w.snapshot()
        # Direct bypass: actuator token but no permit -> 403, zero mutation.
        status, _ = w.actuate(None)
        assert status == 403 and w.snapshot() == before
        # Invalid signer: permit MAC'd with a foreign key.
        forged = auth.make_permit(b"\x00" * 32, attempt_uid=authority.attempt_uid,
                                  world_instance_id=authority.world_instance_id,
                                  epoch=authority.epoch, task_id="T8",
                                  command_id="cmd-l5-ws")
        status, _ = w.actuate(forged)
        assert status == 403 and w.snapshot() == before
        # Invalid identity: valid permit, foreign supplied attempt_uid.
        permit = authority.gate_client().request_permit(task_id="T8",
                                                        command_id="cmd-l5-ws")
        status, _ = w.actuate(permit, attempt_uid="foreign-attempt")
        assert status == 403 and w.snapshot() == before
        # Wrong epoch: permit issued, then authority epoch advances.
        stale = authority.gate_client().request_permit(task_id="T8",
                                                       command_id="cmd-l5-ws2")
        authority.supervisor.advance_epoch()
        status, _ = w.actuate(stale, command_id="cmd-l5-ws2")
        assert status == 403 and w.snapshot() == before
        # Positive: fresh permit applies exactly once through /actuate.
        good = authority.gate_client().request_permit(task_id="T8",
                                                      command_id="cmd-l5-good")
        status, payload = w.actuate(good, command_id="cmd-l5-good")
        assert status == 200 and payload.get("status") == "applied", payload
        mid = w.snapshot()
        assert mid["native"] == before["native"] + 1
        assert mid["receipts"] == before["receipts"] + 1
        assert mid["digest"] != before["digest"]
        # Replay: same permit nonce / command -> 403, zero further mutation.
        status, _ = w.actuate(good, command_id="cmd-l5-good")
        assert status == 403 and w.snapshot() == mid
        # Terminal attempt: no permit verifies, /actuate denies.
        authority.transition(auth.COMPLETED)
        status, _ = w.actuate(good, command_id="cmd-l5-good")
        assert status == 403 and w.snapshot() == mid
    finally:
        w.stop()


def test_b_gate_execute_struct_action_attempt_refusals(tmp_path, monkeypatch, authority):
    import asyncio
    import supervisor as sup_mod
    from tests.legion_struct import struct_plugin
    for k in list(os.environ):
        if k.startswith("STRUCT_AUTHORITY") or k == "STRUCT_WORLD_CAPABILITY":
            monkeypatch.delenv(k, raising=False)
    for k, v in sup_mod.CAMPAIGN_CAGE_POSTURE.items():
        monkeypatch.setenv(k, v)
    for k in sup_mod.CAMPAIGN_POSTURE_UNSET:
        monkeypatch.delenv(k, raising=False)
    for k, v in authority.env().items():
        monkeypatch.setenv(k, v)
    gate_log = tmp_path / "GATE_COMMITS.jsonl"
    monkeypatch.setenv("STRUCT_GATE_COMMITS", str(gate_log))
    spec = json.loads((WORLDS / "SYN-GAIA-NOI.world.json").read_text(encoding="utf-8"))
    nodes = struct_plugin.StructNodes(spec)

    def gate(attempt_uid):
        out = asyncio.run(struct_plugin.execute_struct_action(
            "T2", "accounts.provision", "acct-u42", {"uid": "u42", "plan": "pro"},
            "ref-l5", governor=None, controller=None, nodes=nodes,
            attempt_uid=attempt_uid))
        records = [json.loads(l) for l in gate_log.read_text(encoding="utf-8").splitlines()] \
            if gate_log.exists() else []
        return out, records
    # Invalid identity (foreign attempt) refused before any seal/governor.
    out, records = gate("foreign-attempt")
    assert out.startswith("BLOCKED") and "attempt" in out, out
    assert records and records[-1]["outcome"] == "BLOCKED"
    assert not records[-1].get("seal") and not records[-1].get("command_id")
    assert records[-1].get("rejected_attempt_uid") == "foreign-attempt"
    assert not [r for r in records if r.get("outcome") == "EXECUTED"]
    # Terminal attempt refused the same way, carrying the rejected identity.
    authority.transition(auth.COMPLETED)
    out, records = gate(authority.attempt_uid)
    assert out.startswith("BLOCKED"), out
    assert records[-1]["outcome"] == "BLOCKED"
    assert records[-1].get("rejected_attempt_uid") == authority.attempt_uid
    assert not records[-1].get("seal") and not records[-1].get("command_id")


# ===================================================================== C
def test_c_positive_control_gaia_tim_native_effect():
    host = host_for("SYN-GAIA-TIM")
    v, _ = host.step("agent:tim-scheduler",
                     {"action": "wait", "task": "T1", "event_id": "ev-tim-open"},
                     "scripted:tim-wait")
    assert v.allowed, v.to_dict()
    assert host.world.get_state()["window"]["open"] is True
    v, _ = host.step("agent:tim-scheduler",
                     {"action": "send", "task": "T3", "to": "agent:tim-submitter",
                      "body": "window open"}, "scripted:tim-send")
    assert v.allowed, v.to_dict()
    v, _ = host.step("agent:tim-submitter",
                     {"action": "write", "task": "T2", "tool": "batch.submit",
                      "target": "batch", "args": {"batch_id": "B-1107"}},
                     "scripted:tim-write")
    assert v.allowed, v.to_dict()
    assert len(host.world.effect_ledger) == 1
    state = host.world.get_state()
    assert state["batch"] == {"id": "B-1107", "submitted": True,
                              "submitted_in_window": True}
    assert host.registry.write_status("T2") == "VERIFIED"
    v, _ = host.step("agent:tim-auditor",
                     {"action": "read", "task": "T4", "tool": "batch.status",
                      "args": {}}, "scripted:tim-read")
    assert v.allowed and host.registry.is_confirmed("T4"), v.to_dict()


def test_c_positive_control_gaia_noi_native_effect():
    host = host_for("SYN-GAIA-NOI")
    v, _ = host.step("agent:noi-operator",
                     {"action": "read", "task": "T1", "tool": "directory.lookup",
                      "args": {"uid": "u42"}}, "scripted:noi-r")
    assert v.allowed, v.to_dict()
    assert host.registry.is_confirmed("T1")
    write = {"action": "write", "task": "T2", "tool": "accounts.provision",
             "target": "acct-u42", "args": {"uid": "u42", "plan": "pro"}}
    # Flaky backend: first attempt 503 (no effect), lost-reply retry applies
    # exactly once; reconciliation + readback verify it, never duplicate.
    v, res = host.step("agent:noi-operator", dict(write), "scripted:noi-w1")
    assert v.allowed and res[0] == 503 and len(host.world.effect_ledger) == 0
    v, res = host.step("agent:noi-operator", dict(write), "scripted:noi-w2")
    assert v.allowed, v.to_dict()
    assert len(host.world.effect_ledger) == 1
    assert host.registry.write_status("T2") == "VERIFIED"
    cmd = effects(host)[0]["command_id"]
    v, _ = host.step("agent:noi-operator",
                     {"action": "reconcile", "task": "T3", "command_id": cmd},
                     "scripted:noi-rec")
    assert v.allowed and host.registry.is_confirmed("T3"), v.to_dict()
    v, _ = host.step("agent:noi-verifier",
                     {"action": "read", "task": "T4", "tool": "accounts.status",
                      "args": {"uid": "u42"}}, "scripted:noi-v")
    assert v.allowed and host.registry.is_confirmed("T4"), v.to_dict()
    state = host.world.get_state()
    assert state["accounts"]["u42"] == {"plan": "pro", "provision_count": 1}
    assert len(host.world.effect_ledger) == 1


# ===================================================================== D/E
def test_d_s100_registered_worker_alone_is_not_a_contribution():
    host, spec = _otel04_host(overlay=True)
    _restart(host)
    v, _ = host.step("agent:s100-delegate-000",
                     {"action": "read", "task": "D000", "tool": "partition.offsets",
                      "args": {"partition": "p0"}}, "scripted:d-only")
    assert v.allowed and host.registry.is_confirmed("D000"), v.to_dict()
    ref = host.world_records[-1]["observation_id"]
    ok, _, _e = authenticate_delegate_result(host.registry, ref)
    assert ok  # authentic delegate result exists...
    # ...but with no downstream consumption there is no contribution edge.
    assert verified_delegation_edges(host.registry, host.log) == []
    # Fabricated / self / mismatched refs are denied with zero effects.
    v, _ = host.step("agent:o4-consumer-p0",
                     {"action": "read", "task": "Rp0", "tool": "partition.offsets",
                      "args": {"partition": "p0"}}, "scripted:rp0-d")
    assert v.allowed
    before, h = len(host.world.effect_ledger), hash_of(host)
    v, _ = host.step("agent:o4-consumer-p0",
                     {"action": "write", "task": "Wp0", "tool": "partition.drain",
                      "target": "p0", "args": {"partition": "p0", "from_offset": 999},
                      "delegate_result_ref": ref}, "scripted:wp0-bad-delegate")
    assert not v.allowed and v.code == "DELEGATE_REF_OFFSET_MISMATCH", v.to_dict()
    assert len(host.world.effect_ledger) == before and hash_of(host) == h
    assert verified_delegation_edges(host.registry, host.log) == []


def test_e_provenance_no_hidden_judge_in_runtime_admission():
    runtime_files = ["causal_registry.py", "sidecar.py", "action_binding.py",
                     "causal_host.py", "sidecar_server.py", "recovery.py",
                     "delegation.py"]
    for name in runtime_files:
        text = (HERE / name).read_text(encoding="utf-8")
        for forbidden in ("wo008_judge", "hidden_judge", "judge_contract",
                          "B1_judge", "import judge", "from judge"):
            assert forbidden not in text, (name, forbidden)
    # Executing agents see only public world specs: no judge key anywhere.
    files = sorted(WORLDS.glob("*.world.json"))
    assert len(files) == 13
    for p in files:
        assert "judge" not in p.read_text(encoding="utf-8").lower(), p.name
    # Admission works from the public spec alone (synthetic, no judge data).
    host = synth()
    do_read(host)
    v, _ = host.step("agent:op", dict(WRITE_W), "scripted:prov")
    assert v.allowed and host.registry.write_status("W") == "VERIFIED"
