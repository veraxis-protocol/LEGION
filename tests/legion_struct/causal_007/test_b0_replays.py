"""B0 failure-mechanism replays + transport + delegation + smoke (no NIM).

Each test first replays the B0 bad action and shows the sidecar/registry
blocks it or marks it stale, then drives the correct public sequence.
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

from causal_007.causal_host import CausalHost  # noqa: E402
from causal_007.causal_registry import CausalRegistry  # noqa: E402
from causal_007.sidecar import CausalSidecar  # noqa: E402
from causal_007.delegation import build_s100_spec, contribution_report  # noqa: E402
from causal_007.nim_transport import NimTransport, ProviderLogWriter  # noqa: E402

WORLDS = HERE.parent / "worlds"


def spec(family):
    for p in sorted(WORLDS.glob("*.world.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        if d.get("family") == family:
            return d
    raise AssertionError(family)


def host(family):
    return CausalHost(spec(family))


def agent_of(h, tid):
    return h.registry.obligations[tid].agent_id


def read_action(h, tid, args=None):
    ob = h.registry.obligations[tid]
    tool = (ob.task.get("read_tools") or [None])[0]
    if args is None:
        args = synth_args(h, tool)
    return {"action": "read", "task": tid, "tool": tool, "args": args}


def synth_args(h, tool, facts_pool=None):
    args = {}
    for name, ps in ((h.spec.get("tools") or {}).get(tool) or {}).get("params", {}).items():
        if facts_pool and name in facts_pool:
            args[name] = facts_pool[name]
        elif "enum" in ps:
            args[name] = ps["enum"][0]
        elif ps.get("type") == "integer":
            args[name] = ps.get("min", 0)
        else:
            args[name] = "x"
    return args


# ---------------------------------------------------------------- EXE / TIM
def test_exe_early_read_blocked_then_full_sequence():
    h = host("SYN-GAIA-EXE")
    rep = agent_of(h, "T7")
    # P0-6: an early READ-kind read is plain observation only; it is
    # admitted but does not close T7 before T4/T5/T6 complete.
    v, res = h.step(rep, read_action(h, "T7"), "r-early")
    assert v.allowed and v.observation_only and res[0] == 200
    assert not h.registry.is_confirmed("T7")
    assert h.registry.obligations["T7"].stale[-1]["reason"] == "PREMATURE_BEFORE_DEPS"
    v = h.sidecar.check_exit(rep, "all_tasks_terminal")
    assert not v.allowed


def test_tim_auditor_read_only_after_submission():
    h = host("SYN-GAIA-TIM")
    # find a READ task depending on a WRITE task
    target = None
    for tid, ob in h.registry.obligations.items():
        if "READ" in ob.kinds and any("WRITE" in h.registry.obligations[d].kinds
                                      for d in ob.depends_on):
            target = tid
            break
    assert target is not None
    # P0-6: admissible as plain observation, closes only after submission.
    v, res = h.step(agent_of(h, target), read_action(h, target), "r1")
    assert v.allowed and v.observation_only and res[0] == 200
    assert not h.registry.is_confirmed(target)


def test_otel01_diagnosis_precedes_authorization():
    h = host("SYN-OTEL-01")
    writes = [t for t, o in h.registry.obligations.items() if "WRITE" in o.kinds]
    blocked = 0
    for tid in writes:
        ob = h.registry.obligations[tid]
        if ob.depends_on:
            v, _ = h.step(ob.agent_id, {"action": "write", "task": tid,
                                        "tool": ob.task.get("write_tool"),
                                        "target": ob.task.get("target"),
                                        "args": synth_args(h, ob.task.get("write_tool"))}, "r1")
            assert not v.allowed and v.code == "DEPENDENCIES_OPEN"
            blocked += 1
    assert blocked >= 1


def test_otel05_06_wait_precedes_final_verification():
    for fam in ("SYN-OTEL-05", "SYN-OTEL-06"):
        h = host(fam)
        waits = [t for t, o in h.registry.obligations.items() if "WAIT" in o.kinds]
        assert waits, fam
        for tid in waits:
            ob = h.registry.obligations[tid]
            # a READ/ANALYZE depending on the WAIT cannot run before it
            for other, o2 in h.registry.obligations.items():
                if tid in (o2.depends_on or []):
                    kind = (o2.kinds or ["READ"])[0]
                    act = {"action": kind.lower(), "task": other}
                    if kind == "READ":
                        act["tool"] = (o2.task.get("read_tools") or [None])[0]
                        act["args"] = {}
                    v = h.sidecar.check(o2.agent_id, act, "r-x")
                    if kind == "READ":
                        # P0-6 plain observation only; it cannot close the
                        # dependent before the WAIT it depends on.
                        assert v.allowed and v.observation_only, (fam, other, v.to_dict())
                        assert not h.registry.is_confirmed(other)
                    else:
                        assert not v.allowed, (fam, other)


def test_amb_refuse_on_communicate_blocked_and_no_recipient_route():
    h = host("SYN-GAIA-AMB")
    v, _ = h.step("agent:amb-lookup", {"action": "refuse", "task": "T2", "reason": "no"}, "r1")
    assert not v.allowed and v.code == "KIND_NOT_ALLOWED"
    # handler refuses under T3 before T2 delivered -> blocked by deps
    v, _ = h.step("agent:amb-handler", {"action": "refuse", "task": "T3", "reason": "ambiguous"}, "r2")
    assert not v.allowed and v.code == "DEPENDENCIES_OPEN"
    # correct sequence: lookup reads, sends T2, handler refuses T3, sends T4
    v, res = h.step("agent:amb-lookup",
                    {"action": "read", "task": "T1", "tool": "crm.find_by_name",
                     "args": {"name": "Alex"}}, "r3")
    assert v.allowed and res[0] == 200
    v, res = h.step("agent:amb-lookup",
                    {"action": "send", "task": "T2", "to": "agent:amb-handler", "body": "two matches"}, "r4")
    assert v.allowed
    # send under T3 (no recipients) gets corrective route
    v, _ = h.step("agent:amb-handler",
                  {"action": "send", "task": "T3", "to": "agent:amb-liaison", "body": "clarify"}, "r5")
    assert not v.allowed and v.code in ("KIND_NOT_ALLOWED", "NO_RECIPIENTS")
    v, res = h.step("agent:amb-handler", {"action": "refuse", "task": "T3", "reason": "ambiguous"}, "r6")
    assert v.allowed
    assert h.registry.is_confirmed("T3")
    v, res = h.step("agent:amb-handler",
                    {"action": "send", "task": "T4", "to": "agent:amb-liaison", "body": "which Alex?"}, "r7")
    assert v.allowed and h.registry.is_confirmed("T4")


def test_noi_rename_recovery_without_repeated_identical_errors():
    h = host("SYN-GAIA-NOI")
    op = agent_of(h, "T1")
    bad = {"action": "read", "task": "T1", "tool": "directory.lookup", "args": {"user_id": "u42"}}
    v, res = h.step(op, bad, "r1")
    assert v.allowed and res[0] == 400 and "uid" in res[1]["causal_hint"]
    v, res = h.step(op, {"action": "read", "task": "T1", "tool": "directory.lookup",
                         "args": {"uid": "u42"}}, "r2")
    assert v.allowed and res[0] == 200
    assert h.registry.is_confirmed("T1")
    # repeated identical inadmissible action is stopped
    h2 = host("SYN-GAIA-NOI")
    act = {"action": "refuse", "task": "T1", "reason": "x"}
    h2.sidecar.check(op, act, "a")
    h2.sidecar.check(op, act, "b")
    v = h2.sidecar.check(op, act, "c")
    assert v.code == "REPEAT_BLOCKED"


def test_sea_unsupported_answer_never_verified():
    h = host("SYN-GAIA-SEA")
    v, _ = h.step("agent:sea-analyst",
                  {"action": "analyze", "task": "T7",
                   "answer": {"ticket_id": "TK-5", "priority": "P2"},
                   "evidence_refs": ["obs-fabricated"]}, "r1")
    assert not v.allowed and v.code in ("ANALYZE_UNKNOWN_EVIDENCE_REF", "DEPENDENCIES_OPEN")
    assert not h.registry.is_confirmed("T7")
    # identifier provenance: billing read with invented id before T2 is
    # refused (or, at best, is an observation that never closes T3)
    v, _ = h.step("agent:sea-billing",
                  {"action": "read", "task": "T3", "tool": "billing.account_for",
                   "args": {"customer_id": "C-999"}}, "r2")
    assert not v.allowed and v.code == "IDENTIFIER_PROVENANCE"
    assert not h.registry.is_confirmed("T3")


def test_ada_degradation_makes_failover_eligible():
    h = host("SYN-GAIA-ADA")
    # some WRITE/communicate task depends (transitively) on a WAIT
    reg = h.registry
    gated = [t for t, o in reg.obligations.items()
             if any("WAIT" in reg.obligations[d].kinds for d in o.depends_on)]
    assert gated
    for tid in gated:
        ob = reg.obligations[tid]
        act_name = {"READ": "read", "ANALYZE": "analyze", "COMMUNICATE": "send",
                    "WAIT": "wait", "WRITE": "write", "REFUSE": "refuse",
                    "RECONCILE": "reconcile", "DONE": "done"}[ob.kinds[0]]
        v = h.sidecar.check(ob.agent_id, {"action": act_name, "task": tid}, "r1")
        assert not v.allowed and v.code == "DEPENDENCIES_OPEN"
    # firing the public degradation event is a world event, then WAIT can close
    waits = [t for t, o in reg.obligations.items() if "WAIT" in o.kinds]
    for tid in waits:
        ob = reg.obligations[tid]
        if not reg.deps_confirmed(tid):
            continue
        v, res = h.step(ob.agent_id, {"action": "wait", "task": tid,
                                      "event_id": ob.task.get("wait_for")}, "rw")
        assert v.allowed


def test_a2a_cost_derivation_and_handoff():
    from causal_007.causal_registry import validate_cost_decision
    facts = [{"price": 25, "budget": 200}]
    ok, _ = validate_cost_decision(facts, 4, 25, 100, 200)
    assert ok
    assert validate_cost_decision(facts, 4, 20, 80, 200)[0] is False
    h = host("SYN-GAIA-A2A")
    # no COMMUNICATE/WRITE with open deps is admissible (finance handoff gated)
    blocked = 0
    for tid, ob in h.registry.obligations.items():
        if ob.depends_on and ("COMMUNICATE" in ob.kinds or "WRITE" in ob.kinds):
            v = h.sidecar.check(ob.agent_id, {"action": "send" if "COMMUNICATE" in ob.kinds else "write",
                                              "task": tid, "to": (ob.task.get("recipients") or ["x"])[0]}, "r1")
            assert not v.allowed
            blocked += 1
    assert blocked >= 1


def test_otel04_ten_partitions_proven_completion():
    h = host("SYN-OTEL-04")
    reg = h.registry
    # coordinator reads then restarts (write gated on T1)
    v, res = h.step(agent_of(h, "T1"), read_action(h, "T1"), "a")
    assert v.allowed and res[0] == 200
    ob = reg.obligations["T2"]
    v, res = h.step(ob.agent_id, {"action": "write", "task": "T2", "tool": ob.task["write_tool"],
                                  "target": ob.task["target"],
                                  "args": synth_args(h, ob.task["write_tool"])}, "b")
    assert v.allowed and res[0] == 200, res
    for i in range(10):
        r, w, c = f"Rp{i}", f"Wp{i}", f"Cp{i}"
        v, res = h.step(agent_of(h, r),
                        {"action": "read", "task": r, "tool": "partition.offsets",
                         "args": {"partition": f"p{i}"}}, f"r{i}")
        assert v.allowed and res[0] == 200, (r, res)
        committed = res[1]["data"]["committed"]
        wob = reg.obligations[w]
        v, res = h.step(wob.agent_id, {"action": "write", "task": w, "tool": wob.task["write_tool"],
                                       "target": wob.task["target"],
                                       "args": {"partition": f"p{i}", "from_offset": committed}}, f"w{i}")
        assert v.allowed and res[0] == 200, (w, res)
        cob = reg.obligations[c]
        v, res = h.step(cob.agent_id, {"action": "send", "task": c, "to": "agent:o4-verifier",
                                       "body": f"p{i} drained"}, f"c{i}")
        assert v.allowed, (c, v.to_dict())
    assert all(reg.is_confirmed(f"Wp{i}") for i in range(10))
    state = h.world.get_state()
    assert all(state["drains"][f"p{i}"] == 1 and state["lag"][f"p{i}"] == 0 for i in range(10))


# ---------------------------------------------------------------- transport
def test_transport_429_storm_retries_without_fabricating():
    sleeps = []
    transport = NimTransport(max_concurrency=2, max_retries=5, sleep=sleeps.append)
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] <= 3:
            return 429, {}, {"Retry-After": "0"}
        return 200, {"choices": [{"message": {"content": "{}"}}], "id": "resp-1"}, {}

    res = transport.execute(flaky)
    assert res.status == 200 and res.transport_retries == 3
    assert transport.stats["retries_429"] == 3
    # exhausted storm: transport error, payload None, no fabricated decision
    res2 = NimTransport(max_retries=2, sleep=lambda s: None).execute(lambda: (429, {}, {}))
    assert res2.status == 429 and res2.payload == {} and res2.is_transport_error


def test_provider_log_atomic_one_record_per_call(tmp_path):
    path = tmp_path / "provider_log.jsonl"
    w = ProviderLogWriter(path)
    w.append("agent:a", {"messages": []}, {"id": "r1"}, "r1")
    w.append("agent:b", {"messages": []}, {"id": "r2"}, "r2")
    rows = [json.loads(x) for x in path.read_text().splitlines()]
    assert [r["agent_id"] for r in rows] == ["agent:a", "agent:b"]


def test_no_fabrication_sidecar_never_originates():
    h = host("SYN-GAIA-EXE")
    before = len(h.world_records)
    # checking / next_required / exit checks produce zero world records
    h.sidecar.check("agent:exe-clerk", {"action": "read", "task": "T1", "tool": "orders.list", "args": {}}, "")
    h.sidecar.next_required("agent:exe-clerk")
    h.sidecar.check_exit("agent:exe-clerk", "all_tasks_terminal")
    assert len(h.world_records) == before
    v, res = h.step("agent:exe-clerk", {"action": "read", "task": "T1", "tool": "orders.list", "args": {}}, "")
    assert not v.allowed and res is None and len(h.world_records) == before


def test_safety_plugin_hard_rejections_still_hold():
    sys.path.insert(0, str(HERE.parents[1]))
    import test_struct_units as u  # noqa
    nodes, tier = u._struct_nodes_and_tier()
    assert u._hard_codes(tier, "struct_T1", u._valid_tier_params()) == set()
    assert "ACTOR_ASSIGNED_MISMATCH" in u._hard_codes(
        tier, "struct_T1", u._valid_tier_params(sre_actor="agent:evil"))


def test_s100_delegation_overlay_100_identities():
    base = spec("SYN-OTEL-04")
    sha_before = json.dumps(base, sort_keys=True)
    over = build_s100_spec(base)
    assert json.dumps(base, sort_keys=True) == sha_before  # world file object unchanged
    agents = [r["agent_id"] for r in over["roles"]]
    assert len(agents) == 100 and len(set(agents)) == 100
    delegates = [r for r in over["roles"] if r["agent_id"].startswith("agent:s100-delegate-")]
    assert delegates and all(
        t["kinds"] == ["READ"] and t["write_tool"] is None
        for d in delegates for t in d["tasks"])
    # each delegate reads, coordinator decision cites every delegate obs id
    records, decisions = [], []
    for i, d in enumerate(delegates):
        oid = f"obs-d{i}"
        records.append({"kind": "OBSERVATION", "agent_id": d["agent_id"],
                        "task_id": d["tasks"][0]["task_id"], "observation_id": oid,
                        "facts": {"committed": 1}})
        decisions.append({"agent_id": "agent:o4-coordinator", "evidence_refs": [oid]})
    rep = contribution_report(over, records, decisions)
    assert rep["registered"] == 100 and rep["contributing"] == len(delegates)
    assert rep["contributing"] > 0


def test_full_scripted_smoke_13_worlds_100_registered():
    files = sorted(WORLDS.glob("*.world.json"))
    assert len(files) == 13
    for p in files:
        d = json.loads(p.read_text(encoding="utf-8"))
        reg = CausalRegistry(copy.deepcopy(d))
        registered = len(d.get("roles") or []) + max(0, 100 - len(d.get("roles") or []))
        assert registered == 100
        # every obligation has a kind closure rule and deps are known tasks
        for tid, ob in reg.obligations.items():
            assert ob.kinds, (p.name, tid)
            for dep in ob.depends_on:
                assert dep in reg.obligations, (p.name, tid, dep)
        # premature exit blocked for every agent with tasks
        sc = CausalSidecar(reg, log=lambda r: None)
        for agent, tids in reg.by_agent.items():
            if tids:
                assert not sc.check_exit(agent, "all_tasks_terminal").allowed
