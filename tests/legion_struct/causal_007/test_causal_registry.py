"""Unit tests for the causal registry (WP-A/D) and sidecar (WP-B/C)."""
import copy
import json
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from causal_007.causal_registry import CausalRegistry, validate_cost_decision  # noqa: E402
from causal_007.sidecar import CausalSidecar  # noqa: E402

WORLDS = HERE.parent / "worlds"


def spec(family):
    for p in sorted(WORLDS.glob("*.world.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        if d.get("family") == family:
            return d
    raise AssertionError(family)


def obs(agent, task, oid="obs-1", facts=None):
    return {"kind": "OBSERVATION", "agent_id": agent, "task_id": task,
            "observation_id": oid, "facts": facts if facts is not None else {"x": 1}}


def verified_write(reg, tid, agent):
    """Earned WRITE closure (WO008-02 replacement for effect-only fixtures).

    The pre-WO008-02 version of these tests ingested a bare NATIVE_EFFECT
    and expected confirmation. That assumption is invalid under WO008-02:
    an effect alone is EXECUTED_UNVERIFIED, never VERIFIED, and must not
    unlock dependents (see test_wo008_evidence_closure.py). This helper
    preserves the original tests' intent/assertions but supplies the full
    authentic producer triplet used by causal_host/world_server:
    NATIVE_EFFECT + RECEIPT (permit_verified) + independent
    READBACK_EFFECT (confirmed), agreeing on effect/command identity and
    epoch. It also asserts the negative step (effect alone does not
    confirm) inline, so the legacy assumption cannot silently return.
    """
    ident = {"effect_id": f"eff-{tid}", "command_id": f"cmd-{tid}",
             "epoch": reg.epoch, "permit_epoch": reg.epoch}
    reg.ingest([{"kind": "NATIVE_EFFECT", "task_id": tid, "agent_id": agent, **ident}])
    assert not reg.is_confirmed(tid), (
        f"{tid}: NATIVE_EFFECT alone must stay EXECUTED_UNVERIFIED (WO008-02)")
    assert reg.write_status(tid) == "EXECUTED_UNVERIFIED"
    reg.ingest([
        {"kind": "RECEIPT", "task_id": tid, "agent_id": agent,
         "receipt_id": f"rcpt-cmd-{tid}", "permit_verified": True, **ident},
        {"kind": "READBACK_EFFECT", "task_id": tid, "agent_id": agent,
         "confirmed": True, "state_sha256": f"sha-{tid}", **ident},
    ])
    assert reg.is_confirmed(tid), f"{tid}: complete triplet must verify"
    assert reg.write_status(tid) == "VERIFIED"


def test_registry_multikind_requires_both_and_deps_timing():
    reg = CausalRegistry(spec("SYN-GAIA-EXE"))
    rep, clerk = "agent:exe-reporter", "agent:exe-clerk"
    # premature read (deps open) is stale, never closes
    reg.ingest([obs(rep, "T7", "obs-early")])
    assert not reg.is_confirmed("T7")
    assert reg.obligations["T7"].stale[0]["reason"] == "PREMATURE_BEFORE_DEPS"
    # close deps chain for T4/T5/T6 via effects path: simulate upstream
    reg.ingest([obs(clerk, "T1", "obs-t1")])
    assert reg.is_confirmed("T1")
    for tid, agent in (("T4", "agent:exe-alloc-3"), ("T2", "agent:exe-alloc-1"),
                       ("T3", "agent:exe-alloc-2")):
        verified_write(reg, tid, agent)
    for tid, agent in (("T5", "agent:exe-ship-1"), ("T6", "agent:exe-ship-2")):
        verified_write(reg, tid, agent)
    # READ alone does not close a READ+COMMUNICATE task
    reg.ingest([obs(rep, "T7", "obs-t7")])
    assert not reg.is_confirmed("T7")
    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": rep, "task_id": "T7",
                 "recipient": clerk, "message_id": "msg-1"}])
    assert reg.is_confirmed("T7")
    ok, open_ = reg.can_exit(rep)
    assert ok and open_ == []


def test_registry_analyze_rejects_fabricated_refs_sea():
    reg = CausalRegistry(spec("SYN-GAIA-SEA"))
    # find analyst ANALYZE task generically
    ana = [o for o in reg.obligations.values() if "ANALYZE" in o.kinds][0]
    # close the whole ancestor chain in dependency order
    for _ in range(10):
        progressed = False
        for o in list(reg.obligations.values()):
            if o.task_id == ana.task_id or o.confirmed or not reg.deps_confirmed(o.task_id):
                continue
            for k in list(o.kinds):
                if k == "READ":
                    reg.ingest([obs(o.agent_id, o.task_id, f"obs-{o.task_id}", {"v": 1})])
                elif k == "COMMUNICATE":
                    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": o.agent_id,
                                 "task_id": o.task_id,
                                 "recipient": (o.task.get("recipients") or ["x"])[0],
                                 "message_id": f"m-{o.task_id}"}])
                elif k == "ANALYZE":
                    refs = [f"obs-{d}" for d in o.depends_on if f"obs-{d}" in reg.observations]
                    reg.ingest([{"kind": "ANALYSIS_RECORD", "agent_id": o.agent_id,
                                 "task_id": o.task_id, "facts": {}, "evidence_refs": refs}])
            progressed = True
        if reg.deps_confirmed(ana.task_id) or not progressed:
            break
    assert reg.deps_confirmed(ana.task_id)
    reg.ingest([{"kind": "ANALYSIS_RECORD", "agent_id": ana.agent_id, "task_id": ana.task_id,
                 "facts": {}, "evidence_refs": ["obs-does-not-exist"]}])
    assert not reg.is_confirmed(ana.task_id)
    assert reg.obligations[ana.task_id].stale[-1]["reason"] == "UNKNOWN_EVIDENCE_REF"


def test_registry_wait_wrong_event_and_read_null():
    reg = CausalRegistry(spec("SYN-OTEL-06"))
    waits = [o for o in reg.obligations.values() if "WAIT" in o.kinds]
    assert waits
    # null-data read never closes a READ
    reads = [o for o in reg.obligations.values() if "READ" in o.kinds and not o.depends_on]
    if reads:
        o = reads[0]
        reg.ingest([obs(o.agent_id, o.task_id, "obs-null", {"a": None})])
        assert not reg.is_confirmed(o.task_id)


def test_cost_decision_derivation():
    facts = [{"unit_price": 10, "budget": 100}]
    assert validate_cost_decision(facts, 3, 10, 30, 100) == (True, "OK")
    assert validate_cost_decision(facts, 3, 9, 27, 100)[0] is False
    assert validate_cost_decision(facts, 30, 10, 300, 100) == (False, "TOTAL_EXCEEDS_BUDGET")
    assert validate_cost_decision(facts, 3, 10, 31, 100) == (False, "TOTAL_NOT_DERIVABLE")


def _sidecar(family):
    reg = CausalRegistry(spec(family))
    logs = []
    return reg, CausalSidecar(reg, log=logs.append), logs


def test_sidecar_blocks_premature_and_no_decision_ref_and_exit():
    reg, sc, logs = _sidecar("SYN-GAIA-EXE")
    # P0-6: a READ-kind read before deps are confirmed is plain observation:
    # admissible, but it does not close T7.
    v = sc.check("agent:exe-reporter", {"action": "read", "task": "T7", "tool": "orders.list", "args": {}}, "resp-1")
    assert v.allowed and v.code == "OBSERVATION_ONLY" and v.observation_only
    reg.ingest([obs("agent:exe-reporter", "T7", "obs-early")])
    assert not reg.is_confirmed("T7")
    assert reg.obligations["T7"].stale[-1]["reason"] == "PREMATURE_BEFORE_DEPS"
    v = sc.check("agent:exe-clerk", {"action": "read", "task": "T1", "tool": "orders.list", "args": {}}, "")
    assert not v.allowed and v.code == "NO_DECISION_REF"
    v = sc.check_exit("agent:exe-reporter", "all_tasks_terminal")
    assert not v.allowed and v.code == "EXIT_BLOCKED_OPEN_OBLIGATIONS"
    assert any(r["event"] == "CAUSAL_REFUSAL" for r in logs)
    # sidecar has no world-originating method
    assert not hasattr(sc, "execute") and not hasattr(sc, "send")


def test_sidecar_repeat_block_and_rename_hint():
    reg, sc, _ = _sidecar("SYN-GAIA-NOI")
    op = [a for a in reg.by_agent if reg.by_agent[a]][0]
    task = reg.by_agent[op][0]
    act = {"action": "read", "task": task, "tool": "x", "args": {"bogus": 1}}
    # wrong agent triggers inadmissible; same attempt twice -> repeat blocked for that agent
    a2 = "agent:someone-else"
    sc.check(a2, act, "r1")
    sc.check(a2, act, "r2")
    v = sc.check(a2, act, "r3")
    assert not v.allowed and v.code == "REPEAT_BLOCKED"
    hint = sc.note_result(op, act, 400, {"error": "unknown parameter 'user_id'; this endpoint now expects 'uid'"})
    assert "uid" in hint and "user_id" in hint


def test_sidecar_wrong_recipient_hint_amb():
    reg, sc, _ = _sidecar("SYN-GAIA-AMB")
    found = None
    for tid, ob in reg.obligations.items():
        if "COMMUNICATE" in ob.kinds and not (ob.task.get("recipients") or []):
            found = (ob.agent_id, tid)
    if found:
        agent, tid = found
        # satisfy deps first if any
        v = sc.check(agent, {"action": "send", "task": tid, "to": "agent:x", "body": "hi"}, "r1")
        assert not v.allowed and v.code in ("NO_RECIPIENTS", "DEPENDENCIES_OPEN")
        if v.code == "NO_RECIPIENTS":
            assert "no recipients" in v.hint
    # refuse on a COMMUNICATE-only task -> kind refusal with corrective route
    for tid, ob in reg.obligations.items():
        if ob.kinds == ["COMMUNICATE"]:
            v = sc.check(ob.agent_id, {"action": "refuse", "task": tid, "reason": "x"}, "r9")
            assert not v.allowed and v.code == "KIND_NOT_ALLOWED"
            break


# ------------------------------------------------------- round-2 P0-6/7/8
def _close_t1(reg):
    reg.ingest([obs("agent:exe-clerk", "T1", "obs-t1")])


def test_p0_6_write_task_own_read_tools_admissible_never_closes():
    reg, sc, _ = _sidecar("SYN-GAIA-EXE")
    act = {"action": "read", "task": "T2", "tool": "orders.list", "args": {}}
    # deps (T1) open: a WRITE task's own read is not plain observation; it is
    # a transient DEPENDENCIES_OPEN, not KIND_NOT_ALLOWED.
    v = sc.check("agent:exe-alloc-1", act, "r1")
    assert not v.allowed and v.code == "DEPENDENCIES_OPEN" and v.transient
    _close_t1(reg)
    v = sc.check("agent:exe-alloc-1", act, "r2")
    assert v.allowed and v.observation_only, v.to_dict()
    reg.ingest([obs("agent:exe-alloc-1", "T2", "obs-t2", {"orders": {"ord_1": {"status": "new"}}})])
    assert not reg.is_confirmed("T2")  # a read never closes a non-READ task
    entry = reg.observations["obs-t2"]
    assert entry["_confirmed"]  # eligible observation is usable evidence
    # a tool that is not one of the task's own read_tools is still refused
    v = sc.check("agent:exe-alloc-1",
                 {"action": "read", "task": "T2", "tool": "shipping.create", "args": {}}, "r3")
    assert not v.allowed and v.code == "KIND_NOT_ALLOWED"


def test_p0_7_repeat_blocked_is_state_aware():
    reg, sc, _ = _sidecar("SYN-GAIA-EXE")
    act = {"action": "write", "task": "T5", "tool": "shipping.create",
           "target": "ship-ord_1", "args": {"order_id": "ord_1"}}
    ship = "agent:exe-ship-1"
    codes = [sc.check(ship, act, f"r{i}").code for i in range(3)]
    assert codes[:2] == ["DEPENDENCIES_OPEN", "DEPENDENCIES_OPEN"]
    assert codes[2] == "REPEAT_BLOCKED"  # same reason + same state digest
    rep = sc.check(ship, act, "r3b")
    # repeat-block is signalled once per state; later attempts are
    # re-evaluated and carry the original (transient) reason again
    assert rep.code == "DEPENDENCIES_OPEN" and rep.transient
    # State changes (T1, then T2 confirm): the identical action is
    # re-evaluated, not repeat-blocked, and is admitted once eligible.
    _close_t1(reg)
    v = sc.check(ship, act, "r4")
    assert not v.allowed and v.code == "DEPENDENCIES_OPEN"  # T2 still open, new digest
    verified_write(reg, "T2", "agent:exe-alloc-1")
    v = sc.check(ship, act, "r5")
    assert v.allowed and v.code == "ADMISSIBLE", v.to_dict()


# ------------------------------------------------------- round-3 P0-11/12
def _obs_tool(agent, task, oid, tool, args=None, facts=None):
    return {"kind": "OBSERVATION", "agent_id": agent, "task_id": task,
            "observation_id": oid, "tool": tool, "args": args or {},
            "facts": facts if facts is not None else {"x": 1}}


def test_p0_11_confirmed_read_task_allows_distinct_reads_while_dependents_open():
    reg, sc, _ = _sidecar("SYN-GAIA-A2A")
    fin = "agent:a2a-finance"
    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": "agent:a2a-requester",
                 "task_id": "T1", "recipient": fin, "message_id": "m1"}])
    v = sc.check(fin, {"action": "read", "task": "T2", "tool": "budget.get", "args": {}}, "r1")
    assert v.allowed
    reg.ingest([_obs_tool(fin, "T2", "obs-budget", "budget.get", {}, {"budget_remaining_usd": 10000})])
    assert reg.is_confirmed("T2")  # first read closes the READ obligation
    # Second, distinct read (different tool) must NOT be ALREADY_CONFIRMED:
    # T3 (dependent on T2) is not yet closed.
    v = sc.check(fin, {"action": "read", "task": "T2", "tool": "catalog.price",
                       "args": {"item": "laptop-14"}}, "r2")
    assert v.allowed and v.observation_only and v.code != "ALREADY_CONFIRMED", v.to_dict()
    reg.ingest([_obs_tool(fin, "T2", "obs-price", "catalog.price",
                          {"item": "laptop-14"}, {"unit_price_usd": 1000})])
    # Exact repetition (same tool+args) under unchanged state is throttled.
    v = sc.check(fin, {"action": "read", "task": "T2", "tool": "catalog.price",
                       "args": {"item": "laptop-14"}}, "r3")
    assert not v.allowed and v.code == "ALREADY_CONFIRMED", v.to_dict()
    # Non-read actions on a confirmed task remain refused.
    v = sc.check(fin, {"action": "analyze", "task": "T2", "answer": {}, "evidence_refs": []}, "r4")
    assert not v.allowed and v.code == "ALREADY_CONFIRMED"
    # Once the dependent (T3) is closed, post-confirmation reads stop.
    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": fin, "task_id": "T3",
                 "recipient": "agent:a2a-requester", "message_id": "m3"}])
    assert reg.is_confirmed("T3")
    v = sc.check(fin, {"action": "read", "task": "T2", "tool": "budget.get", "args": {}}, "r5")
    assert not v.allowed and v.code == "ALREADY_CONFIRMED"


def _synthetic_spec():
    return {"world_id": "SYNTH-P0", "family": "SYNTH-P0", "tools": {
                "t.get": {"kind": "read", "params": {}, "returns": {}}},
            "roles": [
                {"agent_id": "agent:a1", "tasks": [
                    {"task_id": "D1", "kinds": ["READ"], "read_tools": ["t.get"],
                     "depends_on": [], "recipients": []},
                    {"task_id": "A", "kinds": ["ANALYZE"], "read_tools": ["t.get"],
                     "depends_on": ["D1"], "recipients": [], "answer_schema": {}}]},
                {"agent_id": "agent:a2", "tasks": [
                    {"task_id": "X", "kinds": ["READ"], "read_tools": ["t.get"],
                     "depends_on": [], "recipients": []},
                    {"task_id": "C", "kinds": ["READ"], "read_tools": ["t.get"],
                     "depends_on": [], "recipients": []}]}]}


def test_p0_11_repeat_read_readmitted_after_state_change():
    reg = CausalRegistry(_synthetic_spec())
    sc = CausalSidecar(reg, log=lambda r: None)
    reg.ingest([_obs_tool("agent:a1", "D1", "obs-d1", "t.get")])
    assert reg.is_confirmed("D1")
    v = sc.check("agent:a1", {"action": "read", "task": "D1", "tool": "t.get", "args": {}}, "r1")
    assert not v.allowed and v.code == "ALREADY_CONFIRMED"  # same read, unchanged state
    # An intervening confirmation changes the causal state: the same read
    # is admissible again while dependent A is still open.
    reg.ingest([_obs_tool("agent:a2", "C", "obs-c", "t.get")])
    v = sc.check("agent:a1", {"action": "read", "task": "D1", "tool": "t.get", "args": {}}, "r2")
    assert v.allowed and v.observation_only, v.to_dict()


def test_p0_12_analyze_admitted_with_stale_plus_fresh_refs():
    reg = CausalRegistry(_synthetic_spec())
    logs = []
    sc = CausalSidecar(reg, log=logs.append)
    # Early observation under A before D1 finished: recorded stale/unconfirmed.
    reg.ingest([_obs_tool("agent:a1", "A", "obs-early", "t.get")])
    reg.ingest([_obs_tool("agent:a1", "D1", "obs-fresh", "t.get")])
    reg.ingest([_obs_tool("agent:a2", "X", "obs-other", "t.get")])
    assert reg.is_confirmed("D1") and not reg.observations["obs-early"]["_confirmed"]
    act = {"action": "analyze", "task": "A", "answer": {"cause": "x"},
           "evidence_refs": ["obs-early", "obs-fresh"]}
    v = sc.check("agent:a1", act, "r1")
    assert v.allowed, v.to_dict()
    assert v.stale_refs == ["obs-early"] and v.valid_refs == ["obs-fresh"]
    assert "obs-early" in v.hint  # reported back to the agent
    admit = [r for r in logs if r["event"] == "CAUSAL_ADMIT"][-1]
    assert admit["stale_refs"] == ["obs-early"]  # and in the controller log
    reg.ingest([{"kind": "ANALYSIS_RECORD", "agent_id": "agent:a1", "task_id": "A",
                 "facts": {"cause": "x"}, "evidence_refs": ["obs-early", "obs-fresh"],
                 "record_id": "ana-1"}])
    assert reg.is_confirmed("A")
    assert reg.obligations["A"].ignored_stale_refs[-1]["refs"] == ["obs-early"]


def test_p0_12_analyze_refused_without_any_fresh_valid_ref():
    reg = CausalRegistry(_synthetic_spec())
    sc = CausalSidecar(reg, log=lambda r: None)
    reg.ingest([_obs_tool("agent:a1", "A", "obs-early", "t.get")])
    reg.ingest([_obs_tool("agent:a1", "D1", "obs-fresh", "t.get")])
    reg.ingest([_obs_tool("agent:a2", "X", "obs-other", "t.get")])
    base = {"action": "analyze", "task": "A", "answer": {}}
    v = sc.check("agent:a1", {**base, "evidence_refs": ["obs-early"]}, "r1")
    assert not v.allowed and v.code == "ANALYZE_STALE_EVIDENCE_REF", v.to_dict()
    v = sc.check("agent:a1", {**base, "evidence_refs": ["obs-early", "obs-nope"]}, "r2")
    assert not v.allowed and v.code == "ANALYZE_UNKNOWN_EVIDENCE_REF", v.to_dict()
    v = sc.check("agent:a1", {**base, "evidence_refs": ["obs-fresh", "obs-other"]}, "r3")
    assert not v.allowed and v.code == "ANALYZE_EVIDENCE_FROM_WRONG_TASK", v.to_dict()
    v = sc.check("agent:a1", {**base, "evidence_refs": []}, "r4")
    assert not v.allowed and v.code == "ANALYZE_MISSING_EVIDENCE_REFS", v.to_dict()
    # The registry (Judge-side rebuild) agrees: stale-only never closes A.
    reg.ingest([{"kind": "ANALYSIS_RECORD", "agent_id": "agent:a1", "task_id": "A",
                 "facts": {}, "evidence_refs": ["obs-early"], "record_id": "ana-x"}])
    assert not reg.is_confirmed("A")
    assert reg.obligations["A"].stale[-1]["reason"] == "STALE_EVIDENCE_REF"
