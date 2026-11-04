"""WO008-01: REQUIRED/CONDITIONAL/OPTIONAL activation semantics (no NIM).

Deterministic, public-spec only. The five counterexamples are the secondary
WRITE tasks whose public briefs are conditional, yet were treated as
mandatory: SEA T8, OTEL-01 T6, OTEL-02 T6, OTEL-05 T6, OTEL-06 T6.
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

from causal_007.causal_registry import CausalRegistry  # noqa: E402
from causal_007.sidecar import CausalSidecar  # noqa: E402

WORLDS = HERE.parent / "worlds"

# family -> (conditional task, its agent, its write tool, target)
COUNTEREXAMPLES = [
    ("SYN-GAIA-SEA", "T8", "agent:sea-analyst", "support.set_priority", "support-records"),
    ("SYN-OTEL-01", "T6", "agent:o1-operator", "checkout.bypass_payment", "checkout-bypass"),
    ("SYN-OTEL-02", "T6", "agent:o2-operator", "catalog.rebuild_entry", "P1"),
    ("SYN-OTEL-05", "T6", "agent:o5-operator", "recommendation.restart", "recommendation"),
    ("SYN-OTEL-06", "T6", "agent:o6-operator", "llm_gateway.disable", "llm-gateway"),
]


def spec(family):
    for p in sorted(WORLDS.glob("*.world.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        if d.get("family") == family:
            return d
    raise AssertionError(family)


def _with_activation(family, task_id, requirement, activation, **extra):
    d = copy.deepcopy(spec(family))
    for role in d["roles"]:
        for t in role["tasks"]:
            if t["task_id"] == task_id:
                t["requirement"] = requirement
                t["activation"] = activation
                t.update(extra)
    return d


def _confirm_chain(reg, skip=()):
    """Confirm every confirmable obligation except `skip`, in dep order."""
    for _ in range(12):
        progressed = False
        for ob in list(reg.obligations.values()):
            if ob.task_id in skip or ob.confirmed or not reg.deps_confirmed(ob.task_id):
                continue
            for k in list(ob.kinds):
                if k == "READ":
                    reg.ingest([{"kind": "OBSERVATION", "agent_id": ob.agent_id,
                                 "task_id": ob.task_id, "observation_id": f"obs-{ob.task_id}",
                                 "facts": {"v": 1}}])
                elif k == "COMMUNICATE":
                    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": ob.agent_id,
                                 "task_id": ob.task_id,
                                 "recipient": (ob.task.get("recipients") or ["x"])[0],
                                 "message_id": f"m-{ob.task_id}"}])
                elif k == "ANALYZE":
                    source_tasks = set()
                    pending = list(ob.depends_on)
                    while pending:
                        dep = pending.pop()
                        if dep in source_tasks:
                            continue
                        source_tasks.add(dep)
                        if dep in reg.obligations:
                            pending.extend(reg.obligations[dep].depends_on)
                    refs = [
                        oid for oid, entry in reg.observations.items()
                        if entry.get("_confirmed")
                        and entry.get("task_id") in source_tasks
                    ]
                    reg.ingest([{"kind": "ANALYSIS_RECORD", "agent_id": ob.agent_id,
                                 "task_id": ob.task_id, "facts": {}, "evidence_refs": refs}])
                elif k == "WRITE":
                    reg.ingest([{"kind": "NATIVE_EFFECT", "agent_id": ob.agent_id,
                                 "task_id": ob.task_id, "effect_id": f"eff-{ob.task_id}"}])
            progressed = True
        if not progressed:
            break


# --------------------------------------------------------------- counterexamples
@pytest.mark.parametrize("family,task_id,agent,tool,target", COUNTEREXAMPLES)
def test_counterexample_inactive_conditional_write_not_required(family, task_id, agent, tool, target):
    reg = CausalRegistry(_with_activation(family, task_id, "CONDITIONAL", "F"))
    sc = CausalSidecar(reg, log=lambda r: None)
    assert reg.obligations[task_id].requirement == "CONDITIONAL"
    assert task_id not in reg.open_obligations(agent)
    v = sc.check(agent, {"action": "write", "task": task_id, "tool": tool,
                         "target": target, "args": {}}, "r1")
    assert not v.allowed and v.code == "NOT_REQUIRED", v.to_dict()
    assert task_id not in (sc.next_required(agent)["next_required"] or "")


@pytest.mark.parametrize("family,task_id,agent,tool,target", COUNTEREXAMPLES)
def test_counterexample_public_brief_compiles_conditional(family, task_id, agent, tool, target):
    # No injected fields: classification must come from the PUBLIC brief.
    reg = CausalRegistry(spec(family))
    assert reg.obligations[task_id].requirement == "CONDITIONAL", family
    assert task_id not in reg.open_obligations(agent)


def test_sea_t7_complete_inactive_t8_exit_ok():
    reg = CausalRegistry(spec("SYN-GAIA-SEA"))
    sc = CausalSidecar(reg, log=lambda r: None)
    _confirm_chain(reg, skip={"T8"})
    assert reg.is_confirmed("T7")
    assert "T8" not in reg.open_obligations("agent:sea-analyst")
    v = sc.check_exit("agent:sea-analyst", "all_tasks_terminal")
    assert v.allowed and v.code == "EXIT_OK", v.to_dict()


# --------------------------------------------------------------- positive controls
def _synthetic(conditional_activation=None, requires_resolution=None):
    w = {"task_id": "W", "kinds": ["WRITE"], "read_tools": [], "write_tool": "t.exec",
         "target": "target", "recipients": [], "depends_on": ["R"], "gate_facts": []}
    if conditional_activation is not None:
        w.update({
            "requirement": "CONDITIONAL",
            "activation": conditional_activation,
            "activation_predicate": {"field": "v", "equals": 1},
        })
    if requires_resolution is not None:
        w["requires_resolution"] = requires_resolution
    return {"world_id": "SYNTH-W008", "family": "SYNTH-W008",
            "tools": {"t.get": {"kind": "read", "params": {}, "returns": {}},
                      "t.exec": {"kind": "write", "params": {}, "returns": {}}},
            "roles": [{"agent_id": "agent:op", "tasks": [
                {"task_id": "R", "kinds": ["READ"], "read_tools": ["t.get"],
                 "write_tool": None, "target": None, "recipients": [],
                 "depends_on": [], "gate_facts": []}, w]}]}


def _close_read(reg):
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:op", "task_id": "R",
                 "observation_id": "obs-r", "facts": {"v": 1}}])


def test_required_write_remains_admissible():
    reg = CausalRegistry(_synthetic())
    sc = CausalSidecar(reg, log=lambda r: None)
    _close_read(reg)
    v = sc.check("agent:op", {"action": "write", "task": "W", "tool": "t.exec",
                              "target": "target", "args": {}}, "r1")
    assert v.allowed and v.code == "ADMISSIBLE", v.to_dict()


def test_activated_conditional_write_remains_admissible():
    reg = CausalRegistry(_synthetic(conditional_activation="Z"))
    sc = CausalSidecar(reg, log=lambda r: None)
    action = {"action": "write", "task": "W", "tool": "t.exec",
              "target": "target", "args": {}}

    # No verified evidence: conditional WRITE must fail closed.
    v = sc.check("agent:op", action, "r1")
    assert not v.allowed and v.code == "ACTIVATION_UNRESOLVED", v.to_dict()
    assert reg.activation_of("W") == "Z"

    # A confirmed observation automatically activates W.
    _close_read(reg)
    v = sc.check("agent:op", action, "r2")
    assert v.allowed and v.code == "ADMISSIBLE", v.to_dict()
    assert reg.activation_of("W") == "T"
    assert reg.obligations["W"].activation_origin == "derived"
    assert reg.obligations["W"].activation_evidence_refs == ["obs-r"]
    assert "W" in reg.open_obligations("agent:op")


def test_activation_requires_verified_evidence():
    reg = CausalRegistry(_synthetic(conditional_activation="Z"))
    _close_read(reg)
    ok, _ = reg.resolve_activation("W", "T", evidence_refs=["obs-nope"], source="public:x")
    assert not ok and reg.activation_of("W") == "Z"
    ok, _ = reg.resolve_activation("W", "T", evidence_refs=[], source="public:x")
    assert not ok and reg.activation_of("W") == "Z"


def test_unknown_critical_activation_blocks_exit_not_false_done():
    reg = CausalRegistry(_synthetic(conditional_activation="Z", requires_resolution=True))
    sc = CausalSidecar(reg, log=lambda r: None)
    # Unknown critical condition blocks exit without evidence.
    assert "W" not in reg.open_obligations("agent:op")
    v = sc.check_exit("agent:op", "all_tasks_terminal")
    assert not v.allowed and v.code == "ACTIVATION_UNRESOLVED", v.to_dict()

    # After a verified true observation, W becomes mandatory.
    _close_read(reg)
    v = sc.check_exit("agent:op", "all_tasks_terminal")
    assert not v.allowed
    assert v.code == "EXIT_BLOCKED_OPEN_OBLIGATIONS", v.to_dict()
    assert reg.activation_of("W") == "T"
    assert "W" in reg.open_obligations("agent:op")


def test_inactive_conditional_does_not_block_exit():
    reg = CausalRegistry(_synthetic(conditional_activation="F"))
    sc = CausalSidecar(reg, log=lambda r: None)
    _close_read(reg)
    assert reg.open_obligations("agent:op") == []
    v = sc.check_exit("agent:op", "all_tasks_terminal")
    assert v.allowed and v.code == "EXIT_OK", v.to_dict()
    v = sc.check("agent:op", {"action": "write", "task": "W", "tool": "t.exec",
                              "target": "target", "args": {}}, "r1")
    assert not v.allowed and v.code == "NOT_REQUIRED", v.to_dict()
