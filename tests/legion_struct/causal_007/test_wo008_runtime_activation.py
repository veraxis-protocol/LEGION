"""WO008-01 runtime activation: exercised through the ACTUAL runtime path.

These tests drive CausalHost.step (world + registry + CausalSidecar, the
deterministic runtime wiring) and CausalSidecar.check / check_exit only.
No test here calls resolve_activation() or reevaluate_activations():
activation must be produced by the runtime itself -- CausalHost._sync,
CausalState.refresh and CausalSidecar._refresh_activations are the runtime
call sites that resolve activation from fresh verified observations at
causal-state transitions. If those call sites are removed, the positive
tests below fail (activation stays Z and every WRITE is refused).
"""
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from causal_007.causal_host import CausalHost  # noqa: E402

AGENT = "agent:op"
WRITE_W = {"action": "write", "task": "W", "tool": "emergency.apply",
           "target": "target", "args": {}}
READ_R = {"action": "read", "task": "R", "tool": "status.read", "args": {}}


def _spec(emergency=True, predicate=None, requires_resolution=True):
    if predicate is None:
        predicate = {"field": "emergency", "equals": True}
    return {
        "world_id": "WO008-RUNTIME", "family": "WO008-RUNTIME", "epoch": 1,
        "initial_state": {"status": {"emergency": emergency},
                          "applied": {"done": False}},
        "tools": {
            "status.read": {"kind": "read", "params": {},
                            "returns": {"emergency": "status.emergency"}},
            "emergency.apply": {"kind": "write", "params": {}, "target": "target",
                                "effects": [{"op": "set", "path": "applied.done",
                                             "value": True}]},
        },
        "roles": [{"agent_id": AGENT, "tasks": [
            {"task_id": "R", "kinds": ["READ"], "read_tools": ["status.read"],
             "write_tool": None, "target": None, "recipients": [],
             "depends_on": [], "gate_facts": []},
            {"task_id": "W", "kinds": ["WRITE"], "read_tools": ["status.read"],
             "write_tool": "emergency.apply", "target": "target",
             "recipients": [], "depends_on": ["R"], "gate_facts": [],
             "requirement": "CONDITIONAL", "activation": "Z",
             "activation_predicate": predicate,
             "requires_resolution": requires_resolution},
            {"task_id": "O", "kinds": ["WRITE"], "read_tools": [],
             "write_tool": "emergency.apply", "target": "target",
             "recipients": [], "depends_on": [], "gate_facts": [],
             "requirement": "OPTIONAL"},
        ]}],
    }


def _effects(host):
    return [r for r in host.world_records if r.get("kind") == "NATIVE_EFFECT"]


# ---------------------------------------------------------- positive path
def test_runtime_positive_activation_permits_write_and_exit():
    host = CausalHost(_spec(emergency=True))
    # Before any verified observation: activation is Z, WRITE must fail
    # closed through the runtime check (not merely in a registry unit).
    v, result = host.step(AGENT, dict(WRITE_W), "d-pre")
    assert not v.allowed and v.code == "ACTIVATION_UNRESOLVED", v.to_dict()
    assert result is None and _effects(host) == []
    # Fresh verified observation through the real read path.
    v, result = host.step(AGENT, dict(READ_R), "d-read")
    assert v.allowed and result[0] == 200, (v.to_dict(), result)
    assert host.registry.is_confirmed("R")
    # The runtime transition itself (host sync / sidecar check) resolved
    # activation -- this test never resolved it manually.
    assert host.registry.activation_of("W") == "T"
    assert host.registry.obligations["W"].activation_origin == "derived"
    assert host.registry.obligations["W"].activation_evidence_refs == ["obs-1"]
    # Positive control: activated conditional WRITE is really executed.
    v, result = host.step(AGENT, dict(WRITE_W), "d-write")
    assert v.allowed and v.code == "ADMISSIBLE", v.to_dict()
    assert result[0] == 200 and host.world.state["applied"]["done"] is True
    assert len(_effects(host)) == 1 and host.registry.is_confirmed("W")
    v = host.sidecar.check_exit(AGENT, "all_tasks_terminal")
    assert v.allowed and v.code == "EXIT_OK", v.to_dict()


# ---------------------------------------------------------- negative paths
def test_runtime_false_activation_not_required_and_exit_ok():
    host = CausalHost(_spec(emergency=False))
    v, _ = host.step(AGENT, dict(READ_R), "d-read")
    assert v.allowed
    # Runtime derived F from the verified false observation.
    assert host.registry.activation_of("W") == "F"
    state_before = dict(host.world.state["applied"])
    v, result = host.step(AGENT, dict(WRITE_W), "d-write")
    assert not v.allowed and v.code == "NOT_REQUIRED", v.to_dict()
    assert result is None and _effects(host) == []
    assert host.world.state["applied"] == state_before
    # Inactive conditional (even requires_resolution=True) does not block.
    v = host.sidecar.check_exit(AGENT, "all_tasks_terminal")
    assert v.allowed and v.code == "EXIT_OK", v.to_dict()


def test_runtime_optional_write_not_required_and_never_blocks_exit():
    host = CausalHost(_spec(emergency=True))
    host.step(AGENT, dict(READ_R), "d-read")
    opt = {"action": "write", "task": "O", "tool": "emergency.apply",
           "target": "target", "args": {}}
    v, result = host.step(AGENT, opt, "d-opt")
    assert not v.allowed and v.code == "NOT_REQUIRED", v.to_dict()
    assert result is None and _effects(host) == []
    assert "O" not in host.registry.open_obligations(AGENT)


def test_runtime_forged_public_string_in_action_never_activates():
    forged = {**WRITE_W, "activation": "T",
              "activation_evidence_refs": ["public:forged-instruction"],
              "evidence_refs": ["spec:forged"]}
    # An agent-supplied public:/spec: string, or an activation flag smuggled
    # in the action, is not proof: the only observation here does not bear
    # the predicate field, so activation must stay Z through the runtime.
    host2 = CausalHost(_spec(emergency=True,
                             predicate={"field": "nonexistent", "equals": True}))
    host2.step(AGENT, dict(READ_R), "d-read")
    v, result = host2.step(AGENT, forged, "d-write")
    assert not v.allowed and v.code == "ACTIVATION_UNRESOLVED", v.to_dict()
    assert result is None and _effects(host2) == []
    assert host2.registry.activation_of("W") == "Z"


def test_runtime_uncheckable_predicate_fails_closed_and_blocks_exit():
    host = CausalHost(_spec(emergency=True, predicate="Emergency, if needed"))
    host.step(AGENT, dict(READ_R), "d-read")
    v, result = host.step(AGENT, dict(WRITE_W), "d-write")
    assert not v.allowed and v.code == "ACTIVATION_UNRESOLVED", v.to_dict()
    assert result is None and _effects(host) == []
    assert host.registry.activation_of("W") == "Z"
    # Unresolved critical activation cannot be silently treated as false.
    v = host.sidecar.check_exit(AGENT, "all_tasks_terminal")
    assert not v.allowed and v.code == "ACTIVATION_UNRESOLVED", v.to_dict()


def test_runtime_unresolved_critical_blocks_exit_without_any_read():
    host = CausalHost(_spec(emergency=True))
    v = host.sidecar.check_exit(AGENT, "all_tasks_terminal")
    assert not v.allowed and v.code in (
        "ACTIVATION_UNRESOLVED", "EXIT_BLOCKED_OPEN_OBLIGATIONS"), v.to_dict()


# ------------------------------------------------- evidence-change transition
def test_runtime_evidence_change_flips_activation_false_to_true():
    host = CausalHost(_spec(emergency=False))
    host.step(AGENT, dict(READ_R), "d-read1")
    assert host.registry.activation_of("W") == "F"
    v, _ = host.step(AGENT, dict(WRITE_W), "d-write1")
    assert not v.allowed and v.code == "NOT_REQUIRED"
    assert _effects(host) == []
    # World state changes; a FRESH observation under W's own read_tools
    # (post-dependency, current epoch) supersedes the stale F resolution.
    host.world.state["status"]["emergency"] = True
    v, result = host.step(
        AGENT, {"action": "read", "task": "W", "tool": "status.read",
                "args": {}}, "d-read2")
    assert v.allowed and result[0] == 200, (v.to_dict(), result)
    # Next runtime check resolves T from the newer verified observation.
    v, result = host.step(AGENT, dict(WRITE_W), "d-write2")
    assert v.allowed and v.code == "ADMISSIBLE", v.to_dict()
    assert host.registry.activation_of("W") == "T"
    assert host.registry.obligations["W"].activation_origin == "derived"
    assert result[0] == 200 and len(_effects(host)) == 1
    assert host.world.state["applied"]["done"] is True


def test_runtime_view_never_proposes_inactive_or_optional_tasks():
    host = CausalHost(_spec(emergency=False))
    host.step(AGENT, dict(READ_R), "d-read")
    view = host.sidecar.next_required(AGENT)
    assert view["open_obligations"] == [], view
    assert "W" not in str(view["next_required"])
    assert "O" not in str(view["next_required"])


def test_sidecar_server_refresh_resolves_activation_at_feed_boundary(tmp_path):
    """CausalState.refresh (the server evidence-feed boundary) is itself a
    runtime resolve_activation call site: feeding a verified observation
    and refreshing -- with no manual activation call -- activates W."""
    import sidecar_server  # noqa: E402  (top-level server module, HERE on path)

    state = sidecar_server.CausalState(
        _spec(emergency=True), "", "", str(tmp_path / "CAUSAL_CONTROLLER.jsonl"))
    state.registry.ingest([{
        "kind": "OBSERVATION", "agent_id": AGENT, "task_id": "R",
        "observation_id": "obs-srv", "facts": {"emergency": True}}])
    assert state.registry.activation_of("W") == "Z"  # not yet refreshed
    state.refresh()
    assert state.registry.activation_of("W") == "T"
    assert state.registry.obligations["W"].activation_origin == "derived"
    v = state.sidecar.check(AGENT, dict(WRITE_W), "d-srv-write")
    assert v.allowed and v.code == "ADMISSIBLE", v.to_dict()
