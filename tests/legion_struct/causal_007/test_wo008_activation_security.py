from causal_007.causal_registry import CausalRegistry
from causal_007.sidecar import CausalSidecar


def registry(value=True, predicate=None, observation_epoch=1,
             include_observation=True):
    if predicate is None:
        predicate = {"field": "emergency", "equals": True}

    spec = {
        "world_id": "WO008-SECURITY",
        "epoch": 1,
        "roles": [{
            "agent_id": "agent:probe",
            "tasks": [
                {
                    "task_id": "R",
                    "kinds": ["READ"],
                    "depends_on": [],
                    "read_tools": ["status.read"]
                },
                {
                    "task_id": "W",
                    "kinds": ["WRITE"],
                    "requirement": "CONDITIONAL",
                    "activation": "Z",
                    "activation_predicate": predicate,
                    "depends_on": ["R"],
                    "write_tool": "emergency.apply"
                }
            ]
        }]
    }

    reg = CausalRegistry(spec)

    if include_observation:
        reg.ingest([{
            "kind": "OBSERVATION",
            "task_id": "R",
            "agent_id": "agent:probe",
            "observation_id": "obs-r",
            "epoch": observation_epoch,
            "facts": {"emergency": value}
        }])

    return reg


def test_forged_public_reference_rejected():
    reg = registry()
    ok, why = reg.resolve_activation(
        "W", "T",
        evidence_refs=["public:nonexistent-forged-reference"]
    )
    assert not ok
    assert reg.activation_of("W") == "Z"


def test_verified_true_condition_activates():
    reg = registry(True)
    ok, why = reg.resolve_activation(
        "W", "T", evidence_refs=["obs-r"]
    )
    assert ok, why
    assert reg.activation_of("W") == "T"


def test_false_fact_cannot_activate_true():
    reg = registry(False)
    ok, why = reg.resolve_activation(
        "W", "T", evidence_refs=["obs-r"]
    )
    assert not ok
    assert reg.activation_of("W") == "Z"


def test_false_fact_can_resolve_inactive():
    reg = registry(False)
    ok, why = reg.resolve_activation(
        "W", "F", evidence_refs=["obs-r"]
    )
    assert ok, why
    assert reg.activation_of("W") == "F"


def test_true_fact_cannot_resolve_false():
    reg = registry(True)
    ok, why = reg.resolve_activation(
        "W", "F", evidence_refs=["obs-r"]
    )
    assert not ok
    assert reg.activation_of("W") == "Z"


def test_stale_epoch_rejected():
    reg = registry(True, observation_epoch=0)
    ok, why = reg.resolve_activation(
        "W", "T", evidence_refs=["obs-r"]
    )
    assert not ok
    assert reg.activation_of("W") == "Z"


def test_unstructured_predicate_fails_closed():
    reg = registry(True, predicate="Emergency, if needed")
    ok, why = reg.resolve_activation(
        "W", "T", evidence_refs=["obs-r"]
    )
    assert not ok
    assert why == "ACTIVATION_PREDICATE_UNCHECKABLE"


def test_activated_write_admissible_after_evidence():
    reg = registry(True, include_observation=False)
    sidecar = CausalSidecar(reg, log=lambda _: None)

    action = {
        "action": "write",
        "task": "W",
        "tool": "emergency.apply",
        "args": {}
    }

    before = sidecar.check("agent:probe", action, "decision-1")
    assert not before.allowed
    assert before.code == "ACTIVATION_UNRESOLVED"
    assert reg.activation_of("W") == "Z"

    reg.ingest([{
        "kind": "OBSERVATION",
        "task_id": "R",
        "agent_id": "agent:probe",
        "observation_id": "obs-r",
        "epoch": 1,
        "facts": {"emergency": True}
    }])

    # No manual activation call: runtime must derive the transition.
    after = sidecar.check("agent:probe", action, "decision-2")
    assert after.allowed, after.to_dict()
    assert reg.activation_of("W") == "T"
    assert reg.obligations["W"].activation_origin == "derived"
    assert reg.obligations["W"].activation_evidence_refs == ["obs-r"]

import pytest
pytestmark = [pytest.mark.unit, pytest.mark.local]
