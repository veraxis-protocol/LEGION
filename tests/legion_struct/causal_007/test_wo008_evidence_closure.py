"""WO008-02 earned closure: WRITE/READ/COMMUNICATE require earned evidence."""
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

ATT, WIN, EPOCH = "att-1", "win-1", 1


def spec():
    return {
        "world_id": "SYNTH-W008-02", "family": "SYNTH-W008-02",
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
            {"task_id": "M", "kinds": ["COMMUNICATE"], "read_tools": [],
             "depends_on": ["R"], "recipients": ["agent:peer"],
             "content_propositions": [{"field": "customer_id", "equals": "C-17"}]},
        ]}, {"agent_id": "agent:peer", "tasks": []}],
    }


def reg_with_r(facts=None):
    reg = CausalRegistry(spec())
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:op", "task_id": "R",
                 "observation_id": "obs-r", "epoch": EPOCH, "attempt_uid": ATT,
                 "world_instance_id": WIN,
                 "facts": facts or {"customer_id": "C-17", "status": "open"}}])
    assert reg.is_confirmed("R")
    return reg


def effect(**kw):
    r = {"kind": "NATIVE_EFFECT", "agent_id": "agent:op", "task_id": "W",
         "effect_id": "eff-1", "command_id": "cmd-1", "epoch": EPOCH,
         "permit_epoch": EPOCH, "attempt_uid": ATT, "world_instance_id": WIN,
         "tool": "t.exec", "target": "target", "args": {}}
    r.update(kw); return r


def receipt(**kw):
    r = {"kind": "RECEIPT", "agent_id": "agent:op", "task_id": "W",
         "receipt_id": "rcpt-1", "effect_id": "eff-1", "command_id": "cmd-1",
         "epoch": EPOCH, "permit_epoch": EPOCH, "attempt_uid": ATT,
         "world_instance_id": WIN, "permit_verified": True,
         "tool": "t.exec", "target": "target", "args": {}}
    r.update(kw); return r


def readback(**kw):
    r = {"kind": "READBACK_EFFECT", "agent_id": "agent:op", "task_id": "W",
         "effect_id": "eff-1", "command_id": "cmd-1", "epoch": EPOCH,
         "attempt_uid": ATT, "world_instance_id": WIN, "confirmed": True,
         "state_sha256": "abc"}
    r.update(kw); return r


def test_effect_without_receipt_does_not_confirm():
    reg = reg_with_r()
    reg.ingest([effect()])
    assert not reg.is_confirmed("W")
    assert reg.write_status("W") == "EXECUTED_UNVERIFIED"
    assert reg.open_deps("D") == ["W"]


def test_receipt_without_readback_does_not_confirm():
    reg = reg_with_r()
    reg.ingest([effect(), receipt()])
    assert not reg.is_confirmed("W")
    assert reg.write_status("W") == "EXECUTED_UNVERIFIED"


def test_mismatched_effect_identity_rejected():
    reg = reg_with_r()
    reg.ingest([effect(), receipt(effect_id="eff-other"), readback(effect_id="eff-other")])
    assert not reg.is_confirmed("W")
    assert any(s["reason"].startswith(("IDENTITY_MISMATCH", "RECEIPT_IDENTITY", "READBACK_IDENTITY"))
               for s in reg.obligations["W"].stale)


def test_cross_epoch_receipt_rejected():
    reg = reg_with_r()
    reg.ingest([effect(), receipt(epoch=99, permit_epoch=99), readback()])
    assert not reg.is_confirmed("W")
    assert reg.write_status("W") == "EXECUTED_UNVERIFIED"


def test_cross_attempt_receipt_rejected():
    reg = reg_with_r()
    reg.ingest([effect(), receipt(attempt_uid="att-foreign"), readback()])
    assert not reg.is_confirmed("W")


def test_cross_world_readback_rejected():
    reg = reg_with_r()
    reg.ingest([effect(), receipt(), readback(world_instance_id="win-foreign")])
    assert not reg.is_confirmed("W")


def test_unverified_readback_does_not_confirm():
    reg = reg_with_r()
    reg.ingest([effect(), receipt(), readback(confirmed=False)])
    assert not reg.is_confirmed("W")


def test_complete_effect_receipt_readback_verifies():
    reg = reg_with_r()
    reg.ingest([effect(), receipt(), readback()])
    assert reg.is_confirmed("W")
    assert reg.write_status("W") == "VERIFIED"
    assert reg.open_deps("D") == []
    # dependent can now close with a fresh read
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:op", "task_id": "D",
                 "observation_id": "obs-d", "epoch": EPOCH, "facts": {"done": True}}])
    assert reg.is_confirmed("D")


def test_complete_triplet_any_order_verifies():
    reg = reg_with_r()
    reg.ingest([readback(), receipt(), effect()])
    assert reg.is_confirmed("W")


def test_duplicate_effect_does_not_double_close():
    reg = reg_with_r()
    reg.ingest([effect(), receipt(), readback()])
    assert reg.is_confirmed("W")
    seq = dict(reg.confirm_seq)
    satisfied = dict(reg.obligations["W"].satisfied)
    reg.ingest([effect(), receipt(), readback()])
    assert reg.confirm_seq == seq
    assert reg.obligations["W"].satisfied == satisfied
    assert any(s["reason"].startswith("DUPLICATE") for s in reg.obligations["W"].stale)


def test_premature_write_effect_does_not_verify_even_with_triplet():
    reg = CausalRegistry(spec())  # R not confirmed
    reg.ingest([effect(), receipt(), readback()])
    assert not reg.is_confirmed("W")


def test_wrong_nonempty_read_fails_predicate():
    reg = CausalRegistry(spec())
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:op", "task_id": "RD",
                 "observation_id": "obs-wrong", "epoch": EPOCH,
                 "facts": {"status": "closed", "priority": "P1", "extra": "nonempty"}}])
    assert not reg.is_confirmed("RD")
    assert not reg.observations["obs-wrong"]["_confirmed"]
    assert reg.obligations["RD"].stale[-1]["reason"].startswith("EVIDENCE_PREDICATE")


def test_correct_read_passes_predicate():
    reg = CausalRegistry(spec())
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:op", "task_id": "RD",
                 "observation_id": "obs-ok", "epoch": EPOCH,
                 "facts": {"status": "open", "priority": "P2"}}])
    assert reg.is_confirmed("RD")
    assert reg.observations["obs-ok"]["_confirmed"]


def test_type_strict_predicate_rejects_bool_int_confusion():
    reg = CausalRegistry(spec())
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:op", "task_id": "RD",
                 "observation_id": "obs-t", "epoch": EPOCH,
                 "facts": {"status": "open", "priority": 2}}])
    assert not reg.is_confirmed("RD")


def test_premature_read_retained_but_requires_fresh_read():
    reg = CausalRegistry(spec())
    # RD has no deps in this spec; use D (depends on W) as premature READ
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:op", "task_id": "D",
                 "observation_id": "obs-early", "epoch": EPOCH, "facts": {"x": 1}}])
    assert "obs-early" in reg.observations
    assert not reg.observations["obs-early"]["_confirmed"]
    assert not reg.is_confirmed("D")


def test_wrong_message_content_does_not_confirm():
    reg = reg_with_r()
    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": "agent:op", "task_id": "M",
                 "recipient": "agent:peer", "message_id": "m1",
                 "facts": {"customer_id": "C-71"}, "evidence_refs": ["obs-r"]}])
    assert not reg.is_confirmed("M")
    assert reg.obligations["M"].stale[-1]["reason"].startswith(("CONTENT", "MESSAGE_CONTENT"))


def test_invented_message_content_not_grounded_does_not_confirm():
    # Message asserts the required value, but cites no verified evidence and
    # the value is absent from confirmed evidence for this registry.
    reg = reg_with_r(facts={"customer_id": "C-99", "status": "open"})
    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": "agent:op", "task_id": "M",
                 "recipient": "agent:peer", "message_id": "m1",
                 "facts": {"customer_id": "C-17"}}])
    assert not reg.is_confirmed("M")


def test_verified_message_delivery_confirms():
    reg = reg_with_r()
    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": "agent:op", "task_id": "M",
                 "recipient": "agent:peer", "message_id": "m1",
                 "facts": {"customer_id": "C-17"}, "evidence_refs": ["obs-r"]}])
    assert reg.is_confirmed("M")


def test_wrong_recipient_message_does_not_confirm():
    reg = reg_with_r()
    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": "agent:op", "task_id": "M",
                 "recipient": "agent:other", "message_id": "m1",
                 "facts": {"customer_id": "C-17"}, "evidence_refs": ["obs-r"]}])
    assert not reg.is_confirmed("M")


def test_sidecar_denies_write_content_and_admission_tracks_state():
    reg = reg_with_r()
    sc = CausalSidecar(reg, log=lambda r: None)
    v = sc.check("agent:op", {"action": "write", "task": "W", "tool": "t.exec",
                              "target": "target", "args": {}}, "d1")
    assert v.allowed, v.to_dict()
    assert reg.write_status("W") == "ADMITTED"
    reg.ingest([effect()])
    assert reg.write_status("W") == "EXECUTED_UNVERIFIED"
    # A READ dependent may observe early (P0-6) but it cannot close D and
    # W remains unverified; the write dependent gate stays shut for closure.
    v = sc.check("agent:op", {"action": "read", "task": "D", "tool": "t.get", "args": {}}, "d2")
    assert v.allowed and v.observation_only, v.to_dict()
    assert not reg.is_confirmed("D") and reg.open_deps("D") == ["W"]
