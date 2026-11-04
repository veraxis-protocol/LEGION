"""WO008-02 evidence-feed integrity: CausalState.refresh must fail closed."""
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import sidecar_server  # noqa: E402

AGENT = "agent:op"
WRITE = {"action": "write", "task": "W", "tool": "t.exec", "target": "target", "args": {}}


def spec():
    return {
        "world_id": "SYNTH-W008-FEED", "family": "SYNTH-W008-FEED", "epoch": 1,
        "attempt_uid": "att-1", "world_instance_id": "win-1",
        "tools": {"t.get": {"kind": "read", "params": {}, "returns": {}},
                  "t.exec": {"kind": "write", "params": {}, "returns": {}}},
        "roles": [{"agent_id": AGENT, "tasks": [
            {"task_id": "R", "kinds": ["READ"], "read_tools": ["t.get"],
             "depends_on": [], "recipients": []},
            {"task_id": "W", "kinds": ["WRITE"], "read_tools": ["t.get"],
             "write_tool": "t.exec", "target": "target",
             "depends_on": ["R"], "recipients": []}]}],
    }


def obs_r(seq=1, epoch=1):
    return {"kind": "OBSERVATION", "agent_id": AGENT, "task_id": "R",
            "observation_id": f"obs-{seq}", "seq": seq, "epoch": epoch,
            "attempt_uid": "att-1", "world_instance_id": "win-1",
            "facts": {"v": seq}}


def make_state(tmp_path):
    st = sidecar_server.CausalState(spec(), "http://world.invalid", "tok",
                                    str(tmp_path / "CAUSAL_CONTROLLER.jsonl"))
    return st


def test_lost_feed_denies_consequence(tmp_path):
    st = make_state(tmp_path)
    st.registry.ingest([obs_r()])
    def boom():
        raise OSError("connection refused")
    st._fetch_world_records = boom
    assert st.refresh() is False
    assert st.feed_unavailable is True
    v = st.sidecar.check(AGENT, dict(WRITE), "d1")
    assert not v.allowed and v.code == "EVIDENCE_FEED_UNAVAILABLE", v.to_dict()
    # previously confirmed state is retained, not silently turned into []
    assert st.registry.is_confirmed("R")


def test_lost_feed_denies_exit(tmp_path):
    st = make_state(tmp_path)
    def boom():
        raise OSError("connection refused")
    st._fetch_world_records = boom
    st.refresh()
    v = st.sidecar.check_exit(AGENT, "all_tasks_terminal")
    assert not v.allowed and v.code == "EVIDENCE_FEED_UNAVAILABLE", v.to_dict()


def test_recovered_feed_restores_admission(tmp_path):
    st = make_state(tmp_path)
    st.registry.ingest([obs_r()])
    calls = {"n": 0}
    def flaky():
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("down")
        return [obs_r(seq=1)]
    st._fetch_world_records = flaky
    st.refresh()
    assert st.sidecar.check(AGENT, dict(WRITE), "d1").allowed is False
    # a sleep/retry that still fails is not recovery
    st._fetch_world_records = lambda: (_ for _ in ()).throw(OSError("still down"))
    st.refresh()
    assert st.feed_unavailable is True
    st._fetch_world_records = lambda: [obs_r(seq=1)]
    assert st.refresh() is True
    assert st.feed_unavailable is False
    v = st.sidecar.check(AGENT, dict(WRITE), "d2")
    assert v.allowed, v.to_dict()


def test_out_of_order_or_truncated_feed_denied(tmp_path):
    st = make_state(tmp_path)
    st._fetch_world_records = lambda: [obs_r(seq=2), obs_r(seq=1)]
    assert st.refresh() is False
    assert st.feed_unavailable is True
    assert not st.registry.is_confirmed("R")

    st2 = make_state(tmp_path)
    st2._fetch_world_records = lambda: [obs_r(seq=1), obs_r(seq=2)]
    assert st2.refresh() is True
    assert st2.registry.is_confirmed("R")
    # truncated: feed shrinks below what was already fed
    st2._fetch_world_records = lambda: [obs_r(seq=1)]
    assert st2.refresh() is False
    assert st2.feed_unavailable is True
    v = st2.sidecar.check_exit(AGENT, "all_tasks_terminal")
    assert not v.allowed and v.code == "EVIDENCE_FEED_UNAVAILABLE", v.to_dict()


def test_stale_epoch_feed_denied(tmp_path):
    st = make_state(tmp_path)
    st._fetch_world_records = lambda: [obs_r(seq=1, epoch=99)]
    assert st.refresh() is False
    assert st.feed_unavailable is True


def test_terminal_epoch_feed_denied(tmp_path):
    st = make_state(tmp_path)
    rec = obs_r(seq=1); rec["attempt_state"] = "COMPLETED"
    st._fetch_world_records = lambda: [rec]
    assert st.refresh() is False
    assert st.feed_unavailable is True


def test_unreadable_gate_feed_denied(tmp_path):
    gate = tmp_path / "GATE_COMMITS.jsonl"
    gate.write_text('{"outcome": "x"}\nNOT-JSON\n', encoding="utf-8")
    rb = tmp_path / "READBACK.jsonl"; rb.write_text("", encoding="utf-8")
    st = sidecar_server.CausalState(spec(), "", "", str(tmp_path / "out.jsonl"),
                                    gate_path=str(gate), readback_path=str(rb))
    assert st.refresh() is False
    assert st.feed_unavailable is True


def test_readback_feed_completes_write(tmp_path):
    rb = tmp_path / "READBACK.jsonl"
    import json as _json
    rb.write_text(_json.dumps({
        "kind": "READBACK_EFFECT", "effect_id": "eff-1", "command_id": "cmd-1",
        "task_id": "W", "agent_id": AGENT, "confirmed": True,
        "attempt_uid": "att-1", "world_instance_id": "win-1", "epoch": 1}) + "\n",
        encoding="utf-8")
    st = sidecar_server.CausalState(spec(), "", "", str(tmp_path / "out.jsonl"),
                                    readback_path=str(rb))
    st.registry.ingest([obs_r()])
    st.registry.ingest([
        {"kind": "NATIVE_EFFECT", "agent_id": AGENT, "task_id": "W",
         "effect_id": "eff-1", "command_id": "cmd-1", "epoch": 1,
         "attempt_uid": "att-1", "world_instance_id": "win-1"},
        {"kind": "RECEIPT", "agent_id": AGENT, "task_id": "W", "receipt_id": "r1",
         "effect_id": "eff-1", "command_id": "cmd-1", "epoch": 1, "permit_epoch": 1,
         "attempt_uid": "att-1", "world_instance_id": "win-1", "permit_verified": True}])
    assert not st.registry.is_confirmed("W")
    assert st.refresh() is True
    assert st.registry.is_confirmed("W")
