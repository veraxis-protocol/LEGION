"""WO008-04 S100: genuine downstream contribution, on the real installed
non-NIM scripted runtime (CausalHost deciders -> CausalSidecar ->
CausalRegistry -> world_engine.World, the same scripted host path used by
the deterministic campaign tests). Registration, delegation requests and
unconsumed delegate results never count: an edge exists only when a
different downstream agent consumes an authenticated delegate result
reference in an admitted consequential action that produces a VERIFIED
effect+receipt+readback and closes the downstream obligation.
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
from causal_007.delegation import (  # noqa: E402
    authenticate_delegate_result, build_s100_spec, verified_collaboration_count,
    verified_delegation_edges)
from causal_007 import recovery as rec  # noqa: E402

ATT, WIN, EPOCH = "att-wo008-04", "win-wo008-04", 1
WORLDS = HERE.parent / "worlds"
COORD = "agent:o4-coordinator"
DELEGATE = "agent:s100-delegate-000"   # D000, partition p0
CONSUMER = "agent:o4-consumer-p0"


def s100_host():
    spec = json.loads((WORLDS / "SYN-OTEL-04.world.json").read_text(encoding="utf-8"))
    spec = build_s100_spec(copy.deepcopy(spec), total=100)
    spec.update(attempt_uid=ATT, world_instance_id=WIN, epoch=EPOCH)
    return CausalHost(spec), spec


def restart_and_delegate(host):
    v, _ = host.step(COORD, {"action": "read", "task": "T1",
                             "tool": "consumer_group.status", "args": {}}, "scripted:t1")
    assert v.allowed, v.code
    v, _ = host.step(COORD, {"action": "write", "task": "T2",
                             "tool": "consumer_group.restart",
                             "target": "cg-fraud-detection",
                             "args": {"group": "fraud-detection"}}, "scripted:t2")
    assert v.allowed and host.registry.write_status("T2") == "VERIFIED"
    v, _ = host.step(DELEGATE, {"action": "read", "task": "D000",
                                "tool": "partition.offsets",
                                "args": {"partition": "p0"}}, "scripted:delegate-read")
    assert v.allowed, v.code
    return host.world_records[-1]["observation_id"]


def test_s100_downstream_consumes_verified_result():
    host, spec = s100_host()
    assert len(spec["roles"]) == 100
    ref = restart_and_delegate(host)
    ok, code, entry = authenticate_delegate_result(host.registry, ref)
    assert ok and code == "DELEGATE_RESULT_AUTHENTICATED", code
    assert entry["agent_id"] == DELEGATE and entry["facts"]["committed"] == 100
    # Delegator -> recipient produced a result; nothing downstream yet.
    assert verified_delegation_edges(host.registry, host.log) == []
    # Downstream agent consumes the exact verified reference consequentially.
    v, _ = host.step(CONSUMER, {"action": "read", "task": "Rp0",
                                "tool": "partition.offsets",
                                "args": {"partition": "p0"}}, "scripted:rp0")
    assert v.allowed, v.code
    v, _ = host.step(CONSUMER, {"action": "write", "task": "Wp0",
                                "tool": "partition.drain", "target": "p0",
                                "args": {"partition": "p0", "from_offset": 100},
                                "delegate_result_ref": ref}, "scripted:wp0-delegated")
    assert v.allowed, v.code
    assert host.registry.write_status("Wp0") == "VERIFIED"
    v, _ = host.step(CONSUMER, {"action": "send", "task": "Cp0",
                                "to": "agent:o4-verifier",
                                "body": f"p0 drained using delegate evidence {ref}"},
                     "scripted:cp0")
    assert v.allowed and host.registry.is_confirmed("Cp0")
    edges = verified_delegation_edges(host.registry, host.log)
    assert len(edges) == 1, edges
    edge = edges[0]
    assert edge["delegate_agent"] == DELEGATE
    assert edge["downstream_agent"] == CONSUMER and edge["downstream_agent"] != DELEGATE
    assert edge["delegate_result_ref"] == ref and edge["decision_ref"]
    assert edge["effect_id"] and edge["receipt_id"] and edge["readback_confirmed"] is True
    assert edge["attempt_uid"] == ATT and edge["world_instance_id"] == WIN
    assert edge["epoch"] == EPOCH and edge["obligation_confirmed"] is True
    assert verified_collaboration_count(host.registry, host.log) == 1
    # Raw evidence preserved: identities, delegate ref, effect, obligation.
    effect = next(r for r in host.world_records
                  if r.get("kind") == "NATIVE_EFFECT" and r.get("task_id") == "Wp0")
    assert effect["delegate_result_ref"] == ref and effect["effect_id"] == edge["effect_id"]
    # The dependent action caused an actual world effect, and the receipt
    # plus independent readback match the effect identity exactly.
    receipt = next(r for r in host.world_records
                   if r.get("kind") == "RECEIPT" and r.get("task_id") == "Wp0")
    readback = next(r for r in host.world_records
                    if r.get("kind") == "READBACK_EFFECT" and r.get("task_id") == "Wp0")
    assert receipt["effect_id"] == effect["effect_id"] == readback["effect_id"]
    assert receipt["receipt_id"] == edge["receipt_id"]
    assert receipt["command_id"] == effect["command_id"] == readback["command_id"]
    assert readback["confirmed"] is True and readback["state_sha256"]
    state = host.world.get_state()
    part0 = spec["initial_state"]["partitions"]["p0"]
    assert state["drains"]["p0"] == 1
    assert state["partitions"]["p0"]["committed"] == part0["log_end"]
    assert state["processed"]["p0"] == part0["log_end"] - part0["committed"]
    assert state["lag"]["p0"] == 0
    # Duplicate consumption of the same verified ref produces no 2nd effect.
    n_effects = len(host.world.effect_ledger)
    v, _ = host.step(CONSUMER, {"action": "write", "task": "Wp0",
                                "tool": "partition.drain", "target": "p0",
                                "args": {"partition": "p0", "from_offset": 100},
                                "delegate_result_ref": ref}, "scripted:wp0-duplicate")
    assert not v.allowed and v.code == "ALREADY_CONFIRMED", v.code
    assert len(host.world.effect_ledger) == n_effects
    assert host.world.get_state()["drains"]["p0"] == 1
    assert verified_delegation_edges(host.registry, host.log) == edges
    bundle = rec.evidence_bundle(host.registry, host, extra={"s100_edges": edges})
    out = HERE.parents[2] / "_wo008_input"
    if out.is_dir():
        (out / "WO008_04_S100_EVIDENCE.json").write_text(
            json.dumps(bundle, indent=1, sort_keys=True), encoding="utf-8")


def test_s100_delegate_without_use_not_counted():
    host, spec = s100_host()
    ref = restart_and_delegate(host)
    # The delegate was registered, was provider/script-active and produced
    # an authenticated result -- but nobody consumed it downstream.
    assert host.registry.is_confirmed("D000")
    ok, code, _ = authenticate_delegate_result(host.registry, ref)
    assert ok, code
    assert verified_delegation_edges(host.registry, host.log) == []
    assert verified_collaboration_count(host.registry, host.log) == 0
    # A mere citation in a non-consequential message is not collaboration
    # either: no VERIFIED downstream WRITE, no edge.
    v, _ = host.step(CONSUMER, {"action": "read", "task": "Rp0",
                                "tool": "partition.offsets",
                                "args": {"partition": "p0"}}, "scripted:rp0")
    assert v.allowed
    assert verified_collaboration_count(host.registry, host.log) == 0


def test_s100_mismatched_delegate_ref_denied():
    host, spec = s100_host()
    ref = restart_and_delegate(host)  # delegate evidence for p0 @ committed 100
    consumer1 = "agent:o4-consumer-p1"
    v, _ = host.step(consumer1, {"action": "read", "task": "Rp1",
                                 "tool": "partition.offsets",
                                 "args": {"partition": "p1"}}, "scripted:rp1")
    assert v.allowed, v.code
    # Wrong partition: p0 delegate result cannot authorize a p1 drain.
    v, _ = host.step(consumer1, {"action": "write", "task": "Wp1",
                                 "tool": "partition.drain", "target": "p1",
                                 "args": {"partition": "p1", "from_offset": 110},
                                 "delegate_result_ref": ref}, "scripted:wp1-wrong-part")
    assert not v.allowed and v.code == "DELEGATE_REF_PARTITION_MISMATCH", v.code
    # Fabricated reference: no such confirmed delegate result exists.
    v, _ = host.step(consumer1, {"action": "write", "task": "Wp1",
                                 "tool": "partition.drain", "target": "p1",
                                 "args": {"partition": "p1", "from_offset": 110},
                                 "delegate_result_ref": "obs-9999"}, "scripted:wp1-fake")
    assert not v.allowed and v.code == "DELEGATE_REF_UNVERIFIED", v.code
    # Offset mismatch: real p0 ref, consequential offset it does not prove.
    v, _ = host.step(CONSUMER, {"action": "read", "task": "Rp0",
                                "tool": "partition.offsets",
                                "args": {"partition": "p0"}}, "scripted:rp0")
    assert v.allowed
    v, _ = host.step(CONSUMER, {"action": "write", "task": "Wp0",
                                "tool": "partition.drain", "target": "p0",
                                "args": {"partition": "p0", "from_offset": 999},
                                "delegate_result_ref": ref}, "scripted:wp0-wrong-offset")
    assert not v.allowed and v.code == "DELEGATE_REF_OFFSET_MISMATCH", v.code
    # None of the denied consumptions produced an effect or an edge.
    assert not any(r.get("kind") == "NATIVE_EFFECT"
                   and r.get("task_id") in ("Wp0", "Wp1")
                   for r in host.world_records)
    assert verified_delegation_edges(host.registry, host.log) == []
    assert host.world.get_state()["drains"] == {f"p{i}": 0 for i in range(10)}
