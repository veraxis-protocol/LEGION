"""WO008-04 OTEL-04: ten shards, fresh post-restart reads only.

After the verified group restart, every Wp<i> is authorized only by its
own fresh Rp<i> evidence, bound to exact partition + committed offset;
Cp<i> closes only from the verified Wp<i> effect; duplicate offsets,
skipped partitions and premature global DONE are all rejected. Real
CausalHost -> CausalSidecar -> CausalRegistry -> World, no NIM.
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
from causal_007 import recovery as rec  # noqa: E402

ATT, WIN, EPOCH = "att-wo008-04", "win-wo008-04", 1
WORLDS = HERE.parent / "worlds"
COORD, VERIFIER = "agent:o4-coordinator", "agent:o4-verifier"


def otel_host():
    spec = json.loads((WORLDS / "SYN-OTEL-04.world.json").read_text(encoding="utf-8"))
    spec = copy.deepcopy(spec)
    spec.update(attempt_uid=ATT, world_instance_id=WIN, epoch=EPOCH)
    return CausalHost(spec), spec


def restart(host):
    v, _ = host.step(COORD, {"action": "read", "task": "T1",
                             "tool": "consumer_group.status", "args": {}}, "scripted:t1")
    assert v.allowed, v.code
    v, _ = host.step(COORD, {"action": "write", "task": "T2",
                             "tool": "consumer_group.restart",
                             "target": "cg-fraud-detection",
                             "args": {"group": "fraud-detection"}}, "scripted:t2")
    assert v.allowed, v.code
    assert host.registry.write_status("T2") == "VERIFIED"
    ev = host.registry.obligations["T2"].satisfied["WRITE"]
    assert ev["receipt"]["permit_verified"] is True and ev["readback"]["confirmed"] is True
    return ev


def drain_shard(host, spec, i, offset=None):
    agent = f"agent:o4-consumer-p{i}"
    v, _ = host.step(agent, {"action": "read", "task": f"Rp{i}",
                             "tool": "partition.offsets",
                             "args": {"partition": f"p{i}"}}, f"scripted:rp{i}")
    assert v.allowed, v.code
    committed = spec["initial_state"]["partitions"][f"p{i}"]["committed"]
    args = {"partition": f"p{i}",
            "from_offset": committed if offset is None else offset}
    ok, code, entry = rec.authorize_wp(host.registry, i, args)
    assert ok, code
    assert entry["observation_id"]
    v, _ = host.step(agent, {"action": "write", "task": f"Wp{i}",
                             "tool": "partition.drain", "target": f"p{i}",
                             "args": args}, f"scripted:wp{i}")
    assert v.allowed, v.code
    v, _ = host.step(agent, {"action": "send", "task": f"Cp{i}", "to": VERIFIER,
                             "body": f"p{i} drained from {args['from_offset']}"},
                     f"scripted:cp{i}")
    assert v.allowed, v.code


def test_otel04_fresh_rp_reads():
    host, spec = otel_host()
    restart(host)
    for i in range(10):
        agent = f"agent:o4-consumer-p{i}"
        v, _ = host.step(agent, {"action": "read", "task": f"Rp{i}",
                                 "tool": "partition.offsets",
                                 "args": {"partition": f"p{i}"}}, f"scripted:rp{i}")
        assert v.allowed, (i, v.code)
        entry, code = rec.fresh_rp_evidence(host.registry, i)
        assert entry is not None and code == "SHARD_READ_FRESH", (i, code)
        assert entry["_seq"] > host.registry.confirm_seq["T2"]
        assert entry["facts"]["committed"] == \
            spec["initial_state"]["partitions"][f"p{i}"]["committed"]
        assert host.registry.is_confirmed(f"Rp{i}")


def test_otel04_stale_reads_rejected():
    host, spec = otel_host()
    agent = "agent:o4-consumer-p0"
    # Pre-restart read: admitted only as an observation, closes nothing.
    v, _ = host.step(agent, {"action": "read", "task": "Rp0",
                             "tool": "partition.offsets",
                             "args": {"partition": "p0"}}, "scripted:early-rp0")
    assert v.allowed and v.observation_only, v.code
    assert not host.registry.is_confirmed("Rp0")
    restart(host)
    entry, code = rec.fresh_rp_evidence(host.registry, 0)
    assert entry is None and code == "SHARD_READ_STALE_OR_MISSING"
    ok, code, _ = rec.authorize_wp(host.registry, 0,
                                   {"partition": "p0", "from_offset": 100})
    assert not ok and code == "SHARD_READ_STALE_OR_MISSING"
    v, _ = host.step(agent, {"action": "write", "task": "Wp0",
                             "tool": "partition.drain", "target": "p0",
                             "args": {"partition": "p0", "from_offset": 100}},
                     "scripted:wp0-stale")
    assert not v.allowed and v.code == "DEPENDENCIES_OPEN", v.code
    assert len(host.world.effect_ledger) == 1  # only the restart effect
    # Wrong-epoch observations are stale evidence, never a fresh read.
    reg = CausalRegistry(spec)
    reg.ingest([{"kind": "OBSERVATION", "agent_id": agent, "task_id": "Rp0",
                 "observation_id": "obs-epoch99", "epoch": 99,
                 "attempt_uid": ATT, "world_instance_id": WIN,
                 "facts": {"committed": 100, "log_end": 103}}])
    assert not reg.is_confirmed("Rp0")
    assert any(s["reason"] in ("PREMATURE_BEFORE_DEPS", "STALE_OBSERVATION_EPOCH")
               for s in reg.obligations["Rp0"].stale)
    # Recovery requires NEW verified evidence: a fresh re-read now works.
    drain_shard(host, spec, 0)
    assert host.registry.write_status("Wp0") == "VERIFIED"


def test_otel04_each_partition_verified():
    host, spec = otel_host()
    restart(host)
    offsets = []
    for i in range(10):
        drain_shard(host, spec, i)
        reg, state = host.registry, host.world.get_state()
        part = spec["initial_state"]["partitions"][f"p{i}"]
        assert reg.write_status(f"Wp{i}") == "VERIFIED", i
        assert reg.is_confirmed(f"Cp{i}"), i  # closed only from verified Wp
        ev = reg.obligations[f"Wp{i}"].satisfied["WRITE"]
        assert ev["receipt"]["effect_id"] == ev["effect_id"]
        assert ev["readback"]["confirmed"] is True
        assert state["partitions"][f"p{i}"]["committed"] == part["log_end"]
        assert state["processed"][f"p{i}"] == part["log_end"] - part["committed"]
        assert state["lag"][f"p{i}"] == 0 and state["drains"][f"p{i}"] == 1
        offsets.append(part["committed"])
    assert len(set(offsets)) == 10  # no duplicate / skipped partitions
    wp_effects = [r for r in host.world_records if r.get("kind") == "NATIVE_EFFECT"
                  and str(r.get("task_id") or "").startswith("Wp")]
    assert len(wp_effects) == 10
    assert len({r["args"]["from_offset"] for r in wp_effects}) == 10
    # Exact binding is enforced: a wrong offset is denied, mutating nothing.
    v, _ = host.step("agent:o4-consumer-p0",
                     {"action": "write", "task": "Wp0", "tool": "partition.drain",
                      "target": "p0", "args": {"partition": "p0", "from_offset": 999}},
                     "scripted:wp0-bad-offset")
    assert not v.allowed and v.code == "ALREADY_CONFIRMED"
    assert host.world.get_state()["drains"]["p0"] == 1


def test_otel04_no_premature_global_done():
    host, spec = otel_host()
    restart(host)
    for i in range(9):  # p9 deliberately skipped
        drain_shard(host, spec, i)
    progress = rec.shard_progress(host.registry)
    assert progress["global_done"] is False
    assert progress["shards"]["p9"]["write_status"] != "VERIFIED"
    # A premature T3 READ is a harmless evidence-gathering observation
    # only (WO008-02, cf. test_otel04_stale_reads_rejected for Rp0): it is
    # admitted as OBSERVATION_ONLY but must not close T3, unlock the
    # dependent T4, authorize DONE, or produce any consequential effect.
    drains_before = dict(host.world.get_state()["drains"])
    effects_before = len(host.world.effect_ledger)
    v, _ = host.step(VERIFIER, {"action": "read", "task": "T3",
                                "tool": "consumer_group.status", "args": {}},
                     "scripted:t3-early")
    assert v.allowed and v.observation_only and v.code == "OBSERVATION_ONLY", v.code
    premature_obs = host.world_records[-1]["observation_id"]
    assert premature_obs
    # Positive evidence of no premature closure:
    assert not host.registry.is_confirmed("T3")
    assert host.registry.state_of("T3") != "CONFIRMED"
    assert any(s["reason"] == "PREMATURE_BEFORE_DEPS"
               for s in host.registry.obligations["T3"].stale)
    assert premature_obs not in [
        oid for oid, e in host.registry.observations.items() if e.get("_confirmed")]
    # The dependent ANALYZE (T4) stays locked on the premature observation.
    total = sum(spec["initial_state"]["lag"].values())
    v, _ = host.step(VERIFIER, {"action": "analyze", "task": "T4",
                                "answer": {"total_processed": total,
                                           "all_lag_zero": True},
                                "evidence_refs": [premature_obs]},
                     "scripted:t4-early")
    assert not v.allowed and v.code == "DEPENDENCIES_OPEN", v.code
    assert not host.registry.is_confirmed("T4")
    # No DONE and no consequential effect from the premature read.
    assert host.world.get_state()["drains"] == drains_before
    assert len(host.world.effect_ledger) == effects_before
    assert host.registry.write_status("Wp9") != "VERIFIED"
    assert not host.sidecar.check_exit(VERIFIER, "all_tasks_terminal").allowed
    assert not host.sidecar.check_exit("agent:o4-consumer-p9",
                                       "all_tasks_terminal").allowed
    # Completing the final shard earns global DONE; nothing before it did.
    drain_shard(host, spec, 9)
    v, _ = host.step(VERIFIER, {"action": "read", "task": "T3",
                                "tool": "consumer_group.status", "args": {}},
                     "scripted:t3")
    assert v.allowed, v.code
    obs = host.world_records[-1]["observation_id"]
    total = sum(spec["initial_state"]["lag"].values())
    v, _ = host.step(VERIFIER, {"action": "analyze", "task": "T4",
                                "answer": {"total_processed": total,
                                           "all_lag_zero": True},
                                "evidence_refs": [obs]}, "scripted:t4")
    assert v.allowed, v.code
    assert rec.shard_progress(host.registry)["global_done"] is True
    assert host.sidecar.check_exit(VERIFIER, "all_tasks_terminal").allowed
    bundle = rec.evidence_bundle(host.registry, host,
                                 extra={"shard_progress": progress})
    assert bundle["obligations"]["T4"]["confirmed"] is True
    out = HERE.parents[2] / "_wo008_input"
    if out.is_dir():
        (out / "WO008_04_SHARDS_EVIDENCE.json").write_text(
            json.dumps(bundle, indent=1, sort_keys=True), encoding="utf-8")
