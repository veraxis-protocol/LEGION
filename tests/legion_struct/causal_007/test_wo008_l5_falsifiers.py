"""WO008-06-L5-FIX-001: independent falsifiers F001-F007, repaired in runtime.

Every test exercises the real installed modules (audit evaluator, sidecar
server feed, sidecar, registry, delegation, CausalHost, native
world_server + struct_readback). No security gate is mocked: admissions
and denials come from the modules under test, and consequential positives
assert a real native effect bound to receipt + readback.
"""
import copy
import json
import sys
import time
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]
HERE = Path(__file__).resolve().parent
LEGION = HERE.parent
WORLDS = LEGION / "worlds"
sys.path.insert(0, str(LEGION))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2]))

import wo008_attempt_audit as audit  # noqa: E402
import sidecar_server  # noqa: E402
from causal_007.causal_host import CausalHost, evaluate_independent_readback  # noqa: E402
from causal_007.causal_registry import CausalRegistry  # noqa: E402
from causal_007.sidecar import CausalSidecar  # noqa: E402
from causal_007.delegation import (  # noqa: E402
    authenticate_delegate_result, verified_collaboration_count,
    verified_delegation_edges)
from world_engine import World  # noqa: E402
import causal_007.attempt_authority as auth  # noqa: E402
import test_wo008_attempt_i3 as i3t  # noqa: E402
import test_wo008_argument_binding as bind  # noqa: E402
import test_wo008_commit_boundary as commit  # noqa: E402
import test_wo008_s100_delegation as s100  # noqa: E402
import test_wo008_l5_integration as l5  # noqa: E402

ATT, WIN, EPOCH = bind.ATT, bind.WIN, bind.EPOCH


def load(family):
    for p in sorted(WORLDS.glob("*.world.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        if d.get("family") == family:
            d = copy.deepcopy(d)
            d.update(attempt_uid=ATT, world_instance_id=WIN, epoch=EPOCH)
            return d
    raise AssertionError(family)


# ------------------------------------------------------------------- F001
def test_f001_positive(tmp_path):
    """Authentic signed trace, mutation only before terminal: I3=T."""
    run = i3t._write_run(tmp_path, i3t._attempt_records({"t_mono": 1100.0}),
                         i3t._world([i3t._mutation(2, 1050.0)]))
    result = audit.evaluate_attempt_i3(run, attempt_key=i3t.TEST_KEY)
    assert result["I3"] == "T", result
    assert result["bridge"] == "authenticated_t_mono"
    assert result["mac_status"] == "verified"
    assert result["world_log_problems"] == []
    # A genuinely late mutation under the same authenticated bridge is F.
    run_f = i3t._write_run(tmp_path / "f", i3t._attempt_records({"t_mono": 1100.0}),
                           i3t._world([i3t._mutation(2, 1200.0)]))
    assert audit.evaluate_attempt_i3(run_f, attempt_key=i3t.TEST_KEY)["I3"] == "F"


def test_f001_negative(tmp_path):
    """Corrupted WORLD_LOG cannot prove I3=T: it is Z (never T/F)."""
    base_attempt = i3t._attempt_records({"t_mono": 1100.0})
    corruptions = {}
    # malformed JSON line appended to an otherwise authentic log
    run = i3t._write_run(tmp_path / "mal", base_attempt,
                         i3t._world([i3t._mutation(2, 1050.0)]))
    with open(run / "WORLD_LOG.jsonl", "a", encoding="utf-8") as fh:
        fh.write("NOT-JSON{\n")
    corruptions["malformed"] = run
    # noncontiguous sequence (seq 2 missing)
    corruptions["gap"] = i3t._write_run(
        tmp_path / "gap", base_attempt, i3t._world([i3t._mutation(3, 1050.0)]))
    # reversed chronology (t_mono goes backwards in seq order)
    corruptions["reversed"] = i3t._write_run(
        tmp_path / "rev", base_attempt,
        i3t._world([i3t._mutation(2, 1050.0), i3t._mutation(3, 900.0)]))
    # ambiguous record identity (mutation carries no attempt/world identity)
    amb = i3t._mutation(2, 1050.0)
    del amb["attempt_uid"], amb["world_instance_id"]
    corruptions["identity"] = i3t._write_run(
        tmp_path / "amb", base_attempt, i3t._world([amb]))
    # boolean seq is not an exact integer seq
    boolseq = i3t._mutation(2, 1050.0)
    boolseq["seq"] = True
    corruptions["boolseq"] = i3t._write_run(
        tmp_path / "bool", base_attempt, i3t._world([boolseq]))
    for name, corrupt_run in corruptions.items():
        result = audit.evaluate_attempt_i3(corrupt_run, attempt_key=i3t.TEST_KEY)
        assert result["I3"] == "Z", (name, result)
        assert result["I3"] != "T"
        assert result["world_log_problems"], (name, result)


# ------------------------------------------------------------------- F002
def _feed_spec():
    return {
        "world_id": "SYNTH-W008-FEED", "family": "SYNTH-W008-FEED", "epoch": 1,
        "attempt_uid": "att-1", "world_instance_id": "win-1",
        "tools": {"t.get": {"kind": "read", "params": {}, "returns": {}},
                  "t.exec": {"kind": "write", "params": {}, "returns": {}}},
        "roles": [{"agent_id": "agent:op", "tasks": [
            {"task_id": "R", "kinds": ["READ"], "read_tools": ["t.get"],
             "depends_on": [], "recipients": []},
            {"task_id": "W", "kinds": ["WRITE"], "read_tools": ["t.get"],
             "write_tool": "t.exec", "target": "target",
             "depends_on": ["R"], "recipients": []}]}]}


def _feed_rec(seq=1, **over):
    rec = {"kind": "OBSERVATION", "agent_id": "agent:op", "task_id": "R",
           "observation_id": f"obs-{seq}", "seq": seq, "epoch": 1,
           "attempt_uid": "att-1", "world_instance_id": "win-1",
           "facts": {"v": seq}}
    rec.update(over)
    return rec


_FEED_WRITE = {"action": "write", "task": "W", "tool": "t.exec",
               "target": "target", "args": {}}


def _feed_state(tmp_path, records):
    st = sidecar_server.CausalState(_feed_spec(), "http://world.invalid", "tok",
                                    str(tmp_path / "CAUSAL_CONTROLLER.jsonl"))
    st._fetch_world_records = lambda: records
    return st


def test_f002_positive(tmp_path):
    st = _feed_state(tmp_path, [_feed_rec(1), _feed_rec(2)])
    assert st.refresh() is True and st.feed_unavailable is False
    assert st.registry.is_confirmed("R")
    view = st.sidecar.next_required("agent:op")
    assert view["next_required"] and view.get("code") != "EVIDENCE_FEED_UNAVAILABLE"
    v = st.sidecar.check("agent:op", dict(_FEED_WRITE), "d-ok")
    assert v.allowed, v.to_dict()


def test_f002_negative(tmp_path):
    variants = {
        "missing_seq": [{k: v for k, v in _feed_rec(1).items() if k != "seq"}],
        "bool_seq": [_feed_rec(True)],
        "string_seq": [_feed_rec("1")],
        "noncontiguous": [_feed_rec(1), _feed_rec(3)],
        "out_of_order": [_feed_rec(2), _feed_rec(1)],
        "missing_attempt": [{k: v for k, v in _feed_rec(1).items()
                             if k != "attempt_uid"}],
        "wrong_attempt": [_feed_rec(1, attempt_uid="att-foreign")],
        "missing_world": [{k: v for k, v in _feed_rec(1).items()
                           if k != "world_instance_id"}],
        "wrong_world": [_feed_rec(1, world_instance_id="win-foreign")],
        "missing_epoch": [{k: v for k, v in _feed_rec(1).items() if k != "epoch"}],
        "stale_epoch": [_feed_rec(1, epoch=99)],
        "non_dict_record": [["not-a-record"]],
    }
    for name, records in variants.items():
        st = _feed_state(tmp_path / name, records)
        assert st.refresh() is False, name
        assert st.feed_unavailable is True, name
        v = st.sidecar.check("agent:op", dict(_FEED_WRITE), f"d-{name}")
        assert not v.allowed and v.code == "EVIDENCE_FEED_UNAVAILABLE", (name, v.to_dict())
        v = st.sidecar.check_exit("agent:op", "all_tasks_terminal")
        assert not v.allowed and v.code == "EVIDENCE_FEED_UNAVAILABLE", name
        view = st.sidecar.next_required("agent:op")
        assert view["next_required"] is None, (name, view)
        assert view["code"] == "EVIDENCE_FEED_UNAVAILABLE", (name, view)
    # No stale cached acceptance: a feed that was accepted, then fails,
    # immediately denies again (check, exit, DONE and the view).
    st = _feed_state(tmp_path / "stale", [_feed_rec(1)])
    assert st.refresh() is True
    assert st.sidecar.check("agent:op", dict(_FEED_WRITE), "d-good").allowed
    st._fetch_world_records = lambda: (_ for _ in ()).throw(OSError("down"))
    assert st.refresh() is False and st.feed_unavailable is True
    v = st.sidecar.check("agent:op", dict(_FEED_WRITE), "d-after-failure")
    assert not v.allowed and v.code == "EVIDENCE_FEED_UNAVAILABLE", v.to_dict()
    assert not st.sidecar.check_exit("agent:op", "all_tasks_terminal").allowed
    v = st.sidecar.check("agent:op", {"action": "done", "task": "W"}, "d-done")
    assert not v.allowed and v.code == "EVIDENCE_FEED_UNAVAILABLE", v.to_dict()
    # Malformed gate feed file is unknown evidence too.
    gate = tmp_path / "gate.jsonl"
    gate.write_text('{"outcome": "x"}\nNOT-JSON\n', encoding="utf-8")
    st2 = sidecar_server.CausalState(_feed_spec(), "", "",
                                     str(tmp_path / "out2.jsonl"), gate_path=str(gate))
    assert st2.refresh() is False and st2.feed_unavailable is True


# ------------------------------------------------------------------- F003
def test_f003_positive():
    host, _spec = s100.s100_host()
    ref = s100.restart_and_delegate(host)
    ok, code, entry = authenticate_delegate_result(host.registry, ref)
    assert ok and entry["agent_id"] == s100.DELEGATE, code
    v, _ = host.step(s100.CONSUMER, {"action": "read", "task": "Rp0",
                                     "tool": "partition.offsets",
                                     "args": {"partition": "p0"}}, "scripted:rp0-f3")
    assert v.allowed, v.to_dict()
    before = len(host.world.effect_ledger)
    v, _ = host.step(s100.CONSUMER,
                     {"action": "write", "task": "Wp0", "tool": "partition.drain",
                      "target": "p0", "args": {"partition": "p0", "from_offset": 100},
                      "delegate_result_ref": ref}, "scripted:wp0-f3")
    assert v.allowed, v.to_dict()
    assert len(host.world.effect_ledger) == before + 1
    assert host.registry.write_status("Wp0") == "VERIFIED"


def test_f003_negative():
    host, _spec = s100.s100_host()
    ref = s100.restart_and_delegate(host)
    v, _ = host.step(s100.CONSUMER, {"action": "read", "task": "Rp0",
                                     "tool": "partition.offsets",
                                     "args": {"partition": "p0"}}, "scripted:rp0-f3n")
    assert v.allowed, v.to_dict()
    n0 = len(host.world.effect_ledger)

    def denied(action, code, refname):
        v, _ = host.step(s100.CONSUMER, action, f"scripted:{refname}")
        assert not v.allowed and v.code == code, (refname, v.to_dict())
        assert len(host.world.effect_ledger) == n0

    base = {"action": "write", "task": "Wp0", "tool": "partition.drain",
            "target": "p0", "args": {"partition": "p0", "from_offset": 100}}
    denied({**base, "delegate_result_ref": "obs-9999"},
           "DELEGATE_REF_UNVERIFIED", "fabricated")
    # Tampered evidence entries: every absent/mismatched identity is denied.
    entry = host.registry.observations[ref]
    saved = dict(entry)
    for field, bad, code in (
            ("decision_ref", None, "DELEGATE_REF_NO_PROVENANCE"),
            ("attempt_uid", None, "DELEGATE_REF_ATTEMPT_MISMATCH"),
            ("attempt_uid", "att-foreign", "DELEGATE_REF_ATTEMPT_MISMATCH"),
            ("world_instance_id", None, "DELEGATE_REF_WORLD_MISMATCH"),
            ("world_instance_id", "win-foreign", "DELEGATE_REF_WORLD_MISMATCH"),
            ("epoch", 99, "DELEGATE_REF_STALE_EPOCH")):
        entry[field] = bad
        denied({**base, "delegate_result_ref": ref}, code, f"tamper-{field}-{bad}")
        ok, acode, _e = authenticate_delegate_result(host.registry, ref)
        assert not ok and acode == code, (field, acode)
        entry[field] = saved[field]
    ok, _c, _e = authenticate_delegate_result(host.registry, ref)
    assert ok  # evidence restored; the denials above were identity-based
    assert verified_delegation_edges(host.registry, host.log) == []


# ------------------------------------------------------------------- F005
def test_f005_positive():
    host, _spec = s100.s100_host()
    ref = s100.restart_and_delegate(host)
    # Registered + active delegate alone is zero verified collaboration.
    assert verified_delegation_edges(host.registry, host.log) == []
    assert verified_collaboration_count(host.registry, host.log) == 0
    v, _ = host.step(s100.CONSUMER, {"action": "read", "task": "Rp0",
                                     "tool": "partition.offsets",
                                     "args": {"partition": "p0"}}, "scripted:rp0-f5")
    assert v.allowed, v.to_dict()
    v, _ = host.step(s100.CONSUMER,
                     {"action": "write", "task": "Wp0", "tool": "partition.drain",
                      "target": "p0", "args": {"partition": "p0", "from_offset": 100},
                      "delegate_result_ref": ref}, "scripted:wp0-f5")
    assert v.allowed, v.to_dict()
    edges = verified_delegation_edges(host.registry, host.log)
    assert len(edges) == 1, edges
    edge = edges[0]
    assert edge["delegate_agent"] == s100.DELEGATE
    assert edge["downstream_agent"] == s100.CONSUMER != s100.DELEGATE
    assert edge["decision_ref"] == "scripted:wp0-f5"
    assert edge["effect_id"] and edge["receipt_id"] and edge["readback_confirmed"]
    assert edge["attempt_uid"] == s100.ATT and edge["world_instance_id"] == s100.WIN
    assert verified_collaboration_count(host.registry, host.log) == 1


def test_f005_negative():
    host, _spec = s100.s100_host()
    ref = s100.restart_and_delegate(host)
    real_log = list(host.log)
    action = {"action": "write", "task": "Wp0", "tool": "partition.drain",
              "target": "p0", "args": {"partition": "p0", "from_offset": 100},
              "delegate_result_ref": ref}
    # Forged CAUSAL_ADMIT edges: no downstream consumption ever happened,
    # so there is no VERIFIED effect/receipt/readback to bind to.
    forgeries = [
        {"event": "CAUSAL_ADMIT", "agent_id": "agent:evil", "action": action,
         "decision_ref": "scripted:forged"},
        {"event": "CAUSAL_ADMIT", "agent_id": s100.CONSUMER, "action": action,
         "decision_ref": "scripted:forged"},
        {"event": "CAUSAL_ADMIT", "agent_id": s100.CONSUMER, "action": action,
         "decision_ref": None},
        {"event": "CAUSAL_ADMIT", "agent_id": s100.DELEGATE, "action": action,
         "decision_ref": "scripted:self"},
        {"event": "CAUSAL_ADMIT", "agent_id": s100.CONSUMER,
         "action": {**action, "delegate_result_ref": "obs-9999"},
         "decision_ref": "scripted:fake-ref"},
    ]
    for forged in forgeries:
        assert verified_delegation_edges(host.registry, real_log + [forged]) == [], forged
    # Even after a real downstream WRITE, admissions that do not bind to
    # its actual decision_ref / actor produce no additional edge.
    v, _ = host.step(s100.CONSUMER, {"action": "read", "task": "Rp0",
                                     "tool": "partition.offsets",
                                     "args": {"partition": "p0"}}, "scripted:rp0-f5n")
    assert v.allowed, v.to_dict()
    v, _ = host.step(s100.CONSUMER,
                     {"action": "write", "task": "Wp0", "tool": "partition.drain",
                      "target": "p0", "args": {"partition": "p0", "from_offset": 100},
                      "delegate_result_ref": ref}, "scripted:wp0-real")
    assert v.allowed and len(verified_delegation_edges(host.registry, host.log)) == 1
    for forged in forgeries:
        edges = verified_delegation_edges(host.registry, list(host.log) + [forged])
        assert len(edges) == 1 and edges[0]["decision_ref"] == "scripted:wp0-real", forged


# ------------------------------------------------------------------- F004
def test_f004_positive(tmp_path):
    """Native world_server effect + separate struct_readback process."""
    authority = auth.TestAuthority()
    w = None
    rb_proc = None
    try:
        w = l5._WorldServer(tmp_path, authority)
        before = w.snapshot()
        permit = authority.gate_client().request_permit(task_id="T8",
                                                        command_id="cmd-f004")
        status, payload = w.actuate(permit, command_id="cmd-f004")
        assert status == 200 and payload.get("status") == "applied", payload
        mid = w.snapshot()
        assert mid["native"] == before["native"] + 1 and mid["digest"] != before["digest"]
        effect_id = payload.get("effect_id") or mid["effects"][-1]["effect_id"]
        # Independent readback: a separate OS process reading the world.
        rb_out = tmp_path / "rbout"
        rb_out.mkdir()
        env = {k: v for k, v in
               ((k, __import__("os").environ.get(k)) for k in ("PATH", "SYSTEMROOT")) if v}
        env.update({"STRUCT_ATTEMPT_UID": authority.attempt_uid,
                    "STRUCT_WORLD_INSTANCE_ID": authority.world_instance_id})
        import subprocess as _sp
        rb_proc = _sp.Popen(
            [sys.executable, "-I", str(LEGION / "struct_readback.py"),
             w.base, "read-token", str(rb_out)],
            stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, env=env)
        readback = None
        deadline = time.monotonic() + 30
        rb_file = rb_out / "READBACK.jsonl"
        while time.monotonic() < deadline:
            if rb_file.exists():
                for line in rb_file.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        rec = json.loads(line)
                        if rec.get("effect_id") == effect_id:
                            readback = rec
                if readback:
                    break
            time.sleep(0.1)
        assert readback is not None and readback["confirmed"] is True, readback
        assert readback["provenance"] == "struct_readback"
        assert readback["independent"] is True
        # Feed the native triplet into a registry for the actuated task.
        spec = {"world_id": "SYNTH-F004", "family": "SYNTH-F004",
                "attempt_uid": authority.attempt_uid,
                "world_instance_id": authority.world_instance_id,
                "epoch": authority.epoch,
                "tools": {"support.set_priority": {"kind": "write", "params": {},
                                                   "returns": {}}},
                "roles": [{"agent_id": "agent:sea-analyst", "tasks": [
                    {"task_id": "T8", "kinds": ["WRITE"], "read_tools": [],
                     "write_tool": "support.set_priority",
                     "target": "support-records", "depends_on": [],
                     "recipients": []}]}]}
        reg = CausalRegistry(spec)
        log_records = [json.loads(l) for l in
                       (w.out / "WORLD_LOG.jsonl").read_text(encoding="utf-8").splitlines()
                       if l.strip()]
        triplet = [r for r in log_records
                   if r.get("kind") in ("NATIVE_EFFECT", "RECEIPT")
                   and r.get("effect_id") == effect_id]
        assert len(triplet) == 2, triplet
        _s, state_payload = l5._req("GET", f"{w.base}/state", bearer="read-token")
        state = state_payload.get("state", state_payload) \
            if isinstance(state_payload, dict) else state_payload
        from causal_007.action_binding import state_sha256
        observed_sha = state_sha256(state)
        assert readback["state_sha256"] == observed_sha, (readback, observed_sha)
        reg.ingest(triplet + [readback])
        assert reg.write_status("T8") == "VERIFIED", reg.obligations["T8"].stale
        assert reg.independent_write_status(
            "T8", independent_state_sha256=observed_sha,
            independent_effect_ids=[effect_id]) == "VERIFIED"
        status2, reason = evaluate_independent_readback(
            triplet[0], triplet[1], readback,
            independent_state_sha256=observed_sha,
            independent_effect_ids=[effect_id],
            post_effect_state_sha256=observed_sha)
        assert status2 == "VERIFIED", reason
    finally:
        if rb_proc is not None and rb_proc.poll() is None:
            rb_proc.terminate()
        if w is not None:
            w.stop()
        authority.stop()


def test_f004_negative():
    # Synthetic CausalHost triplet: registry-VERIFIED in isolation, but
    # never independent (the host manufactured receipt+readback itself).
    host = CausalHost(l5.load("SYN-GAIA-TIM"))
    v, _ = host.step("agent:tim-scheduler",
                     {"action": "wait", "task": "T1", "event_id": "ev-tim-open"},
                     "scripted:f4-wait")
    assert v.allowed, v.to_dict()
    v, _ = host.step("agent:tim-submitter",
                     {"action": "write", "task": "T2", "tool": "batch.submit",
                      "target": "batch", "args": {"batch_id": "B-1107"}},
                     "scripted:f4-write")
    assert v.allowed and host.registry.write_status("T2") == "VERIFIED", v.to_dict()
    assert host.readback_independence == "SYNTHETIC_NOT_INDEPENDENT"
    assert host.independent_write_status("T2") == "UNVERIFIED"
    assert host.registry.independent_write_status("T2") == "UNVERIFIED"
    eff = next(r for r in host.world_records if r.get("kind") == "NATIVE_EFFECT")
    rcpt = next(r for r in host.world_records if r.get("kind") == "RECEIPT")
    rb = next(r for r in host.world_records if r.get("kind") == "READBACK_EFFECT")
    assert rb["provenance"] == "synthetic_host" and rb["independent"] is False
    status, _r = evaluate_independent_readback(eff, rcpt, rb)
    assert status == "UNVERIFIED"
    # Negative 1: success reply with no actual state change / no ledger
    # effect behind it stays UNVERIFIED.
    from causal_007.action_binding import state_sha256
    same_sha = state_sha256({"unchanged": True})
    status, reason = evaluate_independent_readback(
        {"effect_id": "eff-claimed", "command_id": "cmd-claimed"},
        {"effect_id": "eff-claimed", "command_id": "cmd-claimed",
         "receipt_id": "rcpt-claimed"},
        {"effect_id": "eff-claimed", "command_id": "cmd-claimed",
         "confirmed": True, "independent": True,
         "provenance": "struct_readback", "state_sha256": same_sha},
        independent_state_sha256=same_sha, independent_effect_ids=[],
        pre_effect_state_sha256=same_sha, post_effect_state_sha256=same_sha)
    assert status == "UNVERIFIED" and reason in (
        "EFFECT_NOT_IN_INDEPENDENT_LEDGER", "NO_ACTUAL_STATE_CHANGE"), reason
    # Negative 2: forged/altered readback (altered state hash or identity)
    # stays UNVERIFIED, in the evaluator and in the registry.
    for altered in ({**rb, "provenance": "struct_readback", "independent": True,
                     "state_sha256": "0" * 64},
                    {**rb, "provenance": "struct_readback", "independent": True,
                     "effect_id": "eff-forged"}):
        status, _r = evaluate_independent_readback(
            eff, rcpt, altered, independent_state_sha256=rb["state_sha256"],
            independent_effect_ids=[eff["effect_id"]])
        assert status == "UNVERIFIED", altered
    reg = CausalRegistry(l5.load("SYN-GAIA-TIM"))
    reg.ingest(host.world_records)
    # Re-feed a fresh registry with an altered readback identity: no closure
    # beyond the (synthetic) triplet the registry itself can see is claimed
    # independent, and a mismatched readback never verifies the write.
    reg2_spec = l5._closure_spec()
    reg2 = CausalRegistry(reg2_spec)
    reg2.ingest([l5._obs("R", "obs-f4")])
    base = {"agent_id": "agent:op", "task_id": "W", "effect_id": "eff-f4",
            "command_id": "cmd-f4", "epoch": EPOCH, "permit_epoch": EPOCH,
            "attempt_uid": ATT, "world_instance_id": WIN,
            "tool": "t.exec", "target": "target", "args": {}}
    reg2.ingest([{"kind": "NATIVE_EFFECT", **base},
                 {"kind": "RECEIPT", "receipt_id": "rcpt-f4",
                  "permit_verified": True, **base},
                 {"kind": "READBACK_EFFECT", "confirmed": True,
                  "independent": True, "provenance": "struct_readback",
                  "state_sha256": "f" * 64,
                  **{**base, "effect_id": "eff-forged"}}])
    assert reg2.write_status("W") != "VERIFIED"
    assert reg2.independent_write_status("W") == "UNVERIFIED"


# ------------------------------------------------------------------- F006
def _ada_registry_fresh(fresh=True):
    """ADA registry from public evidence only (no T5 message yet)."""
    reg = CausalRegistry(load("SYN-GAIA-ADA"))
    healthy = {"regions": {"east": {"health": "healthy", "latency_ms": 20},
                           "west": {"health": "healthy", "latency_ms": 45}}}
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:ada-monitor",
                 "task_id": "T1", "observation_id": "obs-t1", "epoch": EPOCH,
                 "attempt_uid": ATT, "world_instance_id": WIN, "facts": healthy}])
    bind.triplet(reg, "T2", "agent:ada-operator", "router.set_region",
                 "router", {"region": "east"}, "t2")
    reg.ingest([{"kind": "WAIT_OBSERVED", "agent_id": "agent:ada-monitor",
                 "task_id": "T3", "event_id": "ev-ada-degrade"}])
    if fresh:
        reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:ada-monitor",
                     "task_id": "T1", "observation_id": "obs-t1-fresh",
                     "epoch": EPOCH, "attempt_uid": ATT, "world_instance_id": WIN,
                     "facts": {"regions": {
                         "east": {"health": "degraded", "latency_ms": 950},
                         "west": {"health": "healthy", "latency_ms": 45}}}}])
    return reg


def test_f006_positive():
    reg = _ada_registry_fresh(fresh=True)
    sc = CausalSidecar(reg, log=lambda r: None)
    # Grounded alert from verified fresh evidence satisfies T5.
    v = sc.check("agent:ada-monitor",
                 {"action": "send", "task": "T5", "to": "agent:ada-operator",
                  "body": "east degraded, west healthy",
                  "evidence_refs": ["obs-t1-fresh"]}, "d-ada-msg")
    assert v.allowed, v.to_dict()
    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": "agent:ada-monitor",
                 "task_id": "T5", "recipient": "agent:ada-operator",
                 "message_id": "m-t5-fresh", "body": "east degraded, west healthy",
                 "evidence_refs": ["obs-t1-fresh"]}])
    assert reg.is_confirmed("T5")
    # Failover to the healthy region earns exactly one verified consequence.
    world = World(load("SYN-GAIA-ADA"))
    assert world.call_write("cmd-route", "router.set_region", "router",
                            {"region": "east"})[0] == 200
    world.fire("ev-ada-degrade")
    outcome, trace = commit.attempt_commit(
        reg, sc, world, "agent:ada-operator",
        {"action": "write", "task": "T4", "tool": "router.failover",
         "target": "router-failover", "args": {"region": "west"},
         "attempt_uid": ATT, "world_instance_id": WIN, "epoch": EPOCH}, "cmd-f006")
    assert outcome == "COMMITTED" and trace["native_effect_delta"] == 1, trace
    assert reg.write_status("T4") == "VERIFIED"
    assert world.get_state()["router"]["active_region"] == "west"
    # Exactly once: a second failover is refused, no second effect.
    n = len(world.effect_ledger)
    v = sc.check("agent:ada-operator",
                 {"action": "write", "task": "T4", "tool": "router.failover",
                  "target": "router-failover", "args": {"region": "west"}},
                 "d-ada-again")
    assert not v.allowed and v.code == "ALREADY_CONFIRMED", v.to_dict()
    assert len(world.effect_ledger) == n


def test_f006_negative():
    # After EAST degradation, the stale claim "east healthy" is denied,
    # whether the only evidence is pre-degradation or fresh evidence says
    # the opposite; an unverified degraded claim is denied as stale too.
    for fresh, body in ((True, "east healthy"), (False, "east healthy"),
                        (False, "east degraded, west healthy")):
        reg = _ada_registry_fresh(fresh=fresh)
        sc = CausalSidecar(reg, log=lambda r: None)
        v = sc.check("agent:ada-monitor",
                     {"action": "send", "task": "T5", "to": "agent:ada-operator",
                      "body": body}, f"d-stale-{fresh}-{body[:4]}")
        assert not v.allowed and v.code == "MESSAGE_CONTENT_UNVERIFIED", \
            (fresh, body, v.to_dict())
        assert not reg.is_confirmed("T5")
    # failover(east) to the degraded region is denied with zero effects.
    reg = _ada_registry_fresh(fresh=True)
    sc = CausalSidecar(reg, log=lambda r: None)
    reg.ingest([{"kind": "MESSAGE_DELIVERED", "agent_id": "agent:ada-monitor",
                 "task_id": "T5", "recipient": "agent:ada-operator",
                 "message_id": "m-t5-neg", "body": "east degraded, west healthy",
                 "evidence_refs": ["obs-t1-fresh"]}])
    world = World(load("SYN-GAIA-ADA"))
    assert world.call_write("cmd-route", "router.set_region", "router",
                            {"region": "east"})[0] == 200
    world.fire("ev-ada-degrade")
    n = len(world.effect_ledger)
    outcome, trace = commit.attempt_commit(
        reg, sc, world, "agent:ada-operator",
        {"action": "write", "task": "T4", "tool": "router.failover",
         "target": "router-failover", "args": {"region": "east"}}, "cmd-f006-neg")
    assert outcome == "DENIED" and trace["sidecar_code"] == "ADA_WRONG_DESTINATION", trace
    assert len(world.effect_ledger) == n
    assert world.get_state()["router"]["active_region"] == "east"


# ------------------------------------------------------------------- F007
def _otel_t5_registry():
    reg = CausalRegistry(load("SYN-OTEL-03"))
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:o3-diag", "task_id": "T1",
                 "observation_id": "obs-t1", "epoch": EPOCH, "attempt_uid": ATT,
                 "world_instance_id": WIN,
                 "facts": {"config": {"redis_addr": "redis-cart:6380"},
                           "readiness": "failing"}}])
    reg.ingest([{"kind": "ANALYSIS_RECORD", "agent_id": "agent:o3-diag", "task_id": "T2",
                 "facts": {"cause": "redis_unreachable_wrong_port",
                           "correct_redis_addr": "redis-cart:6379"},
                 "evidence_refs": ["obs-t1"]}])
    bind.triplet(reg, "T3", "agent:o3-operator", "cart.set_config",
                 "cart-config", {"key": "redis_addr", "value": "redis-cart:6379"}, "t3")
    bind.triplet(reg, "T4", "agent:o3-operator", "cart.restart", "cart",
                 {"service": "cart"}, "t4")
    assert reg.is_confirmed("T4")
    return reg


def test_f007_positive():
    # Full host flow: fix + restart, then a verified ready cart and a
    # successful synthetic flow close the verifier obligation.
    host = CausalHost(load("SYN-OTEL-03"))
    v, _ = host.step("agent:o3-diag",
                     {"action": "read", "task": "T1", "tool": "probe.readiness",
                      "args": {}}, "scripted:f7-t1")
    assert v.allowed and host.registry.is_confirmed("T1"), v.to_dict()
    obs = host.world_records[-1]["observation_id"]
    v, _ = host.step("agent:o3-diag",
                     {"action": "analyze", "task": "T2",
                      "answer": {"cause": "redis_unreachable_wrong_port",
                                 "correct_redis_addr": "redis-cart:6379"},
                      "evidence_refs": [obs]}, "scripted:f7-t2")
    assert v.allowed and host.registry.is_confirmed("T2"), v.to_dict()
    v, _ = host.step("agent:o3-operator",
                     {"action": "write", "task": "T3", "tool": "cart.set_config",
                      "target": "cart-config",
                      "args": {"key": "redis_addr", "value": "redis-cart:6379"}},
                     "scripted:f7-t3")
    assert v.allowed and host.registry.write_status("T3") == "VERIFIED", v.to_dict()
    v, _ = host.step("agent:o3-operator",
                     {"action": "write", "task": "T4", "tool": "cart.restart",
                      "target": "cart", "args": {"service": "cart"}}, "scripted:f7-t4")
    assert v.allowed and host.registry.write_status("T4") == "VERIFIED", v.to_dict()
    assert host.world.get_state()["cart"]["readiness"] == "ready"
    assert host.world.get_state()["cart"]["flow_result"] == "ok"
    v, _ = host.step("agent:o3-verifier",
                     {"action": "read", "task": "T5", "tool": "probe.cart_flow",
                      "args": {}}, "scripted:f7-t5")
    assert v.allowed, v.to_dict()
    assert host.registry.is_confirmed("T5")
    assert host.registry.success_status("T5") == "T"
    assert host.sidecar.check_exit("agent:o3-verifier", "all_tasks_terminal").allowed


def test_f007_negative():
    reg = _otel_t5_registry()
    # A nonempty failing readiness probe is not operational success.
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:o3-verifier",
                 "task_id": "T5", "observation_id": "obs-failing", "epoch": EPOCH,
                 "attempt_uid": ATT, "world_instance_id": WIN,
                 "tool": "probe.readiness",
                 "facts": {"readiness": "failing",
                           "last_error": "dial tcp redis-cart:6380: connect: connection refused"}}])
    assert not reg.is_confirmed("T5")
    assert reg.success_status("T5") == "Z"
    assert reg.state_of("T5") == "Z"
    assert any(s["reason"].startswith("EVIDENCE_SUCCESS_PREDICATE_FAILED")
               for s in reg.obligations["T5"].stale)
    # An observed failed cart flow is not a verified successful flow.
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:o3-verifier",
                 "task_id": "T5", "observation_id": "obs-flow-error", "epoch": EPOCH,
                 "attempt_uid": ATT, "world_instance_id": WIN,
                 "tool": "probe.cart_flow",
                 "facts": {"result": "error: cart unavailable"}}])
    assert not reg.is_confirmed("T5") and reg.success_status("T5") == "Z"
    ok, open_ = reg.can_exit("agent:o3-verifier")
    assert not ok and "T5" in open_
    sc = CausalSidecar(reg, log=lambda r: None)
    v = sc.check_exit("agent:o3-verifier", "all_tasks_terminal")
    assert not v.allowed, v.to_dict()
    # Only the grounded successful postcondition closes it in this registry.
    reg.ingest([{"kind": "OBSERVATION", "agent_id": "agent:o3-verifier",
                 "task_id": "T5", "observation_id": "obs-ok", "epoch": EPOCH,
                 "attempt_uid": ATT, "world_instance_id": WIN,
                 "tool": "probe.cart_flow", "facts": {"result": "ok"}}])
    assert reg.is_confirmed("T5") and reg.success_status("T5") == "T"
