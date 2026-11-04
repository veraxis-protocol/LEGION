"""E6c Test F: supervisor bypass, full path (owner addendum F).

Real supervisor / gate / world, stub model, no network. A mission is
run through ``supervisor.py`` until a governed write has committed.
Then, bypassing the supervisor (and the causal sidecar) entirely, the
gate's MCP ``world_write`` and the world's ``/actuate`` are called
directly with:

  (a) the old attempt_uid, after the attempt is terminal (COMPLETED);
  (b) a forged / foreign attempt_uid, while the attempt is RUNNING;
  (c) a replayed decision_ref / seal / command (gate + world /actuate);
  (d) a reused world-creation capability, which must fail to start
      a world.

For every attempt the WHOLE path is verified, not just a BLOCKED
string: no seal and no command_id (or an explicit attempt-identity
refusal record carrying the rejected identity), no EXECUTED gate
commit and no actuation receipt, reader-token /state digest and
/effects identical before/after, no new NATIVE_EFFECT / RECEIPT /
READBACK_EFFECT, and all logs append-only.

The rejection must come from CAGE/VEIP and the world themselves
(gate attempt check + HARD tier server-bound attempt inputs + world
/actuate), not from the supervisor: the supervisor process is only
ever SIGSTOPped (never asked to refuse a write) so the gate/world
stay alive while the attempt is driven to its terminal state through
the attempt registry -- the supervisor's own transition authority.
"""
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local,
              pytest.mark.skipif(os.name != "posix",
                                 reason="supervisor process groups require posix")]
HERE = Path(__file__).resolve().parent
LEGION = HERE.parent
WORLDS = LEGION / "worlds"

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(LEGION))
import attempt as attempt_mod  # noqa: E402
from causal_007.test_runtime_integration import exe_plan  # noqa: E402
from causal_007.test_supervisor_e6b import (  # noqa: E402
    _assert_no_orphans, _load_jsonl, _sup_argv, _sup_env, _wait_for,
    _world_starts)


def _http(method, url, body=None, headers=None, timeout=30):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read().decode()
            return exc.code, (json.loads(raw) if raw else {})
        except Exception:
            return exc.code, {}
    except Exception as exc:
        return 0, {"error": type(exc).__name__}


def _digest(obj) -> str:
    return hashlib.sha256(json.dumps(
        obj, sort_keys=True, separators=(",", ":"), default=str
    ).encode()).hexdigest()


class Probe:
    """Reader-token snapshots of one run dir for full-path checks."""

    def __init__(self, run_dir):
        self.run_dir = Path(run_dir)
        endpoints = json.loads(
            (self.run_dir / "HOST_ENDPOINTS.json").read_text())
        self.world_url = endpoints["world_url"]
        self.gateway_url = endpoints["gateway_url"]
        self.tokens = json.loads(
            (self.run_dir / "world_tokens.json").read_text())
        self.reader = self.tokens["reader"]

    def state_digest(self):
        status, state = _http("GET", f"{self.world_url}/state",
                              headers={"Authorization":
                                       f"Bearer {self.reader}"})
        assert status == 200, (status, state)
        return _digest(state)

    def effects(self):
        status, payload = _http(
            "GET", f"{self.world_url}/effects?after=0&wait_s=0",
            headers={"Authorization": f"Bearer {self.reader}"})
        assert status == 200, (status, payload)
        return payload.get("effects") or []

    def snapshot(self):
        world = _load_jsonl(self.run_dir / "WORLD_LOG.jsonl")
        gates = _load_jsonl(self.run_dir / "GATE_COMMITS.jsonl")
        readback = _load_jsonl(self.run_dir / "READBACK.jsonl")
        chain_path = self.run_dir / "CAGE_EVIDENCE_CHAIN.jsonl"
        chain = chain_path.read_text(
            encoding="utf-8", errors="ignore") if chain_path.exists() else ""
        return {
            "state_digest": self.state_digest(),
            "effects": self.effects(),
            "native_effects": [r for r in world
                               if r.get("kind") == "NATIVE_EFFECT"],
            "env_events": len([r for r in world
                               if r.get("kind") == "ENV_EVENT"]),
            "receipts": [r for r in world if r.get("kind") == "RECEIPT"],
            "world_write_refused": [r for r in world
                                    if r.get("kind") == "WRITE_REFUSED"],
            "readback_effects": [r for r in readback
                                 if r.get("kind") == "READBACK_EFFECT"],
            "gate_executed": [r for r in gates
                              if r.get("outcome") == "EXECUTED"],
            "gate_sealed": [r for r in gates if r.get("seal")],
            "gate_commanded": [r for r in gates if r.get("command_id")],
            "gate_records": gates,
            "actuation_receipts": chain.count("ACTUATION_RECEIPT"),
            "world_bytes": (self.run_dir / "WORLD_LOG.jsonl").read_bytes(),
            "gate_bytes": (self.run_dir / "GATE_COMMITS.jsonl").read_bytes(),
            "readback_bytes": (self.run_dir / "READBACK.jsonl").read_bytes(),
        }

    def assert_unchanged_except_refusals(self, before, *, rejected_uid,
                                         gate_refusals=0, world_refusals=0,
                                         attempt_detail=True):
        after = self.snapshot()
        # World state + effect ledger: identical. The only tolerated
        # state change is a due ENV_EVENT firing on its own schedule
        # (world-internal, not caused by the probe); any probe-caused
        # mutation would appear in effects/native_effects below.
        if after["state_digest"] != before["state_digest"]:
            assert after["env_events"] > before["env_events"], \
                (before["state_digest"], after["state_digest"])
            assert after["effects"] == before["effects"]
        assert after["effects"] == before["effects"]
        # No new effects / receipts / readbacks / actuation receipts.
        assert after["native_effects"] == before["native_effects"]
        assert after["receipts"] == before["receipts"]
        assert after["readback_effects"] == before["readback_effects"]
        assert after["actuation_receipts"] == before["actuation_receipts"]
        # No EXECUTED commit, no new seal, no new command_id.
        assert after["gate_executed"] == before["gate_executed"]
        assert after["gate_sealed"] == before["gate_sealed"]
        assert after["gate_commanded"] == before["gate_commanded"]
        # Logs append-only.
        assert after["world_bytes"].startswith(before["world_bytes"])
        assert after["gate_bytes"].startswith(before["gate_bytes"])
        assert after["readback_bytes"] == before["readback_bytes"]
        # Exactly the expected new refusal records, each carrying the
        # rejected attempt identity.
        new_gates = after["gate_records"][len(before["gate_records"]):]
        assert len(new_gates) == gate_refusals, new_gates
        for rec in new_gates:
            assert rec.get("outcome") == "BLOCKED", rec
            assert not rec.get("seal") and not rec.get("command_id"), rec
            carried = rec.get("rejected_attempt_uid") or \
                (rec.get("caller_args") or {}).get("attempt_uid")
            assert carried == rejected_uid, rec
            if attempt_detail:
                assert "attempt" in (rec.get("detail") or ""), rec
        new_world = after["world_write_refused"][
            len(before["world_write_refused"]):]
        assert len(new_world) == world_refusals, new_world
        for rec in new_world:
            assert rec.get("rejected_attempt_uid") == rejected_uid, rec
        return after

    def gate_write(self, gate_rec, *, attempt_uid, decision_ref=None):
        ca = gate_rec["caller_args"]
        workers = {w["agent_id"]: w for w in
                   _load_jsonl(self.run_dir / "WORKERS.jsonl")}
        status, payload = _http(
            "POST", f"{self.gateway_url}/tools/execute",
            {"tool_name": "world_write",
             "params": {"task_id": ca["task_id"], "tool": ca["tool"],
                        "target": ca["target"],
                        "args_json": json.dumps(ca["args"]),
                        "decision_ref": (gate_rec["decision_ref"]
                                         if decision_ref is None
                                         else decision_ref),
                        "attempt_uid": attempt_uid}},
            headers={"l5d-client-id":
                     workers[gate_rec["agent_id"]]["workload_identity"]},
            timeout=60)
        assert status == 200, (status, payload)
        return str(payload.get("output") or payload)

    def world_actuate(self, gate_rec, *, attempt_uid):
        ca = gate_rec["caller_args"]
        return _http(
            "POST", f"{self.world_url}/actuate",
            {"command_id": gate_rec.get("command_id") or "replay-f",
             "task_id": ca["task_id"], "agent_id": gate_rec["agent_id"],
             "tool": ca["tool"], "target": ca["target"], "args": ca["args"],
             "attempt_uid": attempt_uid,
             "decision_ref": gate_rec.get("decision_ref")},
            headers={"Authorization": f"Bearer {self.tokens['actuator']}"},
            timeout=30)


def _signal_pids(pids, sig):
    for pid in pids:
        try:
            os.kill(int(pid), sig)
        except (ProcessLookupError, PermissionError, OSError, TypeError):
            pass


@pytest.mark.timeout(1200)
def test_f_supervisor_bypass_full_path(tmp_path):
    """F: bypassing the supervisor yields refusal + zero effects."""
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(exe_plan()), encoding="utf-8")
    runs = tmp_path / "runs"
    run_id = "e6c-f"
    run_dir = runs / run_id
    proc = subprocess.Popen(
        _sup_argv(runs, run_id, plan_file, "--stub-delay-s", "2"),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env=_sup_env())
    capability_token = None
    supervisor_stopped = False
    agent_pids: list = []
    try:
        # Capture the single-use world capability while it exists (it
        # is written before the host spawns and consumed by the world),
        # so (d) can attempt a genuine reuse of the same token.
        deadline = time.time() + 300
        while time.time() < deadline:
            cap = run_dir / attempt_mod.CAPABILITY_FILE
            if capability_token is None and cap.exists():
                try:
                    capability_token = json.loads(
                        cap.read_text(encoding="utf-8")).get("token")
                except (OSError, ValueError):
                    pass
            if len(_world_starts(run_dir)) >= 1 and len(
                    _load_jsonl(run_dir / "WORKERS.jsonl")) >= 100:
                break
            if proc.poll() is not None:
                raise AssertionError("supervisor exited before world up")
            time.sleep(0.05)
        assert len(_world_starts(run_dir)) == 1
        _wait_for(lambda: any(
            r.get("effect_id") and r.get("outcome") == "EXECUTED"
            for r in _load_jsonl(run_dir / "GATE_COMMITS.jsonl")), 300,
            "first committed governed effect")
        gate_rec = next(r for r in _load_jsonl(run_dir / "GATE_COMMITS.jsonl")
                        if r.get("effect_id")
                        and r.get("outcome") == "EXECUTED")
        assert gate_rec.get("seal") and gate_rec.get("command_id")
        run_attempt = attempt_mod.read_attempt(run_dir)
        old_uid = run_attempt["attempt_uid"]
        assert attempt_mod.attempt_state(run_dir) == attempt_mod.RUNNING
        probe = Probe(run_dir)

        # Freeze the agents (not the gate/world): world state is then
        # stable, so before/after digests isolate the bypass attempts.
        agent_pids = [r.get("pid") for r in
                      _load_jsonl(run_dir / "WORKERS.jsonl")]
        _signal_pids(agent_pids, signal.SIGSTOP)
        try:
            # Let the independent readback catch up with effects that
            # already committed, so its log is stable during probes.
            _wait_for(lambda: len(
                [r for r in _load_jsonl(run_dir / "READBACK.jsonl")
                 if r.get("kind") == "READBACK_EFFECT"]) >= len(
                [r for r in _load_jsonl(run_dir / "WORLD_LOG.jsonl")
                 if r.get("kind") == "NATIVE_EFFECT"]), 60,
                "readback to catch up with committed effects")
            # SIGSTOP does not cancel requests already in flight to the
            # gate/world (E6e authority round-trips widen that window
            # under parallel load). Wait until the pipeline is observably
            # quiescent -- identical state digest and record counts across
            # two snapshots -- so the before/after digests below isolate
            # only the bypass attempts. No assertion is relaxed: every
            # strict equality check in assert_unchanged_except_refusals
            # still runs on the probe windows.
            def _quiescent():
                s1 = probe.snapshot()
                time.sleep(1.0)
                s2 = probe.snapshot()
                return (s1["state_digest"] == s2["state_digest"]
                        and len(s1["gate_records"]) == len(s2["gate_records"])
                        and len(s1["native_effects"])
                        == len(s2["native_effects"]))

            _wait_for(_quiescent, 60, "pipeline quiescent after agent freeze")
            # ---- (b) forged / foreign attempt_uid, while RUNNING ----
            forged = "forged-attempt-uid-f"
            before = probe.snapshot()
            out = probe.gate_write(gate_rec, attempt_uid=forged)
            assert "BLOCKED" in out and "attempt identity" in out, out
            assert forged in out, out
            probe.assert_unchanged_except_refusals(
                before, rejected_uid=forged, gate_refusals=1)

            # ---- (c) replayed decision_ref / seal / command, RUNNING ----
            # The MCP caller cannot mint a seal; replaying the old
            # decision_ref (and, at the world, the old command_id) must
            # still yield no seal, no command and no second effect.
            before = probe.snapshot()
            out = probe.gate_write(gate_rec, attempt_uid=old_uid)
            assert "BLOCKED" in out, out
            probe.assert_unchanged_except_refusals(
                before, rejected_uid=old_uid, gate_refusals=1,
                attempt_detail=False)
            before = probe.snapshot()
            w_status, w_payload = probe.world_actuate(
                gate_rec, attempt_uid=old_uid)
            # Duplicate command at the world: no new effect/receipt.
            assert w_status in (200, 403), (w_status, w_payload)
            after = probe.snapshot()
            assert after["effects"] == before["effects"]
            assert after["native_effects"] == before["native_effects"]
            assert after["receipts"] == before["receipts"]
            assert after["state_digest"] == before["state_digest"]

            # ---- terminal: attempt driven COMPLETED via the registry;
            # supervisor SIGSTOPped so its monitor cannot tear the
            # gate/world down before the bypass probes run. E6e: the
            # attempt authority is then killed, so the gate/world can
            # obtain no proof of RUNNING -- DENY by default (absence of
            # proof is never permission), exactly as after a terminal
            # transition destroys the permit key. ----
            os.kill(proc.pid, signal.SIGSTOP)
            supervisor_stopped = True
            # E6g: terminal effect via authority death (no file belief);
            # gate/world can prove no RUNNING and DENY by default.
            _auth_pid_file = run_dir / ".authority_pid"
            if _auth_pid_file.exists():
                try:
                    os.kill(int(_auth_pid_file.read_text().strip()),
                            signal.SIGKILL)
                except (OSError, ValueError):
                    pass
                time.sleep(0.5)

            # ---- (a) old attempt_uid after terminal (gate) ----
            before = probe.snapshot()
            out = probe.gate_write(gate_rec, attempt_uid=old_uid)
            assert "BLOCKED" in out and "attempt" in out, out
            probe.assert_unchanged_except_refusals(
                before, rejected_uid=old_uid, gate_refusals=1)

            # ---- (a)+(c) old identity + replayed command at /actuate ----
            before = probe.snapshot()
            w_status, w_payload = probe.world_actuate(
                gate_rec, attempt_uid=old_uid)
            assert w_status == 403, (w_status, w_payload)
            assert "attempt" in str(w_payload), w_payload
            probe.assert_unchanged_except_refusals(
                before, rejected_uid=old_uid, world_refusals=1)

            # ---- (c) replayed decision_ref at the gate, post-terminal ----
            before = probe.snapshot()
            out = probe.gate_write(
                gate_rec, attempt_uid=old_uid,
                decision_ref=gate_rec["decision_ref"])
            assert "BLOCKED" in out and "attempt" in out, out
            probe.assert_unchanged_except_refusals(
                before, rejected_uid=old_uid, gate_refusals=1)

            # ---- (d) reused world-creation capability ----
            before = probe.snapshot()
            tokens_file = run_dir / "world_tokens.json"
            if capability_token:
                (run_dir / attempt_mod.CAPABILITY_FILE).write_text(
                    json.dumps({"token": capability_token}),
                    encoding="utf-8")
            world_env = {**_sup_env(),
                         "STRUCT_ATTEMPT_FILE": str(run_dir / "attempt.json"),
                         "STRUCT_ATTEMPT_UID": old_uid,
                         "STRUCT_WORLD_INSTANCE_ID":
                             run_attempt["world_instance_id"]}
            rw = subprocess.run(
                [sys.executable, "-I", str(LEGION / "world_server.py"), "0",
                 str(WORLDS / "SYN-GAIA-EXE.world.json"), str(run_dir),
                 str(tokens_file)],
                capture_output=True, text=True, timeout=120, env=world_env)
            assert rw.returncode == 3, rw.stdout[-1000:] + rw.stderr[-1000:]
            assert "REFUSED" in (rw.stderr + rw.stdout)
            if capability_token:
                (run_dir / attempt_mod.CAPABILITY_FILE).unlink(
                    missing_ok=True)
            # No world started, nothing at all changed.
            after = probe.snapshot()
            assert after["world_bytes"] == before["world_bytes"]
            assert after["gate_bytes"] == before["gate_bytes"]
            assert after["state_digest"] == before["state_digest"]
            assert len(_world_starts(run_dir)) == 1
        finally:
            _signal_pids(agent_pids, signal.SIGCONT)
    finally:
        if supervisor_stopped and proc.poll() is None:
            try:
                os.kill(proc.pid, signal.SIGCONT)
            except OSError:
                pass
        if proc.poll() is None:
            try:
                rc = proc.wait(timeout=300)
            except subprocess.TimeoutExpired:
                proc.kill()
                rc = proc.wait(timeout=120)
            # E6g: supervisor owner interrupts (authority lost); it never
            # adopts a file-written terminal state.
            assert rc != 0, rc
    rec = attempt_mod.read_attempt(run_dir)
    assert rec["state"] == attempt_mod.INTERRUPTED
    assert rec["attempt_uid"] == old_uid
    ok, problems, log_recs = attempt_mod.verify_attempt_log(run_dir)
    assert ok, problems
    assert log_recs[-1]["state"] == attempt_mod.INTERRUPTED
    assert len(_world_starts(run_dir)) == 1
    _assert_no_orphans(run_dir)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
