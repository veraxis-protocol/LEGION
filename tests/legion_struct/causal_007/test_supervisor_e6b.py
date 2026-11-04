"""E6b falsification tests A-E through the REAL supervisor path.

No network, stub model only. Every test drives
``python -I supervisor.py --campaign B1 --family GAIA-EXE --dry-run``
as a subprocess (the campaign path itself; pytest is only the test
harness here) and falsifies one acceptance invariant:

  A. HostCrash => INTERRUPTED/INVALID, never automatic re-execution:
     kill the supervisor at >=121 s (the b1-GAIA-EXE --timeout=120
     scenario); a restart attempt and a direct host start are refused,
     exactly one WORLD_START ever exists, no orphans.
  B. Two supervisors, same run_id, concurrently: exactly one runs; the
     other is refused before creating anything.
  C. Terminal(attempt) => no further mutations: force INTERRUPTED
     mid-run, replay a previously valid WRITE (same agent identity,
     same decision_ref) at the world /actuate and at the gate; neither
     produces an effect, and the world cannot be restarted.
  D. HTTP 429 storm then recovery inside the live attempt: same world
     continues, one WORLD_START, no causal state reset, mission
     completes; 429s are inference retries only.
  E. Evidence isolation: every event/receipt in the run dir carries an
     unambiguous (attempt_uid, world_instance_id, seq), nothing lost.
"""
from __future__ import annotations

import json
import os
import shutil
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
from causal_007.test_runtime_integration import _registry_from_run, exe_plan  # noqa: E402


# --------------------------------------------------------------- helpers
def _load_jsonl(path):
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _pid_alive(pid):
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
    except (ProcessLookupError, PermissionError, OSError):
        return False
    # A zombie is dead: it executes nothing and holds no sockets (in
    # this sandbox PID 1 never reaps reparented children).
    try:
        stat = Path(f"/proc/{int(pid)}/stat").read_text()
        if stat.rsplit(")", 1)[1].split()[0] == "Z":
            return False
    except Exception:
        pass
    return True


def _world_starts(run_dir):
    return [r for r in _load_jsonl(Path(run_dir) / "WORLD_LOG.jsonl")
            if r.get("kind") == "WORLD_START"]


def _wait_for(predicate, timeout_s, label):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.5)
    raise AssertionError(f"timed out waiting for {label}")


def _assert_no_orphans(run_dir):
    pids = [r.get("pid") for r in _load_jsonl(Path(run_dir) / "WORKERS.jsonl")]
    pids += [r.get("pid") for r in _world_starts(run_dir)]
    assert pids, "expected recorded pids to check for orphans"
    _wait_for(lambda: not [p for p in pids if _pid_alive(p)], 30,
              "orphan processes to die")


def _sup_argv(runs, run_id, plan_file, *extra):
    return [sys.executable, "-I", str(HERE / "supervisor.py"),
            "--campaign", "B1", "--family", "GAIA-EXE",
            "--runs-root", str(runs), "--run-id", run_id,
            "--dry-run", "--stub-plan", str(plan_file), *extra]


def _clean_env(extra=None):
    """Clean environment (E6f): NOT pytest's inherited environment.

    Only minimal system variables + the ZTL pointer survive; every
    CAGE_* posture variable is established explicitly by the supervisor
    (CAMPAIGN_CAGE_POSTURE), exactly as on the real campaign path.
    """
    env = {k: os.environ[k] for k in ("PATH", "HOME", "SYSTEMROOT")
           if os.environ.get(k)}
    env["LEGION_ZTL_SWARM_DIR"] = os.environ.get("LEGION_ZTL_SWARM_DIR") or \
        str(Path.home() / "legion_pf" / "ztl-swarm")
    if extra:
        env.update(extra)
    return env


def _sup_env(extra=None):
    return _clean_env(extra)


def _start_supervisor(runs, run_id, plan_file, *extra):
    return subprocess.Popen(
        _sup_argv(runs, run_id, plan_file, *extra),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env=_sup_env())


def _wait_world_up(run_dir, timeout_s=300):
    _wait_for(lambda: len(_world_starts(run_dir)) >= 1 and
              len(_load_jsonl(Path(run_dir) / "WORKERS.jsonl")) >= 100,
              timeout_s, "world up with 100 workers")


def _http_post(url, body, headers=None, timeout=30):
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode() or "{}")
        except Exception:
            return exc.code, {}


# ------------------------------------------------------------------- A
@pytest.mark.timeout(1200)
def test_a_kill_supervisor_at_121s_no_restart(tmp_path):
    """A: supervisor killed at >=121 s; world never re-created."""
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(exe_plan()), encoding="utf-8")
    runs = tmp_path / "runs"
    run_id = "e6b-a"
    run_dir = runs / run_id
    t0 = time.time()
    proc = _start_supervisor(runs, run_id, plan_file, "--stub-delay-s", "30")
    try:
        _wait_world_up(run_dir)
        uid_before = attempt_mod.read_attempt(run_dir)["attempt_uid"]
        # The incident scenario: the supervisor dies at >=121 s.
        remaining = 121.0 - (time.time() - t0)
        if remaining > 0:
            time.sleep(remaining)
        os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=120)
    finally:
        if proc.poll() is None:
            proc.kill()
    # No orphaned agents/world, and no second world was ever created.
    _assert_no_orphans(run_dir)
    assert len(_world_starts(run_dir)) == 1
    # Nobody restarted anything automatically: still RUNNING, supervisor
    # simply gone.
    assert attempt_mod.attempt_state(run_dir) == attempt_mod.RUNNING
    # Automatic restart attempt: refused; attempt now INTERRUPTED/INVALID.
    r = subprocess.run(_sup_argv(runs, run_id, plan_file),
                       capture_output=True, text=True, timeout=300,
                       env=_sup_env())
    assert r.returncode == 3, r.stdout[-2000:] + r.stderr[-2000:]
    rec = attempt_mod.read_attempt(run_dir)
    assert rec["state"] == attempt_mod.INTERRUPTED
    assert rec["verdict"] == "INVALID"
    assert rec["attempt_uid"] == uid_before
    status = json.loads((run_dir / "ATTEMPT_STATUS.json").read_text())
    assert status["status"] == "INVALID"
    assert len(_world_starts(run_dir)) == 1
    # Manual restart (mission host directly): refused, still no world.
    host_env = {**_sup_env(),
                "STRUCT_ATTEMPT_FILE": str(run_dir / "attempt.json"),
                "STRUCT_ATTEMPT_UID": uid_before,
                "STRUCT_WORLD_INSTANCE_ID": rec["world_instance_id"],
                "STRUCT_RUN_DIR": str(run_dir),
                "STRUCT_WORLD": str(WORLDS / "SYN-GAIA-EXE.world.json"),
                "STRUCT_OUT": str(runs), "STRUCT_RUN_ID": run_id,
                "STRUCT_DECIDER": "scripted", "STRUCT_N_WORKERS": "100"}
    r2 = subprocess.run([sys.executable, "-I", str(HERE / "mission_host.py")],
                        capture_output=True, text=True, timeout=300,
                        env=host_env)
    assert r2.returncode == 3, r2.stdout[-2000:] + r2.stderr[-2000:]
    assert len(_world_starts(run_dir)) == 1
    _assert_no_orphans(run_dir)


# ------------------------------------------------------------------- B
@pytest.mark.timeout(900)
def test_b_two_supervisors_exactly_one_runs(tmp_path):
    """B: second supervisor refused before creating anything."""
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(exe_plan()), encoding="utf-8")
    runs = tmp_path / "runs"
    run_id = "e6b-b"
    run_dir = runs / run_id
    proc = _start_supervisor(runs, run_id, plan_file, "--stub-delay-s", "30")
    try:
        _wait_world_up(run_dir)
        uid_before = attempt_mod.read_attempt(run_dir)["attempt_uid"]
        r2 = subprocess.run(_sup_argv(runs, run_id, plan_file),
                            capture_output=True, text=True, timeout=300,
                            env=_sup_env())
        assert r2.returncode == 3, r2.stdout[-2000:] + r2.stderr[-2000:]
        assert "REFUSED" in (r2.stderr + r2.stdout)
        # The first supervisor still owns the attempt, untouched.
        assert proc.poll() is None
        rec = attempt_mod.read_attempt(run_dir)
        assert rec["state"] == attempt_mod.RUNNING
        assert rec["attempt_uid"] == uid_before
        assert len(_world_starts(run_dir)) == 1
        # And it did not mark the live attempt interrupted.
        assert rec["verdict"] is None
    finally:
        if proc.poll() is None:
            os.kill(proc.pid, signal.SIGKILL)
            proc.wait(timeout=120)
    _assert_no_orphans(run_dir)
    assert len(_world_starts(run_dir)) == 1


# ------------------------------------------------------------------- C
@pytest.mark.timeout(900)
def test_c_replay_after_terminal_produces_no_effect(tmp_path):
    """C: post-terminal replay at world /actuate and at the gate: no effect."""
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(exe_plan()), encoding="utf-8")
    runs = tmp_path / "runs"
    run_id = "e6b-c"
    run_dir = runs / run_id
    proc = _start_supervisor(runs, run_id, plan_file, "--stub-delay-s", "2")
    try:
        _wait_for(lambda: any(r.get("effect_id") for r in
                              _load_jsonl(run_dir / "GATE_COMMITS.jsonl")) and
                  any(r.get("kind") == "NATIVE_EFFECT" for r in
                      _load_jsonl(run_dir / "WORLD_LOG.jsonl")),
                  300, "first committed effect")
        endpoints = json.loads((run_dir / "HOST_ENDPOINTS.json").read_text())
        tokens = json.loads((run_dir / "world_tokens.json").read_text())
        workers = {w["agent_id"]: w
                   for w in _load_jsonl(run_dir / "WORKERS.jsonl")}
        gate_rec = next(r for r in _load_jsonl(run_dir / "GATE_COMMITS.jsonl")
                        if r.get("effect_id"))
        ca = gate_rec["caller_args"]
        # Force terminal effect mid-run (E6g): killing the live authority
        # is fail-closed -- gate/world can prove no RUNNING, supervisor
        # owner interrupts. Files are never believed.
        _ap = run_dir / ".authority_pid"
        if _ap.exists():
            try:
                os.kill(int(_ap.read_text().strip()), signal.SIGKILL)
            except (OSError, ValueError):
                pass
        # Replay the previously valid WRITE at the world actuator.
        w_status, w_payload = None, {}
        try:
            w_status, w_payload = _http_post(
                f"{endpoints['world_url']}/actuate",
                {"command_id": "replay-c-1", "task_id": ca["task_id"],
                 "agent_id": gate_rec["agent_id"], "tool": ca["tool"],
                 "target": ca["target"], "args": ca["args"]},
                headers={"Authorization": f"Bearer {tokens['actuator']}"},
                timeout=15)
        except Exception:
            w_status = None  # tree already down: also no effect
        # Replay the same WRITE at the gate (same identity, same ref).
        g_output = None
        try:
            _gs, g_payload = _http_post(
                f"{endpoints['gateway_url']}/tools/execute",
                {"tool_name": "world_write",
                 "params": {"task_id": ca["task_id"], "tool": ca["tool"],
                            "target": ca["target"],
                            "args_json": json.dumps(ca["args"]),
                            "decision_ref": gate_rec["decision_ref"]}},
                headers={"l5d-client-id":
                         workers[gate_rec["agent_id"]]["workload_identity"]},
                timeout=15)
            g_output = str(g_payload.get("output") or g_payload)
        except Exception:
            g_output = None  # tree already down: also no effect
        rc = proc.wait(timeout=300)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert rc != 0
    # World refused with 403 while alive (or was already gone): no effect.
    assert w_status in (403, None), (w_status, w_payload)
    if g_output is not None:
        assert "BLOCKED" in g_output or "attempt terminal" in g_output, g_output
    assert attempt_mod.attempt_state(run_dir) == attempt_mod.INTERRUPTED
    # Terminal => no further mutations: logs are stable once the tree is
    # down, and there was only ever one world.
    def snapshot():
        world = _load_jsonl(run_dir / "WORLD_LOG.jsonl")
        return (len([r for r in world if r.get("kind") == "NATIVE_EFFECT"]),
                len(_load_jsonl(run_dir / "GATE_COMMITS.jsonl")),
                len(world))
    snap1 = snapshot()
    time.sleep(2)
    assert snapshot() == snap1
    assert len(_world_starts(run_dir)) == 1
    # The world itself refuses to start again (capability consumed).
    tokens_file = tmp_path / "tokens-again.json"
    tokens_file.write_text(json.dumps(tokens), encoding="utf-8")
    rec = attempt_mod.read_attempt(run_dir)
    world_env = {**_sup_env(),
                 "STRUCT_ATTEMPT_FILE": str(run_dir / "attempt.json"),
                 "STRUCT_ATTEMPT_UID": rec["attempt_uid"],
                 "STRUCT_WORLD_INSTANCE_ID": rec["world_instance_id"]}
    rw = subprocess.run(
        [sys.executable, "-I", str(LEGION / "world_server.py"), "0",
         str(WORLDS / "SYN-GAIA-EXE.world.json"), str(run_dir),
         str(tokens_file)],
        capture_output=True, text=True, timeout=120, env=world_env)
    assert rw.returncode == 3, rw.stdout[-1000:] + rw.stderr[-1000:]
    assert len(_world_starts(run_dir)) == 1
    _assert_no_orphans(run_dir)


# ------------------------------------------------------------------- D
@pytest.mark.timeout(1200)
def test_d_429_storm_recovers_inside_same_attempt(tmp_path):
    """D: 429 storm is inference retry only; same world, state intact."""
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(exe_plan()), encoding="utf-8")
    runs = tmp_path / "runs"
    run_id = "e6b-d"
    run_dir = runs / run_id
    r = subprocess.run(
        _sup_argv(runs, run_id, plan_file,
                  "--storm-429-count", "40", "--proxy-max-retries", "60"),
        capture_output=True, text=True, timeout=1100, env=_sup_env())
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
    rec = attempt_mod.read_attempt(run_dir)
    assert rec["state"] == attempt_mod.COMPLETED
    # One world only; the storm created no world and reset nothing.
    assert len(_world_starts(run_dir)) == 1
    provider = _load_jsonl(run_dir / "provider_log.jsonl")
    assert provider, "no provider calls logged"
    # Retries actually happened (storm absorbed in-proxy) yet every call
    # finally succeeded: 429 never escaped the transport as a failure.
    assert sum(p.get("attempts") or 1 for p in provider) > len(provider)
    assert all(p.get("http_status") == 200 for p in provider), provider[:3]
    assert all(p.get("attempt_uid") == rec["attempt_uid"] for p in provider)
    # Causal state intact: the registry rebuilt from the run's own logs
    # confirms every mission task.
    spec = json.loads((WORLDS / "SYN-GAIA-EXE.world.json").read_text())
    reg, _world = _registry_from_run(spec, run_dir)
    for tid in ("T1", "T2", "T3", "T4", "T5", "T6", "T7"):
        assert reg.is_confirmed(tid), (tid, reg.summary())
    assert attempt_mod.validate_evidence(run_dir) == []
    _assert_no_orphans(run_dir)


# ------------------------------------------------------------------- E
@pytest.mark.timeout(900)
def test_e_evidence_identity_unambiguous(tmp_path):
    """E: every event/receipt carries (attempt_uid, world_instance_id, seq)."""
    plan_file = tmp_path / "plan.json"
    plan_file.write_text(json.dumps(exe_plan()), encoding="utf-8")
    runs = tmp_path / "runs"
    run_id = "e6b-e"
    run_dir = runs / run_id
    r = subprocess.run(_sup_argv(runs, run_id, plan_file),
                       capture_output=True, text=True, timeout=800,
                       env=_sup_env())
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
    rec = attempt_mod.read_attempt(run_dir)
    assert rec["state"] == attempt_mod.COMPLETED
    uid, wid = rec["attempt_uid"], rec["world_instance_id"]
    hdr = json.loads((run_dir / "RUN_HEADER.json").read_text())
    assert hdr["attempt_uid"] == uid and hdr["world_instance_id"] == wid
    endpoints = json.loads((run_dir / "HOST_ENDPOINTS.json").read_text())
    assert endpoints["attempt_uid"] == uid
    assert endpoints["world_instance_id"] == wid
    # Nothing lost, nothing foreign, per-file seq strictly monotonic.
    assert attempt_mod.validate_evidence(run_dir) == []
    starts = _world_starts(run_dir)
    assert len(starts) == 1
    assert starts[0]["attempt_uid"] == uid
    assert starts[0]["world_instance_id"] == wid
    workers = _load_jsonl(run_dir / "WORKERS.jsonl")
    assert len(workers) == 100
    assert all(w.get("attempt_uid") == uid and
               w.get("world_instance_id") == wid for w in workers)
    for name in ("WORLD_LOG.jsonl", "GATE_COMMITS.jsonl",
                 "CONTROLLER_EVENTS.jsonl", "CAUSAL_CONTROLLER.jsonl",
                 "READBACK.jsonl", "provider_log.jsonl"):
        recs = _load_jsonl(run_dir / name)
        assert recs, f"{name} empty (evidence lost?)"
        assert all(r.get("attempt_uid") == uid for r in recs), name
        assert all(r.get("world_instance_id") == wid for r in recs), name
    _assert_no_orphans(run_dir)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
