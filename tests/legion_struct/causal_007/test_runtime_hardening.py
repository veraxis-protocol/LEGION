"""P0-13/P0-14/P0-15/P1-3 runtime hardening (no network, loopback only).

- Host runs exactly once: -n0, addopts override, timeout > world budget.
- A pre-existing WORLD_START makes the host refuse (attempt lock).
- A deliberately slow stub mission (>150 s) through run_campaign_core.sh
  yields exactly one WORLD_START / one START per agent / t_agents_end.
- Killing the host mid-mission leaves no world/agent processes and no
  new World; the core records the attempt INVALID and never restarts.
- NIM transport: Retry-After is a floor, a 429 sets a global cooldown,
  and the concurrency semaphore actually bounds upstream parallelism.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]
HERE = Path(__file__).resolve().parent
LEGION = HERE.parent
REPO = HERE.parents[2]
WORLDS = LEGION / "worlds"
MISSION = LEGION / "test_struct_mission.py"
CORE = HERE / "run_campaign_core.sh"

sys.path.insert(0, str(LEGION))
from causal_007.nim_transport import NimTransport  # noqa: E402
from causal_007.test_runtime_integration import exe_plan  # noqa: E402


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
    # this sandbox PID 1 never reaps reparented children). Same
    # zombie-aware check as test_supervisor_e6b._pid_alive.
    try:
        stat = Path(f"/proc/{int(pid)}/stat").read_text()
        if stat.rsplit(")", 1)[1].split()[0] == "Z":
            return False
    except Exception:
        pass
    return True


def _core_env(tmp_path, plan_file, **extra):
    env = {**os.environ, "CAUSAL_PYTHON": sys.executable,
           "LEGION_ZTL_SWARM_DIR": os.environ.get("LEGION_ZTL_SWARM_DIR") or str(HERE),
           "CAUSAL_STUB_PLAN": str(plan_file), "CAUSAL_DRY_RUN_QUICK": "0"}
    env.update(extra)
    return env


def _assert_no_orphans(run_dir):
    pids = [r.get("pid") for r in _load_jsonl(Path(run_dir) / "WORKERS.jsonl")]
    world = [r for r in _load_jsonl(Path(run_dir) / "WORLD_LOG.jsonl")
             if r.get("kind") == "WORLD_START"]
    pids += [r.get("pid") for r in world]
    assert pids, "expected recorded pids to check for orphans"
    deadline = time.time() + 30
    alive = [p for p in pids if _pid_alive(p)]
    while alive and time.time() < deadline:
        time.sleep(0.5)
        alive = [p for p in pids if _pid_alive(p)]
    assert not alive, f"orphan processes still alive: {alive}"


# ------------------------------------------------------------- E6b supervisor
def test_core_invocation_contract_tokens():
    core = CORE.read_text(encoding="utf-8")
    for token in ("supervisor.py", "--attempt-index", "--quick",
                  "CAUSAL_DRY_RUN_QUICK", "CAUSAL_STUB_PLAN",
                  "CAUSAL_STUB_DELAY_S", "|| HOST_RC=$?",
                  "LEGION_ZTL_SWARM_DIR", "ZTL_SWARM_DIR_RESOLVED",
                  "must NOT judge"):
        assert token in core, token
    # E6b: the campaign path never runs through pytest (b1-GAIA-EXE root
    # cause). pytest remains a test tool only.
    assert "-m pytest" not in core and "test_struct_mission" not in core
    sup = (HERE / "supervisor.py").read_text(encoding="utf-8")
    for token in ("mission_host.py", "provider_proxy.py", "stub_model_server.py",
                  "INTERRUPTED", ".host_pid", "attempt.json",
                  "start_new_session"):
        assert token in sup, token
    host = (HERE / "mission_host.py").read_text(encoding="utf-8")
    for token in ("HOST_ATTEMPT_LOCK", "WORLD_START", "AttemptAlreadyStarted",
                  "os.O_EXCL", "STRUCT_ATTEMPT_FILE"):
        assert token in host, token
    att = (HERE / "attempt.py").read_text(encoding="utf-8")
    for token in ("REGISTERED", "RUNNING", "COMPLETED", "INTERRUPTED", "O_EXCL"):
        assert token in att, token
    world_server = (LEGION / "world_server.py").read_text(encoding="utf-8")
    assert "WORLD_START already present" in world_server


# ---------------------------------------------------------------- P1-3 transport
def test_retry_after_is_floor_not_cap():
    t = NimTransport(max_retries=1, sleep=lambda s: None)
    assert t.backoff(0, retry_after=120.0) >= 120.0
    assert t.backoff(0, retry_after=0.0) >= 0.0


def test_global_cooldown_bounds_429_rate():
    calls = {"n": 0}
    lock = threading.Lock()

    def always_429():
        with lock:
            calls["n"] += 1
        return 429, {}, {"Retry-After": "0.2"}

    t0 = time.monotonic()
    res = NimTransport(max_concurrency=2, max_retries=2).execute(always_429)
    elapsed = time.monotonic() - t0
    assert res.status == 429 and res.attempts == 3
    # Two retries, each honouring the 0.2 s global cooldown window.
    assert elapsed >= 0.35, elapsed
    assert res.retry_after_s == 0.2


def test_concurrency_semaphore_bounds_upstream():
    state = {"cur": 0, "max": 0}
    lock = threading.Lock()

    def call():
        with lock:
            state["cur"] += 1
            state["max"] = max(state["max"], state["cur"])
        time.sleep(0.05)
        with lock:
            state["cur"] -= 1
        return 200, {"id": "x"}, {}

    transport = NimTransport(max_concurrency=2, max_retries=0)
    threads = [threading.Thread(target=transport.execute, args=(call,))
               for _ in range(6)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=30)
    assert state["max"] <= 2, state


# ---------------------------------------------------------------- P0-14 refusal
@pytest.mark.timeout(300)
@pytest.mark.skipif(os.name != "posix" or not shutil.which("bash"),
                    reason="mission host subprocess requires posix")
def test_host_refuses_preexisting_world_start(tmp_path):
    out_root = tmp_path / "out"
    run_id = "dry-preexisting"
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "WORLD_LOG.jsonl").write_text(
        json.dumps({"seq": 1, "kind": "WORLD_START", "pid": 999999}) + "\n",
        encoding="utf-8")
    env = {**os.environ, "STRUCT_WORLD": str(WORLDS / "SYN-GAIA-EXE.world.json"),
           "STRUCT_OUT": str(out_root), "STRUCT_RUN_ID": run_id,
           "STRUCT_DECIDER": "scripted", "STRUCT_N_WORKERS": "100",
           "STRUCT_CAUSAL": "1"}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", f"{MISSION}::test_struct_mission",
         "-q", "-n0", "-p", "no:randomly", "-p", "no:cacheprovider",
         "-o", "addopts=", "--timeout=120", "--no-cov"],
        env=env, cwd=str(REPO), capture_output=True, text=True, timeout=240)
    assert result.returncode != 0, result.stdout[-2000:]
    starts = [r for r in _load_jsonl(run_dir / "WORLD_LOG.jsonl")
              if r.get("kind") == "WORLD_START"]
    assert len(starts) == 1  # only the pre-seeded one; no new World
    assert not list(run_dir.glob("agent_*.jsonl"))


# ---------------------------------------------------------------- P0-13 slow dry-run
@pytest.mark.timeout(1200)
@pytest.mark.skipif(os.name != "posix" or not shutil.which("bash"),
                    reason="campaign core requires bash/setsid")
def test_slow_stub_mission_single_world_via_core(tmp_path):
    plan_file = tmp_path / "stub-plan.json"
    plan_file.write_text(json.dumps(exe_plan()), encoding="utf-8")
    runs = tmp_path / "runs"
    t0 = time.monotonic()
    r = subprocess.run(
        ["bash", str(CORE), "--campaign", "B1", "--family", "GAIA-EXE",
         "--dry-run", "--runs-root", str(runs)],
        capture_output=True, text=True, timeout=1100,
        env=_core_env(tmp_path, plan_file, CAUSAL_STUB_DELAY_S="30"),
        cwd=str(REPO))
    elapsed = time.monotonic() - t0
    assert r.returncode == 0, r.stdout[-4000:] + r.stderr[-4000:]
    assert elapsed > 150, f"slow-stub mission should exceed 150 s, took {elapsed:.1f}"
    run_dir = runs / "b1-GAIA-EXE"
    starts = [x for x in _load_jsonl(run_dir / "WORLD_LOG.jsonl")
              if x.get("kind") == "WORLD_START"]
    assert len(starts) == 1, starts
    agent_logs = sorted(run_dir.glob("agent_*.jsonl"))
    assert agent_logs
    for log in agent_logs:
        n_start = sum(1 for x in _load_jsonl(log) if x.get("event") == "START")
        assert n_start == 1, (log, n_start)
    hdr = json.loads((run_dir / "RUN_HEADER.json").read_text(encoding="utf-8"))
    assert hdr.get("t_agents_end"), hdr
    _assert_no_orphans(run_dir)


# ---------------------------------------------------------------- P0-15 kill host
@pytest.mark.timeout(600)
@pytest.mark.skipif(os.name != "posix" or not shutil.which("bash"),
                    reason="campaign core requires bash/setsid")
def test_kill_host_mid_mission_no_orphans_no_new_world(tmp_path):
    plan_file = tmp_path / "stub-plan.json"
    plan_file.write_text(json.dumps(exe_plan()), encoding="utf-8")
    runs = tmp_path / "runs"
    run_dir = runs / "b1-GAIA-EXE"
    proc = subprocess.Popen(
        ["bash", str(CORE), "--campaign", "B1", "--family", "GAIA-EXE",
         "--dry-run", "--runs-root", str(runs)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env=_core_env(tmp_path, plan_file, CAUSAL_STUB_DELAY_S="30"),
        cwd=str(REPO), start_new_session=True)
    try:
        host_pid = None
        deadline = time.time() + 240
        while time.time() < deadline:
            pid_file = run_dir / ".host_pid"
            workers = _load_jsonl(run_dir / "WORKERS.jsonl")
            starts = [x for x in _load_jsonl(run_dir / "WORLD_LOG.jsonl")
                      if x.get("kind") == "WORLD_START"]
            if pid_file.exists() and len(workers) >= 100 and starts:
                host_pid = int(pid_file.read_text().strip())
                break
            if proc.poll() is not None:
                raise AssertionError(f"core exited early rc={proc.returncode}")
            time.sleep(0.5)
        assert host_pid and _pid_alive(host_pid), host_pid
        os.kill(host_pid, signal.SIGKILL)
        out, _ = proc.communicate(timeout=240)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert proc.returncode != 0, out[-3000:]
    status_file = run_dir / "ATTEMPT_STATUS.json"
    assert status_file.exists(), out[-3000:]
    assert json.loads(status_file.read_text())["status"] == "INVALID"
    starts = [x for x in _load_jsonl(run_dir / "WORLD_LOG.jsonl")
              if x.get("kind") == "WORLD_START"]
    assert len(starts) == 1, starts
    _assert_no_orphans(run_dir)
    time.sleep(3)
    starts_after = [x for x in _load_jsonl(run_dir / "WORLD_LOG.jsonl")
                    if x.get("kind") == "WORLD_START"]
    assert len(starts_after) == 1  # never restarted
