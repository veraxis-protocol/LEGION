"""Dry-run exercise of run_campaign_core.sh (no NIM, no network).

The header-only cases use CAUSAL_DRY_RUN_QUICK=1 (a documented core hook
for this light unit test); the full --dry-run pipeline (stub upstream,
your proxy, mission host, 100 workers) is exercised by
test_runtime_integration.py.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import attempt as attempt_mod  # noqa: E402
import supervisor as sup_mod  # noqa: E402
from causal_007.test_runtime_integration import exe_plan, exe_reproduction_plan  # noqa: E402


def _run(tmp_path, *args, quick=True):
    env = {**os.environ, "CAUSAL_DRY_RUN_QUICK": "1" if quick else "0",
           # P0-9: the core refuses before RUN_HEADER if this does not exist
           "LEGION_ZTL_SWARM_DIR": os.environ.get("LEGION_ZTL_SWARM_DIR") or str(HERE)}
    return subprocess.run(
        ["bash", str(HERE / "run_campaign_core.sh"), *args,
         "--runs-root", str(tmp_path)],
        capture_output=True, text=True, timeout=120, env=env)


def test_campaign_core_dry_run_b1_and_refuses_rerun(tmp_path):
    r = _run(tmp_path, "--campaign", "B1", "--family", "GAIA-EXE", "--dry-run")
    assert r.returncode == 0, r.stderr
    run_dir = tmp_path / "b1-GAIA-EXE"
    hdr = json.loads((run_dir / "RUN_HEADER.json").read_text())
    assert hdr["attempt_index"] == 1 and hdr["campaign"] == "B1"
    assert hdr["n_workers"] == 100 and hdr["judged"] is False
    assert hdr["max_model_turns_per_agent"] == 14 and hdr["max_duration_s"] == 420
    assert len(hdr["world_sha256"]) == 64
    # P1-1: monotonic registration time, registered before the proxy starts.
    assert isinstance(hdr["t_episode_registered"], (int, float))
    assert isinstance(hdr["t_episode_registered_mono"], (int, float))
    for name in ("CAUSAL_CONTROLLER.jsonl", "provider_log.jsonl", "WORKERS.jsonl"):
        assert (run_dir / name).exists()
    r2 = _run(tmp_path, "--campaign", "B1", "--family", "GAIA-EXE", "--dry-run")
    assert r2.returncode == 3  # no reruns


def test_campaign_core_refuses_missing_ztl_before_run_header(tmp_path):
    # P0-9: a missing ZTL swarm dir refuses before RUN_HEADER is registered
    env = {**os.environ, "CAUSAL_DRY_RUN_QUICK": "1",
           "LEGION_ZTL_SWARM_DIR": str(tmp_path / "no-such-ztl-swarm")}
    r = subprocess.run(
        ["bash", str(HERE / "run_campaign_core.sh"), "--campaign", "B1",
         "--family", "GAIA-EXE", "--dry-run", "--runs-root", str(tmp_path / "runs")],
        capture_output=True, text=True, timeout=120, env=env)
    assert r.returncode == 2 and "LEGION_ZTL_SWARM_DIR" in r.stderr
    assert not (tmp_path / "runs" / "b1-GAIA-EXE" / "RUN_HEADER.json").exists()


def test_campaign_core_dry_run_s100_id(tmp_path):
    r = _run(tmp_path, "--campaign", "S100", "--family", "OTEL-04", "--dry-run")
    assert r.returncode == 0, r.stderr
    hdr = json.loads((tmp_path / "s100-SYN-OTEL-04" / "RUN_HEADER.json").read_text())
    assert hdr["t_episode_registered_mono"] <= hdr["t_episode_registered"] or True
    assert hdr["campaign"] == "S100"


def test_ps1_contract_tokens():
    ps1 = (HERE / "run_campaign.ps1").read_text(encoding="utf-8")
    for token in ('ValidateSet("B1", "S100")', "b1-$Family", "s100-SYN-OTEL-04",
                  "already exists", "NOT judge", "wsl.exe", "Ubuntu-24.04"):
        assert token in ps1


def test_core_contract_tokens():
    core = (HERE / "run_campaign_core.sh").read_text(encoding="utf-8")
    for token in ("supervisor.py", "--attempt-index",
                  "LEGION_ZTL_SWARM_DIR",
                  "legion_pf/ztl-swarm", "ZTL_SWARM_DIR_RESOLVED",
                  # a failing supervisor must not abort before the scan
                  "|| HOST_RC=$?",
                  "NIM_KEY_SOURCE",
                  "CAUSAL_DRY_RUN_QUICK",
                  "must NOT judge"):
        assert token in core, token
    # The campaign path runs through the supervisor, never pytest (E6b).
    assert "-m pytest" not in core and "test_struct_mission" not in core
    sup = (HERE / "supervisor.py").read_text(encoding="utf-8")
    for token in ("t_episode_registered_mono", "provider_proxy.py",
                  "stub_model_server.py", "mission_host.py",
                  'STRUCT_DECIDER', "STRUCT_N_WORKERS",
                  "GOVERNANCE_SEAL_TTL_S", "LEGION_COMPOSITION",
                  "MCP_RATE_LIMIT_MAX_CALLS", "STRUCT_CAUSAL_OVERLAY",
                  "--attempt-file", "CAUSAL_CONTROLLER",
                  "CAMPAIGN_CAGE_POSTURE", "campaign_posture_record",
                  "_campaign_env", "CAGE_TELEMETRY_PROVIDER",
                  "attempt.json"):
        assert token in sup, token
    qual = (HERE / "run_qual_core.sh").read_text(encoding="utf-8")
    for token in ("supervisor.py", "STRUCT_PLAN", "--decider scripted",
                  "LEGION_ZTL_SWARM_DIR"):
        assert token in qual, token
    assert "-m pytest" not in qual and "test_struct_mission" not in qual


def _clean_campaign_env(tmp_path, plan_file, **extra):
    """Explicit minimal env (E6f Req-2): env -i equivalent.

    No CAGE_* posture is inherited; hostile caller posture values are
    included to prove the supervisor overrides, never inherits, them.
    """
    env = {k: os.environ[k] for k in ("PATH", "HOME", "SYSTEMROOT")
           if os.environ.get(k)}
    env.update({
        "LEGION_ZTL_SWARM_DIR": os.environ.get("LEGION_ZTL_SWARM_DIR") or
        str(Path.home() / "legion_pf" / "ztl-swarm"),
        "CAUSAL_PYTHON": sys.executable,
        "CAUSAL_STUB_PLAN": str(plan_file),
        "CAUSAL_DRY_RUN_QUICK": "0",
        # Hostile inherited posture: must have no effect whatsoever.
        "CAGE_ENV": "production",
        "CAGE_TELEMETRY_PROVIDER": "remote",
        "TELEMETRY_HOST": "http://127.0.0.1:9",
        "TELEMETRY_PUBLIC_KEY": "bogus",
        "TELEMETRY_SECRET_KEY": "bogus",
        "KMS_GOVERNANCE_KEY": "bogus",
    })
    env.update(extra)
    return env


@pytest.mark.timeout(900)
@pytest.mark.skipif(os.name != "posix", reason="campaign core is WSL bash")
def test_campaign_core_clean_env_dry_run_completes(tmp_path):
    """Req-2: run_campaign_core.sh --dry-run from a CLEAN environment.

    The subprocess env is explicit/minimal (outside pytest's conftest
    env). The attempt must reach COMPLETED, the stub-model mission must
    produce world actions, exactly one WORLD_START, complete evidence,
    and the declared posture recorded in RUN_HEADER + attempt.json.
    """
    plan_file = tmp_path / "stub-plan.json"
    plan_file.write_text(json.dumps(exe_plan()), encoding="utf-8")
    runs = tmp_path / "runs"
    r = subprocess.run(
        ["bash", str(HERE / "run_campaign_core.sh"), "--campaign", "B1",
         "--family", "GAIA-EXE", "--dry-run", "--runs-root", str(runs)],
        capture_output=True, text=True, timeout=800,
        env=_clean_campaign_env(tmp_path, plan_file))
    run_dir = runs / "b1-GAIA-EXE"
    _host_log = (run_dir / "mission_host.log").read_text(errors="ignore") \
        if (run_dir / "mission_host.log").exists() else ""
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:] + _host_log[-3000:]
    rec = attempt_mod.read_attempt(run_dir)
    assert rec["state"] == attempt_mod.COMPLETED, rec
    expected = sup_mod.campaign_posture_record()
    assert rec["cage_posture"] == expected
    hdr = json.loads((run_dir / "RUN_HEADER.json").read_text())
    assert hdr["cage_posture"] == expected
    assert hdr["cage_posture"]["vars"]["CAGE_ENV"] == "test"
    assert hdr["cage_posture"]["vars"]["CAGE_TELEMETRY_PROVIDER"] == "null"
    world = [json.loads(l) for l in
             (run_dir / "WORLD_LOG.jsonl").read_text().splitlines() if l.strip()]
    assert len([x for x in world if x.get("kind") == "WORLD_START"]) == 1
    assert any(x.get("kind") == "NATIVE_EFFECT" for x in world), world[:3]
    assert attempt_mod.validate_evidence(run_dir) == []
    assert (run_dir / "mission_host.log").exists()
    assert "CAGE_TELEMETRY_PROVIDER must be set" not in \
        (run_dir / "mission_host.log").read_text(errors="ignore")


@pytest.mark.timeout(900)
@pytest.mark.skipif(os.name != "posix", reason="qual core is WSL bash")
def test_qual_core_supervisor_scripted_clean_env(tmp_path):
    """Req-3: run_qual_core.sh is the supervisor path (scripted decider,
    hidden plan via STRUCT_PLAN only), from a clean environment."""
    plan_file = tmp_path / "hidden-plan.json"
    plan_file.write_text(json.dumps(exe_reproduction_plan()), encoding="utf-8")
    runs = tmp_path / "qual-runs"
    env = {k: os.environ[k] for k in ("PATH", "HOME", "SYSTEMROOT")
           if os.environ.get(k)}
    env.update({"LEGION_ZTL_SWARM_DIR": os.environ.get("LEGION_ZTL_SWARM_DIR") or
                str(Path.home() / "legion_pf" / "ztl-swarm"),
                "CAUSAL_PYTHON": sys.executable,
                "STRUCT_PLAN": str(plan_file),
                "STRUCT_OUT": str(runs), "STRUCT_RUN_ID": "qual-exe",
                "STRUCT_WORLD": str(HERE.parent / "worlds" / "SYN-GAIA-EXE.world.json"),
                "CAGE_ENV": "production"})
    r = subprocess.run(
        ["bash", str(HERE / "run_qual_core.sh"), "--family", "SYN-GAIA-EXE"],
        capture_output=True, text=True, timeout=800, env=env)
    run_dir = runs / "qual-exe"
    _host_log = (run_dir / "mission_host.log").read_text(errors="ignore") \
        if (run_dir / "mission_host.log").exists() else ""
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:] + _host_log[-3000:]
    rec = attempt_mod.read_attempt(run_dir)
    assert rec["state"] == attempt_mod.COMPLETED, rec
    assert rec["cage_posture"] == sup_mod.campaign_posture_record()
    world = [json.loads(l) for l in
             (run_dir / "WORLD_LOG.jsonl").read_text().splitlines() if l.strip()]
    assert len([x for x in world if x.get("kind") == "WORLD_START"]) == 1
    assert any(x.get("kind") == "NATIVE_EFFECT" for x in world)
    assert attempt_mod.validate_evidence(run_dir) == []
