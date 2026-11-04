"""E6g T1-T4: attempt.json / ATTEMPT_LOG tamper (WO-LEGION100-CAUSAL-CLOSURE-007).

Clean-env real supervisor path (posix). Policy: continue_and_record.
Each case: 0 illegal mutations (mission still governed, 1 WORLD_START,
no extra world), owner-written terminal in verified ATTEMPT_LOG chain.
"""
from __future__ import annotations
import json, os, subprocess, sys, time
from pathlib import Path
import pytest
pytestmark = [pytest.mark.unit, pytest.mark.local,
              pytest.mark.skipif(os.name != "posix", reason="supervisor process groups require posix")]
HERE = Path(__file__).resolve().parent
LEGION = HERE.parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(LEGION))
import attempt as attempt_mod  # noqa: E402
from causal_007.test_runtime_integration import exe_plan  # noqa: E402
from causal_007.test_supervisor_e6b import _load_jsonl, _sup_argv, _sup_env, _wait_for, _world_starts  # noqa: E402

def _starts(rd): return _world_starts(rd)
def _native(rd): return [r for r in _load_jsonl(Path(rd)/"WORLD_LOG.jsonl") if r.get("kind")=="NATIVE_EFFECT"]
def _assert_chain_terminal(rd, state):
    ok, problems, recs = attempt_mod.verify_attempt_log(rd)
    assert ok, problems
    assert recs and recs[-1]["state"] == state, recs[-3:]
    # MAC presence on every record (key not available to test; hash+MAC fields checked)
    assert all(r.get("mac") and r.get("hash") and r.get("prev_hash") for r in recs)
    return recs

def _run_with_tamper(tmp_path, run_id, tamper):
    plan = tmp_path/"plan.json"; plan.write_text(json.dumps(exe_plan()))
    runs = tmp_path/"runs"; rd = runs/run_id
    proc = subprocess.Popen(_sup_argv(runs, run_id, plan, "--stub-delay-s", "2"),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=_sup_env())
    try:
        _wait_for(lambda: len(_starts(rd))>=1 and len(_native(rd))>=1, 300, "world up with effect")
        before_native = len(_native(rd))
        tamper(rd)
        rc = proc.wait(timeout=900)
    finally:
        if proc.poll() is None: proc.kill()
    return rd, rc, before_native

@pytest.mark.timeout(1200)
def test_t1_attempt_json_rewritten_completed_midrun(tmp_path):
    rd, rc, before = _run_with_tamper(tmp_path, "e6g-t1", lambda rd: (rd/"attempt.json").write_text(json.dumps({"state":"COMPLETED"})))
    assert rc == 0, rc
    assert len(_starts(rd)) == 1
    assert len(_native(rd)) > before  # legitimate mission continued, attacker caused no mutation/shutdown
    recs = _assert_chain_terminal(rd, attempt_mod.COMPLETED)
    assert any(r.get("event")=="EVIDENCE_TAMPER_DETECTED" for r in recs), recs
    assert attempt_mod.read_attempt(rd)["state"] == attempt_mod.COMPLETED
    assert attempt_mod.validate_evidence(rd) == []

@pytest.mark.timeout(1200)
def test_t2_attempt_json_deleted_midrun(tmp_path):
    rd, rc, before = _run_with_tamper(tmp_path, "e6g-t2", lambda rd: (rd/"attempt.json").unlink())
    assert rc == 0, rc
    assert len(_starts(rd)) == 1
    assert len(_native(rd)) > before
    recs = _assert_chain_terminal(rd, attempt_mod.COMPLETED)
    assert any(r.get("event")=="EVIDENCE_TAMPER_DETECTED" for r in recs), recs
    assert attempt_mod.read_attempt(rd)["state"] == attempt_mod.COMPLETED

@pytest.mark.timeout(1200)
def test_t3_forged_running_after_terminal_refused(tmp_path):
    plan = tmp_path/"plan.json"; plan.write_text(json.dumps(exe_plan()))
    runs = tmp_path/"runs"; run_id="e6g-t3"; rd = runs/run_id
    r = subprocess.run(_sup_argv(runs, run_id, plan), capture_output=True, text=True, timeout=900, env=_sup_env())
    assert r.returncode == 0, r.stdout[-2000:]+r.stderr[-2000:]
    assert len(_starts(rd)) == 1
    _assert_chain_terminal(rd, attempt_mod.COMPLETED)
    native_before = len(_native(rd))
    (rd/"attempt.json").write_text(json.dumps({"attempt_uid":"forged","state":"RUNNING","world_instance_id":"forged"}))
    r2 = subprocess.run(_sup_argv(runs, run_id, plan), capture_output=True, text=True, timeout=300, env=_sup_env())
    assert r2.returncode == 3, r2.stdout[-1000:]+r2.stderr[-1000:]
    # legacy host refused (no live authority)
    env = {**_sup_env(), "STRUCT_ATTEMPT_FILE": str(rd/"attempt.json"), "STRUCT_ATTEMPT_UID":"forged",
           "STRUCT_RUN_DIR": str(rd), "STRUCT_WORLD": str(LEGION/"worlds"/"SYN-GAIA-EXE.world.json"),
           "STRUCT_OUT": str(runs), "STRUCT_RUN_ID": run_id, "STRUCT_DECIDER":"scripted", "STRUCT_N_WORKERS":"100"}
    r3 = subprocess.run([sys.executable, "-I", str(HERE/"mission_host.py")], capture_output=True, text=True, timeout=120, env=env)
    assert r3.returncode == 3, r3.stdout[-1000:]+r3.stderr[-1000:]
    assert len(_starts(rd)) == 1 and len(_native(rd)) == native_before
    _assert_chain_terminal(rd, attempt_mod.COMPLETED)

def test_t4_attempt_log_tail_edited_detected(tmp_path):
    # Unit-level chain verification with known key (owner key)
    import secrets
    rd = tmp_path/"run"; rd.mkdir()
    key = secrets.token_bytes(32)
    log = attempt_mod.AttemptLog(rd, key, attempt_uid="u1")
    log.append("REGISTERED", state="REGISTERED")
    log.append("RUNNING", state="RUNNING")
    log.append("COMPLETED", state="COMPLETED", reason="done")
    ok, problems, _ = attempt_mod.verify_attempt_log(rd, key=key)
    assert ok, problems
    lines = (rd/"ATTEMPT_LOG.jsonl").read_text().splitlines()
    edited = json.loads(lines[-1]); edited["state"]="RUNNING"
    lines[-1] = json.dumps(edited)
    (rd/"ATTEMPT_LOG.jsonl").write_text("\n".join(lines)+"\n")
    ok, problems, _ = attempt_mod.verify_attempt_log(rd, key=key)
    assert not ok and problems
    # also without key, hash chain detects
    ok2, problems2, _ = attempt_mod.verify_attempt_log(rd)
    assert not ok2 and problems2
