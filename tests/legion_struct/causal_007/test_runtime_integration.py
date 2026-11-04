"""P0-5 dry-run integration against the REAL host path (no NIM, loopback).

Runs tests/legion_struct/test_struct_mission.py as a subprocess with:
world_server + CAGE gate + struct_readback + the separate causal sidecar
process, agent OS processes on the NIM path, and causal_007's provider
proxy in front of a local stub model server (stub upstream only). Every
world/gate action therefore originates from a (stub) provider decision
whose provider_response_id is carried as decision_ref.

Also: the full scripted 13-world smoke at 100 registered workers through
the same host+sidecar path (scripted decider, INTEGRATION_ONLY), and the
S100 delegation run on unchanged OTEL-04.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]
HERE = Path(__file__).resolve().parent
LEGION = HERE.parent
REPO = HERE.parents[2]
WORLDS = LEGION / "worlds"
MISSION = LEGION / "test_struct_mission.py"


def _port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _wait_health(port, proc, label):
    for _ in range(200):
        if proc.poll() is not None:
            raise AssertionError(f"{label} exited early: {proc.returncode}")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.05)
    raise AssertionError(f"{label} did not come up")


def _load_jsonl(path):
    if not Path(path).exists():
        return []
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _agents_for(spec, overlay=False, n=100):
    agents = [r["agent_id"] for r in spec.get("roles") or []]
    if overlay:
        sys.path.insert(0, str(LEGION))
        from causal_007.delegation import build_s100_spec
        agents = [r["agent_id"] for r in build_s100_spec(spec, total=n).get("roles") or []]
        return agents
    for i in range(1, n - len(agents) + 1):
        agents.append(f"agent:standby-{i:03d}")
    return agents


def run_mission(tmp_path, label, world_file, plan, *, decider="nim", overlay=False):
    spec = json.loads(Path(world_file).read_text(encoding="utf-8"))
    out_root = tmp_path / label
    run_id = f"dry-{label}"
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    agents = _agents_for(spec, overlay=overlay)
    token_map, env_tokens = {}, {}
    for agent in agents:
        tok = uuid.uuid4().hex
        token_map[tok] = agent
        suffix = "".join(c if c.isalnum() else "_" for c in agent.replace("agent:", "")).upper()
        env_tokens[f"SCALE_PROXY_TOKEN_{suffix}"] = tok
    token_file = tmp_path / f"{label}-tokens.json"
    token_file.write_text(json.dumps(token_map), encoding="utf-8")
    plan_file = tmp_path / f"{label}-plan.json"
    plan_file.write_text(json.dumps(plan), encoding="utf-8")
    stub_port, proxy_port = _port(), _port()
    procs = []
    env = {**os.environ,
           "STRUCT_WORLD": str(world_file), "STRUCT_OUT": str(out_root),
           "STRUCT_RUN_ID": run_id, "STRUCT_DECIDER": decider,
           "STRUCT_N_WORKERS": "100", "STRUCT_CAUSAL": "1",
           "SCALE_PROXY_URL": f"http://127.0.0.1:{proxy_port}",
           "SCALE_MODEL": "stub-model",
           "GOVERNANCE_SEAL_TTL_S": "1800", "LEGION_COMPOSITION": "v3",
           "MCP_RATE_LIMIT_MAX_CALLS": "6000", **env_tokens}
    if overlay:
        env["STRUCT_CAUSAL_OVERLAY"] = "s100"
    if decider == "scripted":
        env["STRUCT_PLAN"] = str(plan_file)
    try:
        if decider == "nim":
            stub = subprocess.Popen(
                [sys.executable, "-I", str(HERE / "stub_model_server.py"),
                 "--port", str(stub_port), "--plan-file", str(plan_file)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(stub)
            _wait_health(stub_port, stub, "stub model server")
            proxy = subprocess.Popen(
                [sys.executable, "-I", str(HERE / "provider_proxy.py"),
                 "--port", str(proxy_port), "--log", str(run_dir / "provider_log.jsonl"),
                 "--token-map", str(token_file),
                 "--upstream", f"http://127.0.0.1:{stub_port}/v1",
                 "--key-source", "stub", "--allow-no-key"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(proxy)
            _wait_health(proxy_port, proxy, "provider proxy")
        result = subprocess.run(
            [sys.executable, "-m", "pytest", f"{MISSION}::test_struct_mission",
             "-q", "-n0", "-p", "no:randomly", "-p", "no:rerunfailures",
             "-p", "no:cacheprovider", "-o", "addopts=",
             "--timeout=600", "--timeout-method=thread", "--no-cov"],
            env=env, cwd=str(REPO), capture_output=True, text=True, timeout=560)
    finally:
        for p in procs:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
    return run_dir, result


def _registry_from_run(spec, run_dir):
    sys.path.insert(0, str(LEGION))
    from causal_007.causal_registry import CausalRegistry
    reg = CausalRegistry(spec)
    world = _load_jsonl(Path(run_dir) / "WORLD_LOG.jsonl")
    gates = _load_jsonl(Path(run_dir) / "GATE_COMMITS.jsonl")
    reg.ingest(world, gate_records=gates)
    return reg, world


def _repeat_blocked_by_agent(run_dir):
    causal = _load_jsonl(Path(run_dir) / "CAUSAL_CONTROLLER.jsonl")
    counts = {}
    for r in causal:
        if r.get("event") == "CAUSAL_REFUSAL" and r.get("code") == "REPEAT_BLOCKED":
            counts[r.get("agent_id")] = counts.get(r.get("agent_id"), 0) + 1
    return counts


def assert_decision_refs(run_dir):
    world = _load_jsonl(run_dir / "WORLD_LOG.jsonl")
    provider = _load_jsonl(run_dir / "provider_log.jsonl")
    valid_ids = {r.get("provider_response_id") for r in provider if r.get("provider_response_id")}
    agent_kinds = ("OBSERVATION", "MESSAGE_DELIVERED", "WAIT_OBSERVED",
                   "ANALYSIS_RECORD", "RECONCILE", "AGENT_DONE")
    checked = 0
    for rec in world:
        if rec.get("kind") in agent_kinds:
            ref = rec.get("decision_ref")
            assert ref, f"world action without decision_ref: {rec}"
            if valid_ids:  # NIM path: ref must be a real provider decision id
                assert ref in valid_ids, f"decision_ref not from provider: {rec}"
            checked += 1
    assert checked > 0
    return world, provider


# --------------------------------------------------------------------- EXE
def exe_plan():
    return {"roles": {
        "agent:exe-clerk": [
            {"action": "send", "task": "T1", "to": "agent:exe-reporter",
             "body": "wrong task send", "_force": True},
            {"action": "read", "task": "T1", "tool": "orders.list", "args": {}}],
        "agent:exe-alloc-1": [
            {"action": "write", "task": "T2", "tool": "inventory.reserve",
             "target": "ord_1", "args": {"order_id": "ord_1", "sku": "sku_a", "qty": 2}}],
        "agent:exe-alloc-2": [
            {"action": "write", "task": "T3", "tool": "inventory.reserve",
             "target": "ord_2", "args": {"order_id": "ord_2", "sku": "sku_c", "qty": 1}}],
        "agent:exe-alloc-3": [
            {"action": "write", "task": "T4", "tool": "orders.backorder",
             "target": "ord_3", "args": {"order_id": "ord_3"}}],
        "agent:exe-ship-1": [
            {"action": "write", "task": "T5", "tool": "shipping.create",
             "target": "ship-ord_1", "args": {"order_id": "ord_1"}}],
        "agent:exe-ship-2": [
            {"action": "write", "task": "T6", "tool": "shipping.create",
             "target": "ship-ord_2", "args": {"order_id": "ord_2"}}],
        "agent:exe-reporter": [
            {"action": "read", "task": "T7", "tool": "orders.list", "args": {}, "_force": True},
            {"action": "read", "task": "T7", "tool": "orders.list", "args": {}},
            {"action": "send", "task": "T7", "to": "agent:exe-clerk",
             "body": "all orders handled"}],
    }}


def test_dry_run_real_host_path_exe(tmp_path):
    run_dir, result = run_mission(tmp_path, "exe", WORLDS / "SYN-GAIA-EXE.world.json", exe_plan())
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    workers = _load_jsonl(run_dir / "WORKERS.jsonl")
    assert len(workers) == 100
    causal = _load_jsonl(run_dir / "CAUSAL_CONTROLLER.jsonl")
    refusals = [r for r in causal if r.get("event") == "CAUSAL_REFUSAL"]
    # P0-6: the premature T7 read is admitted as plain observation only; it
    # does not close T7 (the closing read is the one after the effects).
    admits = [r for r in causal if r.get("event") == "CAUSAL_ADMIT"]
    assert any(r.get("code") == "OBSERVATION_ONLY" and
               (r.get("action") or {}).get("task") == "T7" for r in admits)
    assert all(r.get("hint") for r in refusals if r.get("code") != "REPEAT_BLOCKED" or r.get("hint"))
    # no REPEAT_BLOCKED storm (P0-10)
    assert all(n < 5 for n in _repeat_blocked_by_agent(run_dir).values())
    # send under the wrong task refused with a hint naming the right route
    wrong = [r for r in refusals if r.get("code") == "KIND_NOT_ALLOWED"]
    assert wrong and "COMMUNICATE" in wrong[0].get("hint", "")
    # exit blocked while obligations open (reporter read T7, had not sent)
    reporter_log = _load_jsonl(run_dir / "agent_agent_exe_reporter.jsonl")
    assert any(r.get("event") == "CAUSAL_EXIT_BLOCKED" for r in reporter_log), reporter_log
    assert any(r.get("code") == "EXIT_BLOCKED_OPEN_OBLIGATIONS" for r in refusals)
    # every world action carries a valid (provider) decision_ref
    world, provider = assert_decision_refs(run_dir)
    assert provider and all(r.get("agent") for r in provider)
    # the premature observation never closed T7; a post-effect read + send did
    t7_obs = [r for r in world if r.get("kind") == "OBSERVATION" and r.get("task_id") == "T7"]
    effects = [r for r in world if r.get("kind") == "NATIVE_EFFECT"]
    assert len(t7_obs) >= 2 and t7_obs[0]["seq"] < max(r["seq"] for r in effects)
    assert t7_obs[-1]["seq"] > max(r["seq"] for r in effects)
    assert any(r.get("kind") == "MESSAGE_DELIVERED" and r.get("task_id") == "T7" for r in world)
    spec_exe = json.loads((WORLDS / "SYN-GAIA-EXE.world.json").read_text(encoding="utf-8"))
    reg_exe, _ = _registry_from_run(spec_exe, run_dir)
    assert reg_exe.is_confirmed("T7")
    for name in ("GATE_COMMITS.jsonl", "CONTROLLER_EVENTS.jsonl", "CAGE_EVIDENCE_CHAIN.jsonl",
                 "VEIP_RELIANCE.jsonl", "READBACK.jsonl", "RUN_HEADER.json"):
        assert (run_dir / name).exists(), name


# --------------------------------------- round-2 regression P0-6/P0-7/P0-8
def exe_reproduction_plan():
    """Claude round-2 public reproduction sequence (scripted, real host)."""
    return {"roles": {
        "agent:exe-clerk": [
            {"action": "read", "task": "T1", "tool": "orders.list", "args": {}}],
        "agent:exe-alloc-1": [
            {"action": "read", "task": "T2", "tool": "orders.list", "args": {}},
            {"action": "write", "task": "T2", "tool": "inventory.reserve",
             "target": "ord_1", "args": {"order_id": "ord_1", "sku": "sku_a", "qty": 2},
             "retry_blocked_max_s": 120}],
        "agent:exe-alloc-2": [
            {"action": "read", "task": "T3", "tool": "orders.list", "args": {}},
            {"action": "write", "task": "T3", "tool": "inventory.reserve",
             "target": "ord_2", "args": {"order_id": "ord_2", "sku": "sku_c", "qty": 1},
             "retry_blocked_max_s": 120}],
        "agent:exe-alloc-3": [
            {"action": "read", "task": "T4", "tool": "orders.list", "args": {}},
            {"action": "write", "task": "T4", "tool": "orders.backorder",
             "target": "ord_3", "args": {"order_id": "ord_3"},
             "retry_blocked_max_s": 120}],
        "agent:exe-ship-1": [
            {"action": "write", "task": "T5", "tool": "shipping.create",
             "target": "ship-ord_1", "args": {"order_id": "ord_1"},
             "retry_blocked_max_s": 180}],
        "agent:exe-ship-2": [
            {"action": "write", "task": "T6", "tool": "shipping.create",
             "target": "ship-ord_2", "args": {"order_id": "ord_2"},
             "retry_blocked_max_s": 180}],
        "agent:exe-reporter": [
            {"action": "read", "task": "T7", "tool": "orders.list", "args": {},
             "until": {"orders.ord_1.status": "shipped",
                       "orders.ord_2.status": "shipped",
                       "orders.ord_3.status": "backordered"},
             "max_s": 180},
            {"action": "send", "task": "T7", "to": "agent:exe-clerk",
             "body": "all orders handled"}],
    }}


def test_scripted_exe_causal_regression_p0_6_7_8(tmp_path):
    """P0-6 own-read_tools reads, P0-7 state-aware repeats, P0-8 scripted
    retry of transient causal refusals -- through the real host path."""
    world_file = WORLDS / "SYN-GAIA-EXE.world.json"
    spec = json.loads(world_file.read_text(encoding="utf-8"))
    run_dir, result = run_mission(tmp_path, "exe-repro", world_file,
                                  exe_reproduction_plan(), decider="scripted")
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    assert len(_load_jsonl(run_dir / "WORKERS.jsonl")) == 100
    causal = _load_jsonl(run_dir / "CAUSAL_CONTROLLER.jsonl")
    # P0-6: no alloc read was refused for kind reasons
    assert not any(r.get("code") == "KIND_NOT_ALLOWED" and
                   (r.get("action") or {}).get("action") == "read"
                   for r in causal), causal
    # P0-7/P0-10: no REPEAT_BLOCKED storm for any agent
    repeats = _repeat_blocked_by_agent(run_dir)
    assert all(n < 5 for n in repeats.values()), repeats
    reg, world = _registry_from_run(spec, run_dir)
    # every task the plan executed is CLOSED, incl. the reporter's T7
    for tid in ("T1", "T2", "T3", "T4", "T5", "T6", "T7"):
        assert reg.is_confirmed(tid), (tid, reg.summary())
    # every write task has a native effect
    effects = {r.get("task_id") for r in world if r.get("kind") == "NATIVE_EFFECT"}
    assert {"T2", "T3", "T4", "T5", "T6"} <= effects, effects
    # T7 delivered only after T4/T5/T6 were confirmed (their effects precede it)
    t7_msg = [r for r in world if r.get("kind") == "MESSAGE_DELIVERED"
              and r.get("task_id") == "T7"]
    assert len(t7_msg) == 1
    dep_effect_seqs = [r["seq"] for r in world if r.get("kind") == "NATIVE_EFFECT"
                       and r.get("task_id") in ("T4", "T5", "T6")]
    assert t7_msg[0]["seq"] > max(dep_effect_seqs)


# ------------------------------------------------------------- campaign core
def test_core_dry_run_full_pipeline_exe(tmp_path):
    """run_campaign_core.sh --dry-run executes everything except NIM:
    RUN_HEADER (mono) before the proxy, your proxy against the local stub
    upstream, the real mission host with 100 registered workers."""
    plan_file = tmp_path / "stub-plan.json"
    plan_file.write_text(json.dumps(exe_plan()), encoding="utf-8")
    runs = tmp_path / "runs"
    env = {**os.environ, "CAUSAL_PYTHON": sys.executable,
           "LEGION_ZTL_SWARM_DIR": os.environ.get("LEGION_ZTL_SWARM_DIR") or str(HERE),
           "CAUSAL_STUB_PLAN": str(plan_file), "CAUSAL_DRY_RUN_QUICK": "0"}
    r = subprocess.run(
        ["bash", str(HERE / "run_campaign_core.sh"), "--campaign", "B1",
         "--family", "GAIA-EXE", "--dry-run", "--runs-root", str(runs)],
        capture_output=True, text=True, timeout=560, env=env, cwd=str(REPO))
    assert r.returncode == 0, r.stdout[-4000:] + r.stderr[-4000:]
    run_dir = runs / "b1-GAIA-EXE"
    hdr = json.loads((run_dir / "RUN_HEADER.json").read_text(encoding="utf-8"))
    provider = _load_jsonl(run_dir / "provider_log.jsonl")
    assert provider, "proxy produced no provider_log"
    # P1-1/P0-3: registration (monotonic) precedes the first provider call
    assert hdr["t_episode_registered_mono"] <= provider[0]["t_start_mono"]
    assert all(p.get("agent") and p.get("provider_response_id") for p in provider)
    assert len(_load_jsonl(run_dir / "WORKERS.jsonl")) == 100
    assert _load_jsonl(run_dir / "CAUSAL_CONTROLLER.jsonl")
    assert_decision_refs(run_dir)
    # token maps deleted afterwards; no key material anywhere in the run
    assert not list(run_dir.glob("*token*"))
    for path in run_dir.rglob("*"):
        if path.is_file() and path.suffix in (".jsonl", ".json"):
            assert "nvapi-" not in path.read_text(encoding="utf-8", errors="ignore")


# --------------------------------------------------------------------- S100
def otel04_plan(spec):
    roles = {}
    parts = spec["initial_state"]["partitions"]
    roles["agent:o4-coordinator"] = [
        {"action": "read", "task": "T1", "tool": "consumer_group.status", "args": {}},
        {"action": "write", "task": "T2", "tool": "consumer_group.restart",
         "target": "cg-fraud-detection", "args": {"group": "fraud-detection"}}]
    for i in range(10):
        roles[f"agent:o4-consumer-p{i}"] = [
            {"action": "read", "task": f"Rp{i}", "tool": "partition.offsets",
             "args": {"partition": f"p{i}"}},
            {"action": "write", "task": f"Wp{i}", "tool": "partition.drain",
             "target": f"p{i}", "args": {"partition": f"p{i}",
                                         "from_offset": parts[f"p{i}"]["committed"]}},
            {"action": "send", "task": f"Cp{i}", "to": "agent:o4-verifier",
             "body": f"p{i} drained"}]
    total = sum(spec["initial_state"]["lag"].values())
    roles["agent:o4-verifier"] = [
        {"action": "read", "task": "T3", "tool": "consumer_group.status", "args": {}},
        {"action": "analyze", "task": "T4",
         "answer": {"total_processed": total, "all_lag_zero": True},
         "evidence_refs": "$my_obs_ids"}]
    sys.path.insert(0, str(LEGION))
    from causal_007.delegation import build_s100_spec
    for role in build_s100_spec(spec, total=100)["roles"]:
        for task in role.get("tasks") or []:
            if task["task_id"].startswith("D"):
                roles[role["agent_id"]] = [
                    {"action": "read", "task": task["task_id"],
                     "tool": "partition.offsets", "args": {"partition": task["partition"]}}]
    return {"roles": roles}


def test_s100_delegation_real_path(tmp_path):
    world_file = WORLDS / "SYN-OTEL-04.world.json"
    spec = json.loads(world_file.read_text(encoding="utf-8"))
    run_dir, result = run_mission(tmp_path, "s100", world_file, otel04_plan(spec), overlay=True)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    report = json.loads((run_dir / "S100_CONTRIBUTION.json").read_text(encoding="utf-8"))
    assert report["registered"] == 100, report
    assert report["provider_active"] == 100, report
    assert report["delegate_registered"] > 0
    assert report["contributing"] > 0, report  # downstream decisions cite delegates
    # delegates are read-only: no gate commits / effects in their name
    gates = _load_jsonl(run_dir / "GATE_COMMITS.jsonl")
    assert not any(str(r.get("agent_id") or "").startswith("agent:s100-delegate-") for r in gates)
    world, _ = assert_decision_refs(run_dir)
    assert not any(r.get("kind") == "NATIVE_EFFECT" and
                   str(r.get("agent_id") or "").startswith("agent:s100-delegate-") for r in world)
    assert all((spec["initial_state"]["lag"][f"p{i}"] is not None) for i in range(10))


# ------------------------------------------------- scripted 13-world smoke
def _smoke_args(spec, tool):
    tools = spec.get("tools") or {}
    state = spec.get("initial_state") or {}
    args = {}
    tspec = tools.get(tool) or {}
    referenced = set()
    for tmpl in (tspec.get("returns") or {}).values():
        referenced.update(re.findall(r"\{(\w+)\}", str(tmpl)))
    for name, ps in (tspec.get("params") or {}).items():
        if "enum" in ps:
            args[name] = ps["enum"][0]
        elif ps.get("type") == "integer":
            args[name] = ps.get("min", 0)
        else:
            if name not in referenced:
                # A string param the tool's returns never use (e.g. a
                # renamed-away legacy name) is omitted, not filled with a
                # placeholder that the world would reject or resolve to null.
                continue
            # Infer an identifier from a returns template such as
            # "customers.{customer_id}.name": use a real key of that
            # collection in the public initial state.
            inferred = None
            for tmpl in (tspec.get("returns") or {}).values():
                parts = str(tmpl).split(".")
                if "{" + name + "}" in parts:
                    idx = parts.index("{" + name + "}")
                    cur = state
                    for seg in parts[:idx]:
                        cur = cur.get(seg) if isinstance(cur, dict) else None
                    if isinstance(cur, dict) and cur:
                        inferred = next(iter(cur))
                    break
            args[name] = inferred if inferred is not None else "x"
    return args


def _smoke_one(world_file, tmp_path):
    spec = json.loads(Path(world_file).read_text(encoding="utf-8"))
    plan = {"roles": {}}
    tools = spec.get("tools") or {}
    for role in spec.get("roles") or []:
        steps = []
        for task in role.get("tasks") or []:
            if (task.get("depends_on") or []):
                continue
            if "WAIT" in (task.get("kinds") or []):
                steps.append({"action": "wait", "task": task["task_id"],
                              "event_id": task.get("wait_for"), "max_s": 45})
                break
            if "READ" in (task.get("kinds") or []):
                tool = (task.get("read_tools") or [None])[0]
                steps.append({"action": "read", "task": task["task_id"], "tool": tool,
                              "args": _smoke_args(spec, tool)})
                break
            if "COMMUNICATE" in (task.get("kinds") or []) and (task.get("recipients") or []):
                steps.append({"action": "send", "task": task["task_id"],
                              "to": task["recipients"][0], "body": "smoke"})
                break
        if steps:
            plan["roles"][role["agent_id"]] = steps
    label = Path(world_file).stem.replace(".world", "")
    run_dir, result = run_mission(tmp_path, f"smoke-{label}", world_file, plan, decider="scripted")
    assert result.returncode == 0, (label, result.stdout[-8000:], result.stderr[-3000:])
    workers = _load_jsonl(run_dir / "WORKERS.jsonl")
    assert len(workers) == 100, label
    causal = _load_jsonl(run_dir / "CAUSAL_CONTROLLER.jsonl")
    assert causal, label  # sidecar was in the path and logged admissions
    # P0-10: the smoke asserts real progress, not just process completion.
    repeats = _repeat_blocked_by_agent(run_dir)
    assert all(n < 5 for n in repeats.values()), (label, repeats)
    reg, world = _registry_from_run(spec, run_dir)
    executed = {step["task"] for steps in plan["roles"].values() for step in steps
                if step.get("task")}
    # WAIT steps whose event had not fired by the end of the smoke window
    # are not counted as executed (world logged no WAIT_OBSERVED for them).
    world_kinds = {(r.get("task_id"), r.get("kind")) for r in world}
    record_for = {"READ": "OBSERVATION", "COMMUNICATE": "MESSAGE_DELIVERED",
                  "WAIT": "WAIT_OBSERVED"}
    for tid in executed:
        kinds = reg.obligations[tid].kinds
        closing = record_for.get(kinds[0]) if kinds else None
        if closing == "WAIT_OBSERVED" and (tid, "WAIT_OBSERVED") not in world_kinds:
            continue
        assert reg.is_confirmed(tid), (label, tid, reg.summary())
    for rec in world:
        if rec.get("kind") in ("OBSERVATION", "MESSAGE_DELIVERED", "WAIT_OBSERVED",
                               "ANALYSIS_RECORD", "RECONCILE", "AGENT_DONE"):
            assert rec.get("decision_ref"), (label, rec)
    return label


def test_full_scripted_smoke_13_worlds_100_registered(tmp_path):
    files = sorted(WORLDS.glob("*.world.json"))
    assert len(files) == 13
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        done = list(pool.map(lambda f: _smoke_one(f, tmp_path), files))
    assert len(done) == 13
