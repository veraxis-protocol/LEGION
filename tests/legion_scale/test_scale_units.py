"""Deterministic unit tests for LEGION scale: DAG controller, target invariant, oracle rejection.
No network to NIM. Local target subprocess only where stated."""
from __future__ import annotations
import asyncio, json, os, pathlib, socket, subprocess, sys, time, urllib.request, urllib.error
import pytest
from tests.legion_scale.dag_controller import DagMissionController
from tests.legion_scale import scale_oracle

pytestmark = [pytest.mark.unit, pytest.mark.local]
HERE = pathlib.Path(__file__).parent
CANARY = HERE / "manifests" / "LEGION-10-CANARY-005.json"
MAN = json.loads(CANARY.read_text())


def _ctl(tmp_path, effects=None, state=None):
    ctl = DagMissionController(MAN, "http://127.0.0.1:1", str(tmp_path / "events.jsonl"), observers=2)
    effs = effects if effects is not None else []
    st = state or {"stage_by_shard": dict(MAN["zero_state"]["stage_by_shard"]), "pid": 1}

    async def ns():
        return st

    async def ne():
        return list(effs)
    ctl.native_state, ctl.native_effects = ns, ne
    return ctl, effs


def _free():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _req(method, url, body=None, token=None):
    data = None if body is None else json.dumps(body).encode()
    r = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(r, timeout=5) as x:
            return x.status, json.loads(x.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


@pytest.fixture()
def target(tmp_path):
    port, tok = _free(), "test-token-123"
    env = {**os.environ, "SRE_TARGET_TOKEN": tok}
    p = subprocess.Popen([sys.executable, "-I", str(HERE / "scale_target.py"), str(port), str(tmp_path / "t.jsonl"), str(CANARY)], env=env)
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            _req("GET", f"{url}/state"); break
        except Exception:
            time.sleep(0.05)
    yield url, tok
    p.terminate(); p.wait(timeout=5)


# ------------------------------------------------ controller DAG
async def test_claim_refused_when_deps_open(tmp_path):
    ctl, _ = _ctl(tmp_path)
    d = await ctl.directive_for("L01-S01")
    assert d["directive"].startswith("NOT_ELIGIBLE")
    with pytest.raises(ValueError):
        await ctl.begin("L01-S01", "whatever")


async def test_double_begin_refused_and_close_requires_native_effect(tmp_path):
    ctl, effs = _ctl(tmp_path)
    d = await ctl.directive_for("L00-S00")
    assert d["directive"] == "ACT"
    await ctl.begin("L00-S00", d["command_id"])
    with pytest.raises(ValueError):
        await ctl.begin("L00-S00", d["command_id"])
    out = await ctl.close("L00-S00", d["command_id"])     # no native effect yet
    assert out["closed"] is False
    assert ctl.state["L00-S00"]["status"] == "PENDING"   # reopened
    ev = [json.loads(l) for l in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert any(e["event"] == "OBLIGATION_REOPENED_NO_EFFECT" for e in ev)
    assert all("t" in e and "mono" in e for e in ev)


async def test_close_with_native_effect_and_reconcile_nonlive_claim(tmp_path):
    ctl, effs = _ctl(tmp_path)
    d = await ctl.directive_for("L00-S00")
    await ctl.begin("L00-S00", d["command_id"])
    effs.append({"command_id": d["command_id"], "obligation_id": "L00-S00", "applied": True, "effect_id": "effect-x", "seq": 1})
    out = await ctl.close("L00-S00", d["command_id"])
    assert out["closed"] is True and ctl.state["L00-S00"]["effect_id"] == "effect-x"
    # second obligation: claim, drop liveness (simulated crash), reconcile from readback
    d2 = await ctl.directive_for("L01-S00")
    await ctl.begin("L01-S00", d2["command_id"])
    effs.append({"command_id": d2["command_id"], "obligation_id": "L01-S00", "applied": True, "effect_id": "effect-y", "seq": 2})
    ctl.release(d2["command_id"])
    view = await ctl.role_view("agent:legion-l01-s00")
    assert view["view"] == "OWN_STEP_COMPLETE" and ctl.state["L01-S00"]["status"] == "CLOSED"
    st = await ctl.status()
    assert st["closed"] == 2 and st["admitted"] is False


# ------------------------------------------------ target invariant
def test_target_409_out_of_order_and_duplicate_idempotent(target):
    url, tok = target
    body = {"command_id": "c1", "obligation_id": "L00-S01", "target_id": "service-shard-00", "stage": 1, "actor": "agent:legion-l00-s01", "system": "legion-synthetic-sre", "seal_sha256": "x", "params_hash": "y"}
    code, _ = _req("POST", f"{url}/apply", body, tok)
    assert code == 409
    assert _req("GET", f"{url}/effects")[1]["effects"] == []
    body.update(obligation_id="L00-S00", stage=0)
    code, r = _req("POST", f"{url}/apply", body, tok)
    assert code == 200 and r["status"] == "applied"
    code, r2 = _req("POST", f"{url}/apply", body, tok)
    assert code == 200 and r2["status"] == "duplicate"
    assert len(_req("GET", f"{url}/effects")[1]["effects"]) == 1
    assert _req("GET", f"{url}/state")[1]["stage_by_shard"]["service-shard-00"] == 0
    code, _ = _req("POST", f"{url}/apply", {**body, "command_id": "c2"}, "wrong-token")
    assert code == 401


# ------------------------------------------------ oracle rejects mutated evidence (pure joins)
def test_oracle_helpers_reject_mutations():
    assert scale_oracle.duplicate_values(["a", "b", "a"]) == ["a"]                     # duplicate decision_ref
    nodes = [{"obligation_id": "A", "dependencies": [], "agent_id": "agent:a"},
             {"obligation_id": "B", "dependencies": ["A"], "agent_id": "agent:b"}]
    claims = [{"obligation_id": "B", "t": 5.0}]
    closures = [{"obligation_id": "A", "t": 10.0}]
    effects = [{"obligation_id": "B", "applied_at": 6.0, "actor": "agent:b"}]
    assert scale_oracle.dependency_violations(nodes, claims, closures, effects)       # early dependency
    assert scale_oracle.actor_violations(nodes, [{"obligation_id": "A", "actor": "agent:evil"}])  # wrong actor
    assert not scale_oracle.actor_violations(nodes, [{"obligation_id": "A", "actor": "agent:a"}])




# ------------------------------------------------ oracle fail-closed gaps (GAP 1-5)
_MINI_MANIFEST = {
    "scenario_id": "MINI", "n_agents": 2,
    "nodes": [{"obligation_id": "A", "agent_id": "agent:a", "dependencies": []},
              {"obligation_id": "B", "agent_id": "agent:b", "dependencies": ["A"]}],
    "zero_state": {"stage_by_shard": {}}, "expected_final_state": {"stage_by_shard": {}},
}


def _jl_write(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def _provider(agent="agent:a", **over):
    row = {"agent": agent, "status": "OK", "http_status": 200, "provider_response_id": f"resp-{agent}",
           "t_start_mono": 10.0, "t_end_mono": 11.0,
           "response_content": json.dumps({"action": "done"})}
    row.update(over)
    return row


def _write_run(tmp_path, *, mode="MODEL_E2E", workers="valid", plog=None, commits=None, events=None, header_over=None):
    run = tmp_path / "run"; run.mkdir(parents=True, exist_ok=True)
    hdr = {"run_id": "unit-gap", "mode": mode, "t_episode_registered_mono": 1.0, "attempt_index": 1, "campaign": "legion-unit"}
    hdr.update(header_over or {})
    (run / "RUN_HEADER.json").write_text(json.dumps(hdr))
    if workers == "valid":
        _jl_write(run / "WORKERS.jsonl", [{"pid": 101, "agent_id": "agent:a"}, {"pid": 202, "agent_id": "agent:b"}])
    elif workers == "empty":
        (run / "WORKERS.jsonl").write_text("")
    elif workers == "missing":
        pass
    else:
        _jl_write(run / "WORKERS.jsonl", workers)
    _jl_write(run / "provider_log.jsonl", plog if plog is not None else [_provider(), _provider("agent:b")])
    _jl_write(run / "GATE_COMMITS.jsonl", commits if commits is not None else [{"decision_ref": "r1", "t_start_mono": 2.0, "t_end_mono": 3.0}])
    _jl_write(run / "SCALE_EVENTS.jsonl", events if events is not None else [
        {"event": "CLAIMED", "obligation_id": "A", "mono": 4.0},
        {"event": "OBLIGATION_CLOSED", "obligation_id": "A", "mono": 5.0}])
    return run


def _good_effects():
    return [{"effect_id": "e1", "obligation_id": "A", "applied_mono": 6.0, "applied_at": 999999.0}]


def test_gap_valid_mini_run_pure_checks_pass(tmp_path):
    checks = scale_oracle.pure_run_checks(_write_run(tmp_path), _MINI_MANIFEST, effects=_good_effects())
    assert checks["P0_evidence_files_parseable"]["ok"] is True
    assert checks["W1_worker_pids_distinct_n"]["ok"] is True
    assert checks["T0_monotonic_clock_present"]["ok"] is True
    assert checks["M1_n_distinct_agents_with_provider_ok_calls"]["ok"] is True
    assert checks["M2_registered_before_first_provider_call"]["ok"] is True
    assert checks["M3_first_attempt"]["ok"] is True


def test_gap1_missing_or_empty_workers_fails_W1(tmp_path):
    for kind in ("missing", "empty"):
        run = _write_run(tmp_path / kind, workers=kind)
        checks = scale_oracle.pure_run_checks(run, _MINI_MANIFEST, effects=_good_effects())
        assert "W1_worker_pids_distinct_n" in checks
        assert checks["W1_worker_pids_distinct_n"]["ok"] is False


def test_gap1_workers_wrong_count_duplicate_pid_or_agent_set_fails_W1(tmp_path):
    cases = [
        [{"pid": 101, "agent_id": "agent:a"}],  # count != n_agents
        [{"pid": 101, "agent_id": "agent:a"}, {"pid": 101, "agent_id": "agent:b"}],  # duplicate pid
        [{"pid": 101, "agent_id": "agent:a"}, {"pid": 202, "agent_id": "agent:evil"}],  # agent set mismatch
    ]
    for i, rows in enumerate(cases):
        run = _write_run(tmp_path / f"c{i}", workers=rows)
        assert scale_oracle.pure_run_checks(run, _MINI_MANIFEST, effects=_good_effects())["W1_worker_pids_distinct_n"]["ok"] is False


def test_gap4_failed_only_provider_call_fails_M1(tmp_path):
    bad_logs = [
        [_provider(status="ERROR"), _provider("agent:b")],
        [_provider(http_status=500), _provider("agent:b")],
        [_provider(provider_response_id=""), _provider("agent:b")],
        [_provider(provider_response_id=None), _provider("agent:b")],
    ]
    for i, plog in enumerate(bad_logs):
        run = _write_run(tmp_path / f"c{i}", plog=plog)
        checks = scale_oracle.pure_run_checks(run, _MINI_MANIFEST, effects=_good_effects())
        assert checks["M1_n_distinct_agents_with_provider_ok_calls"]["ok"] is False, plog
        assert checks["M1_n_distinct_agents_with_provider_ok_calls"]["agents_with_calls"] == ["agent:b"]


def test_gap2_registration_after_first_provider_call_fails_M2(tmp_path):
    run = _write_run(tmp_path, header_over={"t_episode_registered_mono": 10.5})  # after min t_start_mono=10.0
    checks = scale_oracle.pure_run_checks(run, _MINI_MANIFEST, effects=_good_effects())
    assert checks["M2_registered_before_first_provider_call"]["ok"] is False
    run2 = _write_run(tmp_path / "absent", header_over={"t_episode_registered_mono": None})
    assert scale_oracle.pure_run_checks(run2, _MINI_MANIFEST, effects=_good_effects())["M2_registered_before_first_provider_call"]["ok"] is False
    run3 = _write_run(tmp_path / "nocalls", plog=[])
    assert scale_oracle.pure_run_checks(run3, _MINI_MANIFEST, effects=_good_effects())["M2_registered_before_first_provider_call"]["ok"] is False


def test_gap2_first_attempt_fails_M3(tmp_path):
    for i, over in enumerate(({"attempt_index": 2}, {"attempt_index": None}, {"campaign": ""}, {"campaign": "  "}, {"campaign": None})):
        run = _write_run(tmp_path / f"c{i}", header_over=over)
        assert scale_oracle.pure_run_checks(run, _MINI_MANIFEST, effects=_good_effects())["M3_first_attempt"]["ok"] is False, over


def test_gap3_missing_mono_fails_T0(tmp_path):
    # effect lacking applied_mono (wall applied_at must not substitute)
    run = _write_run(tmp_path / "eff")
    assert scale_oracle.pure_run_checks(run, _MINI_MANIFEST, effects=[{"effect_id": "e1", "applied_at": 1.0}])["T0_monotonic_clock_present"]["ok"] is False
    # commit lacking a mono field
    run = _write_run(tmp_path / "commit", commits=[{"decision_ref": "r1", "t_start_mono": 2.0}])
    assert scale_oracle.pure_run_checks(run, _MINI_MANIFEST, effects=_good_effects())["T0_monotonic_clock_present"]["ok"] is False
    # provider record lacking a mono field
    bad = _provider(); del bad["t_end_mono"]
    run = _write_run(tmp_path / "prov", plog=[bad, _provider("agent:b")])
    assert scale_oracle.pure_run_checks(run, _MINI_MANIFEST, effects=_good_effects())["T0_monotonic_clock_present"]["ok"] is False
    # CLAIMED / OBLIGATION_CLOSED event lacking mono (wall t must not substitute)
    run = _write_run(tmp_path / "evt", events=[{"event": "CLAIMED", "obligation_id": "A", "t": 4.0},
                                              {"event": "OBLIGATION_CLOSED", "obligation_id": "A", "mono": 5.0}])
    assert scale_oracle.pure_run_checks(run, _MINI_MANIFEST, effects=_good_effects())["T0_monotonic_clock_present"]["ok"] is False


def _all_pass_checks(prefixes):
    return {f"{p}_check": {"ok": True} for p in prefixes}


def test_gap5_verdict_never_passes_when_required_check_missing():
    for mode, prefixes, good in (
        ("MODEL_E2E", scale_oracle.REQUIRED_MODEL_E2E, "LEGION_SCALE_E2E_PASSED"),
        ("INTEGRATION_ONLY", scale_oracle.REQUIRED_INTEGRATION_ONLY, "INTEGRATION_ONLY_SCALE_VERIFIED"),
    ):
        assert scale_oracle.compute_verdict(mode, _all_pass_checks(prefixes)) == good
        for missing in prefixes:
            checks = _all_pass_checks(prefixes); del checks[f"{missing}_check"]
            assert scale_oracle.compute_verdict(mode, checks) != good, (mode, missing)
            assert scale_oracle.compute_verdict(mode, checks) == "NOT_VERIFIED"
        checks = _all_pass_checks(prefixes); checks[f"{prefixes[0]}_check"] = {"ok": False}
        assert scale_oracle.compute_verdict(mode, checks) != good
    # pure checks alone (missing N/C/E/G/Z/F checks) can never yield a pass verdict
    assert scale_oracle.compute_verdict("MODEL_E2E", {}) == "NOT_VERIFIED"
    assert scale_oracle.compute_verdict("INTEGRATION_ONLY", {}) == "NOT_VERIFIED"


def test_oracle_process_rejects_missing_receipt_world(target, tmp_path):
    url, tok = target
    run = tmp_path / "run"; run.mkdir()
    body = {"command_id": "cx", "obligation_id": "L00-S00", "target_id": "service-shard-00", "stage": 0, "actor": "agent:legion-l00-s00", "system": "legion-synthetic-sre", "seal_sha256": "x", "params_hash": "y"}
    assert _req("POST", f"{url}/apply", body, tok)[0] == 200   # direct native effect: no CAGE receipt/commit at all
    (run / "NATIVE_STATE_BEFORE.json").write_text(json.dumps({"state": {"stage_by_shard": MAN["zero_state"]["stage_by_shard"]}, "effects": []}))
    (run / "RUN_HEADER.json").write_text(json.dumps({"run_id": "unit-mutated", "mode": "INTEGRATION_ONLY", "final_ledger": {"admitted": False}}))
    (run / "GATE_COMMITS.jsonl").write_text(json.dumps({"decision_ref": "dup", "outcome": "BLOCKED"}) + "\n" + json.dumps({"decision_ref": "dup", "outcome": "BLOCKED"}) + "\n")
    p = subprocess.run([sys.executable, "-I", str(HERE / "scale_oracle.py"), "--target", url, "--run-dir", str(run),
                        "--header", str(run / "RUN_HEADER.json"), "--manifest", str(CANARY), "--cage", os.getcwd()],
                       capture_output=True, text=True, env={**os.environ, "CAGE_ENV": "test", "CAGE_SEAL_STRICT_MODE": "false"}, timeout=60)
    verdict = json.loads((run / "ORACLE_VERDICT.json").read_text())
    assert verdict["verdict"] in ("NO_GO", "NOT_VERIFIED")
    assert "D1_decision_refs_unique" in verdict["failed_checks"]
    assert "E1_every_effect_exact_governance_chain" in verdict["failed_checks"]  # missing receipt/commit/seal join


def test_model_provider_429_retries_then_tool_called_once_with_successful_decision_ref(tmp_path):
    import http.server, threading, urllib.parse
    state = {"provider_calls": 0, "tool_calls": [], "complete": False}

    class Stub(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path == "/state":
                self._send(200, {"stage_by_shard": {"service-shard-00": -1}})
            elif path == "/obligations":
                view = "OWN_STEP_COMPLETE" if state["complete"] else "ACT_ELIGIBLE"
                self._send(200, {"view": view, "state_version": 2 if state["complete"] else 1})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            path = urllib.parse.urlparse(self.path).path
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                body = {}
            if path == "/v1/chat/completions":
                state["provider_calls"] += 1
                n = state["provider_calls"]
                if n <= 2:
                    self._send(429, {"error": "rate limited", "legion_proxy_log_id": f"proxy-429-{n}"})
                else:
                    content = json.dumps({"action": "call_tool", "tool": "apply_transition",
                                          "args": {"obligation_id": "L00-S00", "target_id": "service-shard-00", "stage": 0},
                                          "reason": "eligible"})
                    self._send(200, {"id": "resp-success-123", "legion_proxy_log_id": "proxy-ok-1",
                                     "choices": [{"message": {"content": content}}]})
            elif path == "/governance/validate-action":
                self._send(200, {"ok": True})
            elif path == "/tools/execute":
                state["tool_calls"].append(body)
                state["complete"] = True
                self._send(200, {"output": "applied"})
            else:
                self._send(404, {"error": "not found"})

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    log_path = tmp_path / "agent.jsonl"
    try:
        proc = subprocess.run(
            [sys.executable, "-I", str(HERE / "scale_agent.py"),
             "--agent-id", "agent:test-429", "--identity", "agent:test-429",
             "--obligation", "L00-S00", "--target", "service-shard-00", "--stage", "0",
             "--gateway", base, "--native", base, "--status", base, "--log", str(log_path),
             "--decider", "nim", "--proxy", base, "--proxy-token", "test-token", "--model", "test-model",
             "--max-model-turns", "1", "--wall-s", "60", "--poll-s", "0.05"],
            capture_output=True, text=True, timeout=60)
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=5)
    assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr, log_path.read_text() if log_path.exists() else "")
    assert state["provider_calls"] == 3
    assert len(state["tool_calls"]) == 1
    assert state["tool_calls"][0]["params"]["decision_ref"] == "resp-success-123"
    events = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    failed = [e for e in events if e.get("event") == "MODEL_CALL_FAILED"]
    assert [e["http_status"] for e in failed] == [429, 429]
    assert [e["proxy_log_id"] for e in failed] == ["proxy-429-1", "proxy-429-2"]
    assert not any(e.get("event") == "MODEL_PROVIDER_UNAVAILABLE" for e in events)


# ------------------------------------------------ torn evidence (P0) + atomic logger
def test_p0_torn_provider_log_fails_and_verdict_not_pass(tmp_path):
    run = _write_run(tmp_path)
    with open(run / "provider_log.jsonl", "a") as fh:
        fh.write('{"agent": "agent:a", "status": "OK", "response_content": "torn-mid-record\n')  # line 3: torn
    checks = scale_oracle.pure_run_checks(run, _MINI_MANIFEST, effects=_good_effects())
    assert checks["P0_evidence_files_parseable"]["ok"] is False
    errs = checks["P0_evidence_files_parseable"]["errors"]
    assert any(e["file"] == "provider_log.jsonl" and e["line"] == 3 for e in errs), errs
    verdict = scale_oracle.compute_verdict("MODEL_E2E", checks)
    assert verdict != "LEGION_SCALE_E2E_PASSED"
    assert verdict == "NOT_VERIFIED"
    # P0 alone blocks an otherwise all-passing required set
    all_pass = _all_pass_checks(scale_oracle.REQUIRED_MODEL_E2E)
    all_pass["P0_evidence_files_parseable"] = checks["P0_evidence_files_parseable"]
    assert scale_oracle.compute_verdict("MODEL_E2E", all_pass) == "NOT_VERIFIED"
    all_pass_i = _all_pass_checks(scale_oracle.REQUIRED_INTEGRATION_ONLY)
    all_pass_i["P0_evidence_files_parseable"] = checks["P0_evidence_files_parseable"]
    assert scale_oracle.compute_verdict("INTEGRATION_ONLY", all_pass_i) == "NOT_VERIFIED"


def test_scale_provider_logger_concurrent_large_records_no_torn_lines(tmp_path):
    import concurrent.futures, http.server, threading
    big_upstream = "y" * 40000

    class Stub(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            data = json.dumps({"id": "resp-stub-1", "model": "test-model",
                               "choices": [{"message": {"content": big_upstream}}],
                               "usage": {"total_tokens": 1}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    up_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    up_thread.start()
    key_file = tmp_path / "dummy.key"
    key_file.write_text("test-dummy-key")
    log_path = tmp_path / "provider_log.jsonl"
    port = _free()
    tokens = {f"tok-{i}": f"agent:{i}" for i in range(200)}
    proc = subprocess.Popen(
        [sys.executable, str(HERE / "scale_provider_logger.py"), str(port), str(log_path),
         json.dumps(tokens), f"http://127.0.0.1:{upstream.server_address[1]}", f"file:{key_file}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        deadline = time.time() + 15
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                if proc.poll() is not None or time.time() > deadline:
                    raise AssertionError(f"logger exited early rc={proc.poll()}")
                time.sleep(0.05)

        def fire(i):
            body = json.dumps({"model": "test-model",
                               "messages": [{"role": "user", "content": ("x" * 40000) + f"-{i}"}]}).encode()
            req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/chat/completions", data=body, method="POST",
                                         headers={"Content-Type": "application/json", "X-Legion-Proxy-Token": f"tok-{i}"})
            with urllib.request.urlopen(req, timeout=30) as r:
                assert r.status == 200
                json.loads(r.read())

        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
            list(ex.map(fire, range(200)))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        upstream.shutdown(); upstream.server_close(); up_thread.join(timeout=5)
    text = log_path.read_text()
    assert "test-dummy-key" not in text
    lines = [l for l in text.splitlines() if l.strip()]
    assert len(lines) == 200
    rows = [json.loads(l) for l in lines]  # every line must parse: no torn/interleaved records
    assert len({r["proxy_log_id"] for r in rows}) == 200
    assert {r["agent"] for r in rows} == {f"agent:{i}" for i in range(200)}
