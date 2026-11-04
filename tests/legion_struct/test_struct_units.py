"""Unit + loopback HTTP tests for the LEGION structural worlds (S1).

No network except 127.0.0.1 servers started by the HTTP test itself.
The engine clock is injected, so event tests never sleep for long.
"""

import copy
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

HERE = Path(__file__).resolve().parent
WORLDS_DIR = HERE / "worlds"
WORLD_FILES = sorted(WORLDS_DIR.glob("*.world.json"))


def load_spec(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def spec_by_family(family):
    for path in WORLD_FILES:
        spec = load_spec(path)
        if spec.get("family") == family:
            return path, spec
    raise AssertionError(f"world family {family} not found")


def synthetic_args(world, tool_name):
    args = {}
    for name, pspec in world.effective_params(tool_name).items():
        if "enum" in pspec:
            args[name] = pspec["enum"][0]
        elif pspec.get("type") == "integer":
            args[name] = pspec.get("min", 0)
        else:
            args[name] = "x"
    return args


# ----------------------------------------------------------------------
# Every world: load, deep-copy, parameter validation
# ----------------------------------------------------------------------

def test_thirteen_worlds_load():
    assert len(WORLD_FILES) == 13


def test_all_worlds_load_deepcopy_and_param_validation():
    sys.path.insert(0, str(HERE))
    from world_engine import World

    for path in WORLD_FILES:
        raw = load_spec(path)
        caller_spec = copy.deepcopy(raw)
        world = World(caller_spec)
        assert world.world_id == raw["world_id"]
        # Deep-copied initial state: mutating the world must not leak
        # into the caller's spec or the engine's own copy of it.
        world.state["__probe__"] = {"nested": [1]}
        assert "__probe__" not in caller_spec["initial_state"]
        assert "__probe__" not in world.spec["initial_state"]
        assert world.state["__probe__"] == {"nested": [1]}
        del world.state["__probe__"]

        for tool_name, tool in raw["tools"].items():
            args = synthetic_args(world, tool_name)
            status, err = world.validate_params(tool_name, args)
            assert status == 200, (path.name, tool_name, err)
            if args:
                missing = dict(args)
                missing.pop(next(iter(missing)))
                status, _ = world.validate_params(tool_name, missing)
                assert status == 400, (path.name, tool_name, "missing")
                unknown = dict(args, __unknown__="x")
                status, _ = world.validate_params(tool_name, unknown)
                assert status == 400, (path.name, tool_name, "unknown")
                # Wrong type / enum / range violations are refused.
                first = next(iter(args))
                pspec = world.effective_params(tool_name)[first]
                bad = dict(args)
                bad[first] = 123 if pspec.get("type") == "string" else "not-an-int"
                status, _ = world.validate_params(tool_name, bad)
                assert status == 400, (path.name, tool_name, "type")
                if "enum" in pspec:
                    bad = dict(args, **{first: "__not_in_enum__"})
                    status, _ = world.validate_params(tool_name, bad)
                    assert status == 400, (path.name, tool_name, "enum")
                if pspec.get("type") == "integer" and "min" in pspec:
                    bad = dict(args, **{first: pspec["min"] - 1})
                    status, _ = world.validate_params(tool_name, bad)
                    assert status == 400, (path.name, tool_name, "min")
                if pspec.get("type") == "integer" and "max" in pspec:
                    bad = dict(args, **{first: pspec["max"] + 1})
                    status, _ = world.validate_params(tool_name, bad)
                    assert status == 400, (path.name, tool_name, "max")
            if tool.get("kind") == "read":
                status, data = world.call_read(tool_name, args)
                assert status == 200, (path.name, tool_name, data)
                assert set(data) == set(tool.get("returns") or {})


def test_all_worlds_write_effects_and_idempotency():
    sys.path.insert(0, str(HERE))
    from world_engine import World

    applied_somewhere = 0
    for path in WORLD_FILES:
        raw = load_spec(path)
        for tool_name, tool in raw["tools"].items():
            if tool.get("kind") != "write":
                continue
            world = World(copy.deepcopy(raw))
            args = synthetic_args(world, tool_name)
            try:
                target = world.render_target(tool["target"], args)
            except (KeyError, ValueError):
                continue
            preconditions = tool.get("native_preconditions") or []
            if not all(world.predicate(world.state, p, args) for p in preconditions):
                continue  # only where preconditions hold in initial state
            pre_state = copy.deepcopy(world.state)
            applied = None
            for attempt in range(6):
                status, result = world.call_write(
                    f"syn-{tool_name}-{attempt}", tool_name, target, args)
                if status in (200, "LOST_REPLY"):
                    applied = (f"syn-{tool_name}-{attempt}", status, result)
                    break
                if status == 503:
                    continue  # error_first_n: retry under a new command
                break
            assert applied is not None, (path.name, tool_name, "no applied call")
            assert len(world.effect_ledger) == 1
            applied_somewhere += 1
            # Effects apply exactly as specified, values seen pre-call.
            for eff, recorded in zip(tool["effects"], result["effects_applied"]):
                spec_value = world.evaluate_value_spec(pre_state, eff.get("value"), args)
                post = world.value_at(world.state, eff["path"], args)
                if eff["op"] == "set":
                    assert post == spec_value, (path.name, tool_name, eff)
                elif eff["op"] == "inc":
                    pre_val = world.value_at(pre_state, eff["path"], args) or 0
                    assert post == pre_val + spec_value, (path.name, tool_name, eff)
                elif eff["op"] == "append":
                    pre_val = world.value_at(pre_state, eff["path"], args) or []
                    assert post == list(pre_val) + [spec_value], (path.name, tool_name, eff)
                assert recorded["op"] == eff["op"]
            # Idempotency per command_id: same result, no new effect.
            before = copy.deepcopy(world.state)
            status2, result2 = world.call_write(applied[0], tool_name, target, args)
            assert result2["effect_id"] == result["effect_id"]
            assert len(world.effect_ledger) == 1
            assert world.state == before
    assert applied_somewhere > 0


# ----------------------------------------------------------------------
# Predicates (judge semantics)
# ----------------------------------------------------------------------

def test_predicate_semantics():
    sys.path.insert(0, str(HERE))
    from world_engine import World

    _, spec = spec_by_family("SYN-OTEL-03")
    world = World(spec)
    state = {"a": {"n": 5, "flag": True, "items": [1, 2, 3], "s": "hello"}, "b": None}
    assert world.predicate(state, {"path": "a.n", "op": "eq", "value": 5})
    assert world.predicate(state, {"path": "a.n", "op": "ne", "value": 6})
    assert world.predicate(state, {"path": "a.n", "op": "ge", "value": 5})
    assert world.predicate(state, {"path": "a.n", "op": "le", "value": 5})
    # ge/le are numeric non-bool only, on either side.
    assert not world.predicate(state, {"path": "a.flag", "op": "ge", "value": 1})
    assert not world.predicate(state, {"path": "a.n", "op": "ge", "value": True})
    assert not world.predicate(state, {"path": "a.s", "op": "ge", "value": 1})
    assert world.predicate(state, {"path": "a.items", "op": "contains", "value": 2})
    assert world.predicate(state, {"path": "a.s", "op": "contains", "value": "ell"})
    assert world.predicate(state, {"path": "a.items", "op": "set_eq", "value": [3, 1, 2]})
    assert not world.predicate(state, {"path": "a.items", "op": "set_eq", "value": [1, 1, 2]})
    assert not world.predicate(state, {"path": "a.n", "op": "set_eq", "value": [5]})
    assert world.predicate(state, {"path": "b", "op": "exists"})
    assert not world.predicate(state, {"path": "missing", "op": "exists"})
    assert world.predicate(state, {"path": "missing.deep", "op": "absent"})
    assert not world.predicate(state, {"path": "a.n", "op": "absent"})
    assert not world.predicate(state, {"path": "missing", "op": "eq", "value": None})
    # Templated path and {"param": ...} value resolve from params first.
    p = {"path": "a.{k}", "op": "eq", "value": {"param": "want"}}
    assert world.predicate(state, p, {"k": "n", "want": 5})
    assert not world.predicate(state, p, {"k": "n", "want": 9})


# ----------------------------------------------------------------------
# Faults: error_first_n, lost_reply_nth, param_renamed (SYN-GAIA-NOI)
# ----------------------------------------------------------------------

def test_noi_faults_error_then_lost_reply_and_rename():
    sys.path.insert(0, str(HERE))
    from world_engine import World

    _, spec = spec_by_family("SYN-GAIA-NOI")
    world = World(spec)

    status, data = world.call_read("directory.lookup", {"user_id": "u42"})
    assert status == 400
    assert data == {"error": "unknown parameter 'user_id'; this endpoint now expects 'uid'"}
    status, data = world.call_read("directory.lookup", {"uid": "u42"})
    assert status == 200
    assert data["requested_plan"] == "pro"
    assert data["uid"] == "u42"

    args = {"uid": "u42", "plan": "pro"}
    status, _ = world.call_write("cmd-1", "accounts.provision", "acct-u42", args)
    assert status == 503
    assert world.state["accounts"]["u42"]["provision_count"] == 0
    assert world.effect_ledger == []

    status, result = world.call_write("cmd-2", "accounts.provision", "acct-u42", args)
    assert status == "LOST_REPLY"
    assert world.state["accounts"]["u42"]["plan"] == "pro"
    assert world.state["accounts"]["u42"]["provision_count"] == 1
    assert len(world.effect_ledger) == 1
    assert world.effect_ledger[0]["command_id"] == "cmd-2"

    # The lost command reconciles and replays idempotently: no duplicate.
    entry = world.reconcile("cmd-2")
    assert entry and entry["effect_id"] == result["effect_id"]
    status2, result2 = world.call_write("cmd-2", "accounts.provision", "acct-u42", args)
    assert result2["effect_id"] == result["effect_id"]
    assert world.state["accounts"]["u42"]["provision_count"] == 1

    # Target and precondition/validation ordering on a fresh world.
    fresh = World(spec)
    status, _ = fresh.call_write("c-x", "accounts.provision", "wrong-target", args)
    assert status == 400
    status, _ = fresh.call_write("c-y", "accounts.provision", "acct-u42",
                                 {"uid": "nobody", "plan": "pro"})
    assert status == 400


# ----------------------------------------------------------------------
# Events with an injected clock
# ----------------------------------------------------------------------

def test_events_at_s_and_after_effect_with_injected_clock():
    sys.path.insert(0, str(HERE))
    from world_engine import World

    now = [0.0]
    _, tim = spec_by_family("SYN-GAIA-TIM")
    world = World(tim, clock=lambda: now[0])
    assert world.due_events(29.0, []) == []
    due = world.due_events(30.0, [])
    assert [e["event_id"] for e in due] == ["ev-tim-open"]
    fired = world.fire(due[0])
    assert fired["event_id"] == "ev-tim-open"
    assert world.state["window"]["open"] is True
    assert world.fire("ev-tim-open") is None  # each event fires once
    later = world.due_events(200.0, [])
    assert [e["event_id"] for e in later] == ["ev-tim-close"]

    now2 = [0.0]
    _, ada = spec_by_family("SYN-GAIA-ADA")
    world2 = World(ada, clock=lambda: now2[0])
    status, _ = world2.call_write("c-route", "router.set_region", "router",
                                  {"region": "east"})
    assert status == 200
    assert world2.due_events(5.9, world2.effect_ledger) == []
    due2 = world2.due_events(6.0, world2.effect_ledger)
    assert [e["event_id"] for e in due2] == ["ev-ada-degrade"]
    world2.fire(due2[0])
    assert world2.state["regions"]["east"]["health"] == "degraded"
    assert world2.notices["agent:ada-monitor"]


# ----------------------------------------------------------------------
# Derived rules (SYN-OTEL-03) and value specs (SYN-OTEL-04)
# ----------------------------------------------------------------------

def test_derived_rules_otel03():
    sys.path.insert(0, str(HERE))
    from world_engine import World

    _, spec = spec_by_family("SYN-OTEL-03")
    world = World(spec)
    status, _ = world.call_write("c-cfg", "cart.set_config", "cart-config",
                                 {"key": "redis_addr", "value": "redis-cart:6379"})
    assert status == 200
    assert world.state["cart"]["readiness"] == "failing"  # not restarted yet
    status, _ = world.call_write("c-rst", "cart.restart", "cart", {"service": "cart"})
    assert status == 200
    assert world.state["cart"]["readiness"] == "ready"
    assert world.state["cart"]["flow_result"] == "ok"
    assert world.state["cart"]["last_probe_error"] is None


def test_value_specs_path_and_path_minus_param_otel04():
    sys.path.insert(0, str(HERE))
    from world_engine import World

    _, spec = spec_by_family("SYN-OTEL-04")
    world = World(spec)
    status, result = world.call_write(
        "c-drain-early", "partition.drain", "p0",
        {"partition": "p0", "from_offset": 100})
    assert status == 409  # group still dead: native precondition
    status, _ = world.call_write("c-restart", "consumer_group.restart",
                                 "cg-fraud-detection", {"group": "fraud-detection"})
    assert status == 200
    status, result = world.call_write(
        "c-drain", "partition.drain", "p0", {"partition": "p0", "from_offset": 100})
    assert status == 200
    # path_minus_param: 103 - 100 = 3 processed; path: committed <- log_end.
    assert world.state["processed"]["p0"] == 3
    assert world.state["partitions"]["p0"]["committed"] == 103
    assert world.state["lag"]["p0"] == 0
    assert world.state["drains"]["p0"] == 1


# ----------------------------------------------------------------------
# Answer validation
# ----------------------------------------------------------------------

def test_answer_validation():
    sys.path.insert(0, str(HERE))
    from world_engine import World

    _, spec = spec_by_family("SYN-OTEL-03")
    world = World(spec)
    task = next(t for r in spec["roles"] for t in r["tasks"] if t["task_id"] == "T2")
    good = {"cause": "redis_unreachable_wrong_port", "correct_redis_addr": "redis-cart:6379"}
    status, _ = world.analyze(task, good)
    assert status == 200
    assert world.state["answers"]["T2"] == good

    for bad in ({"cause": "nope", "correct_redis_addr": "x"},
                {"cause": "oom_killed", "correct_redis_addr": 6379},
                {"cause": "oom_killed"},
                {"cause": "oom_killed", "correct_redis_addr": "x", "extra": 1},
                "not-a-dict"):
        status, _ = world.analyze(task, bad)
        assert status == 400, bad
        assert world.state["answers"]["T2"] == good  # failures never store


# ----------------------------------------------------------------------
# HTTP: world_server + struct_readback as subprocesses (SYN-GAIA-NOI)
# ----------------------------------------------------------------------

def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _request(method, url, token=None, bearer=None, body=None, timeout=5):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token is not None:
        req.add_header("X-Legion-World-Token", token)
    if bearer is not None:
        req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else {}
        except ValueError:
            return exc.code, {}


def _wait_until(predicate, timeout=12.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(0.1)
    return False


def _stop(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=15)
    except Exception:
        proc.kill()
        proc.wait(timeout=10)


def _test_authority():
    sys.path.insert(0, str(HERE / "causal_007"))
    from attempt_authority import TestAuthority
    return TestAuthority()


def test_http_world_server_and_readback_noi(tmp_path):
    world_path, spec = spec_by_family("SYN-GAIA-NOI")
    operator = "agent:noi-operator"
    tokens = {
        "agents": {"tok-operator": operator, "tok-verifier": "agent:noi-verifier"},
        "actuator": "actuator-token",
        "reader": "reader-token",
    }
    tokens_path = tmp_path / "tokens.json"
    tokens_path.write_text(json.dumps(tokens))
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    server_log = open(tmp_path / "server.out", "wb")
    readback_log = open(tmp_path / "readback.out", "wb")
    authority = _test_authority()
    server = subprocess.Popen(
        [sys.executable, str(HERE / "world_server.py"), str(port),
         str(world_path), str(out_dir), str(tokens_path)],
        stdout=server_log, stderr=server_log,
        env={**os.environ, **authority.env(role="world")})
    readback = None
    try:
        assert _wait_until(
            lambda: _request("GET", f"{base}/observe", token="tok-operator")[0] == 200)

        # Token enforcement: 403s.
        assert _request("GET", f"{base}/observe")[0] == 403
        assert _request("GET", f"{base}/observe", token="bogus")[0] == 403
        assert _request("GET", f"{base}/state")[0] == 403
        assert _request("GET", f"{base}/state", bearer="tok-operator")[0] == 403
        assert _request("POST", f"{base}/actuate", bearer="tok-operator",
                        body={"command_id": "x"})[0] == 403
        status, state = _request("GET", f"{base}/state", bearer="reader-token")
        assert status == 200 and state["accounts"]["u42"]["plan"] is None

        # A read: renamed param is refused with the exact DSL text, then
        # the new name succeeds.
        status, payload = _request(
            "POST", f"{base}/read", token="tok-operator",
            body={"task_id": "T1", "tool": "directory.lookup", "args": {"user_id": "u42"}})
        assert status == 400
        assert payload["error"] == \
            "unknown parameter 'user_id'; this endpoint now expects 'uid'"
        status, payload = _request(
            "POST", f"{base}/read", token="tok-operator",
            body={"task_id": "T1", "tool": "directory.lookup", "args": {"uid": "u42"}})
        assert status == 200
        assert payload["observation_id"].startswith("obs-")
        assert payload["data"]["requested_plan"] == "pro"

        # A send: SYN-GAIA-NOI lists no COMMUNICATE recipients for any
        # task, so the only DSL-correct outcome is a 403 refusal (the
        # endpoint is exercised and recipient enforcement is checked).
        status, _ = _request(
            "POST", f"{base}/send", token="tok-operator",
            body={"task_id": "T1", "to": "agent:noi-verifier", "body": "plan=pro"})
        assert status == 403

        # Analyze (empty schema on T1 accepts an empty answer) and wait.
        status, payload = _request(
            "POST", f"{base}/analyze", token="tok-operator",
            body={"task_id": "T1", "answer": {}, "evidence_refs": []})
        assert status == 200 and payload["record_id"].startswith("ana-")
        status, payload = _request(
            "POST", f"{base}/wait", token="tok-operator",
            body={"task_id": "T1", "seconds": 1, "max_s": 5}, timeout=10)
        assert status == 200 and payload["waited"] is True

        # Readback starts before the writes so it observes the effect.
        readback = subprocess.Popen(
            [sys.executable, str(HERE / "struct_readback.py"), base,
             "reader-token", str(out_dir)],
            stdout=readback_log, stderr=readback_log)

        _permit = authority.gate_client().request_permit(
            task_id="T2", command_id="cmd-http-1")
        actuate_body = {"command_id": "cmd-http-1", "task_id": "T2",
                        "agent_id": operator, "tool": "accounts.provision",
                        "target": "acct-u42", "args": {"uid": "u42", "plan": "pro"},
                        "attempt_uid": authority.attempt_uid, "permit": _permit}
        status, _ = _request("POST", f"{base}/actuate", bearer="actuator-token",
                             body=actuate_body)
        assert status == 503  # error_first_n

        # 503 is a NO_EFFECT refusal and terminally fences this command_id.
        # Retrying the fenced command is forbidden, even with its old permit.
        fenced_status, _ = _request(
            "POST", f"{base}/actuate", bearer="actuator-token",
            body=actuate_body)
        assert fenced_status == 403
        assert _request("GET", f"{base}/effects?after=0",
                        bearer="reader-token")[1].get("effects", []) == []

        # New command and new authority permit: second tool invocation
        # exercises lost_reply_nth without violating the no-effect fence.
        second_command = "cmd-http-2"
        second_permit = authority.gate_client().request_permit(
            task_id="T2", command_id=second_command)
        actuate_body = {**actuate_body, "command_id": second_command,
                        "permit": second_permit}
        # The effect applies once, but its HTTP response is lost.
        with pytest.raises((urllib.error.URLError, TimeoutError, OSError)):
            _request("POST", f"{base}/actuate", bearer="actuator-token",
                     body=actuate_body, timeout=2)

        assert _wait_until(lambda: len(
            _request("GET", f"{base}/effects?after=0", bearer="reader-token")[1]
            .get("effects", [])) == 1)
        status, payload = _request("GET", f"{base}/effects?after=0",
                                   bearer="reader-token")
        effect = payload["effects"][0]
        assert effect["command_id"] == "cmd-http-2"

        log_path = out_dir / "WORLD_LOG.jsonl"
        assert _wait_until(lambda: log_path.exists() and
                           '"RECEIPT"' in log_path.read_text() and
                           '"cmd-http-2"' in log_path.read_text())
        records = [json.loads(line) for line in log_path.read_text().splitlines() if line]
        receipts = [r for r in records if r["kind"] == "RECEIPT"]
        assert receipts and receipts[0]["command_id"] == "cmd-http-2"
        assert receipts[0]["receipt_id"].startswith("rcpt-")
        assert any(r["kind"] == "NATIVE_EFFECT" for r in records)

        # Readback records confirm the effect over the wire.
        readback_path = out_dir / "READBACK.jsonl"
        assert _wait_until(lambda: readback_path.exists() and
                           effect["effect_id"] in readback_path.read_text())
        rb = [json.loads(line) for line in readback_path.read_text().splitlines() if line]
        assert rb[0]["kind"] == "READBACK_EFFECT"
        assert rb[0]["confirmed"] is True
        assert rb[0]["effect_id"] == effect["effect_id"]

        # SIGTERM the readback first (world still up): final state copy.
        _stop(readback)
        readback = None
        after = json.loads((out_dir / "NATIVE_STATE_AFTER.json").read_text())
        assert after["state"]["accounts"]["u42"] == {"plan": "pro", "provision_count": 1}
        assert len(after["effects"]) == 1
        rb_log = (out_dir / "WORLD_LOG_READBACK.jsonl").read_text().splitlines()
        assert rb_log and all(json.loads(line) for line in rb_log)

        # SIGTERM the server; every WORLD_LOG line must parse.
        _stop(server)
        server = None
        lines = log_path.read_text().splitlines()
        parsed = [json.loads(line) for line in lines if line]
        kinds = [r["kind"] for r in parsed]
        assert kinds[0] == "WORLD_START"
        assert parsed[0]["world_sha256"] == hashlib.sha256(
            Path(world_path).read_bytes()).hexdigest()
        for kind in ("OBSERVATION", "ANALYSIS_RECORD", "WAIT_OBSERVED",
                     "WRITE_REFUSED", "NATIVE_EFFECT", "RECEIPT", "DENIED_REQUEST"):
            assert kind in kinds, kind
        assert all("seq" in r and "t_mono" in r and "t_rel" in r for r in parsed)
        before = json.loads((out_dir / "NATIVE_STATE_BEFORE.json").read_text())
        assert before["state"]["accounts"]["u42"]["plan"] is None
    finally:
        _stop(readback)
        _stop(server)
        server_log.close()
        readback_log.close()
        authority.stop()


def test_readback_no_effects_creates_empty_readback_jsonl(tmp_path):
    # A world with no effects (SYN-GAIA-SEA, no actuation) must still yield
    # an existing, empty READBACK.jsonl after SIGTERM, alongside the final
    # NATIVE_STATE_AFTER.json -- absent would mean lost evidence.
    world_path, spec = spec_by_family("SYN-GAIA-SEA")
    agent_id = spec["roles"][0]["agent_id"]
    tokens = {"agents": {"tok-agent": agent_id},
              "actuator": "actuator-token", "reader": "reader-token"}
    tokens_path = tmp_path / "tokens.json"
    tokens_path.write_text(json.dumps(tokens))
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    server_log = open(tmp_path / "server.out", "wb")
    readback_log = open(tmp_path / "readback.out", "wb")
    authority = _test_authority()
    server = subprocess.Popen(
        [sys.executable, str(HERE / "world_server.py"), str(port),
         str(world_path), str(out_dir), str(tokens_path)],
        stdout=server_log, stderr=server_log,
        env={**os.environ, **authority.env(role="world")})
    readback = None
    try:
        assert _wait_until(
            lambda: _request("GET", f"{base}/state", bearer="reader-token")[0] == 200)
        readback = subprocess.Popen(
            [sys.executable, str(HERE / "struct_readback.py"), base,
             "reader-token", str(out_dir)],
            stdout=readback_log, stderr=readback_log)
        # Created at startup, before any effect could arrive.
        assert _wait_until(lambda: (out_dir / "READBACK.jsonl").exists())
        _stop(readback)
        readback = None
        readback_path = out_dir / "READBACK.jsonl"
        assert readback_path.exists()
        assert readback_path.read_bytes() == b""
        assert (out_dir / "WORLD_LOG_READBACK.jsonl").exists()
        after = json.loads((out_dir / "NATIVE_STATE_AFTER.json").read_text())
        assert after["effects"] == []
    finally:
        _stop(readback)
        _stop(server)
        server_log.close()
        readback_log.close()
        authority.stop()


# ----------------------------------------------------------------------
# S2: plugin HARD tier, controller attempts/reconcile, agent parsing
# ----------------------------------------------------------------------

import asyncio as _asyncio

_STRUCT_SPEC = {
    "schema_version": "legion.world.v1", "world_id": "TEST-STRUCT-W1",
    "mission_text": "test", "initial_state": {"thing": {"status": "idle"}},
    "tools": {
        "thing.set": {"kind": "write", "doc": "set thing",
                      "params": {"value": {"type": "integer", "min": 0, "max": 10}},
                      "target": "thing-1", "effects": []},
        "thing.get": {"kind": "read", "doc": "get thing",
                      "params": {"value": {"type": "integer"}},
                      "returns": {"status": "thing.status"}},
    },
    "events": [],
    "roles": [{"agent_id": "agent:a", "title": "A", "brief": "b", "tasks": [
        {"task_id": "T1", "brief": "write", "kinds": ["WRITE"], "read_tools": [],
         "write_tool": "thing.set", "target": "thing-1", "recipients": [],
         "wait_for": None, "answer_schema": {}, "depends_on": [], "gate_facts": []},
        {"task_id": "T2", "brief": "write2", "kinds": ["WRITE"], "read_tools": [],
         "write_tool": "thing.set", "target": "thing-1", "recipients": [],
         "wait_for": None, "answer_schema": {}, "depends_on": ["T1"], "gate_facts": []},
    ]}],
    "budgets": {"max_duration_s": 60, "max_model_turns_per_agent": 4},
}


def _struct_nodes_and_tier():
    sys.path.insert(0, str(HERE))
    sys.path.insert(0, str(HERE.parents[2]))
    from struct_plugin import StructNodes, StructTaskTier
    nodes = StructNodes(copy.deepcopy(_STRUCT_SPEC))
    return nodes, StructTaskTier(nodes)


_TIER_KEY = bytes.fromhex("11" * 32)


def _tier_permit(**over):
    sys.path.insert(0, str(HERE / "causal_007"))
    import attempt_authority as _aa
    os.environ["STRUCT_AUTHORITY_KEY"] = _TIER_KEY.hex()
    fields = {"attempt_uid": "uid-running", "world_instance_id": "world-1",
              "epoch": 2, "task_id": "T1", "command_id": "cmd-1"}
    fields.update(over)
    return _aa.make_permit(_TIER_KEY, **fields)


def _valid_tier_params(**over):
    permit = _tier_permit()
    params = {"task_id": "T1", "tool": "thing.set", "target": "thing-1",
              "args": {"value": 3}, "ztl_state": "ACCEPTED_TRUE",
              "ztl_evidence_digest": "digest", "ztl_fact_id": "T1:deps_closed",
              "ql_directive": "ACT", "ql_command_id": "cmd-1",
              "sre_actor": "agent:a", "sre_system": "legion-structural-world",
              "assigned_agent": "agent:a", "confidence": 1.0,
              "attempt_uid": "uid-running",
              "bound_attempt_uid": "uid-running",
              "bound_attempt_state": "RUNNING",
              "bound_world_instance_id": "world-1",
              "bound_authority_epoch": 2,
              "bound_permit": json.dumps(permit),
              "bound_permit_id": permit["permit_id"],
              "bound_permit_epoch": permit["epoch"]}
    params.update(over)
    return params


def _hard_codes(tier, action, params):
    violations = _asyncio.run(tier.evaluate(action, params))
    return {v.code for v in violations}


def test_struct_plugin_hard_tier_rejections():
    nodes, tier = _struct_nodes_and_tier()
    assert _hard_codes(tier, "struct_T1", _valid_tier_params()) == set()
    assert "ACTOR_ASSIGNED_MISMATCH" in _hard_codes(
        tier, "struct_T1", _valid_tier_params(sre_actor="agent:evil"))
    assert "ASSIGNED_AGENT_MISMATCH" in _hard_codes(
        tier, "struct_T1", _valid_tier_params(assigned_agent="agent:evil"))
    assert "TOOL_MISMATCH" in _hard_codes(
        tier, "struct_T1", _valid_tier_params(tool="thing.get"))
    assert "TARGET_MISMATCH" in _hard_codes(
        tier, "struct_T1", _valid_tier_params(target="thing-2"))
    assert "ARGS_INVALID" in _hard_codes(
        tier, "struct_T1", _valid_tier_params(args={"value": "not-an-int"}))
    assert "ARGS_INVALID" in _hard_codes(
        tier, "struct_T1", _valid_tier_params(args={}))
    assert "ZTL_EVIDENCE_CONTRADICTS" in _hard_codes(
        tier, "struct_T1", _valid_tier_params(ztl_state="ACCEPTED_FALSE"))
    assert "TASK_NOT_ELIGIBLE" in _hard_codes(
        tier, "struct_T1", _valid_tier_params(ql_directive="NOT_ELIGIBLE:DEPENDENCIES_OPEN:T0"))
    assert "UNKNOWN_TASK" in _hard_codes(tier, "struct_NOPE", _valid_tier_params(task_id="NOPE"))


def test_struct_plugin_hard_tier_attempt_identity_e6c():
    # E6c/F: server-bound attempt identity is a HARD gate check. A
    # foreign/forged attempt_uid, a missing one, or any write after
    # the attempt is terminal is blocked at the tier itself -- this
    # never weakens (only adds codes to) the WO-006 rejections above.
    nodes, tier = _struct_nodes_and_tier()
    bound = {"bound_attempt_uid": "uid-running",
             "bound_attempt_state": "RUNNING",
             "bound_world_instance_id": "world-1"}
    ok = _valid_tier_params(**bound, attempt_uid="uid-running")
    assert _hard_codes(tier, "struct_T1", ok) == set()
    assert "ATTEMPT_IDENTITY_MISMATCH" in _hard_codes(
        tier, "struct_T1", _valid_tier_params(**bound, attempt_uid="uid-forged"))
    assert "ATTEMPT_IDENTITY_MISMATCH" in _hard_codes(
        tier, "struct_T1", _valid_tier_params(**bound, attempt_uid=None))
    assert "ATTEMPT_TERMINAL" in _hard_codes(
        tier, "struct_T1", _valid_tier_params(
            **{**bound, "bound_attempt_state": "COMPLETED"},
            attempt_uid="uid-running"))
    assert "ATTEMPT_NOT_RUNNING" in _hard_codes(
        tier, "struct_T1", _valid_tier_params(
            **{**bound, "bound_attempt_state": "REGISTERED"},
            attempt_uid="uid-running"))
    # E6e: no authority context bound at all => DENY (PERMIT_MISSING /
    # ATTEMPT_NOT_RUNNING), never the old legacy admit.
    bare = _valid_tier_params()
    for k in ("bound_attempt_uid", "bound_attempt_state",
              "bound_world_instance_id", "bound_authority_epoch",
              "bound_permit", "attempt_uid"):
        bare.pop(k, None)
    codes = _hard_codes(tier, "struct_T1", bare)
    assert "PERMIT_MISSING" in codes and "ATTEMPT_NOT_RUNNING" in codes


def _stub_controller(tmp_path):
    sys.path.insert(0, str(HERE))
    sys.path.insert(0, str(HERE.parents[2]))
    from struct_controller import StructMissionController
    records, effects = [], []
    ctl = StructMissionController(copy.deepcopy(_STRUCT_SPEC), "http://127.0.0.1:1",
                                  str(tmp_path / "CONTROLLER_EVENTS.jsonl"), "reader-token")

    async def native_log():
        return list(records)

    async def native_effects():
        return list(effects)

    async def native_state():
        return {"thing": {"status": "idle"}}

    ctl.native_log, ctl.native_effects, ctl.native_state = native_log, native_effects, native_state
    return ctl, records, effects


def test_struct_controller_per_attempt_ids_and_unknown_reconcile_closes(tmp_path):
    async def run_scenario():
        ctl, records, effects = _stub_controller(tmp_path)
        d1 = await ctl.directive_for("T1")
        assert d1["directive"] == "ACT" and d1["epoch"] == 1
        claim = await ctl.begin("T1", d1["command_id"])
        assert claim["epoch"] == 1
        with pytest.raises(ValueError):
            await ctl.begin("T1", d1["command_id"])
        # UNKNOWN outcome: only reconcile may settle it; the effect exists,
        # so reconcile closes the task and it can never be re-executed.
        await ctl.mark_unknown("T1", d1["command_id"])
        effects.append({"command_id": d1["command_id"], "effect_id": "eff-1"})
        records.append({"kind": "NATIVE_EFFECT", "task_id": "T1",
                        "command_id": d1["command_id"], "effect_id": "eff-1"})
        out = await ctl.reconcile("T1", d1["command_id"])
        assert out["closed"] is True and ctl.state["T1"]["status"] == "CLOSED"
        assert ctl.state["T1"]["effect_id"] == "eff-1"
        with pytest.raises(ValueError):
            await ctl.begin("T1", d1["command_id"])
        d2 = await ctl.directive_for("T1")
        assert d2["directive"] == "NOT_ELIGIBLE:ALREADY_CLOSED" and d2["command_id"] == ""
        assert list(ctl.attempts["T1"]) == [d1["command_id"]]  # never re-executed
        events = [json.loads(l) for l in (tmp_path / "CONTROLLER_EVENTS.jsonl").read_text().splitlines()]
        kinds = [e["event"] for e in events]
        assert "CLAIMED" in kinds and "RECONCILED" in kinds and "OBLIGATION_CLOSED" in kinds
        closed = next(e for e in events if e["event"] == "OBLIGATION_CLOSED")
        assert closed["task_id"] == "T1" and closed["effect_id"] == "eff-1" and "mono" in closed
        claimed = next(e for e in events if e["event"] == "CLAIMED")
        assert claimed["command_id"] == d1["command_id"] and claimed["epoch"] == 1
    _asyncio.run(run_scenario())


def test_struct_controller_unknown_without_effect_releases_new_attempt(tmp_path):
    async def run_scenario():
        ctl, records, effects = _stub_controller(tmp_path)
        d1 = await ctl.directive_for("T1")
        await ctl.begin("T1", d1["command_id"])
        await ctl.mark_unknown("T1", d1["command_id"])
        out = await ctl.reconcile("T1", d1["command_id"])
        assert out["closed"] is False and out["found"] is False
        assert ctl.state["T1"]["status"] == "PENDING"
        d2 = await ctl.directive_for("T1")
        assert d2["directive"] == "ACT" and d2["epoch"] == 2
        assert d2["command_id"] != d1["command_id"]  # per-attempt command id
        events = [json.loads(l) for l in (tmp_path / "CONTROLLER_EVENTS.jsonl").read_text().splitlines()]
        assert any(e["event"] == "CLAIM_RELEASED" for e in events)
    _asyncio.run(run_scenario())


def test_struct_agent_action_parser():
    sys.path.insert(0, str(HERE))
    import struct_agent
    assert struct_agent.parse_action('{"action": "idle", "seconds": 1}') == {"action": "idle", "seconds": 1}
    assert struct_agent.parse_action(
        '{"action":"write","task":"T1","tool":"thing.set","target":"thing-1","args":{"value":1}}')["task"] == "T1"
    assert struct_agent.parse_action('{"action": "idle", "seconds": 1} trailing prose') is None
    assert struct_agent.parse_action('prose {"action": "idle", "seconds": 1}') is None
    assert struct_agent.parse_action('{"action": "idle", ') is None
    assert struct_agent.parse_action('{"action": "explode"}') is None
    assert struct_agent.parse_action('not json at all') is None
    assert struct_agent.parse_action('[{"action": "idle"}]') is None


def test_struct_scripted_placeholders():
    sys.path.insert(0, str(HERE))
    import struct_agent
    step = {"action": "analyze", "task": "T9", "answer": {"x": 1},
            "evidence_refs": "$known_obs_ids", "mine": "$my_obs_ids",
            "cmd": "$last_command_id", "note": "last was $last_command_id"}
    out = struct_agent.substitute_placeholders(
        step, known_obs_ids=["obs-1", "obs-2"], my_obs_ids=["obs-1"], last_command_id="cmd-9")
    assert out["evidence_refs"] == ["obs-1", "obs-2"]
    assert out["mine"] == ["obs-1"]
    assert out["cmd"] == "cmd-9"
    assert out["note"] == "last was cmd-9"
    assert step["evidence_refs"] == "$known_obs_ids"  # input not mutated
    assert struct_agent.backoff_s(1) == 2.0 and struct_agent.backoff_s(10) == 30.0
