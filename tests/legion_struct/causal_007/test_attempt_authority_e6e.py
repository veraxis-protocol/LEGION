"""E6e negative tests N1-N9 (WO-LEGION100-CAUSAL-CLOSURE-007).

Real gate-refusal path (struct_plugin.execute_struct_action, which
refuses before any seal/governor use) and real world path
(world_server.py subprocess over loopback; loopback only, no external
network), against an explicit TEST attempt authority. Every case must
show ZERO actual mutations: no seal, no EXECUTED, reader /state digest
identical, /effects unchanged, no NATIVE_EFFECT/RECEIPT.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]
HERE = Path(__file__).resolve().parent
LEGION = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(LEGION))
sys.path.insert(0, str(LEGION.parent.parent))

import attempt_authority as auth  # noqa: E402
import supervisor as _sup_mod  # noqa: E402


def _clean_env(extra=None):
    """Clean env (E6f): minimal system vars + declared campaign posture.

    Never pytest's inherited environment: the posture is established
    explicitly from supervisor.CAMPAIGN_CAGE_POSTURE, as the campaign
    supervisor establishes it for its children.
    """
    env = {k: os.environ[k] for k in ("PATH", "HOME", "SYSTEMROOT")
           if os.environ.get(k)}
    env.update(_sup_mod.CAMPAIGN_CAGE_POSTURE)
    for name in _sup_mod.CAMPAIGN_POSTURE_UNSET:
        env.pop(name, None)
    if extra:
        env.update(extra)
    return env


def _req(method, url, body=None, bearer=None, token=None, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if data:
        r.add_header("Content-Type", "application/json")
    if bearer:
        r.add_header("Authorization", f"Bearer {bearer}")
    if token:
        r.add_header("X-Legion-World-Token", token)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else {}
        except ValueError:
            return e.code, {}


def _port():
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close(); return p


def _digest(obj):
    return hashlib.sha256(json.dumps(
        obj, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class WorldFixture:
    def __init__(self, tmp_path, authority, *, extra_env=None):
        sys.path.insert(0, str(LEGION))
        self.authority = authority
        spec = json.loads((LEGION / "worlds" / "SYN-GAIA-NOI.world.json").read_text())
        self.operator = "agent:noi-operator"
        tokens = {"agents": {"tok-op": self.operator},
                  "actuator": "act-token", "reader": "read-token"}
        self.tokens_path = tmp_path / "tokens.json"
        self.tokens_path.write_text(json.dumps(tokens))
        self.out = tmp_path / "out"; self.out.mkdir(exist_ok=True)
        self.port = _port()
        self.base = f"http://127.0.0.1:{self.port}"
        env = _clean_env({**authority.env(role="world"), **(extra_env or {})})
        self.proc = subprocess.Popen(
            [sys.executable, "-I", str(LEGION / "world_server.py"),
             str(self.port), str(LEGION / "worlds" / "SYN-GAIA-NOI.world.json"),
             str(self.out), str(self.tokens_path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError(f"world exited {self.proc.returncode}: "
                                     f"{self.proc.stdout.read()[-2000:]}")
            try:
                if _req("GET", f"{self.base}/state", bearer="read-token")[0] == 200:
                    break
            except Exception:
                time.sleep(0.05)
        else:
            raise AssertionError("world did not come up")

    def snapshot(self):
        _, state = _req("GET", f"{self.base}/state", bearer="read-token")
        _, eff = _req("GET", f"{self.base}/effects?after=0", bearer="read-token")
        log = (self.out / "WORLD_LOG.jsonl").read_text() \
            if (self.out / "WORLD_LOG.jsonl").exists() else ""
        kinds = [json.loads(l).get("kind") for l in log.splitlines() if l.strip()]
        return {"digest": _digest(state), "effects": eff.get("effects"),
                "native": kinds.count("NATIVE_EFFECT"),
                "receipts": kinds.count("RECEIPT")}

    def actuate(self, permit, command_id="cmd-n1"):
        return _req("POST", f"{self.base}/actuate", bearer="act-token", body={
            "command_id": command_id, "task_id": "T2", "agent_id": self.operator,
            "tool": "accounts.provision", "target": "acct-u42",
            "args": {"uid": "u42", "plan": "pro"},
            "attempt_uid": self.authority.attempt_uid, "permit": permit})

    def assert_unchanged(self, before):
        after = self.snapshot()
        assert after == before, (before, after)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except Exception:
                self.proc.kill()


@pytest.fixture()
def authority():
    a = auth.TestAuthority()
    yield a
    a.stop()


def _gate_write(tmp_path, monkeypatch, env, attempt_uid=""):
    """Real gate entry: refusal must precede any governor/seal use."""
    sys.path.insert(0, str(LEGION.parent.parent))
    from tests.legion_struct import struct_plugin
    for k in list(os.environ):
        if k.startswith("STRUCT_AUTHORITY") or k == "STRUCT_WORLD_CAPABILITY":
            monkeypatch.delenv(k, raising=False)
    # E6f: gate posture is the declared campaign posture, established
    # explicitly here -- not pytest's inherited conftest environment.
    for k, v in _sup_mod.CAMPAIGN_CAGE_POSTURE.items():
        monkeypatch.setenv(k, v)
    for k in _sup_mod.CAMPAIGN_POSTURE_UNSET:
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    gate_log = tmp_path / "GATE_COMMITS.jsonl"
    monkeypatch.setenv("STRUCT_GATE_COMMITS", str(gate_log))
    import asyncio
    out = asyncio.run(struct_plugin.execute_struct_action(
        "T2", "accounts.provision", "acct-u42", {"uid": "u42", "plan": "pro"},
        "ref-n", governor=None, controller=None, nodes=_nodes(),
        attempt_uid=attempt_uid))
    records = [json.loads(l) for l in gate_log.read_text().splitlines()] \
        if gate_log.exists() else []
    return out, records


def _nodes():
    sys.path.insert(0, str(LEGION))
    from struct_plugin import StructNodes
    spec = json.loads((LEGION / "worlds" / "SYN-GAIA-NOI.world.json").read_text())
    return StructNodes(spec)


def _assert_gate_denied(out, records, rejected=None):
    assert out.startswith("BLOCKED"), out
    assert records and records[-1]["outcome"] == "BLOCKED"
    assert not records[-1].get("seal") and not records[-1].get("command_id")
    assert not [r for r in records if r.get("outcome") == "EXECUTED"]
    if rejected is not None:
        assert records[-1].get("rejected_attempt_uid") == rejected


# N9 + positive gate-refusal ordering: no attempt context at all.
def test_n9_no_attempt_context_denies(tmp_path, monkeypatch):
    out, records = _gate_write(tmp_path, monkeypatch, {})
    _assert_gate_denied(out, records)


# N1: attempt.json deleted during RUNNING -> gate DENY (file is not authority;
# here we also prove a MISSING file cannot admit even with authority up by
# removing authority proof at the gate is N9; N1 world-side: deleting the
# evidence file changes nothing, the permit is still required).
def test_n1_attempt_file_deleted_write_denied(tmp_path, authority):
    w = WorldFixture(tmp_path, authority)
    try:
        (tmp_path / "attempt.json").write_text('{"state":"RUNNING"}')
        (tmp_path / "attempt.json").unlink()
        before = w.snapshot()
        status, _ = w.actuate(None)
        assert status == 403
        w.assert_unchanged(before)
    finally:
        w.stop()


# N2: attempt.json rewritten to RUNNING after terminal -> DENY.
def test_n2_file_rewritten_running_after_terminal_denied(tmp_path, authority, monkeypatch):
    authority.transition(auth.COMPLETED)
    (tmp_path / "attempt.json").write_text(json.dumps(
        {"attempt_uid": authority.attempt_uid, "state": "RUNNING"}))
    out, records = _gate_write(tmp_path, monkeypatch, authority.env(),
                               attempt_uid=authority.attempt_uid)
    _assert_gate_denied(out, records, rejected=authority.attempt_uid)
    assert "terminal" in out


# N3: authority killed/unreachable -> gate DENY.
def test_n3_authority_killed_denies(tmp_path, monkeypatch):
    a = auth.TestAuthority()
    env = a.env()
    a.kill()
    out, records = _gate_write(tmp_path, monkeypatch, env)
    _assert_gate_denied(out, records)
    assert "authority" in out


# N4: stale-epoch and expired permits DENY at the world.
def test_n4_stale_and_expired_permit_denied(tmp_path, authority):
    w = WorldFixture(tmp_path, authority)
    try:
        before = w.snapshot()
        stale = authority.gate_client().request_permit(
            task_id="T2", command_id="cmd-n1")
        authority.supervisor.advance_epoch()
        status, _ = w.actuate(stale)
        assert status == 403
        expired = auth.make_permit(
            authority.state.key, attempt_uid=authority.attempt_uid,
            world_instance_id=authority.world_instance_id,
            epoch=authority.epoch, task_id="T2", command_id="cmd-n1",
            ttl_s=-1)
        # expired permit must be re-MAC'd with current epoch: make_permit
        # already MACs; epoch matches but exp is in the past.
        status, _ = w.actuate(expired, command_id="cmd-n1")
        assert status == 403
        w.assert_unchanged(before)
    finally:
        w.stop()


# N5: permit for another world_instance_id / attempt_uid DENY.
def test_n5_foreign_permit_denied(tmp_path, authority):
    w = WorldFixture(tmp_path, authority)
    try:
        before = w.snapshot()
        foreign = auth.make_permit(
            authority.state.key, attempt_uid="foreign-attempt",
            world_instance_id="foreign-world", epoch=authority.epoch,
            task_id="T2", command_id="cmd-n1")
        status, _ = w.actuate(foreign)
        assert status == 403
        w.assert_unchanged(before)
    finally:
        w.stop()


# N6 + positive: valid permit applies once; replay DENY at the world.
def test_n6_replay_denied_and_positive_applies(tmp_path, authority):
    w = WorldFixture(tmp_path, authority)
    try:
        permit = authority.gate_client().request_permit(
            task_id="T2", command_id="cmd-n6")
        # NOI write has error_first_n: first attempt 503, permit not consumed.
        status, _ = w.actuate(permit, command_id="cmd-n6")
        assert status == 503
        before = w.snapshot()
        # Second attempt is the lost-reply effect; tolerate transport loss.
        try:
            w.actuate(permit, command_id="cmd-n6")
        except Exception:
            pass
        deadline = time.time() + 20
        while time.time() < deadline and w.snapshot()["native"] == before["native"]:
            time.sleep(0.1)
        mid = w.snapshot()
        assert mid["native"] == before["native"] + 1, mid
        # Replay of the same permit/nonce: DENY, zero further mutation.
        status, _ = w.actuate(permit, command_id="cmd-n6")
        assert status == 403
        w.assert_unchanged(mid)
    finally:
        w.stop()


# N7: valid actuator token but no permit DENY (also covered by N1; here
# explicitly with a fresh world and a plausible body).
def test_n7_actuator_token_without_permit_denied(tmp_path, authority):
    w = WorldFixture(tmp_path, authority)
    try:
        before = w.snapshot()
        status, payload = w.actuate(None, command_id="cmd-n7")
        assert status == 403 and payload
        w.assert_unchanged(before)
        refusals = [json.loads(l) for l in
                    (w.out / "WORLD_LOG.jsonl").read_text().splitlines()
                    if '"WRITE_REFUSED"' in l]
        assert refusals and refusals[-1].get("permit_verified") is False
    finally:
        w.stop()


# N8: legacy hosts without a live capability create no world.
def test_n8_legacy_hosts_without_capability_no_world(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "attempt.json").write_text(json.dumps(
        {"attempt_uid": "x", "state": "RUNNING", "world_instance_id": "w"}))
    env = _clean_env()
    env.update({"STRUCT_ATTEMPT_FILE": str(run_dir / "attempt.json"),
                "STRUCT_ATTEMPT_UID": "x", "STRUCT_WORLD_INSTANCE_ID": "w",
                "STRUCT_RUN_DIR": str(run_dir),
                "STRUCT_WORLD": str(LEGION / "worlds" / "SYN-GAIA-EXE.world.json"),
                "STRUCT_OUT": str(tmp_path), "STRUCT_RUN_ID": "run",
                "STRUCT_DECIDER": "scripted", "STRUCT_N_WORKERS": "100"})
    r = subprocess.run([sys.executable, "-I", str(HERE / "mission_host.py")],
                       capture_output=True, text=True, timeout=120, env=env)
    assert r.returncode == 3, r.stdout[-1000:] + r.stderr[-1000:]
    assert not (run_dir / "WORLD_LOG.jsonl").exists(), \
        sorted(p.name for p in run_dir.iterdir())
    # Direct world start likewise refuses without an authority.
    tokens = tmp_path / "tokens.json"
    tokens.write_text(json.dumps({"agents": {}, "actuator": "a", "reader": "r"}))
    r2 = subprocess.run(
        [sys.executable, "-I", str(LEGION / "world_server.py"), "0",
         str(LEGION / "worlds" / "SYN-GAIA-NOI.world.json"),
         str(run_dir), str(tokens)],
        capture_output=True, text=True, timeout=120, env=env)
    assert r2.returncode == 3, r2.stdout[-1000:] + r2.stderr[-1000:]
    # Import-time log fd may create an empty file; no world ever started.
    _wl = run_dir / "WORLD_LOG.jsonl"
    assert not _wl.exists() or "WORLD_START" not in _wl.read_text(
        encoding="utf-8", errors="ignore")


# Positive gate-side: authority RUNNING + correct identity is admitted past
# the attempt check (it then fails later on the absent governor/controller
# in this unit harness, never as an attempt BLOCKED refusal with a seal).
def test_positive_gate_attempt_check_admits_running(tmp_path, authority, monkeypatch):
    for k, v in authority.env().items():
        monkeypatch.setenv(k, v)
    from tests.legion_struct import struct_plugin
    assert struct_plugin._attempt_refusal(authority.attempt_uid) is None
    assert struct_plugin._attempt_refusal("forged") is not None
    permit = authority.gate_client().request_permit(
        task_id="T2", command_id="cmd-p")
    assert authority.world_client().verify_fresh(
        permit, task_id="T2", command_id="cmd-p") is None
