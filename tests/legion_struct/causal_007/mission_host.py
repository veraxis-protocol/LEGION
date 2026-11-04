"""Non-pytest mission host (WO-LEGION100-CAUSAL-CLOSURE-007, E6b).

This is the campaign-path host: the supervisor runs it directly as
``python -I mission_host.py`` (env-driven, exactly like the old pytest
host). It contains the World orchestration formerly in
test_struct_mission.py; that pytest file is now only a thin test wrapper
around :func:`run_mission`. Nothing here runs through pytest, xdist or
pytest-timeout.

When STRUCT_ATTEMPT_FILE is set the host is supervisor-backed: it refuses
a terminal attempt, stamps exported evidence with the attempt identity,
passes the attempt identity to every child process, and dies (os._exit)
if its parent (the supervisor) disappears, so no agent can be orphaned.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib
import json
import os
import pathlib
import re
import signal
import socket
import sys
import threading
import time
import urllib.request
import uuid
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

HERE = pathlib.Path(__file__).resolve().parent
LEGION = HERE.parent
REPO = HERE.parents[2]
for _p in (str(REPO), str(LEGION), str(HERE)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import attempt as attempt_mod  # noqa: E402  (causal_007/attempt.py)
import attempt_authority as auth_mod  # noqa: E402

from tests.legion_struct import struct_plugin  # noqa: E402
from tests.legion_struct.struct_controller import StructMissionController  # noqa: E402
from tests.legion_struct.struct_plugin import StructNodes, action_name, norm_id_for  # noqa: E402

PY = sys.executable
REF = datetime(2026, 10, 7, 14, 0, 10, tzinfo=timezone.utc)
AUTHORITY = "LEGION Structural Change Board (TEST-ONLY)"
CHILD_ENV_BASE = {"PATH": os.environ.get("PATH", ""),
                  **({"SYSTEMROOT": os.environ["SYSTEMROOT"]}
                     if os.environ.get("SYSTEMROOT") else {})}
HOST_EVIDENCE_JSONL = ("GATE_COMMITS.jsonl", "CONTROLLER_EVENTS.jsonl",
                       "CAGE_EVIDENCE_CHAIN.jsonl", "VEIP_RELIANCE.jsonl",
                       "WORKERS.jsonl", "CAUSAL_CONTROLLER.jsonl")


def _child_env():
    env = dict(CHILD_ENV_BASE)
    for key in ("STRUCT_ATTEMPT_FILE", "STRUCT_ATTEMPT_UID",
                "STRUCT_WORLD_INSTANCE_ID", "STRUCT_RUN_DIR"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    return env


# --------------------------------------------------------------------------
# Minimal monkeypatch shim (the campaign path must not depend on pytest)
# --------------------------------------------------------------------------
class ShimPatch:
    def __init__(self):
        self._undo = []

    def setenv(self, name, value):
        old = os.environ.get(name)
        self._undo.append(lambda: (os.environ.__setitem__(name, old)
                                   if old is not None else
                                   os.environ.pop(name, None)))
        os.environ[name] = str(value)

    def delenv(self, name, raising=True):
        if name not in os.environ:
            if raising:
                raise KeyError(name)
            return
        old = os.environ.pop(name)
        self._undo.append(lambda: os.environ.__setitem__(name, old))

    def setattr(self, target, name, value=None):
        if value is None and isinstance(name, object) and not isinstance(target, str):
            # setattr(obj, value) form is not used here; keep explicit form.
            raise TypeError("setattr requires (target, name, value)")
        if isinstance(target, str):
            # pytest.MonkeyPatch semantics: import the longest importable
            # module prefix, then walk the remaining attribute chain
            # (e.g. "pkg.mod.Class.method").
            path, val = target, name
            parts = path.split(".")
            obj, attrs = None, []
            for i in range(len(parts) - 1, 0, -1):
                try:
                    obj = importlib.import_module(".".join(parts[:i]))
                    attrs = parts[i:]
                    break
                except ImportError:
                    continue
            if obj is None or not attrs:
                raise ImportError(f"cannot import any prefix of {path!r}")
            owner = obj
            for attr in attrs[:-1]:
                owner = getattr(owner, attr)
            leaf = attrs[-1]
            old = getattr(owner, leaf)
            self._undo.append(lambda: setattr(owner, leaf, old))
            setattr(owner, leaf, val)
            return
        old = getattr(target, name)
        self._undo.append(lambda: setattr(target, name, old))
        setattr(target, name, value)

    @contextmanager
    def context(self):
        sub = ShimPatch()
        try:
            yield sub
        finally:
            sub.undo()

    def undo(self):
        while self._undo:
            fn = self._undo.pop()
            try:
                fn()
            except Exception:
                pass


# --------------------------------------------------------------------------
# Gateway stack factory (the old pytest ``build`` fixture, replicated)
# --------------------------------------------------------------------------
class _Clock:
    def __init__(self, wall=REF):
        self.mono = 1_000.0
        self.wall = wall

    def warrant_clock(self):
        from src.gateway.governance.warrant import WarrantClock
        return WarrantClock(monotonic=lambda: self.mono, wall_clock=lambda: self.wall)


class _Opa:
    def __init__(self, verdict="ALLOW"):
        self.verdict, self.calls = verdict, []

    async def evaluate_policy(self, payload):
        self.calls.append(payload)
        return self.verdict


class _AdmittingFria:
    async def fetch_baseline(self, region):
        raise NotImplementedError

    async def validate_fria(self, payload):
        from src.gateway.governance.seams.normative import ValidationResult
        return ValidationResult(admitted=True)

    async def submit_evidence(self, receipt):
        raise NotImplementedError


def _eu_jurisdiction():
    from src.gateway.governance.jurisdiction import eu_ai_act
    assessed = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    return eu_ai_act.contribution(
        provider=_AdmittingFria(),
        assessment_lookup=lambda action: {"assessed_at": assessed})


class _Stack:
    def __init__(self, governor, source, clock, evidence_redis, stream_key):
        self.governor, self.source, self.clock = governor, source, clock
        self._evidence_redis, self._stream_key = evidence_redis, stream_key

    async def chain(self):
        from src.gateway.governance.evidence.stream import verify_record
        entries = [f for _id, f in await self._evidence_redis.xrange(self._stream_key)]
        out, prev = [], ""
        for fields in entries:
            assert verify_record(fields, prev_hash=prev).valid
            out.append((fields, prev))
            prev = fields["record_hash"]
        return out


def make_build_factory(mp: ShimPatch):
    """Return (build_factory, cleanup_coro_fn) replicating the pytest fixture."""
    import fakeredis
    import fakeredis.aioredis
    from src.gateway.governance import constants, defer_queue as defer_queue_mod
    from src.gateway.governance.evidence import stream as evidence_stream
    from src.gateway.governance.warrant.source_factory import (
        WARRANT_SOURCE_ENV, warrant_source_from_env)
    from src.gateway.server import governance_middleware
    from src.integrations.provider_05 import Provider05WarrantSource

    mp.setenv("CAGE_SEAL_STRICT_MODE", "false")
    mp.setenv("CAGE_DOMAIN", "finance")
    mp.setenv(WARRANT_SOURCE_ENV, "provider_05")
    mp.delenv("CAGE_DEFER_ENABLED", raising=False)
    # Region pin: the struct mission assembles the EU_ECB jurisdiction
    # contribution. Under pytest the conftest region fixture pins the
    # process-global thresholds; the standalone (supervisor) host has no
    # fixture, so pin here, idempotently, or assembly refuses the
    # governor with a region mismatch.
    if not os.environ.get("CAGE_DEPLOYMENT_REGION"):
        mp.setenv("CAGE_DEPLOYMENT_REGION", "EU_ECB")
    from src.gateway.governance.schemas import thresholds as _thresholds_mod
    mp.setattr(_thresholds_mod, "THRESHOLDS",
               _thresholds_mod.load_and_validate_thresholds(region="EU_ECB"))
    mp.setattr(constants, "_OVERLAY_DIRS", list(constants._OVERLAY_DIRS))
    cbf_redis = fakeredis.aioredis.FakeRedis(decode_responses=False)
    fiscal_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    defer_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    seal_redis = fakeredis.aioredis.FakeRedis(decode_responses=False)
    evidence_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    async def _setup():
        await cbf_redis.set("safety:current_cash", str(1_000_000.0))

    asyncio.get_event_loop_policy()  # no-op; _setup run by caller if needed
    raw_cbf = MagicMock()
    raw_cbf.get_raw_client.return_value = cbf_redis
    mp.setattr("src.gateway.governance.safety.cbf_engine.redis_client", raw_cbf)
    mp.setattr("src.gateway.governance.safety.cbf_engine.sync_redis_client",
               fakeredis.FakeRedis(decode_responses=True))
    mp.setattr("src.gateway.infrastructure.redis_client.redis_client", seal_redis)
    mp.setattr("src.gateway.infrastructure.redis_client.sync_redis_client",
               fakeredis.FakeRedis(decode_responses=True))

    @asynccontextmanager
    async def _queue():
        from src.gateway.governance.defer_queue import DeferQueue
        yield DeferQueue(defer_redis)

    mp.setattr(defer_queue_mod, "open_defer_queue", _queue)
    sink = evidence_stream.EvidenceStreamSink()

    async def _start_sink():
        with mp.context() as m:
            m.setattr("src.gateway.infrastructure.redis_client.build_async_redis",
                      lambda *a, **k: evidence_redis)
            m.setattr("redis.asyncio.from_url", lambda *a, **k: evidence_redis)
            await sink.start()
        mp.setattr(evidence_stream, "_evidence_sink", sink)

    actuate = AsyncMock(side_effect=lambda clearance: _actuation_receipt())
    mp.setattr("src.cage_finance.actuators.broker_actuator.BrokerActuator.actuate",
               actuate)
    mp.setattr(governance_middleware, "_emit_refusal_receipt", AsyncMock())
    governance_middleware._validate_action_rate_buckets.clear()
    state = {"started": False}

    async def _build(*, seed=None, clock=None):
        if not state["started"]:
            await _setup()
            await _start_sink()
            state["started"] = True
        from src.gateway.governance.governor.bootstrap import bootstrap_governor
        from src.gateway.server.governance_middleware import governance_app
        source = warrant_source_from_env()
        assert isinstance(source, Provider05WarrantSource)
        if seed is not None:
            source.seed(seed)
        clock = clock or _Clock()
        opa = _Opa("ALLOW")
        with mp.context() as m:
            m.setattr("redis.asyncio.from_url", lambda *a, **k: fiscal_redis)
            governor = bootstrap_governor(
                opa=opa, warrant_source=source,
                warrant_clock=clock.warrant_clock(),
                jurisdiction=_eu_jurisdiction())
        governance_app.state.governor = governor
        return _Stack(governor, source, clock, evidence_redis, sink._stream_key)

    async def _cleanup():
        from src.gateway.server.governance_middleware import governance_app
        governance_app.state.governor = None
        if state["started"]:
            try:
                await sink.stop()
            except Exception:
                pass

    return _build, _cleanup


def _actuation_receipt():
    from src.gateway.governance.seams.actuation import ActuationReceipt
    return ActuationReceipt(accepted=True, receipt_id=f"r-{uuid.uuid4().hex[:8]}",
                            session_uuid=None, raw_receipt={"status": "executed"})


# --------------------------------------------------------------------------
# Test-only warrant root (copied; avoids importing a pytest module)
# --------------------------------------------------------------------------
_V02 = REPO / "docs" / "partners" / "provider_05" / "veip_v02"
VECTORS = json.loads((_V02 / "warrants_v02_vectors.json").read_text())


class _TestOnlyRoot:
    def __init__(self, root_kid="test-only-root", issuer_kid="test-only-issuer"):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.root, self.issuer = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.root_kid, self.issuer_kid = root_kid, issuer_kid

    def _b64u(self, b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    def _raw(self, k):
        from cryptography.hazmat.primitives import serialization as S
        return k.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)

    def anchor(self):
        from cryptography.hazmat.primitives import serialization as S
        from src.gateway.governance.warrant.trust_anchor import WarrantTrustAnchor
        spki = self.root.public_key().public_bytes(
            S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo)
        return WarrantTrustAnchor(
            root_kid=self.root_kid, public_key_b64=base64.b64encode(spki).decode(),
            expected_fingerprint="sha256:" + hashlib.sha256(self._raw(self.root)).hexdigest())

    def _root_sign(self, body, digest_key):
        from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
        body = dict(body)
        body[digest_key] = hashlib.sha256(jcs_canonicalize_plan(body)).hexdigest()
        body["signature"] = self._b64u(self.root.sign(jcs_canonicalize_plan(body)))
        return body

    def manifest(self, environment="SANDBOX", issuer="TEST-ONLY Technical Issuer"):
        return self._root_sign({
            "schema_version": "veip-key-manifest/0.2", "environment": environment,
            "manifest_id": "test-only-manifest", "issuer": issuer,
            "generated_at": "2026-10-07T14:00:00Z", "valid_until": "2026-11-07T14:00:00Z",
            "root_kid": self.root_kid,
            "keys": [{"kid": self.issuer_kid, "alg": "Ed25519",
                      "public_key_b64u": self._b64u(self._raw(self.issuer)),
                      "status": "ACTIVE", "not_before": "2026-10-07T00:00:00Z",
                      "not_after": "2026-12-31T23:59:59Z", "revoked_at": ""}]},
            "manifest_digest")

    def authz(self, *, environment="SANDBOX", manifest_issuer="TEST-ONLY Technical Issuer",
              kid=None, authorities=("Risk Oversight Committee (EU_ECB)",), status="ACTIVE",
              valid_until="2026-11-07T14:00:00Z"):
        return self._root_sign({
            "schema_version": "veip-authority-authorization/0.1",
            "environment": environment, "authorization_id": "test-only-authz",
            "manifest_issuer": manifest_issuer, "generated_at": "2026-10-07T13:59:00Z",
            "valid_until": valid_until, "root_kid": self.root_kid,
            "authorizations": [{"kid": kid or self.issuer_kid,
                                "authorized_issuing_authorities": list(authorities),
                                "not_before": "2026-10-07T00:00:00Z",
                                "not_after": "2026-11-07T14:00:00Z", "status": status}]},
            "authorization_digest")

    def warrant(self, **overrides):
        from dataclasses import replace
        from src.gateway.governance.warrant import Warrant
        fields = {**VECTORS["ACTIVE"], **overrides,
                  "kid": self.issuer_kid, "digest": "", "signature": ""}
        w = Warrant(**fields)
        w = replace(w, digest=w.compute_digest())
        return replace(w, signature=self._b64u(self.issuer.sign(w.to_signed_bytes())))


def struct_warrant(root, task):
    base = VECTORS["ACTIVE"]
    scope = {"actions": [action_name(task["task_id"])], "actors": [task["agent_id"]],
             "systems": [struct_plugin.SYSTEM],
             "jurisdictions": base["scope"]["jurisdictions"]}
    # E6e: VEIP authorization is scoped to this attempt. Identity comes
    # from the live authority, never from files or caller input.
    try:
        st = auth_mod.client_from_env("gate").status()
        scope["attempt_uid"] = st.get("attempt_uid")
        scope["world_instance_id"] = st.get("world_instance_id")
    except Exception:
        pass
    return root.warrant(
        warrant_id=f"legion-struct-{task['task_id']}-warrant",
        norm_id=norm_id_for(task["task_id"]),
        issuing_authority=AUTHORITY,
        authority_basis="LEGION structural synthetic runbook (TEST-ONLY)",
        environment="SANDBOX",
        scope=scope,
        norm_parameters={"authority": {"type": "decimal", "value": "1", "unit": "generation"}},
        governing_version=struct_plugin.GOVERNING_VERSION)


class AttemptAlreadyStarted(RuntimeError):
    pass


def _claim_attempt(run_dir: pathlib.Path):
    run_dir.mkdir(parents=True, exist_ok=True)
    # Supervisor-backed: the attempt registry is the authority; the host
    # lock is only a secondary guard and must not re-register anything.
    # E6e: no world without a live attempt authority. Files are evidence
    # only; a terminal/foreign/existing run dir without a live RUNNING
    # authority and an unconsumed capability is refused here.
    try:
        _st = auth_mod.client_from_env("gate").status()
    except Exception as exc:
        raise AttemptAlreadyStarted(
            f"REFUSED: attempt authority unavailable ({exc}); "
            "mission host may not create a world")
    if _st.get("state") != auth_mod.RUNNING:
        raise AttemptAlreadyStarted(
            f"REFUSED: attempt authority state is {_st.get('state')}, "
            "not RUNNING; mission host may not create a world")
    if os.environ.get("STRUCT_ATTEMPT_UID") and \
            os.environ["STRUCT_ATTEMPT_UID"] != _st.get("attempt_uid"):
        raise AttemptAlreadyStarted(
            "REFUSED: foreign attempt_uid; mission host may not start")
    # E6g: no file-based state is believed here; live authority above is
    # the only control input. attempt.json is evidence only.
    world_log = run_dir / "WORLD_LOG.jsonl"
    if world_log.exists():
        try:
            if "WORLD_START" in world_log.read_text(encoding="utf-8", errors="ignore"):
                raise AttemptAlreadyStarted(
                    f"REFUSED: WORLD_START already present in {world_log}")
        except OSError:
            pass
    lock_path = run_dir / "HOST_ATTEMPT_LOCK.json"
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        raise AttemptAlreadyStarted(
            f"REFUSED: attempt lock already exists: {lock_path}")
    try:
        os.write(fd, json.dumps({"pid": os.getpid(), "t": time.time(),
                                 "run_dir": str(run_dir)}).encode())
    finally:
        os.close(fd)
    return lock_path


def _authority_identity():
    """(attempt_uid, world_instance_id) from the LIVE attempt authority.

    Evidence is stamped from the authority, never from env vars: env is
    only a spawn-time hint, the authority is the source of truth (E6e).
    """
    st = auth_mod.client_from_env("gate").status()
    return st.get("attempt_uid"), st.get("world_instance_id")


def _port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _get(url, token=None):
    req = urllib.request.Request(url, method="GET")
    if token:
        req.add_header("X-Legion-World-Token", token)
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def _identity_for(agent_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", agent_id.replace("agent:", "").lower()).strip("-") or "worker"
    return f"legion-struct-{slug}-sa.legion.serviceaccount.identity.linkerd.cluster.local"


def _token_env(agent_id: str) -> str:
    name = "SCALE_PROXY_TOKEN_" + "".join(
        ch if ch.isalnum() else "_" for ch in agent_id.replace("agent:", "")).upper()
    return os.environ.get(name) or os.environ.get("SCALE_PROXY_TOKEN", "")


class World:
    def __init__(self, run_dir, spec_path, n_workers):
        self.dir = pathlib.Path(run_dir)
        self.attempt_lock = _claim_attempt(self.dir)
        for _name in HOST_EVIDENCE_JSONL:
            (self.dir / _name).touch(exist_ok=True)
        self.spec_path = pathlib.Path(spec_path)
        self.spec_bytes = self.spec_path.read_bytes()
        self.spec = json.loads(self.spec_bytes.decode("utf-8"))
        self.s100_overlay = os.environ.get("STRUCT_CAUSAL_OVERLAY") == "s100"
        if self.s100_overlay:
            sys.path.insert(0, str(LEGION))
            from causal_007.delegation import build_s100_spec
            self.spec = build_s100_spec(self.spec, total=n_workers)
            self.spec_path = self.dir / "EFFECTIVE_WORLD_S100.json"
            self.spec_path.write_text(json.dumps(self.spec, indent=1), encoding="utf-8")
            self.spec_bytes = self.spec_path.read_bytes()
        self.nodes = StructNodes(self.spec)
        active = [r["agent_id"] for r in self.spec.get("roles") or []]
        if n_workers < len(active):
            raise ValueError(f"INVALID: STRUCT_N_WORKERS={n_workers} < {len(active)} active roles")
        self.workers = [{"agent_id": a, "kind": "active"} for a in active]
        for i in range(1, n_workers - len(active) + 1):
            self.workers.append({"agent_id": f"agent:standby-{i:03d}", "kind": "standby"})
        for w in self.workers:
            w["workload_identity"] = _identity_for(w["agent_id"])
        self.ids = {w["agent_id"]: w["workload_identity"] for w in self.workers}
        self.world_tokens = {w["agent_id"]: uuid.uuid4().hex for w in self.workers}
        self.actuator_token = uuid.uuid4().hex
        self.reader_token = uuid.uuid4().hex
        self.agent_procs: dict = {}
        self.world_proc = None
        self.readback_proc = None
        self.causal_proc = None
        self.tasks: list = []

    def ids_reversed(self):
        return {v: k for k, v in self.ids.items()}

    async def up(self, build, mp):
        import uvicorn
        from cryptography.hazmat.primitives import serialization as S
        from starlette.applications import Starlette
        from starlette.routing import Mount
        from src.gateway.server.governance_middleware import governance_app
        from src.gateway.server.workload_identity import (
            IdentityPolicy, TRUSTED_IDENTITIES_ENV, WorkloadIdentityMiddleware)
        import src.gateway.server.mcp_tool_server as mcp_mod

        d = self.dir
        self.wport, self.gport = _port(), _port()
        self.world_url, self.gw = f"http://127.0.0.1:{self.wport}", f"http://127.0.0.1:{self.gport}"
        tokens_path = d / "world_tokens.json"
        tokens_path.write_text(json.dumps({
            "agents": {tok: agent for agent, tok in self.world_tokens.items()},
            "actuator": self.actuator_token, "reader": self.reader_token}))
        child_env = _child_env()
        # World alone (never agents) inherits the authority channel.
        for _k in (auth_mod.ENV_URL, auth_mod.ENV_KEY,
                   auth_mod.ENV_WORLD_TOKEN, auth_mod.ENV_CAPABILITY):
            if os.environ.get(_k):
                child_env[_k] = os.environ[_k]
        self.world_proc = await asyncio.create_subprocess_exec(
            PY, "-I", str(LEGION / "world_server.py"), str(self.wport),
            str(self.spec_path), str(d), str(tokens_path), env=child_env)
        any_token = next(iter(self.world_tokens.values()))
        for _ in range(200):
            try:
                _get(f"{self.world_url}/observe", token=any_token); break
            except Exception:
                if self.world_proc.returncode is not None:
                    raise RuntimeError(
                        f"world_server exited {self.world_proc.returncode} "
                        "(capability refused or second world)")
                await asyncio.sleep(0.05)
        else:
            raise RuntimeError("world_server did not come up")
        self.causal_url, self.causal_proc = None, None
        if os.environ.get("STRUCT_CAUSAL", "1") != "0":
            cport = _port()
            self.causal_url = f"http://127.0.0.1:{cport}"
            self.causal_proc = await asyncio.create_subprocess_exec(
                PY, "-I", str(HERE / "sidecar_server.py"),
                "--port", str(cport), "--world-file", str(self.spec_path),
                "--world-url", self.world_url, "--reader-token", self.reader_token,
                "--out", str(d / "CAUSAL_CONTROLLER.jsonl"),
                "--gate-commits", str(d / "GATE_COMMITS.jsonl"),
                "--readback", str(d / "READBACK.jsonl"),
                "--tokens", str(tokens_path), env=child_env)
            for _ in range(200):
                try:
                    with urllib.request.urlopen(f"{self.causal_url}/health", timeout=2) as r:
                        if r.status == 200:
                            break
                except Exception:
                    await asyncio.sleep(0.05)
            else:
                raise RuntimeError("causal sidecar did not come up")
        self.readback_proc = await asyncio.create_subprocess_exec(
            PY, "-I", str(LEGION / "struct_readback.py"), self.world_url,
            self.reader_token, str(d), env=child_env)
        mp.setenv("STRUCT_GATE_COMMITS", str(d / "GATE_COMMITS.jsonl"))
        mp.setenv("STRUCT_ACTUATOR_TOKEN", self.actuator_token)
        mp.setenv("CAGE_WARRANT_CONTEXT_BINDING", "required")
        mp.setenv("CAGE_WARRANT_ACTOR_BINDINGS", json.dumps(self.ids_reversed()))
        mp.setenv("CAGE_SYSTEM_ID", struct_plugin.SYSTEM)
        mp.setenv("CAGE_DEPLOYMENT_ENVIRONMENT", "SANDBOX")
        mp.setenv("CAGE_WORKLOAD_IDENTITY_TRANSPORT", "unverified-header-test-only")
        mp.setenv(TRUSTED_IDENTITIES_ENV, ",".join(self.ids.values()))
        # Gate/plugin processes share this process: give them the attempt
        # identity for evidence stamping + terminal checks. Identity is
        # read from the live attempt authority, never from env (E6e).
        _uid, _wid = _authority_identity()
        if _uid:
            mp.setenv("STRUCT_ATTEMPT_UID", _uid)
        if _wid:
            mp.setenv("STRUCT_WORLD_INSTANCE_ID", _wid)
        self.ctl = StructMissionController(self.spec, self.world_url,
                                           str(d / "CONTROLLER_EVENTS.jsonl"),
                                           self.reader_token)
        import dataclasses
        from src.gateway.governance import plugin_loader
        reg = d / "ftra_terminal_registry_composed.json"
        fin = importlib.import_module("src.cage_finance.plugin").FinanceCagePlugin.domain_config
        self.ftra_digest = struct_plugin.composed_ftra_registry(fin.ftra_registry_path, reg, self.nodes)
        for modname in ("src.cage_finance.plugin", "cage_finance.plugin"):
            mp.setattr(importlib.import_module(modname).FinanceCagePlugin,
                       "domain_config",
                       dataclasses.replace(fin, ftra_registry_path=reg))
        for fn in (plugin_loader.active_domain_config, plugin_loader.load_domain_plugin):
            getattr(fn, "cache_clear", lambda: None)()
        for modname in ("src.cage_finance.plugin", "cage_finance.plugin"):
            mod = importlib.import_module(modname)
            cur = mod.FinanceCagePlugin.contribute
            orig = getattr(cur, "__struct_orig__", cur)
            patched = (lambda o, c, n: lambda self: struct_plugin.compose(o(self), c, n))(orig, self.ctl, self.nodes)
            patched.__struct_orig__ = orig
            mp.setattr(mod.FinanceCagePlugin, "contribute", patched)
        root = self.root = _TestOnlyRoot(root_kid="legion-struct-test-only-root",
                                         issuer_kid="legion-struct-test-only-issuer")
        write_tasks = [self.nodes.write_tasks[tid] for tid in sorted(self.nodes.write_tasks)]
        warrants = [struct_warrant(root, t) for t in write_tasks]
        manifest_obj = root.manifest()
        authz = root.authz(authorities=(AUTHORITY,))
        self.stack = await build(seed=warrants[0] if warrants else None, clock=_Clock(wall=REF))
        for w in warrants[1:]:
            self.stack.source.seed(w)
        self.stack.source._explicit_trust_anchor = root.anchor()
        self.stack.source.seed_key_manifest(manifest_obj)
        self.stack.source.seed_authority_authorization(authz)
        tiers = self.stack.governor.registered_tier_names() if hasattr(self.stack.governor, "registered_tier_names") else []
        assert "legion_struct_task" in tiers, f"struct tier not composed: {tiers}"
        spki = root.root.public_key().public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo)
        (d / "TEST_ONLY_FIXTURES.json").write_text(json.dumps({
            "TEST_ONLY": True, "root_kid": root.root_kid,
            "root_fingerprint": root.anchor().fingerprint,
            "root_public_key_spki_b64": base64.b64encode(spki).decode(),
            "key_manifest": manifest_obj, "authority_authorization": authz,
            "warrants": [w.to_dict() for w in warrants]}, indent=1, default=str))
        struct_plugin.register_actuator(self.world_url, self.actuator_token, self.nodes)
        for tool_name in ("world_write", "declare_refusal"):
            mcp_mod.mcp._tool_manager._tools.pop(tool_name, None)
        struct_plugin.StructToolProvider(None, self.ctl, self.nodes).register_tools(
            mcp_mod.mcp, self.stack.governor)
        mcp_mod._rate_limit_buckets.clear()
        root_app = WorkloadIdentityMiddleware(
            Starlette(routes=[Mount("/governance", app=governance_app),
                              Mount("/", app=mcp_mod.app)]),
            IdentityPolicy(trusted=frozenset(self.ids.values())))
        self.gsrv = uvicorn.Server(uvicorn.Config(
            root_app, host="127.0.0.1", port=self.gport, lifespan="off",
            log_level="warning"))
        self.tasks = [asyncio.create_task(self.gsrv.serve())]
        while not self.gsrv.started:
            await asyncio.sleep(0.02)
        await self.ctl.start()
        (d / "HOST_ENDPOINTS.json").write_text(json.dumps({
            "world_url": self.world_url, "gateway_url": self.gw,
            "causal_url": self.causal_url,
            "attempt_uid": _uid,
            "authority_url": os.environ.get(auth_mod.ENV_URL),
            "world_instance_id": _wid},
            indent=1))
        return self

    async def export(self):
        d = self.dir
        try:
            uid, wid = _authority_identity()
        except Exception:
            uid, wid = None, None
        chain = [f for f, _prev in await self.stack.chain()]
        stamped = []
        for i, f in enumerate(chain, 1):
            rec = dict(f)
            if uid:
                rec.setdefault("attempt_uid", uid)
            if wid:
                rec.setdefault("world_instance_id", wid)
            rec["seq"] = i
            stamped.append(rec)
        (d / "CAGE_EVIDENCE_CHAIN.jsonl").write_text(
            "".join(json.dumps(f, default=str) + "\n" for f in stamped))
        seq = 0
        with open(d / "VEIP_RELIANCE.jsonl", "w") as v:
            for f in stamped:
                p = json.loads(f.get("payload_json") or "{}")
                for r in p.get("reliance") or []:
                    seq += 1
                    rec = {"event_type": f.get("event_type"),
                           "record_hash": f.get("record_hash"),
                           "action": p.get("action"), **r}
                    if uid:
                        rec.setdefault("attempt_uid", uid)
                    if wid:
                        rec.setdefault("world_instance_id", wid)
                    rec["seq"] = seq
                    v.write(json.dumps(rec, default=str) + "\n")

    async def _stop_proc(self, proc, grace=10):
        if proc is None or proc.returncode is not None:
            return
        try:
            proc.terminate()
        except ProcessLookupError:
            return
        try:
            await asyncio.wait_for(proc.wait(), timeout=grace)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()

    async def down(self):
        for proc in list(getattr(self, "agent_procs", {}).values()):
            await self._stop_proc(proc, grace=5)
        await self._stop_proc(getattr(self, "causal_proc", None))
        await self._stop_proc(getattr(self, "readback_proc", None), grace=5)
        await self._stop_proc(getattr(self, "world_proc", None), grace=5)
        if getattr(self, "gsrv", None) is not None:
            self.gsrv.should_exit = True
        if getattr(self, "tasks", None):
            try:
                await asyncio.gather(*self.tasks, return_exceptions=True)
            except Exception:
                pass
            self.tasks = []


def _worker_env(world: World, worker: dict, decider: str) -> dict:
    budgets = world.spec.get("budgets") or {}
    env = {**_child_env(),
           "STRUCT_AGENT_ID": worker["agent_id"],
           "STRUCT_WORLD_URL": world.world_url,
           "STRUCT_WORLD_TOKEN": world.world_tokens[worker["agent_id"]],
           "STRUCT_GATEWAY_URL": world.gw,
           "STRUCT_WORKLOAD_IDENTITY": worker["workload_identity"],
           "STRUCT_WORLD_FILE": str(world.spec_path),
           "STRUCT_OUT": str(world.dir),
           "STRUCT_LOG": str(world.dir / ("agent_" + re.sub(r"[^A-Za-z0-9_]", "_", worker["agent_id"]) + ".jsonl")),
           "STRUCT_DECIDER": decider,
           "STRUCT_MAX_TURNS": os.environ.get("STRUCT_MAX_TURNS", str(budgets.get("max_model_turns_per_agent", 14))),
           "STRUCT_WALL_S": os.environ.get("STRUCT_WALL_S", str(budgets.get("max_duration_s", 420)))}
    if os.environ.get("STRUCT_PLAN"):
        env["STRUCT_PLAN"] = os.environ["STRUCT_PLAN"]
    if getattr(world, "causal_url", None):
        env["STRUCT_CAUSAL_URL"] = world.causal_url
    if decider == "nim":
        env["SCALE_PROXY_URL"] = os.environ.get("SCALE_PROXY_URL", "")
        env["SCALE_MODEL"] = os.environ.get("SCALE_MODEL", "")
        env["SCALE_PROXY_TOKEN"] = _token_env(worker["agent_id"])
    return env


def world_path() -> pathlib.Path:
    return pathlib.Path(os.environ.get(
        "STRUCT_WORLD", str(LEGION / "worlds" / "SYN-GAIA-NOI.world.json")))


async def run_mission(build, mp) -> int:
    """The former pytest host body. Returns a process exit code."""
    run_id = os.environ.get("STRUCT_RUN_ID", "struct-run-1")
    mode = os.environ.get("STRUCT_MODE", "INTEGRATION_ONLY")
    decider = os.environ.get("STRUCT_DECIDER", "scripted")
    n_workers = int(os.environ.get("STRUCT_N_WORKERS", "10"))
    out = pathlib.Path(os.environ.get("STRUCT_OUT", "/tmp/struct"))
    spec_file = world_path()
    spec = json.loads(spec_file.read_text(encoding="utf-8"))
    n_active = len(spec.get("roles") or [])
    if n_workers < n_active:
        raise ValueError(
            f"INVALID: STRUCT_N_WORKERS={n_workers} is less than the {n_active} active roles")
    run_dir = out / run_id
    world = World(run_dir, spec_file, n_workers)
    d = world.dir
    try:
        await world.up(build, mp)
        att_uid, att_wid = _authority_identity()
        header = d / "RUN_HEADER.json"
        hdr = json.loads(header.read_text()) if header.exists() else {}
        hdr.update({"run_id": run_id, "world_id": spec.get("world_id"),
                    "world_file": str(spec_file),
                    "world_file_sha256": hashlib.sha256(world.spec_bytes).hexdigest(),
                    "mode": mode, "decider": decider, "n_workers": n_workers,
                    "cage_head": os.environ.get("STRUCT_CAGE_HEAD") or os.environ.get("SCALE_CAGE_HEAD"),
                    "t_world_up": time.time(), "t_world_up_mono": time.monotonic(),
                    "attempt_uid": att_uid,
                    "world_instance_id": att_wid,
                    "agent_prompt_sha256": hashlib.sha256((LEGION / "struct_agent.py").read_bytes()).hexdigest()})
        hdr.setdefault("t_episode_registered", time.time())
        hdr.setdefault("t_episode_registered_mono", time.monotonic())
        header.write_text(json.dumps(hdr, indent=1))
        budgets = spec.get("budgets") or {}
        wall_budget = float(budgets.get("max_duration_s", 420)) + 60.0
        procs: dict = {}
        world.agent_procs = procs
        with open(d / "WORKERS.jsonl", "w") as wf:
            for worker in world.workers:
                wdecider = decider if worker["kind"] == "active" else "standby"
                p = await asyncio.create_subprocess_exec(
                    PY, "-I", str(LEGION / "struct_agent.py"),
                    env=_worker_env(world, worker, wdecider))
                procs[worker["agent_id"]] = p
                wf.write(json.dumps({"agent_id": worker["agent_id"], "pid": p.pid,
                                     "kind": worker["kind"], "decider": wdecider,
                                     "workload_identity": worker["workload_identity"],
                                     "attempt_uid": att_uid,
                                     "world_instance_id": att_wid}) + "\n")
                wf.flush()
        waiters = {aid: asyncio.ensure_future(p.wait()) for aid, p in procs.items()}
        done, pending = await asyncio.wait(list(waiters.values()), timeout=wall_budget)
        rcs = {aid: waiters[aid].result() for aid, w in waiters.items() if w in done}
        for aid, w in waiters.items():
            if w in pending:
                procs[aid].terminate()
                try:
                    await asyncio.wait_for(procs[aid].wait(), timeout=10)
                except asyncio.TimeoutError:
                    procs[aid].kill()
                    await procs[aid].wait()
                rcs[aid] = "TIMEOUT_KILLED"
        if world.s100_overlay:
            sys.path.insert(0, str(LEGION))
            from causal_007.delegation import write_contribution_report
            _wl = d / "WORLD_LOG.jsonl"
            _records = []
            if _wl.exists():
                for _line in _wl.read_text(encoding="utf-8").splitlines():
                    try:
                        _records.append(json.loads(_line))
                    except ValueError:
                        continue
            write_contribution_report(d, world.spec, _records)
        for proc in (world.readback_proc, world.world_proc):
            if proc is not None and proc.returncode is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    await asyncio.wait_for(proc.wait(), timeout=15)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
        await world.export()
        hdr = json.loads(header.read_text()) if header.exists() else hdr
        hdr.update({"t_agents_end": time.time(), "t_agents_end_mono": time.monotonic(),
                    "agent_returncodes": rcs})
        header.write_text(json.dumps(hdr, indent=1, default=str))
        print(json.dumps({"run_id": run_id, "world_id": spec.get("world_id"),
                          "n_workers": n_workers, "workers_exited": len(rcs)}),
              flush=True)
        return 0
    finally:
        await world.down()


def _watch_parent():
    """No orphaned host: if the supervisor dies, the host dies with it."""
    parent = os.getppid()

    def _run():
        while True:
            time.sleep(0.5)
            try:
                if os.getppid() != parent:
                    os._exit(4)
            except Exception:
                return

    threading.Thread(target=_run, daemon=True).start()


async def _amain() -> int:
    mp = ShimPatch()
    build, cleanup = make_build_factory(mp)
    try:
        return await run_mission(build, mp)
    finally:
        await cleanup()
        mp.undo()


def main() -> int:
    _watch_parent()
    if not os.environ.get(auth_mod.ENV_URL):
        print("REFUSED: no attempt authority configured; mission host "
              "may not create a world (no legacy admit path)",
              file=sys.stderr, flush=True)
        return 3
    try:
        _st = auth_mod.client_from_env("gate").status()
    except Exception as exc:
        print(f"REFUSED: attempt authority unavailable ({exc}); mission host may not start",
              file=sys.stderr, flush=True)
        return 3
    if _st.get("state") != auth_mod.RUNNING:
        print(f"REFUSED: attempt authority state is {_st.get('state')}, not RUNNING; mission host may not start",
              file=sys.stderr, flush=True)
        return 3
    try:
        return asyncio.run(_amain())
    except AttemptAlreadyStarted as exc:
        print(str(exc), file=sys.stderr, flush=True)
        return 3
    except Exception as exc:  # host death: supervisor marks INTERRUPTED
        print(f"MISSION_HOST_FAILED: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
