"""Authoritative execution supervisor (WO-LEGION100-CAUSAL-CLOSURE-007, E6b).

The campaign path runs through this process only — never pytest:

    python -I supervisor.py --campaign B1 --family GAIA-EXE \
        --runs-root <dir> --dry-run --stub-plan <plan.json>

Lifecycle it alone owns (see CAUSAL_STATE_SPEC.md):
  register attempt (O_EXCL) -> RUNNING + one single-use world capability
  -> stub/proxy -> mission_host.py (no pytest) -> COMPLETED, or
  -> INTERRUPTED (verdict INVALID) on any host/critical death.
Terminal attempts are immutable; a later supervisor invocation for the
same run refuses (marking a supervisor-less RUNNING attempt INTERRUPTED),
so automatic or manual restart inside the same attempt is impossible.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
LEGION = HERE.parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(LEGION))

import attempt as attempt_mod  # noqa: E402
import attempt_authority as auth_mod  # noqa: E402

EVIDENCE_FILES = ("WORLD_LOG.jsonl", "GATE_COMMITS.jsonl",
                  "CONTROLLER_EVENTS.jsonl", "CAUSAL_CONTROLLER.jsonl",
                  "CAGE_EVIDENCE_CHAIN.jsonl", "VEIP_RELIANCE.jsonl",
                  "READBACK.jsonl", "WORKERS.jsonl", "provider_log.jsonl")
MODEL_DEFAULT = "nvidia/nemotron-3.5-lightning-30b-a3b"
UPSTREAM_DEFAULT = "https://integrate.api.nvidia.com/v1"

# ---------------------------------------------------------------------------
# Campaign CAGE posture (E6f / P0-16)
#
# The campaign path never runs under pytest, so it must not inherit the
# posture pytest's conftest used to supply implicitly. This is the SAME
# declared TEST posture B0/WO-006 and qualification ran under: every
# variable below is replicated from tests/conftest.py (module level +
# pytest_configure) that the gate/governor depends on, with values as
# they effectively were during a struct mission (the eu_ecb-marked
# test_struct_mission pinned CAGE_DEPLOYMENT_REGION=EU_ECB per-test;
# mission_host.py pins the same region + EU thresholds itself).
# It is established EXPLICITLY by the supervisor for every child it
# spawns (authority, stub, proxy, mission host) and is never inherited
# from the caller's environment: a caller exporting CAGE_ENV=production
# or CAGE_TELEMETRY_PROVIDER=remote cannot change it.
#
# Deliberate differences from conftest's literal text (see
# CAUSAL_STATE_SPEC.md "Campaign CAGE posture"): none weaken anything.
#   * CAGE_TELEMETRY_PROVIDER=null is set explicitly. Under conftest it
#     was unset and, with CAGE_ENV=test (non-enforcing) and no
#     TELEMETRY_* credentials in the sandbox, the factory fell back to
#     the identical NullTelemetryProvider. Explicit "null" makes the
#     effective provider deterministic even if the caller exported
#     telemetry credentials. Effective provider: unchanged (null).
#   * KMS_GOVERNANCE_KEY / KMS_GOVERNANCE_PUBLIC_PEM are forced UNSET
#     (conftest pops them), forcing the same HMAC seal fallback.
#   * TELEMETRY_HOST/PUBLIC_KEY/SECRET_KEY are forced UNSET for the
#     same reason (no credential inheritance; provider is null anyway).
CAMPAIGN_CAGE_POSTURE: dict[str, str] = {
    "CAGE_ENV": "test",
    "CAGE_DOMAIN": "finance",
    "CAGE_DEPLOYMENT_REGION": "EU_ECB",
    "GOOGLE_CLOUD_LOCATION": "europe-west1",
    "CAGE_TELEMETRY_PROVIDER": "null",
    "GOVERNANCE_SALT": "dev-only-insecure-placeholder-not-for-production-use",
    "LANGFUSE_POSTURE_DRY_RUN": "true",
    "CMEK_KEY_RESOURCE_NAME": "projects/test-project/locations/us-central1/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/1",
    "CAGE_TRUSTED_CLIENT_IDENTITIES": "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local",
    "LANGCHAIN_TRACING_V2": "false",
    "LANGSMITH_TRACING": "false",
    "OBJC_DISABLE_INITIALIZE_FORK_SAFETY": "YES",
    "TOKENIZERS_PARALLELISM": "false",
    "EVIDENCE_STREAM_ENABLED": "true",
    "OTEL_TRACES_EXPORTER": "none",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:3001/api/public/otel/v1/traces",
    "OPENLLMETRY_ENABLED": "false",
    "BACKEND_URL": "http://localhost:18080",
    "GATEWAY_URL": "http://localhost:8080",
    "LANGFUSE_HOST": "http://localhost:3001",
    "LANGFUSE_BASEURL": "http://localhost:3001",
    "VLLM_REASONING_API_BASE": "http://localhost:8000/v1",
    "VLLM_SERVICE_URL": "http://localhost:8001",
    "COMPLIANCE_BRIDGE_URL": "http://localhost:3002",
    "OPA_URL": "http://localhost:8181",
    "OPA_CACHE_ENABLED": "false",
    "REDIS_URL": "redis://localhost:6379",
}
CAMPAIGN_POSTURE_UNSET: tuple[str, ...] = (
    "KMS_GOVERNANCE_KEY",
    "KMS_GOVERNANCE_PUBLIC_PEM",
    "TELEMETRY_HOST",
    "TELEMETRY_PUBLIC_KEY",
    "TELEMETRY_SECRET_KEY",
)
# Only these non-posture system variables are inherited from the caller;
# everything else a child needs is passed explicitly by the supervisor.
_SYSTEM_ENV_KEYS = ("PATH", "HOME", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR",
                    "LANG", "LC_ALL", "USER", "COMSPEC", "PATHEXT")


def campaign_posture_record() -> dict:
    """Full declared posture for RUN_HEADER/attempt.json (no secrets).

    The salt above is the public dev-only placeholder conftest itself
    uses; forced-unset variables are recorded by name only.
    """
    return {"vars": dict(CAMPAIGN_CAGE_POSTURE),
            "unset": list(CAMPAIGN_POSTURE_UNSET)}


def _campaign_env(extra: dict | None = None) -> dict:
    """Child environment: minimal system vars + declared posture + extra.

    The caller's environment is NOT inherited (in particular no CAGE_*,
    KMS_*, TELEMETRY_* or STRUCT_* variable leaks in); ``extra`` carries
    exactly what the supervisor intends this child to receive.
    """
    env = {k: os.environ[k] for k in _SYSTEM_ENV_KEYS if os.environ.get(k)}
    env.update(CAMPAIGN_CAGE_POSTURE)
    for name in CAMPAIGN_POSTURE_UNSET:
        env.pop(name, None)
    if extra:
        env.update(extra)
    return env


def _port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]; s.close(); return p


def _agents_for(spec, campaign, n_workers):
    agents = [r["agent_id"] for r in spec.get("roles") or []]
    if campaign == "S100":
        sys.path.insert(0, str(LEGION))
        from causal_007.delegation import build_s100_spec
        agents = [r["agent_id"] for r in build_s100_spec(spec, total=n_workers)
                  .get("roles") or []]
        return agents
    for i in range(1, n_workers - len(agents) + 1):
        agents.append(f"agent:standby-{i:03d}")
    return agents


def _kill_group(proc, grace_s=10.0):
    """Kill a whole process group (leader), TERM then KILL; verify empty.

    The group is signalled even when the leader is already dead: a
    SIGKILLed host leaves its agents/world in the group, and they must
    be terminated explicitly, not only via their parent watch.
    """
    if proc is None:
        return
    pid = proc.pid
    try:
        if os.name == "posix":
            os.killpg(pid, signal.SIGTERM)
        else:
            proc.terminate()
    except (ProcessLookupError, PermissionError, OSError):
        pass
    deadline = time.time() + grace_s
    while time.time() < deadline:
        if proc.poll() is not None and not _group_alive(pid):
            break
        time.sleep(0.1)
    if proc.poll() is None or _group_alive(pid):
        try:
            if os.name == "posix":
                os.killpg(pid, signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.wait(timeout=10)
        except Exception:
            pass


def _group_alive(pid) -> bool:
    if os.name != "posix":
        return False
    try:
        os.killpg(pid, 0)
    except (ProcessLookupError, PermissionError, OSError):
        return False
    # A group whose only members are zombies is dead: zombies execute
    # nothing and hold no sockets; their reaper (PID 1) may never
    # collect them in a sandbox.
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                stat = Path("/proc", entry, "stat").read_text()
                rest = stat.rsplit(")", 1)[1].split()
                state, pgrp = rest[0], int(rest[2])
            except (OSError, ValueError, IndexError):
                continue
            if pgrp == pid and state != "Z":
                return True
        return False
    except OSError:
        return True  # no /proc: fall back to the killpg result


class Supervisor:
    def __init__(self, args):
        self.args = args
        self.children: list[subprocess.Popen] = []
        self.host = None
        self.authority = None
        self.authority_client = None
        self._authority_env = {}
        self._stop = False
        self._hb_stop = False
        self._log_key = None
        self._attempt_log = None
        self._rec = None
        self._state = None
        self._snapshot_hash = None
        self._tamper_recorded = False
        self._status_token = ""

    # ---- owner lifecycle record (E6g: ATTEMPT_LOG is truth, attempt.json snapshot only)
    def _snapshot_bytes_hash(self, run_dir):
        try:
            return hashlib.sha256((Path(run_dir) / "attempt.json").read_bytes()).hexdigest()
        except OSError:
            return None

    def _refresh_snapshot_hash(self, run_dir):
        self._snapshot_hash = self._snapshot_bytes_hash(run_dir)

    def _write_snapshot(self, run_dir, state, *, reason="", verdict=None):
        if self._rec is None:
            return
        self._state = state
        self._rec["state"] = state
        if verdict is not None:
            self._rec["verdict"] = verdict
        self._rec.setdefault("transitions", []).append(
            {"state": state, "t": time.time(), "pid": os.getpid(), "reason": reason})
        if self._attempt_log is not None:
            self._attempt_log.world_instance_id = self._rec.get("world_instance_id")
        attempt_mod.write_snapshot(run_dir, self._rec)
        self._refresh_snapshot_hash(run_dir)

    def _log_append(self, run_dir, event, *, state, reason="", verdict=None):
        if self._attempt_log is None:
            return None
        rec = self._attempt_log.append(event, state=state, reason=reason, verdict=verdict)
        return rec

    def _detect_tamper(self, run_dir):
        """E6g declared policy TAMPER_POLICY=continue_and_record: record once, restore snapshot, continue."""
        if self._rec is None or self._snapshot_hash is None:
            return False
        cur = self._snapshot_bytes_hash(run_dir)
        if cur == self._snapshot_hash:
            return False
        if not self._tamper_recorded:
            self._tamper_recorded = True
            try:
                self._log_append(run_dir, "EVIDENCE_TAMPER_DETECTED", state=self._state or self._rec.get("state"),
                                 reason="attempt.json diverged from owner snapshot")
            except Exception:
                pass
            print("EVIDENCE_TAMPER_DETECTED: attempt.json diverged; continuing under live authority", file=sys.stderr)
        # Restore owner snapshot (do not adopt tampered state)
        try:
            attempt_mod.write_snapshot(run_dir, self._rec)
            self._refresh_snapshot_hash(run_dir)
        except Exception:
            pass
        return True

    def _owner_terminal(self, run_dir, state, *, reason="", verdict=None):
        """Owner ALWAYS writes terminal to ATTEMPT_LOG + snapshot, whatever files did."""
        self._detect_tamper(run_dir)
        # Authority first if alive
        try:
            self._authority_transition(state)
        except Exception:
            pass
        try:
            self._log_append(run_dir, state, state=state, reason=reason, verdict=verdict)
        except Exception as exc:
            print(f"ATTEMPT_LOG terminal write failed: {exc}", file=sys.stderr)
        try:
            self._write_snapshot(run_dir, state, reason=reason, verdict=verdict)
        except Exception:
            pass
        # Verify chain at end
        ok, problems = (False, ["no log"])
        if self._attempt_log is not None:
            try:
                ok, problems, _ = self._attempt_log.verify()
            except Exception as exc:
                problems = [str(exc)]
        if not ok:
            print(f"ATTEMPT_LOG verification failed: {problems[:3]}", file=sys.stderr)
        return ok

    def _start_authority(self, run_dir, attempt_uid):
        """Spawn the per-attempt authority process (E6e).

        Key + tokens are generated here, exist only in the authority
        process memory and in the gate/world spawn environments below,
        and never touch the run directory or any agent environment.
        """
        import secrets as _secrets
        port = _port()
        sup_tok, gate_tok, world_tok = (_secrets.token_hex(16) for _ in range(3))
        self._status_token = _secrets.token_hex(16)
        if self._log_key is None:
            self._log_key = _secrets.token_bytes(32)
        key_hex = self._log_key.hex()
        # WO008-MUSE-001: durable authority store (reservations, revocation
        # barrier, transition chain) in a supervisor-owned temp dir --
        # never the run directory, never an agent environment.
        self._authority_store_dir = Path(tempfile.mkdtemp(
            prefix="causal-authority-"))
        env = _campaign_env({
               "ATTEMPT_AUTHORITY_UID": attempt_uid,
               "ATTEMPT_AUTHORITY_STORE": str(
                   self._authority_store_dir / "authority_store.json"),
               "ATTEMPT_AUTHORITY_KEY": key_hex,
               "ATTEMPT_AUTHORITY_SUPERVISOR_TOKEN": sup_tok,
               "ATTEMPT_AUTHORITY_GATE_TOKEN": gate_tok,
               "ATTEMPT_AUTHORITY_WORLD_TOKEN": world_tok,
               "ATTEMPT_AUTHORITY_STATUS_TOKEN": self._status_token})
        self.authority = self._spawn(
            [sys.executable, "-I", str(HERE / "attempt_authority.py"),
             "--port", str(port)], env, "attempt_authority.log", run_dir)
        url = f"http://127.0.0.1:{port}"
        self.authority_client = auth_mod.AuthorityClient(url, sup_tok)
        self._authority_env = {
            auth_mod.ENV_URL: url, auth_mod.ENV_KEY: key_hex,
            auth_mod.ENV_GATE_TOKEN: gate_tok,
            auth_mod.ENV_WORLD_TOKEN: world_tok,
            auth_mod.ENV_STATUS_TOKEN: self._status_token}
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.authority.poll() is not None:
                raise RuntimeError("attempt authority exited early")
            try:
                self.authority_client.status()
                break
            except Exception:
                time.sleep(0.05)
        else:
            raise RuntimeError("attempt authority did not come up")
        return url

    def _authority_transition(self, to_state, *, world_instance_id=None):
        if self.authority_client is not None:
            try:
                return self.authority_client.transition(
                    to_state, world_instance_id=world_instance_id)
            except Exception:
                return None
        return None

    # ------------------------------------------------------------- setup
    def refuse_existing(self, run_dir: Path) -> int | None:
        # E6g: pre-start refusal on authenticated state only: verified
        # ATTEMPT_LOG chain and/or runs-root registry. attempt.json is
        # never believed; a forged/deleted snapshot cannot reset a run.
        registry = attempt_mod.read_registry(run_dir.parent, run_dir.name)
        log_ok, log_problems, log_recs = attempt_mod.verify_attempt_log(run_dir)
        has_log = bool(log_recs)
        terminal_rec = None
        if log_ok:
            for r in reversed(log_recs):
                if r.get("state") in attempt_mod.TERMINAL:
                    terminal_rec = r
                    break
        if terminal_rec is not None:
            print(f"REFUSED: attempt {terminal_rec.get('attempt_uid')} is terminal "
                  f"({terminal_rec.get('state')}) per verified ATTEMPT_LOG; restart is impossible", file=sys.stderr)
            return 3
        if registry is not None:
            pid = registry.get("supervisor_pid")
            if attempt_mod.pid_alive(pid):
                print("REFUSED: attempt already owned by a live supervisor (registry)", file=sys.stderr)
                return 3
            # Owner lost and no owner-written terminal: refuse restart.
            # Mark snapshot INTERRUPTED for legacy readers (evidence only);
            # ATTEMPT_LOG is left untouched (second supervisor has no key).
            try:
                rec = attempt_mod.read_attempt(run_dir) or {}
                rec.update({"state": attempt_mod.INTERRUPTED, "verdict": "INVALID",
                            "attempt_uid": registry.get("attempt_uid") or rec.get("attempt_uid")})
                rec.setdefault("transitions", []).append({"state": attempt_mod.INTERRUPTED, "t": time.time(), "pid": os.getpid(), "reason": "supervisor_lost_restart_refused"})
                attempt_mod.write_snapshot(run_dir, rec)
            except Exception:
                pass
            print("REFUSED: previous supervisor lost (registry); attempt marked "
                  "INTERRUPTED/INVALID; restart is impossible", file=sys.stderr)
            return 3
        if has_log:
            # A used attempt (valid chain or not) is never startable again.
            print(f"REFUSED: ATTEMPT_LOG exists for this run (verified={log_ok}); restart is impossible", file=sys.stderr)
            return 3
        rec = attempt_mod.read_attempt(run_dir)
        if rec is None:
            return None
        print("REFUSED: attempt already registered (legacy evidence); restart is impossible", file=sys.stderr)
        return 3

    def run(self) -> int:
        a = self.args
        world_file = Path(a.world_file) if a.world_file else (
            LEGION / "worlds" / ("SYN-OTEL-04.world.json" if a.campaign == "S100"
                                 else f"SYN-{a.family}.world.json"))
        if not world_file.exists():
            print(f"world not found: {world_file}", file=sys.stderr)
            return 2
        ztl = os.environ.get("LEGION_ZTL_SWARM_DIR") or str(
            Path.home() / "legion_pf" / "ztl-swarm")
        if not Path(ztl).is_dir():
            print(f"REFUSED: LEGION_ZTL_SWARM_DIR does not exist: {ztl}",
                  file=sys.stderr)
            return 2
        run_id = a.run_id or ("s100-SYN-OTEL-04" if a.campaign == "S100"
                              else f"b1-{a.family}")
        runs_root = Path(a.runs_root)
        run_dir = runs_root / run_id
        if run_dir.exists():
            refused = self.refuse_existing(run_dir)
            if refused is not None:
                return refused
            if any(run_dir.iterdir()):
                print(f"REFUSED: run dir already exists: {run_dir}",
                      file=sys.stderr)
                return 3
        elif attempt_mod.read_registry(runs_root, run_id) is not None:
            print("REFUSED: registry entry exists for this run_id; restart is impossible", file=sys.stderr)
            return 3
        spec_bytes = world_file.read_bytes()
        spec = json.loads(spec_bytes.decode("utf-8"))
        world_sha = hashlib.sha256(spec_bytes).hexdigest()
        runtime_sha = attempt_mod.runtime_sha256(REPO)
        run_dir.mkdir(parents=True, exist_ok=True)
        try:
            rec = attempt_mod.register(
                run_dir, campaign_id=a.campaign, run_id=run_id,
                attempt_index=a.attempt_index, world_sha256=world_sha,
                runtime_sha=runtime_sha,
                cage_posture=campaign_posture_record())
        except attempt_mod.AttemptAlreadyRegistered:
            # Concurrent second supervisor: refused before creating anything.
            refused = self.refuse_existing(run_dir)
            return refused if refused is not None else 3
        attempt_uid = rec["attempt_uid"]
        self._rec = dict(rec)
        self._state = attempt_mod.REGISTERED
        import secrets as _sec
        self._log_key = _sec.token_bytes(32)
        self._attempt_log = attempt_mod.AttemptLog(run_dir, self._log_key, attempt_uid=attempt_uid)
        self._log_append(run_dir, attempt_mod.REGISTERED, state=attempt_mod.REGISTERED, reason="register")
        try:
            attempt_mod.write_registry(runs_root, run_id, {"run_id": run_id, "attempt_uid": attempt_uid, "supervisor_pid": os.getpid(), "run_dir": str(run_dir), "t": time.time()})
        except FileExistsError:
            print("REFUSED: registry entry already exists; restart is impossible", file=sys.stderr)
            return 3
        self._refresh_snapshot_hash(run_dir)
        # RUN_HEADER (WO-006 compatible), registered before any proxy.
        budgets = spec.get("budgets") or {}
        hdr = {"run_id": run_id, "attempt_index": a.attempt_index,
               "campaign": a.campaign, "family": a.family,
               "frozen_commit": os.environ.get("STRUCT_CAGE_HEAD", "unknown"),
               "world_sha256": world_sha, "attempt_uid": attempt_uid,
               "t_episode_registered": rec["t_registered"],
               "t_episode_registered_mono": rec["t_registered_mono"],
               "t_registered": rec["t_registered"],
               "n_workers": a.n_workers,
               "model": MODEL_DEFAULT if not a.dry_run else "stub-model",
               "upstream": UPSTREAM_DEFAULT if not a.dry_run else "stub",
               "max_model_turns_per_agent": 14,
               "max_duration_s": int(float(budgets.get("max_duration_s", 420))),
               "cage_posture": campaign_posture_record(),
               "judged": False}
        (run_dir / "RUN_HEADER.json").write_text(json.dumps(hdr, indent=1))
        for name in EVIDENCE_FILES:
            (run_dir / name).touch(exist_ok=True)
        if a.quick:
            print(json.dumps({"dry_run": True, "quick": True,
                              "run_id": run_id, "run_dir": str(run_dir)}))
            return 0
        # REGISTERED -> RUNNING (authority first: it is the source of
        # truth; attempt.json below is evidence). Mint both single-use
        # world capabilities (authority + file-evidence copy).
        self._start_authority(run_dir, attempt_uid)
        (run_dir / ".authority_pid").write_text(str(self.authority.pid))
        world_instance_id = uuid.uuid4().hex
        self._authority_transition(auth_mod.RUNNING,
                                   world_instance_id=world_instance_id)
        self._world_capability = self.authority_client.mint_capability()
        token = uuid.uuid4().hex
        # Owner in-memory RUNNING transition: ATTEMPT_LOG + snapshot, never reading attempt.json
        self._rec["world_instance_id"] = world_instance_id
        self._rec["capability_sha256"] = hashlib.sha256(token.encode()).hexdigest()
        self._attempt_log.world_instance_id = world_instance_id
        self._log_append(run_dir, attempt_mod.RUNNING, state=attempt_mod.RUNNING, reason="supervisor_start")
        self._write_snapshot(run_dir, attempt_mod.RUNNING, reason="supervisor_start")
        attempt_mod.write_capability(run_dir, token)
        hdr["world_instance_id"] = world_instance_id
        (run_dir / "RUN_HEADER.json").write_text(json.dumps(hdr, indent=1))
        return self._run_attempt(run_dir, run_id, spec, world_file,
                                 attempt_uid, world_instance_id, ztl)

    # ------------------------------------------------------------- attempt
    def _heartbeat_loop(self, run_dir):
        while not self._hb_stop:
            attempt_mod.heartbeat(run_dir)
            time.sleep(1.0)

    def _spawn(self, argv, env, log_name, run_dir):
        log_fh = open(run_dir / log_name, "ab")
        kwargs = {"stdout": log_fh, "stderr": subprocess.STDOUT, "env": env}
        if os.name == "posix":
            kwargs["start_new_session"] = True
        proc = subprocess.Popen(argv, **kwargs)
        self.children.append(proc)
        return proc

    def _run_attempt(self, run_dir, run_id, spec, world_file,
                     attempt_uid, world_instance_id, ztl) -> int:
        a = self.args
        import threading
        self._hb_stop = False
        hb = threading.Thread(target=self._heartbeat_loop, args=(run_dir,),
                              daemon=True)
        hb.start()

        def _on_signal(signum, frame):
            self._stop = True

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, _on_signal)
            except (ValueError, OSError):
                pass
        tmpd = Path(tempfile.mkdtemp(prefix="causal-supervisor-"))
        stub = proxy = None
        host_rc = 1
        try:
            agents = _agents_for(spec, a.campaign, a.n_workers)
            token_map, env_tokens = {}, {}
            for agent in agents:
                tok = uuid.uuid4().hex
                token_map[tok] = agent
                suffix = "".join(c if c.isalnum() else "_"
                                 for c in agent.replace("agent:", "")).upper()
                env_tokens[f"SCALE_PROXY_TOKEN_{suffix}"] = tok
            token_file = tmpd / "proxy_tokens.json"
            token_file.write_text(json.dumps(token_map))
            base_env = _campaign_env({**self._authority_env,
                        auth_mod.ENV_CAPABILITY:
                            getattr(self, "_world_capability", ""),
                        "STRUCT_ATTEMPT_FILE": str(run_dir / "attempt.json"),
                        "STRUCT_ATTEMPT_UID": attempt_uid,
                        "STRUCT_WORLD_INSTANCE_ID": world_instance_id,
                        "STRUCT_RUN_DIR": str(run_dir)})
            # Authority channel goes to the host (gate/world) only:
            # stub/proxy children get base_env without it, agents never.
            proxy_env = {k: v for k, v in base_env.items()
                         if not k.startswith("STRUCT_AUTHORITY")
                         and k != auth_mod.ENV_CAPABILITY}
            # Read-only status channel for proxy/sidecar terminal checks (no permit/world power)
            proxy_env[auth_mod.ENV_URL] = self._authority_env.get(auth_mod.ENV_URL, "")
            proxy_env[auth_mod.ENV_STATUS_TOKEN] = self._status_token
            proxy_port = _port()
            if a.decider == "nim" and a.dry_run:
                stub_port = _port()
                stub = self._spawn(
                    [sys.executable, "-I", str(HERE / "stub_model_server.py"),
                     "--port", str(stub_port),
                     "--plan-file", a.stub_plan or str(tmpd / "stub_plan.json"),
                     "--delay-s", str(a.stub_delay_s),
                     "--storm-429-count", str(a.storm_429_count)],
                    {**proxy_env}, "stub_model.log", run_dir)
                proxy = self._spawn(
                    [sys.executable, "-I", str(HERE / "provider_proxy.py"),
                     "--port", str(proxy_port),
                     "--log", str(run_dir / "provider_log.jsonl"),
                     "--token-map", str(token_file),
                     "--upstream", f"http://127.0.0.1:{stub_port}/v1",
                     "--key-source", "stub", "--allow-no-key",
                     "--attempt-file", str(run_dir / "attempt.json"),
                     "--max-retries", str(a.proxy_max_retries)],
                    {**proxy_env}, "provider_proxy.log", run_dir)
                model = "stub-model"
            elif a.decider == "nim":
                proxy = self._spawn(
                    [sys.executable, "-I", str(HERE / "provider_proxy.py"),
                     "--port", str(proxy_port),
                     "--log", str(run_dir / "provider_log.jsonl"),
                     "--token-map", str(token_file),
                     "--upstream", a.upstream, "--key-source", a.key_source,
                     "--attempt-file", str(run_dir / "attempt.json"),
                     "--max-retries", str(a.proxy_max_retries)],
                    {**proxy_env}, "provider_proxy.log", run_dir)
                model = a.model
            else:
                model = a.model
            if proxy is not None:
                self._wait_health(proxy_port, proxy, "provider proxy")
            host_env = {**base_env, **env_tokens,
                        "STRUCT_WORLD": str(world_file),
                        "STRUCT_OUT": str(run_dir.parent),
                        "STRUCT_RUN_ID": run_id,
                        "STRUCT_MODE": a.mode,
                        "STRUCT_DECIDER": a.decider,
                        "STRUCT_N_WORKERS": str(a.n_workers),
                        "STRUCT_CAUSAL": "1",
                        "SCALE_PROXY_URL": f"http://127.0.0.1:{proxy_port}",
                        "SCALE_MODEL": model,
                        "GOVERNANCE_SEAL_TTL_S": "1800",
                        "LEGION_COMPOSITION": "v3",
                        "MCP_RATE_LIMIT_MAX_CALLS": "6000",
                        "LEGION_ZTL_SWARM_DIR": ztl}
            if a.campaign == "S100":
                host_env["STRUCT_CAUSAL_OVERLAY"] = "s100"
            if a.plan:
                host_env["STRUCT_PLAN"] = a.plan
            elif os.environ.get("STRUCT_PLAN"):
                host_env["STRUCT_PLAN"] = os.environ["STRUCT_PLAN"]
            self.host = self._spawn(
                [sys.executable, "-I", str(HERE / "mission_host.py")],
                host_env, "mission_host.log", run_dir)
            (run_dir / ".host_pid").write_text(str(self.host.pid))
            host_rc = self._monitor(run_dir, stub, proxy)
        except Exception as exc:
            print(f"SUPERVISOR_ERROR: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            host_rc = 1
        finally:
            # No child of this attempt may survive, whatever happened.
            _kill_group(self.host)
            _kill_group(proxy)
            _kill_group(stub)
            for proc in (self.host, proxy, stub):
                if proc is not None and _group_alive(proc.pid):
                    print(f"ERROR: orphan process group {proc.pid} remains",
                          file=sys.stderr)
                    host_rc = host_rc or 97
            self._hb_stop = True
            shutil.rmtree(tmpd, ignore_errors=True)
            try:
                (run_dir / "world_tokens.json").unlink(missing_ok=True)
            except OSError:
                pass
        # Owner terminal from in-memory state only (E6g); attempt.json never consulted.
        if self._state in attempt_mod.TERMINAL:
            _kill_group(self.authority)
            return 0 if self._state == attempt_mod.COMPLETED else 4
        if host_rc == 0 and not self._stop:
            problems = self._validate(run_dir)
            if problems:
                print(f"EVIDENCE_INVALID: {problems[:5]}", file=sys.stderr)
                self._owner_terminal(run_dir, attempt_mod.INTERRUPTED, reason="evidence_invalid", verdict="INVALID")
                _kill_group(self.authority)
                return 5
            self._owner_terminal(run_dir, attempt_mod.COMPLETED, reason="mission_host_completed")
            _kill_group(self.authority)
            return 0
        self._owner_terminal(run_dir, attempt_mod.INTERRUPTED,
                             reason="host_died_no_restart" if not self._stop else "supervisor_signalled",
                             verdict="INVALID")
        _kill_group(self.authority)
        return host_rc if host_rc else 4

    def _monitor(self, run_dir, stub, proxy) -> int:
        while True:
            if self._stop:
                return 4
            self._detect_tamper(run_dir)
            # Live authority is truth; unreachable/terminal authority = fail closed
            if self.authority_client is not None:
                try:
                    st = self.authority_client.status()
                    if st.get("state") in attempt_mod.TERMINAL:
                        return 4
                    if st.get("state") != attempt_mod.RUNNING:
                        return 1
                except Exception:
                    return 1
            for critical in (stub, proxy, self.authority):
                if critical is not None and critical.poll() is not None:
                    return 1
            rc = self.host.poll()
            if rc is not None:
                return rc
            time.sleep(0.2)

    @staticmethod
    def _wait_health(port, proc, label):
        import urllib.request
        for _ in range(200):
            if proc.poll() is not None:
                raise RuntimeError(f"{label} exited early: {proc.returncode}")
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/health", timeout=2) as r:
                    if r.status == 200:
                        return
            except Exception:
                time.sleep(0.05)
        raise RuntimeError(f"{label} did not come up")

    @staticmethod
    def _validate(run_dir: Path) -> list[str]:
        problems = attempt_mod.validate_evidence(run_dir)
        world_log = run_dir / "WORLD_LOG.jsonl"
        starts = 0
        if world_log.exists():
            for line in world_log.read_text(
                    encoding="utf-8", errors="ignore").splitlines():
                try:
                    if json.loads(line).get("kind") == "WORLD_START":
                        starts += 1
                except ValueError:
                    continue
        if starts != 1:
            problems.append(f"WORLD_START count is {starts}, expected 1")
        return problems


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--campaign", required=True, choices=("B1", "S100"))
    p.add_argument("--family", required=True)
    p.add_argument("--run-id", default="")
    p.add_argument("--runs-root", required=True)
    p.add_argument("--world-file", default="")
    p.add_argument("--attempt-index", type=int, default=1)
    p.add_argument("--n-workers", type=int, default=100)
    p.add_argument("--decider", default="nim", choices=("nim", "scripted"))
    p.add_argument("--mode", default="MODEL_E2E")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--quick", action="store_true",
                   help="register attempt + RUN_HEADER only (light unit hook)")
    p.add_argument("--stub-plan", default="")
    p.add_argument("--plan", default="", help="scripted plan file")
    p.add_argument("--stub-delay-s", type=float, default=0.0)
    p.add_argument("--storm-429-count", type=int, default=0)
    p.add_argument("--proxy-max-retries", type=int, default=6)
    p.add_argument("--upstream", default=UPSTREAM_DEFAULT)
    p.add_argument("--key-source", default="stub")
    p.add_argument("--model", default=MODEL_DEFAULT)
    args = p.parse_args(argv)
    if args.campaign == "B1" and not args.family:
        p.error("family required")
    return Supervisor(args).run()


if __name__ == "__main__":
    sys.exit(main())
