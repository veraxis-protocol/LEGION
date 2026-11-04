"""Authoritative attempt registry (WO-LEGION100-CAUSAL-CLOSURE-007, E6b).

Single owner of the attempt lifecycle. Stdlib only so it can be imported
with ``python -I`` by the supervisor, the mission host, the world server,
the gate, the sidecar, the readback and the provider proxy alike.

Lifecycle (see CAUSAL_STATE_SPEC.md)::

    REGISTERED -> RUNNING -> COMPLETED
                          -> INTERRUPTED        (verdict path INVALID)

Terminal states (COMPLETED / INTERRUPTED) are immutable: no transition
out of them, and every evidence writer that can see the attempt file
must reject writes once a terminal state is reached.

Registration is an O_EXCL create + fsync of ``attempt.json`` inside the
run directory: re-registering the same (campaign_id, run_id,
attempt_index) key is impossible, even concurrently.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from pathlib import Path

ATTEMPT_FILE = "attempt.json"
ATTEMPT_LOG_FILE = "ATTEMPT_LOG.jsonl"
REGISTRY_DIR = ".attempt_registry"
GENESIS_HASH = "0" * 64
# Declared tamper policy (E6g): detected evidence tampering is recorded
# as EVIDENCE_TAMPER_DETECTED in ATTEMPT_LOG; the attempt CONTINUES under
# the live authority (a forged COMPLETED must never shut it down) unless
# the owner independently decides to interrupt. The owner always writes
# the terminal record itself.
TAMPER_POLICY = "continue_and_record"
STATUS_FILE = "ATTEMPT_STATUS.json"
CAPABILITY_FILE = ".world_capability.json"
CAPABILITY_CONSUMED = ".world_capability.consumed"
HEARTBEAT_FILE = ".supervisor_heartbeat.json"

REGISTERED = "REGISTERED"
RUNNING = "RUNNING"
COMPLETED = "COMPLETED"
INTERRUPTED = "INTERRUPTED"
TERMINAL = frozenset({COMPLETED, INTERRUPTED})
_TRANSITIONS = {
    REGISTERED: frozenset({RUNNING, INTERRUPTED}),
    RUNNING: frozenset({COMPLETED, INTERRUPTED}),
    COMPLETED: frozenset(),
    INTERRUPTED: frozenset(),
}

_lock = threading.Lock()

# Runtime sources whose bytes define the executing runtime. The hash is
# registered before anything starts so a run can never silently mix
# code from two different runtimes.
RUNTIME_FILES = (
    "tests/legion_struct/causal_007/attempt.py",
    "tests/legion_struct/causal_007/attempt_authority.py",
    "tests/legion_struct/causal_007/supervisor.py",
    "tests/legion_struct/causal_007/mission_host.py",
    "tests/legion_struct/causal_007/causal_registry.py",
    "tests/legion_struct/causal_007/sidecar.py",
    "tests/legion_struct/causal_007/sidecar_server.py",
    "tests/legion_struct/causal_007/provider_proxy.py",
    "tests/legion_struct/causal_007/nim_transport.py",
    "tests/legion_struct/causal_007/stub_model_server.py",
    "tests/legion_struct/causal_007/delegation.py",
    "tests/legion_struct/world_server.py",
    "tests/legion_struct/world_engine.py",
    "tests/legion_struct/struct_agent.py",
    "tests/legion_struct/struct_readback.py",
    "tests/legion_struct/struct_plugin.py",
    "tests/legion_struct/struct_controller.py",
    "tests/legion_struct/test_struct_mission.py",
)


class AttemptError(RuntimeError):
    pass


class AttemptAlreadyRegistered(AttemptError):
    pass


class AttemptTerminal(AttemptError):
    pass


def runtime_sha256(repo_root) -> str:
    h = hashlib.sha256()
    root = Path(repo_root)
    for rel in RUNTIME_FILES:
        p = root / rel
        h.update(rel.encode())
        h.update(b"\0")
        try:
            h.update(p.read_bytes())
        except OSError:
            h.update(b"<missing>")
        h.update(b"\0")
    return h.hexdigest()


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _atomic_write(path: Path, obj: dict) -> None:
    tmp = path.with_name(path.name + f".tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    data = (json.dumps(obj, indent=1, default=str) + "\n").encode()
    fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise OSError("os.write wrote no bytes")
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(path))
    _fsync_dir(path.parent)


def _log_canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode()


def read_attempt_log(run_dir) -> list:
    p = Path(run_dir) / ATTEMPT_LOG_FILE
    out = []
    try:
        lines = p.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for line in lines:
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            out.append({"_unparseable": line})
    return out


def verify_attempt_log(run_dir, key: bytes | None = None):
    """Verify hash chain (+MAC when key given). Returns (ok, problems, records)."""
    records = read_attempt_log(run_dir)
    problems: list[str] = []
    if not records:
        return False, ["ATTEMPT_LOG missing or empty"], records
    prev = GENESIS_HASH
    for i, rec in enumerate(records, 1):
        if "_unparseable" in rec:
            problems.append(f"seq {i}: unparseable")
            continue
        if rec.get("seq") != i:
            problems.append(f"seq {i}: out of order {rec.get('seq')}")
        if rec.get("prev_hash") != prev:
            problems.append(f"seq {i}: prev_hash mismatch (tamper)")
        payload = {k: v for k, v in rec.items() if k not in ("hash", "mac")}
        expect_hash = hashlib.sha256(_log_canonical(payload)).hexdigest()
        if rec.get("hash") != expect_hash:
            problems.append(f"seq {i}: hash mismatch (tamper)")
        if key is not None:
            expect_mac = hmac.new(key, expect_hash.encode(), hashlib.sha256).hexdigest()
            if not rec.get("mac") or not hmac.compare_digest(str(rec.get("mac")), expect_mac):
                problems.append(f"seq {i}: MAC mismatch (tamper)")
        prev = rec.get("hash") or prev
    return not problems, problems, records


def attempt_log_terminal(run_dir, key: bytes | None = None):
    ok, _problems, records = verify_attempt_log(run_dir, key=key)
    if not ok:
        return None
    for rec in reversed(records):
        if rec.get("state") in TERMINAL:
            return rec
    return None


class AttemptLog:
    """Owner-written append-only MAC'd hash chain (E6g). Only the supervisor holds the key."""

    def __init__(self, run_dir, key: bytes, *, attempt_uid, world_instance_id=None):
        self.run_dir = Path(run_dir)
        self.key = key
        self.attempt_uid = attempt_uid
        self.world_instance_id = world_instance_id
        self.path = self.run_dir / ATTEMPT_LOG_FILE
        self._lock = threading.Lock()

    def append(self, event, *, state, reason="", verdict=None):
        with self._lock:
            records = read_attempt_log(self.run_dir)
            seq = len(records) + 1
            prev = records[-1].get("hash") if records and "hash" in records[-1] else GENESIS_HASH
            rec = {"seq": seq, "event": event, "state": state, "reason": reason,
                   "verdict": verdict, "attempt_uid": self.attempt_uid,
                   "world_instance_id": self.world_instance_id,
                   "t": time.time(), "prev_hash": prev}
            rec["hash"] = hashlib.sha256(_log_canonical(rec)).hexdigest()
            rec["mac"] = hmac.new(self.key, rec["hash"].encode(), hashlib.sha256).hexdigest()
            data = (json.dumps(rec, default=str) + "\n").encode()
            self.run_dir.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                view = memoryview(data)
                while view:
                    n = os.write(fd, view)
                    if n <= 0:
                        raise OSError("os.write wrote no bytes")
                    view = view[n:]
                os.fsync(fd)
            finally:
                os.close(fd)
            _fsync_dir(self.run_dir)
            return rec

    def verify(self):
        return verify_attempt_log(self.run_dir, key=self.key)


def registry_path(runs_root, run_id) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in str(run_id))
    return Path(runs_root) / REGISTRY_DIR / f"{safe}.json"


def write_registry(runs_root, run_id, entry: dict) -> Path:
    p = registry_path(runs_root, run_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(entry, indent=1, default=str) + "\n").encode()
    fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(p.parent)
    return p


def read_registry(runs_root, run_id):
    try:
        return json.loads(registry_path(runs_root, run_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def write_snapshot(run_dir, rec: dict) -> dict:
    """Owner snapshot write: overwrites attempt.json from in-memory truth, never reads it."""
    run = Path(run_dir)
    run.mkdir(parents=True, exist_ok=True)
    _atomic_write(run / ATTEMPT_FILE, rec)
    _write_status(run, rec, reason=(rec.get("transitions") or [{}])[-1].get("reason", ""))
    return rec


def read_attempt(run_dir) -> dict | None:
    p = Path(run_dir) / ATTEMPT_FILE
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def attempt_state(run_dir) -> str | None:
    rec = read_attempt(run_dir)
    return rec.get("state") if rec else None


def is_terminal(run_dir) -> bool:
    return attempt_state(run_dir) in TERMINAL


def register(run_dir, *, campaign_id, run_id, attempt_index=1,
             world_sha256, runtime_sha, cage_posture=None) -> dict:
    """Atomically register a new attempt. Impossible to repeat."""
    run = Path(run_dir)
    run.mkdir(parents=True, exist_ok=True)
    rec = {
        "campaign_id": campaign_id,
        "run_id": run_id,
        "attempt_index": int(attempt_index),
        "attempt_uid": uuid.uuid4().hex,
        "world_sha256": world_sha256,
        "runtime_sha256": runtime_sha,
        "cage_posture": cage_posture,
        "state": REGISTERED,
        "world_instance_id": None,
        "capability_sha256": None,
        "supervisor_pid": os.getpid(),
        "t_registered": time.time(),
        "t_registered_mono": time.monotonic(),
        "transitions": [{"state": REGISTERED, "t": time.time(),
                         "t_mono": time.monotonic(), "pid": os.getpid()}],
        "verdict": None,
    }
    path = run / ATTEMPT_FILE
    data = (json.dumps(rec, indent=1) + "\n").encode()
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        raise AttemptAlreadyRegistered(
            f"attempt already registered: {path}") from None
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise OSError("os.write wrote no bytes")
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(run)
    return rec


def transition(run_dir, to_state, *, reason="", verdict=None) -> dict:
    """Move the attempt to ``to_state``. Terminal states are immutable."""
    run = Path(run_dir)
    with _lock:
        rec = read_attempt(run)
        if rec is None:
            raise AttemptError(f"no attempt registered in {run}")
        cur = rec.get("state")
        if cur in TERMINAL:
            raise AttemptTerminal(
                f"attempt {rec.get('attempt_uid')} is terminal ({cur}); "
                f"transition to {to_state} refused")
        if to_state not in _TRANSITIONS.get(cur, frozenset()):
            raise AttemptError(f"illegal transition {cur} -> {to_state}")
        rec["state"] = to_state
        if verdict is not None:
            rec["verdict"] = verdict
        rec.setdefault("transitions", []).append(
            {"state": to_state, "t": time.time(), "t_mono": time.monotonic(),
             "pid": os.getpid(), "reason": reason})
        _atomic_write(run / ATTEMPT_FILE, rec)
        _write_status(run, rec, reason=reason)
        return rec


def _write_status(run: Path, rec: dict, *, reason="") -> None:
    status = {
        "status": rec.get("state"),
        "attempt_uid": rec.get("attempt_uid"),
        "world_instance_id": rec.get("world_instance_id"),
        "run_id": rec.get("run_id"),
        "campaign_id": rec.get("campaign_id"),
        "attempt_index": rec.get("attempt_index"),
        "verdict": rec.get("verdict"),
        "reason": reason,
        "t": time.time(),
    }
    if rec.get("state") == INTERRUPTED:
        status["status"] = "INVALID"
        status["attempt_state"] = INTERRUPTED
        status.setdefault("verdict", "INVALID")
    try:
        _atomic_write(run / STATUS_FILE, status)
    except OSError:
        pass


def start_running(run_dir, *, capability_token: str,
                  world_instance_id: str | None = None) -> dict:
    """REGISTERED -> RUNNING; mint the world_instance_id + capability hash.

    The plaintext capability is never stored in attempt.json, only its
    SHA-256. The world server must present the token once to start.
    """
    run = Path(run_dir)
    with _lock:
        rec = read_attempt(run)
        if rec is None:
            raise AttemptError(f"no attempt registered in {run}")
        if rec.get("state") in TERMINAL:
            raise AttemptTerminal("attempt is terminal; cannot start")
        if rec.get("state") != REGISTERED:
            raise AttemptError(
                f"cannot start RUNNING from {rec.get('state')}")
        rec["world_instance_id"] = world_instance_id or uuid.uuid4().hex
        rec["capability_sha256"] = hashlib.sha256(
            capability_token.encode()).hexdigest()
        rec["state"] = RUNNING
        rec.setdefault("transitions", []).append(
            {"state": RUNNING, "t": time.time(), "t_mono": time.monotonic(),
             "pid": os.getpid(), "reason": "supervisor_start"})
        _atomic_write(run / ATTEMPT_FILE, rec)
        _write_status(run, rec, reason="supervisor_start")
        return rec


def write_capability(run_dir, token: str) -> Path:
    """Write the single-use world-creation capability (O_EXCL)."""
    run = Path(run_dir)
    path = run / CAPABILITY_FILE
    data = (json.dumps({"token": token}) + "\n").encode()
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


def consume_capability(run_dir, presented_token: str) -> dict:
    """Verify + consume the capability. Exactly one world may ever start.

    Raises AttemptError on any mismatch, on a terminal attempt, or if
    the capability was already consumed.
    """
    run = Path(run_dir)
    rec = read_attempt(run)
    if rec is None:
        raise AttemptError("no attempt registered; world may not start")
    if rec.get("state") in TERMINAL:
        raise AttemptTerminal(
            f"attempt is terminal ({rec.get('state')}); world may not start")
    if rec.get("state") != RUNNING:
        raise AttemptError(
            f"attempt is {rec.get('state')}, not RUNNING; world may not start")
    expect = rec.get("capability_sha256") or ""
    got = hashlib.sha256((presented_token or "").encode()).hexdigest()
    if not presented_token or got != expect:
        raise AttemptError("world capability mismatch; world may not start")
    marker = run / CAPABILITY_CONSUMED
    try:
        fd = os.open(str(marker), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        raise AttemptError(
            "world capability already consumed; a second world is "
            "impossible in this attempt") from None
    try:
        os.write(fd, json.dumps(
            {"attempt_uid": rec.get("attempt_uid"),
             "world_instance_id": rec.get("world_instance_id"),
             "pid": os.getpid(), "t": time.time()}).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.unlink(str(run / CAPABILITY_FILE))
    except OSError:
        pass
    return rec


def heartbeat(run_dir) -> None:
    try:
        _atomic_write(Path(run_dir) / HEARTBEAT_FILE,
                      {"pid": os.getpid(), "t": time.time(),
                       "t_mono": time.monotonic()})
    except OSError:
        pass


def heartbeat_age_s(run_dir) -> float | None:
    p = Path(run_dir) / HEARTBEAT_FILE
    try:
        rec = json.loads(p.read_text(encoding="utf-8"))
        return max(0.0, time.time() - float(rec.get("t") or 0))
    except (OSError, ValueError, TypeError):
        return None


def pid_alive(pid) -> bool:
    if not pid:
        return False
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if os.name == "nt":  # pragma: no cover - campaign runs under WSL/Linux
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def supervisor_lost(run_dir, *, stale_s: float = 15.0) -> bool:
    """True if the registered supervisor is dead or its heartbeat stale."""
    rec = read_attempt(run_dir)
    if rec is None:
        return False
    if not pid_alive(rec.get("supervisor_pid")):
        return True
    age = heartbeat_age_s(run_dir)
    return age is not None and age > stale_s


def stamp(rec: dict, run_dir=None, *, attempt_uid=None,
          world_instance_id=None) -> dict:
    """Add the unambiguous evidence identity to a record (additive)."""
    if attempt_uid is None and run_dir is not None:
        a = read_attempt(run_dir)
        if a:
            attempt_uid = a.get("attempt_uid")
            world_instance_id = world_instance_id or a.get("world_instance_id")
    if attempt_uid:
        rec.setdefault("attempt_uid", attempt_uid)
    if world_instance_id:
        rec.setdefault("world_instance_id", world_instance_id)
    return rec


def env_identity(env=None) -> tuple[str | None, str | None, str | None]:
    """(attempt_uid, world_instance_id, attempt_file) from an env mapping."""
    e = os.environ if env is None else env
    return (e.get("STRUCT_ATTEMPT_UID") or None,
            e.get("STRUCT_WORLD_INSTANCE_ID") or None,
            e.get("STRUCT_ATTEMPT_FILE") or None)


class EvidenceRejected(AttemptError):
    pass


def check_writable(run_dir, *, attempt_uid=None, world_instance_id=None):
    """Fail closed via LIVE authority only (E6g); files are evidence.

    With no attempt context (legacy unit use, attempt_uid None) there is
    nothing to guard. With a context, a live RUNNING authority matching
    the identity is required; absence of proof is denial.
    """
    if not attempt_uid and not world_instance_id:
        return read_attempt(run_dir)
    try:
        import attempt_authority as _auth
        st = _auth.client_from_env("gate").status()
    except Exception:
        try:
            import attempt_authority as _auth
            st = _auth.client_from_env("world").status()
        except Exception as exc:
            raise EvidenceRejected(f"attempt authority unavailable; write refused ({exc})") from exc
    if st.get("state") in TERMINAL:
        raise AttemptTerminal(f"attempt is terminal ({st.get('state')}); evidence write refused")
    if st.get("state") != RUNNING:
        raise EvidenceRejected(f"attempt is {st.get('state')}, not RUNNING; write refused")
    if attempt_uid and st.get("attempt_uid") != attempt_uid:
        raise EvidenceRejected("foreign attempt_uid; evidence write refused")
    if world_instance_id and st.get("world_instance_id") != world_instance_id:
        raise EvidenceRejected("foreign world_instance_id; evidence write refused")
    return st


def mark_interrupted(run_dir, *, reason="supervisor_lost") -> dict | None:
    """RUNNING/REGISTERED -> INTERRUPTED (no-op if already terminal)."""
    rec = read_attempt(run_dir)
    if rec is None or rec.get("state") in TERMINAL:
        return rec
    try:
        out = transition(run_dir, INTERRUPTED, reason=reason,
                         verdict="INVALID")
    except AttemptError:
        return read_attempt(run_dir)
    out["verdict"] = "INVALID"
    return out


def interrupt_if_supervisor_lost(run_dir, *, stale_s: float = 15.0,
                                 reason="supervisor_lost") -> dict | None:
    rec = read_attempt(run_dir)
    if rec is None or rec.get("state") in TERMINAL:
        return rec
    if supervisor_lost(run_dir, stale_s=stale_s):
        return mark_interrupted(run_dir, reason=reason)
    return rec


class StampedAppender:
    """Append-only JSONL writer stamping (attempt_uid, world_instance_id, seq).

    ``seq`` is strictly monotonic per file (resumed from the existing line
    count). Writers refuse foreign identities and any write after a
    terminal attempt state. Without an attempt context (legacy unit use)
    records are appended unstamped.
    """

    def __init__(self, path, run_dir=None, *, attempt_uid=None,
                 world_instance_id=None, seq_field="seq"):
        self.path = Path(path)
        self.run_dir = Path(run_dir) if run_dir else self.path.parent
        self.seq_field = seq_field
        if attempt_uid is None:
            try:
                import attempt_authority as _auth
                _st = _auth.client_from_env("gate").status()
                attempt_uid = _st.get("attempt_uid")
                world_instance_id = world_instance_id or _st.get("world_instance_id")
            except Exception:
                attempt_uid = os.environ.get("STRUCT_ATTEMPT_UID")
                world_instance_id = world_instance_id or os.environ.get("STRUCT_WORLD_INSTANCE_ID")
        self.attempt_uid = attempt_uid
        self.world_instance_id = world_instance_id
        self._lock = threading.Lock()
        self._seq = 0
        try:
            with open(self.path, encoding="utf-8") as fh:
                self._seq = sum(1 for line in fh if line.strip())
        except OSError:
            self._seq = 0

    def append(self, rec: dict) -> dict:
        rec = dict(rec)
        if rec.get("attempt_uid") and self.attempt_uid and \
                rec["attempt_uid"] != self.attempt_uid:
            raise EvidenceRejected("foreign attempt_uid in record")
        if rec.get("world_instance_id") and self.world_instance_id and \
                rec["world_instance_id"] != self.world_instance_id:
            raise EvidenceRejected("foreign world_instance_id in record")
        if self.attempt_uid:
            check_writable(self.run_dir, attempt_uid=self.attempt_uid,
                           world_instance_id=self.world_instance_id)
        with self._lock:
            self._seq += 1
            if self.attempt_uid:
                rec.setdefault("attempt_uid", self.attempt_uid)
            if self.world_instance_id:
                rec.setdefault("world_instance_id", self.world_instance_id)
            rec[self.seq_field] = self._seq
            data = (json.dumps(rec, default=str) + "\n").encode()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.path),
                         os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                view = memoryview(data)
                while view:
                    n = os.write(fd, view)
                    if n <= 0:
                        raise OSError("os.write wrote no bytes")
                    view = view[n:]
            finally:
                os.close(fd)
            return rec


def validate_evidence(run_dir, *, attempt_uid=None, world_instance_id=None,
                      files=("WORLD_LOG.jsonl", "GATE_COMMITS.jsonl",
                             "CONTROLLER_EVENTS.jsonl",
                             "CAUSAL_CONTROLLER.jsonl", "READBACK.jsonl",
                             "provider_log.jsonl")) -> list[str]:
    """Return evidence-isolation problems for a run directory (E)."""
    problems: list[str] = []
    run = Path(run_dir)
    rec = read_attempt(run)
    if rec:
        attempt_uid = attempt_uid or rec.get("attempt_uid")
        world_instance_id = world_instance_id or rec.get("world_instance_id")
    for name in files:
        p = run / name
        if not p.exists():
            continue
        seqs = []
        for i, line in enumerate(p.read_text(
                encoding="utf-8", errors="ignore").splitlines(), 1):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except ValueError:
                problems.append(f"{name}:{i}: unparseable line (lost?)")
                continue
            if attempt_uid and r.get("attempt_uid") != attempt_uid:
                problems.append(f"{name}:{i}: attempt_uid mismatch")
            if world_instance_id and \
                    r.get("world_instance_id") != world_instance_id:
                problems.append(f"{name}:{i}: world_instance_id mismatch")
            seq = r.get("seq")
            if not isinstance(seq, int):
                problems.append(f"{name}:{i}: missing seq")
            else:
                seqs.append(seq)
        if seqs != sorted(seqs) or len(set(seqs)) != len(seqs):
            problems.append(f"{name}: seq not strictly monotonic")
    return problems


def authority_terminal(env=None) -> bool:
    """True unless the LIVE authority proves RUNNING (fail closed, E6g)."""
    try:
        import attempt_authority as _auth
        st = _auth.client_from_env("gate", env).status()
    except Exception:
        try:
            import attempt_authority as _auth
            st = _auth.client_from_env("world", env).status()
        except Exception:
            return True
    return st.get("state") != RUNNING
