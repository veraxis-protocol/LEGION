"""StructMissionController: world-generalised DagMissionController (LEGION S2).

Single owner of write-obligation STATE plus ZTL EVIDENCE for one structural
world.  Write obligations are the public tasks whose ``kinds`` contain WRITE.

Closure is never taken from agent claims:
* a WRITE task closes only when the world effect ledger / WORLD_LOG (read
  with the reader token) shows an effect for one of its command ids;
* a non-write task closes only when WORLD_LOG has a record by its assigned
  agent for that task of kind OBSERVATION / ANALYSIS_RECORD /
  MESSAGE_DELIVERED / WAIT_OBSERVED / RECONCILE, or the gate has a
  REFUSED_BY_AGENT record for it.

Command ids are PER ATTEMPT: sha256(mission|task|epoch).  ``begin()`` claims
with a fencing epoch; after an UNKNOWN actuation the obligation may only be
re-attempted after ``reconcile()`` has read the effect ledger -- if that
command's effect exists the task closes and is never re-executed, and a
closed task refuses further claims.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone

import httpx

try:  # package import (pytest / host)
    from tests.legion_struct.world_engine import World as _Engine
except ImportError:  # pragma: no cover - direct script-dir import
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from world_engine import World as _Engine  # type: ignore

# ZTL evidence service is only needed by StructMissionController (live
# evidence verdicts), not by the pure StructWorld spec view. Import it
# lazily/optionally so StructWorld/StructNodes can be used hermetically
# (e.g. WO008-03 HARD-tier binding tests) in worktrees where
# tests.legion_overlay is not present. StructMissionController still
# fails closed below if the service is unavailable when instantiated.
try:
    from tests.legion_overlay.ztl_service import Reporter, ZtlEvidenceService
except ImportError:  # pragma: no cover - overlay absent in hermetic worktree
    Reporter = None  # type: ignore
    ZtlEvidenceService = None  # type: ignore


NONWRITE_TERMINAL_KINDS = frozenset({
    "OBSERVATION", "ANALYSIS_RECORD", "MESSAGE_DELIVERED",
    "WAIT_OBSERVED", "RECONCILE",
})


def _utc():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_json(o) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def command_id_for(mission: str, task_id: str, epoch: int) -> str:
    """Per-attempt command id: sha256(mission|task|epoch)."""
    return hashlib.sha256(
        canonical_json({"mission": mission, "task_id": task_id, "epoch": int(epoch)}).encode("utf-8")
    ).hexdigest()


def load_world(world) -> dict:
    if isinstance(world, dict):
        return world
    if isinstance(world, (str, os.PathLike)):
        text = str(world)
        if os.path.exists(text):
            with open(text, encoding="utf-8") as fh:
                return json.load(fh)
        return json.loads(text)
    raise TypeError("world must be a dict, path, or JSON string")


class StructWorld:
    """Public view of one world spec: tasks keyed by (globally unique) task_id."""

    def __init__(self, spec):
        self.spec = load_world(spec)
        self.world_id = self.spec.get("world_id") or "LEGION-STRUCT"
        self.mission_id = self.world_id
        self.tools = self.spec.get("tools") or {}
        self.roles = self.spec.get("roles") or []
        self.tasks: dict[str, dict] = {}
        self.by_agent: dict[str, list[dict]] = {}
        for role in self.roles:
            agent_id = role.get("agent_id")
            for task in role.get("tasks") or []:
                entry = {**task, "agent_id": agent_id,
                         "role_title": role.get("title"), "role_brief": role.get("brief")}
                self.tasks[entry["task_id"]] = entry
                self.by_agent.setdefault(agent_id, []).append(entry)
        self.write_tasks = {tid: t for tid, t in self.tasks.items()
                            if "WRITE" in (t.get("kinds") or [])}
        self._engine = _Engine(self.spec)

    def predicate(self, state, pred, params=None) -> bool:
        return bool(self._engine.predicate(state, pred, params or {}))

    def validate_args(self, tool: str, args) -> tuple[int, dict | None]:
        return self._engine.validate_params(tool, args if isinstance(args, dict) else {})


# Backwards-friendly alias mirroring scale_plugin.ScaleNodes naming.
StructNodes = StructWorld


class StructMissionController:
    def __init__(self, world, world_url: str, events_path: str, reader_token: str = "",
                 *, observers: int = 5, f: int = 1, gate_commits_path: str | None = None):
        self.world = world if isinstance(world, StructWorld) else StructWorld(world)
        self.spec = self.world.spec
        self.mission_id = self.world.mission_id
        self.tasks = self.world.tasks
        self.url = (world_url or "").rstrip("/")
        self.events_path = events_path
        self.reader_token = reader_token or ""
        self.gate_commits_path = gate_commits_path or (
            os.path.join(os.path.dirname(os.path.abspath(events_path)), "GATE_COMMITS.jsonl")
            if events_path else None)
        self.state = {tid: {"status": "PENDING", "command_id": None, "epoch": 0,
                            "effect_id": None, "unknown": False}
                      for tid in self.world.write_tasks}
        self.attempts: dict[str, dict[str, int]] = {tid: {} for tid in self.world.write_tasks}
        self.closed: list[dict] = []
        self.gate_refusals: set[str] = set()
        self._records: list[dict] = []
        self._effects: list[dict] = []
        self._live: set[str] = set()
        self._lock = asyncio.Lock()
        self._log_lock = threading.Lock()
        self.version = 0
        if ZtlEvidenceService is None or Reporter is None:
            raise RuntimeError(
                "ZTL evidence service unavailable (tests.legion_overlay.ztl_service "
                "not importable); StructMissionController fails closed")
        self.ztl = ZtlEvidenceService(f=f, clock=_utc, lean=False)
        self.observers = [Reporter(agent=f"struct-observer-{i}", root=f"struct-observer-root-{i}")
                          for i in range(observers)]
        for i, r in enumerate(self.observers):
            self.ztl.enroll(r, f"independent-readback-basis-{i}")
        if events_path:
            os.makedirs(os.path.dirname(os.path.abspath(events_path)), exist_ok=True)
        self._seq = 0
        if events_path and os.path.exists(events_path):
            try:
                with open(events_path, encoding="utf-8") as fh:
                    self._seq = sum(1 for line in fh if line.strip())
            except OSError:
                self._seq = 0

    # ------------------------------------------------------------ event log
    def log(self, event: str, **kw):
        rec = {"event": event, "mono": time.monotonic(), "t": time.time(),
               "mission_id": self.mission_id, **kw}
        _st = self._attempt_state()
        if _st in ("COMPLETED", "INTERRUPTED"):
            return rec  # writer rejects after terminal (live authority)
        if os.environ.get("STRUCT_ATTEMPT_UID"):
            rec.setdefault("attempt_uid", os.environ["STRUCT_ATTEMPT_UID"])
        if os.environ.get("STRUCT_WORLD_INSTANCE_ID"):
            rec.setdefault("world_instance_id",
                           os.environ["STRUCT_WORLD_INSTANCE_ID"])
        self._seq += 1
        rec["seq"] = self._seq
        if event in ("CLAIMED", "OBLIGATION_CLOSED", "CLAIM_RELEASED", "RECONCILED", "ZTL_VERDICT"):
            self.version += 1
        if not self.events_path:
            return rec
        data = (json.dumps(rec, default=str) + "\n").encode("utf-8")
        with self._log_lock:
            fd = os.open(self.events_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("os.write wrote no bytes")
                    view = view[written:]
            finally:
                os.close(fd)
        return rec

    # ------------------------------------------------------------ native readback (reader token only)
    def _reader_headers(self):
        return {"Authorization": f"Bearer {self.reader_token}"} if self.reader_token else {}

    async def native_state(self) -> dict:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{self.url}/state", headers=self._reader_headers())
            r.raise_for_status()
            return r.json()

    async def native_log(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{self.url}/log", headers=self._reader_headers())
            r.raise_for_status()
            payload = r.json()
            return list(payload.get("records") or []) if isinstance(payload, dict) else list(payload)

    async def native_effects(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{self.url}/effects?after=0&wait_s=0", headers=self._reader_headers())
            r.raise_for_status()
            payload = r.json()
            return list(payload.get("effects") or []) if isinstance(payload, dict) else list(payload)

    # ------------------------------------------------------------ closure (pure, from readback records)
    def _read_gate_refusals(self):
        path = self.gate_commits_path
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if rec.get("outcome") == "REFUSED_BY_AGENT" and rec.get("task_id"):
                        self.gate_refusals.add(rec["task_id"])
        except OSError:
            pass

    def note_gate_refusal(self, task_id: str):
        if task_id:
            self.gate_refusals.add(task_id)

    def _effect_for(self, task_id: str, records, effects):
        """Effect (from native readback) closing task_id, or None."""
        known = set(self.attempts.get(task_id) or {})
        for rec in records or []:
            if rec.get("kind") == "NATIVE_EFFECT" and rec.get("task_id") == task_id \
                    and rec.get("effect_id"):
                if not known or rec.get("command_id") in known:
                    return {"effect_id": rec.get("effect_id"), "command_id": rec.get("command_id")}
        for eff in effects or []:
            if eff.get("command_id") in known and eff.get("effect_id"):
                return {"effect_id": eff.get("effect_id"), "command_id": eff.get("command_id")}
        return None

    def _task_closed_from(self, task_id: str, records, gate_refusals=None) -> bool:
        task = self.tasks.get(task_id)
        if task is None:
            return False
        refusals = self.gate_refusals if gate_refusals is None else gate_refusals
        if "WRITE" in (task.get("kinds") or []):
            st = self.state.get(task_id)
            if st and st["status"] == "CLOSED":
                return True
            return self._effect_for(task_id, records, self._effects) is not None
        if task_id in refusals:
            return True
        assigned = task.get("agent_id")
        return any(r.get("kind") in NONWRITE_TERMINAL_KINDS
                   and r.get("agent_id") == assigned and r.get("task_id") == task_id
                   for r in records or [])

    def _deps_closed_from(self, task, records, gate_refusals=None) -> bool:
        return all(self._task_closed_from(dep, records, gate_refusals)
                   for dep in (task.get("depends_on") or []))

    async def deps_closed(self, task) -> bool:
        """True iff every depends_on task is closed (fresh reader-token readback)."""
        task_id = task.get("task_id") if isinstance(task, dict) else task
        entry = self.tasks.get(task_id)
        if entry is None:
            return False
        await self.refresh()
        return self._deps_closed_from(entry, self._records)

    def _apply_closures_locked(self, via: str):
        for tid in list(self.world.write_tasks):
            st = self.state[tid]
            if st["status"] == "CLOSED":
                continue
            found = self._effect_for(tid, self._records, self._effects)
            if found:
                st.update(status="CLOSED", effect_id=found["effect_id"], unknown=False)
                self._live.discard(found.get("command_id"))
                self.closed.append({"task_id": tid, "command_id": found.get("command_id"),
                                    "effect_id": found["effect_id"], "mono": time.monotonic()})
                self.log("OBLIGATION_CLOSED", task_id=tid, command_id=found.get("command_id"),
                         effect_id=found["effect_id"], via=via)

    async def refresh(self, via: str = "effect_ledger"):
        """Re-read /log (+ effect ledger) via reader token; close what it proves."""
        try:
            self._records = await self.native_log()
        except Exception:
            self._records = self._records or []
        try:
            self._effects = await self.native_effects()
        except Exception:
            self._effects = self._effects or []
        self._read_gate_refusals()
        self._apply_closures_locked(via)
        return self._records

    async def start(self):
        await self.refresh()
        self.log("UNIVERSE_LOADED", world_id=self.mission_id,
                 write_tasks=sorted(self.world.write_tasks), tasks=sorted(self.tasks))

    # ------------------------------------------------------------ directives / claims
    @staticmethod
    def _attempt_state():
        """Attempt state from LIVE authority, or None (no authority context)."""
        if not os.environ.get("STRUCT_AUTHORITY_URL"):
            return None
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "causal_007"))
            import attempt_authority as _auth
            return _auth.client_from_env("gate").status().get("state")
        except Exception:
            return "UNAVAILABLE"

    def _directive_locked(self, task_id: str) -> dict:
        task = self.tasks.get(task_id)
        if task is None or task_id not in self.world.write_tasks:
            return {"directive": "NOT_ELIGIBLE:UNKNOWN_TASK", "command_id": "", "task_id": task_id}
        attempt_state = self._attempt_state()
        if attempt_state in ("COMPLETED", "INTERRUPTED"):
            return {"directive": f"NOT_ELIGIBLE:ATTEMPT_TERMINAL:{attempt_state}",
                    "command_id": "", "task_id": task_id}
        if attempt_state and attempt_state != "RUNNING":
            return {"directive": f"NOT_ELIGIBLE:ATTEMPT_NOT_RUNNING:{attempt_state}",
                    "command_id": "", "task_id": task_id}
        st = self.state[task_id]
        if st["status"] == "CLOSED":
            return {"directive": "NOT_ELIGIBLE:ALREADY_CLOSED", "command_id": "", "task_id": task_id}
        if st["status"] == "CLAIMED":
            return {"directive": "NOT_ELIGIBLE:ALREADY_CLAIMED", "command_id": "", "task_id": task_id}
        if not self._deps_closed_from(task, self._records):
            open_deps = [d for d in (task.get("depends_on") or [])
                         if not self._task_closed_from(d, self._records)]
            return {"directive": f"NOT_ELIGIBLE:DEPENDENCIES_OPEN:{','.join(open_deps)}",
                    "command_id": "", "task_id": task_id}
        epoch = st["epoch"] + 1
        return {"directive": "ACT", "task_id": task_id, "epoch": epoch,
                "command_id": command_id_for(self.mission_id, task_id, epoch)}

    async def _reconcile_claimed_locked(self):
        for tid, st in list(self.state.items()):
            if st["status"] == "CLAIMED" and st["command_id"] not in self._live:
                await self._reconcile_locked(tid, st["command_id"])

    async def directive_for(self, task_id: str) -> dict:
        async with self._lock:
            await self.refresh()
            await self._reconcile_claimed_locked()
            return self._directive_locked(task_id)

    async def begin(self, task_id: str, command_id: str):
        """Claim with a fencing epoch. A closed task refuses further claims."""
        async with self._lock:
            await self.refresh()
            await self._reconcile_claimed_locked()
            d = self._directive_locked(task_id)
            if d["directive"] != "ACT" or d["command_id"] != command_id:
                self.log("CLAIM_REFUSED", task_id=task_id, command_id=command_id,
                         directive=d["directive"])
                raise ValueError(f"task not claimable: {d['directive']}")
            st = self.state[task_id]
            st["epoch"] += 1
            st.update(status="CLAIMED", command_id=command_id, unknown=False)
            self.attempts[task_id][command_id] = st["epoch"]
            self._live.add(command_id)
            rec = self.log("CLAIMED", task_id=task_id, command_id=command_id,
                           epoch=st["epoch"], agent_id=self.tasks[task_id].get("agent_id"))
            return {"task_id": task_id, "command_id": command_id, "epoch": st["epoch"],
                    "event": rec}

    def release(self, command_id: str):
        self._live.discard(command_id)

    async def mark_unknown(self, task_id: str, command_id: str):
        async with self._lock:
            st = self.state.get(task_id)
            if st and st["command_id"] == command_id and st["status"] == "CLAIMED":
                st["unknown"] = True
            self._live.discard(command_id)
            self.log("ACTUATION_UNKNOWN", task_id=task_id, command_id=command_id)

    async def _reconcile_locked(self, task_id: str, command_id: str | None) -> dict:
        await self.refresh(via="reconcile")
        st = self.state.get(task_id)
        if st is None:
            return {"closed": False, "found": False, "reason": "unknown task"}
        if st["status"] == "CLOSED" and (command_id is None or st["command_id"] in (command_id, st["command_id"])):
            self.log("RECONCILED", task_id=task_id, command_id=command_id or st["command_id"],
                     found=True, effect_id=st["effect_id"])
            return {"closed": True, "found": True, "effect_id": st["effect_id"],
                    "command_id": st["command_id"]}
        found = self._effect_for(task_id, self._records, self._effects)
        if found and (command_id is None or found["command_id"] == command_id
                      or command_id in self.attempts.get(task_id, {})):
            # refresh() already transitioned + logged OBLIGATION_CLOSED.
            self.log("RECONCILED", task_id=task_id, command_id=found["command_id"],
                     found=True, effect_id=found["effect_id"])
            return {"closed": True, "found": True, "effect_id": found["effect_id"],
                    "command_id": found["command_id"]}
        # No effect for this command: the claim may be released; only now may
        # a NEW attempt (new epoch, new command id) be made.
        released = False
        if st["status"] == "CLAIMED" and (command_id is None or st["command_id"] == command_id):
            st.update(status="PENDING", command_id=None, unknown=False)
            self._live.discard(command_id)
            released = True
            self.log("CLAIM_RELEASED", task_id=task_id, command_id=command_id,
                     epoch=st["epoch"], reason="reconcile_no_effect")
        self.log("RECONCILED", task_id=task_id, command_id=command_id,
                 found=False, effect_id=None)
        return {"closed": False, "found": False, "released": released,
                "reason": "no native effect"}

    async def reconcile(self, task_id: str, command_id: str | None = None) -> dict:
        async with self._lock:
            return await self._reconcile_locked(task_id, command_id)

    async def close(self, task_id: str, command_id: str) -> dict:
        async with self._lock:
            try:
                out = await self._reconcile_locked(task_id, command_id)
                return {"closed": bool(out.get("closed")), "effect_id": out.get("effect_id"),
                        "found": bool(out.get("found")), "reason": out.get("reason")}
            finally:
                self._live.discard(command_id)

    # ------------------------------------------------------------ ZTL evidence
    def _facts_for(self, task, args=None):
        gate_facts = task.get("gate_facts") or []
        if not gate_facts:
            return [(f"{task['task_id']}:deps_closed", None)]
        facts = []
        for i, pred in enumerate(gate_facts):
            digest = hashlib.sha256(canonical_json(pred).encode("utf-8")).hexdigest()[:12]
            facts.append((f"{task['task_id']}:gate:{i}:{digest}", pred))
        return facts

    async def evidence_verdict(self, task_id: str, args=None) -> dict:
        task = self.tasks.get(task_id)
        if task is None:
            raise KeyError(f"unknown task {task_id!r}")
        await self.refresh()
        facts, recs = self._facts_for(task, args), []
        for fact_id, pred in facts:
            observations = []
            for reporter in self.observers:
                if pred is None:
                    # Trivially-true deps_closed fact: each observer decides
                    # from its OWN /log read.
                    try:
                        records = await self.native_log()
                    except Exception:
                        records = list(self._records)
                    value = self._deps_closed_from(task, records)
                else:
                    state = await self.native_state()  # observer's OWN GET /state
                    value = self.world.predicate(state, pred, args or {})
                observations.append(self.ztl.submit(reporter.report(fact_id, bool(value), _iso(_utc()))))
            rec = await self.ztl.verdict(fact_id)
            entry = {"fact_id": rec["fact_id"], "state": rec["state"], "digest": rec["digest"]}
            recs.append(entry)
            self.log("ZTL_VERDICT", task_id=task_id, fact_id=entry["fact_id"],
                     state=entry["state"], digest=entry["digest"], facts=[entry],
                     seats_true=rec.get("seats_true"), seats_false=rec.get("seats_false"),
                     fresh_reports=rec.get("fresh_reports"), submit=observations)
        ok = bool(recs) and all(r["state"] == "ACCEPTED_TRUE" for r in recs)
        combined = {"fact_id": recs[0]["fact_id"] if recs else "",
                    "state": "ACCEPTED_TRUE" if ok else (recs[0]["state"] if recs else "NOT_DECIDED_INSUFFICIENT"),
                    "digest": hashlib.sha256(canonical_json(recs).encode("utf-8")).hexdigest(),
                    "facts": recs}
        self.log("ZTL_VERDICT", task_id=task_id, fact_id=combined["fact_id"],
                 state=combined["state"], digest=combined["digest"], facts=recs, combined=True)
        return combined

    # ------------------------------------------------------------ views
    async def status(self) -> dict:
        async with self._lock:
            await self.refresh()
            await self._reconcile_claimed_locked()
            closed_w = sum(1 for s in self.state.values() if s["status"] == "CLOSED")
            return {"mission_id": self.mission_id, "world_id": self.mission_id,
                    "write_tasks": len(self.state), "closed": closed_w,
                    "pending": sum(1 for s in self.state.values() if s["status"] == "PENDING"),
                    "claimed": sum(1 for s in self.state.values() if s["status"] == "CLAIMED"),
                    "admitted": closed_w == len(self.state) if self.state else False,
                    "closed_tasks": [dict(c) for c in self.closed]}

    async def role_view(self, agent_id: str) -> dict:
        async with self._lock:
            await self.refresh()
            views = []
            for task in self.world.by_agent.get(agent_id, []):
                tid = task["task_id"]
                closed = self._task_closed_from(tid, self._records)
                views.append({"task_id": tid, "closed": closed,
                              "kinds": task.get("kinds") or [],
                              "directive": self._directive_locked(tid)["directive"]
                              if tid in self.world.write_tasks else None})
            return {"mission_id": self.mission_id, "agent_id": agent_id, "tasks": views,
                    "state_version": self.version}
