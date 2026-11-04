"""DagMissionController: single owner of obligation STATE plus ZTL EVIDENCE for LEGION scale.

Replaces QuantifiedLedger (mini) with an explicit DAG state machine:
PENDING -> CLAIMED(command_id, epoch) -> CLOSED(effect_id). Never closes from agent claims:
close() re-reads the native effect log. Non-live CLAIMED obligations are reconciled from
native readback on the next query (like controller.py _live/release/_reconcile_locked).
ZTL: ZtlEvidenceService(lean=False), N independent observers each GET /state themselves."""
from __future__ import annotations
import asyncio, hashlib, json, time
from datetime import datetime, timezone
import httpx
from tests.legion_overlay.ztl_service import ZtlEvidenceService, Reporter


def _utc():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _canon(o) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str)


def load_manifest(manifest) -> dict:
    if isinstance(manifest, dict):
        return manifest
    return json.load(open(manifest))


def command_id_for(mission: str, node: dict) -> str:
    return hashlib.sha256(_canon({"mission": mission, "obligation_id": node["obligation_id"],
                                   "target": node["target_id"], "stage": node["stage"]}).encode()).hexdigest()


class DagMissionController:
    def __init__(self, manifest, target_url: str, events_path: str, *, observers: int = 5, f: int = 1):
        self.manifest = load_manifest(manifest)
        self.mission_id = self.manifest.get("scenario_id", "LEGION-SCALE")
        self.nodes = {n["obligation_id"]: n for n in self.manifest["nodes"]}
        self.by_agent = {n["agent_id"]: n for n in self.manifest["nodes"]}
        self.url, self.events_path = target_url.rstrip("/"), events_path
        self.state = {oid: {"status": "PENDING", "command_id": None, "epoch": 0, "effect_id": None} for oid in self.nodes}
        self.ztl = ZtlEvidenceService(f=f, clock=_utc, lean=False)
        self.observers = [Reporter(agent=f"native-observer-{i}", root=f"observer-root-{i}") for i in range(observers)]
        for i, r in enumerate(self.observers):
            self.ztl.enroll(r, f"independent-readback-basis-{i}")
        self.lock = asyncio.Lock()
        self._live: set[str] = set()          # command_ids whose owning gateway request still runs
        self.version = 0
        self.closed: list[dict] = []          # closure checkpoints {obligation_id, command_id, effect_id, t, mono}
        self._started = False

    # ------------------------------------------------ native readback (independent of agents)
    async def native_state(self) -> dict:
        async with httpx.AsyncClient(timeout=5) as c:
            return (await c.get(f"{self.url}/state")).json()

    async def native_effects(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=5) as c:
            return (await c.get(f"{self.url}/effects")).json()["effects"]

    def log(self, event: str, **kw):
        if event in ("CLAIMED", "OBLIGATION_CLOSED", "OBLIGATION_REOPENED_NO_EFFECT", "RECONCILE_DONE", "UNIVERSE_LOADED"):
            self.version += 1
        with open(self.events_path, "a") as fh:
            fh.write(json.dumps({"t": time.time(), "mono": time.monotonic(), "event": event, "mission_id": self.mission_id, **kw}, default=str) + "\n")

    async def start(self):
        st = await self.native_state()
        self._started = True
        self.log("UNIVERSE_LOADED", native_state=st, obligations=list(self.nodes))

    # ------------------------------------------------ DAG eligibility
    def _deps_closed(self, node) -> bool:
        return all(self.state[d]["status"] == "CLOSED" for d in node.get("dependencies", []))

    def _directive_locked(self, obligation_id: str) -> dict:
        node = self.nodes.get(obligation_id)
        if node is None:
            return {"directive": "NOT_ELIGIBLE:UNKNOWN_OBLIGATION", "command_id": "", "obligation_id": obligation_id}
        st = self.state[obligation_id]
        if st["status"] == "CLOSED":
            return {"directive": "NOT_ELIGIBLE:ALREADY_CLOSED", "command_id": "", "obligation_id": obligation_id}
        if st["status"] == "CLAIMED":
            return {"directive": "NOT_ELIGIBLE:ALREADY_CLAIMED", "command_id": "", "obligation_id": obligation_id}
        open_deps = [d for d in node.get("dependencies", []) if self.state[d]["status"] != "CLOSED"]
        if open_deps:
            return {"directive": f"NOT_ELIGIBLE:DEPENDENCIES_OPEN:{','.join(open_deps)}", "command_id": "", "obligation_id": obligation_id}
        return {"directive": "ACT", "command_id": command_id_for(self.mission_id, node), "obligation_id": obligation_id}

    async def directive_for(self, obligation_id: str) -> dict:
        async with self.lock:
            await self._reconcile_locked()
            return self._directive_locked(obligation_id)

    async def begin(self, obligation_id: str, command_id: str):
        async with self.lock:
            await self._reconcile_locked()
            d = self._directive_locked(obligation_id)
            if d["directive"] != "ACT" or d["command_id"] != command_id:
                self.log("CLAIM_REFUSED", obligation_id=obligation_id, command_id=command_id, directive=d["directive"])
                raise ValueError(f"obligation not claimable: {d['directive']}")
            st = self.state[obligation_id]
            st["epoch"] += 1
            st.update(status="CLAIMED", command_id=command_id)
            self._live.add(command_id)
            self.log("CLAIMED", obligation_id=obligation_id, command_id=command_id, epoch=st["epoch"],
                     agent_id=self.nodes[obligation_id]["agent_id"], target_id=self.nodes[obligation_id]["target_id"],
                     stage=self.nodes[obligation_id]["stage"])

    async def close(self, obligation_id: str, command_id: str) -> dict:
        async with self.lock:
            try:
                return await self._close_locked(obligation_id, command_id)
            finally:
                self._live.discard(command_id)

    def release(self, command_id: str):
        self._live.discard(command_id)

    async def _close_locked(self, obligation_id: str, command_id: str) -> dict:
        effects = [e for e in await self.native_effects() if e.get("command_id") == command_id and e.get("applied")]
        st = self.state[obligation_id]
        if len(effects) == 1 and effects[0].get("obligation_id") == obligation_id:
            eff = effects[0]
            st.update(status="CLOSED", effect_id=eff["effect_id"])
            self.closed.append({"obligation_id": obligation_id, "command_id": command_id, "effect_id": eff["effect_id"],
                                "t": time.time(), "mono": time.monotonic()})
            self.log("OBLIGATION_CLOSED", obligation_id=obligation_id, command_id=command_id, effect_id=eff["effect_id"],
                     seq=eff.get("seq"), totals=self._totals())
            return {"closed": True, "effect": eff}
        if not effects:
            if st["status"] == "CLAIMED" and st["command_id"] == command_id:
                st.update(status="PENDING", command_id=None)
            self.log("OBLIGATION_REOPENED_NO_EFFECT", obligation_id=obligation_id, command_id=command_id)
            return {"closed": False, "reason": "no native effect"}
        self.log("OBLIGATION_UNRESOLVED", obligation_id=obligation_id, command_id=command_id, effects=effects)
        return {"closed": False, "reason": "ambiguous native effects"}

    async def _reconcile_locked(self):
        """Non-live CLAIMED obligations settled ONLY from the native effect log, never re-issued."""
        for oid, st in list(self.state.items()):
            if st["status"] == "CLAIMED" and st["command_id"] not in self._live:
                cid = st["command_id"]
                self.log("RECONCILE_START", obligation_id=oid, command_id=cid)
                out = await self._close_locked(oid, cid)
                self.log("RECONCILE_DONE", obligation_id=oid, command_id=cid, outcome=out.get("closed"), reason=out.get("reason"))

    # ------------------------------------------------ ZTL evidence
    def _facts_for(self, node) -> list[tuple[str, str, int]]:
        """(fact_id, target_id, stage) : primary precondition plus each cross-shard dependency fact."""
        facts = [(f"{node['target_id']}:at_stage:{node['stage'] - 1}", node["target_id"], node["stage"] - 1)]
        for dep_id in node.get("dependencies", []):
            dep = self.nodes[dep_id]
            if dep["target_id"] != node["target_id"]:
                facts.append((f"{dep['target_id']}:at_stage:{dep['stage']}", dep["target_id"], dep["stage"]))
        return facts

    async def evidence_verdict(self, obligation_id: str) -> dict:
        node = self.nodes[obligation_id]
        facts, recs = self._facts_for(node), []
        for fact, tid, stage in facts:
            now = _utc()
            observations = []
            for r in self.observers:                      # each observer reads native state on its own
                st = await self.native_state()
                value = (st.get("stage_by_shard") or {}).get(tid, -999) >= stage if stage >= 0 else True
                if stage < 0:
                    value = True  # at_stage:-1 is the zero state: trivially reached
                else:
                    value = (st.get("stage_by_shard") or {}).get(tid, -999) >= stage
                observations.append(self.ztl.submit(r.report(fact, bool(value), _iso(now))))
            rec = await self.ztl.verdict(fact)
            self.log("ZTL_VERDICT", obligation_id=obligation_id, fact=fact, fact_id=fact, state=rec["state"], digest=rec["digest"],
                     seats_true=rec["seats_true"], seats_false=rec["seats_false"], fresh_reports=rec["fresh_reports"], submit=observations)
            recs.append(rec)
        ok = all(r["state"] == "ACCEPTED_TRUE" for r in recs)
        combined = {"fact_id": recs[0]["fact_id"] if recs else "", "state": "ACCEPTED_TRUE" if ok else (recs[0]["state"] if recs else "NOT_DECIDED_INSUFFICIENT"),
                    "digest": hashlib.sha256(_canon([{"fact_id": r["fact_id"], "state": r["state"], "digest": r["digest"]} for r in recs]).encode()).hexdigest(),
                    "facts": [{"fact_id": r["fact_id"], "state": r["state"], "digest": r["digest"]} for r in recs]}
        self.log("ZTL_VERDICT", obligation_id=obligation_id, fact_id=combined["fact_id"], state=combined["state"],
                 digest=combined["digest"], combined=True, facts=combined["facts"])
        return combined

    # ------------------------------------------------ views
    def _totals(self) -> dict:
        t = {"pending": 0, "claimed": 0, "closed": 0}
        for st in self.state.values():
            t[{"PENDING": "pending", "CLAIMED": "claimed", "CLOSED": "closed"}[st["status"]]] += 1
        return t

    async def role_view(self, agent_id: str) -> dict:
        async with self.lock:
            await self._reconcile_locked()
            node = self.by_agent.get(agent_id)
            if node is None:
                return {"mission_id": self.mission_id, "agent_id": agent_id, "view": "UNKNOWN_AGENT", "state_version": self.version}
            oid, st = node["obligation_id"], self.state[node["obligation_id"]]
            if st["status"] == "CLOSED":
                view = "OWN_STEP_COMPLETE"
            elif st["status"] == "CLAIMED":
                view = "READBACK_PENDING"
            elif self._directive_locked(oid)["directive"] == "ACT":
                view = "ACT_ELIGIBLE"
            else:
                view = "WAIT_STATE_CHANGE"
            closed_deps = [d for d in node.get("dependencies", []) if self.state[d]["status"] == "CLOSED"]
            return {"mission_id": self.mission_id, "agent_id": agent_id, "view": view, "obligation_id": oid,
                    "target_id": node["target_id"], "stage": node["stage"], "state_version": self.version,
                    "checkpoint": {"closed_obligations": list(self.closed), "closed_dependencies": closed_deps,
                                   "dependencies": list(node.get("dependencies", []))}}

    async def status(self) -> dict:
        async with self.lock:
            await self._reconcile_locked()
            totals = self._totals()
            return {"mission_id": self.mission_id, **totals, "total": len(self.nodes),
                    "admitted": totals["closed"] == len(self.nodes),
                    "completion": {**totals, "admitted": totals["closed"] == len(self.nodes), "verified_effects": totals["closed"]}}
