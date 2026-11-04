"""LEGION-MINI-003 mission controller: obligation STATE (QC002 QuantifiedLedger v002, vendored unchanged) and admission
EVIDENCE (ztl-swarm ZtlSwarm via the LEGION overlay ZtlEvidenceService). The two are kept apart:

* QuantifiedLedger owns the two ordered obligations (restore_config, then restart_service on demo-service). It names the
  only admissible next action (directive ACT + command_id), refuses out-of-order or concurrent begin(), and closes an
  obligation only with a receipt whose effect this controller re-read from the NATIVE effect log (readback_verified).
  It is the single owner of claims. After a crash between actuation and receipt its directive is READBACK, never a second ACT.
* ZtlEvidenceService turns signed reports from 5 independent native observers (each reads GET /state itself) into a
  ZtlSwarm verdict on the precondition fact of the requested action.

Nothing here is reachable by agents except the read-only status view. Agents cannot call begin/close."""
from __future__ import annotations
import asyncio, json, sys, time
from datetime import datetime, timezone
import httpx

MISSION_ID = "LEGION-MINI-DEPENDENT-REPAIR-001"
TARGET = "demo-service"
STEPS = ("restore_config", "restart_service")
ROLE_VERB = {"agent:config-restorer": "restore_config", "agent:service-operator": "restart_service"}


def _utc():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class MissionController:
    def __init__(self, target_url: str, vendor_dir: str, events_path: str, *, generation: int = 1, observers: int = 5, f: int = 1):
        sys.path.insert(0, vendor_dir)
        import quantifier_closure as qc
        from tests.legion_overlay.ztl_service import ZtlEvidenceService, Reporter
        self.qc, self.url, self.generation, self.events_path = qc, target_url.rstrip("/"), generation, events_path
        self.task = qc.Task(task_id=MISSION_ID, instruction_span="repair demo-service: restore config generation 1, then restart it",
                            quantifier="EACH", collection_source="native:demo-service", frozen_predicate="target == demo-service",
                            steps=STEPS)
        self.ledger = qc.QuantifiedLedger(self.task, self._verify_collection, self._verify_receipt, lambda src: "mission-universe-v1")
        self.ztl = ZtlEvidenceService(f=f, clock=_utc, lean=False)
        self.observers = [Reporter(agent=f"native-observer-{i}", root=f"observer-root-{i}") for i in range(observers)]
        for i, r in enumerate(self.observers):
            self.ztl.enroll(r, f"independent-readback-basis-{i}")
        self.lock = asyncio.Lock()
        self._verified_effects: dict[str, dict] = {}
        self._live: set[str] = set()     # claims whose owning gateway request is still running
        self.version = 0                  # bumps on every ledger transition (agents wait for a change)
        self.closed: list[dict] = []      # closure checkpoint delivered to agents (incl. replacements)

    # ------------------------------------------------------------------ native readback (independent of agents)
    async def native_state(self) -> dict:
        async with httpx.AsyncClient(timeout=5) as c:
            return (await c.get(f"{self.url}/state")).json()

    async def native_effects(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=5) as c:
            return (await c.get(f"{self.url}/effects")).json()["effects"]

    def _verify_collection(self, witness) -> bool:
        return witness.source == "native:demo-service" and witness.evidence_id.startswith("native-state:")

    def _verify_receipt(self, receipt) -> bool:
        eff = self._verified_effects.get(receipt.command_id)
        return bool(eff and eff["effect_id"] == receipt.receipt_id and eff["verb"] == receipt.tool)

    def log(self, event: str, **kw):
        if event in ("CLAIMED", "OBLIGATION_CLOSED", "OBLIGATION_REOPENED_NO_EFFECT", "RECONCILE_DONE", "UNIVERSE_LOADED"):
            self.version += 1
        with open(self.events_path, "a") as fh:
            fh.write(json.dumps({"t": time.time(), "mono": time.monotonic(), "event": event, "mission_id": MISSION_ID, **kw}, default=str) + "\n")

    async def start(self):
        st = await self.native_state()
        w = self.qc.CollectionWitness(source="native:demo-service", predicate="target == demo-service", version="mission-universe-v1",
                                      complete=True, reported_total=1,
                                      targets=(self.qc.Target(TARGET, {"generation": str(st["generation"])}),),
                                      evidence_id=f"native-state:{json.dumps(st, sort_keys=True)}")
        self.ledger.load_universe(w)
        self.log("UNIVERSE_LOADED", native_state=st, checkpoint=self.ledger.checkpoint())

    # ------------------------------------------------------------------ ZTL evidence (precondition facts)
    def fact_for(self, action: str, generation: int) -> str:
        return {"restore_config": f"{TARGET}:config_needs_restore:gen{generation}",
                "restart_service": f"{TARGET}:config_restored:gen{generation}"}.get(action, f"{TARGET}:unknown:{action}")

    async def evidence_verdict(self, action: str, generation: int) -> dict:
        fact, now = self.fact_for(action, generation), _utc()
        observations = []
        for r in self.observers:                      # each observer reads native state on its own
            st = await self.native_state()
            value = (not st["config_restored"]) if action == "restore_config" else (st["config_restored"] and st["generation"] == generation)
            observations.append(self.ztl.submit(r.report(fact, bool(value), _iso(now))))
        rec = await self.ztl.verdict(fact)
        self.log("ZTL_VERDICT", action=action, fact=fact, state=rec["state"], digest=rec["digest"], seats_true=rec["seats_true"],
                 seats_false=rec["seats_false"], fresh_reports=rec["fresh_reports"], submit=observations)
        return rec

    # ------------------------------------------------------------------ obligation state (QuantifiedLedger)
    async def directive_for(self, action: str) -> dict:
        async with self.lock:
            await self._reconcile_locked()
            d = self.ledger.next()
            ok = d.kind == "ACT" and d.tool == action and d.target_id == TARGET
            return {"directive": "ACT" if ok else f"NOT_ELIGIBLE:{d.kind}:{d.tool or '-'}", "command_id": d.command_id if ok else "",
                    "ledger_next": d.kind, "ledger_tool": d.tool}

    async def begin(self, action: str, command_id: str):
        async with self.lock:
            await self._reconcile_locked()
            d = self.ledger.next()
            if not (d.kind == "ACT" and d.tool == action and d.command_id == command_id):
                self.log("BEGIN_REFUSED", action=action, command_id=command_id, ledger_next=d.kind, ledger_tool=d.tool)
                raise self.qc.ClosureError(f"obligation not claimable: ledger says {d.kind} {d.tool}")
            self.ledger.begin(d.target_id, d.step_index, command_id)
            self._live.add(command_id)
            self.log("CLAIMED", action=action, command_id=command_id, step_index=d.step_index, checkpoint=self.ledger.checkpoint())

    async def close(self, action: str, command_id: str) -> dict:
        async with self.lock:
            try:
                return await self._close_locked(action, command_id)
            finally:
                self._live.discard(command_id)

    def release(self, command_id: str):
        """Owning request ended without close (cancelled/crashed): leave the claim to native-readback reconciliation."""
        self._live.discard(command_id)

    async def _close_locked(self, action, command_id):
        effects = [e for e in await self.native_effects() if e.get("command_id") == command_id and e.get("applied")]
        step = STEPS.index(action)
        if len(effects) == 1 and effects[0]["verb"] == action:
            eff = effects[0]
            self._verified_effects[command_id] = eff
            r = self.qc.ToolReceipt(task_id=MISSION_ID, target_id=TARGET, step_index=step, tool=action, command_id=command_id,
                                    receipt_id=eff["effect_id"], collection_version="mission-universe-v1", success=True,
                                    readback_verified=True, evidence_ref=f"native-effect:{eff['effect_id']}:seq{eff['seq']}")
            self.ledger.accept_receipt(r)
            self.closed.append({"action": action, "command_id": command_id, "effect_id": eff["effect_id"], "t": time.time(), "mono": time.monotonic()})
            self.log("OBLIGATION_CLOSED", action=action, command_id=command_id, effect_id=eff["effect_id"], seq=eff["seq"],
                     completion=self.ledger.completion(), checkpoint=self.ledger.checkpoint())
            return {"closed": True, "effect": eff}
        if not effects:
            self.ledger.recover_absent_effect(TARGET, step, lambda cmd: cmd == command_id)
            self.log("OBLIGATION_REOPENED_NO_EFFECT", action=action, command_id=command_id)
            return {"closed": False, "reason": "no native effect"}
        self.log("OBLIGATION_UNRESOLVED", action=action, command_id=command_id, effects=effects)
        return {"closed": False, "reason": "ambiguous native effects"}

    async def _reconcile_locked(self):
        """Crash recovery: a pending claim is settled ONLY from the native effect log, never re-issued."""
        d = self.ledger.next()
        if d.kind == "READBACK" and d.command_id not in self._live:
            self.log("RECONCILE_START", action=d.tool, command_id=d.command_id)
            out = await self._close_locked(d.tool, d.command_id)
            self.log("RECONCILE_DONE", action=d.tool, command_id=d.command_id, outcome=out.get("closed"), reason=out.get("reason"))

    async def role_view(self, role: str) -> dict:
        """Observation contract for one role (MINI-004). The ledger stays the eligibility authority."""
        async with self.lock:
            await self._reconcile_locked()
            verb = ROLE_VERB.get(role)
            d = self.ledger.next()
            comp = self.ledger.completion()
            own_done = verb is not None and not any(m["tool"] == verb for m in comp["missing"])
            if verb is None:
                view = "UNKNOWN_ROLE"
            elif own_done:
                view = "OWN_STEP_COMPLETE"          # stop: the role's verified action is done
            elif d.kind == "READBACK":
                view = "READBACK_PENDING"           # no retry until the pending effect is settled from native readback
            elif d.kind == "ACT" and d.tool == verb:
                view = "ACT_ELIGIBLE"               # only this role's own authorized step
            else:
                view = "WAIT_STATE_CHANGE"          # nothing to do until the ledger changes
            return {"mission_id": MISSION_ID, "role": role, "view": view, "my_tool": verb, "state_version": self.version,
                    "checkpoint": {"closed_obligations": list(self.closed), "remaining": comp["pending_effects"]},
                    "next": {"kind": d.kind, "tool": d.tool, "target": d.target_id}}

    async def status(self) -> dict:
        async with self.lock:
            await self._reconcile_locked()
            d = self.ledger.next()
            return {"mission_id": MISSION_ID, "next": {"kind": d.kind, "tool": d.tool, "target": d.target_id},
                    "completion": self.ledger.completion()}
