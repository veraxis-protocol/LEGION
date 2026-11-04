"""LEGION scenario harness on CAGE's own end-to-end stack (tests/governor/test_warrant_reliance_e2e.py `build`):
real composition root, gateway ASGI app behind workload identity, the finance trade tool (commit, seal, verify-and-consume,
actuate), the hash-chained evidence stream and the DeferQueue. LEGION adds the ZTL evidence boundary through the public
plugin contract (cage_compose.compose) and replaces the actuator double with a controlled LEDGER (pre/post state).
Authority: VEIP v0.2 warrants verified by CAGE's own WarrantStandingVerifier against the VEIP sandbox trust root
(hermetic: the frozen vectors, byte-equal to the live sandbox on 2026-10-16; live: CAGE's Provider05WarrantSource over HTTP)."""
from __future__ import annotations
import json, os, pathlib, uuid, hashlib
from datetime import datetime, timedelta, timezone
from typing import Any
from src.gateway.governance.seams.actuation import ActuationReceipt
from src.gateway.governance.warrant import Warrant
from src.gateway.governance.decisions import GovernanceDecision
from src.gateway.governance.governance_envelope import unwrap_governance_envelope
from src.cage_finance.tools.trade_inputs import TRADE_ACTIONS
import src.cage_finance.plugin as finance_plugin
from tests.governor.test_warrant_reliance_e2e import _Clock, trade
from . import cage_compose
from .ztl_service import ZtlEvidenceService, Reporter, h

REF = datetime(2026, 10, 7, 14, 0, 10, tzinfo=timezone.utc)      # VEIP v0.2 reference clock
V02 = pathlib.Path("docs/partners/provider_05/veip_v02")
VECTORS = json.loads((V02 / "warrants_v02_vectors.json").read_text())
KEY_MANIFEST = json.loads((V02 / "key_manifest.json").read_text())
COMPOSITION = os.environ.get("LEGION_COMPOSITION", "v1")
RESULTS = pathlib.Path(os.environ.get("LEGION_RESULTS", "/tmp/legion_results.jsonl"))
ACTIONS = frozenset(TRADE_ACTIONS)

def iso(dt: datetime) -> str: return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

class Ledger:
    """Controlled consequence: a cash/position ledger the actuator mutates. Nothing else may change it."""
    def __init__(self): self.cash, self.positions, self.events, self.clearances = 1_000_000.0, {}, [], []
    def state(self): return {"cash": self.cash, "positions": dict(self.positions)}
    def actuate(self, clearance):
        p = clearance.params; before = self.state()
        amt = float(p["amount"]); self.cash -= amt; self.positions[p["symbol"]] = self.positions.get(p["symbol"], 0.0) + amt
        ev = {"event_id": uuid.uuid4().hex[:12], "params_hash": h({k: p[k] for k in sorted(p) if isinstance(p[k], (str, int, float, bool))}),
              "ztl_evidence_digest": p.get("ztl_evidence_digest"), "ztl_state": p.get("ztl_state"), "pre": before, "post": self.state()}
        self.events.append(ev); self.clearances.append(clearance)
        return ActuationReceipt(accepted=True, receipt_id=ev["event_id"], session_uuid=None, raw_receipt={"status": "executed", **ev})

class Legion:
    """One LEGION world: reporters, ZTL service, CAGE stack, ledger."""
    def __init__(self, stack, ztl, clock, ledger, reporters):
        self.stack, self.ztl, self.clock, self.ledger, self.reporters = stack, ztl, clock, ledger, reporters
    def fact(self, symbol="AAPL", side="buy"): return cage_compose.fact_for({"symbol": symbol, "side": side})
    def say(self, names, value: bool, *, age_s: float = 5.0, fact=None, **kw):
        out = []
        for n in names:
            out.append(self.ztl.submit(self.reporters[n].report(fact or self.fact(), value, iso(self.clock.wall - timedelta(seconds=age_s)), **kw)))
        return out
    async def validate(self, params): r = await self.stack.validate(params); return unwrap_governance_envelope(r.json())
    async def execute(self, params, deferred_id=None): return await self.stack.execute(params, deferred_id)
    def actuations(self): return len(self.ledger.events)

async def make_world(build, monkeypatch, *, f=1, scenario="ACTIVE", live=False, bases=None, trust_anchor=None, key_manifest=None, warrant=None, compose=True):
    clock = _Clock(wall=REF)
    ztl = ZtlEvidenceService(f=f, clock=lambda: clock.wall)
    reporters = {}
    for i in range(9):
        r = Reporter(agent=f"rep{i}", root=f"root{i}")
        reporters[r.agent] = r; ztl.enroll(r, (bases or {}).get(r.agent, f"basis-{i}"))
    import importlib
    for modname in (("src.cage_finance.plugin", "cage_finance.plugin") if compose else ()):   # the cage.plugins entry point loads cage_finance.plugin
        mod = importlib.import_module(modname)
        cur = mod.FinanceCagePlugin.contribute
        orig = getattr(cur, "__legion_orig__", cur)          # never wrap an already-composed contribute twice
        patched = (lambda o: lambda self: cage_compose.compose(o(self), ztl, ACTIONS, COMPOSITION))(orig)
        patched.__legion_orig__ = orig
        monkeypatch.setattr(mod.FinanceCagePlugin, "contribute", patched)
    if live:
        monkeypatch.setenv("PROVIDER_05_ATTESTATION_ENDPOINT", "https://veip-cage-sandbox.am-43b.workers.dev")
        monkeypatch.setenv("PROVIDER_05_WARRANT_SCENARIO", scenario)
        stack = await build(clock=clock)
    else:
        w = warrant if warrant is not None else (None if scenario == "MISSING" else Warrant(**VECTORS[scenario]))
        stack = await build(seed=w, clock=clock)
        if trust_anchor is not None: stack.source._explicit_trust_anchor = trust_anchor
        stack.source.seed_key_manifest(key_manifest if key_manifest is not None else KEY_MANIFEST)
    tiers = [t for t in _all_tiers(stack.governor) if getattr(t, "tier_name", "") == "legion_ztl_evidence"]
    assert bool(tiers) == compose, f"LEGION ZTL tier presence {bool(tiers)} != compose={compose}"
    if COMPOSITION in ("v2", "v3") and compose:
        assert [t for t in _all_tiers(stack.governor) if getattr(t, "tier_name", "") == "legion_ztl_recheck"], "v2 recheck tier missing"
    ledger = Ledger()
    stack.actuate.side_effect = ledger.actuate
    return Legion(stack, ztl, clock, ledger, reporters)

def record(row: dict) -> dict:
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    row = {"composition": COMPOSITION, **row}
    with RESULTS.open("a") as fh: fh.write(json.dumps(row, default=str) + "\n")
    return row

def _all_tiers(gov):
    """Every tier object reachable from the governor (used only to assert the composition took effect)."""
    seen, out, todo = set(), [], [gov]
    while todo:
        o = todo.pop()
        if id(o) in seen or len(seen) > 20000: continue
        seen.add(id(o))
        if hasattr(o, "tier_name") and hasattr(o, "evaluate"): out.append(o)
        vals = []
        if isinstance(o, dict): vals = list(o.values())
        elif isinstance(o, (list, tuple, set, frozenset)): vals = list(o)
        elif hasattr(o, "__dict__"): vals = list(vars(o).values())
        elif hasattr(o, "__slots__"): vals = [getattr(o, s, None) for s in o.__slots__]
        todo.extend(v for v in vals if not isinstance(v, (str, bytes, int, float, bool, type(None))))
    return out
