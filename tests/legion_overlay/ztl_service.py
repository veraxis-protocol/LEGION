"""ZTL evidence service (LEGION candidate). The decision rule is the REAL ztl-swarm 7d2a826 rule: ``ZtlSwarm`` with the
verdict executed by the compiled Lean definition ``zverdict`` (Python rule kept as a differential). Everything else here is
LEGION glue, declared:

* reports are Ed25519-signed by enrolled reporters over JCS({fact_id, agent, root, value, observed_at});
* a report older than ``max_age_s`` on the service clock is excluded (stale evidence);
* one report per agent per fact (latest wins); a replayed report is a no-op; a report signed for another fact fails;
* collapse: reports -> declared independence basis; a basis is seated once per value it reported (B2 / verdictRoots
  semantics, so equivocation pushes both sides toward f + 1 and the rule refuses);
* the fault bound ``f`` is service POLICY, never caller input.

States: ACCEPTED_TRUE | ACCEPTED_FALSE | NOT_DECIDED_INSUFFICIENT | NOT_DECIDED_BOUND_BROKEN (both values reach f + 1).
Faults (injected): TIMEOUT (verdict() sleeps past any caller budget), ERROR (raises). Neither may produce a state."""
from __future__ import annotations
import asyncio, hashlib, json, os, sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable
try:
    import rfc8785
    _jcs = rfc8785.dumps
except ImportError:   # inside the CAGE venv: CAGE's own vendored RFC 8785 canonicalizer
    from src.gateway.governance.vendor.jcs import canonicalize as _jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

ZTL_SWARM_DIR = os.environ.get("LEGION_ZTL_SWARM_DIR", "/home/user/repos/ztl-swarm")
if ZTL_SWARM_DIR not in sys.path:
    sys.path.insert(0, ZTL_SWARM_DIR)
os.environ.setdefault("ZVERDICT", os.path.join(ZTL_SWARM_DIR, "lean/.lake/build/bin/zverdict"))
from ztlswarm.ztlrule import ZtlSwarm, LeanVerdict  # noqa: E402

def jcs(o: Any) -> bytes:
    b = _jcs(o)
    return b if isinstance(b, bytes) else b.encode()
def h(o: Any) -> str: return hashlib.sha256(jcs(o)).hexdigest()
def report_body(fact_id: str, agent: str, root: str, value: bool, observed_at: str) -> dict:
    return {"fact_id": fact_id, "agent": agent, "root": root, "value": value, "observed_at": observed_at}

@dataclass
class Reporter:
    agent: str
    root: str
    key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    def report(self, fact_id: str, value: bool, observed_at: str, *, claim_root: str | None = None, sign_fact: str | None = None) -> dict:
        body = report_body(fact_id, self.agent, claim_root or self.root, value, observed_at)
        signed = report_body(sign_fact or fact_id, self.agent, claim_root or self.root, value, observed_at)
        return {**body, "sig": self.key.sign(jcs(signed)).hex()}

class ZtlEvidenceService:
    def __init__(self, *, f: int, clock: Callable[[], datetime], max_age_s: float = 300.0, lean: bool = True):
        self.f, self.clock, self.max_age_s = f, clock, max_age_s
        self.agents: dict[str, dict] = {}      # agent -> {root, pub}
        self.roots: dict[str, str] = {}        # root -> declared independence basis
        self.reports: dict[str, dict[str, dict]] = {}   # fact -> agent -> report
        self.rejected: list[dict] = []
        self.archive: list[dict] = []        # every accepted report, append-only (audit replay)
        self.fault = "NONE"
        self.lean = LeanVerdict() if lean else None
        self.calls = 0
    def enroll(self, r: Reporter, basis: str) -> None:
        self.agents[r.agent] = {"root": r.root, "pub": r.key.public_key()}
        self.roots[r.root] = basis
    def submit(self, rep: dict) -> str:
        a = self.agents.get(rep.get("agent"))
        if a is None: self.rejected.append({**rep, "why": "NOT_ENROLLED"}); return "NOT_ENROLLED"
        if rep.get("root") != a["root"]: self.rejected.append({**rep, "why": "ROOT_MISMATCH"}); return "ROOT_MISMATCH"
        if type(rep.get("value")) is not bool: self.rejected.append({**rep, "why": "VALUE_TYPE"}); return "VALUE_TYPE"
        try:
            a["pub"].verify(bytes.fromhex(rep["sig"]), jcs(report_body(rep["fact_id"], rep["agent"], rep["root"], rep["value"], rep["observed_at"])))
        except (InvalidSignature, ValueError, KeyError, TypeError):
            self.rejected.append({**rep, "why": "BAD_SIGNATURE"}); return "BAD_SIGNATURE"
        self.reports.setdefault(rep["fact_id"], {})[rep["agent"]] = rep; self.archive.append(rep)
        return "ACCEPTED_FOR_EVALUATION"
    def retract_agent(self, agent: str) -> None:
        for fr in self.reports.values(): fr.pop(agent, None)
    async def verdict(self, fact_id: str) -> dict:
        self.calls += 1
        if self.fault == "TIMEOUT": await asyncio.sleep(3600)
        if self.fault == "ERROR": raise ConnectionError("ZTL evidence service unavailable (injected)")
        now = self.clock()
        fresh, stale = [], []
        for rep in self.reports.get(fact_id, {}).values():
            age = (now - datetime.fromisoformat(rep["observed_at"].replace("Z", "+00:00"))).total_seconds()
            (fresh if 0 <= age <= self.max_age_s else stale).append(rep)
        by_basis: dict[str, set] = {}
        for rep in fresh: by_basis.setdefault(self.roots[self.agents[rep["agent"]]["root"]], set()).add(rep["value"])
        seats = [(b, v) for b in sorted(by_basis) for v in sorted(by_basis[b])]
        t = sum(1 for _, v in seats if v is True); fl = sum(1 for _, v in seats if v is False)
        zs = ZtlSwarm(max(len(seats), 1), self.f)
        if self.lean is not None: zs.lean = self.lean
        v = zs.step({i: val for i, (_, val) in enumerate(seats)}) if seats else None
        if v is True: state = "ACCEPTED_TRUE"
        elif v is False: state = "ACCEPTED_FALSE"
        elif t >= self.f + 1 and fl >= self.f + 1: state = "NOT_DECIDED_BOUND_BROKEN"
        else: state = "NOT_DECIDED_INSUFFICIENT"
        rec = {"fact_id": fact_id, "f": self.f, "state": state, "seats_true": t, "seats_false": fl, "bases": {b: sorted(x) for b, x in by_basis.items()},
               "fresh_reports": len(fresh), "stale_reports": len(stale), "evaluated_at": now.isoformat(), "lean_python_mismatches": zs.lean_mismatches,
               "report_digests": sorted(h({k: r[k] for k in r if k != "sig"}) for r in fresh)}
        rec["digest"] = h(rec)
        return rec
