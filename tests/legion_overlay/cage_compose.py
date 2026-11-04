"""Compose LEGION's ZTL boundary into CAGE through CAGE's PUBLIC plugin contract only (no kernel change):

* ZtlEvidenceTier (ReadOnlyTier, phase 1, order 0) — reads ONLY server-bound params; maps ZTL state to Violations:
    ACCEPTED_TRUE                 -> none
    ACCEPTED_FALSE                -> HARD  ZTL_EVIDENCE_CONTRADICTS
    NOT_DECIDED_INSUFFICIENT      -> HARD  ZTL_EVIDENCE_INSUFFICIENT
    NOT_DECIDED_BOUND_BROKEN      -> HARD  ZTL_BOUND_BROKEN
    absent / unknown (timeout, error, resolver failure) -> HARD ZTL_EVIDENCE_UNAVAILABLE
  HARD because CAGE has no violation kind for "evidence insufficient, park for re-hydration": DEFERRABLE defers only below
  the confidence floor (classification_engine step 6) and RELIANCE_INELIGIBLE is the warrant kind (it would label the
  deferral WARRANT_INELIGIBLE). Gap recorded: the desired DEFER-on-insufficient-evidence needs a kernel change.
* LegionTradeInputResolver — wraps the finance TradeInputResolver for the trade actions (CAGE permits one resolver per
  action) and adds owned keys ztl_state / ztl_evidence_digest / ztl_fact_id: any caller value is stripped by CAGE's
  bind_server_inputs and the committing seal names the bound params, so the ZTL digest is inside CAGE's sealed evidence."""
from __future__ import annotations
import asyncio, dataclasses, time
from typing import Any, Mapping
from src.gateway.governance.contracts import ReadOnlyTier, MutatingTier, CommitReceipt, Violation, ViolationKind, PluginContribution
ZTL_KEYS = frozenset({"ztl_state", "ztl_evidence_digest", "ztl_fact_id"})
ZTL_BUDGET_S = 1.0
def fact_for(params: Mapping[str, Any]) -> str:
    return f"trade-precondition:{params.get('symbol')}:{params.get('side')}"
class LegionTradeInputResolver:
    def __init__(self, inner, ztl, version: str = "v1"):
        self.inner, self.ztl, self.version = inner, ztl, version
        self.owned_keys = frozenset(inner.owned_keys) | ZTL_KEYS
    async def resolve(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        out = dict(await self.inner.resolve(params))
        fact = fact_for(params)
        try:
            t0 = time.monotonic()
            rec = await asyncio.wait_for(self.ztl.verdict(fact), ZTL_BUDGET_S)
            # v3 REMEDIATION (scale finding SC-100000, v2): wait_for cannot pre-empt a CPU-bound verdict with no await
            # point, so a 2.2 s verdict was used under a 1.0 s budget. v3 discards any verdict that arrives late -> the
            # keys stay absent -> ZTL_EVIDENCE_UNAVAILABLE (HARD). v1/v2 keep the original behaviour for the record.
            if self.version == "v3" and time.monotonic() - t0 > ZTL_BUDGET_S:
                self.ztl.last = {**rec, "error": "LateVerdictDiscarded", "elapsed_s": round(time.monotonic() - t0, 3)}
                raise TimeoutError("late ZTL verdict discarded")
            out.update(ztl_state=rec["state"], ztl_evidence_digest=rec["digest"], ztl_fact_id=fact)
            self.ztl.last = rec
            self.ztl.__dict__.setdefault('audit_log', []).append(rec)
        except Exception as e:  # timeout / error: the keys stay absent -> the tier refuses (fail closed)
            if not (isinstance(getattr(self.ztl, "last", None), dict) and self.ztl.last.get("error") == "LateVerdictDiscarded"):
                self.ztl.last = {"fact_id": fact, "error": f"{type(e).__name__}"}
        return out
CODES = {"ACCEPTED_FALSE": "ZTL_EVIDENCE_CONTRADICTS", "NOT_DECIDED_INSUFFICIENT": "ZTL_EVIDENCE_INSUFFICIENT", "NOT_DECIDED_BOUND_BROKEN": "ZTL_BOUND_BROKEN"}
class ZtlEvidenceTier(ReadOnlyTier):
    def __init__(self, actions: frozenset[str]): self._actions = actions
    @property
    def tier_name(self) -> str: return "legion_ztl_evidence"
    @property
    def order(self) -> int: return 0
    def claims_action(self, action: str, params: dict[str, Any]) -> bool: return action in self._actions
    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        st = params.get("ztl_state")
        if st == "ACCEPTED_TRUE" and params.get("ztl_evidence_digest"): return []
        code = CODES.get(st, "ZTL_EVIDENCE_UNAVAILABLE")
        return [Violation(tier=self.tier_name, code=code, message=f"[{code}] ZTL evidence boundary: state={st!r} fact={params.get('ztl_fact_id')!r} digest={params.get('ztl_evidence_digest')!r}",
                          kind=ViolationKind.HARD)]
def _ztl_violations(tier: str, params: Mapping[str, Any]) -> list[Violation]:
    st = params.get("ztl_state")
    if st == "ACCEPTED_TRUE" and params.get("ztl_evidence_digest"): return []
    code = CODES.get(st, "ZTL_EVIDENCE_UNAVAILABLE")
    return [Violation(tier=tier, code=code, message=f"[{code}] ZTL evidence boundary: state={st!r} fact={params.get('ztl_fact_id')!r} digest={params.get('ztl_evidence_digest')!r}",
                      kind=ViolationKind.HARD)]
class ZtlRecheckTier(MutatingTier):
    """v2 REMEDIATION for finding S52 (v1): CAGE's POST_HITL profile re-runs only phase-2 tiers plus the kernel stages
    {opa, warrant} (pipeline.POST_HITL_READ_ONLY_STAGES), so a plugin ReadOnlyTier is NOT re-checked after human approval.
    This phase-2 tier re-applies the same ZTL mapping on the re-resolved server-bound params under every committing profile.
    It reserves nothing: commit() returns (violations, None); rollback/confirm are no-ops. Using MutatingTier for a stateless
    re-check stretches the contract's intent ("reserves state") — recorded as an open contract question, not hidden."""
    def __init__(self, actions: frozenset[str]): self._actions = actions
    @property
    def tier_name(self) -> str: return "legion_ztl_recheck"
    @property
    def order(self) -> int: return 0
    def claims_action(self, action: str, params: dict[str, Any]) -> bool: return action in self._actions
    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]: return _ztl_violations(self.tier_name, params)
    async def commit(self, action: str, params: dict[str, Any]) -> tuple[list[Violation], CommitReceipt | None]:
        return _ztl_violations(self.tier_name, params), None
    async def rollback(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None: return None
    async def confirm(self, action: str, params: dict[str, Any], receipt: CommitReceipt) -> None: return None
def compose(contribution: PluginContribution, ztl, actions: frozenset[str], version: str = "v1") -> PluginContribution:
    """v1 = phase-1 ZtlEvidenceTier only (as pre-registered). v2 = v1 + phase-2 ZtlRecheckTier (S52 remediation).
    v3 = v2 + late-verdict discard in the resolver (SC-100000 remediation)."""
    si = dict(contribution.server_inputs)
    for a in actions: si[a] = LegionTradeInputResolver(si[a], ztl, version)
    extra = (ZtlEvidenceTier(actions),) + ((ZtlRecheckTier(actions),) if version in ("v2", "v3") else ())
    return dataclasses.replace(contribution, tiers=tuple(contribution.tiers) + extra, server_inputs=si)
