"""§12 items added after the first matrix run (pre-registered falsifier families unchanged): post-HITL suspension,
emergency stop (approximated by an operator policy flip — CAGE has no kill switch), unauthorized delegation (actor/system
scope), NARROW-path composition, CAGE timeout."""
from __future__ import annotations
import asyncio
import pytest
from tests.governor.test_warrant_reliance_e2e import build  # noqa: F401
from src.gateway.governance.warrant import Warrant
from .harness import make_world, trade, VECTORS, iso
from .synth import SyntheticIssuer
from .test_legion_matrix import decide, row, no_effect, H5, _approved, norm, commit_outcome
pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.eu_ecb]

async def S58(build, mp):
    w = await make_world(build, mp); w.say(H5, True); v, did = await _approved(w)
    w.stack.source.seed(Warrant(**VECTORS["SUSPENDED"])); w.clock.advance(61); w.say(H5, True)
    o = await decide(w, trade(0.96), did, preview=False); o["first"] = v
    return row("S58", "race: approval -> suspension -> action", ["F03", "F08"], "approved trade; warrant SUSPENDED before execution", "post-HITL suspension", "no consequence while suspended", "DEFER (POST_HITL)", o, no_effect(o) and v == "REQUIRE_APPROVAL")
async def S59(build, mp):
    w = await make_world(build, mp); w.say(H5, True); v, did = await _approved(w)
    w.stack.opa.verdict = "DENY"                     # operator emergency stop expressed as policy (no kill switch exists)
    o_new = await decide(w); o_pend = await decide(w, trade(0.96), did, preview=False)
    o = {"new_request": o_new, "pending_approved": {k: o_pend[k] for k in ("commit", "commit_raw", "ledger_delta")}, "first": v}
    return row("S59", "emergency human stop (operator policy flip to DENY)", ["F08", "D7"], "one approved pending trade + one new request; operator flips OPA to DENY",
               "emergency stop", "no consequence after the stop (new or pending)", "DENY / not EXECUTED", o, no_effect(o_new) and no_effect(o_pend),
               notes="CAGE has no dedicated emergency-stop/kill-switch; this measures the policy channel only (gap G-CAGE-02)")
async def S60(build, mp):
    syn = SyntheticIssuer()
    deleg = syn.sign({**VECTORS["ACTIVE"], "scope": {**VECTORS["ACTIVE"]["scope"], "actors": ["agent:unrelated_delegate"], "systems": ["some-other-system"]}})
    w = await make_world(build, mp, warrant=deleg, key_manifest=syn.manifest(), trust_anchor=syn.anchor()); w.say(H5, True); o = await decide(w)
    return row("S60", "unauthorized delegation (warrant names another actor + system)", ["F05"], "SYNTHETIC root; warrant valid but actors=[agent:unrelated_delegate], systems=[some-other-system]",
               "agent relies on authority delegated to someone else", "out-of-scope actor/system ineligible", "DEFER (INELIGIBLE_OUT_OF_SCOPE)", o, no_effect(o),
               notes="code: WarrantScope.contains checks actor/system only if the context supplies them; WarrantStage supplies action/jurisdiction only")
async def S61(build, mp):
    w = await make_world(build, mp); w.say(H5, True); o = await decide(w, trade(0.98, amount=600_000.0))
    ev = w.ledger.events[-1] if w.ledger.events else {}
    o["executed_amount"] = (w.ledger.clearances[-1].params.get("amount") if w.ledger.clearances else None); o["sealed_ztl"] = ev.get("ztl_state")
    ok = o["ledger_delta"] <= 1 and (o["ledger_delta"] == 0 or (o["executed_amount"] is not None and o["executed_amount"] <= 500_000 and o["sealed_ztl"] == "ACCEPTED_TRUE"))
    return row("S61", "NARROW path with valid evidence (amount 600k > 500k fiscal cap)", ["F15"], "5 honest TRUE; ACTIVE", "over-cap request",
               "narrowed consequence still carries the ZTL digest; never exceeds cap", "NARROW -> EXECUTED <= cap (or refusal)", o, ok)
async def S61b(build, mp):
    w = await make_world(build, mp); w.say(H5, False); o = await decide(w, trade(0.98, amount=600_000.0))
    return row("S61b", "NARROW path with contradicting evidence", ["F01"], "5 TRUE->FALSE; ACTIVE", "over-cap request + bad evidence", "HARD ZTL precedes NARROW", "DENY", o, no_effect(o))
async def S62(build, mp):
    w = await make_world(build, mp); w.say(H5, True)
    async def hang(payload): await asyncio.sleep(3600)
    orig = w.stack.opa.evaluate_policy; w.stack.opa.evaluate_policy = hang
    before = len(w.ledger.events); out = "returned"
    try: await asyncio.wait_for(w.execute(trade(0.98)), 2.0)
    except asyncio.TimeoutError: out = "client timeout (2 s)"
    w.stack.opa.evaluate_policy = orig; await asyncio.sleep(0.5)
    decisions = [f for f, _ in await w.stack.chain() if f["event_type"] == "GOVERNANCE_DECISION"]
    o = {"outcome": out, "ledger_delta": len(w.ledger.events) - before, "seals_minted": len(decisions), "commit": "TIMEOUT"}
    return row("S62", "CAGE timeout (governor stage hangs)", ["F11"], "5 honest TRUE; OPA stage never returns", "CAGE timeout", "no consequence, no seal",
               "no EXECUTED", o, o["ledger_delta"] == 0 and o["seals_minted"] == 0)

async def S63(build, mp):
    syn = SyntheticIssuer(); full = syn.sign({**VECTORS["ACTIVE"]})
    w = await make_world(build, mp, warrant=full, key_manifest=syn.manifest(), trust_anchor=syn.anchor()); w.say(H5, True); o1 = await decide(w)
    w.clock.advance(61); w.say(H5, True)
    w.stack.source.seed(syn.sign({**VECTORS["ACTIVE"], "scope": {**VECTORS["ACTIVE"]["scope"], "actions": ["execute_trade_bounded"]},
                                  "state_as_of": iso(w.clock.wall), "issued_at": iso(w.clock.wall)}))
    o2 = await decide(w)
    o = {"before_reduction": {k: o1[k] for k in ("preview", "commit", "ledger_delta")}, "after_reduction": o2}
    return row("S63", "human scope reduction (execute_trade removed from warrant scope)", ["D7", "F05"], "SYNTHETIC root; full scope, then re-issued without execute_trade",
               "scope reduction", "reduced scope blocks the removed action", "EXECUTED then DEFER", o, o1["commit"] == "EXECUTED" and no_effect(o2))
async def S64(build, mp):
    w = await make_world(build, mp); w.say(H5, True)
    o = await decide(w, trade(0.96), "00000000-0000-4000-8000-000000000000", preview=False)
    return row("S64", "forged approval (fabricated deferred_id)", ["D8", "F06"], "5 honest TRUE; conf 0.96 needs approval; no approval exists", "forged approval reference",
               "no consequence", "not EXECUTED", o, no_effect(o))
async def S65a(build, mp):
    syn = SyntheticIssuer(); other = syn.sign({**VECTORS["ACTIVE"], "norm_id": "fiscal.daily_cap_usd"})
    w = await make_world(build, mp, warrant=other, key_manifest=syn.manifest(), trust_anchor=syn.anchor()); w.say(H5, True); o = await decide(w)
    return row("S65a", "valid key, authority for a different norm", ["D8", "F05"], "SYNTHETIC root; validly signed warrant for norm fiscal.daily_cap_usd only",
               "authority of the wrong class", "does not ground confidence.min_trade_confidence", "DEFER (MISSING)", o, no_effect(o))
async def S65b(build, mp):
    syn = SyntheticIssuer()
    loose = syn.sign({**VECTORS["ACTIVE"], "norm_parameters": {"min_trade_confidence": {"type": "decimal", "value": "0.90", "unit": "ratio"}}})
    w = await make_world(build, mp, warrant=loose, key_manifest=syn.manifest(), trust_anchor=syn.anchor()); w.say(H5, True); o = await decide(w, trade(0.95))
    return row("S65b", "valid key, looser norm parameter (0.90 vs runtime 0.97)", ["D8", "F05"], "SYNTHETIC root; warrant declares floor 0.90; trade conf 0.95",
               "authority asserting a different parameter", "parameter mismatch ineligible; trade not executed", "DEFER/REQUIRE_APPROVAL, not EXECUTED", o, no_effect(o))
async def S66(build, mp):
    from src.gateway.governance import routing_seal as rs
    w = await make_world(build, mp); w.say(H5, True); await decide(w)
    cl = w.ledger.clearances[-1]; forged = cl.routing_seal[:-8] + ("A" * 8 if not cl.routing_seal.endswith("A" * 8) else "B" * 8)
    outs = {}
    for name, seal, params in (("forged_seal", forged, dict(cl.params)), ("seal_other_params", cl.routing_seal, {**cl.params, "amount": 999_999.0})):
        try: await rs.verify_and_consume_seal(seal, "execute_trade", params); outs[name] = "ACCEPTED"
        except Exception as e: outs[name] = f"REFUSED:{type(e).__name__}"
    o = {**outs, "ledger_delta": 0, "commit": "n/a"}
    return row("S66", "agent bypass: forged seal / seal re-bound to other params", ["F06", "D7"], "one legitimate execution", "seal forgery and re-binding",
               "consumer refuses", "REFUSED x2", o, all(v.startswith("REFUSED") for v in outs.values()))

async def S70(build, mp):
    """D4/D5 boundary sweep. Ground truth: precondition FALSE (no consequence should occur). n=7 independent bases, f=2.
    k liars report TRUE; honest report FALSE. Variant 'suppressed': honest reports withheld (strategically positioned coalition)."""
    res = {}
    for variant in ("honest_present", "honest_suppressed"):
        for k in range(0, 8):
            w = await make_world(build, mp, f=2)
            names = [f"rep{i}" for i in range(7)]
            w.say(names[:k], True)
            if variant == "honest_present": w.say(names[k:], False)
            o = await decide(w, preview=False)
            res[f"{variant}:k={k}"] = {"ztl": o["ztl_last"].get("state"), "commit": o["commit"], "ledger_delta": o["ledger_delta"]}
    first = {v: next((k for k in range(8) if res[f"{v}:k={k}"]["ledger_delta"] > 0), None) for v in ("honest_present", "honest_suppressed")}
    o = {"cells": res, "first_false_allow_coalition": first, "f": 2, "n": 7, "commit": "sweep", "ledger_delta": None}
    ok = all(res[f"{v}:k={k}"]["ledger_delta"] == 0 for v in ("honest_present", "honest_suppressed") for k in range(0, 3))   # k <= f never false-allows
    return row("S70", "threshold sweep: coalition size k = 0..7 (n=7, f=2), truth FALSE", ["F13", "D4", "D5"], "n=7 bases; truth FALSE",
               "coalition of k TRUE liars, honest present / suppressed", "no false ALLOW for k <= f", "MEASURED threshold", o, ok,
               notes="beyond-bound false ALLOWs are measured thresholds, not falsification of F13 (pre-registered)")

async def _spend_to(w, total):
    """Spend inside the FTRA envelope (10,000) and below the EU_ECB consensus threshold (7,500): 7,000 per trade."""
    left = total
    while left > 0:
        amt = min(7_000.0, left); r = await w.execute(trade(0.98, amount=amt)); left -= amt
        if not r.upper().startswith("EXECUTED"): return r
    return "ok"
async def S61c(build, mp):
    w = await make_world(build, mp); w.say(H5, True); pre = await _spend_to(w, 496_000.0); n0 = len(w.ledger.events)
    o = await decide(w, trade(0.98, amount=8_000.0))
    o["prespend"] = pre; o["prespend_events"] = n0
    o["executed_amount"] = w.ledger.clearances[-1].params.get("amount") if len(w.ledger.events) > n0 else None
    o["sealed_ztl"] = w.ledger.events[-1].get("ztl_state") if len(w.ledger.events) > n0 else None
    ok = pre == "ok" and o["preview"] == "NARROW" and o["commit"] == "EXECUTED" and o["executed_amount"] is not None and o["executed_amount"] <= 4_000.0 and o["sealed_ztl"] == "ACCEPTED_TRUE"
    o["narrow_reached"] = o["preview"] == "NARROW"
    return row("S61c", "NARROW path (fiscal headroom 4,000; request 8,000)", ["F15", "D4"], "496,000 of 500,000 daily cap spent in 7,000 trades; 5 honest TRUE",
               "over-headroom request", "NARROW re-run keeps ZTL binding; executed amount <= headroom", "NARROW -> EXECUTED <= 4,000", o, ok,
               measured=not o["narrow_reached"] and no_effect(o),
               notes="if narrow_reached is false the NARROW composition is NOT_EXECUTED in this stack (fiscal guard refused HARD); no over-headroom consequence")
async def S61d(build, mp):
    w = await make_world(build, mp); w.say(H5, True); pre = await _spend_to(w, 496_000.0); n0 = len(w.ledger.events)
    w.say(H5, False); o = await decide(w, trade(0.98, amount=8_000.0)); o["prespend"] = pre
    return row("S61d", "NARROW-eligible request with contradicting evidence", ["F01", "D4"], "headroom 4,000; evidence flips to FALSE",
               "narrowable request + bad evidence", "HARD ZTL precedes NARROW", "DENY", o, pre == "ok" and no_effect(o))

async def S67(build, mp):
    syn = SyntheticIssuer()
    alien = syn.sign({**VECTORS["ACTIVE"], "issuing_authority": "Unrelated Body (not the manifest issuer)", "environment": "PRODUCTION"})
    w = await make_world(build, mp, warrant=alien, key_manifest=syn.manifest(), trust_anchor=syn.anchor()); w.say(H5, True); o = await decide(w)
    return row("S67", "issuer identity / environment not bound to the key manifest", ["F05", "D8"],
               "SYNTHETIC root; manifest issuer LEGION-SYNTHETIC, environment SANDBOX; warrant claims another issuing_authority and environment PRODUCTION",
               "authority asserted in the name of a body other than the manifest issuer", "issuer and environment must match the verified manifest",
               "DEFER (INELIGIBLE_AUTHENTICITY)", o, no_effect(o),
               notes="code: issuing_authority is never compared with VerifiedKeyManifest.issuer; environment is not checked (inventory 02)")

ALL = [S58, S59, S60, S61, S61b, S61c, S61d, S62, S63, S64, S65a, S65b, S66, S67, S70]
@pytest.mark.parametrize("scenario", ALL, ids=[f.__name__ for f in ALL])
async def test_extra(scenario, build, monkeypatch):
    r = await asyncio.wait_for(scenario(build, monkeypatch), 60)
    assert r["result"] in ("PASS", "MEASURED"), r
