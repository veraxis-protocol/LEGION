"""LEGION adversarial matrix on the real CAGE stack (see harness.py). Every scenario records a row BEFORE asserting, so
failures stay in the result ledger. result: PASS | FAIL | MEASURED (beyond-bound / assumption-failure rows: the observed
outcome is the measurement, not a pass/fail of a claimed property)."""
from __future__ import annotations
import asyncio, dataclasses, time
from datetime import timedelta
import pytest
from tests.governor.test_warrant_reliance_e2e import build  # noqa: F401  CAGE's own end-to-end stack fixture
from src.gateway.governance.defer_queue import DeferQueue
from src.gateway.server.workload_identity import CLIENT_IDENTITY_HEADER
from src.gateway.governance.warrant import Warrant
from .harness import make_world, trade, record, VECTORS, KEY_MANIFEST, iso
from .synth import SyntheticIssuer
pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.eu_ecb]
H5 = ["rep0", "rep1", "rep2", "rep3", "rep4"]

def norm(v): return {"DENIED": "DENY", "REJECTED": "DENY"}.get(v, v)
def commit_outcome(res: str) -> str:
    for k, v in (("EXECUTED", "EXECUTED"), ("DEFERRED", "DEFER"), ("BLOCKED", "DENY"), ("PENDING", "REQUIRE_APPROVAL"), ("APPROVAL", "REQUIRE_APPROVAL")):
        if res.upper().startswith(k): return v
    return "OTHER:" + res[:60]

async def decide(w, params=None, deferred_id=None, preview=True):
    params = params or trade(0.98)
    out = {}
    if preview:
        b = await w.validate(params); out["preview"] = norm(b.get("verdict")); out["preview_codes"] = [x if isinstance(x, str) else x.get("code") for x in (b.get("violations") or [])]
        out["deferred_id"] = b.get("deferred_id")
    before = w.actuations(); pre = w.ledger.state()
    res = await w.execute(params, deferred_id); out["commit_raw"] = res[:300]; out["commit"] = commit_outcome(res)
    out["ledger_delta"] = w.actuations() - before; out["pre"] = pre; out["post"] = w.ledger.state()
    out["ztl_last"] = {k: v for k, v in (getattr(w.ztl, "last", {}) or {}).items() if k in ("state", "seats_true", "seats_false", "fresh_reports", "stale_reports", "digest", "error")}
    return out

def row(sid, family, falsifiers, initial, attack, invariant, expected, obs, ok, *, measured=False, notes=""):
    return record({"scenario_id": sid, "family": family, "falsifiers": falsifiers, "initial_state": initial, "attack_or_failure": attack,
                   "expected_invariant": invariant, "expected_decision": expected, "observed": obs,
                   "result": "MEASURED" if measured else ("PASS" if ok else "FAIL"), "notes": notes})

def no_effect(o): return o["ledger_delta"] == 0 and o["commit"] != "EXECUTED"

# ---------------------------------------------------------------- positive / negative controls
async def S01(build, mp):
    w = await make_world(build, mp); w.say(H5, True); o = await decide(w)
    ok = o["preview"] == "ALLOW" and o["commit"] == "EXECUTED" and o["ledger_delta"] == 1 and o["ztl_last"]["state"] == "ACCEPTED_TRUE"
    return row("S01", "honest baseline", ["positive control"], "5 honest reporters TRUE; VEIP ACTIVE", "none", "valid composition -> controlled consequence", "ALLOW + EXECUTED", o, ok)
async def S02(build, mp):
    w = await make_world(build, mp); o = await decide(w)
    return row("S02", "evidence omission", ["F01"], "no reports; VEIP ACTIVE", "evidence omission", "no consequence without accepted evidence", "DENY", o, no_effect(o) and o["preview"] == "DENY")
# ---------------------------------------------------------------- ZTL boundary
async def S03(build, mp):
    w = await make_world(build, mp); w.say(H5, True); w.say(["rep5"], False); o = await decide(w)
    return row("S03", "random reporter failure", ["F13"], "5 honest TRUE + 1 faulty FALSE (f=1)", "1 faulty reporter", "truth accepted within bound", "ALLOW", o, o["commit"] == "EXECUTED")
async def S04(build, mp):
    w = await make_world(build, mp); w.say(["rep0"], True); w.say(["rep5"], False); o = await decide(w)
    return row("S04", "minority Byzantine", ["F01", "F13"], "1 honest TRUE + 1 Byzantine FALSE (f=1)", "Byzantine reporter", "no acceptance below f+1", "DENY", o, no_effect(o))
async def S05(build, mp):
    w = await make_world(build, mp, bases={"rep5": "shared", "rep6": "shared", "rep7": "shared"}); w.say(["rep0", "rep1"], True); w.say(["rep5", "rep6", "rep7"], False); o = await decide(w)
    return row("S05", "correlated reporter failure", ["F07"], "2 honest TRUE (distinct bases) + 3 correlated FALSE declaring one basis", "correlated failure", "a shared basis counts once", "ALLOW (2 TRUE seats vs 1 FALSE seat)", o, o["commit"] == "EXECUTED" and o["ztl_last"]["seats_false"] == 1)
async def S06(build, mp):
    w = await make_world(build, mp); w.say(H5, True); w.say(["rep5", "rep6"], False); o = await decide(w)
    return row("S06", "collusion f+1", ["F13"], "5 honest TRUE + 2 colluders FALSE (f=1: coalition f+1)", "coalition of size f+1", "bound broken -> refuse (liveness loss, not false accept)", "DENY (ZTL_BOUND_BROKEN)", o, no_effect(o) and o["ztl_last"]["state"] == "NOT_DECIDED_BOUND_BROKEN")
async def S07(build, mp):
    w = await make_world(build, mp); w.say(["rep5", "rep6", "rep7", "rep8"], True); w.say(["rep0"], False); o = await decide(w)
    return row("S07", "majority capture", ["F13"], "ground truth FALSE: 4 captured reporters say TRUE, 1 honest FALSE (f=1)", "majority coalition (4 > f)", "beyond the f bound acceptance of the lie is possible", "MEASURED", o, False, measured=True,
               notes="coalition size 4 > f=1; first coalition size violating safety = f+1 = 2 when honest seats < f+1")
async def S08(build, mp):
    w = await make_world(build, mp, bases={"rep7": "basis-X", "rep8": "basis-X"}); w.say(["rep7", "rep8"], True); o = await decide(w)
    return row("S08", "false independence (correct labels)", ["F07"], "ground truth FALSE; 2 captured reporters, one physical source, declared ONE basis", "false independence", "one basis = one seat < f+1", "DENY", o, no_effect(o))
async def S09(build, mp):
    w = await make_world(build, mp); w.say(["rep7", "rep8"], True); o = await decide(w)
    return row("S09", "false independence (mislabelled)", ["F07"], "ground truth FALSE; 2 captured reporters, one physical source, declared TWO bases", "false independence with mislabelled bases", "assumption failure: mislabelled bases are not detectable from data", "MEASURED", o, False, measured=True,
               notes="executes => the independence-basis declaration is a trusted input (assumption, not defended)")
async def S10(build, mp):
    w = await make_world(build, mp); w.say(["rep0"] * 5, True); o = await decide(w)
    return row("S10", "evidence duplication", ["F01"], "one reporter submits 5 times", "duplication", "one agent = one report", "DENY", o, no_effect(o))
async def S11(build, mp):
    w = await make_world(build, mp); w.say(["rep0"], True)
    other = w.reporters["rep1"].report("trade-precondition:MSFT:buy", True, iso(w.clock.wall)); other_as_this = {**other, "fact_id": w.fact()}
    r1 = w.ztl.submit(other_as_this); r2 = w.ztl.submit(w.reporters["rep0"].report(w.fact(), True, iso(w.clock.wall)))
    o = await decide(w); o["submit"] = [r1, r2]
    return row("S11", "evidence replay", ["F06", "F01"], "1 honest report; a valid report for another fact replayed onto this fact; a duplicate replay", "replay", "a report signed for fact A does not count for fact B; replay adds no seat", "DENY", o, no_effect(o) and r1 == "BAD_SIGNATURE")
async def S12(build, mp):
    w = await make_world(build, mp); w.say(H5, True, age_s=900); o = await decide(w)
    return row("S12", "stale / delayed evidence", ["F01"], "5 honest reports observed 900 s ago (max age 300 s)", "evidence delay", "stale evidence excluded", "DENY", o, no_effect(o) and o["ztl_last"]["stale_reports"] == 5)
async def S13(build, mp):
    w = await make_world(build, mp); from .ztl_service import Reporter
    mallory = Reporter("rep0", "root0"); subs = [w.ztl.submit(mallory.report(w.fact(), True, iso(w.clock.wall))) for _ in range(3)]
    stranger = Reporter("intruder", "rootX"); subs.append(w.ztl.submit(stranger.report(w.fact(), True, iso(w.clock.wall))))
    o = await decide(w); o["submit"] = subs
    return row("S13", "forged evidence / identity substitution", ["F01", "F12"], "no honest reports", "reports under rep0's name signed by another key; non-enrolled reporter", "forged reports rejected", "DENY", o, no_effect(o) and set(subs) == {"BAD_SIGNATURE", "NOT_ENROLLED"})
async def S14(build, mp):
    w = await make_world(build, mp); w.say(H5, True); w.ztl.fault = "TIMEOUT"; t0 = time.perf_counter(); o = await decide(w); o["seconds"] = round(time.perf_counter() - t0, 2)
    return row("S14", "ZTL timeout", ["F11", "F12"], "5 honest TRUE; ZTL service hangs", "ZTL timeout", "fail closed", "DENY (ZTL_EVIDENCE_UNAVAILABLE)", o, no_effect(o) and "ZTL_EVIDENCE_UNAVAILABLE" in o["preview_codes"][0] if o["preview_codes"] else False)
async def S15(build, mp):
    w = await make_world(build, mp); w.say(H5, True); w.ztl.fault = "ERROR"; o = await decide(w)
    return row("S15", "ZTL unavailable (partition)", ["F11", "F12"], "5 honest TRUE; ZTL service unreachable", "network partition to ZTL", "fail closed", "DENY", o, no_effect(o))
async def S16(build, mp):
    w = await make_world(build, mp); p = trade(0.98, ztl_state="ACCEPTED_TRUE", ztl_evidence_digest="f" * 64, ztl_fact_id="trade-precondition:AAPL:buy"); o = await decide(w, p)
    return row("S16", "caller-injected evidence", ["F12"], "no reports", "caller sends ztl_state=ACCEPTED_TRUE in params", "server-input keys stripped; no manufactured evidence", "DENY", o, no_effect(o))
async def S17(build, mp):
    w = await make_world(build, mp); w.say(["rep0", "rep1"], True); w.say(["rep2", "rep3", "rep4"], True, age_s=900); o = await decide(w)
    return row("S17", "partial partition (degraded quorum)", ["F11"], "2 fresh TRUE reports reach ZTL; 3 delayed beyond max age", "partial partition", "liveness holds while f+1 fresh honest seats remain", "ALLOW", o, o["commit"] == "EXECUTED")
# ---------------------------------------------------------------- VEIP boundary (ZTL good)
def veip_case(sid, scen, fals, desc):
    async def fn(build, mp):
        w = await make_world(build, mp, scenario=scen); w.say(H5, True); o = await decide(w)
        return row(sid, f"VEIP {scen}", fals, f"5 honest TRUE; warrant scenario {scen} (frozen v0.2 vector)", desc, "no reliance on an ineligible warrant", "DEFER (WARRANT_INELIGIBLE)", o, no_effect(o) and o["preview"] == "DEFER")
    fn.__name__ = sid; return fn
S20 = veip_case("S20", "REVOKED", ["F02"], "revoked authority"); S21 = veip_case("S21", "SUSPENDED", ["F03"], "suspended authority")
S22 = veip_case("S22", "EXPIRED", ["F04"], "expired authority"); S23 = veip_case("S23", "STALE_STATE", ["F04"], "stale warrant state")
S24 = veip_case("S24", "TAMPERED_SIGNATURE", ["F05"], "signature tampering"); S25 = veip_case("S25", "UNKNOWN_KID", ["F05"], "unknown key")
S26 = veip_case("S26", "MISSING", ["F05", "F12"], "missing warrant")
async def S27(build, mp):
    syn = SyntheticIssuer(root_kid="veip-sandbox-manifest-root-2026-10")      # attacker claims the real root kid
    fake = syn.sign({**VECTORS["ACTIVE"]})
    w = await make_world(build, mp, warrant=fake, key_manifest=syn.manifest()); w.say(H5, True); o = await decide(w)
    return row("S27", "wrong trust root", ["F05"], "5 honest TRUE; warrant + key manifest signed by an attacker root using the real root kid", "wrong trust root / cloned authority artefact", "manifest must verify against the out-of-band root", "DEFER (INELIGIBLE_*)", o, no_effect(o))
async def S28(build, mp):
    syn = SyntheticIssuer(); out_scope = syn.sign({**VECTORS["ACTIVE"], "scope": {**VECTORS["ACTIVE"]["scope"], "jurisdictions": ["US_FED"]}})
    w = await make_world(build, mp, warrant=out_scope, key_manifest=syn.manifest(), trust_anchor=syn.anchor()); w.say(H5, True); o = await decide(w)
    return row("S28", "valid signature, wrong scope", ["F05"], "SYNTHETIC trusted root (harness-configured); warrant validly signed for jurisdiction US_FED", "valid key under wrong scope", "out-of-scope warrant ineligible", "DEFER (INELIGIBLE_OUT_OF_SCOPE)", o, no_effect(o) and o["preview"] == "DEFER")
async def S28b(build, mp):
    syn = SyntheticIssuer(); good = syn.sign({**VECTORS["ACTIVE"]})
    w = await make_world(build, mp, warrant=good, key_manifest=syn.manifest(), trust_anchor=syn.anchor()); w.say(H5, True); o = await decide(w)
    return row("S28b", "synthetic-root positive control", ["control"], "SYNTHETIC trusted root; warrant validly signed, in scope", "none", "the synthetic setup can ALLOW (so S28's DEFER is caused by scope)", "ALLOW", o, o["commit"] == "EXECUTED")
async def S29(build, mp):
    w = await make_world(build, mp); w.say(H5, True); w.stack.source.inject_fault("timeout"); w.clock.advance(120); w.say(H5, True)
    o = await decide(w)
    return row("S29", "VEIP timeout past freshness window", ["F04", "F11"], "5 honest TRUE; warrant source times out; cached state older than 60 s", "VEIP timeout", "no reliance on stale authority", "DEFER", o, no_effect(o))
async def S30(build, mp):
    w = await make_world(build, mp); w.say(H5, True); w.stack.source.inject_fault("connection_error"); o = await decide(w)
    return row("S30", "VEIP connection error (cold)", ["F11"], "5 honest TRUE; warrant source unreachable, nothing cached", "network partition to VEIP", "fail closed", "DEFER", o, no_effect(o))
async def S31(build, mp):
    w = await make_world(build, mp); w.say(H5, True); w.clock.advance(86400); w.say(H5, True); o = await decide(w)
    return row("S31", "authority replay (old ACTIVE warrant after a day)", ["F04", "F06"], "source keeps serving the 2026-10-07T14:00 ACTIVE warrant; clock +24 h", "authority replay", "state_as_of beyond freshness -> STALE", "DEFER", o, no_effect(o))
# ---------------------------------------------------------------- composition precedence
async def S40(build, mp):
    w = await make_world(build, mp, scenario="REVOKED"); w.say(["rep0"], True); o = await decide(w)
    return row("S40", "ZTL fail + VEIP revoked", ["F01", "F02"], "ZTL insufficient; warrant REVOKED", "both boundaries fail", "HARD dominates; reliance recorded", "DENY", o, no_effect(o) and o["preview"] == "DENY")
async def S41(build, mp):
    w = await make_world(build, mp, scenario="STALE_STATE"); w.say(["rep0"], True); o = await decide(w)
    return row("S41", "ZTL uncertain + VEIP stale", ["F01", "F04"], "ZTL insufficient; warrant STALE", "both boundaries fail", "contract row", "DENY", o, no_effect(o))
async def S42(build, mp):
    w = await make_world(build, mp); w.say(H5, True); o = await decide(w, trade(0.98, symbol="XXXX"))
    return row("S42", "ZTL pass + VEIP active + CAGE hard safety failure", ["F15"], "5 honest TRUE for XXXX (fact differs) ; warrant ACTIVE; instrument outside bounding contract", "CAGE runtime gate", "CAGE gate refuses independently", "DENY", o, no_effect(o))
async def S43(build, mp):
    w = await make_world(build, mp); w.say(H5, True, fact="trade-precondition:AAPL:sell"); o = await decide(w)
    return row("S43", "evidence for a different action", ["F01"], "5 honest TRUE for AAPL:sell; request AAPL:buy", "evidence/action mismatch", "evidence bound to the action's fact", "DENY", o, no_effect(o))
# ---------------------------------------------------------------- human control & races
async def _approved(w, conf=0.96):
    b = await w.validate(trade(conf)); did = b.get("deferred_id")
    if did: await w.stack.approve(did, "urn:op:alice", "urn:op:bob")
    return norm(b.get("verdict")), did
async def S50(build, mp):
    w = await make_world(build, mp); w.say(H5, True); v, did = await _approved(w); o = await decide(w, trade(0.96), did, preview=False); o["first"] = v
    o2 = await decide(w, trade(0.96), did, preview=False); o["replay"] = {k: o2[k] for k in ("commit", "ledger_delta")}
    ok = v == "REQUIRE_APPROVAL" and o["commit"] == "EXECUTED" and o["ledger_delta"] == 1 and o2["ledger_delta"] == 0
    return row("S50", "human approval + approval replay", ["F06", "D7"], "5 honest TRUE; confidence 0.96 < 0.97 floor -> REQUIRE_APPROVAL; 2 approvers", "approve, execute, replay the approval", "approval redeems once", "REQUIRE_APPROVAL -> EXECUTED once", o, ok)
async def S51(build, mp):
    w = await make_world(build, mp); w.say(H5, True); v, did = await _approved(w)
    w.stack.source.seed(Warrant(**VECTORS["REVOKED"])); w.clock.advance(61); w.say(H5, True)
    o = await decide(w, trade(0.96), did, preview=False); o["first"] = v
    return row("S51", "race: approval -> revocation -> action", ["F02", "F08"], "approved trade; issuer revokes before execution", "human/issuer revocation after approval", "no consequence after revocation", "DEFER (POST_HITL)", o, no_effect(o))
async def S52(build, mp):
    w = await make_world(build, mp); w.say(H5, True); v, did = await _approved(w)
    w.say(["rep5", "rep6", "rep7"], False); o = await decide(w, trade(0.96), did, preview=False); o["first"] = v
    return row("S52", "race: approval -> evidence contradiction -> action", ["F09"], "approved with ZTL ACCEPTED_TRUE; 3 more bases then report FALSE", "post-HITL evidence mutation", "POST_HITL re-binds ZTL", "DENY", o, no_effect(o))
async def S53(build, mp):
    w = await make_world(build, mp); w.say(H5, True); b = await w.validate(trade(0.98)); pv = norm(b.get("verdict"))
    for a in H5[:4]: w.ztl.retract_agent(a)
    o = await decide(w, preview=False); o["preview_before_mutation"] = pv
    return row("S53", "race: evidence accepted -> state changes -> action", ["F09"], "preview ALLOW with 5 reports; 4 reports withdrawn before commit", "TOCTOU between preview and commit", "commit re-evaluates", "DENY", o, no_effect(o) and pv == "ALLOW")
async def S54(build, mp):
    w = await make_world(build, mp); w.say(H5, True); b = await w.validate(trade(0.96)); did = b.get("deferred_id")
    o = await decide(w, trade(0.96), did, preview=False); o["first"] = norm(b.get("verdict"))
    return row("S54", "human refusal (no approval given)", ["D7"], "REQUIRE_APPROVAL; no approver acts", "agent attempts execution without approval", "no consequence", "not EXECUTED", o, no_effect(o))
async def S55(build, mp):
    w = await make_world(build, mp); w.say(H5, True); v, did = await _approved(w)
    q = DeferQueue(w.stack.defer_redis); st = await w.stack.defer_redis.hget(f"DEFER:{did}", "status")
    flipped = await q.atomic_resolve(did, expected_status=st, new_status="REJECTED")
    o = await decide(w, trade(0.96), did, preview=False); o.update(first=v, status_before=st, rejected_cas=flipped)
    return row("S55", "conflicting human commands", ["D7"], "2 approvals, then an operator rejects the ticket", "approve vs reject", "rejection wins; no consequence", "not EXECUTED", o, no_effect(o))
async def S56(build, mp):
    w = await make_world(build, mp); w.say(H5, True)
    r = await w.stack.http.post("/governance/validate-action", json={"action": "execute_trade", "params": trade(0.98)}, headers={CLIENT_IDENTITY_HEADER: "evil.ns.serviceaccount.identity.linkerd.cluster.local"})
    o = {"http_status": r.status_code}
    return row("S56", "caller identity substitution", ["D8"], "5 honest TRUE; ACTIVE", "untrusted workload identity at the gateway", "403 fail closed", "403", o, r.status_code == 403)
async def S57(build, mp):
    # SYNTHETIC issuer: the frozen VEIP ACTIVE vector has state_as_of 14:00:00Z and cannot be re-issued later without the
    # VEIP issuer key (trial run: replaying it at +61 s is correctly STALE). Re-issuance therefore uses a throw-away root.
    syn = SyntheticIssuer(); susp = syn.sign({**VECTORS["SUSPENDED"]})
    w = await make_world(build, mp, warrant=susp, key_manifest=syn.manifest(), trust_anchor=syn.anchor()); w.say(H5, True); o1 = await decide(w)
    w.clock.advance(61)
    w.stack.source.seed(syn.sign({**VECTORS["ACTIVE"], "state_as_of": iso(w.clock.wall), "issued_at": iso(w.clock.wall)}))
    w.say(H5, True); o2 = await decide(w)
    o = {"suspended": o1, "reinstated": {k: o2[k] for k in ("preview", "preview_codes", "commit", "ledger_delta")}}
    return row("S57", "human suspension then reinstatement", ["F03", "D7"], "SYNTHETIC root: warrant SUSPENDED, then ACTIVE re-issued at +61 s", "suspension as a control", "suspended blocks; reinstated allows", "DEFER then EXECUTED", o, no_effect(o1) and o2["commit"] == "EXECUTED")

ALL = [S01, S02, S03, S04, S05, S06, S07, S08, S09, S10, S11, S12, S13, S14, S15, S16, S17, S20, S21, S22, S23, S24, S25, S26, S27, S28, S28b, S29, S30, S31,
       S40, S41, S42, S43, S50, S51, S52, S53, S54, S55, S56, S57]
@pytest.mark.parametrize("scenario", ALL, ids=[f.__name__ for f in ALL])
async def test_matrix(scenario, build, monkeypatch):
    r = await asyncio.wait_for(scenario(build, monkeypatch), 60)
    assert r["result"] in ("PASS", "MEASURED"), r
