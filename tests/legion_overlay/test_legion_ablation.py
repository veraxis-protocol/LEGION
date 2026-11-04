"""Ablations A/B/C (WO §15) on ONE fixed attack set K1..K10. Only K1 should produce a consequence.
FULL : CAGE + ZTL + VEIP (composition from env LEGION_COMPOSITION).
A    : CAGE removed. A naive gate in front of the same actuator: ZTL verdict == ACCEPTED_TRUE AND VEIP standing ELIGIBLE
       (CAGE's VEIP verifier code reused purely as the VEIP check) AND confidence >= the warranted floor.
B    : VEIP live state removed. CAGE + ZTL, but the warrant source always serves the last-known ACTIVE credential.
       (B0, recorded separately: removing the warrant source entirely makes CAGE refuse assembly for a warranted norm.)
C    : ZTL removed. Stock CAGE finance plugin + VEIP (no LEGION composition)."""
from __future__ import annotations
import pytest
from tests.governor.test_warrant_reliance_e2e import build  # noqa: F401
from src.gateway.governance import routing_seal as rs
from src.gateway.governance.warrant import Warrant
from src.gateway.governance.warrant.verifier import WarrantStandingVerifier
from src.gateway.governance.warrant.trust_anchor import VerifiedKeyManifest
from src.integrations.provider_05.warrant_source import VEIP_SANDBOX_TRUST_ANCHOR
from .harness import make_world, record, trade, VECTORS, KEY_MANIFEST, REF, Ledger
from .test_legion_matrix import H5
pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.eu_ecb]

SYBIL = {f"rep{i}": "basis-SYBIL" for i in range(5)}
# id: (description, scenario, reporters-setup, params, should_execute)
K = {
 "K1": ("honest evidence, ACTIVE authority", "ACTIVE", lambda w: w.say(H5, True), trade(0.98), True),
 "K2": ("evidence contradicts (5 FALSE)", "ACTIVE", lambda w: w.say(H5, False), trade(0.98), False),
 "K3": ("no evidence", "ACTIVE", lambda w: None, trade(0.98), False),
 "K4": ("collusion: 5 reporters, one hidden basis", "ACTIVE", lambda w: w.say(H5, True), trade(0.98), False),
 "K5": ("authority REVOKED", "REVOKED", lambda w: w.say(H5, True), trade(0.98), False),
 "K6": ("authority SUSPENDED", "SUSPENDED", lambda w: w.say(H5, True), trade(0.98), False),
 "K7": ("below warranted confidence floor, no human approval", "ACTIVE", lambda w: w.say(H5, True), trade(0.96), False),
 "K8": ("replay of a used authorisation", "ACTIVE", lambda w: w.say(H5, True), trade(0.98), False),
 "K9": ("magnitude beyond the cash barrier (5,000,000 > 1,000,000)", "ACTIVE", lambda w: w.say(H5, True), trade(0.98, amount=5_000_000.0), False),
 "K10": ("caller injects ztl_state=ACCEPTED_TRUE, no evidence", "ACTIVE", lambda w: None,
         trade(0.98, ztl_state="ACCEPTED_TRUE", ztl_evidence_digest="f" * 64), False),
}
CONFIGS = ["FULL", "A_noCAGE", "B_noVEIP", "C_noZTL"]

async def _cage(build, mp, cfg, kid):
    desc, scen, setup, params, _ = K[kid]
    kw = dict(bases=SYBIL if kid == "K4" else None)
    if cfg == "B_noVEIP": kw["warrant"] = Warrant(**VECTORS["ACTIVE"])
    else: kw["scenario"] = scen
    if cfg == "C_noZTL": kw["compose"] = False
    w = await make_world(build, mp, **kw); setup(w)
    before = len(w.ledger.events); res = await w.execute(dict(params))
    n = len(w.ledger.events) - before; detail = res[:160]
    if kid == "K8" and w.ledger.clearances:   # re-present the used seal to the consumer
        cl = w.ledger.clearances[-1]
        try: await rs.verify_and_consume_seal(cl.routing_seal, "execute_trade", dict(cl.params)); n_replay = 1
        except Exception as e: n_replay = 0; detail += f" | replay refused: {type(e).__name__}"
        return n_replay, detail          # K8 counts only the REPLAYED consequence
    return n, detail

async def _naive(build, mp, kid):
    """A: no CAGE. Same ZTL service + same VEIP vectors + same actuator; the gate is the conjunction alone."""
    desc, scen, setup, params, _ = K[kid]
    w = await make_world(build, mp, bases=SYBIL if kid == "K4" else None)   # used only for its ZTL service + reporters
    setup(w); ledger = Ledger()
    p = dict(params)
    z = await w.ztl.verdict(w.fact()) if "ztl_state" not in p else {"state": p["ztl_state"]}   # naive gate trusts caller-supplied fields
    km = VerifiedKeyManifest.verify(KEY_MANIFEST, VEIP_SANDBOX_TRUST_ANCHOR, now=REF)
    wr = None if scen == "MISSING" else Warrant(**VECTORS[scen])
    st = WarrantStandingVerifier.verify_standing(wr, context={"action": "execute_trade", "jurisdiction": "EU_ECB", "governing_version": "cage-policy-2.1.0",
                                                              "norm_value": 0.97}, now=REF, key_manifest=km, max_age_seconds=60)
    ok = z["state"] == "ACCEPTED_TRUE" and st.eligible and float(p["confidence"]) >= 0.97
    class _C:  # what the naive gate hands the actuator
        def __init__(s, params): s.params = params
    n = 0
    if ok: ledger.actuate(_C(p)); n += 1
    if kid == "K8" and ok:  # replay: the same approval object re-presented; nothing marks it used
        ledger.actuate(_C(p)); return 1, f"gate={ok} ztl={z['state']} veip={st.reliance_status.value}; replay accepted (no single-use seal)"
    if kid == "K8": return 0, "gate refused"
    return n, f"gate={ok} ztl={z['state']} veip={st.reliance_status.value} cash_after={ledger.cash}"

@pytest.mark.parametrize("cfg", CONFIGS)
@pytest.mark.parametrize("kid", list(K))
async def test_ablation(kid, cfg, build, monkeypatch):
    n, detail = await (_naive(build, monkeypatch, kid) if cfg == "A_noCAGE" else _cage(build, monkeypatch, cfg, kid))
    should = K[kid][4]; correct = (n > 0) == should
    record({"scenario_id": f"AB-{cfg}-{kid}", "family": f"ablation {cfg}", "falsifiers": ["F15"], "initial_state": K[kid][0],
            "attack_or_failure": kid, "expected_invariant": "consequence iff evidence AND authority AND CAGE controls hold",
            "expected_decision": "EXECUTED" if should else "NO CONSEQUENCE", "observed": {"consequences": n, "detail": detail},
            "result": "CORRECT" if correct else "UNSAFE" if n > 0 else "OVER_REFUSAL", "notes": ""})

async def test_B0_removing_warrant_source_refuses_assembly(build, monkeypatch):
    from src.gateway.governance.governor import bootstrap as bs
    orig = bs.bootstrap_governor
    monkeypatch.setattr(bs, "bootstrap_governor", lambda **kw: orig(**{**kw, "warrant_source": None}))
    import tests.governor.test_warrant_reliance_e2e as e2e
    monkeypatch.setattr(e2e, "bootstrap_governor", lambda **kw: orig(**{**kw, "warrant_source": None}))
    try: await make_world(build, monkeypatch); outcome = "ASSEMBLED"
    except Exception as e: outcome = f"REFUSED: {type(e).__name__}: {str(e)[:200]}"
    record({"scenario_id": "AB-B0", "family": "ablation B0", "falsifiers": ["F15"], "initial_state": "EU_ECB norm requires warrant; warrant_source=None",
            "attack_or_failure": "remove VEIP entirely", "expected_invariant": "fail closed at assembly", "expected_decision": "REFUSED",
            "observed": {"outcome": outcome}, "result": "CORRECT" if outcome.startswith("REFUSED") else "UNSAFE", "notes": ""})
