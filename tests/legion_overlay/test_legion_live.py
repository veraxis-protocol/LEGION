"""LIVE VEIP boundary: the composed LEGION stack fetches warrants + the key manifest over HTTPS from the VEIP v0.2 CAGE
sandbox (no seeding). 8 frozen scenarios x {ZTL ACCEPTED_TRUE, ZTL ACCEPTED_FALSE}. Opt-in: LEGION_LIVE=1."""
from __future__ import annotations
import asyncio, os
import pytest
from tests.governor.test_warrant_reliance_e2e import build  # noqa: F401
from .harness import make_world, record
from .test_legion_matrix import decide, H5, no_effect
pytestmark = [pytest.mark.unit, pytest.mark.eu_ecb,
              pytest.mark.skipif(os.environ.get("LEGION_LIVE") != "1", reason="live VEIP run is opt-in")]
SCEN = ["ACTIVE", "REVOKED", "SUSPENDED", "EXPIRED", "STALE_STATE", "TAMPERED_SIGNATURE", "UNKNOWN_KID", "MISSING"]
@pytest.mark.parametrize("ztl", [True, False], ids=["ztlTRUE", "ztlFALSE"])
@pytest.mark.parametrize("scenario", SCEN)
async def test_live(scenario, ztl, build, monkeypatch):
    w = await make_world(build, monkeypatch, scenario=scenario, live=True); w.say(H5, ztl)
    o = await asyncio.wait_for(decide(w), 60)
    exp = ("ALLOW", "EXECUTED") if (ztl and scenario == "ACTIVE") else (("DENY", "DENY") if not ztl else ("DEFER", "DEFER"))
    ok = (o["preview"], o["commit"]) == exp and (o["ledger_delta"] == (1 if exp[1] == "EXECUTED" else 0))
    r = record({"scenario_id": f"L-{scenario}-{'T' if ztl else 'F'}", "family": "live VEIP boundary", "falsifiers": ["F03", "F04", "F05", "F12"],
                "initial_state": f"live sandbox scenario {scenario}; 5 honest ZTL reports value={ztl}", "attack_or_failure": scenario,
                "expected_invariant": "I1/I2/I3 over real HTTP", "expected_decision": "/".join(exp), "observed": o,
                "result": "PASS" if ok else "FAIL", "notes": "live HTTPS to veip-cage-sandbox.am-43b.workers.dev"})
    assert r["result"] == "PASS", r
