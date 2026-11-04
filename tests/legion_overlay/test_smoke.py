import pytest
from tests.governor.test_warrant_reliance_e2e import build  # noqa: F401  (CAGE's own stack fixture)
from .harness import make_world, trade
pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.eu_ecb]
async def test_smoke_positive(build, monkeypatch):
    w = await make_world(build, monkeypatch)
    print("submit", w.say(["rep0", "rep1", "rep2"], True))
    body = await w.validate(trade(0.98)); print("validate", body["verdict"], body.get("violations"))
    res = await w.execute(trade(0.98)); print("execute", res[:200]); print("ledger", w.ledger.events)
async def test_smoke_no_evidence(build, monkeypatch):
    w = await make_world(build, monkeypatch)
    body = await w.validate(trade(0.98)); print("validate", body["verdict"], body.get("violations"))
async def test_smoke_revoked(build, monkeypatch):
    w = await make_world(build, monkeypatch, scenario="REVOKED"); w.say(["rep0", "rep1", "rep2"], True)
    body = await w.validate(trade(0.98)); print("validate", body["verdict"], body.get("violations"), body.get("defer_reason"))
