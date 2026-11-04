"""Scale (WO §16) on the COMPOSED path: N signed reporters -> ZTL ingestion (Ed25519 verify) -> ZTL verdict (compiled Lean
zverdict + Python differential) -> CAGE decision (resolver budget ZTL_BUDGET_S) -> actuator. f = (N-1)//3.
Opt-in: LEGION_SCALE=1; sizes from LEGION_SCALE_N (default 500,5000,100000). Single process, single host, fakeredis CAGE
test posture: numbers describe THIS run only."""
from __future__ import annotations
import math, os, statistics, time
from datetime import timedelta
import pytest
from tests.governor.test_warrant_reliance_e2e import build  # noqa: F401
from .harness import make_world, record, trade, iso
from .ztl_service import Reporter
from . import cage_compose
from .test_legion_matrix import H5, commit_outcome
pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.eu_ecb,
              pytest.mark.skipif(os.environ.get("LEGION_SCALE") != "1", reason="scale run is opt-in")]
SIZES = [int(x) for x in os.environ.get("LEGION_SCALE_N", "500,5000,100000").split(",")]

@pytest.mark.parametrize("liars", ["none", "f", "f+1"])
@pytest.mark.parametrize("n", SIZES)
async def test_scale(n, liars, build, monkeypatch):
    f = (n - 1) // 3
    w = await make_world(build, monkeypatch, f=f)
    for k in list(w.ztl.agents): w.ztl.agents.pop(k)                   # replace the 9 default reporters
    t0 = time.perf_counter(); reps = [Reporter(agent=f"s{i}", root=f"sroot{i}") for i in range(n)]
    for r in reps: w.ztl.enroll(r, f"sbasis-{i}" if False else f"sbasis-{r.agent}")
    nl = {"none": 0, "f": f, "f+1": f + 1}[liars]
    obs = iso(w.clock.wall - timedelta(seconds=5)); fact = w.fact()
    signed = [r.report(fact, i >= nl, obs) for i, r in enumerate(reps)]; t_sign = time.perf_counter() - t0
    t1 = time.perf_counter(); acc = sum(w.ztl.submit(s) == "ACCEPTED_FOR_EVALUATION" for s in signed); t_ingest = time.perf_counter() - t1
    t2 = time.perf_counter(); v = await w.ztl.verdict(fact); t_verdict = time.perf_counter() - t2
    t3 = time.perf_counter(); res = await w.execute(trade(0.98)); t_decide = time.perf_counter() - t3
    expect_state = {"none": "ACCEPTED_TRUE", "f": "ACCEPTED_TRUE", "f+1": "NOT_DECIDED_BOUND_BROKEN"}[liars]
    got = commit_outcome(res); in_budget = t_verdict <= cage_compose.ZTL_BUDGET_S   # contract: over-budget verdict -> UNAVAILABLE -> DENY
    expected_decision = ("EXECUTED" if in_budget else "DENY") if expect_state == "ACCEPTED_TRUE" else "DENY"
    record({"scenario_id": f"SC-{n}-{liars}", "family": "scale composed path", "falsifiers": ["F13", "F14"],
            "initial_state": f"N={n} f={f} liars={nl}", "attack_or_failure": f"{nl} FALSE reporters", "expected_invariant": "no false ALLOW; budget overrun fails closed",
            "expected_decision": expected_decision,
            "observed": {"accepted_reports": acc, "ztl_state": v["state"], "seats_true": v["seats_true"], "seats_false": v["seats_false"],
                         "lean_python_mismatches": v["lean_python_mismatches"], "t_keygen_sign_s": round(t_sign, 3), "t_ingest_verify_s": round(t_ingest, 3),
                         "t_verdict_s": round(t_verdict, 4), "t_cage_decision_s": round(t_decide, 4), "ztl_budget_s": cage_compose.ZTL_BUDGET_S,
                         "resolver_ztl": {k: (w.ztl.last or {}).get(k) for k in ("state", "error", "elapsed_s")}, "commit": got, "ledger_delta": len(w.ledger.events)},
            "result": "PASS" if (v["state"] == expect_state and got == expected_decision) else "FAIL",
            "notes": "single host; fakeredis; HMAC seals (non-strict test posture)"})

async def test_latency_series(build, monkeypatch):
    """F14: 500 sequential composed decisions at N=5 reporters, f=1 (each with a fresh report set)."""
    w = await make_world(build, monkeypatch)
    lat, outs = [], {}
    for i in range(int(os.environ.get("LEGION_LAT_N", "500"))):
        w.ztl.reports.clear(); w.say(H5, True)
        t = time.perf_counter(); res = await w.execute(trade(0.98, amount=100.0)); lat.append(time.perf_counter() - t)
        o = commit_outcome(res); outs[o] = outs.get(o, 0) + 1
    srt = sorted(lat); q = {p: srt[max(0, math.ceil(p / 100 * len(srt)) - 1)] for p in (95, 99)}   # nearest-rank
    obs = {"n": len(lat), "p50_ms": round(statistics.median(lat) * 1e3, 2), "p95_ms": round(q[95] * 1e3, 2), "p99_ms": round(q[99] * 1e3, 2),
           "max_ms": round(max(lat) * 1e3, 2), "first_ms": round(lat[0] * 1e3, 2), "p99_excl_first_ms": round(sorted(lat[1:])[max(0, math.ceil(0.99 * (len(lat) - 1)) - 1)] * 1e3, 2), "outcomes": outs, "ledger_events": len(w.ledger.events)}
    record({"scenario_id": "LAT-500", "family": "latency composed path", "falsifiers": ["F14"], "initial_state": "N=5 f=1 ACTIVE",
            "attack_or_failure": "none", "expected_invariant": "p99 <= 1000 ms (budget chosen in 07, not frozen by any WO)", "expected_decision": "p99<=1000ms",
            "observed": obs, "result": "PASS" if obs["p99_ms"] <= 1000 else "FAIL", "notes": "single host; fakeredis; includes dowhy causal tier"})

LAT_AT = {500: 50, 5000: 50, 100000: 10}
@pytest.mark.parametrize("n", SIZES)
async def test_latency_at_scale(n, build, monkeypatch):
    """Decision latency with a standing population of n signed reports (all honest TRUE), M decisions after one warm-up."""
    f = (n - 1) // 3
    w = await make_world(build, monkeypatch, f=f)
    for k in list(w.ztl.agents): w.ztl.agents.pop(k)
    reps = [Reporter(agent=f"s{i}", root=f"sroot{i}") for i in range(n)]
    for r in reps: w.ztl.enroll(r, f"sbasis-{r.agent}")
    obs_at = iso(w.clock.wall - timedelta(seconds=5)); fact = w.fact()
    for r in reps: w.ztl.submit(r.report(fact, True, obs_at))
    await w.execute(trade(0.98, amount=10.0))                     # warm-up, excluded
    lat, outs = [], {}
    for _ in range(LAT_AT.get(n, 10)):
        t = time.perf_counter(); res = await w.execute(trade(0.98, amount=10.0)); lat.append(time.perf_counter() - t)
        o = commit_outcome(res); outs[o] = outs.get(o, 0) + 1
    srt = sorted(lat); pr = lambda p: srt[max(0, math.ceil(p / 100 * len(srt)) - 1)]
    obs = {"n_reporters": n, "decisions": len(lat), "p50_ms": round(pr(50) * 1e3, 1), "p95_ms": round(pr(95) * 1e3, 1), "p99_ms": round(pr(99) * 1e3, 1),
           "max_ms": round(max(lat) * 1e3, 1), "outcomes": outs, "last_resolver": {k: (w.ztl.last or {}).get(k) for k in ("state", "error", "elapsed_s")}}
    record({"scenario_id": f"LAT-N{n}", "family": "latency composed path at scale", "falsifiers": ["F14"], "initial_state": f"N={n} honest TRUE, f={f}",
            "attack_or_failure": "none", "expected_invariant": "p99 <= 1000 ms (budget chosen in 07)", "expected_decision": "p99<=1000ms",
            "observed": obs, "result": "PASS" if obs["p99_ms"] <= 1000 else "FAIL", "notes": "nearest-rank percentiles; single host; warm-up excluded"})
