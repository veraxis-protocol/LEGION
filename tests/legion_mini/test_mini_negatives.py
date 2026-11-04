"""LEGION-MINI-003 live NEGATIVE CONTROLS on the real gateway (deterministic probe clients, labelled; not model agents).
Each case: a fresh world, native readback before/after, effects counted from the native log. Rows -> OUT/negatives.jsonl.
Denied attempts must cause zero native mutations; valid controls must still execute."""
from __future__ import annotations
import asyncio, json, os, pathlib, time
import pytest
from tests.governor.test_warrant_reliance_e2e import build  # noqa: F401
from tests.legion_mini.test_mini_mission import World, IDS, HERE, PY, CHILD_ENV, OUT, _get, _oracle, _readback

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.eu_ecb]
ROWS = OUT / "negatives" / "negatives.jsonl"
CFG, OPS = IDS["agent:config-restorer"], IDS["agent:service-operator"]
ARGS = {"target": "demo-service", "generation": 1, "confidence": 0.99}


async def probe(world, ident, tool, args=ARGS, preview=True):
    p = await asyncio.create_subprocess_exec(PY, "-I", str(HERE / "probe_client.py"), world.gw, ident, tool, json.dumps(args),
                                             *([] if preview else ["--no-preview"]), env=CHILD_ENV, stdout=asyncio.subprocess.PIPE)
    out, _ = await p.communicate()
    r = json.loads(out)
    r["commit_output"] = str((r.get("commit_body") or {}).get("output") or (r.get("commit_body") or {}).get("detail") or r.get("commit_body"))[:400]
    return r


async def case(build, mp, cid, falsifier, expected_effects, steps, *, oracle=False, **world_kw):
    world = await World(OUT / "negatives" / cid).up(build, mp, **world_kw)
    try:
        await _readback(world.target_url, str(world.dir / "NATIVE_STATE_BEFORE.json"))
        before = _get(f"{world.target_url}/effects")["effects"]
        results = await steps(world)
        after = _get(f"{world.target_url}/effects")["effects"]
        state = _get(f"{world.target_url}/state")
        new = [e for e in after if e not in before]
        ok = len(new) == expected_effects
        row = {"case_id": cid, "falsifier": falsifier, "label": "LIVE_GATEWAY_DETERMINISTIC_PROBE", "expected_native_effects": expected_effects,
               "native_effects": len(new), "effects": [{k: e[k] for k in ("seq", "verb", "actor", "command_id")} for e in new],
               "final_native_state": {k: state[k] for k in ("config_restored", "service_running", "service_healthy", "generation")},
               "probes": results, "result": "PASS" if ok else "FAIL", "t": time.time()}
        await world.export()
        if oracle:
            (world.dir / "RUN_HEADER.json").write_text(json.dumps({"run_id": cid, "mode": "INTEGRATION_ONLY", "final_ledger": await world.ctl.status()}))
            v = await _oracle(world, world.dir / "RUN_HEADER.json")
            row["oracle_verdict"], row["oracle_failed_checks"] = v["verdict"], v["failed_checks"]
    finally:
        await world.down()
    ROWS.parent.mkdir(parents=True, exist_ok=True)
    with ROWS.open("a") as fh:
        fh.write(json.dumps(row, default=str) + "\n")
    return row


async def test_NEG01_actor_mismatch(build, monkeypatch):
    r = await case(build, monkeypatch, "NEG01_ACTOR_MISMATCH", "service-operator identity commits restore_config (warrant scoped to config-restorer)", 0,
                   lambda w: asyncio.gather(probe(w, OPS, "restore_config")))
    assert r["result"] == "PASS", r


async def test_NEG02_system_mismatch(build, monkeypatch):
    r = await case(build, monkeypatch, "NEG02_SYSTEM_MISMATCH", "restore warrant scoped to another system", 0,
                   lambda w: asyncio.gather(probe(w, CFG, "restore_config")), variant="wrong_system")
    assert r["result"] == "PASS", r


async def test_NEG03_environment_mismatch(build, monkeypatch):
    r = await case(build, monkeypatch, "NEG03_ENVIRONMENT_MISMATCH", "restore warrant signed for PRODUCTION (SANDBOX manifest/deployment)", 0,
                   lambda w: asyncio.gather(probe(w, CFG, "restore_config")), variant="wrong_environment")
    assert r["result"] == "PASS", r


async def test_NEG04_authority_mismatch(build, monkeypatch):
    r = await case(build, monkeypatch, "NEG04_AUTHORITY_MISMATCH", "restore warrant names an authority the kid is not granted", 0,
                   lambda w: asyncio.gather(probe(w, CFG, "restore_config")), variant="unauthorized_authority")
    assert r["result"] == "PASS", r


async def test_NEG05_ztl_not_eligible(build, monkeypatch):
    r = await case(build, monkeypatch, "NEG05_ZTL_INSUFFICIENT", "1 observer < f+1 seats: ledger says ACT, ZTL NOT_DECIDED_INSUFFICIENT", 0,
                   lambda w: asyncio.gather(probe(w, CFG, "restore_config")), observers=1)
    assert r["result"] == "PASS", r


async def test_NEG06_dependency_early_then_valid_control(build, monkeypatch):
    async def steps(w):
        early = await probe(w, OPS, "restart_service")                      # before obligation 1: must be refused
        assert not _get(f"{w.target_url}/effects")["effects"], "early restart mutated the target"
        good1 = await probe(w, CFG, "restore_config")                       # valid control
        good2 = await probe(w, OPS, "restart_service")                      # valid control, now eligible
        return [early, good1, good2]
    r = await case(build, monkeypatch, "NEG06_DEPENDENCY_EARLY_THEN_VALID", "restart before config refused (0), then valid sequence executes (2)", 2,
                   steps, oracle=True)
    assert r["result"] == "PASS" and r["effects"][0]["verb"] == "restore_config", r


async def test_NEG07_duplicate_commit(build, monkeypatch):
    async def steps(w):
        concurrent = await asyncio.gather(probe(w, CFG, "restore_config", preview=False), probe(w, CFG, "restore_config", preview=False))
        again = await probe(w, CFG, "restore_config")                       # after closure
        return [*concurrent, again]
    r = await case(build, monkeypatch, "NEG07_DUPLICATE_COMMIT", "two concurrent commits + one later repeat of restore_config", 1, steps)
    assert r["result"] == "PASS", r


async def test_NEG08_false_done_and_partial(build, monkeypatch):
    async def steps(w):
        return [{"note": "no action; an agent claims DONE"}]
    r = await case(build, monkeypatch, "NEG08_FALSE_DONE_NO_EFFECT", "agent DONE with no effect -> Oracle must not pass", 0, steps, oracle=True)
    assert r["result"] == "PASS" and r["oracle_verdict"] not in ("LEGION_MINI_E2E_PASSED", "INTEGRATION_ONLY_GOVERNANCE_VERIFIED"), r

    async def partial(w):
        return [await probe(w, CFG, "restore_config")]
    r2 = await case(build, monkeypatch, "NEG08b_PARTIAL_ONE_EFFECT", "only config restored -> Oracle must not pass", 1, partial, oracle=True)
    assert r2["result"] == "PASS" and r2["oracle_verdict"] not in ("LEGION_MINI_E2E_PASSED", "INTEGRATION_ONLY_GOVERNANCE_VERIFIED"), r2


async def test_NEG09_direct_target_write_without_actuator_credential(build, monkeypatch):
    async def steps(w):
        p = await asyncio.create_subprocess_exec(PY, "-I", "-c", (
            "import json,urllib.request,urllib.error,sys\n"
            "req=urllib.request.Request(sys.argv[1]+'/apply',data=json.dumps({'command_id':'x','verb':'restore_config','target':'demo-service','generation':1}).encode(),"
            "method='POST',headers={'Content-Type':'application/json','Authorization':'Bearer guessed'})\n"
            "try:\n urllib.request.urlopen(req,timeout=10); print(200)\nexcept urllib.error.HTTPError as e: print(e.code)\n"), w.target_url,
            env=CHILD_ENV, stdout=asyncio.subprocess.PIPE)
        out, _ = await p.communicate()
        return [{"direct_write_http": int(out.strip())}]
    r = await case(build, monkeypatch, "NEG09_DIRECT_TARGET_WRITE", "agent-side process writes the target directly with a guessed credential", 0, steps)
    assert r["result"] == "PASS" and r["probes"][0]["direct_write_http"] == 401, r
