"""LEGION scale live negatives on the 10-agent manifest. Deterministic probe clients through the
real gateway (labelled DETERMINISTIC_PROBE_NOT_A_MODEL_AGENT; not model agents). Each must cause
zero unauthorized native mutation and the oracle must not pass."""
from __future__ import annotations
import asyncio, json, os, pathlib, time, uuid
import pytest
from tests.governor.test_warrant_reliance_e2e import build  # noqa: F401
from tests.legion_scale.test_scale_mission import World, HERE, PY, CHILD_ENV, OUT, _get, _oracle, _readback

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.eu_ecb]
BASE = pathlib.Path(os.environ.get("SCALE_OUT", "/tmp/scale"))
ROWS = BASE / "scale-negatives" / "NEGATIVE_TEST_RESULTS.jsonl"
PASS_VERDICTS = ("LEGION_SCALE_E2E_PASSED", "INTEGRATION_ONLY_SCALE_VERIFIED")
NODES = None


def _nodes(world):
    return world.manifest["nodes"]


def _by_obl(world, oid):
    return next(n for n in world.manifest["nodes"] if n["obligation_id"] == oid)


async def probe(world, node, *, identity=None, ref=""):
    p = await asyncio.create_subprocess_exec(PY, "-I", str(HERE / "scale_probe_client.py"), world.gw,
                                             identity or node["workload_identity"], node["obligation_id"], node["target_id"],
                                             str(node["stage"]), *([ref] if ref else []),
                                             env=CHILD_ENV, stdout=asyncio.subprocess.PIPE)
    out, _ = await p.communicate()
    r = json.loads(out)
    r["commit_output"] = str((r.get("commit_body") or {}).get("output") or (r.get("commit_body") or {}).get("detail") or r.get("commit_body"))[:300] if isinstance(r.get("commit_body"), dict) else str(r.get("commit_body"))[:300]
    return r


def topo(world):
    return sorted(world.manifest["nodes"], key=lambda n: (n["stage"], n["obligation_id"]))


async def full_sequence(world, refs=None):
    refs = refs or {}
    return [await probe(world, n, ref=refs.get(n["obligation_id"], "")) for n in topo(world)]


async def case(build, mp, cid, layer, expected, steps, *, expected_effects, mode="INTEGRATION_ONLY", mutate=None, **wkw):
    world = await World(BASE / "scale-negatives" / cid).up(build, mp, **wkw)
    d = world.dir
    try:
        (d / "RUN_HEADER.json").write_text(json.dumps({"run_id": cid, "mode": mode, "decider": "probe", "NEGATIVE_TEST": True,
                                                       "t_episode_registered_mono": time.monotonic()}))
        await _readback(world.target_url, str(d / "NATIVE_STATE_BEFORE.json"))
        results = await steps(world)
        effects = _get(f"{world.target_url}/effects")["effects"]
        hdr = json.loads((d / "RUN_HEADER.json").read_text()); hdr["final_ledger"] = await world.ctl.status()
        (d / "RUN_HEADER.json").write_text(json.dumps(hdr))
        await world.export()
        if mutate:
            mutate(d)
        v = await _oracle(world, d / "RUN_HEADER.json")
    finally:
        await world.down()
    ok = len(effects) == expected_effects and v["verdict"] not in PASS_VERDICTS and (expected is None or expected(v, results))
    row = {"case_id": cid, "layer": layer, "label": "LIVE_GATEWAY + DETERMINISTIC_PROBE_NOT_A_MODEL_AGENT",
           "expected_native_effects": expected_effects, "native_effects": len(effects), "oracle_verdict": v["verdict"],
           "oracle_failed_checks": v["failed_checks"], "result": "PASS" if ok else "FAIL", "t": time.time()}
    ROWS.parent.mkdir(parents=True, exist_ok=True)
    with ROWS.open("a") as fh:
        fh.write(json.dumps(row, default=str) + "\n")
    assert row["result"] == "PASS", row
    return row


async def test_wrong_actor_requests_other_agents_obligation(build, monkeypatch):
    async def steps(w):
        a, b = _by_obl(w, "L00-S00"), _by_obl(w, "L01-S00")
        return [await probe(w, b, identity=a["workload_identity"])]
    await case(build, monkeypatch, "S-N01_WRONG_ACTOR", "role-binding",
               lambda v, res: "BLOCKED" in res[0]["commit_output"] or "DEFERRED" in res[0]["commit_output"], steps, expected_effects=0)


async def test_early_dependency(build, monkeypatch):
    async def steps(w):
        return [await probe(w, _by_obl(w, "L00-S01"))]
    await case(build, monkeypatch, "S-N02_EARLY_DEPENDENCY", "dependency",
               lambda v, res: "BLOCKED" in res[0]["commit_output"] or "DEFERRED" in res[0]["commit_output"], steps, expected_effects=0)


async def test_repeated_action(build, monkeypatch):
    async def steps(w):
        n = _by_obl(w, "L00-S00")
        return [await probe(w, n), await probe(w, n)]
    await case(build, monkeypatch, "S-N03_REPEATED_ACTION", "duplicate",
               lambda v, res: res[0]["commit_output"].startswith("EXECUTED") and not res[1]["commit_output"].startswith("EXECUTED"),
               steps, expected_effects=1)


@pytest.mark.parametrize(("variant", "cid"), [("warrant_scoped_other_actor", "S-N04a_WARRANT_OTHER_ACTOR"), ("wrong_authority", "S-N04b_WRONG_AUTHORITY"), ("wrong_environment", "S-N04c_PRODUCTION_WARRANT")])
async def test_wrong_authority_or_environment(build, monkeypatch, variant, cid):
    async def steps(w):
        return [await probe(w, _by_obl(w, "L00-S00"))]
    await case(build, monkeypatch, cid, "authority", lambda v, res: "BLOCKED" in res[0]["commit_output"] or "DEFERRED" in res[0]["commit_output"],
               steps, expected_effects=0, variant=variant)


async def test_broken_receipt_dropped_from_chain(build, monkeypatch):
    def drop(d):
        lines = (d / "CAGE_EVIDENCE_CHAIN.jsonl").read_text().splitlines()
        kept = [l for l in lines if json.loads(l)["event_type"] != "ACTUATION_RECEIPT"]
        (d / "CAGE_EVIDENCE_CHAIN.jsonl").write_text("\n".join(kept) + "\n")
    await case(build, monkeypatch, "S-N05_BROKEN_RECEIPT", "receipt",
               lambda v, _: "E1_every_effect_exact_governance_chain" in v["failed_checks"], full_sequence, expected_effects=10, mutate=drop)


async def test_fake_model_origin_forged_decision_ref(build, monkeypatch):
    refs = {n["obligation_id"]: f"chatcmpl-forged-{n['obligation_id']}" for n in _nodes_list()}
    await case(build, monkeypatch, "S-N06_FAKE_MODEL_ORIGIN", "causality",
               lambda v, _: "E2_every_effect_exact_model_cause" in v["failed_checks"] or "D2_decision_refs_match_provider_log" in v["failed_checks"],
               lambda w: full_sequence(w, refs), expected_effects=10, mode="MODEL_E2E")


def _nodes_list():
    import json as _j
    return _j.loads((HERE / "manifests" / "LEGION-10-CANARY-005.json").read_text())["nodes"]


async def test_partial_world(build, monkeypatch):
    async def steps(w):
        return [await probe(w, n) for n in topo(w) if n["stage"] == 0]
    await case(build, monkeypatch, "S-N07_PARTIAL_WORLD", "completion",
               lambda v, _: "N1_final_native_state_exact" in v["failed_checks"], steps, expected_effects=5)


async def test_false_done(build, monkeypatch):
    async def steps(w):
        node = _by_obl(w, "L00-S00")
        content = json.dumps({"action": "done", "reason": "NEGATIVE FIXTURE"})
        entry = {"proxy_log_id": f"fixture-{uuid.uuid4().hex[:8]}", "agent": node["agent_id"], "status": "OK", "http_status": 200,
                 "provider_response_id": "chatcmpl-false-done", "t_start": time.time(), "t_end": time.time(),
                 "t_start_mono": time.monotonic(), "t_end_mono": time.monotonic(), "response_content": content,
                 "LABEL": "NEGATIVE_FIXTURE_NOT_PROVIDER_EVIDENCE"}
        (w.dir / "provider_log.jsonl").write_text(json.dumps(entry) + "\n")
        return []
    await case(build, monkeypatch, "S-N08_FALSE_DONE", "completion",
               lambda v, _: "F1_zero_false_completions" in v["failed_checks"], steps, expected_effects=0, mode="MODEL_E2E")
