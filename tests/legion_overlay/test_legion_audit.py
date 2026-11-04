"""F10 audit replay: an auditor holding only (a) CAGE's hash-chained evidence stream, (b) the actuator's clearances/ledger
events, (c) the ZTL verdict records and (d) the archived signed reports + enrolled public keys must reconstruct, for every
consequence: which evidence record authorised it, that the seal commits to exactly those params (incl. the ZTL digest),
that the ZTL digest recomputes from its record, that every counted report verifies, and that no un-sealed consequence exists."""
from __future__ import annotations
import copy, json, os, pathlib
import pytest
from tests.governor.test_warrant_reliance_e2e import build  # noqa: F401
from src.gateway.governance import routing_seal as rs
from .harness import make_world, record, trade
from .ztl_service import h, jcs, report_body
from .test_legion_matrix import H5
pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.eu_ecb]

async def test_audit_replay(build, monkeypatch):
    w = await make_world(build, monkeypatch)
    w.say(H5, True); r1 = await w.execute(trade(0.98))                                  # consequence 1
    w.say(H5, True, fact=w.fact("MSFT")); r2 = await w.execute(trade(0.98, symbol="MSFT"))  # consequence 2
    w.say(["rep5", "rep6", "rep7"], False); r3 = await w.execute(trade(0.98))           # refused (bound broken)
    chain = await w.stack.chain()                                  # CAGE's own verifier: every record + link verifies
    decisions = [(f, prev) for f, prev in chain if f["event_type"] == "GOVERNANCE_DECISION"]
    checks = {"chain_records": len(chain), "chain_verifies": True, "event_types": sorted({f["event_type"] for f, _ in chain}),
              "ledger_events": len(w.ledger.events), "governance_decisions": len(decisions), "outcomes": [r1[:20], r2[:20], r3[:20]]}
    per = []
    used = set()
    for ev, cl in zip(w.ledger.events, w.ledger.clearances):
        match = [i for i, (f, prev) in enumerate(decisions) if _sv(cl.routing_seal, dict(cl.params), f, prev)]
        zrec = [r for r in w.ztl.audit_log if r["digest"] == ev["ztl_evidence_digest"]]
        zr = zrec[0] if zrec else None
        recomputes = bool(zr) and h({k: v for k, v in zr.items() if k != "digest"}) == zr["digest"]
        arch = {h({k: r[k] for k in r if k != "sig"}): r for r in w.ztl.archive}
        reports_ok = bool(zr) and all(d in arch for d in zr["report_digests"]) and all(
            _verify(w, arch[d]) for d in zr["report_digests"])
        # tamper: the same seal must NOT verify against params whose ZTL digest is altered
        bad = dict(cl.params); bad["ztl_evidence_digest"] = "0" * 64
        tamper_detected = not any(_sv(cl.routing_seal, bad, f, p) for f, p in decisions)
        per.append({"event_id": ev["event_id"], "sealed_record_matches": len(match), "ztl_state_in_seal": cl.params.get("ztl_state"),
                    "ztl_digest_recomputes": recomputes, "reports_counted": len(zr["report_digests"]) if zr else 0, "all_reports_verify": reports_ok,
                    "tamper_detected": tamper_detected, "pre": ev["pre"], "post": ev["post"]})
        used.update(match)
    # a tampered evidence record must fail CAGE's verifier
    f0, p0 = decisions[0]; t = copy.deepcopy(f0); pl = json.loads(t["payload_json"]); pl["params_hash"] = "f" * 64; t["payload_json"] = json.dumps(pl)
    rec_tamper = not _sv(w.ledger.clearances[0].routing_seal, dict(w.ledger.clearances[0].params), t, p0)
    checks.update(per_consequence=per, record_tamper_detected=rec_tamper, unsealed_consequences=len(w.ledger.events) - len(used))
    ok = (len(w.ledger.events) == 2 and len(decisions) == 2 and checks["unsealed_consequences"] == 0 and rec_tamper
          and all(p["sealed_record_matches"] == 1 and p["ztl_state_in_seal"] == "ACCEPTED_TRUE" and p["ztl_digest_recomputes"]
                  and p["all_reports_verify"] and p["tamper_detected"] for p in per) and r3.upper().startswith("BLOCKED"))
    if os.environ.get("LEGION_RECEIPTS"):   # export for independent re-verification (public material only; no private keys)
        from cryptography.hazmat.primitives import serialization as S
        pk = {a: v["pub"].public_bytes(S.Encoding.Raw, S.PublicFormat.Raw).hex() for a, v in w.ztl.agents.items()}
        exp = {"note": "CAGE evidence chain (fakeredis; verify each record with CAGE verify_record(prev_hash)); seals are HMAC in this test posture and need the test seal secret to verify; ZTL records recompute from their bodies; reports verify under reporter_public_keys (Ed25519, JCS body)",
               "outcomes": [r1, r2, r3], "evidence_chain": [{"fields": f, "prev_hash": p} for f, p in chain],
               "consequences": [{"ledger_event": ev, "clearance_params": dict(cl.params), "routing_seal": cl.routing_seal} for ev, cl in zip(w.ledger.events, w.ledger.clearances)],
               "ztl_verdict_records": w.ztl.audit_log, "signed_reports": w.ztl.archive, "reporter_public_keys": pk,
               "reporter_bases": {a: w.ztl.roots[v["root"]] for a, v in w.ztl.agents.items()}}
        pathlib.Path(os.environ["LEGION_RECEIPTS"]).write_text(json.dumps(exp, indent=1, default=str))
    r = record({"scenario_id": "A10", "family": "audit replay", "falsifiers": ["F10"], "initial_state": "2 consequences + 1 refusal in one world",
                "attack_or_failure": "post-hoc reconstruction + tamper (params, record)", "expected_invariant": "every consequence reconstructs; tamper detected",
                "expected_decision": "RECONSTRUCTED", "observed": checks, "result": "PASS" if ok else "FAIL", "notes": ""})
    assert r["result"] == "PASS", json.dumps(checks, default=str)[:3000]

def _verify(w, rep):
    pub = w.ztl.agents[rep["agent"]]["pub"]
    try: pub.verify(bytes.fromhex(rep["sig"]), jcs(report_body(rep["fact_id"], rep["agent"], rep["root"], rep["value"], rep["observed_at"]))); return True
    except Exception: return False

def _sv(seal, params, rec, prev):
    """CAGE's stateless auditor check; it raises on any mismatch, which counts as 'does not verify'."""
    try: return bool(rs.verify_seal_against_evidence(seal, "execute_trade", params, rec, prev_hash=prev))
    except rs.SymbolicGovernorViolation: return False
