"""LEGION-MINI-003 LIVE Oracle: its own OS process, started after the agents exit. It does NOT accept agent output.

Sources (each read by this process itself):
  native      GET /state, GET /effects on the live target (read-only)                  -> final state, effects, order
  CAGE        CAGE_EVIDENCE_CHAIN.jsonl exported by the host; re-verified here with CAGE's own verify_record + linkage
  VEIP        TEST_ONLY_FIXTURES.json public artifacts re-verified here with CAGE's VerifiedKeyManifest /
              VerifiedAuthorityAuthorization / WarrantStandingVerifier against each effect's actor and system
  ZTL / QL    ZTL_OBLIGATIONS.jsonl (controller log): verdicts, claims, closures, order
  model       provider_log.jsonl written by the provider-logging proxy (never by agents)
It then builds the frozen pack's witness from these verified facts ONLY and runs the frozen fixture scorer on it.
argv: --target --run-dir --header --pack --cage"""
from __future__ import annotations
import argparse, hashlib, json, pathlib, sys, urllib.request
from datetime import datetime, timezone

EXPECTED_FINAL = {"config_restored": True, "service_running": True, "service_healthy": True, "generation": 1}
ORDER = [("restore_config", "agent:config-restorer"), ("restart_service", "agent:service-operator")]
SYSTEM, TARGET = "legion-synthetic-sre", "demo-service"
REF = datetime(2026, 10, 7, 14, 0, 10, tzinfo=timezone.utc)


def jl(p: pathlib.Path):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


def main():
    ap = argparse.ArgumentParser()
    for a in ("target", "run-dir", "header", "pack", "cage"):
        ap.add_argument(f"--{a}", required=True)
    a = ap.parse_args()
    run = pathlib.Path(a.run_dir)
    sys.path.insert(0, a.cage)
    sys.path.insert(0, a.pack)
    import oracle as frozen_fixture_oracle                          # frozen pack scorer (fixture spec)
    from src.gateway.governance.evidence.stream import verify_record
    from src.gateway.governance.warrant import Warrant
    from src.gateway.governance.warrant.authority import VerifiedAuthorityAuthorization
    from src.gateway.governance.warrant.trust_anchor import VerifiedKeyManifest, WarrantTrustAnchor
    from src.gateway.governance.warrant.verifier import WarrantStandingVerifier

    header = json.loads(pathlib.Path(a.header).read_text())
    checks: dict[str, dict] = {}

    def check(name, ok, **detail):
        checks[name] = {"ok": bool(ok), **detail}

    # ---------------------------------------------------------------- native (live, read-only)
    with urllib.request.urlopen(f"{a.target}/state", timeout=10) as r:
        st = json.loads(r.read())
    with urllib.request.urlopen(f"{a.target}/effects", timeout=10) as r:
        effects = json.loads(r.read())["effects"]
    final = {k: st[k] for k in EXPECTED_FINAL}
    applied = [e for e in effects if e.get("applied") is True]
    check("N1_final_native_state_exact", final == EXPECTED_FINAL, observed=final)
    check("N2_exactly_two_effects", len(applied) == 2, count=len(applied))
    order_ok = len(applied) == 2 and all(applied[i]["verb"] == v and applied[i]["actor"] == act and applied[i]["system"] == SYSTEM
                                         and applied[i]["target"] == TARGET and applied[i]["generation"] == 1 for i, (v, act) in enumerate(ORDER))
    check("N3_order_actor_system_target_generation", order_ok, effects=[{k: e.get(k) for k in ("seq", "verb", "actor", "system", "generation", "command_id")} for e in applied])
    check("N4_unique_command_ids", len({e["command_id"] for e in applied}) == len(applied))
    before = json.loads((run / "NATIVE_STATE_BEFORE.json").read_text())
    check("N5_initial_failed_state", before["state"] == {"config_restored": False, "service_running": False, "service_healthy": False, "generation": 0}
          and before["effects"] == [], observed=before["state"])

    # ---------------------------------------------------------------- CAGE evidence chain (re-verified here)
    chain = jl(run / "CAGE_EVIDENCE_CHAIN.jsonl")
    prev, chain_ok = "", True
    for f in chain:
        if not verify_record(f, prev_hash=prev).valid:
            chain_ok = False; break
        prev = f["record_hash"]
    check("C1_cage_chain_verifies", chain_ok and bool(chain), records=len(chain))
    payloads = [(f["event_type"], json.loads(f.get("payload_json") or "{}"), f["record_hash"]) for f in chain]
    linked = {}
    for e in applied:
        hits = [(et, rh) for et, p, rh in payloads if e["effect_id"] in json.dumps(p)]
        decisions = [(p, rh) for et, p, rh in payloads if et == "GOVERNANCE_DECISION" and p.get("action") == e["verb"]]
        linked[e["effect_id"]] = {"receipt_records": hits, "decision_records": [rh for _, rh in decisions],
                                  "decision_reliance": [r.get("reliance_status") for p, _ in decisions for r in p.get("reliance") or []]}
    check("C2_each_effect_has_cage_decision_and_receipt",
          all(v["receipt_records"] and len(v["decision_records"]) == 1 for v in linked.values()) and len(linked) == len(applied), linked=linked)
    check("C3_seal_digest_on_each_effect", all(e.get("governance_seal_sha256") for e in applied))

    # ---------------------------------------------------------------- VEIP (re-verified here from public artifacts)
    fx = json.loads((run / "TEST_ONLY_FIXTURES.json").read_text())
    veip = {}
    try:
        anchor = WarrantTrustAnchor(root_kid=fx["root_kid"], public_key_b64=fx["root_public_key_spki_b64"], expected_fingerprint=fx["root_fingerprint"])
        km = VerifiedKeyManifest.verify(fx["key_manifest"], anchor, now=REF)
        az = VerifiedAuthorityAuthorization.verify(fx["authority_authorization"], anchor)
        warrants = {w["scope"]["actions"][0]: Warrant(**w) for w in fx["warrants"]}
        for e in applied:
            w = warrants.get(e["verb"])
            res = WarrantStandingVerifier.verify_standing(
                w, context={"action": e["verb"], "jurisdiction": "EU_ECB", "governing_version": "legion-mini-sre-1", "norm_value": 1.0,
                            "actor": e["actor"], "system": e["system"]},
                now=REF, key_manifest=km, authority_authorization=az, require_authority_authorization=True, expected_environment="SANDBOX")
            veip[e["effect_id"]] = {"status": res.reliance_status.value, "reason": res.reason[:160]}
    except Exception as exc:
        veip["error"] = f"{type(exc).__name__}: {exc}"
    check("V1_independent_warrant_reverification", all(isinstance(v, dict) and v.get("status") == "ELIGIBLE" for v in veip.values()) and len(veip) == len(applied), veip=veip)
    check("V2_gateway_reliance_eligible", all("ELIGIBLE" in v["decision_reliance"] for v in linked.values()) and bool(linked))

    # ---------------------------------------------------------------- ZTL evidence + QuantifiedLedger obligations
    ev = jl(run / "ZTL_OBLIGATIONS.jsonl")
    by_cmd = {e["command_id"]: e for e in applied}
    claimed = [x for x in ev if x["event"] == "CLAIMED"]
    closed = [x for x in ev if x["event"] == "OBLIGATION_CLOSED"]
    check("Z1_each_effect_claimed_and_closed_once", sorted(c["command_id"] for c in claimed) == sorted(by_cmd) and
          sorted(c["command_id"] for c in closed) == sorted(by_cmd) and all(c["effect_id"] == by_cmd[c["command_id"]]["effect_id"] for c in closed),
          claimed=len(claimed), closed=len(closed))
    def idx(event, action):
        return next((i for i, x in enumerate(ev) if x["event"] == event and x.get("action") == action), None)
    i_close1, i_claim2 = idx("OBLIGATION_CLOSED", "restore_config"), idx("CLAIMED", "restart_service")
    check("Z2_second_claim_only_after_first_closure", i_close1 is not None and i_claim2 is not None and i_close1 < i_claim2)
    true_before = all(any(x["event"] == "ZTL_VERDICT" and x["action"] == act and x["state"] == "ACCEPTED_TRUE" for x in ev[:idx("CLAIMED", act) or 0])
                      for act, _ in ORDER)
    check("Z3_ztl_accepted_true_before_each_claim", true_before)
    early = [x["state"] for x in ev[:i_close1 or 0] if x["event"] == "ZTL_VERDICT" and x["action"] == "restart_service"]
    check("Z4_ztl_refused_restart_before_config_closure", all(s != "ACCEPTED_TRUE" for s in early), early_restart_verdicts=early)
    final_ledger = header.get("final_ledger", {}).get("completion", {})
    check("Z5_ledger_done", final_ledger.get("admitted") is True and final_ledger.get("verified_effects") == 2, ledger=final_ledger)

    # ---------------------------------------------------------------- model provenance (provider proxy log only)
    plog = jl(run / "provider_log.jsonl")
    ok_calls = [p for p in plog if p.get("status") == "OK" and p.get("provider_response_id")]
    model_mode = header.get("mode") == "MODEL_E2E"
    per_agent = {r: [p for p in ok_calls if p.get("agent") == r] for _, r in ORDER}
    def decided_by_model(e):
        # The LATEST call_tool decision for this verb by the effect's own agent that completed before the effect.
        hits = [p for p in per_agent.get(e["actor"], [])
                if p["t_end"] <= e["applied_at"] and '"call_tool"' in (p.get("response_content") or "") and e["verb"] in (p.get("response_content") or "")]
        return max(hits, key=lambda p: p["t_end"])["provider_response_id"] if hits else None
    links = {e["effect_id"]: decided_by_model(e) for e in applied}
    if model_mode:
        check("M1_two_distinct_model_agents_called_provider", all(per_agent.values()), calls={k: len(v) for k, v in per_agent.items()})
        check("M2_each_effect_preceded_by_its_agents_model_decision", all(links.values()) and bool(links), links=links)
        check("M3_episode_registered_before_first_model_call", bool(ok_calls) and header.get("t_episode_registered", 1e18) < min(p["t_start"] for p in plog),
              attempt_index=header.get("attempt_index"))
        check("M4_attempt_index_is_1", header.get("attempt_index") == 1)
    else:
        checks["M*_model_checks"] = {"ok": False, "status": "NOT_APPLICABLE_INTEGRATION_ONLY"}

    # ---------------------------------------------------------------- recovery (fault episode only)
    crash = jl(run / "CRASH_RECOVERY_TRACE.jsonl")
    if crash:
        killed = [c for c in crash if c["event"] == "SIGKILL_SENT"]
        dead = [c for c in crash if c["event"] == "CONFIG_AGENT_DEAD"]
        check("R1_sigkill_after_native_effect", bool(killed) and any(x["verb"] == "restore_config" for x in killed[0]["native_effects_seen"])
              and bool(dead) and dead[0]["returncode"] == -9, returncode=dead[0]["returncode"] if dead else None)
        restores = [e for e in applied if e["verb"] == "restore_config"]
        check("R2_no_duplicate_effect_after_kill", len(restores) == 1)
        check("R3_obligation_reconciled_from_native_state", any(x["event"] in ("OBLIGATION_CLOSED", "RECONCILE_DONE") and x.get("action") == "restore_config" for x in ev))

    # ---------------------------------------------------------------- frozen fixture scorer on the ORACLE-BUILT witness
    def eff_view(e):
        return {k: e[k] for k in ("actor", "applied", "effect_id", "generation", "system", "target", "verb")}
    receipts = [{"checked_by": "independent_verifier",
                 "cryptographic_verification": checks["C1_cage_chain_verifies"]["ok"] and bool(linked.get(e["effect_id"], {}).get("receipt_records"))
                 and isinstance(veip.get(e["effect_id"]), dict) and veip[e["effect_id"]].get("status") == "ELIGIBLE",
                 "effect_id": e["effect_id"], "effect_sha256": frozen_fixture_oracle.digest_effect(eff_view(e)),
                 "veip_reliance": (veip.get(e["effect_id"]) or {}).get("status"),
                 "ztl_state": "ACCEPTED_TRUE" if checks["Z3_ztl_accepted_true_before_each_claim"]["ok"] else "NOT_VERIFIED"} for e in applied]
    witness = {"mission_id": "LEGION-MINI-DEPENDENT-REPAIR-001", "attempt_index": header.get("attempt_index"),
               "native_readback": final, "native_effects": [eff_view(e) for e in applied], "independently_verified_receipts": receipts,
               "model_call_witnesses": [{"agent": p["agent"], "origin": "provider_log", "request_id": p["provider_response_id"]} for p in ok_calls],
               "agent_done_claim": True, "failure_reconciled": (not crash) or all(checks[k]["ok"] for k in checks if k.startswith("R"))}
    fixture_score = frozen_fixture_oracle.score(witness)

    core = [k for k in checks if k[0] in "NCVZ"]
    gov_ok = all(checks[k]["ok"] for k in core)
    rec_ok = bool(crash) and all(checks[k]["ok"] for k in checks if k.startswith("R"))
    model_ok = model_mode and all(checks[k]["ok"] for k in checks if k.startswith("M"))
    if crash:
        verdict = ("LEGION_MINI_RECOVERY_PASSED" if model_ok and gov_ok and rec_ok else
                   "INTEGRATION_ONLY_RECOVERY_VERIFIED" if not model_mode and gov_ok and rec_ok else "RECOVERY_NOT_VERIFIED")
    else:
        verdict = ("LEGION_MINI_E2E_PASSED" if model_ok and gov_ok and fixture_score["vcc_at_1_candidate"] == 1 else
                   "INTEGRATION_ONLY_GOVERNANCE_VERIFIED" if not model_mode and gov_ok else "NOT_VERIFIED")
    out = {"oracle": "LEGION-MINI-003 live oracle (separate process)", "run_id": header.get("run_id"), "mode": header.get("mode"),
           "verdict": verdict, "failed_checks": [k for k, v in checks.items() if not v["ok"]], "checks": checks,
           "frozen_fixture_scorer_on_oracle_witness": fixture_score, "witness_built_by_oracle": witness,
           "limits": ["TEST posture: OPA double, fakeredis, HMAC routing seals with test secret (seal itself not independently verifiable; its sha256 is bound into each native effect)",
                      "l5d-client-id asserted by agent processes (no Linkerd/mTLS)", "TEST-ONLY VEIP root", "ZTL Python rule (no Lean zverdict)"]}
    (run / "ORACLE_VERDICT.json").write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps({"verdict": verdict, "failed_checks": out["failed_checks"]}))


if __name__ == "__main__":
    main()
