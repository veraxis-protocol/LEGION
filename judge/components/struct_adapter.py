"""LEGION structural evidence adapter (Claude; WO-006). READ-ONLY, separate OS process.

Maps one raw run directory (world server log, gate commit log, controller log, CAGE evidence chain, VEIP reliance, provider
proxy log, readback log, worker registry) into a LEGION100_JUDGE_001 bundle (contract/registration/evidence/manifest).
It never writes the run directory and never decides the verdict: the stand-alone Judge does that in another process.

Trust rules (see TRUST_MATRIX below):
- every judge event carries `src` = {file, line, line_sha256}; booleans such as seal_valid/warrant_valid/credential_valid
  are COMPUTED here by re-verification (TEST posture), never copied from a producer's claim;
- MODEL_DECISION comes only from the provider proxy log (the agent cannot write it), parsed independently by this adapter;
- identities come from WORKERS.jsonl workload identities + proxy/world token maps, never from request bodies;
- any parse error, missing source, broken seq or clock gap -> trace_complete=false / missing readback_origin
  (the Judge turns that into INDETERMINATE), never a silent PASS.
usage: python -I struct_adapter.py --run DIR --world WORLD.json --contract C.json --registration R.json --out BUNDLE
                                   --judge JUDGE_DIR --cage CAGE_DIR --profile PROFILE.json
"""
from __future__ import annotations
import argparse, hashlib, json, re, sys
from pathlib import Path

TRUST_MATRIX = {
    "MODEL_DECISION": "provider_log.jsonl (separate proxy process; agent identity from per-agent proxy token); content parsed by adapter",
    "GOVERNANCE": "GATE_COMMITS.jsonl + CAGE_EVIDENCE_CHAIN.jsonl hash chain + routing seal re-verified (HMAC TEST posture) + ZTL verdict join + VEIP warrant re-verified with TEST root",
    "COMMIT": "GATE_COMMITS.jsonl (gateway process); admitted iff a routing seal was issued (command_id present)",
    "NATIVE_EFFECT": "WORLD_LOG.jsonl NATIVE_EFFECT (world server process; actuator-token only); cross-checked against NATIVE_STATE_AFTER.effects",
    "RECEIPT": "WORLD_LOG.jsonl RECEIPT (world server ledger)",
    "READBACK_EFFECT": "READBACK.jsonl (separate reader process, reader token) re-checked against final ledger",
    "OBSERVATION/ANALYSIS_RECORD/MESSAGE_DELIVERED/RECONCILE": "WORLD_LOG.jsonl (world server; identity from world token map; agents cannot write the log)",
    "WAIT_OBSERVED": "WORLD_LOG.jsonl (server-side blocking wait timed by the world's monotonic clock)",
    "ENV_EVENT": "WORLD_LOG.jsonl (world's own event scheduler)",
    "DENIAL": "GATE_COMMITS.jsonl declare_refusal REFUSED_BY_AGENT (gateway; admitted identity must be the assigned agent)",
    "final_native_state": "NATIVE_STATE_AFTER.json written by the separate reader process after agents ended",
}
TEST_POSTURE = ["SINGLE_HOST_CLOCK_MONOTONIC", "HMAC_ROUTING_SEAL_DEFAULT_TEST_SALT", "VEIP_TEST_ONLY_ROOT", "ZTL_PYTHON_RULE_NOT_LEAN",
                "WORKLOAD_IDENTITY_ASSERTED_BY_LOCAL_PROCESS_NO_MESH", "SYNTHETIC_WORLD_NOT_LIVE_GAIA2_OR_OTEL"]


class Src:
    def __init__(self, run: Path):
        self.run, self.errors, self.files = run, [], {}

    def jl(self, name, required=True):
        p = self.run / name
        if not p.exists():
            if required:
                self.errors.append({"file": name, "error": "MISSING"})
            return []
        raw = p.read_bytes()
        self.files[name] = hashlib.sha256(raw).hexdigest()
        out = []
        for i, line in enumerate(raw.split(b"\n"), 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                if not isinstance(rec, dict):
                    raise ValueError("not an object")
            except ValueError as exc:
                self.errors.append({"file": name, "line": i, "error": f"UNPARSEABLE: {exc}"})
                continue
            rec["__src"] = {"file": name, "line": i, "line_sha256": hashlib.sha256(line).hexdigest()}
            out.append(rec)
        return out

    def js(self, name, required=True):
        p = self.run / name
        if not p.exists():
            if required:
                self.errors.append({"file": name, "error": "MISSING"})
            return None
        raw = p.read_bytes()
        self.files[name] = hashlib.sha256(raw).hexdigest()
        try:
            return json.loads(raw)
        except ValueError as exc:
            self.errors.append({"file": name, "error": f"UNPARSEABLE: {exc}"})
            return None


def parse_action(content):
    """Adapter's own strict parse of a model response: exactly one JSON object (optional ``` fence), with 'action'."""
    s = (content or "").strip()
    m = re.fullmatch(r"```(?:json)?\s*(\{.*\})\s*```", s, re.S)
    if m:
        s = m.group(1)
    try:
        d = json.loads(s)
    except ValueError:
        return None
    return d if isinstance(d, dict) and isinstance(d.get("action"), str) else None


def judge_tool_args(action):
    """Canonical (tool, args) for the Judge, identical for model decision, gate commit and native effect."""
    if action.get("action") == "write":
        return action.get("tool"), {"target": action.get("target"), "args": action.get("args") if isinstance(action.get("args"), dict) else {}}
    return "agent." + str(action.get("action")), {k: v for k, v in action.items() if k != "action"}


def main():
    ap = argparse.ArgumentParser()
    for a in ("run", "world", "contract", "registration", "out", "judge", "cage", "profile"):
        ap.add_argument("--" + a, required=a not in ("cage", "profile"))
    ap.add_argument("--mode", default="MODEL_E2E", choices=["MODEL_E2E", "INTEGRATION_ONLY"])
    a = ap.parse_args()
    sys.path.insert(0, a.judge)
    from legion_judge.core import decision_digest, write_bundle, sha as jsha  # frozen Judge 001 helpers (no evaluation here)
    run, S = Path(a.run), Src(Path(a.run))
    world = json.loads(Path(a.world).read_text())
    contract = json.loads(Path(a.contract).read_text())
    registration = json.loads(Path(a.registration).read_text())
    profile = json.loads(Path(a.profile).read_text()) if a.profile else {}
    report = {"adapter": "legion.struct.adapter.v1.1-s2", "run": str(run), "mode": a.mode, "trust_matrix": TRUST_MATRIX, "test_posture": TEST_POSTURE,
              "checks": {}, "unsupported": [], "notes": []}
    chk = report["checks"]

    world_file_sha = hashlib.sha256(Path(a.world).read_bytes()).hexdigest()
    chk["world_file_matches_contract"] = world_file_sha == contract.get("world_file_sha256")

    header = S.js("RUN_HEADER.json") or {}
    workers = S.jl("WORKERS.jsonl")
    wlog = S.jl("WORLD_LOG.jsonl")
    gate = S.jl("GATE_COMMITS.jsonl")
    ctl = S.jl("CONTROLLER_EVENTS.jsonl")
    rb = S.jl("READBACK.jsonl")
    plog = S.jl("provider_log.jsonl", required=(a.mode == "MODEL_E2E"))
    chain = S.jl("CAGE_EVIDENCE_CHAIN.jsonl", required=bool(gate))
    after = S.js("NATIVE_STATE_AFTER.json") or {}
    agent_logs = {}
    for p in sorted(run.glob("agent_*.jsonl")):
        agent_logs[p.name] = S.jl(p.name)

    # --- identities: role agent ids are public (world); workload identity from the worker registry
    role_agents = {r["agent_id"] for r in world["roles"]}
    wid_to_agent = {}
    for w in workers:
        if w.get("workload_identity"):
            wid_to_agent.setdefault(w["workload_identity"], set()).add(w.get("agent_id"))
    chk["worker_identities_unique"] = all(len(v) == 1 for v in wid_to_agent.values())
    chk["worker_pids_distinct"] = len({w.get("pid") for w in workers}) == len(workers) and bool(workers)
    chk["active_roles_registered"] = role_agents <= {w.get("agent_id") for w in workers}
    task_owner = {t["task_id"]: r["agent_id"] for r in world["roles"] for t in r["tasks"]}

    # --- clock: single host CLOCK_MONOTONIC; t0 = world start
    starts = [r for r in wlog if r.get("kind") == "WORLD_START"]
    # s2 (WO-007, Claude): anchor = the world engine's own start reference (WORLD_START.t_mono - WORLD_START.t_rel).
    # v1 used the WORLD_START record's write time, which lags the engine reference by tens of ms and shifted every event
    # earlier (e.g. an event fired at t_rel 30.005 appeared at 29.965 < not_before 30 -> false FAIL).
    t0 = None
    if len(starts) == 1 and isinstance(starts[0].get("t_mono"), (int, float)):
        tr = starts[0].get("t_rel")
        t0 = starts[0]["t_mono"] - (tr if isinstance(tr, (int, float)) and 0 <= tr < 5 else 0.0)
    chk["world_start_unique"] = t0 is not None
    seqs = [r.get("seq") for r in wlog]
    chk["world_log_seq_contiguous"] = seqs == list(range(seqs[0], seqs[0] + len(seqs))) if seqs else False
    clock_ok = t0 is not None

    def rel(x):
        nonlocal clock_ok
        if not isinstance(x, (int, float)) or isinstance(x, bool) or t0 is None:
            clock_ok = False
            return -1.0
        return round(x - t0, 6)

    events, eid = [], [0]

    def add(kind, origin, rec, t, **kw):
        eid[0] += 1
        e = {"id": kw.pop("id", None) or f"ev-{eid[0]:05d}", "kind": kind, "origin": origin, "t": t, "src": rec.get("__src")}
        e.update(kw)
        events.append(e)
        return e

    # --- MODEL_DECISION (provider proxy) or scripted decisions (INTEGRATION_ONLY, distinct origin)
    model_by_ref = {}
    if a.mode == "MODEL_E2E":
        for r in plog:
            if not (r.get("status") == "OK" and r.get("http_status") == 200 and r.get("provider_response_id")):
                continue
            act = parse_action(r.get("response_content"))
            tool, args = judge_tool_args(act) if act else ("agent.unparsed", {})
            e = add("MODEL_DECISION", "provider_proxy", r, rel(r.get("t_end_mono")), agent_id=r.get("agent"), tool=tool, args=args,
                    decision_digest=decision_digest(tool, args), provider_response_id=r["provider_response_id"], model=r.get("provider_model") or r.get("model"))
            model_by_ref[r["provider_response_id"]] = e
    else:
        for name, recs in agent_logs.items():
            for r in recs:
                if r.get("event") == "SCRIPTED_DECISION" and isinstance(r.get("action"), dict):
                    ref = f"{r.get('agent_id')}|{r.get('decision_ref')}"
                    tool, args = judge_tool_args(r["action"])
                    model_by_ref[ref] = add("MODEL_DECISION", "scripted_decider", r, rel(r.get("mono")), agent_id=r.get("agent_id"), tool=tool, args=args,
                                            decision_digest=decision_digest(tool, args), provider_response_id="scripted:" + ref)

    # --- CAGE chain re-verification (TEST posture) + VEIP re-verification
    gov_verify = cage_verifier(a.cage, chain, run, profile, report) if gate else None

    # --- gate records -> GOVERNANCE + COMMIT / blocked COMMIT / DENIAL
    ztl_ok = {}
    for x in ctl:
        if x.get("event") == "ZTL_VERDICT" and x.get("state") == "ACCEPTED_TRUE":
            ztl_ok.setdefault((x.get("task_id"), x.get("digest")), []).append(x.get("mono"))
    claims = {x.get("command_id"): x for x in ctl if x.get("event") == "CLAIMED"}
    gate_by_cmd = {}
    for g in gate:
        ident = g.get("admitted_identity")
        agents = wid_to_agent.get(ident, set())
        agent = next(iter(agents)) if len(agents) == 1 else None
        ca = g.get("caller_args") or {}
        task = ca.get("task_id") or g.get("task_id")
        ref = g.get("decision_ref") or ca.get("decision_ref")
        pref = ref if a.mode == "MODEL_E2E" else f"{agent}|{ref}"
        ts = rel(g.get("t_start_mono"))
        if g.get("mcp_tool") == "declare_refusal":
            if g.get("outcome") == "REFUSED_BY_AGENT":
                add("DENIAL", "gate_audit", g, rel(g.get("t_end_mono")), agent_id=agent, obligation_id=task, command_id="refusal:" + str(g.get("request_id")),
                    provider_response_id=("" if a.mode == "MODEL_E2E" else "scripted:") + str(pref))
            continue
        jt, ja = ca.get("tool"), {"target": ca.get("target"), "args": ca.get("args") if isinstance(ca.get("args"), dict) else {}}
        digest = decision_digest(jt, ja)
        if g.get("judge_args_digest") not in (None, digest):
            report["notes"].append({"gate_digest_mismatch": g["__src"]})
        cmd = g.get("command_id")
        if not cmd:
            add("COMMIT", "gateway_audit", g, ts, agent_id=agent, tool=jt, target=ja["target"], obligation_id=task, args_digest=digest,
                command_id="blocked:" + str(g.get("request_id")), admitted=False, outcome=g.get("outcome"))
            continue
        gv = gov_verify(g, task) if gov_verify else {}
        bp = g.get("bound_params") or {}
        ztl_t = [m for m in ztl_ok.get((task, bp.get("ztl_evidence_digest")), []) if isinstance(m, (int, float)) and m <= g.get("t_start_mono", -1) + 30]
        cl = claims.get(cmd) or {}
        add("GOVERNANCE", "gate_audit", g, ts, agent_id=agent, tool=jt, target=ja["target"], obligation_id=task, args_digest=digest, command_id=cmd,
            cage="ALLOW" if gv.get("decision_record_exact") else "UNVERIFIED",
            ztl="T" if bp.get("ztl_state") == "ACCEPTED_TRUE" and ztl_t else "UNVERIFIED",
            veip="ELIGIBLE" if gv.get("veip_eligible") else "UNVERIFIED",
            warrant_valid=bool(gv.get("warrant_valid")), seal_valid=bool(gv.get("seal_valid")),
            credential_valid=agent is not None and agent == task_owner.get(task) and bp.get("sre_actor") == agent,
            epoch_valid=cl.get("task_id") == task and cl.get("agent_id") == agent, verification=gv)
        add("COMMIT", "gateway_audit", g, ts, agent_id=agent, tool=jt, target=ja["target"], obligation_id=task, args_digest=digest,
            command_id=cmd, admitted=True, outcome=g.get("outcome"))
        gate_by_cmd.setdefault(cmd, []).append((g, agent, pref))

    # --- world log: effects, receipts, observations, messages, waits, analyses, reconciles, env events, done claims
    ledger = {e.get("command_id"): e for e in after.get("effects", [])} if isinstance(after.get("effects"), list) else {}
    eff_ids = set()
    for r in wlog:
        k, t = r.get("kind"), rel(r.get("t_mono"))
        if k == "NATIVE_EFFECT":
            g = gate_by_cmd.get(r.get("command_id"), [])
            pref = g[0][2] if len(g) == 1 else None
            eff_ids.add(r.get("effect_id"))
            add("NATIVE_EFFECT", "native_target", r, t, agent_id=r.get("agent_id"), tool=r.get("tool"), target=r.get("target"), obligation_id=r.get("task_id"),
                args={"target": r.get("target"), "args": r.get("args") if isinstance(r.get("args"), dict) else {}},
                command_id=r.get("command_id"), effect_id=r.get("effect_id"),
                provider_response_id=(pref if a.mode == "MODEL_E2E" else ("scripted:" + pref if pref else None)))
        elif k == "RECEIPT":
            add("RECEIPT", "native_target", r, t, command_id=r.get("command_id"), effect_id=r.get("effect_id"))
        elif k == "OBSERVATION":
            add("OBSERVATION", "independent_reader", r, t, id=r.get("observation_id"), agent_id=r.get("agent_id"), obligation_id=r.get("task_id"),
                facts=r.get("facts") if isinstance(r.get("facts"), dict) else {})
        elif k == "ANALYSIS_RECORD":
            add("ANALYSIS_RECORD", "independent_reader", r, t, id=r.get("record_id"), agent_id=r.get("agent_id"), obligation_id=r.get("task_id"),
                facts=r.get("facts") if isinstance(r.get("facts"), dict) else {}, evidence_refs=r.get("evidence_refs") or [])
        elif k == "MESSAGE_DELIVERED":
            add("MESSAGE_DELIVERED", "message_bus", r, t, id=r.get("message_id"), agent_id=r.get("agent_id"), recipient=r.get("recipient"), obligation_id=r.get("task_id"))
        elif k == "WAIT_OBSERVED":
            add("WAIT_OBSERVED", "independent_clock", r, t, agent_id=r.get("agent_id"), obligation_id=r.get("task_id"), event_id=r.get("event_id"))
        elif k == "RECONCILE":
            add("RECONCILE", "independent_reader", r, t, agent_id=r.get("agent_id"), obligation_id=r.get("task_id"), command_id=r.get("command_id"), found=r.get("found"))
        elif k == "ENV_EVENT":
            add("ENV_EVENT", "native_target", r, t, id=r.get("event_id"))
        elif k == "AGENT_DONE":
            add("OBSERVATION", "independent_reader", r, t, agent_id=r.get("agent_id"), obligation_id=None, facts={"agent_done_claim": r.get("task_id")},
                agent_claimed_done=True, claimed_obligation_id=r.get("task_id"))
    for r in rb:
        if r.get("kind") != "READBACK_EFFECT":
            continue
        led = ledger.get(r.get("command_id"))
        add("READBACK_EFFECT", "independent_reader", r, rel(r.get("t_mono")), command_id=r.get("command_id"), effect_id=r.get("effect_id"),
            confirmed=bool(r.get("confirmed")) and bool(led) and led.get("effect_id") == r.get("effect_id"))

    events.sort(key=lambda e: (e["t"], e["id"]))
    # --- consistency between independent sources
    chk["effects_world_log_equals_final_ledger"] = eff_ids == {e.get("effect_id") for e in ledger.values()}
    # final independent read must follow the last native effect and every worker's own EXIT record
    exit_monos = [r.get("mono") for recs in agent_logs.values() for r in recs if r.get("event") in ("EXIT", "STANDBY_EXIT")]
    eff_monos = [r.get("t_mono") for r in wlog if r.get("kind") == "NATIVE_EFFECT"]
    rm = after.get("read_mono")
    chk["final_readback_after_agents"] = isinstance(rm, (int, float)) and bool(exit_monos) and all(isinstance(x, (int, float)) and rm >= x for x in exit_monos + eff_monos)
    exits = {}
    for name, recs in agent_logs.items():
        ev = [r.get("event") for r in recs]
        exits[name] = any(x in ("EXIT", "STANDBY_EXIT") for x in ev)
    chk["every_worker_log_terminated"] = bool(exits) and all(exits.values()) and len(exits) == len(workers)
    chk["clock_monotonic_single_host"] = clock_ok
    chk["no_source_errors"] = not S.errors
    trace_complete = all(chk[k] for k in ("world_start_unique", "world_log_seq_contiguous", "effects_world_log_equals_final_ledger",
                                          "every_worker_log_terminated", "no_source_errors", "worker_pids_distinct", "active_roles_registered",
                                          "world_file_matches_contract"))
    evidence = {"mission_id": contract["mission_id"], "scenario_id": contract["scenario_id"], "events": [{k: v for k, v in e.items()} for e in events],
                "final_native_state": after.get("state") if isinstance(after.get("state"), dict) else {}, "trace_complete": trace_complete,
                "adapter_build": "legion.struct.adapter.v1.1-s2", "source_file_sha256": S.files, "source_errors": S.errors}
    if chk["final_readback_after_agents"] and chk["effects_world_log_equals_final_ledger"]:
        evidence["readback_origin"] = "independent_reader"
    if clock_ok:
        evidence["clock_kind"] = "monotonic_single_host"
    write_bundle(Path(a.out), contract, registration, evidence)

    # --- participation diagnostics (reported, not judged here)
    prov_agents = {e["agent_id"] for e in events if e["kind"] == "MODEL_DECISION" and e["origin"] == "provider_proxy"}
    contrib = {e.get("agent_id") for e in events if e["kind"] in ("NATIVE_EFFECT", "OBSERVATION", "ANALYSIS_RECORD", "MESSAGE_DELIVERED",
                                                                    "WAIT_OBSERVED", "RECONCILE", "DENIAL") and e.get("obligation_id")}
    report["participation"] = {"registered_workers": len(workers), "active_roles": len(role_agents), "provider_active_agents": len(prov_agents),
                               "causally_contributing_agents": len(contrib - {None}), "idle_workers": len(workers) - len(prov_agents | contrib),
                               "standby_workers": sum(1 for w in workers if w.get("kind") == "standby")}
    report["counts"] = {k: sum(1 for e in events if e["kind"] == k) for k in sorted({e["kind"] for e in events})}
    report["source_errors"], report["source_file_sha256"] = S.errors, S.files
    report["trace_complete"] = trace_complete
    report["bundle_contract_sha256"] = jsha(contract)
    (Path(a.out) / "ADAPTER_REPORT.json").write_text(json.dumps(report, indent=1, default=str))
    print(json.dumps({"events": len(events), "trace_complete": trace_complete, "errors": len(S.errors), "participation": report["participation"]}))


def cage_verifier(cage_dir, chain, run, profile, report):
    """Returns f(gate_record, task) -> verification dict. Re-verifies, in TEST posture, the CAGE hash chain, the
    GOVERNANCE_DECISION record bound by the routing seal, the seal HMAC, the ACTUATION_RECEIPT and the VEIP warrant."""
    if not cage_dir or not profile:
        report["unsupported"].append("CAGE/VEIP re-verification skipped (no --cage/--profile): governance booleans false")
        return lambda g, task: {}
    sys.path.insert(0, cage_dir)
    from datetime import datetime
    from src.gateway.governance.evidence.stream import verify_record
    from src.gateway.governance import routing_seal
    from src.gateway.governance.warrant import Warrant
    from src.gateway.governance.warrant.authority import VerifiedAuthorityAuthorization
    from src.gateway.governance.warrant.trust_anchor import VerifiedKeyManifest, WarrantTrustAnchor
    from src.gateway.governance.warrant.verifier import WarrantStandingVerifier
    prev, prev_of, ok_chain = "", {}, True   # an empty chain is valid only if no sealed commit refers to it (checked per commit)
    for f in chain:
        try:
            ok_chain &= bool(verify_record({k: v for k, v in f.items() if k != "__src"}, prev_hash=prev).valid)
        except Exception:
            ok_chain = False
        prev_of[f.get("record_hash")] = prev
        prev = f.get("record_hash")
    report["checks"]["cage_chain_verifies"] = ok_chain
    by_hash = {f.get("record_hash"): f for f in chain}
    payload = {}
    for f in chain:
        try:
            payload[f.get("record_hash")] = json.loads(f.get("payload_json") or "{}")
        except ValueError:
            payload[f.get("record_hash")] = {}
    ref = datetime.fromisoformat(profile["ref_time"])
    try:
        fx = json.loads((run / "TEST_ONLY_FIXTURES.json").read_text())
        anchor = WarrantTrustAnchor(root_kid=fx["root_kid"], public_key_b64=fx["root_public_key_spki_b64"], expected_fingerprint=fx["root_fingerprint"])
        km = VerifiedKeyManifest.verify(fx["key_manifest"], anchor, now=ref)
        az = VerifiedAuthorityAuthorization.verify(fx["authority_authorization"], anchor)
        warrants = {w["norm_id"]: Warrant(**w) for w in fx["warrants"]}
        report["checks"]["veip_test_root_fixtures_verify"] = True
    except Exception as exc:
        km = az = None
        warrants = {}
        report["checks"]["veip_test_root_fixtures_verify"] = False
        report["notes"].append({"veip_fixture_error": f"{type(exc).__name__}: {exc}"})

    def verify(g, task):
        act = profile["action_template"].format(task=task, task_us=task.replace("-", "_"))
        norm = profile["norm_template"].format(task=task, task_us=task.replace("-", "_"))
        seal = g.get("seal") or ""
        bp = {k: v for k, v in (g.get("bound_params") or {}).items()}
        parts = seal.split(".")
        dh = parts[2] if len(parts) == 4 else None
        dec, dp = by_hash.get(dh), payload.get(dh, {})
        out = {"seal_kind": "HMAC_SHARED_DEFAULT_TEST_SALT (TEST posture)", "chain_ok": ok_chain}
        try:
            ph = routing_seal.compute_action_hash(act, bp)
        except Exception as exc:
            ph = f"ERR:{exc}"
        out["decision_record_exact"] = ok_chain and bool(dec) and dec.get("event_type") == "GOVERNANCE_DECISION" and dp.get("action") == act and dp.get("params_hash") == ph
        # Seal validity is audited AT USE TIME: routing_seal's HMAC path compares expiry with time.time(); we pin that
        # clock to the commit's own wall start time (recorded by the gateway) so a later replay does not report a
        # seal as "expired" merely because the audit runs after its TTL. Expiry >= use time is still required.
        use_wall = g.get("t_start")
        if not isinstance(use_wall, (int, float)) and dec:
            try:   # use time = the hash-chained GOVERNANCE_DECISION record's own timestamp (seal issued at decision)
                use_wall = datetime.fromisoformat(dec["timestamp_utc"]).timestamp()
                out["seal_use_time_source"] = "GOVERNANCE_DECISION.timestamp_utc"
            except Exception:
                use_wall = None
        out["seal_checked_at_wall"] = use_wall
        real_time = routing_seal.time

        class _AtUse:
            def time(self):
                return float(use_wall)

            def __getattr__(self, name):
                return getattr(real_time, name)
        try:
            if not isinstance(use_wall, (int, float)):
                raise ValueError("commit wall time missing")
            routing_seal.time = _AtUse()
            out["seal_valid"] = bool(dec) and bool(routing_seal.verify_seal_against_evidence(seal, act, bp, dec, prev_hash=prev_of.get(dh, "")))
        except Exception as exc:
            out["seal_valid"], out["seal_error"] = False, f"{type(exc).__name__}: {exc}"
        finally:
            routing_seal.time = real_time
        out["seal_sha256_matches"] = bool(seal) and hashlib.sha256(seal.encode()).hexdigest() == g.get("seal_sha256")
        rel = [r.get("reliance_status") for r in dp.get("reliance") or [] if r.get("norm_id") == norm]
        try:
            res = WarrantStandingVerifier.verify_standing(
                warrants.get(norm), context={"action": act, "jurisdiction": profile["jurisdiction"], "governing_version": profile["governing_version"],
                                             "norm_value": 1.0, "actor": bp.get("sre_actor"), "system": bp.get("sre_system")},
                now=ref, key_manifest=km, authority_authorization=az, require_authority_authorization=True, expected_environment="SANDBOX")
            ind = res.reliance_status.value
        except Exception as exc:
            ind = f"ERR:{type(exc).__name__}"
        out["veip_gateway"], out["veip_independent"] = rel, ind
        out["veip_eligible"] = rel == ["ELIGIBLE"] and ind == "ELIGIBLE"
        out["warrant_valid"] = ind == "ELIGIBLE"
        acts = [h for h, p in payload.items() if by_hash.get(h, {}).get("event_type") == "ACTUATION_RECEIPT" and p.get("governance_decision_digest") == seal]
        out["actuation_receipt_records"] = len(acts)
        return out
    return verify


if __name__ == "__main__":
    main()
