"""WP-F: S100 delegation overlay for the unchanged OTEL-04 world.

The world JSON is never edited. The host loads build_s100_spec(spec) at
runtime: original 12 roles unchanged, plus read-only delegate roles (own
identity, own READ task, no WRITE/REFUSE, no warrants) until 100 roles are
registered. A delegate counts as contributing only when a downstream
decision cites its observation/message id (see contribution_report).
"""
from __future__ import annotations

import copy

DELEGATE_PREFIX = "agent:s100-delegate-"


def build_s100_spec(spec, total=100):
    out = copy.deepcopy(spec)
    roles = out.setdefault("roles", [])
    existing = {r.get("agent_id") for r in roles}
    partitions = [f"p{i}" for i in range(10)]
    n = 0
    while len(roles) < total:
        idx = n
        agent = f"{DELEGATE_PREFIX}{idx:03d}"
        n += 1
        if agent in existing:
            continue
        part = partitions[idx % len(partitions)]
        roles.append({
            "agent_id": agent, "title": f"S100 evidence delegate {n}",
            "brief": "Read-only evidence delegate: read your partition offsets and report them.",
            "tasks": [{
                "task_id": f"D{idx:03d}", "brief": f"Read partition {part} offsets as evidence.",
                "kinds": ["READ"], "read_tools": ["partition.offsets"],
                "write_tool": None, "target": None, "recipients": [],
                "wait_for": None, "answer_schema": {}, "depends_on": [],
                "gate_facts": [], "partition": part,
            }],
        })
    return out


def contribution_report(spec_with_overlay, world_records, decisions):
    """Registered / provider-active / contributing / idle counts.

    decisions: [{agent_id, evidence_refs|body|cites}] - a delegate is
    contributing iff some downstream record/decision cites its
    observation_id or message_id.
    """
    registered = [r.get("agent_id") for r in spec_with_overlay.get("roles") or []]
    obs_owner = {r.get("observation_id"): r.get("agent_id")
                 for r in world_records if r.get("kind") == "OBSERVATION"}
    msg_owner = {r.get("message_id"): r.get("agent_id")
                 for r in world_records if r.get("kind") == "MESSAGE_DELIVERED"}
    active = {r.get("agent_id") for r in world_records if r.get("agent_id")}
    cited_owners = set()
    for d in decisions or []:
        refs = list(d.get("evidence_refs") or []) + list(d.get("cites") or [])
        for ref in refs:
            owner = obs_owner.get(ref) or msg_owner.get(ref)
            if owner:
                cited_owners.add(owner)
        body = str(d.get("body") or "")
        for rid, owner in {**obs_owner, **msg_owner}.items():
            if rid and rid in body:
                cited_owners.add(owner)
    delegates = [a for a in registered if str(a).startswith(DELEGATE_PREFIX)]
    return {"registered": len(registered),
            "provider_active": len(active),
            "contributing": len([a for a in delegates if a in cited_owners]),
            "contributing_agents": sorted(a for a in delegates if a in cited_owners),
            "idle": len([a for a in registered if a not in active]),
            "delegate_registered": len(delegates)}


def decisions_from_run(run_dir):
    """Downstream decisions of a run, from its own logs (no new evidence).

    Sources: agent_*.jsonl DECISION/SCRIPTED_DECISION actions (send body,
    analyze evidence_refs) and provider_log request/response pairs (the
    agent attributed from the proxy token, provider_response_id linking
    the decision to the world/gate action that carried it).
    """
    import json as _json
    import pathlib as _pl
    run = _pl.Path(run_dir)
    decisions = []
    for path in sorted(run.glob("agent_*.jsonl")):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                rec = _json.loads(line)
            except ValueError:
                continue
            if rec.get("event") not in ("DECISION", "SCRIPTED_DECISION"):
                continue
            action = rec.get("action") or {}
            decisions.append({
                "agent_id": rec.get("agent_id"),
                "provider_response_id": rec.get("provider_response_id") or rec.get("decision_ref"),
                "evidence_refs": action.get("evidence_refs") or [],
                "body": action.get("body") or "",
                "cites": [],
                "action": action,
            })
    return decisions


def contribution_report_from_run(run_dir, spec_with_overlay, world_records):
    """Registered/provider-active/contributing/idle for a finished run.

    provider-active = an agent with at least one provider_log record (its
    own NIM call via the proxy); contributing delegates = delegates whose
    observation/message id is cited by a downstream decision.
    """
    import json as _json
    import pathlib as _pl
    run = _pl.Path(run_dir)
    decisions = decisions_from_run(run)
    report = contribution_report(spec_with_overlay, world_records, decisions)
    provider_active = set()
    plog = run / "provider_log.jsonl"
    if plog.exists():
        for line in plog.read_text(encoding="utf-8").splitlines():
            try:
                rec = _json.loads(line)
            except ValueError:
                continue
            if rec.get("agent"):
                provider_active.add(rec["agent"])
    registered = [r.get("agent_id") for r in spec_with_overlay.get("roles") or []]
    delegates = [a for a in registered if str(a).startswith(DELEGATE_PREFIX)]
    report.update({
        "provider_active": len(provider_active),
        "provider_active_agents": sorted(provider_active),
        "delegate_provider_active": len([a for a in delegates if a in provider_active]),
        "idle": len([a for a in registered if a not in provider_active]),
        "decisions_considered": len(decisions),
    })
    return report


def write_contribution_report(run_dir, spec_with_overlay, world_records):
    import json as _json
    import pathlib as _pl
    report = contribution_report_from_run(run_dir, spec_with_overlay, world_records)
    (_pl.Path(run_dir) / "S100_CONTRIBUTION.json").write_text(
        _json.dumps(report, indent=1), encoding="utf-8")
    return report


# ------------------------------------------------------- WO008-04 (S100)
# Registration, delegation requests and even a produced delegate result do
# NOT count as collaboration. One verified collaboration edge requires the
# full chain: delegator action -> recipient (delegate) agent -> confirmed
# delegate observation -> a *different* downstream agent consuming that
# exact reference in an admitted consequential action -> NATIVE_EFFECT +
# RECEIPT + independent READBACK (registry VERIFIED) -> downstream
# obligation CONFIRMED.

def authenticate_delegate_result(registry, ref):
    """(ok, code, entry): ref is a real, confirmed, current-epoch delegate
    observation owned by a delegate agent (never by the consumer).

    Provenance is mandatory and explicit: the observation must carry its
    own decision_ref and explicit attempt_uid / world_instance_id / epoch
    exactly matching the registry. Absent identity is not a match."""
    entry = registry.observations.get(ref or "")
    if entry is None:
        return False, "DELEGATE_REF_UNKNOWN", None
    if not entry.get("_confirmed"):
        return False, "DELEGATE_REF_UNCONFIRMED", entry
    owner = entry.get("agent_id") or ""
    if not str(owner).startswith(DELEGATE_PREFIX):
        return False, "DELEGATE_REF_NOT_A_DELEGATE", entry
    if not entry.get("decision_ref"):
        return False, "DELEGATE_REF_NO_PROVENANCE", entry
    if type(entry.get("epoch")) is not int or entry.get("epoch") != registry.epoch:
        return False, "DELEGATE_REF_STALE_EPOCH", entry
    if not entry.get("attempt_uid") or (
            registry.attempt_uid and entry.get("attempt_uid") != registry.attempt_uid):
        return False, "DELEGATE_REF_ATTEMPT_MISMATCH", entry
    expected_world = (getattr(registry, "expected_world_instance_id", None)
                      or getattr(registry, "world_instance_id", None))
    if not entry.get("world_instance_id") or (
            expected_world and entry.get("world_instance_id") != expected_world):
        return False, "DELEGATE_REF_WORLD_MISMATCH", entry
    return True, "DELEGATE_RESULT_AUTHENTICATED", entry


def verified_delegation_edges(registry, causal_log):
    """Verified downstream-use edges from raw causal-admission records.

    causal_log: CausalHost/sidecar log records (CAUSAL_ADMIT entries whose
    action carries ``delegate_result_ref``). An edge is emitted only when
    the consuming task's WRITE is registry-VERIFIED (effect+receipt+
    readback triplet) and the obligation is CONFIRMED.
    """
    edges = []
    seen = set()
    for rec in causal_log or []:
        if rec.get("event") != "CAUSAL_ADMIT":
            continue
        action = rec.get("action") or {}
        ref = action.get("delegate_result_ref")
        if not ref or ref in seen:
            continue
        ok, _code, entry = authenticate_delegate_result(registry, ref)
        if not ok:
            continue
        downstream = rec.get("agent_id")
        if not downstream or downstream == entry.get("agent_id"):
            continue
        task_id = action.get("task")
        ob = registry.obligations.get(task_id)
        if ob is None or ob.agent_id != downstream:
            continue  # wrong actor: admission is not for the task owner
        decision_ref = rec.get("decision_ref")
        if not decision_ref:
            continue  # no provenance binding from an admitted decision
        if registry.write_status(task_id) != "VERIFIED":
            continue
        if not ob.confirmed and "WRITE" not in ob.satisfied:
            continue
        ev = ob.satisfied.get("WRITE") or {}
        # Binding admitted decision -> actual effect -> receipt -> readback.
        # The registry-satisfied effect must be the very effect produced
        # under this admission: same delegate ref, same decision_ref, and
        # explicit attempt/world/epoch identical across the triplet.
        effect = ev.get("effect") or {}
        receipt = ev.get("receipt") or {}
        readback = ev.get("readback") or {}
        if effect.get("delegate_result_ref") != ref:
            continue  # delegate result was never consumed by the effect
        if effect.get("decision_ref") != decision_ref:
            continue  # admitted decision is not bound to the actual effect
        if not ev.get("effect_id") or effect.get("effect_id") != ev.get("effect_id"):
            continue
        if receipt.get("effect_id") != ev.get("effect_id") or \
                receipt.get("command_id") != effect.get("command_id") or \
                not receipt.get("receipt_id"):
            continue
        if readback.get("confirmed") is not True or \
                readback.get("effect_id") != ev.get("effect_id") or \
                readback.get("command_id") != effect.get("command_id"):
            continue
        for part in (effect, receipt, readback):
            if part.get("attempt_uid") not in (None, entry.get("attempt_uid")) and \
                    part.get("attempt_uid") != entry.get("attempt_uid"):
                break
            if part.get("world_instance_id") not in (None, entry.get("world_instance_id")) and \
                    part.get("world_instance_id") != entry.get("world_instance_id"):
                break
        else:
            seen.add(ref)
            edges.append({
                "delegate_agent": entry.get("agent_id"),
                "delegate_task": entry.get("task_id"),
                "delegate_result_ref": ref,
                "downstream_agent": downstream,
                "downstream_task": task_id,
                "decision_ref": decision_ref,
                "effect_id": ev.get("effect_id"),
                "command_id": ev.get("command_id"),
                "receipt_id": ev.get("receipt_id"),
                "readback_confirmed": bool((ev.get("readback") or {}).get("confirmed")),
                "attempt_uid": entry.get("attempt_uid"),
                "world_instance_id": entry.get("world_instance_id"),
                "epoch": entry.get("epoch", registry.epoch),
                "obligation_confirmed": bool(ob.confirmed),
                "verified": True,
            })
            continue
        continue
    return edges


def verified_collaboration_count(registry, causal_log):
    """Number of delegate agents with >=1 verified downstream-use edge."""
    return len({e["delegate_agent"] for e in verified_delegation_edges(registry, causal_log)})


