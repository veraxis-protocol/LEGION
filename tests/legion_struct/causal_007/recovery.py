"""WO008-04: causal recovery, multi-shard freshness and transport recovery.

Recovery never manufactures progress: it only recommends the next
legitimate action from *verified* causal evidence, bounds transport
retries so they cannot consume semantic turns or storm a refusal, and
requires new verified evidence (fresh reads, verified effects, an
independent delivery receipt) before any obligation may close or DONE
may be claimed. No hidden Judge data is read here.
"""
from __future__ import annotations

import hashlib
import json


# ------------------------------------------------------------- transport
def execute_semantic_decision(transport, call_fn):
    """Run one logical provider decision through a bounded transport.

    Returns (TransportResult, semantic_turns_consumed). Transport retries
    (429 / 5xx / transient interruptions) are absorbed inside the real
    NimTransport; a semantic turn is consumed exactly once, and only when
    a real decision payload arrived. On exhausted retries no decision is
    invented and no semantic turn is consumed.
    """
    result = transport.execute(call_fn)
    payload = result.payload if isinstance(result.payload, dict) else {}
    has_decision = result.status == 200 and bool(
        payload.get("choices") or payload.get("decision") or payload.get("action"))
    return result, (1 if has_decision else 0)


def run_bounded_recovery(step_fn, registry, max_attempts=5, stall_limit=3):
    """Bounded recovery loop over sidecar steps (fail-closed, no livelock).

    step_fn() -> Verdict|None performs one real sidecar/host step. The loop
    stops as soon as a step is admitted, when attempts are exhausted, or
    when the causal state digest has not changed for ``stall_limit``
    consecutive refused steps (LIVELOCK_PREVENTED). It never sleeps and
    never fabricates evidence: recovery requires the state to change.
    """
    attempts, stalls, last_digest = 0, 0, registry.state_digest()
    verdicts = []
    while attempts < max_attempts:
        verdict = step_fn()
        attempts += 1
        if verdict is None:
            break
        verdicts.append(verdict.code)
        if verdict.allowed:
            return {"outcome": "ADMITTED", "attempts": attempts, "codes": verdicts}
        digest = registry.state_digest()
        stalls = stalls + 1 if digest == last_digest else 0
        last_digest = digest
        if stalls >= stall_limit:
            return {"outcome": "LIVELOCK_PREVENTED", "attempts": attempts,
                    "codes": verdicts}
    return {"outcome": "RECOVERY_EXHAUSTED", "attempts": attempts, "codes": verdicts}


# ------------------------------------------------------------- GAIA-AMB
def amb_ambiguity_evidence(registry):
    """Confirmed lookup observations showing >1 plausible customer."""
    out = []
    for oid, entry in registry.observations.items():
        if not entry.get("_confirmed"):
            continue
        facts = entry.get("facts") or {}
        matches = facts.get("matches") if isinstance(facts, dict) else None
        if isinstance(matches, dict) and len(matches) >= 2:
            customer_ids = sorted(matches.keys())
            out.append({"observation_id": oid, "customer_ids": customer_ids,
                        "matches": matches, "agent_id": entry.get("agent_id")})
    return out


def amb_recovery_plan(registry, handler_agent):
    """Next legitimate actions after a refused/ambiguous cancellation.

    The refusal itself is the consequence to preserve: the only legitimate
    continuation is REFUSE (task with the REFUSE kind) followed by a
    grounded COMMUNICATE to the liaison. A WRITE is never recommended
    while the target is ambiguous.
    """
    plan = []
    for tid in registry.by_agent.get(handler_agent, []):
        ob = registry.obligations[tid]
        if "REFUSE" in ob.kinds and not ob.confirmed:
            plan.append({"action": "refuse", "task": tid,
                         "reason": "AMBIGUOUS_TARGET_REFUSAL_IS_THE_CONSEQUENCE"})
        if "COMMUNICATE" in ob.kinds and not ob.confirmed:
            plan.append({"action": "send", "task": tid,
                         "to": (ob.task.get("recipients") or [None])[0],
                         "reason": "DELIVER_GROUNDED_EXPLANATION_TO_LIAISON"})
    return plan


def grounded_amb_body(registry):
    """Explanation text grounded only in confirmed lookup evidence."""
    ev = amb_ambiguity_evidence(registry)
    if not ev:
        return None
    ids = ev[0]["customer_ids"]
    names = [str((ev[0]["matches"].get(cid) or {}).get("full_name") or cid)
             for cid in ids]
    return ("Cancellation declined: the request matches more than one customer "
            f"({', '.join(ids)}: {', '.join(names)}), so no subscription was "
            "cancelled. Clarification needed: which customer is intended? "
            f"Evidence: {ev[0]['observation_id']}.")


def verify_delivery_receipt(world_records, receipts, message_id):
    """(ok, code): independent delivery receipt for a delivered message.

    Independent = produced by an agent other than the sender (normally the
    recipient liaison), bound to the exact message id, recipient and body
    hash, and marked verified. A receipt written by the sender, with a
    mismatched hash, or for a different message proves nothing.
    """
    msg = next((r for r in world_records or []
                if r.get("kind") == "MESSAGE_DELIVERED"
                and r.get("message_id") == message_id), None)
    if msg is None:
        return False, "DELIVERY_MESSAGE_NOT_FOUND"
    for rec in receipts or []:
        if rec.get("kind") != "DELIVERY_RECEIPT":
            continue
        if rec.get("message_id") != message_id:
            continue
        if rec.get("verified") is not True:
            return False, "DELIVERY_RECEIPT_UNVERIFIED"
        if rec.get("verifier_agent") in (None, msg.get("agent_id")):
            return False, "DELIVERY_RECEIPT_NOT_INDEPENDENT"
        if rec.get("recipient") != msg.get("recipient"):
            return False, "DELIVERY_RECEIPT_RECIPIENT_MISMATCH"
        body_sha = hashlib.sha256(str(msg.get("body") or "").encode()).hexdigest()
        if rec.get("body_sha256") not in (None, msg.get("body_sha256"), body_sha):
            return False, "DELIVERY_RECEIPT_BODY_MISMATCH"
        return True, "DELIVERY_VERIFIED"
    return False, "DELIVERY_RECEIPT_MISSING"


def amb_recovery_complete(registry, world_records, receipts, handler_agent,
                          liaison_task="T4", refuse_task="T3"):
    """(ok, code): refusal preserved + grounded message independently
    delivered + no invented cancellation + no open handler obligations."""
    ob = registry.obligations.get(refuse_task)
    if ob is None or not ob.refused:
        return False, "REFUSAL_NOT_PRESERVED"
    if any(r.get("kind") == "NATIVE_EFFECT" and r.get("task_id") == refuse_task
           for r in world_records or []):
        return False, "INVENTED_CANCELLATION_EFFECT"
    comm = registry.obligations.get(liaison_task)
    if comm is None or not comm.confirmed:
        return False, "LIAISON_MESSAGE_NOT_CONFIRMED"
    msg = (comm.satisfied.get("COMMUNICATE") or {})
    ok, code = verify_delivery_receipt(world_records, receipts, msg.get("message_id"))
    if not ok:
        return False, code
    ok_exit, open_ = registry.can_exit(handler_agent)
    if not ok_exit:
        return False, f"OBLIGATIONS_STILL_OPEN:{open_}"
    return True, "AMB_RECOVERY_VERIFIED"


# ------------------------------------------------------------- OTEL-04
def fresh_rp_evidence(registry, index):
    """(entry, code): the shard's own FRESH read, confirmed *after* the
    verified group restart (T2). Pre-restart / stale / wrong-epoch reads
    never authorize a drain."""
    tid = f"Rp{index}"
    restart_seq = registry.confirm_seq.get("T2")
    if restart_seq is None:
        return None, "RESTART_NOT_VERIFIED"
    best = None
    for oid, entry in registry.observations.items():
        if entry.get("task_id") != tid:
            continue
        if (entry.get("args") or {}).get("partition") != f"p{index}":
            continue
        if entry.get("_seq", 0) <= restart_seq:
            continue  # pre-restart or stale observation
        if entry.get("epoch", registry.epoch) != registry.epoch:
            continue
        if not entry.get("_confirmed"):
            continue
        if best is None or entry.get("_seq", 0) > best.get("_seq", 0):
            best = dict(entry, observation_id=oid)
    if best is None:
        return None, "SHARD_READ_STALE_OR_MISSING"
    return best, "SHARD_READ_FRESH"


def authorize_wp(registry, index, args):
    """(ok, code, evidence): Wp<index> only from its own fresh Rp evidence,
    bound to the exact shard, partition and committed offset."""
    entry, code = fresh_rp_evidence(registry, index)
    if entry is None:
        return False, code, None
    if (args or {}).get("partition") != f"p{index}":
        return False, "SHARD_PARTITION_MISMATCH", entry
    committed = (entry.get("facts") or {}).get("committed")
    if (args or {}).get("from_offset") != committed:
        return False, "SHARD_OFFSET_MISMATCH", entry
    if registry.write_status(f"Wp{index}") == "VERIFIED":
        return False, "SHARD_ALREADY_DRAINED", entry
    return True, "SHARD_WRITE_AUTHORIZED", entry


def shard_progress(registry):
    """Per-shard verified state + whether a global DONE may be claimed."""
    shards = {}
    for i in range(10):
        entry, code = fresh_rp_evidence(registry, i)
        shards[f"p{i}"] = {
            "read": code, "read_ref": (entry or {}).get("observation_id"),
            "write_status": registry.write_status(f"Wp{i}"),
            "report_confirmed": registry.is_confirmed(f"Cp{i}")}
    global_done = all(
        s["write_status"] == "VERIFIED" and s["report_confirmed"]
        for s in shards.values()) and registry.is_confirmed("T4")
    return {"shards": shards, "global_done": global_done}


# ------------------------------------------------------------- evidence
def evidence_bundle(registry, host, transport_events=(), extra=None):
    """Raw execution evidence: identities, transport, causal decisions,
    delegate refs, effects, receipts/readback and final obligations."""
    bundle = {
        "attempt_uid": registry.attempt_uid,
        "world_instance_id": registry.world_instance_id,
        "epoch": registry.epoch,
        "agents": sorted(registry.by_agent.keys()),
        "transport_events": list(transport_events or []),
        "causal_decisions": list(getattr(host, "log", []) or []),
        "world_records": list(getattr(host, "world_records", []) or []),
        "effects": [r for r in (getattr(host, "world_records", []) or [])
                    if r.get("kind") == "NATIVE_EFFECT"],
        "obligations": {
            tid: {"state": registry.state_of(tid),
                  "write_status": registry.write_status(tid),
                  "confirmed": registry.is_confirmed(tid),
                  "agent_id": ob.agent_id}
            for tid, ob in sorted(registry.obligations.items())},
        "summary": registry.summary(),
    }
    if extra:
        bundle.update(extra)
    return json.loads(json.dumps(bundle, default=str))
