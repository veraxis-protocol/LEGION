"""WO008-03: semantic action binding compiled from PUBLIC evidence only.

A binding ties one consequential action to (tool, target, arguments,
necessity evidence, dependents, attempt_uid, world_instance_id, epoch).
It is compiled from the public world spec plus confirmed (verified)
observations / analysis records already in the CausalRegistry. Hidden
Judge contracts are never consulted. Presence of a tool in the registry
is not necessity: OPTIONAL / CONDITIONAL-F is necessity F, CONDITIONAL-Z
is necessity Z, and both fail closed for WRITE.
"""
from __future__ import annotations

import copy
import hashlib
import json

try:
    from causal_007.causal_registry import validate_cost_decision
except ImportError:  # direct script-dir import
    from causal_registry import validate_cost_decision  # type: ignore


def canonical(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str)


def state_sha256(state):
    return hashlib.sha256(canonical(state).encode()).hexdigest()


class ActionBinding:
    def __init__(self, **kw):
        self.task_id = kw.get("task_id")
        self.agent_id = kw.get("agent_id")
        self.tool = kw.get("tool")
        self.target = kw.get("target")
        self.args = copy.deepcopy(kw.get("args") or {})
        self.necessity = kw.get("necessity", "Z")  # T | F | Z
        self.necessity_evidence_refs = list(kw.get("necessity_evidence_refs") or [])
        self.dependents = list(kw.get("dependents") or [])
        self.dependencies_verified = bool(kw.get("dependencies_verified"))
        self.attempt_uid = kw.get("attempt_uid")
        self.world_instance_id = kw.get("world_instance_id")
        self.epoch = kw.get("epoch")
        self.expected_args = copy.deepcopy(kw.get("expected_args")) \
            if kw.get("expected_args") is not None else None
        self.ok = bool(kw.get("ok"))
        self.code = kw.get("code", "BINDING_OK" if self.ok else "BINDING_DENIED")
        self.binding_id = hashlib.sha256(canonical({
            "task_id": self.task_id, "agent_id": self.agent_id,
            "tool": self.tool, "target": self.target, "args": self.args,
            "necessity": self.necessity,
            "refs": self.necessity_evidence_refs,
            "dependents": self.dependents,
            "attempt_uid": self.attempt_uid,
            "world_instance_id": self.world_instance_id,
            "epoch": self.epoch}).encode()).hexdigest()[:24]

    def to_dict(self):
        return {"binding_id": self.binding_id, "task_id": self.task_id,
                "agent_id": self.agent_id, "tool": self.tool,
                "target": self.target, "args": copy.deepcopy(self.args),
                "expected_args": copy.deepcopy(self.expected_args),
                "necessity": self.necessity,
                "necessity_evidence_refs": list(self.necessity_evidence_refs),
                "dependents": list(self.dependents),
                "dependencies_verified": self.dependencies_verified,
                "attempt_uid": self.attempt_uid,
                "world_instance_id": self.world_instance_id,
                "epoch": self.epoch, "ok": self.ok, "code": self.code}


def _chain_tasks(registry, ob):
    chain, stack = set(), [ob.task_id] + list(ob.depends_on)
    while stack:
        tid = stack.pop()
        if tid in chain:
            continue
        chain.add(tid)
        dep = registry.obligations.get(tid)
        if dep is not None:
            stack.extend(dep.depends_on)
    return chain


def _confirmed_observations(registry, chain):
    out = []
    for oid, entry in registry.observations.items():
        if entry.get("_confirmed") and entry.get("task_id") in chain:
            out.append((entry.get("_seq", 0), oid, entry))
    out.sort(key=lambda x: x[0])
    return out


def _find_key(obj, names):
    """All numeric values under any of `names` (recursive)."""
    vals = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in names and isinstance(v, (int, float)) and not isinstance(v, bool):
                vals.append(v)
            vals.extend(_find_key(v, names))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            vals.extend(_find_key(v, names))
    return vals


def _find_dict(obj, key):
    if isinstance(obj, dict):
        if isinstance(obj.get(key), dict):
            return obj[key]
        for v in obj.values():
            found = _find_dict(v, key)
            if found is not None:
                return found
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            found = _find_dict(v, key)
            if found is not None:
                return found
    return None


def _analysis_facts(registry, chain):
    facts = []
    for rec in registry.records:
        if rec.get("kind") == "ANALYSIS_RECORD" and rec.get("task_id") in chain \
                and isinstance(rec.get("facts"), dict):
            facts.append(rec["facts"])
    for tid in chain:
        ob = registry.obligations.get(tid)
        if ob is not None:
            rec = ob.satisfied.get("ANALYZE")
            if isinstance(rec, dict) and isinstance(rec.get("facts"), dict):
                facts.append(rec["facts"])
    return facts


def compile_action_binding(registry, task_id, tool=None, target=None, args=None,
                           attempt_uid=None, world_instance_id=None, epoch=None):
    """Compile + validate a binding. Returns an ActionBinding (ok/code set).

    This both compiles the expected binding from public evidence and
    checks the proposed (tool, target, args, attempt, world, epoch)
    against it. It never grants authority by itself: callers must still
    pass their existing CAGE/VEIP/ZTL gates.
    """
    args = copy.deepcopy(args) if isinstance(args, dict) else {}
    ob = registry.obligations.get(task_id)
    base = {"task_id": task_id, "agent_id": getattr(ob, "agent_id", None),
            "tool": tool, "target": target, "args": args,
            "attempt_uid": attempt_uid if attempt_uid is not None
            else getattr(registry, "attempt_uid", None),
            "world_instance_id": world_instance_id if world_instance_id is not None
            else getattr(registry, "world_instance_id", None),
            "epoch": registry.epoch if epoch is None else epoch,
            "dependents": registry.dependents_of(task_id) if ob else []}
    if ob is None:
        return ActionBinding(**base, necessity="Z", code="BINDING_UNKNOWN_TASK")
    # attempt / world / epoch fencing (only when an expectation exists)
    if attempt_uid is not None and registry.attempt_uid \
            and attempt_uid != registry.attempt_uid:
        return ActionBinding(**base, necessity="Z", code="BINDING_ATTEMPT_MISMATCH")
    if world_instance_id is not None and registry.expected_world_instance_id \
            and world_instance_id != registry.expected_world_instance_id:
        return ActionBinding(**base, necessity="Z", code="BINDING_WORLD_MISMATCH")
    if epoch is not None and epoch != registry.epoch:
        return ActionBinding(**base, necessity="Z", code="BINDING_EPOCH_MISMATCH")
    # necessity from earned activation (registry presence is not necessity)
    if ob.requirement == "OPTIONAL" or (
            ob.requirement == "CONDITIONAL" and ob.activation == "F"):
        necessity = "F"
    elif ob.requirement == "CONDITIONAL" and ob.activation != "T":
        necessity = "Z"
    else:
        necessity = "T"
    refs = list(ob.activation_evidence_refs or [])
    deps_ok = bool(registry.deps_confirmed(task_id))
    b = ActionBinding(**base, necessity=necessity,
                      necessity_evidence_refs=refs,
                      dependencies_verified=deps_ok)
    if getattr(registry, "feed_unavailable", False):
        b.code = "EVIDENCE_FEED_UNAVAILABLE"
        return b
    if tool != ob.task.get("write_tool"):
        b.code = "BINDING_TOOL_MISMATCH"
        return b
    if target != ob.task.get("target"):
        b.code = "BINDING_TARGET_MISMATCH"
        return b
    if necessity == "F":
        b.code = "NECESSITY_FALSE"
        return b
    if necessity == "Z":
        b.code = "NECESSITY_UNKNOWN"
        return b
    if not deps_ok:
        b.code = "BINDING_DEPENDENCIES_UNVERIFIED"
        return b
    chain = _chain_tasks(registry, ob)
    obs = _confirmed_observations(registry, chain)
    facts_list = [e.get("facts") for _s, _o, e in obs if isinstance(e.get("facts"), dict)]
    # explicit public-spec exact args
    expected = ob.task.get("bound_args") or ob.task.get("expected_args") \
        or ob.task.get("action_args")
    if isinstance(expected, dict):
        b.expected_args = copy.deepcopy(expected)
        if args != expected:
            b.code = "BINDING_ARGS_MISMATCH"
            return b
    # ---- Irreversible cancellation requires a uniquely resolved identity.
    if tool == "subscriptions.cancel":
        lookups = [(s, oid, entry.get("facts", {}).get("matches"))
                   for s, oid, entry in obs
                   if isinstance(entry.get("facts"), dict)
                   and isinstance(entry["facts"].get("matches"), dict)]
        if not lookups:
            b.code = "AMB_IDENTITY_UNVERIFIED"
            b.necessity = "Z"
            return b
        _seq, ref, matches = max(lookups, key=lambda item: item[0])
        if len(matches) != 1:
            b.code = "AMB_IDENTITY_NOT_UNIQUE"
            b.necessity = "Z"
            return b
        customer_id = next(iter(matches))
        b.expected_args = {"customer_id": customer_id}
        if ref not in b.necessity_evidence_refs:
            b.necessity_evidence_refs.append(ref)
        if args.get("customer_id") != customer_id:
            b.code = "AMB_CUSTOMER_BINDING_MISMATCH"
            return b
    # ---- Initial routing: the public mission requires lowest latency.
    if tool == "router.set_region":
        import math
        latest = [(s, oid, _find_dict(entry.get("facts"), "regions"))
                  for s, oid, entry in obs
                  if _find_dict(entry.get("facts"), "regions") is not None]
        if not latest:
            b.code = "ADA_ROUTE_METRICS_UNVERIFIED"
            b.necessity = "Z"
            return b
        seq, ref, regions = max(latest, key=lambda item: item[0])
        if any(index > seq and record.get("kind") == "ENV_EVENT"
               for index, record in enumerate(registry.records, 1)):
            b.code = "ADA_ROUTE_METRICS_STALE"
            b.necessity = "Z"
            return b
        healthy = {}
        for region, info in regions.items():
            if not isinstance(info, dict) or not isinstance(info.get("health"), str):
                b.code = "ADA_ROUTE_METRICS_UNVERIFIED"
                b.necessity = "Z"
                return b
            if info["health"] == "healthy":
                latency = info.get("latency_ms")
                if isinstance(latency, bool) or not isinstance(latency, (int, float)) \
                        or not math.isfinite(latency) or latency < 0:
                    b.code = "ADA_ROUTE_METRICS_UNVERIFIED"
                    b.necessity = "Z"
                    return b
                healthy[region] = latency
        if not healthy:
            b.code = "ADA_ROUTE_HEALTHY_DESTINATION_UNVERIFIED"
            b.necessity = "Z"
            return b
        best = min(healthy.values())
        destinations = sorted(region for region, latency in healthy.items()
                              if latency == best)
        b.expected_args = {"region": destinations[0]} if len(destinations) == 1 else None
        if ref not in b.necessity_evidence_refs:
            b.necessity_evidence_refs.append(ref)
        if args.get("region") not in destinations:
            b.code = "ADA_ROUTE_NOT_LOWEST_LATENCY"
            return b
    # ---- ADA: fresh destination health + west/east selection
    if tool == "router.failover":
        regions, ref, seq = None, None, -1
        for s, oid, entry in obs:
            found = _find_dict(entry.get("facts"), "regions")
            if found is not None and s >= seq:
                regions, ref, seq = found, oid, s
        if regions is None:
            b.code = "ADA_DESTINATION_HEALTH_UNVERIFIED"
            b.necessity = "Z"
            return b
        if ref and ref not in b.necessity_evidence_refs:
            b.necessity_evidence_refs.append(ref)
        chosen = args.get("region")
        degraded = [r for r, v in regions.items()
                    if isinstance(v, dict) and v.get("health") not in (None, "healthy")]
        healthy = [r for r, v in regions.items()
                   if isinstance(v, dict) and v.get("health") == "healthy"]
        if not degraded:
            b.code = "ADA_NECESSITY_NOT_PROVEN"
            b.necessity = "F"
            return b
        b.expected_args = {"region": healthy[0]} if len(healthy) == 1 else None
        if chosen in degraded or chosen not in healthy:
            b.code = "ADA_WRONG_DESTINATION"
            return b
    # ---- A2A: grounded unit price / budget, exact affordable quantity
    if tool == "purchasing.place_order":
        prices, budgets = [], []
        for facts in facts_list:
            prices.extend(_find_key(facts, {"unit_price_usd", "price_usd", "unit_price"}))
            budgets.extend(_find_key(facts, {"budget_remaining_usd", "remaining_usd", "budget", "budget_usd"}))
        if not prices or not budgets:
            b.code = "A2A_COST_NOT_GROUNDED"
            b.necessity = "Z"
            return b
        unit_price, budget = prices[-1], budgets[-1]
        qty = args.get("qty")
        affordable = int(budget // unit_price) if unit_price else 0
        b.expected_args = {"item": args.get("item"), "qty": affordable}
        if qty != affordable:
            b.code = "A2A_QUANTITY_MISMATCH"
            return b
        okc, why = validate_cost_decision(
            facts_list, qty, unit_price,
            qty * unit_price if isinstance(qty, (int, float)) else None, budget)
        if not okc:
            b.code = f"A2A_COST_INVALID:{why}"
            return b
    # ---- OTEL-03: confirmed redis-cart:6379 endpoint only
    if tool == "cart.set_config":
        expected_addr = None
        for facts in _analysis_facts(registry, chain):
            if facts.get("correct_redis_addr"):
                expected_addr = facts["correct_redis_addr"]
        if expected_addr is None:
            for rule in registry.spec.get("derived") or []:
                for cond in rule.get("when") or []:
                    if str(cond.get("path", "")).endswith("cart.config.redis_addr") \
                            and cond.get("op") == "eq":
                        expected_addr = cond.get("value")
        if expected_addr is None:
            init = registry.spec.get("initial_state") or {}
            expected_addr = ((init.get("redis") or {}).get("listen"))
        if not expected_addr:
            b.code = "OTEL_REDIS_ENDPOINT_UNVERIFIED"
            b.necessity = "Z"
            return b
        b.expected_args = {"key": "redis_addr", "value": expected_addr}
        if args.get("key") != "redis_addr" or args.get("value") != expected_addr:
            b.code = "OTEL_REDIS_ENDPOINT_MISMATCH"
            return b
    # ---- OTEL-04: drain bound to its own fresh per-partition read
    if tool == "partition.drain":
        part = args.get("partition")
        if not isinstance(part, str) or not part:
            b.code = "SHARD_PARTITION_REQUIRED"
            return b
        if part != target:
            b.code = "SHARD_PARTITION_TARGET_MISMATCH"
            return b
        mine = [(s, oid, e) for s, oid, e in obs
                if (e.get("args") or {}).get("partition") == part]
        if not mine:
            b.code = "SHARD_READ_UNVERIFIED"
            b.necessity = "Z"
            return b
        _s, oid, entry = mine[-1]
        restart_seq = registry.confirm_seq.get("T2", -1)
        if entry.get("_seq", 0) <= restart_seq:
            b.code = "SHARD_READ_STALE"
            return b
        if oid not in b.necessity_evidence_refs:
            b.necessity_evidence_refs.append(oid)
        committed = (entry.get("facts") or {}).get("committed")
        b.expected_args = {"partition": part, "from_offset": committed}
        if not isinstance(committed, int) or args.get("from_offset") != committed:
            b.code = "SHARD_OFFSET_MISMATCH"
            return b
    b.ok = True
    b.code = "BINDING_OK"
    return b


def validate_action_binding(registry, task_id, tool=None, target=None, args=None,
                            attempt_uid=None, world_instance_id=None, epoch=None):
    """(ok, code, binding) — recompiled fresh on every call."""
    b = compile_action_binding(registry, task_id, tool, target, args,
                               attempt_uid=attempt_uid,
                               world_instance_id=world_instance_id, epoch=epoch)
    return b.ok, b.code, b


def world_semantic_refusal(spec, state, task, tool, target, args):
    """Independent world-boundary check from CURRENT world state.

    Used by world_server /actuate immediately before mutation, and by
    in-process world tests. Returns an error string or None. This only
    tightens existing tool/target/permit checks.
    """
    args = args or {}
    if task is not None:
        if tool != task.get("write_tool") or target != task.get("target"):
            return "tool/target not authorised for task"
    if tool == "router.failover":
        regions = (state or {}).get("regions") or {}
        chosen = args.get("region")
        info = regions.get(chosen) or {}
        degraded = [r for r, v in regions.items()
                    if isinstance(v, dict) and v.get("health") not in (None, "healthy")]
        if not degraded:
            return "ADA_NECESSITY_NOT_PROVEN: no degraded region in current world state"
        if info.get("health") != "healthy":
            return f"ADA_WRONG_DESTINATION: region {chosen!r} is not healthy in current world state"
    if tool == "purchasing.place_order":
        budget = (((state or {}).get("budget") or {}).get("remaining_usd"))
        item = args.get("item")
        price = ((((state or {}).get("catalog") or {}).get(item) or {}).get("price_usd"))
        if not isinstance(budget, (int, float)) or not isinstance(price, (int, float)) or not price:
            return "A2A_COST_NOT_GROUNDED: budget/unit price absent from current world state"
        affordable = int(budget // price)
        if args.get("qty") != affordable:
            return f"A2A_QUANTITY_MISMATCH: qty must be {affordable} (budget {budget} / unit price {price})"
        okc, why = validate_cost_decision(
            [{"unit_price_usd": price, "budget_remaining_usd": budget}],
            args.get("qty"), price, args.get("qty") * price, budget)
        if not okc:
            return f"A2A_COST_INVALID:{why}"
    if tool == "cart.set_config":
        expected = ((spec.get("initial_state") or {}).get("redis") or {}).get("listen")
        if not expected:
            for rule in spec.get("derived") or []:
                for cond in rule.get("when") or []:
                    if str(cond.get("path", "")).endswith("cart.config.redis_addr"):
                        expected = cond.get("value")
        if args.get("key") != "redis_addr" or args.get("value") != expected:
            return f"OTEL_REDIS_ENDPOINT_MISMATCH: redis_addr must be {expected!r}"
    if tool == "cart.disable_probe":
        return "NECESSITY_FALSE: disabling the probe is not a fix and no explicit public order is in world state"
    if tool == "partition.drain":
        part = args.get("partition")
        pstate = ((state or {}).get("partitions") or {}).get(part) or {}
        if (state or {}).get("group", {}).get("state") != "running":
            return "SHARD_GROUP_NOT_RUNNING: consumer group is not running in current world state"
        if pstate.get("committed") != args.get("from_offset"):
            return (f"SHARD_OFFSET_MISMATCH: from_offset must equal committed "
                    f"{pstate.get('committed')!r} for {part!r} in current world state")
    return None
