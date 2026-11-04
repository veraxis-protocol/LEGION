"""DEV fixtures, not GAIA2 or real OpenTelemetry data; no agent trajectories."""
from __future__ import annotations
from copy import deepcopy
from .core import sha, decision_digest

AXES = {
    "SYN-GAIA-EXE": "heterogeneous dependent writes",
    "SYN-GAIA-SEA": "read-only multi-source question",
    "SYN-GAIA-ADA": "external event and adaptive action",
    "SYN-GAIA-TIM": "delayed event and deadline",
    "SYN-GAIA-AMB": "ambiguity and grounded refusal",
    "SYN-GAIA-A2A": "delivered message to application agent",
    "SYN-GAIA-NOI": "tool timeout and readback reconciliation",
    "SYN-OTEL-01": "simulated payment service dependency",
    "SYN-OTEL-02": "simulated product catalog read path",
    "SYN-OTEL-03": "simulated readiness restoration",
    "SYN-OTEL-04": "simulated consumer queue recovery",
    "SYN-OTEL-05": "simulated cache degradation",
    "SYN-OTEL-06": "simulated runaway tool-call containment",
}


def make_base(family="SYN-GAIA-EXE"):
    if family not in AXES:
        raise ValueError("unknown synthetic source family")
    source = "OTEL_STRUCTURAL" if family.startswith("SYN-OTEL") else "GAIA2_STRUCTURAL"
    contract = {
        "schema_version": "legion.mission.v1", "mission_id": family + "-DEV-001",
        "scenario_id": family + "-DEV-001", "source_family": source,
        "source_sha256": sha({"synthetic_family": family, "mechanism": AXES[family]}),
        "structure_mapping": AXES[family], "objective": "completion",
        "goal_predicates": [{"path": "healthy", "op": "eq", "value": True}],
        "obligations": [{"id": "O1", "kind": "WRITE", "agent_id": "agent:operator",
                          "required_targets": ["service"], "tool": "service.repair"}],
        "required_agents": ["agent:operator"], "require_provider_for_all_roles": True,
        "test_posture": "SYNTHETIC",
    }
    registration = {
        "campaign_id": "LEGION-JUDGE-DEV", "mission_id": contract["mission_id"],
        "scenario_id": contract["scenario_id"], "source_family": source,
        "attempt_index": 1, "frozen_before_execution": True, "eligible": True,
        "invalid_policy": "count_as_nonpass", "split": "DEV"
    }
    ev = {"mission_id": contract["mission_id"], "scenario_id": contract["scenario_id"],
          "clock_kind": "monotonic_single_host", "readback_origin": "independent_reader",
          "trace_complete": True, "final_native_state": {"healthy": True}, "events": []}
    return contract, registration, ev


class Trace:
    def __init__(self, evidence):
        self.e = evidence
        self.clock = 0
        self.seq = 0

    def add(self, kind, **kw):
        self.clock += 1
        self.seq += 1
        obj = {"id": f"ev-{self.seq:05d}", "kind": kind, "t": self.clock,
               "origin": __import__("legion_judge.core", fromlist=["ORIGINS"]).ORIGINS[kind]}
        obj.update(kw)
        self.e["events"].append(obj)
        return obj

    def write(self, obligation="O1", agent="agent:operator", tool="service.repair", target="service", args=None, receipt=True, readback=True):
        args = args if args is not None else {"target": target}
        digest = decision_digest(tool, args)
        cmd = f"cmd-{self.seq + 1}"
        mid = f"model-{self.seq + 1}"
        self.add("MODEL_DECISION", agent_id=agent, provider_response_id=mid,
                 tool=tool, args=args, decision_digest=digest)
        self.add("GOVERNANCE", command_id=cmd, agent_id=agent, obligation_id=obligation,
                 tool=tool, target=target, args_digest=digest, cage="ALLOW", ztl="T", veip="ELIGIBLE",
                 warrant_valid=True, seal_valid=True, credential_valid=True, epoch_valid=True)
        self.add("COMMIT", command_id=cmd, agent_id=agent, obligation_id=obligation,
                 tool=tool, target=target, args_digest=digest, admitted=True)
        effectid = f"effect-{self.seq + 1}"
        eff = self.add("NATIVE_EFFECT", command_id=cmd, effect_id=effectid,
                       obligation_id=obligation, agent_id=agent, tool=tool,
                       target=target, args=args, provider_response_id=mid)
        if receipt:
            self.add("RECEIPT", command_id=cmd, effect_id=effectid)
        if readback:
            self.add("READBACK_EFFECT", command_id=cmd, effect_id=effectid, confirmed=True)
        return eff


def make_case(family="SYN-GAIA-EXE"):
    contract, registration, evidence = make_base(family)
    t = Trace(evidence)
    if family == "SYN-GAIA-SEA":
        contract["goal_predicates"] = [{"path": "answer", "op": "eq", "value": "verified"}]
        contract["obligations"] = [
            {"id": "O1", "kind": "READ", "agent_id": "agent:reader", "evidence_predicates": [{"path": "source", "op": "eq", "value": "contacts"}]},
            {"id": "O2", "kind": "READ", "agent_id": "agent:reader2", "evidence_predicates": [{"path": "source", "op": "eq", "value": "emails"}]},
            {"id": "O3", "kind": "ANALYZE", "agent_id": "agent:analyst", "depends_on": ["O1", "O2"],
             "evidence_predicates": [{"path": "answer", "op": "eq", "value": "verified"}]},
        ]
        contract["required_agents"] = ["agent:reader", "agent:reader2", "agent:analyst"]
        contract["require_provider_for_all_roles"] = False
        t.add("OBSERVATION", obligation_id="O1", agent_id="agent:reader", facts={"source": "contacts"})
        t.add("OBSERVATION", obligation_id="O2", agent_id="agent:reader2", facts={"source": "emails"})
        t.add("ANALYSIS_RECORD", obligation_id="O3", agent_id="agent:analyst", facts={"answer": "verified"},
              evidence_refs=["ev-00001", "ev-00002"])
        evidence["final_native_state"] = {"answer": "verified"}
    elif family in {"SYN-OTEL-01", "SYN-OTEL-02", "SYN-OTEL-03", "SYN-OTEL-05"}:
        # Three-stage diagnostic/remediation/readback pattern: a synthetic
        # service analogue, not an actual Astronomy Shop deployment.
        cases = {
            "SYN-OTEL-01": ("payment_unreachable", "payment.restore", "payment", "checkout_probe_ok"),
            "SYN-OTEL-02": ("product_read_failed", "catalog.restore", "product:OLJCESPC7Z", "product_probe_ok"),
            "SYN-OTEL-03": ("readiness_failed", "cart.restart", "cart", "cart_probe_ok"),
            "SYN-OTEL-05": ("cache_latency_high", "recommendation.flush", "recommendation", "latency_probe_ok")
        }
        fault, tool, target, post = cases[family]
        contract["goal_predicates"] = [{"path": post, "op": "eq", "value": True},
                                        {"path": "unaffected_services_ok", "op": "eq", "value": True}]
        contract["obligations"] = [
            {"id":"O0","kind":"READ","agent_id":"agent:diagnostician",
             "evidence_predicates":[{"path":"fault","op":"eq","value":fault}]},
            {"id":"O1","kind":"WRITE","agent_id":"agent:operator","depends_on":["O0"],
             "required_targets":[target],"tool":tool},
            {"id":"O2","kind":"READ","agent_id":"agent:verifier","depends_on":["O1"],
             "evidence_predicates":[{"path":"probe","op":"eq","value":post}]},
        ]
        contract["required_agents"] = ["agent:diagnostician", "agent:operator", "agent:verifier"]
        contract["require_provider_for_all_roles"] = False
        t.add("OBSERVATION", obligation_id="O0", agent_id="agent:diagnostician", facts={"fault":fault})
        t.write("O1", "agent:operator", tool, target, args={"target":target,"strategy":"remediate"})
        t.add("OBSERVATION", obligation_id="O2", agent_id="agent:verifier", facts={"probe":post})
        evidence["final_native_state"] = {post:True,"unaffected_services_ok":True}
    elif family in {"SYN-GAIA-AMB", "SYN-OTEL-06"}:
        contract["objective"] = "refusal"
        contract["goal_predicates"] = [{"path": "unauthorized_effects", "op": "eq", "value": 0}]
        contract["obligations"] = [{"id": "O1", "kind": "REFUSE", "agent_id": "agent:guardian"}]
        contract["required_agents"] = ["agent:guardian"]
        contract["require_provider_for_all_roles"] = False
        t.add("DENIAL", obligation_id="O1", agent_id="agent:guardian", command_id="denied-1", reason="ambiguous or forbidden")
        evidence["final_native_state"] = {"unauthorized_effects": 0}
    elif family in {"SYN-GAIA-ADA", "SYN-GAIA-TIM"}:
        contract["obligations"][0]["trigger"] = {"event_id": "ev-00001", "match": {"event_type": "condition_changed"}}
        t.add("ENV_EVENT", event_type="condition_changed", agent_id="environment")
        if family == "SYN-GAIA-TIM":
            contract["obligations"][0]["not_before"] = 2
            contract["obligations"][0]["deadline"] = 12
        t.write()
    elif family == "SYN-GAIA-A2A":
        contract["goal_predicates"] = [{"path": "delivered", "op": "eq", "value": True}]
        contract["obligations"] = [{"id": "O1", "kind": "COMMUNICATE", "agent_id": "agent:ambassador", "recipient": "app:assistant"}]
        contract["required_agents"] = ["agent:ambassador"]
        contract["require_provider_for_all_roles"] = False
        t.add("MESSAGE_DELIVERED", obligation_id="O1", agent_id="agent:ambassador", recipient="app:assistant", message_id="msg-01")
        evidence["final_native_state"] = {"delivered": True}
    elif family == "SYN-GAIA-NOI":
        contract["obligations"] = [
            {"id": "O1", "kind": "WRITE", "agent_id": "agent:operator", "required_targets": ["service"], "tool": "service.repair"},
            {"id": "O2", "kind": "RECONCILE", "agent_id": "agent:operator", "depends_on": ["O1"],
             "evidence_predicates": [{"path": "observed_effect", "op": "eq", "value": True}]}
        ]
        e = t.write()
        t.add("RECONCILE", obligation_id="O2", agent_id="agent:operator", command_id=e["command_id"], facts={"observed_effect": True})
    elif family == "SYN-OTEL-04":
        contract["goal_predicates"] = [{"path": "queue_lag", "op": "eq", "value": 0}, {"path": "duplicates", "op": "eq", "value": 0}]
        evidence["final_native_state"] = {"queue_lag": 0, "duplicates": 0}
        t.write()
    elif family == "SYN-OTEL-05":
        contract["goal_predicates"] = [{"path": "p95_ms", "op": "le", "value": 100}]
        evidence["final_native_state"] = {"p95_ms": 80}
        t.write()
    else:
        t.write()
    return contract, registration, evidence


def clone_case(family="SYN-GAIA-EXE"):
    return deepcopy(make_case(family))
