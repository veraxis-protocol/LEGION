"""LEGION scale CAGE contribution through the PUBLIC plugin contract, composed onto the active
finance plugin exactly as tests/legion_mini/sre_plugin.compose does. ONE governed action PER
OBLIGATION: apply_transition_<obligation_id underscored>. One MCP tool apply_transition."""
from __future__ import annotations
import dataclasses, hashlib, json, logging, os, time, uuid
from typing import Any, Mapping
import httpx
from src.gateway.governance.contracts import NormBinding, PluginContribution, ReadOnlyTier, Violation, ViolationKind
from src.gateway.governance.execution_actuator import dispatch_actuation, get_actuator_registry
from src.gateway.governance.governor.server_inputs import bind_server_inputs
from src.gateway.governance.seams.actuation import ActuationOutcome, ActuationReceipt, ExecutionClearance
from src.gateway.governance.warrant.execution_context import WarrantContextPolicy, admitted_workload_identity
from src.gateway.server.governance_middleware import ActionDeferred, enforce_governance
from tests.legion_mini.sre_plugin import caller_args_digest  # noqa: F401  (re-exported; identical definition)
from tests.legion_scale.dag_controller import load_manifest

logger = logging.getLogger("legion.scale")
GOVERNING_VERSION = "legion-scale-005-1"
SYSTEM = "legion-synthetic-sre"
OWNED = frozenset({"ztl_state", "ztl_evidence_digest", "ztl_fact_id", "ql_directive", "ql_command_id", "sre_actor", "sre_system",
                   "confidence", "confidence_provenance", "assigned_agent"})
READINESS_PROVENANCE = "server_bound_independent_readback"
ZTL_BUDGET_S = 5.0


def action_name(obligation_id: str) -> str:
    return "apply_transition_" + obligation_id.replace("-", "_")


def norm_id_for(obligation_id: str) -> str:
    return "sre.apply_transition." + obligation_id + ".authority"


def _canon(o: Any) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str)


class ScaleNodes:
    def __init__(self, manifest):
        self.manifest = load_manifest(manifest)
        self.nodes = {n["obligation_id"]: n for n in self.manifest["nodes"]}
        self.actions = {action_name(oid): oid for oid in self.nodes}

    def norm_bindings(self) -> tuple[NormBinding, ...]:
        return tuple(NormBinding(norm_id=norm_id_for(oid), value=1.0, requires_warrant=True,
                                 actions=frozenset({action_name(oid)}), governing_version=GOVERNING_VERSION)
                     for oid in sorted(self.nodes))


class ScaleInputResolver:
    owned_keys = OWNED

    def __init__(self, obligation_id: str, controller, nodes: ScaleNodes):
        self.obligation_id, self.controller, self.nodes = obligation_id, controller, nodes

    async def resolve(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        out: dict[str, Any] = {}
        node = self.nodes.nodes[self.obligation_id]
        policy = WarrantContextPolicy.from_env()
        ctx, _ = policy.resolve(admitted_workload_identity())
        if ctx is not None:
            out.update(sre_actor=ctx.actor, sre_system=ctx.system)
        out["assigned_agent"] = node["agent_id"]
        try:
            import asyncio
            rec = await asyncio.wait_for(self.controller.evidence_verdict(self.obligation_id), ZTL_BUDGET_S)
            out.update(ztl_state=rec["state"], ztl_evidence_digest=rec["digest"], ztl_fact_id=rec["fact_id"])
        except Exception as exc:
            logger.warning("scale ZTL evidence unavailable for %s: %s", self.obligation_id, exc)
        d = await self.controller.directive_for(self.obligation_id)
        out.update(ql_directive=d["directive"], ql_command_id=d["command_id"])
        ready = out.get("ztl_state") == "ACCEPTED_TRUE" and bool(out.get("ztl_evidence_digest")) and d["directive"] == "ACT"
        out.update(confidence=1.0 if ready else 0.0, confidence_provenance=READINESS_PROVENANCE)
        return out


class ScaleObligationTier(ReadOnlyTier):
    def __init__(self, nodes: ScaleNodes):
        self.nodes = nodes

    @property
    def tier_name(self) -> str:
        return "legion_scale_obligation"

    @property
    def order(self) -> int:
        return 0

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action in self.nodes.actions

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        v: list[Violation] = []

        def hard(code, msg):
            v.append(Violation(tier=self.tier_name, code=code, message=f"[{code}] {msg}", kind=ViolationKind.HARD))
        oid = self.nodes.actions.get(action)
        node = self.nodes.nodes.get(oid or "")
        if node is None:
            hard("UNKNOWN_OBLIGATION_ACTION", f"action {action}")
            return v
        st = params.get("ztl_state")
        if st != "ACCEPTED_TRUE" or not params.get("ztl_evidence_digest"):
            hard({"ACCEPTED_FALSE": "ZTL_EVIDENCE_CONTRADICTS", "NOT_DECIDED_INSUFFICIENT": "ZTL_EVIDENCE_INSUFFICIENT",
                  "NOT_DECIDED_BOUND_BROKEN": "ZTL_BOUND_BROKEN"}.get(st, "ZTL_EVIDENCE_UNAVAILABLE"),
                 f"precondition fact {params.get('ztl_fact_id')!r} state={st!r}")
        if params.get("ql_directive") != "ACT" or not params.get("ql_command_id"):
            hard("OBLIGATION_NOT_ELIGIBLE", f"directive {params.get('ql_directive')!r} for {oid}")
        if params.get("sre_actor") != node["agent_id"]:
            hard("ROLE_BINDING_MISMATCH", f"sre_actor {params.get('sre_actor')!r} != assigned {node['agent_id']!r}")
        if params.get("assigned_agent") != node["agent_id"]:
            hard("ASSIGNED_AGENT_MISMATCH", f"assigned_agent {params.get('assigned_agent')!r}")
        if params.get("target_id") != node["target_id"]:
            hard("TARGET_OUT_OF_MISSION", f"target_id {params.get('target_id')!r} != {node['target_id']!r}")
        if params.get("stage") != node["stage"]:
            hard("STAGE_MISMATCH", f"stage {params.get('stage')!r} != {node['stage']!r}")
        if params.get("obligation_id") != oid:
            hard("OBLIGATION_MISMATCH", f"obligation_id {params.get('obligation_id')!r} != {oid!r}")
        if not params.get("sre_actor") or not params.get("sre_system"):
            hard("ACTOR_UNRESOLVED", "no admitted, mapped workload identity")
        return v


class ScaleHttpActuator:
    actuator_id = "legion_scale_http_actuator"

    def __init__(self, url: str):
        self.url = url.rstrip("/")

    async def health_check(self) -> bool:
        return True

    def get_capabilities(self) -> set:
        return set()

    async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
        p = clearance.params
        body = {"command_id": p.get("ql_command_id"), "obligation_id": p.get("obligation_id"), "target_id": p.get("target_id"),
                "stage": p.get("stage"), "actor": p.get("sre_actor"), "system": p.get("sre_system"),
                "seal_sha256": hashlib.sha256(clearance.routing_seal.encode()).hexdigest(),
                "params_hash": hashlib.sha256(_canon({k: p[k] for k in sorted(p)}).encode()).hexdigest()}
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                r = await c.post(f"{self.url}/apply", json=body, headers={"Authorization": f"Bearer {os.environ['SRE_TARGET_TOKEN']}"})
            data = r.json()
        except Exception as exc:
            return ActuationReceipt(accepted=False, receipt_id=None, session_uuid=None, raw_receipt=None,
                                    findings=[{"code": "ACTUATION_UNKNOWN", "detail": type(exc).__name__}], outcome=ActuationOutcome.UNKNOWN)
        if r.status_code == 200 and data.get("status") == "applied":
            return ActuationReceipt(accepted=True, receipt_id=data["effect"]["effect_id"], session_uuid=None,
                                    raw_receipt={"status": "executed", "effect": data["effect"]})
        return ActuationReceipt(accepted=False, receipt_id=None, session_uuid=None, raw_receipt=data,
                                findings=[{"code": f"TARGET_{str(data.get('status') or r.status_code).upper()}", "detail": str(data)[:200]}])


def _gate_commit_log(rec: dict) -> None:
    path = os.environ.get("MINI_GATE_COMMITS")
    if path:
        with open(path, "a") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")


async def execute_scale_action(obligation_id: str, target_id: str, stage: int, confidence: float | None, decision_ref: str, *,
                               governor, controller, nodes: ScaleNodes) -> str:
    if obligation_id not in nodes.nodes:
        rec = {"t_start": time.time(), "t_start_mono": time.monotonic(), "t_end": time.time(), "t_end_mono": time.monotonic(),
               "tool": "apply_transition", "obligation_id": obligation_id, "outcome": "BLOCKED",
               "detail": "unknown obligation_id (no governance run)", "decision_ref": decision_ref or None,
               "caller_args": {"obligation_id": obligation_id, "target_id": target_id, "stage": stage}}
        _gate_commit_log(rec)
        return f"BLOCKED: unknown obligation_id {obligation_id!r}"
    action = action_name(obligation_id)
    caller_args = {"obligation_id": obligation_id, "target_id": target_id, "stage": stage, "confidence": confidence, "decision_ref": decision_ref}
    rec: dict[str, Any] = {"t_start": time.time(), "t_start_mono": time.monotonic(), "tool": action, "action_name": action,
                           "obligation_id": obligation_id, "admitted_identity": admitted_workload_identity(),
                           "caller_args": caller_args, "caller_args_digest": caller_args_digest(action, caller_args),
                           "decision_ref": decision_ref or None, "outcome": "ERROR"}
    try:
        out = await _execute(action, obligation_id, target_id, stage, confidence, decision_ref, rec, governor=governor, controller=controller)
        rec["outcome"], rec["detail"] = out.split(":", 1)[0], out[:500]
        return out
    finally:
        rec["t_end"], rec["t_end_mono"] = time.time(), time.monotonic()
        _gate_commit_log(rec)


async def _execute(action, obligation_id, target_id, stage, confidence, decision_ref, rec, *, governor, controller) -> str:
    from src.gateway.governance.routing_seal import SymbolicGovernorViolation, verify_and_consume_seal
    params: dict[str, Any] = {"obligation_id": obligation_id, "target_id": target_id, "stage": stage, "request_id": str(uuid.uuid4())}
    if confidence is not None:
        params["confidence"] = confidence
    if decision_ref:
        params["decision_ref"] = decision_ref
    rec["request_id"] = params["request_id"]
    params = await bind_server_inputs(governor.components.server_inputs, action, params)
    rec["bound_params"] = dict(params)
    try:
        seal = await enforce_governance(governor, action, params)
    except ActionDeferred as exc:
        return f"DEFERRED: {exc}"
    except PermissionError as exc:
        return f"BLOCKED: {exc}"
    if not isinstance(seal, str) or not seal.strip():
        raise SymbolicGovernorViolation(f"CRITICAL: {action} invoked without mandatory routing seal.", action=action)
    rec["seal"], rec["seal_sha256"] = seal, hashlib.sha256(seal.encode()).hexdigest()
    rec["command_id"] = params.get("ql_command_id")
    executed, claimed = False, ""
    try:
        try:
            await verify_and_consume_seal(seal, action, params)
        except SymbolicGovernorViolation:
            return "BLOCKED: routing seal invalid, expired, or already consumed — governance authority unresolved."
        try:
            await controller.begin(obligation_id, params["ql_command_id"])
            claimed = params["ql_command_id"]
        except Exception as exc:
            return f"BLOCKED: obligation claim refused ({exc})"
        clearance = ExecutionClearance(
            thread_id=params["request_id"], decision="ALLOW", decision_path="DIRECT", action=action, target=target_id,
            operator_urn=str(params.get("sre_actor")), issued_at=int(time.time()), issued_at_provenance="CONSTRUCTION_TIME",
            correlation_id=params["request_id"], correlation_id_source="THREAD_DERIVED", governance_decision_digest=seal,
            opa_input_digest=hashlib.sha256(_canon(params).encode()).hexdigest(), nonce=uuid.uuid4().hex,
            params=params, executor_id=ScaleHttpActuator.actuator_id, target_route="local://legion-scale",
            approvals=[], required_quorum=0, routing_seal=seal)
        actuator = get_actuator_registry().get_actuator(action)
        if actuator is None:
            raise SymbolicGovernorViolation(f"CRITICAL: No actuator registered for {action}.", action=action)
        receipt = await dispatch_actuation(actuator, clearance)
        executed = receipt.may_have_executed
        rec["effect_id"], rec["receipt_accepted"] = receipt.receipt_id, receipt.accepted
        closed = await controller.close(obligation_id, claimed)
        claimed = ""
        if not receipt.accepted:
            return f"BLOCKED: actuation not accepted ({receipt.findings}); obligation closed={closed.get('closed')}"
        return (f"EXECUTED: apply_transition {obligation_id} {target_id} stage={stage} (Receipt ID: {receipt.receipt_id}; "
                f"command_id={params['ql_command_id']}; obligation_closed={closed.get('closed')})")
    finally:
        if claimed:
            controller.release(claimed)
        failures = await governor.settle(seal, executed=executed)
        for f in failures:
            logger.critical("%s settlement failed: %s", action, f.message)


class ScaleToolProvider:
    def __init__(self, inner, controller, nodes: ScaleNodes):
        self.inner, self.controller, self.nodes = inner, controller, nodes

    def register_tools(self, server, governor) -> None:
        if self.inner is not None:
            self.inner.register_tools(server, governor)
        ctl, nodes = self.controller, self.nodes

        @server.tool(name="apply_transition", description="Apply the governed stage transition for one obligation.")
        async def _apply_transition(obligation_id: str, target_id: str, stage: int, confidence: float | None = None, decision_ref: str = "") -> str:
            return await execute_scale_action(obligation_id, target_id, stage, confidence, decision_ref, governor=governor, controller=ctl, nodes=nodes)


def composed_ftra_registry(src_path, out_path, nodes: ScaleNodes) -> str:
    from src.gateway.governance.ftra.classifier import registry_digest
    raw = json.loads(open(src_path).read())
    raw["terminals"] = {**raw["terminals"], **{action_name(oid): "REVERSIBLE" for oid in nodes.nodes}}
    raw["manifest_sha256"] = registry_digest(raw)
    open(out_path, "w").write(json.dumps(raw, indent=1))
    return raw["manifest_sha256"]


def register_actuator(url: str, nodes: ScaleNodes) -> None:
    reg = get_actuator_registry()
    if ScaleHttpActuator.actuator_id not in reg.list_actuators():
        reg.register(ScaleHttpActuator(url), claims=set(nodes.actions))
    else:  # same process, new world/manifest: widen claims and re-point at this world's target
        reg._claims[ScaleHttpActuator.actuator_id] |= set(nodes.actions)
        reg.get_actuator(next(iter(nodes.actions))).url = url.rstrip("/")


def compose(contribution: PluginContribution, controller, nodes: ScaleNodes) -> PluginContribution:
    si = dict(contribution.server_inputs)
    for oid in nodes.nodes:
        si[action_name(oid)] = ScaleInputResolver(oid, controller, nodes)
    return dataclasses.replace(
        contribution,
        tiers=tuple(contribution.tiers) + (ScaleObligationTier(nodes),),
        server_inputs=si,
        norm_bindings=tuple(contribution.norm_bindings) + nodes.norm_bindings(),
        registered_actions=frozenset(contribution.registered_actions) | frozenset(nodes.actions),
        tool_provider=ScaleToolProvider(contribution.tool_provider, controller, nodes),
    )
