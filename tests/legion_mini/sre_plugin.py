"""LEGION-MINI-003 SRE contribution through CAGE's PUBLIC plugin contract (no kernel change, no second gateway).

CAGE runs exactly one domain plugin per process (CAGE_DOMAIN); this composes two real, distinct governed actions onto the
active plugin's PluginContribution, the same way the LEGION overlay composes its ZTL tier:

* registered_actions        restore_config, restart_service (NOT execute_trade under another name)
* norm_bindings             one warranted norm per action, so each action needs its own VEIP warrant, scoped to its actor
* server_inputs             per-action resolver: binds the ZTL verdict on the action's precondition fact, the
                            QuantifiedLedger directive + command_id, and the actor/system from the admitted identity.
                            The kernel strips any caller-supplied value for these keys before binding.
* tiers                     SreObligationTier (read-only, phase 1): HARD unless ZTL ACCEPTED_TRUE and ledger directive ACT
* tool_provider             MCP tools restore_config / restart_service -> execute_sre_action (commit, seal, verify-and-
                            consume, claim, actuate, native-readback close, settle). Mirrors execute_trade_action.
* actuator                  SreHttpActuator: the only holder of the target's mutation credential."""
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

logger = logging.getLogger("legion.mini.sre")
SRE_ACTIONS = frozenset({"restore_config", "restart_service"})
SRE_TARGET = "demo-service"
SRE_GOVERNING_VERSION = "legion-mini-sre-1"
NORM_IDS = {"restore_config": "sre.restore_config.authority", "restart_service": "sre.restart_service.authority"}
OWNED = frozenset({"ztl_state", "ztl_evidence_digest", "ztl_fact_id", "ql_directive", "ql_command_id", "sre_actor", "sre_system",
                   "confidence", "confidence_provenance"})
# MINI-004: "confidence" is SERVER-OWNED. The kernel strips any caller value before binding. The bound value is a
# readiness indicator derived from server-side readback, NOT a calibrated probability:
#   1.0  iff the ZTL verdict on the action's precondition fact is ACCEPTED_TRUE AND the ledger directive is ACT for it
#   0.0  otherwise.
# The CTRL_AGT_001 floor therefore re-expresses readback-derived readiness and cannot be moved by anything an agent says.
READINESS_PROVENANCE = "server_bound_independent_readback"
ZTL_BUDGET_S = 3.0


def norm_bindings() -> tuple[NormBinding, ...]:
    return tuple(NormBinding(norm_id=NORM_IDS[a], value=1.0, requires_warrant=True, actions=frozenset({a}),
                             governing_version=SRE_GOVERNING_VERSION) for a in sorted(SRE_ACTIONS))


def _canon(o: Any) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str)


class SreInputResolver:
    """Server-bound inputs for one SRE action. Never reads identity or evidence from the request."""

    owned_keys = OWNED

    def __init__(self, action: str, controller):
        self.action, self.controller = action, controller

    async def resolve(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        out: dict[str, Any] = {}
        policy = WarrantContextPolicy.from_env()
        ctx, _ = policy.resolve(admitted_workload_identity())
        if ctx is not None:
            out.update(sre_actor=ctx.actor, sre_system=ctx.system)
        try:
            gen = int(params.get("generation"))
            import asyncio
            rec = await asyncio.wait_for(self.controller.evidence_verdict(self.action, gen), ZTL_BUDGET_S)
            out.update(ztl_state=rec["state"], ztl_evidence_digest=rec["digest"], ztl_fact_id=rec["fact_id"])
        except Exception as exc:   # evidence unavailable -> keys absent -> HARD refusal (fail closed)
            logger.warning("SRE ZTL evidence unavailable for %s: %s", self.action, exc)
        d = await self.controller.directive_for(self.action)
        out.update(ql_directive=d["directive"], ql_command_id=d["command_id"])
        ready = out.get("ztl_state") == "ACCEPTED_TRUE" and bool(out.get("ztl_evidence_digest")) and d["directive"] == "ACT"
        out.update(confidence=1.0 if ready else 0.0, confidence_provenance=READINESS_PROVENANCE)
        return out


class SreObligationTier(ReadOnlyTier):
    @property
    def tier_name(self) -> str:
        return "legion_sre_obligation"

    @property
    def order(self) -> int:
        return 0

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return action in SRE_ACTIONS

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        v: list[Violation] = []

        def hard(code, msg):
            v.append(Violation(tier=self.tier_name, code=code, message=f"[{code}] {msg}", kind=ViolationKind.HARD))
        st = params.get("ztl_state")
        if st != "ACCEPTED_TRUE" or not params.get("ztl_evidence_digest"):
            hard({"ACCEPTED_FALSE": "ZTL_EVIDENCE_CONTRADICTS", "NOT_DECIDED_INSUFFICIENT": "ZTL_EVIDENCE_INSUFFICIENT",
                  "NOT_DECIDED_BOUND_BROKEN": "ZTL_BOUND_BROKEN"}.get(st, "ZTL_EVIDENCE_UNAVAILABLE"),
                 f"precondition fact {params.get('ztl_fact_id')!r} state={st!r}")
        if params.get("ql_directive") != "ACT" or not params.get("ql_command_id"):
            hard("OBLIGATION_NOT_ELIGIBLE", f"ledger directive {params.get('ql_directive')!r} for {action}")
        if params.get("target") != SRE_TARGET:
            hard("TARGET_OUT_OF_MISSION", f"target {params.get('target')!r}")
        if params.get("generation") != 1:
            hard("GENERATION_MISMATCH", f"generation {params.get('generation')!r}")
        if not params.get("sre_actor") or not params.get("sre_system"):
            hard("ACTOR_UNRESOLVED", "no admitted, mapped workload identity")
        return v


class SreHttpActuator:
    """Only holder of the native target's mutation credential (env SRE_TARGET_TOKEN in the gateway process)."""

    actuator_id = "legion_sre_http_actuator"

    def __init__(self, url: str):
        self.url = url.rstrip("/")

    async def health_check(self) -> bool:
        return True

    def get_capabilities(self) -> set:
        return set()

    async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
        p = clearance.params
        body = {"command_id": p.get("ql_command_id"), "verb": clearance.action, "target": p.get("target"),
                "generation": p.get("generation"), "actor": p.get("sre_actor"), "system": p.get("sre_system"),
                "seal_sha256": hashlib.sha256(clearance.routing_seal.encode()).hexdigest(),
                "params_hash": hashlib.sha256(_canon({k: p[k] for k in sorted(p)}).encode()).hexdigest()}
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                r = await c.post(f"{self.url}/apply", json=body, headers={"Authorization": f"Bearer {os.environ['SRE_TARGET_TOKEN']}"})
            data = r.json()
        except Exception as exc:     # effect may have happened: never report REJECTED
            return ActuationReceipt(accepted=False, receipt_id=None, session_uuid=None, raw_receipt=None,
                                    findings=[{"code": "ACTUATION_UNKNOWN", "detail": type(exc).__name__}],
                                    outcome=ActuationOutcome.UNKNOWN)
        if r.status_code == 200 and data.get("status") == "applied":
            return ActuationReceipt(accepted=True, receipt_id=data["effect"]["effect_id"], session_uuid=None,
                                    raw_receipt={"status": "executed", "effect": data["effect"]})
        return ActuationReceipt(accepted=False, receipt_id=None, session_uuid=None, raw_receipt=data,
                                findings=[{"code": f"TARGET_{str(data.get('status') or r.status_code).upper()}", "detail": str(data)[:200]}])


def caller_args_digest(action: str, args: Mapping[str, Any]) -> str:
    """Digest of the tool call exactly as the caller sent it (decision_ref and absent/None args excluded)."""
    return hashlib.sha256(_canon({"tool": action, "args": {k: v for k, v in sorted(args.items()) if k != "decision_ref" and v is not None}}).encode()).hexdigest()


def _gate_commit_log(rec: dict) -> None:
    """Gateway-side record of EVERY commit attempt (written by the gateway process, never by an agent)."""
    path = os.environ.get("MINI_GATE_COMMITS")
    if path:
        with open(path, "a") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")


async def execute_sre_action(action: str, target: str, generation: int, confidence: float | None, decision_ref: str, *,
                             governor, controller) -> str:
    """The single committing run for one SRE action (mirrors execute_trade_action's sequence)."""
    caller_args = {"target": target, "generation": generation, "confidence": confidence, "decision_ref": decision_ref}
    rec: dict[str, Any] = {"t_start": time.time(), "t_start_mono": time.monotonic(), "tool": action, "admitted_identity": admitted_workload_identity(),
                           "caller_args": caller_args, "caller_args_digest": caller_args_digest(action, caller_args),
                           "decision_ref": decision_ref or None, "outcome": "ERROR"}
    try:
        out = await _execute_sre_action(action, target, generation, confidence, decision_ref, rec, governor=governor, controller=controller)
        rec["outcome"], rec["detail"] = out.split(":", 1)[0], out[:500]
        return out
    finally:
        rec["t_end"], rec["t_end_mono"] = time.time(), time.monotonic()
        _gate_commit_log(rec)


async def _execute_sre_action(action, target, generation, confidence, decision_ref, rec, *, governor, controller) -> str:
    from src.gateway.governance.routing_seal import SymbolicGovernorViolation, verify_and_consume_seal
    params: dict[str, Any] = {"target": target, "generation": generation, "request_id": str(uuid.uuid4())}
    if confidence is not None:
        params["confidence"] = confidence            # caller value: stripped by the kernel (server-owned key)
    if decision_ref:
        params["decision_ref"] = decision_ref        # caller-asserted pointer, recorded and sealed, never authority
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
            await controller.begin(action, params["ql_command_id"])
            claimed = params["ql_command_id"]
        except Exception as exc:
            return f"BLOCKED: obligation claim refused ({exc})"
        clearance = ExecutionClearance(
            thread_id=params["request_id"], decision="ALLOW", decision_path="DIRECT", action=action, target=target,
            operator_urn=str(params.get("sre_actor")), issued_at=int(time.time()), issued_at_provenance="CONSTRUCTION_TIME",
            correlation_id=params["request_id"], correlation_id_source="THREAD_DERIVED", governance_decision_digest=seal,
            opa_input_digest=hashlib.sha256(_canon(params).encode()).hexdigest(), nonce=uuid.uuid4().hex,
            params=params, executor_id=SreHttpActuator.actuator_id, target_route="local://legion-mini-sre",
            approvals=[], required_quorum=0, routing_seal=seal)
        actuator = get_actuator_registry().get_actuator(action)
        if actuator is None:
            raise SymbolicGovernorViolation(f"CRITICAL: No actuator registered for {action}.", action=action)
        receipt = await dispatch_actuation(actuator, clearance)
        executed = receipt.may_have_executed
        rec["effect_id"], rec["receipt_accepted"] = receipt.receipt_id, receipt.accepted
        closed = await controller.close(action, claimed)
        claimed = ""
        if not receipt.accepted:
            return f"BLOCKED: actuation not accepted ({receipt.findings}); obligation closed={closed.get('closed')}"
        return (f"EXECUTED: {action} {target} generation={generation} (Receipt ID: {receipt.receipt_id}; "
                f"command_id={params['ql_command_id']}; obligation_closed={closed.get('closed')})")
    finally:
        if claimed:
            controller.release(claimed)
        failures = await governor.settle(seal, executed=executed)
        for f in failures:
            logger.critical("%s settlement failed: %s", action, f.message)


class SreToolProvider:
    def __init__(self, inner, controller):
        self.inner, self.controller = inner, controller

    def register_tools(self, server, governor) -> None:
        if self.inner is not None:
            self.inner.register_tools(server, governor)
        ctl = self.controller

        @server.tool(name="restore_config", description="Restore demo-service configuration to the given generation (governed).")
        async def _restore_config(target: str, generation: int, confidence: float | None = None, decision_ref: str = "") -> str:
            return await execute_sre_action("restore_config", target, generation, confidence, decision_ref, governor=governor, controller=ctl)

        @server.tool(name="restart_service", description="Restart demo-service (governed).")
        async def _restart_service(target: str, generation: int, confidence: float | None = None, decision_ref: str = "") -> str:
            return await execute_sre_action("restart_service", target, generation, confidence, decision_ref, governor=governor, controller=ctl)


#: FTRA classification of the two verbs. Both are operationally reversible (config can be restored again; a service can be
#: stopped), so REVERSIBLE: no autonomy envelope. Declared as domain data in a composed copy of the active domain's
#: terminal registry (absent actions fail closed as IRREVERSIBLE_TERMINAL); the digest is recomputed by CAGE.
SRE_FTRA_CLASSIFICATION = {"restore_config": "REVERSIBLE", "restart_service": "REVERSIBLE"}


def composed_ftra_registry(src_path, out_path) -> str:
    from src.gateway.governance.ftra.classifier import registry_digest
    raw = json.loads(open(src_path).read())
    raw["terminals"] = {**raw["terminals"], **SRE_FTRA_CLASSIFICATION}
    raw["manifest_sha256"] = registry_digest(raw)
    open(out_path, "w").write(json.dumps(raw, indent=1))
    return raw["manifest_sha256"]


def register_actuator(url: str) -> None:
    reg = get_actuator_registry()                 # process singleton: re-point the existing actuator at this world's target
    if SreHttpActuator.actuator_id not in reg.list_actuators():
        reg.register(SreHttpActuator(url), claims=set(SRE_ACTIONS))
    reg.get_actuator("restore_config").url = url.rstrip("/")


def compose(contribution: PluginContribution, controller) -> PluginContribution:
    si = dict(contribution.server_inputs)
    for a in SRE_ACTIONS:
        si[a] = SreInputResolver(a, controller)
    return dataclasses.replace(
        contribution,
        tiers=tuple(contribution.tiers) + (SreObligationTier(),),
        server_inputs=si,
        norm_bindings=tuple(contribution.norm_bindings) + norm_bindings(),
        registered_actions=frozenset(contribution.registered_actions) | SRE_ACTIONS,
        tool_provider=SreToolProvider(contribution.tool_provider, controller),
    )
