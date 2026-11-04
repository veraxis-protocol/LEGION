"""LEGION structural CAGE contribution through the PUBLIC plugin contract.

Exactly like tests/legion_scale/scale_plugin.py, composed onto the active
domain plugin: ONE governed action per write task (``struct_<task_id>``), one
NormBinding (requires_warrant) per action, server-owned inputs bound from ZTL
evidence + the quantified-ledger-style controller directive, a HARD tier, and
MCP tools ``world_write`` / ``declare_refusal``.  The actuator is the only
holder of the world actuator token and posts to the world ``/actuate``.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from typing import Any, Mapping

import httpx

from src.gateway.governance.contracts import NormBinding, PluginContribution, ReadOnlyTier, Violation, ViolationKind
from src.gateway.governance.execution_actuator import dispatch_actuation, get_actuator_registry
from src.gateway.governance.governor.server_inputs import bind_server_inputs
from src.gateway.governance.seams.actuation import ActuationOutcome, ActuationReceipt, ExecutionClearance
from src.gateway.governance.warrant.execution_context import WarrantContextPolicy, admitted_workload_identity
from src.gateway.server.governance_middleware import ActionDeferred, enforce_governance

try:
    from tests.legion_struct.struct_controller import StructWorld
except ImportError:  # pragma: no cover
    from struct_controller import StructWorld  # type: ignore

try:
    from tests.legion_struct.causal_007 import attempt_authority as _auth
except ImportError:  # pragma: no cover
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "causal_007"))
    import attempt_authority as _auth  # type: ignore

logger = logging.getLogger("legion.struct")
GOVERNING_VERSION = "legion-struct-1"
SYSTEM = "legion-structural-world"
OWNED = frozenset({"ztl_state", "ztl_evidence_digest", "ztl_fact_id", "ql_directive", "ql_command_id",
                   "sre_actor", "sre_system", "assigned_agent", "confidence", "confidence_provenance",
                   "bound_attempt_uid", "bound_attempt_state", "bound_world_instance_id",
                   "bound_permit", "bound_permit_id", "bound_permit_epoch", "bound_authority_epoch",
                   "bound_permit_error", "bound_binding_ok", "bound_binding_code",
                   "bound_expected_args", "bound_binding_id", "bound_necessity"})
READINESS_PROVENANCE = "server_bound_independent_readback"
ZTL_BUDGET_S = 5.0


def canonical_json(o) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def action_name(task_id: str) -> str:
    return "struct_" + re.sub(r"[^A-Za-z0-9_]", "_", str(task_id))


def norm_id_for(task_id: str) -> str:
    return "struct." + str(task_id) + ".authority"


def judge_args_digest(tool: str, target, args) -> str:
    judge_args = {"target": target, "args": args}
    return hashlib.sha256(canonical_json({"tool": tool, "args": judge_args}).encode("utf-8")).hexdigest()


class StructNodes:
    """Write-task view of a world (mirrors scale_plugin.ScaleNodes)."""

    def __init__(self, world):
        self.world = world if isinstance(world, StructWorld) else StructWorld(world)
        self.spec = self.world.spec
        self.tasks = self.world.tasks
        self.write_tasks = self.world.write_tasks
        self.actions = {action_name(tid): tid for tid in sorted(self.write_tasks)}

    def task_for_action(self, action: str):
        tid = self.actions.get(action)
        return self.write_tasks.get(tid) if tid else None

    def norm_bindings(self) -> tuple[NormBinding, ...]:
        return tuple(NormBinding(norm_id=norm_id_for(tid), value=1.0, requires_warrant=True,
                                 actions=frozenset({action_name(tid)}), governing_version=GOVERNING_VERSION)
                     for tid in sorted(self.write_tasks))


def _authority_client():
    return _auth.client_from_env("gate")


def _attempt_snapshot() -> dict:
    """Live authority status (E6e). Files/env identity are never believed.

    Unreachable/unconfigured authority yields state=None, which every
    caller treats as DENY (absence of proof is never permission).
    """
    try:
        st = _authority_client().status()
        return {"attempt_uid": st.get("attempt_uid"),
                "world_instance_id": st.get("world_instance_id"),
                "state": st.get("state"), "epoch": st.get("epoch")}
    except Exception:
        return {"attempt_uid": None, "world_instance_id": None,
                "state": None, "epoch": None}


def _attempt_refusal(supplied_attempt_uid) -> str | None:
    """Authority refusal reason, or None. DENY by default (E6e)."""
    try:
        st = _authority_client().status()
    except Exception as exc:
        return (f"attempt authority unavailable ({exc}); DENY: "
                f"attempt_uid={supplied_attempt_uid!r} rejected")
    state = st.get("state")
    bound = st.get("attempt_uid")
    if state in ("COMPLETED", "INTERRUPTED"):
        return (f"attempt terminal ({state}): attempt_uid={supplied_attempt_uid!r} "
                f"rejected; gate refuses commits for terminal attempt {bound!r}")
    if state != "RUNNING":
        return (f"attempt identity refused: attempt is {state}, not RUNNING; "
                f"attempt_uid={supplied_attempt_uid!r} rejected")
    if supplied_attempt_uid and supplied_attempt_uid != bound:
        return (f"attempt identity mismatch: attempt_uid={supplied_attempt_uid!r} "
                f"is not the RUNNING attempt {bound!r}; gate refuses commits")
    return None


def _verified_binding_records(snap, spec):
    """Read native evidence, fail closed on missing or conflicting proof."""
    import hashlib
    import json
    import os
    from pathlib import Path

    if snap.get("state") != "RUNNING":
        raise ValueError("AUTHORITY_NOT_RUNNING")
    if type(snap.get("epoch")) is not int:
        raise ValueError("AUTHORITY_EPOCH_UNKNOWN")
    if not snap.get("attempt_uid") or not snap.get("world_instance_id"):
        raise ValueError("AUTHORITY_IDENTITY_UNKNOWN")

    run_dir = os.environ.get("STRUCT_RUN_DIR")
    world_file = os.environ.get("STRUCT_WORLD")

    if not run_dir or not world_file:
        raise ValueError("NATIVE_SOURCE_UNKNOWN")

    path = Path(run_dir) / "WORLD_LOG.jsonl"
    wf = Path(world_file)

    if not path.is_file() or not wf.is_file():
        raise ValueError("NATIVE_SOURCE_MISSING")

    raw = path.read_bytes()
    if not raw or not raw.endswith(bytes([10])):
        raise ValueError("INCOMPLETE_NATIVE_LOG")
    if len(raw) > 100_000_000:
        raise ValueError("NATIVE_LOG_LIMIT")

    records = []
    for line in raw.splitlines():
        if not line:
            raise ValueError("EMPTY_NATIVE_RECORD")
        record = json.loads(line)
        if not isinstance(record, dict):
            raise ValueError("INVALID_NATIVE_RECORD")
        records.append(record)

    if not records or records[0].get("kind") != "WORLD_START":
        raise ValueError("WORLD_START_MISSING")

    if sum(r.get("kind") == "WORLD_START" for r in records) != 1:
        raise ValueError("WORLD_START_NOT_UNIQUE")

    start = records[0]
    if start.get("world_id") != spec.get("world_id"):
        raise ValueError("WORLD_ID_MISMATCH")

    if start.get("world_sha256") != hashlib.sha256(
        wf.read_bytes()
    ).hexdigest():
        raise ValueError("WORLD_HASH_MISMATCH")

    for index, record in enumerate(records, 1):
        if type(record.get("seq")) is not int or (
            record["seq"] != index
        ):
            raise ValueError("NATIVE_SEQUENCE_INVALID")
        if record.get("attempt_uid") != snap["attempt_uid"]:
            raise ValueError("ATTEMPT_IDENTITY_MISMATCH")
        if record.get("world_instance_id") != (
            snap["world_instance_id"]
        ):
            raise ValueError("WORLD_INSTANCE_MISMATCH")
        if type(record.get("epoch")) is not int or (
            record["epoch"] != snap["epoch"]
        ):
            raise ValueError("NATIVE_EPOCH_MISMATCH")

    # Readback is independently recorded outside WORLD_LOG.
    # A WRITE is verified only when all three identity-linked
    # records are present: native effect, receipt, readback.
    rb_path = Path(run_dir) / "READBACK.jsonl"
    gate_path = Path(run_dir) / "GATE_COMMITS.jsonl"

    if not rb_path.exists():
        return records

    rb_raw = rb_path.read_bytes()
    if not rb_raw:
        return records

    if not gate_path.is_file():
        raise ValueError("GATE_EVIDENCE_MISSING")

    gate_raw = gate_path.read_bytes()

    if not rb_raw.endswith(bytes([10])):
        raise ValueError("TRUNCATED_READBACK")
    if not gate_raw or not gate_raw.endswith(bytes([10])):
        raise ValueError("INCOMPLETE_GATE_EVIDENCE")
    if len(rb_raw) > 10000000 or len(gate_raw) > 50000000:
        raise ValueError("EVIDENCE_SIZE_LIMIT")

    readbacks = [
        json.loads(line)
        for line in rb_raw.splitlines()
    ]
    gates = [
        json.loads(line)
        for line in gate_raw.splitlines()
    ]

    if not all(isinstance(r, dict) for r in readbacks + gates):
        raise ValueError("INVALID_EVIDENCE_RECORD")

    effects = {}
    receipts = {}

    for record in records:
        key = (
            record.get("effect_id"),
            record.get("command_id"),
        )
        if record.get("kind") == "NATIVE_EFFECT":
            if not all(key) or key in effects:
                raise ValueError("DUPLICATE_OR_INVALID_EFFECT")
            if record.get("permit_verified") is not True:
                raise ValueError("EFFECT_PERMIT_UNVERIFIED")
            effects[key] = record

        elif record.get("kind") == "RECEIPT":
            if not all(key) or key in receipts:
                raise ValueError("DUPLICATE_OR_INVALID_RECEIPT")
            if not record.get("receipt_id"):
                raise ValueError("RECEIPT_ID_MISSING")
            if record.get("permit_verified") is not True:
                raise ValueError("RECEIPT_PERMIT_UNVERIFIED")
            receipts[key] = record

    seen = set()
    now = __import__("time").monotonic()

    for index, rb in enumerate(readbacks, 1):
        if rb.get("kind") != "READBACK_EFFECT":
            raise ValueError("INVALID_READBACK_KIND")

        if type(rb.get("seq")) is not int or rb["seq"] != index:
            raise ValueError("READBACK_SEQUENCE_INVALID")

        if rb.get("confirmed") is not True:
            raise ValueError("READBACK_UNCONFIRMED")

        if rb.get("independent") is not True or (
            rb.get("provenance") != "struct_readback"
        ):
            raise ValueError("READBACK_PROVENANCE_UNVERIFIED")

        if rb.get("attempt_uid") != snap["attempt_uid"]:
            raise ValueError("READBACK_ATTEMPT_MISMATCH")

        if rb.get("world_instance_id") != snap["world_instance_id"]:
            raise ValueError("READBACK_WORLD_MISMATCH")

        if rb.get("epoch", snap["epoch"]) != snap["epoch"]:
            raise ValueError("READBACK_EPOCH_MISMATCH")

        state_hash = rb.get("state_sha256")
        if not isinstance(state_hash, str) or (
            len(state_hash) != 64
        ) or any(c not in "0123456789abcdef" for c in state_hash):
            raise ValueError("READBACK_DIGEST_INVALID")

        key = (
            rb.get("effect_id"),
            rb.get("command_id"),
        )

        if not all(key) or key in seen:
            raise ValueError("DUPLICATE_READBACK")

        seen.add(key)

        effect = effects.get(key)
        receipt = receipts.get(key)

        if effect is None or receipt is None:
            raise ValueError("READBACK_TRIPLET_MISSING")

        for field in (
            "task_id", "agent_id", "tool", "target",
            "permit_id", "permit_epoch",
        ):
            if effect.get(field) != receipt.get(field):
                raise ValueError(
                    "EFFECT_RECEIPT_MISMATCH:" + field
                )

        commits = [
            gate for gate in gates
            if gate.get("outcome") == "EXECUTED"
            and gate.get("effect_id") == key[0]
            and gate.get("command_id") == key[1]
            and gate.get("task_id") == effect["task_id"]
            and gate.get("attempt_uid") == snap["attempt_uid"]
            and gate.get("world_instance_id") == snap["world_instance_id"]
            and gate.get("epoch") == snap["epoch"]
            and gate.get("receipt_accepted") is True
        ]

        if len(commits) != 1:
            raise ValueError("GATE_COMMIT_NOT_VERIFIED")

        tm = rb.get("t_mono")
        receipt_tm = receipt.get("t_mono")

        if (
            type(tm) not in (float, int)
            or type(receipt_tm) not in (float, int)
            or tm < receipt_tm
            or tm > now + 1
        ):
            raise ValueError("READBACK_TIME_INVALID")

    # Merge by native monotonic time. Never mark a dependency
    # verified before its independent readback happened.
    combined = records + readbacks

    for record in combined:
        if type(record.get("t_mono")) not in (float, int):
            raise ValueError("EVIDENCE_TIME_MISSING")

    ordered = sorted(
        combined,
        key=lambda r: (
            r["t_mono"],
            1 if r.get("kind") == "READBACK_EFFECT" else 0,
        ),
    )

    # Do not consume a mixed snapshot while writers append.
    if (
        path.read_bytes() != raw
        or rb_path.read_bytes() != rb_raw
        or gate_path.read_bytes() != gate_raw
    ):
        raise ValueError("EVIDENCE_SNAPSHOT_CHANGED")

    return ordered


class StructInputResolver:
    owned_keys = OWNED

    def __init__(self, task_id: str, controller, nodes: StructNodes):
        self.task_id, self.controller, self.nodes = task_id, controller, nodes

    async def resolve(self, params: Mapping[str, Any]) -> Mapping[str, Any]:
        out: dict[str, Any] = {}
        # Server-bound attempt identity (E6c/F): bound from the attempt
        # registry file at call time, never from the caller. The HARD
        # tier compares the caller-supplied attempt_uid against this.
        snap = _attempt_snapshot()
        out.update(bound_attempt_uid=snap.get("attempt_uid"),
                   bound_attempt_state=snap.get("state"),
                   bound_world_instance_id=snap.get("world_instance_id"),
                   bound_authority_epoch=snap.get("epoch"))
        task = self.nodes.write_tasks[self.task_id]
        policy = WarrantContextPolicy.from_env()
        ctx, _ = policy.resolve(admitted_workload_identity())
        if ctx is not None:
            out.update(sre_actor=ctx.actor, sre_system=ctx.system)
        out["assigned_agent"] = task["agent_id"]
        try:
            import asyncio
            rec = await asyncio.wait_for(
                self.controller.evidence_verdict(self.task_id, params.get("args") or {}), ZTL_BUDGET_S)
            out.update(ztl_state=rec["state"], ztl_evidence_digest=rec["digest"], ztl_fact_id=rec["fact_id"])
        except Exception as exc:
            logger.warning("struct ZTL evidence unavailable for %s: %s", self.task_id, exc)
        d = await self.controller.directive_for(self.task_id)
        out.update(ql_directive=d["directive"], ql_command_id=d["command_id"])
        # E6e: fresh authority permit bound to task+command, gate-side only.
        permit, permit_err = None, None
        if snap.get("state") == "RUNNING" and d.get("command_id"):
            try:
                permit = _authority_client().request_permit(
                    task_id=self.task_id, command_id=d["command_id"])
            except Exception as exc:
                permit_err = str(exc)
        out.update(bound_permit=json.dumps(permit) if permit else None,
                   bound_permit_id=(permit or {}).get("permit_id"),
                   bound_permit_epoch=(permit or {}).get("epoch"),
                   bound_permit_error=permit_err)
        # WO008-03: server-bound semantic action binding, compiled fresh
        # from the public spec + the controller's verified WORLD_LOG
        # records (never from the caller, never from a hidden contract).
        # This only tightens the permit/ZTL checks above and below.
        try:
            import sys as _sys
            _c007 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "causal_007")
            if _c007 not in _sys.path:
                _sys.path.insert(0, _c007)
            from causal_007.action_binding import validate_action_binding as _vab
            from causal_007.causal_registry import CausalRegistry as _CR
            _spec = dict(self.nodes.spec)
            if snap.get("state") != "RUNNING" or type(snap.get("epoch")) is not int:
                raise ValueError("AUTHORITY_EPOCH_UNVERIFIED")
            _spec["epoch"] = snap["epoch"]
            if snap.get("attempt_uid"):
                _spec.setdefault("attempt_uid", snap.get("attempt_uid"))
            if snap.get("world_instance_id"):
                _spec.setdefault("world_instance_id", snap.get("world_instance_id"))
            _reg = _CR(_spec)
            _reg.ingest(_verified_binding_records(snap, _spec))
            _reg.reevaluate_activations()
            _okb, _codeb, _binding = _vab(
                _reg, self.task_id, tool=params.get("tool"),
                target=params.get("target"), args=params.get("args") or {},
                attempt_uid=params.get("attempt_uid") or None)
            out.update(bound_binding_ok=bool(_okb), bound_binding_code=_codeb,
                       bound_binding_id=_binding.binding_id,
                       bound_necessity=_binding.necessity,
                       bound_expected_args=(json.dumps(_binding.expected_args, sort_keys=True)
                                            if _binding.expected_args is not None else None))
        except Exception as exc:  # fail closed: uncompilable binding denies
            out.update(bound_binding_ok=False,
                       bound_binding_code=f"BINDING_UNAVAILABLE:{type(exc).__name__}",
                       bound_binding_id=None, bound_necessity="Z",
                       bound_expected_args=None)
        ready = out.get("ztl_state") == "ACCEPTED_TRUE" and bool(out.get("ztl_evidence_digest")) \
            and d["directive"] == "ACT"
        out.update(confidence=1.0 if ready else 0.0, confidence_provenance=READINESS_PROVENANCE)
        return out


class StructTaskTier(ReadOnlyTier):
    def __init__(self, nodes: StructNodes):
        self.nodes = nodes

    @property
    def tier_name(self) -> str:
        return "legion_struct_task"

    @property
    def order(self) -> int:
        return 0

    def claims_action(self, action: str, params: dict[str, Any]) -> bool:
        return isinstance(action, str) and action.startswith("struct_")

    async def evaluate(self, action: str, params: dict[str, Any]) -> list[Violation]:
        v: list[Violation] = []

        def hard(code, msg):
            v.append(Violation(tier=self.tier_name, code=code, message=f"[{code}] {msg}", kind=ViolationKind.HARD))

        task = self.nodes.task_for_action(action)
        if task is None:
            hard("UNKNOWN_TASK", f"action {action} maps to no write task")
            return v
        tid = task["task_id"]
        if params.get("task_id") != tid:
            hard("TASK_MISMATCH", f"task_id {params.get('task_id')!r} != {tid!r}")
        # E6e attempt binding (HARD, server-bound inputs): DENY by
        # default. A write needs a fresh authority permit verified here
        # (MAC, expiry, epoch == authority epoch, identity, task/command)
        # before any seal. Missing/unverifiable authority => DENY; there
        # is no admit-without-authority mode.
        bound_uid = params.get("bound_attempt_uid")
        bound_state = params.get("bound_attempt_state")
        if bound_state in ("COMPLETED", "INTERRUPTED"):
            hard("ATTEMPT_TERMINAL",
                 f"attempt {bound_uid!r} is terminal ({bound_state}); "
                 f"attempt_uid={params.get('attempt_uid')!r} rejected")
        elif bound_state != "RUNNING":
            hard("ATTEMPT_NOT_RUNNING",
                 f"attempt authority state is {bound_state!r}, not RUNNING; "
                 f"attempt_uid={params.get('attempt_uid')!r} rejected")
        elif params.get("attempt_uid") != bound_uid:
            hard("ATTEMPT_IDENTITY_MISMATCH",
                 f"attempt_uid {params.get('attempt_uid')!r} != "
                 f"RUNNING attempt {bound_uid!r}")
        _permit_raw = params.get("bound_permit")
        try:
            _permit = json.loads(_permit_raw) if isinstance(_permit_raw, str) else _permit_raw
        except ValueError:
            _permit = None
        if not isinstance(_permit, dict):
            hard("PERMIT_MISSING",
                 f"no authority permit bound for {tid} "
                 f"({params.get('bound_permit_error') or 'not issued'})")
        else:
            _reason = _auth.verify_permit(
                _auth.key_from_env(), _permit,
                attempt_uid=bound_uid,
                world_instance_id=params.get("bound_world_instance_id"),
                epoch=params.get("bound_authority_epoch"),
                task_id=tid, command_id=params.get("ql_command_id"))
            if _reason:
                hard("PERMIT_INVALID", f"authority permit refused for {tid}: {_reason}")
        st = params.get("ztl_state")
        if st != "ACCEPTED_TRUE" or not params.get("ztl_evidence_digest"):
            hard({"ACCEPTED_FALSE": "ZTL_EVIDENCE_CONTRADICTS",
                  "NOT_DECIDED_INSUFFICIENT": "ZTL_EVIDENCE_INSUFFICIENT",
                  "NOT_DECIDED_BOUND_BROKEN": "ZTL_BOUND_BROKEN"}.get(st, "ZTL_EVIDENCE_UNAVAILABLE"),
                 f"gate facts for {tid} state={st!r}")
        if params.get("ql_directive") != "ACT" or not params.get("ql_command_id"):
            hard("TASK_NOT_ELIGIBLE", f"directive {params.get('ql_directive')!r} for {tid}")
        if not params.get("sre_actor") or not params.get("sre_system"):
            hard("ACTOR_UNRESOLVED", "no admitted, mapped workload identity")
        if params.get("sre_actor") != task["agent_id"]:
            hard("ACTOR_ASSIGNED_MISMATCH",
                 f"actor {params.get('sre_actor')!r} != assigned {task['agent_id']!r}")
        if params.get("assigned_agent") != task["agent_id"]:
            hard("ASSIGNED_AGENT_MISMATCH", f"assigned_agent {params.get('assigned_agent')!r}")
        if params.get("tool") != task.get("write_tool"):
            hard("TOOL_MISMATCH", f"tool {params.get('tool')!r} != {task.get('write_tool')!r}")
        if params.get("target") != task.get("target"):
            hard("TARGET_MISMATCH", f"target {params.get('target')!r} != {task.get('target')!r}")
        # WO008-03: server-bound semantic binding (HARD). Only enforced
        # when the resolver bound it, so direct tier unit params without
        # a resolver keep their prior semantics; the real execution path
        # always binds it server-side before the seal.
        if "bound_binding_ok" in params:
            if params.get("bound_binding_ok") is not True:
                hard(str(params.get("bound_binding_code") or "BINDING_DENIED"),
                     f"semantic action binding refused for {tid}: "
                     f"{params.get('bound_binding_code')!r} necessity={params.get('bound_necessity')!r}")
            _exp = params.get("bound_expected_args")
            if _exp:
                try:
                    _exp_obj = json.loads(_exp) if isinstance(_exp, str) else _exp
                except ValueError:
                    _exp_obj = None
                if isinstance(_exp_obj, dict) and isinstance(params.get("args"), dict):
                    for _k, _v in _exp_obj.items():
                        if _v is not None and params["args"].get(_k) != _v:
                            hard("BINDING_ARGS_MISMATCH",
                                 f"arg {_k}={params['args'].get(_k)!r} != bound {_v!r} for {tid}")
        args = params.get("args")
        if not isinstance(args, dict):
            hard("ARGS_INVALID", "args must be an object")
        else:
            status, err = self.nodes.world.validate_args(task.get("write_tool"), args)
            if status != 200:
                hard("ARGS_INVALID", f"args invalid per public tool schema: {(err or {}).get('error')}")
        return v


class StructHttpActuator:
    actuator_id = "legion_struct_http_actuator"

    def __init__(self, url: str, actuator_token: str = ""):
        self.url = (url or "").rstrip("/")
        self.actuator_token = actuator_token

    async def health_check(self) -> bool:
        return True

    def get_capabilities(self) -> set:
        return set()

    async def actuate(self, clearance: ExecutionClearance) -> ActuationReceipt:
        p = clearance.params
        body = {"command_id": p.get("ql_command_id"), "task_id": p.get("task_id"),
                "agent_id": p.get("sre_actor") or p.get("assigned_agent"),
                "tool": p.get("tool"), "target": p.get("target"), "args": p.get("args") or {},
                "attempt_uid": p.get("bound_attempt_uid"),
                "world_instance_id": p.get("bound_world_instance_id"),
                "permit": json.loads(p["bound_permit"]) if p.get("bound_permit") else None}
        token = self.actuator_token or os.environ.get("STRUCT_ACTUATOR_TOKEN", "")
        try:
            async with httpx.AsyncClient(timeout=30) as c:
                r = await c.post(f"{self.url}/actuate", json=body,
                                 headers={"Authorization": f"Bearer {token}"})
            try:
                data = r.json()
            except ValueError:
                data = {}
        except Exception as exc:  # timeout (30s) etc: effect may have happened
            return ActuationReceipt(accepted=False, receipt_id=None, session_uuid=None, raw_receipt=None,
                                    findings=[{"code": "ACTUATION_UNKNOWN", "detail": type(exc).__name__}],
                                    outcome=ActuationOutcome.UNKNOWN)
        if r.status_code == 200 and isinstance(data, dict) and data.get("status") in ("applied", "duplicate"):
            effect_id = data.get("effect_id") or (data.get("effect") or {}).get("effect_id")
            return ActuationReceipt(accepted=True, receipt_id=effect_id, session_uuid=None,
                                    raw_receipt={"status": "executed", "effect": data.get("effect") or data})
        return ActuationReceipt(accepted=False, receipt_id=None, session_uuid=None, raw_receipt=data,
                                findings=[{"code": f"WORLD_{r.status_code}", "detail": str(data)[:200]}])


_GATE_LOCK = threading.Lock()
_GATE_SEQ = [0]


def _attempt_terminal() -> bool:
    return _attempt_snapshot().get("state") in ("COMPLETED", "INTERRUPTED")


def _gate_commit_log(rec: dict) -> None:
    path = os.environ.get("STRUCT_GATE_COMMITS") or os.environ.get("MINI_GATE_COMMITS")
    if not path:
        return
    if _attempt_terminal():
        # Post-terminal writers refuse every commit record -- except a
        # pure refusal record (BLOCKED, no seal issued, no command_id),
        # which is evidence OF the refusal and effects nothing. It is
        # appended (never overwritten) and carries the rejected identity
        # in rejected_attempt_uid / caller_args (E6c/F full-path proof).
        if not (rec.get("outcome") == "BLOCKED" and not rec.get("seal")
                and not rec.get("command_id")):
            return
    snap = _attempt_snapshot()

    # The journal's record epoch belongs to the authenticated
    # live Authority, not the static world specification.
    # A stale/mismatched permit must NEVER be relabeled.
    _journal_epoch = snap.get("epoch")
    _permit_epoch = rec.get("permit_epoch")

    _permit_epoch_matches = (
        _permit_epoch is None
        or (
            type(_permit_epoch) is int
            and _permit_epoch == _journal_epoch
        )
    )

    _executed_permit_valid = (
        rec.get("outcome") != "EXECUTED"
        or (
            rec.get("permit_verified") is True
            and type(_permit_epoch) is int
            and _permit_epoch == _journal_epoch
        )
    )

    if (
        snap.get("state") == "RUNNING"
        and type(_journal_epoch) is int
        and _permit_epoch_matches
        and _executed_permit_valid
    ):
        rec["epoch"] = _journal_epoch
    uid = snap.get("attempt_uid") or os.environ.get("STRUCT_ATTEMPT_UID")
    wid = snap.get("world_instance_id") or os.environ.get("STRUCT_WORLD_INSTANCE_ID")
    if uid:
        rec.setdefault("attempt_uid", uid)
    if wid:
        rec.setdefault("world_instance_id", wid)
    with _GATE_LOCK:
        _GATE_SEQ[0] += 1
        rec["seq"] = _GATE_SEQ[0]
        data = (json.dumps(rec, default=str) + "\n").encode("utf-8")
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("os.write wrote no bytes")
                view = view[written:]
        finally:
            os.close(fd)


def _admitted_agent(nodes: StructNodes):
    try:
        ctx, _ = WarrantContextPolicy.from_env().resolve(admitted_workload_identity())
        return ctx.actor if ctx is not None else None
    except Exception:
        return None


def _base_rec(mcp_tool, task_id, action, tool_caller, target, args, decision_ref, nodes):
    judge_args = {"target": target, "args": args}
    task = nodes.tasks.get(task_id) if task_id else None
    return {
        "t_start_mono": time.monotonic(), "t_end_mono": None, "mcp_tool": mcp_tool,
        "task_id": task_id, "action_name": action,
        "admitted_identity": admitted_workload_identity(),
        "agent_id": (task or {}).get("agent_id"),
        "caller_args": {"task_id": task_id, "tool": tool_caller, "target": target,
                        "args": args, "decision_ref": decision_ref},
        "judge_args": judge_args,
        "judge_args_digest": judge_args_digest(tool_caller, target, args),
        "decision_ref": decision_ref or None, "outcome": "ERROR", "detail": "",
        "request_id": str(uuid.uuid4()), "seal": None, "seal_sha256": None,
        "bound_params": {}, "effect_id": None, "receipt_accepted": None, "epoch": None,
    }


async def execute_struct_action(task_id: str, tool: str, target: str, args, decision_ref: str, *,
                                governor, controller, nodes: StructNodes,
                                attempt_uid: str = "") -> str:
    """world_write committing run (mirrors execute_scale_action's sequence).

    E6c/F: ``attempt_uid`` is the caller-supplied attempt identity. It is
    checked at the gate (before any seal) against the attempt registry
    and again by the HARD tier against server-bound inputs; a foreign,
    old, missing or post-terminal identity is BLOCKED with no seal, no
    command_id and no effect, and the refusal is gate-logged.
    """
    if isinstance(args, str):
        try:
            args_obj = json.loads(args) if args else {}
        except ValueError:
            args_obj = {}
            parse_error = "args_json is not valid JSON"
        else:
            parse_error = None if isinstance(args_obj, dict) else "args_json must be a JSON object"
            if not isinstance(args_obj, dict):
                args_obj = {}
    else:
        args_obj, parse_error = (args if isinstance(args, dict) else {}), None
    action = action_name(task_id) if task_id else None
    rec = _base_rec("world_write", task_id, action, tool, target, args_obj, decision_ref, nodes)
    rec["caller_args"]["attempt_uid"] = attempt_uid or None
    try:
        refusal = _attempt_refusal(attempt_uid or "")
        if refusal is not None:
            # Gate-tier attempt refusal: no seal, no command_id, no
            # actuation. Logged (append-only) as a BLOCKED record with
            # the rejected identity, even after a terminal state.
            rec["outcome"], rec["detail"] = "BLOCKED", refusal
            rec["rejected_attempt_uid"] = attempt_uid or None
            return f"BLOCKED: {refusal}"
        if parse_error:
            rec["outcome"], rec["detail"] = "BLOCKED", parse_error
            return f"BLOCKED: {parse_error}"
        out = await _execute(task_id, tool, target, args_obj, decision_ref, rec,
                             governor=governor, controller=controller, nodes=nodes,
                             attempt_uid=attempt_uid or "")
        rec["outcome"], rec["detail"] = out.split(":", 1)[0], out[:500]
        return out
    finally:
        rec["t_end_mono"] = time.monotonic()
        _gate_commit_log(rec)


async def _execute(task_id, tool, target, args, decision_ref, rec, *, governor, controller, nodes,
                   attempt_uid: str = "") -> str:
    from src.gateway.governance.routing_seal import SymbolicGovernorViolation, verify_and_consume_seal
    task = nodes.write_tasks.get(task_id)
    if task is None:
        return f"BLOCKED: unknown task {task_id!r}"
    action = action_name(task_id)
    params: dict[str, Any] = {"task_id": task_id, "tool": tool, "target": target,
                              "args": args, "request_id": rec["request_id"],
                              "attempt_uid": attempt_uid}
    if decision_ref:
        params["decision_ref"] = decision_ref
    params = await bind_server_inputs(governor.components.server_inputs, action, params)
    # WO008-03: execute_struct_action independently refuses an unbound /
    # out-of-contract action before any seal is requested. The HARD tier
    # re-checks the same server-bound binding; neither replaces CAGE/VEIP.
    if params.get("bound_binding_ok") is not True and "bound_binding_ok" in params:
        rec["outcome"] = "BLOCKED"
        return (f"BLOCKED: semantic action binding refused for {task_id}: "
                f"{params.get('bound_binding_code')!r}")
    # Evidence completeness (WO-006 invariant): the logged bound_params
    # are EXACTLY the params the routing seal commits to, permit included.
    # Stripping any sealed field would make the seal unverifiable from
    # evidence and the effect unauthorized to a post-hoc auditor.
    rec["bound_params"] = dict(params)
    rec["permit_id"] = params.get("bound_permit_id")
    rec["permit_epoch"] = params.get("bound_permit_epoch")
    rec["permit_verified"] = bool(params.get("bound_permit"))
    try:
        seal = await enforce_governance(governor, action, params)
    except ActionDeferred as exc:
        return f"DEFERRED: {exc}"
    except PermissionError as exc:
        return f"BLOCKED: {exc}"
    if not isinstance(seal, str) or not seal.strip():
        raise SymbolicGovernorViolation(f"CRITICAL: {action} invoked without mandatory routing seal.", action=action)
    rec["seal"], rec["seal_sha256"] = seal, hashlib.sha256(seal.encode()).hexdigest()
    rec["command_id"] = params.get("ql_command_id")  # only once a seal was issued
    executed, claimed, receipt = False, "", None
    try:
        try:
            await verify_and_consume_seal(seal, action, params)
        except SymbolicGovernorViolation:
            return "BLOCKED: routing seal invalid, expired, or already consumed — governance authority unresolved."
        try:
            claim = await controller.begin(task_id, params["ql_command_id"])
            claimed = params["ql_command_id"]
            rec["epoch"] = claim.get("epoch") if isinstance(claim, dict) else None
        except Exception as exc:
            return f"BLOCKED: task claim refused ({exc})"
        clearance = ExecutionClearance(
            thread_id=params["request_id"], decision="ALLOW", decision_path="DIRECT", action=action, target=target,
            operator_urn=str(params.get("sre_actor")), issued_at=int(time.time()), issued_at_provenance="CONSTRUCTION_TIME",
            correlation_id=params["request_id"], correlation_id_source="THREAD_DERIVED", governance_decision_digest=seal,
            opa_input_digest=hashlib.sha256(canonical_json(params).encode()).hexdigest(), nonce=uuid.uuid4().hex,
            params=params, executor_id=StructHttpActuator.actuator_id, target_route="local://legion-struct",
            approvals=[], required_quorum=0, routing_seal=seal)
        actuator = get_actuator_registry().get_actuator(action)
        if actuator is None:
            raise SymbolicGovernorViolation(f"CRITICAL: No actuator registered for {action}.", action=action)
        receipt = await dispatch_actuation(actuator, clearance)
        executed = receipt.may_have_executed
        rec["effect_id"], rec["receipt_accepted"] = receipt.receipt_id, receipt.accepted
        if receipt.outcome is ActuationOutcome.UNKNOWN:
            await controller.mark_unknown(task_id, claimed)
            await controller.reconcile(task_id, claimed)
            claimed = ""
            return f"UNKNOWN: actuation outcome unknown; command_id={params['ql_command_id']}; reconcile before retrying"
        closed = await controller.close(task_id, claimed)
        claimed = ""
        if not receipt.accepted:
            return f"BLOCKED: actuation not accepted ({receipt.findings}); task_closed={closed.get('closed')}"
        return (f"EXECUTED: world_write {task_id} {tool} target={target} "
                f"command_id={params['ql_command_id']} effect_id={receipt.receipt_id}")
    finally:
        if claimed:
            controller.release(claimed)
        failures = await governor.settle(seal, executed=executed)
        for f in failures:
            logger.critical("%s settlement failed: %s", action, f.message)


async def execute_declare_refusal(task_id: str, reason: str, decision_ref: str, *,
                                  governor=None, controller, nodes: StructNodes) -> str:
    """declare_refusal: never mutates the world; gate-logged only."""
    args = {"reason": reason}
    rec = _base_rec("declare_refusal", task_id, None, "declare_refusal", None, args, decision_ref, nodes)
    try:
        task = nodes.tasks.get(task_id)
        actor = _admitted_agent(nodes)
        rec["agent_id"] = actor or (task or {}).get("agent_id")
        if task is None:
            rec["outcome"], rec["detail"] = "BLOCKED", f"unknown task {task_id!r}"
            return f"BLOCKED: unknown task {task_id!r}"
        if "REFUSE" not in (task.get("kinds") or []):
            rec["outcome"], rec["detail"] = "BLOCKED", f"task {task_id} does not allow REFUSE"
            return f"BLOCKED: task {task_id} does not allow REFUSE"
        if actor != task.get("agent_id"):
            rec["outcome"], rec["detail"] = "BLOCKED", \
                f"admitted agent {actor!r} is not the assigned agent {task.get('agent_id')!r}"
            return f"BLOCKED: admitted identity is not the assigned agent for {task_id}"
        if controller is not None and hasattr(controller, "note_gate_refusal"):
            controller.note_gate_refusal(task_id)
        rec["outcome"], rec["detail"] = "REFUSED_BY_AGENT", str(reason)[:500]
        return "REFUSED_BY_AGENT: recorded"
    finally:
        rec["t_end_mono"] = time.monotonic()
        _gate_commit_log(rec)


class StructToolProvider:
    def __init__(self, inner, controller, nodes: StructNodes):
        self.inner, self.controller, self.nodes = inner, controller, nodes

    def register_tools(self, server, governor) -> None:
        if self.inner is not None:
            self.inner.register_tools(server, governor)
        ctl, nodes = self.controller, self.nodes

        @server.tool(name="world_write", description="Governed write to the structural world for one write task.")
        async def _world_write(task_id: str, tool: str, target: str, args_json: str, decision_ref: str = "",
                               attempt_uid: str = "") -> str:
            return await execute_struct_action(task_id, tool, target, args_json, decision_ref,
                                               governor=governor, controller=ctl, nodes=nodes,
                                               attempt_uid=attempt_uid)

        @server.tool(name="declare_refusal", description="Record an assigned agent's refusal for a REFUSE task (never mutates the world).")
        async def _declare_refusal(task_id: str, reason: str, decision_ref: str = "") -> str:
            return await execute_declare_refusal(task_id, reason, decision_ref,
                                                 governor=governor, controller=ctl, nodes=nodes)


def composed_ftra_registry(src_path, out_path, nodes: StructNodes) -> str:
    from src.gateway.governance.ftra.classifier import registry_digest
    raw = json.loads(open(src_path).read())
    raw["terminals"] = {**raw["terminals"], **{action_name(tid): "REVERSIBLE" for tid in nodes.write_tasks}}
    raw["manifest_sha256"] = registry_digest(raw)
    open(out_path, "w").write(json.dumps(raw, indent=1))
    return raw["manifest_sha256"]


def register_actuator(url: str, actuator_token: str, nodes: StructNodes) -> None:
    if not nodes.actions:
        return
    reg = get_actuator_registry()
    if StructHttpActuator.actuator_id not in reg.list_actuators():
        reg.register(StructHttpActuator(url, actuator_token), claims=set(nodes.actions))
    else:
        reg._claims[StructHttpActuator.actuator_id] |= set(nodes.actions)
        act = reg.get_actuator(next(iter(nodes.actions)))
        act.url, act.actuator_token = (url or "").rstrip("/"), actuator_token


def compose(contribution: PluginContribution, controller, nodes: StructNodes) -> PluginContribution:
    si = dict(contribution.server_inputs)
    for tid in nodes.write_tasks:
        si[action_name(tid)] = StructInputResolver(tid, controller, nodes)
    return dataclasses.replace(
        contribution,
        tiers=tuple(contribution.tiers) + (StructTaskTier(nodes),),
        server_inputs=si,
        norm_bindings=tuple(contribution.norm_bindings) + nodes.norm_bindings(),
        registered_actions=frozenset(contribution.registered_actions) | frozenset(nodes.actions),
        tool_provider=StructToolProvider(contribution.tool_provider, controller, nodes),
    )
