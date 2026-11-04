"""WP-A/WP-D: authoritative causal obligation registry (pure, deterministic).

Derived ONLY from the public world spec plus independently logged records
(world WORLD_LOG records, gate REFUSED_BY_AGENT records, native effects).
A successful tool call is NOT closure: every obligation kind has its own
closure condition, and evidence taken before its dependencies were confirmed
is recorded as STALE and never closes the task (the agent must re-do it).

States per obligation: PENDING (deps open) -> ELIGIBLE (deps confirmed,
no closing evidence yet) -> CONFIRMED (closure evidence) ; REFUSED is the
terminal state for a REFUSE obligation closed by a gate refusal record.
No hidden Judge data is read anywhere in this module.

WO008-02 earned closure (actual producer schemas, not a second format):
- ``NATIVE_EFFECT`` (world_server /actuate WORLD_LOG): ``{effect_id,
  command_id, task_id, agent_id, tool, target, args, permit_id,
  permit_epoch, permit_verified, attempt_uid, world_instance_id, seq}``.
- ``RECEIPT`` (same WORLD_LOG, immediately after the effect): ``{receipt_id,
  effect_id, command_id, task_id, agent_id, tool, target, args, permit_id,
  permit_epoch, permit_verified, attempt_uid, world_instance_id}``.
- ``READBACK_EFFECT`` (struct_readback READBACK.jsonl, independent process):
  ``{effect_id, command_id, confirmed, state_sha256, attempt_uid,
  world_instance_id, seq}`` (task/agent may be absent; matched by
  effect/command identity).
WRITE is VERIFIED only when all three agree on attempt/world/epoch/
command/effect identity; an effect alone is EXECUTED_UNVERIFIED.
READ tasks may declare ``evidence_predicates=[{field, equals}]`` (type-strict,
evaluated on observation ``facts``); COMMUNICATE tasks may declare
``content_propositions=[{field, equals}]`` (asserted message facts/body must
equal them and the values must occur in confirmed dependency evidence).

WO008-01: every obligation carries explicit REQUIRED / CONDITIONAL /
OPTIONAL semantics compiled ONLY from the public spec. A task/tool merely
being listed is not proof of necessity: a CONDITIONAL task is mandatory
only when activation=T is grounded in public instructions / verified
(confirmed) evidence; activation=F means NOT_APPLICABLE (never blocks
EXIT); activation=Z blocks its WRITE, and blocks EXIT when the task is
marked requires_resolution. OPTIONAL tasks never block EXIT and never
authorize a WRITE by mere presence.
"""
from __future__ import annotations

import copy

KINDS = ("READ", "ANALYZE", "COMMUNICATE", "WAIT", "WRITE", "REFUSE", "RECONCILE", "DONE")
# world-log record kind that can close each obligation kind (WRITE via effect)
_RECORD_FOR = {"READ": "OBSERVATION", "ANALYZE": "ANALYSIS_RECORD",
               "COMMUNICATE": "MESSAGE_DELIVERED", "WAIT": "WAIT_OBSERVED",
               "RECONCILE": "RECONCILE", "DONE": "AGENT_DONE"}

REQUIREMENTS = ("REQUIRED", "CONDITIONAL", "OPTIONAL")
CLASSIFICATION_VERSION = "wo008-01-v1"
_CONDITIONAL_MARKERS = ("only if", "only when", "last resort", "emergency")
_ACTIVATION_ALIASES = {"T": "T", "TRUE": "T", "ACTIVE": "T", "ACTIVATED": "T",
                       "F": "F", "FALSE": "F", "INACTIVE": "F",
                       "NOT_APPLICABLE": "F", "Z": "Z", "UNKNOWN": "Z",
                       "UNRESOLVED": "Z", "": "Z"}


def _norm_activation(value):
    if value is True:
        return "T"
    if value is False:
        return "F"
    if value is None:
        return "Z"
    return _ACTIVATION_ALIASES.get(str(value).strip().upper(), "Z")


def _compile_requirement(task):
    """(requirement, activation, predicate, source, explicit) from PUBLIC spec.

    Explicit spec fields win; otherwise the task's own public brief is the
    classification source (conditional phrasing -> CONDITIONAL, 'optional'
    -> OPTIONAL, else REQUIRED). Hidden Judge data is never consulted.
    """
    tid = task.get("task_id")
    brief = str(task.get("brief") or "")
    low = brief.lower()
    raw_req = task.get("requirement") or task.get("mode") or task.get("obligation_type")
    explicit = raw_req is not None and str(raw_req).strip().upper() in REQUIREMENTS
    if explicit:
        requirement = str(raw_req).strip().upper()
        source = f"public:spec:task:{tid}:requirement"
    elif any(m in low for m in _CONDITIONAL_MARKERS):
        requirement, source = "CONDITIONAL", f"public:spec:task:{tid}:brief"
    elif "optional" in low:
        requirement, source = "OPTIONAL", f"public:spec:task:{tid}:brief"
    else:
        requirement, source = "REQUIRED", f"public:spec:task:{tid}:brief"
    predicate = task.get("activation_predicate") or (brief if requirement == "CONDITIONAL" else None)
    if "activation" in task or "activation_status" in task:
        activation = _norm_activation(task.get("activation", task.get("activation_status")))
    else:
        activation = {"REQUIRED": "T", "OPTIONAL": "F", "CONDITIONAL": "Z"}[requirement]
    return requirement, activation, predicate, task.get("activation_source") or source, explicit


def _flatten_values(obj, out):
    if isinstance(obj, dict):
        for v in obj.values():
            _flatten_values(v, out)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _flatten_values(v, out)
    elif isinstance(obj, (str, int, float)) and not isinstance(obj, bool):
        out.add(obj)
        out.add(str(obj))


def _find_regions(obj):
    """The ``regions`` mapping of a facts dict, wherever nested, or None."""
    if isinstance(obj, dict):
        regs = obj.get("regions")
        if isinstance(regs, dict):
            return regs
        for v in obj.values():
            found = _find_regions(v)
            if found is not None:
                return found
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            found = _find_regions(v)
            if found is not None:
                return found
    return None


class Obligation:
    def __init__(self, task, agent_id):
        self.task = copy.deepcopy(task)
        self.task_id = task["task_id"]
        self.agent_id = agent_id
        self.kinds = [k for k in (task.get("kinds") or []) if k in KINDS]
        self.depends_on = list(task.get("depends_on") or [])
        self.required_read_tools = list(task.get("required_read_tools") or [])
        if "cart flow" in str(task.get("brief") or "").lower() \
                and "probe.cart_flow" in (task.get("read_tools") or []):
            self.required_read_tools = ["probe.cart_flow"]
        self.satisfied = {}          # kind -> closing record
        self.stale = []              # records rejected as premature/insufficient
        self.ignored_stale_refs = []  # stale refs tolerated by an admitted ANALYZE (P0-12)
        self.refused = False
        (self.requirement, self.activation, self.activation_predicate,
         self.activation_source, explicit) = _compile_requirement(task)
        self.classification_version = CLASSIFICATION_VERSION
        self.activation_evidence_refs = list(
            task.get("activation_evidence_refs") or task.get("evidence_refs") or [])
        self.activation_epoch = task.get("activation_epoch", task.get("evidence_epoch"))
        # A conditional whose truth must be established before DONE. Explicit
        # spec classifications default to critical; alternatives compiled from
        # a public brief do not block EXIT unless the spec says they must.
        if "requires_resolution" in task:
            self.requires_resolution = bool(task["requires_resolution"])
        else:
            self.requires_resolution = bool(explicit and self.requirement == "CONDITIONAL")
        # WO008-02 WRITE lifecycle: PENDING -> ELIGIBLE -> ADMITTED ->
        # EXECUTED_UNVERIFIED -> VERIFIED (see CausalRegistry.write_status).
        self.write_state = "PENDING"
        self.success_predicate_status = "Z"  # T proven / Z unestablished
        self.write_evidence = {}   # slot -> verified-triplet record
        self.write_pending = {}    # slot -> record awaiting its triplet peers
        self.admission = None
        self.activation_seq = -1
        # Origin of the current activation value: "spec" (explicit public
        # spec field, never overridden by inference), "manual" (an explicit
        # resolve_activation call), "derived" (runtime evaluation of the
        # structured predicate against verified observations) or "default".
        self.activation_origin = (
            "spec" if ("activation" in task or "activation_status" in task)
            else "default")
        self.activation_auto = False

    @property
    def is_active_mandatory(self):
        return self.requirement == "REQUIRED" or (
            self.requirement == "CONDITIONAL" and self.activation == "T")

    @property
    def not_applicable(self):
        return self.requirement == "OPTIONAL" or (
            self.requirement == "CONDITIONAL" and self.activation == "F")

    @property
    def confirmed(self):
        # A recorded refusal is a terminal alternative for a REFUSE-capable
        # task (e.g. WRITE|REFUSE): declining closes it without the write.
        if self.refused and "REFUSE" in self.kinds:
            return True
        return bool(self.kinds) and all(k in self.satisfied for k in self.kinds)

    @property
    def status(self):
        return "CONFIRMED" if self.confirmed else "OPEN"


class CausalRegistry:
    """Single obligation registry for one world instance."""

    def __init__(self, spec):
        self.spec = copy.deepcopy(spec)
        self.world_id = self.spec.get("world_id")
        self.tools = self.spec.get("tools") or {}
        self.obligations = {}        # task_id -> Obligation
        self.by_agent = {}
        for role in self.spec.get("roles") or []:
            agent = role.get("agent_id")
            for task in role.get("tasks") or []:
                ob = Obligation(task, agent)
                self.obligations[ob.task_id] = ob
                self.by_agent.setdefault(agent, []).append(ob.task_id)
        self.observations = {}       # observation_id -> record (+_confirmed flag)
        self.records = []            # all ingested records, in order
        self._seq = 0
        self.confirm_seq = {}        # task_id -> seq at which it confirmed
        # WO008-02: expected provenance + evidence-feed integrity state.
        self.attempt_uid = self.spec.get("attempt_uid")
        self.world_instance_id = (self.spec.get("world_instance_id")
                                  or self.spec.get("world_id"))
        # Only an explicitly spec-bound instance is an expected identity;
        # otherwise triplet parts are cross-checked against each other
        # (real world instance ids are runtime-generated, not in the spec).
        self.expected_world_instance_id = self.spec.get("world_instance_id")
        self.feed_unavailable = False
        self.feed_error = None
        self._orphan_write_parts = []  # receipt/readback seen before effect
        try:
            self.epoch = int(self.spec.get("epoch") or 1)
        except (TypeError, ValueError):
            self.epoch = 1

    # ---------------------------------------------------------- ingestion
    def ingest(self, records, gate_records=(), effects=()):
        """Fold logged records (in log order) into causal state."""
        combined = list(records or [])
        for rec in combined:
            self._ingest_one(rec)
        for rec in gate_records or []:
            if rec.get("outcome") == "REFUSED_BY_AGENT" and rec.get("task_id"):
                self.note_gate_refusal(rec["task_id"])
        for eff in effects or []:
            if eff.get("task_id"):
                rec = {"kind": "NATIVE_EFFECT", "task_id": eff.get("task_id"),
                       "agent_id": eff.get("agent_id"),
                       "effect_id": eff.get("effect_id"),
                       "command_id": eff.get("command_id")}
                for k in ("attempt_uid", "world_instance_id", "epoch",
                          "permit_epoch", "tool", "target", "args"):
                    if eff.get(k) is not None:
                        rec[k] = eff.get(k)
                self._ingest_one(rec)
                # A ledger entry may carry its receipt/readback peers.
                for peer in ("receipt", "readback"):
                    p = eff.get(peer)
                    if isinstance(p, dict):
                        self._ingest_one(p)
        return self

    # --------------------------------------------------- WO008-02 evidence
    def set_feed_unavailable(self, unavailable, reason=None):
        self.feed_unavailable = bool(unavailable)
        self.feed_error = reason if unavailable else None

    @staticmethod
    def _explicit_epoch(rec):
        return rec.get("epoch")

    @staticmethod
    def _any_epoch(rec):
        e = rec.get("epoch")
        return e if e is not None else rec.get("permit_epoch")

    def _identity_error(self, rec, effect, slot):
        """None if rec may belong to effect's triplet, else a reason string."""
        for field, label in (("effect_id", "effect_id"), ("command_id", "command_id")):
            if not rec.get(field):
                return f"{slot}_IDENTITY_MISSING:{label}"
            if effect is not None and rec.get(field) != effect.get(field):
                return f"{slot}_IDENTITY_MISMATCH:{label}"
        if effect is not None:
            if rec.get("task_id") and effect.get("task_id") and \
                    rec.get("task_id") != effect.get("task_id"):
                return f"{slot}_IDENTITY_MISMATCH:task_id"
            if rec.get("agent_id") and effect.get("agent_id") and \
                    rec.get("agent_id") != effect.get("agent_id"):
                return f"{slot}_IDENTITY_MISMATCH:agent_id"
            ra, ea = rec.get("attempt_uid"), effect.get("attempt_uid")
            if ra and ea and ra != ea:
                return f"{slot}_IDENTITY_MISMATCH:attempt_uid"
            rw, ew = rec.get("world_instance_id"), effect.get("world_instance_id")
            if rw and ew and rw != ew:
                return f"{slot}_IDENTITY_MISMATCH:world_instance_id"
            re_, ee = self._any_epoch(rec), self._any_epoch(effect)
            if re_ is not None and ee is not None and re_ != ee:
                return f"{slot}_IDENTITY_MISMATCH:epoch"
        if self.attempt_uid and rec.get("attempt_uid") and \
                rec.get("attempt_uid") != self.attempt_uid:
            return f"{slot}_IDENTITY_MISMATCH:attempt_uid"
        if self.expected_world_instance_id and rec.get("world_instance_id") and \
                rec.get("world_instance_id") != self.expected_world_instance_id:
            return f"{slot}_IDENTITY_MISMATCH:world_instance_id"
        exp = self._explicit_epoch(rec)
        if exp is not None and exp != self.epoch:
            return f"{slot}_IDENTITY_MISMATCH:epoch"
        return None

    def _try_verify_write(self, ob):
        if ob.write_state == "VERIFIED" or "WRITE" in ob.satisfied:
            return
        eff = ob.write_pending.get("effect")
        rcpt = ob.write_pending.get("receipt")
        rb = ob.write_pending.get("readback")
        if not (eff and rcpt and rb):
            return
        for slot, part in (("RECEIPT", rcpt), ("READBACK", rb)):
            err = self._identity_error(part, eff, slot)
            if err:
                ob.stale.append({"record": part, "reason": err})
                ob.write_pending.pop(slot.lower(), None)
                return
        ob.write_evidence = {"effect": eff, "receipt": rcpt, "readback": rb}
        ob.satisfied["WRITE"] = {
            "kind": "WRITE_VERIFIED", "effect_id": eff.get("effect_id"),
            "command_id": eff.get("command_id"),
            "receipt_id": rcpt.get("receipt_id"),
            "effect": eff, "receipt": rcpt, "readback": rb}
        ob.write_state = "VERIFIED"
        self._mark_confirm(ob.task_id)

    def _ingest_write_part(self, rec):
        kind = rec.get("kind")
        slot = {"NATIVE_EFFECT": "effect", "RECEIPT": "receipt",
                "READBACK_EFFECT": "readback"}[kind]
        slot_label = slot.upper()
        ob = self.obligations.get(rec.get("task_id") or "")
        if ob is None and slot != "effect":
            # Independent readback records may carry no task_id: match by
            # effect/command identity against a pending effect.
            for cand in self.obligations.values():
                eff = cand.write_pending.get("effect")
                if eff and eff.get("effect_id") == rec.get("effect_id") and \
                        eff.get("command_id") == rec.get("command_id"):
                    ob = cand
                    break
        if ob is None:
            if slot != "effect":
                self._orphan_write_parts.append(rec)
            return
        if "WRITE" not in ob.kinds:
            return
        if rec.get("agent_id") not in (None, ob.agent_id):
            ob.stale.append({"record": rec, "reason": "WRONG_AGENT"})
            return
        if ob.not_applicable:
            ob.stale.append({"record": rec, "reason": "NOT_APPLICABLE"})
            return
        if ob.refused and "REFUSE" in ob.kinds:
            # WO008-04: a recorded refusal is a terminal consequence. Later
            # (possibly fabricated) WRITE evidence cannot resurrect the
            # refused task into a successful consequential outcome.
            ob.stale.append({"record": rec, "reason": "REFUSAL_TERMINAL_WRITE_EVIDENCE_REJECTED"})
            return
        if "WRITE" in ob.satisfied or ob.write_state == "VERIFIED":
            ob.stale.append({"record": rec, "reason": f"DUPLICATE_WRITE_EVIDENCE:{slot}"})
            return
        if slot == "effect":
            if not rec.get("effect_id") or not rec.get("command_id"):
                ob.stale.append({"record": rec, "reason": "EFFECT_IDENTITY_MISSING"})
                return
            err = self._identity_error(rec, None, "EFFECT")
            if err:
                ob.stale.append({"record": rec, "reason": err})
                return
            existing = ob.write_pending.get("effect")
            if existing is not None:
                ob.stale.append({"record": rec, "reason": "DUPLICATE_WRITE_EVIDENCE:effect"})
                return
            if ob.requirement == "CONDITIONAL" and ob.activation != "T":
                ob.stale.append({"record": rec, "reason": "ACTIVATION_UNRESOLVED"})
                return
            if not self._deps_were_confirmed(ob):
                ob.stale.append({"record": rec, "reason": "PREMATURE_WRITE"})
                return
            ob.write_pending["effect"] = rec
            ob.write_state = "EXECUTED_UNVERIFIED"
            # Attach any receipt/readback that arrived before the effect.
            for orphan in list(self._orphan_write_parts):
                if orphan.get("effect_id") == rec.get("effect_id") and \
                        orphan.get("command_id") == rec.get("command_id"):
                    self._orphan_write_parts.remove(orphan)
                    self._ingest_write_part(orphan)
            for pending_slot in ("receipt", "readback"):
                part = ob.write_pending.get(pending_slot)
                if part is not None:
                    err = self._identity_error(part, rec, pending_slot.upper())
                    if err:
                        ob.stale.append({"record": part, "reason": err})
                        ob.write_pending.pop(pending_slot, None)
            self._try_verify_write(ob)
            return
        # receipt / readback slots
        if slot == "receipt":
            if not rec.get("receipt_id"):
                ob.stale.append({"record": rec, "reason": "RECEIPT_IDENTITY_MISSING:receipt_id"})
                return
            if "permit_verified" in rec and rec.get("permit_verified") is not True:
                ob.stale.append({"record": rec, "reason": "RECEIPT_UNVERIFIED"})
                return
        if slot == "readback" and rec.get("confirmed") is not True:
            ob.stale.append({"record": rec, "reason": "READBACK_UNCONFIRMED"})
            return
        if slot in ob.write_pending:
            ob.stale.append({"record": rec, "reason": f"DUPLICATE_WRITE_EVIDENCE:{slot}"})
            return
        eff = ob.write_pending.get("effect")
        if eff is not None:
            err = self._identity_error(rec, eff, slot_label)
            if err:
                ob.stale.append({"record": rec, "reason": err})
                return
        else:
            err = self._identity_error(rec, None, slot_label)
            if err:
                ob.stale.append({"record": rec, "reason": err})
                return
        ob.write_pending[slot] = rec
        if eff is not None:
            ob.write_state = "EXECUTED_UNVERIFIED"
            self._try_verify_write(ob)

    def write_status(self, task_id):
        ob = self.obligations.get(task_id)
        if ob is None:
            return "UNKNOWN"
        if "WRITE" not in ob.kinds:
            return self.state_of(task_id)
        if ob.confirmed and "WRITE" in ob.satisfied:
            return "VERIFIED"
        if ob.write_state == "EXECUTED_UNVERIFIED":
            return "EXECUTED_UNVERIFIED"
        if ob.write_state == "ADMITTED":
            return "ADMITTED"
        return "ELIGIBLE" if self.deps_confirmed(task_id) and \
            ob.is_active_mandatory else "PENDING"

    def independent_write_status(self, task_id, independent_state_sha256=None,
                                 independent_effect_ids=None):
        """VERIFIED only on genuinely independent readback provenance.

        The ordinary VERIFIED triplet may come from a synthetic in-process
        host (isolated tests); that is not independence. A readback whose
        provenance is ``synthetic_host`` / ``independent is False``, whose
        state hash does not match an independently observed state, or whose
        effect is absent from an independently observed ledger stays
        UNVERIFIED here even when ``write_status`` is VERIFIED.
        """
        if self.write_status(task_id) != "VERIFIED":
            return "UNVERIFIED"
        ob = self.obligations.get(task_id)
        ev = (ob.satisfied.get("WRITE") or {}) if ob else {}
        readback = ev.get("readback") or {}
        if readback.get("provenance") == "synthetic_host" or \
                readback.get("independent") is False:
            return "UNVERIFIED"
        if readback.get("independent") is not True and \
                readback.get("provenance") not in ("struct_readback", "independent_process"):
            return "UNVERIFIED"
        if readback.get("confirmed") is not True:
            return "UNVERIFIED"
        if independent_state_sha256 is not None and \
                readback.get("state_sha256") != independent_state_sha256:
            return "UNVERIFIED"
        if independent_effect_ids is not None and \
                ev.get("effect_id") not in set(independent_effect_ids):
            return "UNVERIFIED"
        return "VERIFIED"

    def note_write_admitted(self, task_id, agent_id=None, command_id=None):
        ob = self.obligations.get(task_id)
        if ob is None or "WRITE" not in ob.kinds:
            return False
        if ob.write_state in ("EXECUTED_UNVERIFIED", "VERIFIED"):
            return False
        if not self.deps_confirmed(task_id) or not ob.is_active_mandatory:
            return False
        ob.write_state = "ADMITTED"
        ob.admission = {"task_id": task_id, "agent_id": agent_id,
                        "command_id": command_id, "seq": self._seq}
        return True

    # -- structured evidence predicates (READ / COMMUNICATE) ------------
    @staticmethod
    def _lookup(facts, field):
        value = facts
        for key in str(field).split("."):
            if not isinstance(value, dict) or key not in value:
                return False, None
            value = value[key]
        return True, value

    @classmethod
    def _predicates(cls, task, *names):
        raw = None
        for n in names:
            if task.get(n) is not None:
                raw = task.get(n)
                break
        if raw is None:
            return []
        if isinstance(raw, dict):
            # {"field":..., "equals":...} single, or {field: expected} map
            if "field" in raw or "path" in raw:
                return [raw]
            return [{"field": k, "equals": v} for k, v in raw.items()]
        return list(raw) if isinstance(raw, (list, tuple)) else []

    def _eval_predicates(self, facts, predicates):
        """(ok, failed_field). Type-strict equality, fail closed."""
        if not isinstance(facts, dict):
            return False, "<facts>"
        for pred in predicates:
            if not isinstance(pred, dict):
                return False, "<predicate>"
            field = pred.get("field") or pred.get("path")
            if not field:
                return False, "<predicate>"
            op = pred.get("op") or ("eq" if ("equals" in pred or "value" in pred) else None)
            expected = pred.get("equals", pred.get("value"))
            found, value = self._lookup(facts, field)
            if op in (None, "eq", "equals", "=="):
                if not found or type(value) is not type(expected) or value != expected:
                    return False, field
            elif op == "ne":
                if not found or value == expected:
                    return False, field
            elif op == "exists":
                if not found:
                    return False, field
            elif op == "absent":
                if found:
                    return False, field
            elif op in ("ge", "le"):
                if not found or not isinstance(value, (int, float)) or \
                        isinstance(value, bool) or not isinstance(expected, (int, float)):
                    return False, field
                if (op == "ge" and value < expected) or (op == "le" and value > expected):
                    return False, field
            elif op == "contains":
                if not found or expected not in value:
                    return False, field
            else:
                return False, field
        return True, None

    # -- grounded message requirements compiled from public semantics ----
    _HEALTH_WORDS = ("healthy", "degraded", "unhealthy", "failing", "down", "ready")

    def _health_claims(self, rec):
        """[(region, claimed_health)] asserted by a message, if any."""
        import re as _re
        claims = []

        def walk(obj, region=None):
            if isinstance(obj, dict):
                regs = obj.get("regions")
                if isinstance(regs, dict):
                    for name, info in regs.items():
                        if isinstance(info, dict) and isinstance(info.get("health"), str):
                            claims.append((str(name), info["health"]))
                for k, v in obj.items():
                    if k == "health" and region and isinstance(v, str):
                        claims.append((str(region), v))
                    walk(v, k if isinstance(v, dict) else region)
            elif isinstance(obj, (list, tuple)):
                for v in obj:
                    walk(v, region)
        for key in ("facts", "content", "propositions", "message_facts"):
            if isinstance(rec.get(key), dict):
                walk(rec[key])
        body = rec.get("body")
        if isinstance(body, str):
            for name, health in _re.findall(
                    r"\b([a-z][a-z0-9_-]*)\s+(?:is\s+)?(healthy|degraded|unhealthy|failing|down|ready)\b",
                    body.lower()):
                claims.append((name, health))
            for health, name in _re.findall(
                    r"\b(healthy|degraded|unhealthy|failing)\s*:\s*([a-z][a-z0-9_-]*)\b",
                    body.lower()):
                claims.append((name, health))
        # de-duplicate, preserve order
        seen, out = set(), []
        for c in claims:
            if c not in seen:
                seen.add(c)
                out.append(c)
        return out

    def _validate_health_claims(self, ob, rec):
        """Health claims need fresh, verified, current evidence.

        Absence of explicit content_propositions in the public spec is not
        permission to assert arbitrary health: claims are compiled from
        public world semantics (region health in the spec / confirmed
        observations) and each claim must equal the latest confirmed
        region-health observation, taken after any degradation/wait event
        in this task's dependency chain (fresh, not stale pre-change
        evidence)."""
        claims = self._health_claims(rec)
        if not claims:
            return True, "OK"
        chain = {ob.task_id} | set(ob.depends_on)
        stack = list(ob.depends_on)
        while stack:
            t = stack.pop()
            if t in chain:
                continue
            chain.add(t)
            dep = self.obligations.get(t)
            if dep is not None:
                stack.extend(dep.depends_on)
        event_seq = 0
        for idx, r in enumerate(self.records):
            if r.get("kind") in ("WAIT_OBSERVED", "ENV_EVENT") and (
                    r.get("task_id") in chain or r.get("kind") == "ENV_EVENT"):
                event_seq = max(event_seq, idx + 1)
        known = set(((self.spec.get("initial_state") or {}).get("regions") or {}).keys())
        for _oid, entry in self.observations.items():
            regs = _find_regions(entry.get("facts"))
            if regs:
                known.update(regs.keys())
        for region, claimed in claims:
            if known and region not in known:
                return False, f"CONTENT_UNKNOWN_REGION:{region}"
            best = None  # (seq, health)
            for _oid, entry in self.observations.items():
                if not entry.get("_confirmed"):
                    continue
                regs = _find_regions(entry.get("facts"))
                if not regs or region not in regs:
                    continue
                info = regs[region]
                health = info.get("health") if isinstance(info, dict) else None
                if isinstance(health, str):
                    seq = entry.get("_seq", 0)
                    if best is None or seq > best[0]:
                        best = (seq, health)
            if best is None:
                return False, f"CONTENT_UNGROUNDED:{region}.health"
            if best[0] <= event_seq:
                return False, f"CONTENT_EVIDENCE_STALE:{region}.health"
            if best[1] != claimed:
                return False, f"CONTENT_MISMATCH:{region}.health"
        return True, "OK"

    def validate_message_content(self, ob, rec):
        """(ok, reason): content propositions grounded in verified evidence."""
        # Public budget-and-price checks must both precede financial handoff.
        chain, pending = set(), [ob.task_id]
        while pending:
            tid = pending.pop()
            if tid in chain:
                continue
            chain.add(tid)
            candidate = self.obligations.get(tid)
            if candidate is not None:
                pending.extend(candidate.depends_on)
        source_tools = {tool for tid in chain for tool in
                        self.obligations[tid].task.get("read_tools", [])}
        if {"budget.get", "catalog.price"} <= source_tools:
            import math
            facts = [entry.get("facts", {}) for entry in self.observations.values()
                     if entry.get("_confirmed") and entry.get("task_id") in chain]
            def known_number(field, positive):
                values = [f[field] for f in facts if field in f]
                return bool(values) and not isinstance(values[-1], bool) \
                    and isinstance(values[-1], (int, float)) \
                    and math.isfinite(values[-1]) \
                    and (values[-1] > 0 if positive else values[-1] >= 0)
            if not known_number("budget_remaining_usd", False):
                return False, "CONTENT_COST_BUDGET_UNVERIFIED"
            if not known_number("unit_price_usd", True):
                return False, "CONTENT_COST_PRICE_UNVERIFIED"
        preds = self._predicates(ob.task, "content_propositions",
                                 "required_message_facts", "required_content",
                                 "message_predicates")
        if not preds:
            # No explicit propositions: compile grounded requirements from
            # public world/task semantics + fresh evidence (health claims).
            return self._validate_health_claims(ob, rec)
        refs = rec.get("evidence_refs") or []
        if refs:
            part = self.analyze_ref_partition(ob, refs)
            if part["unknown"] or part["wrong_task"] or part["stale"] or not part["valid"]:
                return False, "CONTENT_EVIDENCE_UNVERIFIED"
        asserted = None
        for key in ("facts", "content", "propositions", "message_facts"):
            if isinstance(rec.get(key), dict):
                asserted = rec[key]
                break
        body = rec.get("body") if isinstance(rec.get("body"), str) else None
        grounded = self.confirmed_evidence_values(ob.task_id)
        for pred in preds:
            if not isinstance(pred, dict):
                return False, "CONTENT_PREDICATE_UNCHECKABLE"
            field = pred.get("field") or pred.get("path")
            if not field or ("equals" not in pred and "value" not in pred):
                return False, "CONTENT_PREDICATE_UNCHECKABLE"
            expected = pred.get("equals", pred.get("value"))
            is_grounded = expected in grounded or str(expected) in grounded
            if asserted is not None:
                found, value = self._lookup(asserted, field)
                if not found:
                    return False, f"CONTENT_MISSING:{field}"
                if type(value) is not type(expected) or value != expected:
                    return False, f"CONTENT_MISMATCH:{field}"
                if not is_grounded:
                    return False, f"CONTENT_UNGROUNDED:{field}"
            elif body is not None:
                if str(expected) not in body:
                    return False, f"CONTENT_MISSING:{field}"
                if not is_grounded:
                    return False, f"CONTENT_UNGROUNDED:{field}"
            else:
                return False, f"CONTENT_UNVERIFIED:{field}"
        return self._validate_health_claims(ob, rec)

    def note_gate_refusal(self, task_id):
        ob = self.obligations.get(task_id)
        if ob is not None and "REFUSE" in ob.kinds:
            ob.refused = True
            ob.satisfied["REFUSE"] = {"kind": "REFUSED_BY_AGENT", "task_id": task_id}
            self._mark_confirm(task_id)

    # ------------------------------------------------- WO008-01 activation
    def activation_of(self, task_id):
        ob = self.obligations.get(task_id)
        if ob is None:
            return "Z"
        if ob.requirement == "REQUIRED":
            return "T"
        if ob.requirement == "OPTIONAL":
            return "F"
        return ob.activation

    def unresolved_activations(self, agent_id=None):
        """CONDITIONAL tasks at Z whose resolution is required before DONE."""
        return [tid for tid, o in self.obligations.items()
                if o.requirement == "CONDITIONAL" and o.activation == "Z"
                and o.requires_resolution and not o.confirmed
                and (agent_id is None or o.agent_id == agent_id)]

    def resolve_activation(self, task_id, outcome, evidence_refs=(), source="", epoch=None):
        """Ground activation T/F in public instructions / verified evidence.

        Every evidence ref must be a confirmed observation id or a public
        instruction reference (``public:``/``spec:``); unattested, unknown,
        stale-epoch or non-conditional resolutions are rejected and the
        activation stays Z. Returns (ok, reason).
        """
        ob = self.obligations.get(task_id)
        if ob is None:
            return False, "UNKNOWN_TASK"
        if ob.requirement != "CONDITIONAL":
            return False, "NOT_CONDITIONAL"
        outcome = _norm_activation(outcome)
        if outcome not in ("T", "F"):
            return False, "INVALID_ACTIVATION"
        if epoch is not None and epoch != self.epoch:
            return False, "STALE_ACTIVATION_EPOCH"
        refs = list(evidence_refs or [])
        if not refs:
            return False, "ACTIVATION_PROOF_MISSING"
        # WO008-01 security: never trust a reference by its prefix.
        # Public instructions define the condition, not its runtime truth.
        predicate = ob.activation_predicate
        if (not isinstance(predicate, dict)
                or not isinstance(predicate.get("field"), str)
                or not predicate["field"]
                or "equals" not in predicate):
            return False, "ACTIVATION_PREDICATE_UNCHECKABLE"

        field_path = predicate["field"].split(".")
        expected = predicate["equals"]

        for ref in refs:
            entry = self.observations.get(ref)

            if entry is None or not entry.get("_confirmed"):
                return False, f"ACTIVATION_EVIDENCE_UNVERIFIED:{ref}"

            if entry.get("epoch", self.epoch) != self.epoch:
                return False, f"STALE_ACTIVATION_EVIDENCE:{ref}"

            value = entry.get("facts")
            for key in field_path:
                if not isinstance(value, dict) or key not in value:
                    return False, f"ACTIVATION_FACT_MISSING:{ref}:{key}"
                value = value[key]

            condition_true = (
                type(value) is type(expected) and value == expected
            )

            if condition_true != (outcome == "T"):
                return False, f"ACTIVATION_TRUTH_MISMATCH:{ref}"

        ob.activation = outcome
        ob.activation_evidence_refs = refs
        if source:
            ob.activation_source = source
        ob.activation_epoch = self.epoch
        ob.activation_seq = self._seq
        ob.activation_origin = "manual"
        ob.activation_auto = False
        return True, "ACTIVATION_RECORDED"

    # Alias matching the reference model's name; same fail-closed contract.
    def update_activation(self, task_id, outcome, evidence_refs=(), source="", epoch=None):
        return self.resolve_activation(task_id, outcome, evidence_refs, source, epoch)

    # ------------------------------------------- runtime activation (WO008-01)
    def _activation_chain(self, ob):
        """Tasks whose verified observations may prove ob's activation.

        Public spec may declare the evidence task(s) explicitly; otherwise
        the task's own transitive dependency chain is the provenance scope.
        Observations from outside this scope never activate the task.
        """
        declared = ob.task.get("activation_evidence_tasks") or \
            ob.task.get("activation_source_tasks")
        if declared:
            return set(declared)
        single = ob.task.get("activation_evidence_task") or \
            ob.task.get("activation_source_task")
        if single:
            return {single}
        chain, stack = set(), [ob.task_id] + list(ob.depends_on)
        while stack:
            tid = stack.pop()
            if tid in chain:
                continue
            chain.add(tid)
            dep = self.obligations.get(tid)
            if dep is not None:
                stack.extend(dep.depends_on)
        return chain

    @staticmethod
    def _predicate_lookup(facts, field):
        value = facts
        for key in str(field).split("."):
            if not isinstance(value, dict) or key not in value:
                return False, None
            value = value[key]
        return True, value

    def activation_candidates(self):
        """[(task_id, outcome, observation_id)] provable from fresh evidence.

        Pure evaluation only: for each CONDITIONAL task with a *structured*
        predicate, the latest (monotonic _seq) confirmed, current-epoch
        observation in the task's provenance scope that bears the predicate
        field decides T (type-strict equality) or F. No bearing observation,
        an unstructured/uncheckable predicate, a stale epoch or an
        unconfirmed observation yields no candidate (activation stays Z,
        fail closed). Explicit public-spec activations are never overridden,
        and a resolution is only superseded by *newer* bearing evidence.
        This method records nothing; runtime call sites apply candidates
        through resolve_activation() so the transition is theirs, not a
        test-only helper's.
        """
        out = []
        for ob in list(self.obligations.values()):
            if ob.requirement != "CONDITIONAL" or ob.confirmed:
                continue
            if ob.activation != "Z" and ob.activation_origin == "spec":
                continue
            predicate = ob.activation_predicate
            if (not isinstance(predicate, dict)
                    or not isinstance(predicate.get("field"), str)
                    or not predicate["field"] or "equals" not in predicate):
                continue  # uncheckable -> stays Z -> WRITE denied
            chain = self._activation_chain(ob)
            candidates = []
            for oid, entry in self.observations.items():
                if not entry.get("_confirmed"):
                    continue
                if entry.get("task_id") not in chain:
                    continue
                if entry.get("epoch", self.epoch) != self.epoch:
                    continue
                found, value = self._predicate_lookup(
                    entry.get("facts"), predicate["field"])
                if found:
                    candidates.append((entry.get("_seq", 0), oid, value))
            if not candidates:
                continue
            candidates.sort(key=lambda c: c[0])
            seq, oid, value = candidates[-1]
            if ob.activation != "Z" and seq <= ob.activation_seq:
                continue  # no evidence newer than the current resolution
            expected = predicate["equals"]
            outcome = "T" if (type(value) is type(expected)
                              and value == expected) else "F"
            if outcome == ob.activation and ob.activation_evidence_refs == [oid]:
                continue
            out.append((ob.task_id, outcome, oid))
        return out

    def reevaluate_activations(self):
        """Apply activation_candidates() via resolve_activation().

        Kept for internal/registry-level use; the real runtime paths
        (CausalSidecar.check/check_exit, CausalHost._sync and
        CausalState.refresh) apply the same candidates with their own
        explicit resolve_activation() calls at causal-state transitions.
        Returns [(task_id, outcome, observation_id)] actually recorded.
        """
        transitions = []
        for task_id, outcome, oid in self.activation_candidates():
            ok, _why = self.resolve_activation(
                task_id, outcome, evidence_refs=[oid],
                source=f"verified-observation:{oid}", epoch=self.epoch)
            if ok:
                ob = self.obligations[task_id]
                ob.activation_origin = "derived"
                ob.activation_auto = True
                transitions.append((task_id, outcome, oid))
        return transitions

    def _dep_satisfied(self, task_id):
        ob = self.obligations.get(task_id)
        if ob is None:
            return False
        return bool(ob.confirmed or ob.not_applicable)

    def deps_confirmed(self, task_id):
        ob = self.obligations.get(task_id)
        if ob is None:
            return False
        return all(self._dep_satisfied(d) for d in ob.depends_on)

    def open_deps(self, task_id):
        ob = self.obligations.get(task_id)
        if ob is None:
            return [task_id]
        return [d for d in ob.depends_on if not self._dep_satisfied(d)]

    def _mark_confirm(self, task_id):
        ob = self.obligations[task_id]
        if ob.confirmed and task_id not in self.confirm_seq:
            self.confirm_seq[task_id] = self._seq

    def _deps_were_confirmed(self, ob):
        def _ok(d):
            dep = self.obligations.get(d)
            if dep is None:
                return False
            if dep.not_applicable:
                return True
            return d in self.confirm_seq and self.confirm_seq[d] <= self._seq
        return all(_ok(d) for d in ob.depends_on)

    def _read_success_check(self, ob, rec, facts):
        """(status, field): grounded success predicate for a validation READ.

        Compiled from public semantics only: the world's ``derived`` rules
        declare the postcondition values a fix must produce (e.g. readiness
        ``ready``, flow ``ok``). A READ task downstream of a WRITE (a
        validation task) may close only on an observation whose mapped
        fields actually equal those success values. A nonempty failing
        observation (readiness=failing, flow=error) is evidence of failure,
        not of success: status F/Z, never closure. Tasks not downstream of
        a WRITE (diagnosis reads) are not gated by the postcondition.
        """
        if "READ" not in ob.kinds or not isinstance(facts, dict):
            return "NA", None
        if ob.required_read_tools and rec.get("tool") not in ob.required_read_tools:
            return "Z", "required_read_tools=" + ",".join(ob.required_read_tools)
        chain, stack = set(), list(ob.depends_on)
        downstream_of_write = False
        while stack:
            t = stack.pop()
            if t in chain:
                continue
            chain.add(t)
            dep = self.obligations.get(t)
            if dep is not None:
                if "WRITE" in dep.kinds:
                    downstream_of_write = True
                stack.extend(dep.depends_on)
        if not downstream_of_write:
            return "NA", None
        success_by_path, success_by_leaf = {}, {}
        for rule in self.spec.get("derived") or []:
            for eff in rule.get("effects") or []:
                if eff.get("op") == "set" and eff.get("value") is not None:
                    path = str(eff.get("path") or "")
                    success_by_path[path] = eff.get("value")
                    success_by_leaf[path.rsplit(".", 1)[-1]] = eff.get("value")
        if not success_by_path:
            return "NA", None
        returns = ((self.tools.get(rec.get("tool") or "") or {}).get("returns") or {})
        applicable = []
        for key, value in facts.items():
            path = returns.get(key, key)
            if path in success_by_path:
                applicable.append((key, success_by_path[path]))
            elif isinstance(path, str) and path.rsplit(".", 1)[-1] in success_by_leaf:
                applicable.append((key, success_by_leaf[path.rsplit(".", 1)[-1]]))
        if not applicable:
            return "Z", "<success-predicate>"
        for key, expected in applicable:
            value = facts.get(key)
            if type(value) is not type(expected) or value != expected:
                return "F", key
        return "T", None

    def success_status(self, task_id):
        """T = success postcondition proven, Z = not established, NA = n/a."""
        ob = self.obligations.get(task_id)
        if ob is None:
            return "Z"
        if ob.confirmed:
            return "T"
        return getattr(ob, "success_predicate_status", "Z")

    def _ingest_one(self, rec):
        self._seq += 1
        self.records.append(rec)
        kind = rec.get("kind")
        task_id = rec.get("task_id")
        if kind == "OBSERVATION" and rec.get("observation_id"):
            entry = dict(rec)
            entry["_confirmed"] = False
            entry["_seq"] = self._seq
            self.observations[rec["observation_id"]] = entry
        ob = self.obligations.get(task_id)
        if ob is None:
            if kind in ("RECEIPT", "READBACK_EFFECT", "NATIVE_EFFECT"):
                self._ingest_write_part(rec)
            return
        if kind in ("NATIVE_EFFECT", "RECEIPT", "READBACK_EFFECT"):
            # WO008-02: WRITE closes only on the full verified triplet;
            # an effect alone is EXECUTED_UNVERIFIED (handled there).
            self._ingest_write_part(rec)
            return
        if rec.get("agent_id") not in (None, ob.agent_id):
            ob.stale.append({"record": rec, "reason": "WRONG_AGENT"})
            return
        if ob.not_applicable and kind == "OBSERVATION":
            # WO008-01: an observation for an inactive task closes nothing,
            # but it is still fresh evidence: retain it (confirmed when its
            # dependencies were confirmed and facts are non-empty) so a
            # later runtime activation transition can reactivate the task
            # when the world changes. Discarding it would freeze F forever.
            entry = self.observations.get(rec.get("observation_id") or "")
            facts = rec.get("facts")
            if (entry is not None and self._deps_were_confirmed(ob)
                    and isinstance(facts, dict)
                    and not all(v is None for v in facts.values())):
                entry["_confirmed"] = True
            ob.stale.append({"record": rec, "reason": "NOT_APPLICABLE_EVIDENCE_ONLY"})
            return
        if ob.not_applicable and (kind == "NATIVE_EFFECT" or kind in _RECORD_FOR.values()):
            # WO008-01: closing evidence for an inactive task closes nothing.
            ob.stale.append({"record": rec, "reason": "NOT_APPLICABLE"})
            return
        # map record kind -> obligation kind
        okind = next((k for k, rk in _RECORD_FOR.items() if rk == kind), None)
        if okind is None:
            return
        if okind not in ob.kinds and kind != "OBSERVATION":
            return
        if not self._deps_were_confirmed(ob):
            # Premature evidence never closes. For a READ-kind task a plain
            # observation is allowed (P0-6) but stays unconfirmed/stale here.
            if okind in ob.kinds:
                ob.stale.append({"record": rec, "reason": "PREMATURE_BEFORE_DEPS"})
            return
        if okind == "READ":
            facts = rec.get("facts")
            if not isinstance(facts, dict) or all(v is None for v in facts.values()):
                if "READ" in ob.kinds:
                    ob.stale.append({"record": rec, "reason": "EMPTY_OBSERVATION_NULL_DATA"})
                return
            # WO008-02: freshness + structured evidence predicates (T only).
            exp = self._explicit_epoch(rec)
            if exp is not None and exp != self.epoch:
                ob.stale.append({"record": rec, "reason": "STALE_OBSERVATION_EPOCH"})
                return
            if self.attempt_uid and rec.get("attempt_uid") and \
                    rec.get("attempt_uid") != self.attempt_uid:
                ob.stale.append({"record": rec, "reason": "CROSS_ATTEMPT_OBSERVATION"})
                return
            if self.expected_world_instance_id and rec.get("world_instance_id") and \
                    rec.get("world_instance_id") != self.expected_world_instance_id:
                ob.stale.append({"record": rec, "reason": "CROSS_WORLD_OBSERVATION"})
                return
            preds = self._predicates(ob.task, "evidence_predicates",
                                     "read_predicates", "evidence_predicate")
            if preds:
                okp, field = self._eval_predicates(facts, preds)
                if not okp:
                    ob.stale.append({"record": rec,
                                     "reason": f"EVIDENCE_PREDICATE_FAILED:{field}"})
                    return
            # F007: a validation READ downstream of a WRITE closes only on
            # the grounded success postcondition, not on any nonempty data.
            sstatus, sfield = self._read_success_check(ob, rec, facts)
            if sstatus == "F":
                ob.success_predicate_status = "Z"
                if "READ" in ob.kinds:
                    ob.stale.append({"record": rec,
                                     "reason": f"EVIDENCE_SUCCESS_PREDICATE_FAILED:{sfield}"})
                return
            if sstatus == "Z":
                ob.success_predicate_status = "Z"
                if "READ" in ob.kinds:
                    ob.stale.append({"record": rec,
                                     "reason": "READ_SUCCESS_PREDICATE_UNESTABLISHED"})
                return
            if sstatus == "T":
                ob.success_predicate_status = "T"
            entry = self.observations.get(rec.get("observation_id"))
            if entry is not None:
                # Eligible observation under the task's own read_tools is real
                # evidence even for a non-READ task (P0-6); it is marked
                # confirmed for provenance/shared evidence but, below, only
                # satisfies the obligation when READ is one of its kinds.
                entry["_confirmed"] = True
            if "READ" not in ob.kinds:
                return
        if okind == "ANALYZE":
            ok, why = self.validate_analysis(ob, rec)
            if not ok:
                ob.stale.append({"record": rec, "reason": why})
                return
            part = self.analyze_ref_partition(ob, rec.get("evidence_refs") or [])
            if part["stale"]:
                # P0-12: stale refs are reported/ignored, not fatal, when
                # sufficient fresh valid evidence is also cited.
                ob.ignored_stale_refs.append(
                    {"record_id": rec.get("record_id"), "refs": list(part["stale"])})
        if okind == "WAIT":
            want = ob.task.get("wait_for")
            if want and rec.get("event_id") != want:
                ob.stale.append({"record": rec, "reason": "WRONG_EVENT"})
                return
        if okind == "COMMUNICATE":
            if rec.get("recipient") not in (ob.task.get("recipients") or []):
                ob.stale.append({"record": rec, "reason": "WRONG_RECIPIENT"})
                return
            if rec.get("delivery_verified") is False:
                ob.stale.append({"record": rec, "reason": "DELIVERY_UNVERIFIED"})
                return
            okc, whyc = self.validate_message_content(ob, rec)
            if not okc:
                ob.stale.append({"record": rec, "reason": whyc})
                return
        if okind == "RECONCILE" and rec.get("found") is False:
            ob.stale.append({"record": rec, "reason": "RECONCILE_NOT_FOUND"})
            return
        ob.satisfied[okind] = rec
        self._mark_confirm(task_id)

    # ---------------------------------------------------------- WP-D validation
    def confirmed_evidence_values(self, task_id):
        """Values seen in confirmed observations of task_id + its dep chain."""
        seen, out = set(), set()
        stack = [task_id]
        while stack:
            tid = stack.pop()
            if tid in seen:
                continue
            seen.add(tid)
            ob = self.obligations.get(tid)
            if ob is None:
                continue
            stack.extend(ob.depends_on)
            for rec in self.records:
                if rec.get("kind") == "OBSERVATION" and rec.get("task_id") == tid:
                    entry = self.observations.get(rec.get("observation_id") or "")
                    if entry is not None and entry.get("_confirmed"):
                        _flatten_values(rec.get("facts"), out)
                        out.add(rec["observation_id"])
        return out

    def dependents_of(self, task_id):
        """Direct dependents: tasks whose depends_on includes task_id."""
        return [tid for tid, o in self.obligations.items() if task_id in o.depends_on]

    def open_dependents(self, task_id):
        """Open downstream consumers, including beyond a confirmed relay.

        Evidence refresh may be needed after an intervening event even when
        the direct consumer has completed. This grants observation only;
        admission of every downstream action is checked independently.
        """
        direct = [tid for tid in self.dependents_of(task_id)
                  if not self.obligations[tid].confirmed]
        last_observation = max(
            (entry.get("_seq", 0) for entry in self.observations.values()
             if entry.get("task_id") == task_id and entry.get("_confirmed")),
            default=0,
        )
        changed_since_observation = last_observation and any(
            idx > last_observation and rec.get("kind") in
            ("ENV_EVENT", "WAIT_OBSERVED")
            for idx, rec in enumerate(self.records, 1)
        )
        if not changed_since_observation:
            return direct
        seen = {task_id}
        pending = list(self.dependents_of(task_id))
        downstream = []
        while pending:
            tid = pending.pop(0)
            if tid in seen:
                continue
            seen.add(tid)
            if not self.obligations[tid].confirmed:
                downstream.append(tid)
            pending.extend(self.dependents_of(tid))
        return downstream

    def performed_observation(self, task_id, tool, args):
        """Latest logged observation for (task, tool, args), if records carry them."""
        best = None
        for entry in self.observations.values():
            if entry.get("task_id") != task_id:
                continue
            if entry.get("tool") != tool or (entry.get("args") or {}) != (args or {}):
                continue
            if best is None or entry.get("_seq", 0) > best.get("_seq", 0):
                best = entry
        return best

    def state_changed_after(self, seq):
        """True if any confirmation / confirmed observation landed after seq."""
        if any(s > seq for s in self.confirm_seq.values()):
            return True
        return any(e.get("_seq", 0) > seq and e.get("_confirmed")
                   for e in self.observations.values())

    def analyze_ref_partition(self, ob, refs):
        """Partition evidence_refs into valid / stale / unknown / wrong_task.

        Valid = real, confirmed (fresh) and from this task's dependency
        chain (itself + transitive dependencies). Stale = real and in-chain
        but not confirmed (e.g. taken before dependencies finished). Unknown
        and wrong-task refs break provenance and are never tolerated.
        """
        chain = set()
        stack = [ob.task_id] + list(ob.depends_on)
        while stack:
            t = stack.pop()
            if t in chain:
                continue
            chain.add(t)
            o = self.obligations.get(t)
            if o:
                stack.extend(o.depends_on)
        part = {"valid": [], "stale": [], "unknown": [], "wrong_task": []}
        for ref in refs or []:
            entry = self.observations.get(ref)
            if entry is None:
                part["unknown"].append(ref)
            elif entry.get("task_id") not in chain:
                part["wrong_task"].append(ref)
            elif not entry.get("_confirmed"):
                part["stale"].append(ref)
            else:
                part["valid"].append(ref)
        return part

    def validate_analysis(self, ob, rec):
        """(ok, reason) under P0-12 tolerant-stale semantics.

        Admitted iff at least one fresh, valid, in-chain ref is cited and no
        cited ref is fabricated (unknown) or from outside the chain
        (provenance break). Stale in-chain refs alone never suffice, but
        stale refs cited alongside sufficient fresh evidence are ignored
        (reported via analyze_ref_partition / Obligation.ignored_stale_refs)
        rather than refusing the whole analysis.
        """
        refs = rec.get("evidence_refs") or []
        if "ANALYZE" in ob.kinds and not refs:
            return False, "MISSING_EVIDENCE_REFS"
        part = self.analyze_ref_partition(ob, refs)
        if part["unknown"]:
            return False, "UNKNOWN_EVIDENCE_REF"
        if part["wrong_task"]:
            return False, "EVIDENCE_FROM_WRONG_TASK"
        if not part["valid"]:
            return False, "STALE_EVIDENCE_REF" if part["stale"] else "MISSING_EVIDENCE_REFS"
        schema = ob.task.get("answer_schema") or {}
        if {"total_processed", "all_lag_zero"} <= set(schema):
            answer = rec.get("facts") or rec.get("answer")
            if not isinstance(answer, dict):
                return False, "AGGREGATE_ANSWER_MISSING"
            chain, pending = set(), list(ob.depends_on)
            while pending:
                tid = pending.pop()
                if tid in chain:
                    continue
                chain.add(tid)
                candidate = self.obligations.get(tid)
                if candidate is not None:
                    pending.extend(candidate.depends_on)
            drains = [candidate for tid, candidate in self.obligations.items()
                      if tid in chain and candidate.task.get("write_tool") == "partition.drain"]
            if not drains or any(candidate.write_state != "VERIFIED" for candidate in drains):
                return False, "AGGREGATE_EFFECTS_UNVERIFIED"
            total, effect_ids = 0, set()
            for candidate in drains:
                effect = candidate.write_evidence.get("effect") or {}
                if not effect.get("effect_id") or effect["effect_id"] in effect_ids:
                    return False, "AGGREGATE_EFFECTS_UNVERIFIED"
                effect_ids.add(effect["effect_id"])
                increments = [e.get("value") for e in effect.get("effects_applied") or []
                              if e.get("op") == "inc" and
                              str(e.get("path") or "").startswith("processed.")]
                if len(increments) != 1 or type(increments[0]) is not int or increments[0] < 0:
                    return False, "AGGREGATE_EFFECTS_UNVERIFIED"
                total += increments[0]
            lag_reads = [entry for entry in self.observations.values()
                         if entry.get("_confirmed") and entry.get("task_id") in chain
                         and isinstance(entry.get("facts", {}).get("lag"), dict)]
            if not lag_reads:
                return False, "AGGREGATE_LAG_UNVERIFIED"
            latest = max(lag_reads, key=lambda entry: entry.get("_seq", 0))
            lag = latest["facts"]["lag"]
            if not lag or any(type(value) is not int or value < 0 for value in lag.values()):
                return False, "AGGREGATE_LAG_UNVERIFIED"
            if type(answer.get("total_processed")) is not int or answer["total_processed"] != total:
                return False, "AGGREGATE_TOTAL_MISMATCH"
            if type(answer.get("all_lag_zero")) is not bool \
                    or answer["all_lag_zero"] != all(value == 0 for value in lag.values()):
                return False, "AGGREGATE_LAG_MISMATCH"
        return True, "OK"

    def identifier_provenance_ok(self, ob, args):
        """Non-enum string args of a dependent read must come from evidence."""
        if not ob.depends_on:
            return True, "OK"
        known = self.confirmed_evidence_values(ob.task_id)
        tool_params = {}
        for name in (ob.task.get("read_tools") or []):
            tool_params.update((self.tools.get(name) or {}).get("params") or {})
        for key, val in (args or {}).items():
            if not isinstance(val, str):
                continue
            pspec = tool_params.get(key) or {}
            if "enum" in pspec and val in pspec["enum"]:
                continue
            if val in known or str(val) in known:
                continue
            # ids obtained via inbox messages also count (obs ids in body text)
            return False, f"IDENTIFIER_NOT_FROM_EVIDENCE:{key}={val}"
        return True, "OK"

    # ---------------------------------------------------------- views
    def is_confirmed(self, task_id):
        ob = self.obligations.get(task_id)
        return bool(ob and ob.confirmed)

    def state_of(self, task_id):
        ob = self.obligations.get(task_id)
        if ob is None:
            return "UNKNOWN"
        if ob.confirmed:
            return "CONFIRMED"
        if "WRITE" in ob.kinds and ob.write_state == "EXECUTED_UNVERIFIED":
            return "EXECUTED_UNVERIFIED"
        if ob.not_applicable:
            return "NOT_APPLICABLE"
        if ob.requirement == "CONDITIONAL" and ob.activation == "Z":
            return "ACTIVATION_UNRESOLVED"
        if "READ" in ob.kinds and getattr(ob, "success_predicate_status", "T") == "Z" and \
                any(s.get("reason", "").startswith(
                    ("EVIDENCE_SUCCESS_PREDICATE_FAILED", "READ_SUCCESS_PREDICATE_UNESTABLISHED"))
                    for s in ob.stale):
            return "Z"
        return "ELIGIBLE" if self.deps_confirmed(task_id) else "PENDING"

    def open_obligations(self, agent_id):
        # WO008-01: only active mandatory obligations can block / be required.
        return [tid for tid in self.by_agent.get(agent_id, [])
                if self.obligations[tid].is_active_mandatory
                and not self.obligations[tid].confirmed]

    def can_exit(self, agent_id):
        if self.feed_unavailable:
            return (False, ["EVIDENCE_FEED_UNAVAILABLE"])
        unresolved = self.unresolved_activations(agent_id)
        if unresolved:
            return (False, unresolved)
        open_ = self.open_obligations(agent_id)
        return (not open_), open_

    def state_digest(self):
        """Digest of causal state relevant to admissibility (P0-7).

        Covers confirmed tasks, satisfied kinds, confirmed observations and
        confirmation order, so a refusal repeated after any of these change
        is a new refusal, not a repeat of the old one.
        """
        import hashlib
        import json as _json
        payload = {
            "confirmed": sorted(t for t in self.obligations if self.is_confirmed(t)),
            "activation": {t: [o.activation, o.activation_evidence_refs]
                           for t, o in sorted(self.obligations.items())},
            "satisfied": {t: sorted(o.satisfied) for t, o in sorted(self.obligations.items())},
            "confirmed_obs": sorted(oid for oid, r in self.observations.items()
                                    if r.get("_confirmed")),
            "confirm_seq": dict(sorted(self.confirm_seq.items())),
            "write_state": {t: o.write_state for t, o in sorted(self.obligations.items())},
            "feed_unavailable": self.feed_unavailable,
        }
        return hashlib.sha256(_json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:16]

    def summary(self):
        return {"world_id": self.world_id,
                "confirmed": sorted(t for t in self.obligations if self.is_confirmed(t)),
                "open": sorted(t for t in self.obligations if not self.is_confirmed(t))}


def validate_cost_decision(observations, quantity, unit_price, total_cost, budget):
    """WP-D A2A: a quantity/cost decision must derive from observed records.

    observations: iterable of fact dicts from confirmed price/budget reads.
    Returns (ok, reason). Pure arithmetic on public observed values only.
    """
    prices, budgets = set(), set()
    for facts in observations or []:
        vals = set()
        _flatten_values(facts, vals)
        for v in vals:
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                prices.add(v)
                budgets.add(v)
    if unit_price not in prices:
        return False, "UNIT_PRICE_NOT_OBSERVED"
    if budget not in budgets:
        return False, "BUDGET_NOT_OBSERVED"
    if quantity is None or quantity <= 0:
        return False, "QUANTITY_NOT_POSITIVE"
    if total_cost != quantity * unit_price:
        return False, "TOTAL_NOT_DERIVABLE"
    if total_cost > budget:
        return False, "TOTAL_EXCEEDS_BUDGET"
    return True, "OK"
