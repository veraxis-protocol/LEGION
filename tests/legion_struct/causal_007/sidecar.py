"""WP-B/WP-C: enforcing causal sidecar between agents and the world.

The sidecar can only REFUSE / EXPLAIN / QUEUE / SUGGEST. It never originates
a world, gate or bus action: every forwarded action must carry the agent's
own decision_ref (provider_response_id or scripted:<n>), and the sidecar
exposes no method that performs a world call itself.

Enforced for READ, WAIT, COMMUNICATE, ANALYZE (and REFUSE/RECONCILE/DONE);
WRITE admissibility is checked here too but ZTL/CAGE/VEIP keep independent
control of consequential writes (this layer may only be stricter).
"""
from __future__ import annotations

import hashlib
import json
import re

_ACTION_KIND = {"read": "READ", "analyze": "ANALYZE", "send": "COMMUNICATE",
                "wait": "WAIT", "write": "WRITE", "refuse": "REFUSE",
                "reconcile": "RECONCILE", "done": "DONE", "idle": None}
_RENAMED_RE = re.compile(r"unknown parameter '([^']+)'; this endpoint now expects '([^']+)'")
# Refusals that may clear when causal/world state changes (P0-7/P0-8). The
# scripted decider retries these; permanent codes (KIND_NOT_ALLOWED etc.) are
# not retried. EVENT_PENDING covers waits whose event has not fired yet.
TRANSIENT_CODES = frozenset({"DEPENDENCIES_OPEN", "EVENT_PENDING", "WAIT_PENDING",
                             "SIDECAR_UNAVAILABLE", "EVIDENCE_FEED_UNAVAILABLE"})


class Verdict:
    def __init__(self, allowed, code, hint="", next_required=None,
                 transient=None, underlying_code=None, observation_only=False,
                 stale_refs=None, valid_refs=None):
        self.allowed, self.code, self.hint = allowed, code, hint
        self.next_required = next_required
        self.underlying_code = underlying_code
        self.observation_only = bool(observation_only)
        self.stale_refs = list(stale_refs or [])
        self.valid_refs = list(valid_refs or [])
        if transient is None:
            transient = (code in TRANSIENT_CODES or
                         (underlying_code in TRANSIENT_CODES if underlying_code else False))
        self.transient = bool(transient)

    def to_dict(self):
        return {"allowed": self.allowed, "code": self.code, "hint": self.hint,
                "next_required": self.next_required,
                "transient": self.transient,
                "underlying_code": self.underlying_code,
                "observation_only": self.observation_only,
                "stale_refs": self.stale_refs,
                "valid_refs": self.valid_refs}


class CausalSidecar:
    def __init__(self, registry, log=None):
        self.registry = registry
        self.log = log or (lambda rec: None)
        self._attempts = {}   # (fingerprint, code, state_digest) -> count (P0-7)
        # P0-11: admitted reads, for state-aware repetition throttling.
        # _read_seen: key -> registry digest once the read was logged;
        # _read_pending: key -> observation count when the read was admitted
        # (settled into _read_seen once a later check sees it logged).
        self._read_seen = {}
        self._read_pending = {}

    def _refresh_activations(self):
        """Derive activation only from confirmed runtime evidence."""
        return self.registry.reevaluate_activations()

    # ------------------------------------------------------------ P0-11 reads
    def _read_key(self, agent_id, action):
        canon = json.dumps(action.get("args") or {}, sort_keys=True, default=str)
        return (agent_id, action.get("task"), action.get("tool"), canon)

    def _settle_reads(self):
        if not self._read_pending:
            return
        n = len(self.registry.observations)
        for key, obs_n in list(self._read_pending.items()):
            if n > obs_n:
                self._read_seen[key] = self.registry.state_digest()
                del self._read_pending[key]

    def _is_repeat_read(self, agent_id, action):
        """Same (tool, args) already observed and causal state unchanged since.

        State-aware only: any intervening confirmation / confirmed
        observation (registry seq, or a changed state digest for records
        without tool/args) makes the read admissible again.
        """
        reg = self.registry
        entry = reg.performed_observation(action.get("task"), action.get("tool"),
                                          action.get("args") or {})
        if entry is not None:
            return not reg.state_changed_after(entry.get("_seq", 0))
        key = self._read_key(agent_id, action)
        if key in self._read_pending:
            return True
        seen = self._read_seen.get(key)
        return seen is not None and seen == reg.state_digest()

    # ------------------------------------------------------------ helpers
    def _fp(self, agent_id, action):
        canon = json.dumps(action, sort_keys=True, default=str)
        return hashlib.sha256(f"{agent_id}|{canon}".encode()).hexdigest()[:16]

    def next_required(self, agent_id):
        """WP-B view: open obligations, confirmed deps, next transition."""
        reg = self.registry
        if getattr(reg, "feed_unavailable", False):
            # Unknown evidence denies the view itself: no stale next step,
            # no WRITE/DONE guidance may be derived from cached state.
            return {"agent_id": agent_id, "allowed": False,
                    "code": "EVIDENCE_FEED_UNAVAILABLE",
                    "open_obligations": [], "obligations": [],
                    "next_required": None,
                    "evidence_feed": "EVIDENCE_FEED_UNAVAILABLE",
                    "shared_evidence": []}
        open_ = reg.open_obligations(agent_id)
        view = []
        for tid in open_:
            ob = reg.obligations[tid]
            missing = [k for k in ob.kinds if k not in ob.satisfied]
            view.append({"task_id": tid, "state": reg.state_of(tid),
                         "open_dependencies": reg.open_deps(tid),
                         "missing_evidence": missing,
                         "action_types": [action for action, action_kind in
                                          _ACTION_KIND.items() if action_kind in missing],
                         "recipients": list(ob.task.get("recipients") or []),
                         "required_read_tools": list(ob.required_read_tools),
                         "next_required": (
                             f"satisfy READ for {tid} using {ob.required_read_tools}"
                             if "READ" in missing and ob.required_read_tools
                             else f"satisfy {missing[0]} for {tid}"
                             if missing else f"complete {tid}")})
        nxt = next((v for v in view if not v["open_dependencies"]), view[0] if view else None)
        shared = [{"observation_id": oid, "agent_id": r.get("agent_id"),
                   "task_id": r.get("task_id"), "facts": r.get("facts")}
                  for oid, r in sorted(self.registry.observations.items())
                  if r.get("_confirmed")]
        return {"agent_id": agent_id, "open_obligations": open_,
                "obligations": view, "next_required": nxt["next_required"] if nxt else None,
                "evidence_feed": ("EVIDENCE_FEED_UNAVAILABLE"
                                   if getattr(reg, "feed_unavailable", False) else "OK"),
                "shared_evidence": shared}

    # ------------------------------------------------------------ enforcement
    def check(self, agent_id, action, decision_ref):
        """Return Verdict. Records a CAUSAL_REFUSAL / CAUSAL_ADMIT log record.

        P0-7: admissibility is re-evaluated first, every time. A repeat is
        blocked only for the same (fingerprint, refusal reason, registry
        state digest); when the state digest or reason changes, or the
        action becomes admissible, it is not REPEAT_BLOCKED.
        """
        self._refresh_activations()
        fp = self._fp(agent_id, action)
        self._settle_reads()
        verdict = self._check_inner(agent_id, action, decision_ref, fp)
        if verdict.allowed:
            if (action or {}).get("action") == "read":
                self._read_pending[self._read_key(agent_id, action)] = \
                    len(self.registry.observations)
            for key in [k for k in self._attempts if k[0] == fp]:
                del self._attempts[key]
        elif verdict.code != "REPEAT_BLOCKED":
            digest = self.registry.state_digest()
            key = (fp, verdict.code, digest)
            count = self._attempts.get(key, 0) + 1
            self._attempts[key] = count
            if count == 3:
                # Blocked as a repeat exactly once per (fingerprint, reason,
                # state digest); later attempts under the same state are
                # re-evaluated and carry the original reason again, so a
                # waiting agent never generates a REPEAT_BLOCKED storm.
                verdict = Verdict(
                    False, "REPEAT_BLOCKED",
                    "This exact action was repeatedly refused for the same reason "
                    f"({verdict.code}) while the causal state was unchanged; "
                    "change the action using the corrective hint instead of repeating it. "
                    f"Original hint: {verdict.hint}",
                    verdict.next_required, underlying_code=verdict.code)
        self.log({"event": "CAUSAL_ADMIT" if verdict.allowed else "CAUSAL_REFUSAL",
                  "agent_id": agent_id, "action": action,
                  "decision_ref": decision_ref, "code": verdict.code,
                  "hint": verdict.hint, "fingerprint": fp,
                  "transient": verdict.transient,
                  "underlying_code": verdict.underlying_code,
                  "observation_only": verdict.observation_only,
                  "stale_refs": verdict.stale_refs,
                  "valid_refs": verdict.valid_refs,
                  "state_digest": self.registry.state_digest()})
        return verdict

    def _refuse(self, agent_id, action, code, hint):
        nxt = self.next_required(agent_id)
        return Verdict(False, code, hint, nxt["next_required"])

    def _check_inner(self, agent_id, action, decision_ref, fp):
        if not decision_ref:
            return self._refuse(agent_id, action, "NO_DECISION_REF",
                                "Every action must originate from your own decision; "
                                "the controller never acts on an agent's behalf.")
        kind = _ACTION_KIND.get((action or {}).get("action"))
        if kind is None:
            return Verdict(True, "IDLE_OK") if (action or {}).get("action") == "idle" \
                else self._refuse(agent_id, action, "UNKNOWN_ACTION", "Use a documented action.")
        reg = self.registry
        # WO008-02: while the authoritative evidence feed is unavailable, no
        # consequential admission and no new evidence-dependent closure.
        if getattr(reg, "feed_unavailable", False) and kind in (
                "WRITE", "READ", "ANALYZE", "COMMUNICATE", "WAIT",
                "RECONCILE", "DONE"):
            return self._refuse(agent_id, action, "EVIDENCE_FEED_UNAVAILABLE",
                                "Authoritative evidence feed is unavailable; "
                                "no consequential or evidence-dependent action "
                                "may proceed until an independent refresh succeeds.")
        task_id = action.get("task")
        ob = reg.obligations.get(task_id)
        if ob is None:
            return self._refuse(agent_id, action, "UNKNOWN_TASK",
                                f"Task {task_id!r} is not in the public world spec.")
        if ob.agent_id != agent_id:
            return self._refuse(agent_id, action, "WRONG_AGENT",
                                f"Task {task_id} belongs to {ob.agent_id}, not {agent_id}.")
        # WO054-R: independent dependency barrier before activation.
        # This changes refusal classification only; never admits WRITE.
        # Unknown activation remains fail-closed after dependencies close.
        if kind == "WRITE":
            _pending = reg.open_deps(task_id)
            if _pending:
                return self._refuse(
                    agent_id, action, "DEPENDENCIES_OPEN",
                    f"Task {task_id} waits on {', '.join(_pending)}; "
                    "consequential execution is forbidden."
                )
        # WO008-01: consequential actions require earned activation.
        # A task appearing in the public DSL is not authorization. Activation
        # is derived above by _refresh_activations() (runtime call site of
        # resolve_activation) from fresh verified observations; unknown or
        # uncheckable stays Z and fails closed.
        if kind == "WRITE":
            if ob.requirement == "OPTIONAL" or (
                ob.requirement == "CONDITIONAL" and ob.activation == "F"
            ):
                return self._refuse(
                    agent_id, action, "NOT_REQUIRED",
                    f"Task {task_id} is not an active obligation; "
                    "its WRITE must not execute."
                )

            if ob.requirement == "CONDITIONAL" and ob.activation != "T":
                return self._refuse(
                    agent_id, action, "ACTIVATION_UNRESOLVED",
                    f"Task {task_id} requires verified activation "
                    "before consequential execution."
                )
        read_tools = list(ob.task.get("read_tools") or [])
        own_read = kind == "READ" and action.get("tool") in read_tools
        if ob.confirmed:
            # P0-11: confirmation must not forbid further evidence gathering.
            # Reads are non-consequential: an own-read_tools read stays
            # admissible after confirmation, at least once per distinct
            # (tool, args), while the task's dependents are not yet closed.
            # Only an exact repetition under unchanged state is throttled.
            if own_read and reg.open_dependents(task_id):
                ok, why = reg.identifier_provenance_ok(ob, action.get("args") or {})
                if not ok:
                    return self._refuse(agent_id, action, "IDENTIFIER_PROVENANCE",
                                        f"{why}; use identifiers from confirmed upstream evidence only.")
                if self._is_repeat_read(agent_id, action):
                    return self._refuse(
                        agent_id, action, "ALREADY_CONFIRMED",
                        f"Task {task_id} is already confirmed and this exact read "
                        f"({action.get('tool')!r} with the same args) was already "
                        "observed with no intervening causal state change; use a "
                        "distinct read or move to the next obligation.")
                return Verdict(True, "ADMISSIBLE",
                               f"Task {task_id} is already confirmed; additional "
                               "observation admitted because its dependents "
                               f"{reg.open_dependents(task_id)} are not yet closed.",
                               self.next_required(agent_id)["next_required"],
                               observation_only=True)
            return self._refuse(agent_id, action, "ALREADY_CONFIRMED",
                                f"Task {task_id} is already confirmed; move to the next obligation.")
        # --- P0-6: READ under a task's own read_tools -------------------
        # WORLD_DSL gives every task read_tools, including WRITE tasks:
        # agents must observe before acting. Such a read is not governed by
        # whether READ is one of the task's closing kinds.
        if kind == "READ" and read_tools and not own_read:
            return self._refuse(agent_id, action, "KIND_NOT_ALLOWED",
                                f"Task {task_id} may read only with its own read_tools "
                                f"{read_tools}, not {action.get('tool')!r}.")
        if kind not in ob.kinds and not own_read:
            hint = self._kind_hint(ob, kind, action)
            return self._refuse(agent_id, action, "KIND_NOT_ALLOWED", hint)
        open_deps = reg.open_deps(task_id)
        if open_deps:
            if kind == "READ" and "READ" in ob.kinds:
                # Plain observation before deps are confirmed (P0-6): allowed,
                # but the registry records it stale, so it does not close the
                # task. Identifier provenance still applies to its args.
                ok, why = reg.identifier_provenance_ok(ob, action.get("args") or {})
                if not ok:
                    return self._refuse(agent_id, action, "IDENTIFIER_PROVENANCE",
                                        f"{why}; use identifiers from confirmed upstream evidence only.")
                return Verdict(True, "OBSERVATION_ONLY",
                               "Observation before dependencies are confirmed; "
                               "it does not close this task, re-read once eligible.",
                               self.next_required(agent_id)["next_required"],
                               observation_only=True)
            return self._refuse(agent_id, action, "DEPENDENCIES_OPEN",
                                f"Task {task_id} waits on {', '.join(open_deps)}; "
                                f"evidence taken now would be stale and would not close it.")
        if kind == "COMMUNICATE":
            recips = ob.task.get("recipients") or []
            if not recips:
                others = [f"{t} -> {o.task.get('recipients')}" for t, o in reg.obligations.items()
                          if o.agent_id == agent_id and o.task.get("recipients")]
                return self._refuse(agent_id, action, "NO_RECIPIENTS",
                                    f"Task {task_id} has no recipients; send under a task that does. "
                                    f"Your communication tasks: {others}")
            if action.get("to") not in recips:
                return self._refuse(agent_id, action, "WRONG_RECIPIENT",
                                    f"Task {task_id} may only send to {recips}, not {action.get('to')!r}.")
            # WO008-02: content must be grounded in verified evidence.
            probe = {"facts": action.get("facts") or action.get("content") or
                     action.get("propositions"),
                     "body": action.get("body"),
                     "evidence_refs": action.get("evidence_refs") or []}
            okc, whyc = reg.validate_message_content(ob, probe)
            if not okc:
                if whyc.startswith("CONTENT_COST_"):
                    reads = [{"task": tid, "tool": tool}
                             for tid, candidate in reg.obligations.items()
                             if candidate.agent_id == agent_id
                             for tool in candidate.task.get("read_tools") or []]
                    return self._refuse(
                        agent_id, action, "MESSAGE_CONTENT_UNVERIFIED",
                        f"{whyc}: read both remaining budget and catalog unit price "
                        f"before a financial decision. Own task/tool pairs: {reads}. "
                        "Do not infer price from requested quantity or budget. "
                        "Confirmed source tasks may still gather missing evidence.")
                return self._refuse(agent_id, action, "MESSAGE_CONTENT_UNVERIFIED",
                                    f"Message content is not grounded in verified "
                                    f"source evidence ({whyc}); cite/derive the "
                                    "required propositions from confirmed evidence.")
            # WO008-04: a message may not invent a consequential outcome.
            # After a REFUSE terminal, claiming that same cancellation (or
            # any un-verified WRITE outcome) succeeded is false evidence.
            body_l = str(action.get("body") or "").lower()
            # Negated mentions ("no subscription was cancelled") report the
            # refusal honestly and are not false outcome claims.
            claim_l = re.sub(r"\b(no|not|never|declined|refused)\b[^.]*cancel\w*",
                             "", body_l)
            if ("cancelled" in claim_l or "canceled" in claim_l) and any(
                    o.agent_id == agent_id and "WRITE" in o.kinds
                    and "WRITE" not in o.satisfied
                    for o in reg.obligations.values()):
                return self._refuse(agent_id, action, "MESSAGE_FALSE_OUTCOME_CLAIM",
                                    "Message claims a cancellation succeeded, but no "
                                    "WRITE obligation of yours is VERIFIED; report the "
                                    "actual refusal/consequence instead.")
        if kind == "REFUSE":
            # Legitimate REFUSE task (kind check above already passed): admit,
            # but the refusal only completes the mission when accompanied by
            # the agent's required COMMUNICATE obligations (see next_required).
            comms = [t for t in reg.by_agent.get(agent_id, [])
                     if "COMMUNICATE" in reg.obligations[t].kinds
                     and not reg.obligations[t].confirmed]
            return Verdict(True, "ADMISSIBLE_WITH_COMMUNICATION_REQUIRED",
                           f"After refusing, also deliver the required communication under {comms}."
                           if comms else "",
                           self.next_required(agent_id)["next_required"])
        if kind == "WAIT":
            want = ob.task.get("wait_for")
            if want and action.get("event_id") not in (want, None):
                return self._refuse(agent_id, action, "WRONG_EVENT",
                                    f"Task {task_id} must wait for event {want!r}.")
        if kind == "READ":
            ok, why = reg.identifier_provenance_ok(ob, action.get("args") or {})
            if not ok:
                return self._refuse(agent_id, action, "IDENTIFIER_PROVENANCE",
                                    f"{why}; use identifiers from confirmed upstream evidence only.")
            if "READ" not in ob.kinds:
                # Own-read_tools observation for a non-READ task (P0-6):
                # admissible, never closes that task.
                return Verdict(True, "ADMISSIBLE", "", self.next_required(agent_id)["next_required"],
                               observation_only=True)
        if kind == "ANALYZE":
            refs = action.get("evidence_refs") or []
            probe = {"kind": "ANALYSIS_RECORD", "task_id": task_id,
                     "evidence_refs": refs, "facts": action.get("answer")}
            ok, why = reg.validate_analysis(ob, probe)
            part = reg.analyze_ref_partition(ob, refs)
            if not ok:
                if why.startswith("AGGREGATE_"):
                    return self._refuse(
                        agent_id, action, f"ANALYZE_{why}",
                        f"{why}: derive total_processed by summing each assigned "
                        "partition's processed increment (log_end minus pre-drain "
                        "committed offset) from confirmed evidence. Derive "
                        "all_lag_zero from the latest confirmed lag observation, "
                        "not historical backlog. Recalculate; never assume equal "
                        "counts per partition. No analysis was recorded.")
                return self._refuse(agent_id, action, f"ANALYZE_{why}",
                                    "Cite real observation ids from your dependency chain "
                                    "(confirmed reads); fabricated ids never verify. "
                                    f"valid={part['valid']} stale={part['stale']} "
                                    f"unknown={part['unknown']} wrong_task={part['wrong_task']}")
            if part["stale"]:
                # P0-12: admitted on the fresh valid refs; stale refs are
                # reported (controller log via Verdict fields, and the hint
                # returned to the agent), not treated as fatal.
                return Verdict(True, "ADMISSIBLE",
                               f"Admitted on fresh evidence {part['valid']}; "
                               f"stale refs ignored (not counted as evidence): {part['stale']}.",
                               self.next_required(agent_id)["next_required"],
                               stale_refs=part["stale"], valid_refs=part["valid"])
        if kind == "WRITE":
            # WO008-04 (S100): an action claiming to consume a delegate
            # result must cite an authentic, confirmed, current result
            # reference from a *different* agent, and the cited facts must
            # bind the consequential arguments (partition / offset).
            delegate_ref = action.get("delegate_result_ref")
            if delegate_ref:
                entry = reg.observations.get(delegate_ref)
                if entry is None or not entry.get("_confirmed"):
                    return self._refuse(agent_id, action, "DELEGATE_REF_UNVERIFIED",
                                        f"Delegate result {delegate_ref!r} is not a "
                                        "confirmed observation; unconsumed or fabricated "
                                        "delegate results never authorize a WRITE.")
                if entry.get("agent_id") in (None, agent_id):
                    return self._refuse(agent_id, action, "DELEGATE_REF_SELF",
                                        "A delegate result must come from a different "
                                        "recipient agent, not from the consuming agent.")
                if not entry.get("decision_ref"):
                    return self._refuse(agent_id, action, "DELEGATE_REF_NO_PROVENANCE",
                                        "Delegate result carries no decision provenance.")
                if type(entry.get("epoch")) is not int or entry.get("epoch") != reg.epoch:
                    return self._refuse(agent_id, action, "DELEGATE_REF_STALE_EPOCH",
                                        "Delegate result is from a stale epoch.")
                if not entry.get("attempt_uid") or (
                        reg.attempt_uid and entry.get("attempt_uid") != reg.attempt_uid):
                    return self._refuse(agent_id, action, "DELEGATE_REF_ATTEMPT_MISMATCH",
                                        "Delegate result attempt identity is absent or mismatched.")
                _expw = getattr(reg, "expected_world_instance_id", None) or \
                    getattr(reg, "world_instance_id", None)
                if not entry.get("world_instance_id") or (
                        _expw and entry.get("world_instance_id") != _expw):
                    return self._refuse(agent_id, action, "DELEGATE_REF_WORLD_MISMATCH",
                                        "Delegate result world identity is absent or mismatched.")
                dargs = action.get("args") or {}
                eargs = entry.get("args") or {}
                if dargs.get("partition") is not None and \
                        eargs.get("partition") != dargs.get("partition"):
                    return self._refuse(agent_id, action, "DELEGATE_REF_PARTITION_MISMATCH",
                                        f"Delegate result was for partition "
                                        f"{eargs.get('partition')!r}, not "
                                        f"{dargs.get('partition')!r}.")
                facts = entry.get("facts") or {}
                if dargs.get("from_offset") is not None and \
                        facts.get("committed") != dargs.get("from_offset"):
                    return self._refuse(agent_id, action, "DELEGATE_REF_OFFSET_MISMATCH",
                                        "Consequential from_offset does not equal the "
                                        "delegate-verified committed offset.")
            # WO008-03: semantic action binding, compiled fresh from the
            # public spec + verified evidence. This only tightens the
            # activation gates above; sidecar admission is never a
            # substitute for CAGE/VEIP/ZTL authorization downstream.
            try:
                from causal_007.action_binding import validate_action_binding
            except ImportError:
                from action_binding import validate_action_binding  # type: ignore
            _ep = action.get("epoch", action.get("permit_epoch"))
            okb, codeb, binding = validate_action_binding(
                reg, task_id, tool=action.get("tool"), target=action.get("target"),
                args=action.get("args") or {},
                attempt_uid=action.get("attempt_uid"),
                world_instance_id=action.get("world_instance_id"),
                epoch=int(_ep) if isinstance(_ep, int) else None)
            if not okb:
                if codeb == "BINDING_TARGET_MISMATCH":
                    return self._refuse(
                        agent_id, action, codeb,
                        f"Task {task_id} requires target={ob.task.get('target')!r}. "
                        "Include this target field separately from tool args; "
                        "target does not replace any required named argument.")
                if codeb in ("SHARD_PARTITION_REQUIRED", "SHARD_PARTITION_TARGET_MISMATCH"):
                    return self._refuse(
                        agent_id, action, codeb,
                        f"For task {task_id}, target and args.partition must both "
                        f"equal the public assigned partition {ob.task.get('target')!r}. "
                        "Include args.from_offset from its confirmed partition.offsets "
                        "observation. A target field does not supply args.partition.")
                if codeb == "AMB_IDENTITY_NOT_UNIQUE" and "REFUSE" in ob.kinds:
                    return self._refuse(
                        agent_id, action, codeb,
                        f"Identity is ambiguous. Do not choose a candidate. "
                        f"Use action=refuse, task={task_id}, reason explaining "
                        "the ambiguity; then use your separate COMMUNICATE "
                        "task to request clarification from its listed recipient. "
                        "No WRITE occurred.")
                return self._refuse(
                    agent_id, action, codeb,
                    f"Action is not bound to the public contract ({codeb}); "
                    f"binding={binding.to_dict()}")
            # WO008-02 lifecycle: ELIGIBLE -> ADMITTED at admission time;
            # only effect+receipt+readback can move it to VERIFIED.
            reg.note_write_admitted(task_id, agent_id=agent_id,
                                    command_id=action.get("command_id"))
        return Verdict(True, "ADMISSIBLE", "", self.next_required(agent_id)["next_required"])

    def _kind_hint(self, ob, kind, action):
        if "REFUSE" in ob.kinds and kind not in ob.kinds:
            return (f"Task {ob.task_id} permits {ob.kinds}. For a refusal use "
                    f"action=refuse, task={ob.task_id}, reason explaining why. "
                    "Encoding REFUSE as analyze/send/write does not record a refusal; "
                    "communication uses your separate COMMUNICATE task.")
        if kind == "REFUSE":
            comms = [t for t, o in self.registry.obligations.items()
                     if o.agent_id == ob.agent_id and "COMMUNICATE" in o.kinds]
            return (f"Task {ob.task_id} does not allow REFUSE. Deliver your findings by "
                    f"send under {comms} instead; refusal belongs to its own REFUSE task.")
        if kind == "COMMUNICATE":
            sends = [t for t, o in self.registry.obligations.items()
                     if o.agent_id == ob.agent_id and "COMMUNICATE" in o.kinds]
            return (f"Task {ob.task_id} allows only {ob.kinds}; send is not one of them. "
                    f"Deliver messages under your COMMUNICATE task(s) {sends} "
                    f"(to their listed recipients) instead.")
        if kind == "READ":
            reads = [{"task": tid, "tool": tool}
                     for tid, candidate in self.registry.obligations.items()
                     if candidate.agent_id == ob.agent_id
                     for tool in candidate.task.get("read_tools") or []]
            return (f"Use your own source task/tool pairs for READ: {reads}. "
                    f"Task {ob.task_id} allows only {ob.kinds}; "
                    "a communication task cannot authorize a read. "
                    "The normal evidence, dependency and repeat checks still apply.")
        return (f"Task {ob.task_id} allows only {ob.kinds}; the requested {kind} is not "
                f"one of its kinds. Use an action matching the task's kinds.")

    # ------------------------------------------------------------ WP-C feedback
    def note_result(self, agent_id, action, http_status, payload):
        """Convert a world result into an explicit corrective hint (public data)."""
        hint = None
        text = ""
        if isinstance(payload, dict):
            text = str(payload.get("error") or "")
        m = _RENAMED_RE.search(text)
        if m:
            hint = (f"Parameter renamed: use '{m.group(2)}' instead of '{m.group(1)}' "
                    f"for this endpoint; do not repeat the old name.")
        elif http_status in (400, 403):
            fallback = "check task, tool, recipients and identifiers against the public spec."
            hint = f"World refused with HTTP {http_status}: {text or fallback}"
        elif isinstance(payload, dict) and payload.get("data") is not None and \
                isinstance(payload.get("data"), dict) and \
                all(v is None for v in payload["data"].values()):
            hint = ("Observation returned null data; the identifiers used were probably "
                    "not obtained from upstream evidence. Re-read the upstream source first.")
        if hint:
            self.log({"event": "CAUSAL_CORRECTION", "agent_id": agent_id,
                      "action": action, "http_status": http_status, "hint": hint})
        return hint

    def check_exit(self, agent_id, reason):
        """WP-A: an agent may not exit 'all tasks terminal' with open obligations."""
        self._refresh_activations()
        if getattr(self.registry, "feed_unavailable", False) and \
                reason == "all_tasks_terminal":
            verdict = Verdict(False, "EVIDENCE_FEED_UNAVAILABLE",
                              "Authoritative evidence feed is unavailable; "
                              "DONE cannot be claimed until an independent "
                              "refresh succeeds.")
            self.log({"event": "CAUSAL_REFUSAL", "agent_id": agent_id,
                      "action": {"action": "exit", "reason": reason},
                      "code": verdict.code, "hint": verdict.hint})
            return verdict
        if reason != "all_tasks_terminal":
            return Verdict(True, "EXIT_OK")
        # WO008-01: unresolved critical conditions cannot become DONE.
        unresolved = self.registry.unresolved_activations(agent_id)
        if unresolved:
            verdict = Verdict(
                False,
                "ACTIVATION_UNRESOLVED",
                f"Critical conditional activation unresolved: {unresolved}"
            )
            self.log({
                "event": "CAUSAL_REFUSAL",
                "agent_id": agent_id,
                "action": {
                    "action": "exit",
                    "reason": reason
                },
                "code": verdict.code,
                "hint": verdict.hint
            })
            return verdict
        ok, open_ = self.registry.can_exit(agent_id)
        if ok:
            return Verdict(True, "EXIT_OK")
        verdict = Verdict(False, "EXIT_BLOCKED_OPEN_OBLIGATIONS",
                          f"Mandatory obligations still unconfirmed: {open_}. "
                          f"Next: {self.next_required(agent_id)['next_required']}")
        self.log({"event": "CAUSAL_REFUSAL", "agent_id": agent_id,
                  "action": {"action": "exit", "reason": reason},
                  "code": verdict.code, "hint": verdict.hint})
        return verdict
