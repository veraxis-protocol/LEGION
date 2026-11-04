"""Pure, deterministic LEGION structural world engine (stdlib only, no I/O).

Implements ``legion.world.v1`` semantics from ``WORLD_DSL.md`` exactly:
paths/templates, predicates, value specs, tool parameter validation,
``param_renamed`` / ``error_first_n`` / ``lost_reply_nth`` faults,
native preconditions, pre-state value-spec evaluation, derived rules,
environment events and ANALYZE answer validation.

Ambiguity resolved here (documented, not world-specific): a path template
is split into dot-separated segments *before* substitution.  A placeholder
that occupies a whole segment is therefore one state key, even when the
substituted value itself contains dots (e.g. an e-mail address used as a
CRM key).  A placeholder embedded inside a larger segment (or inside a
write target) is rejected with 400 when its value contains ``.``, because
there it would silently create extra path segments -- that is the case
the DSL's dot rule guards against.

No network, file or clock I/O is performed: the clock is injectable
(``clock=`` callable returning monotonic seconds, default
``time.monotonic``) purely so tests can control event timing.
"""

import copy
import json
import os
import re
import time
import uuid

_MISSING = object()
_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_FULL_PLACEHOLDER_RE = re.compile(r"^\{([A-Za-z_][A-Za-z0-9_]*)\}$")


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


class World:
    """One world instance. ``spec`` is a parsed world dict (deep-copied)."""

    def __init__(self, spec, clock=None):
        # Accept a parsed dict; a path / JSON string is also accepted
        # for convenience and normalised to the same deep-copied dict.
        if isinstance(spec, (str, os.PathLike)):
            text = None
            try:
                if os.path.exists(spec):
                    with open(spec, encoding="utf-8") as fh:
                        text = fh.read()
            except (OSError, ValueError):
                text = None
            spec = json.loads(text if text is not None else spec)
        if not isinstance(spec, dict):
            raise TypeError("world spec must be a dict")
        self.spec = copy.deepcopy(spec)
        self.world_id = self.spec.get("world_id")
        self.initial_state = copy.deepcopy(self.spec.get("initial_state") or {})
        self.state = copy.deepcopy(self.initial_state)
        self.tools = self.spec.get("tools") or {}
        self.events_spec = self.spec.get("events") or []
        self.derived = self.spec.get("derived") or []
        self.roles = self.spec.get("roles") or []

        self._clock = clock or time.monotonic
        self._start_mono = float(self._clock())

        # Roles / tasks. Task ids are scoped to their owning role: the
        # same task id may appear under different roles in some worlds.
        self.roles_by_id = {}
        self._tasks_by_agent = {}
        self._task_by_global_id = {}
        for role in self.roles:
            agent_id = role.get("agent_id")
            self.roles_by_id[agent_id] = role
            by_id = {}
            for task in role.get("tasks") or []:
                by_id[task.get("task_id")] = task
                self._task_by_global_id.setdefault(task.get("task_id"), task)
            self._tasks_by_agent[agent_id] = by_id

        self.effect_ledger = []
        self._seen_commands = {}  # command_id -> (status, result) for applied calls
        self._tool_call_counts = {}  # tool -> number of counted write calls
        self._fired_events = set()
        self._first_effect_rel = {}  # tool -> t_rel of its first applied effect
        # agent_id -> [notice strings], in delivery order.
        self.notices = {}
        self.notice_records = []

    @property
    def effects(self):
        """Alias for the effect ledger."""
        return self.effect_ledger

    # ------------------------------------------------------------------
    # Clock
    # ------------------------------------------------------------------
    def now_mono(self):
        return float(self._clock())

    def now_rel(self):
        return float(self._clock()) - self._start_mono

    # ------------------------------------------------------------------
    # Paths, templates, values
    # ------------------------------------------------------------------
    def _render_segments(self, template, params):
        """Split a path template into segments, then substitute params.

        Whole-segment placeholders keep a dotted value as one key;
        placeholders embedded in a larger segment reject dotted values.
        Raises KeyError for a missing param, ValueError for a dotted
        embedded substitution.
        """
        params = params or {}
        segments = []
        for segment in str(template).split("."):
            full = _FULL_PLACEHOLDER_RE.match(segment)
            if full:
                name = full.group(1)
                if name not in params:
                    raise KeyError(name)
                segments.append(str(params[name]))
                continue

            def _sub(match):
                name = match.group(1)
                if name not in params:
                    raise KeyError(name)
                value = params[name]
                if isinstance(value, str) and "." in value:
                    raise ValueError(
                        f"invalid parameter '{name}': value must not contain '.'"
                    )
                return str(value)

            segments.append(_PLACEHOLDER_RE.sub(_sub, segment))
        return segments

    def render_target(self, template, params):
        """Render a write-tool target string; dotted values are rejected."""
        params = params or {}

        def _sub(match):
            name = match.group(1)
            if name not in params:
                raise KeyError(name)
            value = params[name]
            if isinstance(value, str) and "." in value:
                raise ValueError(
                    f"invalid parameter '{name}': value must not contain '.'"
                )
            return str(value)

        return _PLACEHOLDER_RE.sub(_sub, str(template))

    @staticmethod
    def _get_segments(state, segments):
        cur = state
        for seg in segments:
            if isinstance(cur, dict):
                if seg not in cur:
                    return _MISSING
                cur = cur[seg]
            elif isinstance(cur, list) and seg.isdigit():
                idx = int(seg)
                if idx >= len(cur):
                    return _MISSING
                cur = cur[idx]
            else:
                return _MISSING
        return cur

    def value_at(self, state, path_template, params=None):
        """Value at a (possibly templated) path, or None when missing."""
        segments = self._render_segments(path_template, params or {})
        value = self._get_segments(state, segments)
        return None if value is _MISSING else copy.deepcopy(value)

    def _set_segments(self, segments, value):
        cur = self.state
        for seg in segments[:-1]:
            nxt = cur.get(seg) if isinstance(cur, dict) else None
            if not isinstance(nxt, dict):
                nxt = {}
                cur[seg] = nxt
            cur = nxt
        cur[segments[-1]] = value

    def evaluate_value_spec(self, state, spec, params=None):
        """Evaluate a DSL value spec against ``state`` (pre-call state)."""
        params = params or {}
        if isinstance(spec, dict):
            keys = set(spec)
            if "param" in keys and keys <= {"param", "negate"}:
                name = spec["param"]
                if name not in params:
                    raise KeyError(name)
                value = copy.deepcopy(params[name])
                if spec.get("negate"):
                    if not _is_number(value):
                        raise ValueError(f"parameter '{name}' is not numeric")
                    value = -value
                return value
            if keys == {"path"}:
                segments = self._render_segments(spec["path"], params)
                value = self._get_segments(state, segments)
                return None if value is _MISSING else copy.deepcopy(value)
            if keys == {"path_minus_param"}:
                template, name = spec["path_minus_param"]
                if name not in params:
                    raise KeyError(name)
                segments = self._render_segments(template, params)
                base = self._get_segments(state, segments)
                if not _is_number(base) or not _is_number(params[name]):
                    raise ValueError("path_minus_param requires numeric operands")
                return base - params[name]
        return copy.deepcopy(spec)

    # ------------------------------------------------------------------
    # Predicates (semantics identical to the judge)
    # ------------------------------------------------------------------
    def predicate(self, state, p, params=None):
        params = params or {}
        try:
            segments = self._render_segments(p.get("path", ""), params)
        except (KeyError, ValueError):
            return False
        actual = self._get_segments(state, segments)
        op = p.get("op")
        if op == "exists":
            return actual is not _MISSING
        if op == "absent":
            return actual is _MISSING
        if actual is _MISSING:
            return False
        expected_raw = p.get("value")
        if isinstance(expected_raw, dict) and set(expected_raw) <= {"param", "negate"} \
                and "param" in expected_raw:
            try:
                expected = self.evaluate_value_spec(state, expected_raw, params)
            except (KeyError, ValueError):
                return False
        else:
            expected = expected_raw

        if op == "eq":
            if isinstance(actual, bool) != isinstance(expected, bool):
                return False
            return actual == expected
        if op == "ne":
            if isinstance(actual, bool) != isinstance(expected, bool):
                return True
            return actual != expected
        if op in ("ge", "le"):
            if not _is_number(actual) or not _is_number(expected):
                return False
            return actual >= expected if op == "ge" else actual <= expected
        if op == "contains":
            if isinstance(actual, str):
                return isinstance(expected, str) and expected in actual
            if isinstance(actual, (list, tuple)):
                return any(item == expected for item in actual)
            if isinstance(actual, dict):
                return expected in actual
            return False
        if op == "set_eq":
            if not isinstance(actual, list) or not isinstance(expected, list):
                return False

            def _has_dup(items):
                seen = []
                for item in items:
                    if any(item == s for s in seen):
                        return True
                    seen.append(item)
                return False

            if _has_dup(actual) or _has_dup(expected):
                return False
            if len(actual) != len(expected):
                return False
            return all(any(a == e for e in expected) for a in actual)
        return False

    # ------------------------------------------------------------------
    # Roles / tasks / authorisation helpers
    # ------------------------------------------------------------------
    def role_for(self, agent_id):
        return self.roles_by_id.get(agent_id)

    def task_for(self, agent_id, task_id):
        """The caller's own task dict, or None if it is not theirs."""
        return self._tasks_by_agent.get(agent_id, {}).get(task_id)

    def tasks_for(self, agent_id):
        role = self.roles_by_id.get(agent_id) or {}
        return copy.deepcopy(role.get("tasks") or [])

    def can_read(self, agent_id, task_id, tool):
        task = self.task_for(agent_id, task_id)
        return bool(task) and tool in (task.get("read_tools") or [])

    def can_write(self, agent_id, task_id, tool, target):
        task = self.task_for(agent_id, task_id)
        if not task:
            return False
        return task.get("write_tool") == tool and task.get("target") == target

    def can_send(self, agent_id, task_id, recipient):
        task = self.task_for(agent_id, task_id)
        return bool(task) and recipient in (task.get("recipients") or [])

    # ------------------------------------------------------------------
    # Parameter validation (incl. param_renamed faults)
    # ------------------------------------------------------------------
    def _renamed_faults(self, tool_spec):
        active, inactive = [], []
        for fault in tool_spec.get("faults") or []:
            if fault.get("type") != "param_renamed":
                continue
            after = fault.get("after_event")
            if after is None or after in self._fired_events:
                active.append(fault)
            else:
                inactive.append(fault)
        return active

    def effective_params(self, tool_name):
        """Declared params after any active param_renamed fault is applied."""
        tool_spec = self.tools.get(tool_name) or {}
        params = copy.deepcopy(tool_spec.get("params") or {})
        for fault in self._renamed_faults(tool_spec):
            old, new = fault.get("old"), fault.get("new")
            if old in params and new not in params:
                params[new] = params.pop(old)
            elif old in params:
                params.pop(old, None)
        return params

    def validate_params(self, tool_name, args):
        """Return (status, error_dict_or_None). 200 means valid."""
        tool_spec = self.tools.get(tool_name)
        if tool_spec is None:
            return 404, {"error": f"unknown tool '{tool_name}'"}
        if args is None:
            args = {}
        if not isinstance(args, dict):
            return 400, {"error": "args must be an object"}
        # param_renamed takes precedence so the exact DSL text is returned
        # even when the caller also omits the new name.
        for fault in self._renamed_faults(tool_spec):
            old, new = fault.get("old"), fault.get("new")
            if old in args:
                return 400, {
                    "error": f"unknown parameter '{old}'; this endpoint now expects '{new}'"
                }
        effective = self.effective_params(tool_name)
        for name in args:
            if name not in effective:
                return 400, {"error": f"unknown parameter '{name}'"}
        for name in effective:
            if name not in args:
                return 400, {"error": f"missing parameter '{name}'"}
        for name, pspec in effective.items():
            value = args[name]
            ptype = pspec.get("type")
            if ptype == "string" and not isinstance(value, str):
                return 400, {"error": f"parameter '{name}' must be a string"}
            if ptype == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
                return 400, {"error": f"parameter '{name}' must be an integer"}
            if "enum" in pspec and value not in pspec["enum"]:
                return 400, {"error": f"parameter '{name}' must be one of {pspec['enum']}"}
            if _is_number(value):
                if "min" in pspec and value < pspec["min"]:
                    return 400, {"error": f"parameter '{name}' is below minimum {pspec['min']}"}
                if "max" in pspec and value > pspec["max"]:
                    return 400, {"error": f"parameter '{name}' exceeds maximum {pspec['max']}"}
        return 200, None

    # ------------------------------------------------------------------
    # Effects / derived rules
    # ------------------------------------------------------------------
    def _prepare_effects(self, effects, params, pre_state):
        """Evaluate ALL value specs against pre_state before applying any."""
        prepared = []
        for eff in effects or []:
            segments = self._render_segments(eff.get("path", ""), params)
            value = self.evaluate_value_spec(pre_state, eff.get("value"), params)
            prepared.append((eff.get("op"), segments, value))
        return prepared

    def _apply_prepared(self, prepared):
        applied = []
        for op, segments, value in prepared:
            path = ".".join(segments)
            if op == "set":
                self._set_segments(segments, copy.deepcopy(value))
            elif op == "inc":
                if not _is_number(value):
                    raise ValueError("inc value is not numeric")
                cur = self._get_segments(self.state, segments)
                if cur is _MISSING:
                    cur = 0
                if not _is_number(cur):
                    raise ValueError(f"cannot inc non-numeric value at '{path}'")
                self._set_segments(segments, cur + value)
            elif op == "append":
                cur = self._get_segments(self.state, segments)
                if cur is _MISSING:
                    self._set_segments(segments, [copy.deepcopy(value)])
                elif isinstance(cur, list):
                    cur.append(copy.deepcopy(value))
                else:
                    raise ValueError(f"cannot append to non-list at '{path}'")
            else:
                raise ValueError(f"unknown effect op '{op}'")
            applied.append({"op": op, "path": path, "value": copy.deepcopy(value)})
        return applied

    def _apply_effects(self, effects, params):
        pre = copy.deepcopy(self.state)
        prepared = self._prepare_effects(effects, params, pre)
        return self._apply_prepared(prepared)

    def _run_derived(self):
        for _ in range(10):
            before = copy.deepcopy(self.state)
            for rule in self.derived:
                when = rule.get("when") or []
                if all(self.predicate(self.state, p, {}) for p in when):
                    self._apply_effects(rule.get("effects") or [], {})
            if self.state == before:
                break

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def call_read(self, tool, args):
        args = args or {}
        tool_spec = self.tools.get(tool)
        if tool_spec is None:
            return 404, {"error": f"unknown tool '{tool}'"}
        if tool_spec.get("kind") != "read":
            return 400, {"error": f"tool '{tool}' is not a read tool"}
        status, err = self.validate_params(tool, args)
        if status != 200:
            return status, err
        data = {}
        try:
            for key, template in (tool_spec.get("returns") or {}).items():
                data[key] = self.value_at(self.state, template, args)
        except KeyError as exc:
            return 400, {"error": f"missing parameter '{exc.args[0]}'"}
        except ValueError as exc:
            return 400, {"error": str(exc)}
        return 200, data

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------
    def call_write(self, command_id, tool, target, args):
        args = args or {}
        # 1. Idempotency: a repeated command_id returns the original
        #    result with no new effect (only applied calls are recorded;
        #    refused calls may be retried under the same command_id).
        if command_id in self._seen_commands:
            orig_status, orig_result = self._seen_commands[command_id]
            result = copy.deepcopy(orig_result)
            result["duplicate"] = True
            return orig_status, result
        tool_spec = self.tools.get(tool)
        if tool_spec is None:
            return 404, {"error": f"unknown tool '{tool}'"}
        if tool_spec.get("kind") != "write":
            return 400, {"error": f"tool '{tool}' is not a write tool"}
        # 2. Param validation.
        status, err = self.validate_params(tool, args)
        if status != 200:
            return status, err
        # 3. Target check: rendered tool target must equal given target.
        try:
            rendered = self.render_target(tool_spec.get("target", ""), args)
        except KeyError as exc:
            return 400, {"error": f"missing parameter '{exc.args[0]}'"}
        except ValueError as exc:
            return 400, {"error": str(exc)}
        if rendered != target:
            return 400, {
                "error": f"target mismatch: expected '{rendered}', got '{target}'"
            }
        # 4. Faults, counted per tool per world instance. The counter
        #    increments for every call reaching this stage, so an
        #    error_first_n call also counts toward lost_reply_nth.
        count = self._tool_call_counts.get(tool, 0) + 1
        self._tool_call_counts[tool] = count
        lost_pending = False
        for fault in tool_spec.get("faults") or []:
            if fault.get("type") == "error_first_n" and count <= int(fault.get("n", 0)):
                fstatus = int(fault.get("status", 503))
                return fstatus, {"error": f"tool '{tool}' temporarily unavailable"}
            if fault.get("type") == "lost_reply_nth" and count == int(fault.get("n", 0)):
                lost_pending = True
        # 5. Native preconditions.
        try:
            for pre in tool_spec.get("native_preconditions") or []:
                if not self.predicate(self.state, pre, args):
                    return 409, {
                        "error": f"native precondition failed: {pre.get('path')} {pre.get('op')}"
                    }
            # 6. Evaluate ALL value specs pre-call, then apply.
            applied = self._apply_effects(tool_spec.get("effects") or [], args)
        except KeyError as exc:
            return 400, {"error": f"missing parameter '{exc.args[0]}'"}
        except ValueError as exc:
            return 400, {"error": str(exc)}
        # 7. Derived rules to a fixed point (bounded in _run_derived).
        self._run_derived()
        # 8. Effect ledger entry.
        t_mono = self.now_mono()
        entry = {
            "seq": len(self.effect_ledger) + 1,
            "effect_id": f"eff-{uuid.uuid4().hex[:12]}",
            "command_id": command_id,
            "tool": tool,
            "target": target,
            "args": copy.deepcopy(args),
            "effects_applied": applied,
            "t_mono": t_mono,
            "t_rel": t_mono - self._start_mono,
        }
        self.effect_ledger.append(entry)
        self._first_effect_rel.setdefault(tool, entry["t_rel"])
        result = {
            "status": "applied",
            "effect_id": entry["effect_id"],
            "seq": entry["seq"],
            "command_id": command_id,
            "tool": tool,
            "target": target,
            "args": copy.deepcopy(args),
            "effects_applied": copy.deepcopy(applied),
        }
        final_status = "LOST_REPLY" if lost_pending else 200
        self._seen_commands[command_id] = (final_status, copy.deepcopy(result))
        return final_status, result

    def reconcile(self, command_id):
        for entry in self.effect_ledger:
            if entry.get("command_id") == command_id:
                return copy.deepcopy(entry)
        return None

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------
    def _first_effect_times(self, effect_history):
        times = dict(self._first_effect_rel)
        if effect_history is None:
            return times
        entries = []
        if isinstance(effect_history, dict):
            for tool_name, tval in effect_history.items():
                entries.append({"tool": tool_name, "t_rel": tval})
        else:
            entries = list(effect_history)
        parsed = {}
        for entry in entries:
            if not isinstance(entry, dict) or "tool" not in entry:
                continue
            tval = None
            if "t_rel" in entry:
                tval = entry["t_rel"]
            elif "t_mono" in entry:
                raw = entry["t_mono"]
                tval = raw - self._start_mono if raw >= self._start_mono else raw
            if _is_number(tval):
                parsed[entry["tool"]] = min(tval, parsed.get(entry["tool"], tval))
                if entry["tool"] not in parsed or tval < parsed[entry["tool"]]:
                    parsed[entry["tool"]] = tval
        # Explicitly supplied history wins over internal bookkeeping.
        times.update(parsed)
        return times

    def due_events(self, now_rel=None, effect_history=None):
        if now_rel is None:
            now_rel = self.now_rel()
        first_times = self._first_effect_times(effect_history)
        due = []
        for event in self.events_spec:
            event_id = event.get("event_id")
            if event_id in self._fired_events:
                continue
            when = event.get("when") or {}
            if "at_s" in when:
                if now_rel >= float(when["at_s"]):
                    due.append(copy.deepcopy(event))
            elif "after_effect" in when:
                tool_name = when["after_effect"]
                if tool_name in first_times and \
                        now_rel >= first_times[tool_name] + float(when.get("delay_s", 0)):
                    due.append(copy.deepcopy(event))
        return due

    def fire(self, event):
        """Apply an event's effects + derived rules, once. Returns the
        fired event dict, or None if unknown / already fired."""
        if isinstance(event, str):
            event_id = event
            spec_event = next(
                (e for e in self.events_spec if e.get("event_id") == event_id), None
            )
        else:
            spec_event = event
            event_id = (event or {}).get("event_id")
        if spec_event is None or event_id in self._fired_events:
            return None
        # Resolve against the spec so a caller cannot invent effects.
        canonical = next(
            (e for e in self.events_spec if e.get("event_id") == event_id), spec_event
        )
        self._fired_events.add(event_id)
        self._apply_effects(canonical.get("effects") or [], {})
        self._run_derived()
        notice = canonical.get("notice")
        record = {
            "event_id": event_id,
            "notice": notice,
            "notify_roles": list(canonical.get("notify_roles") or []),
            "t_mono": self.now_mono(),
            "t_rel": self.now_rel(),
        }
        self.notice_records.append(record)
        if notice is not None:
            for agent_id in record["notify_roles"]:
                self.notices.setdefault(agent_id, []).append(notice)
        return copy.deepcopy(canonical)

    def fired_events(self):
        return set(self._fired_events)

    # ------------------------------------------------------------------
    # Analyze
    # ------------------------------------------------------------------
    def analyze(self, task, answer, agent_id=None):
        """Validate ``answer`` against the task's answer_schema and, on
        success, store it at ``state.answers.<task_id>``.
        Returns (status, payload); 200 on success, 400 on violation."""
        if isinstance(task, dict):
            task_dict = task
            task_id = task.get("task_id")
            if agent_id is not None:
                owned = self.task_for(agent_id, task_id)
                if owned is not None:
                    task_dict = owned
            schema = task_dict.get("answer_schema")
            if schema is None:
                schema = (self._task_by_global_id.get(task_id) or {}).get("answer_schema", {})
        else:
            task_id = task
            if agent_id is not None:
                task_dict = self.task_for(agent_id, task_id)
            else:
                task_dict = self._task_by_global_id.get(task_id)
            if task_dict is None:
                return 404, {"error": f"unknown task '{task_id}'"}
            schema = task_dict.get("answer_schema") or {}
        if not isinstance(answer, dict):
            return 400, {"error": "answer must be an object"}
        schema = schema or {}
        for field in answer:
            if field not in schema:
                return 400, {"error": f"unknown answer field '{field}'"}
        for field, fspec in schema.items():
            if field not in answer:
                return 400, {"error": f"missing answer field '{field}'"}
            value = answer[field]
            fspec = fspec or {}
            if "enum" in fspec and value not in fspec["enum"]:
                return 400, {"error": f"answer field '{field}' must be one of {fspec['enum']}"}
            ftype = fspec.get("type")
            if ftype == "string" and not isinstance(value, str):
                return 400, {"error": f"answer field '{field}' must be a string"}
            if ftype == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
                return 400, {"error": f"answer field '{field}' must be an integer"}
            if ftype == "boolean" and not isinstance(value, bool):
                return 400, {"error": f"answer field '{field}' must be a boolean"}
            if ftype == "number" and not _is_number(value):
                return 400, {"error": f"answer field '{field}' must be a number"}
        answers = self.state.get("answers")
        if not isinstance(answers, dict):
            answers = {}
            self.state["answers"] = answers
        answers[task_id] = copy.deepcopy(answer)
        return 200, {"task_id": task_id, "answer": copy.deepcopy(answer)}

    def get_state(self):
        return copy.deepcopy(self.state)
