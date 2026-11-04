"""LEGION structural agent worker: one OS process per registered worker.

Env only (set by the mission host):
  STRUCT_AGENT_ID, STRUCT_WORLD_URL, STRUCT_WORLD_TOKEN, STRUCT_GATEWAY_URL,
  STRUCT_WORKLOAD_IDENTITY, STRUCT_WORLD_FILE, STRUCT_LOG,
  STRUCT_DECIDER = nim | scripted | standby,
  SCALE_PROXY_URL / SCALE_PROXY_TOKEN (per-agent, as SCALE-005) / SCALE_MODEL,
  STRUCT_PLAN (scripted only), STRUCT_MAX_TURNS (default 14),
  STRUCT_WALL_S (default 420).

A failed provider call follows REV4 backoff and never produces an action.
Scripted decider is INTEGRATION_ONLY qualification only and is always logged
as SCRIPTED_DECISION (never DECISION) with decision_ref ``scripted:<n>``.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request

SCRIPTED_LABEL = "SCRIPTED_DECIDER_INTEGRATION_ONLY_NOT_A_MODEL_AGENT"
VALID_ACTIONS = {"read", "write", "send", "analyze", "wait", "refuse", "reconcile", "done", "idle"}
TERMINAL_KINDS = {"OBSERVATION", "ANALYSIS_RECORD", "MESSAGE_DELIVERED",
                  "WAIT_OBSERVED", "RECONCILE", "AGENT_DONE"}


def backoff_s(consecutive_failures):
    """REV4 bounded exponential backoff: 2s, 4s, 8s, ... capped at 30s."""
    return min(2.0 ** max(1, consecutive_failures), 30.0)


def parse_action(text):
    """Parse exactly ONE JSON action object; any extra prose is rejected."""
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped.startswith("{") or not stripped.endswith("}"):
        return None
    try:
        obj = json.loads(stripped)
    except ValueError:
        return None
    if not isinstance(obj, dict) or obj.get("action") not in VALID_ACTIONS:
        return None
    return obj


def _get_path(data, path):
    cur = data
    for seg in str(path).split("."):
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        elif isinstance(cur, list) and seg.isdigit() and int(seg) < len(cur):
            cur = cur[int(seg)]
        else:
            return None, False
    return cur, True


def predicate_matches(data, pred) -> bool:
    """Small predicate check for scripted read ``until`` (DSL ops)."""
    if pred is None:
        return True
    if isinstance(pred, str):
        return pred in json.dumps(data, default=str)
    if not isinstance(pred, dict):
        return data == pred
    if "path" in pred and "op" in pred:
        actual, found = _get_path(data, pred["path"])
        op, expected = pred["op"], pred.get("value")
        if op == "exists":
            return found
        if op == "absent":
            return not found
        if not found:
            return False
        if op == "eq":
            return actual == expected
        if op == "ne":
            return actual != expected
        if op == "ge":
            return isinstance(actual, (int, float)) and not isinstance(actual, bool) and actual >= expected
        if op == "le":
            return isinstance(actual, (int, float)) and not isinstance(actual, bool) and actual <= expected
        if op == "contains":
            try:
                return expected in actual
            except TypeError:
                return False
        if op == "set_eq":
            return isinstance(actual, list) and isinstance(expected, list) \
                and len(actual) == len(expected) and all(any(a == e for e in expected) for a in actual)
        return False
    # Plain {key: expected} mapping (keys may be dotted paths).
    for key, expected in pred.items():
        actual, found = _get_path(data, key)
        if not found or actual != expected:
            return False
    return True


def substitute_placeholders(value, *, known_obs_ids, my_obs_ids, last_command_id):
    """Expand $known_obs_ids / $my_obs_ids / $last_command_id in a step."""
    if isinstance(value, str):
        if value == "$known_obs_ids":
            return list(known_obs_ids)
        if value == "$my_obs_ids":
            return list(my_obs_ids)
        if value == "$last_command_id":
            return last_command_id
        out = value.replace("$last_command_id", str(last_command_id or ""))
        out = out.replace("$known_obs_ids", ",".join(known_obs_ids))
        out = out.replace("$my_obs_ids", ",".join(my_obs_ids))
        return out
    if isinstance(value, list):
        return [substitute_placeholders(v, known_obs_ids=known_obs_ids,
                                        my_obs_ids=my_obs_ids, last_command_id=last_command_id)
                for v in value]
    if isinstance(value, dict):
        return {k: substitute_placeholders(v, known_obs_ids=known_obs_ids,
                                           my_obs_ids=my_obs_ids, last_command_id=last_command_id)
                for k, v in value.items()}
    return value


def http(method, url, body=None, headers=None, timeout=60):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw) if raw else {}
            except ValueError:
                return r.status, {"raw": raw.decode("utf-8", "replace")[:500]}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else {}
        except ValueError:
            return e.code, {"raw": raw.decode("utf-8", "replace")[:500]}
    except Exception as exc:
        return 0, {"error": type(exc).__name__}


def _legion_dependency_park(view):
    if not isinstance(view, dict):
        return True

    opened = view.get("open_obligations")
    obligations = view.get("obligations")

    if not isinstance(opened, list):
        return True
    if not isinstance(obligations, list):
        return True

    if not opened:
        return False

    if len(obligations) != len(opened):
        return True

    for ob in obligations:
        if not isinstance(ob, dict):
            return True
        deps = ob.get("open_dependencies")
        if not isinstance(deps, list):
            return True
        if not deps:
            return False

    return True


class Agent:
    def __init__(self):
        env = os.environ
        self.agent_id = env.get("STRUCT_AGENT_ID", "")
        self.world_url = (env.get("STRUCT_WORLD_URL") or "").rstrip("/")
        self.world_token = env.get("STRUCT_WORLD_TOKEN", "")
        self.gateway = (env.get("STRUCT_GATEWAY_URL") or "").rstrip("/")
        self.identity = env.get("STRUCT_WORKLOAD_IDENTITY", "")
        self.decider = env.get("STRUCT_DECIDER", "nim")
        self.proxy = (env.get("SCALE_PROXY_URL") or "").rstrip("/")
        suffix = "".join(ch if ch.isalnum() else "_" for ch in self.agent_id.replace("agent:", "")).upper()
        self.proxy_token = env.get(f"SCALE_PROXY_TOKEN_{suffix}") or env.get("SCALE_PROXY_TOKEN", "")
        self.model = env.get("SCALE_MODEL", "")
        self.max_turns = int(env.get("STRUCT_MAX_TURNS", "14") or "14")
        self.wall_s = float(env.get("STRUCT_WALL_S", "420") or "420")
        self.log_path = env.get("STRUCT_LOG") or os.path.join(
            env.get("STRUCT_OUT", "."), "agent_" + re.sub(r"[^A-Za-z0-9_]", "_", self.agent_id) + ".jsonl")
        self.plan_raw = env.get("STRUCT_PLAN", "")
        self.world_file = env.get("STRUCT_WORLD_FILE", "")
        self.causal_url = (env.get("STRUCT_CAUSAL_URL") or "").rstrip("/")
        self.spec = {}
        if self.world_file and os.path.exists(self.world_file):
            try:
                self.spec = json.loads(open(self.world_file, encoding="utf-8").read())
            except (OSError, ValueError):
                self.spec = {}
        self.history: list[dict] = []
        self.my_obs_ids: list[str] = []
        self.known_obs_ids: list[str] = []
        self.last_command_id = None
        self.last_causal_note = None  # P0-12: admitted-with-warning note for the agent
        self.t0 = time.time()

    # ---------------------------------------------------------- logging
    def log(self, rec):
        base = {"t": time.time(), "mono": time.monotonic(), "agent_id": self.agent_id,
                "decider": self.decider}
        self._log_seq = getattr(self, "_log_seq", 0) + 1
        base["seq"] = self._log_seq
        if os.environ.get("STRUCT_ATTEMPT_UID"):
            base["attempt_uid"] = os.environ["STRUCT_ATTEMPT_UID"]
        if os.environ.get("STRUCT_WORLD_INSTANCE_ID"):
            base["world_instance_id"] = os.environ["STRUCT_WORLD_INSTANCE_ID"]
        # E6g: agent log is its own evidence; no file state controls it
        if self.decider == "scripted":
            base["label"] = SCRIPTED_LABEL
        with open(self.log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({**base, **rec}, default=str) + "\n")

    # ---------------------------------------------------------- world helpers
    def _world_headers(self, decision_ref=None):
        h = {"X-Legion-World-Token": self.world_token}
        if decision_ref:
            h["X-Legion-Decision-Ref"] = decision_ref
        return h

    def observe(self, decision_ref=None):
        _, payload = http("GET", f"{self.world_url}/observe",
                          headers=self._world_headers(decision_ref), timeout=30)
        if isinstance(payload, dict):
            for msg in payload.get("inbox") or []:
                for oid in re.findall(r"obs-[0-9a-fA-F]+", str(msg.get("body") or "")):
                    if oid not in self.known_obs_ids:
                        self.known_obs_ids.append(oid)
        return payload if isinstance(payload, dict) else {}

    def _note_ids(self, payload):
        ids = {}
        if isinstance(payload, dict):
            for key in ("observation_id", "message_id", "record_id", "effect_id", "command_id"):
                if payload.get(key):
                    ids[key] = payload[key]
            effect = payload.get("effect")
            if isinstance(effect, dict) and effect.get("effect_id"):
                ids["effect_id"] = effect["effect_id"]
        out = payload.get("output") if isinstance(payload, dict) else None
        if isinstance(out, str):
            for key in ("command_id", "effect_id"):
                m = re.search(rf"{key}=([^\s;]+)", out)
                if m:
                    ids[key] = m.group(1).strip()
        if ids.get("observation_id"):
            for lst in (self.my_obs_ids, self.known_obs_ids):
                if ids["observation_id"] not in lst:
                    lst.append(ids["observation_id"])
        if ids.get("command_id"):
            self.last_command_id = ids["command_id"]
        return ids

    # ---------------------------------------------------------- action execution
    # ---------------------------------------------------------- causal sidecar (WO-007, separate process)
    def _causal_post(self, path, body, timeout=10):
        if not self.causal_url:
            return None
        return http("POST", f"{self.causal_url}{path}", body,
                    headers=self._world_headers(), timeout=timeout)

    def causal_check(self, action, decision_ref):
        """Authoritative admissibility from the separate sidecar process.

        Returns a refusal dict or None (admitted). Fail-closed: if the
        sidecar is configured but unreachable, the action is refused
        locally and never reaches the world/gate unchecked.
        """
        if os.environ.get("STRUCT_CAUSAL", "1") == "0" or not self.causal_url:
            return self._causal_refusal(action, decision_ref)
        status, payload = self._causal_post(
            "/check", {"agent_id": self.agent_id, "action": action,
                       "decision_ref": decision_ref or ""})
        if status != 200 or not isinstance(payload, dict) or "allowed" not in payload:
            return {"code": "SIDECAR_UNAVAILABLE",
                    "hint": "causal sidecar unreachable; action refused fail-closed"}
        if payload.get("allowed"):
            # P0-12: an analysis admitted despite stale refs carries the
            # stale-ref report in its hint; surface it to the agent (below,
            # appended to the action outcome) instead of dropping it.
            if payload.get("stale_refs"):
                self.last_causal_note = {"code": payload.get("code"),
                                         "hint": payload.get("hint") or "",
                                         "stale_refs": payload.get("stale_refs"),
                                         "valid_refs": payload.get("valid_refs")}
            return None
        return {"code": payload.get("code"), "hint": payload.get("hint") or "",
                "next_required": payload.get("next_required"),
                "transient": bool(payload.get("transient")),
                "underlying_code": payload.get("underlying_code"),
                "observation_only": bool(payload.get("observation_only"))}

    def causal_view(self):
        if not self.causal_url or os.environ.get("STRUCT_CAUSAL", "1") == "0":
            return None
        status, payload = http("GET", f"{self.causal_url}/view",
                               headers=self._world_headers(), timeout=10)
        return payload if status == 200 and isinstance(payload, dict) else None

    def causal_check_exit(self, reason):
        if not self.causal_url or os.environ.get("STRUCT_CAUSAL", "1") == "0":
            return None
        status, payload = self._causal_post(
            "/check_exit", {"agent_id": self.agent_id, "reason": reason})
        if status != 200 or not isinstance(payload, dict):
            return {"code": "SIDECAR_UNAVAILABLE", "hint": "exit check unreachable; staying"}
        if payload.get("allowed"):
            return None
        return {"code": payload.get("code"), "hint": payload.get("hint") or ""}

    def causal_note_result(self, action, status, payload):
        if not self.causal_url or status not in (400, 403):
            return None
        _, out = self._causal_post("/note_result", {
            "agent_id": self.agent_id, "action": action,
            "http_status": status, "payload": payload if isinstance(payload, dict) else {}})
        return out.get("hint") if isinstance(out, dict) else None

    def execute(self, action, decision_ref):
        """Sidecar gate, then the unchanged world/gate call.

        Every world/gate action is first checked by the separate causal
        sidecar (fed by the independent world/gate/readback logs). A
        refusal never reaches WORLD_LOG/gate: it is logged by the sidecar
        to CAUSAL_CONTROLLER.jsonl and returned here as a corrective hint
        in the agent's own history. Admitted actions are executed by this
        agent itself, carrying its own decision_ref.
        """
        kind = (action or {}).get("action")
        if kind != "idle":
            refusal = self.causal_check(action, decision_ref)
            if refusal is not None:
                self.log({"event": "CAUSAL_REFUSAL", **refusal, "action": action,
                          "decision_ref": decision_ref})
                return 0, f"CAUSAL_REFUSAL:{refusal.get('code')}:{refusal.get('hint')}", {}, \
                    {"causal_refusal": refusal}
        status, outcome, ids, payload = self._execute_admitted(action, decision_ref)
        if kind != "idle":
            if getattr(self, "last_causal_note", None):
                note, self.last_causal_note = self.last_causal_note, None
                outcome = f"{outcome} CAUSAL_HINT:{note.get('hint')}"
                self.log({"event": "CAUSAL_ADMIT_WARNING", **note,
                          "action": action, "decision_ref": decision_ref})
            hint = self.causal_note_result(action, status, payload)
            if hint:
                outcome = f"{outcome} CAUSAL_HINT:{hint}"
        return status, outcome, ids, payload

    def _execute_admitted(self, action, decision_ref):
        """Execute one parsed action. Returns (http_status, outcome, ids, payload)."""
        kind = action.get("action")
        task = action.get("task")
        if kind == "idle":
            time.sleep(min(float(action.get("seconds") or 1), 10.0))
            return 200, "IDLE", {}, {}
        if kind == "read":
            status, payload = http("POST", f"{self.world_url}/read",
                                   {"task_id": task, "tool": action.get("tool"), "args": action.get("args") or {}},
                                   headers=self._world_headers(decision_ref), timeout=60)
            outcome = "OBSERVED" if status == 200 else f"READ_ERROR_{status}"
            return status, outcome, self._note_ids(payload), payload
        if kind == "write":
            params = {"task_id": task, "tool": action.get("tool"), "target": action.get("target"),
                      "args_json": json.dumps(action.get("args") or {}), "decision_ref": decision_ref or "",
                      "attempt_uid": os.environ.get("STRUCT_ATTEMPT_UID", "")}
            status, payload = http("POST", f"{self.gateway}/tools/execute",
                                   {"tool_name": "world_write", "params": params},
                                   headers={"l5d-client-id": self.identity}, timeout=90)
            out = payload.get("output") if isinstance(payload, dict) else None
            outcome = str(out) if out else str((payload or {}).get("error") or f"HTTP {status}")
            if isinstance(payload, dict) and out:
                self._note_ids(payload)
                m = re.search(r"command_id=([^\s;]+)", out)
                if m:
                    self.last_command_id = m.group(1).strip()
            ids = {"command_id": self.last_command_id} if self.last_command_id else {}
            return status, outcome, ids, payload
        if kind == "send":
            status, payload = http("POST", f"{self.world_url}/send",
                                   {"task_id": task, "to": action.get("to"), "body": action.get("body")},
                                   headers=self._world_headers(decision_ref), timeout=30)
            return status, "DELIVERED" if status == 200 else f"SEND_ERROR_{status}", self._note_ids(payload), payload
        if kind == "analyze":
            status, payload = http("POST", f"{self.world_url}/analyze",
                                   {"task_id": task, "answer": action.get("answer"),
                                    "evidence_refs": action.get("evidence_refs") or []},
                                   headers=self._world_headers(decision_ref), timeout=30)
            return status, "RECORDED" if status == 200 else f"ANALYZE_ERROR_{status}", self._note_ids(payload), payload
        if kind == "wait":
            seconds = action.get("seconds")
            max_s = action.get("max_s")
            if max_s is None:
                max_s = (float(seconds) + 10.0) if seconds is not None else 30.0
            body = {"task_id": task, "max_s": max_s}
            if action.get("event_id"):
                body["event_id"] = action["event_id"]
            if seconds is not None:
                body["seconds"] = seconds
            status, payload = http("POST", f"{self.world_url}/wait", body,
                                   headers=self._world_headers(decision_ref), timeout=float(max_s) + 30)
            waited = isinstance(payload, dict) and payload.get("waited")
            return status, "WAITED" if waited else "WAIT_TIMEOUT", self._note_ids(payload), payload
        if kind == "refuse":
            params = {"task_id": task, "reason": action.get("reason") or "", "decision_ref": decision_ref or ""}
            status, payload = http("POST", f"{self.gateway}/tools/execute",
                                   {"tool_name": "declare_refusal", "params": params},
                                   headers={"l5d-client-id": self.identity}, timeout=60)
            out = payload.get("output") if isinstance(payload, dict) else None
            return status, str(out or (payload or {}).get("error") or f"HTTP {status}"), {}, payload
        if kind == "reconcile":
            cid = action.get("command_id") or self.last_command_id
            status, payload = http("POST", f"{self.world_url}/reconcile",
                                   {"task_id": task, "command_id": cid},
                                   headers=self._world_headers(decision_ref), timeout=30)
            if isinstance(payload, dict) and payload.get("command_id"):
                self.last_command_id = payload["command_id"]
            return status, ("FOUND" if isinstance(payload, dict) and payload.get("found") else "NOT_FOUND"), \
                self._note_ids(payload), payload
        if kind == "done":
            status, payload = http("POST", f"{self.world_url}/done",
                                   {"task_id": task, "note": action.get("note") or "done"},
                                   headers=self._world_headers(decision_ref), timeout=30)
            return status, "DONE_RECORDED" if status == 200 else f"DONE_ERROR_{status}", {}, payload
        return 0, f"UNKNOWN_ACTION_{kind}", {}, {}

    def _record_result(self, action, status, outcome, ids):
        entry = {"action": action, "http_status": status, "outcome": str(outcome)[:500], "ids": ids}
        self.history.append(entry)
        self.log({"event": "ACTION_RESULT", **entry})
        return entry

    # ---------------------------------------------------------- prompt (PUBLIC data only)
    def _role(self):
        for role in self.spec.get("roles") or []:
            if role.get("agent_id") == self.agent_id:
                return role
        return {}

    def build_prompt(self, obs, causal_view=None):
        tools = self.spec.get("tools") or {}
        role = self._role()
        wanted = set()
        for task in obs.get("tasks") or role.get("tasks") or []:
            wanted.update(task.get("read_tools") or [])
            if task.get("write_tool"):
                wanted.add(task["write_tool"])
        tool_docs = {name: {"kind": t.get("kind"), "doc": t.get("doc"), "params": t.get("params"),
                            "target": t.get("target")}
                     for name, t in tools.items() if name in wanted}
        current_transition = None
        if isinstance(causal_view, dict) \
                and causal_view.get("agent_id") == self.agent_id \
                and causal_view.get("evidence_feed") == "OK" \
                and causal_view.get("allowed") is not False:
            eligible = [ob for ob in causal_view.get("obligations") or []
                        if not ob.get("open_dependencies")]
            if eligible:
                candidate = eligible[0]
                task = next((task for task in role.get("tasks") or []
                             if task.get("task_id") == candidate.get("task_id")), None)
                if task is not None:
                    current_transition = {
                        "task": task["task_id"], "brief": task.get("brief"),
                        "action_types": candidate.get("action_types") or [],
                        "missing_evidence": candidate.get("missing_evidence") or [],
                        "recipients": task.get("recipients") or [],
                        "write_tool": task.get("write_tool"),
                        "target": task.get("target"),
                        "required_read_tools": candidate.get("required_read_tools") or [],
                    }
        public = {
            "current_transition": current_transition,
            "mission_text": self.spec.get("mission_text"),
            "agent_id": self.agent_id, "role_title": role.get("title"), "role_brief": role.get("brief"),
            "my_tasks": obs.get("tasks") or role.get("tasks") or [],
            "allowed_evidence_reads": [
                {"task": task["task_id"], "tool": tool}
                for task in role.get("tasks") or []
                for tool in task.get("read_tools") or []
            ],
            "tools": tool_docs, "notices": obs.get("notices") or [],
            "inbox": obs.get("inbox") or [], "my_recent_records": (obs.get("my_records") or [])[-10:],
            "my_previous_results": self.history[-4:],
            "causal_view": causal_view,
        }
        system = (
            f"You are {self.agent_id}, one autonomous agent in a governed structural mission. "
            "Reply with EXACTLY one JSON object and nothing else, one of:\n"
            '{"action":"read","task":"<task_id>","tool":"<read tool>","args":{...}}\n'
            '{"action":"write","task":"<task_id>","tool":"<write tool>","target":"<task target>","args":{...}}\n'
            '{"action":"send","task":"<task_id>","to":"<agent_id>","body":"..."}\n'
            '{"action":"analyze","task":"<task_id>","answer":{...},"evidence_refs":["obs-..."]}\n'
            '{"action":"wait","task":"<task_id>","event_id":"<event>"|"seconds":<n>,"max_s":<n>}\n'
            '{"action":"refuse","task":"<task_id>","reason":"..."}\n'
            '{"action":"reconcile","task":"<task_id>","command_id":"<id>"}\n'
            '{"action":"done","task":"<task_id>"} | {"action":"idle","seconds":<n>}\n'
            "Use current_transition to choose your next required task and JSON action type. "
            "If it requires send, send the required evidence-based handoff to its listed "
            "recipient; do not repeat a closed READ instead. allowed_evidence_reads is "
            "only a task/tool schema map, not a request to keep reading. Once your WRITE "
            "is verified, complete the remaining communication or validation obligation. "
            "Only do what your own tasks' kinds allow; respect depends_on; writes go through a "
            "governance gateway that decides on server-side evidence, so never invent results. "
            "For writes, include the explicit target field from your task AND "
            "all required named tool args. Target never substitutes for an argument "
            "such as partition. Use current tool docs or observed schema updates; "
            "a missing field must be supplied rather than fixed by repeating reads. "
            "If a write outcome is UNKNOWN, reconcile before retrying it. "
            "If a task permits REFUSE and the intended target remains ambiguous, "
            "do not guess among candidates. Use action=refuse with that task id and "
            "a reason. An analyze answer or send body saying REFUSE is not the "
            "refusal action. After the refusal is recorded, use your separate "
            "COMMUNICATE task to ask for clarification from its listed recipient. "
            "causal_view lists your open obligations, confirmed dependencies, missing evidence "
            "and the next required transition: consequential actions require an ELIGIBLE obligation. "
            "You may gather evidence using your own tasks' read_tools even when that task "
            "is already confirmed, while a downstream obligation remains open. After waiting "
            "for a state-changing event, or a CONTENT_EVIDENCE_STALE refusal, refresh the "
            "relevant allowed read before asserting current facts or sending an alert. "
            "For a read, choose its task/tool pair from allowed_evidence_reads; "
            "do not put the next communication task id on a read. A confirmed source "
            "task id remains the correct task id for refreshing its read tool. "
            "An event notification does not itself reveal the new state. Never repeat a "
            "stale factual claim; obtain a fresh observation first. Cite "
            "shared_evidence observation ids (e.g. delegate evidence) in your send/analyze "
            "when you use them. A CAUSAL_REFUSAL in your previous results means that action "
            "did not happen; follow its hint instead of repeating it."
        )

        if (
            self.spec.get("family") == "SYN-OTEL-04"
            and self.agent_id == "agent:o4-verifier"
        ):
            public["verification_instruction"] = (
                "Complete T3 first, then T4. "
                "T4 answer_schema requires exactly total_processed "
                "(integer) and all_lag_zero (boolean). "
                "Derive total_processed from confirmed partition "
                "drain reports and native observations for p0..p9. "
                "Count each partition once. Do not guess values. "
                "If evidence is incomplete, gather missing reports "
                "rather than repeating an invalid analysis. "
                "Submit T4 only when its dependencies are confirmed."
            )
        if (
            self.spec.get("family") == "SYN-OTEL-04"
            and self.agent_id.startswith("agent:o4-consumer-p")
        ):
            public["partition_instruction"] = (
                "After T2, read your own partition offsets. "
                "Use the observed committed offset for the drain. "
                "Do not reuse an observation from before restart. "
                "After successful drain, send the exact processed "
                "message count to agent:o4-verifier under your "
                "COMMUNICATE task. Cite available observation ids."
            )

        if (
            str(self.spec.get("world_id", "")).startswith("SYN-OTEL-04")
            and self.agent_id.startswith("agent:o4-consumer-p")
        ):
            public["exact_action_contract"] = (
                "For partition.drain, produce a complete WRITE action "
                "with these exact JSON fields: action, task, tool, "
                "target, args. The args object MUST contain both "
                "partition and from_offset. "
                "Use your own assigned partition for target AND "
                "args.partition. Use the confirmed committed offset "
                "from your own partition.offsets observation for "
                "args.from_offset. Example structure only: "
                "{'action':'write','task':'WpN',"
                "'tool':'partition.drain','target':'pN',"
                "'args':{'partition':'pN','from_offset':X}}. "
                "Replace N and X with your actual assignment and "
                "verified offset. The controller does not repair "
                "missing or incorrect fields. After the drain "
                "succeeds, complete your CpN communication."
            )

        if (
            str(self.spec.get("world_id", "")).startswith("SYN-OTEL-04")
            and self.agent_id == "agent:o4-verifier"
        ):
            public["verification_arithmetic_rule"] = (
                "For task T4, total_processed is the SUM OF INCREMENTS "
                "over all 10 partitions, not the sum of committed offsets, "
                "not the count of partitions, and not an estimate. "
                "For each distinct partition p0 through p9, find its "
                "confirmed pre-drain partition.offsets observation; "
                "increment = log_end minus committed. "
                "Write the ten increments down, add them arithmetically "
                "and use that exact integer for answer.total_processed. "
                "Do not multiply a representative partition by ten: "
                "partition backlogs differ. "
                "Set answer.all_lag_zero from the latest confirmed "
                "consumer_group.status observation, after all drains, "
                "only if every partition lag is exactly zero. "
                "If any observation is absent, gather permitted evidence "
                "instead of guessing. Model must propose its own action; "
                "the controller will reject incorrect aggregates."
            )

            observed = {}
            view = public.get("causal_view") or {}
            for item in view.get("shared_evidence", []):
                if not isinstance(item, dict):
                    continue
                task_id = item.get("task_id")
                facts = item.get("facts") or {}
                if (
                    isinstance(task_id, str)
                    and task_id in ["Rp" + str(i) for i in range(10)]
                    and isinstance(facts.get("committed"), int)
                    and isinstance(facts.get("log_end"), int)
                ):
                    observed[task_id] = {
                        "observation_id": item.get("observation_id"),
                        "committed": facts["committed"],
                        "log_end": facts["log_end"],
                        "increment": facts["log_end"] - facts["committed"]
                    }

            public["verified_partition_arithmetic"] = {
                "inputs": observed,
                "complete": len(observed) == 10,
                "sum_of_increments": (
                    sum(x["increment"] for x in observed.values())
                    if len(observed) == 10 else None
                )
            }

        # WO042: make an eligible COMMUNICATE transition unambiguous.
        # This changes only the model's input, never its proposed action.
        transition = public.get("current_transition") or {}
        kinds = transition.get("action_types") or []
        task_id = transition.get("task")
        recipients = transition.get("recipients") or []

        if (
            str(self.spec.get("world_id", "")).startswith("SYN-OTEL-04")
            and self.agent_id.startswith("agent:o4-consumer-p")
            and "send" in kinds
            and isinstance(task_id, str)
            and len(recipients) == 1
        ):
            recipient = recipients[0]
            public["mandatory_next_action"] = {
                "action": "send",
                "task": task_id,
                "to": recipient,
                "body": "Supply the actual verified partition, "
                        "processed increment, and evidence reference."
            }
            system += (
                "\nCURRENT ELIGIBLE TRANSITION IS COMMUNICATE. "
                "Your very next response MUST have JSON action='send', "
                "task=" + task_id + ", to=" + recipient + ". "
                "Use body containing actual confirmed processed count "
                "and existing evidence references. "
                "Do NOT select read, write, wait or done for this "
                "COMMUNICATE task. A confirmed read/write is not "
                "the pending action. Do not fabricate counts."
            )

        # WO045: scenario-scoped model guidance.
        # Never rewrite a proposed action or bypass admission.

        world = str(self.spec.get("world_id", ""))

        if (
            world.startswith("SYN-GAIA-ADA")
            and self.agent_id == "agent:ada-monitor"
        ):
            system += (
                "\nADA MONITOR EVIDENCE RULE: "
                "After the degradation event T3, obtain a fresh "
                "regions.status observation under T1 before sending "
                "T5. A pre-event observation is not sufficient "
                "evidence of the post-event state. "
                "Do not repeat a refused message. "
                "Construct the T5 message only from the latest "
                "confirmed region names, health states and latency. "
                "Use short unambiguous propositions, e.g. "
                "'Region east degraded, latency 950ms. "
                "Route to west.' ONLY IF these exact values "
                "are verified by the current observation. "
                "The example is not an assertion of current state. "
                "Do not invent or repeat stale measurements. "
                "When T5 is admitted, move to the next obligation."
            )

        if (
            world.startswith("SYN-OTEL-05")
            and self.agent_id == "agent:o5-analyst"
        ):
            system += (
                "\nOTEL-05 DIAGNOSIS COMPLETENESS RULE: "
                "T1 requires observing both the telemetry window "
                "and the cache configuration before analyzing T2. "
                "First read telemetry.window with task T1, then "
                "read cache.config_get with task T1. "
                "Include references to BOTH confirmed observations "
                "in the T2 analysis evidence_refs. "
                "Do not analyze after only one observation. "
                "Do not infer cache policy from telemetry alone. "

                "T2 ANALYZE ACTION SCHEMA IS STRICT: "
                "answer must be an object containing ONLY the "
                "permitted key 'cause', with its value inferred "
                "from verified observations. "
                "Never include confidence, explanation, notes, "
                "reason, score or additional answer fields. "
                "Put observation identifiers exclusively in "
                "the top-level evidence_refs array. "
                "For a provider HTTP 400 unknown answer field, "
                "remove the unsupported field in your NEXT "
                "model-generated proposal. Never repeat an "
                "identical rejected proposal. "

                "These are observations, not writes; "
                "preserve all causal admission constraints."
            )

        # WO048: clarify communication, never rewrite model output.
        if (
            str(self.spec.get("world_id", "")).startswith("SYN-GAIA-AMB")
            and self.agent_id == "agent:amb-handler"
        ):
            system += (
                "\nAMBIGUOUS SUBSCRIPTION PROTOCOL: "
                "When identity is ambiguous, never choose a customer "
                "and never cancel the subscription. "
                "After recording refusal under T3, complete the "
                "separate communication obligation T4 by asking "
                "the listed recipient for identification. "
                "Use a direct question in present or future tense: "
                "'Which customer should I cancel the pro subscription for?' "
                "Include customer names or IDs only when observed. "
                "Do not say 'cancelled', 'cancellation completed', "
                "'subscription was cancelled' or imply any write occurred. "
                "Do not repeat a refused proposal. "
                "The send action must be generated by the model itself."
            )
        return system, "OBSERVATION:\n" + json.dumps(public, sort_keys=True, default=str)

    # ---------------------------------------------------------- causal sidecar (WO-007)
    def _causal_refusal(self, action, decision_ref):
        """Local causal guard (same-agent obligations + kind/recipient rules).

        Returns a refusal dict or None. Never originates an action: it only
        refuses/explains an agent-supplied decision. Controller-side global
        enforcement lives in causal_007.sidecar.CausalSidecar (host-fed from
        the full world log); this guard covers what the agent can itself see.
        Enabled unless STRUCT_CAUSAL=0.
        """
        if os.environ.get("STRUCT_CAUSAL", "1") == "0":
            return None
        if not decision_ref:
            return {"code": "NO_DECISION_REF", "hint": "decision_ref required"}
        kind = {"read": "READ", "analyze": "ANALYZE", "send": "COMMUNICATE",
                "wait": "WAIT", "write": "WRITE", "refuse": "REFUSE",
                "reconcile": "RECONCILE", "done": "DONE"}.get(action.get("action"))
        if kind is None:
            return None
        role = self._role()
        task = next((t for t in role.get("tasks") or [] if t.get("task_id") == action.get("task")), None)
        if task is None:
            return {"code": "UNKNOWN_TASK", "hint": f"task {action.get('task')!r} is not yours"}
        # P0-6: a READ with one of the task's own read_tools is admissible
        # even when READ is not a closing kind (WRITE tasks observe first).
        own_read = kind == "READ" and action.get("tool") in (task.get("read_tools") or [])
        if kind not in (task.get("kinds") or []) and not own_read:
            return {"code": "KIND_NOT_ALLOWED",
                    "hint": f"task {task.get('task_id')} allows {task.get('kinds')}, not {kind}"}
        if kind == "COMMUNICATE":
            recips = task.get("recipients") or []
            if not recips:
                return {"code": "NO_RECIPIENTS",
                        "hint": f"task {task.get('task_id')} has no recipients; send under a task that does"}
            if action.get("to") not in recips:
                return {"code": "WRONG_RECIPIENT", "hint": f"allowed recipients: {recips}"}
        # Repeat protection is state-aware and lives in the authoritative
        # sidecar (P0-7, per fingerprint+reason+state digest); this local
        # guard has no registry state, so it never REPEAT_BLOCKEDs.
        return None

    def _tasks_terminal(self, obs):
        tasks = obs.get("tasks")
        if tasks is None:
            tasks = self._role().get("tasks") or []
        if not tasks:
            return True
        records = obs.get("my_records") or []
        effected = {r.get("task_id") for r in records if r.get("kind") == "NATIVE_EFFECT"}
        recorded = {r.get("task_id") for r in records if r.get("kind") in TERMINAL_KINDS}
        acted = {h["action"].get("task") for h in self.history
                 if str(h.get("outcome", "")).startswith(("EXECUTED", "REFUSED_BY_AGENT"))}
        for task in tasks:
            tid = task.get("task_id")
            if "WRITE" in (task.get("kinds") or []):
                if tid not in effected and tid not in acted:
                    return False
            elif tid not in recorded and tid not in acted:
                return False
        return True

    # ---------------------------------------------------------- deciders
    def run_standby(self):
        self.log({"event": "START", "mode": "standby"})
        self.observe()
        self.log({"event": "STANDBY_EXIT"})
        self.log({"event": "EXIT", "reason": "standby"})
        return 0

    def run_nim(self):
        self.log({"event": "START", "mode": "nim", "model": self.model})
        turns, provider_failures = 0, 0
        while time.time() - self.t0 < self.wall_s:
            obs = self.observe()

            _view = self.causal_view()
            _park = (
                bool(self.causal_url)
                and os.environ.get("STRUCT_CAUSAL", "1") != "0"
                and _legion_dependency_park(_view)
            )

            if _park:
                if not getattr(self, "_legion_parked", False):
                    self._legion_parked = True
                    self.log({
                        "event": "CAUSAL_PARK",
                        "reason": "DEPENDENCIES_OPEN_OR_VIEW_UNKNOWN",
                        "open_obligations": (
                            _view.get("open_obligations")
                            if isinstance(_view, dict) else None
                        ),
                        "turns": turns,
                    })
                time.sleep(0.5)
                continue

            if getattr(self, "_legion_parked", False):
                self._legion_parked = False
                self.log({
                    "event": "CAUSAL_RESUME",
                    "reason": "ELIGIBLE_OBLIGATION_AVAILABLE",
                    "turns": turns,
                })

            # The authoritative registry excludes inactive optional tasks.
            # A local list of public tasks cannot make those tasks mandatory.
            # This is only a request to exit: check_exit below still decides.
            registry_terminal = (
                isinstance(_view, dict)
                and _view.get("agent_id") == self.agent_id
                and _view.get("evidence_feed") == "OK"
                and _view.get("allowed") is not False
                and _view.get("open_obligations") == []
                and _view.get("obligations") == []
            )
            if self._tasks_terminal(obs) or registry_terminal:
                # WP-A: exit as all_tasks_terminal only if the authoritative
                # registry (separate sidecar) confirms no open obligations.
                blocked = self.causal_check_exit("all_tasks_terminal")
                if blocked is not None:
                    self.log({"event": "CAUSAL_EXIT_BLOCKED", **blocked, "turns": turns})
                    self.history.append({"action": {"action": "exit"},
                                         "http_status": 0,
                                         "outcome": f"CAUSAL_EXIT_BLOCKED:{blocked.get('code')}:{blocked.get('hint')}",
                                         "ids": {}})
                else:
                    self.log({"event": "EXIT", "reason": "all_tasks_terminal", "turns": turns})
                    return 0
            if turns >= self.max_turns:
                self.log({"event": "EXIT", "reason": "turn_budget_exhausted", "turns": turns})
                return 2
            system, user = self.build_prompt(obs, causal_view=_view)
            status, resp = http("POST", f"{self.proxy}/v1/chat/completions",
                                {"model": self.model,
                                 "messages": [{"role": "system", "content": system},
                                              {"role": "user", "content": user}],
                                 "temperature": 0.2, "max_tokens": 500,
                                 "chat_template_kwargs": {"enable_thinking": False}},
                                headers={"X-Legion-Proxy-Token": self.proxy_token}, timeout=180)
            if status != 200 or not isinstance(resp, dict) or not resp.get("choices"):
                provider_failures += 1
                delay = backoff_s(provider_failures)
                if status == 429:
                    # P1-3: never re-call NIM quickly after a 429. The
                    # proxy already retried with Retry-After; the agent's
                    # next decision call must wait at least 30 s so agent
                    # retries cannot re-amplify a rate-limit window.
                    delay = max(delay, 30.0)
                self.log({"event": "MODEL_CALL_FAILED", "http_status": status,
                          "proxy_log_id": resp.get("legion_proxy_log_id") if isinstance(resp, dict) else None,
                          "consecutive_failures": provider_failures, "backoff_s": delay})
                if provider_failures >= 20:
                    self.log({"event": "EXIT", "reason": "provider_unavailable", "turns": turns})
                    return 4
                time.sleep(delay)
                continue
            provider_failures = 0
            turns += 1
            content = (resp["choices"][0].get("message") or {}).get("content") or ""
            action = parse_action(content)
            if action is None:
                self.log({"event": "PARSE_FAILED", "turn": turns,
                          "provider_response_id": resp.get("id"),
                          "content_sha256": hashlib.sha256(content.encode()).hexdigest()})
                continue
            self.log({"event": "DECISION", "turn": turns, "provider_response_id": resp.get("id"),
                      "proxy_log_id": resp.get("legion_proxy_log_id"), "action": action,
                      "content_sha256": hashlib.sha256(content.encode()).hexdigest()})
            # Admissibility is enforced inside execute() by the separate
            # causal sidecar; a refusal is recorded as the action result
            # (with its corrective hint) and never reaches the world/gate.
            status, outcome, ids, _ = self.execute(action, resp.get("id") or "")
            self._record_result(action, status, outcome, ids)
        self.log({"event": "EXIT", "reason": "wall_timeout", "turns": turns})
        return 3

    # ---------------------------------------------------------- scripted (INTEGRATION_ONLY)
    def _load_plan(self):
        raw = self.plan_raw
        if raw and os.path.exists(raw):
            raw = open(raw, encoding="utf-8").read()
        try:
            plan = json.loads(raw) if raw else {}
        except ValueError:
            plan = {}
        roles = plan.get("roles") if isinstance(plan, dict) else None
        return list((roles or {}).get(self.agent_id) or []) if isinstance(roles, dict) else []

    # Transient causal refusals (P0-8): the refusal may clear when causal
    # state changes, so they are retried like gate DEFERRED/BLOCKED.
    _TRANSIENT_CAUSAL = {"DEPENDENCIES_OPEN", "EVENT_PENDING", "WAIT_PENDING",
                         "SIDECAR_UNAVAILABLE"}

    def _causal_refusal_of(self, payload):
        if isinstance(payload, dict):
            ref = payload.get("causal_refusal")
            if isinstance(ref, dict):
                return ref
        return None

    def _is_transient_refusal(self, payload):
        ref = self._causal_refusal_of(payload)
        if ref is None:
            return False
        if ref.get("transient"):
            return True
        return ref.get("code") in self._TRANSIENT_CAUSAL or \
            ref.get("underlying_code") in self._TRANSIENT_CAUSAL

    def _execute_scripted_step(self, step, decision_ref):
        kind = step.get("action")
        if kind == "read":
            # Polling reads: retry until the `until` predicate matches, and
            # retry transient causal refusals exactly like an unmatched
            # observation (P0-8). Without `until`, a transient refusal is
            # retried bounded by max_s or the 180 s await default.
            has_until = step.get("until") is not None
            deadline = time.monotonic() + float(
                step.get("max_s") or (10 if has_until else 180))
            while True:
                status, outcome, ids, payload = self.execute(step, decision_ref)
                self._record_result(step, status, outcome, ids)
                if has_until:
                    data = payload.get("data") if isinstance(payload, dict) else None
                    if status == 200 and predicate_matches(data, step.get("until")):
                        return
                elif not self._is_transient_refusal(payload):
                    return
                if time.monotonic() >= deadline:
                    return
                time.sleep(1.0)
        if kind == "write":
            # Writes: gate DEFERRED/BLOCKED and transient CAUSAL_REFUSAL are
            # retried under retry_blocked_max_s (P0-8); without that bound a
            # single attempt is made, as before.
            bound = step.get("retry_blocked_max_s")
            deadline = time.monotonic() + float(bound) if bound else None
            while True:
                status, outcome, ids, payload = self.execute(step, decision_ref)
                self._record_result(step, status, outcome, ids)
                text = str(outcome)
                gate_retryable = (text.startswith("BLOCKED") or text.startswith("DEFERRED")) \
                    and "actuation not accepted" not in text and not text.startswith("UNKNOWN")
                retryable = gate_retryable or self._is_transient_refusal(payload)
                if not retryable or deadline is None or time.monotonic() >= deadline:
                    return
                time.sleep(1.0)
        # Sends, analyzes and other steps whose dependencies are open:
        # await-style retry of transient causal refusals until admitted,
        # bounded by the step's max_s or a default of 180 s (P0-8).
        deadline = time.monotonic() + float(step.get("max_s") or 180)
        while True:
            status, outcome, ids, payload = self.execute(step, decision_ref)
            self._record_result(step, status, outcome, ids)
            if not self._is_transient_refusal(payload) or time.monotonic() >= deadline:
                return
            time.sleep(1.0)

    def run_scripted(self):
        self.log({"event": "START", "mode": "scripted", "label": SCRIPTED_LABEL})
        steps = self._load_plan()
        for n, raw_step in enumerate(steps, start=1):
            if time.time() - self.t0 >= self.wall_s:
                self.log({"event": "EXIT", "reason": "wall_timeout", "step": n})
                return 3
            step = substitute_placeholders(raw_step, known_obs_ids=self.known_obs_ids,
                                           my_obs_ids=self.my_obs_ids,
                                           last_command_id=self.last_command_id)
            decision_ref = f"scripted:{n}"
            if isinstance(step, dict) and "await_message_from" in step:
                sender, deadline = step["await_message_from"], time.monotonic() + float(step.get("max_s") or 30)
                found = False
                while time.monotonic() < deadline:
                    obs = self.observe(decision_ref)
                    if any(m.get("agent_id") == sender or m.get("sender") == sender
                           for m in obs.get("inbox") or []):
                        found = True
                        break
                    time.sleep(1.0)
                self.log({"event": "SCRIPTED_DECISION", "step": n, "decision_ref": decision_ref, "action": step})
                self._record_result(step, 200 if found else 408,
                                    "MESSAGE_RECEIVED" if found else "AWAIT_TIMEOUT", {})
                continue
            if isinstance(step, dict) and "sleep_s" in step and "action" not in step:
                self.log({"event": "SCRIPTED_DECISION", "step": n, "decision_ref": decision_ref, "action": step})
                time.sleep(min(float(step["sleep_s"]), max(0.0, self.wall_s)))
                self._record_result(step, 200, "SLEPT", {})
                continue
            self.log({"event": "SCRIPTED_DECISION", "step": n, "decision_ref": decision_ref,
                      "action": step, "label": SCRIPTED_LABEL})
            try:
                self._execute_scripted_step(step, decision_ref)
            except Exception as exc:  # read errors are logged; the plan continues
                self.log({"event": "ACTION_RESULT", "action": step, "http_status": 0,
                          "outcome": f"STEP_ERROR_{type(exc).__name__}", "ids": {}})
        self.log({"event": "EXIT", "reason": "plan_complete", "steps": len(steps)})
        return 0


def _watch_parent():
    """P0-15: an agent whose host died must never keep calling NIM."""
    parent = os.getppid()
    def _run():
        while True:
            time.sleep(0.5)
            try:
                if os.getppid() != parent:
                    os._exit(4)
            except Exception:
                return
    threading.Thread(target=_run, daemon=True).start()


def main():
    _watch_parent()
    agent = Agent()
    if agent.decider == "standby":
        return agent.run_standby()
    if agent.decider == "scripted":
        return agent.run_scripted()
    return agent.run_nim()


if __name__ == "__main__":
    sys.exit(main())
