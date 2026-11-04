# LEGION structural world DSL `legion.world.v1` (PUBLIC)

Author: Claude (mission author). This document and `worlds_public/*.world.json` are public. They may be shown to the
runner author (Meta) and, through role briefs and tool docs, to NIM agents. Goal predicates, correct answers, hidden
forbidden states and expected plans are NOT here. They live in the hidden contract store, which is used only by the
Judge adapter.

## Derived rules
`"derived": [{"when": [predicate...], "effects": [effect...]}]` (optional, world-level). After every effect or event,
the world re-evaluates each rule. When all its predicates hold it applies the effects, which must be idempotent. This
models service behaviour such as "readiness becomes ready once config is correct and the service restarted".

## World file
```
{ "schema_version": "legion.world.v1", "world_id", "family", "source_family": "GAIA2_STRUCTURAL"|"OTEL_STRUCTURAL",
  "structure_mapping": str, "mission_text": str (public user mission, given to every active role),
  "initial_state": {...nested dict...},
  "tools": { name: TOOL }, "events": [ EVENT ], "roles": [ ROLE ],
  "budgets": {"max_duration_s": int, "max_model_turns_per_agent": int} }
```

### Paths, templates, predicates
- A path is a dot path into state, for example `orders.ord_1.status`. It may contain `{param}` placeholders, which are
  substituted with the call's argument value. A substituted value must not contain `.` (reject the call with 400
  otherwise).
- A predicate is `{"path", "op", "value"}`, with op in `eq ne ge le contains set_eq exists absent`. Semantics are
  identical to `legion_judge.core.predicate`.
- A value spec is one of:
  - a literal;
  - `{"param": name}`, where `"negate": true` negates a numeric param;
  - `{"path": tmpl}`, the current state value at that path;
  - `{"path_minus_param": [tmpl, name]}`, the numeric state value minus the numeric param.

  All value specs are evaluated BEFORE any effect of the same call is applied, so a call's effects all see the
  pre-call state.
- A predicate value may also be `{"param": name}`, which compares against the call's argument.

### TOOL
```
{ "kind": "read"|"write", "doc": str (shown to agents), "params": {name: {"type": "string"|"integer", "enum"?: [...],
   "min"?: int, "max"?: int}},
  "target": str (write only: the fixed native target id this tool mutates; may be a template such as "{order_id}"),
  "returns": {key: path-template} (read only; the response is {key: value-at-path}, missing path -> null),
  "effects": [ {"op": "set"|"inc"|"append", "path": tmpl, "value": valuespec} ] (write only),
  "native_preconditions": [predicate (templated paths)] (write only; if any is false the world refuses: HTTP 409, no
   effect),
  "faults": [ FAULT ] }
```
`inc` adds a numeric value. `append` appends to a list, creating it if absent.

### FAULT (deterministic; counted per tool per world instance)
- `{"type": "error_first_n", "n": k, "status": 503}`: the first k write calls fail with status and no effect.
- `{"type": "lost_reply_nth", "n": k}`: the k-th write call (1-based, counting all calls) APPLIES the effect and records
  effect and receipt in the world ledgers, then withholds the reply. The connection is held 35 s and closed, so the
  caller sees a timeout.
- `{"type": "param_renamed", "old": "a", "new": "b", "after_event": ev_id | null}`: from that point (or always if null),
  a call using `a` gets HTTP 400 `{"error": "unknown parameter 'a'; this endpoint now expects 'b'"}` and calls must use
  `b`. Tool docs still show the old name, and agents must adapt.

### EVENT (environment events; the world injects them itself)
```
{ "event_id", "when": {"at_s": seconds-after-world-start} | {"after_effect": tool_name, "delay_s": s},
  "effects": [effect], "notice": str|null, "notify_roles": [agent_id] }
```
At fire time the world applies effects, records ENV_EVENT `{event_id, t_mono}`, and puts the notice into the notified
roles' observation feed.

### ROLE (active roles only; the runner adds standby workers up to the registered coalition size)
```
{ "agent_id": "agent:<name>", "title", "brief" (public instructions), "tasks": [ TASK ] }   (tasks may be empty: a registered recipient-only role)
TASK = { "task_id": "T<n>", "brief": str, "kinds": [subset of READ ANALYZE COMMUNICATE WAIT WRITE REFUSE RECONCILE],
         "read_tools": [tool], "write_tool": tool|null, "target": str|null (fixed write target),
         "recipients": [agent_id] (COMMUNICATE), "wait_for": event_id|null, "answer_schema": {field: {"enum": [...]}
         |{"type": ...}} (ANALYZE), "depends_on": [task_id], "gate_facts": [predicate] (WRITE: preconditions that
         ZTL observers must find true in native state before CAGE may commit) }
```
`kinds` lists what the agent MAY do for the task, and the agent decides. `depends_on` and `gate_facts` are enforced by
the governed gate for writes. Agents see their own tasks, the tool docs for their tools, their observations and
messages, and the public mission text.

## World HTTP API (separate OS process; every agent-facing call carries `X-Legion-World-Token`, mapped to agent_id by
the world; the body never decides identity)
- `GET /observe` returns the caller's feed: notices, the caller's own records, and inbox messages.
- `POST /read {task_id, tool, args}` returns `{observation_id, data}` (or 400/404). It logs OBSERVATION
  `{observation_id, agent_id, task_id, tool, args, facts=data, t_mono}`.
- `POST /send {task_id, to, body}` sends an authenticated message. It logs MESSAGE_DELIVERED
  `{message_id, agent_id(sender), recipient, task_id, body_sha256, t_mono}`. Only listed recipients are allowed.
- `POST /wait {task_id, event_id | seconds, max_s}` blocks server-side until the event has fired or the seconds have
  elapsed (bounded by max_s), then logs WAIT_OBSERVED `{agent_id, task_id, event_id, t_mono}`. On timeout it returns
  `{"waited": false}` and logs nothing.
- `POST /analyze {task_id, answer, evidence_refs}` validates the answer against answer_schema and stores
  `state.answers.<task_id> = answer`. It logs ANALYSIS_RECORD `{record_id, agent_id, task_id, facts=answer,
  evidence_refs, t_mono}`.
- `POST /reconcile {task_id, command_id}` looks the command up in the effect ledger. It logs RECONCILE
  `{agent_id, task_id, command_id, found, effect_id, t_mono}` and returns the effect or `found: false`.
- `POST /done {task_id, note}` is an agent self-claim of completion. It logs AGENT_DONE and never changes state.
- `POST /actuate {command_id, task_id, agent_id, tool, target, args}` is ACTUATOR ONLY (bearer token held by the gate
  actuator, never by agents). It enforces params, native_preconditions and faults, and is idempotent per command_id.
  It logs NATIVE_EFFECT and RECEIPT `{effect_id, command_id, task_id, agent_id, tool, target, args, t_mono}`.
- `GET /state`, `GET /effects`, `GET /log` are READER ONLY (separate reader token): full state, effect ledger and
  append-only world log.
- All logs are append-only JSONL written with a lock and atomic `os.write` on an O_APPEND fd, using CLOCK_MONOTONIC.
