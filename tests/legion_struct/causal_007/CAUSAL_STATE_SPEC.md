# CAUSAL_STATE_SPEC — WO-LEGION100-CAUSAL-CLOSURE-007

Implementation: `causal_registry.py` (WP-A/D), enforced by `sidecar.py` (WP-B/C).
Derived only from the public world spec + independently logged world/gate/readback
records. A successful tool call is not closure.

## States (per obligation = one public task)
- `PENDING` — at least one `depends_on` task is not CONFIRMED.
- `ELIGIBLE` — all dependencies CONFIRMED, no closing evidence yet.
- `CONFIRMED` — closure condition (below) met by logged evidence taken while ELIGIBLE.
- Evidence arriving while PENDING is recorded as `stale` (reason
  `PREMATURE_BEFORE_DEPS`) and never closes the task; the agent must redo it.
- `REFUSED` — terminal alternative for a REFUSE-capable task via a gate
  `REFUSED_BY_AGENT` record (e.g. a WRITE|REFUSE task closed by declining).

## Closure conditions per kind (multi-kind tasks need every kind, except REFUSE alternative)
| Kind | Closes on | Extra validation |
|---|---|---|
| READ | `OBSERVATION` by assigned agent, while ELIGIBLE | facts not all null (`EMPTY_OBSERVATION_NULL_DATA`) |
| ANALYZE | `ANALYSIS_RECORD` by assigned agent, while ELIGIBLE | at least one fresh, valid evidence ref from the confirmed dependency chain (`validate_analysis` / `analyze_ref_partition`, P0-12); stale in-chain refs cited alongside are ignored and reported, unknown/wrong-task refs still refuse |
| COMMUNICATE | `MESSAGE_DELIVERED` by assigned agent | recipient in task.recipients |
| WAIT | `WAIT_OBSERVED` by assigned agent | event_id equals task.wait_for (`WRONG_EVENT`) |
| WRITE | `NATIVE_EFFECT` for the task (effect ledger) | governed gate (ZTL/CAGE/VEIP) unchanged and independent |
| REFUSE | gate `REFUSED_BY_AGENT` record | accompanied by required COMMUNICATE obligations (sidecar hint) |
| RECONCILE | `RECONCILE` record with `found=true` | `found:false` never closes |
| DONE | `AGENT_DONE` only for DONE-kind tasks | self-claims never close other kinds |

## Read admissibility (P0-6, re-derived from WORLD_DSL)
WORLD_DSL gives every task `read_tools`, including WRITE tasks (agents must
observe before acting), while `kinds` lists the closing obligation kinds.
The two are not the same check:
- A READ whose tool is one of the task's own `read_tools` is admissible
  whenever the task is open (not CONFIRMED) and its dependencies are
  satisfied. It is marked `observation_only` when READ is not a closing
  kind, and such a read never closes a non-READ task. An eligible such
  observation is confirmed evidence for provenance/shared-evidence purposes.
- For READ-kind tasks a READ (own tool, provenance-valid args) is also
  admissible as plain observation before the dependencies are confirmed
  (verdict `OBSERVATION_ONLY`); the registry records it stale
  (`PREMATURE_BEFORE_DEPS`, not `_confirmed`), so it does not close the
  task — a re-read while ELIGIBLE is required to close it.
- For non-READ tasks, a READ with open dependencies is refused
  `DEPENDENCIES_OPEN` (transient; retryable).
- A READ tool that is not one of the task's own `read_tools` is
  `KIND_NOT_ALLOWED`. Identifier provenance still applies to read args in
  all cases above.

## Post-confirmation reads (P0-11)
Confirmation must not forbid further evidence gathering. Reads are
non-consequential, so an own-`read_tools` read stays admissible after the
task is CONFIRMED, at least once per distinct `(tool, args)`, while the
task's direct dependents (`CausalRegistry.open_dependents`) are not yet
closed; identifier provenance still applies and the read is
`observation_only` (it never re-closes or un-closes anything). Only an
exact repetition — same tool+args already observed with no intervening
confirmation or confirmed observation since (`performed_observation` /
`state_changed_after` on registry sequence, or the sidecar's settled
read digest for records without tool/args) — is throttled, as
`ALREADY_CONFIRMED`, and any causal state change makes it admissible
again. Non-read actions on a CONFIRMED task, and reads once all
dependents are closed, remain `ALREADY_CONFIRMED`.

## ANALYZE stale-ref tolerance (P0-12)
`analyze_ref_partition` splits cited refs into valid (real, confirmed,
in-chain), stale (real, in-chain, not confirmed — e.g. taken before the
dependencies finished), unknown (does not exist) and wrong-task (outside
the dependency chain). An analysis is admitted when it cites at least
one valid fresh ref and no unknown/wrong-task ref; stale refs are then
ignored as evidence but reported in the controller log
(`CAUSAL_ADMIT` carries `stale_refs`/`valid_refs`), in the admitted
verdict's hint returned to the agent (`struct_agent` appends it as
`CAUSAL_HINT:` and logs `CAUSAL_ADMIT_WARNING`), and in the registry
(`Obligation.ignored_stale_refs`). It is refused only when no valid
fresh supporting evidence is cited (`ANALYZE_STALE_EVIDENCE_REF` if only
stale refs were cited, `ANALYZE_MISSING_EVIDENCE_REFS` if none), or a
ref does not exist (`ANALYZE_UNKNOWN_EVIDENCE_REF`) or belongs outside
the chain (`ANALYZE_EVIDENCE_FROM_WRONG_TASK`) — provenance breaks are
never tolerated. The registry applies the same rule on ingest, so a
stale-only `ANALYSIS_RECORD` never closes an ANALYZE task.

## State-aware repeat protection (P0-7)
Admissibility is re-evaluated first on every attempt. Repeated refusals
are tracked per `(action fingerprint, refusal reason, registry state
digest)` (`CausalRegistry.state_digest`: confirmed tasks, satisfied
kinds, confirmed observations, confirmation order). `REPEAT_BLOCKED` is
signalled once, on the third identical refusal under the same reason and
digest, carrying `underlying_code` and `transient`; later attempts under
the same state carry the original reason, and any change of digest or
reason — or the action becoming admissible — clears the repeat. One
`DEPENDENCIES_OPEN` refusal can therefore never become a permanent block.

## Transient refusals and scripted retry (P0-8)
Verdicts carry `transient` (true for `DEPENDENCIES_OPEN`, `EVENT_PENDING`
and the like, including a `REPEAT_BLOCKED` whose `underlying_code` is
transient). The scripted decider (`struct_agent._execute_scripted_step`)
retries a transient `CAUSAL_REFUSAL` exactly like gate DEFERRED/BLOCKED:
writes under `retry_blocked_max_s`, reads under `until` polling (a
transient refusal behaves like an unmatched poll; without `until` it is
retried bounded by `max_s` or 180 s), and sends/analyzes with await-style
retry until admitted, bounded by the step's `max_s` or a default of 180 s.
Permanent refusals are not retried.

## Refusal reasons (sidecar, logged as CAUSAL_REFUSAL with corrective hint)
NO_DECISION_REF, UNKNOWN_TASK, WRONG_AGENT, ALREADY_CONFIRMED, KIND_NOT_ALLOWED,
DEPENDENCIES_OPEN, NO_RECIPIENTS, WRONG_RECIPIENT, WRONG_EVENT,
IDENTIFIER_PROVENANCE, ANALYZE_* (missing/unknown/stale/wrong-task refs),
REPEAT_BLOCKED (same inadmissible action repeated under the same reason and
state digest; see P0-7), EXIT_BLOCKED_OPEN_OBLIGATIONS.
See ACTION_SCHEMAS.json for the per-action checks.

## Exit rule (WP-A)
An agent may not exit as `all_tasks_terminal` while any of its mandatory
obligations is unconfirmed (`CausalRegistry.can_exit`, `CausalSidecar.check_exit`).

## Attempt authority & write permits (E6e, supersedes E6c/E6d file authority)
Execution authority was previously read from a mutable local
`attempt.json` (`STRUCT_ATTEMPT_FILE`/`STRUCT_ATTEMPT_UID`), and absence
of proof was treated as permission. That design is removed.

- **One authority.** `attempt_authority.py` runs as a separate process
  spawned and owned by `supervisor.py` for the attempt's lifetime. It
  alone holds (memory only): `attempt_uid`, `world_instance_id`, state,
  a monotonically increasing `epoch` bumped on EVERY lifecycle
  transition, and the per-attempt HMAC key. The key is generated per
  attempt in supervisor memory and handed only to the gate (mission-host
  process) and the world (`world_server.py`) through their inherited
  spawn environments (`STRUCT_AUTHORITY_URL/KEY/GATE_TOKEN/WORLD_TOKEN`).
  It never touches the run directory and never enters an agent's
  environment. Run-directory files (`attempt.json` etc.) are evidence,
  never authority; nothing in gate/world believes them.
- **Permit format.** `{permit_id, attempt_uid, world_instance_id,
  epoch, task_id, command_id, nonce, exp}` + `mac` =
  HMAC-SHA256(per-attempt key, canonical permit without `mac`).
  Short expiry (300 s default). The authority issues permits (gate
  token only) ONLY while `state == RUNNING`; leaving RUNNING bumps the
  epoch and stops issuance, and a terminal transition destroys the key.
- **Double verification.** (a) Gate: `execute_struct_action` refuses
  before any seal unless the live authority proves RUNNING and the
  caller identity matches; `StructInputResolver` obtains a fresh permit
  bound to task+directive command; the HARD tier
  (`StructTaskTier`) verifies MAC/expiry/epoch/identity/task/command.
  VEIP warrants issued by the host carry `attempt_uid` and
  `world_instance_id` in their scope. (b) World: `/actuate`
  independently re-verifies the same permit against the live authority
  (MAC, freshness, epoch == current, identity, task/command) and burns
  its nonce on first applied effect, so replay is DENIED at the world
  even if the gate were bypassed.
- **Deny matrix.** Missing, substituted, expired, stale-epoch, wrong
  `world_instance_id`/`attempt_uid`, replayed, or unverifiable permit
  => DENY. Unreachable authority => DENY. No fallbacks: no env, no file,
  no legacy admit path. Unit tests construct an explicit
  `attempt_authority.TestAuthority`; there is no admit-without-authority
  mode in campaign or qualification code.
- **No world without authority.** `world_server.py` and
  `mission_host.py` refuse to create a world without a valid single-use
  world capability consumed at a live authority. Terminal, foreign, or
  already-used capabilities => refuse (exit 3, no WORLD_START).
- **Evidence.** Gate commits and world NATIVE_EFFECT/RECEIPT records
  carry `permit_id`, `permit_epoch`, `permit_verified`; WRITE_REFUSED
  records carry the rejected identity, `permit_id/epoch`, and reason.

Negative proof: `test_attempt_authority_e6e.py` N1-N9 (attempt.json
deleted/rewritten, authority killed, stale/expired/foreign/replayed
permits, actuator-token-only actuation, legacy hosts without a live
capability, and no attempt context at all), each asserting zero
mutations (state digest, /effects, NATIVE_EFFECT/RECEIPT unchanged).

## Lifecycle record & tamper policy (E6g, P0-17)

- `terminal_from_env()` is removed. Every runtime control path
  (sidecar `/check`, mission host start, supervisor monitor, provider
  proxy, controller directive, evidence writers) queries the LIVE
  attempt authority (or, in the supervisor, its own in-memory state);
  `attempt.json` is a convenience snapshot that nothing believes.
- The lifecycle record is `ATTEMPT_LOG.jsonl`: owner-written (supervisor
  only), append-only, hash-chained (`prev_hash`/`hash`) and MAC'd
  (HMAC-SHA256 with the per-attempt key, the same key the authority
  holds; it never enters an agent env or the run dir as plaintext).
  Every transition (REGISTERED, RUNNING, COMPLETED/INTERRUPTED with
  reason/verdict) is recorded; the supervisor always writes its terminal
  record itself and verifies the chain afterwards.
- Declared tamper policy (`attempt.TAMPER_POLICY=continue_and_record`):
  the supervisor hashes its own snapshot; any divergence/deletion of
  `attempt.json` is recorded once as `EVIDENCE_TAMPER_DETECTED`, the
  forged snapshot is restored from in-memory truth, and the attempt
  CONTINUES under the live authority (a forged COMPLETED never shuts it
  down). The owner still writes the terminal record.
- Pre-start refusal uses authenticated state: a verified ATTEMPT_LOG
  terminal record and/or the runs-root registry
  (`.attempt_registry/<run_id>.json`, O_EXCL, supervisor pid + attempt_uid).
  Deleting/rewriting `attempt.json` never makes a used run_id startable.
- Negative proof: `test_attempt_log_e6g.py` T1 (rewrite COMPLETED mid-run),
  T2 (delete mid-run), T3 (forged RUNNING after terminal + second
  supervisor/legacy host refused), T4 (ATTEMPT_LOG tail edit detected),
  each asserting 1 WORLD_START and a verified owner terminal record.

## Campaign CAGE posture (E6f, P0-16)

The campaign and qualification paths never run under pytest, so the
supervisor establishes the campaign's CAGE posture EXPLICITLY and
deterministically (`supervisor.CAMPAIGN_CAGE_POSTURE` /
`_campaign_env` / `campaign_posture_record`). Every child the
supervisor spawns (attempt authority, stub model, provider proxy,
mission host) receives: minimal system variables (`PATH`, `HOME`,
`SYSTEMROOT`, temp/locale names) + the declared posture below +
exactly the supervisor-intended variables for that child. The caller's
environment is not inherited; a caller exporting
`CAGE_ENV=production`, `CAGE_TELEMETRY_PROVIDER=remote`, telemetry
credentials or KMS keys cannot change the campaign posture.

Declared posture (replicated from `tests/conftest.py` module level +
`pytest_configure`, as the gate/governor depends on it, with the
values effectively in force during a B0/WO-006 struct mission):
`CAGE_ENV=test`, `CAGE_DOMAIN=finance`,
`CAGE_DEPLOYMENT_REGION=EU_ECB`, `GOOGLE_CLOUD_LOCATION=europe-west1`,
`CAGE_TELEMETRY_PROVIDER=null`,
`GOVERNANCE_SALT=dev-only-insecure-placeholder-not-for-production-use`,
`LANGFUSE_POSTURE_DRY_RUN=true`,
`CMEK_KEY_RESOURCE_NAME=projects/test-project/locations/us-central1/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/1`,
`CAGE_TRUSTED_CLIENT_IDENTITIES=cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local`,
`LANGCHAIN_TRACING_V2=false`, `LANGSMITH_TRACING=false`,
`OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES`,
`TOKENIZERS_PARALLELISM=false`, `EVIDENCE_STREAM_ENABLED=true`,
`OTEL_TRACES_EXPORTER=none`,
`OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:3001/api/public/otel/v1/traces`,
`OPENLLMETRY_ENABLED=false`, `BACKEND_URL=http://localhost:18080`,
`GATEWAY_URL=http://localhost:8080`, `LANGFUSE_HOST=http://localhost:3001`,
`LANGFUSE_BASEURL=http://localhost:3001`,
`VLLM_REASONING_API_BASE=http://localhost:8000/v1`,
`VLLM_SERVICE_URL=http://localhost:8001`,
`COMPLIANCE_BRIDGE_URL=http://localhost:3002`,
`OPA_URL=http://localhost:8181`, `OPA_CACHE_ENABLED=false`,
`REDIS_URL=redis://localhost:6379`. Forced UNSET (recorded by name
only, never by value): `KMS_GOVERNANCE_KEY`,
`KMS_GOVERNANCE_PUBLIC_PEM`, `TELEMETRY_HOST`,
`TELEMETRY_PUBLIC_KEY`, `TELEMETRY_SECRET_KEY` — exactly conftest's
KMS pop, forcing the same HMAC seal fallback B0 used.

The full posture (variable names and values, no secrets — the salt is
conftest's public dev-only placeholder) is recorded in both
`RUN_HEADER.json` (`cage_posture`) and `attempt.json`
(`cage_posture`, at registration, before anything starts).

Differences from conftest's literal text, and why (nothing weakened):

- `CAGE_TELEMETRY_PROVIDER=null` is set explicitly. Under conftest it
  was unset; with `CAGE_ENV=test` (non-enforcing posture) and no
  `TELEMETRY_*` credentials present, the telemetry factory fell back
  to the identical `NullTelemetryProvider`. Explicit `null` only makes
  that effective provider deterministic when the caller exported
  credentials — the effective provider is unchanged, so B1 remains
  comparable to B0.
- `CAGE_DEPLOYMENT_REGION=EU_ECB` (with
  `GOOGLE_CLOUD_LOCATION=europe-west1`): conftest's session default is
  `US_FED`, but the struct mission test is marked `eu_ecb`, so the
  per-test region fixture pinned `EU_ECB` for every B0/qualification
  mission, and `mission_host.make_build_factory` pins the same region
  and EU thresholds. `EU_ECB` is therefore the region B0 effectively
  ran under; recording it explicitly does not change it.
- Supervisor-internal mission variables the old pytest host also set
  (`CAGE_SEAL_STRICT_MODE=false`, the warrant-source selection, the
  EU threshold swap in `mission_host.make_build_factory`) remain set
  by the mission host itself, unchanged.

Qualification uses the identical path: `run_qual_core.sh` invokes the
same supervisor with `--decider scripted`, the hidden plan supplied
only via the `STRUCT_PLAN` environment variable (never on a command
line), honouring the old harness's `STRUCT_OUT` / `STRUCT_RUN_ID` /
`STRUCT_WORLD` contract. `meta_qual.sh` calls this entry; 26/26 is
kept through it.
