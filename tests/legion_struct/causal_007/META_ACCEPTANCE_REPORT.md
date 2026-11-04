# META_ACCEPTANCE_REPORT — WO-LEGION100-CAUSAL-CLOSURE-007 (E6f)

## E6f: P0-16 — the real campaign path did not run from a clean shell
Claude's clean-shell reproduction of `run_campaign_core.sh --dry-run`
died with `CAGE_TELEMETRY_PROVIDER must be set under an enforcing
posture`: every prior run had inherited the CAGE TEST posture from
pytest's `tests/conftest.py`, and the pytest-free supervisor dropped
it. Fixed by construction (CAUSAL_STATE_SPEC.md § Campaign CAGE
posture, ROOT_CAUSE_REGISTRY.md E6f): the supervisor establishes the
declared posture explicitly (`CAMPAIGN_CAGE_POSTURE`, replicated from
conftest; KMS/telemetry credentials forced unset), never inherits it
from the caller, and records it in RUN_HEADER + attempt.json.

## What was run (E6f)
- `test_campaign_dryrun.py::test_campaign_core_clean_env_dry_run_completes`:
  `run_campaign_core.sh --dry-run` from an explicit minimal env with
  hostile inherited posture — COMPLETED, world actions, exactly 1
  WORLD_START, complete evidence, posture recorded.
- `test_campaign_dryrun.py::test_qual_core_supervisor_scripted_clean_env`:
  the new supervisor-based qualification entry `run_qual_core.sh`
  (scripted decider, hidden plan via `STRUCT_PLAN` only) — COMPLETED.
  meta_qual.sh should call this entry instead of the pytest wrapper.
- A–F and N1–N9 re-run on the clean-env path (A, B, F and N3/N7 in
  particular no longer use a pytest-inherited environment).
- `meta_dev.sh units` — **83 passed, EXIT=0**.
- `meta_qual.sh <family> both`, all 13 families — **26/26 qualified**.

## E6e report (superseded sections below)

## E6e: architectural NO-GO of E6c/E6d and the replacement design
E6c/E6d made execution authority depend on a mutable local JSON
(`attempt.json`, `STRUCT_ATTEMPT_*` env): absence of proof was treated
as permission. E6e replaces it by construction (see CAUSAL_STATE_SPEC.md
"E6e" and ROOT_CAUSE_REGISTRY.md):
- One authoritative attempt-state source: a supervisor-owned
  attempt-authority process (`attempt_authority.py`) holding
  attempt_uid/world_instance_id/state/epoch and a per-attempt HMAC key
  in memory only; run-dir files are evidence, never authority.
- Fresh MAC'd permit per consequential write (attempt/world/epoch/
  task/command/nonce/short expiry), issued only while RUNNING; epoch
  bumps on every transition; the key is destroyed at terminal.
- Independent verification twice: the CAGE gate HARD tier verifies the
  permit before any seal (VEIP warrants are scoped to the attempt), and
  the world `/actuate` re-verifies against the live authority and burns
  the nonce. Deny by default; no env/file/legacy fallback; unit tests
  construct an explicit `TestAuthority`.
- No world without a live authority: a single-use world capability
  consumed at the authority is required for world creation.

## What was run (E6e)
- `test_attempt_authority_e6e.py` N1-N9 mandatory negatives (attempt
  file deleted/rewritten, authority killed, stale/expired/foreign/
  replayed permits, actuator-token-only actuation, legacy hosts without
  capability, no attempt context): all DENY with zero mutations.
- `meta_dev.sh units` — **81 passed, EXIT=0**.
- `meta_qual.sh <family> both`, all 13 families — **26/26 qualified**.
  SYN-GAIA-EXE initially returned UNAUTHORIZED_NATIVE_EFFECT x5 during
  the session; it did not reproduce on the final code state (three
  consecutive EXE passes, full sweep re-run end-to-end). See
  PROGRESS.md for the unabridged note.

## Round-4 report (superseded sections below)

## Round-3 NO-GO defects and how they were fixed
One family: the controller declared an obligation closed, or evidence
invalid, too early and too absolutely, refusing legitimate follow-up work.
- **P0-11 Post-confirmation reads.** `ALREADY_CONFIRMED` no longer blocks
  evidence gathering: an own-`read_tools` read stays admissible after its
  task is CONFIRMED, at least once per distinct (tool, args), while the
  task's direct dependents are not yet closed; provenance still applies,
  `observation_only`. Only an exact repetition under unchanged causal
  state is throttled (state-aware; any confirmation/confirmed observation
  since re-admits it). Non-read actions on a confirmed task and reads
  after all dependents close are still refused.
- **P0-12 ANALYZE with some stale refs.** Refs are partitioned
  valid/stale/unknown/wrong-task. Admission requires at least one fresh
  valid in-chain ref and no fabricated/out-of-chain ref; stale refs are
  ignored as evidence but reported in the controller log
  (`stale_refs`/`valid_refs`), in the agent's feedback (`CAUSAL_HINT:` /
  `CAUSAL_ADMIT_WARNING`), and in `Obligation.ignored_stale_refs`. The
  registry applies the same rule on ingest, so stale-only analyses never
  close a task and falsifier provenance breaks still fail.

## What was run (round 4)
- New regressions in test_causal_registry.py (P0-11 distinct/repeat/
  state-change reads; P0-12 stale+fresh admission and stale-only /
  unknown / wrong-task / missing refusal).
- `meta_dev.sh units` — EXIT=0.
- `meta_qual.sh <family> both`, all 13 families — **26/26 qualified**
  (every gold qualified=true, every falsifier qualified=true/rejected;
  round 3 was 23/26).

## Round-3 report (superseded sections below)

## Round-2 NO-GO defects and how they were fixed
- **P0-6 READ under a task's own read_tools.** `CausalSidecar` no longer
  requires READ in `task.kinds` for a read whose tool is in the task's own
  `read_tools`: it is admissible whenever the task is open and dependencies
  are satisfied (`observation_only`; the registry marks an eligible such
  observation `_confirmed` as evidence but never satisfies a non-READ
  task). For READ-kind tasks a read before dependencies confirm is
  admitted as `OBSERVATION_ONLY` and is recorded stale by the registry,
  so it does not close the task. A tool outside `read_tools` stays
  `KIND_NOT_ALLOWED`; identifier provenance still applies. The
  `struct_agent` local guard mirrors the own-`read_tools` rule.
  `CAUSAL_STATE_SPEC.md`/`ACTION_SCHEMAS.json` were re-derived to match.
- **P0-7 State-aware REPEAT_BLOCKED.** Admissibility is re-evaluated
  first on every attempt; repeats are tracked per (action fingerprint,
  refusal reason, `CausalRegistry.state_digest()` over confirmed tasks /
  satisfied kinds / confirmed observations / confirmation order).
  `REPEAT_BLOCKED` is signalled once per such key, with
  `transient`/`underlying_code`; a changed state or reason, or admission,
  clears it. The 171-refusal livelock (one `DEPENDENCIES_OPEN` becoming
  permanent) cannot recur.
- **P0-8 Scripted decider compatibility.** Sidecar verdicts carry
  `transient`; `struct_agent._execute_scripted_step` retries a transient
  `CAUSAL_REFUSAL` exactly like gate DEFERRED/BLOCKED: writes under
  `retry_blocked_max_s`, reads under `until` polling (without `until`,
  bounded by `max_s`/180 s), sends/analyzes await-style until admitted
  bounded by `max_s` or a default of 180 s. Permanent refusals are not
  retried.
- **P0-9 Runner ZTL path.** `ztl_service.py` defaults
  `LEGION_ZTL_SWARM_DIR` to `$HOME/legion_pf/ztl-swarm`;
  `run_campaign_core.sh` resolves the same default, refuses (exit 2)
  before registering RUN_HEADER if the path does not exist, and passes
  the resolved path to the mission host.
- **P1-2 Scan on host failure.** The host invocation is
  `... || HOST_RC=$?`, so under `set -e` cleanup and the key-material scan
  always run, and the core then exits with the host's code.
- **P0-10 Smoke asserts progress.** The 13-world smoke now fails on a
  `REPEAT_BLOCKED` storm (>=5 per agent) or on any plan-executed task not
  CLOSED in a registry rebuilt from the run logs; smoke read args use
  real public identifiers. New regression
  `test_scripted_exe_causal_regression_p0_6_7_8` runs the round-2
  reproduction sequence through the real host path and asserts T1..T7
  CLOSED, native effects for every write task, no read
  `KIND_NOT_ALLOWED`, no repeat storm, and T7 delivered after the
  T4/T5/T6 effects.

## What was run (round 3, sandboxed meta_dev, no NIM/network)
- test_causal_registry.py — 9 passed (incl. new P0-6/P0-7 tests).
- test_b0_replays.py — 16 passed (EXE/TIM/OTEL-05/06 expectations updated
  to plain-observation semantics: early reads are admitted, never close).
- test_campaign_dryrun.py — 5 passed (incl. P0-9 missing-ZTL refusal
  before RUN_HEADER).
- test_runtime_integration.py — 5 passed: EXE dry-run (stub NIM),
  EXE scripted regression P0-6/7/8 (~32 s), core --dry-run pipeline,
  S100 delegation, and the 13-world scripted smoke with progress
  assertions (~285 s).
- Full gate: `meta_dev.sh units` — **52 passed in 416 s**.

## Round-2 report (superseded sections below)

## Round-1 NO-GO defects and how they were fixed
- **P0-1 Runner.** `run_campaign_core.sh` now runs the campaign itself: it
  registers RUN_HEADER (`t_episode_registered` +
  `t_episode_registered_mono`) BEFORE starting the proxy, creates per-agent
  proxy tokens (and the host mints world tokens) for all 100 workers,
  starts `causal_007/provider_proxy.py`, runs the mission host with
  `STRUCT_DECIDER=nim`, 100 workers, cage env
  (`GOVERNANCE_SEAL_TTL_S=1800`, `LEGION_COMPOSITION=v3`,
  `MCP_RATE_LIMIT_MAX_CALLS=6000`, `LEGION_ZTL_SWARM_DIR`), then stops the
  proxy, deletes token maps and scans for key material. `--dry-run`
  executes everything except NIM (proxy against `stub_model_server.py`,
  agents on the stub model only). `run_campaign.ps1` just calls the core
  via `wsl.exe -d Ubuntu-24.04` (MSYS-safe) and refuses existing run dirs.
  S100 sets `STRUCT_CAUSAL_OVERLAY=s100` in the host.
- **P0-2 Enforcement in the real path.** `causal_007/sidecar_server.py` is a
  separate process started by `test_struct_mission.py`, fed by the world
  `/log` (reader token), `GATE_COMMITS.jsonl` and `READBACK.jsonl`. Every
  agent world/gate call (`struct_agent.execute`: read/send/wait/analyze/
  reconcile/done/write/refuse) is checked by it first; refusals (logged
  reason + corrective hint) go to `CAUSAL_CONTROLLER.jsonl`, never to
  WORLD_LOG. The WP-B next-eligible view (incl. confirmed shared evidence)
  is in the agent prompt. Exit as `all_tasks_terminal` is blocked while
  the registry has open obligations; turn/wall exits still allowed. The
  sidecar never originates an action. Admitted actions execute against the
  unchanged world server/gate with the agent's provider_response_id as
  decision_ref.
- **P0-3 Transport.** The runner-started `provider_proxy.py` is built on
  `nim_transport.NimTransport`: global concurrency semaphore/queue, 429
  Retry-After + jittered backoff, 5xx/timeout retries, atomic
  one-record-per-call provider_log with the scale_provider_logger fields
  (agent from token, provider_response_id, http_status, status, usage,
  request_messages, response_content, t_start_mono, t_end_mono).
  Transport retries never consume a decision turn (agent only sees the
  final response; a failed provider call still follows the REV4 no-action
  path in `run_nim`).
- **P0-4 S100.** Host loads `delegation.build_s100_spec` overlay on
  unchanged OTEL-04 (file untouched): 100 distinct agent processes, each
  with its own proxy token/NIM calls; delegates are read-only (READ tasks,
  no write_tool/warrants) and go through the same sidecar; downstream
  `Cp*` send decisions cite delegate observation ids from the shared
  evidence view; the host writes `S100_CONTRIBUTION.json`
  (registered/provider-active/contributing/idle) from the run's logs.
- **P0-5 Proof in the runtime.** `test_runtime_integration.py` runs the
  REAL host path for GAIA-EXE (premature READ refused, wrong-task send
  refused with hint, exit blocked, every world action decision_ref-valid),
  the full core `--dry-run` pipeline, S100 OTEL-04, and the full scripted
  13-world smoke at 100 registered workers (scripted decider,
  INTEGRATION_ONLY) through the same host+sidecar path.
- **P1-1.** RUN_HEADER carries `t_episode_registered_mono`; a test asserts
  it precedes the first provider_log `t_start_mono`. PROGRESS.md updated.

## What was run (sandboxed tool, no NIM/network)
- test_causal_registry.py — 7 passed.
- test_b0_replays.py — 16 passed.
- test_campaign_dryrun.py — 4 passed.
- test_runtime_integration.py::test_dry_run_real_host_path_exe — passed (~29 s).
- test_runtime_integration.py::test_s100_delegation_real_path — passed (~31 s).
- test_runtime_integration.py::test_core_dry_run_full_pipeline_exe — passed (~32 s).
- test_runtime_integration.py::test_full_scripted_smoke_13_worlds_100_registered — passed (~309 s).
- Full gate: `meta_dev.sh units` — see PROGRESS.md for the final result.

## Not run
- No live NIM campaign (sandbox has no network/key). B1/S100 live runs are
  for Claude via run_campaign.ps1. Budgets unchanged (14 turns, 420 s).
