# WO-LEGION100-CAUSAL-CLOSURE-007 Progress

## Status: E6f complete — P0-16 fixed, all gates green on the delivered code state

## E6f (Claude acceptance of E6e: NO-GO P0-16 — real campaign path did not run)
- Root cause: B0/WO-006, qualification and all unit tests ran under
  pytest, whose `tests/conftest.py` implicitly establishes the CAGE
  TEST posture. The pytest-free supervisor inherited the caller's
  environment, so from a clean shell the mission host started under
  the default enforcing posture and died:
  `ConfigurationError: CAGE_TELEMETRY_PROVIDER must be set under an
  enforcing posture` → INTERRUPTED (host_died_no_restart).
- Fix (`supervisor.py`, `attempt.py`): the supervisor now establishes
  the campaign posture EXPLICITLY and deterministically.
  `CAMPAIGN_CAGE_POSTURE` replicates exactly what `tests/conftest.py`
  sets that the gate depends on (full list in CAUSAL_STATE_SPEC.md
  § Campaign CAGE posture); KMS/telemetry credentials are forced
  unset (same HMAC fallback as conftest). `_campaign_env()` builds
  every child environment (authority, stub, proxy, mission host) from
  minimal system vars + declared posture + supervisor-intended vars
  only — the caller's environment is never inherited for posture
  (a caller exporting `CAGE_ENV=production`,
  `CAGE_TELEMETRY_PROVIDER=remote`, bogus KMS/telemetry credentials
  has no effect; proved by the clean-env test). The full posture
  (names+values, no secrets) is recorded in `RUN_HEADER.json`
  (`cage_posture`) and in `attempt.json` (`cage_posture`, at
  registration via `attempt.register(cage_posture=...)`).
  Documented non-weakening differences only: explicit
  `CAGE_TELEMETRY_PROVIDER=null` (identical effective Null provider
  conftest fell back to) and `CAGE_DEPLOYMENT_REGION=EU_ECB` (the
  region the eu_ecb-marked struct mission effectively ran under in
  B0). Nothing else differs; B1 stays comparable to B0.
- Req-2 test: `test_campaign_dryrun.py::
  test_campaign_core_clean_env_dry_run_completes` runs
  `run_campaign_core.sh --dry-run` via subprocess with an explicit
  minimal env (outside pytest's env, with hostile inherited posture):
  COMPLETED, stub-model world actions, exactly 1 WORLD_START,
  complete evidence (`validate_evidence == []`), posture recorded
  and equal in RUN_HEADER + attempt.json.
- Req-3 qualification: new `run_qual_core.sh` is the supervisor-based
  qualification entry — same supervisor, same posture, same attempt
  lifecycle, `--decider scripted`, hidden plan supplied ONLY via the
  `STRUCT_PLAN` environment variable (never on a command line),
  honouring the old harness contract (`STRUCT_OUT`, `STRUCT_RUN_ID`,
  `STRUCT_WORLD`, `STRUCT_FAMILY`, `STRUCT_N_WORKERS`, `STRUCT_MODE`).
  **meta_qual.sh: call `bash tests/legion_struct/causal_007/run_qual_core.sh`
  (with `STRUCT_PLAN`/`STRUCT_OUT`/`STRUCT_RUN_ID`/`STRUCT_WORLD` set
  as today) instead of the pytest wrapper.** Proved clean-env by
  `test_qual_core_supervisor_scripted_clean_env` (COMPLETED, 1
  WORLD_START, native effects, posture recorded). The delivered
  `meta_qual.sh <family> both` sweep remains 26/26 (below); Claude's
  harness switches to `run_qual_core.sh` for the same 26.
- Req-4 re-runs on the clean-env campaign path: A–E
  (`test_supervisor_e6b.py`, `_sup_env` is now `_clean_env`: minimal
  system vars only, posture established by the supervisor) — 5
  passed; F (`test_supervisor_bypass_f.py`, imports that clean env)
  — 1 passed; N1–N9 (`test_attempt_authority_e6e.py`: world fixtures
  and the gate-denial harness now use `_clean_env` / the explicitly
  declared posture, incl. N3 authority-killed and N7
  actuator-token-only) — all passed in the full gate. In particular
  A, B, F and N3/N7 no longer inherit pytest's environment.

## E6f final gate results (delivered code state)
- `meta_dev.sh units` — **83 passed, EXIT=0** (81 prior + the 2 new
  E6f clean-env tests; includes A–F and N1–N9 on the clean-env path).
- `meta_qual.sh <family> both`, all 13 families — **26/26 qualified**
  (every gold qualified=true; every falsifier qualified=true with the
  judge FAIL verdict): SYN-GAIA-EXE, SYN-GAIA-TIM, SYN-GAIA-A2A,
  SYN-GAIA-ADA, SYN-GAIA-NOI, SYN-GAIA-AMB, SYN-GAIA-SEA,
  SYN-OTEL-01..06.

## E6e (architectural NO-GO of E6c/E6d: mutable-file authority, fail-open)
- `causal_007/attempt_authority.py` (new): supervisor-spawned per-attempt
  authority process; sole source of attempt_uid/world_instance_id/state/
  epoch (bumped on every transition) + per-attempt HMAC key in memory
  only. Key generated in supervisor memory, inherited only by gate/world
  spawn env; never run dir, never agent env. Permits
  `{permit_id, attempt_uid, world_instance_id, epoch, task_id,
  command_id, nonce, exp, mac}` issued only while RUNNING; terminal
  destroys the key. `TestAuthority` is the explicit unit-test authority.
- Gate (`struct_plugin.py`): `execute_struct_action` DENYs before any
  seal when the live authority is unreachable/not RUNNING/mismatched;
  resolver obtains a fresh permit per task+command; HARD tier verifies
  MAC/expiry/epoch/identity/task/command (`PERMIT_MISSING`/
  `PERMIT_INVALID`, attempt codes retained). No file/env/legacy admit.
- World (`world_server.py`): startup refuses without a live authority +
  single-use capability consumed at the authority; `/actuate`
  independently re-verifies the permit against the live authority and
  burns its nonce on first applied effect (replay DENIED at the world);
  NATIVE_EFFECT/RECEIPT and WRITE_REFUSED record permit evidence.
- Supervisor/mission_host: supervisor spawns+owns the authority, mirrors
  terminal transitions to it (epoch++/key destroyed), passes the channel
  only to host/world; host refuses any world without a live RUNNING
  authority; VEIP warrant scope carries attempt_uid+world_instance_id.
  `test_struct_mission.py` (pytest/qual wrapper) constructs an explicit
  TEST authority — there is no admit-without-authority path.
- Negative tests N1-N9 in `test_attempt_authority_e6e.py` (real gate
  refusal path + real world subprocess, loopback only), each asserting
  zero mutations; A-F supervisor tests and units updated to E6e.
- `test_supervisor_bypass_f.py` (Test F) hardened for a load race:
  SIGSTOP does not cancel gate/world requests already in flight, so the
  probe now waits for observable pipeline quiescence (identical state
  digest + record counts across two snapshots) before its before/after
  windows. No assertion was relaxed.

## E6e final gate results (delivered code state)
- `meta_dev.sh units` — **81 passed, EXIT=0** (includes N1-N9 and the
  A-F supervisor suite).
- `meta_qual.sh <family> both`, all 13 families — **26/26 qualified**
  (every gold qualified=true; every falsifier qualified=true with the
  judge FAIL verdict the negative control is designed to produce):
  SYN-GAIA-EXE, SYN-GAIA-TIM, SYN-GAIA-A2A, SYN-GAIA-ADA, SYN-GAIA-NOI,
  SYN-GAIA-AMB, SYN-GAIA-SEA, SYN-OTEL-01..06.
- Honest note on SYN-GAIA-EXE: during this session its gold run first
  returned `FAIL:UNAUTHORIZED_NATIVE_EFFECT` x5 on several consecutive
  qual runs, while locally generated evidence (pytest-scripted, NIM
  stub, and supervisor dry-run shapes) satisfied every authorization
  linkage reconstructible from the repo contracts (EXECUTED commit,
  seal, command/effect identity, permit id/epoch, attempt/world
  identity, evidence-chain record hashes). On the final code state EXE
  qualified on three consecutive qual runs and the complete 13-family
  sweep above was executed end-to-end on that exact state; the earlier
  failures did not reproduce and no mission-path code changed between
  the last failing run and the passing sweep (only a temporary,
  since-removed probe in the pytest wrapper). Recorded here rather than
  silently dropped.


## E6b (supersedes E6): authoritative execution supervisor
Root cause (owner statement): mission execution had no single
authoritative owner of the attempt lifecycle/identity. In b1-GAIA-EXE,
pytest-xdist + `--timeout=120` killed the host worker and the World was
re-created 9x under the same run_id. `-n0` alone is not a fix; the
campaign path no longer runs through pytest at all.

- `causal_007/attempt.py`: attempt registry — O_EXCL register of
  (campaign_id, run_id, attempt_index=1) with immutable attempt_uid,
  world_sha256, runtime_sha256, state REGISTERED; lifecycle
  REGISTERED -> RUNNING -> COMPLETED | INTERRUPTED (verdict INVALID);
  terminal states immutable; StampedAppender (attempt_uid,
  world_instance_id, strictly monotonic per-file seq; writers reject
  foreign identity and post-terminal writes); validate_evidence().
- `causal_007/supervisor.py`: the single owner. Registers the attempt,
  writes RUN_HEADER (WO-006 compatible, +attempt identity), mints ONE
  single-use world capability (SHA-256 only in attempt.json; world
  consumes it), spawns stub/proxy/mission_host as process groups,
  heartbeats, and on any host/critical death kills the whole tree and
  marks INTERRUPTED/INVALID. A second supervisor for the same run is
  refused before creating anything; supervisor-less RUNNING attempts are
  marked INTERRUPTED on contact, never restarted.
- `causal_007/mission_host.py`: pytest-free host (World orchestration,
  build factory, ShimPatch). `test_struct_mission.py` is now a thin
  pytest wrapper (own `build` fixture delegating to the factory; fresh
  STRUCT_OUT when unset). meta_qual's STRUCT_* path still drives it.
- `run_campaign_core.sh`: thin wrapper over supervisor.py
  (`|| HOST_RC=$?` + key-material scan preserved; ZTL refuse-before-
  register preserved). Verified: contract tests updated to assert the
  supervisor contract and the absence of any pytest invocation.
- Evidence isolation: WORLD_LOG / GATE_COMMITS / CONTROLLER_EVENTS /
  CAUSAL_CONTROLLER / READBACK / provider_log / CAGE_EVIDENCE_CHAIN /
  VEIP_RELIANCE / WORKERS records carry attempt_uid, world_instance_id,
  seq; gate and world refuse commits/actuation for terminal attempts.
- Provider isolation: HTTP 429 is handled inside the live attempt by
  NimTransport (global queue/cooldown, Retry-After as floor) via
  provider_proxy (`--max-retries`); a transport error never creates a
  world, resets causal state, or consumes an attempt (test D).
- Incident 429 analysis (`incident_analysis.py`,
  `test_incident_analysis.py`, trimmed projection in `incident/`):
  the preserved provider_log.jsonl holds 193 records (memo said
  183/168 — partial capture), 178x429 + 1x502, 14x200, span 993.8 s:
  193 agent calls = 0.194/s (11.6/min) amplified x6.6 to 1280 upstream
  requests = 1.29/s; 179/193 calls exhausted all 7 attempts and failed.

## Status: round-4 fixes complete (round-3 P0-11/P0-12) — meta_qual 26/26, units green

## Round-4 fixes (Claude acceptance round 3: P0-11, P0-12)
One defect family: the controller declared an obligation closed, or
evidence invalid, too early and too absolutely, refusing legitimate
follow-up work.
- P0-11 (`sidecar.py`, `causal_registry.py`): `ALREADY_CONFIRMED` no
  longer blocks evidence gathering. An own-`read_tools` read stays
  admissible after its task is CONFIRMED, at least once per distinct
  (tool, args), while the task's direct dependents are not yet closed
  (`open_dependents`); identifier provenance still applies and the read
  is `observation_only`. Only an exact repetition — same tool+args
  already observed with no intervening confirmation/confirmed
  observation (`performed_observation`/`state_changed_after` on registry
  sequence, sidecar settled-read digest for records without tool/args)
  — is throttled as `ALREADY_CONFIRMED`, in a state-aware way: any
  causal state change re-admits it. Non-read actions on a confirmed
  task, and reads once all dependents are closed, are still refused.
- P0-12 (`causal_registry.py`, `sidecar.py`, `struct_agent.py`):
  `analyze_ref_partition` splits refs into valid/stale/unknown/
  wrong-task. An ANALYZE is admitted when its refs include at least one
  fresh valid in-chain observation and no fabricated or out-of-chain
  ref; stale in-chain refs are ignored as evidence but reported in the
  controller log (`CAUSAL_ADMIT` carries `stale_refs`/`valid_refs`), in
  the agent's feedback (admitted verdict hint appended as
  `CAUSAL_HINT:`, logged `CAUSAL_ADMIT_WARNING`), and in
  `Obligation.ignored_stale_refs`. Refused only when no valid fresh
  supporting evidence is cited, or a ref does not exist / breaks
  provenance. The registry applies the same rule on ingest.
- Regression tests (no hidden data): A2A T2 distinct second read after
  confirmation + exact-repeat throttle + dependents-closed cutoff,
  state-change re-admission of a repeated read, ANALYZE admitted with
  stale+fresh refs (sidecar + registry + log/hint reporting), and
  ANALYZE refused for stale-only / unknown / wrong-task / missing refs.
- Qualification: `meta_qual.sh <family> both` — all 13 worlds gold
  qualified=true and falsifier qualified=true (26/26; was 23/26).
  Nothing was weakened: every falsifier is still rejected by the Judge.
- `meta_dev.sh units`: EXIT=0.

## Done
- WP-A/D `causal_registry.py`, WP-B/C `sidecar.py`: obligation registry,
  per-kind closure, stale premature evidence, exit blocking, corrective
  hints, state-aware REPEAT_BLOCKED, no controller-originated actions.
- P0-2: `causal_007/sidecar_server.py` — separate sidecar process started
  by `test_struct_mission.py`, fed by world /log (reader token),
  GATE_COMMITS and READBACK. `struct_agent.execute` routes every world/
  gate action through it; prompt carries the next-eligible view (+ shared
  confirmed evidence); `all_tasks_terminal` exit is sidecar-checked.
  Refusals land in CAUSAL_CONTROLLER.jsonl only. Admitted actions hit the
  unchanged world/gate with the agent's provider_response_id as
  decision_ref.
- P0-3: `causal_007/provider_proxy.py` on `nim_transport.py` (global
  concurrency, 429 Retry-After/jittered backoff, atomic one-record-per-call
  provider_log with scale_provider_logger fields, agent from token). Only
  this proxy reads the NIM key (`file:<WINDOWS_USER_MOUNT>/Desktop/nvapi.txt`).
- P0-4: S100 overlay (`delegation.py` + host `STRUCT_CAUSAL_OVERLAY=s100`)
  on unchanged OTEL-04: 100 distinct processes/NIM identities, delegates
  read-only through the same sidecar, downstream Cp* decisions cite
  delegate observation ids, host writes S100_CONTRIBUTION.json
  (registered/provider-active/contributing/idle) from run logs.
- P0-1/P1-1: `run_campaign_core.sh` runs the whole campaign itself
  (RUN_HEADER with `t_episode_registered` + `t_episode_registered_mono`
  before the proxy; 100-worker proxy/world tokens; proxy start; mission
  host STRUCT_DECIDER=nim + cage env; proxy stop; token-map deletion;
  key-material scan; S100 overlay). `--dry-run` = full pipeline against
  `stub_model_server.py`. `run_campaign.ps1` is a thin
  `wsl.exe -d Ubuntu-24.04` wrapper refusing existing run dirs.
- P0-5 tests (`test_runtime_integration.py`): real-host EXE dry-run
  (premature READ refused, wrong-task send refused with hint, exit
  blocked, decision_ref audit), core --dry-run pipeline (mono header
  precedes first provider call), S100 real path, scripted 13-world smoke
  at 100 registered workers (INTEGRATION_ONLY).

## Round-3 fixes (Claude acceptance round 2: P0-6..P0-10, P1-2)
- P0-6 (`sidecar.py`, `causal_registry.py`, `struct_agent.py` local guard,
  `CAUSAL_STATE_SPEC.md`, `ACTION_SCHEMAS.json`): a READ with one of the
  task's own `read_tools` is admissible whenever the task is open and its
  dependencies are satisfied — READ need not be a closing kind. For
  READ-kind tasks a read is also admissible before dependencies confirm
  as plain observation (`OBSERVATION_ONLY`): the registry records it
  stale and it does not close the task. Such a read never closes a
  non-READ task; an eligible own-tool observation is confirmed evidence
  for provenance/shared evidence. A tool outside `read_tools` is still
  `KIND_NOT_ALLOWED`, and identifier provenance still applies.
- P0-7 (`sidecar.py`, `CausalRegistry.state_digest`): admissibility is
  re-evaluated first on every attempt. Repeats are tracked per
  (action fingerprint, refusal reason, registry state digest);
  `REPEAT_BLOCKED` is signalled once per such key (third identical
  refusal, with `transient`/`underlying_code`), later attempts under the
  same state carry the original reason, and any state/reason change or
  admission clears it. A `DEPENDENCIES_OPEN` refusal can no longer
  become a permanent block (was: 171 refusals / livelock).
- P0-8 (`struct_agent._execute_scripted_step`): transient `CAUSAL_REFUSAL`
  (incl. `REPEAT_BLOCKED` with a transient underlying code) is retried
  exactly like gate DEFERRED/BLOCKED — writes under
  `retry_blocked_max_s`, reads under `until` polling (without `until`,
  bounded by `max_s` or 180 s), and sends/analyzes await-style until
  admitted bounded by the step's `max_s` or a default of 180 s.
  Sidecar verdicts and `causal_check` now propagate
  `transient`/`underlying_code`/`observation_only`.
- P0-9 (`tests/legion_overlay/ztl_service.py`, `run_campaign_core.sh`):
  the ZTL swarm dir defaults to `$HOME/legion_pf/ztl-swarm` when
  `LEGION_ZTL_SWARM_DIR` is unset (the previous default pointed at a
  non-existent repos path),
  and the core checks the resolved path exists and refuses (exit 2)
  before creating/registering RUN_HEADER.
- P1-2 (`run_campaign_core.sh`): the mission host is run with
  `|| HOST_RC=$?`, so under `set -e` a failing host no longer aborts the
  core before cleanup and the key-material scan; the scan always runs,
  then the core exits with the host's code.
- P0-10 (`test_runtime_integration.py`): the 13-world scripted smoke now
  asserts real progress — fewer than 5 `REPEAT_BLOCKED` per agent, and
  every task the plan executed is CLOSED in a registry rebuilt from the
  run's WORLD_LOG/GATE_COMMITS (smoke read args now use real identifiers
  inferred from public returns templates/initial state, omitting
  renamed-away string params). Dedicated regression
  `test_scripted_exe_causal_regression_p0_6_7_8` runs the Claude
  round-2 reproduction sequence through the real host path (scripted,
  100 registered workers): clerk T1 read, alloc reads under their own
  WRITE tasks T2/T3/T4 then writes, ship T5 write issued while T2 is
  unconfirmed and retried until admitted, reporter T7 `until` polling
  then send. It asserts no read `KIND_NOT_ALLOWED`, no repeat storm,
  T1..T7 all CLOSED, native effects for every write task, and the T7
  message after the T4/T5/T6 effects.

## Test results (sandboxed meta_dev, no NIM)
- test_causal_registry.py: 13 passed (incl. 4 new P0-11/P0-12 regressions)
- test_b0_replays.py: 16 passed
- test_campaign_dryrun.py: 5 passed (incl. P0-9 missing-ZTL refusal)
- test_runtime_integration.py: EXE dry-run, core dry-run, S100,
  EXE scripted regression (P0-6/7/8), and the 13-world smoke — all passed
- `meta_dev.sh units`: see META_ACCEPTANCE_REPORT.md for the final result.

## Remaining
- `SHA256SUMS.txt` regenerated via `make_sums.py` semantics. Live B1/S100
  NIM campaigns are Claude's to run via run_campaign.ps1 (sandbox has no
  network/key).

## Notes
- No files under worlds/ modified; no hidden answers used; budgets
  unchanged (14 turns, 420s). Changes stay under tests/legion_struct/**,
  plus the P0-9 default in tests/legion_overlay/ztl_service.py.
