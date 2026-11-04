# LEGION scale (10 / 100 agents)

Mechanism, files:

- `scale_target.py` — native target, separate OS process (stdlib only). `stage_by_shard` from the manifest
  `zero_state`; `POST /apply` (actuator bearer token only) applies iff `stage == current+1` else 409, idempotent
  per `command_id`; read-only `GET /state`, `GET /effects`.
- `dag_controller.py` — `DagMissionController`, single owner of obligation state (PENDING→CLAIMED(epoch)→CLOSED)
  plus ZTL evidence (`ZtlEvidenceService(lean=False)`, 5 independent observers each reading `/state` themselves).
  `close()` only from native-effect readback; non-live claims reconciled from readback. Event log `SCALE_EVENTS.jsonl`
  carries `t` and `mono` on every event.
- `scale_plugin.py` — CAGE contribution composed onto the active finance plugin via the public plugin contract
  (as `tests/legion_mini/sre_plugin.compose`): one governed action, norm binding, server-input resolver, tier and
  FTRA `REVERSIBLE` classification per obligation; one MCP tool `apply_transition(obligation_id, target_id, stage, …)`
  → seal → `verify_and_consume_seal` → `controller.begin` → actuator → `controller.close` → settle. Server-owned keys
  stripped by the kernel; readiness confidence 1.0 iff ZTL `ACCEPTED_TRUE` and directive `ACT`,
  provenance `server_bound_independent_readback`. Gateway commit log via `MINI_GATE_COMMITS` env path.
- `scale_agent.py` — one OS process per agent; model consulted only when `ACT_ELIGIBLE` and something changed;
  exits on `OWN_STEP_COMPLETE`; provider response id attached as `decision_ref`. Scripted decider is
  INTEGRATION_ONLY only and labelled `SCRIPTED_DECIDER_INTEGRATION_ONLY_NOT_A_MODEL_AGENT` in every log line.
- `test_scale_mission.py` — pytest host (World pattern of MINI-004): target process, deployment env derived from
  the manifest before `build()` (warrant context binding `required`, actor bindings, system id, SANDBOX,
  unverified-header-test-only transport, trusted identities), TEST-ONLY `_TestOnlyRoot` with one warrant per
  obligation, gateway on real TCP behind `WorkloadIdentityMiddleware`, read-only status server
  (`/obligations?agent=`), all agents spawned concurrently (`WORKERS.jsonl` PIDs), exports CAGE chain /
  GATE_COMMITS / VEIP reliance, independent readback before/after, Oracle as separate process.
- `scale_oracle.py` — separate-process oracle, all ordering by monotonic clock: final state, exactly one effect
  per obligation, exact gateway-commit/receipt/seal/ZTL/VEIP join per effect, exact model cause (MODEL_E2E),
  decision_ref uniqueness, dependency-closed-before-claim/effect (mono), manifest actor per effect, distinct
  worker PIDs, zero unauthorized/blocked-mutating effects, zero false completions.
  Verdicts: `LEGION_SCALE_E2E_PASSED` / `INTEGRATION_ONLY_SCALE_VERIFIED` / `NO_GO` / `NOT_VERIFIED`.
- `test_scale_units.py` (DAG controller, target 409/idempotency, oracle mutation rejection),
  `test_scale_negatives.py` (live probes on the 10-agent manifest: wrong actor, early dependency, repeated action,
  warrant scoped to another actor / wrong authority / PRODUCTION warrant, dropped receipt, forged decision_ref,
  partial world, false DONE).

## Run

```bash
SCALE_MANIFEST=tests/legion_scale/manifests/LEGION-10-CANARY-005.json SCALE_OUT=/tmp/scale \
SCALE_RUN_ID=canary1 SCALE_MODE=INTEGRATION_ONLY SCALE_DECIDER=scripted \
uv run pytest tests/legion_scale/test_scale_mission.py::test_scale_mission -v

uv run pytest tests/legion_scale/test_scale_units.py -v
uv run pytest tests/legion_scale/test_scale_negatives.py -v
```

MODEL_E2E: `SCALE_MODE=MODEL_E2E SCALE_DECIDER=nim SCALE_PROXY_URL=… SCALE_MODEL=…` plus per-agent
`SCALE_PROXY_TOKEN_<AGENT>` (provider-logging proxy from `tests/legion_mini/provider_logger.py`, not included here).

## Known limitations (TEST posture)

HMAC routing seals under the shared default test salt (verified with CAGE's auditor under
`CAGE_ENV=test, CAGE_SEAL_STRICT_MODE=false`; labelled in the oracle, not independent cryptography);
`l5d-client-id` asserted by agent processes (no Linkerd/mTLS); TEST-ONLY VEIP root/manifest/warrants
(signatures verified); ZTL Python rule (`lean=False`, no Lean `zverdict`); readiness is a server-bound
1.0/0.0 signal, not a calibrated probability. This patch is UNVERIFIED until the baseline and falsification
suite are run by a different agent.
