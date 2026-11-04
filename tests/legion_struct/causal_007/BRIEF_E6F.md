WO-LEGION100-CAUSAL-CLOSURE-007 — E6f. Claude acceptance of E6e: NO-GO (P0), returned to you (Meta, engineering owner).

What passed review: the E6e authority design is right in principle.
- live authority state;
- MAC'd permits bound to attempt_uid, world_instance_id, epoch, task, command and expiry;
- deny-by-default in the gate HARD tier and in world /actuate, with nonce replay protection;
- the key is given only to the world, never to agents;
- fail-closed INTERRUPTED with no restart, which Claude observed.

**P0-16 — the real campaign path does not run.** Reproduction (Claude, clean shell, frozen candidate):
```
cd ~/legion_pf/cage_s7
bash tests/legion_struct/causal_007/run_campaign_core.sh --campaign B1 --family GAIA-EXE --runs-root /tmp/x --dry-run
→ core rc=1 "supervisor failed: 1"; attempt.json INTERRUPTED (host_died_no_restart) after ~13 s; 1 WORLD_START, no agents
→ mission_host.log: MISSION_HOST_FAILED: ConfigurationError: CAGE_TELEMETRY_PROVIDER must be set under an enforcing posture
```
Root cause:
- Every earlier run (B0/WO-006, qualification and your own tests) executed under pytest, and `tests/conftest.py`
  establishes the CAGE TEST posture (`CAGE_ENV=test`, OTel exporter none, HMAC seal fallback and so on).
- Your pytest-free host dropped that posture implicitly, so it starts under an enforcing posture and dies.
- Your 81 tests and 26/26 still pass because they launch the supervisor and host from inside pytest, which inherits
  conftest's environment. The campaign never runs inside pytest.

REQUIRED:
1. The supervisor must establish the campaign's CAGE posture EXPLICITLY and deterministically. It must be the same
   declared TEST posture that B0/WO-006 and qualification used: replicate exactly what `tests/conftest.py` sets that
   the gate depends on.
   - Record the full posture (variable names and values, no secrets) in RUN_HEADER and attempt.json.
   - Do not inherit it from the caller's environment.
   - Do not weaken anything: the posture must equal B0's, so B1 is comparable.
   - If something must differ, say what and why in CAUSAL_STATE_SPEC.md.
2. Add a test that runs `run_campaign_core.sh --dry-run` from a CLEAN environment (`env -i HOME=… PATH=…`, outside pytest's
   env, e.g. via subprocess with an explicit minimal env). Assert that the attempt reaches COMPLETED, the stub-model
   mission produces world actions, there is exactly 1 WORLD_START, and the evidence is complete.
3. Make `meta_qual.sh` exercise the SAME path the campaign uses. Today qualification runs through the pytest wrapper;
   add a supervisor-based qualification entry (scripted decider, hidden plan path via STRUCT_PLAN) and use it.
   Claude's harness will switch to it. Keep 26/26.
4. Re-run A–F and N1–N9 so that at least A, B, F and N3/N7 use the clean-env campaign path, not a pytest-inherited
   environment.

Execution: only `meta_dev.sh` and `meta_qual.sh` (timeout up to 2400000). Pair every status text with a tool call; your session
ends on a text-only message. Final summary only when 1–4 are done and green.
