WO-LEGION100-CAUSAL-CLOSURE-007 — E6b (supersedes E6; you are Meta Muse Wonder 1.0, the engineering owner).

E6 was stopped by Claude on the owner's directive. Its partial edits in your worktree (struct_agent, struct_readback,
sidecar_server, provider_proxy, nim_transport, run_campaign_core, stub_model_server, test_runtime_hardening,
test_runtime_integration) are unfinished intermediate work. Reuse what fits and discard the rest; the target
architecture below is now mandatory.

ROOT CAUSE (owner): mission execution has no single authoritative owner of the attempt lifecycle and attempt identity.
In b1-GAIA-EXE (`causal_007/CLAUDE_INCIDENT_B1_EXE.md`, evidence in `<WINDOWS_USER_HOME>\legion_meta_wt\b1_exe_incident\`),
pytest-xdist plus `--timeout=120` killed the host worker and re-created the World 9× under the same run_id, resetting
state and appending to the same logs. xdist was only the trigger. The flaw is that a test framework controls the world
lifecycle. **`-n0` alone is NOT an acceptable fix.**

BUILD an authoritative execution SUPERVISOR. The campaign path must not run through pytest at all; pytest remains only a
test tool.

1. **Attempt Registry.** Before anything starts, atomically register (campaign_id, run_id, attempt_index=1) with an
   immutable `attempt_uid`, world_sha256, runtime_sha256 (hash of the runtime sources) and state REGISTERED (O_EXCL
   create plus fsync). Re-registering the same key is impossible.
2. **Single owner of the world.** The supervisor atomically moves the attempt REGISTERED → RUNNING and issues ONE
   single-use world-creation capability (a token bound to attempt_uid). The world server refuses to start without it
   and consumes it.
   - Nothing else — pytest, a worker, an agent, the core script — can create a second world instance.
   - Every world instance has a `world_instance_id`.
3. **Fail-closed recovery.** If the host or any critical component dies, the attempt goes RUNNING → INTERRUPTED and is
   final; its verdict path is INVALID.
   - Kill the whole process tree (process group or PID namespace) and close every effect path: the world refuses
     /actuate and the gate refuses commits for a terminal attempt.
   - Preserve all logs.
   - Automatic restart within the same attempt is forbidden. Normal end is RUNNING → COMPLETED. Terminal states are
     immutable.
4. **Evidence isolation.** Every world-log event, receipt, readback, controller/ZTL decision, gate commit and provider
   call carries attempt_uid, world_instance_id and a strictly monotonic sequence.
   - Writers reject events with a foreign identity, or any event after a terminal state.
   - Logs are append-only.
   - Keep all existing WO-006 fields so Claude's independent Judge adapter still parses the run directory unchanged.
5. **Provider isolation.** HTTP 429 is handled by a global queue plus backoff inside the live attempt. A transport
   error never creates a world, never resets causal state and never consumes an attempt.
   - Analyse the 168×429 storm in the incident evidence and report the effective request rate.
   - Make sure orphaned agents cannot exist.
6. **pytest stays a test tool only.** The campaign runner (`run_campaign_core.sh` / PS1) calls the supervisor directly,
   e.g. `python -I .../supervisor.py --campaign B1 --family GAIA-EXE ...`. Nothing in the campaign path may depend on
   pytest, xdist or pytest timeouts.

Acceptance invariants (Claude will try to falsify them independently on the real path):
- WorldStarts(attempt_uid) ≤ 1
- Terminal(attempt_uid) ⇒ no further mutations
- CommittedEffect ⇒ valid attempt_uid ∧ authorized world_instance_id
- HostCrash ⇒ INTERRUPTED/INVALID, never an automatic re-execution
- HTTP429 ⇒ inference retry only, no world state change

Your own falsification tests, through the REAL supervisor path, no network, stub model:
- A. Kill the host/supervisor at ≥121 s, then try to bring it back up automatically and manually. A second
  WORLD_START must be impossible and the attempt must be INTERRUPTED.
- B. Start two supervisors with the same run_id concurrently. Exactly one may run; the other must be refused before
  creating anything.
- C. After the attempt reaches a terminal state, replay a previously valid WRITE (same agent identity, same
  decision_ref) directly to the gate and to the world /actuate. Neither may produce an effect.
- D. Stub provider returns a 429 storm, then recovers. The same world continues: one WORLD_START, no state reset, causal
  registry intact, the mission completes.
- E. Every event and receipt in the run directory has an unambiguous (attempt_uid, world_instance_id, seq) and nothing
  is lost.

Also keep `meta_qual.sh` at 26/26 through the new supervisor path. `meta_qual` currently starts the host via
pytest+STRUCT_*; if you change the entry point, give the host a supervisor-backed path that qualification can use, and
document it in PROGRESS.md so Claude can update the qualification harness.

Keep `meta_dev.sh units` green (timeouts up to 40 min). Update PROGRESS.md, ROOT_CAUSE_REGISTRY.md, CAUSAL_STATE_SPEC.md
(add the attempt lifecycle state machine) and SHA256SUMS. Do not stop until A–E pass on the real supervisor path.
