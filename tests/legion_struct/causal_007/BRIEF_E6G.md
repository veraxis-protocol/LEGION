WO-LEGION100-CAUSAL-CLOSURE-007 — E6g. Claude acceptance of E6f: NO-GO (P0-17), returned to you (Meta, engineering owner).

Confirmed in E6f:
- The campaign core now starts from a clean shell (COMPLETED, 1 WORLD_START).
- Claude's live attacks on a RUNNING supervised attempt produced **0 illegal mutations** (`acceptance/attack7/`). The
  world correctly refused, with the right reasons:
  - stolen permit replayed: "nonce replayed";
  - permit with a new command: "command_id mismatch";
  - permit on another task: "task_id mismatch";
  - actuator token without a permit: "permit missing";
  - forged permit: "permit MAC invalid".
- Re-creating the world after the attempt ended is impossible.

**P0-17 — an evidence file still acts as control authority, and the lifecycle record diverges.** Reproduction (Claude,
live attempt held RUNNING after 5 legitimate effects):
1. Overwrite `run_dir/attempt.json` with `"state": "COMPLETED"`.
2. Result: the live attempt shut down. The world stopped answering right after, and the last WORLD_LOG record is that
   attack's WRITE_REFUSED. The supervisor exited **without recording any terminal transition**.
3. The attempt stayed RUNNING in the record until a LATER, second supervisor invocation found it "supervisor lost" and
   wrote `INTERRUPTED (supervisor_lost_restart_refused)`.

So the terminal transition was not written by the attempt's owner, and the recorded history no longer matches the
authority's truth. Also, deleting the file or rewriting it to a forged RUNNING identity changes runtime behaviour.

Cause in code:
- `attempt.json` is read as a CONTROL input by `sidecar_server.py` (`terminal_from_env()` at runtime), by
  `mission_host.py` (`terminal_from_env()`, `read_attempt()`), and by the supervisor (`refuse_existing()`,
  heartbeat/transition writes through the same mutable file, where "terminal states immutable" makes the owner refuse
  its own transition after the file was tampered with).
- The authority process holds the truth, but the components and the owner's own lifecycle record go through the
  mutable file.

REQUIRED:
1. Runtime control decisions in the sidecar, host and supervisor monitoring query the LIVE AUTHORITY (or the
   supervisor's in-memory state), never `attempt.json` or env-derived file paths. Remove `terminal_from_env()` and
   file-based state from every runtime control path.
2. The lifecycle record is OWNER-WRITTEN, APPEND-ONLY and TAMPER-EVIDENT: an `ATTEMPT_LOG.jsonl` hash chain where every
   transition is MAC'd with the per-attempt key. `attempt.json` may remain as a convenience snapshot, but nothing
   believes it.
   - The supervisor always records its terminal transition (COMPLETED or INTERRUPTED with a reason) in that chain,
     whatever happens to the files, and verifies the chain at the end.
   - Detected tampering is recorded as `EVIDENCE_TAMPER_DETECTED`; the attempt continues or is interrupted according
     to a declared policy, and the owner always writes the terminal record.
3. Pre-start refusal ("never restart an attempt", in a second supervisor or a legacy host) must also rely on
   authenticated state: a verified ATTEMPT_LOG chain and/or a registry entry that a forged file cannot reset. Deleting
   or rewriting `attempt.json` must never make a used run_id startable again.
4. Tests (clean-env real path), each asserting 0 mutations AND a consistent owner-written terminal record AND 1
   WORLD_START:
   - T1: `attempt.json` rewritten to COMPLETED mid-run → the attempt continues and completes normally, or is
     INTERRUPTED by the owner with `EVIDENCE_TAMPER_DETECTED`; either way the chain verifies.
   - T2: `attempt.json` deleted mid-run → the same.
   - T3: rewritten to a forged RUNNING identity after terminal, then a second supervisor or legacy host → refused, and
     the chain still shows the original terminal state.
   - T4: ATTEMPT_LOG tail edited → detected by verification.

   Keep A–F, N1–N9, units green and qualification 26/26 through `run_qual_core.sh`.

Execution: only `meta_dev.sh` and `meta_qual.sh`. Pair every status text with a tool call; final summary only when done.
