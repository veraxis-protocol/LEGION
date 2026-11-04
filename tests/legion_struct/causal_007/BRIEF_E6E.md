WO-LEGION100-CAUSAL-CLOSURE-007 — E6e. ARCHITECTURAL NO-GO of E6c/E6d, returned to you (Meta Muse Wonder 1.0, engineering
owner). Your E6d session was stopped because the design is wrong by construction; more tests on it would not help.

ROOT DEFECT (owner/architect; confirmed by Claude's code review):
- Execution authority depends on a MUTABLE LOCAL JSON (`attempt.json`, `STRUCT_ATTEMPT_FILE`/`STRUCT_ATTEMPT_UID` env).
- ABSENCE OF PROOF IS TREATED AS PERMISSION.

Concretely:
- `struct_plugin._attempt_refusal()` returns None (admit) when there is no attempt context.
- When the file is deleted or unreadable it falls back to env with state None, so the terminal check is skipped.
- The HARD tier checks only `if bound_uid or bound_state`.
- `world_server._attempt_terminal()` returns False when ATTEMPT_FILE is unset.
- attempt.json has no authentication and no epoch, and rewriting `state` to RUNNING is believed.
- VEIP warrants are not bound to the attempt.
- The legacy pytest host can still create a world without any registered attempt.

A cosmetic fix of these `if`s is NOT acceptable. Required architecture:

1. **ONE authoritative source of attempt state.**
   - The supervisor owns an attempt-authority service for the attempt's lifetime (for example a loopback HTTP or Unix
     socket endpoint owned by the supervisor process). It holds attempt_uid, world_instance_id, a monotonically
     increasing `epoch` (bumped on every lifecycle transition) and the state.
   - The authority's secret material never touches the run directory or the environment of agents. It is generated per
     attempt in supervisor memory and handed only to the gate and the world via an inherited channel at spawn.
   - Files in the run directory are evidence, never authority.
2. **AUTHENTICATED write authorization.** Every consequential write needs a fresh permit issued by the authority and
   bound to: attempt_uid, world_instance_id, epoch, task_id, command or nonce, and a short expiry. The permit is MAC'd or
   signed with the per-attempt key.
   - The authority issues permits ONLY while state == RUNNING.
   - The moment the attempt leaves RUNNING, epoch++ and permit issuance stops; on terminal states the key is destroyed.
3. **INDEPENDENT verification at the commit boundary, twice.**
   - (a) The CAGE gate HARD tier verifies the permit's authenticity, freshness, epoch == current and identity match
     against the authority before any seal is issued. VEIP authorization is scoped to the attempt (attempt_uid and
     world_instance_id in the warrant/authority scope issued for that attempt).
   - (b) The world server's /actuate independently verifies the same permit (or its own permit from the authority)
     before applying any effect, and records a nonce so it cannot be replayed.
4. **DENY by default.** Missing, substituted, expired, stale-epoch, wrong world_instance_id, replayed or unverifiable
   permits ⇒ DENY. An unreachable authority ⇒ DENY. No fallbacks: no env, no file and no "legacy" admit path. Unit tests
   that need a gate must construct an explicit TEST authority; there is no admit-without-authority mode in campaign or
   qualification code.
5. **No world without authority.** The legacy pytest host (`test_struct_mission.py`) and mission_host must refuse to
   create a world unless they hold a valid single-use world capability from a live authority. A capability for a
   terminal or foreign attempt, or one already used, ⇒ refuse.
6. **Evidence.** Every gate commit and every world effect records the permit id, epoch and verification result.
   Refusals record the rejected identity and the reason.

Mandatory negative tests (real path, no network). Each must show ZERO actual mutations: no seal, no EXECUTED, no
ACTUATION_RECEIPT, reader `/state` digest identical, `/effects` unchanged, no NATIVE_EFFECT/RECEIPT/READBACK.
- N1. attempt.json deleted during RUNNING, then a write → DENY.
- N2. attempt.json rewritten to RUNNING after terminal, then a write → DENY.
- N3. authority process killed or unreachable, then a write → DENY.
- N4. a stale permit (old epoch) or an expired permit → DENY.
- N5. a permit for another world_instance_id or attempt_uid → DENY.
- N6. replay of a previously valid permit or nonce → DENY at the world even if the gate were bypassed.
- N7. direct world /actuate with a valid actuator token but no valid permit → DENY.
- N8. legacy pytest host or mission_host started on an existing or terminal run dir without a live capability → no
  world.
- N9. no attempt context at all (env unset, no file) → DENY, not admit.

Positive tests: legitimate executions still work. A–F pass, `meta_dev.sh units` green, and `meta_qual.sh` 26/26 for
all 13 families. Keep the evidence formats WO-006-compatible. ZTL/CAGE/VEIP may only become stricter.

Documents: CAUSAL_STATE_SPEC.md (attempt authority, permit format, epoch rules, deny matrix), PROGRESS.md,
ROOT_CAUSE_REGISTRY.md and SHA256SUMS.

Execution: use only `meta_dev.sh` and `meta_qual.sh` (Bash timeout up to 2400000). In this non-interactive mode your session
ENDS whenever you write a message without a tool call, so always pair status text with the next tool call. Write the final
summary only when everything above is done.
