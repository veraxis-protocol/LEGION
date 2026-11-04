# E6c ADDENDUM (owner/architect, via Claude) — mandatory acceptance test F: SUPERVISOR BYPASS

The Attempt Registry must NOT be the only protection. CAGE/VEIP must independently reject a WRITE whose attempt
identity is foreign or terminal, even when the request reaches the gate directly and bypasses the supervisor.

Required behaviour, enforced in the governed write path (gate tier, server-bound inputs and VEIP warrant scope), never
only in the supervisor:
- A world_write carrying an attempt_uid other than the RUNNING attempt's is BLOCKED by the gate; no seal, no effect.
- A world_write after the attempt is terminal (COMPLETED or INTERRUPTED) is BLOCKED by the gate and refused by the
  world /actuate, even with a previously valid decision_ref, workload identity and command.
- An old token or capability (world-creation capability, actuator token, warrant, seal or command id) from a previous
  or terminal attempt yields no effect. The world-creation capability is single-use, and warrants or authorizations
  are bound to the attempt (attempt_uid in the warrant scope or in the server-bound inputs checked by a HARD tier).
- ZTL/CAGE/VEIP checks may only become STRICTER. Every existing HARD rejection must still hold. Any weakening is NO-GO.

Test F (real path, no network): with a stub model, run a mission to a terminal state. Then, bypassing the supervisor,
call the gate's MCP world_write directly with:
- (a) the old attempt_uid;
- (b) a forged or foreign attempt_uid;
- (c) a replayed decision_ref, seal or command;
- (d) a reused world-creation capability, which must fail to start a world.

Assert: zero new NATIVE_EFFECT/RECEIPT, gate outcome BLOCKED with an attempt-identity reason, and the world log
unchanged.

## F — full-path verification (owner addendum 2)
An HTTP 403 or BLOCKED string alone proves nothing. For every bypass attempt (a)–(d), test F must verify the WHOLE path
WRITE → admission → commit → world state → receipt:
- admission: the gate record shows no routing seal issued and no command_id, or an explicit attempt-identity refusal;
- commit: no EXECUTED gate commit and no actuation dispatched (no CAGE ACTUATION_RECEIPT in the evidence chain);
- world state: a reader-token GET /state digest taken before and after each attempt is IDENTICAL, and the effect
  ledger (/effects) is unchanged;
- receipt: no new NATIVE_EFFECT or RECEIPT in WORLD_LOG, and no new READBACK_EFFECT;
- evidence preserved: all logs append-only and identical except the refusal records, with every refusal carrying the
  attempt identity it rejected.

GO = refusal AND unchanged world state AND 0 effects AND evidence preserved. Any discrepancy = NO-GO.
