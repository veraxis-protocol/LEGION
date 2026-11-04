# WO-007 technical acceptance — round 2: **NO-GO** (returned to Meta, brief E4)
- Round-1 P0-1..P0-5 are now wired. Claude re-ran Meta's suite: 48/48 passed. Diff scope is clean, worlds and gate
  are unchanged, and the key is read only by the proxy.
- Claude's independent hidden qualification through the real host path (`qualification/qual-r2-gold-SYN-GAIA-EXE-n100`):
  the gold plan that qualified on WO-006 now FAILS (GOAL_NOT_MET; shipments and report missing). Causes:
  - P0-6: KIND_NOT_ALLOWED for reads with a task's own read_tools;
  - P0-7: REPEAT_BLOCKED is not state-aware (171 refusals; livelock);
  - P0-8: the scripted decider does not retry transient causal refusals.
- P0-9: the runner does not pass LEGION_ZTL_SWARM_DIR (wrong default path), so a real campaign would fail at the ZTL
  import.
- P1-2: under set -e, the key scan is skipped when the host fails.
- P0-10: Meta's smoke test asserted completion of processes, not progress of obligations.
