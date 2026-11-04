# WO-007 technical acceptance — round 1: **NO-GO** (returned to Meta)

Package: Meta E1+E2 in worktree `legion_meta_wt/s7`.
- E1: 27 turns, exploration only, no files written.
- E2: 64 turns, ~$6.3; Meta reported "43 passed".

Reviewed by Claude, who did not change Meta's code.

The new mechanisms exist as **library modules plus scripted replay tests**, but **none of them is wired into the
runtime that a campaign actually executes**. The final NIM campaign would therefore run the WO-006 runtime almost
unchanged. Evidence:

| ID | Defect (reproducible) | Evidence |
|---|---|---|
| P0-1 | `run_campaign.ps1` cannot run a campaign. It never starts the provider-logging proxy, never creates per-agent proxy tokens, never wires the key source, and never sets `CAUSAL_HOST_CMD`, so `run_campaign_core.sh` real mode exits at `: "${CAUSAL_HOST_CMD:?...}"`. | `grep provider_logger\|SCALE_PROXY run_campaign.ps1 run_campaign_core.sh` finds only comments |
| P0-2 | WP-A/WP-B are not enforced in the real mission path. `test_struct_mission.py`, `world_server.py`, `struct_controller.py` and `struct_plugin.py` are unchanged and do not reference `causal_007`; `causal_host.py` is a "reference" host that nothing imports except a test. The only live change is a local guard inside the agent process (`struct_agent._causal_refusal`), which covers kind, recipient and repeats only. It does not check cross-agent dependency confirmation, does not gate READ/WAIT/COMMUNICATE/ANALYZE on confirmed dependencies, and does not prevent exit with open obligations. Being inside the agent process, it is also not an independent controller. | `git diff --stat`: only `struct_agent.py` +49; grep shows no imports of causal_host / sidecar in the runtime |
| P0-3 | WP-E is not wired. `nim_transport.py` is used by no proxy, host or runner; a campaign would still use `scale_provider_logger.py`, which has no concurrency or 429 control. | grep: only test_b0_replays imports it |
| P0-4 | WP-F is not wired. `delegation.py` is loaded by no host, there is no delegate agent behaviour, and no S100 run path exists in the runner beyond a run id. | same grep |
| P0-5 | The required "full scripted 13-world smoke at 100 registered workers through the new controller" does not exist; the B0 replays run against the library objects, not the runtime. | test files: test_b0_replays.py, test_causal_registry.py, test_campaign_dryrun.py only |
| P1-1 | RUN_HEADER lacks `t_episode_registered_mono`, needed to prove registration precedes the first provider call (provider logs use CLOCK_MONOTONIC). PROGRESS.md is stale. | run_campaign_core.sh |

Acceptance criteria for round 2 are in `META_ENGINEERING_BRIEF_E3.md`.
