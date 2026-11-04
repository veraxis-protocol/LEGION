# INCIDENT — B1 first attempt `b1-GAIA-EXE`: world restarted 9×, evidence integrity broken → **NO-GO / INVALID_TEST**

Evidence is preserved untouched: `runs/b1-GAIA-EXE/` (116 files) and `logs/campaign_B1_GAIA-EXE.log`, with hashes at stop in
`HISTORY/b1_exe_incident/RUN_DIR_SHA256_AT_STOP.txt`. Nothing was rewritten.

## Causal chain
1. **Origin.** The CAGE repository's `pytest.ini` has `addopts = -n auto --dist loadscope --timeout=120 --timeout-method=thread`.
   Meta's campaign core (`run_campaign_core.sh`, frozen `e0b49d3b`) runs the mission host as
   `python -m pytest tests/legion_struct/test_struct_mission.py::test_struct_mission -q -p no:cacheprovider --no-cov`,
   with **no `-n0` and no timeout override**. The host therefore runs inside a pytest-xdist worker under a 120 s
   per-test timeout. Every Claude qualification run passed `-n0 --timeout=650`. Meta's dry-run finished in under
   120 s with the stub model, so it never hit the limit.
2. **First violation.** At t_mono 255910.5 the first world started (pid 824918). The agents worked normally: 6
   observations and 3 native effects, T4 backorder, T2 and T3 reservations, each with a receipt. The causal controller
   behaved as designed. At ~120 s, pytest-timeout killed the xdist worker (`[gw2] node down: Not properly terminated`).
3. **Restart mechanism.** xdist replaced the crashed worker and re-dispatched the host test. Each re-execution
   minted a new World (fresh world-server process, **state reset to the initial state**, `seq` back to 1) and
   restarted all 7 agents, **appending to the same run directory**. This repeated every ~124 s (120 s timeout plus
   start-up): 9 WORLD_STARTs, pids 824918…867381, and 9 STARTs in every agent log. Claude stopped it at the ninth
   incarnation.
4. **Actual consequences.**
   - Incarnations 1–8 produced no world actions: only WORLD_START.
   - Across the run, provider_log shows 183 calls: 14 HTTP 200, **168 HTTP 429**, 1 HTTP 502. The NIM rate limit was
     exhausted, plausibly by repeated agent restarts and orphaned agents. No duplicate effects exist, since all 3
     effects belong to incarnation 0.
   - The last world's state was reset, so the final native state no longer reflects the effects that were recorded.
     One run directory mixes 9 world histories, and RUN_HEADER lacks `t_agents_end`.
5. **Decision for EXE.**
   - **NO-GO**: state reset, several world histories under one attempt identity, and no single consistent causal
     history.
   - The EXE first attempt is spent. It is recorded as **INVALID_TEST and counted as non-pass** under the preregistered
     `invalid_policy: count_as_nonpass`, so it stays in the B1 denominator.
   - **No rerun** of EXE.
6. **Scope.** The defect is in the shared campaign core invocation, so every NIM mission longer than 120 s would hit
   it (all of them, given the 420 s budget). The campaign was **halted by Claude before any other mission started**:
   only `runs/b1-GAIA-EXE` exists. The other 12 B1 missions and S100 have not been attempted, and their first attempts
   are intact.

Positive evidence preserved: before the restarts, the causal controller admitted 10 actions, refused 13, and blocked 9
premature reporter EXITs.

Next: the runtime defect goes back to Meta (`META_ENGINEERING_BRIEF_E6.md`). After the fix, Claude re-runs technical
acceptance and amends the preregistration for the 12 unattempted B1 missions and S100. EXE stays INVALID (non-pass);
nothing is relabelled.
