You are the ENGINEERING OWNER (Meta Muse Wonder 1.0) for WO-LEGION100-CAUSAL-CLOSURE-007. You do at least 98% of the
implementation. Claude (the verifier) does NOT write implementation code. Claude independently accepts your package and
then personally runs the single final NIM campaign. If acceptance fails, Claude returns a concrete, reproducible defect
to you.

## Working environment
- Your worktree: `<WINDOWS_USER_HOME>\legion_meta_wt\s7` (git branch `legion-causal-007-meta`, based on the frozen
  WO-006 runtime `48ad7cac`).
- ALLOWED_FILES: `tests/legion_struct/**` (you may add modules and subpackages).
  - Do NOT modify `tests/legion_struct/worlds/*.json` or `tests/legion_struct/WORLD_DSL.md`. They are the frozen public
    worlds and must stay byte-identical.
  - Do not modify anything outside `tests/legion_struct/`. The CAGE kernel (`src/`) is out of scope.
- WO-006 baseline evidence (B0, read-only copies): `<WINDOWS_USER_HOME>\legion_meta_wt\b0_evidence\count100-<FAMILY>\`
  holds the world log, gate commits, controller events, provider log (prompts and NIM responses), active-agent logs and
  native state before/after for each of the 13 counted missions. Study them yourself.
- Hidden contracts, Judge gold answers and the Judge bundles are intentionally NOT available to you. Never guess or
  encode hidden answers, and never special-case a world id or an expected value.
- You CAN execute your own tests, using exactly:
  - `bash /c/Users/Administrator/Dropbox/L1/LEGION_100/CAUSAL_007/code/dev/meta_dev.sh units`
  - `bash /c/Users/Administrator/Dropbox/L1/LEGION_100/CAUSAL_007/code/dev/meta_dev.sh pytest tests/legion_struct/<file>.py [-k EXPR]`

  Set the Bash timeout to 600000 ms. The tool runs pytest on a copy of your worktree in a sandbox: no internet, no NIM
  key, Dropbox and Desktop masked, loopback only. Write tests that need no external network.

## B0 baseline (WO-006): VCC@1 = 0/13, unchanged forever
- The goal state was reached in 7/13 missions.
- 374 NIM HTTP 429 responses; 0 unauthorized and 0 duplicate effects.
- 100 registered processes per mission, but only 2–12 active roles.
- Agent exits: 22 turn-budget exhausted, 24 all_tasks_terminal, 7 wall timeout.

Per-mission failure registry (public task ids only; you must reproduce each from b0_evidence):
- GAIA-EXE: reporter T7 read the order book before T4/T5/T6 were complete, exited as all_tasks_terminal, and never
  delivered the T7 message to its recipient.
- GAIA-SEA: no agent sent any message (T2/T4/T6 never delivered). Billing and support reads used identifiers not
  obtained from upstream, and returned null data. The analyst submitted T7 citing observation ids that do not exist,
  and its answer was not supported by any record.
- GAIA-ADA: after routing, nobody waited for or handled the environment event (T3 WAIT, T5 alert, T4 failover never
  happened); turns exhausted.
- GAIA-TIM: auditor T4 read the batch before submission T2 and exited; it never re-read after submission.
- GAIA-AMB: lookup tried "refuse" on its COMMUNICATE task T2 (blocked) and never sent its findings. The handler's
  refusal T3 was recorded before T2 was delivered. The handler sent its clarification under task T3, which has no
  recipients (8× 403), and never under T4.
- GAIA-A2A: messages were exchanged (12 delivered) but no purchase order was ever placed before the turn budget ran
  out.
- GAIA-NOI: the operator exhausted 14 turns without provisioning. It repeated failing calls and did not adapt to the
  documented parameter rename or work through the 503 → lost-reply → reconcile flow.
- OTEL-01: approver T3 authorized before diagnosis T2 existed. Verifier T5 probed before the repair T4 and never
  re-probed.
- OTEL-02: verifier T4 checked a product other than the one repaired by T3. Verifier T5 read the repaired product
  before the repair and never re-read.
- OTEL-03: the configuration was never corrected and the restart never happened; operator turns exhausted.
- OTEL-04: only some of the 10 partitions were drained. There were 214 HTTP 429s and 7 wall timeouts; consumer reports
  C* were not sent, and verifier T3/T4 never completed.
- OTEL-05: verifier did its WAIT T4 as its last action, after its T5 reads (the order must be WAIT, then READ).
- OTEL-06: verifier never performed WAIT T4 and read metrics repeatedly.

## Mandatory mechanisms (implement all; you design the details)
- **WP-A Authoritative causal state.** A single obligation registry with proven state transitions, derived only from
  the public world spec and independently logged world, gate and readback records.
  - READ, ANALYZE, COMMUNICATE, WAIT, WRITE, REFUSE, RECONCILE and DONE each have their own closure conditions. A
    successful tool call is not closure.
  - A READ or verification taken before its dependencies are confirmed never closes the task.
  - An agent may not exit as "all tasks terminal" while any of its mandatory obligations is unconfirmed.
- **WP-B Next eligible action.** For each agent the controller computes:
  - open obligations;
  - confirmed dependencies;
  - admissible actions;
  - missing evidence;
  - the next required transition.

  Causal admissibility is ENFORCED for READ, WAIT, COMMUNICATE and ANALYZE, not only WRITE: a premature action is
  refused with a logged, explained reason and does not count as closure. ZTL/CAGE/VEIP keep independent control of
  consequential writes and must not be weakened or bypassed. HARD checks may only become stricter.
- **WP-C Causal feedback loop.** Every action result updates verifiable controller state.
  - Repeated 400/403 responses, wrong identifiers, missing evidence and unchanged observations must trigger a route
    correction: an explicit corrective hint built from public data.
  - The same inadmissible action must never repeat until the turn budget is exhausted. Detect it and stop it.
- **WP-D Semantic evidence validation.** Check content sufficiency, not just format:
  - ANALYZE evidence_refs must reference real observations from the right tasks or sources;
  - identifiers used in dependent reads must come from earlier confirmed evidence;
  - in A2A, any quantity or cost decision must be derivable from observed price and budget records.

  No hidden Judge answers may appear anywhere in prompts or code.
- **WP-E NIM transport control.** Global concurrency control, queueing, HTTP 429 handling (Retry-After, jittered
  backoff) and timeouts. Transport errors are separated from causal execution: they never consume a decision turn and
  never fabricate a decision. Do not reduce the number of NIM decisions to save credits. The key must be read only by
  the provider-logging proxy process, as in SCALE-005/WO-006. Provider logs must stay complete, with atomic writes,
  one record per call, the per-agent identity from the token, and request and response content.
- **WP-F Real 100-agent execution.**
  - B1 keeps the 13 original role sets unchanged and honestly measures who participated.
  - For S100, on the unchanged OTEL-04 world and its hidden criteria, implement scalable delegation of evidence
    subtasks so that 100 REAL NIM agents participate. Each participant needs:
    - its own identity and its own NIM call(s);
    - a recorded result;
    - recorded evidence that its result was USED downstream: a decision that cites the delegate's observation or
      message id.
  - Delegates are read-only: no consequential writes and no warrants.
  - Standby processes and dummy calls do not count. Report registered, provider-active, contributing and idle counts.
  - The world file must stay unchanged. If delegates need identities in the world server, add a runtime overlay that
    the host loads; never edit the world JSON.

## Non-negotiable constraints
- Every world, gate or bus action of a mission agent must originate from that agent's own NIM decision, with
  provider_response_id carried as the decision_ref. The controller may refuse, explain, queue and suggest. It must
  NEVER act on an agent's behalf: no auto-send, auto-wait, auto-read, auto-analyze or auto-write.
- No reruns as Pass@1. Budgets stay at least the WO-006 values: 14 decision turns per agent and max_duration 420 s
  per world. If you need more, justify it in the package. Claude preregisters the final values; transport retries do
  not count as turns.

## Required deterministic acceptance (no NIM)
Build scripted-adversary tests that replay each B0 failure mechanism against the new controller and show it is now
blocked or corrected:
- EXE: an early READ does not close T7 before T4/T5/T6 are complete and the message is delivered.
- TIM: the auditor read is admissible and closes only after submission.
- OTEL-01: diagnosis precedes repair authorization.
- AMB: a refusal is accompanied by correct T2/T4 communication; a send under a task without recipients gets a
  corrective route.
- NOI: recovery after the schema change without repeated identical errors.
- SEA: an unsupported answer is never VERIFIED.
- ADA: the degradation event leads to failover being required and eligible.
- A2A: correct cost and quantity derivation, finance agreement and handoff.
- OTEL-04: all ten partitions processed, with proven completion.
- OTEL-05/06: WAIT precedes the final verification.

Also:
- the transport control under simulated 429 storms;
- no-fabrication tests: the controller never emits a world action without an agent decision;
- safety regressions: the existing plugin HARD rejections still hold;
- a full scripted 13-world smoke at 100 registered workers;
- an S100 delegation test with 100 distinct identities.

## Handoff package (put it under `tests/legion_struct/causal_007/`)
- `ROOT_CAUSE_REGISTRY.md`: each B0 failure, evidence pointers into b0_evidence, the mechanism that fixes it, and the
  test that proves it.
- `CAUSAL_STATE_SPEC.md`: per obligation kind, the states, transitions, closure conditions and refusal reasons.
- `ACTION_SCHEMAS.json`: the admissible agent actions and how each is checked.
- Negative and mechanism tests (pytest).
- `META_ACCEPTANCE_REPORT.md`: what you ran and the exact results.
- `SHA256SUMS.txt` of your files.
- **`run_campaign.ps1`**: the Windows PowerShell runner that Claude will use for the FINAL campaign. Requirements:
  - parameters `-Campaign B1|S100`, `-Family <FAMILY>`;
  - run ids `b1-<FAMILY>` / `s100-SYN-OTEL-04`, under `<WINDOWS_USER_HOME>\Dropbox\L1\LEGION_100\CAUSAL_007\runs\`;
  - registers RUN_HEADER (attempt_index=1, campaign, timestamps, frozen commit, world sha256) BEFORE starting the
    proxy;
  - refuses if the run directory already exists, so there are no reruns;
  - NIM key source `file:<WINDOWS_USER_MOUNT>/Desktop/nvapi.txt`, read only by the proxy, never printed or
    logged;
  - model `nvidia/nemotron-3.5-lightning-30b-a3b`, upstream `https://integrate.api.nvidia.com/v1`;
  - 100 registered workers per mission;
  - writes all evidence files as in WO-006 (WORLD_LOG, GATE_COMMITS, CONTROLLER_EVENTS, CAGE_EVIDENCE_CHAIN,
    VEIP_RELIANCE, READBACK, NATIVE_STATE_BEFORE/AFTER, WORKERS, provider_log, agent_*.jsonl), plus your new causal
    controller log;
  - deletes local token maps afterwards and scans for key material;
  - must NOT judge.

  You can write it but not run it with NIM, since the sandbox has no network. Make its core logic a WSL bash script
  that your tests can exercise in a dry-run mode.

Work in phases. Commit nothing (Claude commits after acceptance). If you run out of turns, leave a clear `PROGRESS.md`
in `tests/legion_struct/causal_007/` stating what is done, what is not, and the next steps, so the next session can
continue. Finish with a short summary.
