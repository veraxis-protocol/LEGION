# LEGION-100

**Verified multi-agent execution infrastructure for consequential tasks**

> Intelligence is abundant. Control over consequence is scarce.

**Release status:** publicly published functional development snapshot (WO057). Licensing policy is confirmed; file-level provenance review and public clean-room reproduction remain open. LEGION-100 is a source-available Veraxis research implementation. The repository documents 100 registered agents operating across 13 bounded, executable state-machine worlds. Seven world structures were developed from GAIA2 scenario categories and six from OpenTelemetry Astronomy Shop operational patterns. This is not a claim that any synthetic world reproduces all conditions of a production enterprise system.

LEGION's central question is not whether 100 agents can exchange messages. It is whether a collective can satisfy **causal obligations**, admit consequential actions under verifiable authority, produce actual state changes, preserve receipts and readbacks, and earn completion from an **independent Judge**.

## Technical scope

The core execution boundary is:

`mission → executable world → 100 registered agents / assigned active roles → causal controller → ZTL evidence/admissibility → CAGE and VEIP governance → native world tools → consequential state effects → receipts + independent readbacks → independent Judge`.

The agents *propose* actions. The control and governance layers determine whether actions may be executed. The world adapter enacts eligible operations and produces evidence. The Judge decides whether the resulting collective mission satisfied all specified obligations. The consequential-action boundary and upstream CAGE attribution are described below.

```mermaid
flowchart LR
  W[Mission + world state machine] --> A[100 registered agents]
  A --> C[Causal controller + obligation DAG]
  C --> Z[ZTL eligibility]
  Z --> G[CAGE governance / VEIP warrants]
  G -->|allowed| T[Native world tools]
  G -->|refused or deferred| L[Refusal and causal log]
  T --> E[Effects + receipts]
  E --> B[Independent readbacks]
  B --> J[Independent Judge]
  J --> V[VCC@1]
```

### Why 100 does not mean 100 NIM calls

Each world registers 100 workers. Role assignment determines which workers actually pursue obligations. The public index shows between **2 and 12 actively assigned roles per world**. The system must report active agent contributions separately from registration counts; worker registration, model calls, coordination events and native effects are distinct measurements.

## Where LEGION lives

The repository root retains the inherited Google CAGE project layout. The LEGION-specific research implementation is concentrated in:

- [`worlds/`](worlds/) — published world assets.
- [`tests/legion_struct/`](tests/legion_struct/) — causal runtime, structural worlds, controller, adapters and tests.
- [`tests/legion_scale/`](tests/legion_scale/) — coordination and scaling experiments.
- [`tests/legion_mini/`](tests/legion_mini/) — reduced execution tests.
- [`tests/legion_overlay/`](tests/legion_overlay/) — integration and governance overlays.
- [`judge/`](judge/) — independent Judge, the runnable `judge/judge.sh` wrapper and the `judge/components/run_judge.py` Python entry point.

The root CAGE `docker-compose.yml` and deployment scripts are **not** a stand-alone LEGION-100 mission launcher.

## Thirteen executable worlds

Names below describe *engineering analogues*, not claims of integration into named enterprise products. The `SYN-` identifiers signal structurally inspired, controlled synthetic environments.

| World | Engineering mission | Active roles | Essential constraint / independent Judge condition |
|---|---|---:|---|
| `SYN-GAIA-EXE` | Order Fulfillment Assurance | 7 | Reserve/decrement inventory before permitted shipments; preserve stock; handle backorder correctly |
| `SYN-GAIA-SEA` | Customer Case Intelligence | 4 | Join CRM/billing/support evidence; disambiguate decoy; no consequential writes |
| `SYN-GAIA-ADA` | Adaptive Infrastructure Operations | 3 | Detect regional degradation event; authorize healthy failover; verify actual routing state |
| `SYN-GAIA-TIM` | Settlement Window Execution | 3 | Submit exactly once inside an event-gated time window; read back batch state |
| `SYN-GAIA-AMB` | Customer Identity Resolution | 3 | Refuse ambiguous identity operations pending sufficient evidence |
| `SYN-GAIA-A2A` | Enterprise Procurement Coordination | 3 | Multiple-agent agreement; respect fixed shared budget (requested 12 units exceeds available budget) |
| `SYN-GAIA-NOI` | Resilient Identity Provisioning | 2 | Handle 503/lost response with reconciliation; exactly-once account provision |
| `SYN-OTEL-01` | Payment Recovery & Continuity | 4 | Repair payment capacity without disabling payment controls; probe recovery |
| `SYN-OTEL-02` | Product Catalog Reliability | 3 | Rebuild corrupted P2 index without disturbing healthy items |
| `SYN-OTEL-03` | Commerce Transaction Recovery | 3 | Correct misconfigured Redis endpoint and validate checkout readiness |
| `SYN-OTEL-04` | Event Processing Integrity | 12 | Coordinate 10 partitions; preserve ordering and avoid duplicate event processing |
| `SYN-OTEL-05` | Service Performance Assurance | 3 | Reduce recommendation latency and memory pressure; verify two windows without session loss |
| `SYN-OTEL-06` | Autonomous AI Containment | 3 | Bound a runaway assistant's call rate while leaving unrelated services available |

The public world catalogue is [`tests/legion_struct/worlds/INDEX.json`](tests/legion_struct/worlds/INDEX.json). Individual definitions are in the same directory; the Judge and its schemas are in [`judge/components/judge_s1/`](judge/components/judge_s1/).

## Evidence and measured outcomes

**WO050: 13/13 PASS.** Unified frozen-source campaign;
100 registered workers per structural world.

**WO059: 13/13 PASS.** Independent Judge replay of original
native evidence, without using historical Judge verdicts.

**WO060: 2/2 PASS.** Negative controls detected an evidence
hash mismatch and a causal dependency violation.

See [WO059 replay and WO060 controls](docs/WO059_INDEPENDENT_REPLAY.md).

**Public reproducibility: PENDING.** Evidence bundles are retained
by Veraxis and available on request; they are not included here.

These results concern bounded GAIA2/OpenTelemetry-derived
synthetic worlds, not an official GAIA2 benchmark score.

### Video cross-reference (illustrative, not a controlled comparison)

The accompanying film reports a **65.3% reduction** from **85,558 FAIL** to **29,707 PASS** for its ADA illustration. **Footnote:** one run per condition; reasoning differed; **not** a matched, controlled benchmark and **not** the LEGION-100 VCC@1 result. These figures are film-reported and are not independently evidenced by the WO050/WO059 Judge bundles here.

## Architecture and formal boundary

- **Causal controller:** Tracks prerequisite obligations and state transitions. Agent self-report does not close an obligation without the required evidence.
- **ZTL:** Evidence/admissibility logic. Earlier source pins identify `inventor1975/ztl-swarm` at `7d2a8265926aecab9a838b09059bd106941b5c18` using its **Python rule**, not a compiled Lean `zverdict`. Separately proved Lean theorems in the broader ZTL work should not be represented as proofs of end-to-end LEGION runtime execution.
- **Google CAGE:** An upstream Apache-2.0 governance engine; in tested configurations it provides gateway/governor, warrant and evidence machinery. LEGION adds adapters and task-specific control. The attribution and test-only execution limits are noted in this section and in [license scope](LICENSE-SCOPE.md).
- **VEIP:** Admissibility and warrant/authority elements. Earlier preflight used **test-only** authority roots. Test fixture authority is not production authority.
- **Native adapters:** Implement side effects in the 13 controlled worlds; must preserve idempotency, deadlines, obligation dependencies and receipt/readback joins.
- **Independent Judge:** Reads execution artifacts and validates mission obligations independently of proposing agents and causal controller. Mock permissive checks are not a substitute.

**Formal-methods provenance:** LEGION integrates ZTL evidence/admissibility mechanisms, but this repository does not ship Lean `.lean` files or establish a Lean proof of the entire LEGION runtime. Lean source and formal theorems are maintained separately at [inventor1975/ZTL](https://github.com/inventor1975/ZTL). The LEGION experiment described here used a Python rule at its pinned source revision.

## NVIDIA NIM and runtime configuration

LEGION experiments have used NVIDIA NIM and the model identifier `nvidia/nemotron-3.5-lightning-30b-a3b`. The tested execution configuration is version-specific; the public DEV Judge smoke test above does not require NIM, a model API, or secrets. Credentials must never be committed to this repository.

## Quick start: run the independent Judge

Clone the repository. Python 3.10+ is required for the standard-library Judge; no model credentials, NIM calls, or live services are required for this sample.

From the repository root on Linux, macOS, or WSL:

```bash
python3 -I judge/components/run_judge.py judge/components/judge_s1 evaluate judge/components/judge_s1/fixtures/DEV/SYN-GAIA-EXE --out /tmp/legion-dev-verdict.json
python3 -c 'import json; print(json.load(open("/tmp/legion-dev-verdict.json"))["verdict"])'
```

Expected result: `PASS` and process exit code `0`. On Windows PowerShell, use `python` in place of `python3` and a Windows path for `--out` (for example, `dev-verdict.json`).

**What this proves:** The published deterministic reference Judge accepts the bundled **synthetic DEV fixture**. It is not a WO050 production mission, not WO059's 13/13 historical replay, and not proof that 100 live agents were run by this command. The historical WO050 evidence bundles are retained by Veraxis and are available on request; public third-party reproduction of all 13 remains pending.

To inspect all 13 public structural world definitions, see [`tests/legion_struct/worlds/INDEX.json`](tests/legion_struct/worlds/INDEX.json). This repository does not contain local Lean proof sources; the upstream formal logic research is maintained separately in [ZTL](https://github.com/inventor1975/ZTL).

## Licenses and provenance

LEGION original content: **PolyForm Noncommercial 1.0.0** (source-available; not an OSI open-source license). Google CAGE upstream source: **Apache-2.0**. Other components retain their applicable licenses. These are separate obligations: [license scope](LICENSE-SCOPE.md), [third-party notices](THIRD_PARTY_NOTICES.md), [NOTICE](NOTICE). Google did not develop or certify LEGION-100; CAGE is not an officially supported Google product.

This repository is **published** as a functional development snapshot, not a production-certified release. WO059 independent Judge replay and WO060 negative controls are PASS. File-level provenance review and public reproduction remain open.

## Submission and engineering context

LEGION-100 addresses the Meta Global AI Developer Hackathon's **Push the Frontier** theme: giving a collective of agentic systems a new capability—controlled, attributable execution with independently adjudicated consequences. Development-stage source provenance includes Meta Muse operated through Claude Code CLI. Neither Meta nor Google independently evaluated the reported LEGION-100 result.

---

Maintainer: Veraxis. The published source snapshot is version-specific; claims must be evaluated against the corresponding manifest and reproducible execution evidence.
