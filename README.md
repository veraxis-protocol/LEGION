# LEGION-100

**Verified multi-agent execution infrastructure for consequential tasks**

> Intelligence is abundant. Control over consequence is scarce.

**Release status:** publicly published functional development snapshot (WO057). Licensing policy is confirmed; file-level provenance review and public clean-room reproduction remain open. LEGION-100 is a source-available Veraxis research implementation. The repository documents 100 registered agents operating across 13 bounded, executable state-machine worlds. Seven world structures were developed from GAIA2 scenario categories and six from OpenTelemetry Astronomy Shop operational patterns. This is not a claim that any synthetic world reproduces all conditions of a production enterprise system.

LEGION's central question is not whether 100 agents can exchange messages. It is whether a collective can satisfy **causal obligations**, admit consequential actions under verifiable authority, produce actual state changes, preserve receipts and readbacks, and earn completion from an **independent Judge**.

## Technical scope

The core execution boundary is:

`mission → executable world → 100 registered agents / assigned active roles → causal controller → ZTL evidence/admissibility → CAGE and VEIP governance → native world tools → consequential state effects → receipts + independent readbacks → independent Judge`.

The agents *propose* actions. The control and governance layers determine whether actions may be executed. The world adapter enacts eligible operations and produces evidence. The Judge decides whether the resulting collective mission satisfied all specified obligations. See execution boundaries and CAGE disclosure.

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

For each world, inspect its actual JSON under `worlds/`, obligation graph, assigned roles, event timing, adapter action set, permitted authority, expected effect and Judge specification. The 13 identifiers above are based on `STRUCTURAL_001/worlds_public/INDEX.json`, not inferred from run successes. Detailed reproducibility instructions are tracked in world specifications.

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

## Architecture and formal boundary

- **Causal controller:** Tracks prerequisite obligations and state transitions. Agent self-report does not close an obligation without the required evidence.
- **ZTL:** Evidence/admissibility logic. Earlier source pins identify `inventor1975/ztl-swarm` at `7d2a8265926aecab9a838b09059bd106941b5c18` using its **Python rule**, not a compiled Lean `zverdict`. Separately proved Lean theorems in the broader ZTL work should not be represented as proofs of end-to-end LEGION runtime execution.
- **Google CAGE:** An upstream Apache-2.0 governance engine; in tested configurations it provides gateway/governor, warrant and evidence machinery. LEGION adds adapters and task-specific control. Attribution and execution-scoped limitations: CAGE disclosure.
- **VEIP:** Admissibility and warrant/authority elements. Earlier preflight used **test-only** authority roots. Test fixture authority is not production authority.
- **Native adapters:** Implement side effects in the 13 controlled worlds; must preserve idempotency, deadlines, obligation dependencies and receipt/readback joins.
- **Independent Judge:** Reads execution artifacts and validates mission obligations independently of proposing agents and causal controller. Mock permissive checks are not a substitute.

## NVIDIA NIM and runtime configuration

Successful-experiment model recorded in the WO: `nvidia/nemotron-3.5-lightning-30b-a3b`. Earlier source pins reference `https://integrate.api.nvidia.com/v1`, with `enable_thinking=false`. Credentials must be provided via environment variables, never committed. Exact runtime values for temperature, token budget, concurrency, 429 retries, transport timeouts, causal park deadlines, global rate controls and maximum semantic turns must be extracted from the *frozen* runner/config, not guessed. See NIM integration.

## Quick start / reproducibility

**Do not use upstream CAGE's root README or `docker-compose.yml` as LEGION's complete installation instructions.** The source snapshot was captured from a CAGE-based development tree; the release candidate requires a verified LEGION-specific entry point. The following non-mutating commands are valid source inspection steps, **not proof of a runnable mission**:

```bash
python3 --version
find . -maxdepth 3 -name 'pyproject.toml' -o -name 'uv.lock' -o -name 'requirements*.txt'
find . -type f \( -name 'JUDGE_RESULT.json' -o -name 'WORLD_RESULT.json' -o -name 'WORLD_LOG.jsonl' \)
find . -type f -name '*.lean' | sort
sha256sum -c SOURCE_FILES_SHA256.txt
```

WO059 independently replayed all 13 historical missions. Public evidence distribution, clean-room reproduction and documented mission/NIM commands remain separate release tasks. The pinned lockfiles and supported Python/WSL versions, required environment keys, synthetic fixture setup and exact CLI routes will be documented against an actual clean execution. Do not substitute mock data or fabricated CLI commands.

## Licenses and provenance

LEGION original content: **PolyForm Noncommercial 1.0.0** (source-available; not an OSI open-source license). Google CAGE upstream source: **Apache-2.0**. Other components retain their applicable licenses. These are separate obligations: [license scope](LICENSE-SCOPE.md), [third-party notices](THIRD_PARTY_NOTICES.md), [NOTICE](NOTICE). Google did not develop or certify LEGION-100; CAGE is not an officially supported Google product.

This repository is **published** as a functional development snapshot, not a production-certified release. WO059 independent Judge replay and WO060 negative controls are PASS. File-level provenance review and public reproduction remain open.

## Submission and engineering context

LEGION-100 addresses the Meta Global AI Developer Hackathon's **Push the Frontier** theme: giving a collective of agentic systems a new capability—controlled, attributable execution with independently adjudicated consequences. Earlier provenance records identify Meta Muse through Claude Code CLI as a code-producing tool for a development stage. Declare that provenance accurately where hackathon rules require it; neither Meta nor Google independently evaluated the claimed result.

---

Maintainer: Veraxis. The published source snapshot is version-specific; claims must be evaluated against the corresponding manifest and reproducible execution evidence.
