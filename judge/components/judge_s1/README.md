# LEGION-100 Independent Judge — Reference Implementation 001

**Status: TEST-POSTURE SYNTHETIC REFERENCE IMPLEMENTATION; NOT DEPLOYED; NO LEGION-100 VCC@1 MEASURED.**

This is a runnable, deterministic, Python-standard-library reference evaluator implementing the core of the two requirements files already saved at `/L1/LEGION_100/judge requirements.md` and `judge validation protocol.md`. It checks frozen mission/evidence bundles without calling an LLM or executing a mission. It does **not** make authorization decisions and has no permission to write the target application. It is **not yet a trusted production Oracle**: evidence origins, boolean CAGE/ZTL/VEIP verification fields and the final native readback are *assertions in synthetic JSON*, not cryptographic attestations or independently queried real-world services. Hashes detect changes relative to a manifest, but an untrusted manifest can be rewritten with its files; a pre-run external anchor is required.

## Contents

- `legion_judge/core.py`: deterministic evaluator, evidence chain checks, attempt/preregistration guards, issue taxonomy and VCC@1 aggregator.
- `legion_judge/__main__.py`: stand-alone command-line interface (`evaluate`, `aggregate`).
- `legion_judge/synthetic.py`: explicitly synthetic positive DEV fixtures across seven GAIA2-style and six OTel-style *mechanism categories*.
- `schemas/*.schema.json`: JSON Schema (draft 2020-12) for mission, registration, evidence, verdict and cohort.
- `tests/test_oracle.py`: 45 regression tests, including OR-01 through OR-30 falsifications and a scripted 100-effect/100-role test.
- `fixtures/DEV/*`: 13 pre-generated scripted smoke episodes with frozen local SHA-256 manifests and validator outputs. These are not LEGION mission attempts or a measured VCC@1.
- `results/*`: test and CLI outputs, SHA-256 manifest in package root.

## Run on Windows / Linux (Python 3.10+)

From this archive's root:

```bash
python -m unittest discover -s tests -v
python -m legion_judge evaluate fixtures/DEV/SYN-GAIA-EXE
python -m legion_judge evaluate fixtures/DEV/SYN-GAIA-SEA
python tools/build_dev_corpus.py
```

CLI `evaluate` returns exit 0 for `PASS`, 1 for non-PASS. To write an output:

```bash
python -m legion_judge evaluate fixtures/DEV/SYN-OTEL-01 --out my_verdict.json
```

Optional schema validation requires `pip install jsonschema` but the Oracle itself uses only stdlib. `python tools/make_schemas.py` regenerates schema files.

Aggregate a **preregistered counted cohort** (not the packaged DEV episodes):

```bash
python -m legion_judge aggregate frozen_cohort.json first_attempt_1.json first_attempt_2.json
```

The frozen cohort contains `schema_version: legion.cohort.v1`, `invalid_policy: count_as_nonpass | exclude_preregistered`, and `missions[]` with exact `mission_id`, `scenario_id`, `eligible` and, if frozen before execution, `invalid_disposition`. An eligible missing verdict counts as `INDETERMINATE`, **never PASS**. `INVALID_TEST` cannot be excluded ad hoc. VCC@1 is successes divided by all eligible first attempts, not test PASS percentage.

## What the code can establish in TEST posture

1. Goals are true in a supplied, separately labelled final-state readback; agent `DONE` does not establish the goal.
2. Obligations are closed by observed source records; the validator supports `WRITE`, `READ`, `ANALYZE`, `COMMUNICATE`, `WAIT`, `REFUSE`, `RECONCILE`; conditional obligations require their declared native event; `WRITE` demands every enumerated target exactly once.
3. Each native write joins exactly one eligible governance record, admitted commit, exact agent/provider model decision and digest, receipt and effect readback. Unknown/equivocal evidence does not confer PASS.
4. Actor, system representation, tool, target, obligation, digest, model decision ID, policy verdict and epoch checks are pinned by the synthetic trace; false, missing and contradictory records block PASS.
5. Dependency order uses independently verified **receipt/readback** closure, not an agent self-declaration or merely tool-return success. Timing uses a single-host monotonic timeline.
6. Double effects, out-of-contract writes, false DONE, stale fenced claims, early action, deadlines, budgets and tampered manifest hashes are rejected.
7. `PASS`, `FAIL`, `SAFE_STOP`, `INDETERMINATE`, `INVALID_TEST` are distinct. A safe halt does not count as completion; a mission whose goal is legitimate refusal can PASS with zero mutations.
8. `check_families.J08` is `NOT_APPLICABLE` absent an actual independently specified dynamic/recovery requirement: lack of a negative test is not a success claim.

## Critical boundaries **NOT** implemented / NOT yet demonstrated

- No real OpenTelemetry or ARE/GAIA2 service connections. Synthetic OTEL cases contain simplified state/observations; they do not test instrumented spans, native probes, Rabbit/Kafka, Kubernetes or actual fault injection.
- No dataset-to-contract importer, no real 100-agent inference or autonomous coordination, no independent 100-agent campaign, no official GAIA2 Judge, **no observed LEGION VCC@1**.
- No cryptographic validation of CAGE attestation, VEIP root signatures, revocation epochs, Linkerd identity or native receipt signatures: test boolean flags are **not** a secure substitute. Do not use the package to certify a production environment.
- No production-grade distributed clock proof (single-host monotonic only); no networked lease service or true fencing enforcement; no real gateway/controller crash/restart exercise, no external oracle gold isolation, no opaque independent data-source ingestion.
- No independent semantic rubric for ambiguous human-language goals: explicitly unresolved semantic issues return `INDETERMINATE`, not post hoc judge preference. The Oracle does not ask an LLM for a soft verdict.
- `J08` adaptation checks are bounded to explicit event and obligation tracking; no model of unobserved counterfactual adaptations. `J09` provenance cannot be trusted from untrusted source-provided strings.
- Hash manifest is **not signed**, and a malicious producer controlling both manifest and inputs can forge consistency. Required next: detached hash freeze and read-only, attested native data adapters verified by an independent auditor.

## Integration acceptance (Claude / Meta)

1. Review and run all 45 tests in a clean process. Any mutation in a positive test should change expected outcome; audit any false PASS as a P0.
2. Implement **outside** this evaluator a source adapter that acquires actual native state and logs through independent, authenticated, read-only channels; bind hashes externally *before* a counted run. Do not trust the agents' `readback_origin` or `seal_valid` fields.
3. Reconcile real CAGE/ZTL/VEIP evidence with the exact requirements; replace test booleans with independently verified signatures and correctly scoped capability proofs.
4. Add real 10/100-agent controlled negative, crash/recovery and cross-host tests. Freeze the judge before first official attempt; retain failing attempts.
5. Create held-out structured GAIA2/OTEL-inspired scenarios with versioned coverage and independently authored acceptance criteria. Do not reward a generic `apply_transition` graph as collective intelligence.
6. Only then publish a cohort VCC@1, per-axis breakdown, safety ledger and remaining `INDETERMINATE`/`INVALID_TEST` rates.

## Change discipline

The 2 existing requirements documents and historical MINI-004/SCALE-005 artifacts were not modified. This package is a new, independent implementation baseline. It does not replace the SCALE-005 Oracle or reinterpret any historical verdict.
