# LEGION-100: Independent Judge Replay — WO059

## Verified result

13/13 historical WO050 missions independently replayed: PASS.

- Seven GAIA2-derived structural worlds.
- Six OpenTelemetry-derived structural worlds.
- 100 registered agents per world.
- Complete evidence traces in all 13.
- Zero source errors, Judge failures, or replay execution errors.
- Windows PowerShell 5.1 / Ubuntu 24.04 WSL2 / Python 3.12.3.
- Published repository baseline: bd8305edab4079de5360708194a30f8998f1e840.
- Frozen Core SHA-256: e7908a640788deff33ac49a1534524d906745fa027ec0b207adfa32aacd904a0.

## Independent verification method

Each original WO050 `NATIVE_EVIDENCE` directory was processed
using the published `judge/components/struct_adapter.py`.

The resulting evidence bundle was evaluated in a separate process
using the published `judge/components/run_judge.py` and `judge_s1`.

Historical JUDGE_RESULT.json files were not supplied to the evaluator.

All 13 replay verdicts were PASS. The process exited with code 0.

## Primary evidence

Windows/Dropbox:

`L1/LEGION_100/WO059_WINDOWS_ACCEPTANCE_20261104_195405/REPLAY_CORRECTED/`

Original campaign:

`L1/LEGION_100/CODEX_WO_LEGION100_GO_001/WO050_UNIFIED/`

## Scope and limitations

This result establishes deterministic independent Judge replay
of 13 historical synthetic-world executions. It does not establish
a new live campaign, an official GAIA2 score, or production-grade
cryptographic attestation.

The replay uses the documented TEST-posture HMAC fallback.

No NIM inference or mission re-execution was required.
