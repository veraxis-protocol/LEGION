"""WO008-05 B: repaired I3 in the real wo008_attempt_audit evaluator.

I3 is three-valued: T = proven no mutation after terminal under a genuinely
comparable authenticated clock / proven event-order bridge; F = proven
mutation after terminal; Z = unknown chronology (never a fabricated PASS).

Synthetic records are signed with an isolated TEST signer only
(TEST_KEY below); no real credentials are accessed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import shutil
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import wo008_attempt_audit as audit  # noqa: E402

ROOT = HERE.parents[2]
FROZEN_DIR = ROOT / "_wo008_input" / "WO008_05_FROZEN"
TEST_KEY = b"wo008-test-only-isolated-signer-not-a-real-credential"
UID = "attempt-test-001"
WID = "world-test-001"
GENESIS = "0" * 64


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode()


def _sign(records, key=TEST_KEY):
    """Isolated TEST signer: hash chain + HMAC exactly as attempt.py writes."""
    out, prev = [], GENESIS
    for rec in records:
        rec = dict(rec)
        rec["prev_hash"] = prev
        rec["hash"] = hashlib.sha256(_canonical(rec)).hexdigest()
        rec["mac"] = hmac.new(key, rec["hash"].encode(), hashlib.sha256).hexdigest()
        prev = rec["hash"]
        out.append(rec)
    return out


def _attempt_records(terminal_extra=None, states=("REGISTERED", "RUNNING", "COMPLETED")):
    recs = []
    for i, state in enumerate(states, 1):
        rec = {"seq": i, "event": state, "state": state, "reason": "test",
               "verdict": None, "attempt_uid": UID,
               "world_instance_id": WID if i > 1 else None,
               "t": 1_700_000_000.0 + 10 * i}  # wall clock only by default
        if state == "COMPLETED" and terminal_extra:
            rec.update(terminal_extra)
        recs.append(rec)
    return recs


def _write_run(tmp_path, attempt_records, world_records, *, sign=True, key=TEST_KEY):
    run = tmp_path / "run"
    run.mkdir(parents=True, exist_ok=True)
    recs = _sign(attempt_records, key) if sign else attempt_records
    (run / "ATTEMPT_LOG.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    (run / "WORLD_LOG.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in world_records), encoding="utf-8")
    return run


def _world(mutations=()):
    rows = [{"seq": 1, "kind": "WORLD_START", "t_mono": 1000.0,
             "attempt_uid": UID, "world_instance_id": WID}]
    rows += list(mutations)
    return rows


def _mutation(seq, t_mono, kind="NATIVE_EFFECT", uid=UID, wid=WID):
    return {"seq": seq, "kind": kind, "t_mono": t_mono, "effect_id": f"eff-{seq}",
            "attempt_uid": uid, "world_instance_id": wid}


def _frozen_run(tmp_path):
    run = tmp_path / "frozen"
    run.mkdir()
    shutil.copy(FROZEN_DIR / "ATTEMPT_LOG.jsonl", run / "ATTEMPT_LOG.jsonl")
    shutil.copy(FROZEN_DIR / "RUN_HEADER.json", run / "RUN_HEADER.json")
    shutil.copy(FROZEN_DIR / "WORLD_LOG_READBACK.jsonl", run / "WORLD_LOG.jsonl")
    return run


# --- Frozen historical data: no provable bridge -> Z, never fabricated T ---

def test_frozen_b1_historical_i3_is_z_not_fabricated_t(tmp_path):
    run = _frozen_run(tmp_path)
    result = audit.evaluate_attempt_i3(run)  # no TEST key material available
    assert result["I3"] == "Z"
    assert result["bridge"] is None
    assert result["mac_status"] == "unverified"
    assert result["reason"] == "WALL_CLOCK_TERMINAL_NOT_COMPARABLE_TO_T_MONO"
    # Wall t exists on the terminal, t_mono exists on mutations; they were
    # NOT compared (the legacy defect).
    assert result["terminal"]["state"] == "COMPLETED"
    assert result["terminal_clock"]["wall_t"] is not None
    assert result["terminal_clock"]["wall_t_compared_to_t_mono"] is False


def test_frozen_b1_full_evaluator_reports_indeterminate_i3(tmp_path):
    res = audit.evaluate_attempt_integrity(_frozen_run(tmp_path))
    assert res["checks"]["I3_no_mutation_after_terminal"] == "Z"
    assert res["details"]["chronology_bridge"] is None
    assert res["verdict"] != "ATTEMPT_INTEGRITY_GO"


# --- Authenticated monotonic terminal clock ---

def test_effect_before_authenticated_terminal_is_t(tmp_path):
    run = _write_run(tmp_path, _attempt_records({"t_mono": 1100.0}),
                     _world([_mutation(2, 1050.0)]))
    result = audit.evaluate_attempt_i3(run, attempt_key=TEST_KEY)
    assert result["I3"] == "T"
    assert result["bridge"] == "authenticated_t_mono"
    assert result["mac_status"] == "verified"
    assert result["mutations_after_terminal"] == []


def test_native_mutation_after_authenticated_terminal_is_f(tmp_path):
    run = _write_run(tmp_path, _attempt_records({"t_mono": 1100.0}),
                     _world([_mutation(2, 1050.0), _mutation(3, 1200.0)]))
    result = audit.evaluate_attempt_i3(run, attempt_key=TEST_KEY)
    assert result["I3"] == "F"
    assert [m["line"] for m in result["mutations_after_terminal"]] == [3]


def test_receipt_after_authenticated_terminal_is_also_f(tmp_path):
    run = _write_run(tmp_path, _attempt_records({"t_mono": 1100.0}),
                     _world([_mutation(2, 1200.0, kind="RECEIPT")]))
    assert audit.evaluate_attempt_i3(run, attempt_key=TEST_KEY)["I3"] == "F"


def test_wall_clock_only_terminal_never_compared_to_t_mono(tmp_path):
    # Terminal wall t (1.7e9) is numerically >> every t_mono (~1000); the old
    # comparison would have hidden the later mutation. Repaired: Z.
    run = _write_run(tmp_path, _attempt_records(),
                     _world([_mutation(2, 1200.0)]))
    result = audit.evaluate_attempt_i3(run, attempt_key=TEST_KEY)
    assert result["I3"] == "Z"
    assert result["reason"] == "WALL_CLOCK_TERMINAL_NOT_COMPARABLE_TO_T_MONO"


def test_unverified_mac_cannot_authenticate_terminal_clock(tmp_path):
    run = _write_run(tmp_path, _attempt_records({"t_mono": 1100.0}),
                     _world([_mutation(2, 1050.0)]))
    no_key = audit.evaluate_attempt_i3(run)  # MAC present, material absent
    assert no_key["I3"] == "Z"
    assert no_key["mac_status"] == "unverified"
    wrong_key = audit.evaluate_attempt_i3(run, attempt_key=b"wrong-test-key")
    assert wrong_key["I3"] == "Z"
    assert wrong_key["mac_status"] == "failed"


def test_tampered_terminal_hash_is_z(tmp_path):
    run = _write_run(tmp_path, _attempt_records({"t_mono": 1100.0}),
                     _world([_mutation(2, 1050.0)]))
    lines = (run / "ATTEMPT_LOG.jsonl").read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[-1])
    rec["t_mono"] = 9999.0  # edited without re-signing: hash chain breaks
    lines[-1] = json.dumps(rec)
    (run / "ATTEMPT_LOG.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = audit.evaluate_attempt_i3(run, attempt_key=TEST_KEY)
    assert result["I3"] == "Z"
    assert result["hash_chain_verified"] is False
    assert result["attempt_log_problems"]


# --- Proven event-order bridge (world seq watermark) ---

def test_world_seq_watermark_bridge_t_then_f(tmp_path):
    before = _write_run(tmp_path / "a", _attempt_records({"world_seq_at_terminal": 2}),
                        _world([_mutation(2, 1050.0)]))
    assert audit.evaluate_attempt_i3(before, attempt_key=TEST_KEY)["I3"] == "T"

    after = _write_run(tmp_path / "b", _attempt_records({"world_seq_at_terminal": 2}),
                       _world([_mutation(2, 1050.0), _mutation(3, 900.0)]))
    result = audit.evaluate_attempt_i3(after, attempt_key=TEST_KEY)
    # seq 3 is after the terminal watermark even though its t_mono is lower:
    # ordering comes from the proven seq bridge, not clock comparison.
    assert result["I3"] == "F"
    assert result["bridge"] == "authenticated_world_seq"


# --- Ordering / identity validation ---

def test_duplicate_attempt_seq_is_z(tmp_path):
    recs = _attempt_records({"t_mono": 1100.0})
    recs[2] = dict(recs[2], seq=2)  # duplicate seq 2, no seq 3
    run = _write_run(tmp_path, recs, _world([_mutation(2, 1050.0)]))
    result = audit.evaluate_attempt_i3(run, attempt_key=TEST_KEY)
    assert result["I3"] == "Z"
    assert any("duplicate seq" in p for p in result["attempt_log_problems"])


def test_out_of_order_attempt_seq_is_z(tmp_path):
    recs = _attempt_records({"t_mono": 1100.0})
    recs[1] = dict(recs[1], seq=3)  # file order seqs are 1, 3, 2
    recs[2] = dict(recs[2], seq=2)
    run = _write_run(tmp_path, recs, _world([_mutation(2, 1050.0)]))
    result = audit.evaluate_attempt_i3(run, attempt_key=TEST_KEY)
    assert result["I3"] == "Z"
    assert result["attempt_log_problems"]


def test_no_terminal_is_z(tmp_path):
    run = _write_run(tmp_path, _attempt_records(states=("REGISTERED", "RUNNING")),
                     _world([_mutation(2, 1050.0)]))
    result = audit.evaluate_attempt_i3(run, attempt_key=TEST_KEY)
    assert result["I3"] == "Z"
    assert result["reason"] == "TERMINAL_MISSING"


def test_cross_attempt_attempt_log_record_is_z(tmp_path):
    recs = _attempt_records({"t_mono": 1100.0})
    recs.append({"seq": 4, "event": "RUNNING", "state": "RUNNING", "reason": "x",
                 "verdict": None, "attempt_uid": "foreign-attempt",
                 "world_instance_id": WID, "t": 1_700_000_100.0})
    run = _write_run(tmp_path, recs, _world([_mutation(2, 1050.0)]))
    result = audit.evaluate_attempt_i3(run, attempt_key=TEST_KEY)
    assert result["I3"] == "Z"
    assert any("multiple attempt_uid" in p for p in result["attempt_log_problems"])


def test_cross_attempt_and_cross_world_mutations_rejected_not_counted(tmp_path):
    foreign_uid = _mutation(3, 1200.0, uid="foreign-attempt")
    foreign_wid = _mutation(4, 1300.0, wid="foreign-world")
    run = _write_run(tmp_path, _attempt_records({"t_mono": 1100.0}),
                     _world([_mutation(2, 1050.0), foreign_uid, foreign_wid]))
    res = audit.evaluate_attempt_integrity(run, attempt_key=TEST_KEY)
    # Foreign mutations are rejected as this attempt's violations...
    assert res["checks"]["I3_no_mutation_after_terminal"] == "T"
    assert len(res["details"]["rejected_foreign_records"]) == 2
    # ...but identity/effect binding checks still fail on them (fail-closed).
    assert res["checks"]["I4_effects_bound_to_attempt_and_world"] is False
    assert res["verdict"] == "ATTEMPT_INTEGRITY_NO_GO"


def test_domestic_mutation_after_terminal_still_f_despite_foreign_noise(tmp_path):
    run = _write_run(tmp_path, _attempt_records({"t_mono": 1100.0}),
                     _world([_mutation(2, 1050.0),
                             _mutation(3, 1200.0, uid="foreign-attempt"),
                             _mutation(4, 1400.0)]))
    result = audit.evaluate_attempt_i3(run, attempt_key=TEST_KEY)
    assert result["I3"] == "F"
    assert [m["seq"] for m in result["mutations_after_terminal"]] == [4]


# --- Legacy CLI preserved ---

def test_legacy_cli_writes_verdict_file(tmp_path):
    run = _frozen_run(tmp_path)
    out = tmp_path / "out.json"
    rc = audit.main([str(run), str(out)])
    assert rc == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["checks"]["I3_no_mutation_after_terminal"] == "Z"
    assert payload["verdict"] == "ATTEMPT_INTEGRITY_INDETERMINATE"


def test_legacy_cli_with_test_key_hex_authenticates(tmp_path):
    run = _write_run(tmp_path, _attempt_records({"t_mono": 1100.0}),
                     _world([_mutation(2, 1050.0)]))
    out = tmp_path / "out.json"
    rc = audit.main([str(run), str(out), "--test-key-hex", TEST_KEY.hex()])
    assert rc == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["checks"]["I3_no_mutation_after_terminal"] == "T"
