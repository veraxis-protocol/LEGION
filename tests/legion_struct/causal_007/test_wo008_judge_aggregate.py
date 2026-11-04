"""WO008-05 A: regression tests for the real wo008_judge aggregate().

The supplied aggregate already counts INVALID_TEST under count_as_nonpass;
these tests prove it against the frozen B1 data and preserve the frozen
historical 2/12 file as evidence of the old defect (file left unchanged).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from wo008_judge.core import aggregate  # noqa: E402

ROOT = HERE.parents[2]
FROZEN = ROOT / "_wo008_input" / "WO008_05_FROZEN" / "VCC_AT_1_B1.json"


def _frozen_registry_and_verdicts():
    data = json.loads(FROZEN.read_text(encoding="utf-8"))
    attempts = data["B1_judge_aggregate"]["attempts"]
    registry = {
        "schema_version": "legion.cohort.v1",
        "invalid_policy": "count_as_nonpass",
        "missions": [
            {"mission_id": a["mission_id"], "scenario_id": None, "eligible": True}
            for a in attempts
        ],
    }
    verdicts = [
        {"mission_id": a["mission_id"], "scenario_id": None,
         "verdict": a["verdict"], "attempt_index": 1}
        for a in attempts
    ]
    return data, registry, verdicts


def _registry(policy="count_as_nonpass", missions=None):
    return {"schema_version": "legion.cohort.v1", "invalid_policy": policy,
            "missions": missions if missions is not None else [
                {"mission_id": "M1", "scenario_id": "S1", "eligible": True},
                {"mission_id": "M2", "scenario_id": "S1", "eligible": True},
                {"mission_id": "M3", "scenario_id": "S1", "eligible": True}]}


def _verdict(mid, status, attempt_index=1):
    return {"mission_id": mid, "scenario_id": "S1",
            "verdict": status, "attempt_index": attempt_index}


def test_frozen_b1_real_aggregate_counts_invalid_as_nonpass():
    _data, registry, verdicts = _frozen_registry_and_verdicts()
    result = aggregate(registry, verdicts)
    assert result["numerator"] == 2          # PASS=2
    assert result["registered"] == 13        # REGISTERED=13
    assert result["invalid_tests"] == 1      # INVALID_TEST=1
    assert result["denominator"] == 13       # DENOMINATOR=13 (not 12)
    assert result["value"] == pytest.approx(2 / 13)  # VCC@1 = 2/13
    assert result["missing_verdicts"] == 0
    assert len(result["attempts"]) == 13


def test_frozen_historical_file_still_records_old_2_of_12_defect():
    data = json.loads(FROZEN.read_text(encoding="utf-8"))
    hist = data["B1_judge_aggregate"]
    # Evidence of the old defect, left unchanged in the frozen source.
    assert hist["denominator"] == 12
    assert hist["numerator"] == 2
    assert hist["invalid_tests"] == 1
    assert hist["registered"] == 13


def test_missing_verdict_counts_in_denominator_as_nonpass():
    registry = _registry()
    result = aggregate(registry, [_verdict("M1", "PASS")])
    assert result["registered"] == 3
    assert result["missing_verdicts"] == 2
    assert result["denominator"] == 3
    assert result["numerator"] == 1
    statuses = {a["mission_id"]: a["verdict"] for a in result["attempts"]}
    assert statuses["M2"] == "INDETERMINATE"
    assert statuses["M3"] == "INDETERMINATE"


def test_duplicate_registry_mission_rejected():
    registry = _registry(missions=[
        {"mission_id": "M1", "scenario_id": "S1", "eligible": True},
        {"mission_id": "M1", "scenario_id": "S1", "eligible": True}])
    with pytest.raises(ValueError, match="duplicate mission"):
        aggregate(registry, [])


def test_duplicate_verdict_rejected():
    with pytest.raises(ValueError, match="duplicate verdict"):
        aggregate(_registry(), [_verdict("M1", "PASS"), _verdict("M1", "FAIL")])


def test_unregistered_verdict_rejected():
    with pytest.raises(ValueError, match="unregistered"):
        aggregate(_registry(), [_verdict("M9", "PASS")])


def test_non_first_attempt_verdict_rejected():
    with pytest.raises(ValueError, match="attempt_index=1"):
        aggregate(_registry(), [_verdict("M1", "PASS", attempt_index=2)])


def test_invalid_policy_missing_from_registry_rejected():
    registry = _registry()
    del registry["invalid_policy"]
    with pytest.raises(ValueError, match="invalid preregistered cohort"):
        aggregate(registry, [])


def test_count_as_nonpass_keeps_invalid_in_denominator_even_if_marked_exclude():
    registry = _registry(missions=[
        {"mission_id": "M1", "scenario_id": "S1", "eligible": True,
         "invalid_disposition": "EXCLUDE"},
        {"mission_id": "M2", "scenario_id": "S1", "eligible": True},
        {"mission_id": "M3", "scenario_id": "S1", "eligible": True}])
    result = aggregate(registry, [_verdict("M1", "INVALID_TEST"),
                                  _verdict("M2", "PASS"), _verdict("M3", "FAIL")])
    assert result["invalid_tests"] == 1
    assert result["denominator"] == 3
    assert result["numerator"] == 1


def test_exclude_preregistered_only_excludes_frozen_exclude_disposition():
    missions = [
        {"mission_id": "M1", "scenario_id": "S1", "eligible": True,
         "invalid_disposition": "EXCLUDE"},
        {"mission_id": "M2", "scenario_id": "S1", "eligible": True},
        {"mission_id": "M3", "scenario_id": "S1", "eligible": True}]
    result = aggregate(_registry(policy="exclude_preregistered", missions=missions),
                       [_verdict("M1", "INVALID_TEST"),
                        _verdict("M2", "PASS"), _verdict("M3", "FAIL")])
    assert result["invalid_tests"] == 1
    assert result["denominator"] == 2  # M1 excluded by frozen policy only
    assert result["numerator"] == 1
    excluded = [a for a in result["attempts"] if a.get("excluded_by_frozen_policy")]
    assert [a["mission_id"] for a in excluded] == ["M1"]


def test_exclude_policy_without_frozen_disposition_still_counts_invalid():
    result = aggregate(_registry(policy="exclude_preregistered"),
                       [_verdict("M1", "INVALID_TEST"),
                        _verdict("M2", "PASS"), _verdict("M3", "FAIL")])
    assert result["denominator"] == 3
    assert result["numerator"] == 1


def test_ineligible_mission_excluded_from_denominator_but_registered():
    registry = _registry(missions=[
        {"mission_id": "M1", "scenario_id": "S1", "eligible": True},
        {"mission_id": "M2", "scenario_id": "S1", "eligible": False},
        {"mission_id": "M3", "scenario_id": "S1", "eligible": True}])
    result = aggregate(registry, [_verdict("M1", "PASS"), _verdict("M3", "FAIL")])
    assert result["registered"] == 3
    assert result["denominator"] == 2
    assert result["value"] == pytest.approx(1 / 2)


def test_denominator_zero_when_no_eligible_missions():
    registry = _registry(missions=[
        {"mission_id": "M1", "scenario_id": "S1", "eligible": False}])
    result = aggregate(registry, [])
    assert result["denominator"] == 0
    assert result["value"] is None
