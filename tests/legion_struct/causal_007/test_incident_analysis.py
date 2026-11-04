"""Incident b1-GAIA-EXE 429-storm analysis (E6b item 5).

Recomputes the effective request rates from the preserved incident
provider log (trimmed projection in incident/, same 193 records and
field values for t_start_mono / http_status / transport_retries /
attempts as b1_exe_incident/provider_log.jsonl) and prints the report.

Finding: in ~994 s the fleet issued only 193 agent calls (0.194/s,
11.6/min), but the pre-isolation retry path amplified them to 1280
upstream requests (1.29/s, 6.6x amplification); 179 of 193 calls burned
their entire 7-attempt budget and still failed. The fix is provider
isolation (NimTransport global cooldown + Retry-After floor inside the
live attempt), not a slower caller.
"""
import json
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.local]
HERE = Path(__file__).resolve().parent


def test_incident_b1_exe_429_storm_rates(capsys):
    import sys
    sys.path.insert(0, str(HERE))
    from incident_analysis import analyse
    report = analyse(HERE / "incident" / "b1_exe_provider_log.trimmed.jsonl")
    print(json.dumps(report, indent=1))
    # The preserved log has 193 records (the incident memo's 183/168 was
    # an early partial capture; the file itself says 178x429 + 1x502).
    assert report["records"] == 193
    assert report["http_429"] == 178
    assert report["http_200"] == 14
    assert report["http_5xx"] == 1
    # Every failed call exhausted its full retry budget (7 attempts).
    assert report["attempts_histogram"] == {
        "1": 9, "2": 1, "3": 2, "4": 1, "6": 1, "7": 179}
    assert report["total_upstream_attempts"] == 1280
    assert report["total_transport_retries"] == 1087
    assert report["exhausted_budget_calls"] == 179
    # Effective rates over the ~994 s storm window.
    assert 900.0 < report["span_s"] < 1100.0
    assert 0.15 < report["agent_call_rate_per_s"] < 0.25
    assert 1.2 < report["upstream_request_rate_per_s"] < 1.4
    assert 6.0 < report["retry_amplification"] < 7.0
    out = capsys.readouterr().out
    assert "upstream_request_rate_per_s" in out
