"""Incident b1-GAIA-EXE HTTP-429 storm analysis (WO-007, E6b item 5).

Computes, from a provider_log.jsonl (one record per agent call), the
effective request rates the incident actually produced:

  * agent-call rate      = records / span(t_start_mono)
  * upstream request     = sum(attempts) / span(t_start_mono)
    rate                   (the proxy amplified each call by its retries)
  * retry amplification  = sum(attempts) / records
  * exhausted-budget share = records with attempts == max attempts that
    still ended in a transport status (429/5xx)

The incident narrative (CLAUDE_INCIDENT_B1_EXE.md) cites 183 calls /
168x429 from an early partial capture. The preserved provider_log.jsonl
contains 193 records / 178x429 / 14x200 / 1x502; the trimmed projection
(incident/b1_exe_provider_log.trimmed.jsonl, fields t_start_mono,
http_status, transport_retries, attempts, in file order) reproduces those
figures exactly and is what the regression test runs against, since the
sandbox can only see the worktree copy. Run standalone on the full log
for identical results:

    python -I incident_analysis.py <provider_log.jsonl>
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def analyse(path) -> dict:
    records = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    statuses = Counter(int(r.get("http_status") or 0) for r in records)
    attempts = [int(r.get("attempts") or 1) for r in records]
    starts = [float(r["t_start_mono"]) for r in records
              if r.get("t_start_mono") is not None]
    span_s = (max(starts) - min(starts)) if len(starts) >= 2 else 0.0
    max_attempts = max(attempts) if attempts else 0
    exhausted = sum(1 for r, a in zip(records, attempts)
                    if a == max_attempts and
                    (int(r.get("http_status") or 0) == 429 or
                     int(r.get("http_status") or 0) >= 500))
    n = len(records)
    total_upstream = sum(attempts)
    return {
        "records": n,
        "status_counts": {str(k): statuses[k] for k in sorted(statuses)},
        "http_429": statuses.get(429, 0),
        "http_200": statuses.get(200, 0),
        "http_5xx": sum(v for k, v in statuses.items() if k >= 500),
        "span_s": round(span_s, 3),
        "total_upstream_attempts": total_upstream,
        "total_transport_retries": sum(
            int(r.get("transport_retries") or 0) for r in records),
        "agent_call_rate_per_s": (n / span_s) if span_s else None,
        "agent_call_rate_per_min": (60.0 * n / span_s) if span_s else None,
        "upstream_request_rate_per_s": (total_upstream / span_s) if span_s else None,
        "retry_amplification": (total_upstream / n) if n else None,
        "max_attempts_per_call": max_attempts,
        "exhausted_budget_calls": exhausted,
        "attempts_histogram": {str(k): v for k, v in
                               sorted(Counter(attempts).items())},
    }


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: incident_analysis.py <provider_log.jsonl>",
              file=sys.stderr)
        return 2
    print(json.dumps(analyse(argv[0]), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
