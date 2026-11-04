"""WO008-05 repaired ATTEMPT-INTEGRITY invariant audit over one run directory (read-only).

Legacy purpose (preserved): independent audit of
  I1 WorldStarts(attempt_uid) <= 1
  I2 every event carries attempt_uid + world_instance_id, one value each, strictly monotonic seq per log
  I3 Terminal(attempt) => no further mutations
  I4 CommittedEffect => valid attempt_uid & authorized world_instance_id
  I5 agent START once per worker

WO008-05 repair of I3
--------------------
The legacy implementation read the terminal time from ATTEMPT*.json(state +
``mono``) but in practice the owner-written ATTEMPT_LOG records carry only
wall-clock ``t``, while WORLD_LOG mutations carry monotonic ``t_mono``.
Comparing those two numbers directly is meaningless and fabricated I3
verdicts (both false PASS and false FAIL).

Repaired rule (fail-closed, three-valued):
  * I3 = "T" only under a genuinely comparable, authenticated terminal clock
    (terminal record carries ``t_mono``/``mono`` and its hash chain verifies
    and its MAC verifies against caller-supplied authoritative TEST material)
    or under a proven event-order bridge (an authenticated terminal
    ``world_seq`` watermark, or a terminal marker inside the totally ordered
    WORLD_LOG itself), and only when no later mutation exists.
  * I3 = "F" when such a comparable ordering proves a native mutation
    (NATIVE_EFFECT / RECEIPT in WORLD_LOG, or gate EXECUTED commit) happened
    after the terminal.
  * I3 = "Z" (unknown) in every other case: no terminal, incomparable clocks
    (wall ``t`` vs unrelated ``t_mono``), an unverified/failed MAC, a broken
    hash chain, duplicate/out-of-order records, or ambiguous attempt/world
    identity.  Z is never reported as PASS.

An unverified MAC is never treated as verified: if no authoritative TEST
verification material (``attempt_key``) is supplied, MAC status is reported
as ``unverified`` and cannot authenticate a terminal clock.

Callable evaluator: ``evaluate_attempt_integrity(run_dir, attempt_key=None)``
(also ``evaluate_attempt_i3``). Legacy CLI preserved:
  python3 -I wo008_attempt_audit.py RUN_DIR OUT_JSON [--test-key-hex HEX]
The optional TEST key may also be supplied as hex via the environment
variable ``WO008_TEST_ATTEMPT_KEY_HEX``. Only isolated TEST keys may be used;
never pass real credentials.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import hmac
import json
import os
import pathlib
import sys

TERMINAL_STATES = frozenset({"COMPLETED", "INTERRUPTED", "INVALID", "ABORTED"})
GENESIS_HASH = "0" * 64
MUTATION_KINDS = frozenset({"NATIVE_EFFECT", "RECEIPT"})
WORLD_TERMINAL_MARKERS = frozenset({"ATTEMPT_TERMINAL", "RUN_STOPPED", "TERMINAL"})


def _jl(p: pathlib.Path):
    rows = []
    if p.exists():
        for i, line in enumerate(p.read_bytes().split(b"\n"), 1):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except ValueError:
                rows.append({"__unparseable_line": i})
                continue
            if isinstance(r, dict):
                r["__line"] = i
                rows.append(r)
    return rows


def _canonical(obj) -> bytes:
    # Same canonicalisation as attempt.py `_log_canonical`.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _read_attempt_records(run: pathlib.Path):
    """Owner-written ATTEMPT_LOG first; legacy ATTEMPT*.json/.jsonl fallback."""
    primary = run / "ATTEMPT_LOG.jsonl"
    if primary.exists():
        return _jl(primary), "ATTEMPT_LOG.jsonl"
    recs = []
    for p in sorted(run.glob("ATTEMPT*.json")) + sorted(run.glob("ATTEMPT*.jsonl")):
        if p.name == "ATTEMPT_LOG.jsonl":
            continue
        if p.suffix == ".jsonl":
            recs.extend(_jl(p))
        else:
            try:
                recs.append(json.loads(p.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                recs.append({"__unparseable_line": 0})
    return recs, "ATTEMPT*"


def _verify_attempt_records(records, attempt_key: bytes | None):
    """Validate order/identity/hash-chain/MAC. Returns (problems, info)."""
    problems: list[str] = []
    seen_seq = set()
    uids = set()
    wids = set()
    hash_present = False
    hash_ok = True
    mac_present = False
    mac_ok = True
    prev_hash = GENESIS_HASH
    for i, r in enumerate(records, 1):
        if "__unparseable_line" in r:
            problems.append(f"attempt_log line {r['__unparseable_line']}: unparseable")
            hash_ok = False
            continue
        seq = r.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            # Legacy ATTEMPT*.json single-record files carry no seq; file order stands.
            if len(records) > 1:
                problems.append(f"attempt_log record {i}: missing/invalid seq")
        else:
            if seq in seen_seq:
                problems.append(f"attempt_log record {i}: duplicate seq {seq}")
            seen_seq.add(seq)
            if seq != i:
                problems.append(f"attempt_log record {i}: out-of-order seq {seq}")
        if r.get("attempt_uid"):
            uids.add(r.get("attempt_uid"))
        else:
            problems.append(f"attempt_log record {i}: missing attempt_uid")
        if r.get("world_instance_id"):
            wids.add(r.get("world_instance_id"))
        if "hash" in r or "prev_hash" in r:
            hash_present = True
            if r.get("prev_hash") != prev_hash:
                problems.append(f"attempt_log record {i}: prev_hash mismatch")
                hash_ok = False
            payload = {k: v for k, v in r.items()
                       if k not in ("hash", "mac", "__line")}
            expect = hashlib.sha256(_canonical(payload)).hexdigest()
            if r.get("hash") != expect:
                problems.append(f"attempt_log record {i}: hash mismatch")
                hash_ok = False
            else:
                prev_hash = r.get("hash")
            if r.get("mac"):
                mac_present = True
                if attempt_key is not None:
                    expect_mac = hmac.new(attempt_key, expect.encode(),
                                          hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(str(r.get("mac")), expect_mac):
                        problems.append(f"attempt_log record {i}: MAC mismatch")
                        mac_ok = False
        # else: legacy record without a chain; integrity simply unproven.
    if len(uids) > 1:
        problems.append("attempt_log: multiple attempt_uid values")
    if len(wids) > 1:
        problems.append("attempt_log: multiple world_instance_id values")
    if mac_present and attempt_key is not None:
        mac_status = "verified" if mac_ok else "failed"
    elif mac_present:
        mac_status = "unverified"  # material not supplied; never treat as verified
    else:
        mac_status = "absent"
    info = {
        "attempt_uids": sorted(str(u) for u in uids),
        "world_instance_ids": sorted(str(w) for w in wids),
        "hash_chain_present": hash_present,
        "hash_chain_verified": bool(hash_present and hash_ok),
        "mac_status": mac_status,
    }
    return problems, info


def _world_log_integrity(rows, uid, wid):
    """Problems that make WORLD_LOG chronology unauthenticatable.

    A totally-ordered log must parse, carry an exact-int (non-bool)
    contiguous monotonic seq, non-reversed t_mono chronology, and an
    explicit identity on every record that could order a mutation or
    terminal marker. Foreign-but-explicit identities are not ambiguous
    (they are rejected as foreign elsewhere); missing/duplicate/confused
    identity is.
    """
    problems = []
    seqs = []
    prev_mono = None
    for r in rows:
        if "__unparseable_line" in r:
            problems.append(f"world_log line {r['__unparseable_line']}: unparseable")
            continue
        seq = r.get("seq")
        if type(seq) is not int:
            problems.append(f"world_log line {r.get('__line')}: missing/invalid seq")
        else:
            if seq in seqs:
                problems.append(f"world_log line {r.get('__line')}: duplicate seq {seq}")
            seqs.append(seq)
        if r.get("kind") in MUTATION_KINDS or r.get("kind") in WORLD_TERMINAL_MARKERS \
                or r.get("kind") == "WORLD_START":
            if not r.get("attempt_uid") or not r.get("world_instance_id"):
                problems.append(
                    f"world_log line {r.get('__line')}: ambiguous record identity")
        mono = r.get("t_mono")
        if _is_number(mono):
            if prev_mono is not None and float(mono) < prev_mono:
                problems.append(
                    f"world_log line {r.get('__line')}: reversed t_mono chronology")
            prev_mono = float(mono)
    if seqs:
        if seqs != sorted(seqs):
            problems.append("world_log: seq out of order")
        elif any(b - a != 1 for a, b in zip(seqs, seqs[1:])):
            problems.append("world_log: noncontiguous seq")
    return problems


def evaluate_attempt_integrity(run_dir, attempt_key: bytes | None = None) -> dict:
    """Evaluate attempt-integrity invariants for one run directory.

    ``attempt_key`` is authoritative TEST verification material for the
    ATTEMPT_LOG MAC (isolated test signer only). Without it, a present MAC
    is reported ``unverified`` and cannot authenticate a terminal clock.
    I3 is three-valued: "T" (proven), "F" (proven violation), "Z" (unknown).
    """
    run = pathlib.Path(run_dir)
    if isinstance(attempt_key, str):
        attempt_key = attempt_key.encode("utf-8")

    wl_path = run / "WORLD_LOG.jsonl"
    if not wl_path.exists() and (run / "WORLD_LOG_READBACK.jsonl").exists():
        wl_path = run / "WORLD_LOG_READBACK.jsonl"
    wl = _jl(wl_path)
    logs = {
        "WORLD_LOG.jsonl": wl,
        "GATE_COMMITS.jsonl": _jl(run / "GATE_COMMITS.jsonl"),
        "READBACK.jsonl": _jl(run / "READBACK.jsonl"),
        "CONTROLLER_EVENTS.jsonl": _jl(run / "CONTROLLER_EVENTS.jsonl"),
        "CAUSAL_CONTROLLER.jsonl": _jl(run / "CAUSAL_CONTROLLER.jsonl"),
        "provider_log.jsonl": _jl(run / "provider_log.jsonl"),
    }
    starts = [r for r in wl if r.get("kind") == "WORLD_START"]
    chk: dict = {}
    det: dict = {}
    chk["I1_single_world_start"] = (
        len(starts) == 1
        and all(v == 1 for v in collections.Counter(
            r.get("attempt_uid") for r in starts).values()))
    det["world_starts"] = [{
        "line": r.get("__line"), "pid": r.get("pid"),
        "attempt_uid": r.get("attempt_uid"),
        "world_instance_id": r.get("world_instance_id"),
        "t_mono": r.get("t_mono")} for r in starts]
    uid = starts[0].get("attempt_uid") if len(starts) == 1 else None
    wid = starts[0].get("world_instance_id") if len(starts) == 1 else None

    bad_id, unparse, seq_bad = collections.Counter(), collections.Counter(), collections.Counter()
    for name, rows in logs.items():
        prev = None
        for r in rows:
            if "__unparseable_line" in r:
                unparse[name] += 1
                continue
            if r.get("attempt_uid") != uid or (
                    name != "provider_log.jsonl"
                    and r.get("world_instance_id") not in (wid,)):
                bad_id[name] += 1
            s = r.get("seq") if name == "WORLD_LOG.jsonl" else r.get("attempt_seq", r.get("seq"))
            if isinstance(s, int) and not isinstance(s, bool):
                if prev is not None and s <= prev:
                    seq_bad[name] += 1
                prev = s
    chk["I2_identity_on_every_event"] = uid is not None and not bad_id
    chk["I2_monotonic_seq"] = not seq_bad
    chk["no_unparseable_lines"] = not unparse
    det["events_with_missing_or_foreign_identity"] = dict(bad_id)
    det["seq_regressions"] = dict(seq_bad)
    det["unparseable"] = dict(unparse)

    # --- Owner-written ATTEMPT_LOG: identity, order, hash/MAC integrity ---
    records, attempt_source = _read_attempt_records(run)
    problems, ainfo = _verify_attempt_records(records, attempt_key)
    det["attempt_log_source"] = attempt_source
    det["attempt_log_problems"] = problems
    det["attempt_log_integrity"] = ainfo
    attempt_uid = ainfo["attempt_uids"][0] if len(ainfo["attempt_uids"]) == 1 else None
    attempt_wid = (ainfo["world_instance_ids"][0]
                   if len(ainfo["world_instance_ids"]) == 1 else None)
    if uid is None:
        uid = attempt_uid
    if wid is None:
        wid = attempt_wid
    identity_ambiguous = (
        attempt_uid is None
        or (uid is not None and attempt_uid is not None and uid != attempt_uid)
        or (wid is not None and attempt_wid is not None and wid != attempt_wid)
        or len(ainfo["attempt_uids"]) != 1)
    det["attempt_uid"] = uid
    det["world_instance_id"] = wid

    terminal = None
    for r in records:
        if "__unparseable_line" in r:
            continue
        if str(r.get("state", "")).upper() in TERMINAL_STATES:
            terminal = r  # last terminal record in file order wins
    det["terminal"] = (
        {"state": str(terminal.get("state", "")).upper(),
         "event": terminal.get("event"), "seq": terminal.get("seq"),
         "t": terminal.get("t"),
         "t_mono": terminal.get("t_mono", terminal.get("mono")),
         "world_seq_at_terminal": terminal.get(
             "world_seq_at_terminal", terminal.get("world_seq"))}
        if terminal is not None else None)

    # --- Mutations, rejecting cross-attempt / cross-world records ---
    mutations, rejected_foreign = [], []
    for r in wl:
        if r.get("kind") not in MUTATION_KINDS:
            continue
        if (r.get("attempt_uid") != uid
                or (wid is not None and r.get("world_instance_id") != wid)):
            rejected_foreign.append({"log": wl_path.name, "line": r.get("__line"),
                                       "kind": r.get("kind"),
                                       "attempt_uid": r.get("attempt_uid"),
                                       "world_instance_id": r.get("world_instance_id")})
            continue
        mutations.append({"log": wl_path.name, "line": r.get("__line"),
                          "kind": r.get("kind"), "seq": r.get("seq"),
                          "t_mono": r.get("t_mono")})
    for g in logs["GATE_COMMITS.jsonl"]:
        if g.get("outcome") != "EXECUTED":
            continue
        if g.get("attempt_uid") not in (None, uid):
            rejected_foreign.append({"log": "GATE_COMMITS.jsonl",
                                     "line": g.get("__line"), "kind": "GATE_EXECUTED",
                                     "attempt_uid": g.get("attempt_uid"),
                                     "world_instance_id": g.get("world_instance_id")})
            continue
        mutations.append({"log": "GATE_COMMITS.jsonl", "line": g.get("__line"),
                          "kind": "GATE_EXECUTED", "seq": g.get("seq"),
                          "t_mono": g.get("t_end_mono", g.get("t_mono"))})
    det["rejected_foreign_records"] = rejected_foreign

    # --- I3: only genuinely comparable orderings may decide T/F ---
    world_problems = _world_log_integrity(wl, uid, wid)
    det["world_log_problems"] = world_problems
    integrity_failed = bool(problems) or bool(world_problems) or (
        ainfo["hash_chain_present"] and not ainfo["hash_chain_verified"]) \
        or ainfo["mac_status"] == "failed"
    bridge = None
    bridge_reason = None
    term_mono = None
    term_world_seq = None
    if terminal is not None:
        raw_mono = terminal.get("t_mono", terminal.get("mono"))
        if _is_number(raw_mono):
            term_mono = float(raw_mono)
        raw_wseq = terminal.get("world_seq_at_terminal", terminal.get("world_seq"))
        if isinstance(raw_wseq, int) and not isinstance(raw_wseq, bool):
            term_world_seq = raw_wseq
    authenticated = ainfo["mac_status"] == "verified" and ainfo["hash_chain_verified"]
    i3 = "Z"
    if terminal is None:
        i3, i3_reason = "Z", "TERMINAL_MISSING"
    elif identity_ambiguous:
        i3, i3_reason = "Z", "ATTEMPT_OR_WORLD_IDENTITY_AMBIGUOUS"
    elif world_problems:
        i3, i3_reason = "Z", "WORLD_LOG_INTEGRITY_UNPROVEN"
    elif integrity_failed:
        i3, i3_reason = "Z", "ATTEMPT_LOG_INTEGRITY_UNPROVEN"
    elif term_mono is not None and authenticated:
        bridge, bridge_reason = "authenticated_t_mono", "terminal t_mono with verified hash+MAC"
    elif term_world_seq is not None and authenticated:
        bridge, bridge_reason = "authenticated_world_seq", "terminal world_seq watermark with verified hash+MAC"
    else:
        # Proven event-order bridge: terminal marker in the same totally
        # ordered WORLD_LOG as the mutations (seq order, no clock compare).
        marker = None
        for r in wl:
            if (r.get("kind") in WORLD_TERMINAL_MARKERS
                    and r.get("attempt_uid") == uid
                    and (wid is None or r.get("world_instance_id") == wid)
                    and isinstance(r.get("seq"), int)):
                marker = r
        if marker is not None and ainfo["hash_chain_verified"]:
            bridge = "world_log_event_order"
            bridge_reason = "terminal marker inside totally ordered WORLD_LOG"
            term_world_seq = marker["seq"]
        elif term_mono is not None or term_world_seq is not None:
            i3_reason = "TERMINAL_CLOCK_UNAUTHENTICATED_MAC_UNVERIFIED"
        else:
            # Historical shape: wall-clock `t` only. Never compare to t_mono.
            i3_reason = "WALL_CLOCK_TERMINAL_NOT_COMPARABLE_TO_T_MONO"
    late, unorderable = [], []
    if terminal is not None and bridge is not None:
        for m in mutations:
            if bridge == "authenticated_t_mono":
                if _is_number(m.get("t_mono")):
                    if float(m["t_mono"]) > term_mono:
                        late.append(m)
                else:
                    unorderable.append(m)
            else:  # seq-based bridges
                if isinstance(m.get("seq"), int) and m["log"] == wl_path.name:
                    if m["seq"] > term_world_seq:
                        late.append(m)
                elif bridge == "authenticated_world_seq" and isinstance(m.get("seq"), int):
                    if m["seq"] > term_world_seq:
                        late.append(m)
                else:
                    unorderable.append(m)
        if late:
            i3, i3_reason = "F", "MUTATION_AFTER_TERMINAL"
        elif unorderable:
            i3, i3_reason = "Z", "MUTATION_CHRONOLOGY_UNORDERABLE"
        else:
            i3, i3_reason = "T", "NO_MUTATION_AFTER_TERMINAL"
    det["chronology_bridge"] = bridge
    det["chronology_bridge_reason"] = bridge_reason
    det["terminal_clock"] = {
        "wall_t": terminal.get("t") if terminal is not None else None,
        "t_mono": term_mono,
        "world_seq_at_terminal": term_world_seq,
        "mac_status": ainfo["mac_status"],
        "wall_t_compared_to_t_mono": False,
    }
    det["mutations_after_terminal"] = late
    det["mutations_unorderable"] = unorderable
    det["i3_reason"] = i3_reason
    chk["I3_no_mutation_after_terminal"] = i3

    eff = [r for r in wl if r.get("kind") in MUTATION_KINDS]
    chk["I4_effects_bound_to_attempt_and_world"] = uid is not None and all(
        r.get("attempt_uid") == uid and r.get("world_instance_id") == wid for r in eff)
    starts_per_agent = collections.Counter()
    for p in run.glob("agent_*.jsonl"):
        starts_per_agent[p.name] = sum(1 for r in _jl(p) if r.get("event") == "START")
    chk["I5_agent_started_once"] = bool(starts_per_agent) and all(
        v == 1 for v in starts_per_agent.values())
    det["agents_started_more_than_once"] = {
        k: v for k, v in starts_per_agent.items() if v != 1}

    bool_checks = [v for k, v in chk.items()
                   if not k.startswith("I3") and isinstance(v, bool)]
    if i3 == "T" and all(bool_checks):
        verdict = "ATTEMPT_INTEGRITY_GO"
    elif i3 == "F":
        verdict = "ATTEMPT_INTEGRITY_NO_GO"
    elif i3 == "Z":
        # Chronology unknown: never GO; indeterminate takes precedence so a
        # Z is not silently flattened into either PASS or a proven NO_GO.
        verdict = "ATTEMPT_INTEGRITY_INDETERMINATE"
    else:
        verdict = "ATTEMPT_INTEGRITY_NO_GO"
    return {"run": str(run), "checks": chk, "details": det, "verdict": verdict}


def evaluate_attempt_i3(run_dir, attempt_key: bytes | None = None) -> dict:
    """Return only the repaired I3 determination (T / F / Z) with its basis."""
    res = evaluate_attempt_integrity(run_dir, attempt_key=attempt_key)
    det = res["details"]
    return {"I3": res["checks"]["I3_no_mutation_after_terminal"],
            "reason": det["i3_reason"], "bridge": det["chronology_bridge"],
            "terminal": det["terminal"], "terminal_clock": det["terminal_clock"],
            "mac_status": det["attempt_log_integrity"]["mac_status"],
            "hash_chain_verified": det["attempt_log_integrity"]["hash_chain_verified"],
            "mutations_after_terminal": det["mutations_after_terminal"],
            "rejected_foreign_records": det["rejected_foreign_records"],
            "world_log_problems": det.get("world_log_problems", []),
            "attempt_log_problems": det["attempt_log_problems"]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="ATTEMPT-INTEGRITY invariant audit (WO008-05 repaired I3)")
    parser.add_argument("run_dir")
    parser.add_argument("out_json")
    parser.add_argument("--test-key-hex", default=None,
                        help="isolated TEST ATTEMPT_LOG key, hex-encoded")
    args = parser.parse_args(argv)
    key = None
    key_hex = args.test_key_hex or os.environ.get("WO008_TEST_ATTEMPT_KEY_HEX")
    if key_hex:
        key = bytes.fromhex(key_hex)
    res = evaluate_attempt_integrity(args.run_dir, attempt_key=key)
    pathlib.Path(args.out_json).write_text(
        json.dumps(res, indent=1, default=str), encoding="utf-8")
    print(json.dumps({"verdict": res["verdict"], "checks": res["checks"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
