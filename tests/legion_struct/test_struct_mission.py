"""LEGION structural mission host — pytest wrapper ONLY (E6b).

The real campaign host is causal_007/mission_host.py, run directly by
causal_007/supervisor.py with no pytest in the path. This file remains so
existing unit/qualification tests can drive the same host through pytest
fixtures; it contains no world lifecycle logic of its own.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "causal_007"))

from causal_007.mission_host import World, make_build_factory, run_mission  # noqa: E402,F401

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.eu_ecb]


@pytest.fixture
async def build(monkeypatch):
    """Thin pytest adapter over mission_host.make_build_factory.

    The factory itself is pytest-free (ShimPatch-compatible interface);
    only this wrapper knows about pytest.
    """
    _build, _cleanup = make_build_factory(monkeypatch)
    yield _build
    await _cleanup()


async def test_struct_mission(build, monkeypatch, tmp_path):
    # Fresh run dir per test: the host (correctly) refuses to re-enter a
    # run directory that already contains a WORLD_START. Callers that pass
    # their own STRUCT_OUT/STRUCT_RUN_ID (integration harness, meta_qual)
    # keep them.
    import hashlib
    import json
    import os
    import uuid
    # E6e: no admit-without-authority mode. This pytest wrapper is the
    # unit/qualification harness, so it acts as the supervisor-equivalent
    # registrar: it registers the attempt (attempt.json evidence), then
    # constructs an explicit TEST authority (the sanctioned test path)
    # holding that exact identity, and only then drives the mission.
    # When the harness has already registered an attempt identity (env
    # or attempt evidence file), the TEST authority adopts that exact
    # identity -- the same registration flow the supervisor performs --
    # so gate/world evidence carries the registered attempt_uid and
    # world_instance_id rather than a divergent wrapper-local one.
    sys.path.insert(0, str(HERE / "causal_007"))
    import attempt as attempt_mod
    import attempt_authority as auth_mod
    from attempt_authority import TestAuthority

    if "STRUCT_OUT" not in os.environ:
        monkeypatch.setenv("STRUCT_OUT", str(tmp_path))
    if "STRUCT_RUN_ID" not in os.environ:
        monkeypatch.setenv("STRUCT_RUN_ID", "struct-run-test")
    run_dir = Path(os.environ["STRUCT_OUT"]) / os.environ["STRUCT_RUN_ID"]

    if os.environ.get(auth_mod.ENV_URL):
        # A live attempt authority is already provided by the harness
        # (supervisor/qualification). NEVER shadow it with a wrapper-local
        # authority: the gate, the VEIP warrants and the world must all
        # bind to the one authorized attempt_uid/world_instance_id, and
        # the harness retains lifecycle control (transitions, key
        # destruction). The wrapper only stamps the live identity into
        # the mission env; registration remains the harness's job.
        st = auth_mod.client_from_env("gate").status()
        if not os.environ.get("STRUCT_ATTEMPT_UID"):
            monkeypatch.setenv("STRUCT_ATTEMPT_UID", st["attempt_uid"])
        if not os.environ.get("STRUCT_WORLD_INSTANCE_ID"):
            monkeypatch.setenv("STRUCT_WORLD_INSTANCE_ID",
                               st["world_instance_id"])
        rc = await run_mission(build, monkeypatch)
        assert rc == 0
        return
    def _registered_identity():
        uid = os.environ.get("STRUCT_ATTEMPT_UID") or None
        wid = os.environ.get("STRUCT_WORLD_INSTANCE_ID") or None
        candidates = []
        if os.environ.get("STRUCT_ATTEMPT_FILE"):
            candidates.append(Path(os.environ["STRUCT_ATTEMPT_FILE"]))
        candidates.append(run_dir / attempt_mod.ATTEMPT_FILE)
        for cand in candidates:
            if uid and wid:
                break
            try:
                rec = json.loads(cand.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            uid = uid or rec.get("attempt_uid")
            wid = wid or rec.get("world_instance_id")
        return uid, wid

    _uid, _wid = _registered_identity()
    existing = attempt_mod.read_attempt(run_dir)
    needs_start = existing is None or existing.get("state") == attempt_mod.REGISTERED
    if existing is None:
        world_env = os.environ.get("STRUCT_WORLD")
        if world_env and Path(world_env).exists():
            world_sha = hashlib.sha256(Path(world_env).read_bytes()).hexdigest()
        else:
            world_sha = "0" * 64
        try:
            rec = attempt_mod.register(
                run_dir,
                campaign_id=os.environ.get("STRUCT_CAMPAIGN", "pytest-harness"),
                run_id=os.environ["STRUCT_RUN_ID"],
                world_sha256=world_sha,
                runtime_sha=attempt_mod.runtime_sha256(HERE.parent.parent))
            _uid = _uid or rec["attempt_uid"]
        except attempt_mod.AttemptAlreadyRegistered:
            existing = attempt_mod.read_attempt(run_dir)
            needs_start = existing is not None and \
                existing.get("state") == attempt_mod.REGISTERED
            _uid, _wid = _registered_identity()
    authority = TestAuthority(attempt_uid=_uid, world_instance_id=_wid)
    try:
        if needs_start:
            token = uuid.uuid4().hex
            attempt_mod.start_running(
                run_dir, capability_token=token,
                world_instance_id=authority.world_instance_id)
            try:
                attempt_mod.write_capability(run_dir, token)
            except FileExistsError:
                pass
        for key, value in authority.env(role="world").items():
            monkeypatch.setenv(key, value)
        monkeypatch.setenv("STRUCT_ATTEMPT_UID", authority.attempt_uid)
        monkeypatch.setenv("STRUCT_WORLD_INSTANCE_ID",
                           authority.world_instance_id)
        rc = await run_mission(build, monkeypatch)
        assert rc == 0
    finally:
        authority.stop()
