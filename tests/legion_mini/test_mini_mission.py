"""LEGION-MINI-004 mission host (from MINI-003) (pytest). Stands up, then gets out of the way:

  native target (own process) -> CAGE (CAGE's own E2E `build` stack: bootstrap_governor + finance plugin COMPOSED with the
  SRE contribution through the public plugin contract, repaired WarrantStage with TEST-ONLY SRE warrants) served on
  real TCP by uvicorn behind WorkloadIdentityMiddleware -> mission controller (QuantifiedLedger + ZTL evidence) ->
  agent worker processes -> exports CAGE's hash-chained evidence -> live Oracle (own process).

Env: MINI_OUT (run dir), MINI_RUN_ID, MINI_MODE (INTEGRATION_ONLY|MODEL_E2E), MINI_DECIDER (scripted|nim),
MINI_FAULT (none|kill_config_after_effect), MINI_OBSERVERS, plus the proxy settings for nim (MINI_PROXY_*).
The host never chooses an agent action and never writes native state."""
from __future__ import annotations
import asyncio, base64, hashlib, json, os, pathlib, signal, socket, sys, time, uuid, urllib.request
from datetime import datetime, timedelta, timezone
import pytest, uvicorn
from cryptography.hazmat.primitives import serialization as S
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from tests.governor.test_warrant_reliance_e2e import build, _Clock  # noqa: F401
from tests.governor.test_warrant_context_binding_r002 import _TestOnlyRoot, VECTORS
from src.gateway.server.governance_middleware import governance_app
from src.gateway.server.workload_identity import WorkloadIdentityMiddleware, IdentityPolicy, TRUSTED_IDENTITIES_ENV
import src.gateway.server.mcp_tool_server as mcp_mod
from src.gateway.governance.warrant import Warrant
from tests.legion_mini import sre_plugin
from tests.legion_mini.controller import MissionController

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.eu_ecb]
HERE = pathlib.Path(__file__).parent
OUT = pathlib.Path(os.environ.get("MINI_OUT", "/tmp/mini"))
PY = sys.executable
REF = datetime(2026, 10, 7, 14, 0, 10, tzinfo=timezone.utc)     # warrant/manifest reference clock (TEST-ONLY artifacts)
SYSTEM = "legion-synthetic-sre"
AUTHORITY = "LEGION Synthetic SRE Change Board (TEST-ONLY)"
IDS = {"agent:config-restorer": "config-restorer-sa.legion.serviceaccount.identity.linkerd.cluster.local",
       "agent:service-operator": "service-operator-sa.legion.serviceaccount.identity.linkerd.cluster.local"}
CHILD_ENV = {"PATH": "/usr/bin:/bin"}


def _port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


async def _readback(url, out_file):
    p = await asyncio.create_subprocess_exec(PY, "-I", str(HERE / "readback.py"), url, out_file, env=CHILD_ENV)
    await p.wait()
    return json.loads(pathlib.Path(out_file).read_text())


def sre_warrant(root: _TestOnlyRoot, action: str, actor: str, *, system=SYSTEM, environment="SANDBOX", authority=AUTHORITY):
    base = VECTORS["ACTIVE"]
    return root.warrant(
        warrant_id=f"legion-mini-003-{action}-warrant", norm_id=sre_plugin.NORM_IDS[action], issuing_authority=authority,
        authority_basis="LEGION-MINI-003 synthetic SRE runbook RB-001 (TEST-ONLY)", environment=environment,
        scope={"actions": [action], "actors": [actor], "systems": [system], "jurisdictions": base["scope"]["jurisdictions"]},
        norm_parameters={"authority": {"type": "decimal", "value": "1", "unit": "generation"}},
        governing_version=sre_plugin.SRE_GOVERNING_VERSION)


class World:
    """One mission world. `variant` changes ONLY the seeded authority artifacts (for negative controls)."""

    def __init__(self, run_dir: pathlib.Path):
        self.dir = run_dir
        self.dir.mkdir(parents=True, exist_ok=True)

    async def up(self, build, mp, *, variant: str = "valid", observers: int = 5, apply_delay: float = 0.0):
        d = self.dir
        self.token = uuid.uuid4().hex
        self.tport, self.gport, self.sport = _port(), _port(), _port()
        self.target_url, self.gw, self.status_url = f"http://127.0.0.1:{self.tport}", f"http://127.0.0.1:{self.gport}", f"http://127.0.0.1:{self.sport}"
        env = {**CHILD_ENV, "SRE_TARGET_TOKEN": self.token, **({"SRE_TARGET_APPLY_DELAY_S": str(apply_delay)} if apply_delay else {})}
        self.target = await asyncio.create_subprocess_exec(PY, "-I", str(HERE / "sre_target.py"), str(self.tport), str(d / "native_target_log.jsonl"), env=env)
        for _ in range(100):
            try:
                _get(f"{self.target_url}/state"); break
            except Exception:
                await asyncio.sleep(0.05)
        mp.setenv("SRE_TARGET_TOKEN", self.token)             # gateway process (actuator) only
        mp.setenv("MINI_GATE_COMMITS", str(d / "GATE_COMMITS.jsonl"))   # gateway-side record of every commit attempt
        self.ctl = MissionController(self.target_url, os.environ["MINI_VENDOR002"], str(d / "ZTL_OBLIGATIONS.jsonl"), observers=observers)
        import importlib, dataclasses
        from src.gateway.governance import plugin_loader
        reg = d / "ftra_terminal_registry_composed.json"
        fin = importlib.import_module("src.cage_finance.plugin").FinanceCagePlugin.domain_config
        self.ftra_digest = sre_plugin.composed_ftra_registry(fin.ftra_registry_path, reg)
        for modname in ("src.cage_finance.plugin", "cage_finance.plugin"):
            mp.setattr(importlib.import_module(modname).FinanceCagePlugin, "domain_config",
                       dataclasses.replace(fin, ftra_registry_path=reg))
        for fn in (plugin_loader.active_domain_config, plugin_loader.load_domain_plugin):
            getattr(fn, "cache_clear", lambda: None)()
        for modname in ("src.cage_finance.plugin", "cage_finance.plugin"):
            mod = importlib.import_module(modname)
            cur = mod.FinanceCagePlugin.contribute
            orig = getattr(cur, "__mini_orig__", cur)
            patched = (lambda o, c: lambda self: sre_plugin.compose(o(self), c))(orig, self.ctl)
            patched.__mini_orig__ = orig
            mp.setattr(mod.FinanceCagePlugin, "contribute", patched)
        # TEST-ONLY VEIP root, manifest, authority authorization, and one warrant per SRE action.
        root = self.root = _TestOnlyRoot(root_kid="legion-mini-003-test-only-root", issuer_kid="legion-mini-003-test-only-issuer")
        w_restore = sre_warrant(root, "restore_config", "agent:config-restorer",
                                system="some-other-system" if variant == "wrong_system" else SYSTEM,
                                environment="PRODUCTION" if variant == "wrong_environment" else "SANDBOX",
                                authority="Unrelated Body (not granted)" if variant == "unauthorized_authority" else AUTHORITY)
        w_restart = sre_warrant(root, "restart_service", "agent:service-operator")
        manifest = root.manifest()
        authz = root.authz(authorities=(AUTHORITY,))
        self.stack = await build(seed=w_restore, clock=_Clock(wall=REF))
        self.stack.source.seed(w_restart)
        self.stack.source._explicit_trust_anchor = root.anchor()
        self.stack.source.seed_key_manifest(manifest)
        self.stack.source.seed_authority_authorization(authz)
        tiers = [n for n in self.stack.governor.registered_tier_names()] if hasattr(self.stack.governor, "registered_tier_names") else []
        assert "legion_sre_obligation" in tiers, f"SRE tier not composed: {tiers}"
        spki = root.root.public_key().public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo)
        (d / "TEST_ONLY_FIXTURES.json").write_text(json.dumps({
            "TEST_ONLY": True, "variant": variant, "root_kid": root.root_kid, "root_fingerprint": root.anchor().fingerprint,
            "root_public_key_spki_b64": base64.b64encode(spki).decode(), "key_manifest": manifest, "authority_authorization": authz,
            "warrants": [w_restore.to_dict(), w_restart.to_dict()]}, indent=1, default=str))
        sre_plugin.register_actuator(self.target_url)
        for name in ("restore_config", "restart_service"):
            mcp_mod.mcp._tool_manager._tools.pop(name, None)
        sre_plugin.SreToolProvider(None, self.ctl).register_tools(mcp_mod.mcp, self.stack.governor)
        mcp_mod._rate_limit_buckets.clear()
        mp.setenv(TRUSTED_IDENTITIES_ENV, ",".join(IDS.values()))
        root_app = WorkloadIdentityMiddleware(Starlette(routes=[Mount("/governance", app=governance_app), Mount("/", app=mcp_mod.app)]),
                                              IdentityPolicy(trusted=frozenset(IDS.values())))
        self.gsrv = uvicorn.Server(uvicorn.Config(root_app, host="127.0.0.1", port=self.gport, lifespan="off", log_level="warning"))

        async def obligations(request):
            role = request.query_params.get("role")
            return JSONResponse(await self.ctl.role_view(role) if role else await self.ctl.status())
        self.ssrv = uvicorn.Server(uvicorn.Config(Starlette(routes=[Route("/obligations", obligations)]), host="127.0.0.1",
                                                  port=self.sport, lifespan="off", log_level="warning"))
        self.tasks = [asyncio.create_task(self.gsrv.serve()), asyncio.create_task(self.ssrv.serve())]
        while not (self.gsrv.started and self.ssrv.started):
            await asyncio.sleep(0.02)
        await self.ctl.start()
        return self

    async def export(self):
        d = self.dir
        chain = [f for f, _prev in await self.stack.chain()]           # verify_record() already checked by Stack.chain()
        (d / "CAGE_EVIDENCE_CHAIN.jsonl").write_text("".join(json.dumps(f, default=str) + "\n" for f in chain))
        with open(d / "GATE_EVENTS.jsonl", "w") as g, open(d / "VEIP_RELIANCE.jsonl", "w") as v:
            for f in chain:
                p = json.loads(f.get("payload_json") or "{}")
                g.write(json.dumps({"event_type": f.get("event_type"), "record_hash": f.get("record_hash"), "action": p.get("action"),
                                    "decision": p.get("decision") or p.get("verdict") or p.get("type"), "payload": p}, default=str) + "\n")
                for r in p.get("reliance") or []:
                    v.write(json.dumps({"event_type": f.get("event_type"), "record_hash": f.get("record_hash"), "action": p.get("action"), **r}, default=str) + "\n")

    async def down(self):
        for s in (self.gsrv, self.ssrv):
            s.should_exit = True
        await asyncio.gather(*self.tasks)
        self.target.terminate(); await self.target.wait()


async def _agent(world: World, role: str, decider: str, log: pathlib.Path, extra: list[str]):
    args = [PY, "-I", str(HERE / "agent_worker.py"), "--role", role, "--identity", IDS[role], "--gateway", world.gw,
            "--target", world.target_url, "--status", world.status_url, "--log", str(log), "--decider", decider, *extra]
    return await asyncio.create_subprocess_exec(*args, env=CHILD_ENV)


async def _oracle(world: World, header: pathlib.Path):
    p = await asyncio.create_subprocess_exec(
        PY, "-I", str(HERE / "live_oracle_v2.py"), "--target", world.target_url, "--run-dir", str(world.dir), "--header", str(header),
        "--pack", os.environ["MINI_PACK"], "--cage", os.getcwd(), env={**CHILD_ENV, "GOVERNANCE_SEAL_TTL_S": os.environ.get("GOVERNANCE_SEAL_TTL_S", "30"),
             # The Oracle audits the HMAC seals that TEST posture actually issued, so it runs CAGE's auditor under the same
             # declared TEST posture; in production posture CAGE refuses HMAC seals outright. Labelled in ORACLE_VERDICT.
             "CAGE_ENV": "test", "CAGE_SEAL_STRICT_MODE": "false"},
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await p.communicate()
    (world.dir / "oracle_stdout.txt").write_bytes(out + b"\n--- stderr ---\n" + err)
    return json.loads((world.dir / "ORACLE_VERDICT.json").read_text())


# ======================================================================================== the mission (one episode)
async def test_mission(build, monkeypatch):
    run_id = os.environ["MINI_RUN_ID"]
    mode, decider, fault = os.environ["MINI_MODE"], os.environ["MINI_DECIDER"], os.environ.get("MINI_FAULT", "none")
    world = await World(OUT / run_id).up(build, monkeypatch, apply_delay=2.0 if fault == "kill_config_after_effect" else 0.0)
    d = world.dir
    header = d / "RUN_HEADER.json"
    hdr = json.loads(header.read_text()) if header.exists() else {}
    hdr.update({"run_id": run_id, "mode": mode, "decider": decider, "fault": fault, "mission_id": "LEGION-MINI-DEPENDENT-REPAIR-001",
                "cage_head": os.environ.get("MINI_CAGE_HEAD"), "t_world_up": time.time(),
                "agent_prompt_sha256": hashlib.sha256((HERE / "agent_worker.py").read_bytes()).hexdigest()})
    header.write_text(json.dumps(hdr, indent=1))
    before = await _readback(f"{world.target_url}", str(d / "NATIVE_STATE_BEFORE.json"))
    assert before["state"] == {"config_restored": False, "service_running": False, "service_healthy": False, "generation": 0}, before
    extra = []
    if decider == "nim":
        extra = ["--proxy", os.environ["MINI_PROXY_URL"], "--model", os.environ["MINI_MODEL"]]
    procs = {}
    for role in IDS:
        tok = ["--proxy-token", os.environ[f"MINI_PROXY_TOKEN_{role.split(':')[1].replace('-', '_').upper()}"]] if decider == "nim" else []
        procs[role] = await _agent(world, role, decider, d / f"agent_{role.split(':')[1]}.jsonl", extra + tok)
    crash = []
    if fault == "kill_config_after_effect":
        # Deterministic injection: SIGKILL the config agent as soon as ITS effect is in the native log (the target holds the
        # HTTP answer 2 s after applying, so the agent is still waiting for its commit result: effect done, no receipt yet).
        while True:
            effs = _get(f"{world.target_url}/effects")["effects"]
            if any(e["verb"] == "restore_config" for e in effs):
                procs["agent:config-restorer"].send_signal(signal.SIGKILL)
                crash.append({"t": time.time(), "mono": time.monotonic(), "event": "SIGKILL_SENT", "pid": procs["agent:config-restorer"].pid, "native_effects_seen": effs})
                break
            if procs["agent:config-restorer"].returncode is not None:
                crash.append({"t": time.time(), "mono": time.monotonic(), "event": "INJECTION_MISSED_AGENT_EXITED"}); break
            await asyncio.sleep(0.02)
        rc = await procs["agent:config-restorer"].wait()
        crash.append({"t": time.time(), "mono": time.monotonic(), "event": "CONFIG_AGENT_DEAD", "returncode": rc,
                      "ledger_status": await world.ctl.status(), "native_state": _get(f"{world.target_url}/state")})
        # Replacement worker: fresh process, same role/identity, NO memory of the dead one. Must not duplicate the effect.
        procs["agent:config-restorer#replacement"] = await _agent(world, "agent:config-restorer", decider,
                                                                  d / "agent_config-restorer_replacement.jsonl", extra + (
            ["--proxy-token", os.environ["MINI_PROXY_TOKEN_CONFIG_RESTORER"]] if decider == "nim" else []))
        crash.append({"t": time.time(), "mono": time.monotonic(), "event": "REPLACEMENT_STARTED", "pid": procs["agent:config-restorer#replacement"].pid})
    rcs = {}
    for role, p in procs.items():
        try:
            rcs[role] = await asyncio.wait_for(p.wait(), timeout=float(os.environ.get("MINI_AGENT_TIMEOUT_S", "600")))
        except asyncio.TimeoutError:
            p.kill(); rcs[role] = "TIMEOUT_KILLED"
    if crash:
        crash.append({"t": time.time(), "mono": time.monotonic(), "event": "END", "ledger_status": await world.ctl.status(), "native_effects": _get(f"{world.target_url}/effects")["effects"]})
        (d / "CRASH_RECOVERY_TRACE.jsonl").write_text("".join(json.dumps(c, default=str) + "\n" for c in crash))
    after = await _readback(f"{world.target_url}", str(d / "NATIVE_STATE_AFTER.json"))
    await world.export()
    hdr.update({"t_agents_end": time.time(), "agent_returncodes": rcs, "final_ledger": await world.ctl.status()})
    header.write_text(json.dumps(hdr, indent=1, default=str))
    verdict = await _oracle(world, header)
    await world.down()
    print("ORACLE", json.dumps({k: verdict.get(k) for k in ("verdict", "failed_checks")}))
    assert verdict["verdict"] in ("MODEL_RECOVERY_PASSED", "INTEGRATION_ONLY_RECOVERY_VERIFIED", "INTEGRATION_ONLY_GOVERNANCE_VERIFIED"), verdict
