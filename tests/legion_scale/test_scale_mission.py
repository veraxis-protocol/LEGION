"""LEGION scale mission host (pytest). Pattern of tests/legion_mini/test_mini_mission.py World.

Env: SCALE_MANIFEST, SCALE_OUT, SCALE_RUN_ID, SCALE_MODE (INTEGRATION_ONLY|MODEL_E2E),
SCALE_DECIDER (scripted|nim), SCALE_PROXY_URL, SCALE_MODEL, SCALE_AGENT_TIMEOUT_S, proxy tokens
SCALE_PROXY_TOKEN_<AGENT> / SCALE_PROXY_TOKEN. Host never chooses an agent action."""
from __future__ import annotations
import asyncio, base64, hashlib, json, os, pathlib, socket, sys, time, urllib.request
from datetime import datetime, timezone
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
from tests.legion_scale import scale_plugin
from tests.legion_scale.dag_controller import DagMissionController, load_manifest
from tests.legion_scale.scale_plugin import ScaleNodes, action_name, norm_id_for

pytestmark = [pytest.mark.unit, pytest.mark.local, pytest.mark.eu_ecb]
HERE = pathlib.Path(__file__).parent
MANIFEST_DEFAULT = HERE / "manifests" / "LEGION-10-CANARY-005.json"
OUT = pathlib.Path(os.environ.get("SCALE_OUT", "/tmp/scale"))
PY = sys.executable
REF = datetime(2026, 10, 7, 14, 0, 10, tzinfo=timezone.utc)
SYSTEM = "legion-synthetic-sre"
AUTHORITY = "LEGION Synthetic SRE Change Board (TEST-ONLY)"
CHILD_ENV = {"PATH": os.environ.get("PATH", ""), **({"SYSTEMROOT": os.environ["SYSTEMROOT"]} if os.environ.get("SYSTEMROOT") else {})}


def manifest_path() -> pathlib.Path:
    return pathlib.Path(os.environ.get("SCALE_MANIFEST", str(MANIFEST_DEFAULT)))


def _port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


async def _readback(url, out_file):
    p = await asyncio.create_subprocess_exec(PY, "-I", str(HERE / "scale_readback.py"), url, out_file, env=CHILD_ENV)
    await p.wait()
    return json.loads(pathlib.Path(out_file).read_text())


def scale_warrant(root: _TestOnlyRoot, node: dict, *, system=SYSTEM, environment="SANDBOX", authority=AUTHORITY, actor=None):
    base = VECTORS["ACTIVE"]
    return root.warrant(
        warrant_id=f"legion-scale-005-{node['obligation_id']}-warrant", norm_id=norm_id_for(node["obligation_id"]),
        issuing_authority=authority, authority_basis="LEGION scale synthetic SRE runbook (TEST-ONLY)", environment=environment,
        scope={"actions": [action_name(node["obligation_id"])], "actors": [actor or node["agent_id"]], "systems": [system],
               "jurisdictions": base["scope"]["jurisdictions"]},
        norm_parameters={"authority": {"type": "decimal", "value": "1", "unit": "generation"}},
        governing_version=scale_plugin.GOVERNING_VERSION)


def _token_env(agent_id: str) -> str:
    name = "SCALE_PROXY_TOKEN_" + "".join(ch if ch.isalnum() else "_" for ch in agent_id.replace("agent:", "")).upper()
    return os.environ.get(name) or os.environ.get("SCALE_PROXY_TOKEN", "")


class World:
    def __init__(self, run_dir: pathlib.Path, manifest=None):
        self.dir = run_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self.manifest = load_manifest(manifest or manifest_path())
        self.nodes = ScaleNodes(self.manifest)
        self.ids = {n["agent_id"]: n["workload_identity"] for n in self.manifest["nodes"]}

    async def up(self, build, mp, *, variant: str = "valid", observers: int = 5):
        d = self.dir
        self.token = __import__("uuid").uuid4().hex
        self.tport, self.gport, self.sport = _port(), _port(), _port()
        self.target_url, self.gw, self.status_url = f"http://127.0.0.1:{self.tport}", f"http://127.0.0.1:{self.gport}", f"http://127.0.0.1:{self.sport}"
        env = {**CHILD_ENV, "SRE_TARGET_TOKEN": self.token}
        self.target = await asyncio.create_subprocess_exec(PY, "-I", str(HERE / "scale_target.py"), str(self.tport),
                                                           str(d / "native_target_log.jsonl"), str(manifest_path() if not isinstance(self.manifest, dict) else self._manifest_file()), env=env)
        for _ in range(100):
            try:
                _get(f"{self.target_url}/state"); break
            except Exception:
                await asyncio.sleep(0.05)
        mp.setenv("SRE_TARGET_TOKEN", self.token)
        mp.setenv("MINI_GATE_COMMITS", str(d / "GATE_COMMITS.jsonl"))
        # Deployment env derived FROM THE MANIFEST before build()
        mp.setenv("CAGE_WARRANT_CONTEXT_BINDING", "required")
        mp.setenv("CAGE_WARRANT_ACTOR_BINDINGS", json.dumps(self.ids_reversed()))
        mp.setenv("CAGE_SYSTEM_ID", SYSTEM)
        mp.setenv("CAGE_DEPLOYMENT_ENVIRONMENT", "SANDBOX")
        mp.setenv("CAGE_WORKLOAD_IDENTITY_TRANSPORT", "unverified-header-test-only")
        mp.setenv(TRUSTED_IDENTITIES_ENV, ",".join(self.ids.values()))
        self.ctl = DagMissionController(self.manifest, self.target_url, str(d / "SCALE_EVENTS.jsonl"), observers=observers)
        import importlib, dataclasses
        from src.gateway.governance import plugin_loader
        reg = d / "ftra_terminal_registry_composed.json"
        fin = importlib.import_module("src.cage_finance.plugin").FinanceCagePlugin.domain_config
        self.ftra_digest = scale_plugin.composed_ftra_registry(fin.ftra_registry_path, reg, self.nodes)
        for modname in ("src.cage_finance.plugin", "cage_finance.plugin"):
            mp.setattr(importlib.import_module(modname).FinanceCagePlugin, "domain_config", dataclasses.replace(fin, ftra_registry_path=reg))
        for fn in (plugin_loader.active_domain_config, plugin_loader.load_domain_plugin):
            getattr(fn, "cache_clear", lambda: None)()
        for modname in ("src.cage_finance.plugin", "cage_finance.plugin"):
            mod = importlib.import_module(modname)
            cur = mod.FinanceCagePlugin.contribute
            orig = getattr(cur, "__scale_orig__", cur)
            patched = (lambda o, c, n: lambda self: scale_plugin.compose(o(self), c, n))(orig, self.ctl, self.nodes)
            patched.__scale_orig__ = orig
            mp.setattr(mod.FinanceCagePlugin, "contribute", patched)
        root = self.root = _TestOnlyRoot(root_kid="legion-scale-005-test-only-root", issuer_kid="legion-scale-005-test-only-issuer")
        nodes_list = self.manifest["nodes"]
        warrants = []
        for i, node in enumerate(nodes_list):
            kw = {}
            if i == 0 and variant == "wrong_system":
                kw["system"] = "some-other-system"
            if i == 0 and variant == "wrong_environment":
                kw["environment"] = "PRODUCTION"
            if i == 0 and variant == "wrong_authority":
                kw["authority"] = "Unrelated Body (not granted)"
            if i == 0 and variant == "warrant_scoped_other_actor":
                kw["actor"] = nodes_list[1]["agent_id"] if len(nodes_list) > 1 else "agent:other"
            warrants.append(scale_warrant(root, node, **kw))
        manifest_obj = root.manifest()
        authz = root.authz(authorities=(AUTHORITY,))
        self.stack = await build(seed=warrants[0], clock=_Clock(wall=REF))
        for w in warrants[1:]:
            self.stack.source.seed(w)
        self.stack.source._explicit_trust_anchor = root.anchor()
        self.stack.source.seed_key_manifest(manifest_obj)
        self.stack.source.seed_authority_authorization(authz)
        tiers = self.stack.governor.registered_tier_names() if hasattr(self.stack.governor, "registered_tier_names") else []
        assert "legion_scale_obligation" in tiers, f"scale tier not composed: {tiers}"
        spki = root.root.public_key().public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo)
        (d / "TEST_ONLY_FIXTURES.json").write_text(json.dumps({
            "TEST_ONLY": True, "variant": variant, "root_kid": root.root_kid, "root_fingerprint": root.anchor().fingerprint,
            "root_public_key_spki_b64": base64.b64encode(spki).decode(), "key_manifest": manifest_obj, "authority_authorization": authz,
            "warrants": [w.to_dict() for w in warrants]}, indent=1, default=str))
        scale_plugin.register_actuator(self.target_url, self.nodes)
        mcp_mod.mcp._tool_manager._tools.pop("apply_transition", None)
        scale_plugin.ScaleToolProvider(None, self.ctl, self.nodes).register_tools(mcp_mod.mcp, self.stack.governor)
        mcp_mod._rate_limit_buckets.clear()
        root_app = WorkloadIdentityMiddleware(Starlette(routes=[Mount("/governance", app=governance_app), Mount("/", app=mcp_mod.app)]),
                                              IdentityPolicy(trusted=frozenset(self.ids.values())))
        self.gsrv = uvicorn.Server(uvicorn.Config(root_app, host="127.0.0.1", port=self.gport, lifespan="off", log_level="warning"))

        async def obligations(request):
            agent = request.query_params.get("agent") or request.query_params.get("role")
            return JSONResponse(await self.ctl.role_view(agent) if agent else await self.ctl.status())
        self.ssrv = uvicorn.Server(uvicorn.Config(Starlette(routes=[Route("/obligations", obligations)]), host="127.0.0.1",
                                                  port=self.sport, lifespan="off", log_level="warning"))
        self.tasks = [asyncio.create_task(self.gsrv.serve()), asyncio.create_task(self.ssrv.serve())]
        while not (self.gsrv.started and self.ssrv.started):
            await asyncio.sleep(0.02)
        await self.ctl.start()
        return self

    def ids_reversed(self):
        return {v: k for k, v in self.ids.items()}

    def _manifest_file(self):
        p = self.dir / "MANIFEST_USED.json"
        p.write_text(json.dumps(self.manifest))
        return str(p)

    async def export(self):
        d = self.dir
        chain = [f for f, _prev in await self.stack.chain()]
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


async def _agent(world: World, node: dict, decider: str, log: pathlib.Path, extra: list[str]):
    args = [PY, "-I", str(HERE / "scale_agent.py"), "--agent-id", node["agent_id"], "--identity", node["workload_identity"],
            "--obligation", node["obligation_id"], "--target", node["target_id"], "--stage", str(node["stage"]),
            "--gateway", world.gw, "--native", world.target_url, "--status", world.status_url, "--log", str(log), "--decider", decider, *extra]
    return await asyncio.create_subprocess_exec(*args, env=CHILD_ENV)


async def _oracle(world: World, header: pathlib.Path):
    p = await asyncio.create_subprocess_exec(
        PY, "-I", str(HERE / "scale_oracle.py"), "--target", world.target_url, "--run-dir", str(world.dir), "--header", str(header),
        "--manifest", str(manifest_path()), "--cage", os.getcwd(),
        env={**CHILD_ENV, "GOVERNANCE_SEAL_TTL_S": os.environ.get("GOVERNANCE_SEAL_TTL_S", "30"), "CAGE_ENV": "test", "CAGE_SEAL_STRICT_MODE": "false"},
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await p.communicate()
    (world.dir / "oracle_stdout.txt").write_bytes(out + b"\n--- stderr ---\n" + err)
    return json.loads((world.dir / "ORACLE_VERDICT.json").read_text())


async def test_scale_mission(build, monkeypatch):
    run_id = os.environ.get("SCALE_RUN_ID", "scale-run-1")
    mode, decider = os.environ.get("SCALE_MODE", "INTEGRATION_ONLY"), os.environ.get("SCALE_DECIDER", "scripted")
    world = World(OUT / run_id, manifest_path())
    d = world.dir
    await world.up(build, monkeypatch)
    header = d / "RUN_HEADER.json"
    hdr = json.loads(header.read_text()) if header.exists() else {}
    hdr.update({"run_id": run_id, "mode": mode, "decider": decider, "scenario_id": world.manifest["scenario_id"],
           "manifest": str(manifest_path()), "cage_head": os.environ.get("SCALE_CAGE_HEAD"),
           "t_world_up": time.time(), "t_world_up_mono": time.monotonic(),
           "agent_prompt_sha256": hashlib.sha256((HERE / "scale_agent.py").read_bytes()).hexdigest()})
    header.write_text(json.dumps(hdr, indent=1))
    before = await _readback(world.target_url, str(d / "NATIVE_STATE_BEFORE.json"))
    assert before["state"] == {"stage_by_shard": world.manifest["zero_state"]["stage_by_shard"]}, before
    extra = []
    if decider == "nim":
        extra = ["--proxy", os.environ["SCALE_PROXY_URL"], "--model", os.environ["SCALE_MODEL"]]
    hdr.setdefault("t_episode_registered", time.time()); hdr.setdefault("t_episode_registered_mono", time.monotonic())
    header.write_text(json.dumps(hdr, indent=1))
    procs = {}
    with open(d / "WORKERS.jsonl", "w") as wf:
        for node in world.manifest["nodes"]:
            tok = ["--proxy-token", _token_env(node["agent_id"])] if decider == "nim" else []
            logname = "agent_" + "".join(ch if ch.isalnum() else "_" for ch in node["agent_id"]) + ".jsonl"
            p = await _agent(world, node, decider, d / logname, extra + tok)
            procs[node["agent_id"]] = p
            wf.write(json.dumps({"t": time.time(), "mono": time.monotonic(), "event": "WORKER_STARTED", "pid": p.pid,
                                 "agent_id": node["agent_id"], "obligation_id": node["obligation_id"]}) + "\n"); wf.flush()
    rcs = {}
    for agent_id, p in procs.items():
        try:
            rcs[agent_id] = await asyncio.wait_for(p.wait(), timeout=float(os.environ.get("SCALE_AGENT_TIMEOUT_S", "900")))
        except asyncio.TimeoutError:
            p.kill(); rcs[agent_id] = "TIMEOUT_KILLED"
    after = await _readback(world.target_url, str(d / "NATIVE_STATE_AFTER.json"))
    await world.export()
    hdr = json.loads(header.read_text()) if header.exists() else hdr
    hdr.update({"t_agents_end": time.time(), "agent_returncodes": rcs, "final_ledger": await world.ctl.status()})
    header.write_text(json.dumps(hdr, indent=1, default=str))
    verdict = await _oracle(world, header)
    await world.down()
    print("ORACLE", json.dumps({k: verdict.get(k) for k in ("verdict", "failed_checks")}))
    assert verdict["verdict"] in ("LEGION_SCALE_E2E_PASSED", "INTEGRATION_ONLY_SCALE_VERIFIED"), verdict
