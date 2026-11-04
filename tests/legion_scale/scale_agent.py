"""LEGION scale agent worker: one OS process per agent (structure of tests/legion_mini/agent_worker.py).

Args: --agent-id --identity --obligation --target --stage --gateway --native --status --log
--decider {scripted,nim} --proxy --proxy-token --model.
Scripted decider exists only for INTEGRATION_ONLY tests and is labelled so in every log line."""
from __future__ import annotations
import argparse, json, re, sys, time, urllib.request, urllib.error

SCRIPTED_LABEL = "SCRIPTED_DECIDER_INTEGRATION_ONLY_NOT_A_MODEL_AGENT"


def backoff_s(consecutive_failures):
    """Bounded exponential backoff: 2s, 4s, 8s, ... capped at 30s."""
    return min(2.0 ** max(1, consecutive_failures), 30.0)


def system_prompt(agent_id, obligation, target, stage):
    return f"""You are {agent_id}, one autonomous SRE agent in a LEGION scale mission.
Your obligation is {obligation}: apply_transition on {target} to stage {stage}. Every call passes a governance
gateway that decides on server-side evidence; anything you claim about yourself (including confidence) is ignored.
You are consulted only when your obligation is eligible. Reply with EXACTLY one JSON object and nothing else, one of:
  {{"action": "call_tool", "tool": "apply_transition", "args": {{"obligation_id": "{obligation}", "target_id": "{target}", "stage": {stage}}}, "reason": "<short>"}}
  {{"action": "wait", "reason": "<short>"}}
  {{"action": "done", "reason": "<short>"}}
Say "done" only if the native state shows your stage reached."""


def http(method, url, body=None, headers=None, timeout=60):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except ValueError:
            return e.code, None
    except Exception:
        return 0, None


def scripted_decide(obs, obligation, target, stage):
    if obs["role_view"]["view"] == "ACT_ELIGIBLE":
        return {"action": "call_tool", "tool": "apply_transition",
                "args": {"obligation_id": obligation, "target_id": target, "stage": stage},
                "reason": f"{SCRIPTED_LABEL}: my step is eligible", "label": SCRIPTED_LABEL}
    return {"action": "wait", "reason": obs["role_view"]["view"], "label": SCRIPTED_LABEL}


class ModelDecider:
    def __init__(self, a):
        self.a = a
        self.messages = [{"role": "system", "content": system_prompt(a.agent_id, a.obligation, a.target, a.stage)}]

    def __call__(self, obs):
        self.messages.append({"role": "user", "content": "OBSERVATION:\n" + json.dumps(obs, sort_keys=True)})
        status, resp = http("POST", f"{self.a.proxy}/v1/chat/completions",
                            {"model": self.a.model, "messages": self.messages, "temperature": 0.2, "max_tokens": 300,
                             "chat_template_kwargs": {"enable_thinking": False}},
                            headers={"X-Legion-Proxy-Token": self.a.proxy_token}, timeout=180)
        if status != 200 or not isinstance(resp, dict) or not resp.get("choices"):
            return {"action": "wait", "reason": f"model call failed HTTP {status}", "model_error": True,
                    "http_status": status, "status": status,
                    "proxy_log_id": (resp or {}).get("legion_proxy_log_id") if isinstance(resp, dict) else None}
        text = resp["choices"][0]["message"].get("content") or ""
        self.messages.append({"role": "assistant", "content": text})
        m = re.search(r"\{.*\}", text, re.S)
        try:
            d = json.loads(m.group(0)) if m else {}
        except ValueError:
            d = {}
        if d.get("action") not in ("call_tool", "wait", "done"):
            d = {"action": "wait", "reason": "unparseable model reply", "unparseable": True}
        d["provider_response_id"] = resp.get("id")
        d["proxy_log_id"] = resp.get("legion_proxy_log_id")
        return d


def main():
    ap = argparse.ArgumentParser()
    for n in ("agent-id", "identity", "obligation", "target", "gateway", "native", "status", "log"):
        ap.add_argument(f"--{n}", required=True)
    ap.add_argument("--stage", type=int, required=True)
    ap.add_argument("--decider", default="scripted", choices=["scripted", "nim"])
    ap.add_argument("--proxy"); ap.add_argument("--proxy-token"); ap.add_argument("--model")
    ap.add_argument("--max-model-turns", type=int, default=12); ap.add_argument("--wall-s", type=float, default=600)
    ap.add_argument("--poll-s", type=float, default=0.5)
    a = ap.parse_args()
    decide = (lambda obs: scripted_decide(obs, a.obligation, a.target, a.stage)) if a.decider == "scripted" else ModelDecider(a)
    history, turns, last_seen, t0 = [], 0, None, time.time()
    provider_failures, tool_failures = 0, 0

    def log(rec):
        base = {"t": time.time(), "mono": time.monotonic(), "agent_id": a.agent_id, "obligation_id": a.obligation, "decider": a.decider}
        if a.decider == "scripted":
            base["label"] = SCRIPTED_LABEL
        with open(a.log, "a") as fh:
            fh.write(json.dumps({**base, **rec}, default=str) + "\n")

    log({"event": "START", "target_id": a.target, "stage": a.stage})
    while time.time() - t0 < a.wall_s:
        _, st = http("GET", f"{a.native}/state")
        _, view = http("GET", f"{a.status}/obligations?agent={urllib.request.quote(a.agent_id, safe='')}")
        if not isinstance(view, dict):
            view = {}
        native = (st or {}).get("stage_by_shard") if isinstance(st, dict) else None
        if view.get("view") == "OWN_STEP_COMPLETE":
            log({"event": "OWN_STEP_COMPLETE_EXIT", "role_view": view, "native_state": native}); return 0
        if view.get("view") != "ACT_ELIGIBLE":
            time.sleep(a.poll_s); continue
        seen = (view.get("state_version"), json.dumps(native, sort_keys=True), len(history))
        if seen == last_seen:
            time.sleep(a.poll_s); continue
        last_seen = seen
        if turns >= a.max_model_turns:
            log({"event": "MODEL_TURN_BUDGET_EXHAUSTED", "turns": turns}); return 2
        turns += 1
        obs = {"native_state": native, "role_view": view, "my_previous_results": history[-4:]}
        d = decide(obs) if a.decider == "nim" else decide(obs)
        if d.get("model_error"):
            # A failed provider call produced no decision: it must not consume
            # a model turn and must not strand this observation (last_seen was
            # already set above). Back off, then re-consult on the same obs.
            turns -= 1
            provider_failures += 1
            delay = backoff_s(provider_failures)
            log({"event": "MODEL_CALL_FAILED", "http_status": d.get("http_status"), "status": d.get("http_status"),
                 "proxy_log_id": d.get("proxy_log_id"), "reason": d.get("reason"),
                 "consecutive_failures": provider_failures, "backoff_s": delay})
            if provider_failures >= 20:
                log({"event": "MODEL_PROVIDER_UNAVAILABLE", "consecutive_failures": provider_failures,
                     "http_status": d.get("http_status"), "status": d.get("http_status"), "proxy_log_id": d.get("proxy_log_id")})
                return 4
            last_seen = None
            time.sleep(delay)
            continue
        provider_failures = 0
        log({"event": "DECISION", "turn": turns, "observation": obs, "decision": d})
        if d.get("action") == "call_tool":
            tool, args = d.get("tool"), dict(d.get("args") or {})
            # The governed tool is always apply_transition for this agent's manifest obligation values.
            args = {"obligation_id": a.obligation, "target_id": a.target, "stage": a.stage} if a.decider == "scripted" else args
            body_args = {**args, "decision_ref": d.get("provider_response_id") or ""}
            hdr = {"l5d-client-id": a.identity}
            action = "apply_transition_" + a.obligation.replace("-", "_")
            ps, pb = http("POST", f"{a.gateway}/governance/validate-action", {"action": action, "params": args}, hdr)
            cs, cb = http("POST", f"{a.gateway}/tools/execute", {"tool_name": "apply_transition", "params": body_args}, hdr)
            out = (cb or {}).get("output") or (cb or {}).get("error") or (cb or {}).get("detail") if isinstance(cb, dict) else None
            history.append({"turn": turns, "tool": tool, "args": args, "preview_http": ps, "commit_http": cs, "commit_result": str(out)[:300]})
            log({"event": "TOOL_CALL", "turn": turns, "tool": tool, "args": args, "decision_ref": body_args["decision_ref"],
                 "preview_http": ps, "commit_http": cs, "commit_body": cb})
            if cs == 429 or cs >= 500:
                # Transient gateway refusal (not a governed BLOCKED/DEFERRED
                # refusal, which arrives as HTTP 200): do not consume the model
                # turn, back off, and seek a fresh model decision before any
                # further tool call.
                turns -= 1
                tool_failures += 1
                delay = backoff_s(tool_failures)
                log({"event": "TOOL_CALL_TRANSIENT", "turn": turns, "commit_http": cs,
                     "consecutive_failures": tool_failures, "backoff_s": delay})
                last_seen = None
                time.sleep(delay)
            else:
                tool_failures = 0
        elif d.get("action") == "done":
            log({"event": "AGENT_SAYS_DONE", "turn": turns, "provider_response_id": d.get("provider_response_id")})
            time.sleep(a.poll_s)
        else:
            time.sleep(a.poll_s)
    log({"event": "WALL_TIMEOUT", "turns": turns}); return 3


if __name__ == "__main__":
    sys.exit(main())
