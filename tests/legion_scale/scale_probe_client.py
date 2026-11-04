"""DETERMINISTIC probe client for live NEGATIVE CONTROLS (labelled; NOT a model agent).
Own OS process, no credentials. Calls real CAGE gateway: preview (per-obligation action) then commit
(MCP tool apply_transition). argv: GATEWAY IDENTITY OBLIGATION TARGET STAGE [DECISION_REF]"""
import json, sys, urllib.request, urllib.error


def post(url, body, ident):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "l5d-client-id": ident})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"null")
        except Exception:
            return e.code, None


gw, ident, obl, target, stage = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
ref = sys.argv[6] if len(sys.argv) > 6 else ""
action = "apply_transition_" + obl.replace("-", "_")
args = {"obligation_id": obl, "target_id": target, "stage": stage}
out = {"labelled": "DETERMINISTIC_PROBE_NOT_A_MODEL_AGENT", "identity": ident, "tool": "apply_transition", "action": action, "args": args}
s, b = post(f"{gw}/governance/validate-action", {"action": action, "params": args}, ident)
out["preview_http"], out["preview_body_head"] = s, json.dumps(b)[:600]
body_args = {**args, **({"decision_ref": ref} if ref else {})}
s, b = post(f"{gw}/tools/execute", {"tool_name": "apply_transition", "params": body_args}, ident)
out["commit_http"], out["commit_body"] = s, b
print(json.dumps(out))
