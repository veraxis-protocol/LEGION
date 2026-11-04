"""DETERMINISTIC probe client for live NEGATIVE CONTROLS (labelled; NOT a model agent). Own OS process, no credentials.
Calls the real CAGE gateway: preview then commit for one tool. argv: GATEWAY IDENTITY TOOL ARGS_JSON [--no-preview]"""
import json, sys, urllib.request, urllib.error


def post(url, body, ident):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "l5d-client-id": ident})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


gw, ident, tool, args = sys.argv[1], sys.argv[2], sys.argv[3], json.loads(sys.argv[4])
out = {"labelled": "DETERMINISTIC_PROBE_NOT_A_MODEL_AGENT", "identity": ident, "tool": tool, "args": args}
if "--no-preview" not in sys.argv:
    s, b = post(f"{gw}/governance/validate-action", {"action": tool, "params": args}, ident)
    out["preview_http"] = s
    out["preview_verdict"] = (b or {}).get("verdict") if isinstance(b, dict) else None
    out["preview_body_head"] = json.dumps(b)[:600]
s, b = post(f"{gw}/tools/execute", {"tool_name": tool, "params": args}, ident)
out["commit_http"], out["commit_body"] = s, b
print(json.dumps(out))
