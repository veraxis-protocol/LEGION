"""Independent native readback for LEGION scale (own OS process, stdlib only, read-only GETs).
argv: TARGET_URL OUT_JSON"""
import json, sys, time, urllib.request

url, out = sys.argv[1].rstrip("/"), sys.argv[2]
with urllib.request.urlopen(f"{url}/state", timeout=10) as r:
    st = json.loads(r.read())
with urllib.request.urlopen(f"{url}/effects", timeout=10) as r:
    effects = json.loads(r.read())["effects"]
rec = {"read_at": time.time(), "read_mono": time.monotonic(), "target_pid": st.get("pid"),
       "state": {"stage_by_shard": st.get("stage_by_shard")}, "effects": effects}
open(out, "w").write(json.dumps(rec, indent=1))
print(json.dumps(rec["state"]))
