"""Emit 13 explicitly uncounted positive DEV synthetic evidence bundles."""
import json
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from legion_judge.core import write_bundle, evaluate_bundle
from legion_judge.synthetic import AXES, make_case

root = Path(__file__).resolve().parents[1]
summary = {"kind":"SYNTHETIC_DEV_SMOKE_NOT_COUNTED_VCC", "authoritative_service":"NONE", "results":[]}
for family in AXES:
    c, r, e=make_case(family)
    out=root / "fixtures" / "DEV" / family
    write_bundle(out,c,r,e)
    v=evaluate_bundle(out)
    if v["verdict"] != "PASS":
        raise RuntimeError(f"Fixture {family} failed: {v['mandatory_checks']}")
    (out/"ORACLE_VERDICT.json").write_text(json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+"\n")
    summary["results"].append({"family":family,"verdict":v["verdict"],"native_effects":v["native_effects"]["observed"], "run_type":"SCRIPTED_FIXTURE"})
(root/"results"/"dev_smoke_summary.json").write_text(json.dumps(summary,ensure_ascii=False,sort_keys=True,indent=2)+"\n")
print(f"Generated {len(summary['results'])} DEV test fixtures: all {len(summary['results'])} mechanically PASS, not 13 counted missions")
