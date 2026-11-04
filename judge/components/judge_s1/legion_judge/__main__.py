import argparse, json
from pathlib import Path
from .core import evaluate_bundle, aggregate

def main():
    p = argparse.ArgumentParser(description="Deterministic LEGION-100 TEST-posture synthetic Oracle")
    sub = p.add_subparsers(dest="op", required=True)
    ep = sub.add_parser("evaluate")
    ep.add_argument("bundle", type=Path)
    ep.add_argument("--out", type=Path)
    ap = sub.add_parser("aggregate")
    ap.add_argument("registry", type=Path)
    ap.add_argument("verdicts", type=Path, nargs="+")
    args = p.parse_args()
    if args.op == "evaluate":
        result = evaluate_bundle(args.bundle)
    else:
        registry = json.loads(args.registry.read_text(encoding="utf-8"))
        verdicts = [json.loads(x.read_text(encoding="utf-8")) for x in args.verdicts]
        result = aggregate(registry, verdicts)
    payload = json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    if getattr(args, "out", None):
        args.out.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0 if (args.op == "aggregate" or result.get("verdict") == "PASS") else 1

if __name__ == "__main__":
    raise SystemExit(main())
