#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JUDGE="$HERE/components/judge_s1"
RUNNER="$HERE/components/run_judge.py"
PYTHON="${LEGION_JUDGE_PYTHON:-python3}"
[[ -d "$JUDGE" && -f "$RUNNER" ]] || { echo 'JUDGE_COMPONENTS_MISSING' >&2; exit 2; }
[[ $# -ge 1 ]] || { echo 'Usage: judge.sh evaluate BUNDLE [--out PATH] | aggregate REGISTRY VERDICTS...' >&2; exit 2; }
exec "$PYTHON" -I "$RUNNER" "$JUDGE" "$@"
