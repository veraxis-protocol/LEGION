#!/usr/bin/env bash
# WO-LEGION100-CAUSAL-CLOSURE-007 supervisor-based qualification entry (E6f).
#
# This is the SAME path the campaign uses: supervisor.py owns the attempt
# lifecycle (register -> RUNNING + live attempt authority -> mission_host.py
# -> COMPLETED/INTERRUPTED), establishes the declared campaign CAGE posture
# explicitly (CAMPAIGN_CAGE_POSTURE in supervisor.py), and never runs pytest.
# It differs from the campaign only in the decider: scripted, with the
# (hidden) plan supplied exclusively through the STRUCT_PLAN environment
# variable -- the plan path never appears on any command line.
#
# meta_qual.sh should call THIS entry instead of the pytest wrapper.
# Drop-in contract with the
# old harness: STRUCT_PLAN (required), STRUCT_OUT, STRUCT_RUN_ID and
# STRUCT_WORLD are honoured from the environment exactly as before;
# explicit flags below override them.
#
#   STRUCT_PLAN=<hidden-plan.json> STRUCT_OUT=<out-root> \
#   STRUCT_RUN_ID=<run-id> STRUCT_WORLD=<world.json> \
#     bash run_qual_core.sh [--family SYN-GAIA-EXE] [--n-workers 100]
#
# Exit code is the supervisor's: 0 iff the attempt reached COMPLETED.
set -euo pipefail
FAMILY="${STRUCT_FAMILY:-}"; RUNS_ROOT="${STRUCT_OUT:-}"; RUN_ID="${STRUCT_RUN_ID:-}"
WORLD_FILE="${STRUCT_WORLD:-}"; N_WORKERS="${STRUCT_N_WORKERS:-100}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --family) FAMILY="$2"; shift 2;;
    --runs-root) RUNS_ROOT="$2"; shift 2;;
    --run-id) RUN_ID="$2"; shift 2;;
    --world-file) WORLD_FILE="$2"; shift 2;;
    --n-workers) N_WORKERS="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[[ -n "${STRUCT_PLAN:-}" ]] || { echo "REFUSED: STRUCT_PLAN (hidden plan path) must be set" >&2; exit 2; }
[[ -f "$STRUCT_PLAN" ]] || { echo "REFUSED: STRUCT_PLAN file not found: $STRUCT_PLAN" >&2; exit 2; }
[[ -n "$RUNS_ROOT" ]] || { echo "REFUSED: --runs-root or STRUCT_OUT required" >&2; exit 2; }
[[ -n "$RUN_ID" ]] || { echo "REFUSED: --run-id or STRUCT_RUN_ID required" >&2; exit 2; }
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
if [[ -z "$WORLD_FILE" && -n "$FAMILY" ]]; then
  WORLD_FILE="${REPO_ROOT}/tests/legion_struct/worlds/${FAMILY}.world.json"
fi
[[ -n "$WORLD_FILE" && -f "$WORLD_FILE" ]] || { echo "REFUSED: world not found: $WORLD_FILE" >&2; exit 2; }
if [[ -z "$FAMILY" ]]; then FAMILY="$(basename "$WORLD_FILE" .world.json)"; fi
ZTL_SWARM_DIR_RESOLVED="${LEGION_ZTL_SWARM_DIR:-$HOME/legion_pf/ztl-swarm}"
if [[ ! -d "$ZTL_SWARM_DIR_RESOLVED" ]]; then
  echo "REFUSED: LEGION_ZTL_SWARM_DIR does not exist: $ZTL_SWARM_DIR_RESOLVED" >&2; exit 2
fi
PYTHON_BIN="${CAUSAL_PYTHON:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then PYTHON_BIN="$REPO_ROOT/.venv/bin/python";
  elif [[ -x "$REPO_ROOT/.venv/Scripts/python.exe" ]]; then PYTHON_BIN="$REPO_ROOT/.venv/Scripts/python.exe";
  else PYTHON_BIN="python3"; fi
fi
# Family argument for the supervisor is only used for defaults (world /
# run-id), both supplied explicitly here; strip the SYN- prefix as the
# campaign does (B1 family GAIA-EXE for world SYN-GAIA-EXE).
SUP_FAMILY="${FAMILY#SYN-}"
HOST_RC=0
LEGION_ZTL_SWARM_DIR="$ZTL_SWARM_DIR_RESOLVED" \
STRUCT_PLAN="$STRUCT_PLAN" \
  STRUCT_CAGE_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)" \
  "$PYTHON_BIN" -I "$SCRIPT_DIR/supervisor.py" \
    --campaign B1 --family "$SUP_FAMILY" --run-id "$RUN_ID" \
    --runs-root "$RUNS_ROOT" --world-file "$WORLD_FILE" \
    --attempt-index 1 --n-workers "$N_WORKERS" \
    --decider scripted --mode "${STRUCT_MODE:-INTEGRATION_ONLY}" || HOST_RC=$?
if [[ "$HOST_RC" != "0" ]]; then echo "supervisor failed: $HOST_RC" >&2; exit "$HOST_RC"; fi
echo "{\"qual_entry\": \"supervisor\", \"run_id\": \"$RUN_ID\", \"run_dir\": \"${RUNS_ROOT}/${RUN_ID}\"}"
