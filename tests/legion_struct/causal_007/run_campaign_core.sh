#!/usr/bin/env bash
# WO-LEGION100-CAUSAL-CLOSURE-007 campaign core (WSL bash).
#
# E6b: the authoritative execution supervisor (causal_007/supervisor.py)
# owns the attempt lifecycle end to end:
#   register attempt (O_EXCL, attempt_index=1, RUN_HEADER with
#   t_episode_registered AND t_episode_registered_mono) BEFORE any proxy;
#   REGISTERED -> RUNNING with one single-use world capability;
#   stub/proxy (dry-run) and the mission host as process groups;
#   COMPLETED on success, INTERRUPTED (verdict INVALID) on any host or
#   critical-child death; terminal attempts are immutable and a second
#   supervisor for the same run is refused before creating anything.
# This core only parses args, resolves paths/env, delegates to the
# supervisor, and scans the run dir for key material afterwards. This
# core must NOT judge. The campaign path contains no pytest invocation:
# test tool only, never the host launcher (incident b1-GAIA-EXE root
# cause: pytest-xdist/--timeout killed the host and the world was
# re-created 9x under one run_id).
set -euo pipefail
CAMPAIGN=""; FAMILY=""; DRY_RUN=0; RUNS_ROOT="${CAUSAL_RUNS_ROOT:-${LEGION_RUNS_ROOT:-$PWD/runs}}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --campaign) CAMPAIGN="$2"; shift 2;;
    --family) FAMILY="$2"; shift 2;;
    --runs-root) RUNS_ROOT="$2"; shift 2;;
    --dry-run) DRY_RUN=1; shift;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[[ "$CAMPAIGN" == "B1" || "$CAMPAIGN" == "S100" ]] || { echo "campaign must be B1|S100" >&2; exit 2; }
[[ -n "$FAMILY" || "$CAMPAIGN" == "S100" ]] || { echo "family required" >&2; exit 2; }
if [[ "$CAMPAIGN" == "S100" ]]; then RUN_ID="s100-SYN-OTEL-04"; else RUN_ID="b1-${FAMILY}"; fi
RUN_DIR="${RUNS_ROOT}/${RUN_ID}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
WORLD_FILE="${REPO_ROOT}/tests/legion_struct/worlds/SYN-${FAMILY}.world.json"
if [[ "$CAMPAIGN" == "S100" ]]; then WORLD_FILE="${REPO_ROOT}/tests/legion_struct/worlds/SYN-OTEL-04.world.json"; fi
[[ -f "$WORLD_FILE" ]] || { echo "world not found: $WORLD_FILE" >&2; exit 2; }
# P0-9: ZTL swarm path. Default is $HOME/legion_pf/ztl-swarm when
# LEGION_ZTL_SWARM_DIR is unset, and it must exist BEFORE any run is
# registered so a campaign never fails later at import.
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
MODEL="nvidia/nemotron-3.5-lightning-30b-a3b"
UPSTREAM="https://integrate.api.nvidia.com/v1"
# Real mode: the NIM key is read ONLY by the provider proxy process from
# this source; it is never printed or logged here.
KEY_SOURCE="${NIM_KEY_SOURCE:-}"
if [[ "$DRY_RUN" != "1" && -z "$KEY_SOURCE" ]]; then echo "REFUSED: NIM_KEY_SOURCE unset" >&2; exit 2; fi
SUP_ARGS=(--campaign "$CAMPAIGN" --family "$FAMILY" --run-id "$RUN_ID"
          --runs-root "$RUNS_ROOT" --world-file "$WORLD_FILE"
          --attempt-index 1 --n-workers 100 --decider nim --mode MODEL_E2E)
if [[ "$DRY_RUN" == "1" ]]; then
  SUP_ARGS+=(--dry-run
             --stub-plan "${CAUSAL_STUB_PLAN:-${STUB_PLAN_FILE:-}}"
             --stub-delay-s "${CAUSAL_STUB_DELAY_S:-0}"
             --storm-429-count "${CAUSAL_STUB_429_COUNT:-0}")
  # Quick header-only check, used only by the light unit test. The default
  # --dry-run (without this env) executes the full pipeline.
  if [[ "${CAUSAL_DRY_RUN_QUICK:-0}" == "1" ]]; then SUP_ARGS+=(--quick); fi
else
  SUP_ARGS+=(--upstream "$UPSTREAM" --key-source "$KEY_SOURCE" --model "$MODEL")
fi
# A failing supervisor (host death, refusal) must not abort this core
# before the key-material scan; the scan always runs, then the core
# exits with the supervisor's code.
HOST_RC=0
LEGION_ZTL_SWARM_DIR="$ZTL_SWARM_DIR_RESOLVED" \
  STRUCT_CAGE_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)" \
  "$PYTHON_BIN" -I "$SCRIPT_DIR/supervisor.py" "${SUP_ARGS[@]}" || HOST_RC=$?
if [[ -d "$RUN_DIR" ]] && grep -rIl 'nvapi-\|NVIDIA_API_KEY=' "$RUN_DIR" >/dev/null 2>&1; then
  echo "REFUSED: key material found in run dir" >&2; exit 4
fi
if [[ "$HOST_RC" != "0" ]]; then echo "supervisor failed: $HOST_RC" >&2; exit "$HOST_RC"; fi
echo "{\"dry_run\": $([[ "$DRY_RUN" == "1" ]] && echo true || echo false), \"run_id\": \"$RUN_ID\", \"run_dir\": \"$RUN_DIR\"}"
