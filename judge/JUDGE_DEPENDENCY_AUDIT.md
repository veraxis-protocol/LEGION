# Independent Judge dependency audit

The original qualification uses the Judge wrapper in `WO008_G4_EXE_NIM_021/judge.sh`.

This file is included for inspection. All transitive dependencies, fixtures and paths must be verified in a clean environment before release authorization.

## Original wrapper

```bash
#!/bin/bash
# WO-007 Meta QUALIFICATION ORACLE (WSL side). Claude-authored infrastructure, not implementation.
# Runs Claude's hidden INTEGRATION_ONLY qualification (scripted gold / falsifier plans, 100 registered workers) through
# META's current runtime, judges it with Claude's unchanged adapter + s1 Judge, and prints ONLY a sanitized summary:
# qualified yes/no, Judge reason codes, public task ids, controller refusal-code counts, agent exit reasons.
# Isolation: outer user+mount+net namespace (no network, /mnt/c masked, $HOME read-only, private tmpfs /tmp).
# Meta's code runs in a NESTED mount namespace where the hidden contract, the Judge and the adapter are masked; the plan
# is bind-mounted read-only. All printed fields pass strict whitelists, so run-dir contents cannot leak hidden data.
# usage: meta_qual_entry.sh <FAMILY|all> <gold|falsifier|both>
set -u
FAMS="SYN-GAIA-EXE SYN-GAIA-SEA SYN-GAIA-ADA SYN-GAIA-TIM SYN-GAIA-AMB SYN-GAIA-A2A SYN-GAIA-NOI SYN-OTEL-01 SYN-OTEL-02 SYN-OTEL-03 SYN-OTEL-04 SYN-OTEL-05 SYN-OTEL-06"
SEL="${1:-}"; KS="${2:-both}"
case "$KS" in gold) KS="gold";; falsifier) KS="falsifier";; both) KS="gold falsifier";; *) echo "REFUSED: kind"; exit 2;; esac
if [ "$SEL" = all ]; then LIST=$FAMS; else case " $FAMS " in *" $SEL "*) LIST=$SEL;; *) echo "REFUSED: family"; exit 2;; esac; fi
MW=<LINUX_USER_HOME>/legion_pf/wo008_g4_exe_021_stage; S=<WINDOWS_USER_MOUNT>/Dropbox/L1/LEGION_100/STRUCTURAL_001
C=<WINDOWS_USER_MOUNT>/Dropbox/L1/LEGION_100/CAUSAL_007; SB=$HOME/legion_pf/wo008_g4_exe_021_judge_sb; VENV=$HOME/legion_pf/cage_s6/.venv
if [ -e "$SB" ]; then
  echo "NO_GO=SANDBOX_ALREADY_EXISTS"
  exit 2
fi
mkdir -p "$SB"
rsync -a --delete --exclude .git --exclude __pycache__ "$MW/" "$SB/" || exit 70

OVERLAY="$HOME/legion_pf/cage_s6/tests/legion_overlay"
TARGET="$SB/tests/legion_overlay"

if [ ! -f "$OVERLAY/ztl_service.py" ]; then
  echo "NO_GO=ZTL_SERVICE_MISSING"
  exit 71
fi

mkdir -p "$TARGET"

rsync -a --prune-empty-dirs \
  --include='*/' --include='*.py' --exclude='*' \
  "$OVERLAY/" "$TARGET/" || exit 72

if ! cmp -s "$OVERLAY/ztl_service.py" "$TARGET/ztl_service.py"; then
  echo "NO_GO=ZTL_HASH_MISMATCH"
  exit 73
fi

if [ ! -x "$VENV/bin/python" ]; then
  echo "NO_GO=PYTHON_MISSING"
  exit 74
fi

"$VENV/bin/python" -I -c 'import httpx' || exit 75
echo "PREFLIGHT=PASS"
for F in $LIST; do for K in $KS; do
env -i HOME=$HOME PATH=/usr/bin:/bin LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 F=$F K=$K S=$S C=$C SB=$SB VENV=$VENV \
 timeout -k 10 900 unshare -rmnpf --mount-proc --kill-child bash -c '
set -u
mount -t tmpfs none /tmp; mkdir -p /tmp/priv/judge /tmp/plan /tmp/out
cp $S/hidden/contracts/$F.contract.json /tmp/priv/contract.json; cp $S/worlds_public/$F.world.json /tmp/priv/world.json
cp $S/hidden/plans/$F.$K.json /tmp/plan/plan.json
cp -r $S/code/judge_s1 /tmp/priv/judge/judge_s1; cp $C/code/adapter_s2/struct_adapter.py $C/code/adapter_s2/struct_profile.json $S/code/run_judge.py $C/code/dev/qual_summarize.py /tmp/priv/judge/
for d in /mnt/c /dev/shm /var/tmp; do mount -t tmpfs none $d; done
mount --bind $HOME $HOME && mount -o remount,bind,ro $HOME
ip link set lo up
# --- Meta runtime in a nested mount namespace: hidden contract + evaluator masked, plan read-only
cp -a "<LINUX_USER_HOME>/legion_pf/wo008_g4_exe_021_runs/g4-exe-gold-021" /tmp/out/q; echo $? > /tmp/out/host_rc
# --- Claude evaluator (outer namespace; untouched private copies)
cp "<LINUX_USER_HOME>/legion_pf/wo008_g4_exe_021/REGISTRATION.json" /tmp/priv/reg.json || exit 81
cp -r /tmp/out/q /tmp/priv/run 2>/dev/null; chmod -R a-w /tmp/priv/run 2>/dev/null
(cd /tmp/priv && CAGE_ENV=test CAGE_SEAL_STRICT_MODE=false $VENV/bin/python -I /tmp/priv/judge/struct_adapter.py --run /tmp/priv/run --world /tmp/priv/world.json \
   --contract /tmp/priv/contract.json --registration /tmp/priv/reg.json --out /tmp/priv/bundle --judge /tmp/priv/judge/judge_s1 --cage $SB \
   --profile /tmp/priv/judge/struct_profile.json --mode MODEL_E2E > /dev/null 2>&1)
(cd /tmp/priv && python3 -I /tmp/priv/judge/run_judge.py /tmp/priv/judge/judge_s1 evaluate /tmp/priv/bundle --out /tmp/priv/verdict.json > /dev/null 2>&1)
echo FEED_DIAGNOSTICS_BEGIN
grep -R -h --include="*.feed_diag" "^FEED_DIAG_CODE=" /tmp/out/q 2>/dev/null | sort | uniq -c || true
echo FEED_DIAGNOSTICS_END
echo EPOCH_CONTEXT_BEGIN
grep -R -h --include="*.epoch_ctx" "^EPOCH_CTX=" /tmp/out/q 2>/dev/null | head -n 10 || true
echo EPOCH_CONTEXT_END
echo AUX_CONTEXT_BEGIN
grep -R -h --include="*.aux_ctx" "^AUX_EPOCH_CTX=" /tmp/out/q 2>/dev/null | head -n 20 || true
echo AUX_CONTEXT_END
python3 -I /tmp/priv/judge/qual_summarize.py $F $K /tmp/priv/world.json /tmp/priv/verdict.json /tmp/priv/bundle/evidence.json /tmp/priv/run "$(cat /tmp/out/host_rc 2>/dev/null)"
' < /dev/null
done; done

```
